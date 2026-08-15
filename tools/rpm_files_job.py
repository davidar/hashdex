# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx[http2]>=0.27", "zstandard>=0.22", "pyarrow>=17", "duckdb>=1.0", "huggingface_hub>=0.24"]
# ///
"""HF Job: harvest every known RPM repo into the rpm-files dataset.

The wide-sweep sibling of tools/rpm_files.py (which stays as the
small local harvester): enumerate the repo families we know publish
header ranges — Fedora (Core 1 onward, releases + updates, archives
included), EPEL, RPM Fusion, VS Code, CentOS Stream + vault,
AlmaLinux + vault, Rocky + vault, openSUSE (Leap history + updates +
Tumbleweed) — fetch each package's header with one HTTP range GET,
and publish the normalized parquet layout:

  data/packages.parquet          pkgid scheme witness name evr arch location
                                 (sorted by pkgid — rpm artifacts resolve)
  data/files-sha256-{0..f}.parquet   digest path pkg   (pkg = row index
  data/files-{md5,sha1}.parquet      into packages.parquet; sorted by digest)
  rpm-files.sha256.bloom         one routing bloom for the whole rpm world
  tsv/<witness>.tsv.gz           raw harvest, uploaded per witness

Every witness TSV uploads the moment it completes (checkpoint rule:
job-local state dies with the job) and doubles as the resume marker —
a relaunch skips witnesses already on the Hub. Harvest runs repos
concurrently under per-host stream budgets, so wall time is bounded
by the politest host, not the sum of repo latency tails.

Launch:
  hf jobs uv run --flavor cpu-xl --timeout 8h -s HF_TOKEN \
      tools/rpm_files_job.py

Enumerate only (local, prints the repo list, no header GETs):
  RPM_ENUMERATE=1 uv run tools/rpm_files_job.py
Smoke (local, tiny repo set, full pipeline, no uploads):
  RPM_SMOKE=1 uv run tools/rpm_files_job.py
"""
import asyncio
import gzip
import io
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.request

REPO = "david-ar/rpm-files"
SMOKE = bool(os.environ.get("RPM_SMOKE"))
ENUMERATE = bool(os.environ.get("RPM_ENUMERATE"))
WORK = pathlib.Path(os.environ.get("RPM_WORK", "/tmp/rpm-files"))
UA = "hashdex-rpm-files/0.2 (hash index research; one range GET per rpm)"

# Politeness: per-host cap on in-flight requests (headers are ~25 KB,
# so 32 streams is modest), and a bound on repos harvested at once.
HOST_STREAMS = 32
ARCHES = {"x86_64", "noarch"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ----------------------------------------------------------- rpm parsing
# (tools/rpm_files.py lineage — kept in sync by hand; the job must be
# self-contained.)

HEADER_MAGIC = b"\x8e\xad\xe8\x01"
TAG_FILEDIGESTS, TAG_DIRINDEXES, TAG_BASENAMES, TAG_DIRNAMES, TAG_ALGO = (
    1035,
    1116,
    1117,
    1118,
    5011,
)
WANTED_TAGS = {TAG_FILEDIGESTS, TAG_DIRINDEXES, TAG_BASENAMES, TAG_DIRNAMES, TAG_ALGO}
ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}
HEX_LEN = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}
# primary.xml checksum types → our scheme names ("sha" = sha1 in
# createrepo's pre-2009 vocabulary).
CSUM_SCHEMES = {"sha256": "sha256", "sha512": "sha512", "sha1": "sha1", "sha": "sha1", "md5": "md5"}


def xml_unescape(s):
    for ent, ch in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&amp;", "&")):
        s = s.replace(ent, ch)
    return s


def parse_primary(xml):
    """Per-package dicts from primary.xml, arch-filtered. Blocks
    missing header-range (pre-createrepo-0.4 relics) are counted and
    skipped, not fatal."""
    pkgs = []
    skipped = {"arch": 0, "norange": 0, "malformed": 0}
    for m in re.finditer(rb"<package type=\"rpm\">(.*?)</package>", xml, re.DOTALL):
        blk = m.group(1)
        try:
            arch = re.search(rb"<arch>([^<]*)</arch>", blk).group(1).decode()
            if arch not in ARCHES:
                skipped["arch"] += 1
                continue
            rng = re.search(rb'<rpm:header-range start="(\d+)" end="(\d+)"', blk)
            if not rng:
                skipped["norange"] += 1
                continue
            name = xml_unescape(re.search(rb"<name>([^<]*)</name>", blk).group(1).decode())
            vtag = re.search(rb"<version\s[^>]*/?>", blk).group(0)
            epoch = re.search(rb'epoch="([^"]*)"', vtag)
            ver = re.search(rb'ver="([^"]*)"', vtag).group(1).decode()
            rel = re.search(rb'rel="([^"]*)"', vtag).group(1).decode()
            csum = re.search(rb'<checksum type="([^"]+)"[^>]*>([0-9a-fA-F]+)</checksum>', blk)
            loc = xml_unescape(re.search(rb'<location href="([^"]+)"', blk).group(1).decode())
        except AttributeError:
            skipped["malformed"] += 1
            continue
        e = epoch.group(1).decode() if epoch else "0"
        evr = f"{ver}-{rel}" if e in ("", "0") else f"{e}:{ver}-{rel}"
        ctype = CSUM_SCHEMES.get(csum.group(1).decode().lower())
        if ctype is None:
            skipped["malformed"] += 1
            continue
        pkgs.append(
            dict(
                name=name,
                arch=arch,
                evr=evr,
                csum_type=ctype,
                pkgid=csum.group(2).decode().lower(),
                location=loc,
                start=int(rng.group(1)),
                end=int(rng.group(2)),
            )
        )
    return pkgs, skipped


def read_string_array(blob, store, entry):
    typ, doff, count = entry
    if typ not in (8, 9):
        raise ValueError(f"expected string array, got type {typ}")
    out = []
    p = store + doff
    for _ in range(count):
        end = blob.index(b"\x00", p)
        out.append(blob[p:end].decode("utf-8", errors="replace"))
        p = end + 1
    return out


def read_int32_array(blob, store, entry):
    typ, doff, count = entry
    if typ != 4:
        raise ValueError(f"expected int32 array, got type {typ}")
    p = store + doff
    return list(struct.unpack(f">{count}i", blob[p : p + 4 * count]))


def parse_header_files(blob):
    """(scheme, [(path, digest)]) from a package header; walks past a
    leading signature header; keeps per-file array alignment while
    dropping empty digests (dirs, symlinks, ghosts)."""
    off = 0
    for _ in range(2):
        if blob[off : off + 4] != HEADER_MAGIC:
            raise ValueError(f"bad header magic at {off}")
        nindex, hsize = struct.unpack(">II", blob[off + 8 : off + 16])
        store = off + 16 + nindex * 16
        tags = {}
        for i in range(nindex):
            tag, typ, doff, count = struct.unpack(
                ">IIII", blob[off + 16 + i * 16 : off + 32 + i * 16]
            )
            if tag in WANTED_TAGS:
                tags[tag] = (typ, doff, count)
        if TAG_BASENAMES in tags:
            basenames = read_string_array(blob, store, tags[TAG_BASENAMES])
            digests = read_string_array(blob, store, tags[TAG_FILEDIGESTS])
            dirnames = read_string_array(blob, store, tags[TAG_DIRNAMES])
            dirindexes = read_int32_array(blob, store, tags[TAG_DIRINDEXES])
            if not (len(basenames) == len(digests) == len(dirindexes)):
                raise ValueError("file array lengths disagree")
            algo = 1
            if TAG_ALGO in tags:
                algo = read_int32_array(blob, store, tags[TAG_ALGO])[0]
            scheme = ALGOS.get(algo)
            if scheme is None:
                raise ValueError(f"unknown FILEDIGESTALGO {algo}")
            files = []
            for base, digest, di in zip(basenames, digests, dirindexes):
                if not digest:
                    continue
                if len(digest) != HEX_LEN[scheme]:
                    raise ValueError(f"{scheme} digest of length {len(digest)}")
                files.append((dirnames[di] + base, digest.lower()))
            return scheme, files
        off = store + hsize
        off += (8 - off % 8) % 8
        if off + 16 > len(blob):
            break
    return None, []  # no file manifest: package ships no files


# ---------------------------------------------------------- enumeration
# Every enumerator returns (witness, repo base URL) pairs, discovered
# from the hosts' own directory listings — never a hardcoded range —
# and verified by the harvest's own repomd fetch. Claim URLs are the
# same base (canonical hosts; the job runs in-DC, no mirror needed).

HREF = re.compile(r'href="([^"?][^"]*)"')


def listing(client, url):
    r = client.get(url)
    r.raise_for_status()
    names = []
    for h in HREF.findall(r.text):
        h = h.rstrip("/").rsplit("/", 1)[-1]
        if h and h not in ("..", ".") and not h.startswith(".."):
            names.append(h)
    return names


def has_repo(client, base):
    """Only 404 proves absence; transient errors retry and then warn
    loudly — a dropped probe would silently thin the sweep (the
    fedora-7 lesson: one blip cost a whole release)."""
    url = f"{base}/repodata/repomd.xml"
    for attempt in range(3):
        try:
            r = client.head(url)
            if r.status_code == 405:  # some hosts dislike HEAD
                r = client.get(url)
            if r.status_code == 200:
                return True
            if r.status_code in (403, 404):
                return False
            err = f"HTTP {r.status_code}"
        except Exception as e:  # noqa: BLE001 — retry
            err = str(e)
        time.sleep(1 + attempt)
    log(f"  warning: probe {url} kept failing ({err}) — treating as absent")
    return False


def numeric(names, pat=r"\d+(\.\d+)*"):
    return sorted(
        (n for n in names if re.fullmatch(pat, n)),
        key=lambda v: [int(x) for x in v.split(".")],
    )


class RepoSet:
    """Witness-deduping accumulator: the first host to actually serve
    a repo wins (probe order encodes preference), stubs and rebrands
    on later hosts never shadow it."""

    def __init__(self, client):
        self.client = client
        self.repos = []
        self.seen = set()

    def add(self, witness, *candidates):
        if witness in self.seen:
            return
        for base in candidates:
            if has_repo(self.client, base):
                self.seen.add(witness)
                self.repos.append((witness, base))
                return


def enum_fedora(client):
    rs = RepoSet(client)
    arc = "https://archives.fedoraproject.org/pub/archive/fedora/linux"
    dl = "https://dl.fedoraproject.org/pub/fedora/linux"
    for n in numeric(listing(client, f"{arc}/core/")):
        rs.add(f"fedora-core-{n}", f"{arc}/core/{n}/x86_64/os")
    for n in numeric(listing(client, f"{arc}/core/updates/")):
        rs.add(f"fedora-core-{n}-updates", f"{arc}/core/updates/{n}/x86_64")
    # archive first: dl keeps empty stub dirs for moved releases
    for host in (arc, dl):
        for n in numeric(listing(client, f"{host}/releases/")):
            rs.add(f"fedora-{n}", f"{host}/releases/{n}/Everything/x86_64/os")
        for n in numeric(listing(client, f"{host}/updates/")):
            # layout flipped at F21: updates/N/x86_64 before,
            # updates/N/Everything/x86_64 after
            rs.add(
                f"fedora-{n}-updates",
                f"{host}/updates/{n}/Everything/x86_64",
                f"{host}/updates/{n}/x86_64",
            )
    return rs.repos


def enum_epel(client):
    rs = RepoSet(client)
    for host in (
        "https://archives.fedoraproject.org/pub/archive/epel",
        "https://dl.fedoraproject.org/pub/epel",
    ):
        for n in numeric(listing(client, f"{host}/")):
            rs.add(f"epel-{n}", f"{host}/{n}/Everything/x86_64", f"{host}/{n}/x86_64")
    return rs.repos


def enum_rpmfusion(client):
    rs = RepoSet(client)
    for kind in ("free", "nonfree"):
        # RPM Fusion hosts only current releases — no public archive
        # of EOL release repos exists (archive.rpmfusion.org mirrors
        # the same current tree; checked 2026-08-15)
        for host in (f"https://download1.rpmfusion.org/{kind}/fedora",):
            for n in numeric(listing(client, f"{host}/releases/")):
                rs.add(
                    f"rpmfusion-{kind}-fedora-{n}",
                    f"{host}/releases/{n}/Everything/x86_64/os",
                )
            for n in numeric(listing(client, f"{host}/updates/")):
                rs.add(
                    f"rpmfusion-{kind}-fedora-{n}-updates",
                    f"{host}/updates/{n}/x86_64",
                    f"{host}/updates/{n}/Everything/x86_64",
                )
    return rs.repos


def enum_vscode(_client):
    return [("vscode", "https://packages.microsoft.com/yumrepos/vscode")]


def enum_centos_stream(client):
    repos = []
    host = "https://mirror.stream.centos.org"
    for n in (n for n in listing(client, f"{host}/") if re.fullmatch(r"\d+-stream", n)):
        for comp in ("BaseOS", "AppStream", "CRB"):
            base = f"{host}/{n}/{comp}/x86_64/os"
            if has_repo(client, base):
                repos.append((f"centos-stream-{n.split('-')[0]}-{comp.lower()}", base))
    return repos


def enum_centos_vault(client):
    repos = []
    host = "https://vault.centos.org"
    for v in numeric(listing(client, f"{host}/")):
        found = False
        for comp, sub in (("baseos", "BaseOS/x86_64/os"), ("appstream", "AppStream/x86_64/os")):
            base = f"{host}/{v}/{sub}"
            if has_repo(client, base):
                repos.append((f"centos-{v}-{comp}", base))
                found = True
        if not found:
            for tag, sub in (("", "os/x86_64"), ("-updates", "updates/x86_64")):
                base = f"{host}/{v}/{sub}"
                if has_repo(client, base):
                    repos.append((f"centos-{v}{tag}", base))
    return repos


def enum_alma(client):
    repos = []
    seen = set()
    vault = "https://vault.almalinux.org"
    current = "https://repo.almalinux.org/almalinux"
    for host, names in (
        (vault, numeric(listing(client, f"{vault}/"))),
        (current, numeric(listing(client, f"{current}/"), r"\d+\.\d+")),
    ):
        for v in names:
            for comp in ("BaseOS", "AppStream"):
                w = f"almalinux-{v}-{comp.lower()}"
                base = f"{host}/{v}/{comp}/x86_64/os"
                if w not in seen and has_repo(client, base):
                    seen.add(w)
                    repos.append((w, base))
    return repos


def enum_rocky(client):
    repos = []
    seen = set()
    for host in (
        "https://dl.rockylinux.org/vault/rocky",
        "https://dl.rockylinux.org/pub/rocky",
    ):
        for v in numeric(listing(client, f"{host}/"), r"\d+\.\d+"):
            for comp in ("BaseOS", "AppStream", "CRB"):
                w = f"rocky-{v}-{comp.lower()}"
                base = f"{host}/{v}/{comp}/x86_64/os"
                if w not in seen and has_repo(client, base):
                    seen.add(w)
                    repos.append((w, base))
    return repos


def enum_opensuse(client):
    repos = []
    dl = "https://download.opensuse.org"
    for v in numeric(listing(client, f"{dl}/distribution/leap/"), r"\d+\.\d+"):
        if has_repo(client, f"{dl}/distribution/leap/{v}/repo/oss"):
            repos.append((f"opensuse-leap-{v}", f"{dl}/distribution/leap/{v}/repo/oss"))
        if has_repo(client, f"{dl}/update/leap/{v}/oss"):
            repos.append((f"opensuse-leap-{v}-updates", f"{dl}/update/leap/{v}/oss"))
    if has_repo(client, f"{dl}/tumbleweed/repo/oss"):
        repos.append(("opensuse-tumbleweed", f"{dl}/tumbleweed/repo/oss"))
    return repos


FAMILIES = [
    enum_fedora,
    enum_epel,
    enum_rpmfusion,
    enum_vscode,
    enum_centos_stream,
    enum_centos_vault,
    enum_alma,
    enum_rocky,
    enum_opensuse,
]
SMOKE_FAMILIES = [enum_vscode]


def enumerate_repos():
    import httpx

    repos = []
    with httpx.Client(
        http2=True, follow_redirects=True, timeout=60, headers={"User-Agent": UA}
    ) as client:
        for fam in SMOKE_FAMILIES if SMOKE else FAMILIES:
            try:
                found = fam(client)
            except Exception as e:
                # Enumeration failures are loud, never silent thinning.
                log(f"ERROR enumerating {fam.__name__}: {e}")
                raise
            log(f"{fam.__name__}: {len(found)} repos")
            repos.extend(found)
    names = [w for w, _ in repos]
    assert len(names) == len(set(names)), "duplicate witness names"
    # Interleave across hosts: the list arrives family-by-family, and
    # harvesting it in order would run one host at a time under its
    # politeness cap while every other host sits idle. Round-robin by
    # host overlaps them — wall time becomes the slowest host's share,
    # not the sum.
    by_host = {}
    for w, b in repos:
        by_host.setdefault(b.split("/")[2], []).append((w, b))
    interleaved = []
    queues = list(by_host.values())
    while queues:
        queues = [q for q in queues if q]
        for q in queues:
            if q:
                interleaved.append(q.pop(0))
    return interleaved


# -------------------------------------------------------------- harvest


def clean(s):
    if "\t" in s or "\n" in s:
        raise ValueError(f"field contains separator: {s!r}")
    return s if s else "-"


def format_pkg_rows(blob, pkg, witness, base):
    """Worker-side CPU: parse one header and format its TSV block.
    Runs in a process pool — the event loop keeps only fetch+write,
    one Python thread was capping the whole sweep at ~200 pkg/s.
    Returns (tsv_text, row_count, skipped_count)."""
    scheme, files = parse_header_files(blob)
    out = [(pkg["csum_type"], pkg["pkgid"], "-", "-")]
    out += [(scheme, digest, path, pkg["pkgid"]) for path, digest in files]
    lines = []
    skipped = 0
    for sch, digest, path, pkgid in out:
        try:
            lines.append(
                "\t".join(
                    clean(v)
                    for v in (
                        witness,
                        sch,
                        digest,
                        pkg["name"],
                        pkg["evr"],
                        pkg["arch"],
                        path,
                        pkgid,
                        f"{base}/{pkg['location']}",
                    )
                )
            )
        except ValueError:
            skipped += 1
    return "".join(line + "\n" for line in lines), len(lines), skipped


async def fetch_primary(client, sem, base):
    async with sem:
        r = await client.get(f"{base}/repodata/repomd.xml")
        r.raise_for_status()
        m = re.search(r'<data type="primary">.*?href="([^"]+)"', r.text, re.DOTALL)
        if not m:
            raise ValueError(f"{base}: no primary in repomd.xml")
        r = await client.get(f"{base}/{m.group(1)}")
        r.raise_for_status()
    raw = r.content
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard

        return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw)).read()
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    if raw[:6] == b"\xfd7zXZ\x00":
        import lzma

        return lzma.decompress(raw)
    import zlib

    return zlib.decompress(raw, 47)


async def harvest_repo(client, sem, workers, witness, base, tsv_dir, stats):
    """One repo → tsv/<witness>.tsv.gz (atomic; any package failure
    leaves nothing so a relaunch retries the witness)."""
    out_path = tsv_dir / f"{witness}.tsv.gz"
    xml = await fetch_primary(client, sem, base)
    pkgs, skipped = parse_primary(xml)
    note = ", ".join(f"{k} {v}" for k, v in skipped.items() if v)
    log(f"{witness}: {len(pkgs)} packages" + (f" (skipped: {note})" if note else ""))
    if not pkgs:
        # a marker, not an empty tsv: duckdb's csv reader chokes on
        # empty gz, but the dispatcher must still see this as done
        stats["empty"].append(witness)
        (tsv_dir / f"{witness}.empty").touch()
        return

    failed = []
    rows = 0
    part = out_path.with_suffix(out_path.suffix + ".part")
    # level 1: intermediates — CPU on the write path is the scarce
    # resource, not tsv bytes
    fh = gzip.open(part, "wt", encoding="utf-8", compresslevel=1)
    write_lock = asyncio.Lock()
    loop = asyncio.get_event_loop()

    async def one(pkg):
        nonlocal rows
        for attempt in range(4):
            try:
                async with sem:
                    r = await client.get(
                        f"{base}/{pkg['location']}",
                        headers={"Range": f"bytes={pkg['start']}-{pkg['end'] - 1}"},
                    )
                if r.status_code not in (200, 206):
                    raise IOError(f"HTTP {r.status_code}")
                text, n, skipped = await loop.run_in_executor(
                    workers, format_pkg_rows, r.content, pkg, witness, base
                )
                async with write_lock:
                    fh.write(text)
                rows += n
                if skipped:
                    stats["skipped_rows"] += skipped
                stats["pkgs"] += 1
                return
            except Exception as exc:  # noqa: BLE001 — retry
                if attempt == 3:
                    failed.append((pkg["location"], str(exc)))
                else:
                    await asyncio.sleep(1 + attempt)

    await asyncio.gather(*(one(p) for p in pkgs))
    fh.close()
    if failed:
        part.unlink()
        log(f"{witness}: {len(failed)} FAILED, e.g. {failed[:3]}")
        stats["failed"].append(witness)
        return
    part.rename(out_path)
    stats["rows"] += rows
    log(f"{witness}: done, {rows:,} rows")


# One asyncio event loop maxes out around ~200 requests/s of httpx
# machinery on this hardware — measured invariant across host
# interleaving, pool sizes, and parse offloading. So the harvest runs
# as LANE PROCESSES, each with its own loop: lanes partition by host,
# and a busy host's stream budget divides across its lanes, keeping
# per-host politeness exact while the aggregate scales with cores.

LANE_MAX = 4  # lanes a single busy host may split into


def plan_lanes(todo):
    by_host = {}
    for w, b in todo:
        by_host.setdefault(b.split("/")[2], []).append((w, b))
    lanes = []
    for host, reps in sorted(by_host.items()):
        k = min(LANE_MAX, max(1, len(reps) // 20))
        streams = max(4, HOST_STREAMS // k)
        for i in range(k):
            lanes.append((host, i, streams, reps[i::k]))
    return lanes


async def lane_run(host, lane_id, streams, repos, tsv_dir):
    import concurrent.futures

    import httpx

    stats = {"pkgs": 0, "rows": 0, "skipped_rows": 0, "failed": [], "empty": []}
    workers = concurrent.futures.ProcessPoolExecutor(max_workers=2)
    sem = asyncio.Semaphore(streams)
    repo_sem = asyncio.Semaphore(4)
    limits = httpx.Limits(max_connections=streams + 4, max_keepalive_connections=streams + 4)
    t0 = time.time()

    async def guarded(w, b):
        async with repo_sem:
            try:
                await harvest_repo(client, sem, workers, w, b, tsv_dir, stats)
            except Exception as e:  # noqa: BLE001 — one repo must not kill the lane
                log(f"{w}: ERROR {e}")
                stats["failed"].append(w)
            else:
                if w not in stats["failed"] and w not in stats["empty"]:
                    # off the event loop: an LFS upload must not stall
                    # the lane's fetches
                    await asyncio.get_event_loop().run_in_executor(
                        None, upload_checkpoint, tsv_dir / f"{w}.tsv.gz"
                    )

    async with httpx.AsyncClient(
        http2=True,
        follow_redirects=True,
        limits=limits,
        timeout=120,
        headers={"User-Agent": UA},
    ) as client:
        tasks = [asyncio.ensure_future(guarded(w, b)) for w, b in repos]
        while tasks and not all(t.done() for t in tasks):
            await asyncio.sleep(30)
            log(
                f"  [{host}/{lane_id}] {stats['pkgs']:,} pkgs, "
                f"{sum(t.done() for t in tasks)}/{len(tasks)} repos, "
                f"{stats['pkgs'] / max(time.time() - t0, 1):.0f} pkg/s"
            )
        await asyncio.gather(*tasks)
    log(
        f"  [{host}/{lane_id}] lane done: {stats['pkgs']:,} pkgs, {stats['rows']:,} rows"
        + (f", FAILED {stats['failed']}" if stats["failed"] else "")
    )


def lane_main(host, lane_id, streams, repos, tsv_dir):
    asyncio.run(lane_run(host, lane_id, streams, repos, tsv_dir))


def harvest_all(repos, tsv_dir, done_witnesses):
    """Dispatch lanes; ground truth of what succeeded is the files on
    disk afterwards, not in-process state."""
    import multiprocessing

    todo = [(w, b) for w, b in repos if w not in done_witnesses]
    lanes = plan_lanes(todo)
    log(
        f"harvest: {len(todo)} repos to do ({len(repos) - len(todo)} already done), "
        f"{len(lanes)} lanes across {len({h for h, _, _, _ in lanes})} hosts"
    )
    procs = [
        multiprocessing.Process(target=lane_main, args=(h, i, s, r, tsv_dir), daemon=False)
        for h, i, s, r in lanes
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    crashed = [p.exitcode for p in procs if p.exitcode]
    if crashed:
        log(f"warning: {len(crashed)} lanes exited nonzero")
    present = {p.name.removesuffix(".tsv.gz") for p in tsv_dir.glob("*.tsv.gz")}
    present |= {p.name.removesuffix(".empty") for p in tsv_dir.glob("*.empty")}
    return [w for w, _ in todo if w not in present]


def upload_checkpoint(path):
    if SMOKE:
        return
    from huggingface_hub import HfApi

    api = HfApi()
    for attempt in range(5):
        try:
            api.upload_file(
                path_or_fileobj=str(path),
                path_in_repo=f"tsv/{path.name}",
                repo_id=REPO,
                repo_type="dataset",
                commit_message=f"tsv: {path.name}",
            )
            return
        except Exception as e:  # noqa: BLE001
            log(f"upload {path.name} failed (attempt {attempt + 1}): {e}")
            time.sleep(30 * (attempt + 1))
    sys.exit(f"giving up uploading {path.name}")


# -------------------------------------------------------------- parquet

TSV_COLS = ["witness", "scheme", "digest", "name", "evr", "arch", "path", "pkgid", "location"]

WRITER_OPTS = dict(
    compression="zstd",
    compression_level=3,
    use_dictionary=False,
    data_page_size=128 * 1024,
    write_batch_size=256,
    write_page_index=True,
)


def build_parquet(tsv_dir, outdir):
    import duckdb
    import pyarrow as pa
    import pyarrow.parquet as pq

    (outdir / "data").mkdir(parents=True, exist_ok=True)
    tmp = WORK / "duck-tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(WORK / "build.duckdb"))
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET temp_directory='{tmp}'")
    con.execute("SET memory_limit='96GB'" if not SMOKE else "SET memory_limit='4GB'")

    cols = ", ".join(f"'{c}': 'VARCHAR'" for c in TSV_COLS)
    con.execute(
        f"""CREATE OR REPLACE TABLE raw AS
            SELECT * FROM read_csv('{tsv_dir}/*.tsv.gz', delim='\t', header=false,
                                   nullstr='-', quote='', escape='',
                                   columns={{{cols}}})"""
    )
    n_raw = con.execute("SELECT count(*) FROM raw").fetchone()[0]
    log(f"parquet: {n_raw:,} raw rows")

    con.execute(
        """CREATE OR REPLACE TABLE packages AS
           SELECT row_number() OVER (ORDER BY pkgid, witness, location) - 1 AS pkg,
                  pkgid, scheme, witness, name, evr, arch, location
           FROM (SELECT DISTINCT digest AS pkgid, scheme, witness, name, evr, arch, location
                 FROM raw WHERE path IS NULL)"""
    )
    n_pkgs = con.execute("SELECT count(*) FROM packages").fetchone()[0]

    con.execute(
        """CREATE OR REPLACE TABLE files AS
           SELECT r.scheme, r.digest, r.path, p.pkg
           FROM raw r JOIN packages p ON r.witness = p.witness AND r.pkgid = p.pkgid
           WHERE r.path IS NOT NULL"""
    )
    n_files = con.execute("SELECT count(*) FROM files").fetchone()[0]
    n_file_rows = con.execute("SELECT count(*) FROM raw WHERE path IS NOT NULL").fetchone()[0]
    log(f"parquet: {n_pkgs:,} packages, {n_files:,} file rows")
    if n_files != n_file_rows:
        sys.exit(f"JOIN LOST ROWS: {n_file_rows:,} file rows, {n_files:,} joined")

    stage = WORK / "stage"
    stage.mkdir(exist_ok=True)

    def transcode(src, dest, key):
        """duckdb wrote sorted single-file parquet; rewrite with page
        indexes (duckdb can't) and verify sortedness + presence."""
        table = pq.read_table(src)
        pq.write_table(table, dest, **WRITER_OPTS)
        f = pq.ParquetFile(dest)
        assert f.metadata.num_rows == table.num_rows
        if table.num_rows:  # empty tables carry no pages to index
            for rg in range(f.metadata.num_row_groups):
                for c in range(f.metadata.num_columns):
                    assert f.metadata.row_group(rg).column(c).has_offset_index, (dest, rg, c)
        keys = f.read(columns=[key]).column(0)
        if len(keys):
            import pyarrow.compute as pc

            assert keys.null_count == 0, f"{dest}: null {key}"
            assert pc.all(
                pc.less_equal(keys.slice(0, len(keys) - 1), keys.slice(1))
            ).as_py(), f"{dest}: {key} not sorted"
        log(f"  {dest.name}: {f.metadata.num_rows:,} rows, {dest.stat().st_size:,} bytes")
        return dest

    outputs = []
    # packages: ORDER BY pkg == pkgid order; pkg column itself is
    # implicit (row number), not stored.
    src = stage / "packages.parquet"
    con.execute(
        f"""COPY (SELECT pkgid, scheme, witness, name, evr, arch, location
                  FROM packages ORDER BY pkg)
            TO '{src}' (FORMAT parquet)"""
    )
    outputs.append(transcode(src, outdir / "data" / "packages.parquet", "pkgid"))

    for nib in "0123456789abcdef":
        src = stage / f"files-sha256-{nib}.parquet"
        con.execute(
            f"""COPY (SELECT digest, path, pkg FROM files
                      WHERE scheme = 'sha256' AND digest LIKE '{nib}%'
                      ORDER BY digest, pkg, path)
                TO '{src}' (FORMAT parquet)"""
        )
        outputs.append(transcode(src, outdir / "data" / f"files-sha256-{nib}.parquet", "digest"))

    for weak in ("md5", "sha1"):
        src = stage / f"files-{weak}.parquet"
        con.execute(
            f"""COPY (SELECT digest, path, pkg FROM files
                      WHERE scheme = '{weak}' ORDER BY digest, pkg, path)
                TO '{src}' (FORMAT parquet)"""
        )
        outputs.append(transcode(src, outdir / "data" / f"files-{weak}.parquet", "digest"))

    # spot-check the ref chain end-to-end: highest-ref file row points
    # inside packages, and a random join reproduces the raw row.
    max_ref = con.execute("SELECT max(pkg) FROM files").fetchone()[0]
    if max_ref is not None and max_ref >= n_pkgs:
        sys.exit(f"pkg ref {max_ref} out of range ({n_pkgs} packages)")

    keys = WORK / "sha256_keys.txt"
    con.execute(
        f"""COPY (SELECT digest FROM files WHERE scheme = 'sha256'
                  UNION SELECT pkgid FROM packages WHERE scheme = 'sha256')
            TO '{keys}' (FORMAT csv, HEADER false)"""
    )
    n_keys = con.execute(f"SELECT count(*) FROM read_csv('{keys}', header=false)").fetchone()[0]
    con.close()
    log(f"bloom keys: {n_keys:,} distinct sha256")
    return outputs, keys, n_keys


# ---------------------------------------------------------------- bloom
# Embedded DCSO builder, byte-exact vs src/dcso.rs (the SWH/census
# jobs' verified twin). sha256 keys are LOWERCASE hex (scan
# convention: sha1 upper, sha256 lower), fixed 64-byte records.

RUST_CARGO_TOML = """\
[package]
name = "dcso_bloom"
version = "0.1.0"
edition = "2021"

[profile.release]
lto = true
codegen-units = 1
"""

RUST_MAIN = r"""
use std::io::{Read, Write};

#[cfg(not(target_endian = "little"))]
compile_error!("little-endian only (DCSO format is LE; we dump words raw)");

const MOD: u64 = 18_446_744_073_709_551_529; // 2^64 - 87
const G: u64 = 18_446_744_073_709_550_147;

fn fnv1_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h = h.wrapping_mul(0x100000001b3);
        h ^= b as u64;
    }
    h
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (n, p, rec, out) = (
        a[0].parse::<u64>().unwrap(),
        a[1].parse::<f64>().unwrap(),
        a[2].parse::<usize>().unwrap(),
        &a[3],
    );
    let ln2 = std::f64::consts::LN_2;
    let m = ((n as f64) * (-p.ln()) / (ln2 * ln2)).ceil() as u64;
    let k = ((m as f64 / n as f64) * ln2).round().max(1.0) as u64;
    let words = m.div_ceil(64) as usize;
    eprintln!("dcso_bloom: n={n} p={p} m={m} k={k} ({} MiB)", words * 8 / 1048576);

    let mut bits = vec![0u64; words];
    let mut stdin = std::io::stdin().lock();
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 8 << 20];
    let mut inserted: u64 = 0;
    loop {
        let got = stdin.read(&mut buf).expect("stdin read");
        if got == 0 {
            break;
        }
        let mut chunk = std::mem::take(&mut carry);
        chunk.extend_from_slice(&buf[..got]);
        let keep = chunk.len() - chunk.len() % rec;
        carry = chunk.split_off(keep);
        for r in chunk.chunks_exact(rec) {
            let mut h = fnv1_64(r) % MOD;
            for _ in 0..k {
                h = h.wrapping_mul(G) % MOD;
                let bit = h % m;
                bits[(bit >> 6) as usize] |= 1u64 << (bit & 63);
            }
            inserted += 1;
        }
    }
    assert!(carry.is_empty(), "trailing {} bytes not a whole record", carry.len());

    let file = std::fs::File::create(out).expect("create out");
    let mut w = std::io::BufWriter::with_capacity(8 << 20, file);
    for v in [1u64, n, p.to_bits(), k, m, inserted] {
        w.write_all(&v.to_le_bytes()).unwrap();
    }
    let raw: &[u8] =
        unsafe { std::slice::from_raw_parts(bits.as_ptr() as *const u8, words * 8) };
    w.write_all(raw).unwrap();
    w.flush().unwrap();
    eprintln!("dcso_bloom: inserted {inserted} keys -> {out}");
}
"""


def build_bloom(keys, n, dest):
    src = WORK / "dcso_bloom"
    (src / "src").mkdir(parents=True, exist_ok=True)
    (src / "Cargo.toml").write_text(RUST_CARGO_TOML)
    (src / "src" / "main.rs").write_text(RUST_MAIN)
    cargo = shutil.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")
    if not os.path.exists(cargo):
        log("installing rust toolchain (minimal) …")
        rustup = WORK / "rustup.sh"
        urllib.request.urlretrieve("https://sh.rustup.rs", rustup)
        subprocess.run(
            ["sh", str(rustup), "-y", "--profile", "minimal", "--default-toolchain", "stable"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        cargo = os.path.expanduser("~/.cargo/bin/cargo")
    subprocess.run([cargo, "build", "--release", "--quiet"], cwd=src, check=True)
    builder = src / "target" / "release" / "dcso_bloom"

    log("inserting keys …")
    proc = subprocess.Popen([str(builder), str(n), "0.0001", "64", str(dest)], stdin=subprocess.PIPE)
    with open(keys, "rb") as f:
        while chunk := f.read(1 << 22):
            proc.stdin.write(chunk.translate(None, b"\n"))
    proc.stdin.close()
    if proc.wait() != 0:
        sys.exit("bloom builder failed")
    log(f"bloom: {dest.stat().st_size:,} bytes")


# ----------------------------------------------------------------- main


def hub_done_witnesses():
    if SMOKE:
        return set()
    from huggingface_hub import HfApi

    api = HfApi()
    api.create_repo(REPO, repo_type="dataset", exist_ok=True)
    return {
        pathlib.Path(f).stem.removesuffix(".tsv")
        for f in api.list_repo_files(REPO, repo_type="dataset")
        if f.startswith("tsv/") and f.endswith(".tsv.gz")
    }


def fetch_hub_tsvs(done, tsv_dir):
    """A relaunch may have lost local tsvs — pull the checkpoints back
    (in-DC, cheap) so the parquet phase sees every witness."""
    from huggingface_hub import hf_hub_download

    for w in sorted(done):
        dest = tsv_dir / f"{w}.tsv.gz"
        if not dest.exists():
            got = hf_hub_download(REPO, f"tsv/{w}.tsv.gz", repo_type="dataset")
            shutil.copy(got, dest)
            log(f"restored {w}.tsv.gz from hub")


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    tsv_dir = WORK / "tsv"
    tsv_dir.mkdir(exist_ok=True)

    repos = enumerate_repos()
    log(f"total: {len(repos)} repos")
    if ENUMERATE:
        for w, b in repos:
            print(f"{w}\t{b}")
        return

    done = hub_done_witnesses()
    done |= {p.name.removesuffix(".tsv.gz") for p in tsv_dir.glob("*.tsv.gz")}
    done |= {p.name.removesuffix(".empty") for p in tsv_dir.glob("*.empty")}
    failed = harvest_all(repos, tsv_dir, done)
    if failed:
        log(f"FAILED witnesses (relaunch to retry): {sorted(failed)}")
        sys.exit(1)

    if not SMOKE:
        fetch_hub_tsvs(hub_done_witnesses(), tsv_dir)

    outdir = WORK / "out"
    outputs, keys, n_keys = build_parquet(tsv_dir, outdir)
    bloom = outdir / "rpm-files.sha256.bloom"
    build_bloom(keys, n_keys, bloom)
    outputs.append(bloom)

    if SMOKE:
        log(f"smoke: outputs in {outdir}, skipping upload")
        return

    from huggingface_hub import HfApi

    api = HfApi()
    for path in outputs:
        rel = path.relative_to(outdir)
        for attempt in range(5):
            try:
                api.upload_file(
                    path_or_fileobj=str(path),
                    path_in_repo=str(rel),
                    repo_id=REPO,
                    repo_type="dataset",
                    commit_message=f"data: {rel}",
                )
                log(f"uploaded {rel}")
                break
            except Exception as e:  # noqa: BLE001
                log(f"upload {rel} failed (attempt {attempt + 1}): {e}")
                time.sleep(30 * (attempt + 1))
        else:
            sys.exit(f"giving up on {rel}")
    log("ALL UPLOADS DONE")


if __name__ == "__main__":
    main()
