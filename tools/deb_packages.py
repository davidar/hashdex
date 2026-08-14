#!/usr/bin/env python3
"""Harvest binary .deb hashes from apt Packages indexes.

Where release_tarballs.py covers SOURCE artifacts, this covers the
BINARY packages — the .debs that install media and mirrors actually
ship. Every Packages stanza carries the pool path (a claim URL by
construction: mirror base + Filename) plus strong digests:

  debian  MD5sum + SHA256          (SHA1 dropped ~2016)
  ubuntu  MD5sum + SHA1 + SHA256 + SHA512  (4-hash single-witness
          rows — the richest crosswalk edges in the distro family)
  kali    MD5sum + SHA1 + SHA256

Ingest is a few hundred HTTP GETs of index metadata, never content:
admission-rule clean. Dumps are kept beside the output.

NOTE: fetch() reuses dumps already on disk — a real re-harvest must
delete the old dumps first (same gotcha as release_tarballs.py).

Usage:
  tools/deb_packages.py [outdir]     # default ~/.cache/hashdex/debs
  tools/debs_parquet.py              # then convert for publishing

Output TSV columns (one row per deb×witness, "-" = absent):
  witness sha256 sha1 md5 sha512 name version arch filename
where filename is the pool path relative to the archive root; the
witness prefix picks the archive base URL.
"""
import asyncio
import gzip
import lzma
import pathlib
import re
import socket
import sys
import time
import urllib.request

UA = "hashdex-deb-packages/0.1 (hash index research; index GETs only)"

# Fetch concurrency (fedora_headers.py pattern): the deb archive hosts
# are ~300ms away and urllib cold-starts TCP+TLS per request, so the
# harvest is latency-bound. httpx negotiates h2 where offered
# (deb.debian.org, security.debian.org) and falls back to keepalive
# h1.1 elsewhere (archive/old-releases.ubuntu.com and kali are
# h1-only, verified 2026-08-14) — either way the per-request
# handshake dies.
STREAMS = 12  # in-flight requests
CONNECTIONS = 8  # TCP connections in the pool, across all hosts

# Prefer IPv4: urllib has no happy-eyeballs, so on networks with a
# silently-broken IPv6 path every request burns the full timeout in
# SYN-SENT before falling back (same fix as install_media.py; bit
# old-releases.ubuntu.com in practice — only some of its AAAA records
# blackhole).
_getaddrinfo = socket.getaddrinfo


def _ipv4_first(host, port, family=0, *args, **kwargs):
    infos = _getaddrinfo(host, port, family, *args, **kwargs)
    return sorted(infos, key=lambda i: i[0] != socket.AF_INET)


socket.getaddrinfo = _ipv4_first

# (witness, archive base, dists base, components). Architecture is
# amd64 — arch:all packages ride in the amd64 Packages file.
DEB_COMPONENTS = ["main", "contrib", "non-free", "non-free-firmware"]
UBU_COMPONENTS = ["main", "restricted", "universe", "multiverse"]
SUITES = [
    ("debian-trixie", "https://deb.debian.org/debian", "trixie", DEB_COMPONENTS),
    ("debian-trixie-updates", "https://deb.debian.org/debian", "trixie-updates", DEB_COMPONENTS),
    (
        "debian-trixie-security",
        "https://security.debian.org/debian-security",
        "trixie-security",
        DEB_COMPONENTS,
    ),
    ("debian-sid", "https://deb.debian.org/debian", "sid", DEB_COMPONENTS),
    ("kali-rolling", "https://http.kali.org/kali", "kali-rolling", DEB_COMPONENTS),
]

# Ubuntu is enumerated, not listed: supported releases live on
# archive.ubuntu.com, EOL releases move wholesale (pool included) to
# old-releases.ubuntu.com, and between the two every release ever is
# still fully hosted. src/debs.rs mirrors the EOL codename set to pick
# the claim-URL base — a re-harvest after a release EOLs must update
# UBUNTU_EOL there too.
UBUNTU_HOSTS = [
    "https://archive.ubuntu.com/ubuntu",
    "https://old-releases.ubuntu.com/ubuntu",
]
HREF = re.compile(r'href="([^"/]+)/"')


def ubuntu_suites():
    """(witness, base, suite, comps) for every Ubuntu release on both
    hosts: release + -updates + -security pockets, skipping backports/
    proposed and the devel* symlinks. Pre-gutsy (2007) indexes carry
    no SHA256, so their rows self-filter in stanza_rows."""
    entries = []
    for base in UBUNTU_HOSTS:
        req = urllib.request.Request(f"{base}/dists/", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as resp:
            names = set(HREF.findall(resp.read().decode("utf-8", errors="replace")))
        codenames = sorted(n for n in names if "-" not in n and n != "devel")
        for code in codenames:
            for pocket in ("", "-updates", "-security"):
                if code + pocket in names:
                    entries.append((f"ubuntu-{code}{pocket}", base, code + pocket, UBU_COMPONENTS))
    return entries

HEX = {
    "SHA256": re.compile(r"[0-9a-f]{64}"),
    "SHA1": re.compile(r"[0-9a-f]{40}"),
    "MD5sum": re.compile(r"[0-9a-f]{32}"),
    "SHA512": re.compile(r"[0-9a-f]{128}"),
}


def dump_dest(dumps, witness, comp, installer):
    tag = f"{comp}-installer" if installer else comp
    return dumps / f"{witness}-{tag}-Packages"


def fetch(dest):
    """Read a prefetched dump: .xz/.gz cache hit, .404 marker =
    confirmed absent upstream (both markers persist across runs — a
    real re-harvest deletes the dumps dir first)."""
    for ext in (".xz", ".gz"):
        cached = dest.with_suffix(dest.suffix + ext)
        if cached.exists():
            return cached.read_bytes()
    if dest.with_suffix(dest.suffix + ".404").exists():
        raise FileNotFoundError("HTTP 404 (cached)")
    raise FileNotFoundError("not prefetched (transient fetch failure — rerun)")


async def prefetch(suites, dumps):
    """Concurrently download every missing suite/component Packages
    index (xz preferred, gz fallback — kali publishes gz only) plus
    the debian-installer udeb sub-indexes, into the dumps cache. 404
    on both extensions writes a .404 marker; transient failures leave
    nothing so a rerun retries them."""
    try:
        import httpx
    except ImportError:
        sys.exit("needs httpx[http2] (pip install 'httpx[http2]')")
    work = []
    for witness, base, suite, comps in suites:
        for installer in (False, True):
            for comp in comps:
                work.append((witness, base, suite, comp, installer))
    sem = asyncio.Semaphore(STREAMS)
    done = 0
    fetched = 0
    absent = 0
    failed = []
    t0 = time.time()

    async def one(client, witness, base, suite, comp, installer):
        nonlocal done, fetched, absent
        dest = dump_dest(dumps, witness, comp, installer)
        exists = [dest.with_suffix(dest.suffix + e) for e in (".xz", ".gz", ".404")]
        if any(p.exists() for p in exists):
            done += 1
            return
        sub = "debian-installer/binary-amd64" if installer else "binary-amd64"
        async with sem:
            saw_404 = 0
            for ext in (".xz", ".gz"):
                url = f"{base}/dists/{suite}/{comp}/{sub}/Packages{ext}"
                for attempt in range(4):
                    try:
                        r = await client.get(url)
                    except Exception as exc:  # noqa: BLE001 — retry
                        if attempt == 3:
                            failed.append((url, str(exc)))
                        else:
                            await asyncio.sleep(1 + attempt)
                        continue
                    if r.status_code == 200:
                        dest.with_suffix(dest.suffix + ext).write_bytes(r.content)
                        fetched += 1
                        done += 1
                        return
                    if r.status_code == 404:
                        saw_404 += 1
                        break
                    if attempt == 3:
                        failed.append((url, f"HTTP {r.status_code}"))
                    else:
                        await asyncio.sleep(1 + attempt)
            if saw_404 == 2:
                dest.with_suffix(dest.suffix + ".404").touch()
                absent += 1
            done += 1

    limits = httpx.Limits(max_connections=CONNECTIONS, max_keepalive_connections=CONNECTIONS)
    async with httpx.AsyncClient(
        http2=True, follow_redirects=True, limits=limits, timeout=90, headers={"User-Agent": UA}
    ) as client:
        tasks = [asyncio.ensure_future(one(client, *w)) for w in work]
        while not all(t.done() for t in tasks):
            await asyncio.sleep(5)
            print(
                f"  prefetch {done}/{len(work)} ({fetched} fetched, "
                f"{done / max(time.time() - t0, 1):.0f}/s)",
                file=sys.stderr,
            )
        await asyncio.gather(*tasks)
    print(
        f"  prefetch done: {fetched} fetched, {absent} absent (404), "
        f"{done - fetched - absent} cached, {len(failed)} failed",
        file=sys.stderr,
    )
    for url, err in failed[:10]:
        print(f"  warning: {url}: {err}", file=sys.stderr)


def decompress(data):
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(data)
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    return data


def stanza_rows(witness, blob):
    text = decompress(blob).decode("utf-8", errors="replace")
    for stanza in text.split("\n\n"):
        if not stanza.strip():
            continue
        fields = {}
        for line in stanza.split("\n"):
            if line[:1] not in (" ", "\t"):
                key, _, val = line.partition(":")
                fields[key] = val.strip()
        pkg = fields.get("Package", "")
        version = fields.get("Version", "")
        arch = fields.get("Architecture", "")
        filename = fields.get("Filename", "")
        sha256 = fields.get("SHA256", "")
        if not (pkg and version and filename and HEX["SHA256"].fullmatch(sha256)):
            continue
        digests = {}
        for key in ("SHA1", "MD5sum", "SHA512"):
            v = fields.get(key, "")
            digests[key] = v if HEX[key].fullmatch(v) else "-"
        yield (
            witness,
            sha256,
            digests["SHA1"],
            digests["MD5sum"],
            digests["SHA512"],
            pkg,
            version,
            arch,
            filename,
        )


def clean(s, what):
    if "\t" in s or "\n" in s:
        raise ValueError(f"{what} contains separator: {s!r}")
    return s if s else "-"


# Suites whose debian-installer IMAGES (initrds, kernels, efi.img —
# the bytes install media carry outside any .deb) get harvested from
# the published SHA256SUMS under installer-<arch>/<version>/images/.
INSTALLER_SUITES = [
    ("debian-trixie", "https://deb.debian.org/debian", "trixie"),
    ("debian-sid", "https://deb.debian.org/debian", "sid"),
]


def installer_image_rows(witness, base, suite, dumps):
    """Rows for the d-i images tree: resolve the current version from
    the directory listing (claim URLs must be versioned — `current` is
    a symlink that moves), then read its SHA256SUMS."""
    listing_url = f"{base}/dists/{suite}/main/installer-amd64/"
    req = urllib.request.Request(listing_url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        listing = resp.read().decode("utf-8", errors="replace")
    versions = sorted(set(re.findall(r'href="(\d[^"/]*)/"', listing)))
    if not versions:
        raise ValueError(f"no versioned installer dirs under {listing_url}")
    ver = versions[-1]
    sums_path = dumps / f"{witness}-installer-images-{ver}-SHA256SUMS"
    if sums_path.exists():
        print(f"  reusing {sums_path.name}", file=sys.stderr)
        sums = sums_path.read_text()
    else:
        url = f"{base}/dists/{suite}/main/installer-amd64/{ver}/images/SHA256SUMS"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as resp:
            sums = resp.read().decode("utf-8")
        sums_path.write_text(sums)
        print(f"  fetched {sums_path.name} ({len(sums):,} bytes)", file=sys.stderr)
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) != 2 or not HEX["SHA256"].fullmatch(parts[0]):
            continue
        rel = parts[1].lstrip("./")
        yield (
            witness,
            parts[0],
            "-",
            "-",
            "-",
            "debian-installer",
            ver,
            "amd64",
            f"dists/{suite}/main/installer-amd64/{ver}/images/{rel}",
        )


def main():
    outdir = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/debs"
    )
    dumps = outdir / "dumps"
    dumps.mkdir(parents=True, exist_ok=True)

    out = outdir / "debs.tsv.gz"
    seen = set()
    counts = {}
    skipped = 0
    suites = SUITES + ubuntu_suites()
    asyncio.run(prefetch(suites, dumps))
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for witness, base, suite, comps in suites:
            print(f"{witness}:", file=sys.stderr)
            fetches = [(comp, False) for comp in comps]
            # udeb sub-indexes exist only for some suites; a 404 there
            # is routine, not a warning worth shouting about.
            fetches += [(comp, True) for comp in comps]
            for comp, installer in fetches:
                try:
                    data = fetch(dump_dest(dumps, witness, comp, installer))
                except FileNotFoundError as e:
                    if not installer:
                        print(f"  warning: {comp}: {e}", file=sys.stderr)
                    continue
                for row in stanza_rows(witness, data):
                    try:
                        line = "\t".join(clean(v, "field") for v in row)
                    except ValueError as e:
                        skipped += 1
                        if skipped <= 10:
                            print(f"  warning: skipping row: {e}", file=sys.stderr)
                        continue
                    if line in seen:
                        continue
                    seen.add(line)
                    fh.write(line + "\n")
                    counts[witness] = counts.get(witness, 0) + 1
        for witness, base, suite in INSTALLER_SUITES:
            print(f"{witness} installer images:", file=sys.stderr)
            try:
                for row in installer_image_rows(witness, base, suite, dumps):
                    line = "\t".join(clean(v, "field") for v in row)
                    if line in seen:
                        continue
                    seen.add(line)
                    fh.write(line + "\n")
                    counts[witness] = counts.get(witness, 0) + 1
            except Exception as e:  # noqa: BLE001
                print(f"  warning: {e}", file=sys.stderr)
    per = ", ".join(f"{w} {n:,}" for w, n in sorted(counts.items()))
    print(f"wrote {out}: {sum(counts.values()):,} rows ({per}), {skipped} skipped", file=sys.stderr)
    print(out)


if __name__ == "__main__":
    main()
