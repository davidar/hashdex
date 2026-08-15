#!/usr/bin/env python3
"""Harvest per-file digests + package identities from RPM repo metadata.

Repo metadata (primary.xml) publishes each package's exact header byte
range, so one HTTP range GET per RPM fetches the header alone — the
FILEDIGESTS tag inside holds a digest of every installed file's
contents, aligned with BASENAMES/DIRNAMES/DIRINDEXES for the paths.
Ingest cost scales with metadata, never content: admission-rule clean.
This is fedora_headers.py grown up: full witness rows with claim URLs
instead of a bare digest list (the fedora bloom's big brother).

Fetches go to a fast mirror; claim URLs use the project's canonical
host. Repos are listed in REPOS — new repos are new list entries, the
schema and src/rpm_files.rs never change.

NOTE: per-witness outputs in dumps/ are resume markers — a real
re-harvest must delete the dumps dir first (release_tarballs gotcha).

Usage:
  tools/rpm_files.py [outdir]     # default ~/.cache/hashdex/rpm
  tools/rpm_parquet.py            # then convert for publishing

Output TSV columns (one row per file×package plus one per package,
"-" = absent):
  witness scheme digest name evr arch path pkgid location
package rows: digest = the rpm file's own checksum (pkgid attribute),
path and pkgid are "-"; file rows: digest = the FILEDIGESTS entry,
pkgid = the containing rpm's checksum. location is the full URL of
the rpm — a claim URL by construction.
"""
import asyncio
import gzip
import io
import pathlib
import re
import struct
import sys
import time

try:
    import httpx
    import zstandard
except ImportError:
    sys.exit("needs httpx[http2] and zstandard (pip install 'httpx[http2]' zstandard)")

STREAMS = 64  # concurrent h2 streams
CONNECTIONS = 4  # TCP connections they multiplex over
UA = "hashdex-rpm-files/0.1 (hash index research; one range GET per rpm)"

# (witness, fetch base, claim base). Fetch from a close mirror; claim
# URLs on the canonical host. Fedora releases move from dl to
# archives.fedoraproject.org when they EOL — an archived release's
# entry uses the archive base for BOTH (mirrors drop it too).
AARNET = "https://mirror.aarnet.edu.au/pub/fedora/linux"
DL = "https://dl.fedoraproject.org/pub/fedora/linux"
REPOS = [
    (
        "fedora-44",
        f"{AARNET}/releases/44/Everything/x86_64/os",
        f"{DL}/releases/44/Everything/x86_64/os",
    ),
    (
        "fedora-44-updates",
        f"{AARNET}/updates/44/Everything/x86_64",
        f"{DL}/updates/44/Everything/x86_64",
    ),
]

HEADER_MAGIC = b"\x8e\xad\xe8\x01"
RPMTAG_FILEDIGESTS = 1035
RPMTAG_DIRINDEXES = 1116
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
RPMTAG_FILEDIGESTALGO = 5011
WANTED_TAGS = {
    RPMTAG_FILEDIGESTS,
    RPMTAG_DIRINDEXES,
    RPMTAG_BASENAMES,
    RPMTAG_DIRNAMES,
    RPMTAG_FILEDIGESTALGO,
}

# RFC 4880 hash-algorithm ids (RPMTAG_FILEDIGESTALGO values); absent
# tag = md5, the pre-2009 default.
ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}
HEX_LEN = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}


def xml_unescape(s):
    for ent, ch in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&amp;", "&")):
        s = s.replace(ent, ch)
    return s


def parse_primary(xml):
    """Per-package dicts from primary.xml. Attribute lookups are
    per-attribute (never positional) — createrepo variants order them
    differently."""
    pkgs = []
    for m in re.finditer(rb"<package type=\"rpm\">(.*?)</package>", xml, re.DOTALL):
        blk = m.group(1)

        def grab(pattern, what):
            g = re.search(pattern, blk)
            if not g:
                raise ValueError(f"package block missing {what}")
            return g

        name = grab(rb"<name>([^<]*)</name>", "name").group(1).decode()
        arch = grab(rb"<arch>([^<]*)</arch>", "arch").group(1).decode()
        vtag = grab(rb"<version\s[^>]*/?>", "version").group(0)
        epoch = re.search(rb'epoch="([^"]*)"', vtag)
        ver = re.search(rb'ver="([^"]*)"', vtag)
        rel = re.search(rb'rel="([^"]*)"', vtag)
        if not (ver and rel):
            raise ValueError(f"{name}: version tag lacks ver/rel")
        csum = grab(
            rb'<checksum type="([^"]+)"[^>]*>([0-9a-f]+)</checksum>', "checksum"
        )
        loc = grab(rb'<location href="([^"]+)"', "location").group(1).decode()
        rng = grab(rb'<rpm:header-range start="(\d+)" end="(\d+)"', "header-range")
        e = epoch.group(1).decode() if epoch else "0"
        evr = ver.group(1).decode() + "-" + rel.group(1).decode()
        if e not in ("", "0"):
            evr = f"{e}:{evr}"
        pkgs.append(
            dict(
                name=xml_unescape(name),
                arch=arch,
                evr=evr,
                csum_type=csum.group(1).decode(),
                pkgid=csum.group(2).decode(),
                location=xml_unescape(loc),
                start=int(rng.group(1)),
                end=int(rng.group(2)),
            )
        )
    return pkgs


def read_string_array(blob, store, entry):
    typ, doff, count = entry
    if typ not in (8, 9):  # STRING_ARRAY / I18NSTRING
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
    """(scheme, [(path, digest)]) from the package header. The
    header-range usually covers the main header alone, but tolerate a
    signature header in front (walk up to two headers, 8-aligned);
    the main header is the one carrying BASENAMES. Empty digest
    entries (dirs, symlinks, ghosts) are skipped WITHOUT breaking the
    per-file alignment between the four arrays."""
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
        if RPMTAG_BASENAMES in tags:
            basenames = read_string_array(blob, store, tags[RPMTAG_BASENAMES])
            digests = read_string_array(blob, store, tags[RPMTAG_FILEDIGESTS])
            dirnames = read_string_array(blob, store, tags[RPMTAG_DIRNAMES])
            dirindexes = read_int32_array(blob, store, tags[RPMTAG_DIRINDEXES])
            if not (len(basenames) == len(digests) == len(dirindexes)):
                raise ValueError("file array lengths disagree")
            algo = 1
            if RPMTAG_FILEDIGESTALGO in tags:
                algo = read_int32_array(blob, store, tags[RPMTAG_FILEDIGESTALGO])[0]
            scheme = ALGOS.get(algo)
            if scheme is None:
                raise ValueError(f"unknown FILEDIGESTALGO {algo}")
            files = []
            for base, digest, di in zip(basenames, digests, dirindexes):
                if not digest:
                    continue
                if len(digest) != HEX_LEN[scheme]:
                    raise ValueError(f"{scheme} digest of length {len(digest)}")
                files.append((dirnames[di] + base, digest))
            return scheme, files
        off = store + hsize
        off += (8 - off % 8) % 8
        if off + 16 > len(blob):
            break
    return None, []  # no file manifest: package ships no files


async def fetch_primary(client, witness, fetch_base, dumps):
    cached = dumps / f"{witness}-primary"
    if cached.exists():
        raw = cached.read_bytes()
    else:
        r = await client.get(f"{fetch_base}/repodata/repomd.xml")
        r.raise_for_status()
        m = re.search(r'<data type="primary">.*?href="([^"]+)"', r.text, re.DOTALL)
        if not m:
            raise ValueError(f"{fetch_base}: no primary in repomd.xml")
        r = await client.get(f"{fetch_base}/{m.group(1)}")
        r.raise_for_status()
        raw = r.content
        cached.write_bytes(raw)
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw)).read()
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    import zlib

    return zlib.decompress(raw, 47)


def clean(s, what):
    if "\t" in s or "\n" in s:
        raise ValueError(f"{what} contains separator: {s!r}")
    return s if s else "-"


async def harvest(client, witness, fetch_base, claim_base, dumps):
    """Harvest one repo into dumps/<witness>.tsv.gz (atomic rename =
    the resume marker; any header failure leaves no output so a rerun
    retries the whole witness)."""
    out_path = dumps / f"{witness}.tsv.gz"
    if out_path.exists():
        print(f"{witness}: reusing {out_path.name}", file=sys.stderr)
        return
    xml = await fetch_primary(client, witness, fetch_base, dumps)
    pkgs = parse_primary(xml)
    total_b = sum(p["end"] - p["start"] for p in pkgs)
    print(
        f"{witness}: {len(pkgs)} packages, {total_b / 2**30:.2f} GiB of headers",
        file=sys.stderr,
    )
    sem = asyncio.Semaphore(STREAMS)
    done = 0
    rows = 0
    skipped = 0
    failed = []
    t0 = time.time()
    part = out_path.with_suffix(out_path.suffix + ".part")
    fh = gzip.open(part, "wt", encoding="utf-8")

    def write_row(scheme, digest, pkg, path, pkgid):
        nonlocal rows, skipped
        row = (
            witness,
            scheme,
            digest,
            pkg["name"],
            pkg["evr"],
            pkg["arch"],
            path,
            pkgid,
            f"{claim_base}/{pkg['location']}",
        )
        try:
            fh.write("\t".join(clean(v, "field") for v in row) + "\n")
            rows += 1
        except ValueError as e:
            skipped += 1
            if skipped <= 10:
                print(f"  warning: skipping row: {e}", file=sys.stderr)

    async def one(pkg):
        nonlocal done
        async with sem:
            for attempt in range(4):
                try:
                    r = await client.get(
                        f"{fetch_base}/{pkg['location']}",
                        headers={"Range": f"bytes={pkg['start']}-{pkg['end'] - 1}"},
                    )
                    if r.status_code not in (200, 206):
                        raise IOError(f"HTTP {r.status_code}")
                    scheme, files = parse_header_files(r.content)
                    write_row(pkg["csum_type"], pkg["pkgid"], pkg, "-", "-")
                    for path, digest in files:
                        write_row(scheme, digest, pkg, path, pkg["pkgid"])
                    done += 1
                    return
                except Exception as exc:  # noqa: BLE001 — retry
                    if attempt == 3:
                        failed.append((pkg["location"], str(exc)))
                    else:
                        await asyncio.sleep(1 + attempt)

    tasks = [asyncio.ensure_future(one(p)) for p in pkgs]
    while not all(t.done() for t in tasks):
        await asyncio.sleep(10)
        print(
            f"  {done}/{len(pkgs)} pkgs, {rows:,} rows,"
            f" {done / max(time.time() - t0, 1):.0f} pkg/s",
            file=sys.stderr,
        )
    await asyncio.gather(*tasks)
    fh.close()
    if failed:
        part.unlink()
        print(f"  {len(failed)} FAILED, e.g. {failed[:3]}", file=sys.stderr)
        raise IOError(f"{witness}: {len(failed)} packages failed — rerun to retry")
    part.rename(out_path)
    print(f"  {out_path.name}: {rows:,} rows, {skipped} skipped", file=sys.stderr)


async def run(outdir):
    dumps = outdir / "dumps"
    dumps.mkdir(parents=True, exist_ok=True)
    limits = httpx.Limits(
        max_connections=CONNECTIONS, max_keepalive_connections=CONNECTIONS
    )
    async with httpx.AsyncClient(
        http2=True,
        follow_redirects=True,
        limits=limits,
        timeout=90,
        headers={"User-Agent": UA},
    ) as client:
        for witness, fetch_base, claim_base in REPOS:
            await harvest(client, witness, fetch_base, claim_base, dumps)


def main():
    outdir = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/rpm"
    )
    asyncio.run(run(outdir))

    out = outdir / "rpm-files.tsv.gz"
    counts = {}
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for witness, _, _ in REPOS:
            with gzip.open(outdir / "dumps" / f"{witness}.tsv.gz", "rt") as src:
                for line in src:
                    fh.write(line)
                    counts[witness] = counts.get(witness, 0) + 1
    per = ", ".join(f"{w} {n:,}" for w, n in sorted(counts.items()))
    print(f"wrote {out}: {sum(counts.values()):,} rows ({per})", file=sys.stderr)
    print(out)


if __name__ == "__main__":
    main()
