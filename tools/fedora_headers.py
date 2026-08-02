#!/usr/bin/env python3
"""Harvest per-file sha256 digests from Fedora RPM headers.

Repo metadata (primary.xml) publishes each package's exact header byte
range, so one HTTP range GET per RPM fetches the header alone — the
FILEDIGESTS tag inside holds sha256 of every installed file's contents.
Ingest cost scales with metadata (~2.5 GiB of headers for ~100k
packages), never with package content: admission-rule clean.

Uses HTTP/2 multiplexing (many streams, few connections) when the
mirror supports it — this workload is RTT-bound, not bandwidth-bound.

Usage:
  tools/fedora_headers.py <repo-base-url>... > digests.hex
  sort -u digests.hex > fedora.sha256.hex
  hdx filters build fedora sha256 fedora.sha256.hex

Example repo base URLs (AARNET mirror, h2):
  https://mirror.aarnet.edu.au/pub/fedora/linux/releases/44/Everything/x86_64/os
  https://mirror.aarnet.edu.au/pub/fedora/linux/updates/44/Everything/x86_64
"""
import asyncio
import io
import re
import struct
import sys
import time

try:
    import httpx
    import zstandard
except ImportError:
    sys.exit("needs httpx[http2] and zstandard (pip install 'httpx[http2]' zstandard)")

STREAMS = 64          # concurrent h2 streams
CONNECTIONS = 4       # TCP connections they multiplex over
UA = "hashdex-fedora-headers/0.2 (hash index research; one range GET per rpm)"

RPMTAG_FILEDIGESTS = 1035
HEADER_MAGIC = b"\x8e\xad\xe8\x01"


def parse_primary(xml):
    """Yield (location, start, end) per package."""
    return [
        (m.group(1).decode(), int(m.group(2)), int(m.group(3)))
        for m in re.finditer(
            rb'<location href="([^"]+)"/>.*?<rpm:header-range start="(\d+)" end="(\d+)"',
            xml,
            re.DOTALL,
        )
    ]


def parse_header_blob(blob):
    """Extract the FILEDIGESTS string array. The header-range usually
    covers the main header alone, but tolerate a signature header in
    front (walk up to two headers, 8-aligned)."""
    off = 0
    for _ in range(2):
        if blob[off : off + 4] != HEADER_MAGIC:
            raise ValueError(f"bad header magic at {off}")
        nindex, hsize = struct.unpack(">II", blob[off + 8 : off + 16])
        store = off + 16 + nindex * 16
        digests = None
        for i in range(nindex):
            tag, typ, doff, count = struct.unpack(
                ">IIII", blob[off + 16 + i * 16 : off + 32 + i * 16]
            )
            if tag == RPMTAG_FILEDIGESTS and typ == 8:  # STRING_ARRAY
                digests = []
                p = store + doff
                for _ in range(count):
                    end = blob.index(b"\x00", p)
                    s = blob[p:end]
                    p = end + 1
                    if len(s) == 64:  # empty for dirs/symlinks/ghosts
                        digests.append(s.decode())
                break
        if digests is not None:
            return digests
        off = store + hsize
        off += (8 - off % 8) % 8
        if off >= len(blob):
            break
    return []  # no regular files in package (metapackages etc.)


async def fetch_primary(client, base):
    r = await client.get(f"{base}/repodata/repomd.xml")
    r.raise_for_status()
    m = re.search(r'<data type="primary">.*?href="([^"]+)"', r.text, re.DOTALL)
    if not m:
        sys.exit(f"{base}: no primary in repomd.xml")
    loc = m.group(1)
    r = await client.get(f"{base}/{loc}")
    r.raise_for_status()
    if loc.endswith(".zst"):
        return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(r.content)).read()
    import zlib

    return zlib.decompress(r.content, 47)


async def harvest(client, base, out):
    xml = await fetch_primary(client, base)
    pkgs = parse_primary(xml)
    total_b = sum(e - s for _, s, e in pkgs)
    print(
        f"{base}: {len(pkgs)} packages, {total_b / 2**30:.2f} GiB of headers",
        file=sys.stderr,
    )
    sem = asyncio.Semaphore(STREAMS)
    done = 0
    failed = []
    t0 = time.time()

    async def one(loc, s, e):
        nonlocal done
        async with sem:
            for attempt in range(4):
                try:
                    r = await client.get(
                        f"{base}/{loc}", headers={"Range": f"bytes={s}-{e - 1}"}
                    )
                    if r.status_code not in (200, 206):
                        raise IOError(f"HTTP {r.status_code}")
                    out.update(parse_header_blob(r.content))
                    done += 1
                    return
                except Exception as exc:
                    if attempt == 3:
                        failed.append((loc, str(exc)))
                    else:
                        await asyncio.sleep(1 + attempt)

    tasks = [asyncio.ensure_future(one(*p)) for p in pkgs]
    while not all(t.done() for t in tasks):
        await asyncio.sleep(10)
        print(
            f"  {done}/{len(pkgs)} pkgs, {len(out)} digests,"
            f" {done / max(time.time() - t0, 1):.0f} pkg/s",
            file=sys.stderr,
        )
    await asyncio.gather(*tasks)
    if failed:
        print(f"  {len(failed)} FAILED, e.g. {failed[:3]}", file=sys.stderr)


async def main():
    bases = sys.argv[1:]
    if not bases:
        sys.exit(__doc__)
    out = set()
    limits = httpx.Limits(
        max_connections=CONNECTIONS, max_keepalive_connections=CONNECTIONS
    )
    async with httpx.AsyncClient(
        http2=True, limits=limits, timeout=90, headers={"User-Agent": UA}
    ) as client:
        for base in bases:
            await harvest(client, base, out)
    for d in sorted(out):
        print(d)
    print(f"total distinct file digests: {len(out)}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
