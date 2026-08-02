#!/usr/bin/env python3
"""Extract per-file sha1 digests from Steam depot manifests.

Steam caches a ContentManifestPayload per installed depot in
steamapps/depotcache/<depot>_<manifestgid>.manifest — the same
manifests SteamDB renders. Each FileMapping carries sha_content, the
SHA-1 of the file's full raw bytes (verified locally against installed
game files before first use). Purely local: no network, no auth, and
ingest cost scales with metadata (the manifests), never content.

File format (SteamKit): uint32 magic 0x71F617D0, uint32 payload_len,
then protobuf ContentManifestPayload { repeated FileMapping mappings=1
{ filename=1, size=2, flags=3, sha_filename=4, sha_content=5, ... } },
followed by metadata/signature sections we ignore. Directories carry an
all-zero sha_content and are skipped.

Usage:
  tools/steam_manifests.py <depotcache-dir>... > steam.sha1.hex
  tools/steam_manifests.py --names <depotcache-dir>   # filename<TAB>sha1
  sort -u steam.sha1.hex -o steam.sha1.hex
  hdx filters build steam sha1 steam.sha1.hex
"""
import sys
from pathlib import Path

PAYLOAD_MAGIC = 0x71F617D0


def varint(buf, i):
    n = shift = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, i
        shift += 7


def fields(buf):
    """Yield (field_no, wire_type, value) over one protobuf message."""
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        fno, wt = key >> 3, key & 7
        if wt == 0:
            val, i = varint(buf, i)
        elif wt == 2:
            ln, i = varint(buf, i)
            val = buf[i:i + ln]
            i += ln
        elif wt == 5:
            val = buf[i:i + 4]
            i += 4
        elif wt == 1:
            val = buf[i:i + 8]
            i += 8
        else:
            raise ValueError(f"unsupported wire type {wt}")
        yield fno, wt, val


def mappings(path):
    raw = path.read_bytes()
    magic = int.from_bytes(raw[0:4], "little")
    if magic != PAYLOAD_MAGIC:
        print(f"warning: {path.name}: unknown magic {magic:#x}, skipped",
              file=sys.stderr)
        return
    plen = int.from_bytes(raw[4:8], "little")
    for fno, wt, val in fields(raw[8:8 + plen]):
        if fno == 1 and wt == 2:  # FileMapping
            name, sha = None, None
            for f2, w2, v2 in fields(val):
                if f2 == 1 and w2 == 2:
                    name = v2.decode("utf-8", "replace")
                elif f2 == 5 and w2 == 2:
                    sha = v2
            if sha and len(sha) == 20 and any(sha):
                yield name, sha.hex()


def main():
    args = sys.argv[1:]
    names = "--names" in args
    dirs = [a for a in args if not a.startswith("--")]
    if not dirs:
        sys.exit(__doc__)
    n_files = n_shas = 0
    for d in dirs:
        for mf in sorted(Path(d).glob("*.manifest")):
            n_files += 1
            for name, hexsha in mappings(mf):
                n_shas += 1
                print(f"{name}\t{hexsha}" if names else hexsha)
    print(f"{n_files} manifests, {n_shas} file digests", file=sys.stderr)


if __name__ == "__main__":
    main()
