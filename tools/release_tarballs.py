#!/usr/bin/env python3
"""Harvest release-artifact hashes from distro package indexes.

Three sources publish full per-artifact hash indexes — the tarballs
themselves as shipped, the lifecycle every other hashdex source misses
(SWH unpacks archives; Fedora FILEDIGESTS covers installed files):

  debian    deb.debian.org sid Sources.xz — md5 AND sha256 per source
            file (orig/debian tarballs, .dsc, .asc): multi-hash
            single-witness rows, an edge-minting-compliant crosswalk
  homebrew  formulae.brew.sh/api/formula.json — sha256 of each
            formula's stable upstream archive
  guix      guix.gnu.org/sources.json — SRI sha256 of raw tarball
            bytes for outputHashMode=flat entries, each carrying a
            content-addressed mirror URL (a claim URL by construction)

Preimage trap: Guix "recursive" entries (git/svn/hg) are NAR-style
directory hashes, NOT raw bytes — only flat url entries are ingested.

Ingest is 6 HTTP GETs of index metadata (~50 MB), never content:
admission-rule clean. Dumps are kept beside the output.

Usage:
  tools/release_tarballs.py [outdir]     # default ~/.cache/hashdex/tarballs
  hdx index build tarballs <outdir>/tarballs.tsv.gz

Output TSV columns (one row per file×witness, "-" = absent):
  witness sha256 md5 name version filename loc
where loc is the Debian pool directory, the Homebrew upstream URL, or
the Guix content-addressed mirror URL.
"""
import base64
import gzip
import json
import lzma
import pathlib
import re
import sys
import urllib.request

UA = "hashdex-release-tarballs/0.1 (hash index research; 6 index GETs)"

DEBIAN_BASE = "https://deb.debian.org/debian/dists/sid"
DEBIAN_COMPONENTS = ["main", "contrib", "non-free", "non-free-firmware"]
BREW_URL = "https://formulae.brew.sh/api/formula.json"
GUIX_URL = "https://guix.gnu.org/sources.json"

HEX256 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{32}")


def fetch(url, dest):
    """GET url to dest (skipping if already present), return bytes."""
    if dest.exists():
        print(f"  reusing {dest.name} ({dest.stat().st_size:,} bytes)", file=sys.stderr)
        return dest.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
        # urllib does not decompress; guix.gnu.org serves sources.json
        # with Content-Encoding: gzip.
        if resp.headers.get("Content-Encoding") == "gzip" or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
    dest.write_bytes(data)
    print(f"  fetched {dest.name} ({len(data):,} bytes)", file=sys.stderr)
    return data


def field(s, width, what):
    if "\t" in s or "\n" in s:
        raise ValueError(f"{what} contains separator: {s!r}")
    if len(s.encode()) > width:
        raise ValueError(f"{what} over {width} bytes: {s!r}")
    return s if s else "-"


def debian_rows(sources_xz):
    """Parse RFC822 stanzas; one row per Checksums-Sha256 file, md5
    joined from the Files paragraph by filename."""
    text = lzma.decompress(sources_xz).decode("utf-8", errors="replace")
    for stanza in text.split("\n\n"):
        if not stanza.strip():
            continue
        fields = {}
        key = None
        for line in stanza.split("\n"):
            if line[:1] in (" ", "\t"):
                if key:
                    fields[key] += "\n" + line.strip()
            else:
                key, _, val = line.partition(":")
                fields[key] = val.strip()
        pkg = fields.get("Package", "")
        version = fields.get("Version", "")
        directory = fields.get("Directory", "")
        if not (pkg and version and directory):
            continue
        md5s = {}
        for line in fields.get("Files", "").split("\n"):
            parts = line.split()
            if len(parts) == 3 and HEX128.fullmatch(parts[0]):
                md5s[parts[2]] = parts[0]
        for line in fields.get("Checksums-Sha256", "").split("\n"):
            parts = line.split()
            if len(parts) != 3 or not HEX256.fullmatch(parts[0]):
                continue
            sha256, _, filename = parts
            yield ("debian", sha256, md5s.get(filename, "-"), pkg, version, filename, directory)


def brew_rows(formula_json):
    for f in json.loads(formula_json):
        stable = (f.get("urls") or {}).get("stable") or {}
        sha256 = stable.get("checksum")
        url = stable.get("url")
        if not (sha256 and url and HEX256.fullmatch(sha256)):
            continue
        version = (f.get("versions") or {}).get("stable") or ""
        yield ("homebrew", sha256, "-", f["name"], version, "-", url)


def guix_rows(sources_json):
    data = json.loads(sources_json)
    entries = data["sources"] if isinstance(data, dict) else data
    dropped = 0
    for e in entries:
        if e.get("type") != "url" or e.get("outputHashMode") != "flat":
            continue  # recursive = NAR directory hash, not raw bytes
        integrity = e.get("integrity", "")
        if not integrity.startswith("sha256-"):
            continue
        try:
            digest = base64.b64decode(integrity[len("sha256-") :])
        except ValueError:
            continue
        if len(digest) != 32:
            continue
        urls = e.get("urls") or []
        # Prefer the content-addressed mirrors: URLs that name the hash
        # are claims about the bytes by construction.
        loc = next(
            (u for u in urls if "bordeaux.guix.gnu.org/file/" in u),
            next((u for u in urls if "tarballs.nixos.org/sha256/" in u), None),
        )
        # The content-addressed URLs are .../file/<filename>/sha256/<hash>
        # — the artifact's name is the segment after /file/, never the
        # URL basename (that's the hash).
        filename = next(
            (u.split("/file/", 1)[1].split("/", 1)[0] for u in urls if "/file/" in u),
            urls[0].rsplit("/", 1)[-1] if urls else "",
        )
        if not (loc and filename):
            dropped += 1
            continue
        yield ("guix", digest.hex(), "-", "-", "-", filename, loc)
    if dropped:
        print(
            f"  note: {dropped} flat entries had no content-addressed mirror URL, dropped",
            file=sys.stderr,
        )


# Widths mirror the tarballs SourceSpec row layout in src/inverted.rs.
WIDTHS = {"name": 72, "version": 56, "filename": 128, "loc": 192}


def main():
    outdir = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/tarballs"
    )
    outdir.mkdir(parents=True, exist_ok=True)

    rows = []
    print("debian sid Sources:", file=sys.stderr)
    for comp in DEBIAN_COMPONENTS:
        url = f"{DEBIAN_BASE}/{comp}/source/Sources.xz"
        try:
            data = fetch(url, outdir / f"debian-sid-{comp}-Sources.xz")
        except Exception as e:
            print(f"  warning: {comp}: {e}", file=sys.stderr)
            continue
        rows.extend(debian_rows(data))
    print("homebrew formula.json:", file=sys.stderr)
    rows.extend(brew_rows(fetch(BREW_URL, outdir / "brew-formula.json")))
    print("guix sources.json:", file=sys.stderr)
    rows.extend(guix_rows(fetch(GUIX_URL, outdir / "guix-sources.json")))

    out = outdir / "tarballs.tsv.gz"
    seen = set()
    counts = {}
    skipped = 0
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for witness, sha256, md5, name, version, filename, loc in rows:
            try:
                line = "\t".join(
                    [
                        witness,
                        sha256,
                        md5,
                        field(name, WIDTHS["name"], "name"),
                        field(version, WIDTHS["version"], "version"),
                        field(filename, WIDTHS["filename"], "filename"),
                        field(loc, WIDTHS["loc"], "loc"),
                    ]
                )
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
    per = ", ".join(f"{w} {n:,}" for w, n in sorted(counts.items()))
    print(f"wrote {out}: {sum(counts.values()):,} rows ({per}), {skipped} skipped", file=sys.stderr)
    print(out)


if __name__ == "__main__":
    main()
