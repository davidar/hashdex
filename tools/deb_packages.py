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

Ingest is a few dozen HTTP GETs of index metadata, never content:
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
import gzip
import lzma
import pathlib
import re
import sys
import urllib.request

UA = "hashdex-deb-packages/0.1 (hash index research; index GETs only)"

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
    ("ubuntu-noble", "https://archive.ubuntu.com/ubuntu", "noble", UBU_COMPONENTS),
    ("ubuntu-noble-updates", "https://archive.ubuntu.com/ubuntu", "noble-updates", UBU_COMPONENTS),
    (
        "ubuntu-noble-security",
        "https://archive.ubuntu.com/ubuntu",
        "noble-security",
        UBU_COMPONENTS,
    ),
    ("ubuntu-jammy", "https://archive.ubuntu.com/ubuntu", "jammy", UBU_COMPONENTS),
    ("ubuntu-jammy-updates", "https://archive.ubuntu.com/ubuntu", "jammy-updates", UBU_COMPONENTS),
    (
        "ubuntu-jammy-security",
        "https://archive.ubuntu.com/ubuntu",
        "jammy-security",
        UBU_COMPONENTS,
    ),
    ("kali-rolling", "https://http.kali.org/kali", "kali-rolling", DEB_COMPONENTS),
]

HEX = {
    "SHA256": re.compile(r"[0-9a-f]{64}"),
    "SHA1": re.compile(r"[0-9a-f]{40}"),
    "MD5sum": re.compile(r"[0-9a-f]{32}"),
    "SHA512": re.compile(r"[0-9a-f]{128}"),
}


def fetch(base, suite, comp, dest, installer=False):
    """GET the suite/component Packages index (xz preferred, gz
    fallback — kali publishes gz only), reusing an existing dump.
    `installer` fetches the debian-installer sub-index instead — the
    udebs on install media live there, not in the main Packages."""
    for ext in (".xz", ".gz"):
        cached = dest.with_suffix(dest.suffix + ext)
        if cached.exists():
            print(f"  reusing {cached.name} ({cached.stat().st_size:,} bytes)", file=sys.stderr)
            return cached.read_bytes()
    sub = "debian-installer/binary-amd64" if installer else "binary-amd64"
    last = None
    for ext in (".xz", ".gz"):
        url = f"{base}/dists/{suite}/{comp}/{sub}/Packages{ext}"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = resp.read()
            out = dest.with_suffix(dest.suffix + ext)
            out.write_bytes(data)
            print(f"  fetched {out.name} ({len(data):,} bytes)", file=sys.stderr)
            return data
        except Exception as e:  # noqa: BLE001 — try the next extension
            last = e
    raise last


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
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for witness, base, suite, comps in SUITES:
            print(f"{witness}:", file=sys.stderr)
            fetches = [(comp, False) for comp in comps]
            # udeb sub-indexes exist only for some suites; a 404 there
            # is routine, not a warning worth shouting about.
            fetches += [(comp, True) for comp in comps]
            for comp, installer in fetches:
                tag = f"{comp}-installer" if installer else comp
                try:
                    data = fetch(base, suite, comp, dumps / f"{witness}-{tag}-Packages", installer)
                except Exception as e:  # noqa: BLE001 — a missing component is a warning
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
