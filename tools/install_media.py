#!/usr/bin/env python3
"""Harvest install-media checksum statements from distro release trees.

Every distro publishes checksum files (SHA256SUMS and friends) beside
its release images — per-release statements signed by the project.
Nobody aggregates them (verified 2026-08-12: quickget ships per-distro
endpoint *recipes*, osinfo-db has no hashes at all), so hashdex does.
The endpoint catalog below is seeded from quickget's recipes plus the
projects' own archive trees; where a directory listing enumerates all
releases ever made, the harvest takes the full history, not just
current.

Witnesses with full history: ubuntu (releases + old-releases),
fedora (releases 7+ on the master mirror), archlinux (releng JSON,
every monthly ISO), rockylinux (vault), almalinux, kali (cdimage
tree), linuxmint (kernel.org mirror), openbsd, freebsd (ISO-IMAGES),
void (dated dirs), proxmox (one cumulative SHA256SUMS), zorin,
centos-stream. debian covers current + current-live (the cdimage
archive tree is a follow-up).

Deferred (registry gap, not an oversight): SourceForge-hosted
checksums (redirect chains, one sidecar per file), sha512-only
witnesses (endeavouros, manjaro, gentoo, mageia), and md5/sha1-only
witnesses (slackware, netbsd, trisquel, …) — the TSV carries a scheme
column, so they slot in without a format change. Weak-digest rows are
lookup keys, never merge keys, per DESIGN.md.

Ingest is index-metadata GETs only, never content: admission-rule
clean. Checksum files are cached beside the output; a re-harvest must
delete stale dumps first (fetch() reuses anything already on disk).

Usage:
  tools/install_media.py [outdir]     # default ~/.cache/hashdex/media
  hdx index build install-media <outdir>/media.tsv.gz

Output TSV columns (one row per file×witness, "-" = absent):
  witness scheme digest name version filename loc
where loc is the URL of the checksum document stating the digest —
the claim URL by construction.
"""
import gzip
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser

UA = "hashdex-install-media/0.1 (hash index research; checksum-file GETs only)"
DELAY = 0.05  # between uncached requests — polite to mirrors

# Prefer IPv4: urllib has no happy-eyeballs, so on networks with a
# silently-broken IPv6 path every request burns the full timeout in
# SYN-SENT before falling back. curl survives this; urllib does not.
import socket  # noqa: E402

_getaddrinfo = socket.getaddrinfo


def _ipv4_first(host, port, family=0, *args, **kwargs):
    infos = _getaddrinfo(host, port, family, *args, **kwargs)
    return sorted(infos, key=lambda i: i[0] != socket.AF_INET)


socket.getaddrinfo = _ipv4_first

HEX = {"sha256": re.compile(r"^[0-9a-f]{64}$"), "sha512": re.compile(r"^[0-9a-f]{128}$")}
# BSD-style checksum line: SHA256 (filename) = hex
BSD = re.compile(r"^(SHA256|SHA512)\s*\((.+)\)\s*=\s*([0-9a-fA-F]+)$")

_last_fetch = 0.0


class _Hrefs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)


def fetch(url, cache):
    """GET url, caching the body on disk keyed by the URL."""
    import hashlib

    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", url.split("//", 1)[-1])[:120]
    dest = cache / f"{slug}.{hashlib.sha1(url.encode()).hexdigest()[:8]}"
    if dest.exists():
        return dest.read_bytes()
    global _last_fetch
    wait = _last_fetch + DELAY - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last_fetch = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip" or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
    dest.write_bytes(data)
    return data


def listing(url, cache):
    """Directory-index hrefs: subdirectory and file names, no parents."""
    parser = _Hrefs()
    parser.feed(fetch(url, cache).decode("utf-8", errors="replace"))
    out = []
    for h in parser.hrefs:
        if h.startswith(("?", "/", "#")) or "://" in h:
            continue
        out.append(h)
    return out


def checksum_rows(text, scheme="sha256"):
    """Parse a checksum document: coreutils `hex  name` / `hex *name`
    lines and BSD `ALGO (name) = hex` lines, PGP armor ignored."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-----", "Hash:", "Version:")):
            continue
        m = BSD.match(line)
        if m:
            algo, name, digest = m.groups()
            if algo.lower() == scheme:
                yield digest.lower(), name.strip()
            continue
        parts = line.split()
        if len(parts) >= 2 and HEX[scheme].match(parts[0].lower()):
            yield parts[0].lower(), parts[1].lstrip("*")


VERSION_DIR = re.compile(r"^(\d[\w.\-]*)/$")


def ubuntu(cache):
    """releases.ubuntu.com + old-releases: every release directory's
    SHA256SUMS. Numeric dirs first; codename dirs (which duplicate or
    predate them) fill in only unseen files."""
    for base in ("https://releases.ubuntu.com/", "https://old-releases.ubuntu.com/releases/"):
        dirs = [d for d in listing(base, cache) if d.endswith("/")]
        numeric = [d for d in dirs if VERSION_DIR.match(d)]
        codename = [d for d in dirs if re.match(r"^[a-z]+/$", d) and d != "torrent/"]
        for d in numeric + codename:
            loc = f"{base}{d}SHA256SUMS"
            try:
                text = fetch(loc, cache).decode("utf-8", errors="replace")
            except urllib.error.HTTPError:
                continue  # pre-SHA256 era (warty…edgy ship MD5SUMS only)
            version = d.rstrip("/") if VERSION_DIR.match(d) else "-"
            for digest, name in checksum_rows(text):
                yield ("ubuntu", "sha256", digest, "-", version, name, loc)


def debian(cache):
    """debian-cd current + current-live, all architectures, iso-* dirs.
    (The full cdimage archive tree is a follow-up harvest.)"""
    for tree in ("current", "current-live"):
        base = f"https://cdimage.debian.org/debian-cd/{tree}/"
        try:
            archs = [d for d in listing(base, cache) if d.endswith("/")]
        except urllib.error.HTTPError:
            continue
        for arch in archs:
            if arch in ("source/", "trace/"):
                continue
            try:
                subdirs = listing(base + arch, cache)
            except urllib.error.HTTPError:
                continue
            for sub in subdirs:
                if not sub.startswith("iso-"):
                    continue
                loc = f"{base}{arch}{sub}SHA256SUMS"
                try:
                    text = fetch(loc, cache).decode("utf-8", errors="replace")
                except urllib.error.HTTPError:
                    continue
                for digest, name in checksum_rows(text):
                    version = m.group(1) if (m := re.search(r"(\d+\.\d+\.\d+)", name)) else "-"
                    yield ("debian", "sha256", digest, "-", version, name, loc)


def fedora(cache):
    """dl.fedoraproject.org keeps releases 7+ live: crawl
    releases/<N>/<Edition>/<arch>/iso/ for *CHECKSUM* documents."""
    base = "https://dl.fedoraproject.org/pub/fedora/linux/releases/"
    releases = sorted(
        (d for d in listing(base, cache) if re.match(r"^\d+/$", d)),
        key=lambda d: int(d.rstrip("/")),
    )
    for rel in releases:
        try:
            editions = [d for d in listing(base + rel, cache) if d.endswith("/")]
        except urllib.error.HTTPError:
            continue
        for ed in editions:
            try:
                archs = [d for d in listing(base + rel + ed, cache) if d.endswith("/")]
            except urllib.error.HTTPError:
                continue
            for arch in archs:
                iso_dir = f"{base}{rel}{ed}{arch}iso/"
                try:
                    files = listing(iso_dir, cache)
                except urllib.error.HTTPError:
                    continue
                for f in files:
                    if "CHECKSUM" not in f.upper() or f.endswith("/"):
                        continue
                    loc = iso_dir + f
                    try:
                        text = fetch(loc, cache).decode("utf-8", errors="replace")
                    except urllib.error.HTTPError:
                        continue
                    for digest, name in checksum_rows(text):
                        yield ("fedora", "sha256", digest, ed.rstrip("/"), rel.rstrip("/"), name, loc)


def archlinux(cache):
    """archlinux.org/releng/releases/json/ lists every monthly ISO ever
    cut, sha256 included — full history in one GET."""
    loc = "https://archlinux.org/releng/releases/json/"
    data = json.loads(fetch(loc, cache))
    for r in data.get("releases", []):
        digest = r.get("sha256_sum")
        iso_url = r.get("iso_url") or ""
        version = r.get("version") or "-"
        if not (digest and HEX["sha256"].match(digest)):
            continue  # oldest releases predate sha256 publication
        yield ("archlinux", "sha256", digest, "-", version, iso_url.rsplit("/", 1)[-1], loc)


def almalinux(cache):
    base = "https://repo.almalinux.org/almalinux/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        for arch_dir in _try_listing(f"{base}{d}isos/", cache):
            loc = f"{base}{d}isos/{arch_dir}CHECKSUM"
            try:
                text = fetch(loc, cache).decode("utf-8", errors="replace")
            except urllib.error.HTTPError:
                continue
            for digest, name in checksum_rows(text):
                yield ("almalinux", "sha256", digest, "-", d.rstrip("/"), name, loc)


def rockylinux(cache):
    """dl.rockylinux.org/vault holds every point release."""
    base = "https://dl.rockylinux.org/vault/rocky/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        for arch_dir in _try_listing(f"{base}{d}isos/", cache):
            loc = f"{base}{d}isos/{arch_dir}CHECKSUM"
            try:
                text = fetch(loc, cache).decode("utf-8", errors="replace")
            except urllib.error.HTTPError:
                continue
            for digest, name in checksum_rows(text):
                yield ("rockylinux", "sha256", digest, "-", d.rstrip("/"), name, loc)


def linuxmint(cache):
    base = "https://mirrors.kernel.org/linuxmint/stable/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        loc = f"{base}{d}sha256sum.txt"
        try:
            text = fetch(loc, cache).decode("utf-8", errors="replace")
        except urllib.error.HTTPError:
            continue
        for digest, name in checksum_rows(text):
            yield ("linuxmint", "sha256", digest, "-", d.rstrip("/"), name, loc)
    loc = "https://mirrors.kernel.org/linuxmint/debian/sha256sum.txt"
    try:
        for digest, name in checksum_rows(fetch(loc, cache).decode("utf-8", errors="replace")):
            yield ("linuxmint", "sha256", digest, "lmde", "-", name, loc)
    except urllib.error.HTTPError:
        pass


def kali(cache):
    """cdimage.kali.org keeps every kali-<version> directory."""
    base = "https://cdimage.kali.org/"
    for d in listing(base, cache):
        if not re.match(r"^kali-\d[\w.]*/$", d):
            continue
        loc = f"{base}{d}SHA256SUMS"
        try:
            text = fetch(loc, cache).decode("utf-8", errors="replace")
        except urllib.error.HTTPError:
            continue
        for digest, name in checksum_rows(text):
            yield ("kali", "sha256", digest, "-", d.rstrip("/").removeprefix("kali-"), name, loc)


def openbsd(cache):
    base = "https://ftp.openbsd.org/pub/OpenBSD/"
    for d in listing(base, cache):
        if not re.match(r"^\d+\.\d+/$", d):
            continue
        for arch in ("amd64/", "arm64/", "i386/"):
            loc = f"{base}{d}{arch}SHA256"
            try:
                text = fetch(loc, cache).decode("utf-8", errors="replace")
            except urllib.error.HTTPError:
                continue
            for digest, name in checksum_rows(text):
                yield ("openbsd", "sha256", digest, "-", d.rstrip("/"), name, loc)


def freebsd(cache):
    for arch in ("amd64/amd64/", "arm64/aarch64/"):
        base = f"https://download.freebsd.org/releases/{arch}ISO-IMAGES/"
        for d in _try_listing(base, cache):
            if not VERSION_DIR.match(d):
                continue
            try:
                files = listing(base + d, cache)
            except urllib.error.HTTPError:
                continue
            for f in files:
                if not f.startswith("CHECKSUM.SHA256"):
                    continue
                loc = base + d + f
                try:
                    text = fetch(loc, cache).decode("utf-8", errors="replace")
                except urllib.error.HTTPError:
                    continue
                for digest, name in checksum_rows(text):
                    yield ("freebsd", "sha256", digest, "-", d.rstrip("/"), name, loc)


def void(cache):
    """repo-default.voidlinux.org/live/<YYYYMMDD>/ dated dirs are the
    release history; `current` duplicates the newest."""
    base = "https://repo-default.voidlinux.org/live/"
    for d in listing(base, cache):
        if not re.match(r"^\d{8}/$", d):
            continue
        loc = f"{base}{d}sha256sum.txt"
        try:
            text = fetch(loc, cache).decode("utf-8", errors="replace")
        except urllib.error.HTTPError:
            continue
        for digest, name in checksum_rows(text):
            yield ("void", "sha256", digest, "-", d.rstrip("/"), name, loc)


def proxmox(cache):
    """One cumulative SHA256SUMS covering every ISO they have shipped."""
    loc = "https://enterprise.proxmox.com/iso/SHA256SUMS"
    for digest, name in checksum_rows(fetch(loc, cache).decode("utf-8", errors="replace")):
        version = m.group(1) if (m := re.search(r"(\d+\.\d+[\w.-]*)", name)) else "-"
        yield ("proxmox", "sha256", digest, "-", version, name, loc)


def zorin(cache):
    base = "https://plug-mirror.rcac.purdue.edu/zorin-iso/"
    for d in _try_listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        loc = f"{base}{d}SHA256SUMS.txt"
        try:
            text = fetch(loc, cache).decode("utf-8", errors="replace")
        except urllib.error.HTTPError:
            continue
        for digest, name in checksum_rows(text):
            yield ("zorin", "sha256", digest, "-", d.rstrip("/"), name, loc)


def centos_stream(cache):
    """mirror.stream.centos.org: per-ISO .SHA256SUM sidecars."""
    base = "https://mirror.stream.centos.org/"
    for d in _try_listing(base, cache):
        if not re.match(r"^\d+-stream/$", d):
            continue
        for arch in _try_listing(f"{base}{d}BaseOS/", cache):
            iso_dir = f"{base}{d}BaseOS/{arch}iso/"
            for f in _try_listing(iso_dir, cache):
                if not f.endswith(".SHA256SUM"):
                    continue
                loc = iso_dir + f
                try:
                    text = fetch(loc, cache).decode("utf-8", errors="replace")
                except urllib.error.HTTPError:
                    continue
                for digest, name in checksum_rows(text):
                    yield ("centos-stream", "sha256", digest, "-", d.rstrip("/"), name, loc)


def _try_listing(url, cache):
    try:
        return [d for d in listing(url, cache) if d.endswith("/") or "." in d]
    except urllib.error.HTTPError:
        return []


ADAPTERS = [
    ubuntu,
    debian,
    fedora,
    archlinux,
    almalinux,
    rockylinux,
    linuxmint,
    kali,
    openbsd,
    freebsd,
    void,
    proxmox,
    zorin,
    centos_stream,
]

# Widths mirror the install-media SourceSpec row layout in src/inverted.rs.
WIDTHS = {"witness": 24, "name": 48, "version": 32, "filename": 128, "loc": 192}


def field(s, width, what):
    if "\t" in s or "\n" in s:
        raise ValueError(f"{what} contains separator: {s!r}")
    if len(s.encode()) > width:
        raise ValueError(f"{what} over {width} bytes: {s!r}")
    return s if s else "-"


def main():
    outdir = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/media"
    )
    cache = outdir / "dumps"
    cache.mkdir(parents=True, exist_ok=True)

    out = outdir / "media.tsv.gz"
    seen = set()
    counts = {}
    skipped = 0
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for adapter in ADAPTERS:
            print(f"{adapter.__name__}:", file=sys.stderr)
            n0 = sum(counts.values())
            try:
                rows = list(adapter(cache))
            except Exception as e:
                print(f"  warning: {adapter.__name__} failed: {e}", file=sys.stderr)
                continue
            for witness, scheme, digest, name, version, filename, loc in rows:
                # One row per (witness, digest, filename): codename dirs
                # and mirror aliases restate the same fact — keep the
                # first (canonical-ordered) statement.
                key = (witness, digest, filename)
                if key in seen:
                    continue
                try:
                    line = "\t".join(
                        [
                            field(witness, WIDTHS["witness"], "witness"),
                            scheme,
                            digest,
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
                seen.add(key)
                fh.write(line + "\n")
                counts[witness] = counts.get(witness, 0) + 1
            print(f"  {sum(counts.values()) - n0:,} rows", file=sys.stderr)
    per = ", ".join(f"{w} {n:,}" for w, n in sorted(counts.items()))
    print(f"wrote {out}: {sum(counts.values()):,} rows ({per}), {skipped} skipped", file=sys.stderr)
    print(out)


if __name__ == "__main__":
    main()
