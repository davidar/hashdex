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

Full-history witnesses: ubuntu (releases + old-releases + the cdimage
flavor trees), debian (current + the whole cdimage archive), fedora
(dl + archives + Fedora Core + secondary arches), archlinux (releng
JSON), rockylinux (vault), almalinux, kali, linuxmint, openbsd,
freebsd, netbsd, void, alpine, opensuse (leap history + tumbleweed
current), qubes (multi-hash .DIGESTS docs — single-witness rows
co-stating md5+sha1+sha256+sha512), raspberrypi, endeavouros,
openwrt, proxmox, zorin, centos-stream.

The scheme column carries whatever the document states: sha256 and
sha512 are strong; md5/sha1 rows (pre-SHA256-era Ubuntu/Fedora Core
media) are lookup keys for the weak "consistent with" tier, never
merge keys, per DESIGN.md. One row per (witness, scheme-digest,
filename); rows from the SAME document later regroup into
multi-digest rows at parquet build (sibling documents never merge —
that would be a filename join, not a witness statement).

Deferred (noted, not oversights): haiku (cdn.haiku-os.org unreachable
2026-08-15), manjaro (CDN, no crawlable checksum tree), gentoo
(.DIGESTS mixes BLAKE2B with SHA512 at the same hex width — needs a
section-aware parser), SourceForge-hosted checksums (redirect chains,
one sidecar per file), Android factory images (HTML tables only).

Ingest is index-metadata GETs only, never content: admission-rule
clean. Checksum files are cached beside the output (404s too); a
real re-harvest must delete the dumps dir first — fetch() reuses
anything already on disk.

Usage:
  tools/install_media.py [outdir]     # default ~/.cache/hashdex/media
  tools/media_parquet.py              # then TSV -> published parquet

Output TSV columns (one row per file×witness×scheme, "-" = absent):
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

try:
    import httpx
except ImportError:
    sys.exit("needs httpx (pip install httpx[http2])")

UA = "hashdex-install-media/0.2 (hash index research; checksum-file GETs only)"
# Politeness is a per-host concurrency bound, not a global serial
# crawl: every adapter fans out over at most WORKERS connections to
# its own host(s), and adapters (different hosts) run concurrently.
WORKERS = 12

# Prefer IPv4: urllib has no happy-eyeballs, so on networks with a
# silently-broken IPv6 path every request burns the full timeout in
# SYN-SENT before falling back. curl survives this; urllib does not.
import socket  # noqa: E402

_getaddrinfo = socket.getaddrinfo


def _ipv4_first(host, port, family=0, *args, **kwargs):
    infos = _getaddrinfo(host, port, family, *args, **kwargs)
    return sorted(infos, key=lambda i: i[0] != socket.AF_INET)


socket.getaddrinfo = _ipv4_first

# Digest hex width identifies the scheme in coreutils-style lines.
# (BLAKE2B shares sha512's width — any adapter harvesting documents
# that may contain it must not rely on this table; see gentoo note.)
SCHEME_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
# BSD-style checksum line: ALGO (filename) = hex
BSD = re.compile(r"^(MD5|SHA1|SHA256|SHA512)\s*\((.+)\)\s*=\s*([0-9a-fA-F]+)$")
HEXCHARS = re.compile(r"^[0-9a-fA-F]+$")


def pmap(fn, items):
    """Map fn over items on a bounded thread pool, flattening the
    per-item row lists. Item failures propagate (adapter-level catch)."""
    from concurrent.futures import ThreadPoolExecutor

    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(min(WORKERS, len(items))) as ex:
        return [row for rows in ex.map(fn, items) for row in rows]


class _Hrefs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)


_client = None


def client():
    """One shared connection pool for the whole harvest: HTTP/2
    multiplexing where the host offers it, keepalive h1.1 otherwise
    (the deb_packages.py lesson — archive mirrors are latency-bound,
    not bandwidth-bound). The global connection cap is the politeness
    ceiling across all adapters."""
    global _client
    if _client is None:
        _client = httpx.Client(
            http2=True,
            follow_redirects=True,
            timeout=60,
            headers={"User-Agent": UA},
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=64),
        )
    return _client


def fetch(url, cache):
    """GET url, caching the body on disk keyed by the URL (404s cached
    as markers so re-runs and resumed harvests stay cheap). Raises
    urllib.error.HTTPError on HTTP failure so adapter catch-sites are
    transport-agnostic."""
    import hashlib

    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", url.split("//", 1)[-1])[:120]
    dest = cache / f"{slug}.{hashlib.sha1(url.encode()).hexdigest()[:8]}"
    marker = dest.with_name(dest.name + ".404")
    if dest.exists():
        return dest.read_bytes()
    if marker.exists():
        raise urllib.error.HTTPError(url, 404, "cached miss", {}, None)
    for attempt in range(3):
        try:
            resp = client().get(url)
        except httpx.RemoteProtocolError as e:
            # Some servers emit framing python's strict h11 refuses
            # (cdn.netbsd.org chunk headers); curl tolerates them.
            import subprocess

            r = subprocess.run(
                ["curl", "-4", "-sfL", "--max-time", "60", "-A", UA, url],
                capture_output=True,
            )
            if r.returncode == 22:  # HTTP error >= 400 (assume miss)
                marker.touch()
                raise urllib.error.HTTPError(url, 404, "curl -f", {}, None) from e
            if r.returncode != 0:
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise urllib.error.URLError(f"curl exit {r.returncode}") from e
            data = r.stdout
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            dest.write_bytes(data)
            return data
        except httpx.HTTPError as e:
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            raise urllib.error.URLError(str(e)) from e
        if resp.status_code == 404:
            marker.touch()
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)
        if resp.status_code in (429, 500, 502, 503, 504) and attempt < 2:
            time.sleep(2 * (attempt + 1))
            continue
        if resp.status_code >= 400:
            raise urllib.error.HTTPError(url, resp.status_code, resp.reason_phrase, {}, None)
        data = resp.content
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        dest.write_bytes(data)
        return data


def listing(url, cache):
    """Directory-index hrefs: subdirectory and file names, no parents."""
    parser = _Hrefs()
    parser.feed(fetch(url, cache).decode("utf-8", errors="replace"))
    out = []
    for h in parser.hrefs:
        h = h.removeprefix("./")
        if not h or h.startswith(("?", "/", "#", "..")) or "://" in h:
            continue
        out.append(h)
    return out


def checksum_rows(text):
    """Parse a checksum document into (scheme, digest, filename):
    coreutils `hex  name` / `hex *name` lines (scheme by hex width)
    and BSD `ALGO (name) = hex` lines, PGP armor ignored."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-----", "Hash:", "Version:")):
            continue
        m = BSD.match(line)
        if m:
            algo, name, digest = m.groups()
            scheme = algo.lower()
            if SCHEME_BY_LEN.get(len(digest)) is not None and len(digest) == {
                "md5": 32,
                "sha1": 40,
                "sha256": 64,
                "sha512": 128,
            }.get(scheme):
                yield scheme, digest.lower(), name.strip()
            continue
        parts = line.split()
        if len(parts) >= 2 and HEXCHARS.match(parts[0]):
            scheme = SCHEME_BY_LEN.get(len(parts[0]))
            if scheme:
                yield scheme, parts[0].lower(), parts[1].lstrip("*")


def _absent(e):
    """Only a 404 means the document doesn't exist. Anything else is a
    transport failure that must fail the adapter loudly — swallowing
    it silently thins the harvest (this bit: dl.fedoraproject.org
    transients dropped whole release subtrees on the first run)."""
    if e.code != 404:
        raise e
    return True


def doc_rows(loc, cache, witness, name="-", version="-"):
    """All rows one checksum document states; [] when it 404s."""
    try:
        text = fetch(loc, cache).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        _absent(e)
        return []
    return [
        (witness, scheme, digest, name, version, fname, loc)
        for scheme, digest, fname in checksum_rows(text)
    ]


VERSION_DIR = re.compile(r"^(\d[\w.\-]*)/$")


def ubuntu(cache):
    """releases.ubuntu.com + old-releases: every release directory's
    SHA256SUMS (MD5SUMS for the pre-sha256 warty..edgy era). Numeric
    dirs first; codename dirs (which duplicate or predate them) fill
    in only unseen files."""
    def one(pair):
        base, d = pair
        version = d.rstrip("/") if VERSION_DIR.match(d) else "-"
        rows = doc_rows(f"{base}{d}SHA256SUMS", cache, "ubuntu", version=version)
        if not rows:
            rows = doc_rows(f"{base}{d}MD5SUMS", cache, "ubuntu", version=version)
        return rows

    pairs = []
    for base in ("https://releases.ubuntu.com/", "https://old-releases.ubuntu.com/releases/"):
        dirs = [d for d in listing(base, cache) if d.endswith("/")]
        numeric = [d for d in dirs if VERSION_DIR.match(d)]
        codename = [d for d in dirs if re.match(r"^[a-z]+/$", d) and d != "torrent/"]
        pairs += [(base, d) for d in numeric + codename]
    return pmap(one, pairs)


# cdimage.ubuntu.com flavor trees: <flavor>/releases/<ver>/release/.
# The empty slug is Ubuntu's own cdimage tree (server/legacy images
# releases.ubuntu.com never carried).
UBUNTU_FLAVORS = [
    ("", "ubuntu"),
    ("kubuntu", "kubuntu"),
    ("xubuntu", "xubuntu"),
    ("lubuntu", "lubuntu"),
    ("ubuntu-mate", "ubuntu-mate"),
    ("ubuntustudio", "ubuntustudio"),
    ("ubuntu-budgie", "ubuntu-budgie"),
    ("ubuntukylin", "ubuntukylin"),
    ("ubuntucinnamon", "ubuntucinnamon"),
    ("edubuntu", "edubuntu"),
    ("ubuntu-unity", "ubuntu-unity"),
    ("ubuntu-gnome", "ubuntu-gnome"),
    ("mythbuntu", "mythbuntu"),
]


def ubuntu_cdimage(cache):
    pairs = []
    for slug, witness in UBUNTU_FLAVORS:
        base = f"https://cdimage.ubuntu.com/{slug + '/' if slug else ''}releases/"
        try:
            dirs = [d for d in listing(base, cache) if d.endswith("/")]
        except urllib.error.HTTPError as e:
            _absent(e)
            continue
        pairs += [(base, d, witness) for d in dirs]

    def one(p):
        base, d, witness = p
        version = d.rstrip("/") if VERSION_DIR.match(d) else "-"
        return doc_rows(f"{base}{d}release/SHA256SUMS", cache, witness, version=version)

    return pmap(one, pairs)


def debian(cache):
    """debian-cd current + current-live, all architectures, iso-* dirs."""
    for tree in ("current", "current-live"):
        base = f"https://cdimage.debian.org/debian-cd/{tree}/"
        try:
            archs = [d for d in listing(base, cache) if d.endswith("/")]
        except urllib.error.HTTPError as e:
            _absent(e)
            continue
        for arch in archs:
            if arch in ("source/", "trace/"):
                continue
            for sub in _try_listing(base + arch, cache):
                if not sub.startswith("iso-"):
                    continue
                for row in doc_rows(f"{base}{arch}{sub}SHA256SUMS", cache, "debian"):
                    name = row[5]
                    version = m.group(1) if (m := re.search(r"(\d+\.\d+\.\d+)", name)) else "-"
                    yield row[:4] + (version,) + row[5:]


def debian_archive(cache):
    """The whole cdimage archive: every point release (and -live tree)
    Debian still hosts, ~150 version directories. SHA256SUMS where
    published, MD5SUMS for the pre-sha256 era (3.x/4.x)."""
    base = "https://cdimage.debian.org/cdimage/archive/"
    vers = sorted({d for d in listing(base, cache) if d.endswith("/") and d[0].isdigit()})

    def one(v):
        out = []
        for arch in _try_listing(base + v, cache):
            if not arch.endswith("/") or arch in ("source/", "trace/"):
                continue
            for sub in _try_listing(base + v + arch, cache):
                if not (sub.startswith("iso-") and sub.endswith("/")):
                    continue
                loc_base = f"{base}{v}{arch}{sub}"
                rows = doc_rows(f"{loc_base}SHA256SUMS", cache, "debian", version=v.rstrip("/"))
                if not rows:
                    rows = doc_rows(f"{loc_base}MD5SUMS", cache, "debian", version=v.rstrip("/"))
                out.extend(rows)
        return out

    return pmap(one, vers)


# Directory names never descended in release trees: package/repo
# payloads, not media. (iso/ and edition/arch dirs stay crawlable.)
FEDORA_SKIP = {
    "os/",
    "source/",
    "tree/",
    "debug/",
    "drpms/",
    "repodata/",
    "headers/",
    "Packages/",
    "RPMS/",
    "SRPMS/",
    "images/",
    "isolinux/",
    "LiveOS/",
    "EFI/",
    "repoview/",
}


def _fedora_checksums(url, cache, witness, version, depth, name="-"):
    """Bounded crawl for *CHECKSUM* / SHA*SUM / MD5SUM documents.
    Pre-F21 keeps them beside the images (no iso/ subdir), newer trees
    under iso/ — so every level within depth is checked for both.
    `name` picks up the first directory level under the release (the
    edition: Workstation, Live, Fedora, …)."""
    try:
        entries = listing(url, cache)
    except urllib.error.HTTPError as e:
        _absent(e)
        return
    for f in entries:
        if f.endswith("/"):
            continue
        up = f.upper()
        if "CHECKSUM" in up or up in ("SHA256SUM", "SHA1SUM", "MD5SUM"):
            yield from doc_rows(url + f, cache, witness, name=name, version=version)
    if depth == 0:
        return
    for d in entries:
        if d.endswith("/") and d not in FEDORA_SKIP:
            child = d.rstrip("/") if name == "-" else name
            yield from _fedora_checksums(url + d, cache, witness, version, depth - 1, child)


FEDORA_ROOTS = [
    "https://dl.fedoraproject.org/pub/fedora/linux/releases/",
    "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/",
    "https://archives.fedoraproject.org/pub/archive/fedora/linux/core/",
    "https://dl.fedoraproject.org/pub/fedora-secondary/releases/",
    "https://archives.fedoraproject.org/pub/archive/fedora-secondary/releases/",
]


def fedora(cache):
    """Every Fedora release tree: dl (current), archives (history),
    Fedora Core (sha1-era), secondary arches. dl is crawled first so
    its live URLs win the claim-URL dedup for current releases."""
    pairs = []
    for root in FEDORA_ROOTS:
        try:
            releases = sorted(
                (d for d in listing(root, cache) if re.match(r"^\d+/$", d)),
                key=lambda d: int(d.rstrip("/")),
            )
        except urllib.error.HTTPError as e:
            _absent(e)
            continue
        pairs += [(root, rel) for rel in releases]
    return pmap(
        lambda p: list(_fedora_checksums(p[0] + p[1], cache, "fedora", p[1].rstrip("/"), 3)),
        pairs,
    )


def archlinux(cache):
    """archlinux.org/releng/releases/json/ lists every monthly ISO ever
    cut, sha256 included — full history in one GET."""
    loc = "https://archlinux.org/releng/releases/json/"
    data = json.loads(fetch(loc, cache))
    for r in data.get("releases", []):
        iso_url = r.get("iso_url") or ""
        version = r.get("version") or "-"
        for scheme, key in (("sha256", "sha256_sum"), ("md5", "md5_sum"), ("sha1", "sha1_sum")):
            digest = r.get(key)
            if digest and HEXCHARS.match(digest) and SCHEME_BY_LEN.get(len(digest)) == scheme:
                yield ("archlinux", scheme, digest.lower(), "-", version, iso_url.rsplit("/", 1)[-1], loc)


def almalinux(cache):
    base = "https://repo.almalinux.org/almalinux/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        for arch_dir in _try_listing(f"{base}{d}isos/", cache):
            yield from doc_rows(
                f"{base}{d}isos/{arch_dir}CHECKSUM", cache, "almalinux", version=d.rstrip("/")
            )


def rockylinux(cache):
    """dl.rockylinux.org/vault holds every point release."""
    base = "https://dl.rockylinux.org/vault/rocky/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        for arch_dir in _try_listing(f"{base}{d}isos/", cache):
            yield from doc_rows(
                f"{base}{d}isos/{arch_dir}CHECKSUM", cache, "rockylinux", version=d.rstrip("/")
            )


def linuxmint(cache):
    base = "https://mirrors.kernel.org/linuxmint/stable/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        yield from doc_rows(f"{base}{d}sha256sum.txt", cache, "linuxmint", version=d.rstrip("/"))
    yield from doc_rows(
        "https://mirrors.kernel.org/linuxmint/debian/sha256sum.txt", cache, "linuxmint", name="lmde"
    )


def kali(cache):
    """cdimage.kali.org keeps every kali-<version> directory."""
    base = "https://cdimage.kali.org/"
    for d in listing(base, cache):
        if not re.match(r"^kali-\d[\w.]*/$", d):
            continue
        version = d.rstrip("/").removeprefix("kali-")
        yield from doc_rows(f"{base}{d}SHA256SUMS", cache, "kali", version=version)


def openbsd(cache):
    base = "https://ftp.openbsd.org/pub/OpenBSD/"
    for d in listing(base, cache):
        if not re.match(r"^\d+\.\d+/$", d):
            continue
        for arch in ("amd64/", "arm64/", "i386/"):
            yield from doc_rows(f"{base}{d}{arch}SHA256", cache, "openbsd", version=d.rstrip("/"))


def freebsd(cache):
    for arch in ("amd64/amd64/", "arm64/aarch64/"):
        base = f"https://download.freebsd.org/releases/{arch}ISO-IMAGES/"
        for d in _try_listing(base, cache):
            if not VERSION_DIR.match(d):
                continue
            for f in _try_listing(base + d, cache):
                if f.startswith("CHECKSUM.SHA256"):
                    yield from doc_rows(base + d + f, cache, "freebsd", version=d.rstrip("/"))


def netbsd(cache):
    """ftp.netbsd.org/pub/NetBSD/images/<ver>/: one SHA512 document
    (BSD-style) per release covering every image. The origin host, not
    cdn.netbsd.org — the CDN edge emits chunked framing that breaks
    python HTTP stacks and flakes under curl too. Archived versions
    301 into the archive tree; redirects are followed."""
    base = "https://ftp.netbsd.org/pub/NetBSD/images/"
    for d in listing(base, cache):
        if not VERSION_DIR.match(d):
            continue
        yield from doc_rows(f"{base}{d}SHA512", cache, "netbsd", version=d.rstrip("/"))


def void(cache):
    """repo-default.voidlinux.org/live/<YYYYMMDD>/ dated dirs are the
    release history; `current` duplicates the newest."""
    base = "https://repo-default.voidlinux.org/live/"
    for d in listing(base, cache):
        if re.match(r"^\d{8}/$", d):
            yield from doc_rows(f"{base}{d}sha256sum.txt", cache, "void", version=d.rstrip("/"))


def alpine(cache):
    """dl-cdn.alpinelinux.org/alpine/v3.N/releases/<arch>/: one .sha256
    sidecar per image (sha256 era begins around v3.3)."""
    base = "https://dl-cdn.alpinelinux.org/alpine/"
    vers = [d for d in listing(base, cache) if re.match(r"^v\d+\.\d+/$", d)]

    def one(p):
        v, arch = p
        rel = f"{base}{v}releases/{arch}"
        out = []
        for f in _try_listing(rel, cache):
            if f.endswith(".sha256"):
                out.extend(doc_rows(rel + f, cache, "alpine", version=v.strip("v/")))
        return out

    return pmap(one, [(v, a) for v in sorted(vers) for a in ("x86_64/", "aarch64/", "x86/")])


def opensuse(cache):
    """Leap history + Tumbleweed current: per-ISO .sha256 sidecars."""
    leap = "https://download.opensuse.org/distribution/leap/"
    docs = []
    for d in _try_listing(leap, cache):
        if not VERSION_DIR.match(d):
            continue
        iso = f"{leap}{d}iso/"
        docs += [
            (iso + f, "-", d.rstrip("/"))
            for f in _try_listing(iso, cache)
            if f.endswith(".sha256")
        ]
    tw = "https://download.opensuse.org/tumbleweed/iso/"
    docs += [(tw + f, "tumbleweed", "-") for f in _try_listing(tw, cache) if f.endswith(".sha256")]
    return pmap(lambda d: doc_rows(d[0], cache, "opensuse", name=d[1], version=d[2]), docs)


def qubes(cache):
    """ftp.qubes-os.org/iso/*.DIGESTS: one document co-stating
    md5+sha1+sha256+sha512 per ISO — single-witness multi-hash rows."""
    base = "https://ftp.qubes-os.org/iso/"

    def one(f):
        version = m.group(1) if (m := re.search(r"R?(\d[\w.\-]*)-x86", f)) else "-"
        return doc_rows(base + f, cache, "qubes", version=version)

    return pmap(one, [f for f in listing(base, cache) if f.endswith(".DIGESTS")])


def raspberrypi(cache):
    """downloads.raspberrypi.com/<tree>/images/<dated>/: one .sha256
    sidecar per image, full history per tree."""
    trees = [
        "raspios_arm64",
        "raspios_armhf",
        "raspios_lite_arm64",
        "raspios_lite_armhf",
        "raspios_full_arm64",
        "raspios_full_armhf",
        "raspbian",
        "raspbian_lite",
        "raspbian_full",
    ]
    def tree_dirs(t):
        base = f"https://downloads.raspberrypi.com/{t}/images/"
        return [(base, d, t) for d in _try_listing(base, cache) if d.endswith("/")]

    def one(p):
        base, d, t = p
        version = m.group(1) if (m := re.search(r"(\d{4}-\d{2}-\d{2})", d)) else "-"
        out = []
        for f in _try_listing(base + d, cache):
            if f.endswith(".sha256"):
                out.extend(doc_rows(base + d + f, cache, "raspberrypi", name=t, version=version))
        return out

    return pmap(one, pmap(tree_dirs, trees))


def endeavouros(cache):
    """Project mirror tree: one .sha512sum sidecar per ISO."""
    base = "https://mirror.alpix.eu/endeavouros/iso/"
    for f in _try_listing(base, cache):
        if f.endswith(".sha512sum"):
            version = m.group(1) if (m := re.search(r"EndeavourOS_(.+)\.iso", f)) else "-"
            yield from doc_rows(base + f, cache, "endeavouros", version=version)


def openwrt(cache):
    """downloads.openwrt.org/releases/<ver>/targets/<t>/<sub>/sha256sums
    — every firmware image of every release, all targets."""
    base = "https://downloads.openwrt.org/releases/"
    vers = sorted(d for d in listing(base, cache) if re.match(r"^\d+\.\d+\.\d+", d))

    def targets(v):
        out = []
        for t in _try_listing(f"{base}{v}targets/", cache):
            if not t.endswith("/"):
                continue
            out += [
                (v, t, sub)
                for sub in _try_listing(f"{base}{v}targets/{t}", cache)
                if sub.endswith("/")
            ]
        return out

    def one(p):
        v, t, sub = p
        rows = doc_rows(
            f"{base}{v}targets/{t}{sub}sha256sums",
            cache,
            "openwrt",
            name=f"{t}{sub}".rstrip("/"),
            version=v.rstrip("/"),
        )
        # The subtarget document also lists packages/*.ipk — that's a
        # package tier, not install media. Keep top-level images only.
        return [r for r in rows if "/" not in r[5]]

    return pmap(one, pmap(targets, vers))


def proxmox(cache):
    """One cumulative SHA256SUMS covering every ISO they have shipped."""
    for row in doc_rows("https://enterprise.proxmox.com/iso/SHA256SUMS", cache, "proxmox"):
        name = row[5]
        version = m.group(1) if (m := re.search(r"(\d+\.\d+[\w.-]*)", name)) else "-"
        yield row[:4] + (version,) + row[5:]


def zorin(cache):
    base = "https://plug-mirror.rcac.purdue.edu/zorin-iso/"
    for d in _try_listing(base, cache):
        if VERSION_DIR.match(d):
            yield from doc_rows(f"{base}{d}SHA256SUMS.txt", cache, "zorin", version=d.rstrip("/"))


def centos_stream(cache):
    """mirror.stream.centos.org: per-ISO .SHA256SUM sidecars."""
    base = "https://mirror.stream.centos.org/"
    for d in _try_listing(base, cache):
        if not re.match(r"^\d+-stream/$", d):
            continue
        for arch in _try_listing(f"{base}{d}BaseOS/", cache):
            iso_dir = f"{base}{d}BaseOS/{arch}iso/"
            for f in _try_listing(iso_dir, cache):
                if f.endswith(".SHA256SUM"):
                    yield from doc_rows(iso_dir + f, cache, "centos-stream", version=d.rstrip("/"))


def _try_listing(url, cache):
    try:
        return [d for d in listing(url, cache) if d.endswith("/") or "." in d]
    except urllib.error.HTTPError as e:
        _absent(e)
        return []


ADAPTERS = [
    ubuntu,
    ubuntu_cdimage,
    debian,
    debian_archive,
    fedora,
    archlinux,
    almalinux,
    rockylinux,
    linuxmint,
    kali,
    openbsd,
    freebsd,
    netbsd,
    void,
    alpine,
    opensuse,
    qubes,
    raspberrypi,
    endeavouros,
    openwrt,
    proxmox,
    zorin,
    centos_stream,
]

MAX_FIELD = 512  # sanity cap; parquet has no fixed widths


def field(s, what):
    if "\t" in s or "\n" in s:
        raise ValueError(f"{what} contains separator: {s!r}")
    if len(s.encode()) > MAX_FIELD:
        raise ValueError(f"{what} over {MAX_FIELD} bytes: {s!r}")
    return s if s else "-"


def main():
    outdir = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/media"
    )
    cache = outdir / "dumps"
    cache.mkdir(parents=True, exist_ok=True)

    # Every adapter runs concurrently (each talks to its own hosts);
    # results are then processed in catalog order so canonical-first
    # dedup stays deterministic.
    from concurrent.futures import ThreadPoolExecutor

    def run(adapter):
        t0 = time.monotonic()
        rows = list(adapter(cache))
        print(
            f"  {adapter.__name__}: {len(rows):,} rows in {time.monotonic() - t0:.0f}s",
            file=sys.stderr,
            flush=True,
        )
        return rows

    with ThreadPoolExecutor(len(ADAPTERS)) as ex:
        futures = [(a, ex.submit(run, a)) for a in ADAPTERS]
        results = []
        for adapter, fut in futures:
            try:
                results.append((adapter, fut.result()))
            except Exception as e:
                print(f"  warning: {adapter.__name__} failed: {e}", file=sys.stderr, flush=True)
                results.append((adapter, []))

    out = outdir / "media.tsv.gz"
    seen = set()
    counts = {}
    skipped = 0
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for adapter, rows in results:
            n0 = sum(counts.values())
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
                            field(witness, "witness"),
                            scheme,
                            digest,
                            field(name, "name"),
                            field(version, "version"),
                            field(filename, "filename"),
                            field(loc, "loc"),
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
            kept = sum(counts.values()) - n0
            if kept != len(rows):
                print(
                    f"  {adapter.__name__}: kept {kept:,} of {len(rows):,} after dedup",
                    file=sys.stderr,
                    flush=True,
                )
    per = ", ".join(f"{w} {n:,}" for w, n in sorted(counts.items()))
    print(f"wrote {out}: {sum(counts.values()):,} rows ({per}), {skipped} skipped", file=sys.stderr)
    print(out)


if __name__ == "__main__":
    main()
