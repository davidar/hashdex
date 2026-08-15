# hashdex

**Given any content hash, return everything the world knows about it.**

`hdx` resolves hashes against the public inverted indexes the world
already maintains — and scans your disk against local membership
filters to tell you which of your files are publicly known bytes, and
what they actually are.

```
$ hdx 9dc7a584db576910856ac7aa5cffbaeefe9cf427
sha1:9dc7a584db576910856ac7aa5cffbaeefe9cf427
  circl-hashlookup     known file: hello-2.10.tar.gz.sig, 819 bytes
  software-heritage    archived source blob, 819 bytes
                       → https://archive.softwareheritage.org/swh:1:cnt:4072e401ab530bf73e060db9383d75e7b4e9a46b
  snapshot.debian.org  hello_2.10.orig.tar.gz.asc in debian/pool/main/h/hello (first seen 20221227T032939Z)
                       → https://snapshot.debian.org/archive/debian/20221227T032939Z/pool/main/h/hello/hello_2.10.orig.tar.gz.asc
  coordinates          md5:e6074bb23a0f184e00fdfb5c546b3bc2
                       sha256:4ea69de913428a4034d30dcdcb34ab84f5c4a76acf9040f3091f0d3fac411b60
                       sha1_git:4072e401ab530bf73e060db9383d75e7b4e9a46b …
```

```
$ hdx scan ~/papers
fatcat       ~/papers/abramowitz_and_stegun.pdf
             fatcat       scholarly file: "Handbook of Mathematical Functions…" (1988),
                          American Journal of Physics, doi:10.1119/1.15378
                          → https://web.archive.org/web/20120407023803/http://people.math.sfu.ca/~cbm/aands/abramowitz_and_stegun.pdf
fatcat       ~/papers/mackay.pdf
             fatcat       scholarly file: "Information Theory, Inference, and
                          Learning Algorithms" (2004), doi:10.1109/tit.2004.834752
                          → https://web.archive.org/web/20051013062140/http://www.inference.phy.cam.ac.uk:80/itprnn/book.pdf
…
68 files (182.5 MiB) — 15 known (104.3 MiB), 9 attributed, 53 unknown
  fatcat: 9 files    swh: 6 files
```

A scan attributes what it can name: local bloom filters decide which
files are *known*, then offline indexes plus range reads over published
datasets turn known digests into citations — no server, no API keys.
A warm rescan of ~200k files takes about a minute and touches no
network at all.

## Why

Every package registry, software archive, and transparency log already
maintains a mapping from content hashes to what-and-where. Nobody joins
them. hashdex federates over the indexes that exist, ingests digest
extracts where an inversion exists but isn't queryable, and only
self-inverts (from metadata, never content) where nobody else has.
It never downloads content to hash it — ingest cost scales with
metadata, full stop.

## Commands

| | |
|---|---|
| `hdx <hash>` | resolve: local walk over pulled datasets + observation store, then live backends (hex, base32, SRI, SWHID, `scheme:hex`); `--offline` skips the network |
| `hdx scan <paths>` | scan + attribute: hash files (persisted updatedb-style, so rescans are stat-only), check membership filters, cite what the indexes can name. An explicitly named container file gets the hashoscope: full recursive descent — gzip/xz/zstd/bzip2, tar, zip, ar/deb, rpm, cpio, squashfs, erofs, iso, nested any way — hashing every member in one streaming pass and identifying each like a file on disk (a pristine tarball no index has seen usually contains hundreds of files the indexes know). Unknown containers found under directory roots are descended too, demand-driven: anything a filter already recognizes stays closed. By default only formats readable in place are entered (tar, zip, ar, cpio, squashfs, erofs, iso — a `.tar.gz` stays closed); `--deep` adds compressed wrappers, `--shallow` disables descent. Descents are cached content-addressed by the container's sha256, so rescans replay them without re-reading. `--no-resolve` = membership census only; `-v` = full citation blocks; `--list unknown\|known\|all` = per-file lines |
| `hdx recipe <file>` | mint a reconstruction manifest from a container: its bytes as a verified splice of refs — member byte ranges the indexes actually name, claim URLs attached — plus a literal residue sidecar (zstd) carrying every byte no URL fetches. Compressed wrappers become compression nodes when a cataloged compressor reproduces them byte-exact (`gzip@0`, GNU gzip levels ± `--rsyncable` — the disarchive trick): a `.tar.gz` whose members the indexes name rebuilds from those refs plus its tar headers, recompressed to the identical file. Refs require claims: a member boundary no index verifies is just bytes, and its bytes ride in the sidecar, so recipe + sidecar + fetched refs rebuild the file with nothing else on hand. Verified byte-exact at mint: every ref re-read and re-hashed, every splice re-assembled, every recompression compared against the original. A file the indexes already name yields a one-line recipe. Writes `FILE.recipe.json` + `.recipe.residue`; a jigdo generalized to nested containers |
| `hdx recipe check <recipe> <dir>` | rebuild a recipe from blobs already on disk (matched by sha256, names irrelevant) and verify the result byte-exact; `--output` writes the rebuilt container. Never fetches — missing members are listed with their claim URLs, which is where to get them. Rebuilding `gzip@0` nodes shells out to GNU gzip (on PATH virtually everywhere; a wrong gzip fails the byte check loudly, never silently) |
| `hdx recipe jigdo <recipe>` | project a recipe into a `.jigdo` + `.template` pair that stock jigdo tooling consumes: claimed refs become fetchable parts, everything else rides in the template (libjte-compatible template 2.0 — `jigdo-file make-image` rebuilds the Debian DVD from our projection byte-identically) |
| `hdx coords <file> [--lookup]` | mint all six coordinates of a local file (md5, sha1, sha256, sha512, blake2s256, git blob); recorded as a local crosswalk observation |
| `hdx locate <hash>` | find local files by digest (inverse of `hdx <hash>`) |
| `hdx index pull <name>` | download a published claim dataset (fatcat, tarballs) for local + offline resolution — by default hdx range-reads the published parquet on demand; `hdx index rm` frees the copy |
| `hdx index verify [name]` | hash pulled copies and check them byte-for-byte against the published repo's own hash index (LFS sha256 per file); drifted files are quarantined and re-downloaded on the next pull |
| `hdx filters fetch [names\|--all]` | download published membership filters (no args: list what's available) |
| `hdx filters build <name> <scheme> <files>` | build a DCSO-format bloom from hex digest lines |
| `hdx filters fold <name>` | halve a filter's size in place, trading false-positive rate for space |
| `hdx filters list` / `hdx index list` | show what's installed |

`--json` on any command emits machine-readable output.

## Who gets told what

Privacy is a consent line, not a mode:

- **Offline by default where it matters**: membership checks and
  `scan`'s attribution walk run against local filters and indexes.
- **Dataset transports** (the fatcat scholarly index, release
  tarballs, the IA census) are range reads over static published
  parquet — the server sees byte offsets, never your digests — so
  `scan` uses them without asking. `hdx index pull` makes them local
  and fully offline.
- **Third-party APIs** (CIRCL, deps.dev, Software Heritage, Rekor,
  snapshot.debian.org) are only told your digests when you
  ask: single-hash `hdx <hash>` lookups query them, and batch scans
  need explicit `--online` consent (optionally restricted:
  `--online=circl,swh`). Per-scan politeness ceilings apply.
- `--offline` globally guarantees zero network.

Every answer line carries its attestor — hdx never presents an
aggregated answer as its own knowledge. Results are cached as
observations in `~/.cache/hashdex/`; errors are never cached.

Env: `SWH_TOKEN` raises the Software Heritage rate limit,
`HF_TOKEN` lifts anonymous Hugging Face limits for dataset range
reads.

## Per-source filters

Membership filters make `hdx scan` work offline and tell the resolver
which backends are worth asking. Beyond CIRCL's published bloom, we
build our own from public digest extracts:

- **Software Heritage** — 29.3B archived source-file sha256s (70 GiB
  filter, built for ~$3 of cloud compute by `tools/swh_extract_job.py`
  from SWH's public dataset — no content downloaded). Too big?
  `hdx filters fold swh` halves it (~2% false positives instead
  of 0.01%).
- **fatcat** — 122M scholarly-file hashes (sha1+sha256) from the
  Internet Archive's bibliographic catalog bulk export; the companion
  [fatcat-files dataset](https://huggingface.co/datasets/david-ar/fatcat-files)
  turns matches into full citations with archived-copy URLs.
- **IA census** — 150M per-file md5+sha1 rows covering every public
  Internet Archive item as of April 2016 (the only bulk hash
  inventory of IA ever published), as the
  [ia-census dataset](https://huggingface.co/datasets/david-ar/ia-census).
  Both digests are weak, so scan reports census matches as
  "consistent (sha1)" — a separate verdict tier that never claims
  verified identity — with the item's download URL as the claim.
- **deps.dev** — 172M package-artifact digests (sha1+sha256) from the
  BigQuery public dataset, free tier.
- **Rekor** — attestation subject digests from the BigQuery public
  dataset.
- **Fedora / RPM Fusion / VS Code repo** — `tools/fedora_headers.py`
  harvests per-file sha256 for every package **without downloading
  packages**: repo metadata publishes each RPM's header byte range,
  one HTTP/2 range GET per package fetches just the header, and its
  FILEDIGESTS tag lists every installed file's digest. ~100k packages
  → 2.5 GiB of headers → ~2.5 minutes → a 15 MiB filter that took one
  machine's `/usr` from 4% known (CIRCL's Oct-2023 bloom) to 93.7%.
- **Common Crawl** — document-type payload digests (PDF etc.) from
  one crawl's URL index.
- **Steam** — `tools/steam_manifests.py` parses the depot manifests
  Steam already cached on your disk (per-file sha1, the metadata
  SteamDB shows) — game content has no public URLs, so this one is
  build-your-own from your own library.

All of the above except Steam are published on Hugging Face and
installable with `hdx filters fetch <name>`.

Filter hits are probabilistic (default p = 10⁻⁴) and per-source, so a
scan line tells you *which* index knows the file. Confirm anything
important with `hdx <hash>`.

Some sources are exact witness indexes rather than filter-only:

- **Release tarballs** — every content-level source above indexes what
  is *inside* an archive, never the archive itself (Software Heritage
  unpacks tarballs; Fedora hashes installed files), so a pristine
  `hello-2.12.3.tar.gz` used to resolve to nothing. Debian sid,
  Homebrew, and GNU Guix all publish per-artifact checksums for the
  source archives they package: `tools/release_tarballs.py` harvests
  all three indexes (six metadata GETs, no content) into ~160k witness
  rows, published as page-indexed parquet
  ([release-tarballs](https://huggingface.co/datasets/david-ar/release-tarballs)).
  `hdx <hash>` point-reads it remotely by default and resolves to
  claims like "Debian sid packages these bytes as
  hello_2.12.3.orig.tar.gz" with a download URL — Guix's are
  content-addressed mirror URLs that name the hash itself. Debian rows
  carry md5 alongside sha256, a single-witness crosswalk edge.
  A companion bloom (`hdx filters fetch tarballs`, 359 KiB) routes
  scans to it; `hdx index pull tarballs` (~25 MB) makes the whole
  index local and offline.
- **Binary packages (.deb)** — the same idea for the packages install
  media and mirrors actually ship: `tools/deb_packages.py` harvests
  the apt `Packages` indexes of Debian (trixie + sid + security,
  udeb sub-indexes included), every Ubuntu release ever (supported
  suites on archive.ubuntu.com, all EOL codenames back to warty via
  old-releases — claim URLs stay live for dead releases), and Kali
  into ~2.9M witness rows with pool-path claim URLs, published as
  page-indexed parquet
  ([deb-packages](https://huggingface.co/datasets/david-ar/deb-packages)).
  Ubuntu rows carry md5+sha1+sha256+sha512 — 4-hash single-witness
  crosswalk edges. `hdx filters fetch debs` routes scans to it;
  `hdx index pull debs` (~100 MB) goes offline. This is what lets
  `hdx recipe` of a Debian install DVD attach fetchable claim URLs to
  93% of the image's bytes, offline — a verified, generalized jigdo.
- **RPM files** — the fedora bloom's big brother: `tools/rpm_files.py`
  keeps the header-range trick but records the full witness rows —
  every installed file's sha256 with its path, package, and the rpm's
  own checksum (so both `/usr/bin/bash` *and* `bash-….rpm` resolve),
  published as page-indexed parquet
  ([rpm-files](https://huggingface.co/datasets/david-ar/rpm-files)).
  Claim URLs point at the rpm in the repo. Scan answers become
  "Fedora 44 ships these bytes as /usr/bin/bash in
  bash-5.3.9-3.fc44.x86_64.rpm" instead of a bare filter tag.
  `hdx filters fetch rpm-files` routes scans to it; `hdx index pull
  rpm-files` (~1 GB) goes offline. New repos (EPEL, CentOS Stream,
  openSUSE, …) are one harvester list entry each.
- **Install media** — the images themselves. Every distro publishes
  checksum documents beside its releases (SHA256SUMS and friends) and
  nobody aggregates them, so `tools/install_media.py` does: 32
  witnesses — Ubuntu (+ every cdimage flavor), the full Debian
  cdimage archive, every Fedora release back to Fedora Core 1, Arch,
  Alma/Rocky/CentOS Stream, Mint, Kali, openSUSE, Alpine, the BSDs,
  Void, Qubes, Raspberry Pi OS, EndeavourOS, OpenWrt, Proxmox, Zorin
  — ~383k rows, full history wherever the tree enumerates it. The
  claim URL is the checksum document itself. Modern rows are
  sha256/sha512; pre-2007 media (Warty's MD5SUMS, Fedora Core's
  SHA1SUM) resolve through the weak "consistent with" tier, and
  Qubes' `.DIGESTS` documents co-state all four schemes in one
  witness row. Drop an ISO on `hdx` and it answers "Fedora releases
  these bytes as Fedora-Workstation-Live-44-1.7.x86_64.iso" with the
  CHECKSUM URL — offline with `hdx index pull install-media`
  (~25 MB).

## Build

```
cargo install hashdex   # binary is hdx
```

or from a checkout: `cargo build --release` (binary at
`target/release/hdx`), `cargo test`.

## Status

Early but real: the federated resolver, disk scanner, local hash
index, cross-source crosswalk walk, and ten filter families work
today. On the author's
machine the filters identify 68% of all files (by count) as publicly
known bytes — most of the remainder is content that only ever existed
there. The bigger arc — more sources, richer crosswalk edges, web-tier
coverage for the stubborn residue — is designed and not yet built.
