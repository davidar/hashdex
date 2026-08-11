# hashdex — bulk source inventory

*The verified inventory behind the design's federate-first rule: where
do URL→hash dumps already exist, so we can invert them ourselves
without ever fetching content? Every claim marked "verified" was
checked by direct HTTP probe or document fetch (baseline sweep
2026-08-01; second sweep 2026-08-12: install media, NSRL deep-dive,
CIRCL demotion, ArchiveTeam corpus, per-distro package indexes);
UNVERIFIED flags are honest gaps, not oversights.*

**Admission rule for this list:** ingest cost must scale with metadata,
never with content, and new-algorithm support must never imply re-fetch.
Sources that would make us the hasher of record are excluded by
construction.

**Legend:** 🔀 = multi-hash rows (one row carries ≥2 digest algorithms for
the same bytes → free cross-algorithm crosswalk edges, no content needed).
🪤 = wrapper-hash trap (digest is not of the raw bytes; must be modeled as
its own scheme).

---

## Tier 0 — aggregators (one ingest, many ecosystems)

### deps.dev BigQuery (Google Open Source Insights) 🔀
- `bigquery-public-data.deps_dev_v1` — npm, Go, Maven, PyPI, Cargo, NuGet.
- Dedicated `PackageVersionHashes` table + `Hashes` array on
  `PackageVersions` (npm sha1+sha512; Maven sha1; PyPI sha256; per-system
  coverage varies). ⚠️ Go rows are dirhash H1 (see Go 🪤).
- Also `PackageVersions.Attestations` pre-joins Rekor attestations.
- License CC-BY 4.0. Snapshot model, ~weekly (UNVERIFIED cadence).
- REST API: `GetVersion` returns no hashes, **but `GET /v3/query`
  accepts `hash.type` (MD5/SHA1/SHA256/SHA512) + `hash.value`
  (base64) and answers inverse lookups live** across npm, Cargo,
  Maven, NuGet, PyPI, RubyGems (verified 2026-08-01; ≤1000 results,
  one artifact may map to many versions). A free, Google-operated
  inverted index over six registries — federate it, don't ingest it.
  BigQuery remains the bulk path.
- Related: `digest.ecosyste.ms` is an on-demand tarball-URL hasher —
  not an index, but a third-party witness/edge-minting service.

### ecosyste.ms open data
- Full PostgreSQL dumps: `https://packages.ecosyste.ms/open-data` — latest
  `packages-2026-02-05.tar.gz`, 63.7 GB, CC-BY-SA 4.0. 70+ registries,
  version rows keep upstream hash fields (npm shasum+integrity etc.).
- Irregular cadence (2023-08 … 2026-02) — use as long-tail backfill,
  direct feeds for freshness. Live API works with a proper User-Agent.

### Rekor BigQuery (Google) — ready-made inverted index
- `bigquery-public-data.rekor` (announced 2025-10-15). **`IndexKeys`
  table: `sha256:<digest>` (or email) → EntryUUID** — an inverted hash
  index over ~2.3B signing events, maintained for us.
- `Entries`, `Identities` (Fulcio OIDs: issuer, source repo, owner),
  `Artifacts` (in-toto bodies: subject name + digest).
- Live updates: Pub/Sub topic `new-entry` in GCP project `project-rekor`.
- npm provenance, PyPI PEP-740, Homebrew attestations all flow through
  Rekor → this one dataset covers them in bulk; per-registry attestation
  endpoints become verification-only.

### CIRCL hashlookup 🔀 — demoted to hint layer (2026-08-12)
- Aggregates NSRL + Windows builds + Ubuntu/CentOS/Fedora/Kali/OpenSUSE/
  OpenBSD + CDNJS + Snap store — **published source list is incomplete**:
  live lookups also return Debian and Alpine records (verified), and
  some records carry no `source` field at all.
- REST + DNS lookup (md5/sha1/sha256/sha512); bulk Bloom filter
  `https://cra.circl.lu/hashlookup/hashlookup-full.bloom` (956 MB,
  418M SHA-1 keys; anonymous direct fetch works but the host is slow
  — we mirror it on HF).
- Bloom = membership only; metadata via API. Published filter frozen
  since **Oct 2023** (docs claim monthly); live DB reports 6.4B keys,
  NSRL 2023.09.2.
- 🪤 **Records are keyed on SHA-1 internally** (kvrocks primary key;
  md5/sha256 are secondary indexes into sha1 records) — a sha256
  lookup of one SHAttered half returns the *other* half's record
  verbatim, returned SHA-256 field not matching the query (verified
  live 2026-08-12). Architectural, not a data glitch.
- **Verdict: keep the mirrored bloom as a free corroborating filter;
  never source claims from the API — go direct to its sources
  (NSRL + the per-distro indexes below).**

---

## Tier 1 — software artifacts (the v1 scope fence)

### Language registries

| Source | Bulk path | Hashes | Scale | Cadence |
|---|---|---|---|---|
| **PyPI** 🔀 | `bigquery-public-data.pypi.distribution_metadata` | md5+sha256+blake2_256 | 20.4M files | real-time inserts |
| **npm** 🔀 | `_changes` (gutted 2025-05: no `include_docs`) + per-packument fetch; or Tier-0 aggregators | sha1 (`shasum`) + sha512 (`integrity`, ≥~2017) | 4.25M pkgs / ~73M versions | real-time |
| **crates.io** | `https://static.crates.io/db-dump.tar.gz` (1.65 GB) | sha256 only | 309k crates / ~1.9M versions | daily |
| **Go sumdb** 🪤 | tlog tile crawl of `sum.golang.org` (~58.5M leaves, low GB) | H1 dirhash of *extracted* tree + hash of .mod — never matches raw-bytes corpora; own scheme | 58.5M module-versions | continuous |
| **Maven Central** | Central Index `.index/nexus-maven-repository-index.gz` (3.15 GB, weekly) or deps.dev | sha1 (index); per-file .md5/.sha1 sidecars, .sha256/.sha512 newer uploads only | ~15M+ GAVs (UNVERIFIED) | weekly |
| **RubyGems** | S3 `rubygems-dumps` weekly Postgres dump (648 MB) | sha256 (base64) in `versions` | ~185k gems / ~1.4M versions | weekly |
| **NuGet** | catalog0 append-only log (22,882 pages, cursor crawl) | sha512 per .nupkg (leaf fetch required) | 472k pkgs / ~7–8M versions | real-time |
| **conda** 🔀 | `repodata.json[.zst]` per channel/subdir | md5+sha256 both | conda-forge ~1.5M+ files (UNVERIFIED) | continuous |
| **CPAN** 🔀 | rsync mirror → per-author `CHECKSUMS` files | md5+sha256, each for gz AND ungz (bonus edges) | ~45k dists (UNVERIFIED) | continuous |
| **Hackage** 🔀 | `01-index.tar.gz` (137 MB, appended; range-request incremental) | TUF targets md5+sha256 (both-present UNVERIFIED) | 19.4k pkgs | continuous |
| **Homebrew** | `formulae.brew.sh/api/formula.json` (31 MB) | sha256; bottle URL **is** `ghcr.io/...blobs/sha256:<digest>` | ~7.5k formulae × platforms + casks | multiple/day |
| **CRAN** | `src/contrib/PACKAGES` | md5 only; archived versions unhashed — weak | 24.5k pkgs | continuous |
| **Packagist** | — | `shasum` empty; GitHub zipballs = unstable bytes. Near-useless; `reference` gives git-commit edges only | 462k pkgs | — |

Notes:
- **PyPI's URL is derivable from the hash itself**:
  `files.pythonhosted.org/packages/{b2[:2]}/{b2[2:4]}/{b2[4:]}/{filename}`
  where `b2` = blake2_256 hex. Verified empirically. Same property as
  Homebrew bottles. Hash→URL with zero inference.
- PEP 691 simple JSON (sha256 only) + bandersnatch `release-files=false`
  are the non-BigQuery PyPI paths.
- npm packuments pre-2017 have sha1 only.

### Linux distros / OS packages

- **Ubuntu** 🔀 — **richest cross-algorithm source in the family**:
  Packages/Sources stanzas carry **MD5+SHA1+SHA256+SHA512** (4-way, one
  .xz index per suite/arch) + pool `Filename` → direct URL. Verified
  2026-08-12 on noble binary-amd64: all four digests present per
  stanza, 100% coverage (restricted 492/492); `Contents-*.gz` and
  `.manifest` files confirmed hashless; no Ubuntu analogue of
  dedup.debian.net exists.
  `old-releases.ubuntu.com` back to 2004. Launchpad API adds the full
  publication history incl. **all PPAs** (`binaryFileUrls` → url+sha1+
  sha256 per file) — API-only, paginated, no dump.
- **Kali** — same Debian Packages format (verified 2026-08-12):
  MD5+SHA1+SHA256 per .deb (3-way, no SHA512), `http.kali.org/kali/
  dists/kali-rolling/<comp>/binary-<arch>/Packages.gz`. Zero marginal
  parser cost next to Ubuntu/Debian.
- **msys2** — `repo.msys2.org/<repo>/<arch>/<repo>.db.tar.zst`
  (~0.5 MB each): `%SHA256SUM%` per `.pkg.tar.zst` artifact, 100%
  coverage, ~10K rows across msys/mingw64/ucrt64/clang64/mingw32.
  Verified 2026-08-12. A handful of GETs.
- **Debian** 🔀 — current Packages: MD5+SHA256 (SHA1 dropped ~2016;
  pre-2016 indexes via snapshot.d.o carry all three). `Filename` → pool
  URL. **buildinfos.debian.net**: every buildd-built .deb since ~2016
  with **MD5+SHA1+SHA256** (3-way); bulk enumerator
  `buildinfo-pool.list` (307 MB, regenerated daily).
- **snapshot.debian.org** — SHA1-addressed farm, 2005→present, ~6h
  granularity. `/mr/file/<sha1>/info` is a per-hash inverted index
  already; **no bulk dump** — the bulk path is harvesting timestamped
  Packages/Sources indexes from `archive/debian/<timestamp>/`. Rate
  limiting reportedly removed ~Aug 2024 (UNVERIFIED; crawl politely).
  `metasnap.debian.net` time-bounds URL validity.
- **Fedora** — repodata primary.xml: sha256 pkgid + location href
  (76k pkgs in F44); archives.fedoraproject.org keeps EOL trees back to
  Fedora Core. **Koji**: ~46.4M RPMs / 2.95M builds, every build ever
  (incl. never-shipped); `getRPMChecksums` → md5+sha256 🔀 but
  XMLRPC-per-RPM only, no dump.
- **RPM repodata carries `<rpm:header-range>` per package** (verified
  2026-08-12 on CentOS Stream 9, Alma 9, Rocky 9, openSUSE
  Tumbleweed): primary.xml hands over the exact byte range for the
  RPM header — the `fedora_headers.py` FILEDIGESTS range-GET
  technique ports to all of them with zero discovery cost. filelists
  .xml on all four = paths only, no digests (confirmed). openSUSE:
  pkgid is **sha512** and repodata is `.zst` not `.gz`.
- **Arch** 🔀 — repo .db files (sha256 only today); **Arch Linux
  Archive**: daily .db snapshots back to 2013, and 2013–~2022 DBs carry
  **MD5+SHA256** → historical 2-way edges. Archive keeps every package
  version + sig. Don't hammer: robots.txt, "not a regular mirror".
- **Alpine** 🪤 — **trap, verified empirically**: APKINDEX `C:Q1…` is
  the SHA-1 of the *control segment only*, not the whole .apk —
  unusable for whole-file hash↔URL. Whole-file hashes need another
  source (or apk v3 .adb, not yet served for stable branches).
- **openSUSE** — Tumbleweed primary.xml uses **sha512** pkgid (52k
  pkgs); `download.opensuse.org/history/` snapshots appear to be a
  rolling ~30-day window (UNVERIFIED). OBS `/public` API: source files
  MD5 per-request; binary listings carry no hashes.
- **Nix / cache.nixos.org** 🪤(domain) — narinfo per store path:
  `FileHash` (compressed NAR) + `NarHash` (uncompressed NAR), both
  sha256 — a compressed↔uncompressed edge pair, but in the **NAR
  domain**, not raw-file. Enumerate via `channels.nixos.org/<ch>/
  store-paths.xz` (205k paths for 25.05); `WantMassQuery: 1` explicitly
  blesses mass narinfo fetches. S3 bucket is requester-pays; >1B
  objects, >600 TB; numtide/narwal promises published inventory dumps
  "soon" (UNVERIFIED). Bonus: nixpkgs fixed-output derivations map
  upstream source URL→SRI hash, greppable at repo scale.
- **F-Droid** 🔀 — `index-v2.json`, GPG-signed (verified 2026-08-12:
  repo 55.5 MB = 12.6K APK versions, archive 108.1 MB = 80.0K):
  per APK **sha256 + IPFS CIDv1** (a free cross-*namespace* edge) +
  source-tarball sha256 (~92.4K) — **~185K strong-digest rows in 2–3
  GETs**, preimage verified raw bytes, claim URLs live
  (`f-droid.org/repo|archive/<name>`). IzzyOnDroid third-party repo
  speaks the same format (14 MB).
- **Microsoft Update (via ArchiveTeam)** — `github.com/ArchiveTeam/
  microsoftupdate-items` publishes the tracker item list:
  `added/bin{1..28}.txt.zst` (~28 MB) = **419,130 unique
  `bin:<base32-sha1>:<msdownload path>` rows** (RFC4648 base32 of raw
  sha1, WARC-digest convention; preimage byte-verified twice, incl. a
  hashless-filename 1999-era cabpool file — keys come from
  Microsoft's own update metadata). Plus `raw/WUDrivers.csv.zst.*`
  (197 MB): ~1.8M rows sha1 → vendor/models/hardware IDs/driver
  version/date/size. Claim URL by construction:
  `download.windowsupdate.com/<path>` — verified live even for 2004
  files. The biggest Windows-binary gap-filler short of NSRL;
  **sha1-only** (weak tier). The IA mirror collection (3,360 items,
  ~36 TB, with CDX) is access-restricted — unusable.
- **Snap store** — **negative** (verified 2026-08-12): per-revision
  digest is **SHA3-384** (a scheme hdx doesn't mint), served only by
  `/v2/snaps/info/<name>`; the find endpoint strips it and no
  enumerate-all endpoint exists. Effectively unharvestable.
- **cdnjs** — `github.com/cdnjs/SRIs` (MIT, ~228 MB): per-library/
  per-version JSON of **per-contained-file SRI sha512** — the only
  per-file web-asset corpus found, one git clone. ⚠️ Frozen at
  2021-04-26; post-2021 = ~10^5–10^6 API calls (live API serves
  per-version SRI but no bulk). Verified 2026-08-12.
- **reproduce.debian.net** 🔀 — rebuilderd attestations: per rebuilt
  .deb **sha256+sha512** + GOOD/BAD verdict + direct pool URL; bulk
  package list in one request (~36k records/arch/release), attestation
  fetch per build. This is the "rebuilt-identically-by" claim source
  the design calls for, live. (Arch's equivalent exists but its API
  was flaky/unverifiable.)

### Install media / OS release images (2026-08-12 sweep)

**Nobody aggregates ISO hashes** (verified: quickget ships per-distro
checksum-endpoint *recipes* for ~100 OSes — code, not data; osinfo-db
has URLs + volume-id regexes, zero hashes). But every distro publishes
per-release checksum documents, and the majors' trees enumerate full
history — so hashdex compiles the aggregate itself
(`tools/install_media.py`, quickget-seeded catalog; the checksum
document URL is the claim URL by construction). Verified endpoints:

- **Ubuntu**: `releases.ubuntu.com/<ver>/SHA256SUMS` +
  `old-releases.ubuntu.com/releases/<codename>/` (SHA256SUMS from
  ~dapper on; warty–edgy are MD5SUMS-only). Also a **GPG-signed
  simplestreams index** `releases.ubuntu.com/streams/v1/
  com.ubuntu.releases:ubuntu.json` (+`:ubuntu-server`) — sha256 +
  size + path per image incl. zsync/manifest sidecars, LTS products.
- **Fedora**: `dl.fedoraproject.org/pub/fedora/linux/releases/<N>/
  <Edition>/<arch>/iso/*-CHECKSUM` — but old release dirs on dl are
  **empty stubs**; real history is `archives.fedoraproject.org/pub/
  archive/fedora/linux/releases/<N>/…`, and pre-~F21 the CHECKSUM
  sits in `<Edition>/<arch>/` with **no `iso/` subdir** (verified
  F20). Oldest releases are SHA1SUM-era.
- **Arch**: `archlinux.org/releng/releases/json/` — **every monthly
  ISO ever in one GET**, sha256 (null for the oldest).
- **Debian**: `cdimage.debian.org/debian-cd/current{,-live}/<arch>/
  iso-*/SHA256SUMS`; archive under `/mirror/cdimage/archive/`.
  SHA512SUMS also published (same dir, unjoined — one witness file
  per scheme).
- **Rocky**: `dl.rockylinux.org/vault/rocky/<ver>/isos/<arch>/
  CHECKSUM` — vault = every point release. **Alma**:
  `repo.almalinux.org/almalinux/<ver>/isos/<arch>/CHECKSUM`.
- **Kali**: `cdimage.kali.org/kali-<ver>/SHA256SUMS` — full history.
- **Mint**: `mirrors.kernel.org/linuxmint/stable/<ver>/sha256sum.txt`
  (+ `linuxmint/debian/` for LMDE).
- **OpenBSD**: `ftp.openbsd.org/pub/OpenBSD/<ver>/<arch>/SHA256`,
  BSD-format hex (the CDN keeps ~3 releases; ftp.openbsd.org keeps
  all). 🪤 parser gotcha: `<ver>/packages/<arch>/SHA256` digests are
  **base64** while install-set files are hex, same tree.
- **FreeBSD**: `download.freebsd.org/releases/<arch path>/ISO-IMAGES/
  <ver>/CHECKSUM.SHA256-*`. **Void**: dated dirs
  `repo-default.voidlinux.org/live/<YYYYMMDD>/sha256sum.txt`.
  **Proxmox**: one cumulative `enterprise.proxmox.com/iso/SHA256SUMS`.
  **Zorin**: purdue mirror `zorin-iso/<ver>/SHA256SUMS.txt`.
  **CentOS Stream**: `mirror.stream.centos.org/<N>-stream/BaseOS/
  <arch>/iso/*.SHA256SUM` sidecars.
- Sidecar-per-file tail (deferred): openSUSE `.sha256` sidecars,
  NixOS channels, Tails, KDE neon, haiku/ghostbsd/solus/openindiana;
  SourceForge-hosted checksums (redirect chains); sha512-only
  witnesses (EndeavourOS, Manjaro, Gentoo `.DIGESTS`, Mageia);
  md5/sha1-only (Slackware, NetBSD, Trisquel) → weak tier.
- Related finds: 203 MSDN Windows-ISO sha1s on the ArchiveTeam wiki
  (`Microsoft` page); **Redump DATs** (`redump.org/downloads/`, 60
  systems, crc32+md5+sha1 per disc image, no sha256, no artifact
  URLs — preservation-grade attestor, weak tier). 🪤 BitTorrent v1
  infohash/piece-sha1s are never whole-file digests; v2 per-file
  pieces-root is a 16 KiB-leaf sha256 merkle (a potential future
  scheme hdx could mint itself).

### Security / forensic hash sets

- **NSRL RDS (NIST)** 🔀 — public domain-ish, anonymous S3
  (`s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_<ver>/`). RDSv3 SQLite
  only (text format publication ended). Deep-dive verified 2026-08-12:
  - **Minimal sets exist for all four corpora** (modern/legacy/android/
    ios), 43.3 GB zipped / 327.6 GB unpacked total, **209,541,002
    distinct sha256** (modern 72.9M + legacy 69.7M + android 34.2M +
    ios 32.8M), 804M file rows. Full sets (211 GB zipped) add a
    METADATA table: in-product **paths**, mtime, and `extractee_id` +
    `recursion_level` 0–10 — NSRL digests containers AND their
    extracted contents (covers tarball-tier + peek-inside at once).
  - Schema (extracted from the live zip by range-read): `FILE(sha256,
    sha1, md5, crc32, file_name, file_size, package_id)` ⋈
    `PKG/OS/MFG` (product name, version, OS, vendor, language, app
    type) — claims even in minimal; `DISTINCT_HASH` view = the 4-way
    crosswalk table, pre-defined by NIST.
  - Cadence: full each March; quarterly `.sql` deltas (modern_minimal
    delta ~240 MB) applied to an *unmodified* prior full, verified via
    published `dbhash` values.
  - ⚠️ License clause: modified redistributions must **remove**
    references to NIST as producer — word derived-artifact cards
    carefully. ⚠️ Corpus is ~1-in-400k internally inconsistent
    (verified: one sha1+md5 pair carrying two sha256 values) — never
    let a single row weld clusters. Rows are UPPERCASE hex.
  - 91 MB `RDS_2021.12.2_curated.zip` is the practical smoke-test DB.
    The old sha1→sha256 mapping + block-hash zips 403 (and are
    obsolete — RDSv3 carries sha256 natively). NSRL-CAID: excluded.
- **MalwareBazaar (abuse.ch)** 🔀 — hourly full CSV export (auth-key since
  2025-06, free): sha256+sha1+md5+imphash+ssdeep+tlsh per row + malware
  family. ~1.1M samples. ⚠️ License no longer clearly CC0 post-Spamhaus
  (UNVERIFIED redistribution rights).
- **URLhaus** — payload md5+sha256 → distributing URL, first/last seen.
  ThreatFox exports cover trailing 6 months only.
- **VirusShare** — md5-only, label-free chunk lists; membership flag only,
  low value. MalShare/Hybrid-Analysis: daily feeds only, marginal.
- **CISA MARs** — STIX JSON per report, public domain, tiny; enrichment
  only.

### Attestation / transparency logs

- **Rekor v1** (`rekor.sigstore.dev`) — ~2.31B entries (verified via
  `/api/v1/log`); still default log, 1-year notice promised before
  shutdown. API-scale extraction infeasible → use Rekor BigQuery (Tier 0).
  Entries = signing *events*, not unique artifacts; junk/test hashes
  common (top IndexKey = a conformance-test file, 5.6M entries).
- **Rekor v2** (tiled, GA 2025-10) — `log2025-1.rekor.sigstore.dev`,
  47.7M entries, **cleanly bulk-clonable** via C2SP tlog-tiles
  (`/tile/entries/<n>`, ~125 GB full). v2 dropped the search index —
  hash lookup now *requires* a mirror like us. Discover shards via
  Sigstore TUF root, don't hardcode.
- **PyPI PEP-740** — per-file Integrity API; bulk via Rekor. (JSON API's
  `provenance` field can be null where provenance exists — use Integrity
  API.)
- **npm provenance** — per-version attestations endpoint (subject digest =
  sha512 matching `dist.integrity`); bulk via Rekor/deps.dev.
- **Homebrew attestations** — per-digest GitHub API (auth, 5k/h);
  enumerate digests from formula.json; also in Rekor.
- **Pixel / Google system-APK binary transparency** — tiny logs, single
  GET; VBMeta digest 🪤 (not the downloadable zip's hash).
- **LVFS firmware transparency** (`fwupd.org/ftlog/lvfs/`) — firmware
  archive hashes; small but high-value niche. Sigsum: sha256+pubkey only,
  no metadata — skip.
- **OpenTimestamps** — 🪤 **trap, excluded**: calendars are bulk-
  downloadable (105 GB on archive.org, CC0, + live backup endpoints,
  ~513M commitments) but commitments are nonce-blinded — original file
  hashes unrecoverable. Verification resolver only, not an index source.

### Containers / OCI

- **No bulk dataset exists** (verified negative for a Docker Hub BigQuery
  dataset). Digest→name is per-registry-API-only:
  - Docker Hub: `HEAD /v2/<name>/manifests/<tag>` returns digest and
    **does not count as a pull**; authenticated free account = unlimited.
    Tags API gives tag→digest incl. per-arch. No global catalog — need
    name lists first.
  - Quay.io has an enumerable public-repo catalog; GHCR/GCR/ECR-public do
    not.
  - Academic seeds (Zenodo 2020 crawl 39.4 GB CC-BY; VUB MSR 2023) are
    stale and digests rot as tags repush.
- Defer: demand-driven probing fits the design better than a census here
  (this is the one family where the census failure mode looms).

---

## Tier 2 — source code

### Software Heritage graph dataset 🔀 — the crosswalk crown jewel
- `s3://softwareheritage` — anonymous, free, **not** requester-pays
  (verified). Latest full export 2026-06-04: 58.7B nodes / 1.1T edges;
  ORC 33 TiB, compressed WebGraph 16 TiB. ~quarterly.
- `content` table: **sha1 + sha1_git + sha256 + blake2s256** per row —
  4-way crosswalk edges for **29.3B blobs**, free.
- **Content→origin is precomputed**: `derived_datasets/<v>/contents/`
  Parquet — id, popular filename, first-occurrence origin/revision/
  timestamp. 2025-10-08 version: 313 GiB, ~23B rows (verified via live
  Parquet footer). ⚠️ 2026-06-04 copy incomplete as of 2026-08-01 — use
  2025-10-08. Node-id↔SWHID via `derived_datasets/<v>/nodes/` (1.8 TiB).
- Metadata-scale recipe: contents parquet (313 GiB) + nodes mapping +
  column-pruned ORC `content` hash columns + `origin` table (437M URLs).
  No 33 TiB download, no trillion-edge join. Athena-queryable in place
  (~$5/TiB scanned).
- REST API: 120 req/h anon / 1200 auth — useless at scale; dataset is the
  only path. License CC-BY 4.0 (graph) + bulk-access ToU + ethical
  charter; hash→origin indexing squarely within intended use.
- Caveat: an SWH "URL" is origin repo + path + ref, not a raw-bytes HTTP
  URL (forge raw URLs often derivable; sha1_git = git object id joins
  directly against git-native corpora).

---

## Tier 3 — the web

**Scope policy: stable static files only.** The
index wants hashes where two people could plausibly hold identical copies
of the same bytes; per-visit dynamic content is noise. Two filters, both
computable from index metadata alone:

1. **MIME cut**: drop `text/html` &co. by default (measured on
   CC-MAIN-2026-30: HTML+XHTML ≈ **99.2%** of captures, not the ~70%
   folklore — CC crawls pages, never subresources, so there are almost
   no js/css/images to keep; the surviving ~0.8% is documents, 74% PDF);
   keep `application/*`, images, audio/video, fonts, archives, wasm.
   Also drop `content_truncated IS NOT NULL` (~9% of PDFs): CC caps
   payloads ~1 MiB and digests the truncated bytes — poison keys.
2. **Recurrence rescue**: admit *any* MIME type whose digest recurs —
   same digest at one URL across ≥2 crawls, or at ≥2 URLs. Recurrence is
   demonstrated stability, and it rescues genuinely-static HTML (mirrored
   RFCs, docs) that the MIME cut would wrongly kill.

Corollary: **full crawl history is not retained, only scanned.** Old
crawls are mostly dead URLs, worthless as coverage — but they're cheap
recurrence *evidence* (Athena over CC's parquet in place). Ingest scans
history; the index keeps only what history stabilizes.

*(Shared convention: CC, Wayback, Arquivo.pt, EOT, Archive-It all use
SHA-1 of the WARC payload, base32 — the whole family joins on one key.
Wikimedia is SHA-1 base36; IA files are md5/sha1 hex. SHA-256+ edges for
web content come only from elsewhere — e.g. SWH for anything that's also
in a repo. File-hosting sources — IA items, Wikimedia uploads — are
versioned static files by construction and skip the stability filter.)*

- **Common Crawl** — index-only download: CDXJ
  `s3://commoncrawl/cc-index/collections/CC-MAIN-*/indexes/` (300 shards,
  ~245 GB gz/crawl) or Parquet `cc-index/table/` (~300 GB/crawl),
  Athena-queryable in place. `digest` = payload SHA-1 base32, single
  algorithm (no SHA-256 as of CC-MAIN-2026-30; verified). ~2.1B pages/
  crawl, every 4–5 weeks, back to 2013 (~100 crawls). Free HTTPS, no AWS
  account needed. Gotchas: pre-2025-03 payloads truncated at 1 MB (digest
  is of truncated bytes); `robotstxt`/`crawldiagnostics` subsets mixed
  into CDX — filter by status; no revisit records (good: every capture
  carries a full digest).
- **Internet Archive / Wayback** — **no bulk CDX for wayback, period**
  (~1T captures; API-only, rate-limited; ARCH researcher service is
  paid/contract). Wayback CDX has `warc/revisit` dedup records.
  Per-item route: 124.29M public items (verified via Scrape API), each
  `_files.xml` / Metadata API carries **md5+sha1+crc32 per file** 🔀
  with deterministic URLs — O(items) polite sweep ≈ months, or
  lazy/demand-driven.
- **IA census** (verified 2026-08-12) — `archive.org/details/
  ia_census_201604`: `file_hashes_{md5,sha1}_20160411221100_public
  .tsv.gz` (4,971 + 5,836 MiB), format `identifier \t filename \t
  hash` (range-read verified), ~14.9M items; claim URL
  `archive.org/download/<id>/<file>` by construction. Joining the two
  files on (id,file) = two-hash single-witness rows, **both weak**.
  Frozen April 2016 — the third and last census; the 2016/2017
  ArchiveTeam census projects are identifier lists only.
- **ArchiveTeam collections = hash-indexed via CDX** (verified
  2026-08-12 with real bytes): every ArchiveBot item carries per-WARC
  `.os.cdx.gz` sidecars **plus an item-level merged `.cdx.gz`**; CDX
  `k` column = WARC payload digest, **base32 sha1**. archivebot
  collection alone = 89,596 items. Rows: sha1 → URL + timestamp +
  WARC path (wayback claim URL constructible). Weak tier; harvest =
  ~90K polite GETs.
- **IA bulk mechanics** (verified 2026-08-12): `s3.us.archive.org/
  <identifier>/<file>` answers GET (307 → datanode, Range + CORS
  open); Scrape API enumerates collections cursor-paged; blessed bulk
  client is the `internetarchive` CLI (`ia download --itemlist
  --glob`); every item also has a web-seeded torrent.
- **codearchiver** (ArchiveTeam-adjacent, verified 2026-08-12) — each
  git bundle in `archiveteam_codearchiver` has a sibling
  `*_codearchiver_metadata.txt` on IA (range-readable): complete
  `Object: <oid> blob|tree|commit|tag` inventory of the packfile +
  upstream `Input URL`. 1,362 sidecars / 2.9 GB / ~10–13M **sha1_git
  blob IDs**. Corpus (Linux kernel, codeaurora/Android,
  twitter/the-algorithm) is largely inside SWH already —
  second-witness value only. Source: `gitea.arpa.li/
  JustAnotherArchivist/codearchiver` (GitHub mirrors 404).
- **e621 db_export** — `static1.e621.net/data/db_export/posts.csv.gz`
  (1.9 GB, daily, 4-day retention): ~5.5–6.6M rows md5 + tags + size
  + ext; claim URL by construction `static1.e621.net/data/{m[0:2]}/
  {m[2:4]}/{md5}.{ext}` (verified live). md5-only + adult art booru —
  **attestor-taste call pending, not queued**.
- **Fatcat / IA Scholar** 🔀 — the scholarly-PDF jackpot: `archive.org/details/fatcat_snapshots_and_exports`,
  item `fatcat_bulk_exports_2024-02-18` contains
  `file_hashes.tsv.gz` (14.23 GiB) — schema
  `file_ident, release_ident, sha1, sha256, md5` (3-way,
  single-witness → edge-minting legal), **122.3M unique sha1 /
  122.2M sha256** measured on ingest; plus
  `file_export.json.gz` (23 GiB, adds URLs + mimetype + DOI-linked
  release ids) and `release_extid.tsv.gz` (10.7 GiB, DOI/PMID/arXiv
  crosswalk). Free HTTPS download, no auth. ⚠️ Fatcat is frozen —
  2024-02-18 is the **last** export (editing paused after IA
  cutbacks); treat as one-shot corpus. Metadata license CC0 per
  fatcat guide (UNVERIFIED — guide.fatcat.wiki unreachable).
  Ops note: IA item torrents are web-seeded by the same datanodes as
  HTTP (no external seeders for datasets like this) — for the
  multi-hundred-GB items (release_export_expanded: 216 GiB), parallel
  HTTP ranges (`aria2c -x16`) beat both single-stream curl and
  torrents; single-stream measured ~12 MB/s.
- **Scholarly-PDF dead ends & maybes**:
  **arXiv** S3/GCS manifests carry md5 per 500 MB *tar chunk* only,
  no per-PDF hashes (+ requester-pays $$, + PDFs regenerate/stamp so
  bytes drift) — content-scaled, excluded. **S2ORC / Semantic
  Scholar**: current API-gated dataset (ODC-By) documents no pdf
  hash field; v1's `pdf_hash` is deprecated/gone. **CiteSeerX**:
  effectively dead, never published dumps. **CORE** (core.ac.uk):
  300 GB+ dataset behind registration; ResourceSync metadata shows
  `rs:md hash="md5:…"` per resource — per-file md5 plausible,
  UNVERIFIED. **Zenodo**: per-file md5 in record API; monthly
  `/api/exporter` metadata dumps exist but whether file checksums
  are in the export JSON is UNVERIFIED.
- **Arquivo.pt** — **entire index published openly**:
  `https://arquivo.pt/datasets/cdxj/` — ~216 plain CDXJ files,
  **~12.4 TiB total**, >21B captures. SHA-1 base32. Rate limits with
  permanent-block teeth; citation requested.
- **End of Term archive** — `s3://eotarchive/` anonymous, **CC0**:
  CDXJ + Parquet indexes per election cycle (EOT-2024: 227 GiB CDXJ).
  US .gov every 4 years.
- **Wikimedia** 🖼 — `commonswiki-latest-image.sql.gz` (18.1 GB,
  2×/month): 145.3M files, `img_sha1` (base36) + filename; upload URL
  derivable via MD5-of-filename path scheme. Zero content fetches.
  ⚠️ Schema migration `image`→`filerevision` in flight (T28741); dump
  still ships `image` as of July 2026.
- **HTTP Archive BigQuery** — **negative**: no digest column in the
  schema; hashing response bodies ourselves would violate the admission
  rule. Excluded.
- National archives (UK etc.): closed/on-site CDX; nothing bulk-public
  found.

---

## Sizing and hosting (2026-08 estimates)

| Tier | Rows (order) | Compact sorted index |
|---|---|---|
| Software artifacts (registries+distros+NSRL+Rekor) | ~1–2B | ~100–300 GB |
| Source (SWH contents+origins) | ~25B | ~1.5–3 TB |
| Web, static-stable subset (CC + Arquivo + EOT + Wikimedia + IA files) | ~2–5B | ~200–500 GB |

Assumes ~50–80 B/row zstd in digest-sorted columnar form; the URL column
dominates (sorted-by-digest URLs compress poorly). The static-stable
policy above cuts the web tier ~10×: ~300–500M static-MIME rows per CC
crawl, deduped across crawls by digest, plus recurrence-admitted
stragglers. Full-history retention (would have been 10–30 TB) is
dropped by policy — the whole index now fits in ~1–3 TB.

Cost levers, in order:
1. **Query big sources in place.** CC-index and SWH already sit on AWS
   Open Data; Athena at $5/TB-scanned makes the entire historical CC
   extract tens of dollars of one-time query, not 25 TB through our NIC.
   The only real AWS toll is egressing the compacted result (~$90/TB),
   once per source. Rekor/PyPI/deps.dev live in BigQuery (1 TB/month
   free tier).
2. **Serve static, not a database.** Digest-sorted, prefix-sharded files
   on object storage; clients use HTTP range requests (Go-sumdb / HIBP
   model). Zero query compute, and prefix ranges give k-anonymity for
   free — closes the query-privacy open question. R2 (zero egress,
   $15/TB-mo): software tier ≈ $3/mo, current-web ≈ $50/mo, full history
   ≈ $200–450/mo. Hetzner box (~€50–110/mo) whenever a live resolver is
   wanted.
3. **Dumps ride free open-data hosting.** Internet Archive hosts open
   datasets gratis (the census precedent), Hugging Face hosts public
   datasets into TB range (verify current caps), AWS Open Data /
   Source Cooperative sponsorship is the endgame (CC and SWH's own
   route). Canonical dumps on free hosts; the landlord serves only the
   compact query index. Torrents as costless mirror channel.

Failure mode to avoid: a fat always-on database over 300B rows. Nothing
in the query pattern (point lookups by digest prefix) needs one.

---

## Cross-cutting findings

1. **Multi-hash rows mint crosswalk edges without bytes.** SWH (4-way ×
   29.3B), **Ubuntu Packages (4-way, incl. sha512)**, NSRL (4-way × 1.5B
   rows), PyPI (3-way × 20.4M), Debian buildinfo (3-way), npm, conda,
   CPAN (gz+ungz pairs), Hackage, IA files.xml, F-Droid (sha256+IPFS
   CID), NIST's dedicated sha1→sha256 table, MalwareBazaar (incl. fuzzy
   hashes). The original design notes
   assumed crosswalk edges require holding content — for whole-file
   coordinates the dumps already carry them. Hash-archive's re-fetch
   problem never existed for this class of edge.
2. **Sometimes the hash IS the URL** (PyPI blake2 path, Homebrew ghcr
   blobs, static.crates.io by name-version): those sources give
   availability claims by construction.
3. **Wrapper traps confirmed in the wild**: Go H1 dirhash, VBMeta
   digests, OTS blinded commitments, Packagist unstable zipballs, Alpine
   APKINDEX (2026-08-12, byte-verified twice: `C:Q1…` = sha1 of the
   *compressed control tar.gz segment*; `.PKGINFO` `datahash` = sha256
   of the *compressed data segment* — both unusable; real per-file
   sha1 hides in data-segment PAX headers, full-download-only), Nix
   NAR-domain hashes, BitTorrent v1 infohashes/piece-sha1s, Roblox CDN
   paths (md5 of asset bytes, verified, but per-asset API only — no
   dump). Encoding gotchas, same lesson: OpenBSD packages SHA256 files
   are base64 while its install-set files are hex; Snap is SHA3-384
   (foreign scheme, not a trap). Each is either its own crosswalk
   scheme or excluded. The lesson generalizes: **never assume a hash
   in the wild is of the raw bytes — verify the preimage definition
   per source before ingest.**
4. **The web-archive family shares one join key** (SHA-1 base32 payload
   digest) — CC, Wayback, Arquivo, EOT, Archive-It interoperate
   directly; it's also the family stuck hardest on SHA-1, which is where
   the collision-safe identity model earns its keep.
5. **Licenses are mostly friendly**: public domain (NSRL, CISA, EOT),
   CC-BY (deps.dev, SWH, CIRCL), CC-BY-SA (ecosyste.ms), CC0 (OTS dumps).
   Watch: abuse.ch post-Spamhaus ambiguity; IA ToS for the item-metadata
   sweep; Arquivo.pt rate limits.
