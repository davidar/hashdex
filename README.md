# hashdex

**Given any content hash, return everything the world knows about it.**

`hdx` resolves hashes against the public inverted indexes the world
already maintains — and scans your disk against local membership
filters to tell you which of your files are publicly known bytes.

```
$ hdx 9dc7a584db576910856ac7aa5cffbaeefe9cf427
sha1:9dc7a584db576910856ac7aa5cffbaeefe9cf427
  circl-hashlookup     known file (hashlookup)
  software-heritage    archived source file
                       → https://archive.softwareheritage.org/api/1/content/sha1:9dc7a584…
  snapshot-debian      sig-1.10/hello.sig, seen 2005-05-20
                       → https://snapshot.debian.org/archive/debian/20050520T000000Z/…
  coordinates          md5:… sha256:… sha512:… swh:1:cnt:…
```

```
$ hdx scan ~
3620056 files (476.3 GiB) — 2467170 known (113.7 GiB), 1152886 unknown
  cc: 30699 files          fedora: 1548022 files
  circl: 799152 files      rekor: 693 files
  depsdev: 11962 files     rpmfusion: 7166 files
  fatcat: 4624 files       swh: 2088888 files
                           vscode: 58277 files
```

## Why

Every package registry, software archive, and transparency log already
maintains a mapping from content hashes to what-and-where. Nobody joins
them. hashdex federates over the indexes that exist, ingests digest
extracts where an inversion exists but isn't queryable, and only
self-inverts (from metadata, never content) where nobody else has.
It never downloads content to hash it — ingest cost scales with
metadata, full stop. See [DESIGN.md](DESIGN.md) for the whole argument;
[SOURCES.md](SOURCES.md) is the verified inventory of bulk hash sources.

## Commands

| | |
|---|---|
| `hdx <hash>` | resolve: local walk over inverted indexes + observation store, then live backends (hex, base32, SRI, SWHID, `scheme:hex`); `--offline` skips the network |
| `hdx coords <file> [--lookup]` | mint all six coordinates of a local file (md5, sha1, sha256, sha512, blake2s256, git blob); recorded as a local crosswalk observation |
| `hdx scan <paths> [--list unknown\|known\|all] [--resolve]` | offline scan against installed filters; `--resolve` adds citations from local indexes; hashes persist in a local index (updatedb-style), so rescans are stat-only |
| `hdx locate <hash>` | find local files by digest (inverse of `hdx <hash>`) |
| `hdx index build <source> <dump>` | self-invert a source dump (e.g. fatcat) into a sorted mmap coordinate index |
| `hdx index list` | show installed inverted indexes |
| `hdx filters fetch [names\|--all]` | download published membership filters (no args: list what's available) |
| `hdx filters build <name> <scheme> <files>` | build a DCSO-format bloom from hex digest lines |
| `hdx filters list` | show installed filters |

Live backends: [deps.dev](https://deps.dev) (npm/PyPI/Maven/Cargo/NuGet/RubyGems),
[CIRCL hashlookup](https://hashlookup.circl.lu) (NSRL + distros),
[Software Heritage](https://archive.softwareheritage.org) (29B source files),
[snapshot.debian.org](https://snapshot.debian.org),
[Rekor](https://rekor.sigstore.dev) (sigstore transparency log),
VirusTotal (opt-in via `VT_API_KEY`).

Every answer line carries its attestor; results are cached locally as
observations (`~/.cache/hashdex/`). `SWH_TOKEN` raises the Software
Heritage rate limit.

## Per-source filters

Membership filters make `hdx scan` work offline and tell the resolver
which backends are worth asking. Beyond CIRCL's published bloom, we
build our own from public digest extracts:

- **Software Heritage** — 29.3B archived source-file sha256s (70 GiB
  filter, built for ~$3 of cloud compute by `tools/swh_extract_job.py`
  from SWH's public dataset — no content downloaded).
- **fatcat** — 122M scholarly-file hashes (sha1+sha256) from the
  Internet Archive's bibliographic catalog bulk export.
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

## Build

```
cargo build --release    # binary is target/release/hdx
cargo test
```

## Status

Early but real: the federated resolver, disk scanner, local hash
index, and nine filter families work today ([DESIGN.md](DESIGN.md)
tracks the MVP ladder). On the author's machine the filters identify
68% of all files (by count) as publicly known bytes — most of the
remainder is content that only ever existed there. The bigger arc — crosswalk edges from
single-witness multi-hash observations, a published append-only
ledger, web-tier coverage — is designed and not yet built.
