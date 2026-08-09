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
metadata, full stop. See [DESIGN.md](DESIGN.md) for the whole argument;
[SOURCES.md](SOURCES.md) is the verified inventory of bulk hash sources.

## Commands

| | |
|---|---|
| `hdx <hash>` | resolve: local walk over inverted indexes + observation store, then live backends (hex, base32, SRI, SWHID, `scheme:hex`); `--offline` skips the network |
| `hdx scan <paths>` | scan + attribute: hash files (persisted updatedb-style, so rescans are stat-only), check membership filters, cite what the indexes can name. `--no-resolve` = membership census only; `-v` = full citation blocks; `--list unknown\|known\|all` = per-file lines |
| `hdx coords <file> [--lookup]` | mint all six coordinates of a local file (md5, sha1, sha256, sha512, blake2s256, git blob); recorded as a local crosswalk observation |
| `hdx locate <hash>` | find local files by digest (inverse of `hdx <hash>`) |
| `hdx index build <source> <dump>` | self-invert a source dump (e.g. fatcat) into a sorted mmap coordinate index |
| `hdx filters fetch [names\|--all]` | download published membership filters (no args: list what's available) |
| `hdx filters build <name> <scheme> <files>` | build a DCSO-format bloom from hex digest lines |
| `hdx filters fold <name>` | halve a filter's size in place, trading false-positive rate for space |
| `hdx filters list` / `hdx index list` | show what's installed |

`--json` on any command emits machine-readable output.

## Who gets told what

Privacy is a consent line, not a mode:

- **Offline by default where it matters**: membership checks and
  `scan`'s attribution walk run against local filters and indexes.
- **Dataset transports** (the fatcat scholarly index) are range reads
  over static published parquet — the server sees byte offsets, never
  your digests — so `scan` uses them without asking.
- **Third-party APIs** (CIRCL, deps.dev, Software Heritage, Rekor,
  snapshot.debian.org, VirusTotal) are only told your digests when you
  ask: single-hash `hdx <hash>` lookups query them, and batch scans
  need explicit `--online` consent (optionally restricted:
  `--online=circl,swh`). Per-scan politeness ceilings apply.
- `--offline` globally guarantees zero network.

Every answer line carries its attestor — hdx never presents an
aggregated answer as its own knowledge. Results are cached as
observations in `~/.cache/hashdex/`; errors are never cached.

Env: `SWH_TOKEN` raises the Software Heritage rate limit,
`HF_TOKEN` lifts anonymous Hugging Face limits for dataset range
reads, `VT_API_KEY` enables the VirusTotal backend.

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
cargo install hashdex   # binary is hdx
```

or from a checkout: `cargo build --release` (binary at
`target/release/hdx`), `cargo test`.

## Status

Early but real: the federated resolver, disk scanner, local hash
index, inverted-index crosswalk walk, and ten filter families work
today ([DESIGN.md](DESIGN.md) tracks the MVP ladder). On the author's
machine the filters identify 68% of all files (by count) as publicly
known bytes — most of the remainder is content that only ever existed
there. The bigger arc — more sources, richer crosswalk edges, web-tier
coverage for the stubborn residue — is designed and not yet built.
