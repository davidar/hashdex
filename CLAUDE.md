# hashdex

`hdx` resolves content hashes against the public indexes the world
already maintains, and scans disks against local membership filters.

## Documents — read in this order

- **DESIGN.md** — canonical design. Authoritative on every question;
  where anything else disagrees, DESIGN.md wins.
- **SOURCES.md** — verified inventory of bulk hash sources (dump URLs,
  hash algorithms, preimage gotchas, scale, licenses). Facts were
  live-verified 2026-08-01; UNVERIFIED flags are honest.

## Build & test

```
cargo build          # binary is target/debug/hdx
cargo test
hdx <hash>            # resolve (hex, base32, SRI, SWHID, scheme:hex);
                      #   local walk first, then network (--offline to skip)
hdx coords <file>     # mint all six coordinates of local files
hdx scan <paths>      # scan against filters + attribute what it can
                      #   (dataset probes by default; --no-resolve =
                      #   census; --online consents to third-party APIs).
                      #   A named container FILE gets the hashoscope:
                      #   full recursive descent (tar/zip/deb/rpm/cpio/
                      #   squashfs/iso — 7z detected, not descended).
                      #   Unknown containers under dir roots descend
                      #   too (demand-driven; default = in-place
                      #   formats only, --deep adds compressed
                      #   wrappers, --shallow none); descents cache
                      #   content-addressed in local.db and replay
hdx recipe FILE       # reconstruction manifest: verified splice of
                      #   member byte ranges (refs by digest + claim
                      #   URLs) + gzip@0 compression nodes (GNU gzip
                      #   catalog via shell-out, byte-verified — the
                      #   disarchive trick) + literal residue →
                      #   FILE.recipe.json; `hdx recipe check RECIPE
                      #   DIR` rebuilds from local blobs, never
                      #   fetches; `hdx recipe jigdo|disarchive` emit
                      #   stock-tool-consumable projections
hdx index pull tarballs           # local copy of a published dataset
                                  #   (same parquet, mmap'd; resolution
                                  #   is remote range reads by default)
tools/release_tarballs.py         # harvest debian/homebrew/guix artifact
                                  #   hashes (dump → published parquet)
hdx filters fetch     # install CIRCL bloom (~1 GB) into the cache dir
```

Env: `SWH_TOKEN` (raises SWH quota 120→1200/h), `HF_TOKEN` (raises
Hub rate limits for the dataset backends' range reads). Cache +
filters: `~/.cache/hashdex/`. Published datasets are parquet on the
wire AND at rest — no bespoke local index formats (HDXI is retired).

## Rules that must not be violated (from DESIGN.md)

- **Admission rule**: ingest cost scales with metadata, never content;
  new hash algorithms never imply re-fetching. Exceptions are
  user-initiated local hashing and demand-driven single probes only.
- **Edge-minting rule**: only single-witness multi-hash rows create
  equivalence edges. Never join two sources on (URL, time) to infer
  same-content — that's a hint, not an edge.
- **Weak digests (md5, sha1) are lookup keys, never merge keys.**
  Identity-grade-ness is query-time policy, not schema.
- **Every output line carries its attestor.** hdx must never present an
  aggregated answer as its own knowledge.
- **hdx tells you where things are; it never fetches content on the
  user's behalf** (a fetch service = proxy = every problem the design
  routes around).
- **Preimage discipline**: never assume a wild hash is of raw bytes —
  check SOURCES.md for the source's wrapper scheme before ingesting
  (Go H1, Alpine APKINDEX, NAR, VBMeta, OTS are known traps).

## Implementation gotchas (learned the hard way)

- deps.dev `/v3/query` signals a miss with **HTTP 404**, not an empty
  result set. Rekor `index/retrieve` wants `"sha256:<hex>"` strings.
- CIRCL bloom = DCSO format: LE u64 header (version,n,p,k,m,N) then
  bit array. Hashing is FNV-1 64 → `% (2^64-87)`, then k rounds of
  **Go-semantics wrapping multiply** by 18446744073709550147 before
  `% (2^64-87)`; keys are **UPPERCASE hex** digests. Verified
  bit-exact against the live filter; don't "fix" the wrapping.
- CIRCL's published filter is dated Oct 2023 — recent binaries miss.
  Filter hits are probabilistic; errors are never cached as misses.
- Filters bigger than RAM need `madvise(Random)` on the mmap (done in
  Bloom::open) — default readahead turns each 8-byte probe into a
  ~128 KiB read; the 70 GB SWH filter ran ~200x slower without it.

## Working state

Machine-specific state, the source queue, and cost history live in
CLAUDE.local.md (gitignored — private to this machine).
