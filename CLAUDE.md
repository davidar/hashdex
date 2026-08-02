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
hdx <hash>            # resolve (hex, base32, SRI, SWHID, scheme:hex)
hdx coords <file>     # mint all six coordinates of local files
hdx scan <dir>        # offline scan against installed filters
hdx filters fetch     # install CIRCL bloom (~1 GB) into the cache dir
```

Env: `SWH_TOKEN` (raises SWH quota 120→1200/h), `VT_API_KEY` (enables
the VirusTotal backend). Cache + filters: `~/.cache/hashdex/`.

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
