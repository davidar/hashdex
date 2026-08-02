# SWH content bloom filter (sha256, rung 2)

Build a DCSO membership filter over every content blob Software
Heritage has archived, from the graph dataset's `content` table.
Recon 2026-08-01 against export **2026-06-04**.

## Dataset facts (verified)

- `s3://softwareheritage/graph/2026-06-04/orc/content/` — **128 ORC
  files, 2.96 TiB, 29.28B rows** (228.8M rows × ~361 stripes per file),
  ZSTD, anonymous access, bucket region us-east-1, not requester-pays.
- `sha256` column is a **string of 64-char lowercase hex** — matches
  hdx's sha256 filter key convention as-is. (sha1/sha1_git/blake2s256
  columns also present; we build sha256 only.)
- Transfer for the sha256 column alone ≈ **~1 TB** (hex is ~2×
  ZSTD-compressible; other columns are skipped via ORC column
  projection with stripe-ranged reads).

## The job

`tools/swh_extract_job.py` (self-contained uv script):

1. Lists the ORC files (anonymous S3), sums exact row counts from
   footers for sizing.
2. Embeds a zero-dependency Rust bloom builder — a bit-exact copy of
   `src/filter.rs` arithmetic, **verified byte-identical** output vs
   `hdx filters build` on the same input (2026-08-01) — and compiles
   it at start (rustup bootstrap if no cargo).
3. Streams the sha256 column stripe-by-stripe (6 parallel readers,
   zero-copy arrow buffers) into the builder's stdin; builder hashes
   on all cores into an atomic bit array.
4. Writes `swh.sha256.bloom` + `stats.json`, uploads them plus a
   dataset card to a public HF dataset repo.

Filter sizing at n = 29.3B, per scheme:

| p | size | k |
|---|---|---|
| 1e-3 | 52.7 GB | 10 |
| 1e-4 | **70.2 GB** | 13 |

Defaults: **p = 1e-4** (10× precision for
40% more bytes; ~200 false labels on a ~2M-file scan, confirmable via
the live API), and **all four schemes** — sha256 (what `hdx scan`
checks), sha1_git (git blob id: membership from an object id alone),
sha1 (resolver prefilter for wild 40-hex hashes; UPPERCASE keys per
the CIRCL convention), blake2s256 (completeness; it's ~$1.50 of
marginal cost). 4 × 70.2 GB = 281 GB total, which exceeds
cpu-performance's 256 GB RAM — hence `--per-pass 2`: two passes of
two schemes, each pass downloading only its own columns (ORC column
projection), so total transfer is unchanged (~3 TB). `Bloom::open`
mmaps, so scan-side RAM is page cache only; locally you only download
the schemes you use (sha256, 70 GB). Upload is straight to a
**public** dataset repo with a generated dataset card (CC-BY
attribution) — public storage under PRO is 10 TB vs 1 TB private.
Note: hdx's filter loader only knows md5/sha1/sha256 filenames today;
`swh.sha1_git.bloom` / `swh.blake2s256.bloom` are published for other
consumers (and future hdx tiers) and are skipped harmlessly if
installed locally.

## Cost (HF Jobs, prepaid credits)

`cpu-performance` (32 vCPU / 256 GB / 1 TB disk / $1.90 h), all four
schemes in two passes: ~3 TB in-AWS transfer at 300–700 MB/s ≈
1.2–2.5 h, hashing overlaps download, 281 GB upload ≈ 15–30 min.

- Expected wall: **2.5–4 h → $5–8** (sha256-only would be $2–5)
- `--timeout 8h` hard-caps the worst case at **$15.20**
- Suggested credit top-up: $10–15
- The job stops (and billing stops) the moment the script exits.
  Watch live: `hf jobs logs <id>` / the job page (logs + metrics).

## Run it

```sh
# local smoke test (~40 MB, one stripe of one file, two passes):
uv run tools/swh_extract_job.py --export 2026-06-04 \
    --schemes sha256,sha1 --per-pass 1 \
    --limit-files 1 --limit-stripes 1 --no-upload --out /tmp/swh-smoke

# the real thing, all four schemes (needs `hf auth login` + credits):
hf jobs uv run --flavor cpu-performance --timeout 8h -s HF_TOKEN \
    tools/swh_extract_job.py -- --export 2026-06-04 \
    --repo <user>/swh-content-bloom
```

Install locally afterwards:

```sh
hf download <user>/swh-content-bloom --repo-type dataset \
    --include '2026-06-04/swh.sha256.bloom' --local-dir /tmp/swh
mv /tmp/swh/2026-06-04/swh.sha256.bloom ~/.cache/hashdex/filters/
```

## Notes

- License: graph dataset is CC-BY 4.0 + bulk-access ToU; a hash
  membership filter is derived metadata, attribution goes in the
  dataset card when published.
- Incremental updates: DCSO blooms with identical (n, p, m, k) merge
  by bitwise OR — a future export can be a delta job + merge, and the
  same trick allows sharding the build across parallel jobs if ever
  needed.
- The content table rows also carry sha1 + sha1_git + blake2s256 —
  the 4-way crosswalk edges (29.3B single-witness multi-hash rows)
  for the future ledger; same download, different consumer. Not this
  job's problem.
