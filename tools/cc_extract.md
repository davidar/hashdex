# Common Crawl digest extract (filter + inverted index)

How the `cc` filter and the published CC document index are produced.
First run: CC-MAIN-2026-30 (July 2026), recon 2026-08-01.

## What Common Crawl actually contains (measured, don't trust folklore)

CC is an **HTML crawler** — it does not fetch page subresources. Measured
on CC-MAIN-2026-30 part-00000 (7.29M captures):

- 99.2% of captures are HTML/XHTML. The non-HTML remainder (~0.8%) is
  **documents**: 74% PDF, then text/plain, feeds (rss/atom/xml), office
  formats, a trickle of everything else. Almost no js/css/images.
- Whole crawl ≈ 2.2B captures → **~15M kept rows, ~14M distinct sha1**.
- So: bloom ≈ 35 MiB, inverted index ≈ 2 GiB per crawl. This is a
  *document* index, not a static-asset index. The static-asset web is
  simply not in CC. (An earlier note claiming ~30% non-HTML was wrong.)

## Preimage gotchas

- `content_digest` = WARC-Payload-Digest: **sha1, base32**, over the
  transfer payload. For identity-served binaries (PDFs etc.) this is
  sha1 of the file bytes and matches `hdx scan`. Responses served with
  `Content-Encoding: gzip` hash the *compressed* stream — those keys
  will never match local files (harmless noise in the filter).
- `content_truncated IS NOT NULL` rows are digests of **truncated**
  payloads (CC caps at ~1 MiB; ~9% of PDFs). Excluded — poison keys.
- Filter: status 200, mime_detected not `text/html%` / `application/xhtml%`,
  not truncated. `subset=warc` only (other subsets are diagnostics/robots).

## Run it

The job streams ~100–150 GB of parquet column chunks (projection
pushdown; the 300 `subset=warc` files total ~180 GB) and outputs ~2 GiB.
On HF Jobs the transfer is in-AWS. `cpu-upgrade` (8 vCPU/32 GB/50 GB,
$0.03/h) fits comfortably; expect ~0.5–1.5 h ≈ **$0.02–0.05**.

```sh
# smoke test, local, ~1 GB transfer, no upload:
uv run tools/cc_extract_job.py --crawl CC-MAIN-2026-30 --limit 2 --no-upload

# real run on HF Jobs (needs `hf auth login` + credit balance):
hf jobs uv run --flavor cpu-upgrade --timeout 4h -s HF_TOKEN \
    tools/cc_extract_job.py -- --crawl CC-MAIN-2026-30 --repo <user>/hashdex-cc
```

Outputs land in `crawls/<CRAWL>/` of the dataset repo:
`index-*.parquet` (digest_b32-sorted: digest, url, fetch_time, mime,
warc coords) + `digests.parquet` (distinct) + `stats.json`.

## Build the filter locally

```sh
hf download <user>/hashdex-cc --repo-type dataset \
    --include 'crawls/CC-MAIN-2026-30/digests.parquet' --local-dir /tmp/cc
uv run tools/cc_digests_to_hex.py /tmp/cc/crawls/CC-MAIN-2026-30/digests.parquet \
    > ~/.cache/hashdex/extracts/cc.sha1.hex
hdx filters build cc sha1 ~/.cache/hashdex/extracts/cc.sha1.hex
```

## Resolution path

The index parquet is sorted by digest and row-group-pruned, so a point
lookup (`WHERE digest_b32 = ...`) over HF's HTTP range requests touches
only a few MB — the published dataset *is* the query backend; no server.
CC has no digest-keyed API of its own (CDX is URL-keyed), so this
self-inversion from their metadata is the only resolution path
(admission-rule clean: metadata only, no content fetched).

Convert local sha1 → base32 for lookups: `base64.b32encode(bytes.fromhex(h))`.

## Multi-crawl

Each crawl is an independent `crawls/<id>/` subtree; a union bloom can
be rebuilt from the digests.parquet files. Marginal cost per additional
crawl ≈ $0.05 of job compute. Storage: ~2 GiB/crawl, public HF dataset
(free-tier "best effort" is fine at this scale; PRO's 10 TB if it grows).
