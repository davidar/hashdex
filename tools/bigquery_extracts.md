# BigQuery digest extracts (deps.dev, Rekor)

How the `depsdev` and `rekor` filters were produced, 2026-08-01.
Everything runs in the free tier: a **billing-free sandbox project**
(queries cannot be charged; 1 TB/month processing, 10 GB storage cap),
and `tabledata.list` paging for download, which is free and doesn't
count as query processing.

```sh
gcloud projects create hashdex-sandbox   # NO billing account attached
gcloud config set project hashdex-sandbox
bq mk --location=US -d hashdex_extracts
```

## deps.dev: 344.9M artifact digests (47 GB scan)

`PackageVersionHashes` is 9.2 TiB across daily snapshot partitions —
**always filter to one partition with a literal timestamp** (the
`*Latest` views don't prune). Find the newest:

```sql
SELECT partition_id, total_rows
FROM `bigquery-public-data.deps_dev_v1.INFORMATION_SCHEMA.PARTITIONS`
WHERE table_name = 'PackageVersionHashes' AND partition_id != '__NULL__'
ORDER BY partition_id DESC LIMIT 3
```

Extract (store BYTES, not base64 strings — a Hash+HashType string
table blew the sandbox's 10 GB storage cap; raw bytes squeak under at
8.99 GiB, and scheme is recoverable from digest length):

```sql
SELECT DISTINCT FROM_BASE64(`Hash`) AS h
FROM `bigquery-public-data.deps_dev_v1.PackageVersionHashes`
WHERE TIMESTAMP_TRUNC(SnapshotAt, DAY) = TIMESTAMP('2026-07-20')
  AND HashType IN ('SHA1','SHA256')
```

→ destination table `hashdex_extracts.depsdev_hashes`. Gotchas:
`Hash` needs backticks (reserved word); values are base64; dry-run
first (`bq query --dry_run`) — the free tier is a hard monthly budget.

## Rekor: 8.2M attestation-subject digests (3.2 GB scan)

`rekor.Artifacts.Digest` is `ARRAY<STRING>` of `sha256:<hex>` (some
empty):

```sql
SELECT DISTINCT REGEXP_EXTRACT(d, r'^sha256:([0-9a-fA-F]{64})$') AS digest
FROM `bigquery-public-data.rekor.Artifacts`, UNNEST(Digest) AS d
WHERE REGEXP_CONTAINS(d, r'^sha256:[0-9a-fA-F]{64}$')
```

→ `hashdex_extracts.rekor_digests`. Note this is attestation
*subjects* only (39M rows). The full `rekor.IndexKeys` (8.4B rows,
every hashedrekord digest — where goreleaser release binaries live)
costs ~636 GB of quota to distinct-scan and produces a result too big
for sandbox storage; deferred until a billed GCS staging path or a
patient paging session is worth it.

## Download + build

```sh
tools/bq_download.py all     # parallel tabledata.list paging (free),
                             # ~160k rows/s with 24 workers; writes hex
                             # lines split per scheme into
                             # ~/.cache/hashdex/extracts/
hdx filters build depsdev sha1   ~/.cache/hashdex/extracts/depsdev.sha1.*.hex
hdx filters build depsdev sha256 ~/.cache/hashdex/extracts/depsdev.sha256.*.hex
hdx filters build rekor  sha256  ~/.cache/hashdex/extracts/rekor.sha256.*.hex
```

Key convention (must match `hdx scan`): sha1 keys UPPERCASE hex,
sha256 lowercase — `filters build` normalizes.
