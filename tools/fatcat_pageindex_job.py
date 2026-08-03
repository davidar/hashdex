# /// script
# requires-python = ">=3.11"
# dependencies = ["pyarrow>=15", "duckdb>=1.1", "huggingface_hub>=0.30"]
# ///
"""Transcode the published fatcat-files parquet with page indexes.

The dataset was written by DuckDB, which cannot emit the parquet
PageIndex (offset + column indexes). hdx's range-read backend then has
to fetch whole column chunks (~8.5 MB for a key column) and walk page
headers. With per-page min/max and byte offsets in the footer, a point
lookup becomes a handful of ~128 KB page reads — or a footer-only
absence proof. This job rewrites every file page-indexed, preserving
row-group boundaries and row order exactly (read row group N, write
row group N), so all sortedness guarantees carry over verbatim.

Dictionary encoding is disabled: the wide columns are high-cardinality
(dictionaries fall back anyway, after wasting a page-sized dict read
per chunk) and zstd on plain pages compresses the rest fine.

Each output file is VERIFIED before upload (page-index presence via
duckdb parquet_metadata, per-row-group key stats identical to the
source, order-independent content checksums) and uploaded to
staging-pi/ immediately — phase outputs live on the Hub, not in the
job. The final swap is two metadata-only commits: copy staging-pi/*
into place, then drop staging-pi/. History squash happens outside
this job, after independent verification.

    # local smoke test (no network):
    uv run tools/fatcat_pageindex_job.py --smoke

    hf jobs uv run --flavor cpu-xl --timeout 3h -s HF_TOKEN \
        tools/fatcat_pageindex_job.py -- --repo david-ar/fatcat-files
"""

import argparse
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

STAGING = "staging-pi"
DATA_PAGE = 128 << 10
# Page size is only checked every write_batch_size values; 1024 keeps
# key-column pages near DATA_PAGE without a per-value check.
WRITE_BATCH = 1024

# Order-independent content checksums (from fatcat_sort_fix_job.py).
DATA_CHECK = """
    count(*)                                AS n,
    sum(hash(sha256))                       AS h_sha256,
    sum(hash(sha1))                         AS h_sha1,
    sum(hash(coalesce(md5, '')))            AS h_md5,
    sum(hash(coalesce(file_ident, '')))     AS h_file,
    sum(hash(coalesce(release_ident, '')))  AS h_release,
    sum(hash(coalesce(doi, '')))            AS h_doi,
    sum(hash(coalesce(wayback_url, '')))    AS h_wayback,
    sum(hash(coalesce(title, '')))          AS h_title,
    sum(coalesce(size_bytes, 0))            AS s_bytes
"""
MAP_CHECK = "count(*) AS n, sum(hash({key})) AS h_key, sum(hash(sha256)) AS h_sha256"


def transcode(src: Path, dst: Path):
    f = pq.ParquetFile(src)
    with pq.ParquetWriter(
        dst,
        f.schema_arrow,
        compression="zstd",
        compression_level=3,
        use_dictionary=False,
        write_page_index=True,
        data_page_size=DATA_PAGE,
        write_batch_size=WRITE_BATCH,
    ) as w:
        for i in range(f.metadata.num_row_groups):
            w.write_table(f.read_row_group(i))


def key_column(path: Path) -> str:
    names = pq.ParquetFile(path).schema_arrow.names
    return "sha256" if "title" in names else ("sha1" if "sha1" in names else "md5")


def verify(con, src: Path, dst: Path):
    """Page index present everywhere; row groups, order, and content
    byte-identical in meaning to the source. Raises on any mismatch."""
    key = key_column(src)

    meta = pq.ParquetFile(dst).metadata
    missing = sum(
        not (c.has_offset_index and c.has_column_index)
        for rg in range(meta.num_row_groups)
        for c in (meta.row_group(rg).column(i) for i in range(meta.num_columns))
    )
    if missing:
        raise RuntimeError(f"{dst.name}: {missing} column chunks lack a page index")

    def rg_stats(path):
        return con.execute(
            f"""SELECT row_group_id, row_group_num_rows,
                       stats_min_value, stats_max_value
                FROM parquet_metadata('{path}')
                WHERE path_in_schema = '{key}' ORDER BY row_group_id"""
        ).fetchall()

    if (s := rg_stats(src)) != (d := rg_stats(dst)):
        raise RuntimeError(f"{dst.name}: row-group {key} stats diverge\n  src {s[:3]}…\n  dst {d[:3]}…")

    check = DATA_CHECK if key == "sha256" else MAP_CHECK.format(key=key)
    sig = lambda p: con.execute(f"SELECT {check} FROM read_parquet('{p}')").fetchone()  # noqa: E731
    if (s := sig(src)) != (d := sig(dst)):
        raise RuntimeError(f"{dst.name}: content signature mismatch\n  src {s}\n  dst {d}")


def smoke(work: Path):
    """End-to-end transcode+verify on a synthetic table shaped like the
    real one (sorted keys, nulls, nested columns, an all-null tail)."""
    src, dst = work / "smoke_src.parquet", work / "smoke_dst.parquet"
    n = 3000
    rows = {
        "file_ident": [f"f{i}" for i in range(n)],
        "sha256": [f"{i * 16 + 8:064x}" for i in range(n - 100)] + [None] * 100,
        "sha1": [f"{i:040x}" for i in range(n)],
        "md5": [None if i % 7 == 0 else f"{i:032x}" for i in range(n)],
        "size_bytes": list(range(n)),
        "release_ident": [f"r{i}" for i in range(n)],
        "title": [None if i % 13 == 0 else f"Paper {i}" for i in range(n)],
        "doi": [None if i % 3 == 0 else f"10.5555/{i}" for i in range(n)],
        "wayback_url": [f"https://web.archive.org/web/2022/{i}" for i in range(n)],
        "contribs": [[f"A {i}", f"B {i}"] if i % 2 else [] for i in range(n)],
        "urls": [
            [{"url": f"https://x/{i}", "rel": "web"}] if i % 5 else [] for i in range(n)
        ],
    }
    table = pa.table(rows)
    # Source mimics the DuckDB output: multiple row groups, no page index.
    with pq.ParquetWriter(src, table.schema, compression="zstd") as w:
        for i in range(0, n, 1024):
            w.write_table(table.slice(i, 1024))

    con = duckdb.connect()
    src_meta = pq.ParquetFile(src).metadata
    assert not src_meta.row_group(0).column(0).has_offset_index, (
        "smoke source unexpectedly page-indexed"
    )

    transcode(src, dst)
    verify(con, src, dst)

    # The verify must actually bite: a corrupted copy has to fail it.
    bad = work / "smoke_bad.parquet"
    with pq.ParquetWriter(bad, table.schema, compression="zstd") as w:
        w.write_table(table.slice(0, n - 1))  # one row short
    try:
        verify(con, src, bad)
    except RuntimeError:
        pass
    else:
        raise AssertionError("verify accepted a corrupted file")
    print("smoke OK: page index written, verify passes and bites")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    work = Path(os.environ.get("TMPDIR", "/tmp")) / "fatcat-pageindex"
    (work / "out").mkdir(parents=True, exist_ok=True)

    if args.smoke:
        smoke(work)
        return
    if not args.repo:
        ap.error("--repo is required without --smoke")

    from huggingface_hub import CommitOperationCopy, CommitOperationDelete, HfApi, hf_hub_download

    api = HfApi()
    files = [
        p
        for p in api.list_repo_files(args.repo, repo_type="dataset")
        if p.endswith(".parquet") and (p.startswith("data/") or p.startswith("maps/"))
    ]
    staged = {
        p
        for p in api.list_repo_files(args.repo, repo_type="dataset")
        if p.startswith(f"{STAGING}/")
    }
    print(f"{len(files)} files, {len(staged)} already staged", flush=True)

    def one(path: str):
        t0 = time.time()
        if f"{STAGING}/{path}" in staged:
            print(f"[skip] {path} (staged)", flush=True)
            return
        src = Path(
            hf_hub_download(args.repo, path, repo_type="dataset", local_dir=work / "src")
        )
        dst = work / "out" / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        transcode(src, dst)
        verify(duckdb.connect(), src, dst)
        api.upload_file(
            path_or_fileobj=dst,
            path_in_repo=f"{STAGING}/{path}",
            repo_id=args.repo,
            repo_type="dataset",
            commit_message=f"stage page-indexed {path}",
        )
        src.unlink()  # bound disk: keep only the staged output
        print(f"[done] {path} in {time.time() - t0:.0f}s", flush=True)

    with ThreadPoolExecutor(args.workers) as ex:
        for _ in ex.map(one, files):
            pass

    print("[swap] copying staged files into place…", flush=True)
    api.create_commit(
        repo_id=args.repo,
        repo_type="dataset",
        operations=[
            CommitOperationCopy(src_path_in_repo=f"{STAGING}/{p}", path_in_repo=p)
            for p in files
        ],
        commit_message="page-indexed parquet: offset+column indexes, no dictionaries "
        "(order and row groups preserved; see tools/fatcat_pageindex_job.py)",
    )
    api.create_commit(
        repo_id=args.repo,
        repo_type="dataset",
        operations=[CommitOperationDelete(path_in_repo=f"{STAGING}/", is_folder=True)],
        commit_message="drop staging-pi/",
    )
    print("[swap] done — verify remotely, then squash history", flush=True)


if __name__ == "__main__":
    main()
