# /// script
# requires-python = ">=3.11"
# dependencies = ["duckdb>=1.1", "huggingface_hub>=0.30"]
# ///
"""Re-sort the published fatcat-files data/ shards, which shipped
interleaved: the original build ran the final COPY under
`preserve_insertion_order = false`, which licenses DuckDB to reorder
the whole pipeline — including between the ORDER BY and a parallel
multi-file COPY sink — so 479/480 row groups overlap. maps/ (single-file
COPYs) are sorted and untouched.

Reads the published parquet (in-datacenter), rewrites data/ globally
sorted, VERIFIES before upload (footer disjointness + order-independent
content checksums vs the source), then replaces data/ in one commit.
History squash happens outside this job, after independent verification.

    hf jobs uv run --flavor cpu-xl --timeout 4h -s HF_TOKEN \
        tools/fatcat_sort_fix_job.py -- --repo david-ar/fatcat-files
"""

import argparse
import os
import time
from pathlib import Path

import duckdb

CHECK_COLS = """
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


def content_signature(con, glob):
    return con.execute(f"SELECT {CHECK_COLS} FROM read_parquet('{glob}')").fetchone()


def assert_sorted(con, glob):
    rows = con.execute(
        f"""SELECT stats_min_value, stats_max_value
            FROM parquet_metadata('{glob}')
            WHERE path_in_schema = 'sha256'
            ORDER BY stats_min_value"""
    ).fetchall()
    # All-NULL row groups (the sha256-less tail bucket) carry no stats;
    # they hold no lookup targets, so sortedness doesn't apply to them.
    nulls = sum(1 for r in rows if r[0] is None or r[1] is None)
    rows = [r for r in rows if r[0] is not None and r[1] is not None]
    overlaps = sum(1 for i in range(1, len(rows)) if rows[i][0] < rows[i - 1][1])
    print(f"  {len(rows)} keyed row groups ({nulls} null), {overlaps} overlapping", flush=True)
    if not rows or overlaps:
        raise RuntimeError(f"output not globally sorted: {overlaps} overlaps")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    args = ap.parse_args()

    work = Path(os.environ.get("TMPDIR", "/tmp")) / "fatcat-sort-fix"
    out = work / "data"
    out.mkdir(parents=True, exist_ok=True)

    # Local copy first: a whole-table ORDER BY + order-preserving COPY
    # over 62 HTTP-streamed shards exhausted cpu-xl's memory (first
    # attempt). Local shards + bucketed sorts bound memory instead.
    t0 = time.time()
    print("[download] data/ shards…", flush=True)
    from huggingface_hub import snapshot_download

    local = snapshot_download(
        repo_id=args.repo,
        repo_type="dataset",
        allow_patterns="data/*.parquet",
        local_dir=str(work / "src"),
    )
    src = f"{local}/data/*.parquet"
    print(f"[download] done in {(time.time()-t0)/60:.1f} min", flush=True)

    con = duckdb.connect(str(work / "build.duckdb"))
    con.execute(f"SET temp_directory = '{work / 'tmp'}'")
    con.execute("SET memory_limit = '95GB'")  # cgroup kills, duckdb spills
    con.execute(f"SET threads = {os.cpu_count() or 8}")
    # preserve_insertion_order stays at its default (true): that is the
    # entire fix — the sort must survive into the writer.

    t0 = time.time()
    print("[signature] source…", flush=True)
    src_sig = content_signature(con, src)
    print(f"  {src_sig[0]:,} rows in {time.time()-t0:.0f}s", flush=True)

    # 16 sequential nibble-bucket sorts, written in bucket order: global
    # order = bucket order + in-bucket ORDER BY, and each bucket (~1/16
    # of the table) sorts comfortably in RAM. OOM-proof by construction.
    t0 = time.time()
    buckets = [(nib, f"sha256 LIKE '{nib}%'") for nib in "0123456789abcdef"]
    # ORDER BY sha256 is NULLS LAST: sha256-less rows go in a final
    # bucket ('z' sorts after 'f' so plain filename order stays global).
    buckets.append(("znull", "sha256 IS NULL"))
    for i, (tag, cond) in enumerate(buckets):
        print(f"[sort] bucket {tag} ({i + 1}/{len(buckets)})…", flush=True)
        # ONE file per bucket. FILE_SIZE_BYTES multi-file rotation does
        # not preserve ORDER BY across (or within) the emitted files —
        # reproduced on duckdb 1.5.5 regardless of
        # preserve_insertion_order; single-file COPY does.
        con.execute(
            f"""
            COPY (SELECT * FROM read_parquet('{src}')
                  WHERE {cond} ORDER BY sha256)
            TO '{out / f"files-{tag}.parquet"}'
            (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 262144)
            """
        )
    print(f"[sort] done in {(time.time()-t0)/60:.1f} min", flush=True)

    print("[verify] footer disjointness…", flush=True)
    assert_sorted(con, str(out / "*.parquet"))
    print("[verify] content signature…", flush=True)
    out_sig = content_signature(con, str(out / "*.parquet"))
    if out_sig != src_sig:
        raise RuntimeError(f"content signature mismatch:\n  src {src_sig}\n  out {out_sig}")
    print("[verify] OK — signatures identical, output sorted", flush=True)

    from huggingface_hub import HfApi

    print("[upload] replacing data/ in one commit…", flush=True)
    HfApi().upload_folder(
        repo_id=args.repo,
        repo_type="dataset",
        folder_path=str(out),
        path_in_repo="data",
        delete_patterns="*.parquet",
        commit_message="re-sort data/ globally by sha256 (fix interleaved parallel COPY)",
    )
    print("[upload] done — verify remotely, then squash history", flush=True)


if __name__ == "__main__":
    main()
