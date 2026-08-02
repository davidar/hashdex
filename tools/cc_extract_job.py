# /// script
# requires-python = ">=3.11"
# dependencies = ["duckdb>=1.0", "huggingface_hub>=0.30"]
# ///
"""Extract non-HTML content digests + inverted index from one Common Crawl
columnar index, and (optionally) upload the result to a Hugging Face dataset.

Designed to run on HF Jobs (in-AWS, fat pipe to data.commoncrawl.org):

    hf jobs uv run --flavor cpu-upgrade --timeout 4h -s HF_TOKEN \
        tools/cc_extract_job.py -- --crawl CC-MAIN-2026-30 --repo <user>/hashdex-cc

or locally for a smoke test (a couple of ~600 MB index files):

    uv run tools/cc_extract_job.py --crawl CC-MAIN-2026-30 --limit 2 --no-upload

Outputs, per crawl:
  index-*.parquet   digest_b32-sorted (digest, url, fetch_time, mime,
                    warc_filename/offset/length) for every kept capture
  digests.parquet   distinct digest_b32 (sha1 of payload, base32)

Kept = fetch_status 200, mime_detected not HTML/XHTML, not truncated.
The digest is CC's WARC-Payload-Digest: sha1 over the transfer payload.
For identity-served binaries (PDF and friends) that equals sha1 of the
file bytes; gzip-content-encoded responses do NOT match local files.
"""

import argparse
import gzip
import io
import json
import os
import sys
import time
import urllib.request

USER_AGENT = "hashdex-cc/0.1 (hash index research)"
CC_BASE = "https://data.commoncrawl.org"


def fetch_warc_index_paths(crawl: str) -> list[str]:
    url = f"{CC_BASE}/crawl-data/{crawl}/cc-index-table.paths.gz"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp:
        paths = gzip.decompress(resp.read()).decode().splitlines()
    warc = [p for p in paths if "/subset=warc/" in p]
    if not warc:
        sys.exit(f"no subset=warc files listed for {crawl}")
    return warc


def run_extract(con, files: list[str], out_dir: str) -> dict:
    file_list = ", ".join(f"'{CC_BASE}/{p}'" for p in files)
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()
    con.execute(f"""
        COPY (
            SELECT content_digest AS digest_b32,
                   url,
                   fetch_time,
                   content_mime_detected AS mime,
                   warc_filename,
                   warc_record_offset,
                   warc_record_length
            FROM read_parquet([{file_list}])
            WHERE fetch_status = 200
              AND content_digest IS NOT NULL
              AND content_truncated IS NULL
              AND content_mime_detected IS NOT NULL
              AND content_mime_detected NOT LIKE 'text/html%'
              AND content_mime_detected NOT LIKE 'application/xhtml%'
            ORDER BY digest_b32
        ) TO '{out_dir}/index.parquet'
        (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 262144,
         FILE_SIZE_BYTES '1900MB', FILENAME_PATTERN 'index-{{i}}',
         OVERWRITE_OR_IGNORE)
    """)
    scan_s = time.time() - t0
    con.execute(f"""
        COPY (
            SELECT DISTINCT digest_b32
            FROM '{out_dir}/index.parquet/*.parquet'
            ORDER BY digest_b32
        ) TO '{out_dir}/digests.parquet'
        (FORMAT PARQUET, COMPRESSION ZSTD)
    """)
    rows, distinct = con.execute(f"""
        SELECT (SELECT count(*) FROM '{out_dir}/index.parquet/*.parquet'),
               (SELECT count(*) FROM '{out_dir}/digests.parquet')
    """).fetchone()
    return {"rows_kept": rows, "distinct_digests": distinct,
            "scan_seconds": round(scan_s, 1), "files_scanned": len(files)}


def upload(repo: str, crawl: str, out_dir: str, stats: dict):
    from huggingface_hub import HfApi

    api = HfApi()
    api.create_repo(repo, repo_type="dataset", exist_ok=True)
    with open(os.path.join(out_dir, "stats.json"), "w") as f:
        json.dump(stats, f, indent=2)
    api.upload_folder(
        repo_id=repo,
        repo_type="dataset",
        folder_path=out_dir,
        path_in_repo=f"crawls/{crawl}",
        commit_message=f"{crawl}: {stats['distinct_digests']} distinct digests",
    )
    print(f"uploaded to https://huggingface.co/datasets/{repo}/tree/main/crawls/{crawl}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crawl", required=True, help="e.g. CC-MAIN-2026-30")
    ap.add_argument("--repo", help="HF dataset repo to upload to, e.g. user/hashdex-cc")
    ap.add_argument("--limit", type=int, help="only scan first N index files (smoke test)")
    ap.add_argument("--out", default="cc-out", help="local output directory")
    ap.add_argument("--no-upload", action="store_true")
    ap.add_argument("--threads", type=int, default=0, help="duckdb threads (0 = auto)")
    ap.add_argument("--memory", default="8GB",
                    help="duckdb memory_limit; spill goes to <out>/.duckdb-tmp")
    args = ap.parse_args()

    import duckdb

    files = fetch_warc_index_paths(args.crawl)
    print(f"{args.crawl}: {len(files)} subset=warc index files", flush=True)
    if args.limit:
        files = files[: args.limit]
        print(f"limited to {len(files)} files", flush=True)

    con = duckdb.connect(config={"custom_user_agent": USER_AGENT})
    con.execute("INSTALL httpfs; LOAD httpfs")
    con.execute("SET http_keep_alive=true")
    con.execute("SET http_retries=6")
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET memory_limit='{args.memory}'")
    tmp = os.path.join(args.out, ".duckdb-tmp")
    os.makedirs(tmp, exist_ok=True)
    con.execute(f"SET temp_directory='{tmp}'")
    if args.threads:
        con.execute(f"SET threads={args.threads}")

    out_dir = os.path.join(args.out, args.crawl)
    stats = run_extract(con, files, out_dir)
    print(json.dumps(stats, indent=2), flush=True)

    if args.no_upload:
        return
    if not args.repo:
        sys.exit("--repo required unless --no-upload")
    upload(args.repo, args.crawl, out_dir, stats)


if __name__ == "__main__":
    main()
