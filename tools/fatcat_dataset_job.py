# /// script
# requires-python = ">=3.11"
# dependencies = ["duckdb>=1.1", "orjson>=3.10", "pyarrow>=17", "huggingface_hub>=0.30"]
# ///
"""Convert the final fatcat bulk export (2024-02-18, archive.org) into a
single queryable parquet dataset on Hugging Face: one big `files` table,
one row per (file x release), sorted by sha256 — hash in, everything out
(digests, wayback URLs, DOI/arXiv/PMID, title, authors, venue) in one
row-group range read. Plus two slim digest maps (sha1->sha256,
md5->sha256, sorted by key) so weak-digest point lookups don't scan.

Fatcat idents ride along as join keys back into the raw dumps; the
user-facing identifiers are the ones that still resolve (wayback URL =
the actual hashed bytes; DOI = the work).

Designed for HF Jobs:

    hf jobs uv run --flavor cpu-xl --timeout 12h -s HF_TOKEN \
        tools/fatcat_dataset_job.py -- --repo <user>/fatcat-files

Local smoke test (a few MB range-read from archive.org, ~1 min):

    uv run tools/fatcat_dataset_job.py --limit-lines 20000 \
        --no-upload --out /tmp/fatcat-smoke

Phases (marker files skip finished phases on rerun — the SWH lesson;
cpu-xl has 1 TB of scratch, so dumps land on disk first):
  1. download file_export.json.gz     (23 GiB, segmented ranged fetch)
  2. parse -> files_raw parquet parts (block fan-out to JSON workers)
  3. download release_export_expanded (216 GiB, same fetch; resumable
     per 256 MiB part)
  4. parse -> releases_slim parquet parts
  5. duckdb join + global sort by sha256 -> data/*.parquet,
     maps/sha1.parquet, maps/md5.parquet, README.md
"""

import argparse
import math
import multiprocessing as mp
import os
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ITEM = "https://archive.org/download/fatcat_bulk_exports_2024-02-18"
FILE_EXPORT = f"{ITEM}/file_export.json.gz"
RELEASE_EXPORT = f"{ITEM}/release_export_expanded.json.gz"

BLOCK_BYTES = 8 << 20
# Round-robin block dealing means all workers hit this threshold in
# lockstep, so peak memory is nworkers * (rows list + arrow table).
# 1M rows/worker OOMKilled cpu-xl (124 GB); the intermediate parts get
# re-sorted by duckdb anyway, so small row groups here cost nothing.
ROWS_PER_FLUSH = 100_000

FILES_SCHEMA = {
    "file_ident": "string",
    "sha1": "string",
    "sha256": "string",
    "md5": "string",
    "size_bytes": "int64",
    "mimetype": "string",
    "wayback_url": "string",
    "urls": "list<struct>",
    "release_idents": "list<string>",
}

RELEASES_SCHEMA = {
    "release_ident": "string",
    "work_ident": "string",
    "title": "string",
    "release_type": "string",
    "release_stage": "string",
    "release_year": "int32",
    "release_date": "string",
    "doi": "string",
    "arxiv": "string",
    "pmid": "string",
    "pmcid": "string",
    "wikidata_qid": "string",
    "dblp": "string",
    "container_name": "string",
    "container_issnl": "string",
    "publisher": "string",
    "volume": "string",
    "issue": "string",
    "pages": "string",
    "language": "string",
    "license": "string",
    "contribs": "list<string>",
}


def pa_schema(spec):
    import pyarrow as pa

    fields = []
    for name, kind in spec.items():
        if kind == "string":
            t = pa.string()
        elif kind == "int64":
            t = pa.int64()
        elif kind == "int32":
            t = pa.int32()
        elif kind == "list<string>":
            t = pa.list_(pa.string())
        elif kind == "list<struct>":
            t = pa.list_(pa.struct([("url", pa.string()), ("rel", pa.string())]))
        else:
            raise ValueError(kind)
        fields.append(pa.field(name, t))
    return pa.schema(fields)


def extract_file(entity):
    if entity.get("state") not in (None, "active"):
        return None
    urls = [
        {"url": u.get("url"), "rel": u.get("rel")}
        for u in entity.get("urls") or []
        if u.get("url")
    ]
    wayback = next(
        (u["url"] for u in urls if u["rel"] == "webarchive"),
        next((u["url"] for u in urls if "web.archive.org/" in u["url"]), None),
    )
    return {
        "file_ident": entity.get("ident"),
        "sha1": entity.get("sha1"),
        "sha256": entity.get("sha256"),
        "md5": entity.get("md5"),
        "size_bytes": entity.get("size"),
        "mimetype": entity.get("mimetype"),
        "wayback_url": wayback,
        "urls": urls,
        "release_idents": entity.get("release_ids") or [],
    }


def extract_release(entity):
    if entity.get("state") not in (None, "active"):
        return None
    ext = entity.get("ext_ids") or {}
    container = entity.get("container") or {}
    contribs = [
        c.get("raw_name") or " ".join(filter(None, [c.get("given_name"), c.get("surname")]))
        for c in sorted(entity.get("contribs") or [], key=lambda c: c.get("index") or 0)
        if c.get("role") in (None, "author")
    ]
    return {
        "release_ident": entity.get("ident"),
        "work_ident": entity.get("work_id"),
        "title": entity.get("title"),
        "release_type": entity.get("release_type"),
        "release_stage": entity.get("release_stage"),
        "release_year": entity.get("release_year"),
        "release_date": entity.get("release_date"),
        "doi": ext.get("doi"),
        "arxiv": ext.get("arxiv"),
        "pmid": ext.get("pmid"),
        "pmcid": ext.get("pmcid"),
        "wikidata_qid": ext.get("wikidata_qid"),
        "dblp": ext.get("dblp"),
        "container_name": container.get("name"),
        "container_issnl": container.get("issnl"),
        "publisher": entity.get("publisher") or container.get("publisher"),
        "volume": entity.get("volume"),
        "issue": entity.get("issue"),
        "pages": entity.get("pages"),
        "language": entity.get("language"),
        "license": entity.get("license_slug"),
        "contribs": [c for c in contribs if c],
    }


def worker(wid, out_dir, schema_spec, extract_name, q):
    """Parse newline-delimited JSON blocks into parquet parts."""
    import orjson
    import pyarrow as pa
    import pyarrow.parquet as pq

    extract = {"file": extract_file, "release": extract_release}[extract_name]
    schema = pa_schema(schema_spec)
    rows, part, writer, part_rows = [], 0, None, 0

    def flush(final=False):
        nonlocal rows, part, writer, part_rows
        if rows:
            table = pa.Table.from_pylist(rows, schema=schema)
            if writer is None:
                writer = pq.ParquetWriter(
                    out_dir / f"part-w{wid:02d}-{part:04d}.parquet",
                    schema,
                    compression="zstd",
                )
            writer.write_table(table)
            part_rows += len(rows)
            rows = []
        if writer and (final or part_rows >= 8_000_000):
            writer.close()
            writer, part, part_rows = None, part + 1, 0

    while True:
        block = q.get()
        if block is None:
            break
        for line in block.splitlines():
            if not line:
                continue
            try:
                row = extract(orjson.loads(line))
            except orjson.JSONDecodeError:
                continue
            if row is not None:
                rows.append(row)
        if len(rows) >= ROWS_PER_FLUSH:
            flush()
    flush(final=True)


def cgroup_mem_gib():
    try:
        return int(Path("/sys/fs/cgroup/memory.current").read_text()) / 2**30
    except (OSError, ValueError):
        return 0.0


def remote_size(url):
    head = subprocess.run(
        ["curl", "-sIL", "--retry", "3", url], capture_output=True, text=True
    )
    size = None
    for line in head.stdout.splitlines():
        k, _, v = line.partition(":")
        if k.strip().lower() == "content-length":
            size = int(v.strip())
    return size


def download_ranged(url, parts_dir, connections, chunk_bytes, max_chunks=0):
    """aria2c-style segmented download: archive.org throttles per
    connection, so N parallel range requests multiply throughput. Parts
    land on disk (cpu-xl has 1 TB) and already-complete parts are
    skipped, so reruns resume. Parts stay gzip-concatenatable in order."""
    total = remote_size(url)
    if not total:
        raise RuntimeError(f"no content-length for {url}")
    parts_dir.mkdir(parents=True, exist_ok=True)
    nchunks = math.ceil(total / chunk_bytes)
    if max_chunks:
        nchunks = min(nchunks, max_chunks)
    done = [0]
    t0 = time.time()

    def fetch(i):
        start = i * chunk_bytes
        end = min(start + chunk_bytes, total) - 1
        path = parts_dir / f"part-{i:06d}"
        want = end - start + 1
        if path.exists() and path.stat().st_size == want:
            return
        for attempt in range(6):
            r = subprocess.run(
                ["curl", "-sfL", "--retry", "3", "-r", f"{start}-{end}",
                 "-o", str(path), url]
            )
            if r.returncode == 0 and path.stat().st_size == want:
                done[0] += 1
                if done[0] % 20 == 0:
                    gb = done[0] * chunk_bytes / 2**30
                    print(f"  … {gb:.0f} GiB down, {gb/max(time.time()-t0,1)*3600:.0f} GiB/h",
                          flush=True)
                return
            time.sleep(2 * attempt + 1)
        raise RuntimeError(f"range {start}-{end} failed after retries")

    with ThreadPoolExecutor(max_workers=connections) as ex:
        for _ in ex.map(fetch, range(nchunks)):
            pass


def parse_phase(parts_dir, out_dir, schema_spec, extract_name, nworkers, limit_lines):
    """gunzip over the ordered local parts -> 8 MiB line-aligned blocks
    fanned out to parser workers."""
    out_dir.mkdir(parents=True, exist_ok=True)
    queues = [mp.Queue(maxsize=8) for _ in range(nworkers)]
    procs = [
        mp.Process(target=worker, args=(i, out_dir, schema_spec, extract_name, queues[i]))
        for i in range(nworkers)
    ]
    for p in procs:
        p.start()

    # In smoke mode only the head of the gz stream exists, so gzip's
    # trailing-EOF complaint is expected; in a real run a nonzero gzip
    # exit means corruption and MUST fail the phase (gzip's CRC is our
    # end-to-end integrity check on the download).
    gunzip = subprocess.Popen(
        ["gzip", "-dc"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if limit_lines else None,
    )

    def feeder():
        try:
            for part in sorted(parts_dir.iterdir()):
                with open(part, "rb") as f:
                    shutil.copyfileobj(f, gunzip.stdin, 4 << 20)
            gunzip.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass

    feeder_t = threading.Thread(target=feeder, daemon=True)
    feeder_t.start()

    carry = b""
    read_bytes, lines, blocks, t0 = 0, 0, 0, time.time()
    try:
        while True:
            chunk = gunzip.stdout.read(BLOCK_BYTES)
            if not chunk:
                break
            read_bytes += len(chunk)
            buf = carry + chunk
            cut = buf.rfind(b"\n")
            if cut < 0:
                carry = buf
                continue
            block, carry = buf[: cut + 1], buf[cut + 1 :]
            lines += block.count(b"\n")
            queues[blocks % nworkers].put(block)
            blocks += 1
            if blocks % 1000 == 0:
                gb = read_bytes / 2**30
                rate = gb / max(time.time() - t0, 1)
                print(f"  … {gb:.1f} GiB json, {lines/1e6:.1f}M lines, "
                      f"{rate:.2f} GiB/s, mem {cgroup_mem_gib():.0f} GiB", flush=True)
            if limit_lines and lines >= limit_lines:
                break
        if carry and not limit_lines:
            queues[0].put(carry + b"\n")
    finally:
        gunzip.stdout.close()
        if limit_lines:
            gunzip.terminate()
        gzip_rc = gunzip.wait()
        feeder_t.join(timeout=30)
        for q in queues:
            q.put(None)
        for p in procs:
            p.join()
    if not limit_lines and gzip_rc != 0:
        raise RuntimeError(f"gzip exited {gzip_rc}: corrupt download, phase failed")
    print(f"  phase done: {lines} lines in {time.time()-t0:.0f}s", flush=True)


def build_final(work: Path, out: Path, threads: int):
    """Join, sort by sha256, write the published artifacts."""
    import duckdb

    con = duckdb.connect(str(work / "build.duckdb"))
    con.execute(f"SET threads = {threads}")
    con.execute(f"SET temp_directory = '{work / 'duckdb-tmp'}'")
    con.execute("SET preserve_insertion_order = false")

    files_glob = str(work / "files_raw" / "*.parquet")
    rel_glob = str(work / "releases_slim" / "*.parquet")
    (out / "data").mkdir(parents=True, exist_ok=True)
    (out / "maps").mkdir(parents=True, exist_ok=True)

    rel_cols = ", ".join(k for k in RELEASES_SCHEMA if k != "release_ident")
    con.execute(
        f"""
        COPY (
            WITH f AS (
                SELECT * EXCLUDE (release_idents),
                       unnest(if(len(release_idents) = 0, [NULL], release_idents))
                           AS release_ident
                FROM read_parquet('{files_glob}')
            )
            SELECT f.*, {rel_cols}
            FROM f LEFT JOIN read_parquet('{rel_glob}') r USING (release_ident)
            ORDER BY f.sha256
        ) TO '{out / "data"}'
        (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 262144,
         FILE_SIZE_BYTES '1GB', FILENAME_PATTERN 'files-{{i}}')
        """
    )
    for scheme in ("sha1", "md5"):
        con.execute(
            f"""
            COPY (
                SELECT DISTINCT {scheme}, sha256
                FROM read_parquet('{files_glob}')
                WHERE {scheme} IS NOT NULL AND sha256 IS NOT NULL
                ORDER BY {scheme}
            ) TO '{out / "maps" / (scheme + ".parquet")}'
            (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 262144)
            """
        )
    n = con.execute(f"SELECT count(*) FROM read_parquet('{out}/data/*.parquet')").fetchone()[0]
    print(f"final table: {n} rows", flush=True)


CARD = """\
---
license: cc0-1.0
pretty_name: fatcat files — hash-keyed scholarly file catalog
tags: [file-hashes, bibliography, fatcat, provenance]
---

One row per (file x release) from the **final fatcat bulk export**
(2024-02-18, Internet Archive; fatcat.wiki is offline). Sorted by
`sha256`, so hash point-lookups read one row group:

    SELECT title, doi, wayback_url
    FROM 'hf://datasets/{repo}/data/*.parquet'
    WHERE sha256 = '...';

`maps/sha1.parquet` and `maps/md5.parquet` (sorted by key) translate
weak digests to sha256 first. `wayback_url` points at the archived
bytes that actually carry the hash; DOI/arXiv/PMID identify the work;
fatcat idents remain as join keys into the raw dumps.

Built by [hashdex](https://github.com/davidar/hashdex)
`tools/fatcat_dataset_job.py`. Data: CC0 (fatcat's license).
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=None, help="HF dataset repo (user/name)")
    ap.add_argument("--out", default=None, help="work dir (default: $TMPDIR)")
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 4))
    ap.add_argument("--limit-lines", type=int, default=0, help="smoke test cap per input")
    ap.add_argument("--connections", type=int, default=5,
                    help="parallel range connections to archive.org (be polite)")
    ap.add_argument("--no-upload", action="store_true")
    args = ap.parse_args()
    if not args.no_upload and not args.repo:
        ap.error("--repo required unless --no-upload")

    work = Path(args.out or os.environ.get("TMPDIR", "/tmp")) / "fatcat-dataset"
    out = work / "publish"
    work.mkdir(parents=True, exist_ok=True)

    api = None
    if not args.no_upload:
        from huggingface_hub import HfApi

        api = HfApi()
        api.create_repo(args.repo, repo_type="dataset", exist_ok=True)

    def phase(name, fn):
        marker = work / f".done-{name}"
        if marker.exists():
            print(f"[{name}] already done, skipping", flush=True)
            return
        print(f"[{name}] start", flush=True)
        t0 = time.time()
        fn()
        marker.touch()
        print(f"[{name}] done in {(time.time()-t0)/60:.1f} min", flush=True)

    # Smoke tests fetch just the head of each dump in small chunks.
    chunk = (8 << 20) if args.limit_lines else (256 << 20)
    max_chunks = 2 if args.limit_lines else 0
    for name, url, schema_spec, extract_name in [
        ("files", FILE_EXPORT, FILES_SCHEMA, "file"),
        ("releases", RELEASE_EXPORT, RELEASES_SCHEMA, "release"),
    ]:
        dl = work / "dl" / name
        raw = work / ("files_raw" if name == "files" else "releases_slim")
        phase(
            f"download-{name}",
            lambda dl=dl, url=url: download_ranged(
                url, dl, args.connections, chunk, max_chunks
            ),
        )
        phase(
            f"parse-{name}",
            lambda dl=dl, raw=raw, s=schema_spec, e=extract_name: parse_phase(
                dl, raw, s, e, args.workers, args.limit_lines
            ),
        )
    phase("join", lambda: build_final(work, out, os.cpu_count() or 8))

    (out / "README.md").write_text(CARD.format(repo=args.repo or "<repo>"))
    if api:
        # Upload immediately after the join phase; data/ and maps/ are
        # the deliverables, README last so the card implies completeness.
        phase(
            "upload",
            lambda: api.upload_folder(
                repo_id=args.repo, repo_type="dataset", folder_path=str(out)
            ),
        )
        print(f"published: https://huggingface.co/datasets/{args.repo}", flush=True)
    else:
        print(f"artifacts in {out} (upload skipped)", flush=True)


if __name__ == "__main__":
    main()
