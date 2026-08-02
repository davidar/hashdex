#!/usr/bin/env python3
"""Parallel tabledata.list downloader for the hashdex_extracts tables.

tabledata.list is free (no query cost) and supports random access via
startIndex, so N workers page through disjoint row ranges concurrently.
Output: hex digest lines split per scheme, ready for `hdx filters build`.
"""
import base64, gzip, io, json, os, subprocess, sys, threading, time, urllib.request

PROJECT = "hashdex-sandbox"
DATASET = "hashdex_extracts"
OUTDIR = os.path.expanduser("~/.cache/hashdex/extracts")
WORKERS = 24
PAGE = 80000

_token_lock = threading.Lock()
_token = {"v": None, "t": 0}

def token():
    with _token_lock:
        if time.time() - _token["t"] > 1800:
            _token["v"] = subprocess.check_output(
                ["gcloud", "auth", "print-access-token"], text=True).strip()
            _token["t"] = time.time()
        return _token["v"]

def fetch(url):
    for attempt in range(6):
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token()}",
            "Accept-Encoding": "gzip",
        })
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return json.loads(data)
        except Exception as e:
            if attempt == 5:
                raise
            time.sleep(2 ** attempt)
            if getattr(e, "code", None) == 401:
                with _token_lock:
                    _token["t"] = 0

def table_rows(table):
    meta = fetch(f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/{DATASET}/tables/{table}")
    return int(meta["numRows"])

progress = {"rows": 0}
_plock = threading.Lock()

def worker(table, kind, start, end, wid, files):
    i = start
    while i < end:
        n = min(PAGE, end - i)
        url = (f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}"
               f"/datasets/{DATASET}/tables/{table}/data?startIndex={i}&maxResults={n}&alt=json")
        d = fetch(url)
        rows = d.get("rows", [])
        if not rows:
            print(f"  worker {wid}: empty page at {i}, stopping", file=sys.stderr)
            break
        out = {k: [] for k in files}
        for r in rows:
            v = r["f"][0]["v"]
            if v is None:
                continue
            if kind == "bytes":
                raw = base64.b64decode(v)
                if len(raw) == 20:
                    out["sha1"].append(raw.hex().upper())
                elif len(raw) == 32:
                    out["sha256"].append(raw.hex())
            else:
                out["sha256"].append(v.lower())
        for k, lines in out.items():
            if lines:
                files[k].write("\n".join(lines) + "\n")
        i += len(rows)
        with _plock:
            progress["rows"] += len(rows)

def run(table, kind, prefix):
    total = table_rows(table)
    print(f"{table}: {total} rows", file=sys.stderr)
    chunk = (total + WORKERS - 1) // WORKERS
    threads = []
    all_files = []
    schemes = ["sha1", "sha256"] if kind == "bytes" else ["sha256"]
    for w in range(WORKERS):
        files = {s: open(os.path.join(OUTDIR, f"{prefix}.{s}.{w}.hex"), "w", buffering=1 << 20)
                 for s in schemes}
        all_files.append(files)
        t = threading.Thread(target=worker, args=(
            table, kind, w * chunk, min((w + 1) * chunk, total), w, files))
        t.start()
        threads.append(t)
    t0 = time.time()
    while any(t.is_alive() for t in threads):
        time.sleep(10)
        r = progress["rows"]
        rate = r / max(time.time() - t0, 1)
        print(f"  {r}/{total} rows ({rate:,.0f}/s)", file=sys.stderr)
    for t in threads:
        t.join()
    for files in all_files:
        for f in files.values():
            f.close()
    print(f"{table} done: {progress['rows']} rows", file=sys.stderr)
    progress["rows"] = 0

if __name__ == "__main__":
    os.makedirs(OUTDIR, exist_ok=True)
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "rekor"):
        run("rekor_digests", "string", "rekor")
    if which in ("all", "depsdev"):
        run("depsdev_hashes", "bytes", "depsdev")
