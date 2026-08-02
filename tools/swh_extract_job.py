# /// script
# requires-python = ">=3.11"
# dependencies = ["pyarrow>=17", "huggingface_hub>=0.30"]
# ///
"""Build the SWH content bloom filter (sha256, DCSO format) by streaming
the hash column of Software Heritage's graph dataset `content` table
(s3://softwareheritage, anonymous, ~29.3B rows / 128 ORC files).

Designed for HF Jobs (in-AWS, same region as the bucket):

    hf jobs uv run --flavor cpu-performance --timeout 8h -s HF_TOKEN \
        tools/swh_extract_job.py -- --export 2026-06-04 \
        --repo <user>/swh-content-bloom

Local smoke test (one stripe of one file, ~100 MB):

    uv run tools/swh_extract_job.py --export 2026-06-04 \
        --limit-files 1 --limit-stripes 1 --no-upload --out /tmp/swh-smoke

The bloom builder is an embedded zero-dependency Rust program whose
hashing is a bit-exact copy of src/filter.rs (DCSO: FNV-1 64 % (2^64-87),
k rounds of Go-semantics wrapping multiply by 18446744073709550147).
Keys are LOWERCASE sha256 hex, matching hdx's filter convention.
Byte-identical output to `hdx filters build` on identical input order.
"""

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

BUCKET = "softwareheritage"
REGION = "us-east-1"

RUST_CARGO_TOML = """\
[package]
name = "swh_bloom"
version = "0.1.0"
edition = "2021"

[profile.release]
lto = true
codegen-units = 1
"""

# Keep in sync with src/filter.rs (BloomBuilder). Same constants, same
# sizing formulas, same insertion arithmetic, same file layout.
RUST_MAIN = r"""
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

#[cfg(not(target_endian = "little"))]
compile_error!("little-endian only (DCSO format is LE; we dump words raw)");

const MOD: u64 = 18_446_744_073_709_551_529; // 2^64 - 87
const G: u64 = 18_446_744_073_709_550_147;
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn fnv1_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h = h.wrapping_mul(0x100000001b3);
        h ^= b as u64;
    }
    h
}

struct Args {
    n: u64,
    p: f64,
    record: usize,
    mode: String, // "raw-to-hex" | "hex" | "hex-to-lower"
    out: String,
}

fn parse_args() -> Args {
    let mut a = Args { n: 0, p: 0.001, record: 32, mode: "raw-to-hex".into(), out: String::new() };
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        let mut v = || it.next().expect("missing value");
        match f.as_str() {
            "--n" => a.n = v().parse().unwrap(),
            "--p" => a.p = v().parse().unwrap(),
            "--record" => a.record = v().parse().unwrap(),
            "--mode" => a.mode = v(),
            "--out" => a.out = v(),
            _ => panic!("unknown flag {f}"),
        }
    }
    assert!(a.n > 0 && a.p > 0.0 && a.p < 1.0 && !a.out.is_empty());
    a
}

fn main() {
    let args = parse_args();
    let ln2 = std::f64::consts::LN_2;
    let m = ((args.n as f64) * (-args.p.ln()) / (ln2 * ln2)).ceil() as u64;
    let k = ((m as f64 / args.n as f64) * ln2).round().max(1.0) as u64;
    let words = m.div_ceil(64) as usize;
    eprintln!("swh_bloom: n={} p={} m={} k={} ({} MiB)", args.n, args.p, m, k, words * 8 / 1048576);

    let mut bits: Vec<AtomicU64> = Vec::with_capacity(words);
    bits.resize_with(words, || AtomicU64::new(0));
    let bits = Arc::new(bits);

    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(2) - 1;
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(threads * 2);
    let rx = Arc::new(Mutex::new(rx));
    let total = Arc::new(AtomicU64::new(0));
    let rec = args.record;
    let mode = args.mode.clone();

    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let rx = rx.clone();
            let bits = bits.clone();
            let total = total.clone();
            let mode = mode.clone();
            std::thread::spawn(move || {
                let mut key = [0u8; 128];
                loop {
                    let chunk = match rx.lock().unwrap().recv() {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let mut n = 0u64;
                    for r in chunk.chunks_exact(rec) {
                        let kb: &[u8] = match mode.as_str() {
                            "raw-to-hex" | "raw-to-hex-upper" => {
                                let tab = if mode == "raw-to-hex" { HEX_LOWER } else { HEX_UPPER };
                                for (i, &b) in r.iter().enumerate() {
                                    key[i * 2] = tab[(b >> 4) as usize];
                                    key[i * 2 + 1] = tab[(b & 15) as usize];
                                }
                                &key[..rec * 2]
                            }
                            "hex-to-lower" => {
                                for (i, &b) in r.iter().enumerate() {
                                    key[i] = b.to_ascii_lowercase();
                                }
                                &key[..rec]
                            }
                            "hex-to-upper" => {
                                for (i, &b) in r.iter().enumerate() {
                                    key[i] = b.to_ascii_uppercase();
                                }
                                &key[..rec]
                            }
                            _ => r,
                        };
                        let mut h = fnv1_64(kb) % MOD;
                        for _ in 0..k {
                            h = h.wrapping_mul(G) % MOD;
                            let bit = h % m;
                            bits[(bit >> 6) as usize].fetch_or(1u64 << (bit & 63), Ordering::Relaxed);
                        }
                        n += 1;
                    }
                    total.fetch_add(n, Ordering::Relaxed);
                }
            })
        })
        .collect();

    // reader: stdin -> record-aligned chunks
    let mut stdin = std::io::stdin().lock();
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 8 << 20];
    loop {
        let got = stdin.read(&mut buf).expect("stdin read");
        if got == 0 {
            break;
        }
        let mut chunk = std::mem::take(&mut carry);
        chunk.extend_from_slice(&buf[..got]);
        let keep = chunk.len() - chunk.len() % rec;
        carry = chunk.split_off(keep);
        if !chunk.is_empty() {
            tx.send(chunk).expect("send");
        }
    }
    assert!(carry.is_empty(), "trailing {} bytes not a whole record", carry.len());
    drop(tx);
    for w in workers {
        w.join().unwrap();
    }
    let n_elements = total.load(Ordering::Relaxed);

    let file = std::fs::File::create(&args.out).expect("create out");
    let mut w = std::io::BufWriter::with_capacity(8 << 20, file);
    for v in [1u64, args.n, args.p.to_bits(), k, m, n_elements] {
        w.write_all(&v.to_le_bytes()).unwrap();
    }
    // LE host (enforced above): AtomicU64 array is plain u64 words in memory
    let raw: &[u8] =
        unsafe { std::slice::from_raw_parts(bits.as_ptr() as *const u8, words * 8) };
    w.write_all(raw).unwrap();
    w.flush().unwrap();
    eprintln!("swh_bloom: inserted {} keys -> {}", n_elements, args.out);
}
"""


def ensure_cargo() -> str:
    cargo = shutil.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")
    if os.path.exists(cargo):
        return cargo
    print("installing rust toolchain (minimal)...", flush=True)
    rustup = tempfile.mktemp(suffix=".sh")
    urllib.request.urlretrieve("https://sh.rustup.rs", rustup)
    subprocess.run(
        ["sh", rustup, "-y", "--profile", "minimal", "--default-toolchain", "stable"],
        check=True, stdout=subprocess.DEVNULL,
    )
    return os.path.expanduser("~/.cargo/bin/cargo")


def build_builder(workdir: str) -> str:
    src = os.path.join(workdir, "swh_bloom")
    os.makedirs(os.path.join(src, "src"), exist_ok=True)
    with open(os.path.join(src, "Cargo.toml"), "w") as f:
        f.write(RUST_CARGO_TOML)
    with open(os.path.join(src, "src", "main.rs"), "w") as f:
        f.write(RUST_MAIN)
    cargo = ensure_cargo()
    subprocess.run(
        [cargo, "build", "--release", "--quiet"],
        cwd=src, check=True,
    )
    return os.path.join(src, "target", "release", "swh_bloom")


def list_content_files(export: str) -> list[tuple[str, int]]:
    files, token = [], None
    while True:
        q = {"list-type": "2", "prefix": f"graph/{export}/orc/content/", "max-keys": "1000"}
        if token:
            q["continuation-token"] = token
        url = f"https://{BUCKET}.s3.amazonaws.com/?" + urllib.parse.urlencode(q)
        with urllib.request.urlopen(url, timeout=60) as r:
            xml = r.read().decode()
        import re
        keys = re.findall(r"<Key>([^<]+)</Key>", xml)
        sizes = re.findall(r"<Size>(\d+)</Size>", xml)
        assert len(keys) == len(sizes), "unparseable S3 listing"
        files += [(k, int(s)) for k, s in zip(keys, sizes) if k.endswith(".orc")]
        t = re.search(r"<NextContinuationToken>([^<]+)</NextContinuationToken>", xml)
        if not t:
            break
        token = t.group(1)
    if not files:
        sys.exit(f"no content ORC files found for export {export}")
    return sorted(files)


def chunk_data(chunk) -> memoryview:
    """Zero-copy bytes of a uniform-width binary/string arrow array chunk."""
    import pyarrow as pa

    assert chunk.null_count == 0, "unexpected nulls in hash column"
    t = chunk.type
    bufs = chunk.buffers()
    if pa.types.is_fixed_size_binary(t):
        w = t.byte_width
        return memoryview(bufs[1])[chunk.offset * w:(chunk.offset + len(chunk)) * w]
    fmt = "q" if (pa.types.is_large_binary(t) or pa.types.is_large_string(t)) else "i"
    off = memoryview(bufs[1]).cast(fmt)
    start, end = off[chunk.offset], off[chunk.offset + len(chunk)]
    data = memoryview(bufs[2])[start:end]
    assert len(data) % len(chunk) == 0, "non-uniform hash column widths"
    return data


# hdx filter-key conventions: sha1 is UPPERCASE hex (CIRCL's choice,
# inherited by every sha1 filter); everything else lowercase hex.
SCHEME_CASE = {"sha1": "hex-to-upper", "sha1_git": "hex-to-lower",
               "sha256": "hex-to-lower", "blake2s256": "hex-to-lower"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", required=True, help="e.g. 2026-06-04")
    ap.add_argument("--repo", help="HF repo for the result (created private)")
    ap.add_argument("--out", default="swh-out")
    ap.add_argument("--p", type=float, default=0.0001)
    ap.add_argument("--n", type=int, help="override key-count estimate for sizing")
    ap.add_argument("--schemes", default="sha256,sha1_git,sha1,blake2s256",
                    help="comma-separated content-table hash columns to build filters for")
    ap.add_argument("--per-pass", type=int, default=2,
                    help="schemes built concurrently; each holds a full bit array in RAM")
    ap.add_argument("--limit-files", type=int)
    ap.add_argument("--limit-stripes", type=int)
    ap.add_argument("--readers", type=int, default=6)
    ap.add_argument("--no-upload", action="store_true")
    args = ap.parse_args()

    schemes = [s.strip() for s in args.schemes.split(",") if s.strip()]
    for s in schemes:
        if s not in SCHEME_CASE:
            sys.exit(f"unknown scheme {s} (know: {', '.join(SCHEME_CASE)})")

    from pyarrow import fs, orc

    os.makedirs(args.out, exist_ok=True)
    builder_bin = build_builder(args.out)
    files = list_content_files(args.export)
    total_bytes = sum(s for _, s in files)
    print(f"export {args.export}: {len(files)} content ORC files, "
          f"{total_bytes / 2**40:.2f} TiB total", flush=True)
    if args.limit_files:
        files = files[: args.limit_files]

    s3 = fs.S3FileSystem(anonymous=True, region=REGION)

    # exact row count from footers (cheap metadata reads) unless overridden
    if args.n:
        n = args.n
    else:
        counts = {}
        lock = threading.Lock()

        def footer(key):
            f = orc.ORCFile(s3.open_input_file(f"{BUCKET}/{key}"))
            with lock:
                counts[key] = f.nrows

        threads = [threading.Thread(target=footer, args=(k,)) for k, _ in files]
        for i in range(0, len(threads), 16):
            batch = threads[i:i + 16]
            [t.start() for t in batch]
            [t.join() for t in batch]
        n = sum(counts.values())
    print(f"sizing for n={n} keys at p={args.p}", flush=True)

    # peek one stripe to learn each column's encoding: raw digest bytes
    # -> hex-encode in the builder; hex strings -> case-normalize.
    peek = orc.ORCFile(s3.open_input_file(f"{BUCKET}/{files[0][0]}"))
    peek_batch = peek.read_stripe(0, columns=schemes)
    plans = {}  # scheme -> (record_width, builder_mode)
    raw_widths = {"sha1": 20, "sha1_git": 20, "sha256": 32, "blake2s256": 32}
    for s in schemes:
        pk = peek_batch.column(s)
        pk = pk.chunks[0] if hasattr(pk, "chunks") else pk
        width = len(chunk_data(pk)) // len(pk)
        if width == raw_widths[s]:
            mode = "raw-to-hex-upper" if SCHEME_CASE[s] == "hex-to-upper" else "raw-to-hex"
        elif width == raw_widths[s] * 2:
            mode = SCHEME_CASE[s]
        else:
            sys.exit(f"unexpected {s} column width {width}")
        plans[s] = (width, mode)
        print(f"{s}: {width}-byte records, mode {mode}", flush=True)

    all_stats = {"export": args.export, "n_sized_for": n, "p": args.p,
                 "schemes": {}, "t0": time.time()}
    for pass_schemes in [schemes[i:i + args.per_pass]
                         for i in range(0, len(schemes), args.per_pass)]:
        print(f"=== pass: {', '.join(pass_schemes)} ===", flush=True)
        children = {}
        for s in pass_schemes:
            width, mode = plans[s]
            children[s] = subprocess.Popen(
                [builder_bin, "--n", str(n), "--p", str(args.p),
                 "--record", str(width), "--mode", mode,
                 "--out", os.path.join(args.out, f"swh.{s}.bloom")],
                stdin=subprocess.PIPE,
            )
        state = {"rows": 0, "bytes": 0, "t0": time.time()}
        write_lock = threading.Lock()
        work = queue.Queue()
        for key, _ in files:
            work.put(key)

        def reader():
            while True:
                try:
                    key = work.get_nowait()
                except queue.Empty:
                    return
                f = orc.ORCFile(s3.open_input_file(f"{BUCKET}/{key}"))
                nstripes = f.nstripes
                if args.limit_stripes:
                    nstripes = min(nstripes, args.limit_stripes)
                for i in range(nstripes):
                    tbl = f.read_stripe(i, columns=pass_schemes)
                    per_scheme = []
                    rows = 0
                    for s in pass_schemes:
                        col = tbl.column(s)
                        chunks = col.chunks if hasattr(col, "chunks") else [col]
                        datas = [chunk_data(c) for c in chunks]
                        rows = sum(len(c) for c in chunks)
                        assert sum(len(d) for d in datas) == plans[s][0] * rows, \
                            f"{s} column width changed mid-stream"
                        per_scheme.append((s, datas))
                    with write_lock:
                        for s, datas in per_scheme:
                            for d in datas:
                                children[s].stdin.write(d)
                                state["bytes"] += len(d)
                        state["rows"] += rows
                        dt = time.time() - state["t0"]
                        if state["rows"] % 50_000_000 < rows:
                            pct = 100 * state["rows"] / n
                            print(f"{state['rows']:,} rows ({pct:.1f}%), "
                                  f"{state['bytes'] / 2**30:.1f} GiB, "
                                  f"{state['bytes'] / dt / 2**20:.0f} MiB/s", flush=True)

        readers = [threading.Thread(target=reader) for _ in range(args.readers)]
        [t.start() for t in readers]
        [t.join() for t in readers]
        for s in pass_schemes:
            children[s].stdin.close()
        for s in pass_schemes:
            rc = children[s].wait()
            if rc != 0:
                sys.exit(f"bloom builder for {s} exited {rc}")
            all_stats["schemes"][s] = {
                "bloom_bytes": os.path.getsize(os.path.join(args.out, f"swh.{s}.bloom")),
                "rows_streamed": state["rows"],
            }
        print(f"pass done in {time.time() - state['t0']:.0f}s", flush=True)

    all_stats["wall_seconds"] = round(time.time() - all_stats.pop("t0"), 1)
    stats = all_stats
    with open(os.path.join(args.out, "stats.json"), "w") as f:
        json.dump(stats, f, indent=2)
    print(json.dumps(stats, indent=2), flush=True)

    if args.no_upload:
        return
    if not args.repo:
        sys.exit("--repo required unless --no-upload")
    from huggingface_hub import HfApi

    scheme_rows = "\n".join(
        f"| `swh.{s}.bloom` | {s} | "
        f"{'UPPERCASE' if SCHEME_CASE[s] == 'hex-to-upper' else 'lowercase'} hex |"
        for s in schemes)
    card = f"""---
license: cc-by-4.0
pretty_name: Software Heritage content bloom filters
---

# Software Heritage content membership filters

DCSO-format bloom filters over the content hashes of **all {n:,}
content blobs** in the [Software Heritage](https://www.softwareheritage.org/)
archive (graph dataset export {args.export}, `content` table), one
filter per hash scheme, false-positive rate p = {args.p} each:

| file | keyed on | key encoding |
|---|---|---|
{scheme_rows}

`sha1_git` is the git blob id — membership testing straight from a git
object id, no file bytes needed.

Ask "has SWH archived this content?" without touching the rate-limited
API — then confirm hits at
`https://archive.softwareheritage.org/api/1/content/<scheme>:<hex>/`.
Built for [hashdex](https://github.com/davidar/hashdex) (`hdx scan`),
readable by any DCSO/hashlookup-compatible bloom implementation
(header: LE u64 version, n, p-bits, k, m, N; then bit array;
membership = FNV-1 64 mod 2^64-87, k rounds of wrapping multiply by
18446744073709550147 mod 2^64-87, bit index mod m).

Derived from the Software Heritage graph dataset (CC-BY 4.0,
attribution: Software Heritage). See their
[dataset docs](https://docs.softwareheritage.org/devel/swh-export/graph/dataset.html).
"""
    api = HfApi()
    api.create_repo(args.repo, repo_type="dataset", private=False, exist_ok=True)
    api.upload_file(path_or_fileobj=card.encode(), path_in_repo="README.md",
                    repo_id=args.repo, repo_type="dataset")
    for name in [f"swh.{s}.bloom" for s in schemes] + ["stats.json"]:
        api.upload_file(
            path_or_fileobj=os.path.join(args.out, name),
            path_in_repo=f"{args.export}/{name}",
            repo_id=args.repo,
            repo_type="dataset",
        )
    print(f"uploaded to https://huggingface.co/datasets/{args.repo}")


if __name__ == "__main__":
    main()
