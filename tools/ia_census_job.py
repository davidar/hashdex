# /// script
# requires-python = ">=3.10"
# dependencies = ["pyarrow>=17", "duckdb>=1.0", "huggingface_hub>=0.24"]
# ///
"""HF Job: build and publish the ia-census dataset entirely in-DC.

The laptop route died on residential uplink (14 GB of parquet); the
job downloads the two census dumps from archive.org, runs the
published rebuild script (fetched from the dataset repo itself), and
uploads every artifact THE MOMENT it verifies — phase outputs must
land on the Hub mid-run, job-local state dies with the job.

Launch:
  hf jobs uv run --flavor cpu-xl --timeout 4h -s HF_TOKEN \
      tools/ia_census_job.py

Smoke (local, no network writes):
  CENSUS_SMOKE=1 uv run tools/ia_census_job.py
"""
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

REPO = "david-ar/ia-census"
CENSUS_ITEM = "https://archive.org/download/ia_census_201604"
# name -> exact size: the census is frozen, so byte counts are facts.
DUMPS = {
    "file_hashes_md5_20160411221100_public.tsv.gz": 5_212_673_170,
    "file_hashes_sha1_20160411221100_public.tsv.gz": 6_120_162_493,
}
SMOKE = bool(os.environ.get("CENSUS_SMOKE"))
WORK = pathlib.Path(os.environ.get("CENSUS_WORK", "/tmp/census"))


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ------------------------------------------------------------- bloom
# The same embedded DCSO builder the SWH job verified byte-exact
# against src/filter.rs: FNV-1 64 % (2^64-87), k rounds of Go-wrapping
# multiply by G, LE u64 header (version,n,p,k,m,N) then the bit array.
# Keys are UPPERCASE hex sha1 (the scan convention), streamed on stdin
# as fixed 40-byte records.

RUST_CARGO_TOML = """\
[package]
name = "dcso_bloom"
version = "0.1.0"
edition = "2021"

[profile.release]
lto = true
codegen-units = 1
"""

RUST_MAIN = r"""
use std::io::{Read, Write};

#[cfg(not(target_endian = "little"))]
compile_error!("little-endian only (DCSO format is LE; we dump words raw)");

const MOD: u64 = 18_446_744_073_709_551_529; // 2^64 - 87
const G: u64 = 18_446_744_073_709_550_147;

fn fnv1_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h = h.wrapping_mul(0x100000001b3);
        h ^= b as u64;
    }
    h
}

fn main() {
    // args: n p record out — keys arrive on stdin as fixed-width
    // records, ALREADY uppercased, no separators.
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (n, p, rec, out) = (
        a[0].parse::<u64>().unwrap(),
        a[1].parse::<f64>().unwrap(),
        a[2].parse::<usize>().unwrap(),
        &a[3],
    );
    let ln2 = std::f64::consts::LN_2;
    let m = ((n as f64) * (-p.ln()) / (ln2 * ln2)).ceil() as u64;
    let k = ((m as f64 / n as f64) * ln2).round().max(1.0) as u64;
    let words = m.div_ceil(64) as usize;
    eprintln!("dcso_bloom: n={n} p={p} m={m} k={k} ({} MiB)", words * 8 / 1048576);

    let mut bits = vec![0u64; words];
    let mut stdin = std::io::stdin().lock();
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 8 << 20];
    let mut inserted: u64 = 0;
    loop {
        let got = stdin.read(&mut buf).expect("stdin read");
        if got == 0 {
            break;
        }
        let mut chunk = std::mem::take(&mut carry);
        chunk.extend_from_slice(&buf[..got]);
        let keep = chunk.len() - chunk.len() % rec;
        carry = chunk.split_off(keep);
        for r in chunk.chunks_exact(rec) {
            let mut h = fnv1_64(r) % MOD;
            for _ in 0..k {
                h = h.wrapping_mul(G) % MOD;
                let bit = h % m;
                bits[(bit >> 6) as usize] |= 1u64 << (bit & 63);
            }
            inserted += 1;
        }
    }
    assert!(carry.is_empty(), "trailing {} bytes not a whole record", carry.len());

    let file = std::fs::File::create(out).expect("create out");
    let mut w = std::io::BufWriter::with_capacity(8 << 20, file);
    for v in [1u64, n, p.to_bits(), k, m, inserted] {
        w.write_all(&v.to_le_bytes()).unwrap();
    }
    let raw: &[u8] =
        unsafe { std::slice::from_raw_parts(bits.as_ptr() as *const u8, words * 8) };
    w.write_all(raw).unwrap();
    w.flush().unwrap();
    eprintln!("dcso_bloom: inserted {inserted} keys -> {out}");
}
"""


def build_bloom(outdir, dest):
    import duckdb

    keys = WORK / "sha1_keys.txt"
    con = duckdb.connect()
    con.execute("SET preserve_insertion_order=false")
    con.execute("SET memory_limit='6GB'")
    con.execute(
        f"""COPY (SELECT DISTINCT upper(sha1) FROM read_parquet('{outdir}/data/census-*.parquet'))
            TO '{keys}' (FORMAT csv, HEADER false)"""
    )
    n = con.execute(
        f"SELECT count(*) FROM read_csv('{keys}', header=false)"
    ).fetchone()[0]
    con.close()
    log(f"bloom keys: {n:,} distinct sha1")

    src = WORK / "dcso_bloom"
    (src / "src").mkdir(parents=True, exist_ok=True)
    (src / "Cargo.toml").write_text(RUST_CARGO_TOML)
    (src / "src" / "main.rs").write_text(RUST_MAIN)
    cargo = shutil.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")
    if not os.path.exists(cargo):
        log("installing rust toolchain (minimal) …")
        rustup = WORK / "rustup.sh"
        urllib.request.urlretrieve("https://sh.rustup.rs", rustup)
        subprocess.run(
            ["sh", str(rustup), "-y", "--profile", "minimal", "--default-toolchain", "stable"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        cargo = os.path.expanduser("~/.cargo/bin/cargo")
    subprocess.run([cargo, "build", "--release", "--quiet"], cwd=src, check=True)
    builder = src / "target" / "release" / "dcso_bloom"

    log("inserting keys …")
    proc = subprocess.Popen(
        [str(builder), str(n), "0.0001", "40", str(dest)], stdin=subprocess.PIPE
    )
    with open(keys, "rb") as f:
        while chunk := f.read(1 << 22):
            proc.stdin.write(chunk.translate(None, b"\n"))
    proc.stdin.close()
    if proc.wait() != 0:
        sys.exit("bloom builder failed")
    log(f"bloom: {dest.stat().st_size:,} bytes")


def fetch(url, dest, want):
    """Resumable download: a 60s socket timeout turns a stalled IA
    datanode connection into a Range-resumed retry instead of an
    eternal hang (one stall once sat 30 minutes on a 2-minute file)."""
    if dest.exists() and dest.stat().st_size == want:
        log(f"kept {dest.name} ({want:,} bytes)")
        return
    part = dest.with_name(dest.name + ".part")
    log(f"downloading {url}")
    for attempt in range(30):
        have = part.stat().st_size if part.exists() else 0
        if have >= want:
            break
        req = urllib.request.Request(
            url, headers={"Range": f"bytes={have}-"} if have else {}
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r, open(part, "ab") as out:
                got = have
                t0 = last = time.monotonic()
                base = have
                while chunk := r.read(1 << 22):
                    out.write(chunk)
                    got += len(chunk)
                    now = time.monotonic()
                    if now - last >= 15:
                        last = now
                        rate = (got - base) / (now - t0)
                        eta = int((want - got) / rate) if rate > 0 else -1
                        log(
                            f"  {got / 1e9:.2f} / {want / 1e9:.2f} GB "
                            f"({rate / 1e6:.1f} MB/s, ETA {eta // 60}m{eta % 60:02d}s)"
                        )
        except Exception as e:
            log(f"  stalled at {have:,}/{want:,} (attempt {attempt + 1}): {e}")
            time.sleep(10)
    got = part.stat().st_size if part.exists() else 0
    if got != want:
        sys.exit(f"{dest.name}: got {got:,} bytes, expected {want:,}")
    part.rename(dest)
    log(f"got {dest.name} ({want:,} bytes)")


def main():
    WORK.mkdir(parents=True, exist_ok=True)

    if SMOKE:
        import gzip
        import hashlib

        rows = []
        for i in range(5000):
            ident = f"item_{i // 10:04d}"
            fname = f"file_{i % 10}.pdf" if i % 10 else f"{ident}_meta.xml"
            content = f"content{i}".encode()
            rows.append(
                (
                    ident,
                    fname,
                    hashlib.md5(content).hexdigest(),
                    hashlib.sha1(content).hexdigest(),
                )
            )
        names = list(DUMPS)
        with gzip.open(WORK / names[0], "wt") as f:
            for r in rows:
                f.write(f"{r[0]}\t{r[1]}\t{r[2]}\n")
        with gzip.open(WORK / names[1], "wt") as f:
            for r in rows:
                f.write(f"{r[0]}\t{r[1]}\t{r[3]}\n")
        tool = pathlib.Path(__file__).parent / "ia_census_parquet.py"
        log("smoke dumps written")
    else:
        for name, want in DUMPS.items():
            fetch(f"{CENSUS_ITEM}/{name}", WORK / name, want)
        from huggingface_hub import hf_hub_download

        tool = pathlib.Path(
            hf_hub_download(REPO, "ia_census_parquet.py", repo_type="dataset")
        )
        log(f"pipeline: {tool}")

    outdir = WORK / "parquet"
    log("running pipeline …")
    subprocess.run(
        [sys.executable, str(tool), str(WORK), str(outdir)], check=True
    )

    files = sorted(p.relative_to(outdir) for p in outdir.rglob("*.parquet"))
    log(f"pipeline done: {len(files)} files")

    bloom = outdir / "ia-census.sha1.bloom"
    build_bloom(outdir, bloom)
    files.append(bloom.relative_to(outdir))

    if SMOKE:
        log("smoke: skipping upload")
        return

    # Upload the moment each artifact exists — a later failure must
    # not orphan finished work.
    from huggingface_hub import HfApi

    api = HfApi()
    for rel in files:
        for attempt in range(5):
            try:
                api.upload_file(
                    path_or_fileobj=str(outdir / rel),
                    path_in_repo=str(rel),
                    repo_id=REPO,
                    repo_type="dataset",
                    commit_message=f"data: {rel}",
                )
                log(f"uploaded {rel}")
                break
            except Exception as e:
                log(f"upload {rel} failed (attempt {attempt + 1}): {e}")
                time.sleep(30 * (attempt + 1))
        else:
            sys.exit(f"giving up on {rel}")
    log("ALL UPLOADS DONE")


if __name__ == "__main__":
    main()
