#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyarrow>=17", "duckdb>=1.0"]
# ///
"""Build the ia-census parquet dataset from the 2016 IA census dumps.

The April 2016 Internet Archive census (archive.org/details/ia_census_201604)
published per-file md5 and sha1 for every public item — two TSVs from
the same item walk, LINE-ALIGNED with each other (verified: identical
(identifier, filename) sequences; they are NOT lexicographically
sorted — filenames come in files.xml order), so the md5+sha1 join is
a zip that asserts alignment on every line. Each joined row is a
single witness co-observing both weak digests, with a claim URL by
construction: https://archive.org/download/<identifier>/<filename>.

Output mirrors the fatcat layout (sharded by first sha1 nibble so cold
point lookups parse a small footer):

  data/census-{0..f}.parquet   sha1 md5 identifier filename, sorted by sha1
  maps/md5.parquet             md5 sha1, sorted by md5

Item-machinery sidecars (<id>_meta.xml, <id>_files.xml, .torrent, …)
are dropped: they are per-item derivative plumbing, not content anyone
holds. Rows with a malformed hash or a tab in the filename are dropped
and counted.

Usage:
  uv run tools/ia_census_parquet.py [census_dir] [outdir]
  (defaults: ~/.cache/hashdex/census, sibling parquet/)
"""
import gzip
import json
import pathlib
import sys

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

MD5_DUMP = "file_hashes_md5_20160411221100_public.tsv.gz"
SHA1_DUMP = "file_hashes_sha1_20160411221100_public.tsv.gz"

SCHEMA = pa.schema(
    [
        ("sha1", pa.string()),
        ("md5", pa.string()),
        ("identifier", pa.string()),
        ("filename", pa.string()),
    ]
)

# Page size is only enforced per write batch: a large batch writes one
# giant page regardless of data_page_size. Keep batches small.
WRITER_OPTS = dict(
    compression="zstd",
    compression_level=3,
    use_dictionary=False,
    data_page_size=128 * 1024,
    write_batch_size=256,
    write_page_index=True,
)
ROW_GROUP = 262144

# IA-generated item plumbing, present in virtually every item and held
# by nobody's disk. Suffix-matched against "<identifier>_<suffix>".
SIDECAR_SUFFIXES = (
    "meta.xml",
    "files.xml",
    "meta.sqlite",
    "archive.torrent",
    "reviews.xml",
)


def split3(line):
    """(identifier, filename, last-field) or None. First field is the
    identifier, LAST field the hash — filenames may contain tabs."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 3:
        return None
    return parts[0], "\t".join(parts[1:-1]), parts[-1]


def valid_hex(s, hex_len):
    s = s.lower()
    if len(s) != hex_len or any(c not in "0123456789abcdef" for c in s):
        return None
    return s


def is_sidecar(ident, fname):
    return any(fname == f"{ident}_{s}" for s in SIDECAR_SUFFIXES)


def merge_join(census_dir, tmp_dir, counts):
    """Zip the two line-aligned dumps into unsorted parquet parts,
    asserting (identifier, filename) alignment on EVERY line — a
    desync would silently pair wrong hashes, so it is fatal."""
    tmp_dir.mkdir(parents=True, exist_ok=True)

    part_no = 0
    buf = {c: [] for c in SCHEMA.names}

    def flush():
        nonlocal part_no, buf
        if not buf["sha1"]:
            return
        table = pa.table({c: pa.array(buf[c], type=pa.string()) for c in SCHEMA.names})
        pq.write_table(table, tmp_dir / f"part-{part_no:05d}.parquet")
        part_no += 1
        buf = {c: [] for c in SCHEMA.names}

    opts = dict(encoding="utf-8", errors="replace")
    with gzip.open(census_dir / MD5_DUMP, "rt", **opts) as fa, gzip.open(
        census_dir / SHA1_DUMP, "rt", **opts
    ) as fb:
        for lineno, (la, lb) in enumerate(zip(fa, fb), 1):
            a = split3(la)
            b = split3(lb)
            if a is None or b is None:
                # One side without even 3 fields while the other has
                # them would mean different walks — fatal. Both bad:
                # count and continue (alignment is per line, so a
                # skipped pair cannot desync the zip).
                if (a is None) != (b is None):
                    sys.exit(f"line {lineno}: one-sided malformed row\n{la!r}\n{lb!r}")
                counts["malformed"] += 1
                continue
            if (a[0], a[1]) != (b[0], b[1]):
                sys.exit(f"line {lineno}: dumps desynced — {a[:2]!r} vs {b[:2]!r}")
            # Hash fields are occasionally garbage (e.g. a URL-encoded
            # JSON array where an md5 should be) — drop the row, keep
            # the alignment.
            md5 = valid_hex(a[2], 32)
            sha1 = valid_hex(b[2], 40)
            if md5 is None or sha1 is None:
                counts["badhash"] += 1
                continue
            if is_sidecar(a[0], a[1]):
                counts["sidecar"] += 1
                continue
            buf["sha1"].append(sha1)
            buf["md5"].append(md5)
            buf["identifier"].append(a[0])
            buf["filename"].append(a[1])
            counts["joined"] += 1
            if len(buf["sha1"]) >= 2_000_000:
                flush()
                print(f"  … {counts['joined']:,} rows joined", flush=True)
        # A dump with leftover lines would mean different walks.
        if next(fa, None) is not None or next(fb, None) is not None:
            sys.exit("dumps have different line counts")
    flush()


def transcode(src, dest, key):
    """Rewrite one sorted parquet file with page indexes. Row groups
    are accumulated to ROW_GROUP rows from smaller read batches, so
    peak memory is one row group of strings."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    f = pq.ParquetFile(src)
    writer = pq.ParquetWriter(part, f.schema_arrow, **WRITER_OPTS)
    last = ""
    n = 0
    pending = []
    pending_rows = 0

    def flush():
        nonlocal pending, pending_rows
        if pending:
            writer.write_table(pa.Table.from_batches(pending))
            pending = []
            pending_rows = 0

    for batch in f.iter_batches(batch_size=65536):
        first = batch.column(key)[0].as_py()
        last_here = batch.column(key)[batch.num_rows - 1].as_py()
        assert last <= first <= last_here, f"{src}: unsorted"
        last = last_here
        pending.append(batch)
        pending_rows += batch.num_rows
        if pending_rows >= ROW_GROUP:
            flush()
        n += batch.num_rows
    flush()
    writer.close()
    part.rename(dest)  # a dest that exists is COMPLETE by construction
    return n


def transcode_child(src, dest, key):
    """Run one file's transcode in a child process: arrow's allocator
    retains memory within a process, and 17 sequential multi-GB files
    in one process once swap-thrashed a 30 GB machine. A child gives
    every file a fresh address space that dies with it."""
    import subprocess

    r = subprocess.run(
        [sys.executable, __file__, "--transcode-one", str(src), str(dest), key],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        sys.exit(f"transcode of {src} failed:\n{r.stdout}\n{r.stderr}")
    return int(r.stdout.strip().splitlines()[-1])


def verify(path, key_col):
    f = pq.ParquetFile(path)
    for rg in range(f.metadata.num_row_groups):
        for col in range(f.metadata.num_columns):
            assert f.metadata.row_group(rg).column(col).has_offset_index, (path, rg, col)

    print(
        f"  {path.name}: {f.metadata.num_rows:,} rows, sorted by {key_col}, "
        f"page-indexed, {path.stat().st_size:,} bytes"
    )
    return f.metadata.num_rows


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--transcode-one":
        n = transcode(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), sys.argv[4])
        print(n)
        return
    census_dir = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/census"
    )
    outdir = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else census_dir / "parquet"
    tmp_dir = census_dir / "tmp-join"
    counts = {k: 0 for k in "joined sidecar malformed badhash".split()}

    done_marker = tmp_dir / "JOIN_DONE.json"
    if done_marker.exists():
        counts = json.loads(done_marker.read_text())
        print(f"merge-join already done: {counts}", flush=True)
    else:
        print("merge-joining dumps …", flush=True)
        merge_join(census_dir, tmp_dir, counts)
        done_marker.write_text(json.dumps(counts))
        print(json.dumps(counts, indent=2))

    print("sorting (duckdb, one file per sha1 nibble) …", flush=True)
    sorted_dir = census_dir / "tmp-sorted"
    sorted_dir.mkdir(exist_ok=True)
    con = duckdb.connect()
    # Bounded: the md5-map DISTINCT over 150M pairs otherwise builds a
    # RAM-sized hash table; spill to disk instead of into swap.
    con.execute("SET preserve_insertion_order=false")
    con.execute("SET memory_limit='6GB'")
    con.execute(f"SET temp_directory='{census_dir}/tmp-duck'")
    parts = str(tmp_dir / "part-*.parquet")
    for nib in "0123456789abcdef":
        dest = sorted_dir / f"census-{nib}.parquet"
        if dest.exists():
            print(f"  … nibble {nib} (kept)", flush=True)
            continue
        con.execute(
            f"""COPY (SELECT * FROM read_parquet('{parts}')
                     WHERE sha1 LIKE '{nib}%' ORDER BY sha1, identifier, filename)
                TO '{dest}.part'
                (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE {ROW_GROUP})"""
        )
        (dest.parent / f"{dest.name}.part").rename(dest)
        print(f"  … nibble {nib}", flush=True)
    if not (sorted_dir / "md5.parquet").exists():
        con.execute(
            f"""COPY (SELECT DISTINCT md5, sha1 FROM read_parquet('{parts}')
                     ORDER BY md5, sha1)
                TO '{sorted_dir}/md5.parquet.part'
                (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE {ROW_GROUP})"""
        )
        (sorted_dir / "md5.parquet.part").rename(sorted_dir / "md5.parquet")
    print("  … md5 map", flush=True)
    con.close()  # release the buffer pool BEFORE arrow starts allocating

    print("transcoding with page indexes …", flush=True)
    total = 0
    for nib in "0123456789abcdef":
        dest = outdir / "data" / f"census-{nib}.parquet"
        if dest.exists():
            try:
                total += pq.ParquetFile(dest).metadata.num_rows
                print(f"  … {dest.name} (kept)", flush=True)
                continue
            except Exception:
                dest.unlink()  # truncated leftover from a killed run
        total += transcode_child(sorted_dir / f"census-{nib}.parquet", dest, "sha1")
        print(f"  … {dest.name}", flush=True)
    map_dest = outdir / "maps" / "md5.parquet"
    if map_dest.exists():
        map_rows = pq.ParquetFile(map_dest).metadata.num_rows
    else:
        map_rows = transcode_child(sorted_dir / "md5.parquet", map_dest, "md5")
    print("  … md5.parquet", flush=True)

    assert total == counts["joined"], (total, counts["joined"])
    print("verifying …")
    got = sum(verify(outdir / "data" / f"census-{n}.parquet", "sha1") for n in "0123456789abcdef")
    verify(outdir / "maps" / "md5.parquet", "md5")
    assert got == counts["joined"]
    print(f"{outdir}: {total:,} rows + {map_rows:,} map pairs")
    print("(tmp-join/ and tmp-sorted/ left for inspection; delete when happy)")


if __name__ == "__main__":
    main()
