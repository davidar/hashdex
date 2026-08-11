#!/usr/bin/env python3
"""Convert the release-tarballs TSV to the published parquet layout.

Parquet is the wire format (HDXI stays a locally-derived index): one
data table sorted by sha256 with page indexes for ~64 KB point reads,
plus a small md5→sha256 map (Debian rows carry md5) sorted by md5.

  data/tarballs.parquet   witness sha256 md5 name version filename loc
  maps/md5.parquet        md5 sha256

Usage:
  tools/tarballs_parquet.py [tarballs.tsv.gz] [outdir]
  (defaults: ~/.cache/hashdex/tarballs/tarballs.tsv.gz, sibling parquet/)

Then upload outdir to the HF dataset and point hdx/web at it.
"""
import gzip
import pathlib
import sys

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    sys.exit("needs pyarrow (pip install pyarrow)")

COLUMNS = ["witness", "sha256", "md5", "name", "version", "filename", "loc"]

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


def read_rows(tsv_path):
    rows = []
    with gzip.open(tsv_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(COLUMNS):
                sys.exit(f"malformed TSV line: {line!r}")
            rows.append([None if v == "-" else v for v in parts])
    return rows


def write_sorted(rows, cols, sort_key, path):
    rows = sorted(rows, key=sort_key)
    table = pa.table(
        {c: pa.array([r[i] for r in rows], type=pa.string()) for i, c in enumerate(cols)}
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, path, **WRITER_OPTS)
    return len(rows)


def verify(path, key_col, expect_rows):
    f = pq.ParquetFile(path)
    assert f.metadata.num_rows == expect_rows, (path, f.metadata.num_rows, expect_rows)
    # Page indexes must be physically present — readers rely on them
    # for point lookups (duckdb's parquet_metadata does not show this).
    for rg in range(f.metadata.num_row_groups):
        for col in range(f.metadata.num_columns):
            assert f.metadata.row_group(rg).column(col).has_offset_index, (path, rg, col)
    keys = f.read(columns=[key_col]).column(0).to_pylist()
    assert keys == sorted(keys), f"{path}: {key_col} not sorted"
    print(
        f"  {path}: {expect_rows:,} rows, sorted by {key_col}, "
        f"page-indexed, {path.stat().st_size:,} bytes"
    )


def main():
    tsv = pathlib.Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else pathlib.Path.home() / ".cache/hashdex/tarballs/tarballs.tsv.gz"
    )
    outdir = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else tsv.parent / "parquet"

    rows = read_rows(tsv)
    n = write_sorted(
        rows,
        COLUMNS,
        lambda r: (r[1], r[0], r[3] or "", r[5] or ""),
        outdir / "data" / "tarballs.parquet",
    )

    md5_rows = sorted({(r[2], r[1]) for r in rows if r[2]})
    m = write_sorted(
        [list(t) for t in md5_rows],
        ["md5", "sha256"],
        lambda r: (r[0], r[1]),
        outdir / "maps" / "md5.parquet",
    )

    verify(outdir / "data" / "tarballs.parquet", "sha256", n)
    verify(outdir / "maps" / "md5.parquet", "md5", m)
    print(outdir)


if __name__ == "__main__":
    main()
