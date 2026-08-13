#!/usr/bin/env python3
"""Convert the deb-packages TSV to the published parquet layout.

One data table sorted by sha256 with page indexes for point reads,
plus sha1→sha256 and md5→sha256 maps (ubuntu/kali rows carry sha1;
every witness carries md5). sha512 stays in the data table only — a
crosswalk edge, not a lookup key.

  data/debs.parquet   witness sha256 sha1 md5 sha512 name version arch filename
  maps/sha1.parquet   sha1 sha256
  maps/md5.parquet    md5 sha256

Usage:
  tools/debs_parquet.py [debs.tsv.gz] [outdir]
  (defaults: ~/.cache/hashdex/debs/debs.tsv.gz, sibling parquet/)
"""
import gzip
import pathlib
import sys

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    sys.exit("needs pyarrow (pip install pyarrow)")

COLUMNS = ["witness", "sha256", "sha1", "md5", "sha512", "name", "version", "arch", "filename"]

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
        sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / ".cache/hashdex/debs/debs.tsv.gz"
    )
    outdir = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else tsv.parent / "parquet"

    rows = read_rows(tsv)
    n = write_sorted(
        rows,
        COLUMNS,
        lambda r: (r[1], r[0], r[5] or "", r[8] or ""),
        outdir / "data" / "debs.parquet",
    )

    for key, idx in [("sha1", 2), ("md5", 3)]:
        pairs = sorted({(r[idx], r[1]) for r in rows if r[idx]})
        m = write_sorted(
            [list(t) for t in pairs],
            [key, "sha256"],
            lambda r: (r[0], r[1]),
            outdir / "maps" / f"{key}.parquet",
        )
        verify(outdir / "maps" / f"{key}.parquet", key, m)

    verify(outdir / "data" / "debs.parquet", "sha256", n)
    print(outdir)


if __name__ == "__main__":
    main()
