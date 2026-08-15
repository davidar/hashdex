#!/usr/bin/env python3
"""Convert the rpm-files TSV to the published parquet layout.

One page-indexed data table per key scheme, each holding every row
whose digest is of that scheme, sorted by it for point reads:

  data/rpm-<scheme>.parquet   digest witness name evr arch path pkgid location

(F44-era repos are all sha256; md5/sha1 tables appear when ancient
releases are harvested — the reader routes by whatever tables exist.)
Also writes rpm-files.sha256.hex (distinct digests, sorted) for
`hdx filters build rpm-files sha256 …`.

Rows are read and sorted columnar (pyarrow csv + take): the row count
is fatcat-shaped, python-list sorting would thrash.

Usage:
  tools/rpm_parquet.py [rpm-files.tsv.gz] [outdir]
  (defaults: ~/.cache/hashdex/rpm/rpm-files.tsv.gz, sibling parquet/)
"""
import pathlib
import sys

try:
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.csv
    import pyarrow.parquet as pq
except ImportError:
    sys.exit("needs pyarrow (pip install pyarrow)")

TSV_COLS = ["witness", "scheme", "digest", "name", "evr", "arch", "path", "pkgid", "location"]
OUT_COLS = ["digest", "witness", "name", "evr", "arch", "path", "pkgid", "location"]
SCHEMES = ["sha256", "sha512", "sha1", "md5"]

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


def read_table(tsv_path):
    return pyarrow.csv.read_csv(
        tsv_path,
        read_options=pyarrow.csv.ReadOptions(column_names=TSV_COLS),
        parse_options=pyarrow.csv.ParseOptions(delimiter="\t", quote_char=False),
        convert_options=pyarrow.csv.ConvertOptions(
            column_types={c: pa.string() for c in TSV_COLS},
            null_values=["-"],
            strings_can_be_null=True,
        ),
    )


def verify(path, expect_rows):
    f = pq.ParquetFile(path)
    assert f.metadata.num_rows == expect_rows, (path, f.metadata.num_rows, expect_rows)
    # Page indexes must be physically present — readers rely on them
    # for point lookups (duckdb's parquet_metadata does not show this).
    for rg in range(f.metadata.num_row_groups):
        for col in range(f.metadata.num_columns):
            assert f.metadata.row_group(rg).column(col).has_offset_index, (path, rg, col)
    keys = f.read(columns=["digest"]).column(0)
    assert keys.null_count == 0, f"{path}: null digest key"
    assert pc.all(
        pc.less_equal(keys.slice(0, len(keys) - 1), keys.slice(1))
    ).as_py(), f"{path}: digest not sorted"
    print(
        f"  {path}: {expect_rows:,} rows, sorted by digest, "
        f"page-indexed, {path.stat().st_size:,} bytes"
    )


def main():
    tsv = pathlib.Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else pathlib.Path.home() / ".cache/hashdex/rpm/rpm-files.tsv.gz"
    )
    outdir = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else tsv.parent / "parquet"

    table = read_table(tsv)
    print(f"{table.num_rows:,} rows", file=sys.stderr)
    schemes = pc.unique(table.column("scheme")).to_pylist()
    if not set(schemes) <= set(SCHEMES):
        sys.exit(f"unknown schemes in TSV: {sorted(set(schemes) - set(SCHEMES))}")

    for scheme in SCHEMES:
        subset = table.filter(pc.equal(table.column("scheme"), scheme))
        if subset.num_rows == 0:
            continue
        subset = subset.select(OUT_COLS)
        order = pc.sort_indices(
            subset, sort_keys=[("digest", "ascending"), ("witness", "ascending"), ("path", "ascending")]
        )
        subset = subset.take(order)
        path = outdir / "data" / f"rpm-{scheme}.parquet"
        path.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(subset, path, **WRITER_OPTS)
        verify(path, subset.num_rows)
        if scheme == "sha256":
            uniq = pc.unique(subset.column("digest"))
            hexfile = outdir / "rpm-files.sha256.hex"
            with open(hexfile, "w") as fh:
                for d in sorted(uniq.to_pylist()):
                    fh.write(d + "\n")
            print(f"  {hexfile}: {len(uniq):,} distinct digests", file=sys.stderr)
    print(outdir)


if __name__ == "__main__":
    main()
