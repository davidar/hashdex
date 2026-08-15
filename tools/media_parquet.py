#!/usr/bin/env python3
"""Convert the install-media TSV to the published parquet layout.

Rows that came from the SAME checksum document (witness, loc,
filename) regroup into one multi-digest row — a single witness
statement co-observing several schemes (Qubes .DIGESTS states all
four). Sibling documents (SHA256SUMS next to MD5SUMS) never merge:
that would be a filename join, not a witness statement.

One data table per key scheme, each holding every grouped row that
carries that scheme, sorted by it and page-indexed for point reads:

  data/media-sha256.parquet   witness sha256 sha512 sha1 md5
  data/media-sha512.parquet     name version filename loc
  data/media-sha1.parquet     (same columns, different sort key;
  data/media-md5.parquet       weak-keyed tables serve the
                               "consistent with" tier)

Usage:
  tools/media_parquet.py [media.tsv.gz] [outdir]
  (defaults: ~/.cache/hashdex/media/media.tsv.gz, sibling parquet/)

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

TSV_COLS = ["witness", "scheme", "digest", "name", "version", "filename", "loc"]
SCHEMES = ["sha256", "sha512", "sha1", "md5"]
OUT_COLS = ["witness"] + SCHEMES + ["name", "version", "filename", "loc"]

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


def read_groups(tsv_path):
    """(witness, loc, filename) -> row dict with per-scheme digests.
    A scheme conflict inside one group (a document restating a file
    with a different digest) refuses to merge: each conflicting row
    stays its own single-scheme group."""
    groups = {}
    split = 0
    with gzip.open(tsv_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(TSV_COLS):
                sys.exit(f"malformed TSV line: {line!r}")
            witness, scheme, digest, name, version, filename, loc = parts
            if scheme not in SCHEMES:
                sys.exit(f"unknown scheme {scheme!r}: {line!r}")
            key = (witness, loc, filename)
            g = groups.setdefault(
                key, {"witness": witness, "filename": filename, "loc": loc, "digests": {}}
            )
            if scheme in g["digests"] and g["digests"][scheme] != digest:
                split += 1
                key = (witness, loc, filename, digest)
                g = groups.setdefault(
                    key, {"witness": witness, "filename": filename, "loc": loc, "digests": {}}
                )
            g["digests"][scheme] = digest
            for k, v in (("name", name), ("version", version)):
                if v != "-" and not g.get(k):
                    g[k] = v
    if split:
        print(f"  {split} same-document digest conflicts kept unmerged", file=sys.stderr)
    return list(groups.values())


def row_values(g):
    return (
        [g["witness"]]
        + [g["digests"].get(s) for s in SCHEMES]
        + [g.get("name"), g.get("version"), g["filename"], g["loc"]]
    )


def write_sorted(rows, sort_idx, path):
    rows = sorted(rows, key=lambda r: (r[sort_idx], r[0], r[-2]))
    table = pa.table(
        {c: pa.array([r[i] for r in rows], type=pa.string()) for i, c in enumerate(OUT_COLS)}
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
    assert all(k is not None for k in keys), f"{path}: null {key_col} key"
    assert keys == sorted(keys), f"{path}: {key_col} not sorted"
    print(
        f"  {path}: {expect_rows:,} rows, sorted by {key_col}, "
        f"page-indexed, {path.stat().st_size:,} bytes"
    )


def main():
    tsv = pathlib.Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else pathlib.Path.home() / ".cache/hashdex/media/media.tsv.gz"
    )
    outdir = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else tsv.parent / "parquet"

    groups = read_groups(tsv)
    all_rows = [row_values(g) for g in groups]
    print(f"{len(all_rows):,} grouped rows", file=sys.stderr)

    for scheme in SCHEMES:
        idx = OUT_COLS.index(scheme)
        rows = [r for r in all_rows if r[idx] is not None]
        if not rows:
            continue
        path = outdir / "data" / f"media-{scheme}.parquet"
        n = write_sorted(rows, idx, path)
        verify(path, scheme, n)
    print(outdir)


if __name__ == "__main__":
    main()
