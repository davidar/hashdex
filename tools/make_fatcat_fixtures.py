# /// script
# requires-python = ">=3.11"
# dependencies = ["pyarrow>=15"]
# ///
"""Generate the page-indexed fatcat test fixtures
(tests/data/fatcat/*_pi.parquet).

Tiny data pages (1 KB) over three explicit row groups exercise the
page-index read path: per-page min/max routing, zero-read absence
proofs, a key straddling a row-group boundary, and a key spanning
multiple pages. Keys follow key(i) = f"{i*16+8:064x}" so the Rust
tests can mint them without a lookup table; the +8 leaves room on
both sides for absent-but-in-range probes.

The original plain fixtures (files.parquet, sha1_map.parquet) are
left untouched — they cover the no-page-index fallback path.
"""

from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "fatcat"
ROWS_PER_GROUP = 2000
GROUPS = 3

SCHEMA = pa.schema(
    [
        ("sha256", pa.string()),
        ("sha1", pa.string()),
        ("md5", pa.string()),
        ("title", pa.string()),
        ("release_year", pa.int32()),
        ("container_name", pa.string()),
        ("doi", pa.string()),
        ("arxiv", pa.string()),
        ("wayback_url", pa.string()),
    ]
)


def key(i: int) -> str:
    return f"{i * 16 + 8:064x}"


def files_rows():
    rows = []
    i = 0
    while len(rows) < ROWS_PER_GROUP * GROUPS:
        n = len(rows)
        if n == 2000:  # duplicate of row 1999: straddles the rg0/rg1 edge
            rows.append(dict(rows[-1], title="Straddle Two", doi="10.1234/straddle-two"))
            continue
        if 4000 < n <= 4040:  # 41 releases of one file: spans pages
            rows.append(dict(rows[-1], title=f"Many Releases {n - 4000}"))
            continue
        rows.append(
            {
                "sha256": key(i),
                "sha1": f"{i:040x}",
                "md5": None if i % 7 == 0 else f"{i:032x}",
                "title": "Straddle One" if n == 1999 else f"Paper {i}: a study of things",
                "release_year": 1900 + i % 120,
                "container_name": None if i % 5 == 0 else f"Journal of {i % 50}",
                "doi": None if i % 3 == 0 else f"10.5555/x{i}",
                "arxiv": f"240{i % 10}.0{i % 1000:04d}" if i % 11 == 0 else None,
                "wayback_url": None if i % 13 == 0 else f"https://web.archive.org/web/2022/{i}",
            }
        )
        i += 1
    return rows


def write(path: Path, schema: pa.Schema, rows: list[dict]):
    with pq.ParquetWriter(
        path,
        schema,
        compression="zstd",
        use_dictionary=False,
        write_page_index=True,
        data_page_size=1024,
        # Page size is only checked every write_batch_size values; the
        # default (1024 rows) would leave ~2 pages per chunk.
        write_batch_size=16,
    ) as w:
        for g in range(0, len(rows), ROWS_PER_GROUP):
            cols = {f.name: [r[f.name] for r in rows[g : g + ROWS_PER_GROUP]] for f in schema}
            w.write_table(pa.table(cols, schema=schema))
    meta = pq.ParquetFile(path).metadata
    print(f"{path.name}: {meta.num_rows} rows, {meta.num_row_groups} row groups")


def main():
    write(OUT / "files_pi.parquet", SCHEMA, files_rows())
    map_schema = pa.schema([("sha1", pa.string()), ("sha256", pa.string())])
    map_rows = [
        {"sha1": f"{i:040x}", "sha256": key(i)} for i in range(ROWS_PER_GROUP * GROUPS)
    ]
    write(OUT / "sha1_map_pi.parquet", map_schema, map_rows)


if __name__ == "__main__":
    main()
