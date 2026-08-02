#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["duckdb>=1.0"]
# ///
"""Convert a digests.parquet (base32 sha1, Common Crawl convention) to
uppercase-hex lines on stdout, ready for `hdx filters build cc sha1`.

    uv run tools/cc_digests_to_hex.py cc-out/CC-MAIN-2026-30/digests.parquet \
        > ~/.cache/hashdex/extracts/cc.sha1.hex
"""

import base64
import sys

import duckdb


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    con = duckdb.connect()
    cur = con.execute(
        "SELECT digest_b32 FROM read_parquet(?)", [sys.argv[1]]
    )
    out = sys.stdout
    bad = 0
    while batch := cur.fetchmany(100_000):
        lines = []
        for (b32,) in batch:
            try:
                raw = base64.b32decode(b32)
            except Exception:
                bad += 1
                continue
            if len(raw) != 20:
                bad += 1
                continue
            lines.append(raw.hex().upper())
        out.write("\n".join(lines) + "\n")
    if bad:
        print(f"skipped {bad} undecodable digests", file=sys.stderr)


if __name__ == "__main__":
    main()
