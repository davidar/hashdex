//! The 2016 Internet Archive census, transport-free: identity, routing,
//! and claim rendering for the per-file md5+sha1 index of every public
//! IA item as of April 2016 (archive.org/details/ia_census_201604),
//! republished as page-indexed parquet sorted by sha1 (an md5→sha1 map
//! alongside). Both digests are weak, so census rows are crosswalk and
//! "consistent with" evidence, never identity-grade — but every row
//! carries a live claim URL by construction:
//! `https://archive.org/download/<identifier>/<filename>`.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::find_rows;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

pub const NAME: &str = "ia-census";

const SHOWN: usize = 5;
/// Items read per digest (claims render at most SHOWN; the rest is only
/// counted). Popular bytes live in MANY items — mirrors, re-uploads.
pub const MAX_ROWS: usize = 50;

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha1)
}

pub const DATA_COLS: &[&str] = &["md5", "identifier", "filename"];

/// Repo-relative path of the data file holding `sha1` (keyed by its
/// first nibble).
pub fn data_path(sha1: &str) -> String {
    format!("data/census-{}.parquet", &sha1[..1])
}

/// Repo-relative paths a lookup of `coord` starts in.
pub fn start_paths(coord: &Coord) -> Vec<String> {
    match coord.scheme {
        Scheme::Sha1 => vec![data_path(&coord.hex())],
        Scheme::Md5 => vec!["maps/md5.parquet".to_string()],
        _ => vec![],
    }
}

/// Census filenames come percent-encoded from the dump (verified:
/// zero raw spaces; a subdirectory slash arrives as `%2f`), so a
/// claim URL uses them VERBATIM — re-encoding would double-escape.
/// The human-readable statement decodes them instead.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1..i + 3)) {
            (b'%', Some(hex)) => {
                if let Ok(b) = u8::from_str_radix(std::str::from_utf8(hex).unwrap_or(""), 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn claim(row: &Value) -> Claim {
    let ident = row["identifier"].as_str().unwrap_or("?");
    let fname = row["filename"].as_str().unwrap_or("?");
    Claim::new(
        format!(
            "Internet Archive item {ident} held these bytes as {} (April 2016 census)",
            percent_decode(fname)
        ),
        Some(format!("https://archive.org/download/{ident}/{fname}")),
    )
}

/// The whole lookup, generic over how a repo-relative path becomes a
/// readable file: md5 goes through the sorted map to sha1 first, then
/// the data shards yield claims. One finding per sha1 — both digests
/// are weak, so distinct sha1s reached from one md5 stay distinct.
pub fn lookup_with<R, F>(open: F, coord: &Coord) -> Result<Vec<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    let hex = coord.hex();
    let sha1s: Vec<String> = match coord.scheme {
        Scheme::Sha1 => vec![hex],
        Scheme::Md5 => {
            let (reader, meta) = open("maps/md5.parquet")?;
            let (rows, _) = find_rows(&reader, &meta, "md5", &["sha1"], &hex, 8)?;
            let mut v: Vec<String> = rows
                .iter()
                .filter_map(|r| r["sha1"].as_str().map(str::to_string))
                .collect();
            v.dedup();
            v.truncate(3); // weak-digest collisions are rendered, not merged
            v
        }
        _ => return Ok(Vec::new()),
    };

    let mut findings = Vec::new();
    for sha in &sha1s {
        let (reader, meta) = open(&data_path(sha))?;
        let (rows, total) = find_rows(&reader, &meta, "sha1", DATA_COLS, sha, MAX_ROWS)?;
        if rows.is_empty() {
            continue;
        }
        let mut claims: Vec<Claim> = rows.iter().take(SHOWN).map(claim).collect();
        if total > SHOWN {
            claims.push(Claim::new(
                format!("… and {} more items", total - SHOWN),
                None,
            ));
        }
        // A census row is a single witness co-observing sha1 + md5 —
        // a legitimate crosswalk edge, though both schemes are weak.
        let mut coords = vec![format!("sha1:{sha}")];
        if let Some(md5) = rows[0]["md5"].as_str() {
            coords.push(format!("md5:{md5}"));
        }
        findings.push(Finding {
            backend: NAME.into(),
            claims,
            coords,
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_uses_stored_encoding_and_decodes_for_humans() {
        // Filenames arrive percent-encoded from the census dump (the
        // real corpus spells a subdirectory slash as %2f): the URL
        // keeps them verbatim, the statement decodes them.
        let row = serde_json::json!({
            "identifier": "hashdex-test-fixture",
            "filename": "scans%2fpage%20%281%29.jpg",
        });
        let c = claim(&row);
        assert!(
            c.statement
                .contains("held these bytes as scans/page (1).jpg"),
            "{}",
            c.statement
        );
        assert_eq!(
            c.url.as_deref(),
            Some("https://archive.org/download/hashdex-test-fixture/scans%2fpage%20%281%29.jpg")
        );
        // Malformed escapes degrade to literal text, never panic.
        assert_eq!(percent_decode("100%zz%2"), "100%zz%2");
    }

    #[test]
    fn routing_by_scheme() {
        let sha1 = Coord::parse(&format!("sha1:{}", "ab".repeat(20))).unwrap();
        assert_eq!(
            start_paths(&sha1),
            vec!["data/census-a.parquet".to_string()]
        );
        let md5 = Coord::parse(&format!("md5:{}", "cd".repeat(16))).unwrap();
        assert_eq!(start_paths(&md5), vec!["maps/md5.parquet".to_string()]);
        let sha256 = Coord::parse(&format!("sha256:{}", "ef".repeat(32))).unwrap();
        assert!(start_paths(&sha256).is_empty());
        assert!(supports(Scheme::Sha1) && supports(Scheme::Md5) && !supports(Scheme::Sha256));
    }
}
