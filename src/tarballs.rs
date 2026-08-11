//! The release-tarballs dataset, transport-free: identity, routing,
//! and claim rendering for the Debian/Homebrew/Guix artifact-checksum
//! index, published as page-indexed parquet sorted by sha256 (an
//! md5→sha256 map for the Debian rows). The native side reads it over
//! HTTP ranges or from a pulled local copy; wasm drives it over fetch.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::find_rows;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

pub const DATASET_BASE: &str = "https://huggingface.co/datasets/david-ar/release-tarballs/resolve";
pub const REVISION_API: &str =
    "https://huggingface.co/api/datasets/david-ar/release-tarballs/revision/main";
/// Witness rows read per digest — a digest is rarely packaged by more
/// than a handful of distros.
pub const MAX_ROWS: usize = 20;

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha256)
}

pub const DATA_COLS: &[&str] = &["witness", "md5", "name", "version", "filename", "loc"];

/// Repo-relative paths a lookup of `coord` starts in.
pub fn start_paths(coord: &Coord) -> Vec<String> {
    match coord.scheme {
        Scheme::Sha256 => vec!["data/tarballs.parquet".to_string()],
        Scheme::Md5 => vec!["maps/md5.parquet".to_string()],
        _ => vec![],
    }
}

/// One row's fields, decoded from the parquet.
pub struct Row<'a> {
    pub witness: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub filename: &'a str,
    pub loc: &'a str,
    pub sha256: String,
    pub md5: Option<String>,
}

/// Render one witness row: the finding's backend is the actual
/// attestor (debian/homebrew/guix), never the index's name.
pub fn finding(row: &Row) -> Finding {
    let (backend, statement, url) = match row.witness {
        "debian" => (
            "debian",
            format!(
                "Debian sid packages these bytes as {} (source package {} {})",
                row.filename, row.name, row.version
            ),
            format!("https://deb.debian.org/debian/{}/{}", row.loc, row.filename),
        ),
        "homebrew" => (
            "homebrew",
            format!(
                "Homebrew packages these bytes as {} {} (upstream source)",
                row.name, row.version
            ),
            row.loc.to_string(),
        ),
        _ => (
            "guix",
            format!("GNU Guix packages these bytes as {}", row.filename),
            row.loc.to_string(),
        ),
    };
    let mut coords = vec![format!("sha256:{}", row.sha256)];
    if let Some(md5) = &row.md5 {
        coords.push(format!("md5:{md5}"));
    }
    Finding {
        backend: backend.into(),
        claims: vec![Claim::new(statement, Some(url))],
        coords,
    }
}

fn json_row<'a>(v: &'a Value, sha256: &str) -> Row<'a> {
    let s = |k: &str| v[k].as_str().unwrap_or("");
    Row {
        witness: s("witness"),
        name: s("name"),
        version: s("version"),
        filename: s("filename"),
        loc: s("loc"),
        sha256: sha256.to_string(),
        md5: v["md5"].as_str().map(str::to_string),
    }
}

/// The whole lookup, generic over how a repo-relative path becomes a
/// readable file: md5 goes through the sorted map to sha256 first,
/// then the data file yields one finding per witness row.
pub fn lookup_with<R, F>(open: F, coord: &Coord) -> Result<Vec<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    let hex = coord.hex();
    let sha256s: Vec<String> = match coord.scheme {
        Scheme::Sha256 => vec![hex],
        Scheme::Md5 => {
            let (reader, meta) = open("maps/md5.parquet")?;
            let (rows, _) = find_rows(&reader, &meta, "md5", &["sha256"], &hex, 8)?;
            let mut v: Vec<String> = rows
                .iter()
                .filter_map(|r| r["sha256"].as_str().map(str::to_string))
                .collect();
            v.dedup();
            v.truncate(3); // weak-digest collisions are rendered, not merged
            v
        }
        _ => return Ok(Vec::new()),
    };

    let mut findings = Vec::new();
    for sha in &sha256s {
        let (reader, meta) = open("data/tarballs.parquet")?;
        let (rows, _) = find_rows(&reader, &meta, "sha256", DATA_COLS, sha, MAX_ROWS)?;
        findings.extend(rows.iter().map(|r| finding(&json_row(r, sha))));
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_per_witness_with_claim_urls() {
        let debian = finding(&Row {
            witness: "debian",
            name: "hello",
            version: "2.12.3-1",
            filename: "hello_2.12.3.orig.tar.gz",
            loc: "pool/main/h/hello",
            sha256: "ab".repeat(32),
            md5: Some("cd".repeat(16)),
        });
        assert_eq!(debian.backend, "debian");
        assert_eq!(
            debian.claims[0].statement,
            "Debian sid packages these bytes as hello_2.12.3.orig.tar.gz \
             (source package hello 2.12.3-1)"
        );
        assert_eq!(
            debian.claims[0].url.as_deref(),
            Some("https://deb.debian.org/debian/pool/main/h/hello/hello_2.12.3.orig.tar.gz")
        );
        // single-witness multi-hash row: the md5 is co-observed
        assert!(debian.coords.contains(&format!("md5:{}", "cd".repeat(16))));

        let brew = finding(&Row {
            witness: "homebrew",
            name: "wget",
            version: "1.25.0",
            filename: "",
            loc: "https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz",
            sha256: "ef".repeat(32),
            md5: None,
        });
        assert_eq!(brew.backend, "homebrew");
        assert!(brew.claims[0].statement.contains("wget 1.25.0"));
        assert_eq!(
            brew.claims[0].url.as_deref(),
            Some("https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz")
        );
        // md5-less rows co-observe nothing beyond sha256
        assert_eq!(brew.coords.len(), 1);

        let guix = finding(&Row {
            witness: "guix",
            name: "",
            version: "",
            filename: "hello-2.12.3.tar.gz",
            loc: "https://bordeaux.guix.gnu.org/file/hello-2.12.3.tar.gz/sha256/086vqwk2",
            sha256: "01".repeat(32),
            md5: None,
        });
        assert_eq!(guix.backend, "guix");
        assert!(guix.claims[0]
            .statement
            .contains("packages these bytes as hello-2.12.3.tar.gz"));
    }
}
