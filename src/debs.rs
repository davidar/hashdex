//! The deb-packages dataset, transport-free: identity, routing, and
//! claim rendering for the binary-package checksum index harvested
//! from Debian/Ubuntu/Kali apt Packages files, published as
//! page-indexed parquet sorted by sha256 (sha1→sha256 and md5→sha256
//! maps; Ubuntu rows carry all four digests). The native side reads it
//! over HTTP ranges or from a pulled local copy; wasm drives it over
//! fetch. Claim URLs are pool paths by construction: archive base +
//! the stanza's Filename.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::find_rows;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

/// Witness rows read per digest: one deb can legitimately sit in
/// several suites (release + updates + security + sid) across
/// distros.
pub const MAX_ROWS: usize = 30;

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256)
}

pub const DATA_COLS: &[&str] = &[
    "witness", "sha1", "md5", "sha512", "name", "version", "arch", "filename",
];

/// Repo-relative paths a lookup of `coord` starts in.
pub fn start_paths(coord: &Coord) -> Vec<String> {
    match coord.scheme {
        Scheme::Sha256 => vec!["data/debs.parquet".to_string()],
        Scheme::Sha1 => vec!["maps/sha1.parquet".to_string()],
        Scheme::Md5 => vec!["maps/md5.parquet".to_string()],
        _ => vec![],
    }
}

/// One row's fields, decoded from the parquet.
pub struct Row<'a> {
    pub witness: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub arch: &'a str,
    pub filename: &'a str,
    pub sha256: String,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub sha512: Option<String>,
}

/// Archive base URL for a witness — the claim URL is base + Filename.
fn archive_base(witness: &str) -> &'static str {
    if witness.starts_with("debian-") && witness.ends_with("-security") {
        "https://security.debian.org/debian-security"
    } else if witness.starts_with("debian-") {
        "https://deb.debian.org/debian"
    } else if witness.starts_with("ubuntu-") {
        "https://archive.ubuntu.com/ubuntu"
    } else {
        "https://http.kali.org/kali"
    }
}

/// Render one witness row: the finding's backend is the actual
/// attestor project (debian/ubuntu/kali); the suite lives in the
/// statement.
pub fn finding(row: &Row) -> Finding {
    let (project, suite) = row.witness.split_once('-').unwrap_or((row.witness, ""));
    let statement = format!(
        "{} {} ships these bytes as {} {} ({})",
        // "debian" → "Debian" for the sentence; ASCII names only.
        project
            .char_indices()
            .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c })
            .collect::<String>(),
        suite,
        row.name,
        row.version,
        row.arch,
    );
    let url = format!("{}/{}", archive_base(row.witness), row.filename);
    let mut coords = vec![format!("sha256:{}", row.sha256)];
    if let Some(d) = &row.sha1 {
        coords.push(format!("sha1:{d}"));
    }
    if let Some(d) = &row.md5 {
        coords.push(format!("md5:{d}"));
    }
    if let Some(d) = &row.sha512 {
        coords.push(format!("sha512:{d}"));
    }
    Finding {
        backend: project.into(),
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
        arch: s("arch"),
        filename: s("filename"),
        sha256: sha256.to_string(),
        sha1: v["sha1"].as_str().map(str::to_string),
        md5: v["md5"].as_str().map(str::to_string),
        sha512: v["sha512"].as_str().map(str::to_string),
    }
}

/// The whole lookup, generic over how a repo-relative path becomes a
/// readable file: weak digests go through their sorted map to sha256
/// first, then the data file yields one finding per witness row.
pub fn lookup_with<R, F>(open: F, coord: &Coord) -> Result<Vec<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    let hex = coord.hex();
    let sha256s: Vec<String> = match coord.scheme {
        Scheme::Sha256 => vec![hex],
        Scheme::Sha1 | Scheme::Md5 => {
            let map = start_paths(coord).pop().expect("weak scheme has a map");
            let key = coord.scheme.as_str();
            let (reader, meta) = open(&map)?;
            let (rows, _) = find_rows(&reader, &meta, key, &["sha256"], &hex, 8)?;
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
        let (reader, meta) = open("data/debs.parquet")?;
        let (rows, _) = find_rows(&reader, &meta, "sha256", DATA_COLS, sha, MAX_ROWS)?;
        findings.extend(rows.iter().map(|r| finding(&json_row(r, sha))));
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_per_witness_with_pool_urls() {
        let deb = finding(&Row {
            witness: "debian-trixie",
            name: "hello",
            version: "2.10-3",
            arch: "amd64",
            filename: "pool/main/h/hello/hello_2.10-3_amd64.deb",
            sha256: "ab".repeat(32),
            sha1: None,
            md5: Some("cd".repeat(16)),
            sha512: None,
        });
        assert_eq!(deb.backend, "debian");
        assert_eq!(
            deb.claims[0].statement,
            "Debian trixie ships these bytes as hello 2.10-3 (amd64)"
        );
        assert_eq!(
            deb.claims[0].url.as_deref(),
            Some("https://deb.debian.org/debian/pool/main/h/hello/hello_2.10-3_amd64.deb")
        );
        assert!(deb.coords.contains(&format!("md5:{}", "cd".repeat(16))));

        let sec = finding(&Row {
            witness: "debian-trixie-security",
            name: "linux-image",
            version: "6.12.94-1",
            arch: "amd64",
            filename: "pool/updates/main/l/linux-signed-amd64/li.deb",
            sha256: "ef".repeat(32),
            sha1: None,
            md5: None,
            sha512: None,
        });
        assert!(sec.claims[0]
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://security.debian.org/debian-security/pool/"));

        // Ubuntu rows are 4-hash single-witness: every digest is a
        // co-observed coordinate (the edge-minting-legal kind).
        let ubu = finding(&Row {
            witness: "ubuntu-noble",
            name: "wget",
            version: "1.21.4-1ubuntu4",
            arch: "amd64",
            filename: "pool/main/w/wget/wget_1.21.4-1ubuntu4_amd64.deb",
            sha256: "01".repeat(32),
            sha1: Some("23".repeat(20)),
            md5: Some("45".repeat(16)),
            sha512: Some("67".repeat(64)),
        });
        assert_eq!(ubu.backend, "ubuntu");
        assert_eq!(ubu.coords.len(), 4);
        assert!(ubu.claims[0]
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://archive.ubuntu.com/ubuntu/pool/"));

        let kali = finding(&Row {
            witness: "kali-rolling",
            name: "nmap",
            version: "7.94",
            arch: "amd64",
            filename: "pool/main/n/nmap/nmap_7.94_amd64.deb",
            sha256: "89".repeat(32),
            sha1: Some("ab".repeat(20)),
            md5: None,
            sha512: None,
        });
        assert_eq!(kali.backend, "kali");
        assert!(kali.claims[0]
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://http.kali.org/kali/pool/"));
    }
}
