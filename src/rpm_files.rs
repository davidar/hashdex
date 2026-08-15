//! The rpm-files dataset, transport-free: identity, routing, and
//! claim rendering for the per-file digest index harvested from RPM
//! repo metadata (tools/rpm_files.py: one header range-GET per rpm;
//! FILEDIGESTS is the witness statement). Published as one
//! page-indexed parquet table per key scheme
//! (`data/rpm-<scheme>.parquet`), sorted by digest.
//!
//! Two row shapes share the table: file rows (digest of an installed
//! file's contents, `path` + `pkgid` present) and package rows
//! (digest of the .rpm artifact itself, `path`/`pkgid` null). The
//! `location` column is the full URL of the rpm — a claim URL by
//! construction — and the witness is carried as a string, so new
//! repos never change the schema or this module.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::find_rows;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

/// Witness rows read per digest. File contents genuinely recur across
/// packages (every subpackage of a source package ships the same
/// COPYING), so the cap is higher than artifact-level datasets'.
pub const MAX_ROWS: usize = 40;

/// Schemes with a published table. F44-era repos state sha256 only;
/// md5 joins when ancient releases are harvested (the TSV's scheme
/// column is ready for it).
const KEY_SCHEMES: &[(Scheme, &str)] = &[(Scheme::Sha256, "sha256")];

pub fn supports(s: Scheme) -> bool {
    KEY_SCHEMES.iter().any(|(k, _)| *k == s)
}

fn key_col(s: Scheme) -> Option<&'static str> {
    KEY_SCHEMES.iter().find(|(k, _)| *k == s).map(|(_, c)| *c)
}

pub const DATA_COLS: &[&str] = &[
    "witness", "name", "evr", "arch", "path", "pkgid", "location",
];

/// Repo-relative paths a lookup of `coord` starts in.
pub fn start_paths(coord: &Coord) -> Vec<String> {
    match key_col(coord.scheme) {
        Some(col) => vec![format!("data/rpm-{col}.parquet")],
        None => vec![],
    }
}

/// One row's fields. `path` is None for package rows (the digest is
/// the rpm artifact's own).
pub struct Row<'a> {
    pub witness: &'a str,
    pub name: &'a str,
    pub evr: &'a str,
    pub arch: &'a str,
    pub path: Option<&'a str>,
    pub location: &'a str,
}

/// Known witness projects: (slug prefix, display name). A witness is
/// `<project>-<repo detail>`; longest matching prefix wins so
/// multi-segment slugs like centos-stream parse. Unknown projects
/// degrade to the first dash split, rendered verbatim.
const PROJECTS: &[(&str, &str)] = &[
    ("fedora", "Fedora"),
    ("epel", "EPEL"),
    ("centos-stream", "CentOS Stream"),
    ("almalinux", "AlmaLinux"),
    ("rockylinux", "Rocky Linux"),
    ("opensuse", "openSUSE"),
    ("rpmfusion", "RPM Fusion"),
];

/// (backend slug, human name with the repo detail appended):
/// "fedora-44-updates" → ("fedora", "Fedora 44 updates").
fn witness_display(witness: &str) -> (&str, String) {
    for (slug, human) in PROJECTS {
        if let Some(rest) = witness.strip_prefix(slug) {
            if rest.is_empty() {
                return (slug, human.to_string());
            }
            if let Some(detail) = rest.strip_prefix('-') {
                return (slug, format!("{human} {}", detail.replace('-', " ")));
            }
        }
    }
    let (project, detail) = witness.split_once('-').unwrap_or((witness, ""));
    (project, format!("{project} {}", detail.replace('-', " ")))
}

/// Render one witness row. The backend is the project (matching the
/// scan tag convention the fedora bloom established); the repo detail
/// lives in the statement.
pub fn finding(row: &Row, scheme: Scheme, hex: &str) -> Finding {
    let (project, human) = witness_display(row.witness);
    let rpm = row.location.rsplit('/').next().unwrap_or(row.location);
    let statement = match row.path {
        Some(path) => format!("{human} ships these bytes as {path} in {rpm}"),
        None => format!(
            "{human} packages these bytes as {rpm} ({} {})",
            row.name, row.evr
        ),
    };
    Finding {
        backend: project.into(),
        claims: vec![Claim::new(statement, Some(row.location.to_string()))],
        coords: vec![format!("{}:{hex}", scheme.as_str())],
    }
}

fn json_row(v: &Value) -> Row<'_> {
    let s = |k: &str| v[k].as_str().unwrap_or("");
    Row {
        witness: s("witness"),
        name: s("name"),
        evr: s("evr"),
        arch: s("arch"),
        path: v["path"].as_str(),
        location: s("location"),
    }
}

/// The whole lookup, generic over how a repo-relative path becomes a
/// readable file: the coord's scheme routes to that scheme's table,
/// whose key column is never null by construction.
pub fn lookup_with<R, F>(open: F, coord: &Coord) -> Result<Vec<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    let Some(col) = key_col(coord.scheme) else {
        return Ok(Vec::new());
    };
    let (reader, meta) = open(&format!("data/rpm-{col}.parquet"))?;
    let hex = coord.hex();
    let (rows, _) = find_rows(&reader, &meta, "digest", DATA_COLS, &hex, MAX_ROWS)?;
    Ok(rows
        .iter()
        .map(|r| finding(&json_row(r), coord.scheme, &hex))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_file_and_package_rows() {
        let hex = "2c".repeat(32);
        let file = finding(
            &Row {
                witness: "fedora-44",
                name: "bash",
                evr: "5.3.9-3.fc44",
                arch: "x86_64",
                path: Some("/usr/bin/bash"),
                location: "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/Packages/b/bash-5.3.9-3.fc44.x86_64.rpm",
            },
            Scheme::Sha256,
            &hex,
        );
        assert_eq!(file.backend, "fedora");
        assert_eq!(
            file.claims[0].statement,
            "Fedora 44 ships these bytes as /usr/bin/bash in bash-5.3.9-3.fc44.x86_64.rpm"
        );
        assert!(file.claims[0]
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://dl.fedoraproject.org/"));
        assert_eq!(file.coords, vec![format!("sha256:{hex}")]);

        let pkg = finding(
            &Row {
                witness: "fedora-44-updates",
                name: "bash",
                evr: "5.3.9-4.fc44",
                arch: "x86_64",
                path: None,
                location: "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/Packages/b/bash-5.3.9-4.fc44.x86_64.rpm",
            },
            Scheme::Sha256,
            &hex,
        );
        assert_eq!(pkg.backend, "fedora");
        assert_eq!(
            pkg.claims[0].statement,
            "Fedora 44 updates packages these bytes as bash-5.3.9-4.fc44.x86_64.rpm (bash 5.3.9-4.fc44)"
        );
    }

    #[test]
    fn witness_slugs_parse_and_degrade() {
        assert_eq!(
            witness_display("centos-stream-10"),
            ("centos-stream", "CentOS Stream 10".to_string())
        );
        assert_eq!(
            witness_display("opensuse-tumbleweed"),
            ("opensuse", "openSUSE tumbleweed".to_string())
        );
        // unknown projects degrade to the first dash split, verbatim
        assert_eq!(
            witness_display("mageia-9"),
            ("mageia", "mageia 9".to_string())
        );
    }

    #[test]
    fn routes_by_scheme() {
        let sha256 = Coord {
            scheme: Scheme::Sha256,
            digest: vec![0xab; 32],
        };
        assert_eq!(start_paths(&sha256), vec!["data/rpm-sha256.parquet"]);
        let md5 = Coord {
            scheme: Scheme::Md5,
            digest: vec![0xab; 16],
        };
        assert!(start_paths(&md5).is_empty());
        assert!(supports(Scheme::Sha256));
        assert!(!supports(Scheme::Md5));
    }
}
