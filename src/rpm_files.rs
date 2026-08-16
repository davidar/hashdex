//! The rpm-files dataset, transport-free: identity, routing, and
//! claim rendering for the per-file digest index harvested from RPM
//! repo metadata (tools/rpm_files.py: one header range-GET per rpm;
//! FILEDIGESTS is the witness statement).
//!
//! The published layout is normalized — package identity is stated
//! once, not repeated per file:
//!
//! - `data/packages.parquet` — one row per package × witness
//!   (pkgid, scheme, witness, name, evr, arch, location), **sorted by
//!   pkgid**, so the rpm artifact's own checksum is a direct lookup
//!   key. `location` is the full URL of the rpm — a claim URL by
//!   construction — and the witness is a string, so new repos never
//!   change the schema or this module.
//! - `data/files-sha256-{0..f}.parquet` (sharded by first digest
//!   nibble) plus single-file `files-md5` / `files-sha1` tables for
//!   ancient repos — (digest, path, pkg), sorted by digest, where
//!   `pkg` is the absolute row index into packages.parquet. All file
//!   tables exist even when empty: routing is static, absence is
//!   proved by footer stats.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::{find_rows, rows_at};
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

/// Witness rows read per digest. File contents genuinely recur across
/// packages (every subpackage of a source package ships the same
/// COPYING), so the cap is higher than artifact-level datasets'.
pub const MAX_ROWS: usize = 40;

/// Columns fetched from packages.parquet, whether by pkgid key or by
/// row index. pkgid + scheme ride along so a file row's finding can
/// state its containment edge (the rpm artifact's own checksum).
pub const PKG_COLS: &[&str] = &[
    "pkgid", "scheme", "witness", "name", "evr", "arch", "location",
];

pub fn supports(s: Scheme) -> bool {
    matches!(
        s,
        Scheme::Sha256 | Scheme::Sha512 | Scheme::Sha1 | Scheme::Md5
    )
}

/// The file-digest table for a scheme. sha256 (every modern repo) is
/// nibble-sharded; the weak schemes of ancient repos are single small
/// files. sha512 has no file table — it appears only as openSUSE's
/// pkgid scheme.
fn file_table(coord: &Coord) -> Option<String> {
    match coord.scheme {
        Scheme::Sha256 => Some(format!(
            "data/files-sha256-{}.parquet",
            coord.hex().chars().next().unwrap_or('0')
        )),
        Scheme::Md5 => Some("data/files-md5.parquet".to_string()),
        Scheme::Sha1 => Some("data/files-sha1.parquet".to_string()),
        _ => None,
    }
}

/// Repo-relative paths a lookup of `coord` starts in.
pub fn start_paths(coord: &Coord) -> Vec<String> {
    let mut paths: Vec<String> = file_table(coord).into_iter().collect();
    if supports(coord.scheme) {
        paths.push("data/packages.parquet".to_string());
    }
    paths
}

/// One package's identity, however it was fetched.
pub struct Pkg<'a> {
    pub pkgid: &'a str,
    pub scheme: &'a str,
    pub witness: &'a str,
    pub name: &'a str,
    pub evr: &'a str,
    pub arch: &'a str,
    pub location: &'a str,
}

/// Known witness projects: (slug prefix, backend tag, display name).
/// Longest matching prefix wins, so multi-segment slugs parse
/// ("fedora-core-4" before "fedora"); the remainder joins the display
/// name with dashes as spaces ("fedora-44-updates" → "Fedora 44
/// updates"). Unknown projects degrade to the first dash split,
/// rendered verbatim.
const PROJECTS: &[(&str, &str, &str)] = &[
    ("fedora-core", "fedora", "Fedora Core"),
    ("fedora", "fedora", "Fedora"),
    ("epel", "epel", "EPEL"),
    ("rpmfusion-free", "rpmfusion", "RPM Fusion free"),
    ("rpmfusion-nonfree", "rpmfusion", "RPM Fusion nonfree"),
    ("vscode", "vscode", "Microsoft VS Code"),
    ("centos-stream", "centos", "CentOS Stream"),
    ("centos", "centos", "CentOS"),
    ("almalinux", "almalinux", "AlmaLinux"),
    ("rocky", "rocky", "Rocky Linux"),
    ("opensuse-leap", "opensuse", "openSUSE Leap"),
    ("opensuse", "opensuse", "openSUSE"),
];

/// (backend tag, human name with the repo detail appended).
fn witness_display(witness: &str) -> (&str, String) {
    let mut best: Option<&(&str, &str, &str)> = None;
    for p in PROJECTS {
        let matches =
            witness == p.0 || witness.starts_with(p.0) && witness.as_bytes()[p.0.len()] == b'-';
        if matches && best.is_none_or(|b| p.0.len() > b.0.len()) {
            best = Some(p);
        }
    }
    if let Some((slug, backend, human)) = best {
        let rest = &witness[slug.len()..];
        return match rest.strip_prefix('-') {
            Some(detail) => (backend, format!("{human} {}", detail.replace('-', " "))),
            None => (backend, human.to_string()),
        };
    }
    let (project, detail) = witness.split_once('-').unwrap_or((witness, ""));
    if detail.is_empty() {
        (project, project.to_string())
    } else {
        (project, format!("{project} {}", detail.replace('-', " ")))
    }
}

/// Render a file row joined with its package.
pub fn file_finding(path: &str, pkg: &Pkg, scheme: Scheme, hex: &str) -> Finding {
    let (backend, human) = witness_display(pkg.witness);
    let rpm = pkg.location.rsplit('/').next().unwrap_or(pkg.location);
    // The URL fetches the rpm, not these bytes — the containment edge
    // rides structured on the finding (recipe extract nodes need the
    // rpm's own checksum, which FILEDIGESTS witnesses alongside).
    let archive = (!pkg.pkgid.is_empty()).then(|| crate::finding::Archive {
        scheme: pkg.scheme.to_string(),
        digest: pkg.pkgid.to_string(),
        path: path.to_string(),
        name: rpm.to_string(),
        url: Some(pkg.location.to_string()),
    });
    Finding {
        backend: backend.into(),
        claims: vec![Claim::new(
            format!("{human} ships these bytes as {path} in {rpm}"),
            Some(pkg.location.to_string()),
        )],
        coords: vec![format!("{}:{hex}", scheme.as_str())],
        archive,
    }
}

/// Render a package row — the digest is the rpm artifact's own.
pub fn pkg_finding(pkg: &Pkg, scheme: Scheme, hex: &str) -> Finding {
    let (backend, human) = witness_display(pkg.witness);
    let rpm = pkg.location.rsplit('/').next().unwrap_or(pkg.location);
    Finding {
        backend: backend.into(),
        claims: vec![Claim::new(
            format!(
                "{human} packages these bytes as {rpm} ({} {})",
                pkg.name, pkg.evr
            ),
            Some(pkg.location.to_string()),
        )],
        coords: vec![format!("{}:{hex}", scheme.as_str())],
        archive: None,
    }
}

/// Package rows already resolved, by their row index in
/// `packages.parquet`.
///
/// Packages recur relentlessly: a live image's 119,736 files come from
/// a few thousand rpms, and every file row points at one. Reading a
/// package row means seven scattered column reads, so each index is
/// paid for once per process. Row indices address the copy this
/// process reads, and a process reads one copy of a dataset (local if
/// pulled, remote otherwise), so the index is a stable key.
///
/// Capped: a scan wide enough to touch a large fraction of 3.77M
/// packages stops adding rather than growing without bound — a full
/// memo would be hundreds of MB, and the cap costs only re-reads.
const PKG_MEMO_MAX: usize = 100_000;

fn pkg_memo() -> &'static std::sync::Mutex<std::collections::HashMap<u64, Arc<Value>>> {
    static MEMO: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, Arc<Value>>>> =
        std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}

fn json_pkg(v: &Value) -> Pkg<'_> {
    let s = |k: &str| v[k].as_str().unwrap_or("");
    Pkg {
        pkgid: s("pkgid"),
        scheme: s("scheme"),
        witness: s("witness"),
        name: s("name"),
        evr: s("evr"),
        arch: s("arch"),
        location: s("location"),
    }
}

/// Package rows by index, memoized: only the ones this process has
/// never seen are read, and they are read in one grouped pass.
fn packages_at<R, F>(open: &F, refs: &[u64]) -> Result<Vec<Arc<Value>>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    let missing: Vec<u64> = {
        let memo = pkg_memo().lock().expect("package memo");
        refs.iter()
            .filter(|r| !memo.contains_key(r))
            .copied()
            .collect()
    };
    if !missing.is_empty() {
        let (preader, pmeta) = open("data/packages.parquet")?;
        let fetched = rows_at(&preader, &pmeta, PKG_COLS, &missing)?;
        let mut memo = pkg_memo().lock().expect("package memo");
        if memo.len() < PKG_MEMO_MAX {
            for (idx, row) in missing.iter().zip(fetched.iter()) {
                memo.insert(*idx, Arc::new(row.clone()));
            }
        }
        // Serve this call from what was just read, so a full memo
        // still answers correctly.
        let mut out = Vec::with_capacity(refs.len());
        for r in refs {
            let v = match memo.get(r) {
                Some(v) => Arc::clone(v),
                None => match missing.iter().position(|m| m == r) {
                    Some(i) => Arc::new(fetched[i].clone()),
                    None => Arc::new(Value::Null),
                },
            };
            out.push(v);
        }
        return Ok(out);
    }
    let memo = pkg_memo().lock().expect("package memo");
    Ok(refs
        .iter()
        .map(|r| {
            memo.get(r)
                .cloned()
                .unwrap_or_else(|| Arc::new(Value::Null))
        })
        .collect())
}

/// The whole lookup, generic over how a repo-relative path becomes a
/// readable file: file rows resolve their package by row index into
/// packages.parquet (the second hop), and the digest doubles as a
/// pkgid key into the same packages table.
pub fn lookup_with<R, F>(open: F, coord: &Coord) -> Result<Vec<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    if !supports(coord.scheme) {
        return Ok(Vec::new());
    }
    let hex = coord.hex();
    let mut findings = Vec::new();

    if let Some(table) = file_table(coord) {
        let (reader, meta) = open(&table)?;
        let (rows, _) = find_rows(&reader, &meta, "digest", &["path", "pkg"], &hex, MAX_ROWS)?;
        if !rows.is_empty() {
            let mut refs: Vec<u64> = rows
                .iter()
                .filter_map(|r| r["pkg"].as_u64())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            refs.truncate(MAX_ROWS);
            let pkgs = packages_at(&open, &refs)?;
            for row in &rows {
                let (Some(path), Some(pref)) = (row["path"].as_str(), row["pkg"].as_u64()) else {
                    continue;
                };
                let Some(i) = refs.iter().position(|r| *r == pref) else {
                    continue;
                };
                findings.push(file_finding(path, &json_pkg(&pkgs[i]), coord.scheme, &hex));
            }
        }
    }

    let (preader, pmeta) = open("data/packages.parquet")?;
    let (rows, _) = find_rows(&preader, &pmeta, "pkgid", PKG_COLS, &hex, MAX_ROWS)?;
    findings.extend(
        rows.iter()
            .map(|r| pkg_finding(&json_pkg(r), coord.scheme, &hex)),
    );
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_file_and_package_rows() {
        let hex = "2c".repeat(32);
        let pkg = Pkg {
            pkgid: &"3d".repeat(32),
            scheme: "sha256",
            witness: "fedora-44",
            name: "bash",
            evr: "5.3.9-3.fc44",
            arch: "x86_64",
            location: "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/Packages/b/bash-5.3.9-3.fc44.x86_64.rpm",
        };
        let file = file_finding("/usr/bin/bash", &pkg, Scheme::Sha256, &hex);
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
        let a = file.archive.as_ref().expect("containment edge");
        assert_eq!(
            (a.scheme.as_str(), a.digest.as_str()),
            ("sha256", pkg.pkgid)
        );
        assert_eq!(a.path, "/usr/bin/bash");
        assert_eq!(a.name, "bash-5.3.9-3.fc44.x86_64.rpm");
        assert_eq!(a.url.as_deref(), Some(pkg.location));

        let p = pkg_finding(&pkg, Scheme::Sha256, &hex);
        assert_eq!(
            p.claims[0].statement,
            "Fedora 44 packages these bytes as bash-5.3.9-3.fc44.x86_64.rpm (bash 5.3.9-3.fc44)"
        );
        // Artifact-level rows ARE the bytes at the URL — no edge.
        assert!(p.archive.is_none());
    }

    #[test]
    fn witness_slugs_parse_and_degrade() {
        assert_eq!(
            witness_display("fedora-44-updates"),
            ("fedora", "Fedora 44 updates".to_string())
        );
        // longest prefix wins over the shorter project
        assert_eq!(
            witness_display("fedora-core-4"),
            ("fedora", "Fedora Core 4".to_string())
        );
        assert_eq!(
            witness_display("rpmfusion-free-fedora-44"),
            ("rpmfusion", "RPM Fusion free fedora 44".to_string())
        );
        assert_eq!(
            witness_display("centos-stream-10"),
            ("centos", "CentOS Stream 10".to_string())
        );
        assert_eq!(
            witness_display("centos-7.9"),
            ("centos", "CentOS 7.9".to_string())
        );
        assert_eq!(
            witness_display("vscode"),
            ("vscode", "Microsoft VS Code".to_string())
        );
        assert_eq!(
            witness_display("opensuse-leap-15.6"),
            ("opensuse", "openSUSE Leap 15.6".to_string())
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
        assert_eq!(
            start_paths(&sha256),
            vec!["data/files-sha256-a.parquet", "data/packages.parquet"]
        );
        // sha512 digests are pkgid-only (openSUSE)
        let sha512 = Coord {
            scheme: Scheme::Sha512,
            digest: vec![0xab; 64],
        };
        assert_eq!(start_paths(&sha512), vec!["data/packages.parquet"]);
        // ancient repos state md5 file digests
        let md5 = Coord {
            scheme: Scheme::Md5,
            digest: vec![0x01; 16],
        };
        assert_eq!(
            start_paths(&md5),
            vec!["data/files-md5.parquet", "data/packages.parquet"]
        );
        assert!(!supports(Scheme::Blake2s256));
    }
}
