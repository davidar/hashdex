//! The install-media dataset, transport-free: identity, routing, and
//! claim rendering for distro release-image checksum statements.
//! tools/install_media.py harvests SHA256SUMS-style documents from
//! the projects' own release trees (full history where the tree
//! enumerates it); every row's `loc` is the checksum document itself,
//! a claim URL by construction. The witness is carried as a string so
//! new distros never change the schema or this module.
//!
//! Published as one page-indexed parquet table per key scheme
//! (`data/media-<scheme>.parquet`), each holding every row that
//! carries that scheme, sorted by it. Rows regroup digests only when
//! one document co-stated them (single-witness multi-hash rows);
//! sha512 is a strong key alongside sha256, md5/sha1-keyed rows serve
//! the weak "consistent with" tier.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::find_rows;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

/// Witness rows read per digest — an image is rarely stated by more
/// than a couple of witnesses (distro + a derivative or mirror tree).
pub const MAX_ROWS: usize = 10;

const KEY_SCHEMES: &[(Scheme, &str)] = &[
    (Scheme::Sha256, "sha256"),
    (Scheme::Sha512, "sha512"),
    (Scheme::Sha1, "sha1"),
    (Scheme::Md5, "md5"),
];

pub fn supports(s: Scheme) -> bool {
    KEY_SCHEMES.iter().any(|(k, _)| *k == s)
}

fn key_col(s: Scheme) -> Option<&'static str> {
    KEY_SCHEMES.iter().find(|(k, _)| *k == s).map(|(_, c)| *c)
}

pub const DATA_COLS: &[&str] = &[
    "witness", "sha256", "sha512", "sha1", "md5", "name", "version", "filename", "loc",
];

/// Repo-relative paths a lookup of `coord` starts in.
pub fn start_paths(coord: &Coord) -> Vec<String> {
    match key_col(coord.scheme) {
        Some(col) => vec![format!("data/media-{col}.parquet")],
        None => vec![],
    }
}

/// One row's fields, however they were stored. Digests are optional
/// per scheme: a row carries exactly what its source document stated.
pub struct Row<'a> {
    pub witness: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub filename: &'a str,
    pub loc: &'a str,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

/// Render one witness row. The backend is the witness (the distro
/// project), never the index's name. Coords carry every digest the
/// document co-stated — single-witness multi-hash observations.
pub fn finding(row: &Row) -> Finding {
    let mut what = row.filename.to_string();
    let mut detail: Vec<&str> = Vec::new();
    if !row.name.is_empty() {
        detail.push(row.name);
    }
    if !row.version.is_empty() {
        detail.push(row.version);
    }
    if !detail.is_empty() {
        what = format!("{what} ({})", detail.join(" "));
    }
    let mut coords = Vec::new();
    for (scheme, digest) in [
        ("sha256", &row.sha256),
        ("sha512", &row.sha512),
        ("sha1", &row.sha1),
        ("md5", &row.md5),
    ] {
        if let Some(d) = digest {
            coords.push(format!("{scheme}:{d}"));
        }
    }
    Finding {
        backend: row.witness.into(),
        claims: vec![Claim::new(
            format!(
                "{} releases these bytes as {what}",
                display_name(row.witness)
            ),
            Some(row.loc.to_string()),
        )],
        coords,
        archive: None,
    }
}

fn json_row(v: &Value) -> Row<'_> {
    let s = |k: &str| v[k].as_str().unwrap_or("");
    let d = |k: &str| v[k].as_str().map(str::to_string);
    Row {
        witness: s("witness"),
        name: s("name"),
        version: s("version"),
        filename: s("filename"),
        loc: s("loc"),
        sha256: d("sha256"),
        sha512: d("sha512"),
        sha1: d("sha1"),
        md5: d("md5"),
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
    let cols: Vec<&str> = DATA_COLS.iter().copied().filter(|c| *c != col).collect();
    let (reader, meta) = open(&format!("data/media-{col}.parquet"))?;
    let (rows, _) = find_rows(&reader, &meta, col, &cols, &coord.hex(), MAX_ROWS)?;
    let hex = coord.hex();
    Ok(rows
        .iter()
        .map(|r| {
            let mut row = json_row(r);
            // The projection omitted the key column; restore it from
            // the query so coords carry the co-stated set complete.
            match coord.scheme {
                Scheme::Sha256 => row.sha256 = Some(hex.clone()),
                Scheme::Sha512 => row.sha512 = Some(hex.clone()),
                Scheme::Sha1 => row.sha1 = Some(hex.clone()),
                Scheme::Md5 => row.md5 = Some(hex.clone()),
                _ => {}
            }
            finding(&row)
        })
        .collect())
}

/// Human name for a witness slug; unknown slugs render as-is, so new
/// harvester witnesses degrade gracefully.
fn display_name(witness: &str) -> &str {
    match witness {
        "ubuntu" => "Ubuntu",
        "kubuntu" => "Kubuntu",
        "xubuntu" => "Xubuntu",
        "lubuntu" => "Lubuntu",
        "ubuntu-mate" => "Ubuntu MATE",
        "ubuntustudio" => "Ubuntu Studio",
        "ubuntu-budgie" => "Ubuntu Budgie",
        "ubuntukylin" => "Ubuntu Kylin",
        "ubuntucinnamon" => "Ubuntu Cinnamon",
        "edubuntu" => "Edubuntu",
        "ubuntu-unity" => "Ubuntu Unity",
        "ubuntu-gnome" => "Ubuntu GNOME",
        "mythbuntu" => "Mythbuntu",
        "debian" => "Debian",
        "fedora" => "Fedora",
        "archlinux" => "Arch Linux",
        "almalinux" => "AlmaLinux",
        "rockylinux" => "Rocky Linux",
        "linuxmint" => "Linux Mint",
        "kali" => "Kali Linux",
        "openbsd" => "OpenBSD",
        "freebsd" => "FreeBSD",
        "netbsd" => "NetBSD",
        "void" => "Void Linux",
        "alpine" => "Alpine Linux",
        "opensuse" => "openSUSE",
        "qubes" => "Qubes OS",
        "raspberrypi" => "Raspberry Pi OS",
        "endeavouros" => "EndeavourOS",
        "openwrt" => "OpenWrt",
        "proxmox" => "Proxmox",
        "zorin" => "Zorin OS",
        "centos-stream" => "CentOS Stream",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_and_unknown_witnesses() {
        let ubuntu = finding(&Row {
            witness: "ubuntu",
            name: "",
            version: "26.04",
            filename: "ubuntu-26.04-desktop-amd64.iso",
            loc: "https://releases.ubuntu.com/26.04/SHA256SUMS",
            sha256: Some("ab".repeat(32)),
            sha512: None,
            sha1: None,
            md5: None,
        });
        assert_eq!(ubuntu.backend, "ubuntu");
        assert_eq!(
            ubuntu.claims[0].statement,
            "Ubuntu releases these bytes as ubuntu-26.04-desktop-amd64.iso (26.04)"
        );
        assert_eq!(
            ubuntu.claims[0].url.as_deref(),
            Some("https://releases.ubuntu.com/26.04/SHA256SUMS")
        );
        assert_eq!(ubuntu.coords, vec![format!("sha256:{}", "ab".repeat(32))]);

        // a multi-hash document (Qubes .DIGESTS) co-states schemes in
        // one witness row: all of them ride the finding's coords
        let qubes = finding(&Row {
            witness: "qubes",
            name: "",
            version: "4.3.1",
            filename: "Qubes-R4.3.1-x86_64.iso",
            loc: "https://ftp.qubes-os.org/iso/Qubes-R4.3.1-x86_64.iso.DIGESTS",
            sha256: Some("ab".repeat(32)),
            sha512: Some("cd".repeat(64)),
            sha1: Some("ef".repeat(20)),
            md5: Some("01".repeat(16)),
        });
        assert_eq!(qubes.coords.len(), 4);
        assert!(qubes
            .coords
            .contains(&format!("sha512:{}", "cd".repeat(64))));
        assert!(qubes.claims[0].statement.starts_with("Qubes OS releases"));

        // unknown witness slugs render as-is — new harvester witnesses
        // must degrade gracefully, not crash or vanish
        let haiku = finding(&Row {
            witness: "haiku",
            name: "",
            version: "r1beta5",
            filename: "haiku-r1beta5-x86_64-anyboot.iso",
            loc: "https://example.org/SHA256SUMS",
            sha256: Some("cd".repeat(32)),
            sha512: None,
            sha1: None,
            md5: None,
        });
        assert_eq!(haiku.backend, "haiku");
        assert!(haiku.claims[0].statement.starts_with("haiku releases"));
    }

    #[test]
    fn routes_by_scheme() {
        let sha256 = Coord {
            scheme: Scheme::Sha256,
            digest: vec![0xab; 32],
        };
        assert_eq!(start_paths(&sha256), vec!["data/media-sha256.parquet"]);
        let sha512 = Coord {
            scheme: Scheme::Sha512,
            digest: vec![0xab; 64],
        };
        assert_eq!(start_paths(&sha512), vec!["data/media-sha512.parquet"]);
        let git = Coord {
            scheme: Scheme::Sha1Git,
            digest: vec![0xab; 20],
        };
        assert!(start_paths(&git).is_empty());
        assert!(supports(Scheme::Md5));
        assert!(!supports(Scheme::Blake2s256));
    }
}
