//! Install-media checksum statements — distro release images, hashed
//! by the projects that ship them. tools/install_media.py harvests
//! SHA256SUMS-style documents from the projects' own release trees
//! (full history where the tree enumerates it); every row's `loc` is
//! the checksum document itself, a claim URL by construction. The
//! witness is carried as a string so new distros never change the
//! schema or this module.

use crate::finding::{Claim, Finding};

/// One row's fields, however they were stored.
pub struct Row<'a> {
    pub witness: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub filename: &'a str,
    pub loc: &'a str,
    pub sha256: String,
}

/// Render one witness row. The backend is the witness (the distro
/// project), never the index's name.
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
    Finding {
        backend: row.witness.into(),
        claims: vec![Claim::new(
            format!(
                "{} releases these bytes as {what}",
                display_name(row.witness)
            ),
            Some(row.loc.to_string()),
        )],
        coords: vec![format!("sha256:{}", row.sha256)],
    }
}

/// Human name for a witness slug; unknown slugs render as-is, so new
/// harvester witnesses degrade gracefully.
fn display_name(witness: &str) -> &str {
    match witness {
        "ubuntu" => "Ubuntu",
        "debian" => "Debian",
        "fedora" => "Fedora",
        "archlinux" => "Arch Linux",
        "almalinux" => "AlmaLinux",
        "rockylinux" => "Rocky Linux",
        "linuxmint" => "Linux Mint",
        "kali" => "Kali Linux",
        "openbsd" => "OpenBSD",
        "freebsd" => "FreeBSD",
        "void" => "Void Linux",
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
            sha256: "ab".repeat(32),
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

        // unknown witness slugs render as-is — new harvester witnesses
        // must degrade gracefully, not crash or vanish
        let haiku = finding(&Row {
            witness: "haiku",
            name: "",
            version: "r1beta5",
            filename: "haiku-r1beta5-x86_64-anyboot.iso",
            loc: "https://example.org/SHA256SUMS",
            sha256: "cd".repeat(32),
        });
        assert_eq!(haiku.backend, "haiku");
        assert!(haiku.claims[0].statement.starts_with("haiku releases"));
    }
}
