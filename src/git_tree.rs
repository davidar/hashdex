//! Git object hashing for directory trees: the intrinsic identity
//! behind SWHIDs. `blob_hashes` is git's blob hash (`"blob <len>\0"`
//! prefix — the sha1 form is our `sha1_git` coordinate), and
//! [`Tree::hash`] is git's tree hash over sorted entries, computed
//! disarchive-style: empty directories are kept (Software Heritage's
//! documented deviation from git, which cannot represent them). The
//! sha1 tree hash IS `swh:1:dir:<hex>` — mintable entirely from local
//! bytes, no API asked. The same tree serialized under sha256 is the
//! digest disarchive's directory-refs carry.
//!
//! A minted tree hash is a lookup key, not a claim: it identifies the
//! content of a whole tree independent of any serialization (tar
//! member order, mtimes, compression), and pays off exactly when a
//! witness has archived that exact tree.

use anyhow::{bail, Result};
use sha2::Digest as _;
use std::collections::HashMap;

pub enum TNode {
    File {
        exec: bool,
        sha1: [u8; 20],
        sha256: [u8; 32],
    },
    Symlink {
        sha1: [u8; 20],
        sha256: [u8; 32],
    },
    Dir(Tree),
}

#[derive(Default)]
pub struct Tree {
    entries: HashMap<Vec<u8>, TNode>,
}

/// Git blob hash under sha1 and sha256, streaming: the caller feeds
/// the bytes, whose total length must equal `prefix_len`.
pub fn blob_hashes(
    prefix_len: u64,
    feed: impl FnOnce(&mut dyn FnMut(&[u8])),
) -> ([u8; 20], [u8; 32]) {
    let mut h1 = sha1::Sha1::new();
    let mut h256 = sha2::Sha256::new();
    let head = format!("blob {prefix_len}\0");
    h1.update(head.as_bytes());
    h256.update(head.as_bytes());
    feed(&mut |b: &[u8]| {
        h1.update(b);
        h256.update(b);
    });
    (h1.finalize().into(), h256.finalize().into())
}

impl Tree {
    pub fn insert(&mut self, path: &[u8], node: TNode) -> Result<()> {
        let mut parts = path.split(|&b| b == b'/').filter(|p| !p.is_empty());
        let Some(first) = parts.next() else {
            bail!("empty path in tar");
        };
        let rest: Vec<&[u8]> = parts.collect();
        if rest.is_empty() {
            self.entries.insert(first.to_vec(), node);
            return Ok(());
        }
        let sub = self
            .entries
            .entry(first.to_vec())
            .or_insert_with(|| TNode::Dir(Tree::default()));
        match sub {
            TNode::Dir(t) => {
                let mut joined = Vec::new();
                for (i, p) in rest.iter().enumerate() {
                    if i > 0 {
                        joined.push(b'/');
                    }
                    joined.extend_from_slice(p);
                }
                t.insert(&joined, node)
            }
            _ => bail!(
                "tar places a file inside a non-directory: {}",
                String::from_utf8_lossy(path)
            ),
        }
    }

    /// Git tree hash under both algorithms, disarchive-style (empty
    /// directories included; dir names sort as name+'/').
    pub fn hash(&self) -> ([u8; 20], [u8; 32]) {
        let mut names: Vec<&Vec<u8>> = self.entries.keys().collect();
        names.sort_by(|a, b| {
            let (da, db) = (
                matches!(self.entries[*a], TNode::Dir(_)),
                matches!(self.entries[*b], TNode::Dir(_)),
            );
            let ka: Vec<u8> = a
                .iter()
                .copied()
                .chain(if da { Some(b'/') } else { None })
                .collect();
            let kb: Vec<u8> = b
                .iter()
                .copied()
                .chain(if db { Some(b'/') } else { None })
                .collect();
            ka.cmp(&kb)
        });
        let mut nodes1: Vec<u8> = Vec::new();
        let mut nodes256: Vec<u8> = Vec::new();
        for name in names {
            let (mode, h1, h256): (&[u8], [u8; 20], [u8; 32]) = match &self.entries[name] {
                TNode::File { exec, sha1, sha256 } => {
                    (if *exec { b"100755" } else { b"100644" }, *sha1, *sha256)
                }
                TNode::Symlink { sha1, sha256 } => (b"120000", *sha1, *sha256),
                TNode::Dir(t) => {
                    let (h1, h256) = t.hash();
                    (b"40000", h1, h256)
                }
            };
            for (nodes, h) in [(&mut nodes1, &h1[..]), (&mut nodes256, &h256[..])] {
                nodes.extend_from_slice(mode);
                nodes.push(b' ');
                nodes.extend_from_slice(name);
                nodes.push(0);
                nodes.extend_from_slice(h);
            }
        }
        let mut h1 = sha1::Sha1::new();
        h1.update(format!("tree {}\0", nodes1.len()).as_bytes());
        h1.update(&nodes1);
        let mut h256 = sha2::Sha256::new();
        h256.update(format!("tree {}\0", nodes256.len()).as_bytes());
        h256.update(&nodes256);
        (h1.finalize().into(), h256.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        data_encoding::HEXLOWER.encode(b)
    }

    #[test]
    fn git_tree_matches_git_itself() {
        // Oracle vectors computed with `git hash-object`:
        // blob "hi\n" = 45b983be36b73c0788dc9cbcb76cbb80fc7bb057.
        let (s1, _) = blob_hashes(3, |f| f(b"hi\n"));
        assert_eq!(hex(&s1), "45b983be36b73c0788dc9cbcb76cbb80fc7bb057");
        // Tree with one entry "hi.txt" mode 100644 → verified against
        // `git init; git add hi.txt; git write-tree`:
        // b0e66a8a93b83161375f18dcdc9e9329af61e04f.
        let mut t = Tree::default();
        t.insert(
            b"hi.txt",
            TNode::File {
                exec: false,
                sha1: s1,
                sha256: [0; 32],
            },
        )
        .unwrap();
        let (t1, _) = t.hash();
        assert_eq!(hex(&t1), "b0e66a8a93b83161375f18dcdc9e9329af61e04f");
    }
}
