use crate::cache::Cache;
use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::{Context, Result};
use sha2::Digest;
use std::io::Read;
use std::path::Path;

/// The attestor name for locally minted coordinates: the one case where
/// hashdex legitimately vouches for bytes, because the user held them.
pub const LOCAL_ATTESTOR: &str = "local-hash";

/// Compute every whole-file coordinate we know how to mint, in one streaming
/// pass. This is the user hashing their *own* bytes — the allowed exception
/// to the admission rule.
pub fn compute(path: &Path) -> Result<Vec<Coord>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let len = file.metadata()?.len();
    let mut reader = std::io::BufReader::new(file);

    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();
    let mut sha512 = sha2::Sha512::new();
    let mut blake2s = blake2::Blake2s256::new();
    // git blob hash: sha1 over "blob <len>\0" + content
    let mut sha1_git = sha1::Sha1::new();
    sha1_git.update(format!("blob {len}\0").as_bytes());

    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        sha512.update(chunk);
        blake2s.update(chunk);
        sha1_git.update(chunk);
    }

    Ok(vec![
        Coord::new(Scheme::Md5, md5.finalize().to_vec())?,
        Coord::new(Scheme::Sha1, sha1.finalize().to_vec())?,
        Coord::new(Scheme::Sha256, sha256.finalize().to_vec())?,
        Coord::new(Scheme::Sha512, sha512.finalize().to_vec())?,
        Coord::new(Scheme::Blake2s256, blake2s.finalize().to_vec())?,
        Coord::new(Scheme::Sha1Git, sha1_git.finalize().to_vec())?,
    ])
}

/// Record the six-scheme row as an observation keyed on the sha256
/// coordinate. Single witness (this machine), multiple digests: a
/// crosswalk edge the walk can traverse — the only local source of
/// sha1_git/blake2s256 links. Never leaves the machine.
pub fn record(cache: &Cache, path: &Path, coords: &[Coord]) {
    let Some(sha256) = coords.iter().find(|c| c.scheme == Scheme::Sha256) else {
        return;
    };
    let finding = Finding {
        backend: LOCAL_ATTESTOR.into(),
        claims: vec![Claim::new(
            format!("hashed locally: {}", path.display()),
            None,
        )],
        coords: coords.iter().map(|c| c.to_string()).collect(),
    };
    cache.put(LOCAL_ATTESTOR, sha256, Some(&finding));
}
