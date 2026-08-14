//! The compressor catalog for recipe compression nodes (`gzip@0`):
//! named, deterministic compressors that mint verifies against the
//! original bytes and `recipe check` re-runs to rebuild them.
//!
//! The GNU family currently shells out to the system's GNU gzip —
//! whose deflate output has been byte-stable since 1993, and which is
//! exactly what pristine-tar and disarchive lean on (their `zgz` is
//! GNU gzip's deflate.c compiled with extra flags). A native port can
//! slot in behind the same catalog names later; recipes carry the
//! name, not the implementation. The credibility rule does the safety
//! work: a recipe names a compressor only after it reproduced the
//! original bytes byte-exact at mint time, so a BSD gzip or a missing
//! binary never yields a wrong recipe — only honest residue (mint) or
//! a clear failure (check).

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// One GNU-gzip catalog entry: a compression level, optionally with
/// the rsyncable rolling-window resets (gzip ≥ 1.7 `--rsyncable`,
/// identical to Debian's original patch — verified against zgz).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GnuGzip {
    pub level: u8,
    pub rsyncable: bool,
}

impl GnuGzip {
    pub fn name(self) -> String {
        match self.rsyncable {
            true => format!("gnu-{}-rsyncable", self.level),
            false => format!("gnu-{}", self.level),
        }
    }

    pub fn parse(name: &str) -> Option<GnuGzip> {
        let (level_str, rsyncable) = match name.strip_suffix("-rsyncable") {
            Some(rest) => (rest, true),
            None => (name, false),
        };
        let level: u8 = level_str.strip_prefix("gnu-")?.parse().ok()?;
        (1..=9)
            .contains(&level)
            .then_some(GnuGzip { level, rsyncable })
    }
}

/// Search order: the levels real release tooling uses first (`-9` is
/// `--best`, 6 is the default, 1 is `--fast`), each plain before
/// rsyncable, then the rest for completeness.
pub const GNU_GZIP_CANDIDATES: [u8; 9] = [9, 6, 1, 8, 7, 5, 4, 3, 2];

/// Run GNU gzip over `input` and hand the output BODY — everything
/// after the fixed 10-byte `-n` header — to `sink` in order. The
/// recorded header of the original file is spliced back in by the
/// caller, so header variance (embedded names, mtimes) never touches
/// the compressor. `sink` returning false aborts the run (a search
/// candidate mismatched): the child is killed and Ok(false) comes
/// back; Ok(true) means gzip ran to completion and `sink` accepted
/// every byte.
pub fn gzip_body(
    params: GnuGzip,
    input: &mut (dyn Read + Send),
    sink: &mut dyn FnMut(&[u8]) -> Result<bool>,
) -> Result<bool> {
    let mut cmd = Command::new("gzip");
    cmd.arg(format!("-{}", params.level));
    if params.rsyncable {
        cmd.arg("--rsyncable");
    }
    cmd.args(["-n", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd
        .spawn()
        .context("spawn gzip — GNU gzip on PATH is required for gzip@0 nodes")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");

    let result = std::thread::scope(|scope| -> Result<bool> {
        let writer = scope.spawn(move || {
            let mut buf = vec![0u8; 1 << 20];
            loop {
                match input.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // A write error means the child exited (an
                        // aborted candidate) — just stop feeding.
                        if stdin.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            drop(stdin);
        });
        let mut skip = 10usize;
        let mut buf = vec![0u8; 1 << 20];
        let mut accepted = true;
        loop {
            let n = stdout.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let mut b = &buf[..n];
            if skip > 0 {
                let k = skip.min(b.len());
                skip -= k;
                b = &b[k..];
            }
            if b.is_empty() {
                continue;
            }
            if !sink(b)? {
                accepted = false;
                break;
            }
        }
        if !accepted {
            let _ = child.kill();
        }
        drop(stdout);
        let _ = writer.join();
        let status = child.wait()?;
        if accepted && !status.success() {
            bail!("gzip exited with {status}");
        }
        Ok(accepted)
    });
    result
}

/// Parse a gzip member header from the start of `r`: returns its raw
/// bytes (recorded verbatim into the recipe node, spliced back at
/// rebuild). None if this isn't a healthy single-member gzip head.
pub fn parse_gzip_header(r: &mut dyn Read) -> Result<Option<Vec<u8>>> {
    const FHCRC: u8 = 0x02;
    const FEXTRA: u8 = 0x04;
    const FNAME: u8 = 0x08;
    const FCOMMENT: u8 = 0x10;
    const HEADER_CAP: usize = 64 << 10;

    let mut hdr = vec![0u8; 10];
    if r.read_exact(&mut hdr).is_err() {
        return Ok(None);
    }
    if hdr[0] != 0x1f || hdr[1] != 0x8b || hdr[2] != 8 {
        return Ok(None);
    }
    let flg = hdr[3];
    if flg & 0xe0 != 0 {
        return Ok(None); // reserved flag bits set
    }
    if flg & FEXTRA != 0 {
        let mut xlen = [0u8; 2];
        r.read_exact(&mut xlen)?;
        hdr.extend_from_slice(&xlen);
        let n = u16::from_le_bytes(xlen) as usize;
        let mut extra = vec![0u8; n];
        r.read_exact(&mut extra)?;
        hdr.extend_from_slice(&extra);
    }
    for flag in [FNAME, FCOMMENT] {
        if flg & flag != 0 {
            loop {
                let mut b = [0u8; 1];
                r.read_exact(&mut b)?;
                hdr.push(b[0]);
                if b[0] == 0 {
                    break;
                }
                if hdr.len() > HEADER_CAP {
                    return Ok(None);
                }
            }
        }
    }
    if flg & FHCRC != 0 {
        let mut crc = [0u8; 2];
        r.read_exact(&mut crc)?;
        hdr.extend_from_slice(&crc);
    }
    Ok(Some(hdr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnu_gzip_names_round_trip() {
        for level in 1..=9 {
            for rsyncable in [false, true] {
                let c = GnuGzip { level, rsyncable };
                assert_eq!(GnuGzip::parse(&c.name()), Some(c));
            }
        }
        assert_eq!(GnuGzip::parse("gnu-0"), None);
        assert_eq!(GnuGzip::parse("gnu-10"), None);
        assert_eq!(GnuGzip::parse("zlib-9"), None);
        assert_eq!(GnuGzip::parse("gnu-9-rsyncable-extra"), None);
    }

    #[test]
    fn gzip_header_parses_fields() {
        // Minimal -n header.
        let plain = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3];
        let got = parse_gzip_header(&mut &plain[..]).unwrap().unwrap();
        assert_eq!(got, plain);
        // FNAME header embeds a NUL-terminated file name.
        let mut named = vec![0x1f, 0x8b, 8, 0x08, 1, 2, 3, 4, 0, 3];
        named.extend_from_slice(b"hello.tar\0");
        let mut r = &named[..];
        let got = parse_gzip_header(&mut r).unwrap().unwrap();
        assert_eq!(got, named);
        // Non-gzip bytes are a clean None, not an error.
        assert!(parse_gzip_header(&mut &b"not gzip at all"[..])
            .unwrap()
            .is_none());
    }
}
