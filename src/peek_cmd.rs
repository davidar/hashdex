//! `hdx peek` — the hashoscope. Diffoscope dissects containers to
//! diff them; peek dissects them to *identify* them: every nested
//! member gets its coordinates minted in one streaming pass and is
//! then checked against the membership filters and claim indexes,
//! exactly like a file on disk in `hdx scan`. A pristine tarball no
//! index has ever seen usually contains hundreds of files the indexes
//! know intimately — peek makes that visible.
//!
//! This is user-initiated local hashing, the one admission-rule
//! exception: no format handler here may ever imply a fetch.

use crate::coord::{Coord, Scheme};
use crate::filter::NamedFilter;
use crate::finding::Finding;
use crate::scan_cmd::{
    hex_lower, hex_upper, human, local_verdicts, online_probe, s, FileResult, Ticker,
    EXPENSIVE_FILTER_BYTES, IDENTITY_MIN_BYTES,
};
use anyhow::{Context, Result};
use serde_json::json;
use sha2::Digest;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

/// Containers nested deeper than this are hashed but not entered.
const MAX_DEPTH: usize = 16;
/// Beyond this many members the descent stops (reported honestly).
const MAX_MEMBERS: usize = 1_000_000;
/// Members that need random access (zip) spool to RAM up to this,
/// then overflow to a temp file.
const RAM_SPOOL_MAX: u64 = 256 << 20;
/// Bytes sniffed to decide whether a member is itself a container
/// (512 = one tar block, enough for every magic we look at).
const HEAD: usize = 512;

// ---------------------------------------------------------------- mint

/// All six coordinate hashers run in one pass over the raw member
/// bytes. sha1_git needs the length as a prefix, so streams of
/// unknown length (a decompressed wrapper) mint five coordinates.
struct Mint {
    md5: md5::Md5,
    sha1: sha1::Sha1,
    sha256: sha2::Sha256,
    sha512: sha2::Sha512,
    blake2s: blake2::Blake2s256,
    sha1_git: Option<sha1::Sha1>,
    n: u64,
}

struct Minted {
    size: u64,
    sha1: [u8; 20],
    sha256: [u8; 32],
    coords: Vec<Coord>,
}

impl Mint {
    fn new(len: Option<u64>) -> Mint {
        let sha1_git = len.map(|len| {
            let mut h = sha1::Sha1::new();
            h.update(format!("blob {len}\0").as_bytes());
            h
        });
        Mint {
            md5: md5::Md5::new(),
            sha1: sha1::Sha1::new(),
            sha256: sha2::Sha256::new(),
            sha512: sha2::Sha512::new(),
            blake2s: blake2::Blake2s256::new(),
            sha1_git,
            n: 0,
        }
    }

    fn update(&mut self, b: &[u8]) {
        self.md5.update(b);
        self.sha1.update(b);
        self.sha256.update(b);
        self.sha512.update(b);
        self.blake2s.update(b);
        if let Some(g) = &mut self.sha1_git {
            g.update(b);
        }
        self.n += b.len() as u64;
    }

    fn finish(self) -> Minted {
        let sha1: [u8; 20] = self.sha1.finalize().into();
        let sha256: [u8; 32] = self.sha256.finalize().into();
        let mut coords = vec![
            Coord::new(Scheme::Md5, self.md5.finalize().to_vec()),
            Coord::new(Scheme::Sha1, sha1.to_vec()),
            Coord::new(Scheme::Sha256, sha256.to_vec()),
            Coord::new(Scheme::Sha512, self.sha512.finalize().to_vec()),
            Coord::new(Scheme::Blake2s256, self.blake2s.finalize().to_vec()),
        ];
        if let Some(g) = self.sha1_git {
            coords.push(Coord::new(Scheme::Sha1Git, g.finalize().to_vec()));
        }
        Minted {
            size: self.n,
            sha1,
            sha256,
            coords: coords.into_iter().flatten().collect(),
        }
    }
}

/// Feeds every byte the consumer pulls into the mint. Container
/// parsers sit on top of this, so the member's own hash covers
/// exactly the bytes the parser walked plus whatever we drain after.
struct Tee<'a> {
    inner: Box<dyn Read + 'a>,
    mint: Mint,
}

impl Read for Tee<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.mint.update(&buf[..n]);
        Ok(n)
    }
}

fn drain(r: &mut dyn Read) {
    let _ = std::io::copy(r, &mut std::io::sink());
}

// -------------------------------------------------------------- sniff

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Tar,
    Zip,
    Ar,
    Rpm,
    Cpio,
    SquashFs,
    SevenZ,
    Iso,
    Plain,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Gzip => "gzip",
            Kind::Xz => "xz",
            Kind::Zstd => "zstd",
            Kind::Bzip2 => "bzip2",
            Kind::Tar => "tar",
            Kind::Zip => "zip",
            Kind::Ar => "ar",
            Kind::Rpm => "rpm",
            Kind::Cpio => "cpio",
            Kind::SquashFs => "squashfs",
            Kind::SevenZ => "7z",
            Kind::Iso => "iso9660",
            Kind::Plain => "file",
        }
    }
}

fn sniff(head: &[u8], name: &str) -> Kind {
    if head.starts_with(b"!<arch>\n") {
        Kind::Ar
    } else if head.starts_with(&[0x1f, 0x8b]) {
        Kind::Gzip
    } else if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Kind::Xz
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Kind::Zstd
    } else if head.starts_with(b"BZh") && head.get(3).is_some_and(u8::is_ascii_digit) {
        Kind::Bzip2
    } else if head.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
        Kind::Zip
    } else if head.starts_with(&[0xed, 0xab, 0xee, 0xdb]) {
        Kind::Rpm
    } else if head.starts_with(b"070701") || head.starts_with(b"070702") {
        Kind::Cpio
    } else if head.len() > 262 && &head[257..262] == b"ustar" {
        Kind::Tar
    } else if head.starts_with(b"hsqs") {
        Kind::SquashFs
    } else if head.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        Kind::SevenZ
    } else if name.to_ascii_lowercase().ends_with(".iso") {
        // iso9660's magic sits at byte 32769 — out of head range, so
        // the extension stands in (only affects the "not descended"
        // note, never identity).
        Kind::Iso
    } else {
        Kind::Plain
    }
}

/// What a decompressed wrapper member should be called: the name
/// minus the compression suffix, `.tgz`-style contractions expanded.
fn unwrapped_name(name: &str, kind: Kind) -> String {
    let lower = name.to_ascii_lowercase();
    let map: &[(&str, &str)] = match kind {
        Kind::Gzip => &[(".tgz", ".tar"), (".gz", "")],
        Kind::Xz => &[(".txz", ".tar"), (".xz", "")],
        Kind::Zstd => &[(".tzst", ".tar"), (".zst", "")],
        Kind::Bzip2 => &[(".tbz2", ".tar"), (".tbz", ".tar"), (".bz2", "")],
        _ => &[],
    };
    for (suffix, replacement) in map {
        if lower.ends_with(suffix) {
            return format!("{}{replacement}", &name[..name.len() - suffix.len()]);
        }
    }
    format!("{name}~unpacked")
}

// ------------------------------------------------------------- member

/// One member's resolution tier, computed once and reused by the
/// listing, the summary, and the container rollups.
#[derive(Clone, Copy, PartialEq)]
enum Class {
    Identified,
    Consistent,
    Membership,
    Unknown,
    Floor,
}

/// Recursive verdict for a container: counts over every LEAF
/// descendant, at any depth.
#[derive(Default, Clone, Copy)]
struct Rollup {
    total: usize,
    known: usize,
    unknown: usize,
    floor: usize,
}

pub struct Member {
    pub path: String,
    pub depth: usize,
    pub kind: &'static str,
    pub size: u64,
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
    pub coords: Vec<Coord>,
    pub matched: Vec<String>,
    pub children: usize,
    pub note: Option<String>,
}

struct Ctx<'a> {
    members: Vec<Option<Member>>,
    /// The root file's path: already seekable, so seek-needing
    /// containers at depth 0 re-open it instead of spooling a copy.
    root: Option<PathBuf>,
    /// Probe order mirrors scan: cheapest filter first, RAM-dwarfing
    /// ones skipped once a smaller filter already matched.
    probe_order: Vec<&'a NamedFilter>,
    truncated: bool,
    ticker: &'a Ticker,
}

impl Ctx<'_> {
    /// Probe the member's digests against the filters and file it into
    /// its reserved slot. `member.matched` arrives empty and is filled
    /// here (sub-floor members never probe).
    fn seal(&mut self, slot: usize, mut member: Member) {
        if member.size >= IDENTITY_MIN_BYTES {
            let sha1_hex = hex_upper(&member.sha1);
            let sha256_hex = hex_lower(&member.sha256);
            for f in &self.probe_order {
                if f.bytes >= EXPENSIVE_FILTER_BYTES && !member.matched.is_empty() {
                    continue;
                }
                let key: &[u8] = match f.scheme {
                    Scheme::Sha1 => sha1_hex.as_bytes(),
                    Scheme::Sha256 => sha256_hex.as_bytes(),
                    _ => continue,
                };
                if f.bloom.check(key) {
                    member.matched.push(f.name.clone());
                }
            }
            member.matched.sort();
            member.matched.dedup();
        }
        self.members[slot] = Some(member);
        self.ticker.update(64, self.members.len(), || {
            format!("descending… {} members", self.members.len())
        });
    }
}

impl Member {
    fn build(
        path: String,
        depth: usize,
        kind: Kind,
        minted: Minted,
        children: usize,
        note: Option<String>,
    ) -> Member {
        Member {
            path,
            depth,
            kind: kind.label(),
            size: minted.size,
            sha1: minted.sha1,
            sha256: minted.sha256,
            coords: minted.coords,
            matched: Vec::new(),
            children,
            note,
        }
    }
}

// ------------------------------------------------------------ descent

/// Hash one member and, if it is a container we understand, descend
/// into it. `len` is the member's size when the enclosing format
/// states it (tar/zip/ar/cpio do; decompressed streams don't).
fn process(
    ctx: &mut Ctx,
    reader: &mut dyn Read,
    len: Option<u64>,
    path: String,
    name: &str,
    depth: usize,
) -> Result<()> {
    if ctx.members.len() >= MAX_MEMBERS {
        ctx.truncated = true;
        drain(reader);
        return Ok(());
    }

    let mut head = vec![0u8; HEAD];
    let mut got = 0;
    while got < HEAD {
        let n = reader.read(&mut head[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    head.truncate(got);

    let kind = sniff(&head, name);
    let slot = ctx.members.len();
    ctx.members.push(None);

    let mut tee = Tee {
        inner: Box::new(std::io::Cursor::new(head).chain(reader)),
        mint: Mint::new(len),
    };

    // Depth-capped or unsupported containers still get fully hashed —
    // identity never depends on whether we can see inside.
    let too_deep = depth >= MAX_DEPTH && !matches!(kind, Kind::Plain | Kind::SevenZ);
    let mut note = None;
    let mut children = 0usize;

    match kind {
        Kind::Plain => drain(&mut tee),
        // The cap must outrank every container arm below.
        _ if too_deep => {
            note = Some(format!(
                "nested deeper than {MAX_DEPTH} levels — not descended"
            ));
            drain(&mut tee);
        }
        Kind::SquashFs => {
            // backhand needs BufRead + Seek, so squashfs spools like zip.
            let (minted, spool) = spool_or_root(ctx, tee, depth)?;
            if let Err(e) = walk_squashfs(ctx, spool, &path, depth, &mut children) {
                note = Some(format!("squashfs parse failed: {e}"));
            }
            ctx.seal(
                slot,
                Member::build(path, depth, kind, minted, children, note),
            );
            return Ok(());
        }
        Kind::Iso => {
            // iso9660 files are contiguous extents — pure (offset, len)
            // reads over the spooled image, no decompression at all.
            let (minted, mut spool) = spool_or_root(ctx, tee, depth)?;
            if let Err(e) = walk_iso(ctx, &mut spool, &path, depth, &mut children) {
                note = Some(format!("iso9660 parse failed: {e}"));
            }
            ctx.seal(
                slot,
                Member::build(path, depth, kind, minted, children, note),
            );
            return Ok(());
        }
        Kind::SevenZ => {
            note = Some(format!(
                "{} recognized — descending into it is not supported yet",
                kind.label()
            ));
            drain(&mut tee);
        }
        Kind::Gzip => {
            let mut dec = flate2::read::MultiGzDecoder::new(tee);
            let child = unwrapped_name(name, kind);
            let r = process(
                ctx,
                &mut dec,
                None,
                format!("{path}!{child}"),
                &child,
                depth + 1,
            );
            children = 1;
            tee = dec.into_inner();
            drain(&mut tee);
            if let Err(e) = r {
                note = Some(format!("decompression stopped: {e}"));
            }
        }
        Kind::Xz => {
            let mut dec = liblzma::read::XzDecoder::new_multi_decoder(tee);
            let child = unwrapped_name(name, kind);
            let r = process(
                ctx,
                &mut dec,
                None,
                format!("{path}!{child}"),
                &child,
                depth + 1,
            );
            children = 1;
            tee = dec.into_inner();
            drain(&mut tee);
            if let Err(e) = r {
                note = Some(format!("decompression stopped: {e}"));
            }
        }
        Kind::Zstd => {
            let mut dec = zstd::stream::read::Decoder::new(tee)?;
            let child = unwrapped_name(name, kind);
            let r = process(
                ctx,
                &mut dec,
                None,
                format!("{path}!{child}"),
                &child,
                depth + 1,
            );
            children = 1;
            tee = dec.finish().into_inner();
            drain(&mut tee);
            if let Err(e) = r {
                note = Some(format!("decompression stopped: {e}"));
            }
        }
        Kind::Bzip2 => {
            let mut dec = bzip2::read::MultiBzDecoder::new(tee);
            let child = unwrapped_name(name, kind);
            let r = process(
                ctx,
                &mut dec,
                None,
                format!("{path}!{child}"),
                &child,
                depth + 1,
            );
            children = 1;
            tee = dec.into_inner();
            drain(&mut tee);
            if let Err(e) = r {
                note = Some(format!("decompression stopped: {e}"));
            }
        }
        Kind::Tar => {
            let mut archive = tar::Archive::new(tee);
            match archive.entries() {
                Ok(entries) => {
                    for entry in entries {
                        let mut entry = match entry {
                            Ok(e) => e,
                            Err(e) => {
                                note = Some(format!("tar walk stopped: {e}"));
                                break;
                            }
                        };
                        if !entry.header().entry_type().is_file() {
                            continue;
                        }
                        let ename = entry
                            .path()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|_| {
                                String::from_utf8_lossy(&entry.path_bytes()).into_owned()
                            });
                        let size = entry.size();
                        children += 1;
                        let leaf = ename.rsplit('/').next().unwrap_or(&ename).to_string();
                        process(
                            ctx,
                            &mut entry,
                            Some(size),
                            format!("{path}!{ename}"),
                            &leaf,
                            depth + 1,
                        )?;
                    }
                }
                Err(e) => note = Some(format!("tar parse failed: {e}")),
            }
            tee = archive.into_inner();
            drain(&mut tee);
        }
        Kind::Ar => {
            let mut archive = ar::Archive::new(tee);
            while let Some(entry) = archive.next_entry() {
                let mut entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        note = Some(format!("ar walk stopped: {e}"));
                        break;
                    }
                };
                let ename = String::from_utf8_lossy(entry.header().identifier())
                    .trim_end_matches('/')
                    .to_string();
                let size = entry.header().size();
                children += 1;
                process(
                    ctx,
                    &mut entry,
                    Some(size),
                    format!("{path}!{ename}"),
                    &ename,
                    depth + 1,
                )?;
            }
            tee = archive.into_inner()?;
            drain(&mut tee);
        }
        Kind::Cpio => {
            match walk_cpio(ctx, &mut tee, &path, depth, &mut children) {
                Ok(n) => note = n,
                Err(e) => note = Some(format!("cpio walk stopped: {e}")),
            }
            drain(&mut tee);
        }
        Kind::Rpm => {
            // Lead (96 bytes, magic already sniffed) + signature header
            // (8-aligned) + main header, then the payload — which is
            // just a compressed cpio the wrapper/cpio arms above know
            // how to walk, so hand it back to process() as a member.
            match skip_rpm_headers(&mut tee) {
                Ok(()) => {
                    children = 1;
                    process(
                        ctx,
                        &mut tee,
                        None,
                        format!("{path}!payload"),
                        "payload",
                        depth + 1,
                    )?;
                }
                Err(e) => note = Some(format!("rpm header parse failed: {e}")),
            }
            drain(&mut tee);
        }
        Kind::Zip => {
            // Zip needs random access (the truth lives in the central
            // directory), so the member spools — hashed on the way in.
            let (minted, spool) = spool_or_root(ctx, tee, depth)?;
            match walk_zip(ctx, spool, &path, depth, &mut children) {
                Ok(()) => {}
                Err(e) => note = Some(format!("zip parse failed: {e}")),
            }
            ctx.seal(
                slot,
                Member::build(path, depth, kind, minted, children, note),
            );
            return Ok(());
        }
    }

    ctx.seal(
        slot,
        Member::build(path, depth, kind, tee.mint.finish(), children, note),
    );
    Ok(())
}

fn read_exact_n(r: &mut dyn Read, n: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn skip_n(r: &mut dyn Read, n: u64) -> Result<()> {
    let copied = std::io::copy(&mut r.take(n), &mut std::io::sink())?;
    anyhow::ensure!(copied == n, "truncated (wanted {n} bytes, got {copied})");
    Ok(())
}

/// RPM = lead ‖ signature header (padded to 8) ‖ header ‖ payload.
/// Both headers are index blocks: magic(3) ver(1) reserved(4)
/// nindex(u32be) hsize(u32be) ‖ nindex×16 ‖ hsize.
fn skip_rpm_headers(r: &mut dyn Read) -> Result<()> {
    skip_n(r, 96)?;
    for pad in [true, false] {
        let intro = read_exact_n(r, 16)?;
        anyhow::ensure!(intro[..3] == [0x8e, 0xad, 0xe8], "bad header magic");
        let nindex = u32::from_be_bytes(intro[8..12].try_into().unwrap()) as u64;
        let hsize = u32::from_be_bytes(intro[12..16].try_into().unwrap()) as u64;
        let body = nindex * 16 + hsize;
        skip_n(r, body)?;
        if pad {
            skip_n(r, (8 - body % 8) % 8)?;
        }
    }
    Ok(())
}

/// cpio "newc"/"crc" ASCII format: fixed 110-byte hex headers, names
/// and data padded to 4. The trailer is a member literally named
/// TRAILER!!! — the format is nothing if not self-documenting.
fn walk_cpio(
    ctx: &mut Ctx,
    r: &mut dyn Read,
    path: &str,
    depth: usize,
    children: &mut usize,
) -> Result<Option<String>> {
    fn hexfield(h: &[u8], i: usize) -> Result<u64> {
        let f = std::str::from_utf8(&h[6 + i * 8..14 + i * 8])?;
        Ok(u64::from_str_radix(f, 16)?)
    }
    loop {
        let mut hdr = [0u8; 110];
        match r.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(_) => return Ok(Some("cpio ended without trailer".into())),
        }
        if &hdr[..6] != b"070701" && &hdr[..6] != b"070702" {
            return Ok(Some("cpio walk stopped: bad member magic".into()));
        }
        let mode = hexfield(&hdr, 1)?;
        let filesize = hexfield(&hdr, 6)?;
        let namesize = hexfield(&hdr, 11)?;
        let name_padded = (110 + namesize).div_ceil(4) * 4 - 110;
        let name_raw = read_exact_n(r, name_padded)?;
        let name = String::from_utf8_lossy(&name_raw[..namesize.saturating_sub(1) as usize])
            .trim_start_matches("./")
            .to_string();
        if name == "TRAILER!!!" {
            return Ok(None);
        }
        let data_pad = filesize.div_ceil(4) * 4 - filesize;
        if mode & 0o170000 == 0o100000 {
            *children += 1;
            let leaf = name.rsplit('/').next().unwrap_or(&name).to_string();
            let mut data = r.take(filesize);
            process(
                ctx,
                &mut data,
                Some(filesize),
                format!("{path}!{name}"),
                &leaf,
                depth + 1,
            )?;
            drain(&mut data);
        } else {
            skip_n(r, filesize)?;
        }
        skip_n(r, data_pad)?;
    }
}

/// Seek-needing containers: the root file is already seekable, so
/// hash it in place and re-open it rather than copying gigabytes into
/// a spool; nested members genuinely need the copy.
fn spool_or_root(ctx: &Ctx, mut tee: Tee<'_>, depth: usize) -> Result<(Minted, Spool)> {
    if depth == 0 {
        if let Some(p) = &ctx.root {
            drain(&mut tee);
            let f = std::fs::File::open(p).with_context(|| format!("reopen {}", p.display()))?;
            return Ok((tee.mint.finish(), Spool::File(std::io::BufReader::new(f))));
        }
    }
    spool_all(tee.mint, tee.inner)
}

enum Spool {
    Mem(std::io::Cursor<Vec<u8>>),
    File(std::io::BufReader<std::fs::File>),
}

impl Read for Spool {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Spool::Mem(c) => c.read(buf),
            Spool::File(f) => f.read(buf),
        }
    }
}

impl Seek for Spool {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            Spool::Mem(c) => c.seek(pos),
            Spool::File(f) => f.seek(pos),
        }
    }
}

/// Drain a stream into a seekable spool, hashing every byte on the
/// way. RAM up to the cap, an unlinked temp file beyond it.
fn spool_all(mut mint: Mint, mut src: Box<dyn Read + '_>) -> Result<(Minted, Spool)> {
    let mut mem: Vec<u8> = Vec::new();
    let mut file: Option<std::fs::File> = None;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        mint.update(&buf[..n]);
        if let Some(f) = &mut file {
            f.write_all(&buf[..n])?;
        } else {
            mem.extend_from_slice(&buf[..n]);
            if mem.len() as u64 > RAM_SPOOL_MAX {
                // NOT tempfile::tempfile(): std's temp dir is tmpfs on
                // many distros, and a multi-GB spool in tmpfs is a
                // memory bomb. The cache dir is real disk.
                let dir = crate::filter::filters_dir()
                    .parent()
                    .map(|p| p.join("tmp"))
                    .context("no cache dir")?;
                std::fs::create_dir_all(&dir)?;
                let mut f = tempfile::tempfile_in(&dir).context("create spool temp file")?;
                f.write_all(&mem)?;
                mem = Vec::new();
                file = Some(f);
            }
        }
    }
    let spool = match file {
        Some(mut f) => {
            f.seek(std::io::SeekFrom::Start(0))?;
            Spool::File(std::io::BufReader::new(f))
        }
        None => Spool::Mem(std::io::Cursor::new(mem)),
    };
    Ok((mint.finish(), spool))
}

/// iso9660, hand-rolled read-only. Volume descriptors start at sector
/// 16; the primary descriptor's root record leads to a directory tree
/// where every file is one or more contiguous extents. Names prefer
/// Rock Ridge NM entries (Linux media carry them); plain 9660 names
/// get their ";1" version suffix stripped. Joliet is not read.
fn walk_iso(
    ctx: &mut Ctx,
    spool: &mut Spool,
    path: &str,
    depth: usize,
    children: &mut usize,
) -> Result<()> {
    const SECTOR: u64 = 2048;
    let mut root: Option<(u64, u64)> = None;
    for sector in 16..48u64 {
        let mut vd = [0u8; 2048];
        spool.seek(std::io::SeekFrom::Start(sector * SECTOR))?;
        spool.read_exact(&mut vd)?;
        anyhow::ensure!(&vd[1..6] == b"CD001", "no CD001 volume descriptor");
        match vd[0] {
            1 if root.is_none() => {
                // The root record's "name" is the pseudo-entry byte
                // 0x00, so read the fields raw instead of via
                // parse_iso_record (which rightly skips pseudo-entries).
                let rec = &vd[156..190];
                anyhow::ensure!(rec[0] >= 34, "bad root record");
                let lba = u32::from_le_bytes(rec[2..6].try_into().unwrap()) as u64;
                let size = u32::from_le_bytes(rec[10..14].try_into().unwrap()) as u64;
                root = Some((lba, size));
            }
            255 => break,
            _ => {}
        }
    }
    let (lba, size) = root.context("no primary volume descriptor")?;
    walk_iso_dir(ctx, spool, lba, size, path, "", depth, children)
}

struct IsoRecord {
    lba: u64,
    size: u64,
    is_dir: bool,
    more_extents: bool,
    name: String,
}

fn parse_iso_record(rec: &[u8]) -> Option<IsoRecord> {
    let len = rec[0] as usize;
    if len < 34 || rec.len() < len {
        return None;
    }
    let lba = u32::from_le_bytes(rec[2..6].try_into().ok()?) as u64;
    let size = u32::from_le_bytes(rec[10..14].try_into().ok()?) as u64;
    let flags = rec[25];
    let name_len = rec[32] as usize;
    if 33 + name_len > len {
        return None;
    }
    let raw = &rec[33..33 + name_len];
    // 0x00/0x01 are the self/parent pseudo-entries.
    if raw == [0x00] || raw == [0x01] {
        return None;
    }
    let mut name = String::from_utf8_lossy(raw)
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_string();
    // Rock Ridge: the system use area (after the name, padded to even)
    // may carry NM entries with the real name.
    let mut su = 33 + name_len + (1 - name_len % 2);
    let mut rr_name = String::new();
    while su + 4 <= len {
        let (sig, entry_len) = (&rec[su..su + 2], rec[su + 2] as usize);
        if entry_len < 4 || su + entry_len > len {
            break;
        }
        if sig == b"NM" && entry_len > 5 {
            rr_name.push_str(&String::from_utf8_lossy(&rec[su + 5..su + entry_len]));
        }
        su += entry_len;
    }
    if !rr_name.is_empty() && rr_name != "." && rr_name != ".." {
        name = rr_name;
    }
    Some(IsoRecord {
        lba,
        size,
        is_dir: flags & 0x02 != 0,
        more_extents: flags & 0x80 != 0,
        name,
    })
}

/// Reads a file that spans one or more extents of the spooled image.
struct ExtentReader<'a> {
    spool: &'a mut Spool,
    extents: std::collections::VecDeque<(u64, u64)>, // (byte offset, len)
    current: u64,                                    // bytes left in the seeked extent
}

impl Read for ExtentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.current == 0 {
            let Some((off, len)) = self.extents.pop_front() else {
                return Ok(0);
            };
            self.spool.seek(std::io::SeekFrom::Start(off))?;
            self.current = len;
        }
        let want = buf.len().min(self.current as usize);
        let n = self.spool.read(&mut buf[..want])?;
        self.current -= n as u64;
        Ok(n)
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_iso_dir(
    ctx: &mut Ctx,
    spool: &mut Spool,
    lba: u64,
    size: u64,
    path: &str,
    prefix: &str,
    depth: usize,
    children: &mut usize,
) -> Result<()> {
    anyhow::ensure!(size < 64 << 20, "directory extent implausibly large");
    spool.seek(std::io::SeekFrom::Start(lba * 2048))?;
    let mut dir = vec![0u8; size as usize];
    spool.read_exact(&mut dir)?;

    // Parse the whole directory before touching the spool again.
    let mut files: Vec<(String, Vec<(u64, u64)>)> = Vec::new();
    let mut dirs: Vec<(String, u64, u64)> = Vec::new();
    let mut pending: Option<(String, Vec<(u64, u64)>)> = None;
    let mut off = 0usize;
    while off < dir.len() {
        if dir[off] == 0 {
            // Records never span sectors; a zero length pads to the
            // next sector boundary.
            off = (off / 2048 + 1) * 2048;
            continue;
        }
        let len = dir[off] as usize;
        if off + len > dir.len() {
            break;
        }
        if let Some(rec) = parse_iso_record(&dir[off..off + len]) {
            if rec.is_dir {
                dirs.push((rec.name, rec.lba, rec.size));
            } else {
                let extent = (rec.lba * 2048, rec.size);
                match &mut pending {
                    // Multi-extent continuation of the same file.
                    Some((_, extents)) => extents.push(extent),
                    None => pending = Some((rec.name, vec![extent])),
                }
                if !rec.more_extents {
                    files.push(pending.take().unwrap());
                }
            }
        }
        off += len;
    }

    for (name, extents) in files {
        *children += 1;
        let total: u64 = extents.iter().map(|(_, l)| l).sum();
        let mut rdr = ExtentReader {
            spool,
            extents: extents.into(),
            current: 0,
        };
        process(
            ctx,
            &mut rdr,
            Some(total),
            format!("{path}!{prefix}{name}"),
            &name.clone(),
            depth + 1,
        )?;
    }
    for (name, sub_lba, sub_size) in dirs {
        walk_iso_dir(
            ctx,
            spool,
            sub_lba,
            sub_size,
            path,
            &format!("{prefix}{name}/"),
            depth,
            children,
        )?;
    }
    Ok(())
}

fn walk_squashfs(
    ctx: &mut Ctx,
    spool: Spool,
    path: &str,
    depth: usize,
    children: &mut usize,
) -> Result<()> {
    let fs = backhand::FilesystemReader::from_reader(std::io::BufReader::new(spool))?;
    for node in fs.files() {
        let backhand::InnerNode::File(f) = &node.inner else {
            continue;
        };
        let size = f.file_len() as u64;
        let full = node.fullpath.to_string_lossy();
        let name = full.trim_start_matches('/');
        *children += 1;
        let leaf = name.rsplit('/').next().unwrap_or(name).to_string();
        let mut reader = backhand::FilesystemReaderFile::new(&fs, f).reader();
        process(
            ctx,
            &mut reader,
            Some(size),
            format!("{path}!{name}"),
            &leaf,
            depth + 1,
        )?;
    }
    Ok(())
}

fn walk_zip(
    ctx: &mut Ctx,
    spool: Spool,
    path: &str,
    depth: usize,
    children: &mut usize,
) -> Result<()> {
    let mut za = zip::ZipArchive::new(spool)?;
    for i in 0..za.len() {
        let index_name = za
            .name_for_index(i)
            .map(str::to_string)
            .unwrap_or_else(|| format!("#{i}"));
        let mut f = match za.by_index(i) {
            Ok(f) => f,
            // Encrypted or unsupported-method entries: name them, keep going.
            Err(e) => {
                let name = index_name;
                let slot = ctx.members.len();
                ctx.members.push(None);
                ctx.seal(
                    slot,
                    Member::build(
                        format!("{path}!{name}"),
                        depth + 1,
                        Kind::Plain,
                        Mint::new(Some(0)).finish(),
                        0,
                        Some(format!("unreadable zip member: {e}")),
                    ),
                );
                continue;
            }
        };
        if !f.is_file() {
            continue;
        }
        let name = f.name().to_string();
        let size = f.size();
        *children += 1;
        let leaf = name.rsplit('/').next().unwrap_or(&name).to_string();
        process(
            ctx,
            &mut f,
            Some(size),
            format!("{path}!{name}"),
            &leaf,
            depth + 1,
        )?;
    }
    Ok(())
}

// ------------------------------------------------------------ command

pub struct Options {
    pub verbose: bool,
    pub json: bool,
    /// --online consent, parsed like scan's: Some([]) = all
    /// third-party APIs, Some(list) restricts, None = datasets only.
    pub online: Option<Vec<String>>,
}

pub async fn peek(
    paths: &[PathBuf],
    opts: &Options,
    ropts: &crate::resolve::Options,
    client: &reqwest::Client,
) -> Result<()> {
    let filters = crate::filter::load_all()?;
    let ticker = Ticker::new();

    let mut members: Vec<Member> = Vec::new();
    let mut truncated = false;
    for root in paths {
        let mut file =
            std::fs::File::open(root).with_context(|| format!("open {}", root.display()))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "{} is not a file (peek opens containers; scan walks trees)",
            root.display()
        );
        let mut probe_order: Vec<&NamedFilter> = filters.iter().collect();
        probe_order.sort_by_key(|f| f.bytes);
        let mut ctx = Ctx {
            members: Vec::new(),
            root: Some(root.clone()),
            probe_order,
            truncated: false,
            ticker: &ticker,
        };
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.display().to_string());
        process(
            &mut ctx,
            &mut file,
            Some(std::fs::metadata(root)?.len()),
            root.display().to_string(),
            &name,
            0,
        )?;
        truncated |= ctx.truncated;
        members.extend(ctx.members.into_iter().flatten());
    }
    ticker.clear();

    // Demand-driven probes for matched digests — same consent line as
    // scan: dataset transports by default, third-party APIs behind
    // --online.
    let results: Vec<FileResult> = members
        .iter()
        .map(|m| FileResult {
            path: PathBuf::from(&m.path),
            size: m.size,
            mtime_ns: 0,
            sha1: m.sha1,
            sha256: m.sha256,
            from_index: false,
            matched: m.matched.clone(),
        })
        .collect();
    if !ropts.offline {
        online_probe(
            &results,
            &filters,
            opts.online.as_deref(),
            client,
            ropts,
            &ticker,
        )
        .await;
        ticker.clear();
    }

    // Local resolution: pulled datasets + the observation store the
    // probes just enriched. Members below the identity floor are never
    // attributed.
    let datasets = crate::datasets::open_all();
    let cache = crate::cache::Cache::open().ok();
    let mut rendered = Vec::new();
    let mut n_identified = 0usize;
    let mut n_consistent = 0usize;
    let mut n_membership = 0usize;
    let mut n_unknown = 0usize;
    let mut per_filter: std::collections::BTreeMap<String, usize> = Default::default();
    for m in &members {
        let (identified, consistent) = if m.size >= IDENTITY_MIN_BYTES {
            local_verdicts(&m.sha256, &m.sha1, datasets, cache.as_ref())
        } else {
            (Vec::new(), Vec::new())
        };
        for name in &m.matched {
            *per_filter.entry(name.clone()).or_default() += 1;
        }
        let has_claims = identified.iter().any(|f| !f.claims.is_empty());
        let has_consistent = consistent.iter().any(|f| !f.claims.is_empty());
        let class = if m.size < IDENTITY_MIN_BYTES {
            Class::Floor
        } else if has_claims {
            n_identified += 1;
            Class::Identified
        } else if has_consistent {
            n_consistent += 1;
            Class::Consistent
        } else if !m.matched.is_empty() {
            n_membership += 1;
            Class::Membership
        } else {
            n_unknown += 1;
            Class::Unknown
        };
        rendered.push((m, identified, consistent, class));
    }

    // A container's verdict is recursive: roll up every LEAF
    // descendant (members are in DFS order, so a member's subtree is
    // the run of deeper entries that follows it). Wrapper
    // pseudo-members and nested containers don't count against the
    // rollup — their own bytes being unindexed says nothing about
    // what they hold.
    let rollups: Vec<Option<Rollup>> = (0..rendered.len())
        .map(|i| {
            let (m, ..) = &rendered[i];
            if m.children == 0 {
                return None;
            }
            let mut r = Rollup::default();
            for (d, .., class) in rendered.iter().skip(i + 1) {
                if d.depth <= m.depth {
                    break;
                }
                if d.children > 0 {
                    continue;
                }
                r.total += 1;
                match class {
                    Class::Identified | Class::Consistent | Class::Membership => r.known += 1,
                    Class::Unknown => r.unknown += 1,
                    Class::Floor => r.floor += 1,
                }
            }
            Some(r)
        })
        .collect();

    if opts.json {
        let out: Vec<serde_json::Value> = rendered
            .iter()
            .zip(&rollups)
            .map(|((m, identified, consistent, _), rollup)| {
                let mut v = json!({
                    "path": m.path,
                    "depth": m.depth,
                    "kind": m.kind,
                    "size": m.size,
                    "members": m.children,
                    "coords": m.coords.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "filters": m.matched,
                    "identified": identified,
                    "consistent": consistent,
                    "note": m.note,
                });
                if let Some(r) = rollup {
                    v["rollup"] = json!({
                        "files": r.total,
                        "known": r.known,
                        "unknown": r.unknown,
                        "below_floor": r.floor,
                    });
                }
                v
            })
            .collect();
        println!(
            "{}",
            json!({
                "members": out,
                "truncated": truncated,
                "per_filter": per_filter,
            })
        );
        return Ok(());
    }

    for ((m, identified, consistent, _), rollup) in rendered.iter().zip(&rollups) {
        let indent = "  ".repeat(m.depth);
        let leaf = m.path.rsplit('!').next().unwrap_or(&m.path);
        let mut line = format!("{indent}{leaf} — {}", human(m.size));
        if m.kind != "file" {
            line.push_str(&format!(", {}", m.kind));
        }
        if let Some(r) = rollup {
            // The container's verdict is its contents', recursively.
            if r.total == 0 {
                line.push_str(" (no file members)");
            } else if r.unknown == 0 && r.floor == 0 {
                line.push_str(&format!(" ({} member{}, all known)", r.total, s(r.total)));
            } else {
                let mut parts = format!(" ({} member{}: {} known", r.total, s(r.total), r.known);
                if r.unknown > 0 {
                    parts.push_str(&format!(", {} unknown", r.unknown));
                }
                if r.floor > 0 {
                    parts.push_str(&format!(", {} below floor", r.floor));
                }
                parts.push(')');
                line.push_str(&parts);
            }
        }
        let no_claims = identified.iter().all(|f| f.claims.is_empty())
            && consistent.iter().all(|f| f.claims.is_empty());
        if m.size < IDENTITY_MIN_BYTES {
            line.push_str("  (below identity floor)");
        } else if no_claims && !m.matched.is_empty() {
            line.push_str(&format!("  [{}]", m.matched.join(",")));
        } else if no_claims && m.children == 0 {
            // Only leaves wear "unknown" — a container's own unindexed
            // bytes say nothing about what it holds.
            line.push_str("  — unknown");
        }
        println!("{line}");
        if let Some(note) = &m.note {
            println!("{indent}  note: {note}");
        }
        render_claims(&indent, "", identified, opts.verbose);
        render_claims(&indent, "consistent (sha1): ", consistent, opts.verbose);
    }

    let total_bytes: u64 = members
        .iter()
        .filter(|m| m.depth <= 1)
        .map(|m| m.size)
        .sum();
    let mut summary = format!(
        "\n{} member{} ({}) — {n_identified} identified, {n_consistent} consistent (weak digests only), \
         {n_membership} known to filters, {n_unknown} unknown",
        members.len(),
        s(members.len()),
        human(total_bytes),
    );
    if truncated {
        summary.push_str(&format!(
            "\nstopped at {MAX_MEMBERS} members — the rest were not examined"
        ));
    }
    eprintln!("{summary}");
    if !per_filter.is_empty() {
        let tags: Vec<String> = per_filter
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        eprintln!("  {}", tags.join("   "));
    }
    Ok(())
}

fn render_claims(indent: &str, prefix: &str, findings: &[Finding], verbose: bool) {
    if verbose {
        for f in findings {
            for c in &f.claims {
                println!("{indent}  {prefix}{}: {}", f.backend, c.statement);
                if let Some(url) = &c.url {
                    println!("{indent}    → {url}");
                }
            }
        }
        return;
    }
    // Compact: the most informative claim per backend — a URL beats
    // none, longer statements beat join-key stubs.
    let mut best: std::collections::BTreeMap<&str, &crate::finding::Claim> = Default::default();
    for f in findings {
        for c in &f.claims {
            let e = best.entry(f.backend.as_str()).or_insert(c);
            if (c.url.is_some(), c.statement.len()) > (e.url.is_some(), e.statement.len()) {
                *e = c;
            }
        }
    }
    for (backend, c) in best {
        println!("{indent}  {prefix}{backend}: {}", c.statement);
        if let Some(url) = &c.url {
            println!("{indent}    → {url}");
        }
    }
}
