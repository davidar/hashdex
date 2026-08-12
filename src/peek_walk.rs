//! peek's descent. Two input shapes: a `Stream` (bytes that only flow
//! forward — a decompressed wrapper, a tar entry) is hashed through a
//! `Tee` as the walker parses it; a `Ranged` member (a `View` of
//! seekable bytes — the root file, extents inside an iso, a stored
//! zip entry) is handed to the pool to hash independently while the
//! walker descends it by range reads, so nothing is copied or spooled.
//!
//! Spooling survives only for seek-needing containers that arrive as
//! streams (squashfs/iso behind compression, and zips whose stream
//! walk turned out untrustworthy — see `RetryConservative`).

use crate::peek_pool::{Feed, Pool};
use crate::peek_source::{spool_stream, View};
use anyhow::{Context, Result};
use std::io::{BufReader, Read, Seek};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Containers nested deeper than this are hashed but not entered.
pub(crate) const MAX_DEPTH: usize = 16;
/// Beyond this many members the descent stops (reported honestly).
pub(crate) const MAX_MEMBERS: usize = 1_000_000;
/// Bytes sniffed to decide whether a member is itself a container
/// (512 = one tar block, enough for every magic we look at).
const HEAD: usize = 512;
/// A squashfs reader's fragment cache grows without bound (every
/// decompressed fragment block is kept forever), so after this many
/// bytes of fragment-backed files the reader is rebuilt — dropping
/// the cache — and the walk resumes where it left off.
const SQUASHFS_FRAG_CAP: u64 = 256 << 20;

/// A zip walked speculatively from its stream turned out misbehaved:
/// local headers disagree with the central directory, or the stream
/// walk failed outright (data-descriptor entries — common in jars —
/// carry no lengths in their local headers). The error unwinds to the
/// nearest re-derivable boundary — the enclosing ranged member, spool,
/// or squashfs file — which discards just that subtree and re-walks it
/// conservatively, with stream-fed zips spooled.
#[derive(Debug)]
pub(crate) struct RetryConservative(pub String);

fn is_retry(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RetryConservative>().is_some()
}

impl std::fmt::Display for RetryConservative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RetryConservative {}

// -------------------------------------------------------------- sniff

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Kind {
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
    pub(crate) fn label(self) -> &'static str {
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
        // for streams the extension stands in (seekable members get
        // the real magic probed in process_ranged).
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

// ---------------------------------------------------------------- tee

/// Feeds every byte the consumer pulls into the member's hash jobs.
/// Container parsers sit on top of this, so the member's own hash
/// covers exactly the bytes the parser walked plus whatever we drain
/// after.
struct Tee<'r, 'p, 'f> {
    inner: Box<dyn Read + 'r>,
    feed: Feed,
    pool: &'p Pool<'f>,
}

impl Read for Tee<'_, '_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.feed.push(self.pool, &buf[..n]);
        Ok(n)
    }
}

fn drain(r: &mut dyn Read) {
    let _ = std::io::copy(r, &mut std::io::sink());
}

/// Child-walk errors become notes on the parent — except the
/// conservative-retry marker, which must reach a retry boundary.
fn swallow(r: Result<()>, what: &str) -> Result<Option<String>> {
    match r {
        Ok(()) => Ok(None),
        Err(e) if is_retry(&e) => Err(e),
        Err(e) => Ok(Some(format!("{what}: {e}"))),
    }
}

// ------------------------------------------------------------ descent

pub(crate) struct Walk<'a, 'f> {
    pub(crate) pool: &'a Pool<'f>,
    pub(crate) truncated: AtomicBool,
    /// Slots whose members sealed but belong to abandoned subtrees
    /// (conservative retries, batches cut short by an error); cleared
    /// from the member table after the pool drains.
    pub(crate) dead: Mutex<Vec<usize>>,
    /// Worker count for parallel container descent (squashfs).
    pub(crate) threads: usize,
}

/// Per-descent state, owned by whichever thread walks the subtree:
/// the conservative flag (spool stream zips instead of walking them
/// speculatively — set while redoing a subtree after a
/// `RetryConservative`) and the slots allocated by the current retry
/// boundary's attempt, so a retry knows exactly what to discard.
/// `count` bounds the members of ONE root descent (shared by every
/// worker walking the same container tree) — the cap is per descended
/// container, not per pool, so a multi-million-file disk scan never
/// trips it.
#[derive(Default)]
pub(crate) struct Ctx {
    conservative: bool,
    slots: Vec<usize>,
    count: std::sync::Arc<AtomicUsize>,
}

impl Walk<'_, '_> {
    /// Full descent of an explicitly named container file — the
    /// hashoscope entry point. On error the partial subtree is
    /// discarded (its members still seal and are dropped by slot);
    /// the caller reports the error without aborting anything else.
    pub(crate) fn walk_root(&self, path: &std::path::Path) -> Result<()> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let mut ctx = Ctx::default();
        let r = View::of_file(path).and_then(|view| {
            self.process_ranged(view, path.display().to_string(), &name, 0, None, &mut ctx)
        });
        if r.is_err() {
            self.discard(&mut ctx, 0);
        }
        r
    }

    /// Hash and descend a member whose bytes only flow forward.
    /// `len` is the member's size when the enclosing format states it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn process_stream(
        &self,
        r: &mut dyn Read,
        len: Option<u64>,
        path: String,
        name: &str,
        depth: usize,
        parent: Option<usize>,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if self.capped(ctx) {
            drain(r);
            return Ok(());
        }
        let (meta, feed) = self.pool.member(path.clone(), depth, parent, len, None);
        ctx.slots.push(meta.slot());
        self.run_member(r, meta, feed, path, name, depth, ctx)
    }

    /// Hash and descend a member whose handles are already allocated
    /// (the squashfs walker allocates a whole batch up front so slot
    /// order stays sibling order, then workers run the members in
    /// parallel). Both handles are closed before returning, error or
    /// not — every member seals, and a subtree abandoned by a retry
    /// is dropped from the member table by slot instead of being left
    /// half-open.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_member(
        &self,
        r: &mut dyn Read,
        meta: crate::peek_pool::MetaClose,
        mut feed: Feed,
        path: String,
        name: &str,
        depth: usize,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let pool = self.pool;
        let own = meta.slot();
        let mut head = vec![0u8; HEAD];
        let mut got = 0;
        loop {
            if got >= HEAD {
                break;
            }
            match r.read(&mut head[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => {
                    feed.close(pool);
                    meta.close(pool, Kind::Plain.label(), 0, None);
                    return Err(e.into());
                }
            }
        }
        head.truncate(got);
        let kind = sniff(&head, name);

        let too_deep = depth >= MAX_DEPTH && !matches!(kind, Kind::Plain | Kind::SevenZ);

        // Seek-needing containers fed by a stream have to spool; the
        // spool then descends exactly like a ranged member, so their
        // children can be views over the spool.
        let spools =
            matches!(kind, Kind::SquashFs | Kind::Iso) || (kind == Kind::Zip && ctx.conservative);
        if !too_deep && spools {
            let mut src = std::io::Cursor::new(head).chain(r);
            let view = match spool_stream(&mut src, |b| feed.push(pool, b)) {
                Ok(v) => v,
                Err(e) => {
                    feed.close(pool);
                    meta.close(pool, kind.label(), 0, None);
                    return Err(e);
                }
            };
            feed.close(pool);
            return match self.descend_retrying(kind, &view, &path, name, depth, own, ctx) {
                Ok((children, note)) => {
                    meta.close(pool, kind.label(), children, note);
                    Ok(())
                }
                Err(e) => {
                    meta.close(pool, kind.label(), 0, None);
                    Err(e)
                }
            };
        }

        let mut tee = Tee {
            inner: Box::new(std::io::Cursor::new(head).chain(r)),
            feed,
            pool,
        };
        let res = if too_deep {
            drain(&mut tee);
            Ok((
                0,
                Some(format!(
                    "nested deeper than {MAX_DEPTH} levels — not descended"
                )),
            ))
        } else {
            self.stream_arms(kind, &mut tee, &path, name, depth, own, ctx)
        };
        tee.feed.close(pool);
        match res {
            Ok((children, note)) => {
                meta.close(pool, kind.label(), children, note);
                Ok(())
            }
            Err(e) => {
                meta.close(pool, kind.label(), 0, None);
                Err(e)
            }
        }
    }

    /// The container arms of the stream path. Retry markers (and
    /// genuine child errors) propagate out of here; `run_member`
    /// closes the member's handles either way.
    #[allow(clippy::too_many_arguments)]
    fn stream_arms(
        &self,
        kind: Kind,
        tee: &mut Tee<'_, '_, '_>,
        path: &str,
        name: &str,
        depth: usize,
        own: usize,
        ctx: &mut Ctx,
    ) -> Result<(usize, Option<String>)> {
        let mut note = None;
        let mut children = 0usize;

        match kind {
            Kind::Plain => drain(&mut *tee),
            Kind::SevenZ => {
                note = Some(format!(
                    "{} recognized — descending into it is not supported yet",
                    kind.label()
                ));
                drain(&mut *tee);
            }
            Kind::Gzip => {
                let mut dec = flate2::read::MultiGzDecoder::new(&mut *tee);
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                children = 1;
                drop(dec);
                note = swallow(r, "decompression stopped")?;
                drain(&mut *tee);
            }
            Kind::Xz => {
                let mut dec = liblzma::read::XzDecoder::new_multi_decoder(&mut *tee);
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                children = 1;
                drop(dec);
                note = swallow(r, "decompression stopped")?;
                drain(&mut *tee);
            }
            Kind::Zstd => {
                let mut dec = zstd::stream::read::Decoder::new(&mut *tee)?;
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                children = 1;
                drop(dec);
                note = swallow(r, "decompression stopped")?;
                drain(&mut *tee);
            }
            Kind::Bzip2 => {
                let mut dec = bzip2::read::MultiBzDecoder::new(&mut *tee);
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                children = 1;
                drop(dec);
                note = swallow(r, "decompression stopped")?;
                drain(&mut *tee);
            }
            Kind::Tar => {
                let mut archive = tar::Archive::new(&mut *tee);
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
                            self.process_stream(
                                &mut entry,
                                Some(size),
                                format!("{path}!{ename}"),
                                &leaf,
                                depth + 1,
                                Some(own),
                                ctx,
                            )?;
                        }
                    }
                    Err(e) => note = Some(format!("tar parse failed: {e}")),
                }
                drain(&mut *tee);
            }
            Kind::Ar => {
                let mut archive = ar::Archive::new(&mut *tee);
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
                    self.process_stream(
                        &mut entry,
                        Some(size),
                        format!("{path}!{ename}"),
                        &ename,
                        depth + 1,
                        Some(own),
                        ctx,
                    )?;
                }
                drop(archive);
                drain(&mut *tee);
            }
            Kind::Cpio => {
                match self.cpio_stream(tee, path, depth, own, &mut children, ctx) {
                    Ok(n) => note = n,
                    Err(e) if e.downcast_ref::<RetryConservative>().is_some() => return Err(e),
                    Err(e) => note = Some(format!("cpio walk stopped: {e}")),
                }
                drain(&mut *tee);
            }
            Kind::Rpm => {
                // Lead (96 bytes, magic already sniffed) + signature
                // header (8-aligned) + main header, then the payload —
                // a compressed cpio the arms above know how to walk.
                match skip_rpm_headers(&mut *tee) {
                    Ok(()) => {
                        children = 1;
                        self.process_stream(
                            &mut *tee,
                            None,
                            format!("{path}!payload"),
                            "payload",
                            depth + 1,
                            Some(own),
                            ctx,
                        )?;
                    }
                    Err(e) => note = Some(format!("rpm header parse failed: {e}")),
                }
                drain(&mut *tee);
            }
            Kind::Zip => {
                // Optimistic streaming walk over the local headers,
                // reconciled against the central directory at the end.
                let (n, walk_note) = self.zip_speculative(tee, path, depth, own, ctx)?;
                children = n;
                note = walk_note;
                drain(&mut *tee);
            }
            Kind::SquashFs | Kind::Iso => unreachable!("handled by the spool path above"),
        }

        Ok((children, note))
    }

    /// Hash and descend a member backed by seekable bytes: the pool
    /// reads and hashes the extents while the walker descends.
    pub(crate) fn process_ranged(
        &self,
        view: View,
        path: String,
        name: &str,
        depth: usize,
        parent: Option<usize>,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if self.capped(ctx) {
            return Ok(());
        }
        let mut head = vec![0u8; HEAD];
        let got = view.read_full_at(&mut head, 0)?;
        head.truncate(got);
        let mut kind = sniff(&head, name);
        if kind == Kind::Plain && view.len() >= 32774 {
            // Seekable bytes can afford the real iso9660 check: the
            // primary volume descriptor's magic at byte 32769.
            let mut magic = [0u8; 5];
            if view.read_full_at(&mut magic, 32769)? == 5 && &magic == b"CD001" {
                kind = Kind::Iso;
            }
        }
        let pool = self.pool;
        let (meta, feed) = pool.member(path.clone(), depth, parent, Some(view.len()), None);
        ctx.slots.push(meta.slot());
        let own = meta.slot();
        pool.read_task(view.clone(), feed);

        let too_deep = depth >= MAX_DEPTH && !matches!(kind, Kind::Plain | Kind::SevenZ);
        let res = if too_deep {
            Ok((
                0,
                Some(format!(
                    "nested deeper than {MAX_DEPTH} levels — not descended"
                )),
            ))
        } else {
            self.descend_retrying(kind, &view, &path, name, depth, own, ctx)
        };
        match res {
            Ok((children, note)) => {
                meta.close(pool, kind.label(), children, note);
                Ok(())
            }
            Err(e) => {
                meta.close(pool, kind.label(), 0, None);
                Err(e)
            }
        }
    }

    /// Descend a seekable member, and — because its view can be
    /// re-walked at will — serve as a retry boundary: if a zip
    /// somewhere below turned out misbehaved, discard just this
    /// subtree and redo it conservatively instead of letting the
    /// error unwind any further.
    #[allow(clippy::too_many_arguments)]
    fn descend_retrying(
        &self,
        kind: Kind,
        view: &View,
        path: &str,
        name: &str,
        depth: usize,
        own: usize,
        ctx: &mut Ctx,
    ) -> Result<(usize, Option<String>)> {
        let start = ctx.slots.len();
        match self.descend_seekable(kind, view, path, name, depth, own, ctx) {
            Err(e) if is_retry(&e) && !ctx.conservative => {
                eprintln!("note: {e}; re-reading {path} with spooling");
                self.discard(ctx, start);
                ctx.conservative = true;
                let redo = self.descend_seekable(kind, view, path, name, depth, own, ctx);
                ctx.conservative = false;
                redo
            }
            r => r,
        }
    }

    /// The slots recorded since `start` belong to an abandoned
    /// subtree. Their members still seal — handles are closed on
    /// every path — so nothing here needs counting; marking the slots
    /// dead just drops them from the member table afterwards.
    fn discard(&self, ctx: &mut Ctx, start: usize) {
        self.dead.lock().unwrap().extend(ctx.slots.drain(start..));
    }

    /// Bump this descent's member count against the per-root cap.
    fn capped(&self, ctx: &Ctx) -> bool {
        if ctx.count.fetch_add(1, Ordering::Relaxed) >= MAX_MEMBERS {
            self.truncated.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Walk the inside of a seekable container (a ranged member or a
    /// fresh spool). Children of uncompressed formats become views —
    /// ranges of the same underlying source; only decompressed data
    /// flows as streams.
    #[allow(clippy::too_many_arguments)]
    fn descend_seekable(
        &self,
        kind: Kind,
        view: &View,
        path: &str,
        name: &str,
        depth: usize,
        own: usize,
        ctx: &mut Ctx,
    ) -> Result<(usize, Option<String>)> {
        let mut children = 0usize;
        let note = match kind {
            Kind::Plain => None,
            Kind::SevenZ => Some(format!(
                "{} recognized — descending into it is not supported yet",
                kind.label()
            )),
            Kind::Gzip => {
                let mut dec = flate2::read::MultiGzDecoder::new(BufReader::new(view.rewound()));
                children = 1;
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                swallow(r, "decompression stopped")?
            }
            Kind::Xz => {
                let mut dec =
                    liblzma::read::XzDecoder::new_multi_decoder(BufReader::new(view.rewound()));
                children = 1;
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                swallow(r, "decompression stopped")?
            }
            Kind::Zstd => {
                let mut dec = zstd::stream::read::Decoder::new(BufReader::new(view.rewound()))?;
                children = 1;
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                swallow(r, "decompression stopped")?
            }
            Kind::Bzip2 => {
                let mut dec = bzip2::read::MultiBzDecoder::new(BufReader::new(view.rewound()));
                children = 1;
                let child = unwrapped_name(name, kind);
                let r = self.process_stream(
                    &mut dec,
                    None,
                    format!("{path}!{child}"),
                    &child,
                    depth + 1,
                    Some(own),
                    ctx,
                );
                swallow(r, "decompression stopped")?
            }
            Kind::Tar => self.tar_ranged(view, path, depth, own, &mut children, ctx)?,
            Kind::Ar => {
                let mut note = None;
                let mut archive = ar::Archive::new(BufReader::new(view.rewound()));
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
                    self.process_stream(
                        &mut entry,
                        Some(size),
                        format!("{path}!{ename}"),
                        &ename,
                        depth + 1,
                        Some(own),
                        ctx,
                    )?;
                }
                note
            }
            Kind::Cpio => match self.cpio_ranged(view, path, depth, own, &mut children, ctx) {
                Ok(n) => n,
                Err(e) if e.downcast_ref::<RetryConservative>().is_some() => return Err(e),
                Err(e) => Some(format!("cpio walk stopped: {e}")),
            },
            Kind::Rpm => {
                let mut br = BufReader::new(view.rewound());
                match skip_rpm_headers(&mut br) {
                    Ok(()) => {
                        let pos = br.stream_position()?;
                        children = 1;
                        let payload = view.slice(&[(pos, view.len() - pos)]);
                        self.process_ranged(
                            payload,
                            format!("{path}!payload"),
                            "payload",
                            depth + 1,
                            Some(own),
                            ctx,
                        )?;
                        None
                    }
                    Err(e) => Some(format!("rpm header parse failed: {e}")),
                }
            }
            Kind::Zip => swallow(
                self.zip_ranged(view, path, depth, own, &mut children, ctx),
                "zip parse failed",
            )?,
            Kind::SquashFs => swallow(
                self.squashfs_ranged(view, path, depth, own, &mut children, ctx),
                "squashfs parse failed",
            )?,
            Kind::Iso => swallow(
                self.iso_ranged(view, path, depth, own, &mut children, ctx),
                "iso9660 parse failed",
            )?,
        };
        Ok((children, note))
    }

    // ------------------------------------------------------------ tar

    #[allow(clippy::too_many_arguments)]
    fn tar_ranged(
        &self,
        view: &View,
        path: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<Option<String>> {
        let mut note = None;
        let mut archive = tar::Archive::new(BufReader::with_capacity(64 << 10, view.rewound()));
        match archive.entries_with_seek() {
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
                    *children += 1;
                    let leaf = ename.rsplit('/').next().unwrap_or(&ename).to_string();
                    // Sparse entries expand on read — their on-disk
                    // range is not their content, so they stream.
                    let mut sparse = entry.header().entry_type().is_gnu_sparse();
                    if !sparse {
                        if let Ok(Some(exts)) = entry.pax_extensions() {
                            sparse = exts.flatten().any(|e| {
                                e.key().map(|k| k.starts_with("GNU.sparse")).unwrap_or(true)
                            });
                        }
                    }
                    if sparse {
                        self.process_stream(
                            &mut entry,
                            Some(size),
                            format!("{path}!{ename}"),
                            &leaf,
                            depth + 1,
                            Some(own),
                            ctx,
                        )?;
                    } else {
                        let pos = entry.raw_file_position();
                        let sub = view.slice(&[(pos, size)]);
                        self.process_ranged(
                            sub,
                            format!("{path}!{ename}"),
                            &leaf,
                            depth + 1,
                            Some(own),
                            ctx,
                        )?;
                    }
                }
            }
            Err(e) => note = Some(format!("tar parse failed: {e}")),
        }
        Ok(note)
    }

    // ------------------------------------------------------------ zip

    /// Seekable zip: the central directory is the truth, walk it
    /// directly. Stored entries become views; compressed ones stream.
    #[allow(clippy::too_many_arguments)]
    fn zip_ranged(
        &self,
        view: &View,
        path: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let pool = self.pool;
        let mut za = zip::ZipArchive::new(view.rewound())?;
        for i in 0..za.len() {
            let index_name = za
                .name_for_index(i)
                .map(str::to_string)
                .unwrap_or_else(|| format!("#{i}"));
            let mut f = match za.by_index(i) {
                Ok(f) => f,
                // Encrypted or unsupported-method entries: name them,
                // keep going.
                Err(e) => {
                    if !self.capped(ctx) {
                        let (meta, feed) = pool.member(
                            format!("{path}!{index_name}"),
                            depth + 1,
                            Some(own),
                            Some(0),
                            None,
                        );
                        ctx.slots.push(meta.slot());
                        feed.close(pool);
                        meta.close(
                            pool,
                            Kind::Plain.label(),
                            0,
                            Some(format!("unreadable zip member: {e}")),
                        );
                    }
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
            let stored_range = (f.compression() == zip::CompressionMethod::Stored
                && f.compressed_size() == size)
                .then(|| f.data_start())
                .flatten();
            match stored_range {
                Some(data_start) => {
                    drop(f);
                    let sub = view.slice(&[(data_start, size)]);
                    self.process_ranged(
                        sub,
                        format!("{path}!{name}"),
                        &leaf,
                        depth + 1,
                        Some(own),
                        ctx,
                    )?;
                }
                None => {
                    self.process_stream(
                        &mut f,
                        Some(size),
                        format!("{path}!{name}"),
                        &leaf,
                        depth + 1,
                        Some(own),
                        ctx,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Stream-fed zip, walked optimistically from its local headers —
    /// no spool. The central directory (which arrives at the end of
    /// the stream anyway) is then required to agree with what we saw;
    /// any disagreement or stream-walk failure aborts the whole
    /// descent with `RetryConservative`.
    fn zip_speculative(
        &self,
        tee: &mut Tee<'_, '_, '_>,
        path: &str,
        depth: usize,
        own: usize,
        ctx: &mut Ctx,
    ) -> Result<(usize, Option<String>)> {
        let mut children = 0usize;
        let mut streamed: Vec<(String, u32)> = Vec::new();
        loop {
            match zip::read::read_zipfile_from_stream(tee) {
                Ok(Some(mut zf)) => {
                    let name = zf.name().to_string();
                    let crc = zf.crc32();
                    let size = zf.size();
                    let is_file = zf.is_file();
                    if !name.ends_with('/') {
                        streamed.push((name.clone(), crc));
                    }
                    if is_file {
                        children += 1;
                        let leaf = name.rsplit('/').next().unwrap_or(&name).to_string();
                        self.process_stream(
                            &mut zf,
                            Some(size),
                            format!("{path}!{name}"),
                            &leaf,
                            depth + 1,
                            Some(own),
                            ctx,
                        )?;
                    }
                    // zf's Drop advances the stream past the entry.
                }
                Ok(None) => break, // central directory reached
                Err(e) => {
                    return Err(anyhow::Error::new(RetryConservative(format!(
                        "zip stream walk failed at {path}: {e}"
                    ))))
                }
            }
        }
        match reconcile_central_dir(tee, &streamed) {
            Ok(true) => Ok((children, None)),
            Ok(false) => Err(anyhow::Error::new(RetryConservative(format!(
                "zip local headers disagree with the central directory in {path}"
            )))),
            Err(e) => Err(anyhow::Error::new(RetryConservative(format!(
                "zip central directory unreadable in {path}: {e}"
            )))),
        }
    }

    // ----------------------------------------------------------- cpio

    #[allow(clippy::too_many_arguments)]
    fn cpio_stream(
        &self,
        r: &mut Tee<'_, '_, '_>,
        path: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<Option<String>> {
        loop {
            let mut hdr = [0u8; 110];
            match r.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(_) => return Ok(Some("cpio ended without trailer".into())),
            }
            let Some((mode, filesize, name)) = cpio_header(&hdr, |buf| r.read_exact(buf))? else {
                return Ok(Some("cpio walk stopped: bad member magic".into()));
            };
            if name == "TRAILER!!!" {
                return Ok(None);
            }
            let data_pad = filesize.div_ceil(4) * 4 - filesize;
            if mode & 0o170000 == 0o100000 {
                *children += 1;
                let leaf = name.rsplit('/').next().unwrap_or(&name).to_string();
                let mut data = r.take(filesize);
                self.process_stream(
                    &mut data,
                    Some(filesize),
                    format!("{path}!{name}"),
                    &leaf,
                    depth + 1,
                    Some(own),
                    ctx,
                )?;
                drain(&mut data);
            } else {
                skip_n(r, filesize)?;
            }
            skip_n(r, data_pad)?;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cpio_ranged(
        &self,
        view: &View,
        path: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<Option<String>> {
        let mut pos = 0u64;
        loop {
            let mut hdr = [0u8; 110];
            if view.read_full_at(&mut hdr, pos)? < 110 {
                return Ok(Some("cpio ended without trailer".into()));
            }
            let mut name_off = pos + 110;
            let Some((mode, filesize, name)) = cpio_header(&hdr, |buf| {
                let n = view.read_full_at(buf, name_off)?;
                name_off += n as u64;
                if n < buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "cpio name truncated",
                    ));
                }
                Ok(())
            })?
            else {
                return Ok(Some("cpio walk stopped: bad member magic".into()));
            };
            if name == "TRAILER!!!" {
                return Ok(None);
            }
            let data_off = name_off;
            let data_pad = filesize.div_ceil(4) * 4 - filesize;
            if mode & 0o170000 == 0o100000 {
                *children += 1;
                let leaf = name.rsplit('/').next().unwrap_or(&name).to_string();
                let sub = view.slice(&[(data_off, filesize)]);
                self.process_ranged(
                    sub,
                    format!("{path}!{name}"),
                    &leaf,
                    depth + 1,
                    Some(own),
                    ctx,
                )?;
            }
            pos = data_off + filesize + data_pad;
        }
    }

    // ------------------------------------------------------- squashfs

    /// Squashfs members are walked by a worker team: the walker
    /// enumerates the files and allocates their member slots in
    /// order (slot order stays sibling order), then workers
    /// decompress, hash, sniff and descend whole files in parallel —
    /// the reader's internals are lock-protected (a Mutex around the
    /// raw byte source, held only per block read; decompression runs
    /// outside it).
    #[allow(clippy::too_many_arguments)]
    fn squashfs_ranged(
        &self,
        view: &View,
        path: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<()> {
        struct Item<'i> {
            meta: crate::peek_pool::MetaClose,
            feed: Feed,
            file: &'i backhand::SquashfsFileReader,
            path: String,
            leaf: String,
            size: u64,
        }
        let mut done = 0usize;
        loop {
            // Rebuilding the reader is how the fragment cache gets
            // dropped: backhand keeps every decompressed fragment
            // block for the reader's lifetime. One reader serves one
            // batch, capped by fragment-backed bytes; the batch
            // barrier below is also what lets the reader be rebuilt
            // safely.
            let fs = backhand::FilesystemReader::from_reader(BufReader::with_capacity(
                1 << 20,
                view.rewound(),
            ))?;
            let files: Vec<_> = fs
                .files()
                .filter(|n| matches!(&n.inner, backhand::InnerNode::File(_)))
                .collect();
            let total = files.len();
            let mut end = done;
            let mut frag_bytes = 0u64;
            while end < total && frag_bytes < SQUASHFS_FRAG_CAP {
                if let backhand::InnerNode::File(f) = &files[end].inner {
                    if f.frag_index() != 0xffff_ffff {
                        frag_bytes += f.file_len() as u64;
                    }
                }
                end += 1;
            }
            let mut batch: Vec<Mutex<Option<Item>>> = Vec::with_capacity(end - done);
            for node in &files[done..end] {
                let backhand::InnerNode::File(f) = &node.inner else {
                    continue;
                };
                if self.capped(ctx) {
                    break;
                }
                let size = f.file_len() as u64;
                let full = node.fullpath.to_string_lossy();
                let name = full.trim_start_matches('/');
                *children += 1;
                let leaf = name.rsplit('/').next().unwrap_or(name).to_string();
                let child_path = format!("{path}!{name}");
                let (meta, feed) =
                    self.pool
                        .member(child_path.clone(), depth + 1, Some(own), Some(size), None);
                batch.push(Mutex::new(Some(Item {
                    meta,
                    feed,
                    file: f,
                    path: child_path,
                    leaf,
                    size,
                })));
            }
            let next = AtomicUsize::new(0);
            let failed: Mutex<Option<anyhow::Error>> = Mutex::new(None);
            let batch_slots: Mutex<Vec<usize>> = Mutex::new(Vec::new());
            let conservative = ctx.conservative;
            let count = &ctx.count;
            if !batch.is_empty() {
                std::thread::scope(|scope| {
                    for _ in 0..self.threads.min(batch.len()) {
                        scope.spawn(|| loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= batch.len() || failed.lock().unwrap().is_some() {
                                break;
                            }
                            let item = batch[i].lock().unwrap().take().expect("item taken once");
                            let slot = item.meta.slot();
                            let mut wctx = Ctx {
                                conservative,
                                slots: vec![slot],
                                count: count.clone(),
                            };
                            let mut reader =
                                backhand::FilesystemReaderFile::new(&fs, item.file).reader();
                            let r = self.run_member(
                                &mut reader,
                                item.meta,
                                item.feed,
                                item.path.clone(),
                                &item.leaf,
                                depth + 1,
                                &mut wctx,
                            );
                            let r = match r {
                                // A squashfs file is re-derivable on its
                                // own — a misbehaved zip inside it costs
                                // one file redone, not the whole image.
                                // The redo member inherits the ord of the
                                // one it replaces, keeping its place
                                // among siblings.
                                Err(e) if is_retry(&e) && !conservative => {
                                    eprintln!("note: {e}; re-reading {} with spooling", item.path);
                                    self.dead.lock().unwrap().append(&mut wctx.slots);
                                    wctx.conservative = true;
                                    let (meta, feed) = self.pool.member(
                                        item.path.clone(),
                                        depth + 1,
                                        Some(own),
                                        Some(item.size),
                                        Some(slot),
                                    );
                                    wctx.slots.push(meta.slot());
                                    let mut again =
                                        backhand::FilesystemReaderFile::new(&fs, item.file)
                                            .reader();
                                    self.run_member(
                                        &mut again,
                                        meta,
                                        feed,
                                        item.path,
                                        &item.leaf,
                                        depth + 1,
                                        &mut wctx,
                                    )
                                }
                                r => r,
                            };
                            batch_slots.lock().unwrap().append(&mut wctx.slots);
                            if let Err(e) = r {
                                let mut f = failed.lock().unwrap();
                                if f.is_none() {
                                    *f = Some(e);
                                }
                                break;
                            }
                        });
                    }
                });
            }
            // Slots this batch allocated belong to the enclosing
            // retry boundary's attempt like any other descendant's.
            ctx.slots.append(&mut batch_slots.into_inner().unwrap());
            // Items never taken (a worker error abandoned the batch):
            // close their handles so they seal, and drop them from
            // the member table — they were never examined.
            for cell in &batch {
                if let Some(item) = cell.lock().unwrap().take() {
                    *children -= 1;
                    self.dead.lock().unwrap().push(item.meta.slot());
                    item.feed.close(self.pool);
                    item.meta.close(self.pool, Kind::Plain.label(), 0, None);
                }
            }
            if let Some(e) = failed.into_inner().unwrap() {
                return Err(e);
            }
            done = end;
            if done >= total || self.truncated.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
    }

    // ------------------------------------------------------------ iso

    /// iso9660, hand-rolled read-only. Volume descriptors start at
    /// sector 16; the primary descriptor's root record leads to a
    /// directory tree where every file is one or more contiguous
    /// extents — which become views, not copies. Names prefer Rock
    /// Ridge NM entries; plain 9660 names get their ";1" version
    /// suffix stripped. Joliet is not read.
    #[allow(clippy::too_many_arguments)]
    fn iso_ranged(
        &self,
        view: &View,
        path: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<()> {
        const SECTOR: u64 = 2048;
        let mut root: Option<(u64, u64)> = None;
        for sector in 16..48u64 {
            let mut vd = [0u8; 2048];
            anyhow::ensure!(
                view.read_full_at(&mut vd, sector * SECTOR)? == 2048,
                "truncated volume descriptor"
            );
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
        self.iso_dir(view, lba, size, path, "", depth, own, children, ctx)
    }

    #[allow(clippy::too_many_arguments)]
    fn iso_dir(
        &self,
        view: &View,
        lba: u64,
        size: u64,
        path: &str,
        prefix: &str,
        depth: usize,
        own: usize,
        children: &mut usize,
        ctx: &mut Ctx,
    ) -> Result<()> {
        anyhow::ensure!(size < 64 << 20, "directory extent implausibly large");
        let mut dir = vec![0u8; size as usize];
        anyhow::ensure!(
            view.read_full_at(&mut dir, lba * 2048)? == dir.len(),
            "truncated directory extent"
        );

        // Parse the whole directory before descending.
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
            let sub = view.slice(&extents);
            self.process_ranged(
                sub,
                format!("{path}!{prefix}{name}"),
                &name,
                depth + 1,
                Some(own),
                ctx,
            )?;
        }
        for (name, sub_lba, sub_size) in dirs {
            self.iso_dir(
                view,
                sub_lba,
                sub_size,
                path,
                &format!("{prefix}{name}/"),
                depth,
                own,
                children,
                ctx,
            )?;
        }
        Ok(())
    }
}

// ------------------------------------------------------------ helpers

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
        let mut intro = [0u8; 16];
        r.read_exact(&mut intro)?;
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
/// and data padded to 4. Parses one header (already read into `hdr`)
/// and pulls the padded name via `read_name`. Returns None on bad
/// magic.
fn cpio_header(
    hdr: &[u8; 110],
    mut read_name: impl FnMut(&mut [u8]) -> std::io::Result<()>,
) -> Result<Option<(u64, u64, String)>> {
    fn hexfield(h: &[u8], i: usize) -> Result<u64> {
        let f = std::str::from_utf8(&h[6 + i * 8..14 + i * 8])?;
        Ok(u64::from_str_radix(f, 16)?)
    }
    if &hdr[..6] != b"070701" && &hdr[..6] != b"070702" {
        return Ok(None);
    }
    let mode = hexfield(hdr, 1)?;
    let filesize = hexfield(hdr, 6)?;
    let namesize = hexfield(hdr, 11)?;
    let name_padded = (110 + namesize).div_ceil(4) * 4 - 110;
    let mut name_raw = vec![0u8; name_padded as usize];
    read_name(&mut name_raw)?;
    let name = String::from_utf8_lossy(&name_raw[..namesize.saturating_sub(1) as usize])
        .trim_start_matches("./")
        .to_string();
    Ok(Some((mode, filesize, name)))
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

/// Parse the central directory records that follow the stream walk
/// (`read_zipfile_from_stream` has already consumed the first
/// record's 4-byte signature) and compare against what the stream
/// yielded: same entries, same names, same crc32s. Non-UTF-8 names
/// may decode differently on the two sides — that only costs a
/// spurious conservative retry, never a wrong answer.
fn reconcile_central_dir(r: &mut dyn Read, streamed: &[(String, u32)]) -> Result<bool> {
    const CENTRAL: u32 = 0x0201_4b50;
    const EOCD: u32 = 0x0605_4b50;
    const EOCD64: u32 = 0x0606_4b50;
    const EOCD64_LOCATOR: u32 = 0x0706_4b50;
    let mut cd: Vec<(String, u32)> = Vec::new();
    let mut first = true;
    loop {
        if !first {
            let mut sig = [0u8; 4];
            r.read_exact(&mut sig)?;
            match u32::from_le_bytes(sig) {
                CENTRAL => {}
                EOCD | EOCD64 | EOCD64_LOCATOR => break,
                _ => return Ok(false),
            }
        }
        first = false;
        let mut rec = [0u8; 42];
        r.read_exact(&mut rec)?;
        let crc = u32::from_le_bytes(rec[12..16].try_into().unwrap());
        let nlen = u16::from_le_bytes(rec[24..26].try_into().unwrap()) as u64;
        let elen = u16::from_le_bytes(rec[26..28].try_into().unwrap()) as u64;
        let clen = u16::from_le_bytes(rec[28..30].try_into().unwrap()) as u64;
        let mut name_raw = vec![0u8; nlen as usize];
        r.read_exact(&mut name_raw)?;
        skip_n(r, elen + clen)?;
        let name = String::from_utf8_lossy(&name_raw).into_owned();
        if !name.ends_with('/') {
            cd.push((name, crc));
        }
    }
    Ok(cd.as_slice() == streamed)
}
