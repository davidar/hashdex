use crate::coord::Scheme;
use crate::filter::NamedFilter;
use crate::local_index::{CachedEntry, LocalIndex};
use crate::peek_pool::{Digests, Member, Pool};
pub use crate::peek_walk::Descent;
use crate::peek_walk::Walk;
use crate::report::{self, Class};
use anyhow::{Context, Result};
use serde_json::json;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

pub struct ScanOptions {
    pub list: ListMode,
    pub json: bool,
    /// Skip the local hash index entirely (no reads, no writes).
    pub no_index: bool,
    /// Rehash every file even if the index has a fresh entry.
    pub rehash: bool,
    /// Resolve files through the local walk (pulled datasets +
    /// observation store) plus dataset-transport probes. Off =
    /// membership-only census (--no-resolve).
    pub resolve: bool,
    /// Full citation blocks (URLs, several claims) instead of one
    /// compact attribution line per file.
    pub verbose: bool,
    /// Probe every filter even when a smaller one already matched
    /// (full attribution at the cost of big-filter page faults).
    pub probe_all: bool,
    /// How far the walk follows containers it discovers under
    /// directory roots. Descent is demand-driven: a container a
    /// filter already recognizes is not entered — its identity is
    /// settled. Explicitly named container files always descend in
    /// Full, whatever this says.
    pub descent: Descent,
    /// Consent to tell third-party APIs about matched digests.
    /// Dataset-transport backends (range reads over our own published
    /// parquet — nobody is told anything) are probed whenever
    /// resolving; this opt-in covers the rest. Empty list = all;
    /// non-empty restricts (accepts filter or backend names).
    pub online: Option<Vec<String>>,
}

/// Per-backend probe ceiling per scan run: a batch resolve must not
/// turn into a hammering of somebody's public API. Narrow the scan
/// path or the --online backend list instead of raising this.
const PROBE_CAP: usize = 1000;
/// SWH's anonymous quota (120/h) gets a stricter ceiling.
const SWH_ANON_CAP: usize = 100;

/// Filters at least this big are probed only for files no smaller filter
/// recognized: each probe of a bigger-than-RAM mmap is a random page
/// fault, and known-file corroboration isn't worth disk seeks.
pub(crate) const EXPENSIVE_FILTER_BYTES: u64 = 2 << 30;

/// A file smaller than the digest that names it cannot be identified
/// BY that digest: the name carries more information than the content,
/// so "identity" degenerates into transcription — you'd quote such a
/// file, not cite it. (The single newline is in every corpus and also
/// registered to a real 1993 paper by a botched fatcat deposit.)
/// Sub-digest files keep their true membership tags but are never
/// attributed or probed; explicit `hdx <hash>` lookups still render
/// every witness.
pub(crate) const IDENTITY_MIN_BYTES: u64 = 32; // = the sha256 digest's length

#[derive(Clone, Copy, PartialEq)]
pub enum ListMode {
    None,
    Unknown,
    Known,
    All,
    /// Files with at least one actual claim — the default when
    /// resolving: a whole-disk scan stays a summary plus the files hdx
    /// can genuinely name, not millions of membership lines.
    Attributed,
}

/// Single-line in-place progress on a tty (throttled), occasional
/// plain lines otherwise. Results appearing all at once after minutes
/// of silence is the failure mode this exists for.
pub struct Ticker {
    tty: bool,
    start: std::time::Instant,
    last_ms: std::sync::atomic::AtomicU64,
}

impl Default for Ticker {
    fn default() -> Ticker {
        Ticker::new()
    }
}

impl Ticker {
    pub fn new() -> Ticker {
        use std::io::IsTerminal;
        Ticker {
            tty: std::io::stderr().is_terminal(),
            start: std::time::Instant::now(),
            last_ms: 0.into(),
        }
    }

    /// `every` paces the non-tty fallback lines; the tty path paces
    /// itself by wall clock.
    pub fn update(&self, every: usize, n: usize, msg: impl Fn() -> String) {
        use std::sync::atomic::Ordering::Relaxed;
        if self.tty {
            let now = self.start.elapsed().as_millis() as u64;
            let last = self.last_ms.load(Relaxed);
            if now.saturating_sub(last) >= 100
                && self
                    .last_ms
                    .compare_exchange(last, now, Relaxed, Relaxed)
                    .is_ok()
            {
                eprint!("\r\x1b[2K  {}", msg());
            }
        } else if n > 0 && n.is_multiple_of(every) {
            eprintln!("  … {}", msg());
        }
    }

    /// Clear the in-place line before real output takes the terminal.
    pub fn clear(&self) {
        if self.tty {
            eprint!("\r\x1b[2K");
        }
    }
}

pub(crate) struct FileResult {
    pub(crate) path: PathBuf,
    pub(crate) size: u64,
    pub(crate) mtime_ns: i64,
    pub(crate) sha1: [u8; 20],
    pub(crate) sha256: [u8; 32],
    pub(crate) from_index: bool,
    pub(crate) matched: Vec<String>, // filter names
}

fn to_fresh(r: &FileResult) -> crate::local_index::FreshEntry {
    (
        r.path.to_string_lossy().into_owned(),
        r.size,
        r.mtime_ns,
        r.sha1,
        r.sha256,
    )
}

/// Storage key for the member cache: descents under different
/// policies produce different trees, so they cache separately.
fn descent_key(d: Descent) -> i64 {
    match d {
        Descent::None => -1,
        Descent::Cheap => 0,
        Descent::Full => 1,
    }
}

/// Rebuild a cached descent as members under `container_slot`. The
/// structure and digests replay verbatim; bloom matches are probed
/// fresh (filters change — knowledge is query-time policy). Probing
/// is the expensive half (big-filter page faults), and a fresh
/// descent spreads it over every pool worker — the replay must not
/// pay it serially, so it probes on a worker team first and fills
/// slots (order-sensitive: parents before children) afterwards.
#[allow(clippy::too_many_arguments)]
fn materialize_cached(
    pool: &Pool,
    container_slot: usize,
    base_path: &str,
    base_depth: usize,
    rows: &[crate::local_index::CachedMember],
    probe_all: bool,
    threads: usize,
    ticker: &Ticker,
) {
    let matched: Vec<Vec<String>> = {
        let out: Mutex<Vec<Option<Vec<String>>>> = Mutex::new(vec![None; rows.len()]);
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..threads.min(rows.len()).max(1) {
                scope.spawn(|| loop {
                    // Chunked so the big-filter mmap faults batch per
                    // thread instead of ping-ponging the cursor.
                    let start = next.fetch_add(256, Ordering::Relaxed);
                    if start >= rows.len() {
                        break;
                    }
                    let end = (start + 256).min(rows.len());
                    let mut chunk: Vec<Option<Vec<String>>> = Vec::with_capacity(end - start);
                    for m in &rows[start..end] {
                        chunk.push(Some(if m.size >= IDENTITY_MIN_BYTES {
                            pool.probe(&m.sha1, &m.sha256, probe_all).0
                        } else {
                            Vec::new()
                        }));
                    }
                    out.lock().unwrap()[start..end].swap_with_slice(&mut chunk);
                    let d = done.fetch_add(end - start, Ordering::Relaxed) + (end - start);
                    ticker.update(100_000, d, || {
                        format!("replaying cached descent… {d}/{} members", rows.len())
                    });
                });
            }
        });
        out.into_inner()
            .unwrap()
            .into_iter()
            .map(|v| v.expect("every row probed"))
            .collect()
    };
    let mut slot_of: Vec<usize> = Vec::with_capacity(rows.len());
    for (m, matched) in rows.iter().zip(matched) {
        let mslot = pool.reserve();
        let parent = Some(match m.parent {
            Some(p) => slot_of[p],
            None => container_slot,
        });
        slot_of.push(mslot.idx());
        pool.fill_slot(
            mslot,
            Member {
                path: format!("{base_path}!{}", m.rel),
                depth: base_depth + m.depth,
                parent,
                ord: m.ord,
                kind: crate::peek_walk::Kind::intern_label(&m.kind),
                size: m.size,
                fs: false,
                digests: Some(Digests {
                    md5: m.md5,
                    sha1: m.sha1,
                    sha256: m.sha256,
                    sha512: m.sha512,
                    blake2s: m.blake2s,
                    sha1_git: m.sha1_git,
                }),
                extents: None,
                space: None,
                matched,
                children: m.children,
                note: m.note.clone(),
            },
        );
    }
}

/// Walk paths, hash every regular file (sha1 + sha256 in one pass), check
/// membership filters locally, and — for explicitly named container
/// files — descend recursively, minting all six coordinates per nested
/// member (the hashoscope). Everything lands in ONE member tree:
/// directories are digestless container nodes, disk files are members,
/// nested members hang under the file that holds them. Zero network
/// unless resolving.
///
/// Hashes persist in the local index (updatedb-style): unchanged files
/// (same size + mtime) are not re-read on later scans, and `hdx locate`
/// can find files by digest.
pub async fn scan(
    paths: &[PathBuf],
    filters: &[NamedFilter],
    opts: &ScanOptions,
    client: &reqwest::Client,
    ropts: &crate::resolve::Options,
) -> Result<()> {
    // Canonical roots first: the local index keys on the literal path
    // string, so `scan .` and `scan /same/dir` must agree on spelling
    // or every rescan re-hashes and local.db accretes parallel trees.
    // A root that doesn't resolve is an error, not an empty scan: a
    // typo'd path must not report "0 files, 0 unknown" and exit 0.
    let paths: Vec<PathBuf> = paths
        .iter()
        .map(|p| {
            p.canonicalize()
                .with_context(|| format!("cannot scan {}", p.display()))
        })
        .collect::<Result<_>>()?;
    let paths = &paths;

    let own_cache = crate::cache::cache_dir();
    let ticker = &Ticker::new();

    let index = if opts.no_index {
        None
    } else {
        match LocalIndex::open() {
            Ok(ix) => Some(ix),
            Err(e) => {
                eprintln!("warning: local index unavailable ({e}); hashing everything");
                None
            }
        }
    };
    let mut cached: HashMap<String, CachedEntry> = HashMap::new();
    if let Some(ix) = &index {
        for root in paths {
            match ix.load_under(root) {
                Ok(map) => cached.extend(map),
                Err(e) => eprintln!("warning: index read failed for {}: {e}", root.display()),
            }
        }
    }
    eprintln!("scanning… ({} entries in index)", cached.len());

    // Probe cheapest-first so membership is usually settled before any
    // bigger-than-RAM filter would need a disk seek.
    let mut probe_order: Vec<&NamedFilter> = filters.iter().collect();
    probe_order.sort_by_key(|f| f.bytes);

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(2);
    let pool = Pool::new(probe_order, ticker, threads, opts.probe_all);

    let done = AtomicUsize::new(0);
    let found = AtomicUsize::new(0);
    let walk_done = AtomicBool::new(false);
    let hashed_fresh = AtomicUsize::new(0);
    let reused = AtomicUsize::new(0);
    let big_skipped_files = AtomicUsize::new(0);
    // Freshly hashed disk files bound for the incremental index flush.
    let fresh: Mutex<Vec<crate::local_index::FreshEntry>> = Mutex::new(Vec::new());
    // Disk-file paths actually walked over (index hits included) — the
    // complement drives stale-entry deletion.
    let seen: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let skipped: Mutex<Vec<String>> = Mutex::new(Vec::new());
    // Unreadable paths (permission denied, vanished mid-scan, …) are
    // routine on real machines; collect them and report once at the end
    // instead of spamming the terminal as they're hit.
    let unreadable: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// A unit of worker work: a file found under a directory root, or
    /// an explicitly named root file (which gets the full recursive
    /// descent — pointing hdx at a container IS the demand).
    enum Job {
        File {
            path: PathBuf,
            parent: Option<usize>,
            ord: usize,
            depth: usize,
        },
        Root(PathBuf),
    }
    // Bounded: backpressure keeps the walker a few thousand entries
    // ahead of the workers instead of materializing the whole tree.
    let (walk_tx, walk_rx) = std::sync::mpsc::sync_channel::<Job>(8192);
    let walk_rx = Mutex::new(walk_rx);
    let cached_ref = &cached;
    let index_cell = Mutex::new(index);

    let walk = Walk {
        pool: &pool,
        truncated: AtomicBool::new(false),
        dead: Mutex::new(Vec::new()),
        threads,
        spool_wrappers: false,
    };
    std::thread::scope(|scope| {
        // The hash/read pool: container descent (root files) feeds
        // per-member hash jobs here; plain disk files are hashed
        // inline by the scan workers below and never touch it.
        for _ in 0..threads {
            scope.spawn(|| pool.worker());
        }
        let walk = &walk;
        // The walker only enumerates: directory nodes are allocated
        // (and closed with their child counts) as it goes, files
        // stream to the workers (hdx's own cache pruned — it would
        // pollute the known/unknown metrics with our own artifacts —
        // unless a scan root points inside it explicitly). Workers
        // stat, index-check, filter, and hash in parallel from the
        // first entry on. Recognized files cost one stat; only
        // unrecognized content is read at all.
        let (found_ref, walk_done_ref) = (&found, &walk_done);
        let unreadable_ref = &unreadable;
        let pool_ref = &pool;
        let walker = scope.spawn(move || {
            for root in paths {
                if root.is_file() {
                    found_ref.fetch_add(1, Ordering::Relaxed);
                    if walk_tx.send(Job::Root(root.clone())).is_err() {
                        return; // workers are gone
                    }
                    continue;
                }
                let prune_cache = !root.starts_with(&own_cache);
                let mut excluded = false;
                // Open directory nodes, deepest last; a node closes
                // (child count final) when the walk moves past its
                // subtree.
                struct OpenDir {
                    slot: crate::peek_pool::Slot,
                    path: String,
                    depth: usize,
                    parent: Option<usize>,
                    ord: usize,
                    children: usize,
                }
                let close = |d: OpenDir| {
                    pool_ref.fill_slot(
                        d.slot,
                        Member {
                            path: d.path,
                            depth: d.depth,
                            parent: d.parent,
                            ord: d.ord,
                            kind: "dir",
                            size: 0,
                            fs: true,
                            digests: None,
                            extents: None,
                            space: None,
                            matched: Vec::new(),
                            children: d.children,
                            note: None,
                        },
                    );
                };
                let mut stack: Vec<OpenDir> = Vec::new();
                let walker = walkdir::WalkDir::new(root)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|e| {
                        if prune_cache && e.path() == own_cache {
                            excluded = true;
                            return false;
                        }
                        true
                    });
                for entry in walker {
                    match entry {
                        Ok(e) => {
                            let ft = e.file_type();
                            let depth = e.depth();
                            while stack.len() > depth {
                                close(stack.pop().unwrap());
                            }
                            if !ft.is_dir() && !ft.is_file() {
                                continue; // symlinks, sockets, …
                            }
                            let (parent, ord) = match stack.last_mut() {
                                Some(p) => {
                                    let ord = p.children;
                                    p.children += 1;
                                    (Some(p.slot.idx()), ord)
                                }
                                None => (None, 0),
                            };
                            if ft.is_dir() {
                                stack.push(OpenDir {
                                    slot: pool_ref.reserve(),
                                    path: e.path().display().to_string(),
                                    depth,
                                    parent,
                                    ord,
                                    children: 0,
                                });
                            } else {
                                found_ref.fetch_add(1, Ordering::Relaxed);
                                if walk_tx
                                    .send(Job::File {
                                        path: e.into_path(),
                                        parent,
                                        ord,
                                        depth,
                                    })
                                    .is_err()
                                {
                                    // Workers are gone; close what's
                                    // open so every slot still fills.
                                    while let Some(d) = stack.pop() {
                                        close(d);
                                    }
                                    return;
                                }
                            }
                        }
                        Err(e) => unreadable_ref.lock().unwrap().push(e.to_string()),
                    }
                }
                while let Some(d) = stack.pop() {
                    close(d);
                }
                if excluded {
                    eprintln!(
                        "excluding hashdex's own cache ({}); scan it explicitly to include it",
                        own_cache.display()
                    );
                }
            }
            drop(walk_tx);
            walk_done_ref.store(true, Ordering::Release);
        });
        // Incremental persistence: a killed scan keeps the hashing it
        // already paid for. Fresh hashes flush in batches as workers
        // produce them; stale-path deletion stays at the very end —
        // only a COMPLETE walk is allowed to delete.
        let flusher = scope.spawn(|| {
            let mut last_flush = std::time::Instant::now();
            loop {
                std::thread::park_timeout(std::time::Duration::from_millis(500));
                let finished = walk_done.load(Ordering::Acquire)
                    && done.load(Ordering::Relaxed) >= found.load(Ordering::Relaxed);
                let pending = fresh.lock().unwrap().len();
                if pending > 0
                    && (finished || pending >= 2000 || last_flush.elapsed().as_secs() >= 5)
                {
                    let batch: Vec<crate::local_index::FreshEntry> =
                        fresh.lock().unwrap().drain(..).collect();
                    last_flush = std::time::Instant::now();
                    if let Some(ix) = index_cell.lock().unwrap().as_mut() {
                        if let Err(e) = ix.commit_scan(&batch, &[]) {
                            eprintln!("warning: incremental index flush failed: {e}");
                        }
                    }
                }
                if finished {
                    break;
                }
            }
        });
        let mut workers = Vec::new();
        for _ in 0..threads {
            workers.push(scope.spawn(|| {
                let mut buf = vec![0u8; 1 << 20];
                // Read-only handle to the member cache (replay);
                // absent index or --no-cache = no replay.
                let rix = if opts.no_index {
                    None
                } else {
                    LocalIndex::open_read().ok()
                };
                loop {
                    // Bind before matching: a `match recv()` scrutinee
                    // would hold the receiver lock through the whole
                    // file examination, serializing every worker.
                    let job = walk_rx.lock().unwrap().recv();
                    let Ok(job) = job else { break };
                    match job {
                        Job::Root(path) => {
                            // The hashoscope path: full recursive
                            // descent, all six schemes per member —
                            // unless an unchanged copy (index hit by
                            // size+mtime) has a complete cached
                            // descent to replay.
                            let pstr = path.to_string_lossy().into_owned();
                            let replay = (!opts.rehash)
                                .then(|| cached_ref.get(pstr.as_str()))
                                .flatten()
                                .filter(|e| {
                                    std::fs::metadata(&path).is_ok_and(|md| {
                                        let mtime = md
                                            .modified()
                                            .ok()
                                            .and_then(|t| {
                                                t.duration_since(std::time::UNIX_EPOCH).ok()
                                            })
                                            .map(|d| d.as_nanos() as i64)
                                            .unwrap_or(0);
                                        md.len() == e.size && mtime == e.mtime_ns
                                    })
                                })
                                .and_then(|e| {
                                    let cd = rix
                                        .as_ref()?
                                        .load_container(&e.sha256, descent_key(Descent::Full))
                                        .ok()
                                        .flatten()?;
                                    Some((e, cd))
                                });
                            match replay {
                                Some((e, (c, rows))) => {
                                    let slot = pool.reserve();
                                    materialize_cached(
                                        &pool,
                                        slot.idx(),
                                        &pstr,
                                        0,
                                        &rows,
                                        opts.probe_all,
                                        threads,
                                        ticker,
                                    );
                                    let matched = if e.size >= IDENTITY_MIN_BYTES {
                                        pool.probe(&e.sha1, &e.sha256, opts.probe_all).0
                                    } else {
                                        Vec::new()
                                    };
                                    reused.fetch_add(1, Ordering::Relaxed);
                                    pool.fill_slot(
                                        slot,
                                        Member {
                                            path: pstr.clone(),
                                            depth: 0,
                                            parent: None,
                                            ord: 0,
                                            kind: crate::peek_walk::Kind::intern_label(&c.kind),
                                            size: e.size,
                                            fs: true,
                                            digests: Some(Digests {
                                                md5: None,
                                                sha1: e.sha1,
                                                sha256: e.sha256,
                                                sha512: None,
                                                blake2s: None,
                                                sha1_git: None,
                                            }),
                                            extents: None,
                                            space: None,
                                            matched,
                                            children: c.children,
                                            note: c.note.clone(),
                                        },
                                    );
                                    seen.lock().unwrap().push(pstr);
                                }
                                None => match walk.walk_root(&path) {
                                    Ok(()) => seen.lock().unwrap().push(pstr),
                                    Err(e) => unreadable
                                        .lock()
                                        .unwrap()
                                        .push(format!("{}: {e}", path.display())),
                                },
                            }
                        }
                        Job::File {
                            path,
                            parent,
                            ord,
                            depth,
                        } => match examine(&path, cached_ref, opts.rehash, &mut buf) {
                            Ok(Some(r)) => {
                                if r.from_index {
                                    reused.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    hashed_fresh.fetch_add(1, Ordering::Relaxed);
                                    fresh.lock().unwrap().push(to_fresh(&r));
                                }
                                let (matched, skipped_big) =
                                    pool.probe(&r.sha1, &r.sha256, opts.probe_all);
                                if skipped_big {
                                    big_skipped_files.fetch_add(1, Ordering::Relaxed);
                                }
                                seen.lock()
                                    .unwrap()
                                    .push(r.path.to_string_lossy().into_owned());
                                let slot = pool.reserve();
                                let display = path.display().to_string();
                                // Demand-driven descent: only containers
                                // no filter recognized are worth opening —
                                // a bloom hit settles the file's identity
                                // at the container level. A complete
                                // cached descent (content-addressed by
                                // this exact sha256) replays instead of
                                // re-reading the container.
                                let descend = opts.descent != Descent::None
                                    && matched.is_empty()
                                    && r.size >= IDENTITY_MIN_BYTES;
                                let replay = if descend && !opts.rehash {
                                    rix.as_ref().and_then(|ix| {
                                        ix.load_container(&r.sha256, descent_key(opts.descent))
                                            .ok()
                                            .flatten()
                                    })
                                } else {
                                    None
                                };
                                let (children, note, kind) = if let Some((c, rows)) = replay {
                                    materialize_cached(
                                        &pool,
                                        slot.idx(),
                                        &display,
                                        depth,
                                        &rows,
                                        opts.probe_all,
                                        threads,
                                        ticker,
                                    );
                                    (
                                        c.children,
                                        c.note.clone(),
                                        crate::peek_walk::Kind::intern_label(&c.kind),
                                    )
                                } else if descend {
                                    let name = path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().into_owned())
                                        .unwrap_or_default();
                                    walk.descend_within(
                                        &path,
                                        &display,
                                        &name,
                                        slot.idx(),
                                        depth,
                                        opts.descent,
                                    )
                                } else {
                                    (0, None, "file")
                                };
                                pool.fill_slot(
                                    slot,
                                    Member {
                                        path: display,
                                        depth,
                                        parent,
                                        ord,
                                        kind,
                                        size: r.size,
                                        fs: true,
                                        digests: Some(Digests {
                                            md5: None,
                                            sha1: r.sha1,
                                            sha256: r.sha256,
                                            sha512: None,
                                            blake2s: None,
                                            sha1_git: None,
                                        }),
                                        extents: None,
                                        space: None,
                                        matched,
                                        children,
                                        note,
                                    },
                                );
                            }
                            Ok(None) => {
                                skipped
                                    .lock()
                                    .unwrap()
                                    .push(path.to_string_lossy().into_owned());
                            }
                            Err(e) => unreadable
                                .lock()
                                .unwrap()
                                .push(format!("{}: {e}", path.display())),
                        },
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    // Most files are index hits (stat + compare), not
                    // hashing — the label must not claim otherwise.
                    ticker.update(100_000, d, || {
                        let f = found.load(Ordering::Relaxed);
                        let fresh = hashed_fresh.load(Ordering::Relaxed);
                        if walk_done.load(Ordering::Acquire) {
                            format!("checking… {d}/{f} files ({fresh} hashed fresh)")
                        } else {
                            format!("checking… {d} of {f}+ found ({fresh} hashed fresh)")
                        }
                    });
                }
            }));
        }
        walker.join().unwrap();
        for w in workers {
            w.join().unwrap();
        }
        flusher.join().unwrap();
        // Container descents may still be hashing on the pool.
        pool.wait_idle();
        pool.close();
    });
    // Partial-moving Walk's state ends its borrow of the pool, so the
    // member table can be consumed below.
    let truncated = walk.truncated.into_inner();
    let dead = walk.dead.into_inner().unwrap();
    ticker.clear();

    let members = report::compact_members(pool.members.into_inner().unwrap(), &dead);

    let seen = seen.into_inner().unwrap();
    let skipped = skipped.into_inner().unwrap();
    let unreadable = unreadable.into_inner().unwrap();

    // Persist: root files in (they were descended, so always freshly
    // hashed — the incremental flusher covered everything else),
    // vanished paths out.
    let mut index = index_cell.into_inner().unwrap();
    if let Some(ix) = &mut index {
        let mut fresh_roots: Vec<crate::local_index::FreshEntry> = Vec::new();
        for m in &members {
            if m.parent.is_none() && m.kind != "dir" {
                if let Some(d) = &m.digests {
                    let mtime_ns = std::fs::metadata(Path::new(&m.path))
                        .ok()
                        .and_then(|meta| meta.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|dur| dur.as_nanos() as i64)
                        .unwrap_or(0);
                    fresh_roots.push((m.path.clone(), m.size, mtime_ns, d.sha1, d.sha256));
                }
            }
        }
        let seen_set: HashSet<&str> = seen.iter().map(String::as_str).collect();
        let mut stale: Vec<String> = cached
            .keys()
            .filter(|p| !seen_set.contains(p.as_str()))
            .cloned()
            .collect();
        stale.extend(skipped);
        if let Err(e) = ix.commit_scan(&fresh_roots, &stale) {
            eprintln!("warning: index update failed: {e}");
        }
    }

    // Demand-driven network probes for matched digests, each visiting
    // only the backends whose filter fired: dataset-transport backends
    // by default, third-party APIs with --online consent. Runs before
    // the local walk so fresh findings are in the observation store
    // when the per-member resolution below sweeps it. Nested members
    // probe exactly like disk files — a bloom hit is the demand.
    let results: Vec<FileResult> = members
        .iter()
        .filter(|m| !m.matched.is_empty())
        .filter_map(|m| {
            m.digests.as_ref().map(|d| FileResult {
                path: PathBuf::from(&m.path),
                size: m.size,
                mtime_ns: 0,
                sha1: d.sha1,
                sha256: d.sha256,
                from_index: false,
                matched: m.matched.clone(),
            })
        })
        .collect();
    if opts.resolve && !ropts.offline {
        online_probe(
            &results,
            filters,
            opts.online.as_deref(),
            client,
            ropts,
            ticker,
        )
        .await;
    }

    // Local resolution for --resolve: every member walks from its
    // sha256 AND sha1 seeds through the pulled datasets and the
    // observation store (which --online may have just enriched).
    // Verdicts per witness row (the approved weak-digest policy):
    //   identified — the row's cluster contains the member's sha256;
    //   consistent — the row matches only on weak digests, and NO
    //     scheme it co-states contradicts a locally-minted digest
    //     (a contradicted row describes other bytes → related,
    //     silently);
    // both tiers count as known, reported separately.
    let evidence: Vec<report::Evidence> = if opts.resolve {
        let datasets = crate::datasets::open_all();
        report::resolve_members(&members, datasets, threads, !opts.no_index, ticker)
    } else {
        members.iter().map(|_| Default::default()).collect()
    };
    ticker.clear();

    let classes: Vec<Class> = members
        .iter()
        .zip(&evidence)
        .map(|(m, ev)| report::classify(m, ev))
        .collect();

    // Which members live inside an explicitly named container root
    // (rendered as a tree) as opposed to the flat filesystem listing.
    // Parents always precede children in the member table, so one
    // forward pass settles it.
    let mut in_tree: Vec<bool> = vec![false; members.len()];
    for i in 0..members.len() {
        in_tree[i] = match members[i].parent {
            Some(p) => in_tree[p],
            None => members[i].kind != "dir",
        };
    }

    // Summary counters. Disk files (scan's headline) and nested
    // members (the hashoscope's) are counted separately — "12 known
    // files" must keep meaning files on disk even when one of them
    // held half a million members.
    let mut scanned = 0usize;
    let mut known = 0usize;
    let mut attributed = 0usize;
    let mut consistent_files = 0usize;
    let mut membership_only = 0usize;
    let mut known_bytes = 0u64;
    let mut total_bytes = 0u64;
    let mut nested = 0usize;
    let (mut n_identified, mut n_consistent, mut n_membership, mut n_unknown) = (0, 0, 0, 0usize);
    let mut per_filter: std::collections::BTreeMap<&str, usize> = Default::default();
    for ((m, ev), class) in members.iter().zip(&evidence).zip(&classes) {
        for name in &m.matched {
            *per_filter.entry(name.as_str()).or_default() += 1;
        }
        let (identified, consistent) = ev;
        let has_claims = identified.iter().any(|f| !f.claims.is_empty());
        let has_consistent = consistent.iter().any(|f| !f.claims.is_empty());
        if m.fs && m.digests.is_some() {
            scanned += 1;
            total_bytes += m.size;
            if has_claims {
                attributed += 1;
            } else if has_consistent {
                consistent_files += 1;
            }
            // Known = a filter matched OR the walk produced a claim:
            // index rows (tarballs, cached observations) are
            // witness-grade evidence, stronger than a probabilistic
            // bloom hit — a file can't be both attributed and
            // "unknown".
            if !m.matched.is_empty() || has_claims || has_consistent {
                known += 1;
                known_bytes += m.size;
            }
            if opts.resolve && !m.matched.is_empty() && !has_claims && !has_consistent {
                membership_only += 1;
            }
        } else if !m.fs {
            nested += 1;
            match class {
                Class::Identified => n_identified += 1,
                Class::Consistent => n_consistent += 1,
                Class::Membership => n_membership += 1,
                Class::Unknown => n_unknown += 1,
                Class::Floor | Class::Node => {}
            }
        }
    }

    // Tree machinery, shared by both render sections: DFS order (a
    // node's subtree is the contiguous run after it), position index,
    // recursive rollups.
    let rollups = report::rollups(&members, &classes);
    let order = report::tree_order(&members);
    let mut pos: Vec<usize> = vec![0; members.len()];
    for (p, &i) in order.iter().enumerate() {
        pos[i] = p;
    }
    let render_subtree = |i: usize| {
        let base = members[i].depth;
        let mut j = pos[i];
        loop {
            let k = order[j];
            if opts.json {
                println!(
                    "{}",
                    report::member_json(&members[k], &evidence[k], &rollups[k])
                );
            } else {
                report::render_tree_line(
                    &members[k],
                    &evidence[k],
                    &rollups[k],
                    opts.verbose,
                    base,
                );
            }
            j += 1;
            if j >= order.len() || members[order[j]].depth <= base {
                break;
            }
        }
    };

    // Tree sections first: every explicitly named container file
    // renders its full descent, hashoscope style.
    for &i in order
        .iter()
        .filter(|&&i| in_tree[i] && members[i].parent.is_none())
    {
        ticker.clear();
        render_subtree(i);
    }

    // Flat listing over the filesystem files, sorted by path. A
    // container the walk descended renders as a tree block in its
    // sorted position — its rollup line plus its members.
    let mut flat: Vec<usize> = (0..members.len())
        .filter(|&i| members[i].fs && members[i].digests.is_some() && !in_tree[i])
        .collect();
    flat.sort_by(|&a, &b| members[a].path.cmp(&members[b].path));
    for &i in &flat {
        let m = &members[i];
        let (identified, consistent) = &evidence[i];
        let has_claims = identified.iter().any(|f| !f.claims.is_empty());
        let has_consistent = consistent.iter().any(|f| !f.claims.is_empty());
        let show = match opts.list {
            ListMode::None => false,
            ListMode::All => true,
            ListMode::Known => !m.matched.is_empty(),
            ListMode::Unknown => m.matched.is_empty(),
            // Descended containers (children > 0) were unknown at the
            // container level — their rollup is the payload.
            ListMode::Attributed => has_claims || has_consistent || m.children > 0,
        };
        if !show {
            continue;
        }
        ticker.clear();
        if m.children > 0 {
            render_subtree(i);
            continue;
        }
        // Every consistent match is via sha1 — the only weak digest
        // scan mints (md5 joins when an md5-only source needs it).
        const WEAK_VIA: &str = "sha1";
        let d = m.digests.as_ref().expect("flat members carry digests");
        if opts.json {
            let mut obj = json!({
                "path": m.path,
                "size": m.size,
                "sha1": hex_lower(&d.sha1),
                "sha256": hex_lower(&d.sha256),
                "known": !m.matched.is_empty(),
                "filters": m.matched,
            });
            if opts.resolve {
                obj["resolved"] = identified
                    .iter()
                    .map(|f| json!({"backend": f.backend, "claims": f.claims}))
                    .collect();
                obj["consistent"] = consistent
                    .iter()
                    .map(|f| json!({"backend": f.backend, "claims": f.claims, "via": [WEAK_VIA]}))
                    .collect();
            }
            println!("{obj}");
        } else {
            let backends_of = |fs: &[crate::finding::Finding]| {
                let mut backends: Vec<&str> = fs
                    .iter()
                    .filter(|f| !f.claims.is_empty())
                    .map(|f| f.backend.as_str())
                    .collect();
                backends.sort_unstable();
                backends.dedup();
                backends.join(",")
            };
            let tag = if !m.matched.is_empty() {
                m.matched.join(",")
            } else if has_claims {
                // No filter fired but the local walk attributed it
                // (index-only sources like tarballs have no bloom):
                // name the attestors, don't call it unknown.
                backends_of(identified)
            } else if has_consistent {
                backends_of(consistent)
            } else {
                "unknown".to_string()
            };
            println!("{:<12} {}", tag, m.path);
            if opts.resolve {
                // Weak-only matches never present as identity: their
                // lines carry the tier and the scheme that matched.
                let prefix = format!("consistent ({WEAK_VIA}): ");
                // (identity-tier?, backend, statement, url) —
                // identified claims always outrank consistent ones.
                let lines: Vec<(bool, &str, String, &Option<String>)> = identified
                    .iter()
                    .flat_map(|f| {
                        f.claims
                            .iter()
                            .map(move |c| (true, f.backend.as_str(), c.statement.clone(), &c.url))
                    })
                    .chain(consistent.iter().flat_map(|f| {
                        f.claims.iter().map(|c| {
                            (
                                false,
                                f.backend.as_str(),
                                format!("{prefix}{}", c.statement),
                                &c.url,
                            )
                        })
                    }))
                    .collect();
                if opts.verbose {
                    const SHOWN: usize = 3;
                    for (_, backend, statement, url) in lines.iter().take(SHOWN) {
                        println!("             {backend:<12} {statement}");
                        if let Some(url) = url {
                            println!("             {:<12} → {url}", "");
                        }
                    }
                    if lines.len() > SHOWN {
                        println!("             … and {} more claims", lines.len() - SHOWN);
                    }
                } else if let Some((_, backend, statement, url)) = lines
                    .iter()
                    .max_by_key(|(id, _, s, url)| (*id, url.is_some(), s.len()))
                {
                    // Compact default: the most informative single
                    // claim (URL-bearing beats bare join keys) WITH
                    // its URL — the URL is usually the payload the
                    // user is after (wayback copy, SWH archive).
                    // -v for the full multi-claim blocks.
                    println!("             {backend:<12} {statement}");
                    if let Some(url) = url {
                        println!("             {:<12} → {url}", "");
                    }
                }
            }
        }
    }

    // Persist fresh descents into the content-addressed member cache:
    // the next scan that meets these exact bytes replays them without
    // reading the container. Truncated walks never cache (an
    // incomplete tree must not masquerade as the whole).
    if !truncated {
        if let Some(ix) = &mut index {
            for i in 0..members.len() {
                let m = &members[i];
                if !m.fs || m.children == 0 {
                    continue;
                }
                let Some(dg) = m.digests.as_ref() else {
                    continue;
                };
                let key = if in_tree[i] {
                    descent_key(Descent::Full)
                } else {
                    descent_key(opts.descent)
                };
                if ix.has_container(&dg.sha256, key) {
                    continue; // replayed or identical content: rows exist
                }
                let base_depth = m.depth;
                let prefix = m.path.len() + 1; // past the '!' separator
                let mut local_of: HashMap<usize, usize> = HashMap::new();
                let mut rows: Vec<crate::local_index::CachedMember> = Vec::new();
                let mut j = pos[i] + 1;
                while j < order.len() && members[order[j]].depth > base_depth {
                    let k = order[j];
                    let n = &members[k];
                    let nd = n.digests.as_ref().expect("nested members carry digests");
                    local_of.insert(k, rows.len());
                    rows.push(crate::local_index::CachedMember {
                        rel: n.path.get(prefix..).unwrap_or("").to_string(),
                        parent: match n.parent {
                            Some(p) if p == i => None,
                            Some(p) => Some(local_of[&p]),
                            None => None,
                        },
                        ord: n.ord,
                        depth: n.depth - base_depth,
                        kind: n.kind.to_string(),
                        size: n.size,
                        children: n.children,
                        note: n.note.clone(),
                        md5: nd.md5,
                        sha1: nd.sha1,
                        sha256: nd.sha256,
                        sha512: nd.sha512,
                        blake2s: nd.blake2s,
                        sha1_git: nd.sha1_git,
                    });
                    j += 1;
                }
                if rows.len() >= 50_000 {
                    // No silent phases: a big store is visible work.
                    eprintln!(
                        "caching {} members of {} in the local index…",
                        rows.len(),
                        m.path
                    );
                }
                let container = crate::local_index::CachedContainer {
                    kind: m.kind.to_string(),
                    children: m.children,
                    note: m.note.clone(),
                };
                if let Err(e) = ix.store_container(&dg.sha256, key, &container, &rows) {
                    eprintln!("warning: member-cache write failed for {}: {e}", m.path);
                }
            }
        }
    }

    ticker.clear();
    let reused = reused.load(Ordering::Relaxed);
    let mut summary = json!({
        "files": scanned,
        "bytes": total_bytes,
        "known": known,
        "known_bytes": known_bytes,
        "unknown": scanned - known,
        "hashed": scanned - reused,
        "from_index": reused,
        "big_filters_skipped_files": big_skipped_files.load(Ordering::Relaxed),
        "unreadable": unreadable.len(),
        "per_filter": per_filter.iter().map(|(k, v)| (k.to_string(), v)).collect::<std::collections::BTreeMap<_,_>>(),
        "filters_loaded": filters.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
    });
    if opts.resolve {
        summary["attributed"] = json!(attributed);
        summary["consistent"] = json!(consistent_files);
        summary["membership_only"] = json!(membership_only);
    }
    if nested > 0 {
        summary["members"] = json!(nested);
        summary["members_identified"] = json!(n_identified);
        summary["members_consistent"] = json!(n_consistent);
        summary["members_membership"] = json!(n_membership);
        summary["members_unknown"] = json!(n_unknown);
    }
    if truncated {
        summary["truncated"] = json!(true);
    }
    if opts.json {
        println!("{summary}");
    } else {
        eprintln!();
        let mut attribution = if opts.resolve {
            format!(", {attributed} attributed")
        } else {
            String::new()
        };
        if consistent_files > 0 {
            // Weak-digest tier: matched on sha1 only — the headline
            // "known" includes these, but never as verified identity.
            attribution.push_str(&format!(
                ", {consistent_files} consistent (weak digests only)"
            ));
        }
        println!(
            "{scanned} file{} ({}) — {known} known ({}){attribution}, {} unknown",
            s(scanned),
            human(total_bytes),
            human(known_bytes),
            scanned - known
        );
        if nested > 0 {
            println!(
                "{nested} nested member{} — {n_identified} identified, {n_consistent} consistent \
                 (weak digests only), {n_membership} known to filters, {n_unknown} unknown",
                s(nested)
            );
        }
        if truncated {
            println!(
                "  (a descent stopped at {} members — the rest were not examined)",
                crate::peek_walk::MAX_MEMBERS
            );
        }
        for (f, n) in &per_filter {
            println!("  {f}: {n} file{}", s(*n));
        }
        if membership_only > 0 {
            let consent = if opts.online.is_none() {
                "; --online asks their sources for claims"
            } else {
                ""
            };
            println!(
                "  ({membership_only} known file{} matched filters but carry no claims — membership only{consent}; --known lists them)",
                s(membership_only)
            );
        }
        let big_skipped = big_skipped_files.load(Ordering::Relaxed);
        if big_skipped > 0 {
            println!(
                "  ({big_skipped} known file{} skipped filters over {} — per-filter counts are a floor; --probe-all for full attribution)",
                s(big_skipped),
                human(EXPENSIVE_FILTER_BYTES)
            );
        }
        println!(
            "  hashed {} file{}, reused {reused} from local index",
            scanned - reused,
            s(scanned - reused)
        );
        if !unreadable.is_empty() {
            println!(
                "  {} path{} unreadable (not counted)",
                unreadable.len(),
                s(unreadable.len())
            );
        }
        if filters.is_empty() {
            println!("  (no filters installed — run `hdx filters fetch` first; every file reports unknown)");
        }
        println!("  note: filter matches are probabilistic (small false-positive rate); confirm important ones with `hdx <hash>`");
    }
    // Diagnostics for both output modes: stderr, so JSON stdout stays pure.
    if !unreadable.is_empty() {
        const SHOWN: usize = 5;
        eprintln!(
            "{} path{} unreadable:",
            unreadable.len(),
            s(unreadable.len())
        );
        for u in unreadable.iter().take(SHOWN) {
            eprintln!("  {u}");
        }
        if unreadable.len() > SHOWN {
            eprintln!("  … and {} more", unreadable.len() - SHOWN);
        }
    }
    Ok(())
}

/// Which network backend answers for a membership filter's source.
/// Filters without a backend (steam, fedora, …) resolve offline only.
/// The per-digest local resolution recipe shared by scan and peek:
/// walk from both seeds, cluster on the strong digest, and split the
/// witness rows into the two verdict tiers of the weak-digest policy —
/// identified (the row's cluster contains the file's sha256) and
/// consistent (weak match, no co-stated scheme contradicts a locally
/// minted digest; a contradicted row describes other bytes).
pub(crate) fn local_verdicts(
    sha256_digest: &[u8; 32],
    sha1_digest: &[u8; 20],
    datasets: &[crate::datasets::LocalDataset],
    cache: Option<&crate::cache::Cache>,
) -> (Vec<crate::finding::Finding>, Vec<crate::finding::Finding>) {
    let sha256 = crate::coord::Coord {
        scheme: Scheme::Sha256,
        digest: sha256_digest.to_vec(),
    };
    let sha1 = crate::coord::Coord {
        scheme: Scheme::Sha1,
        digest: sha1_digest.to_vec(),
    };
    let local = |c: &crate::coord::Coord| -> Vec<crate::finding::Finding> {
        datasets.iter().flat_map(|d| d.lookup(c)).collect()
    };
    let ev = crate::walk::walk(&[sha256.clone(), sha1], &local, cache);
    let mut identified = Vec::new();
    let mut consistent = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for cl in crate::walk::cluster(ev, &sha256).clusters {
        for f in cl.findings {
            let key = serde_json::to_string(&f).unwrap_or_default();
            if cl.primary {
                if seen.insert(key) {
                    identified.push(f);
                }
                continue;
            }
            let coords: Vec<crate::coord::Coord> = f
                .coords
                .iter()
                .filter_map(|c| crate::coord::Coord::parse(c).ok())
                .collect();
            let contradicted = coords.iter().any(|c| match c.scheme {
                Scheme::Sha256 => c.digest[..] != sha256_digest[..],
                Scheme::Sha1 => c.digest[..] != sha1_digest[..],
                _ => false,
            });
            let weak_match = coords
                .iter()
                .any(|c| c.scheme == Scheme::Sha1 && c.digest[..] == sha1_digest[..]);
            if !contradicted && weak_match && seen.insert(key) {
                consistent.push(f);
            }
        }
    }
    (identified, consistent)
}

fn backend_for_filter(name: &str) -> Option<&'static str> {
    match name {
        "fatcat" => Some("fatcat"),
        "tarballs" => Some("tarballs"),
        "ia-census" => Some("ia-census"),
        "debs" => Some("debs"),
        "install-media" => Some("install-media"),
        // The fedora bloom predates the dataset; its hits route to the
        // same rpm-files probes (a probe miss is a cheap absence proof).
        "rpm-files" | "fedora" => Some("rpm-files"),
        "circl" => Some(crate::backends::circl::NAME),
        "depsdev" => Some(crate::backends::depsdev::NAME),
        "rekor" => Some(crate::backends::rekor::NAME),
        "swh" => Some(crate::backends::swh::NAME),
        _ => None,
    }
}

/// Probe each matched digest against exactly the backends whose filter
/// fired: the bloom hit is the demand that justifies the single probe
/// (DESIGN.md admission rule). Hits land in the durable cache, so
/// reruns only pay for digests never probed before.
pub(crate) async fn online_probe(
    results: &[FileResult],
    filters: &[NamedFilter],
    selection: Option<&[String]>,
    client: &reqwest::Client,
    ropts: &crate::resolve::Options,
    ticker: &Ticker,
) {
    use futures::StreamExt;
    use std::collections::{BTreeMap, HashMap, HashSet};

    // Dataset transports need no consent; --online grants the APIs
    // (bare = all of them, a list restricts by filter or backend name).
    let selected = |filter: &str, backend: &str| {
        crate::datasets::is_dataset(backend)
            || match selection {
                None => false,
                Some([]) => true,
                Some(list) => list.iter().any(|s| s == filter || s == backend),
            }
    };
    let mut probes: HashMap<crate::coord::Coord, HashSet<&'static str>> = HashMap::new();
    for r in results {
        // Sub-digest files never earn a probe: nothing that small is
        // identifiable, however many corpora contain it.
        if r.matched.is_empty() || r.size < IDENTITY_MIN_BYTES {
            continue;
        }
        // One probe per (file, backend): when several of a backend's
        // filters matched the same file (e.g. its sha1 and sha256
        // blooms), the strongest scheme answers for all of them.
        let mut best: HashMap<&'static str, Scheme> = HashMap::new();
        for f in filters {
            if !r.matched.iter().any(|m| m == &f.name) {
                continue;
            }
            let Some(backend) = backend_for_filter(&f.name) else {
                continue;
            };
            // A pulled dataset already answered in the local walk.
            if crate::datasets::is_local(backend) {
                continue;
            }
            if !selected(&f.name, backend) || !matches!(f.scheme, Scheme::Sha1 | Scheme::Sha256) {
                continue;
            }
            let e = best.entry(backend).or_insert(f.scheme);
            if f.scheme == Scheme::Sha256 {
                *e = Scheme::Sha256;
            }
        }
        for (backend, scheme) in best {
            let digest = match scheme {
                Scheme::Sha1 => r.sha1.to_vec(),
                _ => r.sha256.to_vec(),
            };
            probes
                .entry(crate::coord::Coord { scheme, digest })
                .or_default()
                .insert(backend);
        }
    }

    // A batch scan must not hammer public APIs: any backend that would
    // exceed its ceiling is skipped whole (partial probing would read as
    // complete coverage). SWH's anonymous quota is 120 req/h.
    let swh = crate::backends::swh::NAME;
    let mut per_backend: BTreeMap<&'static str, usize> = BTreeMap::new();
    for set in probes.values() {
        for b in set {
            *per_backend.entry(b).or_default() += 1;
        }
    }
    for (backend, n) in per_backend {
        let cap = if backend == swh && std::env::var("SWH_TOKEN").is_err() {
            SWH_ANON_CAP
        } else {
            PROBE_CAP
        };
        if n > cap {
            eprintln!(
                "note: skipping {n} {backend} probes (per-scan ceiling {cap}; narrow the path or use --online with a backend list)"
            );
            for set in probes.values_mut() {
                set.remove(backend);
            }
        }
    }
    probes.retain(|_, set| !set.is_empty());
    if probes.is_empty() {
        return;
    }

    let total = probes.len();
    eprintln!("probing {total} matched digest{} online…", s(total));
    // Probe width: 6 is politeness for third-party APIs. A batch that
    // only touches our published datasets hits a CDN over one
    // multiplexed connection — far wider is fine.
    let width = if probes
        .values()
        .all(|s| s.iter().all(|b| crate::datasets::is_dataset(b)))
    {
        32
    } else {
        6
    };
    // Cold remote-file opens run before the probe stream, outside any
    // per-probe timeout: a first-contact burst must not eat probe
    // budgets on suffix fetches.
    for spec in crate::datasets::SPECS {
        let warm: Vec<crate::coord::Coord> = probes
            .iter()
            .filter(|(_, set)| set.contains(spec.name))
            .map(|(coord, _)| coord.clone())
            .collect();
        if !warm.is_empty() {
            let _ =
                tokio::task::spawn_blocking(move || crate::backends::dataset::preopen(spec, &warm))
                    .await;
        }
    }
    let done = AtomicUsize::new(0);
    let errors: Mutex<std::collections::BTreeMap<String, usize>> = Mutex::new(Default::default());
    futures::stream::iter(probes.into_iter().map(|(coord, only)| {
        let popts = crate::resolve::Options {
            refresh: ropts.refresh,
            no_cache: ropts.no_cache,
            offline: false,
            // Wide fatcat batches sit in 429-backoff and stream queues
            // that a single-lookup budget doesn't anticipate.
            timeout_secs: ropts.timeout_secs.max(if width > 6 { 120 } else { 0 }),
            only: Some(only),
            // The probe stream has its own ticker; per-digest progress
            // lines would fight over the terminal.
            progress: false,
        };
        let (done, errors) = (&done, &errors);
        async move {
            match crate::resolve::resolve(client, &coord, &popts).await {
                Ok(res) => {
                    for (backend, msg) in res.errors {
                        // One line per distinct failure mode, not per
                        // probe: keep the message, it names the cause.
                        *errors
                            .lock()
                            .unwrap()
                            .entry(format!("{backend}: {msg}"))
                            .or_default() += 1;
                    }
                }
                Err(e) => {
                    *errors.lock().unwrap().entry(e.to_string()).or_default() += 1;
                }
            }
            let d = done.fetch_add(1, Ordering::Relaxed) + 1;
            ticker.update(50, d, || format!("probing online… {d}/{total} digests"));
        }
    }))
    .buffer_unordered(width)
    .collect::<Vec<()>>()
    .await;
    ticker.clear();
    for (what, n) in errors.lock().unwrap().iter() {
        eprintln!("warning: {n} probes failed: {what} (errors are not cached; rerun retries)");
    }
}

/// Stat the file; reuse the indexed digests when size+mtime match, else
/// read and hash. Returns None for empty files (trivially "known").
fn examine(
    path: &Path,
    cached: &HashMap<String, CachedEntry>,
    rehash: bool,
    buf: &mut [u8],
) -> Result<Option<FileResult>> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    if size == 0 {
        return Ok(None);
    }
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    if !rehash {
        if let Some(entry) = cached.get(path.to_string_lossy().as_ref()) {
            if entry.size == size && entry.mtime_ns == mtime_ns {
                return Ok(Some(FileResult {
                    path: path.to_path_buf(),
                    size,
                    mtime_ns,
                    sha1: entry.sha1,
                    sha256: entry.sha256,
                    from_index: true,
                    matched: Vec::new(),
                }));
            }
        }
    }

    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();
    loop {
        let n = reader.read(buf)?;
        if n == 0 {
            break;
        }
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
    }
    Ok(Some(FileResult {
        path: path.to_path_buf(),
        size,
        mtime_ns,
        sha1: sha1.finalize().into(),
        sha256: sha256.finalize().into(),
        from_index: false,
        matched: Vec::new(),
    }))
}

/// Pluralizing suffix: `{n} file{}` with `s(n)`.
pub(crate) fn s(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub(crate) fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}
