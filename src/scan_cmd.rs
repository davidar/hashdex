use crate::coord::Scheme;
use crate::filter::NamedFilter;
use crate::local_index::{CachedEntry, LocalIndex};
use anyhow::{Context, Result};
use serde_json::json;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
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
const EXPENSIVE_FILTER_BYTES: u64 = 2 << 30;

/// A file smaller than the digest that names it cannot be identified
/// BY that digest: the name carries more information than the content,
/// so "identity" degenerates into transcription — you'd quote such a
/// file, not cite it. (The single newline is in every corpus and also
/// registered to a real 1993 paper by a botched fatcat deposit.)
/// Sub-digest files keep their true membership tags but are never
/// attributed or probed; explicit `hdx <hash>` lookups still render
/// every witness.
const IDENTITY_MIN_BYTES: u64 = 32; // = the sha256 digest's length

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

struct FileResult {
    path: PathBuf,
    size: u64,
    mtime_ns: i64,
    sha1: [u8; 20],
    sha256: [u8; 32],
    from_index: bool,
    matched: Vec<String>, // filter names
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

/// Walk paths, hash every regular file (sha1 + sha256 in one pass), check
/// membership filters locally. Zero network. This is the personal-NSRL
/// scan: "which of my files are publicly known bytes."
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

    // Roots the user named as literal files always get a per-file
    // verdict: an explicit two-file scan that prints nothing reads as
    // "scan doesn't know these" even when the summary counted them.
    let file_roots: HashSet<&Path> = paths
        .iter()
        .filter(|p| p.is_file())
        .map(|p| p.as_path())
        .collect();

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
    let probe_order = &probe_order;

    let done = AtomicUsize::new(0);
    let found = AtomicUsize::new(0);
    let walk_done = std::sync::atomic::AtomicBool::new(false);
    let hashed_fresh = AtomicUsize::new(0);
    let big_skipped_files = AtomicUsize::new(0);
    let results: Mutex<Vec<FileResult>> = Mutex::new(Vec::new());
    let skipped: Mutex<Vec<String>> = Mutex::new(Vec::new());
    // Unreadable paths (permission denied, vanished mid-scan, …) are
    // routine on real machines; collect them and report once at the end
    // instead of spamming the terminal as they're hit.
    let unreadable: Mutex<Vec<String>> = Mutex::new(Vec::new());
    // Bounded: backpressure keeps the walker a few thousand paths
    // ahead of the workers instead of materializing the whole tree.
    let (walk_tx, walk_rx) = std::sync::mpsc::sync_channel::<PathBuf>(8192);
    let walk_rx = Mutex::new(walk_rx);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let cached_ref = &cached;
    let index_cell = Mutex::new(index);

    std::thread::scope(|scope| {
        // ONE fused pass over the filesystem. The walker reads
        // directory blocks and streams paths (hdx's own cache pruned —
        // it would pollute the known/unknown metrics with our own
        // artifacts — unless a scan root points inside it explicitly);
        // workers stat, index-check, filter, and hash in parallel from
        // the first path on. Recognized files cost one stat; only
        // unrecognized content is read at all.
        let (found, walk_done) = (&found, &walk_done);
        let unreadable_ref = &unreadable;
        scope.spawn(move || {
            for root in paths {
                if root.is_file() {
                    found.fetch_add(1, Ordering::Relaxed);
                    let _ = walk_tx.send(root.clone());
                    continue;
                }
                let prune_cache = !root.starts_with(&own_cache);
                let mut excluded = false;
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
                        Ok(e) if e.file_type().is_file() => {
                            found.fetch_add(1, Ordering::Relaxed);
                            if walk_tx.send(e.into_path()).is_err() {
                                return; // workers are gone
                            }
                        }
                        Ok(_) => {}
                        Err(e) => unreadable_ref.lock().unwrap().push(e.to_string()),
                    }
                }
                if excluded {
                    eprintln!(
                        "excluding hashdex's own cache ({}); scan it explicitly to include it",
                        own_cache.display()
                    );
                }
            }
            drop(walk_tx);
            walk_done.store(true, Ordering::Release);
        });
        // Incremental persistence: a killed scan keeps the hashing it
        // already paid for. Fresh hashes flush in batches as workers
        // produce them; stale-path deletion stays at the very end —
        // only a COMPLETE walk is allowed to delete.
        scope.spawn(|| {
            let mut flushed_upto = 0usize;
            let mut last_flush = std::time::Instant::now();
            loop {
                std::thread::park_timeout(std::time::Duration::from_millis(500));
                let finished = walk_done.load(Ordering::Acquire)
                    && done.load(Ordering::Relaxed) >= found.load(Ordering::Relaxed);
                let pending = results.lock().unwrap().len() - flushed_upto;
                if pending > 0
                    && (finished || pending >= 2000 || last_flush.elapsed().as_secs() >= 5)
                {
                    let fresh: Vec<crate::local_index::FreshEntry> = {
                        let res = results.lock().unwrap();
                        let batch = res[flushed_upto..]
                            .iter()
                            .filter(|r| !r.from_index)
                            .map(to_fresh)
                            .collect();
                        flushed_upto = res.len();
                        batch
                    };
                    last_flush = std::time::Instant::now();
                    if !fresh.is_empty() {
                        if let Some(ix) = index_cell.lock().unwrap().as_mut() {
                            if let Err(e) = ix.commit_scan(&fresh, &[]) {
                                eprintln!("warning: incremental index flush failed: {e}");
                            }
                        }
                    }
                }
                if finished {
                    break;
                }
            }
        });
        for _ in 0..threads {
            scope.spawn(|| {
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    // Bind before matching: a `match recv()` scrutinee
                    // would hold the receiver lock through the whole
                    // file examination, serializing every worker.
                    let path = walk_rx.lock().unwrap().recv();
                    let Ok(path) = path else { break };
                    match examine(&path, cached_ref, opts.rehash, &mut buf) {
                        Ok(Some(mut r)) => {
                            if !r.from_index {
                                hashed_fresh.fetch_add(1, Ordering::Relaxed);
                            }
                            let sha1_hex = hex_upper(&r.sha1);
                            let sha256_hex = hex_lower(&r.sha256);
                            let mut skipped_big = false;
                            for f in probe_order {
                                if !opts.probe_all
                                    && f.bytes >= EXPENSIVE_FILTER_BYTES
                                    && !r.matched.is_empty()
                                {
                                    skipped_big = true;
                                    continue;
                                }
                                let key: &[u8] = match f.scheme {
                                    Scheme::Sha1 => sha1_hex.as_bytes(),
                                    Scheme::Sha256 => sha256_hex.as_bytes(),
                                    _ => continue,
                                };
                                if f.bloom.check(key) {
                                    r.matched.push(f.name.clone());
                                }
                            }
                            // One name per source: a source with sha1 AND
                            // sha256 blooms firing on the same file must
                            // not render as "fatcat,fatcat" or count twice
                            // in the per-source summary.
                            r.matched.sort();
                            r.matched.dedup();
                            if skipped_big {
                                big_skipped_files.fetch_add(1, Ordering::Relaxed);
                            }
                            results.lock().unwrap().push(r);
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
            });
        }
    });
    ticker.clear();

    let mut results = results.into_inner().unwrap();
    results.sort_by(|a, b| a.path.cmp(&b.path));
    let skipped = skipped.into_inner().unwrap();
    let unreadable = unreadable.into_inner().unwrap();

    // Persist: fresh hashes in (idempotent over the incremental
    // flushes), vanished paths out.
    let mut index = index_cell.into_inner().unwrap();
    let reused = results.iter().filter(|r| r.from_index).count();
    if let Some(ix) = &mut index {
        let fresh: Vec<crate::local_index::FreshEntry> = results
            .iter()
            .filter(|r| !r.from_index)
            .map(to_fresh)
            .collect();
        let seen: HashSet<String> = results
            .iter()
            .map(|r| r.path.to_string_lossy().into_owned())
            .collect();
        let mut stale: Vec<String> = cached
            .keys()
            .filter(|p| !seen.contains(p.as_str()))
            .cloned()
            .collect();
        stale.extend(skipped);
        if let Err(e) = ix.commit_scan(&fresh, &stale) {
            eprintln!("warning: index update failed: {e}");
        }
    }

    // Demand-driven network probes for matched digests, each visiting
    // only the backends whose filter fired: dataset-transport backends
    // by default, third-party APIs with --online consent. Runs before
    // the walk so fresh findings are in the observation store when the
    // per-file resolution below sweeps it.
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

    // Local resolution context for --resolve: pulled datasets + the
    // observation store (which --online may have just enriched).
    let resolver = if opts.resolve {
        let datasets = crate::datasets::open_all();
        let cache = if opts.no_index {
            None
        } else {
            crate::cache::Cache::open().ok()
        };
        Some((datasets, cache))
    } else {
        None
    };

    let mut known = 0usize;
    let mut attributed = 0usize;
    let mut consistent_files = 0usize;
    let mut membership_only = 0usize;
    let mut known_bytes = 0u64;
    let mut total_bytes = 0u64;
    let mut per_filter: std::collections::BTreeMap<&str, usize> = Default::default();
    for (i, r) in results.iter().enumerate() {
        ticker.update(100_000, i, || {
            format!("resolving locally… {i}/{} files", results.len())
        });
        total_bytes += r.size;
        for m in &r.matched {
            *per_filter.entry(m.as_str()).or_default() += 1;
        }
        // Attributed listing needs the evidence to decide visibility,
        // so the walk runs for every file whenever we resolve — except
        // sub-digest-size files, which are never attributed. The walk
        // is seeded with every digest scan minted (sha256 AND sha1 —
        // weak-keyed sources are only reachable via the weak seed).
        // Verdicts per witness row (the approved weak-digest policy):
        //   identified — the row's cluster contains the file's sha256;
        //   consistent — the row matches only on weak digests, and NO
        //     scheme it co-states contradicts a locally-minted digest
        //     (a contradicted row describes other bytes → related,
        //     silently);
        // both tiers count as known, reported separately.
        let evidence = resolver
            .as_ref()
            .filter(|_| r.size >= IDENTITY_MIN_BYTES)
            .map(|(datasets, cache)| {
                let sha256 = crate::coord::Coord {
                    scheme: Scheme::Sha256,
                    digest: r.sha256.to_vec(),
                };
                let sha1 = crate::coord::Coord {
                    scheme: Scheme::Sha1,
                    digest: r.sha1.to_vec(),
                };
                let local = |c: &crate::coord::Coord| -> Vec<crate::finding::Finding> {
                    datasets.iter().flat_map(|d| d.lookup(c)).collect()
                };
                let ev = crate::walk::walk(&[sha256.clone(), sha1], &local, cache.as_ref());
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
                            Scheme::Sha256 => c.digest[..] != r.sha256[..],
                            Scheme::Sha1 => c.digest[..] != r.sha1[..],
                            _ => false,
                        });
                        let weak_match = coords
                            .iter()
                            .any(|c| c.scheme == Scheme::Sha1 && c.digest[..] == r.sha1[..]);
                        if !contradicted && weak_match && seen.insert(key) {
                            consistent.push(f);
                        }
                    }
                }
                (identified, consistent)
            });
        let has_claims = evidence
            .as_ref()
            .is_some_and(|(id, _)| id.iter().any(|f| !f.claims.is_empty()));
        let has_consistent = evidence
            .as_ref()
            .is_some_and(|(_, co)| co.iter().any(|f| !f.claims.is_empty()));
        if has_claims {
            attributed += 1;
        } else if has_consistent {
            consistent_files += 1;
        }
        // Known = a filter matched OR the walk produced a claim: index
        // rows (tarballs, cached observations) are witness-grade
        // evidence, stronger than a probabilistic bloom hit — a file
        // can't be both attributed and "unknown".
        if !r.matched.is_empty() || has_claims || has_consistent {
            known += 1;
            known_bytes += r.size;
        }
        if resolver.is_some() && !r.matched.is_empty() && !has_claims && !has_consistent {
            membership_only += 1;
        }
        let show = match opts.list {
            ListMode::None => false,
            ListMode::All => true,
            ListMode::Known => !r.matched.is_empty(),
            ListMode::Unknown => r.matched.is_empty(),
            ListMode::Attributed => {
                has_claims || has_consistent || file_roots.contains(r.path.as_path())
            }
        };
        if show {
            ticker.clear();
            // Every consistent match is via sha1 — the only weak digest
            // scan mints (md5 joins when an md5-only source needs it).
            const WEAK_VIA: &str = "sha1";
            if opts.json {
                let mut obj = json!({
                    "path": r.path.display().to_string(),
                    "size": r.size,
                    "sha1": hex_lower(&r.sha1),
                    "sha256": hex_lower(&r.sha256),
                    "known": !r.matched.is_empty(),
                    "filters": r.matched,
                });
                if let Some((identified, consistent)) = &evidence {
                    obj["resolved"] = identified
                        .iter()
                        .map(|f| json!({"backend": f.backend, "claims": f.claims}))
                        .collect();
                    obj["consistent"] = consistent
                        .iter()
                        .map(|f| {
                            json!({"backend": f.backend, "claims": f.claims, "via": [WEAK_VIA]})
                        })
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
                let tag = if !r.matched.is_empty() {
                    r.matched.join(",")
                } else if has_claims {
                    // No filter fired but the local walk attributed it
                    // (index-only sources like tarballs have no bloom):
                    // name the attestors, don't call it unknown.
                    evidence.as_ref().map(|(id, _)| backends_of(id)).unwrap()
                } else if has_consistent {
                    evidence.as_ref().map(|(_, co)| backends_of(co)).unwrap()
                } else {
                    "unknown".to_string()
                };
                println!("{:<12} {}", tag, r.path.display());
                if let Some((identified, consistent)) = &evidence {
                    // Weak-only matches never present as identity: their
                    // lines carry the tier and the scheme that matched.
                    let prefix = format!("consistent ({WEAK_VIA}): ");
                    // (identity-tier?, backend, statement, url) —
                    // identified claims always outrank consistent ones.
                    let lines: Vec<(bool, &str, String, &Option<String>)> = identified
                        .iter()
                        .flat_map(|f| {
                            f.claims.iter().map(move |c| {
                                (true, f.backend.as_str(), c.statement.clone(), &c.url)
                            })
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
    }

    ticker.clear();
    let scanned = results.len();
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
    if resolver.is_some() {
        summary["attributed"] = json!(attributed);
        summary["consistent"] = json!(consistent_files);
        summary["membership_only"] = json!(membership_only);
    }
    if opts.json {
        println!("{summary}");
    } else {
        eprintln!();
        let mut attribution = if resolver.is_some() {
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
fn backend_for_filter(name: &str) -> Option<&'static str> {
    match name {
        "fatcat" => Some("fatcat"),
        "tarballs" => Some("tarballs"),
        "ia-census" => Some("ia-census"),
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
async fn online_probe(
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
fn s(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}
