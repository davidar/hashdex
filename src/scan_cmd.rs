use crate::coord::Scheme;
use crate::filter::NamedFilter;
use crate::local_index::{CachedEntry, LocalIndex};
use anyhow::Result;
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
    /// Resolve listed files through the local walk (inverted indexes +
    /// observation store). Never touches the network.
    pub resolve: bool,
    /// Probe every filter even when a smaller one already matched
    /// (full attribution at the cost of big-filter page faults).
    pub probe_all: bool,
}

/// Filters at least this big are probed only for files no smaller filter
/// recognized: each probe of a bigger-than-RAM mmap is a random page
/// fault, and known-file corroboration isn't worth disk seeks.
const EXPENSIVE_FILTER_BYTES: u64 = 2 << 30;

#[derive(Clone, Copy, PartialEq)]
pub enum ListMode {
    None,
    Unknown,
    Known,
    All,
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

/// Walk paths, hash every regular file (sha1 + sha256 in one pass), check
/// membership filters locally. Zero network. This is the personal-NSRL
/// scan: "which of my files are publicly known bytes."
///
/// Hashes persist in the local index (updatedb-style): unchanged files
/// (same size + mtime) are not re-read on later scans, and `hdx locate`
/// can find files by digest.
pub fn scan(paths: &[PathBuf], filters: &[NamedFilter], opts: &ScanOptions) -> Result<()> {
    // Collect the file list first so workers can chew through it by index.
    // hdx's own cache (dumps, extracts, filters, local.db) is excluded —
    // it would pollute the known/unknown metrics with our own artifacts —
    // unless a scan root points inside it explicitly.
    let own_cache = crate::cache::cache_dir();
    let mut excluded_own_cache = false;
    let mut files = Vec::new();
    for root in paths {
        if root.is_file() {
            files.push(root.clone());
            continue;
        }
        let prune_cache = !root.starts_with(&own_cache);
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if prune_cache && e.path() == own_cache {
                    excluded_own_cache = true;
                    return false;
                }
                true
            });
        for entry in walker {
            match entry {
                Ok(e) if e.file_type().is_file() => files.push(e.into_path()),
                Ok(_) => {}
                Err(e) => eprintln!("warning: {e}"),
            }
        }
    }
    let total = files.len();
    if excluded_own_cache {
        eprintln!(
            "excluding hashdex's own cache ({}); scan it explicitly to include it",
            own_cache.display()
        );
    }

    let mut index = if opts.no_index {
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
    eprintln!("scanning {total} files ({} in index)…", cached.len());

    // Probe cheapest-first so membership is usually settled before any
    // bigger-than-RAM filter would need a disk seek.
    let mut probe_order: Vec<&NamedFilter> = filters.iter().collect();
    probe_order.sort_by_key(|f| f.bytes);
    let probe_order = &probe_order;

    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let big_skipped_files = AtomicUsize::new(0);
    let results: Mutex<Vec<FileResult>> = Mutex::new(Vec::with_capacity(total));
    let skipped: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let cached_ref = &cached;

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    match examine(&files[i], cached_ref, opts.rehash, &mut buf) {
                        Ok(Some(mut r)) => {
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
                            r.matched.sort();
                            if skipped_big {
                                big_skipped_files.fetch_add(1, Ordering::Relaxed);
                            }
                            results.lock().unwrap().push(r);
                        }
                        Ok(None) => {
                            skipped
                                .lock()
                                .unwrap()
                                .push(files[i].to_string_lossy().into_owned());
                        }
                        Err(e) => eprintln!("warning: {}: {e}", files[i].display()),
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if d.is_multiple_of(100_000) {
                        eprintln!("  … {d}/{total}");
                    }
                }
            });
        }
    });

    let mut results = results.into_inner().unwrap();
    results.sort_by(|a, b| a.path.cmp(&b.path));
    let skipped = skipped.into_inner().unwrap();

    // Persist: fresh hashes in, vanished paths out.
    let reused = results.iter().filter(|r| r.from_index).count();
    if let Some(ix) = &mut index {
        let fresh: Vec<crate::local_index::FreshEntry> = results
            .iter()
            .filter(|r| !r.from_index)
            .map(|r| {
                (
                    r.path.to_string_lossy().into_owned(),
                    r.size,
                    r.mtime_ns,
                    r.sha1,
                    r.sha256,
                )
            })
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

    // Local-only resolution context for --resolve: inverted indexes +
    // the observation store, zero network (that's `hdx <hash>`'s job).
    let resolver = if opts.resolve {
        let indexes = crate::inverted::open_all().unwrap_or_default();
        let cache = if opts.no_index {
            None
        } else {
            crate::cache::Cache::open().ok()
        };
        Some((indexes, cache))
    } else {
        None
    };

    let mut known = 0usize;
    let mut known_bytes = 0u64;
    let mut total_bytes = 0u64;
    let mut per_filter: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in &results {
        total_bytes += r.size;
        if !r.matched.is_empty() {
            known += 1;
            known_bytes += r.size;
            for m in &r.matched {
                *per_filter.entry(m.as_str()).or_default() += 1;
            }
        }
        let show = match opts.list {
            ListMode::None => false,
            ListMode::All => true,
            ListMode::Known => !r.matched.is_empty(),
            ListMode::Unknown => r.matched.is_empty(),
        };
        if show {
            let evidence = resolver.as_ref().map(|(indexes, cache)| {
                let coord = crate::coord::Coord {
                    scheme: Scheme::Sha256,
                    digest: r.sha256.to_vec(),
                };
                crate::walk::walk(&coord, indexes, cache.as_ref())
            });
            if opts.json {
                let mut obj = json!({
                    "path": r.path.display().to_string(),
                    "size": r.size,
                    "sha1": hex_lower(&r.sha1),
                    "sha256": hex_lower(&r.sha256),
                    "known": !r.matched.is_empty(),
                    "filters": r.matched,
                });
                if let Some(evidence) = &evidence {
                    obj["resolved"] = evidence
                        .iter()
                        .map(|e| {
                            json!({
                                "backend": e.finding.backend,
                                "claims": e.finding.claims,
                            })
                        })
                        .collect();
                }
                println!("{obj}");
            } else {
                let tag = if r.matched.is_empty() {
                    "unknown".to_string()
                } else {
                    r.matched.join(",")
                };
                println!("{:<12} {}", tag, r.path.display());
                if let Some(evidence) = &evidence {
                    const SHOWN: usize = 3;
                    for e in evidence.iter().take(SHOWN) {
                        let Some(claim) = e.finding.claims.first() else {
                            continue;
                        };
                        println!("             {:<12} {}", e.finding.backend, claim.statement);
                    }
                    if evidence.len() > SHOWN {
                        println!("             … and {} more claims", evidence.len() - SHOWN);
                    }
                }
            }
        }
    }

    let scanned = results.len();
    let summary = json!({
        "files": scanned,
        "bytes": total_bytes,
        "known": known,
        "known_bytes": known_bytes,
        "unknown": scanned - known,
        "hashed": scanned - reused,
        "from_index": reused,
        "big_filters_skipped_files": big_skipped_files.load(Ordering::Relaxed),
        "per_filter": per_filter.iter().map(|(k, v)| (k.to_string(), v)).collect::<std::collections::BTreeMap<_,_>>(),
        "filters_loaded": filters.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
    });
    if opts.json {
        println!("{summary}");
    } else {
        eprintln!();
        println!(
            "{scanned} files ({}) — {known} known ({}), {} unknown",
            human(total_bytes),
            human(known_bytes),
            scanned - known
        );
        for (f, n) in &per_filter {
            println!("  {f}: {n} files");
        }
        let big_skipped = big_skipped_files.load(Ordering::Relaxed);
        if big_skipped > 0 {
            println!(
                "  ({big_skipped} known files skipped filters over {} — per-filter counts are a floor; --probe-all for full attribution)",
                human(EXPENSIVE_FILTER_BYTES)
            );
        }
        println!(
            "  hashed {} files, reused {reused} from local index",
            scanned - reused
        );
        if filters.is_empty() {
            println!("  (no filters installed — run `hdx filters fetch` first; every file reports unknown)");
        }
        println!("  note: filter matches are probabilistic (small false-positive rate); confirm important ones with `hdx <hash>`");
    }
    Ok(())
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
