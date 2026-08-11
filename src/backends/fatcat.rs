//! Native transport for the fatcat dataset (`crate::fatcat`): blocking
//! HTTP range reads against the published parquet, revision-pinned and
//! persisted on disk.
//!
//! URLs are pinned to a repo revision (Hub API, refreshed hourly), so
//! every byte range is immutable and fetched ranges persist on disk
//! across invocations with no validation traffic. A stale pin is safe:
//! old revisions stay fetchable, they're just up to an hour behind.

use crate::coord::Coord;
use crate::fatcat::{start_paths, DATASET_BASE, REVISION_API};
use crate::finding::Finding;
use anyhow::{Context, Result};
use bytes::Bytes;
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};
use parquet::file::reader::{ChunkReader, Length};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub use crate::fatcat::{supports, NAME};

const REVISION_TTL: Duration = Duration::from_secs(3600);
/// Block size for page-header walks through uncached territory.
const HEADER_BLOCK: usize = 16 << 10;

// ---------------------------------------------------------------- transport

struct RemoteInner {
    client: reqwest::blocking::Client,
    url: String,
    /// Where the resolve URL's redirect landed (a signed CAS URL):
    /// later requests go direct and skip the redirect round trip,
    /// falling back to `url` once when the signature expires.
    effective: Mutex<Option<String>>,
    len: u64,
    /// Fetched ranges keyed by start offset. Ranges may overlap; a
    /// lookup is served by any single cached range that covers it.
    /// Cleared wholesale past CACHE_MAX so batch scans stay bounded —
    /// the footer is already parsed, so eviction only costs refetches.
    cache: Mutex<BTreeMap<u64, Bytes>>,
    /// Revision-pinned blobs surviving across invocations (None when
    /// the revision is unknown — then nothing on disk can be trusted).
    disk: Option<DiskCache>,
    /// Range starts currently being fetched: concurrent probes landing
    /// in the same row group wait for one fetch instead of duplicating
    /// a multi-megabyte request.
    inflight: Mutex<HashSet<u64>>,
    inflight_done: Condvar,
}

/// Per-file cap on cached range bytes (17 data files + 2 maps can be
/// open at once in a scan).
const CACHE_MAX: usize = 96 << 20;
/// Cold-open speculative suffix: must cover magic + footer (~150 KB)
/// + page-index region (~5 MB on the data files) in one request.
const SUFFIX: u64 = 8 << 20;
/// Per-file cap on persisted range bytes; oldest blobs go first.
const DISK_MAX: u64 = 64 << 20;

fn http_cache_root() -> PathBuf {
    crate::cache::cache_dir().join("fatcat").join("http")
}

/// The pinned repo revision: the on-disk pin when fresh, else the Hub
/// API (pruning caches of older revisions), else the stale pin —
/// offline reuse is exactly what pinning makes safe. None only on a
/// first run that can't reach the Hub.
fn pinned_revision() -> Option<String> {
    let root = http_cache_root();
    let pin = root.join("revision");
    let stale = || {
        std::fs::read_to_string(&pin)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let age = std::fs::metadata(&pin)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok());
    if age.is_some_and(|a| a < REVISION_TTL) {
        if let Some(sha) = stale() {
            return Some(sha);
        }
    }
    let fetched: Result<String> = (|| {
        let v: Value = maybe_auth(http().get(REVISION_API), REVISION_API)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(v["sha"]
            .as_str()
            .context("no sha in revision response")?
            .to_string())
    })();
    match fetched {
        Ok(sha) => {
            // A new revision orphans every blob pinned to older ones.
            if let Ok(entries) = std::fs::read_dir(&root) {
                for e in entries.flatten() {
                    if e.file_name().to_str() != Some(&sha) && e.path().is_dir() {
                        let _ = std::fs::remove_dir_all(e.path());
                    }
                }
            }
            let _ = std::fs::create_dir_all(&root);
            let _ = std::fs::write(&pin, &sha);
            Some(sha)
        }
        Err(_) => stale(),
    }
}

/// On-disk range blobs for one remote file at one revision. Blob files
/// are named `<start>-<len>`; the map mirrors the directory listing.
struct DiskCache {
    dir: PathBuf,
    ranges: Mutex<BTreeMap<u64, u64>>,
}

impl DiskCache {
    fn open(dir: PathBuf) -> Option<DiskCache> {
        std::fs::create_dir_all(&dir).ok()?;
        let mut ranges = BTreeMap::new();
        for e in std::fs::read_dir(&dir).ok()?.flatten() {
            if let Some((s, l)) = e
                .file_name()
                .to_str()
                .and_then(|n| n.split_once('-'))
                .and_then(|(s, l)| Some((s.parse().ok()?, l.parse().ok()?)))
            {
                ranges.insert(s, l);
            }
        }
        Some(DiskCache {
            dir,
            ranges: Mutex::new(ranges),
        })
    }

    /// The whole blob covering [start, start+length), if any.
    fn get(&self, start: u64, length: usize) -> Option<(u64, Bytes)> {
        let (s, l) = {
            let ranges = self.ranges.lock().unwrap();
            let (&s, &l) = ranges.range(..=start).next_back()?;
            (s, l)
        };
        if start + length as u64 > s + l {
            return None;
        }
        let b = std::fs::read(self.dir.join(format!("{s}-{l}"))).ok()?;
        (b.len() as u64 == l).then(|| (s, Bytes::from(b)))
    }

    /// Best-effort persist; evicts oldest blobs past DISK_MAX.
    fn put(&self, start: u64, b: &Bytes) {
        let mut ranges = self.ranges.lock().unwrap();
        if ranges.contains_key(&start) {
            return;
        }
        if std::fs::write(self.dir.join(format!("{start}-{}", b.len())), b).is_err() {
            return;
        }
        ranges.insert(start, b.len() as u64);
        while ranges.values().sum::<u64>() > DISK_MAX {
            let oldest = ranges
                .iter()
                .filter_map(|(&s, &l)| {
                    let p = self.dir.join(format!("{s}-{l}"));
                    Some((std::fs::metadata(&p).and_then(|m| m.modified()).ok()?, s, p))
                })
                .min();
            let Some((_, s, p)) = oldest else { break };
            let _ = std::fs::remove_file(p);
            ranges.remove(&s);
        }
    }
}

/// One remote parquet file addressed by HTTP range requests, cached
/// per-process so a batch scan shares footers, key chunks, and pages.
#[derive(Clone)]
struct Remote {
    inner: Arc<RemoteInner>,
}

fn http() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .user_agent(concat!("hdx/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("http client")
    })
}

/// HF_TOKEN (optional, like SWH_TOKEN) raises the Hub's anonymous
/// rate limits. Attached only to huggingface.co itself — never to the
/// CAS hosts its redirects land on.
fn maybe_auth(
    req: reqwest::blocking::RequestBuilder,
    url: &str,
) -> reqwest::blocking::RequestBuilder {
    match std::env::var("HF_TOKEN") {
        Ok(t) if !t.is_empty() && url.starts_with("https://huggingface.co/") => req.bearer_auth(t),
        _ => req,
    }
}

/// Ranged GET remembering where the redirect landed. Standalone so
/// open_remote's suffix probe shares it before RemoteInner exists.
///
/// 429s back off (honoring Retry-After, bounded) and retry the SAME
/// target — clearing the memoized CAS URL on them would stampede the
/// rate-limited resolve host, which is how a burst of first-contact
/// probes once turned one 429 into a per-file cascade. Other direct-
/// target failures (expired signature, dropped connection) fall back
/// to the resolve URL once.
fn ranged_get(
    client: &reqwest::blocking::Client,
    url: &str,
    effective: &Mutex<Option<String>>,
    range: &str,
) -> reqwest::Result<reqwest::blocking::Response> {
    let mut fell_back = false;
    let mut attempts = 0u32;
    loop {
        let direct = (!fell_back)
            .then(|| effective.lock().unwrap().clone())
            .flatten();
        let target = direct.as_deref().unwrap_or(url);
        attempts += 1;
        match maybe_auth(client.get(target), target)
            .header(reqwest::header::RANGE, range)
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                let landed = resp.url().as_str();
                if landed != url {
                    *effective.lock().unwrap() = Some(landed.to_string());
                }
                return Ok(resp);
            }
            Ok(resp)
                if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempts <= 5 =>
            {
                // The Hub's anonymous window outlasts a polite pause;
                // short caps just burn attempts inside it.
                let wait = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                    .unwrap_or(1 << attempts.min(5))
                    .clamp(2, 30);
                std::thread::sleep(Duration::from_secs(wait));
            }
            Ok(resp) => {
                if target != url {
                    *effective.lock().unwrap() = None;
                    fell_back = true;
                    continue;
                }
                return resp.error_for_status();
            }
            Err(e) => {
                if target != url {
                    *effective.lock().unwrap() = None;
                    fell_back = true;
                    continue;
                }
                if attempts > 4 {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

impl RemoteInner {
    fn fetch(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        let end = start + length as u64 - 1;
        let resp = ranged_get(
            &self.client,
            &self.url,
            &self.effective,
            &format!("bytes={start}-{end}"),
        )
        .and_then(|r| r.bytes())
        .map_err(|e| {
            parquet::errors::ParquetError::External(format!("{}: {e}", self.url).into())
        })?;
        if resp.len() < length {
            return Err(parquet::errors::ParquetError::EOF(format!(
                "short range read from {}",
                self.url
            )));
        }
        Ok(resp)
    }

    fn mem_cached(&self, start: u64, length: usize) -> Option<Bytes> {
        let cache = self.cache.lock().unwrap();
        let (&s, b) = cache.range(..=start).next_back()?;
        let off = (start - s) as usize;
        if b.len() >= off + length {
            Some(b.slice(off..off + length))
        } else {
            None
        }
    }

    fn remember(&self, start: u64, b: Bytes) {
        let mut cache = self.cache.lock().unwrap();
        if cache.values().map(Bytes::len).sum::<usize>() + b.len() > CACHE_MAX {
            cache.clear();
        }
        cache.insert(start, b);
    }

    /// Memory first, then disk (promoting the covering blob so header
    /// walks stay in memory).
    fn cached(&self, start: u64, length: usize) -> Option<Bytes> {
        if let Some(b) = self.mem_cached(start, length) {
            return Some(b);
        }
        let (s, blob) = self.disk.as_ref()?.get(start, length)?;
        self.remember(s, blob.clone());
        let off = (start - s) as usize;
        Some(blob.slice(off..off + length))
    }

    /// Cache-through read of an exact range, single-flighted by start
    /// offset: a loser of the race waits, then rechecks the cache.
    fn read_range(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }
        loop {
            if let Some(b) = self.cached(start, length) {
                return Ok(b);
            }
            let mut inflight = self.inflight.lock().unwrap();
            if inflight.insert(start) {
                break;
            }
            let _wait = self.inflight_done.wait(inflight).unwrap();
        }
        let fetched = self.fetch(start, length);
        self.inflight.lock().unwrap().remove(&start);
        self.inflight_done.notify_all();
        let b = fetched?;
        self.remember(start, b.clone());
        if let Some(disk) = &self.disk {
            disk.put(start, &b);
        }
        Ok(b)
    }
}

/// Sequential cursor for page-header walks: serves from cache, and
/// fetches small blocks (not chunk-to-EOF streams) on a miss so a
/// skipped-over page costs a header-sized request, not its data.
struct RemoteCursor {
    inner: Arc<RemoteInner>,
    pos: u64,
}

impl Read for RemoteCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.inner.len || buf.is_empty() {
            return Ok(0);
        }
        let avail = (self.inner.len - self.pos).min(buf.len() as u64) as usize;
        let got = match self.inner.cached(self.pos, 1) {
            // Serve as much as this cached range holds, up to avail.
            Some(_) => {
                let mut n = avail;
                loop {
                    if let Some(b) = self.inner.cached(self.pos, n) {
                        break b;
                    }
                    n /= 2;
                    if n == 0 {
                        break self.inner.cached(self.pos, 1).unwrap();
                    }
                }
            }
            None => {
                let n = avail.max(HEADER_BLOCK.min((self.inner.len - self.pos) as usize));
                self.inner
                    .read_range(self.pos, n)
                    .map_err(std::io::Error::other)?
            }
        };
        let n = got.len().min(avail);
        buf[..n].copy_from_slice(&got[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Length for Remote {
    fn len(&self) -> u64 {
        self.inner.len
    }
}

impl ChunkReader for Remote {
    type T = RemoteCursor;

    fn get_read(&self, start: u64) -> parquet::errors::Result<RemoteCursor> {
        Ok(RemoteCursor {
            inner: Arc::clone(&self.inner),
            pos: start,
        })
    }

    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        self.inner.read_range(start, length)
    }
}

/// A remote file plus its parsed footer, opened once per process.
struct RemoteFile {
    remote: Arc<Remote>,
    meta: Arc<ParquetMetaData>,
}

fn open_remote(path: &str) -> Result<Arc<RemoteFile>> {
    type Slot = Arc<Mutex<Option<Arc<RemoteFile>>>>;
    static FILES: OnceLock<Mutex<HashMap<String, Slot>>> = OnceLock::new();
    let slot: Slot = {
        let mut files = FILES.get_or_init(Default::default).lock().unwrap();
        Arc::clone(files.entry(path.to_string()).or_default())
    };
    // Per-path build lock: racing opens of one file build it once,
    // while different files still open in parallel.
    let mut slot = slot.lock().unwrap();
    if let Some(f) = &*slot {
        return Ok(Arc::clone(f));
    }

    static REVISION: OnceLock<Option<String>> = OnceLock::new();
    let revision = REVISION.get_or_init(pinned_revision);
    let rev = revision.as_deref().unwrap_or("main");
    let url = format!("{DATASET_BASE}/{rev}/{path}");
    let disk = revision
        .as_ref()
        .and_then(|sha| DiskCache::open(http_cache_root().join(sha).join(path.replace('/', "_"))));

    // File length: persisted beside the blobs (the disk cache then
    // already holds the footer region from the first open). On a cold
    // open, ONE speculative suffix request answers everything: its
    // Content-Range carries the file length, and the last SUFFIX bytes
    // cover magic + footer + the whole page-index region, so the
    // metadata parse below does no further requests. (HEAD is useless
    // here — the resolve redirect's CDN doesn't answer it reliably.)
    let effective = Mutex::new(None);
    let len_path = disk.as_ref().map(|d| d.dir.join("len"));
    let cached_len: Option<u64> = len_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok()?.trim().parse().ok());
    let mut suffix: Option<(u64, Bytes)> = None;
    let len = match cached_len {
        Some(n) => n,
        None => {
            let resp = ranged_get(http(), &url, &effective, &format!("bytes=-{SUFFIX}"))?;
            let content_range = resp
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body = resp.bytes()?;
            // "bytes <start>-<end>/<total>"; a file smaller than
            // SUFFIX arrives whole with start 0.
            let (start, n) = match content_range
                .as_deref()
                .and_then(|v| v.strip_prefix("bytes "))
                .and_then(|v| v.split_once('/'))
                .and_then(|(range, total)| {
                    Some((range.split_once('-')?.0.parse().ok()?, total.parse().ok()?))
                }) {
                Some((s, t)) => (s, t),
                None => (0, body.len() as u64), // 200: served whole
            };
            suffix = Some((start, body));
            if let Some(p) = &len_path {
                let _ = std::fs::write(p, n.to_string());
            }
            n
        }
    };

    let remote = Arc::new(Remote {
        inner: Arc::new(RemoteInner {
            client: http().clone(),
            url,
            effective,
            len,
            cache: Mutex::new(BTreeMap::new()),
            disk,
            inflight: Mutex::new(HashSet::new()),
            inflight_done: Condvar::new(),
        }),
    });
    if let Some((start, body)) = suffix {
        if let Some(d) = &remote.inner.disk {
            d.put(start, &body);
        }
        remote.inner.remember(start, body);
    }
    // Optional, not Required: pre-page-index revisions still work via
    // the whole-chunk path.
    let meta = ParquetMetaDataReader::new()
        .with_page_index_policy(PageIndexPolicy::Optional)
        .parse_and_finish(remote.as_ref())?;
    let file = Arc::new(RemoteFile {
        remote,
        meta: Arc::new(meta),
    });
    *slot = Some(Arc::clone(&file));
    Ok(file)
}

// ------------------------------------------------------------------ lookup

/// Open every remote file a probe batch will certainly need, in
/// parallel and outside any per-probe timeout. Cold opens (an 8 MB
/// suffix request each) are the bulk of a first-contact batch's
/// work; inside probe budgets they starved probes queued behind them
/// (241/596 timed out on the first full-Dropbox run). Weak digests
/// fan out to data files only known after the map lookup — those
/// still open lazily, one single-flighted open per file.
pub fn preopen(coords: &[Coord]) {
    let paths: HashSet<String> = coords.iter().flat_map(start_paths).collect();
    std::thread::scope(|s| {
        for p in &paths {
            s.spawn(move || {
                let _ = open_remote(p); // probes retry and report errors
            });
        }
    });
}

fn open_pair(path: &str) -> Result<(Arc<Remote>, Arc<ParquetMetaData>)> {
    let file = open_remote(path)?;
    Ok((Arc::clone(&file.remote), Arc::clone(&file.meta)))
}

pub async fn lookup(_client: &reqwest::Client, coord: &Coord) -> Result<Option<Finding>> {
    let coord = coord.clone();
    tokio::task::spawn_blocking(move || crate::fatcat::lookup_with(open_pair, &coord)).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_cache_roundtrip_and_eviction() {
        let dir = std::env::temp_dir().join(format!("hdx-fatcat-disk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = DiskCache::open(dir.clone()).unwrap();
        cache.put(100, &Bytes::from(vec![7u8; 50]));
        // Covered sub-range comes back sliced from the blob.
        let (s, b) = cache.get(120, 10).unwrap();
        assert_eq!((s, b.len()), (100, 50));
        assert!(cache.get(100, 51).is_none(), "past blob end");
        assert!(cache.get(99, 1).is_none(), "before blob start");
        // A fresh open rebuilds the map from the directory listing.
        let reopened = DiskCache::open(dir.clone()).unwrap();
        assert!(reopened.get(100, 50).is_some());
        // Blobs past DISK_MAX evict oldest-first, keeping the rest.
        let big = Bytes::from(vec![0u8; (DISK_MAX / 2 + 1) as usize]);
        cache.put(1 << 30, &big);
        cache.put(2 << 30, &big);
        assert!(cache.get(100, 50).is_none(), "oldest blob evicted");
        assert!(cache.get(2 << 30, 8).is_some(), "newest survives");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
