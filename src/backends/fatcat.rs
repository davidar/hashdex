use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::{Context, Result};
use bytes::Bytes;
use parquet::column::reader::{get_typed_column_reader, ColumnReaderImpl};
use parquet::data_type::{ByteArrayType, DataType, Int32Type, Int64Type};
use parquet::file::metadata::{
    PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader, RowGroupMetaData,
};
use parquet::file::page_index::column_index::ColumnIndexMetaData;
use parquet::file::page_index::offset_index::PageLocation;
use parquet::file::reader::{ChunkReader, Length};
use parquet::file::serialized_reader::SerializedPageReader;
use parquet::file::statistics::Statistics;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub const NAME: &str = "fatcat";

/// The final fatcat bulk export (2024-02-18), republished as parquet
/// sorted by sha256 (weak-digest maps sorted by their key). fatcat.wiki
/// is offline, so the claim URLs are the ones that still resolve: the
/// wayback capture of the hashed bytes first, then the DOI.
///
/// Transport: HTTP range reads against the published parquet itself.
/// Row-group footer stats route each digest to one ~256K-row group;
/// the sorted key column is fetched in a single ranged request and
/// scanned with early exit; the handful of claim columns are then
/// page-skipped to the matching rows. No server-side query layer —
/// the sorted layout IS the index.
///
/// URLs are pinned to a repo revision (Hub API, refreshed hourly), so
/// every byte range is immutable and fetched ranges persist on disk
/// across invocations with no validation traffic. A stale pin is safe:
/// old revisions stay fetchable, they're just up to an hour behind.
const DATASET_BASE: &str = "https://huggingface.co/datasets/david-ar/fatcat-files/resolve";
const REVISION_API: &str =
    "https://huggingface.co/api/datasets/david-ar/fatcat-files/revision/main";
const REVISION_TTL: Duration = Duration::from_secs(3600);
const SHOWN: usize = 5;
/// Releases read per digest (claims render at most SHOWN; the rest is
/// only counted). Bounds pathological many-release files.
const MAX_ROWS: usize = 50;
/// Block size for page-header walks through uncached territory.
const HEADER_BLOCK: usize = 16 << 10;
/// Column chunks at or below this arrive as one ranged request instead
/// of a header walk: below ~4 MB one bulk fetch beats a round-trip per
/// skipped page.
const PREFETCH_MAX: u64 = 4 << 20;

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256)
}

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

// ------------------------------------------------------------------ search

fn column_index(meta: &ParquetMetaData, name: &str) -> Result<usize> {
    meta.file_metadata()
        .schema_descr()
        .columns()
        .iter()
        .position(|c| c.path().string() == name)
        .with_context(|| format!("column {name} not in parquet schema"))
}

/// Row groups whose footer min/max admit `key` (0 or 1 in practice;
/// 2 when a digest's rows straddle a boundary).
fn candidate_row_groups(meta: &ParquetMetaData, col: usize, key: &[u8]) -> Vec<usize> {
    meta.row_groups()
        .iter()
        .enumerate()
        .filter(|(_, rg)| match rg.column(col).statistics() {
            Some(Statistics::ByteArray(s)) => match (s.min_opt(), s.max_opt()) {
                (Some(min), Some(max)) => min.data() <= key && key <= max.data(),
                _ => false,
            },
            _ => false,
        })
        .map(|(i, _)| i)
        .collect()
}

/// Page locations for one column chunk, when the footer carries an
/// offset index. With locations the page reader seeks straight to a
/// page and skips others without any read; without, skipping means
/// walking page headers.
fn page_locations(meta: &ParquetMetaData, rgi: usize, col: usize) -> Option<Vec<PageLocation>> {
    Some(
        meta.offset_index()?
            .get(rgi)?
            .get(col)?
            .page_locations()
            .clone(),
    )
}

fn typed_reader<R: ChunkReader + 'static, T: DataType>(
    reader: &Arc<R>,
    rg: &RowGroupMetaData,
    col: usize,
    locations: Option<Vec<PageLocation>>,
) -> Result<ColumnReaderImpl<T>> {
    let pages = SerializedPageReader::new(
        Arc::clone(reader),
        rg.column(col),
        rg.num_rows() as usize,
        locations,
    )?;
    Ok(get_typed_column_reader::<T>(
        parquet::column::reader::get_column_reader(meta_column(rg, col), Box::new(pages)),
    ))
}

fn meta_column(rg: &RowGroupMetaData, col: usize) -> parquet::schema::types::ColumnDescPtr {
    rg.schema_descr().column(col)
}

/// Scan the sorted key column of one row group for `key`: returns the
/// first matching record index and how many match (counting continues
/// past `cap` so "and N more" stays honest, but stops at the group end
/// or first greater value).
///
/// With a page index, per-page min/max route the scan straight to the
/// first admitting page (or prove absence with no data read at all).
/// Without one, the whole key chunk is fetched up front in one ranged
/// request — it gets decoded anyway.
fn scan_key_column<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    col: usize,
    key: &[u8],
) -> Result<Option<(usize, usize)>> {
    let rg = meta.row_group(rgi);
    let locations = page_locations(meta, rgi, col);
    let column_index = meta
        .column_index()
        .and_then(|c| c.get(rgi)?.get(col))
        .and_then(|ix| match ix {
            ColumnIndexMetaData::BYTE_ARRAY(ix) => Some(ix),
            _ => None,
        });
    let skip = match (&locations, column_index) {
        (Some(locs), Some(ix)) => {
            // Keys are globally sorted, so admitting pages are
            // contiguous; land on the first.
            let admits = (0..locs.len()).position(|i| {
                matches!((ix.min_value(i), ix.max_value(i)),
                    (Some(mn), Some(mx)) if mn <= key && key <= mx)
            });
            match admits {
                Some(page) => locs[page].first_row_index as usize,
                None => return Ok(None),
            }
        }
        _ => {
            let (start, len) = rg.column(col).byte_range();
            let _ = reader.get_bytes(start, len as usize)?; // warm the range cache
            0
        }
    };
    let mut r = typed_reader::<R, ByteArrayType>(reader, rg, col, locations)?;
    if skip > 0 {
        r.skip_records(skip)?;
    }
    let max_def = meta_column(rg, col).max_def_level();
    let (mut record, mut first, mut count) = (skip, None, 0usize);
    loop {
        let mut vals = Vec::new();
        let mut defs: Vec<i16> = Vec::new();
        // Modest batches: the reader only fetches pages it must, so a
        // small batch keeps the early exit from dragging in pages past
        // the match (in-page state carries across calls).
        let (records, _, _) = r.read_records(256, Some(&mut defs), None, &mut vals)?;
        if records == 0 {
            break;
        }
        // A required column (max_def 0) fills no def levels.
        defs.resize(records, max_def);
        let mut vi = 0;
        for &d in defs.iter().take(records) {
            let val = if d == max_def {
                let v = vals[vi].data();
                vi += 1;
                Some(v)
            } else {
                None
            };
            if let Some(v) = val {
                if v == key {
                    first.get_or_insert(record);
                    count += 1;
                } else if v > key {
                    return Ok(first.map(|f| (f, count)));
                }
            }
            record += 1;
        }
    }
    Ok(first.map(|f| (f, count)))
}

enum ColValues {
    Str(Vec<Option<String>>),
    I32(Vec<Option<i32>>),
    I64(Vec<Option<i64>>),
}

/// Read `take` records of one column starting at record `skip`,
/// page-skipping everything before it.
fn read_column<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    col: usize,
    skip: usize,
    take: usize,
) -> Result<ColValues> {
    use parquet::basic::Type;
    let rg = meta.row_group(rgi);
    let locations = page_locations(meta, rgi, col);
    let max_def = meta_column(rg, col).max_def_level();
    macro_rules! read {
        ($t:ty, $conv:expr) => {{
            let mut r = typed_reader::<R, $t>(reader, rg, col, locations.clone())?;
            if skip > 0 {
                r.skip_records(skip)?;
            }
            let mut vals = Vec::new();
            let mut defs: Vec<i16> = Vec::new();
            let mut out = Vec::with_capacity(take);
            while out.len() < take {
                vals.clear();
                defs.clear();
                let (records, _, _) =
                    r.read_records(take - out.len(), Some(&mut defs), None, &mut vals)?;
                if records == 0 {
                    break;
                }
                defs.resize(records, max_def); // required cols fill no def levels
                let mut vi = 0;
                for &d in defs.iter().take(records) {
                    if d == max_def {
                        out.push(Some($conv(&vals[vi])));
                        vi += 1;
                    } else {
                        out.push(None);
                    }
                }
            }
            out
        }};
    }
    Ok(match meta_column(rg, col).physical_type() {
        Type::BYTE_ARRAY => {
            ColValues::Str(read!(ByteArrayType, |v: &parquet::data_type::ByteArray| {
                String::from_utf8_lossy(v.data()).into_owned()
            }))
        }
        Type::INT32 => ColValues::I32(read!(Int32Type, |v: &i32| *v)),
        Type::INT64 => ColValues::I64(read!(Int64Type, |v: &i64| *v)),
        t => anyhow::bail!("unsupported column type {t}"),
    })
}

/// Point lookup in a parquet file sorted by `key_col`: rows (as JSON
/// objects of the requested columns) whose key equals `key`, plus the
/// total number of matching rows.
fn find_rows<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    key_col: &str,
    cols: &[&str],
    key: &str,
    cap: usize,
) -> Result<(Vec<Value>, usize)> {
    let kidx = column_index(meta, key_col)?;
    let mut rows = Vec::new();
    let mut total = 0usize;
    for rgi in candidate_row_groups(meta, kidx, key.as_bytes()) {
        let rg = meta.row_group(rgi);
        let Some((first, count)) = scan_key_column(reader, meta, rgi, kidx, key.as_bytes())? else {
            continue;
        };
        total += count;
        let take = count.min(cap.saturating_sub(rows.len()));
        if take == 0 {
            continue;
        }
        let mut objs: Vec<serde_json::Map<String, Value>> = vec![serde_json::Map::new(); take];
        // One thread per column: each is a chain of ranged reads, so
        // the wall clock is the slowest column, not the sum.
        let col_vals: Vec<(&str, Result<ColValues>)> = std::thread::scope(|s| {
            let handles: Vec<_> = cols
                .iter()
                .map(|name| {
                    s.spawn(move || {
                        let cidx = column_index(meta, name)?;
                        // Whole-chunk prefetch only pays off when there
                        // is no offset index to seek by.
                        if meta.offset_index().is_none() {
                            let (start, len) = rg.column(cidx).byte_range();
                            if len <= PREFETCH_MAX {
                                let _ = reader.get_bytes(start, len as usize)?;
                            }
                        }
                        read_column(reader, meta, rgi, cidx, first, take)
                    })
                })
                .collect();
            cols.iter()
                .zip(handles)
                .map(|(name, h)| (*name, h.join().expect("column reader panicked")))
                .collect()
        });
        for (name, vals) in col_vals {
            let vals = vals?;
            for (i, obj) in objs.iter_mut().enumerate() {
                let v = match &vals {
                    ColValues::Str(v) => v[i].as_ref().map_or(Value::Null, |s| json!(s)),
                    ColValues::I32(v) => v[i].map_or(Value::Null, |n| json!(n)),
                    ColValues::I64(v) => v[i].map_or(Value::Null, |n| json!(n)),
                };
                obj.insert(name.to_string(), v);
            }
        }
        for mut obj in objs {
            obj.insert(key_col.to_string(), json!(key));
            rows.push(Value::Object(obj));
        }
    }
    Ok((rows, total))
}

// ------------------------------------------------------------------ lookup

const DATA_COLS: &[&str] = &[
    "title",
    "release_year",
    "container_name",
    "doi",
    "arxiv",
    "wayback_url",
    "sha1",
    "md5",
];

fn data_path(sha256: &str) -> String {
    format!("data/files-{}.parquet", &sha256[..1])
}

fn hex(coord: &Coord) -> String {
    coord.digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Open every remote file a probe batch will certainly need, in
/// parallel and outside any per-probe timeout. Cold opens (an 8 MB
/// suffix request each) are the bulk of a first-contact batch's
/// work; inside probe budgets they starved probes queued behind them
/// (241/596 timed out on the first full-Dropbox run). Weak digests
/// fan out to data files only known after the map lookup — those
/// still open lazily, one single-flighted open per file.
pub fn preopen(coords: &[Coord]) {
    let mut paths = HashSet::new();
    for c in coords {
        match c.scheme {
            Scheme::Sha256 => {
                paths.insert(data_path(&hex(c)));
            }
            Scheme::Sha1 => {
                paths.insert("maps/sha1.parquet".to_string());
            }
            Scheme::Md5 => {
                paths.insert("maps/md5.parquet".to_string());
            }
            _ => {}
        }
    }
    std::thread::scope(|s| {
        for p in &paths {
            s.spawn(move || {
                let _ = open_remote(p); // probes retry and report errors
            });
        }
    });
}

fn blocking_lookup(coord: &Coord) -> Result<Option<Finding>> {
    let hex: String = coord.digest.iter().map(|b| format!("{b:02x}")).collect();
    // Weak digests go through the sorted maps to sha256 first.
    let sha256s: Vec<String> = match coord.scheme {
        Scheme::Sha256 => vec![hex],
        Scheme::Sha1 | Scheme::Md5 => {
            let scheme = if coord.scheme == Scheme::Sha1 {
                "sha1"
            } else {
                "md5"
            };
            let file = open_remote(&format!("maps/{scheme}.parquet"))?;
            let (rows, _) = find_rows(&file.remote, &file.meta, scheme, &["sha256"], &hex, 8)?;
            let mut v: Vec<String> = rows
                .iter()
                .filter_map(|r| r["sha256"].as_str().map(str::to_string))
                .collect();
            v.dedup();
            v.truncate(3); // weak-digest collisions are rendered, not merged
            v
        }
        _ => return Ok(None),
    };
    if sha256s.is_empty() {
        return Ok(None);
    }

    let mut rows = Vec::new();
    let mut total = 0usize;
    for sha in &sha256s {
        let file = open_remote(&data_path(sha))?;
        let (mut r, t) = find_rows(&file.remote, &file.meta, "sha256", DATA_COLS, sha, MAX_ROWS)?;
        rows.append(&mut r);
        total += t;
    }
    if rows.is_empty() {
        return Ok(None);
    }
    let mut claims: Vec<Claim> = rows.iter().take(SHOWN).map(claim).collect();
    if total > SHOWN {
        claims.push(Claim::new(
            format!("… and {} more releases", total - SHOWN),
            None,
        ));
    }
    // Each dataset row is a single witness carrying all three digests —
    // exactly the multi-hash row the edge-minting rule admits.
    let coords = ["sha1", "sha256", "md5"]
        .iter()
        .filter_map(|s| {
            let hex = rows[0][*s].as_str()?;
            Some(format!("{s}:{hex}"))
        })
        .collect();
    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords,
    }))
}

pub async fn lookup(_client: &reqwest::Client, coord: &Coord) -> Result<Option<Finding>> {
    let coord = coord.clone();
    tokio::task::spawn_blocking(move || blocking_lookup(&coord)).await?
}

fn claim(row: &Value) -> Claim {
    let mut statement = format!(
        "scholarly file: \"{}\"",
        row["title"].as_str().unwrap_or("(untitled)")
    );
    if let Some(year) = row["release_year"].as_i64() {
        statement.push_str(&format!(" ({year})"));
    }
    if let Some(venue) = row["container_name"].as_str() {
        statement.push_str(&format!(", {venue}"));
    }
    let doi = row["doi"].as_str();
    let arxiv = row["arxiv"].as_str();
    if let Some(doi) = doi {
        statement.push_str(&format!(", doi:{doi}"));
    } else if let Some(arxiv) = arxiv {
        statement.push_str(&format!(", arXiv:{arxiv}"));
    }
    let url = row["wayback_url"]
        .as_str()
        .map(str::to_string)
        .or_else(|| doi.map(|d| format!("https://doi.org/{d}")))
        .or_else(|| arxiv.map(|a| format!("https://arxiv.org/abs/{a}")));
    Claim::new(statement, url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Bytes, not File: File's ChunkReader dups the fd, whose shared
    // seek position races under the parallel column reads.
    fn fixture(name: &str) -> Option<(Arc<Bytes>, Arc<ParquetMetaData>)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/fatcat")
            .join(name);
        let bytes = Bytes::from(std::fs::read(path).ok()?);
        let meta = ParquetMetaDataReader::new().parse_and_finish(&bytes).ok()?;
        Some((Arc::new(bytes), Arc::new(meta)))
    }

    /// In-memory reader that counts every data byte handed out, so
    /// tests can assert what the page index saves us from reading.
    struct Counting {
        inner: Bytes,
        read: Arc<AtomicUsize>,
    }

    struct CountingRead {
        inner: Bytes,
        read: Arc<AtomicUsize>,
    }

    impl Read for CountingRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.len().min(buf.len());
            buf[..n].copy_from_slice(&self.inner.split_to(n));
            self.read.fetch_add(n, Ordering::Relaxed);
            Ok(n)
        }
    }

    impl Length for Counting {
        fn len(&self) -> u64 {
            self.inner.len() as u64
        }
    }

    impl ChunkReader for Counting {
        type T = CountingRead;
        fn get_read(&self, start: u64) -> parquet::errors::Result<CountingRead> {
            Ok(CountingRead {
                inner: self.inner.slice(start as usize..),
                read: Arc::clone(&self.read),
            })
        }
        fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
            self.read.fetch_add(length, Ordering::Relaxed);
            Ok(self.inner.slice(start as usize..start as usize + length))
        }
    }

    /// The page-indexed fixtures (tools/make_fatcat_fixtures.py). The
    /// footer MUST carry the index — Required, not Optional — so a
    /// regressed generator fails loudly instead of silently testing
    /// the fallback path twice.
    fn fixture_pi(name: &str) -> Option<(Arc<Counting>, Arc<AtomicUsize>, Arc<ParquetMetaData>)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/fatcat")
            .join(name);
        let bytes = Bytes::from(std::fs::read(path).ok()?);
        let meta = ParquetMetaDataReader::new()
            .with_page_index_policy(PageIndexPolicy::Required)
            .parse_and_finish(&bytes)
            .expect("page-indexed fixture must carry offset+column indexes");
        let read = Arc::new(AtomicUsize::new(0));
        let counting = Arc::new(Counting {
            inner: bytes,
            read: Arc::clone(&read),
        });
        Some((counting, read, Arc::new(meta)))
    }

    /// key(i) from tools/make_fatcat_fixtures.py.
    fn key(i: u64) -> String {
        format!("{:064x}", i * 16 + 8)
    }

    /// A key strictly between page 0's max and page 1's min in the
    /// first row group: admitted by row-group stats, by no page.
    fn page_gap_key(meta: &ParquetMetaData, kidx: usize) -> String {
        let Some(ColumnIndexMetaData::BYTE_ARRAY(ix)) = meta.column_index().unwrap()[0].get(kidx)
        else {
            panic!("no byte-array column index on the key column")
        };
        let max0 = std::str::from_utf8(ix.max_value(0).unwrap()).unwrap();
        let tail = u64::from_str_radix(&max0[max0.len() - 16..], 16).unwrap();
        format!("{:064x}", tail + 8)
    }

    #[test]
    fn page_index_point_lookup() {
        let Some((file, read, meta)) = fixture_pi("files_pi.parquet") else {
            return; // fixture not generated on this machine
        };

        // Straddle key: two releases across the rg0/rg1 boundary.
        let k = key(1999);
        let (rows, total) = find_rows(&file, &meta, "sha256", DATA_COLS, &k, MAX_ROWS).unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows[0]["title"].as_str(), Some("Straddle One"));
        assert_eq!(rows[1]["doi"].as_str(), Some("10.1234/straddle-two"));

        // The point of the page index: a small fraction of the file
        // read, not whole column chunks.
        let bytes_read = read.load(Ordering::Relaxed);
        let total_bytes: i64 = meta
            .row_groups()
            .iter()
            .map(|rg| rg.compressed_size())
            .sum();
        assert!(
            (bytes_read as i64) * 5 < total_bytes,
            "read {bytes_read} of {total_bytes} compressed bytes"
        );

        // One key, 41 releases spanning several pages: honest count.
        let (rows, total) =
            find_rows(&file, &meta, "sha256", DATA_COLS, &key(3999), MAX_ROWS).unwrap();
        assert_eq!(total, 41);
        assert_eq!(rows[40]["title"].as_str(), Some("Many Releases 40"));

        // Admitted by a page but absent: settled by reading pages.
        let absent = format!("{:064x}", 16u64); // between key(0) and key(1)
        let (rows, total) =
            find_rows(&file, &meta, "sha256", DATA_COLS, &absent, MAX_ROWS).unwrap();
        assert!(rows.is_empty() && total == 0);

        // Falling between two pages: absence proven from the footer
        // alone — zero data bytes fetched.
        let kidx = column_index(&meta, "sha256").unwrap();
        let gap = page_gap_key(&meta, kidx);
        let before = read.load(Ordering::Relaxed);
        let (rows, total) = find_rows(&file, &meta, "sha256", DATA_COLS, &gap, MAX_ROWS).unwrap();
        assert!(rows.is_empty() && total == 0);
        assert_eq!(
            read.load(Ordering::Relaxed),
            before,
            "between-pages absence must not read data"
        );
    }

    #[test]
    fn page_index_weak_digest_map() {
        let Some((file, _read, meta)) = fixture_pi("sha1_map_pi.parquet") else {
            return;
        };
        let sha1 = format!("{:040x}", 1999);
        let (rows, _) = find_rows(&file, &meta, "sha1", &["sha256"], &sha1, 8).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["sha256"].as_str(), Some(key(1999).as_str()));
    }

    #[test]
    fn fixture_point_lookup() {
        let Some((file, meta)) = fixture("files.parquet") else {
            return; // fixture not generated on this machine
        };
        // Key present with two releases (rows straddle a row-group edge).
        let key = "aa".repeat(32);
        let (rows, total) = find_rows(&file, &meta, "sha256", DATA_COLS, &key, MAX_ROWS).unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["title"].as_str(), Some("Straddle Paper"));
        assert_eq!(rows[0]["sha1"].as_str(), Some("11".repeat(20).as_str()));
        assert_eq!(rows[1]["doi"].as_str(), Some("10.1234/second"));
        // Null columns render as JSON null, not a crash.
        assert!(rows[1]["container_name"].is_null());
        let c = claim(&rows[0]);
        assert!(c.statement.contains("Straddle Paper"));
        assert!(c.url.as_deref().unwrap().contains("web.archive.org"));

        // Absent key: no candidate row group admits it.
        let (rows, total) = find_rows(
            &file,
            &meta,
            "sha256",
            DATA_COLS,
            &"00".repeat(32),
            MAX_ROWS,
        )
        .unwrap();
        assert!(rows.is_empty() && total == 0);

        // Present nibble range but absent key: scan returns nothing.
        let (rows, _) = find_rows(
            &file,
            &meta,
            "sha256",
            DATA_COLS,
            &"ab".repeat(32),
            MAX_ROWS,
        )
        .unwrap();
        assert!(rows.is_empty());
    }

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

    #[test]
    fn fixture_weak_digest_map() {
        let Some((file, meta)) = fixture("sha1_map.parquet") else {
            return;
        };
        let (rows, _) = find_rows(&file, &meta, "sha1", &["sha256"], &"11".repeat(20), 8).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["sha256"].as_str(), Some("aa".repeat(32).as_str()));
    }
}
