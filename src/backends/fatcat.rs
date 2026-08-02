use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::{Context, Result};
use bytes::Bytes;
use parquet::column::reader::{get_typed_column_reader, ColumnReaderImpl};
use parquet::data_type::{ByteArrayType, DataType, Int32Type, Int64Type};
use parquet::file::metadata::{ParquetMetaData, ParquetMetaDataReader, RowGroupMetaData};
use parquet::file::reader::{ChunkReader, Length};
use parquet::file::serialized_reader::SerializedPageReader;
use parquet::file::statistics::Statistics;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock};

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
const DATASET_URL: &str = "https://huggingface.co/datasets/david-ar/fatcat-files/resolve/main";
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
    len: u64,
    /// Fetched ranges keyed by start offset. Ranges may overlap; a
    /// lookup is served by any single cached range that covers it.
    /// Cleared wholesale past CACHE_MAX so batch scans stay bounded —
    /// the footer is already parsed, so eviction only costs refetches.
    cache: Mutex<BTreeMap<u64, Bytes>>,
}

/// Per-file cap on cached range bytes (17 data files + 2 maps can be
/// open at once in a scan).
const CACHE_MAX: usize = 96 << 20;

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

impl RemoteInner {
    fn fetch(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        let end = start + length as u64 - 1;
        let resp = self
            .client
            .get(&self.url)
            .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
            .send()
            .and_then(|r| r.error_for_status())
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

    fn cached(&self, start: u64, length: usize) -> Option<Bytes> {
        let cache = self.cache.lock().unwrap();
        let (&s, b) = cache.range(..=start).next_back()?;
        let off = (start - s) as usize;
        if b.len() >= off + length {
            Some(b.slice(off..off + length))
        } else {
            None
        }
    }

    /// Cache-through read of an exact range.
    fn read_range(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }
        if let Some(b) = self.cached(start, length) {
            return Ok(b);
        }
        let b = self.fetch(start, length)?;
        let mut cache = self.cache.lock().unwrap();
        if cache.values().map(Bytes::len).sum::<usize>() + b.len() > CACHE_MAX {
            cache.clear();
        }
        cache.insert(start, b.clone());
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
    static FILES: OnceLock<Mutex<HashMap<String, Arc<RemoteFile>>>> = OnceLock::new();
    let files = FILES.get_or_init(Default::default);
    if let Some(f) = files.lock().unwrap().get(path) {
        return Ok(Arc::clone(f));
    }
    let url = format!("{DATASET_URL}/{path}");
    // File length via a 1-byte range probe: HEAD on the resolve URL
    // redirects to a CDN that doesn't always answer HEAD usefully.
    let resp = http()
        .get(&url)
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()?
        .error_for_status()?;
    let len: u64 = resp
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit('/').next())
        .and_then(|v| v.parse().ok())
        .with_context(|| format!("no content-range from {url}"))?;
    let remote = Arc::new(Remote {
        inner: Arc::new(RemoteInner {
            client: http().clone(),
            url,
            len,
            cache: Mutex::new(BTreeMap::new()),
        }),
    });
    let meta = ParquetMetaDataReader::new().parse_and_finish(remote.as_ref())?;
    let file = Arc::new(RemoteFile {
        remote,
        meta: Arc::new(meta),
    });
    files
        .lock()
        .unwrap()
        .insert(path.to_string(), Arc::clone(&file));
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

fn typed_reader<R: ChunkReader + 'static, T: DataType>(
    reader: &Arc<R>,
    rg: &RowGroupMetaData,
    col: usize,
) -> Result<ColumnReaderImpl<T>> {
    let pages = SerializedPageReader::new(
        Arc::clone(reader),
        rg.column(col),
        rg.num_rows() as usize,
        None,
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
/// or first greater value). The whole key chunk is fetched up front in
/// one ranged request — it gets decoded anyway.
fn scan_key_column<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    rg: &RowGroupMetaData,
    col: usize,
    key: &[u8],
) -> Result<Option<(usize, usize)>> {
    let (start, len) = rg.column(col).byte_range();
    let _ = reader.get_bytes(start, len as usize)?; // warm the range cache
    let mut r = typed_reader::<R, ByteArrayType>(reader, rg, col)?;
    let max_def = meta_column(rg, col).max_def_level();
    let (mut record, mut first, mut count) = (0usize, None, 0usize);
    loop {
        let mut vals = Vec::new();
        let mut defs: Vec<i16> = Vec::new();
        let (records, _, _) = r.read_records(4096, Some(&mut defs), None, &mut vals)?;
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
    rg: &RowGroupMetaData,
    col: usize,
    skip: usize,
    take: usize,
) -> Result<ColValues> {
    use parquet::basic::Type;
    let max_def = meta_column(rg, col).max_def_level();
    macro_rules! read {
        ($t:ty, $conv:expr) => {{
            let mut r = typed_reader::<R, $t>(reader, rg, col)?;
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
        let Some((first, count)) = scan_key_column(reader, rg, kidx, key.as_bytes())? else {
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
                        let (start, len) = rg.column(cidx).byte_range();
                        if len <= PREFETCH_MAX {
                            let _ = reader.get_bytes(start, len as usize)?;
                        }
                        read_column(reader, rg, cidx, first, take)
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
    fn fixture_weak_digest_map() {
        let Some((file, meta)) = fixture("sha1_map.parquet") else {
            return;
        };
        let (rows, _) = find_rows(&file, &meta, "sha1", &["sha256"], &"11".repeat(20), 8).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["sha256"].as_str(), Some("aa".repeat(32).as_str()));
    }
}
