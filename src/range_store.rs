//! An in-memory [`ChunkReader`] over ranges fetched so far, for
//! drivers whose transport can't block inside a read — a browser's
//! fetch is async-only, while parquet decoding is synchronous. A read
//! that touches unfetched bytes records the missing range and fails;
//! the driver fetches it, [`insert`](RangeStore::insert)s, and retries
//! the decode. With page-indexed files a lookup converges in a handful
//! of round trips (footer suffix, key pages, claim pages), and a
//! driver that prefetches those ranges up front decodes in one pass —
//! the miss path is the correctness backstop, not the plan.
//!
//! No eviction: a store lives for one lookup session and holds only
//! the ranges lookups actually touched (KBs to a few MB per file).

use bytes::Bytes;
use parquet::file::reader::{ChunkReader, Length};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Default for [`RangeStore::new`]: reads below this are rounded up on
/// a miss, so a run of small pages costs one round trip, not one each.
const FETCH_BLOCK: usize = 64 << 10;

#[derive(Clone)]
pub struct RangeStore {
    inner: Arc<Inner>,
}

struct Inner {
    len: u64,
    fetch_block: usize,
    ranges: Mutex<BTreeMap<u64, Bytes>>,
    /// The range the last failing read needed. A failing decode stops
    /// at its first miss, so one slot is enough; the driver takes it,
    /// fetches, inserts, retries.
    miss: Mutex<Option<(u64, usize)>>,
}

impl RangeStore {
    /// `len` is the remote file's total length (a cold open learns it
    /// from the Content-Range of a suffix request).
    pub fn new(len: u64) -> RangeStore {
        Self::with_fetch_block(len, FETCH_BLOCK)
    }

    /// A store whose misses round up to `fetch_block` — the round-trip
    /// vs bytes-per-trip trade is the driver's to make.
    pub fn with_fetch_block(len: u64, fetch_block: usize) -> RangeStore {
        RangeStore {
            inner: Arc::new(Inner {
                len,
                fetch_block,
                ranges: Mutex::new(BTreeMap::new()),
                miss: Mutex::new(None),
            }),
        }
    }

    /// Make `[start, start+bytes.len())` readable.
    pub fn insert(&self, start: u64, bytes: Bytes) {
        self.inner.ranges.lock().unwrap().insert(start, bytes);
    }

    /// The range the last failing read needed, clearing it.
    pub fn take_miss(&self) -> Option<(u64, usize)> {
        self.inner.miss.lock().unwrap().take()
    }

    /// Total bytes held (diagnostics: what a lookup actually cost).
    pub fn bytes_held(&self) -> usize {
        self.inner
            .ranges
            .lock()
            .unwrap()
            .values()
            .map(Bytes::len)
            .sum()
    }
}

impl Inner {
    fn cached(&self, start: u64, length: usize) -> Option<Bytes> {
        let ranges = self.ranges.lock().unwrap();
        let (&s, b) = ranges.range(..=start).next_back()?;
        let off = (start - s) as usize;
        (b.len() >= off + length).then(|| b.slice(off..off + length))
    }

    fn miss(&self, start: u64, length: usize) -> parquet::errors::ParquetError {
        // Round small reads up to a block — page-index seeks read each
        // page exactly, and pages can be tiny; without rounding every
        // page is its own round trip. Never ask past EOF though: the
        // decoder legitimately reads up to the end of the file, and a
        // ranged GET past it would 416.
        let length = length
            .max(self.fetch_block)
            .min(self.len.saturating_sub(start) as usize)
            .max(length);
        *self.miss.lock().unwrap() = Some((start, length));
        parquet::errors::ParquetError::External(
            format!("range [{start}, +{length}) not fetched yet").into(),
        )
    }
}

impl Length for RangeStore {
    fn len(&self) -> u64 {
        self.inner.len
    }
}

/// Sequential cursor for page reads; misses request whole
/// [`FETCH_BLOCK`]s.
pub struct StoreCursor {
    inner: Arc<Inner>,
    pos: u64,
}

impl std::io::Read for StoreCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.inner.len || buf.is_empty() {
            return Ok(0);
        }
        let avail = (self.inner.len - self.pos).min(buf.len() as u64) as usize;
        // Serve as much as the covering range holds, up to avail.
        let mut n = avail;
        let got = loop {
            if let Some(b) = self.inner.cached(self.pos, n) {
                break b;
            }
            n /= 2;
            if n == 0 {
                return Err(std::io::Error::other(self.inner.miss(self.pos, avail)));
            }
        };
        buf[..got.len()].copy_from_slice(&got);
        self.pos += got.len() as u64;
        Ok(got.len())
    }
}

impl ChunkReader for RangeStore {
    type T = StoreCursor;

    fn get_read(&self, start: u64) -> parquet::errors::Result<StoreCursor> {
        Ok(StoreCursor {
            inner: Arc::clone(&self.inner),
            pos: start,
        })
    }

    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }
        self.inner
            .cached(start, length)
            .ok_or_else(|| self.inner.miss(start, length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord::Coord;
    use crate::fatcat;
    use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The browser driver in miniature: a "remote" file served from a
    /// byte slice, fetched range by range as the store asks for them.
    struct Driver {
        file: Bytes,
        store: RangeStore,
        round_trips: AtomicUsize,
        fetched: AtomicUsize,
    }

    /// Cold-open speculative suffix and fetch block, scaled to the
    /// ~300 KB fixtures (the real driver uses an 8 MB suffix and
    /// 64 KiB blocks against the multi-GB published files).
    const SUFFIX: usize = 16 << 10;
    const BLOCK: usize = 4 << 10;

    impl Driver {
        fn open(file: Bytes) -> Driver {
            let d = Driver {
                store: RangeStore::with_fetch_block(file.len() as u64, BLOCK),
                file,
                round_trips: AtomicUsize::new(0),
                fetched: AtomicUsize::new(0),
            };
            // One suffix request answers length + footer + page index.
            let start = d.file.len().saturating_sub(SUFFIX);
            d.fetch(start as u64, SUFFIX);
            d
        }

        fn fetch(&self, start: u64, length: usize) {
            let start = start as usize;
            let end = (start + length).min(self.file.len());
            self.round_trips.fetch_add(1, Ordering::Relaxed);
            self.fetched.fetch_add(end - start, Ordering::Relaxed);
            self.store.insert(start as u64, self.file.slice(start..end));
        }

        /// Retry a decode until the store stops reporting misses —
        /// exactly what the async wasm driver does with awaited
        /// fetches in place of `fetch`.
        fn drive<T>(&self, mut attempt: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
            for _ in 0..64 {
                match attempt() {
                    Ok(v) => return Ok(v),
                    Err(e) => match self.store.take_miss() {
                        Some((start, len)) => self.fetch(start, len),
                        None => return Err(e),
                    },
                }
            }
            anyhow::bail!("lookup did not converge in 64 round trips")
        }

        fn metadata(&self) -> anyhow::Result<Arc<ParquetMetaData>> {
            let meta = self.drive(|| {
                Ok(ParquetMetaDataReader::new()
                    .with_page_index_policy(PageIndexPolicy::Required)
                    .parse_and_finish(&self.store)?)
            })?;
            Ok(Arc::new(meta))
        }
    }

    fn fixture(name: &str) -> Option<Bytes> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/fatcat")
            .join(name);
        Some(Bytes::from(std::fs::read(path).ok()?))
    }

    /// End-to-end proof of the browser model: the full fatcat lookup
    /// (weak digest → map → data file → claims) running over stores
    /// that only ever receive ranges they asked for, converging in few
    /// round trips and reading a small fraction of the files.
    #[test]
    fn fatcat_lookup_over_range_store() {
        let (Some(files), Some(map)) =
            (fixture("files_pi.parquet"), fixture("sha1_map_pi.parquet"))
        else {
            return; // fixtures not generated on this machine
        };
        let total_len = files.len() + map.len();
        let files = Driver::open(files);
        let map = Driver::open(map);
        let files_meta = files.metadata().unwrap();
        let map_meta = map.metadata().unwrap();

        let open = |path: &str| match path {
            "maps/sha1.parquet" => Ok((Arc::new(map.store.clone()), Arc::clone(&map_meta))),
            p if p.starts_with("data/files-") => {
                Ok((Arc::new(files.store.clone()), Arc::clone(&files_meta)))
            }
            p => anyhow::bail!("unexpected open of {p}"),
        };

        // sha1 of row 1999 (tools/make_fatcat_fixtures.py key scheme);
        // resolves via the map to sha256 key(1999), a straddle key
        // with two releases.
        let sha1 = format!("{:040x}", 1999);
        let coord = Coord::parse(&format!("sha1:{sha1}")).unwrap();
        let finding = map
            .drive(|| files.drive(|| fatcat::lookup_with(open, &coord)))
            .unwrap()
            .expect("known digest must resolve");

        assert_eq!(finding.backend, "fatcat");
        assert!(finding.claims[0].statement.contains("Straddle One"));
        assert!(finding
            .coords
            .iter()
            .any(|c| c == &format!("sha256:{:064x}", 1999 * 16 + 8)));

        // The fixtures' tiny pages make their page-index region and
        // dictionary pages disproportionately large (the published
        // dataset uses 128 KiB pages and no dictionaries), so the
        // meaningful bounds are convergence and never reading the
        // files wholesale — the ratio is fixture geometry.
        let round_trips =
            map.round_trips.load(Ordering::Relaxed) + files.round_trips.load(Ordering::Relaxed);
        let fetched = map.fetched.load(Ordering::Relaxed) + files.fetched.load(Ordering::Relaxed);
        assert!(round_trips <= 24, "too chatty: {round_trips} round trips");
        assert!(
            fetched < total_len,
            "read {fetched} of {total_len} bytes — range reads defeated"
        );

        // A key that falls between pages: absence is proven from the
        // already-held footer alone — ZERO further round trips.
        let before = files.round_trips.load(Ordering::Relaxed);
        let gap = Coord::parse(&format!("sha256:{:064x}", 16u64 * 16)).unwrap();
        let miss = files.drive(|| fatcat::lookup_with(open, &gap)).unwrap();
        assert!(miss.is_none());
        assert_eq!(
            files.round_trips.load(Ordering::Relaxed),
            before,
            "between-pages absence must not fetch"
        );
    }
}
