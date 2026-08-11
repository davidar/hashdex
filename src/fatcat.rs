//! The fatcat scholarly file index, transport-free: dataset identity,
//! digest→file routing, claim rendering, and the lookup driver. The
//! native backend (`backends::fatcat`) drives this over blocking HTTP
//! range reads with a disk cache; a wasm build drives it over fetch.
//!
//! The dataset is the final fatcat bulk export (2024-02-18),
//! republished as parquet sorted by sha256 (weak-digest maps sorted by
//! their key). fatcat.wiki is offline, so the claim URLs are the ones
//! that still resolve: the wayback capture of the hashed bytes first,
//! then the DOI.

use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use crate::parquet_index::find_rows;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use serde_json::Value;
use std::sync::Arc;

pub const NAME: &str = "fatcat";

pub const DATASET_BASE: &str = "https://huggingface.co/datasets/david-ar/fatcat-files/resolve";
pub const REVISION_API: &str =
    "https://huggingface.co/api/datasets/david-ar/fatcat-files/revision/main";
const SHOWN: usize = 5;
/// Releases read per digest (claims render at most SHOWN; the rest is
/// only counted). Bounds pathological many-release files.
pub const MAX_ROWS: usize = 50;

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256)
}

pub const DATA_COLS: &[&str] = &[
    "title",
    "release_year",
    "container_name",
    "doi",
    "arxiv",
    "wayback_url",
    "sha1",
    "md5",
];

/// Repo-relative path of the data file holding `sha256` (keyed by its
/// first nibble).
pub fn data_path(sha256: &str) -> String {
    format!("data/files-{}.parquet", &sha256[..1])
}

/// Repo-relative paths a lookup of `coord` starts in (the weak-digest
/// fan-out to data files is only known after the map lookup).
pub fn start_paths(coord: &Coord) -> Vec<String> {
    match coord.scheme {
        Scheme::Sha256 => vec![data_path(&hex(coord))],
        Scheme::Sha1 => vec!["maps/sha1.parquet".to_string()],
        Scheme::Md5 => vec!["maps/md5.parquet".to_string()],
        _ => vec![],
    }
}

fn hex(coord: &Coord) -> String {
    coord.digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The whole lookup, generic over how a repo-relative path becomes a
/// readable file: weak digests go through the sorted maps to sha256
/// first, then the data files yield claims.
pub fn lookup_with<R, F>(open: F, coord: &Coord) -> Result<Option<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    let hex = hex(coord);
    let sha256s: Vec<String> = match coord.scheme {
        Scheme::Sha256 => vec![hex],
        Scheme::Sha1 | Scheme::Md5 => {
            let scheme = if coord.scheme == Scheme::Sha1 {
                "sha1"
            } else {
                "md5"
            };
            let (reader, meta) = open(&format!("maps/{scheme}.parquet"))?;
            let (rows, _) = find_rows(&reader, &meta, scheme, &["sha256"], &hex, 8)?;
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
        let (reader, meta) = open(&data_path(sha))?;
        let (mut r, t) = find_rows(&reader, &meta, "sha256", DATA_COLS, sha, MAX_ROWS)?;
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

pub fn claim(row: &Value) -> Claim {
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
    use crate::parquet_index::column_index;
    use bytes::Bytes;
    use parquet::file::metadata::{PageIndexPolicy, ParquetMetaDataReader};
    use parquet::file::page_index::column_index::ColumnIndexMetaData;
    use parquet::file::reader::Length;
    use std::io::Read;
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
    fn fixture_weak_digest_map() {
        let Some((file, meta)) = fixture("sha1_map.parquet") else {
            return;
        };
        let (rows, _) = find_rows(&file, &meta, "sha1", &["sha256"], &"11".repeat(20), 8).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["sha256"].as_str(), Some("aa".repeat(32).as_str()));
    }
}
