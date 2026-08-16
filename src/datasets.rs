//! The published claim datasets (page-indexed parquet on the Hub) and
//! their local copies. Resolution range-reads the published files by
//! default; `hdx index pull <name>` downloads a dataset into
//! `~/.cache/hashdex/datasets/<name>/` (mirroring the repo layout) and
//! lookups then run over an mmap of the very same parquet — one wire
//! format, two transports.

use crate::coord::Coord;
use crate::finding::Finding;
use anyhow::{Context, Result};
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};
use parquet::file::reader::{ChunkReader, Length};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once, OnceLock};

// Identity and routing (Spec, SPECS, lookup_in, …) live in the core
// registry — the single source of truth the web page also enumerates.
// This module owns only the local transport: pulled copies on disk.
pub use crate::registry::{
    is_dataset, lookup_in, spec, Spec, CENSUS, DEBS, FATCAT, MEDIA, RPM_FILES, SPECS, TARBALLS,
};

pub fn datasets_dir() -> PathBuf {
    crate::cache::cache_dir().join("datasets")
}

// -------------------------------------------------------------- local

/// A parquet file mmap'd whole, served as a [`ChunkReader`]. Probes
/// are random (same lesson as `Bloom::open`): without `Advice::Random`
/// readahead turns each page read into much larger I/O on datasets
/// bigger than RAM.
pub struct MmapReader(Arc<memmap2::Mmap>);

pub struct MmapCursor {
    mmap: Arc<memmap2::Mmap>,
    pos: usize,
}

impl std::io::Read for MmapCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.mmap.len().saturating_sub(self.pos));
        buf[..n].copy_from_slice(&self.mmap[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Length for MmapReader {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
}

impl ChunkReader for MmapReader {
    type T = MmapCursor;

    fn get_read(&self, start: u64) -> parquet::errors::Result<MmapCursor> {
        Ok(MmapCursor {
            mmap: Arc::clone(&self.0),
            pos: start as usize,
        })
    }

    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<bytes::Bytes> {
        let (start, end) = (start as usize, start as usize + length);
        if end > self.0.len() {
            return Err(parquet::errors::ParquetError::EOF(format!(
                "range {start}..{end} past mmap end {}",
                self.0.len()
            )));
        }
        Ok(bytes::Bytes::copy_from_slice(&self.0[start..end]))
    }
}

type OpenedFile = (Arc<MmapReader>, Arc<ParquetMetaData>);

/// A pulled dataset: the repo's parquet files on local disk, opened
/// (mmap + footer parse) lazily and memoized for the process.
pub struct LocalDataset {
    pub spec: &'static Spec,
    dir: PathBuf,
    files: Mutex<HashMap<String, OpenedFile>>,
    warned: Once,
}

impl LocalDataset {
    /// Present only when a pull COMPLETED: the `revision` file is
    /// written last, so an interrupted download never masquerades as
    /// an installed dataset.
    fn open(spec: &'static Spec) -> Option<LocalDataset> {
        let dir = datasets_dir().join(spec.name);
        dir.join("revision").is_file().then(|| LocalDataset {
            spec,
            dir,
            files: Mutex::new(HashMap::new()),
            warned: Once::new(),
        })
    }

    pub fn revision(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("revision"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn open_file(&self, path: &str) -> Result<OpenedFile> {
        let mut files = self.files.lock().unwrap();
        if let Some((r, m)) = files.get(path) {
            return Ok((Arc::clone(r), Arc::clone(m)));
        }
        let full = self.dir.join(path);
        let file =
            std::fs::File::open(&full).with_context(|| format!("open {}", full.display()))?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        let _ = mmap.advise(memmap2::Advice::Random);
        let reader = Arc::new(MmapReader(Arc::new(mmap)));
        let meta = Arc::new(
            ParquetMetaDataReader::new()
                .with_page_index_policy(PageIndexPolicy::Optional)
                .parse_and_finish(reader.as_ref())
                .with_context(|| format!("parse {}", full.display()))?,
        );
        files.insert(path.to_string(), (Arc::clone(&reader), Arc::clone(&meta)));
        Ok((reader, meta))
    }

    /// Witness findings for this digest from the local copy. Errors
    /// warn once per dataset (a corrupt pull must not kill the walk)
    /// and read as no evidence.
    pub fn lookup(&self, coord: &Coord) -> Vec<Finding> {
        match lookup_in(self.spec.name, |p| self.open_file(p), coord) {
            Ok(v) => v,
            // A data file the routing named but the repo doesn't hold
            // (a key-range shard with no rows) is absence, not failure.
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                Vec::new()
            }
            Err(e) => {
                self.warned.call_once(|| {
                    eprintln!(
                        "warning: local {} dataset lookup failed: {e} (re-pull with `hdx index pull {}`?)",
                        self.spec.name, self.spec.name
                    );
                });
                Vec::new()
            }
        }
    }
}

/// Every completely-pulled dataset, opened once per process.
pub fn open_all() -> &'static [LocalDataset] {
    static ALL: OnceLock<Vec<LocalDataset>> = OnceLock::new();
    ALL.get_or_init(|| SPECS.iter().filter_map(|s| LocalDataset::open(s)).collect())
}

/// A dataset's own membership filter, standing in front of its parquet.
///
/// A point lookup costs a page decode — cheap once, and the whole
/// resolve phase when half a million members each ask every dataset
/// about two digests. The bloom published alongside a dataset holds
/// every key that dataset can answer for, so a bloom miss is an
/// absence proof and the read can be skipped outright. This is the
/// probe rule scan already applies to the network (a filter hit is the
/// demand that justifies a request), pointed at the local read.
///
/// The gate's soundness is coherence: a filter that predates the rows
/// on disk would deny keys the parquet holds, silently dropping
/// evidence. So only the bloom pulled WITH a dataset — installed by
/// `index pull` beside the parquet, under the same revision pin —
/// gates it; the independently-fetched filters dir is never consulted
/// here. Only the schemes a pulled filter covers are gated; everything
/// else keeps reading its parquet, so absence stays proved by the
/// data either way.
pub struct Gates {
    blooms: Vec<(String, crate::coord::Scheme, crate::filter::Bloom)>,
}

impl Gates {
    /// Filters that belong to a dataset. Filters of every other source
    /// (circl, swh, …) are not a statement about any dataset's rows
    /// and are dropped here.
    pub fn new(filters: Vec<crate::filter::NamedFilter>) -> Gates {
        Gates {
            blooms: filters
                .into_iter()
                .filter(|f| spec(&f.name).is_some())
                .map(|f| (f.name, f.scheme, f.bloom))
                .collect(),
        }
    }

    /// The pulled datasets' own filters, opened once per process. A
    /// dataset dir holding no bloom (a pull from before blooms were
    /// part of one — re-pull to add it) is simply ungated.
    pub fn installed() -> &'static Gates {
        static GATES: OnceLock<Gates> = OnceLock::new();
        GATES.get_or_init(|| {
            Gates::new(
                open_all()
                    .iter()
                    .flat_map(|d| {
                        crate::filter::load_dir(&d.dir)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|f| f.name == d.spec.name)
                    })
                    .collect(),
            )
        })
    }

    /// Whether `dataset` could hold a row keyed by this coordinate.
    /// True whenever no filter can say otherwise.
    pub fn admits(&self, dataset: &str, coord: &Coord) -> bool {
        let Some((_, _, bloom)) = self
            .blooms
            .iter()
            .find(|(n, s, _)| n == dataset && *s == coord.scheme)
        else {
            return true;
        };
        match crate::filter::bloom_key(coord.scheme, &coord.digest) {
            Some(key) => bloom.check(key.as_bytes()),
            None => true,
        }
    }
}

/// Whether this dataset has a complete local copy (then its network
/// backend is redundant: the walk reads the same rows from disk).
pub fn is_local(name: &str) -> bool {
    open_all().iter().any(|d| d.spec.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmap_reader_serves_ranges_and_rejects_overruns() {
        let dir = std::env::temp_dir().join(format!("hdx-mmapreader-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        std::fs::write(&path, b"0123456789").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
        let r = MmapReader(Arc::new(mmap));
        assert_eq!(r.len(), 10);
        assert_eq!(&r.get_bytes(2, 3).unwrap()[..], b"234");
        assert!(r.get_bytes(8, 3).is_err(), "read past end must error");
        use std::io::Read;
        let mut cursor = r.get_read(7).unwrap();
        let mut buf = Vec::new();
        cursor.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"789");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use crate::coord::Scheme;

    fn bloom_over(keys: &[String], dir: &std::path::Path, name: &str) -> crate::filter::Bloom {
        // Padded: a bloom over a handful of keys answers yes to
        // everything, which would make the negative case meaningless.
        let mut b = crate::filter::BloomBuilder::new(1000, 0.0001).unwrap();
        for k in keys {
            b.add(k.as_bytes());
        }
        for i in 0..500 {
            b.add(format!("PAD{i:04}").as_bytes());
        }
        let path = dir.join(name);
        b.write(&path).unwrap();
        crate::filter::Bloom::open(&path).unwrap()
    }

    /// A dataset's own filter answers for its rows: present digests are
    /// admitted, absent ones are skipped, and anything the filters
    /// don't cover — another dataset, another scheme — is admitted so
    /// absence stays proved by the parquet.
    #[test]
    fn gates_skip_only_what_a_filter_denies() {
        let dir = std::env::temp_dir().join(format!("hdx-gates-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let present = Coord {
            scheme: Scheme::Sha256,
            digest: vec![0x11; 32],
        };
        let absent = Coord {
            scheme: Scheme::Sha256,
            digest: vec![0x22; 32],
        };
        let key = crate::filter::bloom_key(present.scheme, &present.digest).unwrap();
        let gates = Gates::new(vec![
            crate::filter::NamedFilter {
                name: "tarballs".into(),
                scheme: Scheme::Sha256,
                bloom: bloom_over(&[key], &dir, "tarballs.sha256.bloom"),
                bytes: 0,
            },
            // Not a dataset: never a statement about dataset rows.
            crate::filter::NamedFilter {
                name: "circl".into(),
                scheme: Scheme::Sha256,
                bloom: bloom_over(&[], &dir, "circl.sha256.bloom"),
                bytes: 0,
            },
        ]);
        assert!(gates.admits("tarballs", &present));
        assert!(!gates.admits("tarballs", &absent), "filter denied it");
        // No filter for this dataset, or this scheme, or this source:
        // read the parquet and let the data answer.
        assert!(gates.admits("debs", &absent));
        assert!(gates.admits(
            "tarballs",
            &Coord {
                scheme: Scheme::Md5,
                digest: vec![0x22; 16]
            }
        ));
        assert!(gates.admits("circl", &absent));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The referee for the gate's premise: every key a pulled dataset
    /// holds must be admitted by the filter published with it, or the
    /// gate would skip a read that had an answer. Needs local copies —
    /// run it after `hdx index pull`.
    #[test]
    #[ignore]
    fn gates_admit_every_local_row() {
        let gates = Gates::installed();
        let mut checked = 0usize;
        for d in open_all() {
            for (name, scheme, _) in gates.blooms.iter().filter(|(n, _, _)| n == d.spec.name) {
                let width = match scheme {
                    Scheme::Sha256 => 64,
                    Scheme::Sha1 => 40,
                    Scheme::Md5 => 32,
                    _ => continue,
                };
                let dir = datasets_dir().join(name);
                for entry in walkdir::WalkDir::new(&dir).into_iter().flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("parquet") {
                        continue;
                    }
                    let file = std::fs::File::open(path).unwrap();
                    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
                    let reader = Arc::new(MmapReader(Arc::new(mmap)));
                    let Ok(meta) = ParquetMetaDataReader::new()
                        .with_page_index_policy(PageIndexPolicy::Optional)
                        .parse_and_finish(reader.as_ref())
                    else {
                        continue;
                    };
                    let meta = Arc::new(meta);
                    for rgi in 0..meta.num_row_groups() {
                        let rows = meta.row_group(rgi).num_rows() as usize;
                        if rows == 0 {
                            continue;
                        }
                        // First, middle and last row of EVERY row
                        // group: a filter built from another
                        // revision's rows differs mid-file, where a
                        // head sample never looks.
                        let mut positions = vec![0, rows / 2, rows - 1];
                        positions.dedup();
                        for col in ["digest", "sha256", "sha1", "md5", "pkgid"] {
                            let Ok(cidx) = crate::parquet_index::column_index(&meta, col) else {
                                continue;
                            };
                            let vals = crate::parquet_index::read_records(
                                &reader,
                                &meta,
                                rgi,
                                cidx,
                                crate::parquet_index::Rows::At(&positions),
                            )
                            .unwrap();
                            let crate::parquet_index::ColValues::Str(vals) = vals else {
                                continue;
                            };
                            for hex in vals.into_iter().flatten() {
                                // A column of another scheme's digests
                                // proves nothing about this filter.
                                if hex.len() != width {
                                    continue;
                                }
                                let digest: Vec<u8> = (0..hex.len() / 2)
                                    .map(|i| {
                                        u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()
                                    })
                                    .collect();
                                let coord = Coord {
                                    scheme: *scheme,
                                    digest,
                                };
                                assert!(
                                    gates.admits(name, &coord),
                                    "{name} filter denies {hex}, a key in {}",
                                    path.display()
                                );
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        eprintln!("gates_admit_every_local_row: {checked} keys admitted");
        assert!(checked > 0, "no local dataset keys were checked");
    }
}
