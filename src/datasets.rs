//! The published claim datasets (page-indexed parquet on the Hub) and
//! their local copies. Resolution range-reads the published files by
//! default; `hdx index pull <name>` downloads a dataset into
//! `~/.cache/hashdex/datasets/<name>/` (mirroring the repo layout) and
//! lookups then run over an mmap of the very same parquet — one wire
//! format, two transports.

use crate::coord::{Coord, Scheme};
use crate::finding::Finding;
use anyhow::{Context, Result};
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};
use parquet::file::reader::{ChunkReader, Length};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once, OnceLock};

/// One published dataset: identity and routing. The digest→path logic
/// lives in the dataset's core module (`fatcat`, `tarballs`); this is
/// the registry the transports and the CLI share.
pub struct Spec {
    pub name: &'static str,
    /// Hub repo id, e.g. "david-ar/fatcat-files".
    pub repo: &'static str,
    /// Rough published size, shown before a pull.
    pub approx_size: &'static str,
    /// Cold-open speculative suffix: must cover magic + footer + the
    /// page-index region in one ranged request. Dataset-sized: fatcat's
    /// multi-GB files carry ~5 MB of page index; tarballs' whole data
    /// file is 15 MB.
    pub suffix: u64,
    pub supports: fn(Scheme) -> bool,
    pub start_paths: fn(&Coord) -> Vec<String>,
}

impl Spec {
    pub fn resolve_base(&self) -> String {
        format!("https://huggingface.co/datasets/{}/resolve", self.repo)
    }
    pub fn revision_api(&self) -> String {
        format!(
            "https://huggingface.co/api/datasets/{}/revision/main",
            self.repo
        )
    }
    pub fn tree_api(&self, revision: &str) -> String {
        // expand=true adds LFS metadata per entry; lfs.oid is the
        // file's sha256, which is what `hdx index verify` checks
        // local copies against.
        format!(
            "https://huggingface.co/api/datasets/{}/tree/{revision}?recursive=true&expand=true",
            self.repo
        )
    }
}

pub static FATCAT: Spec = Spec {
    name: "fatcat",
    repo: "david-ar/fatcat-files",
    approx_size: "~52 GB",
    suffix: 8 << 20,
    supports: crate::fatcat::supports,
    start_paths: crate::fatcat::start_paths,
};

pub static TARBALLS: Spec = Spec {
    name: "tarballs",
    repo: "david-ar/release-tarballs",
    approx_size: "~25 MB",
    suffix: 1 << 20,
    supports: crate::tarballs::supports,
    start_paths: crate::tarballs::start_paths,
};

pub static CENSUS: Spec = Spec {
    name: "ia-census",
    repo: "david-ar/ia-census",
    approx_size: "~14 GB",
    suffix: 8 << 20,
    supports: crate::census::supports,
    start_paths: crate::census::start_paths,
};

pub static DEBS: Spec = Spec {
    name: "debs",
    repo: "david-ar/deb-packages",
    approx_size: "~200 MB",
    suffix: 4 << 20,
    supports: crate::debs::supports,
    start_paths: crate::debs::start_paths,
};

pub static MEDIA: Spec = Spec {
    name: "install-media",
    repo: "david-ar/install-media",
    approx_size: "~40 MB",
    suffix: 1 << 20,
    supports: crate::media::supports,
    start_paths: crate::media::start_paths,
};

pub static SPECS: &[&Spec] = &[&FATCAT, &TARBALLS, &CENSUS, &DEBS, &MEDIA];

pub fn spec(name: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|s| s.name == name).copied()
}

/// Backends that are range reads against our published static datasets:
/// probing them discloses digests to no one.
pub fn is_dataset(backend: &str) -> bool {
    spec(backend).is_some()
}

/// One lookup, dispatched to the dataset's core module — generic over
/// the transport (remote range reads or a local mmap), monomorphized
/// per open-fn.
pub fn lookup_in<R, F>(name: &str, open: F, coord: &Coord) -> Result<Vec<Finding>>
where
    R: ChunkReader + 'static,
    F: Fn(&str) -> Result<(Arc<R>, Arc<ParquetMetaData>)>,
{
    match name {
        "fatcat" => crate::fatcat::lookup_with(open, coord),
        "tarballs" => crate::tarballs::lookup_with(open, coord),
        "ia-census" => crate::census::lookup_with(open, coord),
        "debs" => crate::debs::lookup_with(open, coord),
        "install-media" => crate::media::lookup_with(open, coord),
        _ => Ok(Vec::new()),
    }
}

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
}
