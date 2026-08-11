//! The hashdex web resolver: the same lookup logic the CLI runs,
//! compiled to wasm and driven over browser fetch range reads. Nothing
//! is ever uploaded — dropped files are hashed in the page, and the
//! only network traffic is small range reads into hashdex's published
//! datasets on Hugging Face (bloom filter bits and parquet pages).
//!
//! The JS side orchestrates: it calls [`probe_filter`] once per
//! (filter, scheme) and [`fatcat_lookup`] once per resolution, all
//! concurrently, and renders each result as it lands. Rust owns the
//! formats: coordinate parsing, DCSO bloom math, parquet point
//! lookups over [`hashdex::range_store::RangeStore`].

mod fetch;

use anyhow::{bail, Context, Result};
use blake2::Blake2s256;
use bytes::Bytes;
use hashdex::coord::{Coord, Scheme};
use hashdex::range_store::RangeStore;
use hashdex::{dcso, fatcat, tarballs};
use md5::Md5;
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

fn err_js(e: anyhow::Error) -> JsValue {
    JsValue::from_str(&format!("{e:#}"))
}

// ---------------------------------------------------------------- coords

/// Canonicalize any accepted hash spelling (hex, scheme:hex, SRI,
/// SWHID, CDX base32) to "scheme:hex", or a parse error.
#[wasm_bindgen]
pub fn parse_coord(input: &str) -> Result<String, JsValue> {
    Ok(Coord::parse(input).map_err(err_js)?.to_string())
}

/// Streaming six-scheme hasher for dropped files, mirroring
/// `hdx coords`. The constructor needs the file length up front
/// because the git blob hash's preimage starts with "blob <len>\0".
#[wasm_bindgen]
pub struct Hasher {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
    sha512: Sha512,
    blake2s: Blake2s256,
    sha1_git: Sha1,
}

#[wasm_bindgen]
impl Hasher {
    #[wasm_bindgen(constructor)]
    pub fn new(len: f64) -> Hasher {
        let mut sha1_git = Sha1::new();
        sha1_git.update(format!("blob {}\0", len as u64).as_bytes());
        Hasher {
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
            sha512: Sha512::new(),
            blake2s: Blake2s256::new(),
            sha1_git,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.md5.update(chunk);
        self.sha1.update(chunk);
        self.sha256.update(chunk);
        self.sha512.update(chunk);
        self.blake2s.update(chunk);
        self.sha1_git.update(chunk);
    }

    /// JSON object mapping scheme name to lowercase hex digest.
    pub fn finish(self) -> String {
        let hex = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        serde_json::json!({
            "md5": hex(&self.md5.finalize()),
            "sha1": hex(&self.sha1.finalize()),
            "sha256": hex(&self.sha256.finalize()),
            "sha512": hex(&self.sha512.finalize()),
            "blake2s256": hex(&self.blake2s.finalize()),
            "sha1_git": hex(&self.sha1_git.finalize()),
        })
        .to_string()
    }
}

// --------------------------------------------------------------- filters

/// The published membership filters the page can probe remotely.
/// Mirrors the CLI registry (src/filters_cmd.rs), HF URLs only.
struct FilterEntry {
    name: &'static str,
    scheme: Scheme,
    url: &'static str,
    source: &'static str,
}

const FILTERS: &[FilterEntry] = &[
    FilterEntry {
        name: "circl",
        scheme: Scheme::Sha1,
        url: "https://huggingface.co/datasets/david-ar/circl-hashlookup-mirror/resolve/main/circl.sha1.bloom",
        source: "CIRCL hashlookup: NSRL, Windows, distros",
    },
    FilterEntry {
        name: "fedora",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/rpm-header-blooms/resolve/main/fedora.sha256.bloom",
        source: "Fedora repo metadata: per-file RPM digests",
    },
    FilterEntry {
        name: "rpmfusion",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/rpm-header-blooms/resolve/main/rpmfusion.sha256.bloom",
        source: "RPM Fusion free+nonfree per-file digests",
    },
    FilterEntry {
        name: "vscode",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/rpm-header-blooms/resolve/main/vscode.sha256.bloom",
        source: "Microsoft VS Code yum repo per-file digests",
    },
    FilterEntry {
        name: "fatcat",
        scheme: Scheme::Sha1,
        url: "https://huggingface.co/datasets/david-ar/fatcat-file-bloom/resolve/main/fatcat.sha1.bloom",
        source: "IA fatcat: 122M scholarly-file hashes",
    },
    FilterEntry {
        name: "fatcat",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/fatcat-file-bloom/resolve/main/fatcat.sha256.bloom",
        source: "IA fatcat: 122M scholarly-file hashes",
    },
    FilterEntry {
        name: "depsdev",
        scheme: Scheme::Sha1,
        url: "https://huggingface.co/datasets/david-ar/depsdev-bloom/resolve/main/depsdev.sha1.bloom",
        source: "deps.dev package-file hashes",
    },
    FilterEntry {
        name: "depsdev",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/depsdev-bloom/resolve/main/depsdev.sha256.bloom",
        source: "deps.dev package-file hashes",
    },
    FilterEntry {
        name: "rekor",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/rekor-bloom/resolve/main/rekor.sha256.bloom",
        source: "Sigstore Rekor transparency-log digests",
    },
    FilterEntry {
        name: "cc",
        scheme: Scheme::Sha1,
        url: "https://huggingface.co/datasets/david-ar/cc-document-bloom/resolve/main/cc.sha1.bloom",
        source: "Common Crawl document payload digests",
    },
    FilterEntry {
        name: "swh",
        scheme: Scheme::Sha256,
        url: "https://huggingface.co/datasets/david-ar/swh-content-bloom/resolve/main/2026-06-04/swh.sha256.bloom",
        source: "Software Heritage: 29.3B archived file contents",
    },
];

#[derive(Serialize)]
struct FilterInfo {
    name: &'static str,
    scheme: &'static str,
    source: &'static str,
}

/// JSON array of probeable filters, for the page to fan out over.
#[wasm_bindgen]
pub fn filter_list() -> String {
    let list: Vec<FilterInfo> = FILTERS
        .iter()
        .map(|f| FilterInfo {
            name: f.name,
            scheme: f.scheme.as_str(),
            source: f.source,
        })
        .collect();
    serde_json::to_string(&list).unwrap()
}

thread_local! {
    static BLOOM_HEADERS: RefCell<HashMap<&'static str, dcso::Header>> =
        RefCell::new(HashMap::new());
}

/// Probe one published bloom filter for `coord`: read the 48-byte DCSO
/// header (cached per session), then the k bit words as parallel
/// 8-byte range reads. True = probable member at the filter's fpp.
#[wasm_bindgen]
pub async fn probe_filter(name: String, scheme: String, coord: String) -> Result<bool, JsValue> {
    probe_filter_inner(&name, &scheme, &coord)
        .await
        .map_err(err_js)
}

async fn probe_filter_inner(name: &str, scheme: &str, coord: &str) -> Result<bool> {
    let coord = Coord::parse(coord)?;
    let entry = FILTERS
        .iter()
        .find(|f| f.name == name && f.scheme.as_str() == scheme)
        .with_context(|| format!("unknown filter {name}.{scheme}"))?;
    if coord.scheme != entry.scheme {
        bail!(
            "{name}.{scheme} cannot be probed with a {} digest",
            coord.scheme.as_str()
        );
    }
    let header = match BLOOM_HEADERS.with(|h| h.borrow().get(entry.url).copied()) {
        Some(h) => h,
        None => {
            // Fetching the header first also memoizes the post-redirect
            // URL, so the k probe reads below go straight to the CDN.
            let bytes = fetch::get_range(entry.url, 0, dcso::HEADER_LEN).await?;
            let h = dcso::Header::parse(&bytes, entry.url)?;
            BLOOM_HEADERS.with(|m| m.borrow_mut().insert(entry.url, h));
            h
        }
    };
    // Key convention from the filter builders: sha1 filters store
    // UPPERCASE hex (CIRCL's), sha256 filters lowercase.
    let key = match entry.scheme {
        Scheme::Sha1 => coord.hex().to_ascii_uppercase(),
        _ => coord.hex(),
    };
    let locs: Vec<(u64, u64)> = dcso::bit_positions(key.as_bytes(), header.k, header.m)
        .map(dcso::bit_location)
        .collect();
    let words = futures::future::try_join_all(
        locs.iter()
            .map(|(off, _)| fetch::get_range(entry.url, *off, 8)),
    )
    .await?;
    Ok(locs
        .iter()
        .zip(&words)
        .all(|((_, mask), w)| u64::from_le_bytes(w[..8].try_into().unwrap()) & mask != 0))
}

// -------------------------------------------------------------- datasets

/// Cold-open speculative suffix: length (via Content-Range) + footer +
/// page-index region in one request. The fatcat data files' index
/// region is ~4.8 MB; 8 MB covers it with margin.
const SUFFIX: usize = 8 << 20;

/// A published parquet dataset the page can point-look-up into. The
/// session machinery (revision pin, opened files, miss feeding) is
/// keyed per dataset; the lookup logic itself lives in the core crate.
#[derive(Clone, Copy)]
struct Dataset {
    base: &'static str,
    revision_api: &'static str,
}

const FATCAT: Dataset = Dataset {
    base: fatcat::DATASET_BASE,
    revision_api: fatcat::REVISION_API,
};
const TARBALLS: Dataset = Dataset {
    base: tarballs::DATASET_BASE,
    revision_api: tarballs::REVISION_API,
};

struct Opened {
    url: String,
    store: RangeStore,
    meta: Arc<ParquetMetaData>,
}

thread_local! {
    /// Opened remote files, keyed by (dataset base, repo-relative path).
    static OPENED: RefCell<HashMap<(&'static str, String), Rc<Opened>>> =
        RefCell::new(HashMap::new());
    static REVISIONS: RefCell<HashMap<&'static str, String>> = RefCell::new(HashMap::new());
}

/// The dataset revision to read, pinned once per page session so a
/// mid-session republish can't tear a lookup. Falls back to "main".
async fn pinned_revision(ds: &Dataset) -> String {
    if let Some(rev) = REVISIONS.with(|r| r.borrow().get(ds.revision_api).cloned()) {
        return rev;
    }
    let rev = match fetch::get_json(ds.revision_api).await {
        Ok(v) => v["sha"].as_str().unwrap_or("main").to_string(),
        Err(_) => "main".to_string(),
    };
    REVISIONS.with(|r| r.borrow_mut().insert(ds.revision_api, rev.clone()));
    rev
}

async fn ensure_open(ds: &Dataset, path: &str) -> Result<()> {
    if OPENED.with(|f| f.borrow().contains_key(&(ds.base, path.to_string()))) {
        return Ok(());
    }
    let rev = pinned_revision(ds).await;
    let url = format!("{}/{}/{}", ds.base, rev, path);
    let (total, start, bytes) = fetch::get_suffix(&url, SUFFIX).await?;
    let store = RangeStore::new(total);
    store.insert(start, Bytes::from(bytes));
    // Drive the metadata parse: the suffix nearly always suffices, but
    // an oversized index region shows up as a miss to fetch and retry.
    let meta = loop {
        match ParquetMetaDataReader::new()
            .with_page_index_policy(PageIndexPolicy::Optional)
            .parse_and_finish(&store)
        {
            Ok(m) => break Arc::new(m),
            Err(e) => match store.take_miss() {
                Some((s, l)) => {
                    let b = fetch::get_range(&url, s, l).await?;
                    store.insert(s, Bytes::from(b));
                }
                None => return Err(e.into()),
            },
        }
    };
    OPENED.with(|f| {
        f.borrow_mut().insert(
            (ds.base, path.to_string()),
            Rc::new(Opened { url, store, meta }),
        )
    });
    Ok(())
}

/// The sync lookup over async fetches: run the whole lookup; when it
/// stops on a missing range (or a data file a weak-digest map just
/// revealed), fetch that and run it again. Identical in shape to the
/// range_store test Driver, with awaited fetches.
async fn drive_lookup<T>(
    ds: &Dataset,
    start_paths: &[String],
    run: impl Fn(&dyn Fn(&str) -> Result<(Arc<RangeStore>, Arc<ParquetMetaData>)>) -> Result<T>,
) -> Result<T> {
    for path in start_paths {
        ensure_open(ds, path).await?;
    }
    for _ in 0..96 {
        let files: HashMap<String, Rc<Opened>> = OPENED.with(|f| {
            f.borrow()
                .iter()
                .filter(|((base, _), _)| *base == ds.base)
                .map(|((_, path), o)| (path.clone(), Rc::clone(o)))
                .collect()
        });
        let need_open: RefCell<Option<String>> = RefCell::new(None);
        let open = |path: &str| -> Result<(Arc<RangeStore>, Arc<ParquetMetaData>)> {
            match files.get(path) {
                Some(o) => Ok((Arc::new(o.store.clone()), Arc::clone(&o.meta))),
                None => {
                    *need_open.borrow_mut() = Some(path.to_string());
                    bail!("not opened yet: {path}")
                }
            }
        };
        match run(&open) {
            Ok(out) => return Ok(out),
            Err(e) => {
                // Take before awaiting: a borrow in the `if let`
                // scrutinee would live across the await.
                let pending = need_open.borrow_mut().take();
                if let Some(path) = pending {
                    ensure_open(ds, &path).await?;
                    continue;
                }
                let mut fed = false;
                for o in files.values() {
                    if let Some((s, l)) = o.store.take_miss() {
                        let b = fetch::get_range(&o.url, s, l).await?;
                        o.store.insert(s, Bytes::from(b));
                        fed = true;
                    }
                }
                if !fed {
                    return Err(e);
                }
            }
        }
    }
    bail!("lookup did not converge")
}

/// Resolve one coordinate against the fatcat file dataset. Returns the
/// finding as JSON, or "null" for unsupported schemes and misses.
#[wasm_bindgen]
pub async fn fatcat_lookup(coord: String) -> Result<String, JsValue> {
    fatcat_lookup_inner(&coord).await.map_err(err_js)
}

async fn fatcat_lookup_inner(coord: &str) -> Result<String> {
    let coord = Coord::parse(coord)?;
    if !fatcat::supports(coord.scheme) {
        return Ok("null".to_string());
    }
    let finding = drive_lookup(&FATCAT, &fatcat::start_paths(&coord), |open| {
        fatcat::lookup_with(|p| open(p), &coord)
    })
    .await?;
    Ok(serde_json::to_string(&finding)?)
}

/// Resolve one coordinate against the release-tarballs dataset.
/// Returns a JSON array of findings (one per witness row; empty =
/// no hits), or "null" for unsupported schemes.
#[wasm_bindgen]
pub async fn tarballs_lookup(coord: String) -> Result<String, JsValue> {
    tarballs_lookup_inner(&coord).await.map_err(err_js)
}

async fn tarballs_lookup_inner(coord: &str) -> Result<String> {
    let coord = Coord::parse(coord)?;
    if !tarballs::supports(coord.scheme) {
        return Ok("null".to_string());
    }
    let findings = drive_lookup(&TARBALLS, &tarballs::start_paths(&coord), |open| {
        tarballs::lookup_with(|p| open(p), &coord)
    })
    .await?;
    Ok(serde_json::to_string(&findings)?)
}
