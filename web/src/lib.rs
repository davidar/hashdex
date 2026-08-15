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
use hashdex::registry::{BloomEntry, Spec, BLOOMS, SPECS};
use hashdex::{dcso, registry};
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

/// Filters come from the core registry (`hashdex::registry::BLOOMS`)
/// — the page probes `urls[0]` (an HF mirror) with ranged reads, so a
/// bloom added to the registry is probeable here at the next build.
fn scheme_of(s: &str) -> Option<Scheme> {
    match s {
        "md5" => Some(Scheme::Md5),
        "sha1" => Some(Scheme::Sha1),
        "sha256" => Some(Scheme::Sha256),
        "sha512" => Some(Scheme::Sha512),
        _ => None,
    }
}

#[derive(Serialize)]
struct FilterInfo {
    name: &'static str,
    scheme: &'static str,
    source: &'static str,
}

/// JSON array of probeable filters, for the page to fan out over.
#[wasm_bindgen]
pub fn filter_list() -> String {
    let list: Vec<FilterInfo> = BLOOMS
        .iter()
        .map(|f| FilterInfo {
            name: f.name,
            scheme: f.scheme,
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
    let entry: &BloomEntry = BLOOMS
        .iter()
        .find(|f| f.name == name && f.scheme == scheme)
        .with_context(|| format!("unknown filter {name}.{scheme}"))?;
    let entry_scheme =
        scheme_of(entry.scheme).with_context(|| format!("unprobeable scheme {}", entry.scheme))?;
    if coord.scheme != entry_scheme {
        bail!(
            "{name}.{scheme} cannot be probed with a {} digest",
            coord.scheme.as_str()
        );
    }
    let url: &'static str = entry.urls[0];
    let header = match BLOOM_HEADERS.with(|h| h.borrow().get(url).copied()) {
        Some(h) => h,
        None => {
            // Fetching the header first also memoizes the post-redirect
            // URL, so the k probe reads below go straight to the CDN.
            let bytes = fetch::get_range(url, 0, dcso::HEADER_LEN).await?;
            let h = dcso::Header::parse(&bytes, url)?;
            BLOOM_HEADERS.with(|m| m.borrow_mut().insert(url, h));
            h
        }
    };
    // Key convention from the filter builders: sha1 filters store
    // UPPERCASE hex (CIRCL's), sha256 filters lowercase.
    let key = match entry_scheme {
        Scheme::Sha1 => coord.hex().to_ascii_uppercase(),
        _ => coord.hex(),
    };
    let locs: Vec<(u64, u64)> = dcso::bit_positions(key.as_bytes(), header.k, header.m)
        .map(dcso::bit_location)
        .collect();
    let words =
        futures::future::try_join_all(locs.iter().map(|(off, _)| fetch::get_range(url, *off, 8)))
            .await?;
    Ok(locs
        .iter()
        .zip(&words)
        .all(|((_, mask), w)| u64::from_le_bytes(w[..8].try_into().unwrap()) & mask != 0))
}

// -------------------------------------------------------------- datasets

/// Datasets come from the core registry (`hashdex::registry::SPECS`):
/// the session machinery below (revision pin, opened files, miss
/// feeding) is keyed per dataset name; routing, lookup, and claim
/// rendering live in each dataset's core module, dispatched by
/// `registry::lookup_in`. A dataset added to the registry resolves
/// here at the next build. Cold opens read `spec.suffix` (length via
/// Content-Range + footer + page-index region in one request) —
/// dataset-sized, so small indexes are not opened with fatcat-scale
/// requests.
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
async fn pinned_revision(ds: &'static Spec) -> String {
    if let Some(rev) = REVISIONS.with(|r| r.borrow().get(ds.name).cloned()) {
        return rev;
    }
    let rev = match fetch::get_json(&ds.revision_api()).await {
        Ok(v) => v["sha"].as_str().unwrap_or("main").to_string(),
        Err(_) => "main".to_string(),
    };
    REVISIONS.with(|r| r.borrow_mut().insert(ds.name, rev.clone()));
    rev
}

async fn ensure_open(ds: &'static Spec, path: &str) -> Result<()> {
    if OPENED.with(|f| f.borrow().contains_key(&(ds.name, path.to_string()))) {
        return Ok(());
    }
    let rev = pinned_revision(ds).await;
    let url = format!("{}/{}/{}", ds.resolve_base(), rev, path);
    let (total, start, bytes) = fetch::get_suffix(&url, ds.suffix as usize).await?;
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
            (ds.name, path.to_string()),
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
    ds: &'static Spec,
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
                .filter(|((name, _), _)| *name == ds.name)
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

#[derive(Serialize)]
struct DatasetInfo {
    name: &'static str,
    schemes: Vec<&'static str>,
}

/// JSON array of resolvable datasets with the schemes each can be
/// keyed by, for the page to fan out over.
#[wasm_bindgen]
pub fn dataset_list() -> String {
    let all = [Scheme::Sha256, Scheme::Sha512, Scheme::Sha1, Scheme::Md5];
    let list: Vec<DatasetInfo> = SPECS
        .iter()
        .map(|s| DatasetInfo {
            name: s.name,
            schemes: all
                .iter()
                .filter(|sch| (s.supports)(**sch))
                .map(|sch| sch.as_str())
                .collect(),
        })
        .collect();
    serde_json::to_string(&list).unwrap()
}

/// Resolve one coordinate against a registry dataset. Returns a JSON
/// array of findings (one per witness row or distinct content; empty
/// = no hits), or "null" for schemes the dataset has no key for.
#[wasm_bindgen]
pub async fn dataset_lookup(name: String, coord: String) -> Result<String, JsValue> {
    dataset_lookup_inner(&name, &coord).await.map_err(err_js)
}

async fn dataset_lookup_inner(name: &str, coord: &str) -> Result<String> {
    let ds = registry::spec(name).with_context(|| format!("unknown dataset {name}"))?;
    let coord = Coord::parse(coord)?;
    if !(ds.supports)(coord.scheme) {
        return Ok("null".to_string());
    }
    let findings = drive_lookup(ds, &(ds.start_paths)(&coord), |open| {
        registry::lookup_in(ds.name, |p| open(p), &coord)
    })
    .await?;
    Ok(serde_json::to_string(&findings)?)
}
