//! The published-artifact registries: every claim dataset and every
//! membership filter hashdex knows how to reach. This module is the
//! single source of truth — the CLI (`hdx index pull`, `hdx filters
//! fetch`, scan routing) and the web page all enumerate it, so a
//! dataset or bloom added here appears everywhere at the next build
//! with no per-consumer wiring.

use crate::coord::{Coord, Scheme};
use crate::finding::Finding;
use anyhow::Result;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::reader::ChunkReader;
use std::sync::Arc;

// -------------------------------------------------------------- datasets

/// One published dataset: identity and routing. The digest→path logic
/// lives in the dataset's core module (`fatcat`, `tarballs`, …); this
/// is the registry the transports and the CLI share.
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

pub static RPM_FILES: Spec = Spec {
    name: "rpm-files",
    repo: "david-ar/rpm-files",
    approx_size: "~1 GB",
    suffix: 8 << 20,
    supports: crate::rpm_files::supports,
    start_paths: crate::rpm_files::start_paths,
};

pub static SPECS: &[&Spec] = &[&FATCAT, &TARBALLS, &CENSUS, &DEBS, &MEDIA, &RPM_FILES];

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
        "rpm-files" => crate::rpm_files::lookup_with(open, coord),
        _ => Ok(Vec::new()),
    }
}

// --------------------------------------------------------------- blooms

/// One downloadable membership filter. `urls` are tried in order —
/// mirrors first, canonical host as fallback — so a missing mirror
/// degrades to slow rather than broken. The web page probes `urls[0]`
/// with ranged reads instead of downloading.
pub struct BloomEntry {
    pub name: &'static str,
    pub scheme: &'static str,
    pub urls: &'static [&'static str],
    pub size: &'static str,
    pub source: &'static str,
    /// Excluded from `hdx filters fetch --all`; must be named
    /// explicitly.
    pub huge: bool,
}

pub static BLOOMS: &[BloomEntry] = &[
    BloomEntry {
        name: "circl",
        scheme: "sha1",
        urls: &[
            // CIRCL's own host is very slow; mirror first (CC-BY-4.0).
        "https://huggingface.co/datasets/david-ar/circl-hashlookup-mirror/resolve/main/circl.sha1.bloom",
            "https://cra.circl.lu/hashlookup/hashlookup-full.bloom",
        ],
        size: "956 MiB",
        source: "CIRCL hashlookup: NSRL, Windows, distros (CC-BY-4.0)",
        huge: false,
    },
    BloomEntry {
        name: "fatcat",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/fatcat-file-bloom/resolve/main/fatcat.sha1.bloom"],
        size: "279 MiB",
        source: "IA fatcat: 122M scholarly-file hashes (CC0)",
        huge: false,
    },
    BloomEntry {
        name: "fatcat",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/fatcat-file-bloom/resolve/main/fatcat.sha256.bloom"],
        size: "279 MiB",
        source: "IA fatcat: 122M scholarly-file hashes (CC0)",
        huge: false,
    },
    BloomEntry {
        name: "depsdev",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/depsdev-bloom/resolve/main/depsdev.sha1.bloom"],
        size: "395 MiB",
        source: "deps.dev package-file hashes (CC-BY-4.0)",
        huge: false,
    },
    BloomEntry {
        name: "depsdev",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/depsdev-bloom/resolve/main/depsdev.sha256.bloom"],
        size: "395 MiB",
        source: "deps.dev package-file hashes (CC-BY-4.0)",
        huge: false,
    },
    BloomEntry {
        name: "rekor",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/rekor-bloom/resolve/main/rekor.sha256.bloom"],
        size: "19 MiB",
        source: "Sigstore Rekor transparency-log subject digests",
        huge: false,
    },
    BloomEntry {
        name: "cc",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/cc-document-bloom/resolve/main/cc.sha1.bloom"],
        size: "71 MiB",
        source: "Common Crawl document payload digests",
        huge: false,
    },
    BloomEntry {
        name: "tarballs",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/release-tarballs/resolve/main/tarballs.sha256.bloom"],
        size: "359 KiB",
        source: "Debian sid / Homebrew / Guix release-artifact checksums",
        huge: false,
    },
    BloomEntry {
        name: "debs",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/deb-packages/resolve/main/debs.sha256.bloom"],
        size: "~2 MiB",
        source: "Debian/Ubuntu/Kali binary-package (.deb) checksums",
        huge: false,
    },
    BloomEntry {
        name: "install-media",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/install-media/resolve/main/install-media.sha256.bloom"],
        size: "887 KiB",
        source: "distro install-media checksum documents (32 witnesses)",
        huge: false,
    },
    // Replaces the rpm-header-blooms trio (fedora/rpmfusion/vscode):
    // one bloom over every harvested rpm repo, with the rpm-files
    // dataset behind it turning hits into package+path claims.
    BloomEntry {
        name: "rpm-files",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/rpm-files/resolve/main/rpm-files.sha256.bloom"],
        size: "~450 MiB",
        source: "RPM repos (Fedora/EPEL/CentOS/Alma/Rocky/openSUSE/…): per-file digests + package checksums",
        huge: false,
    },
    BloomEntry {
        name: "ia-census",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/ia-census/resolve/main/ia-census.sha1.bloom"],
        size: "311 MiB",
        source: "Internet Archive 2016 census: every public item's files",
        huge: false,
    },
    BloomEntry {
        name: "swh",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/swh-content-bloom/resolve/main/2026-06-04/swh.sha256.bloom"],
        size: "70 GiB",
        source: "Software Heritage: 29.3B archived file contents (CC-BY-4.0)",
        huge: true,
    },
];
