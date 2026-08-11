//! hashdex core: hash coordinates, findings, and the range-read
//! machinery for resolving digests against published datasets.
//!
//! The default `cli` feature adds the native side: network backends,
//! local membership filters, the observation cache, and the scan
//! pipeline. Without it the crate compiles for wasm32 targets, where
//! a browser page drives the same lookup logic over fetch-based range
//! reads.

pub mod coord;
pub mod dcso;
pub mod fatcat;
pub mod finding;
pub mod parquet_index;
pub mod range_store;
pub mod tarballs;

#[cfg(feature = "cli")]
pub mod backends;
#[cfg(feature = "cli")]
pub mod cache;
#[cfg(feature = "cli")]
pub mod coords_cmd;
#[cfg(feature = "cli")]
pub mod filter;
#[cfg(feature = "cli")]
pub mod filters_cmd;
#[cfg(feature = "cli")]
pub mod index_cmd;
#[cfg(feature = "cli")]
pub mod inverted;
#[cfg(feature = "cli")]
pub mod local_index;
#[cfg(feature = "cli")]
pub mod resolve;
#[cfg(feature = "cli")]
pub mod scan_cmd;
#[cfg(feature = "cli")]
pub mod walk;
