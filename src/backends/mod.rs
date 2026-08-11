pub mod circl;
pub mod dataset;
pub mod depsdev;
pub mod rekor;
pub mod snapshot;
pub mod swh;

use crate::coord::{Coord, Scheme};
use crate::datasets;
use crate::finding::Finding;
use anyhow::Result;
use futures::future::BoxFuture;
use reqwest::Client;

/// Backend registry. Each entry: (name, supports-scheme predicate, lookup fn).
/// A lookup returns Ok(vec![]) on a definitive miss, findings on a hit
/// (most backends yield at most one; dataset indexes yield one per
/// witness or per distinct content), and Err only on transport/upstream
/// failure (which is reported, not cached).
pub struct Backend {
    pub name: &'static str,
    pub supports: fn(Scheme) -> bool,
    pub lookup: for<'a> fn(&'a Client, &'a Coord) -> BoxFuture<'a, Result<Vec<Finding>>>,
}

/// Adapt a single-answer backend future to the registry's vec shape.
macro_rules! single {
    ($m:ident) => {
        |c, k| Box::pin(async move { Ok($m::lookup(c, k).await?.into_iter().collect()) })
    };
}

pub fn all() -> Vec<Backend> {
    vec![
        Backend {
            name: depsdev::NAME,
            supports: depsdev::supports,
            lookup: single!(depsdev),
        },
        Backend {
            name: circl::NAME,
            supports: circl::supports,
            lookup: single!(circl),
        },
        Backend {
            name: datasets::FATCAT.name,
            supports: datasets::FATCAT.supports,
            lookup: |_, k| Box::pin(dataset::lookup(&datasets::FATCAT, k)),
        },
        Backend {
            name: datasets::TARBALLS.name,
            supports: datasets::TARBALLS.supports,
            lookup: |_, k| Box::pin(dataset::lookup(&datasets::TARBALLS, k)),
        },
        Backend {
            name: swh::NAME,
            supports: swh::supports,
            lookup: single!(swh),
        },
        Backend {
            name: snapshot::NAME,
            supports: snapshot::supports,
            lookup: single!(snapshot),
        },
        Backend {
            name: rekor::NAME,
            supports: rekor::supports,
            lookup: single!(rekor),
        },
    ]
}
