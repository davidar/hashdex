pub mod circl;
pub mod depsdev;
pub mod fatcat;
pub mod rekor;
pub mod snapshot;
pub mod swh;
pub mod virustotal;

use crate::coord::{Coord, Scheme};
use crate::finding::Finding;
use anyhow::Result;
use reqwest::Client;

/// Backend registry. Each entry: (name, supports-scheme predicate, lookup fn).
/// A lookup returns Ok(None) on a definitive miss, Ok(Some) on a hit, and
/// Err only on transport/upstream failure (which is reported, not cached).
pub struct Backend {
    pub name: &'static str,
    pub supports: fn(Scheme) -> bool,
    pub lookup: for<'a> fn(
        &'a Client,
        &'a Coord,
    ) -> futures::future::BoxFuture<'a, Result<Option<Finding>>>,
}

pub fn all() -> Vec<Backend> {
    let mut v = vec![
        Backend {
            name: depsdev::NAME,
            supports: depsdev::supports,
            lookup: |c, k| Box::pin(depsdev::lookup(c, k)),
        },
        Backend {
            name: circl::NAME,
            supports: circl::supports,
            lookup: |c, k| Box::pin(circl::lookup(c, k)),
        },
        Backend {
            name: fatcat::NAME,
            supports: fatcat::supports,
            lookup: |c, k| Box::pin(fatcat::lookup(c, k)),
        },
        Backend {
            name: swh::NAME,
            supports: swh::supports,
            lookup: |c, k| Box::pin(swh::lookup(c, k)),
        },
        Backend {
            name: snapshot::NAME,
            supports: snapshot::supports,
            lookup: |c, k| Box::pin(snapshot::lookup(c, k)),
        },
        Backend {
            name: rekor::NAME,
            supports: rekor::supports,
            lookup: |c, k| Box::pin(rekor::lookup(c, k)),
        },
    ];
    if virustotal::enabled() {
        v.push(Backend {
            name: virustotal::NAME,
            supports: virustotal::supports,
            lookup: |c, k| Box::pin(virustotal::lookup(c, k)),
        });
    }
    v
}
