use crate::backends;
use crate::cache::{Cache, Cached};
use crate::coord::Coord;
use crate::finding::Finding;
use crate::walk;
use anyhow::Result;
use futures::future::join_all;
use reqwest::Client;
use std::time::Duration;

pub struct Resolution {
    pub coord: Coord,
    /// Evidence grouped into identity clusters (usually exactly one).
    pub clusters: Vec<walk::Cluster>,
    pub collision: bool,
    pub truncated: bool,
    pub misses: Vec<&'static str>,
    pub errors: Vec<(&'static str, String)>,
    pub offline: bool,
}

pub struct Options {
    pub refresh: bool,
    pub no_cache: bool,
    pub offline: bool,
    pub timeout_secs: u64,
}

/// Resolution order (DESIGN.md): network backends are asked about the
/// queried coordinate only; the local walk then expands across the
/// inverted indexes and the observation store — including coordinates
/// the network answers just crosswalked. Network runs first so fresh
/// observations are in the store before the walk sweeps it.
pub async fn resolve(client: &Client, coord: &Coord, opts: &Options) -> Result<Resolution> {
    let cache = if opts.no_cache {
        None
    } else {
        Cache::open().ok()
    };
    let mut misses = Vec::new();
    let mut errors = Vec::new();
    let mut fresh: Vec<Finding> = Vec::new();

    if !opts.offline {
        let mut to_fetch = Vec::new();
        for backend in backends::all() {
            if !(backend.supports)(coord.scheme) {
                continue;
            }
            if !opts.refresh {
                if let Some(cache) = &cache {
                    match cache.get(backend.name, coord) {
                        // A cached hit is already in the observation
                        // store; the walk picks it up from there.
                        Cached::Hit => continue,
                        Cached::Miss => {
                            misses.push(backend.name);
                            continue;
                        }
                        Cached::Absent => {}
                    }
                }
            }
            to_fetch.push(backend);
        }

        let timeout = Duration::from_secs(opts.timeout_secs);
        let fetches = to_fetch.iter().map(|b| {
            let client = client.clone();
            let coord = coord.clone();
            async move {
                match tokio::time::timeout(timeout, (b.lookup)(&client, &coord)).await {
                    Ok(Ok(result)) => (b.name, Ok(result)),
                    Ok(Err(e)) => (b.name, Err(e.to_string())),
                    Err(_) => (b.name, Err("timed out".to_string())),
                }
            }
        });
        for (name, outcome) in join_all(fetches).await {
            match outcome {
                Ok(Some(finding)) => {
                    if let Some(cache) = &cache {
                        cache.put(name, coord, Some(&finding));
                    }
                    fresh.push(finding);
                }
                Ok(None) => {
                    if let Some(cache) = &cache {
                        cache.put(name, coord, None);
                    }
                    misses.push(name);
                }
                // Errors are reported but never cached: transient
                // upstream failure must not masquerade as a durable miss.
                Err(e) => errors.push((name, e)),
            }
        }
    }

    let indexes = crate::inverted::open_all().unwrap_or_default();
    let mut evidence = walk::walk(coord, &indexes, cache.as_ref());

    // With --no-cache the fresh findings never reached the store, so
    // the walk can't have seen them; merge them in (dedup by identity).
    let seen: std::collections::HashSet<String> = evidence
        .iter()
        .map(|e| serde_json::to_string(&e.finding).unwrap_or_default())
        .collect();
    for finding in fresh {
        if !seen.contains(&serde_json::to_string(&finding).unwrap_or_default()) {
            evidence.push(walk::Evidence {
                found_at: coord.clone(),
                finding,
            });
        }
    }

    let result = walk::cluster(evidence, coord);
    Ok(Resolution {
        coord: coord.clone(),
        clusters: result.clusters,
        collision: result.collision,
        truncated: result.truncated,
        misses,
        errors,
        offline: opts.offline,
    })
}
