use crate::backends;
use crate::cache::{Cache, Cached};
use crate::coord::Coord;
use crate::finding::Finding;
use anyhow::Result;
use futures::future::join_all;
use reqwest::Client;
use std::time::Duration;

pub struct Resolution {
    pub coord: Coord,
    pub findings: Vec<Finding>,
    pub misses: Vec<&'static str>,
    pub errors: Vec<(&'static str, String)>,
}

pub struct Options {
    pub refresh: bool,
    pub no_cache: bool,
    pub timeout_secs: u64,
}

pub async fn resolve(client: &Client, coord: &Coord, opts: &Options) -> Result<Resolution> {
    let cache = if opts.no_cache { None } else { Cache::open().ok() };
    let mut findings = Vec::new();
    let mut misses = Vec::new();
    let mut to_fetch = Vec::new();

    for backend in backends::all() {
        if !(backend.supports)(coord.scheme) {
            continue;
        }
        if !opts.refresh {
            if let Some(cache) = &cache {
                match cache.get(backend.name, coord) {
                    Cached::Hit(f) => {
                        findings.push(f);
                        continue;
                    }
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

    let mut errors = Vec::new();
    for (name, outcome) in join_all(fetches).await {
        match outcome {
            Ok(Some(finding)) => {
                if let Some(cache) = &cache {
                    cache.put(name, coord, Some(&finding));
                }
                findings.push(finding);
            }
            Ok(None) => {
                if let Some(cache) = &cache {
                    cache.put(name, coord, None);
                }
                misses.push(name);
            }
            // Errors are reported but never cached: transient upstream
            // failure must not masquerade as a durable miss.
            Err(e) => errors.push((name, e)),
        }
    }

    Ok(Resolution {
        coord: coord.clone(),
        findings,
        misses,
        errors,
    })
}
