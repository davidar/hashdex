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
    /// Restrict network probes to these backends (None = all). Scan's
    /// --online sets this so each digest only visits backends whose
    /// membership filter matched.
    pub only: Option<std::collections::HashSet<&'static str>>,
    /// Show a live stderr line naming the backends still being waited
    /// on. Single lookups want this (one slow backend blocks the whole
    /// render — the wait must not look like a hang); scan's batch
    /// probes run under their own ticker and set it false.
    pub progress: bool,
}

/// Resolution order (DESIGN.md): network backends are asked about the
/// queried coordinate only; the local walk then expands across the
/// pulled datasets and the observation store — including coordinates
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
            // A pulled dataset answers from disk in the walk below —
            // its network backend would re-read the same rows remotely.
            if crate::datasets::is_local(backend.name) {
                continue;
            }
            if let Some(only) = &opts.only {
                if !only.contains(backend.name) {
                    continue;
                }
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
        let pending: std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<&'static str>>> =
            std::sync::Arc::new(std::sync::Mutex::new(
                to_fetch.iter().map(|b| b.name).collect(),
            ));
        // The render is all-or-nothing (cluster welding needs every
        // answer), so one slow backend holds the terminal — name it
        // instead of sitting silent.
        let ticker = if opts.progress && !to_fetch.is_empty() {
            let ticker = std::sync::Arc::new(crate::scan_cmd::Ticker::new());
            let task = tokio::spawn({
                let (ticker, pending) = (ticker.clone(), pending.clone());
                let start = std::time::Instant::now();
                async move {
                    loop {
                        let names: Vec<&str> = pending.lock().unwrap().iter().copied().collect();
                        if names.is_empty() {
                            break;
                        }
                        ticker.update(usize::MAX, 0, || {
                            format!(
                                "asking {}… ({}s)",
                                names.join(", "),
                                start.elapsed().as_secs()
                            )
                        });
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            });
            Some((ticker, task))
        } else {
            None
        };
        let fetches = to_fetch.iter().map(|b| {
            let client = client.clone();
            let coord = coord.clone();
            let pending = pending.clone();
            async move {
                let outcome = match tokio::time::timeout(timeout, (b.lookup)(&client, &coord)).await
                {
                    Ok(Ok(result)) => (b.name, Ok(result)),
                    Ok(Err(e)) => (b.name, Err(e.to_string())),
                    Err(_) => (b.name, Err("timed out".to_string())),
                };
                pending.lock().unwrap().remove(b.name);
                outcome
            }
        });
        let outcomes = join_all(fetches).await;
        if let Some((ticker, task)) = ticker {
            task.abort();
            ticker.clear();
        }
        for (name, outcome) in outcomes {
            match outcome {
                Ok(findings) if findings.is_empty() => {
                    if let Some(cache) = &cache {
                        cache.put(name, coord, &[]);
                    }
                    misses.push(name);
                }
                Ok(findings) => {
                    if let Some(cache) = &cache {
                        cache.put(name, coord, &findings);
                    }
                    fresh.extend(findings);
                }
                // Errors are reported but never cached: transient
                // upstream failure must not masquerade as a durable miss.
                Err(e) => errors.push((name, e)),
            }
        }
    }

    let datasets = crate::datasets::open_all();
    let local = |c: &Coord| -> Vec<Finding> { datasets.iter().flat_map(|d| d.lookup(c)).collect() };
    let mut evidence = walk::walk(std::slice::from_ref(coord), &local, cache.as_ref());

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
