//! `hdx index`: local copies of the published claim datasets. Nothing
//! here is required — resolution range-reads the published parquet on
//! demand — but a pulled copy makes lookups local-disk fast and fully
//! offline. The local file IS the published file (same page-indexed
//! parquet, byte for byte), read via mmap instead of HTTP.

use crate::datasets::{self, Spec};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use std::io::Write;
use std::path::PathBuf;

fn known_names() -> String {
    datasets::SPECS
        .iter()
        .map(|s| s.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn find_spec(name: &str) -> Result<&'static Spec> {
    datasets::spec(name)
        .with_context(|| format!("unknown dataset {name:?} (known: {})", known_names()))
}

/// HF_TOKEN raises the Hub's anonymous rate limits; attached only to
/// huggingface.co itself.
fn maybe_auth(req: reqwest::RequestBuilder, url: &str) -> reqwest::RequestBuilder {
    match std::env::var("HF_TOKEN") {
        Ok(t) if !t.is_empty() && url.starts_with("https://huggingface.co/") => req.bearer_auth(t),
        _ => req,
    }
}

/// The repo's parquet files at one revision, via the Hub tree API
/// (following Link pagination).
async fn list_remote_files(
    client: &reqwest::Client,
    spec: &Spec,
    revision: &str,
) -> Result<Vec<(String, u64)>> {
    let mut url = spec.tree_api(revision);
    let mut files = Vec::new();
    loop {
        let resp = maybe_auth(client.get(&url), &url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("list {}", spec.repo))?;
        let next = resp
            .headers()
            .get(reqwest::header::LINK)
            .and_then(|v| v.to_str().ok())
            .and_then(|link| {
                link.split(',').find_map(|part| {
                    part.contains("rel=\"next\"")
                        .then(|| part.split_once('<')?.1.split_once('>').map(|(u, _)| u))?
                        .map(str::to_string)
                })
            });
        let entries: Vec<serde_json::Value> = resp.json().await?;
        for e in &entries {
            let (Some(kind), Some(path)) = (e["type"].as_str(), e["path"].as_str()) else {
                continue;
            };
            if kind == "file"
                && path.ends_with(".parquet")
                && (path.starts_with("data/") || path.starts_with("maps/"))
            {
                files.push((path.to_string(), e["size"].as_u64().unwrap_or(0)));
            }
        }
        match next {
            Some(n) => url = n,
            None => break,
        }
    }
    files.sort();
    Ok(files)
}

/// `hdx index pull <name>`: download a dataset's parquet files into
/// the datasets dir, pinned to one revision. Idempotent — files whose
/// size already matches are kept, so an interrupted pull resumes.
pub async fn pull(client: &reqwest::Client, name: &str) -> Result<()> {
    let spec = find_spec(name)?;
    let rev_api = spec.revision_api();
    let v: serde_json::Value = maybe_auth(client.get(&rev_api), &rev_api)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("resolve revision of {}", spec.repo))?
        .json()
        .await?;
    let revision = v["sha"]
        .as_str()
        .context("no sha in revision response")?
        .to_string();

    let files = list_remote_files(client, spec, &revision).await?;
    if files.is_empty() {
        bail!("no parquet files under data/ or maps/ in {}", spec.repo);
    }
    let total: u64 = files.iter().map(|(_, s)| s).sum();
    let dir = datasets::datasets_dir().join(spec.name);
    eprintln!(
        "pulling {name} ({} files, {}) from hf.co/datasets/{} @ {}",
        files.len(),
        human(total),
        spec.repo,
        &revision[..revision.len().min(12)],
    );

    // A new revision may rename or change files: clear a stale pin so
    // a half-updated mix never reads as one dataset.
    let pin = dir.join("revision");
    if let Ok(old) = std::fs::read_to_string(&pin) {
        if old.trim() != revision {
            let _ = std::fs::remove_file(&pin);
        }
    }

    // In-place progress only on a tty; piped stderr gets one line per
    // file, not a chunk stream.
    let tty = {
        use std::io::IsTerminal;
        std::io::stderr().is_terminal()
    };
    let mut last_tick = std::time::Instant::now();
    let mut done_bytes = 0u64;
    for (path, size) in &files {
        let dest = dir.join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if dest.metadata().is_ok_and(|m| m.len() == *size) && *size > 0 {
            eprintln!("  {path} — already present");
            done_bytes += size;
            continue;
        }
        let url = format!("{}/{revision}/{path}", spec.resolve_base());
        let resp = maybe_auth(client.get(&url), &url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("download {path}"))?;
        let part = dest.with_extension("parquet.part");
        let mut out = std::io::BufWriter::new(
            std::fs::File::create(&part).with_context(|| format!("create {}", part.display()))?,
        );
        let mut stream = resp.bytes_stream();
        let mut got = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            out.write_all(&chunk)?;
            got += chunk.len() as u64;
            if tty && last_tick.elapsed().as_millis() >= 100 {
                last_tick = std::time::Instant::now();
                eprint!(
                    "\r  {path} — {} / {} ({} of {} total)   ",
                    human(got),
                    human(*size),
                    human(done_bytes + got),
                    human(total)
                );
            }
        }
        out.flush()?;
        drop(out);
        if *size > 0 && got != *size {
            bail!("{path}: got {got} bytes, expected {size}");
        }
        std::fs::rename(&part, &dest)?;
        done_bytes += got;
        if tty {
            eprint!("\r\x1b[2K");
        }
        eprintln!("  {path} — done ({})", human(got));
    }

    // Written LAST: its presence is the "pull completed" marker that
    // makes the local copy eligible for resolution.
    std::fs::write(&pin, &revision)?;
    println!(
        "installed {name}: {} files, {} in {} — resolution now reads it from disk \
         (offline included); `hdx index rm {name}` frees it",
        files.len(),
        human(total),
        dir.display()
    );
    Ok(())
}

/// `hdx index list`: every known dataset and its local state.
pub fn list() -> Result<()> {
    for spec in datasets::SPECS {
        let dir = datasets::datasets_dir().join(spec.name);
        let pulled = dir.join("revision").is_file();
        if pulled {
            let (n, bytes) = dir_stats(&dir);
            let rev = std::fs::read_to_string(dir.join("revision")).unwrap_or_default();
            println!(
                "{:<10} local: {n} files, {} @ {} ({})",
                spec.name,
                human(bytes),
                &rev.trim()[..rev.trim().len().min(12)],
                dir.display()
            );
        } else {
            println!(
                "{:<10} remote (range reads on demand) — `hdx index pull {}` ({}) for a local copy",
                spec.name, spec.name, spec.approx_size
            );
        }
    }
    // The pre-parquet HDXI format is retired; leftover files are dead
    // weight worth naming (they can be large).
    let old = crate::cache::cache_dir().join("index");
    if let Some((n, bytes)) = Some(dir_stats(&old)).filter(|(n, _)| *n > 0) {
        println!(
            "note: {} obsolete HDXI index file{} ({}) in {} — the format is retired; \
             delete the directory to reclaim the space",
            n,
            if n == 1 { "" } else { "s" },
            human(bytes),
            old.display()
        );
    }
    Ok(())
}

/// `hdx index rm <name>`: delete the local copy; resolution falls back
/// to remote range reads.
pub fn rm(name: &str) -> Result<()> {
    let spec = find_spec(name)?;
    let dir = datasets::datasets_dir().join(spec.name);
    if !dir.is_dir() {
        bail!("{name} has no local copy");
    }
    let (_, bytes) = dir_stats(&dir);
    std::fs::remove_dir_all(&dir)?;
    println!(
        "removed the local {name} copy ({}) — resolution goes back to range reads",
        human(bytes)
    );
    Ok(())
}

fn dir_stats(dir: &PathBuf) -> (usize, u64) {
    let mut n = 0;
    let mut bytes = 0;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        if entry.file_type().is_file() {
            n += 1;
            bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    (n, bytes)
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}
