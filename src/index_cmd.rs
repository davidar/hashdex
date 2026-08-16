//! `hdx index`: local copies of the published claim datasets. Nothing
//! here is required — resolution range-reads the published parquet on
//! demand — but a pulled copy makes lookups local-disk fast and fully
//! offline. The local file IS the published file (same page-indexed
//! parquet, byte for byte), read via mmap instead of HTTP.

use crate::datasets::{self, Spec};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// One stream to the Hub's CDN saturates around 8 MB/s however fat the
/// link is, so multi-GB datasets arrive as concurrent ranged chunks —
/// the same trick `hf_transfer` plays. Chunks are big enough that the
/// per-request round trip disappears, and few enough that the in-flight
/// buffers stay bounded (one streaming chunk per job, not one whole
/// chunk in memory).
const CHUNK: u64 = 16 << 20;
const JOBS: usize = 8;
/// Below this a single stream is already the whole story.
const PARALLEL_MIN: u64 = 32 << 20;
/// A chunk is re-requested from scratch on a transport error; a whole
/// pull is long enough that one dropped connection must not lose it.
const TRIES: usize = 3;

/// The Hub speaks HTTP/2, which multiplexes every concurrent range
/// request onto ONE TCP connection — one congestion window, one
/// stream's worth of throughput, precisely what the chunking is trying
/// to escape (measured: 8 jobs over h2 moved 10 MB/s where 6 separate
/// connections moved 24). Bulk transfers get their own HTTP/1.1 client
/// so a job really is its own connection.
fn bulk_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(format!("hashdex-hdx/{}", env!("CARGO_PKG_VERSION")))
        .http1_only()
        .pool_max_idle_per_host(JOBS)
        .build()?)
}

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

struct RemoteFile {
    path: String,
    size: u64,
    /// LFS oid = the file's sha256. Absent only for git-stored files
    /// (under the LFS threshold), where `oid` is the git blob sha1.
    sha256: Option<String>,
    git_oid: String,
}

/// The repo's parquet files at one revision, via the Hub tree API
/// (following Link pagination).
async fn list_remote_files(
    client: &reqwest::Client,
    spec: &Spec,
    revision: &str,
) -> Result<Vec<RemoteFile>> {
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
            let is_parquet = path.ends_with(".parquet")
                && (path.starts_with("data/") || path.starts_with("maps/"));
            // The dataset's own membership filter is published in the
            // same repo. Pulled under the same revision pin, it can be
            // trusted to gate the parquet it was built from
            // (datasets::Gates); the independently-fetched filters dir
            // cannot.
            let is_bloom = path.ends_with(".bloom") && !path.contains('/');
            if kind == "file" && (is_parquet || is_bloom) {
                files.push(RemoteFile {
                    path: path.to_string(),
                    size: e["size"].as_u64().unwrap_or(0),
                    sha256: e["lfs"]["oid"].as_str().map(str::to_string),
                    git_oid: e["oid"].as_str().unwrap_or_default().to_string(),
                });
            }
        }
        match next {
            Some(n) => url = n,
            None => break,
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
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
    if !files.iter().any(|f| f.path.ends_with(".parquet")) {
        bail!("no parquet files under data/ or maps/ in {}", spec.repo);
    }
    let total: u64 = files.iter().map(|f| f.size).sum();
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
    let progress = Progress::new(tty, total);
    let bulk = bulk_client()?;
    for RemoteFile { path, size, .. } in &files {
        let dest = dir.join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if dest.metadata().is_ok_and(|m| m.len() == *size) && *size > 0 {
            eprintln!("  {path} — already present");
            progress.skip(*size);
            continue;
        }
        let url = format!("{}/{revision}/{path}", spec.resolve_base());
        let part = dir.join(format!("{path}.part"));
        let got = download(&bulk, &url, &part, *size, path, &progress)
            .await
            .with_context(|| format!("download {path}"))?;
        if *size > 0 && got != *size {
            bail!("{path}: got {got} bytes, expected {size}");
        }
        std::fs::rename(&part, &dest)?;
        progress.finish_file();
        if tty {
            eprint!("\r\x1b[2K");
        }
        eprintln!("  {path} — done ({})", human(got));
    }

    // Written LAST: its presence is the "pull completed" marker that
    // makes the local copy eligible for resolution.
    std::fs::write(&pin, &revision)?;

    // Length said every byte arrived; only hashing says the RIGHT
    // bytes did. The transport this checks is the pull's own, so it
    // runs now instead of waiting to be remembered — a file that
    // doesn't hash to its published oid is quarantined and the pin
    // dropped before anything reads it as evidence.
    verify(client, Some(name)).await?;

    println!(
        "installed {name}: {} files, {} in {} — resolution now reads it from disk \
         (offline included); `hdx index rm {name}` frees it",
        files.len(),
        human(total),
        dir.display()
    );
    Ok(())
}

/// The one-line download display, shared by every chunk job in flight:
/// jobs report the bytes they land, and whichever one crosses the next
/// tick prints. Rates count moved bytes only — files already present
/// are progress, but they are not throughput.
struct Progress {
    tty: bool,
    total: u64,
    done: AtomicU64,
    moved: AtomicU64,
    file_done: AtomicU64,
    file_size: AtomicU64,
    started: std::time::Instant,
    last_tick_ms: AtomicU64,
    /// `moved` as of the last printed tick: the displayed rate is the
    /// last window's, not the whole run's, so a stall reads as one.
    tick_moved: AtomicU64,
}

impl Progress {
    fn new(tty: bool, total: u64) -> Progress {
        Progress {
            tty,
            total,
            done: AtomicU64::new(0),
            moved: AtomicU64::new(0),
            file_done: AtomicU64::new(0),
            file_size: AtomicU64::new(0),
            started: std::time::Instant::now(),
            last_tick_ms: AtomicU64::new(0),
            tick_moved: AtomicU64::new(0),
        }
    }

    /// A file already on disk: counted toward the total, never toward
    /// the rate.
    fn skip(&self, size: u64) {
        self.done.fetch_add(size, Ordering::Relaxed);
    }

    fn start_file(&self, size: u64) {
        self.file_done.store(0, Ordering::Relaxed);
        self.file_size.store(size, Ordering::Relaxed);
    }

    fn finish_file(&self) {
        self.file_done.store(0, Ordering::Relaxed);
    }

    fn advance(&self, label: &str, n: u64) {
        let file_done = self.file_done.fetch_add(n, Ordering::Relaxed) + n;
        let done = self.done.fetch_add(n, Ordering::Relaxed) + n;
        let moved = self.moved.fetch_add(n, Ordering::Relaxed) + n;
        if !self.tty {
            return;
        }
        // One printer at a time: the job that wins the tick swap owns
        // the line until the next one is due.
        let ms = self.started.elapsed().as_millis() as u64;
        let last = self.last_tick_ms.load(Ordering::Relaxed);
        if ms < last + 100
            || self
                .last_tick_ms
                .compare_exchange(last, ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        // The CAS above guarantees ms - last >= 100. A retry's rewind
        // can put `moved` below the last tick's; that window prints 0.
        let prev = self.tick_moved.swap(moved, Ordering::Relaxed);
        let rate = moved.saturating_sub(prev) * 1000 / (ms - last);
        eprint!(
            "\r  {label} — {} / {} ({} of {} total, {}/s)   ",
            human(file_done),
            human(self.file_size.load(Ordering::Relaxed)),
            human(done),
            human(self.total),
            human(rate),
        );
    }

    /// Un-count a failed attempt's bytes before it is retried.
    fn rewind(&self, n: u64) {
        self.file_done.fetch_sub(n, Ordering::Relaxed);
        self.done.fetch_sub(n, Ordering::Relaxed);
        self.moved.fetch_sub(n, Ordering::Relaxed);
    }
}

/// Write at an absolute offset, on a handle of this job's own: chunk
/// jobs share the file, never a file cursor (Windows' positional write
/// moves one, and two jobs sharing it would race).
fn write_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut offset) = (buf, offset);
        while !buf.is_empty() {
            let n = file.seek_write(buf, offset)?;
            buf = &buf[n..];
            offset += n as u64;
        }
        Ok(())
    }
}

/// One file into `part`. Big files arrive as `JOBS` concurrent ranged
/// chunks — a single stream to the Hub's CDN plateaus around 8 MB/s,
/// which turns a 10 GB dataset into an hour — and anything else (or a
/// server that ignores Range) streams once, as before.
async fn download(
    client: &reqwest::Client,
    url: &str,
    part: &Path,
    size: u64,
    label: &str,
    progress: &Progress,
) -> Result<u64> {
    progress.start_file(size);
    if size < PARALLEL_MIN || !supports_ranges(client, url).await {
        return stream_whole(client, url, part, label, progress).await;
    }

    // Preallocated, so every job writes straight to its own offset.
    let file = std::fs::File::create(part).with_context(|| format!("create {}", part.display()))?;
    file.set_len(size)?;
    drop(file);

    let ranges: Vec<(u64, u64)> = (0..size.div_ceil(CHUNK))
        .map(|i| {
            let start = i * CHUNK;
            (start, CHUNK.min(size - start))
        })
        .collect();
    let mut jobs = futures::stream::iter(
        ranges
            .into_iter()
            .map(|(start, len)| chunk(client, url, part, start, len, label, progress)),
    )
    .buffer_unordered(JOBS);
    let mut got = 0u64;
    while let Some(n) = jobs.next().await {
        got += n?;
    }
    Ok(got)
}

/// Whether the server answers a ranged request with partial content.
/// One tiny request per file, which the parallel path pays back many
/// times over — and when the answer is no, the caller streams instead
/// of failing every chunk in turn.
async fn supports_ranges(client: &reqwest::Client, url: &str) -> bool {
    let resp = maybe_auth(client.get(url), url)
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .await;
    matches!(resp, Ok(r) if r.status() == reqwest::StatusCode::PARTIAL_CONTENT)
}

/// One chunk, retried from scratch on a transport error: a 10 GB pull
/// is long enough that a single dropped connection must not lose it.
async fn chunk(
    client: &reqwest::Client,
    url: &str,
    part: &Path,
    start: u64,
    len: u64,
    label: &str,
    progress: &Progress,
) -> Result<u64> {
    let mut last = None;
    for attempt in 1..=TRIES {
        let mut wrote = 0u64;
        match try_chunk(client, url, part, start, len, label, progress, &mut wrote).await {
            Ok(()) => return Ok(wrote),
            Err(e) => {
                progress.rewind(wrote);
                if attempt < TRIES {
                    eprintln!("\r\x1b[2K  {label} — chunk at {start} failed ({e}), retrying");
                    // A moment's pause: a transport blip needs it, and
                    // a systemic failure shouldn't burn its retries in
                    // the same millisecond it first failed in.
                    tokio::time::sleep(std::time::Duration::from_secs(attempt as u64)).await;
                }
                last = Some(e);
            }
        }
    }
    Err(last.expect("a failed chunk carries its error"))
}

#[allow(clippy::too_many_arguments)]
async fn try_chunk(
    client: &reqwest::Client,
    url: &str,
    part: &Path,
    start: u64,
    len: u64,
    label: &str,
    progress: &Progress,
    wrote: &mut u64,
) -> Result<()> {
    let resp = maybe_auth(client.get(url), url)
        .header(
            reqwest::header::RANGE,
            format!("bytes={start}-{}", start + len - 1),
        )
        .send()
        .await?
        .error_for_status()?;
    if resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        bail!(
            "ranged request answered {} — expected partial content",
            resp.status()
        );
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(part)
        .with_context(|| format!("open {}", part.display()))?;
    let mut stream = resp.bytes_stream();
    while let Some(bytes) = stream.next().await {
        let bytes = bytes?;
        write_at(&file, &bytes, start + *wrote)?;
        *wrote += bytes.len() as u64;
        progress.advance(label, bytes.len() as u64);
    }
    if *wrote != len {
        bail!("chunk at {start}: got {wrote} bytes, expected {len}");
    }
    Ok(())
}

/// The single-stream path: small files, and any server that won't serve
/// ranges.
async fn stream_whole(
    client: &reqwest::Client,
    url: &str,
    part: &Path,
    label: &str,
    progress: &Progress,
) -> Result<u64> {
    use std::io::Write;
    let resp = maybe_auth(client.get(url), url)
        .send()
        .await?
        .error_for_status()?;
    let mut out = std::io::BufWriter::new(
        std::fs::File::create(part).with_context(|| format!("create {}", part.display()))?,
    );
    let mut stream = resp.bytes_stream();
    let mut got = 0u64;
    while let Some(bytes) = stream.next().await {
        let bytes = bytes?;
        out.write_all(&bytes)?;
        got += bytes.len() as u64;
        progress.advance(label, bytes.len() as u64);
    }
    out.flush()?;
    Ok(got)
}

/// `hdx index verify [name]`: hash every file of a pulled dataset and
/// compare against the repo's LFS oids (= sha256 of the published
/// bytes) at the pinned revision. The local copy is supposed to BE the
/// published file, so any difference is drift worth naming: bitrot,
/// truncation, or a repo that changed under the pin.
pub async fn verify(client: &reqwest::Client, name: Option<&str>) -> Result<()> {
    let specs: Vec<&'static Spec> = match name {
        Some(n) => vec![find_spec(n)?],
        None => datasets::SPECS.to_vec(),
    };
    let mut checked = 0usize;
    let mut drifted = 0usize;
    for spec in specs {
        let dir = datasets::datasets_dir().join(spec.name);
        let pin = match std::fs::read_to_string(dir.join("revision")) {
            Ok(p) => p.trim().to_string(),
            Err(_) => {
                if name.is_some() {
                    bail!("{} has no local copy — nothing to verify", spec.name);
                }
                continue;
            }
        };

        // Prefer the pinned revision: it names the exact bytes pull
        // installed. A copy installed by hand carries no real pin, and
        // history rewrites (squashes) can kill old revisions — main is
        // the only tree left in either case.
        let is_sha = pin.len() == 40 && pin.bytes().all(|b| b.is_ascii_hexdigit());
        let (files, against) = if !is_sha {
            eprintln!(
                "{}: local copy wasn't installed by pull (marker {pin:?}) — \
                 verifying against main",
                spec.name
            );
            (
                list_remote_files(client, spec, "main").await?,
                "main".to_string(),
            )
        } else {
            match list_remote_files(client, spec, &pin).await {
                Ok(f) => (f, pin.clone()),
                Err(e) if format!("{e:?}").contains("404") => {
                    eprintln!(
                        "{}: pinned revision {} is no longer addressable (history \
                         rewritten?) — verifying against main",
                        spec.name,
                        &pin[..pin.len().min(12)]
                    );
                    (
                        list_remote_files(client, spec, "main").await?,
                        "main".into(),
                    )
                }
                Err(e) => return Err(e),
            }
        };
        println!(
            "verifying {} against hf.co/datasets/{} @ {}",
            spec.name,
            spec.repo,
            &against[..against.len().min(12)]
        );

        let mut local_seen = std::collections::HashSet::new();
        let mut quarantine: Vec<PathBuf> = Vec::new();
        let mut missing = 0usize;
        for f in &files {
            local_seen.insert(dir.join(&f.path));
            checked += 1;
            let dest = dir.join(&f.path);
            let meta = match dest.metadata() {
                Ok(m) => m,
                Err(_) => {
                    println!("  {} — MISSING locally", f.path);
                    drifted += 1;
                    missing += 1;
                    continue;
                }
            };
            if meta.len() != f.size {
                println!(
                    "  {} — SIZE MISMATCH (local {}, published {})",
                    f.path,
                    human(meta.len()),
                    human(f.size)
                );
                drifted += 1;
                quarantine.push(dest);
                continue;
            }
            let ok = match &f.sha256 {
                Some(want) => {
                    let got = hash_file_sha256(&dest, &f.path)?;
                    if &got == want {
                        true
                    } else {
                        println!(
                            "  {} — MISMATCH (local sha256 {}…, published {}…)",
                            f.path,
                            &got[..12],
                            &want[..want.len().min(12)]
                        );
                        false
                    }
                }
                // Small git-stored file: no LFS oid, but the tree oid
                // is the git blob sha1 — the same sha1_git coordinate
                // hdx mints, so compare that instead.
                None => {
                    let got = hash_file_git_blob(&dest)?;
                    if got == f.git_oid {
                        true
                    } else {
                        println!(
                            "  {} — MISMATCH (local git blob {}…, published {}…)",
                            f.path,
                            &got[..12],
                            &f.git_oid[..f.git_oid.len().min(12)]
                        );
                        false
                    }
                }
            };
            if ok {
                println!("  {} — ok ({})", f.path, human(f.size));
            } else {
                drifted += 1;
                quarantine.push(dest);
            }
        }

        // Files the published revision doesn't have are never read by
        // resolution (lookups open expected paths only) — name the
        // debris, don't fail on it.
        for entry in walkdir::WalkDir::new(&dir).into_iter().flatten() {
            let p = entry.path();
            if !entry.file_type().is_file() || local_seen.contains(p) {
                continue;
            }
            match p.extension().and_then(|e| e.to_str()) {
                Some("parquet") => println!(
                    "  note: {} is not in the published revision (stale leftover, \
                     safe to delete)",
                    p.strip_prefix(&dir).unwrap_or(p).display()
                ),
                Some("part") => println!(
                    "  note: leftover partial download {} (safe to delete)",
                    p.strip_prefix(&dir).unwrap_or(p).display()
                ),
                Some("drifted") => println!(
                    "  note: previously quarantined {} (safe to delete)",
                    p.strip_prefix(&dir).unwrap_or(p).display()
                ),
                // Stale parquet is inert (lookups open expected paths
                // only), but a bloom in this dir WOULD be read — Gates
                // trusts it as coherent with the pin. Move it out of
                // trust, don't just mention it.
                Some("bloom") => {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("bloom");
                    let q = p.with_file_name(format!("{name}.drifted"));
                    std::fs::rename(p, &q)
                        .with_context(|| format!("quarantine {}", p.display()))?;
                    println!(
                        "  note: {} is not in the published revision — quarantined as \
                         *.drifted (safe to delete)",
                        p.strip_prefix(&dir).unwrap_or(p).display()
                    );
                }
                _ => {}
            }
        }

        // A drifted file must not keep serving wrong bytes, and a
        // local copy with a hole must not keep serving absence proofs:
        // quarantine the bad files and drop the completeness pin so
        // resolution falls back to remote range reads. A re-pull
        // re-downloads exactly what's gone (pull's size-based resume
        // would otherwise keep a size-preserving corruption).
        if !quarantine.is_empty() || missing > 0 {
            for p in &quarantine {
                // Appended, not substituted: a drifted bloom must not
                // quarantine under a parquet name.
                let q = match p.file_name().and_then(|n| n.to_str()) {
                    Some(n) => p.with_file_name(format!("{n}.drifted")),
                    None => p.with_extension("drifted"),
                };
                std::fs::rename(p, &q).with_context(|| format!("quarantine {}", p.display()))?;
            }
            let _ = std::fs::remove_file(dir.join("revision"));
            if !quarantine.is_empty() {
                println!(
                    "  {} drifted file{} quarantined as *.drifted (safe to delete)",
                    quarantine.len(),
                    if quarantine.len() == 1 { "" } else { "s" },
                );
            }
            println!(
                "  the local copy is unpinned — resolution falls back to remote range \
                 reads; `hdx index pull {}` reinstalls",
                spec.name
            );
        }

        // A moved main is not drift — the pin still names real bytes —
        // but it is worth a line.
        if against == pin {
            if let Ok(v) = revision_of(client, spec).await {
                if v != pin {
                    println!(
                        "  note: the repo has moved on since this pull (main @ {}) — \
                         `hdx index pull {}` to update",
                        &v[..v.len().min(12)],
                        spec.name
                    );
                }
            }
        }
    }
    if checked == 0 {
        println!("no local dataset copies to verify — `hdx index pull <name>` installs one");
    } else if drifted == 0 {
        println!(
            "{checked} file{} verified — every local byte matches the published dataset{}",
            if checked == 1 { "" } else { "s" },
            if name.is_none() { "s" } else { "" }
        );
    } else {
        bail!("{drifted} of {checked} files FAILED verification");
    }
    Ok(())
}

async fn revision_of(client: &reqwest::Client, spec: &Spec) -> Result<String> {
    let rev_api = spec.revision_api();
    let v: serde_json::Value = maybe_auth(client.get(&rev_api), &rev_api)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(v["sha"].as_str().context("no sha")?.to_string())
}

fn hash_file_sha256(path: &std::path::Path, label: &str) -> Result<String> {
    use sha2::Digest;
    let tty = {
        use std::io::IsTerminal;
        std::io::stderr().is_terminal()
    };
    let mut file = std::fs::File::open(path)?;
    let total = file.metadata()?.len();
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 8 << 20];
    let mut done = 0u64;
    let mut last_tick = std::time::Instant::now();
    loop {
        use std::io::Read;
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        done += n as u64;
        if tty && last_tick.elapsed().as_millis() >= 100 {
            last_tick = std::time::Instant::now();
            eprint!(
                "\r  {label} — hashing {} / {}   ",
                human(done),
                human(total)
            );
        }
    }
    if tty {
        eprint!("\r\x1b[2K");
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hash_file_git_blob(path: &std::path::Path) -> Result<String> {
    use sha1::Digest;
    let bytes = std::fs::read(path)?;
    let mut hasher = sha1::Sha1::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(&bytes);
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
