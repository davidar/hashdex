//! `hdx peek` — the hashoscope. Diffoscope dissects containers to
//! diff them; peek dissects them to *identify* them: every nested
//! member gets its coordinates minted in one streaming pass and is
//! then checked against the membership filters and claim indexes,
//! exactly like a file on disk in `hdx scan`. A pristine tarball no
//! index has ever seen usually contains hundreds of files the indexes
//! know intimately — peek makes that visible.
//!
//! This is user-initiated local hashing, the one admission-rule
//! exception: no format handler here may ever imply a fetch.
//!
//! The machinery lives next door: `peek_walk` parses formats on one
//! thread, `peek_pool` hashes and probes on all the others, and
//! `peek_source` provides the range views that keep seekable
//! containers (an iso, the squashfs inside it) from ever being
//! copied or spooled.

use crate::filter::NamedFilter;
use crate::finding::Finding;
use crate::peek_pool::{Member, Pool};
use crate::peek_source::View;
use crate::peek_walk::{Walk, MAX_MEMBERS};
use crate::scan_cmd::{
    human, local_verdicts, online_probe, s, FileResult, Ticker, IDENTITY_MIN_BYTES,
};
use anyhow::{Context, Result};
use serde_json::json;
use std::path::PathBuf;

/// One member's resolution tier, computed once and reused by the
/// listing, the summary, and the container rollups.
#[derive(Clone, Copy, PartialEq)]
enum Class {
    Identified,
    Consistent,
    Membership,
    Unknown,
    Floor,
}

/// Recursive verdict for a container: counts over every LEAF
/// descendant, at any depth.
#[derive(Default, Clone, Copy)]
struct Rollup {
    total: usize,
    known: usize,
    unknown: usize,
    floor: usize,
}

// ------------------------------------------------------------ command

pub struct Options {
    pub verbose: bool,
    pub json: bool,
    /// --online consent, parsed like scan's: Some([]) = all
    /// third-party APIs, Some(list) restricts, None = datasets only.
    pub online: Option<Vec<String>>,
}

pub async fn peek(
    paths: &[PathBuf],
    opts: &Options,
    ropts: &crate::resolve::Options,
    client: &reqwest::Client,
) -> Result<()> {
    let filters = crate::filter::load_all()?;
    let ticker = Ticker::new();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(2);

    let mut members: Vec<Member> = Vec::new();
    let mut truncated = false;
    for root in paths {
        let meta = std::fs::metadata(root).with_context(|| format!("open {}", root.display()))?;
        anyhow::ensure!(
            meta.is_file(),
            "{} is not a file (peek opens containers; scan walks trees)",
            root.display()
        );
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.display().to_string());
        // Misbehaved stream zips are handled inside the walk: the
        // nearest re-derivable ancestor (ranged member, spool, or
        // squashfs file) discards just that subtree and redoes it
        // conservatively, so no error escapes to this level short of
        // a genuinely unreadable file.
        let mut probe_order: Vec<&NamedFilter> = filters.iter().collect();
        probe_order.sort_by_key(|f| f.bytes);
        let pool = Pool::new(probe_order, &ticker, threads);
        let (trunc, discarded) = std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| pool.worker());
            }
            let mut walk = Walk {
                pool: &pool,
                slots: 0,
                truncated: false,
                conservative: false,
                discarded: Vec::new(),
            };
            let r = View::of_file(root)
                .and_then(|view| walk.process_ranged(view, root.display().to_string(), &name, 0));
            if r.is_ok() {
                // Only a complete descent closed every member; an
                // aborted one just lets the queue drain.
                pool.wait_idle();
            }
            pool.close();
            r.map(|()| (walk.truncated, walk.discarded))
        })?;
        truncated |= trunc;
        let mut sealed = pool.members.into_inner().unwrap();
        // Subtrees abandoned by conservative retries: straggler seals
        // may have landed in these slots after the discard — clear
        // them now that the workers have joined.
        for range in discarded {
            for slot in range {
                sealed[slot] = None;
            }
        }
        members.extend(sealed.into_iter().flatten());
    }
    ticker.clear();

    // Demand-driven probes for matched digests — same consent line as
    // scan: dataset transports by default, third-party APIs behind
    // --online. Only members a filter matched can be probed, so only
    // those need FileResults.
    let results: Vec<FileResult> = members
        .iter()
        .filter(|m| !m.matched.is_empty())
        .map(|m| FileResult {
            path: PathBuf::from(&m.path),
            size: m.size,
            mtime_ns: 0,
            sha1: m.digests.sha1,
            sha256: m.digests.sha256,
            from_index: false,
            matched: m.matched.clone(),
        })
        .collect();
    if !ropts.offline {
        online_probe(
            &results,
            &filters,
            opts.online.as_deref(),
            client,
            ropts,
            &ticker,
        )
        .await;
        ticker.clear();
    }

    // Local resolution: pulled datasets + the observation store the
    // probes just enriched. Members below the identity floor are never
    // attributed. The per-member walk is embarrassingly parallel
    // (dataset reads are lock-free mmap lookups; each worker opens its
    // own read connection to the observation store), and half a
    // million members at a millisecond each is far too long to be a
    // silent single-threaded phase.
    type Evidence = (Vec<Finding>, Vec<Finding>);
    let datasets = crate::datasets::open_all();
    let evidence: Vec<Evidence> = {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let out: std::sync::Mutex<Vec<Option<Evidence>>> =
            std::sync::Mutex::new((0..members.len()).map(|_| None).collect());
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    let cache = crate::cache::Cache::open().ok();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= members.len() {
                            break;
                        }
                        let m = &members[i];
                        let v = if m.size >= IDENTITY_MIN_BYTES {
                            local_verdicts(
                                &m.digests.sha256,
                                &m.digests.sha1,
                                datasets,
                                cache.as_ref(),
                            )
                        } else {
                            (Vec::new(), Vec::new())
                        };
                        out.lock().unwrap()[i] = Some(v);
                        let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                        ticker.update(100_000, d, || {
                            format!("resolving locally… {d}/{} members", members.len())
                        });
                    }
                });
            }
        });
        out.into_inner()
            .unwrap()
            .into_iter()
            .map(|v| v.expect("every member resolved"))
            .collect()
    };
    ticker.clear();
    let mut rendered = Vec::new();
    let mut n_identified = 0usize;
    let mut n_consistent = 0usize;
    let mut n_membership = 0usize;
    let mut n_unknown = 0usize;
    let mut per_filter: std::collections::BTreeMap<String, usize> = Default::default();
    for (m, (identified, consistent)) in members.iter().zip(evidence) {
        for name in &m.matched {
            *per_filter.entry(name.clone()).or_default() += 1;
        }
        let has_claims = identified.iter().any(|f| !f.claims.is_empty());
        let has_consistent = consistent.iter().any(|f| !f.claims.is_empty());
        let class = if m.size < IDENTITY_MIN_BYTES {
            Class::Floor
        } else if has_claims {
            n_identified += 1;
            Class::Identified
        } else if has_consistent {
            n_consistent += 1;
            Class::Consistent
        } else if !m.matched.is_empty() {
            n_membership += 1;
            Class::Membership
        } else {
            n_unknown += 1;
            Class::Unknown
        };
        rendered.push((m, identified, consistent, class));
    }

    // A container's verdict is recursive: roll up every LEAF
    // descendant (members are in DFS order, so a member's subtree is
    // the run of deeper entries that follows it). Wrapper
    // pseudo-members and nested containers don't count against the
    // rollup — their own bytes being unindexed says nothing about
    // what they hold.
    let rollups: Vec<Option<Rollup>> = (0..rendered.len())
        .map(|i| {
            let (m, ..) = &rendered[i];
            if m.children == 0 {
                return None;
            }
            let mut r = Rollup::default();
            for (d, .., class) in rendered.iter().skip(i + 1) {
                if d.depth <= m.depth {
                    break;
                }
                if d.children > 0 {
                    continue;
                }
                r.total += 1;
                match class {
                    Class::Identified | Class::Consistent | Class::Membership => r.known += 1,
                    Class::Unknown => r.unknown += 1,
                    Class::Floor => r.floor += 1,
                }
            }
            Some(r)
        })
        .collect();

    if opts.json {
        let out: Vec<serde_json::Value> = rendered
            .iter()
            .zip(&rollups)
            .map(|((m, identified, consistent, _), rollup)| {
                let mut v = json!({
                    "path": m.path,
                    "depth": m.depth,
                    "kind": m.kind,
                    "size": m.size,
                    "members": m.children,
                    "coords": m.digests.coords().iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "filters": m.matched,
                    "identified": identified,
                    "consistent": consistent,
                    "note": m.note,
                });
                if let Some(r) = rollup {
                    v["rollup"] = json!({
                        "files": r.total,
                        "known": r.known,
                        "unknown": r.unknown,
                        "below_floor": r.floor,
                    });
                }
                v
            })
            .collect();
        println!(
            "{}",
            json!({
                "members": out,
                "truncated": truncated,
                "per_filter": per_filter,
            })
        );
        return Ok(());
    }

    for ((m, identified, consistent, _), rollup) in rendered.iter().zip(&rollups) {
        let indent = "  ".repeat(m.depth);
        let leaf = m.path.rsplit('!').next().unwrap_or(&m.path);
        let mut line = format!("{indent}{leaf} — {}", human(m.size));
        if m.kind != "file" {
            line.push_str(&format!(", {}", m.kind));
        }
        if let Some(r) = rollup {
            // The container's verdict is its contents', recursively.
            if r.total == 0 {
                line.push_str(" (no file members)");
            } else if r.unknown == 0 && r.floor == 0 {
                line.push_str(&format!(" ({} member{}, all known)", r.total, s(r.total)));
            } else {
                let mut parts = format!(" ({} member{}: {} known", r.total, s(r.total), r.known);
                if r.unknown > 0 {
                    parts.push_str(&format!(", {} unknown", r.unknown));
                }
                if r.floor > 0 {
                    parts.push_str(&format!(", {} below floor", r.floor));
                }
                parts.push(')');
                line.push_str(&parts);
            }
        }
        let no_claims = identified.iter().all(|f| f.claims.is_empty())
            && consistent.iter().all(|f| f.claims.is_empty());
        if m.size < IDENTITY_MIN_BYTES {
            line.push_str("  (below identity floor)");
        } else if no_claims && !m.matched.is_empty() {
            line.push_str(&format!("  [{}]", m.matched.join(",")));
        } else if no_claims && m.children == 0 {
            // Only leaves wear "unknown" — a container's own unindexed
            // bytes say nothing about what it holds.
            line.push_str("  — unknown");
        }
        println!("{line}");
        if let Some(note) = &m.note {
            println!("{indent}  note: {note}");
        }
        render_claims(&indent, "", identified, opts.verbose);
        render_claims(&indent, "consistent (sha1): ", consistent, opts.verbose);
    }

    let total_bytes: u64 = members
        .iter()
        .filter(|m| m.depth <= 1)
        .map(|m| m.size)
        .sum();
    let mut summary = format!(
        "\n{} member{} ({}) — {n_identified} identified, {n_consistent} consistent (weak digests only), \
         {n_membership} known to filters, {n_unknown} unknown",
        members.len(),
        s(members.len()),
        human(total_bytes),
    );
    if truncated {
        summary.push_str(&format!(
            "\nstopped at {MAX_MEMBERS} members — the rest were not examined"
        ));
    }
    eprintln!("{summary}");
    if !per_filter.is_empty() {
        let tags: Vec<String> = per_filter
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        eprintln!("  {}", tags.join("   "));
    }
    Ok(())
}

fn render_claims(indent: &str, prefix: &str, findings: &[Finding], verbose: bool) {
    if verbose {
        for f in findings {
            for c in &f.claims {
                println!("{indent}  {prefix}{}: {}", f.backend, c.statement);
                if let Some(url) = &c.url {
                    println!("{indent}    → {url}");
                }
            }
        }
        return;
    }
    // Compact: the most informative claim per backend — a URL beats
    // none, longer statements beat join-key stubs.
    let mut best: std::collections::BTreeMap<&str, &crate::finding::Claim> = Default::default();
    for f in findings {
        for c in &f.claims {
            let e = best.entry(f.backend.as_str()).or_insert(c);
            if (c.url.is_some(), c.statement.len()) > (e.url.is_some(), e.statement.len()) {
                *e = c;
            }
        }
    }
    for (backend, c) in best {
        println!("{indent}  {prefix}{backend}: {}", c.statement);
        if let Some(url) = &c.url {
            println!("{indent}    → {url}");
        }
    }
}
