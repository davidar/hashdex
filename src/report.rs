//! The shared reporting layer over a member tree: local resolution,
//! verdict classification, recursive container rollups, tree ordering,
//! and the tree renderer. `hdx scan` builds one member tree for
//! everything it examines — directories (digestless container nodes),
//! disk files, and the nested members of descended containers — and
//! this module turns that tree plus the resolution evidence into
//! verdicts and output.

use crate::finding::Finding;
use crate::peek_pool::Member;
use crate::scan_cmd::{human, local_verdicts, s, Ticker, IDENTITY_MIN_BYTES};

/// One member's resolution tier, computed once and reused by the
/// listing, the summary, and the container rollups.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Class {
    Identified,
    Consistent,
    Membership,
    Unknown,
    Floor,
    /// A tree node without a bytestream of its own (a directory):
    /// no digests, no verdict — only its contents have verdicts.
    Node,
}

/// Recursive verdict for a container: counts over every LEAF
/// descendant, at any depth.
#[derive(Default, Clone, Copy)]
pub(crate) struct Rollup {
    pub(crate) total: usize,
    pub(crate) known: usize,
    pub(crate) unknown: usize,
    pub(crate) floor: usize,
}

pub(crate) type Evidence = (Vec<Finding>, Vec<Finding>);

/// Assemble the member tree from the pool's slot table: drop members
/// sealed into abandoned subtrees (conservative retries), renumber
/// parent pointers into the surviving table. A survivor's parent
/// always survives — discards drop whole subtrees, never a member
/// without its descendants. Roots are filesystem objects whichever
/// arm created them.
pub(crate) fn compact_members(mut sealed: Vec<Option<Member>>, dead: &[usize]) -> Vec<Member> {
    for &slot in dead {
        sealed[slot] = None;
    }
    let mut members: Vec<Member> = Vec::new();
    let mut remap: Vec<Option<usize>> = vec![None; sealed.len()];
    for (slot, m) in sealed.into_iter().enumerate() {
        if let Some(mut m) = m {
            remap[slot] = Some(members.len());
            m.parent = m.parent.map(|p| remap[p].expect("parent survived discard"));
            if m.parent.is_none() {
                m.fs = true;
            }
            members.push(m);
        }
    }
    members
}

/// Resolve every member against the pulled datasets + observation
/// store, in parallel: dataset reads are lock-free mmap lookups, each
/// worker opens its own read connection to the observation store, and
/// half a million members at a millisecond each is far too long to be
/// a silent single-threaded phase. Digestless nodes and sub-floor
/// members get empty evidence.
pub(crate) fn resolve_members(
    members: &[Member],
    datasets: &[crate::datasets::LocalDataset],
    threads: usize,
    use_cache: bool,
    ticker: &Ticker,
) -> Vec<Evidence> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let out: std::sync::Mutex<Vec<Option<Evidence>>> =
        std::sync::Mutex::new((0..members.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let cache = use_cache
                    .then(|| crate::cache::Cache::open().ok())
                    .flatten();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= members.len() {
                        break;
                    }
                    let m = &members[i];
                    let v = match &m.digests {
                        Some(d) if m.size >= IDENTITY_MIN_BYTES => {
                            local_verdicts(&d.sha256, &d.sha1, datasets, cache.as_ref())
                        }
                        _ => (Vec::new(), Vec::new()),
                    };
                    out.lock().unwrap()[i] = Some(v);
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    ticker.update(100_000, d, || {
                        format!("resolving locally… {d}/{} files", members.len())
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
}

pub(crate) fn classify(m: &Member, evidence: &Evidence) -> Class {
    if m.digests.is_none() {
        return Class::Node;
    }
    let (identified, consistent) = evidence;
    let has_claims = identified.iter().any(|f| !f.claims.is_empty());
    let has_consistent = consistent.iter().any(|f| !f.claims.is_empty());
    if m.size < IDENTITY_MIN_BYTES {
        Class::Floor
    } else if has_claims {
        Class::Identified
    } else if has_consistent {
        Class::Consistent
    } else if !m.matched.is_empty() {
        Class::Membership
    } else {
        Class::Unknown
    }
}

/// A container's verdict is recursive: every LEAF descendant, at any
/// depth, rolls up into every enclosing container — each leaf walks
/// its parent chain once. Wrapper pseudo-members, nested containers,
/// and digestless nodes don't count against the rollup — their own
/// bytes being unindexed says nothing about what they hold.
pub(crate) fn rollups(members: &[Member], classes: &[Class]) -> Vec<Option<Rollup>> {
    let mut rollups: Vec<Option<Rollup>> = members
        .iter()
        .map(|m| (m.children > 0).then(Rollup::default))
        .collect();
    for (m, class) in members.iter().zip(classes) {
        if m.children > 0 || *class == Class::Node {
            continue;
        }
        let mut up = m.parent;
        while let Some(p) = up {
            if let Some(r) = rollups[p].as_mut() {
                r.total += 1;
                match class {
                    Class::Identified | Class::Consistent | Class::Membership => r.known += 1,
                    Class::Unknown => r.unknown += 1,
                    Class::Floor => r.floor += 1,
                    Class::Node => unreachable!(),
                }
            }
            up = members[p].parent;
        }
    }
    rollups
}

/// Output order is the tree's: children lists rebuilt from the parent
/// pointers, ordered by ord (allocation order within any one
/// container's walking thread; a retried member inherits its
/// predecessor's ord), depth-first from the roots. Nothing here
/// depends on the member table's own order.
pub(crate) fn tree_order(members: &[Member]) -> Vec<usize> {
    let mut kids: Vec<Vec<usize>> = vec![Vec::new(); members.len()];
    let mut roots_idx: Vec<usize> = Vec::new();
    for (i, m) in members.iter().enumerate() {
        match m.parent {
            Some(p) => kids[p].push(i),
            None => roots_idx.push(i),
        }
    }
    for k in &mut kids {
        k.sort_by_key(|&i| members[i].ord);
    }
    let mut order = Vec::with_capacity(members.len());
    let mut stack: Vec<usize> = roots_idx.into_iter().rev().collect();
    while let Some(i) = stack.pop() {
        order.push(i);
        stack.extend(std::mem::take(&mut kids[i]).into_iter().rev());
    }
    order
}

/// Render one member's tree line (indent, leaf name, size, kind,
/// rollup verdict, tags) plus its note and claims. `base` is the
/// depth rendered at indent zero — a container discovered deep in a
/// directory walk renders its subtree relative to itself.
pub(crate) fn render_tree_line(
    m: &Member,
    evidence: &Evidence,
    rollup: &Option<Rollup>,
    verbose: bool,
    base: usize,
) {
    let (identified, consistent) = evidence;
    let indent = "  ".repeat(m.depth.saturating_sub(base));
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
    if m.digests.is_some() {
        if m.size < IDENTITY_MIN_BYTES {
            line.push_str("  (below identity floor)");
        } else if no_claims && !m.matched.is_empty() {
            line.push_str(&format!("  [{}]", m.matched.join(",")));
        } else if no_claims && m.children == 0 {
            // Only leaves wear "unknown" — a container's own unindexed
            // bytes say nothing about what it holds.
            line.push_str("  — unknown");
        }
    }
    println!("{line}");
    if let Some(note) = &m.note {
        println!("{indent}  note: {note}");
    }
    render_claims(&indent, "", identified, verbose);
    render_claims(&indent, "consistent (sha1): ", consistent, verbose);
}

/// One member as a JSON object (the NDJSON line scan emits per member
/// in tree mode).
pub(crate) fn member_json(
    m: &Member,
    evidence: &Evidence,
    rollup: &Option<Rollup>,
) -> serde_json::Value {
    let (identified, consistent) = evidence;
    let mut v = serde_json::json!({
        "path": m.path,
        "depth": m.depth,
        "kind": m.kind,
        "size": m.size,
        "members": m.children,
        "coords": m.digests.as_ref().map(|d| {
            d.coords().iter().map(|c| c.to_string()).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "filters": m.matched,
        "identified": identified,
        "consistent": consistent,
        "note": m.note,
    });
    if let Some(r) = rollup {
        v["rollup"] = serde_json::json!({
            "files": r.total,
            "known": r.known,
            "unknown": r.unknown,
            "below_floor": r.floor,
        });
    }
    v
}

pub(crate) fn render_claims(indent: &str, prefix: &str, findings: &[Finding], verbose: bool) {
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
