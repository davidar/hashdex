//! Recipes: reconstruction manifests minted from container descents
//! (splice@0 — the first rung). A recipe is a verified proof of
//! composition: the container's bytes are a deterministic splice of
//! refs — member byte ranges the indexes actually name, claim URLs
//! attached — plus literal bytes carried in a zstd residue sidecar.
//! Refs require claims: descent's member boundaries are hypotheses
//! about public availability, and one no index verifies collapses
//! back into literal bytes (an unwitnessed digest is not knowledge —
//! you can hash any string). Recipe + sidecar + fetched refs rebuild
//! the file with nothing else on hand. `check` rebuilds from
//! locally-present blobs and verifies byte-exactness; it never
//! fetches — the claims say where the missing members live.
//!
//! The credibility rule: every build node is verified at mint time by
//! re-reading the recorded ranges and reproducing the node's sha256
//! byte-exact, and every ref is re-read and re-hashed the same way.
//! Anything that can't be verified stays literal — a recipe is never
//! wrong, only more or less compressed toward pure structure.

use crate::peek_pool::{Member, Pool};
use crate::peek_source::View;
use crate::peek_walk::Walk;
use crate::report;
use crate::scan_cmd::{hex_lower, human, s, Ticker, IDENTITY_MIN_BYTES};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::Digest as _;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Gap runs at or under this many bytes inline into the document as
/// hex; longer runs go to the residue sidecar.
const INLINE_MAX: u64 = 64;
/// `check` materializes a rebuilt container (needed only when a slice
/// addresses one) in RAM up to this, then in a temp file.
const CHECK_SPOOL_MAX: u64 = 64 << 20;

// ------------------------------------------------------------- planning

/// One input segment of a build's splice, in the build's own logical
/// coordinate space. Segments tile [0, size) exactly — asserted, then
/// proven by the verify pass re-splicing the bytes.
enum Seg {
    /// `len` bytes of member `idx` starting at its logical `from`;
    /// `root_off` is where those bytes live in the root file (known at
    /// mapping time because both members' extents share the source).
    Child {
        idx: usize,
        from: u64,
        len: u64,
        at: u64,
        root_off: u64,
    },
    /// A literal gap no surviving reference covers. `bytes` is filled
    /// by the verify pass: inline capture for short runs, residue
    /// offset for the rest.
    Gap {
        at: u64,
        len: u64,
        residue_off: Option<u64>,
        inline: Option<Vec<u8>>,
    },
}

struct Build {
    segs: Vec<Seg>,
    /// Children whose extents collided with an already-accepted
    /// sibling (iso hardlinks share extents) — their bytes are still
    /// covered, by the sibling; count kept for the node's note.
    dropped: usize,
    /// The coordinate space this build splices in — `View::src_id` of
    /// the source its children's extents name (the root file, or the
    /// spool of a decompressed wrapper) — and the build's own runs
    /// there.
    space: usize,
    runs: Vec<(u64, u64, u64)>,
}

/// A compression node: this member's bytes are a cataloged compressor
/// run over its decompressed child, plus its recorded raw header.
/// Verified at planning time — the compressor search compares the
/// recompressed body against the original bytes, so a Compress in the
/// plan IS a proof, same as a verified splice.
struct Compress {
    child: usize,
    params: crate::compressors::GnuGzip,
    /// The original gzip header, spliced back verbatim at rebuild
    /// (embedded names and mtimes never touch the compressor).
    header: Vec<u8>,
}

struct Plan {
    /// Member idx → its build plan; members referenced but not built
    /// appear only as `Seg::Child` entries.
    builds: HashMap<usize, Build>,
    /// Member idx → its compression plan (gzip@0 nodes).
    compress: HashMap<usize, Compress>,
    root: usize,
}

/// Map a member-logical range through its extent runs to root ranges,
/// in logical order.
fn map_range(runs: &[(u64, u64, u64)], from: u64, len: u64) -> Vec<(u64, u64)> {
    let (mut out, end) = (Vec::new(), from + len);
    for &(rlog, roff, rlen) in runs {
        let lo = from.max(rlog);
        let hi = end.min(rlog + rlen);
        if lo < hi {
            out.push((roff + (lo - rlog), hi - lo));
        }
    }
    out
}

/// Non-overlapping interval set over one build's logical space.
#[derive(Default)]
struct Intervals(BTreeMap<u64, u64>); // start → end

impl Intervals {
    fn admits(&self, at: u64, len: u64) -> bool {
        let end = at + len;
        if let Some((_, &pe)) = self.0.range(..=at).next_back() {
            if pe > at {
                return false;
            }
        }
        self.0.range(at..end).next().is_none()
    }

    fn insert(&mut self, at: u64, len: u64) {
        self.0.insert(at, at + len);
    }
}

// ---------------------------------------------------------------- mint

pub fn mint(path: &Path, use_cache: bool, json_out: bool) -> Result<()> {
    let md = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    ensure!(md.is_file(), "{}: not a file", path.display());
    ensure!(
        md.len() >= IDENTITY_MIN_BYTES,
        "{}: below the identity floor ({} bytes) — nothing to reference",
        path.display(),
        md.len()
    );

    let ticker = Ticker::new();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(2);
    // No membership filters: bloom tags don't change a recipe.
    let pool = Pool::new(Vec::new(), &ticker, threads, false);
    let walk = Walk {
        pool: &pool,
        truncated: AtomicBool::new(false),
        dead: Mutex::new(Vec::new()),
        threads,
        // Recipes need the decompressed bytes of every wrapper again
        // (splice verification, compressor search), so wrapper
        // children spool and keep their spaces.
        spool_wrappers: true,
    };
    let walked = std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| pool.worker());
        }
        let r = walk.walk_root(path);
        pool.wait_idle();
        pool.close();
        r
    });
    ticker.clear();
    walked?;
    let truncated = walk.truncated.into_inner();
    let dead = walk.dead.into_inner().unwrap();
    ensure!(
        !truncated,
        "descent hit the member cap — refusing to mint from a partial tree"
    );
    let members = report::compact_members(pool.members.into_inner().unwrap(), &dead);

    let datasets = crate::datasets::open_all();
    let evidence = report::resolve_members(&members, datasets, threads, use_cache, &ticker);
    ticker.clear();

    let mut kids: Vec<Vec<usize>> = vec![Vec::new(); members.len()];
    let mut root = None;
    for (i, m) in members.iter().enumerate() {
        match m.parent {
            Some(p) => kids[p].push(i),
            None => root = Some(i),
        }
    }
    for k in &mut kids {
        k.sort_by_key(|&i| members[i].ord);
    }
    let root = root.context("descent produced no root member")?;
    let root_src = members[root]
        .extents
        .as_ref()
        .map(|e| e.src)
        .context("root member carries no extents")?;

    // Space views: every coordinate space extents can name. The walk's
    // root view is gone, so the recorded root src maps to a fresh one;
    // wrapper spools are still alive inside their members. (No id can
    // collide: all spool views coexisted with the walk-time root.)
    let root_view = View::of_file(path)?;
    let mut spaces: HashMap<usize, View> = HashMap::new();
    spaces.insert(root_src, root_view);
    for m in &members {
        if let Some(v) = &m.space {
            spaces.insert(v.src_id(), v.clone());
        }
    }

    let claims_of = |i: usize| claims_json(&evidence[i].0);

    // The indexes already name the whole file: the recipe is a single
    // reference — nothing to reconstruct, nothing literal.
    let root_claims = claims_of(root);
    if !root_claims.is_empty() {
        let doc = json!({
            "hdx_recipe": "0",
            "source": source_json(path, &members[root]),
            "root": ref_json(&members[root], root_claims),
        });
        let out = write_doc(path, &doc)?;
        let line = format!(
            "100% fetchable — the indexes name these bytes; nothing to reconstruct\n→ {}",
            out.display()
        );
        report_summary(json_out, &doc, None, &line);
        return Ok(());
    }

    let mut plan = Plan {
        builds: HashMap::new(),
        compress: HashMap::new(),
        root,
    };
    let mut planner = Planner {
        members: &members,
        kids: &kids,
        evidence: &evidence,
        spaces: &spaces,
        ticker: &ticker,
    };
    let planned = planner.plan_node(root, &mut plan);
    ticker.clear();
    ensure!(
        planned,
        "no member of {} is reachable as a byte range — nothing beyond a trivial full-literal recipe",
        path.display()
    );

    // Verify: every ref re-read from its recorded ranges must
    // reproduce its digest, and every build re-spliced from its
    // segments must reproduce its own. (Compression nodes were
    // verified during planning — the search IS the byte comparison.)
    // The residue is written during the splice pass (document order),
    // so the sidecar is a byproduct of the proof.
    verify_refs(&spaces, &members, &plan, threads, &ticker)?;
    let residue = ResidueWriter::new(&residue_path(&doc_path(path)));
    let mut vs = VerifyState {
        spaces: &spaces,
        members: &members,
        residue,
        done: 0,
        ticker: &ticker,
    };
    verify_node(root, &mut plan, &mut vs)?;
    let residue = vs.residue.finish()?;
    ticker.clear();

    // Coverage is fetchability, and the artifact matches the metric:
    // every ref carries claim URLs (planning collapses unverified
    // member boundaries into literals), so the recipe + sidecar alone
    // rebuild the file — residue IS the sidecar's uncompressed bytes
    // plus the inlined runs, and nothing is quietly delegated to "a
    // copy you happen to have".
    // With compression nodes in the tree, refs and literals live in
    // decompressed spaces, so fetchable + residue no longer tile the
    // root's compressed size; the honest ratio is between them.
    let total = members[root].size;
    let is_leaf = |i: &usize| !plan.builds.contains_key(i) && !plan.compress.contains_key(i);
    let mut fetchable = 0u64;
    let mut residue_total = 0u64;
    let mut nrefs = 0usize;
    for b in plan.builds.values() {
        for seg in &b.segs {
            match seg {
                Seg::Child { idx, len, .. } => {
                    if is_leaf(idx) {
                        fetchable += len;
                    }
                }
                Seg::Gap { len, .. } => residue_total += len,
            }
        }
    }
    for c in plan.compress.values() {
        if is_leaf(&c.child) {
            fetchable += members[c.child].size;
        }
    }
    for (i, m) in members.iter().enumerate() {
        if referenced_as_leaf(&plan, i) && m.size > 0 {
            nrefs += 1;
        }
    }

    let doc = json!({
        "hdx_recipe": "0",
        "source": source_json(path, &members[root]),
        "root": node_json(root, &members, &plan, &evidence),
        "residue": residue.as_ref().map(|r| json!({
            "sha256": hex_lower(&r.sha256),
            "size": r.file_len,
            "uncompressed_size": r.raw_len,
            "compression": "zstd",
        })),
        "coverage": {
            "total_bytes": total,
            "fetchable_bytes": fetchable,
            "residue_bytes": residue_total,
        },
    });
    let out = write_doc(path, &doc)?;

    let covered = fetchable + residue_total;
    let pct = 100.0 * fetchable as f64 / covered.max(1) as f64;
    let mut line = format!(
        "{pct:.1}% fetchable ({} of {}) · residue {}",
        human(fetchable),
        human(covered),
        human(residue_total),
    );
    if let Some(r) = &residue {
        line.push_str(&format!(" (sidecar {} zstd)", human(r.file_len)));
    }
    line.push_str(&format!(
        " · verified byte-exact\n→ {} ({} ref{}, {} build{})",
        out.display(),
        nrefs,
        s(nrefs),
        plan.builds.len() + plan.compress.len(),
        s(plan.builds.len() + plan.compress.len()),
    ));
    let mut compressors: Vec<String> = plan.compress.values().map(|c| c.params.name()).collect();
    compressors.sort();
    compressors.dedup();
    if !compressors.is_empty() {
        line.push_str(&format!(" · compressors: {}", compressors.join(", ")));
    }
    if fetchable == 0 {
        line.push_str("\nnote: nothing fetchable — this recipe is a full literal copy of the file");
    }
    report_summary(json_out, &doc, residue.as_ref().map(|r| r.file_len), &line);
    Ok(())
}

fn referenced_as_leaf(plan: &Plan, i: usize) -> bool {
    !plan.builds.contains_key(&i)
        && !plan.compress.contains_key(&i)
        && (plan.builds.values().any(|b| {
            b.segs
                .iter()
                .any(|s| matches!(s, Seg::Child { idx, .. } if *idx == i))
        }) || plan.compress.values().any(|c| c.child == i))
}

struct Planner<'a> {
    members: &'a [Member],
    kids: &'a [Vec<usize>],
    evidence: &'a [report::Evidence],
    spaces: &'a HashMap<usize, View>,
    ticker: &'a Ticker,
}

impl Planner<'_> {
    /// Plan member `i` as a non-leaf node: a compression chain when
    /// it's a compressed wrapper the catalog can reproduce, else a
    /// splice build. (Claimed members never get here — a claim stops
    /// descent at the caller.)
    fn plan_node(&mut self, i: usize, plan: &mut Plan) -> bool {
        if self.members[i].kind == "gzip" && self.plan_compress(i, plan) {
            return true;
        }
        self.plan_build(i, plan)
    }

    /// Plan wrapper `i` as a gzip@0 node: its single decompressed
    /// child must itself be plannable (a claimed ref, or a verified
    /// build/chain), and a catalog compressor must reproduce the
    /// wrapper's body byte-exact from the child's bytes. The search
    /// IS the verification — no node is emitted on faith.
    fn plan_compress(&mut self, i: usize, plan: &mut Plan) -> bool {
        let m = &self.members[i];
        if m.size < IDENTITY_MIN_BYTES || m.digests.is_none() {
            return false;
        }
        let &[c] = &self.kids[i][..] else {
            return false;
        };
        let child = &self.members[c];
        if child.digests.is_none() || child.size < IDENTITY_MIN_BYTES {
            return false;
        }
        // The child's bytes (the search input) come from its spool;
        // the wrapper's own bytes (the target) from its extents.
        let Some(cview) = child.space.clone() else {
            return false;
        };
        let Some(wext) = m.extents.as_ref() else {
            return false;
        };
        let Some(wspace) = self.spaces.get(&wext.src) else {
            return false;
        };
        // An unclaimed, unplannable child doesn't kill the chain: the
        // decompressed bytes ride in the sidecar as an all-literal
        // build. Fetchability stays at zero — honestly — but the
        // verified structure survives (and tar bytes zstd far better
        // than the gzip stream they came from).
        let claimed = self.evidence[c].0.iter().any(|f| !f.claims.is_empty());
        let synthetic = !claimed && !self.plan_node(c, plan);
        let wruns: Vec<(u64, u64)> = wext.runs.iter().map(|&(_, off, len)| (off, len)).collect();
        let wview = wspace.slice(&wruns);
        let header = match crate::compressors::parse_gzip_header(&mut wview.rewound()) {
            Ok(Some(h)) => h,
            _ => {
                if !synthetic {
                    remove_plan_subtree(plan, c);
                }
                return false;
            }
        };
        let name = leaf_name(m).to_string();
        self.ticker
            .update(1, 0, || format!("searching compressors… {name}"));
        match search_gzip(&wview, header.len() as u64, &cview) {
            Some(params) => {
                if synthetic {
                    plan.builds.insert(
                        c,
                        Build {
                            segs: vec![Seg::Gap {
                                at: 0,
                                len: child.size,
                                residue_off: None,
                                inline: None,
                            }],
                            dropped: 0,
                            space: cview.src_id(),
                            runs: vec![(0, 0, child.size)],
                        },
                    );
                }
                plan.compress.insert(
                    i,
                    Compress {
                        child: c,
                        params,
                        header,
                    },
                );
                true
            }
            None => {
                // No catalog compressor reproduces these bytes — the
                // wrapper stays literal, honestly.
                if !synthetic {
                    remove_plan_subtree(plan, c);
                }
                false
            }
        }
    }

    /// Plan member `i` as a build. A child earns a place in the splice
    /// only through verification: refs require claim URLs, and an
    /// unclaimed child survives only as a build whose subtree holds
    /// claimed refs. Everything else collapses into literal gaps — a
    /// member boundary the indexes don't verify was a hypothesis about
    /// public availability that failed, and its bytes are just bytes
    /// (you can hash any string; an unwitnessed digest is not knowledge).
    /// Claims stop descent the other way too: a member the indexes
    /// already name is one line — its inside needs no proof.
    fn plan_build(&mut self, i: usize, plan: &mut Plan) -> bool {
        let members = self.members;
        let m = &members[i];
        if m.size < IDENTITY_MIN_BYTES || m.digests.is_none() {
            return false;
        }
        // A spooled member owns a fresh space and covers all of it; a
        // ranged member splices inside its own source.
        let (space, runs): (usize, Vec<(u64, u64, u64)>) = match &m.space {
            Some(v) => (v.src_id(), vec![(0, 0, m.size)]),
            None => match m.extents.as_ref() {
                Some(e) => (e.src, e.runs.to_vec()),
                None => return false,
            },
        };
        let mut segs: Vec<Seg> = Vec::new();
        let mut taken = Intervals::default();
        let mut dropped = 0usize;
        for &c in self.kids[i].iter() {
            let Some(cruns) = rangeable(members, space, c) else {
                continue;
            };
            let claimed = self.evidence[c].0.iter().any(|f| !f.claims.is_empty());
            if !claimed && !self.plan_node(c, plan) {
                continue; // unverified hypothesis — bytes stay literal
            }
            // Map the child's runs into this build's logical space;
            // each run lies inside one of our runs by construction
            // (the child's view was sliced from ours).
            let mut pieces: Vec<Seg> = Vec::new();
            let mut ok = true;
            for &(clog, coff, clen) in cruns {
                match runs
                    .iter()
                    .find(|&&(_, off, len)| off <= coff && coff + clen <= off + len)
                {
                    Some(&(rlog, roff, _)) => pieces.push(Seg::Child {
                        idx: c,
                        from: clog,
                        len: clen,
                        at: rlog + (coff - roff),
                        root_off: coff,
                    }),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            let fits = ok
                && pieces
                    .iter()
                    .all(|p| matches!(p, Seg::Child { at, len, .. } if taken.admits(*at, *len)));
            if !fits {
                dropped += 1;
                remove_plan_subtree(plan, c);
                continue;
            }
            for p in &pieces {
                if let Seg::Child { at, len, .. } = p {
                    taken.insert(*at, *len);
                }
            }
            segs.extend(pieces);
        }
        if segs.is_empty() && i != plan.root {
            return false;
        }
        segs.sort_by_key(|s| match s {
            Seg::Child { at, .. } | Seg::Gap { at, .. } => *at,
        });
        // Gaps between accepted segments become literals; the tiling
        // must come out exact or the plan is wrong.
        let mut tiled: Vec<Seg> = Vec::new();
        let mut pos = 0u64;
        for seg in segs {
            let at = match &seg {
                Seg::Child { at, .. } | Seg::Gap { at, .. } => *at,
            };
            assert!(at >= pos, "overlapping splice segments survived planning");
            if at > pos {
                tiled.push(Seg::Gap {
                    at: pos,
                    len: at - pos,
                    residue_off: None,
                    inline: None,
                });
            }
            pos = at
                + match &seg {
                    Seg::Child { len, .. } | Seg::Gap { len, .. } => *len,
                };
            tiled.push(seg);
        }
        let size = members[i].size;
        if pos < size {
            tiled.push(Seg::Gap {
                at: pos,
                len: size - pos,
                residue_off: None,
                inline: None,
            });
        }
        plan.builds.insert(
            i,
            Build {
                segs: tiled,
                dropped,
                space,
                runs,
            },
        );
        true
    }
}

/// Discard a rejected subtree's plans (a parent refused the child on
/// extent overlap or a failed compressor search after recursion had
/// already planned it).
fn remove_plan_subtree(plan: &mut Plan, i: usize) {
    if let Some(c) = plan.compress.remove(&i) {
        remove_plan_subtree(plan, c.child);
    }
    if let Some(b) = plan.builds.remove(&i) {
        for seg in &b.segs {
            if let Seg::Child { idx, .. } = seg {
                remove_plan_subtree(plan, *idx);
            }
        }
    }
}

fn rangeable(members: &[Member], space: usize, i: usize) -> Option<&[(u64, u64, u64)]> {
    let m = &members[i];
    if m.size < IDENTITY_MIN_BYTES || m.digests.is_none() {
        return None;
    }
    m.extents
        .as_ref()
        .filter(|e| e.src == space)
        .map(|e| &e.runs[..])
}

/// Try catalog compressors until one reproduces the wrapper's body —
/// everything after its recorded header, trailer included — from the
/// decompressed child's bytes. Mismatched candidates abort on their
/// first differing chunk.
fn search_gzip(
    wrapper: &View,
    header_len: u64,
    input: &View,
) -> Option<crate::compressors::GnuGzip> {
    use crate::compressors::{gzip_body, GnuGzip, GNU_GZIP_CANDIDATES};
    let end = wrapper.len();
    if header_len >= end {
        return None;
    }
    for level in GNU_GZIP_CANDIDATES {
        for rsyncable in [false, true] {
            let params = GnuGzip { level, rsyncable };
            let mut inp = input.rewound();
            let mut pos = header_len;
            let mut cmp = vec![0u8; 1 << 20];
            let run = gzip_body(params, &mut inp, &mut |b: &[u8]| {
                if pos + b.len() as u64 > end {
                    return Ok(false);
                }
                let mut off = 0;
                while off < b.len() {
                    let n = (b.len() - off).min(cmp.len());
                    let got = wrapper.read_full_at(&mut cmp[..n], pos)?;
                    if got < n || cmp[..n] != b[off..off + n] {
                        return Ok(false);
                    }
                    pos += n as u64;
                    off += n;
                }
                Ok(true)
            });
            // Errors (no gzip on PATH, --rsyncable unsupported) just
            // mean this candidate can't be tried — never a wrong node.
            if matches!(run, Ok(true)) && pos == end {
                return Some(params);
            }
        }
    }
    None
}

// ------------------------------------------------------------ verifying

/// The space view and runs a member's bytes are read back through: a
/// spooled member reads its whole spool, a ranged member its recorded
/// extents.
fn member_ranges<'s>(
    m: &Member,
    spaces: &'s HashMap<usize, View>,
) -> (&'s View, Vec<(u64, u64, u64)>) {
    if let Some(v) = &m.space {
        let view = spaces
            .get(&v.src_id())
            .expect("spooled member's space view");
        return (view, vec![(0, 0, m.size)]);
    }
    let e = m.extents.as_ref().expect("ref has extents");
    let view = spaces.get(&e.src).expect("ranged member's space view");
    (view, e.runs.to_vec())
}

/// Re-read every referenced member's recorded ranges (logical order)
/// and require its sha256 back, in parallel.
fn verify_refs(
    spaces: &HashMap<usize, View>,
    members: &[Member],
    plan: &Plan,
    threads: usize,
    ticker: &Ticker,
) -> Result<()> {
    let refs: Vec<usize> = (0..members.len())
        .filter(|&i| referenced_as_leaf(plan, i))
        .collect();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let failed: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..threads.min(refs.len()).max(1) {
            scope.spawn(|| {
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    if k >= refs.len() || failed.lock().unwrap().is_some() {
                        break;
                    }
                    let i = refs[k];
                    let m = &members[i];
                    let (view, runs) = member_ranges(m, spaces);
                    let mut h = sha2::Sha256::new();
                    for &(_, off, len) in runs.iter() {
                        if let Err(e) = hash_root_range(view, off, len, &mut buf, |b| h.update(b))
                        {
                            *failed.lock().unwrap() = Some(e.context(m.path.clone()));
                            return;
                        }
                    }
                    let got: [u8; 32] = h.finalize().into();
                    let want = m.digests.as_ref().expect("ref has digests").sha256;
                    if got != want {
                        *failed.lock().unwrap() = Some(anyhow::anyhow!(
                            "{}: re-read of recorded ranges does not reproduce sha256 — file changed during mint?",
                            m.path
                        ));
                        return;
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    ticker.update(10_000, d, || format!("verifying refs… {d}/{}", refs.len()));
                }
            });
        }
    });
    match failed.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn hash_root_range(
    view: &View,
    off: u64,
    len: u64,
    buf: &mut [u8],
    mut feed: impl FnMut(&[u8]),
) -> Result<()> {
    let mut pos = off;
    let end = off + len;
    while pos < end {
        let want = ((end - pos) as usize).min(buf.len());
        let n = view.read_full_at(&mut buf[..want], pos)?;
        ensure!(
            n == want,
            "short read at {pos} — file truncated during mint?"
        );
        feed(&buf[..n]);
        pos += n as u64;
    }
    Ok(())
}

/// Residue sidecar: a zstd stream of the literal bytes in document
/// order, created lazily on the first literal byte. Offsets in the
/// document index the UNCOMPRESSED stream; the recorded sha256 names
/// the file as written.
struct ResidueWriter {
    path: PathBuf,
    enc: Option<zstd::stream::write::Encoder<'static, std::fs::File>>,
    /// Uncompressed bytes written so far — the document's offsets.
    len: u64,
}

struct Residue {
    sha256: [u8; 32],
    file_len: u64,
    raw_len: u64,
}

impl ResidueWriter {
    fn new(path: &Path) -> ResidueWriter {
        ResidueWriter {
            path: path.to_path_buf(),
            enc: None,
            len: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.enc.is_none() {
            let f = std::fs::File::create(&self.path)
                .with_context(|| format!("create {}", self.path.display()))?;
            self.enc = Some(zstd::stream::write::Encoder::new(f, 3)?);
        }
        self.enc.as_mut().unwrap().write_all(bytes)?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    fn finish(self) -> Result<Option<Residue>> {
        let Some(enc) = self.enc else {
            return Ok(None);
        };
        let f = enc.finish()?;
        f.sync_all().ok();
        drop(f);
        // Hash the file as written (integrity covers the compressed
        // artifact users copy around).
        let mut f = std::fs::File::open(&self.path)?;
        let mut h = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut file_len = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            file_len += n as u64;
        }
        Ok(Some(Residue {
            sha256: h.finalize().into(),
            file_len,
            raw_len: self.len,
        }))
    }
}

struct VerifyState<'a> {
    spaces: &'a HashMap<usize, View>,
    members: &'a [Member],
    residue: ResidueWriter,
    done: usize,
    ticker: &'a Ticker,
}

/// Verify the node at `i` in document order: builds re-splice and
/// capture their residue; compression nodes were byte-verified at
/// planning time, so only their input subtree still needs the pass.
fn verify_node(i: usize, plan: &mut Plan, vs: &mut VerifyState) -> Result<()> {
    if let Some(c) = plan.compress.get(&i) {
        let child = c.child;
        if plan.builds.contains_key(&child) || plan.compress.contains_key(&child) {
            return verify_node(child, plan, vs);
        }
        return Ok(());
    }
    verify_build(i, plan, vs)
}

/// Re-splice build `i` from its segments and require its sha256 back;
/// literal gaps are captured (inline or into the residue) on the way
/// through. Child builds recurse at their position, so residue order
/// is document order.
fn verify_build(i: usize, plan: &mut Plan, vs: &mut VerifyState) -> Result<()> {
    let build = plan.builds.get_mut(&i).expect("planned build");
    let mut segs = std::mem::take(&mut build.segs);
    let runs = build.runs.clone();
    let view = vs
        .spaces
        .get(&build.space)
        .expect("build space view")
        .clone();
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    for seg in &mut segs {
        match seg {
            Seg::Child {
                idx, root_off, len, ..
            } => {
                hash_root_range(&view, *root_off, *len, &mut buf, |b| h.update(b))
                    .with_context(|| vs.members[*idx].path.clone())?;
                let idx = *idx;
                let planned_build =
                    plan.builds.contains_key(&idx) && !plan.builds[&idx].segs.is_empty();
                if planned_build || plan.compress.contains_key(&idx) {
                    verify_node(idx, plan, vs)?;
                }
            }
            Seg::Gap {
                at,
                len,
                residue_off,
                inline,
            } => {
                let small = *len <= INLINE_MAX;
                let mut capture: Vec<u8> = Vec::new();
                if !small {
                    *residue_off = Some(vs.residue.len);
                }
                for (off, l) in map_range(&runs, *at, *len) {
                    let mut pos = off;
                    let end = off + l;
                    while pos < end {
                        let want = ((end - pos) as usize).min(buf.len());
                        let n = view.read_full_at(&mut buf[..want], pos)?;
                        ensure!(n == want, "short read in gap at {pos}");
                        h.update(&buf[..n]);
                        if small {
                            capture.extend_from_slice(&buf[..n]);
                        } else {
                            vs.residue.write(&buf[..n])?;
                        }
                        pos += n as u64;
                    }
                }
                if small {
                    *inline = Some(capture);
                }
            }
        }
    }
    let got: [u8; 32] = h.finalize().into();
    let want = vs.members[i]
        .digests
        .as_ref()
        .expect("build digests")
        .sha256;
    ensure!(
        got == want,
        "{}: splice does not reproduce sha256 — recipe planning bug or file changed",
        vs.members[i].path
    );
    plan.builds.get_mut(&i).unwrap().segs = segs;
    vs.done += 1;
    let d = vs.done;
    vs.ticker
        .update(64, d, || format!("verifying splices… {d} builds"));
    Ok(())
}

// ------------------------------------------------------------- emitting

fn claims_json(findings: &[crate::finding::Finding]) -> Vec<Value> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for f in findings {
        for c in &f.claims {
            if let Some(url) = &c.url {
                if seen.insert((f.backend.clone(), url.clone())) {
                    out.push(json!({
                        "attestor": f.backend,
                        "statement": c.statement,
                        "url": url,
                    }));
                }
            }
        }
    }
    out
}

fn leaf_name(m: &Member) -> &str {
    m.path.rsplit('!').next().unwrap_or(&m.path)
}

fn digests_json(m: &Member) -> Value {
    let d = m.digests.as_ref().expect("digests");
    let mut v = json!({
        "sha1": hex_lower(&d.sha1),
        "sha256": hex_lower(&d.sha256),
    });
    if let Some(x) = &d.md5 {
        v["md5"] = json!(hex_lower(x));
    }
    if let Some(x) = &d.sha512 {
        v["sha512"] = json!(hex_lower(x));
    }
    if let Some(x) = &d.blake2s {
        v["blake2s256"] = json!(hex_lower(x));
    }
    if let Some(x) = &d.sha1_git {
        v["sha1_git"] = json!(hex_lower(x));
    }
    v
}

fn ref_json(m: &Member, claims: Vec<Value>) -> Value {
    let mut r = json!({
        "digests": digests_json(m),
        "size": m.size,
        "name": leaf_name(m),
    });
    if !claims.is_empty() {
        r["claims"] = json!(claims);
    }
    json!({ "ref": r })
}

fn source_json(path: &Path, root: &Member) -> Value {
    json!({
        "name": path.file_name().map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        "size": root.size,
        "sha256": hex_lower(&root.digests.as_ref().expect("root digests").sha256),
    })
}

fn node_json(i: usize, members: &[Member], plan: &Plan, evidence: &[report::Evidence]) -> Value {
    let m = &members[i];
    if let Some(c) = plan.compress.get(&i) {
        return json!({ "build": {
            "builder": "gzip@0",
            "name": leaf_name(m),
            "params": {
                "compressor": c.params.name(),
                "header_hex": hex_lower(&c.header),
            },
            "output": { "sha256": hex_lower(&m.digests.as_ref().expect("digests").sha256),
                        "size": m.size },
            "inputs": [node_json(c.child, members, plan, evidence)],
        } });
    }
    match plan.builds.get(&i) {
        None => ref_json(m, claims_json(&evidence[i].0)),
        Some(b) => {
            let inputs: Vec<Value> = b
                .segs
                .iter()
                .map(|seg| match seg {
                    Seg::Child { idx, from, len, .. } => {
                        let node = node_json(*idx, members, plan, evidence);
                        if *from == 0 && *len == members[*idx].size {
                            node
                        } else {
                            json!({ "slice": { "of": node, "from": from, "len": len } })
                        }
                    }
                    Seg::Gap {
                        len,
                        residue_off,
                        inline,
                        ..
                    } => match inline {
                        Some(bytes) => json!({ "literal": {
                            "inline_hex": hex_lower(bytes), "len": len } }),
                        None => json!({ "literal": {
                            "residue_offset": residue_off.expect("residue offset assigned"),
                            "len": len } }),
                    },
                })
                .collect();
            let mut node = json!({
                "builder": "splice@0",
                "name": leaf_name(m),
                "output": { "sha256": hex_lower(&m.digests.as_ref().expect("digests").sha256),
                            "size": m.size },
                "inputs": inputs,
            });
            if b.dropped > 0 {
                node["note"] = json!(format!(
                    "{} member{} share extents with an accepted sibling and are covered by it",
                    b.dropped,
                    s(b.dropped)
                ));
            }
            json!({ "build": node })
        }
    }
}

fn doc_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".recipe.json");
    PathBuf::from(os)
}

fn residue_path(doc: &Path) -> PathBuf {
    let sstr = doc.to_string_lossy();
    PathBuf::from(
        sstr.strip_suffix(".json")
            .map(|p| format!("{p}.residue"))
            .unwrap_or_else(|| format!("{sstr}.residue")),
    )
}

fn write_doc(path: &Path, doc: &Value) -> Result<PathBuf> {
    let out = doc_path(path);
    let f = std::fs::File::create(&out).with_context(|| format!("create {}", out.display()))?;
    let mut w = std::io::BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, doc)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(out)
}

fn report_summary(json_out: bool, doc: &Value, residue: Option<u64>, line: &str) {
    if json_out {
        let mut sum = json!({
            "source": doc["source"],
            "coverage": doc["coverage"],
        });
        if let Some(r) = residue {
            sum["residue_bytes_written"] = json!(r);
        }
        println!("{sum}");
    } else {
        println!("{line}");
    }
}

// ---------------------------------------------------------------- check

/// Rebuild a recipe from locally-present blobs and verify byte-exact.
/// Never fetches: missing members are reported with their claim URLs
/// and the check fails.
pub fn check(recipe: &Path, dir: &Path, output: Option<&Path>) -> Result<()> {
    let doc: Value = serde_json::from_reader(std::io::BufReader::new(
        std::fs::File::open(recipe).with_context(|| format!("open {}", recipe.display()))?,
    ))
    .with_context(|| format!("parse {}", recipe.display()))?;
    ensure!(
        doc["hdx_recipe"] == json!("0"),
        "{}: not an hdx recipe (or an unknown version)",
        recipe.display()
    );

    // The residue sidecar sits next to the document: verify the file
    // as written, then open the uncompressed stream for offset reads
    // (in RAM when small, a temp file when not).
    let residue = match doc["residue"].is_object() {
        false => None,
        true => {
            let want = doc["residue"]["sha256"]
                .as_str()
                .context("residue sha256")?;
            let p = residue_path(recipe);
            let bytes = std::fs::read(&p).with_context(|| {
                format!(
                    "residue sidecar {} (expected next to the recipe)",
                    p.display()
                )
            })?;
            let got = hex_lower(&sha2::Sha256::digest(&bytes));
            ensure!(
                got == want,
                "{}: residue does not match the recipe (sha256 {got} != {want})",
                p.display()
            );
            let raw_len = doc["residue"]["uncompressed_size"]
                .as_u64()
                .unwrap_or(bytes.len() as u64);
            let spool = if doc["residue"]["compression"] == json!("zstd") {
                if raw_len <= CHECK_SPOOL_MAX {
                    Spool::Mem(zstd::stream::decode_all(&bytes[..])?)
                } else {
                    let dir = crate::filter::filters_dir()
                        .parent()
                        .map(|d| d.join("tmp"))
                        .context("no cache dir")?;
                    std::fs::create_dir_all(&dir)?;
                    let mut f = tempfile::tempfile_in(&dir)?;
                    zstd::stream::copy_decode(&bytes[..], &mut f)?;
                    Spool::File(f)
                }
            } else {
                Spool::Mem(bytes)
            };
            Some(spool)
        }
    };

    // Index the blob directory by sha256 (the only key refs need).
    let files = list_files(dir)?;
    let ticker = Ticker::new();
    let blobs = index_blobs(&files, &ticker)?;
    ticker.clear();

    // Availability first, so ALL missing members are reported, with
    // their claim URLs, before any rebuild work.
    let mut missing: Vec<(String, String, Vec<String>)> = Vec::new();
    let root = &doc["root"];
    collect_missing(root, &blobs, &mut missing);
    if !missing.is_empty() {
        for (name, sha, urls) in &missing {
            eprintln!("missing: {name} (sha256 {sha})");
            for u in urls {
                eprintln!("  → {u}");
            }
        }
        bail!(
            "{} member{} not present under {} — hdx never fetches; the URLs above say where",
            missing.len(),
            s(missing.len()),
            dir.display()
        );
    }

    // Rebuild.
    let mut out: Box<dyn Write> = match output {
        Some(p) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("create {}", p.display()))?,
        )),
        None => Box::new(std::io::sink()),
    };
    let mut ctx = CheckCtx {
        blobs: &blobs,
        residue,
        built: HashMap::new(),
    };
    let mut h = sha2::Sha256::new();
    let n = assemble(root, &mut ctx, &mut |b| {
        h.update(b);
        out.write_all(b)
    })?;
    out.flush()?;
    let got = hex_lower(&h.finalize());
    let want = node_sha256(root)?;
    ensure!(
        got == want,
        "rebuild hashes to {got}, recipe says {want} — a blob passed its own hash but the splice disagrees"
    );
    println!("rebuilt byte-exact: sha256 {got} ({})", human(n),);
    if let Some(p) = output {
        println!("→ {}", p.display());
    }
    Ok(())
}

struct CheckCtx<'a> {
    blobs: &'a HashMap<String, PathBuf>,
    residue: Option<Spool>,
    /// Builds materialized for slicing, by output sha256.
    built: HashMap<String, Spool>,
}

/// RAM-or-tempfile bytes for a rebuilt container a slice addresses.
enum Spool {
    Mem(Vec<u8>),
    File(std::fs::File),
}

impl Spool {
    /// A sequential reader over the spool (positional reads — the
    /// spool is shared).
    fn reader(&self) -> SpoolReader<'_> {
        SpoolReader {
            spool: self,
            pos: 0,
        }
    }

    fn read_range(
        &self,
        from: u64,
        len: u64,
        mut feed: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        match self {
            Spool::Mem(v) => {
                let lo = (from as usize).min(v.len());
                let hi = ((from + len) as usize).min(v.len());
                ensure!(hi - lo == len as usize, "slice out of range of built bytes");
                feed(&v[lo..hi])
            }
            Spool::File(f) => {
                let mut pos = from;
                let end = from + len;
                let mut buf = vec![0u8; 1 << 20];
                while pos < end {
                    let want = ((end - pos) as usize).min(buf.len());
                    #[cfg(unix)]
                    let n = std::os::unix::fs::FileExt::read_at(f, &mut buf[..want], pos)?;
                    #[cfg(windows)]
                    let n = std::os::windows::fs::FileExt::seek_read(f, &mut buf[..want], pos)?;
                    ensure!(n > 0, "slice out of range of built bytes");
                    feed(&buf[..n])?;
                    pos += n as u64;
                }
                Ok(())
            }
        }
    }
}

struct SpoolReader<'a> {
    spool: &'a Spool,
    pos: u64,
}

impl Read for SpoolReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = match self.spool {
            Spool::Mem(v) => {
                let start = (self.pos as usize).min(v.len());
                let n = buf.len().min(v.len() - start);
                buf[..n].copy_from_slice(&v[start..start + n]);
                n
            }
            #[cfg(unix)]
            Spool::File(f) => std::os::unix::fs::FileExt::read_at(f, buf, self.pos)?,
            #[cfg(windows)]
            Spool::File(f) => std::os::windows::fs::FileExt::seek_read(f, buf, self.pos)?,
        };
        self.pos += n as u64;
        Ok(n)
    }
}

fn node_sha256(node: &Value) -> Result<String> {
    if node["ref"].is_object() {
        let r = &node["ref"];
        return Ok(r["digests"]["sha256"]
            .as_str()
            .context("ref without sha256")?
            .to_string());
    }
    if node["build"].is_object() {
        let b = &node["build"];
        return Ok(b["output"]["sha256"]
            .as_str()
            .context("build without output sha256")?
            .to_string());
    }
    bail!("node is neither ref nor build")
}

fn node_name(node: &Value) -> String {
    node["ref"]["name"]
        .as_str()
        .or(node["build"]["name"].as_str())
        .unwrap_or("?")
        .to_string()
}

fn collect_missing(
    node: &Value,
    blobs: &HashMap<String, PathBuf>,
    missing: &mut Vec<(String, String, Vec<String>)>,
) {
    if node["ref"].is_object() {
        let r = &node["ref"];
        let sha = r["digests"]["sha256"].as_str().unwrap_or("");
        if !blobs.contains_key(sha) {
            let urls = r["claims"]
                .as_array()
                .map(|cs| {
                    cs.iter()
                        .filter_map(|c| c["url"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let entry = (
                r["name"].as_str().unwrap_or("?").to_string(),
                sha.to_string(),
                urls,
            );
            if !missing.iter().any(|(_, s, _)| *s == entry.1) {
                missing.push(entry);
            }
        }
        return;
    }
    if node["build"].is_object() {
        let b = &node["build"];
        // A locally-present copy of the build's own output short-
        // circuits its whole subtree.
        if let Some(sha) = b["output"]["sha256"].as_str() {
            if blobs.contains_key(sha) {
                return;
            }
        }
        for input in b["inputs"].as_array().into_iter().flatten() {
            let inner = if input["slice"].is_object() {
                &input["slice"]["of"]
            } else {
                input
            };
            if inner["literal"].is_object() {
                continue;
            }
            collect_missing(inner, blobs, missing);
        }
    }
}

/// Produce a node's bytes into `feed`, returning the byte count.
fn assemble(
    node: &Value,
    ctx: &mut CheckCtx,
    feed: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<u64> {
    if node["literal"].is_object() {
        let l = &node["literal"];
        if let Some(hexs) = l["inline_hex"].as_str() {
            let bytes = data_encoding::HEXLOWER
                .decode(hexs.as_bytes())
                .context("bad inline_hex literal")?;
            feed(&bytes)?;
            return Ok(bytes.len() as u64);
        }
        let off = l["residue_offset"].as_u64().context("literal offset")?;
        let len = l["len"].as_u64().context("literal len")?;
        let res = ctx
            .residue
            .as_ref()
            .context("recipe has literals but no residue")?;
        res.read_range(off, len, |b| {
            feed(b)?;
            Ok(())
        })?;
        return Ok(len);
    }
    if node["slice"].is_object() {
        let sl = &node["slice"];
        let of = &sl["of"];
        let from = sl["from"].as_u64().context("slice from")?;
        let len = sl["len"].as_u64().context("slice len")?;
        let sha = node_sha256(of)?;
        // Slices need random access: a local blob file, or the built
        // bytes of the referenced node, materialized once.
        if let Some(p) = ctx.blobs.get(&sha) {
            let f = std::fs::File::open(p)?;
            Spool::File(f).read_range(from, len, |b| {
                feed(b)?;
                Ok(())
            })?;
            return Ok(len);
        }
        if !ctx.built.contains_key(&sha) {
            let spool = materialize(of, ctx)?;
            ctx.built.insert(sha.clone(), spool);
        }
        ctx.built[&sha].read_range(from, len, |b| {
            feed(b)?;
            Ok(())
        })?;
        return Ok(len);
    }
    if node["ref"].is_object() {
        let r = &node["ref"];
        let sha = r["digests"]["sha256"].as_str().context("ref sha256")?;
        let path = ctx
            .blobs
            .get(sha)
            .with_context(|| format!("missing blob for {}", node_name(node)))?;
        let mut f = std::fs::File::open(path)?;
        let mut h = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut n = 0u64;
        loop {
            let k = f.read(&mut buf)?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            feed(&buf[..k])?;
            n += k as u64;
        }
        let got = hex_lower(&h.finalize());
        ensure!(
            got == sha,
            "{}: changed since indexing (sha256 {got})",
            path.display()
        );
        return Ok(n);
    }
    if node["build"].is_object() {
        let b = &node["build"];
        // A local copy of the output short-circuits the subtree —
        // stream it like a ref.
        let sha = node_sha256(node)?;
        if ctx.blobs.contains_key(&sha) {
            let as_ref = json!({ "ref": { "digests": { "sha256": sha },
                                          "name": b["name"] } });
            return assemble(&as_ref, ctx, feed);
        }
        let builder = b["builder"].as_str().unwrap_or("splice@0");
        match builder {
            "splice@0" => {}
            "gzip@0" => return assemble_gzip(b, &sha, ctx, feed),
            other => bail!(
                "{}: unknown builder {other:?} — this recipe needs a newer hdx",
                node_name(node)
            ),
        }
        let mut h = sha2::Sha256::new();
        let mut n = 0u64;
        let inputs = b["inputs"].as_array().context("build inputs")?.clone();
        for input in &inputs {
            n += assemble(input, ctx, &mut |bytes| {
                h.update(bytes);
                feed(bytes)
            })?;
        }
        let got = hex_lower(&h.finalize());
        ensure!(
            got == sha,
            "{}: rebuilt bytes hash to {got}, recipe says {sha}",
            node_name(node)
        );
        if let Some(size) = b["output"]["size"].as_u64() {
            ensure!(
                n == size,
                "{}: rebuilt {n} bytes, recipe says {size}",
                node_name(node)
            );
        }
        return Ok(n);
    }
    bail!("unknown recipe node: {node}")
}

/// Rebuild a gzip@0 node: materialize its input (whose own assembly
/// verifies its digest), splice the recorded header back on, and run
/// the named compressor over the input for the body — trailer
/// included, since crc and length are functions of the same bytes.
fn assemble_gzip(
    b: &Value,
    sha: &str,
    ctx: &mut CheckCtx,
    feed: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<u64> {
    let name = b["name"].as_str().unwrap_or("?").to_string();
    let cname = b["params"]["compressor"]
        .as_str()
        .context("gzip@0 compressor name")?;
    let params = crate::compressors::GnuGzip::parse(cname)
        .with_context(|| format!("unknown compressor {cname:?} — this recipe needs a newer hdx"))?;
    let header = data_encoding::HEXLOWER
        .decode(
            b["params"]["header_hex"]
                .as_str()
                .context("gzip@0 header_hex")?
                .as_bytes(),
        )
        .context("bad gzip@0 header_hex")?;
    let inputs = b["inputs"].as_array().context("build inputs")?;
    ensure!(inputs.len() == 1, "gzip@0 takes exactly one input");
    let spool = materialize(&inputs[0], ctx)?;

    let mut h = sha2::Sha256::new();
    let mut n = 0u64;
    h.update(&header);
    feed(&header)?;
    n += header.len() as u64;
    let ran = crate::compressors::gzip_body(params, &mut spool.reader(), &mut |bytes| {
        h.update(bytes);
        feed(bytes)?;
        n += bytes.len() as u64;
        Ok(true)
    })
    .with_context(|| format!("{name}: running {cname}"))?;
    ensure!(ran, "{name}: {cname} run aborted");
    let got = hex_lower(&h.finalize());
    ensure!(
        got == sha,
        "{name}: recompression hashes to {got}, recipe says {sha} — is the system gzip the same GNU gzip that minted this?"
    );
    if let Some(size) = b["output"]["size"].as_u64() {
        ensure!(n == size, "{name}: rebuilt {n} bytes, recipe says {size}");
    }
    Ok(n)
}

/// Materialize a node's bytes for random access (slices of rebuilt
/// containers), in RAM below CHECK_SPOOL_MAX, else in a temp file.
fn materialize(node: &Value, ctx: &mut CheckCtx) -> Result<Spool> {
    let size = node["build"]["output"]["size"]
        .as_u64()
        .or(node["ref"]["size"].as_u64())
        .unwrap_or(0);
    if size > CHECK_SPOOL_MAX {
        let dir = crate::filter::filters_dir()
            .parent()
            .map(|p| p.join("tmp"))
            .context("no cache dir")?;
        std::fs::create_dir_all(&dir)?;
        let mut f = tempfile::tempfile_in(&dir)?;
        assemble(node, ctx, &mut |b| f.write_all(b))?;
        Ok(Spool::File(f))
    } else {
        let mut v = Vec::with_capacity(size as usize);
        assemble(node, ctx, &mut |b| {
            v.extend_from_slice(b);
            Ok(())
        })?;
        Ok(Spool::Mem(v))
    }
}

fn list_files(dir: &Path) -> Result<Vec<PathBuf>> {
    ensure!(dir.is_dir(), "{}: not a directory", dir.display());
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("read {}", d.display()))? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn index_blobs(files: &[PathBuf], ticker: &Ticker) -> Result<HashMap<String, PathBuf>> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let out: Mutex<HashMap<String, PathBuf>> = Mutex::new(HashMap::new());
    std::thread::scope(|scope| {
        for _ in 0..threads.min(files.len()).max(1) {
            scope.spawn(|| {
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let Ok(mut f) = std::fs::File::open(&files[i]) else {
                        continue; // unreadable blobs simply aren't available
                    };
                    let mut h = sha2::Sha256::new();
                    loop {
                        match f.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => h.update(&buf[..n]),
                            Err(_) => break,
                        }
                    }
                    out.lock()
                        .unwrap()
                        .insert(hex_lower(&h.finalize()), files[i].clone());
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    ticker.update(1000, d, || {
                        format!("hashing local blobs… {d}/{}", files.len())
                    });
                }
            });
        }
    });
    Ok(out.into_inner().unwrap())
}

// ------------------------------------------------------- jigdo emission

/// Project a splice recipe into a `.jigdo` + `.template` pair that
/// stock jigdo tooling consumes. Claimed refs become fetchable parts;
/// everything else — literals, claim-less refs, slices — becomes
/// template data, exactly as `jigdo-file make-template` would have
/// classified bytes it couldn't match. Conventions byte-verified
/// against Debian's own libjte-2.0 output: template 2.0 framing,
/// sha256 DESC entries, RsyncSum64 over the first 1024 bytes
/// (table-based; the table's author explicitly permits
/// reimplementation under any license), base64url-no-pad checksums.
const JIGDO_BLOCKLEN: u32 = 1024;
/// Literal bytes per zlib DATA part (libjte's chunking).
const JIGDO_CHUNK: usize = 1 << 20;

/// jigdo's 64-bit rolling checksum: independent per-byte table sums.
/// Table values from jigdo's rsyncsum.cc, where Richard Atterer
/// disclaims copyright over the numbers.
fn rsync64(data: &[u8]) -> [u8; 8] {
    let (mut a, mut b) = (0u32, 0u32);
    for &byte in data {
        a = a.wrapping_add(RSYNC_TABLE[byte as usize]);
        b = b.wrapping_add(a);
    }
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&a.to_le_bytes());
    out[4..].copy_from_slice(&b.to_le_bytes());
    out
}

fn b64url(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

fn u48(n: u64) -> [u8; 6] {
    let b = n.to_le_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5]]
}

/// One flattened region of the image, in image order.
enum JRegion {
    Part {
        len: u64,
        sha256: [u8; 32],
        urls: Vec<String>,
    },
    Literal {
        len: u64,
    },
}

/// Flatten a recipe tree: claimed refs (whole, unsliced) become
/// parts; all other bytes are literal. Adjacent literals merge.
fn jigdo_flatten(node: &Value, out: &mut Vec<JRegion>) -> Result<()> {
    let push_literal = |out: &mut Vec<JRegion>, len: u64| {
        if len == 0 {
            return;
        }
        if let Some(JRegion::Literal { len: l }) = out.last_mut() {
            *l += len;
        } else {
            out.push(JRegion::Literal { len });
        }
    };
    if node["literal"].is_object() {
        push_literal(out, node["literal"]["len"].as_u64().context("literal len")?);
        return Ok(());
    }
    if node["slice"].is_object() {
        // A slice is a window of a member — jigdo can't fetch part of
        // a file, so its bytes ride in the template.
        push_literal(out, node["slice"]["len"].as_u64().context("slice len")?);
        return Ok(());
    }
    if node["ref"].is_object() {
        let r = &node["ref"];
        let len = r["size"].as_u64().context("ref size")?;
        let urls: Vec<String> = r["claims"]
            .as_array()
            .map(|cs| {
                cs.iter()
                    .filter_map(|c| c["url"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if urls.is_empty() {
            push_literal(out, len);
        } else {
            let mut sha256 = [0u8; 32];
            let hex = r["digests"]["sha256"].as_str().context("ref sha256")?;
            data_encoding::HEXLOWER
                .decode_mut(hex.as_bytes(), &mut sha256)
                .map_err(|_| anyhow::anyhow!("bad sha256 hex in ref"))?;
            out.push(JRegion::Part { len, sha256, urls });
        }
        return Ok(());
    }
    if node["build"].is_object() {
        for input in node["build"]["inputs"].as_array().context("build inputs")? {
            jigdo_flatten(input, out)?;
        }
        return Ok(());
    }
    bail!("unknown recipe node in jigdo projection")
}

/// Split a claim URL into (server prefix, path) at the archive root:
/// before a `pool/` or `dists/` component when present, else after
/// the host.
fn jigdo_split_url(url: &str) -> (String, String) {
    for marker in ["/pool/", "/dists/"] {
        if let Some(i) = url.find(marker) {
            return (url[..i + 1].to_string(), url[i + 1..].to_string());
        }
    }
    let after_scheme = url.find("//").map(|i| i + 2).unwrap_or(0);
    match url[after_scheme..].find('/') {
        Some(i) => {
            let cut = after_scheme + i + 1;
            (url[..cut].to_string(), url[cut..].to_string())
        }
        None => (url.to_string(), String::new()),
    }
}

pub fn emit_jigdo(recipe: &Path) -> Result<()> {
    let doc: Value = serde_json::from_reader(std::io::BufReader::new(
        std::fs::File::open(recipe).with_context(|| format!("open {}", recipe.display()))?,
    ))?;
    ensure!(doc["hdx_recipe"] == json!("0"), "not an hdx recipe");
    let image_path = PathBuf::from(
        recipe
            .to_string_lossy()
            .strip_suffix(".recipe.json")
            .context("recipe path must end in .recipe.json (the image sits beside it)")?
            .to_string(),
    );
    let image_name = doc["source"]["name"].as_str().context("source name")?;
    let image_size = doc["source"]["size"].as_u64().context("source size")?;
    let image_sha = doc["source"]["sha256"].as_str().context("source sha256")?;

    let mut regions = Vec::new();
    jigdo_flatten(&doc["root"], &mut regions)?;
    ensure!(
        regions.iter().any(|r| matches!(r, JRegion::Part { .. })),
        "recipe has no claimed refs — a jigdo projection would be one big template"
    );

    // Stream the image once: literals into zlib DATA parts, parts
    // hashed for their DESC entries (rsync64 needs the head bytes;
    // sha256 re-verified while we're reading anyway).
    let img = std::fs::File::open(&image_path).with_context(|| {
        format!(
            "image {} (must sit beside the recipe)",
            image_path.display()
        )
    })?;
    ensure!(
        img.metadata()?.len() == image_size,
        "{}: size differs from the recipe — re-mint first",
        image_path.display()
    );
    let view = View::of_file(&image_path)?;
    let template_path = image_path.with_extension(
        image_path
            .extension()
            .map(|e| format!("{}.template", e.to_string_lossy()))
            .unwrap_or_else(|| "template".into()),
    );
    let mut tf = std::io::BufWriter::new(std::fs::File::create(&template_path)?);
    let header = format!(
        "JigsawDownload template 2.0 hashdex-hdx/{} \r\n\
         Projected from {}.recipe.json ; hdx at https://github.com/davidar/hashdex \r\n\r\n",
        env!("CARGO_PKG_VERSION"),
        image_name,
    );
    tf.write_all(header.as_bytes())?;

    let mut desc: Vec<u8> = Vec::new();
    let mut image_hash = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    let mut lit_chunk: Vec<u8> = Vec::with_capacity(JIGDO_CHUNK);
    let flush_chunk = |tf: &mut dyn Write, chunk: &mut Vec<u8>| -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        z.write_all(chunk)?;
        let zbytes = z.finish()?;
        tf.write_all(b"DATA")?;
        tf.write_all(&u48(16 + zbytes.len() as u64))?;
        tf.write_all(&u48(chunk.len() as u64))?;
        tf.write_all(&zbytes)?;
        chunk.clear();
        Ok(())
    };
    for region in &regions {
        match region {
            JRegion::Literal { len } => {
                desc.push(2);
                desc.extend_from_slice(&u48(*len));
                let mut left = *len;
                while left > 0 {
                    let want = (left as usize)
                        .min(buf.len())
                        .min(JIGDO_CHUNK - lit_chunk.len());
                    let n = view.read_full_at(&mut buf[..want], pos)?;
                    ensure!(n == want, "short read at {pos}");
                    image_hash.update(&buf[..n]);
                    lit_chunk.extend_from_slice(&buf[..n]);
                    if lit_chunk.len() >= JIGDO_CHUNK {
                        flush_chunk(&mut tf, &mut lit_chunk)?;
                    }
                    pos += n as u64;
                    left -= n as u64;
                }
            }
            JRegion::Part { len, sha256, .. } => {
                // Parts flush the pending literal chunk so DATA parts
                // and files interleave in image order.
                flush_chunk(&mut tf, &mut lit_chunk)?;
                let mut h = sha2::Sha256::new();
                let mut head = vec![0u8; (JIGDO_BLOCKLEN as u64).min(*len) as usize];
                let n = view.read_full_at(&mut head, pos)?;
                ensure!(n == head.len(), "short read at {pos}");
                let mut left = *len;
                let mut p = pos;
                while left > 0 {
                    let want = (left as usize).min(buf.len());
                    let n = view.read_full_at(&mut buf[..want], p)?;
                    ensure!(n == want, "short read at {p}");
                    image_hash.update(&buf[..n]);
                    h.update(&buf[..n]);
                    p += n as u64;
                    left -= n as u64;
                }
                let got: [u8; 32] = h.finalize().into();
                ensure!(
                    &got == sha256,
                    "part at {pos} does not hash to its recipe digest — image changed?"
                );
                desc.push(9);
                desc.extend_from_slice(&u48(*len));
                desc.extend_from_slice(&rsync64(&head));
                desc.extend_from_slice(sha256);
                pos += *len;
            }
        }
    }
    flush_chunk(&mut tf, &mut lit_chunk)?;
    ensure!(
        pos == image_size,
        "regions tile {pos} of {image_size} bytes"
    );
    let got_image: [u8; 32] = image_hash.finalize().into();
    ensure!(
        hex_lower(&got_image) == image_sha,
        "image no longer matches the recipe — re-mint first"
    );
    desc.push(8);
    desc.extend_from_slice(&u48(image_size));
    desc.extend_from_slice(&got_image);
    desc.extend_from_slice(&JIGDO_BLOCKLEN.to_le_bytes());
    let total = 4 + 6 + desc.len() as u64 + 6;
    tf.write_all(b"DESC")?;
    tf.write_all(&u48(total))?;
    tf.write_all(&desc)?;
    tf.write_all(&u48(total))?;
    tf.flush()?;
    drop(tf);

    // The .jigdo text: servers derived from the claim URLs.
    let template_bytes = std::fs::read(&template_path)?;
    let template_sha = sha2::Sha256::digest(&template_bytes);
    let mut servers: Vec<String> = Vec::new(); // prefix, label = S<idx>
    let mut parts_lines = String::new();
    for region in &regions {
        if let JRegion::Part { sha256, urls, .. } = region {
            for url in urls {
                let (prefix, path) = jigdo_split_url(url);
                let idx = match servers.iter().position(|s| *s == prefix) {
                    Some(i) => i,
                    None => {
                        servers.push(prefix);
                        servers.len() - 1
                    }
                };
                parts_lines.push_str(&format!("{}=S{idx}:{path}\n", b64url(sha256)));
            }
        }
    }
    let jigdo_path = image_path.with_extension(
        image_path
            .extension()
            .map(|e| format!("{}.jigdo", e.to_string_lossy()))
            .unwrap_or_else(|| "jigdo".into()),
    );
    let template_name = template_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut jt = String::new();
    jt.push_str("# JigsawDownload\n# Projected by hdx from a verified splice recipe\n\n");
    jt.push_str("[Jigdo]\nVersion=2.0\n");
    jt.push_str(&format!(
        "Generator=hashdex-hdx/{}\n\n",
        env!("CARGO_PKG_VERSION")
    ));
    jt.push_str("[Image]\n");
    jt.push_str(&format!("Filename={image_name}\n"));
    jt.push_str(&format!("Template={template_name}\n"));
    jt.push_str(&format!("Template-SHA256Sum={}\n", b64url(&template_sha)));
    jt.push_str(&format!("# Image Hex SHA256Sum {image_sha}\n"));
    jt.push_str(&format!("# Image size {image_size} bytes\n\n"));
    jt.push_str("[Parts]\n");
    jt.push_str(&parts_lines);
    jt.push_str("\n[Servers]\n");
    for (i, prefix) in servers.iter().enumerate() {
        jt.push_str(&format!("S{i}={prefix}\n"));
    }
    std::fs::write(&jigdo_path, jt)?;

    let nparts = regions
        .iter()
        .filter(|r| matches!(r, JRegion::Part { .. }))
        .count();
    let part_bytes: u64 = regions
        .iter()
        .map(|r| match r {
            JRegion::Part { len, .. } => *len,
            _ => 0,
        })
        .sum();
    println!(
        "jigdo projection: {nparts} parts ({}) fetchable, template {} ({} literal)\n→ {}\n→ {}",
        human(part_bytes),
        human(template_bytes.len() as u64),
        human(image_size - part_bytes),
        jigdo_path.display(),
        template_path.display(),
    );
    Ok(())
}

/// jigdo RsyncSum64 byte table (rsyncsum.cc; values explicitly free
/// for reimplementation under any license).
#[rustfmt::skip]
const RSYNC_TABLE: [u32; 256] = [
    0x51d65c0f, 0x083cd94b, 0x77f73dd8, 0xa0187d36, 0x29803d07, 0x7ea8ac0e, 0xea4c16c9, 0xfc576443,
    0x6213df29, 0x1c012392, 0xb38946ae, 0x2e20ca31, 0xe4dc532f, 0xcb281c47, 0x8508b6a5, 0xb93c210d,
    0xef02b5f3, 0x66548c74, 0x9ae2deab, 0x3b59f472, 0x4e546447, 0x45232d1f, 0x0ac0a4b1, 0x6c4c264b,
    0x5d24ce84, 0x0f2752cc, 0xa35c7ac7, 0x3e31af51, 0x79675a59, 0x581f0e81, 0x49053122, 0x7339c9d8,
    0xf9833565, 0xa3dbe5b3, 0xcc06eeb9, 0x92d0671c, 0x3eb220a7, 0x64864eae, 0xca100872, 0xc50977a1,
    0xd90378e1, 0x7a36cab9, 0x15c15f4b, 0x8b9ef749, 0xcc1432dc, 0x1ec578ed, 0x27e6e092, 0xbb06db8f,
    0x67f661ac, 0x8dd1a3db, 0x2a0ca16b, 0xb229ab84, 0x127a3337, 0x347d846f, 0xe1ea4b50, 0x008dbb91,
    0x414c1426, 0xd2be76f0, 0x08789a39, 0xb4d93e30, 0x61667760, 0x8871bee9, 0xab7da12d, 0xe3c58620,
    0xe9fdfbbe, 0x64fb04f7, 0x8cc5bbf0, 0xf5272d30, 0x8f161b50, 0x11122b05, 0x7695e72e, 0xa1c5d169,
    0x1bfd0e20, 0xef7e6169, 0xf652d08e, 0xa9d0f139, 0x2f70aa04, 0xae2c7d6d, 0xa3cb9241, 0x3ae7d364,
    0x348788f8, 0xf483b8f1, 0x55a011da, 0x189719dc, 0xb0c5d723, 0x8b344e33, 0x300d46eb, 0xd44fe34f,
    0x1a2016c1, 0x66ce4cd7, 0xa45ea5e3, 0x55cb708a, 0xbce430df, 0xb01ae6e0, 0x3551163b, 0x2c5b157a,
    0x574c4209, 0x430fd0e4, 0x3387e4a5, 0xee1d7451, 0xa9635623, 0x873ab89b, 0xb96bc6aa, 0x59898937,
    0xe646c6e7, 0xb79f8792, 0x3f3235d8, 0xef1b5acf, 0xd975b22b, 0x427acce6, 0xe47a2411, 0x75f8c1e8,
    0xa63f799d, 0x53886ad8, 0x9b2d6d32, 0xea822016, 0xcdee2254, 0xd98bcd98, 0x2933a544, 0x961f379f,
    0x49219792, 0xc61c360f, 0x77cc0c64, 0x7b872046, 0xb91c7c12, 0x7577154b, 0x196573be, 0xf788813f,
    0x41e2e56a, 0xec3cd244, 0x8c7401f1, 0xc2e805fe, 0xe8872fbe, 0x9e2faf7d, 0x6766456b, 0x888e2197,
    0x28535c6d, 0x2ce45f3f, 0x24261d2a, 0xd6faab8b, 0x7a7b42b8, 0x15f0f6fa, 0xfe1711df, 0x7e5685a6,
    0x00930268, 0x74755331, 0x1998912c, 0x7b60498b, 0x501a5786, 0x92ace0f6, 0x1d9752fe, 0x5a731add,
    0x5b3b44fc, 0x473673f9, 0xa42c0321, 0xd82f9f18, 0xb4b225da, 0xfc89ece2, 0x072e1130, 0x5772aae3,
    0x29010857, 0x542c970c, 0x94f67fe5, 0x71209e9b, 0xdb97ea39, 0x2689b41b, 0xae815804, 0xfc5e2651,
    0xd4521674, 0x48ed979a, 0x2f617da3, 0xc350353d, 0xc3accd94, 0xbd8d313a, 0xc61a8e77, 0xf34940a4,
    0x8d2c6b0f, 0x0f0e7225, 0x39e183db, 0xd19ebba9, 0x6a0f37b9, 0xd18922f3, 0x106420c5, 0xaa5a640b,
    0x7cf0d273, 0xcf3238a7, 0x3b33204f, 0x476be7bb, 0x09d23bca, 0xbe84b2f7, 0xb7a3bace, 0x2528cee1,
    0x3dcaa1dd, 0x900ad31a, 0xf21dea6d, 0x9ce51463, 0xf1540bba, 0x0fab1bdd, 0x89cfb79a, 0x01a2a6e6,
    0x6f85d67c, 0xd1669ec4, 0x355db722, 0x00ebd5c4, 0x926eb385, 0x69ead869, 0x0da2b122, 0x402779fe,
    0xdaed92d0, 0x57e9aabb, 0x3df64854, 0xfcc774b5, 0x2e1740ed, 0xa615e024, 0xf7bac938, 0x377dfd1a,
    0xd0559d66, 0x25499be8, 0x2d8f2006, 0xfaa9e486, 0x95e980e7, 0x82aeba67, 0x5a7f2561, 0xbc60dff6,
    0x6c8739a2, 0x7ec59a8b, 0x9998f265, 0xdfe37e5e, 0xb47cee1e, 0x4dd8bc9e, 0x35c57e09, 0x07850b63,
    0x06eadbcb, 0x6c1f2956, 0x01685c2c, 0xf5725eef, 0xf13b98b5, 0xaab739c2, 0x200b1da2, 0xa716b98b,
    0xd9ee3058, 0x76acf20b, 0x2f259e04, 0xed11658b, 0x1532b331, 0x0ab43204, 0xf0beb023, 0xb1685483,
    0x58cbdc4f, 0x079384d3, 0x049b141c, 0xc38184b9, 0xaf551d9a, 0x66222560, 0x059deeca, 0x535f99e2,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_range_translates_through_runs() {
        // Logical [0,20) lives at 100; [20,30) lives at 500.
        let runs = [(0, 100, 20), (20, 500, 10)];
        assert_eq!(map_range(&runs, 0, 20), vec![(100, 20)]);
        assert_eq!(map_range(&runs, 15, 10), vec![(115, 5), (500, 5)]);
        assert_eq!(map_range(&runs, 20, 10), vec![(500, 10)]);
        assert_eq!(map_range(&runs, 5, 3), vec![(105, 3)]);
        assert!(map_range(&runs, 30, 5).is_empty());
    }

    #[test]
    fn intervals_reject_overlap() {
        let mut iv = Intervals::default();
        assert!(iv.admits(10, 10));
        iv.insert(10, 10);
        assert!(!iv.admits(15, 10)); // straddles the end
        assert!(!iv.admits(5, 10)); // straddles the start
        assert!(!iv.admits(10, 10)); // exact duplicate (hardlink twin)
        assert!(!iv.admits(0, 100)); // encloses
        assert!(iv.admits(0, 10)); // flush against the start
        assert!(iv.admits(20, 1)); // flush against the end
        iv.insert(20, 1);
        assert!(iv.admits(21, 5));
    }
}
