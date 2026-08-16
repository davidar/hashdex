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
    /// Bytes stored verbatim in the container that ARE a member's
    /// bytes — an uncompressed erofs pcluster. The member's node lives
    /// in the sources table: it has no extents of its own, so it can't
    /// be a `Child`.
    Tabled {
        idx: usize,
        from: u64,
        len: u64,
        at: u64,
        root_off: u64,
    },
    /// One stored pcluster of an erofs image, rebuilt by re-encoding
    /// the member bytes it holds; `pc` indexes `Plan::pclusters`.
    PCluster {
        pc: usize,
        at: u64,
        len: u64,
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

impl Seg {
    fn at(&self) -> u64 {
        match self {
            Seg::Child { at, .. }
            | Seg::Tabled { at, .. }
            | Seg::PCluster { at, .. }
            | Seg::Gap { at, .. } => *at,
        }
    }

    fn len(&self) -> u64 {
        match self {
            Seg::Child { len, .. }
            | Seg::Tabled { len, .. }
            | Seg::PCluster { len, .. }
            | Seg::Gap { len, .. } => *len,
        }
    }
}

/// A microlzma@0 node: one stored pcluster of an erofs image's packed
/// inode, reproduced by re-encoding the member bytes packed into it.
/// Verified at planning time — the encoder's output is compared with
/// the stored bytes, so a PClusterNode in the plan IS a proof, exactly
/// like a Compress.
struct PClusterNode {
    /// Stored size and digest — what the node must produce.
    size: u64,
    sha256: [u8; 32],
    /// Leading zero bytes erofs pads the stored data with (0padding).
    pad: usize,
    preset: u32,
    dict_size: u32,
    inputs: Vec<PcInput>,
    name: String,
}

/// One input of a microlzma@0 node, in packed-stream order.
enum PcInput {
    /// Bytes of a member the sources table carries a node for.
    Member { idx: usize, from: u64, len: u64 },
    /// Packed-stream bytes no fetchable member covers. Spooled during
    /// planning (they are gone once the sweep moves on) and copied
    /// into the residue in document order by the verify pass.
    Literal {
        spool_off: u64,
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

/// An extract node: this member's bytes live at a path inside a
/// published archive — a witness stated so (FILEDIGESTS-grade
/// metadata), and the claim rides on the node. The output digest is
/// locally verified like any leaf; the archive→path→bytes edge is
/// ATTESTED, not mint-verified — mint never opens the rpm (`recipe
/// check` walks it for real at rebuild). Same trust shape as a ref's
/// claim URL: a stale attestation surfaces exactly like a dead link.
struct Extract {
    archive: crate::finding::Archive,
    attestor: String,
    statement: String,
}

struct Plan {
    /// Member idx → its build plan; members referenced but not built
    /// appear only as `Seg::Child` entries.
    builds: HashMap<usize, Build>,
    /// Member idx → its compression plan (gzip@0 nodes).
    compress: HashMap<usize, Compress>,
    /// Member idx → its extract plan (leaves fetched via an archive).
    extracts: HashMap<usize, Extract>,
    /// microlzma@0 nodes, referenced by `Seg::PCluster`.
    pclusters: Vec<PClusterNode>,
    /// Members whose nodes live in the top-level sources table because
    /// pcluster inputs slice them (they have no place in any splice —
    /// their bytes only exist inside a compressed pcluster).
    tabled: std::collections::BTreeSet<usize>,
    /// Packed-stream literal bytes, spooled during planning.
    literals: Option<LiteralSpool>,
    /// What the pcluster sweeps found, for the summary line.
    pcstats: PcStats,
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

    // The indexes already name the whole file: the recipe is a single
    // reference — nothing to reconstruct, nothing literal. (Direct
    // claims only: an archive-interior claim's URL fetches the
    // containing archive, so it earns an extract node, not a ref.)
    let root_claims = claims_json(&evidence[root].0);
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
        extracts: HashMap::new(),
        pclusters: Vec::new(),
        tabled: Default::default(),
        literals: None,
        pcstats: PcStats::default(),
        root,
    };
    let mut planner = Planner {
        members: &members,
        kids: &kids,
        evidence: &evidence,
        spaces: &spaces,
        ticker: &ticker,
        threads,
    };
    // A whole-file extract attestation wins outright (100% fetchable);
    // otherwise plan the tree. Order matters: a plain root always
    // "plans" as an all-literal build, which must not shadow this.
    let planned = planner.plan_extract(root, &mut plan) || planner.plan_node(root, &mut plan);
    ticker.clear();
    ensure!(
        planned,
        "no member of {} is reachable as a byte range — nothing beyond a trivial full-literal recipe",
        path.display()
    );

    // The whole file is one attested archive member: the recipe is a
    // single extract node — nothing to splice, nothing literal.
    if plan.extracts.contains_key(&root) {
        let (sources, src_of, node_of) = sources_json(&plan, &members, &evidence);
        let doc = json!({
            "hdx_recipe": "1",
            "source": source_json(path, &members[root]),
            "sources": sources,
            "root": node_json(root, &members, &plan, &evidence, &src_of, &node_of),
        });
        let out = write_doc(path, &doc)?;
        let line = format!(
            "100% fetchable — an archive the indexes name ships these bytes; fetch it and extract\n→ {}",
            out.display()
        );
        report_summary(json_out, &doc, None, &line);
        return Ok(());
    }

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
                Seg::Tabled { len, .. } => fetchable += len,
                // A pcluster's stored bytes are neither: they are
                // accounted for through the node's own inputs, in
                // packed space, below.
                Seg::PCluster { .. } => {}
                Seg::Gap { len, .. } => residue_total += len,
            }
        }
    }
    for node in &plan.pclusters {
        for input in &node.inputs {
            match input {
                PcInput::Member { len, .. } => fetchable += len,
                PcInput::Literal { len, .. } => residue_total += len,
            }
        }
    }
    for c in plan.compress.values() {
        if is_leaf(&c.child) {
            fetchable += members[c.child].size;
        }
    }
    let mut nextracts = 0usize;
    for (i, m) in members.iter().enumerate() {
        if (referenced_as_leaf(&plan, i) || plan.tabled.contains(&i)) && m.size > 0 {
            if plan.extracts.contains_key(&i) {
                nextracts += 1;
            } else {
                nrefs += 1;
            }
        }
    }

    // New grammar forms (extract nodes, the sources table) bump the
    // version so an older hdx bails with its "unknown version" path
    // instead of misreading the document.
    // Only nodes the surviving splices actually reference belong in
    // the table: a build the tree rejected after its pclusters were
    // planned would otherwise leave entries nothing points at.
    plan.tabled = referenced_tabled(&plan);
    let (sources, src_of, node_of) = sources_json(&plan, &members, &evidence);
    let narchives = src_of
        .values()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let mut doc = json!({
        "hdx_recipe": if sources.is_empty() { "0" } else { "1" },
        "source": source_json(path, &members[root]),
        "root": node_json(root, &members, &plan, &evidence, &src_of, &node_of),
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
    if !sources.is_empty() {
        doc["sources"] = json!(sources);
    }
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
        " · verified byte-exact\n→ {} ({} ref{}, {} build{}",
        out.display(),
        nrefs,
        s(nrefs),
        plan.builds.len() + plan.compress.len(),
        s(plan.builds.len() + plan.compress.len()),
    ));
    if nextracts > 0 {
        line.push_str(&format!(
            ", {nextracts} extract{} from {narchives} archive{}",
            s(nextracts),
            s(narchives),
        ));
    }
    // Nodes the document actually references: planning can produce two
    // for the same image range (deduplicated files share pclusters),
    // and only the first one takes the splice.
    let npc = plan
        .builds
        .values()
        .flat_map(|b| &b.segs)
        .filter(|s| matches!(s, Seg::PCluster { .. }))
        .count();
    if npc > 0 {
        line.push_str(&format!(", {npc} pcluster{}", s(npc)));
    }
    line.push(')');
    line.push_str(&pcluster_note(&plan.pcstats));
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

/// What the erofs sweep left behind, stated rather than implied: a
/// pcluster that stays literal is a byte range no index verified, and
/// the reasons are worth naming.
fn pcluster_note(st: &PcStats) -> String {
    if st.total == 0 {
        return String::new();
    }
    let mut why: Vec<String> = Vec::new();
    for (n, what) in [
        (st.uncovered, "no fetchable members"),
        (st.not_verbatim, "stored, but not verbatim"),
        (st.mismatch, "re-encoded differently"),
        (st.margin, "input margin too small"),
    ] {
        if n > 0 {
            why.push(format!("{n} {what}"));
        }
    }
    let mut note = format!(
        "\nerofs: {}/{} pcluster{} rebuilt byte-exact",
        st.verified + st.verbatim,
        st.total,
        s(st.total)
    );
    if st.verbatim > 0 {
        note.push_str(&format!(" ({} stored uncompressed, spliced)", st.verbatim));
    }
    if !why.is_empty() {
        note.push_str(&format!(" ({} — literal)", why.join(", ")));
    }
    if st.unverified_members > 0 {
        note.push_str(&format!(
            "; {} member{} dropped: packed bytes don't match their digest",
            st.unverified_members,
            s(st.unverified_members)
        ));
    }
    note
}

/// Members a batch of segments references through the sources table.
fn tabled_of(segs: &[Seg], pclusters: &[PClusterNode]) -> std::collections::BTreeSet<usize> {
    let mut out = std::collections::BTreeSet::new();
    for seg in segs {
        match seg {
            Seg::Tabled { idx, .. } => {
                out.insert(*idx);
            }
            Seg::PCluster { pc, .. } => {
                for input in &pclusters[*pc].inputs {
                    if let PcInput::Member { idx, .. } = input {
                        out.insert(*idx);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Members the surviving splices reference through the sources table:
/// spliced verbatim, or sliced by a pcluster node that a build still
/// points at.
fn referenced_tabled(plan: &Plan) -> std::collections::BTreeSet<usize> {
    let mut out = std::collections::BTreeSet::new();
    for b in plan.builds.values() {
        out.append(&mut tabled_of(&b.segs, &plan.pclusters));
    }
    out
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
    threads: usize,
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
        // An erofs image keeps its build even when no child of it can
        // be spliced: an -Eall-fragments image has no plain ranges at
        // all, and everything it holds arrives in the second pass.
        if self.members[i].kind == "erofs" {
            if !self.plan_build_inner(i, plan, true) {
                return false;
            }
            match self.plan_erofs(i, plan) {
                Ok(stats) => plan.pcstats.add(stats),
                // An image this reader can't re-plan is not a failure:
                // its bytes stay literal, exactly as before rung E.
                Err(e) => eprintln!(
                    "note: {}: erofs pclusters stay literal: {e:#}",
                    self.members[i].path
                ),
            }
            let useful = plan
                .builds
                .get(&i)
                .is_some_and(|b| b.segs.iter().any(|s| !matches!(s, Seg::Gap { .. })));
            if !useful && i != plan.root {
                remove_plan_subtree(plan, i);
                return false;
            }
            return true;
        }
        self.plan_build(i, plan)
    }

    /// Whether a witness claims THESE bytes at a URL. Archive-interior
    /// claims don't count: their URL fetches the containing archive,
    /// so a plain ref built on one would lie about fetchability —
    /// those members are planned as extract nodes instead.
    fn direct_claimed(&self, i: usize) -> bool {
        self.evidence[i]
            .0
            .iter()
            .any(|f| f.archive.is_none() && f.claims.iter().any(|c| c.url.is_some()))
    }

    /// Plan member `i` as an extract node: a witness states these
    /// bytes sit at a path inside a sha256-named archive with a claim
    /// URL. Weak-digest archives don't qualify (lookup keys, never
    /// merge keys — and `check` finds local blobs by sha256).
    fn plan_extract(&mut self, i: usize, plan: &mut Plan) -> bool {
        if self.members[i].digests.is_none() || self.members[i].size < IDENTITY_MIN_BYTES {
            return false;
        }
        let Some(f) = self.evidence[i].0.iter().find(|f| {
            f.archive
                .as_ref()
                .is_some_and(|a| a.scheme == "sha256" && a.url.is_some())
        }) else {
            return false;
        };
        plan.extracts.insert(
            i,
            Extract {
                archive: f.archive.clone().expect("filtered on archive"),
                attestor: f.backend.clone(),
                statement: f
                    .claims
                    .first()
                    .map(|c| c.statement.clone())
                    .unwrap_or_default(),
            },
        );
        true
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
        let claimed = self.direct_claimed(c);
        let synthetic = !claimed && !self.plan_node(c, plan) && !self.plan_extract(c, plan);
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
        self.plan_build_inner(i, plan, false)
    }

    /// `keep_empty` holds on to a build with no accepted children —
    /// for the root (whose all-literal recipe is still a recipe) and
    /// for erofs images, whose children arrive in a second pass.
    fn plan_build_inner(&mut self, i: usize, plan: &mut Plan, keep_empty: bool) -> bool {
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
            let claimed = self.direct_claimed(c);
            if !claimed && !self.plan_node(c, plan) && !self.plan_extract(c, plan) {
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
        if segs.is_empty() && i != plan.root && !keep_empty {
            return false;
        }
        segs.sort_by_key(|s| s.at());
        plan.builds.insert(
            i,
            Build {
                segs: tile_gaps(segs, members[i].size),
                dropped,
                space,
                runs,
            },
        );
        true
    }
}

// ------------------------------------------------------- erofs images

/// How many bytes past a pcluster's own span the encoder may read.
/// mkfs encodes fixed-output — it stops when the output buffer fills,
/// mid-symbol — so the input must not run out first; anything the
/// encoder consumes beyond its logical span is just more slices.
const ENCODE_MARGIN: usize = 1 << 20;

/// Packed-stream bytes no member covers, parked in a temp file during
/// the sweep (they are gone once the sweep moves past them, and the
/// residue can only take them in document order, later).
struct LiteralSpool {
    file: Mutex<(std::fs::File, u64)>,
}

impl LiteralSpool {
    fn new() -> Result<LiteralSpool> {
        let dir = crate::filter::filters_dir()
            .parent()
            .map(|p| p.join("tmp"))
            .context("no cache dir")?;
        std::fs::create_dir_all(&dir)?;
        Ok(LiteralSpool {
            file: Mutex::new((tempfile::tempfile_in(&dir)?, 0)),
        })
    }

    fn append(&self, bytes: &[u8]) -> Result<u64> {
        let mut g = self.file.lock().unwrap();
        let at = g.1;
        g.0.write_all(bytes)?;
        g.1 += bytes.len() as u64;
        Ok(at)
    }

    fn read_at(&self, off: u64, len: u64, feed: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let g = self.file.lock().unwrap();
        let mut pos = off;
        let end = off + len;
        let mut buf = vec![0u8; 1 << 20];
        while pos < end {
            let want = ((end - pos) as usize).min(buf.len());
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::read_at(&g.0, &mut buf[..want], pos)?;
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_read(&g.0, &mut buf[..want], pos)?;
            ensure!(n > 0, "literal spool truncated");
            feed(&buf[..n])?;
            pos += n as u64;
        }
        Ok(())
    }
}

/// What one pass over a packed stream produced: the pcluster nodes
/// that came back byte-exact (by pcluster index), the verbatim
/// splices, and the members whose packed bytes did not hash to their
/// digest.
/// What planning one own-pcluster file produced: its nodes with the
/// image offsets they occupy, its verbatim splices, and a tally.
type PlannedFile = (Vec<(PClusterNode, u64)>, Vec<Seg>, PcStats);

type Swept = (
    Vec<(usize, PClusterNode)>,
    Vec<Seg>,
    std::collections::HashSet<usize>,
);

/// What the sweep should do with a pcluster.
#[derive(Clone, Copy, PartialEq)]
enum Elig {
    /// Nothing fetchable is packed in it: its bytes stay literal.
    No,
    /// Compressed: re-encode it and compare, then emit a node.
    Encode,
    /// Stored uncompressed: if the stored bytes really are the member
    /// bytes, splice them straight in — no encoder, no node.
    Verbatim,
}

/// A member whose bytes ARE a span of the packed stream.
#[derive(Clone)]
struct Cover {
    idx: usize,
    pstart: u64,
    len: u64,
}

impl Cover {
    fn end(&self) -> u64 {
        self.pstart + self.len
    }
}

/// What the pcluster sweep did, for the mint summary and the honest
/// accounting of what stayed literal.
#[derive(Default)]
struct PcStats {
    /// Stored pclusters of the packed inode, and how they ended up.
    total: usize,
    verified: usize,
    /// No fetchable member covers enough of the span for a node to
    /// shrink the residue.
    uncovered: usize,
    /// Stored uncompressed and spliced straight in — no encoder, no
    /// node, just member bytes at their place in the image.
    verbatim: usize,
    /// Not compressed, but not a verbatim copy either (rotated in
    /// place, or an algorithm with no encoder here).
    not_verbatim: usize,
    /// Re-encoded to different bytes: a compressor this hdx can't
    /// reproduce. These stay literal, like an unreproducible gzip.
    mismatch: usize,
    /// The encoder wanted more input than the sweep had buffered.
    margin: usize,
    /// Members dropped because the packed bytes don't hash to their
    /// digest (a mapping this reader got wrong — never a silent slice).
    unverified_members: usize,
}

impl PcStats {
    /// One image's tally into the recipe's (an iso can hold several).
    fn add(&mut self, o: PcStats) {
        self.total += o.total;
        self.verified += o.verified;
        self.uncovered += o.uncovered;
        self.verbatim += o.verbatim;
        self.not_verbatim += o.not_verbatim;
        self.mismatch += o.mismatch;
        self.margin += o.margin;
        self.unverified_members += o.unverified_members;
    }
}

/// liblzma's "extreme" preset flag (`LZMA_PRESET_EXTREME`).
const LZMA_PRESET_EXTREME: u32 = 1 << 31;

impl Planner<'_> {
    /// The view a member's own bytes are read through.
    fn member_view(&self, i: usize) -> Option<View> {
        let m = &self.members[i];
        if let Some(v) = &m.space {
            return Some(v.clone());
        }
        let e = m.extents.as_ref()?;
        let space = self.spaces.get(&e.src)?;
        let runs: Vec<(u64, u64)> = e.runs.iter().map(|&(_, off, len)| (off, len)).collect();
        Some(space.slice(&runs))
    }

    /// Plan the compressed bulk of an erofs image. `plan_build` has
    /// already spliced whatever the image stores as plain ranges;
    /// everything else sits in stored pclusters, in two places: the
    /// packed inode shared by files mkfs turned into fragments (all of
    /// them, on `-Eall-fragments` live media), and pclusters belonging
    /// to one file each. Both become microlzma@0 nodes — re-encoded
    /// and byte-compared right here, so a node that survives is a
    /// proof, not a hypothesis — or, when stored uncompressed, direct
    /// splices of the member's own bytes.
    fn plan_erofs(&mut self, i: usize, plan: &mut Plan) -> Result<PcStats> {
        let mut stats = PcStats::default();
        let view = self
            .member_view(i)
            .context("erofs member has no readable space")?;
        let fs = crate::erofs::Erofs::open(view.clone())?;
        let Some(cfg) = fs.lzma_cfg()? else {
            return Ok(stats); // no MicroLZMA configured: nothing to rebuild
        };
        // Format 0 is plain LZMA1, the only shape erofs defines and the
        // only one `microlzma_encode` models.
        ensure!(
            cfg.format == 0,
            "unknown erofs lzma format {} — pclusters stay literal",
            cfg.format
        );
        let (files, _) = fs.files()?;

        // Which member is which file: the walker names erofs children
        // "<image path>!<path inside>".
        let mut by_path: HashMap<&str, usize> = HashMap::new();
        for &c in self.kids[i].iter() {
            by_path.insert(self.members[c].path.as_str(), c);
        }
        let preset = Mutex::new(None::<u32>);
        let mut segs: Vec<Seg> = Vec::new();
        self.plan_packed_inode(
            i, plan, &fs, &view, &files, &by_path, &cfg, &preset, &mut segs, &mut stats,
        )?;
        self.plan_own_pclusters(
            i, plan, &fs, &view, &files, &by_path, &cfg, &preset, &mut segs, &mut stats,
        )?;
        if segs.is_empty() {
            return Ok(stats);
        }
        plan.tabled = plan
            .tabled
            .union(&tabled_of(&segs, &plan.pclusters))
            .copied()
            .collect();
        splice_in(i, plan, segs, &view)?;
        Ok(stats)
    }

    /// Pass one: the packed inode, whose pclusters hold many members
    /// each.
    #[allow(clippy::too_many_arguments)]
    fn plan_packed_inode(
        &mut self,
        i: usize,
        plan: &mut Plan,
        fs: &crate::erofs::Erofs,
        view: &View,
        files: &[crate::erofs::FileItem],
        by_path: &HashMap<&str, usize>,
        cfg: &crate::erofs::LzmaCfg,
        preset: &Mutex<Option<u32>>,
        out: &mut Vec<Seg>,
        stats: &mut PcStats,
    ) -> Result<()> {
        let (pcs, _) = fs.packed_pclusters()?;
        stats.total += pcs.len();
        if pcs.is_empty() {
            return Ok(());
        }
        let mut covers: Vec<Cover> = Vec::new();
        for f in files {
            let Some(off) = f.plan.packed_whole() else {
                continue; // own pclusters, or only a packed tail
            };
            let path = format!("{}!{}", self.members[i].path, f.path);
            let Some(&c) = by_path.get(path.as_str()) else {
                continue;
            };
            let m = &self.members[c];
            if m.size != f.size || m.size < IDENTITY_MIN_BYTES || m.digests.is_none() {
                continue;
            }
            // A node for these bytes, or they may as well be literal:
            // a claim URL that fetches them directly, or a witness that
            // states them inside an archive (rung D).
            if !self.direct_claimed(c) && !self.plan_extract(c, plan) {
                continue;
            }
            covers.push(Cover {
                idx: c,
                pstart: off,
                len: m.size,
            });
        }
        if covers.is_empty() {
            stats.uncovered += pcs.len();
            return Ok(());
        }
        // Dedupe (and hardlinks) put two members on the same bytes:
        // longest-first at a shared start, and the tiling takes one
        // cover per byte.
        covers.sort_by_key(|c| (c.pstart, std::cmp::Reverse(c.len)));

        // A node earns its place only by shrinking the residue: it
        // trades `plen` stored bytes for whatever of its input span no
        // member covers.
        let union = merge_spans(&covers);
        let mut eligible = vec![Elig::No; pcs.len()];
        for (k, pc) in pcs.iter().enumerate() {
            let covered = overlap(&union, pc.la, pc.llen);
            if covered == 0 {
                stats.uncovered += 1;
                continue;
            }
            if pc.lzma {
                // A node earns its place only by shrinking the residue.
                if pc.llen - covered < pc.plen {
                    eligible[k] = Elig::Encode;
                } else {
                    stats.uncovered += 1;
                }
            } else {
                // Stored uncompressed: no node needed at all, if the
                // bytes really are verbatim (checked in the sweep).
                eligible[k] = Elig::Verbatim;
            }
        }
        if eligible.iter().all(|e| *e == Elig::No) {
            return Ok(());
        }
        // Covers touching an eligible pcluster are the ones worth
        // verifying; their spans decide which pclusters must decode.
        let used: Vec<Cover> = covers
            .iter()
            .filter(|c| {
                pcs.iter()
                    .zip(&eligible)
                    .any(|(pc, e)| *e != Elig::No && c.pstart < pc.la + pc.llen && pc.la < c.end())
            })
            .cloned()
            .collect();
        let mut need: Vec<bool> = eligible.iter().map(|e| *e != Elig::No).collect();
        for (k, pc) in pcs.iter().enumerate() {
            if need[k] {
                continue;
            }
            need[k] = used
                .iter()
                .any(|c| c.pstart < pc.la + pc.llen && pc.la < c.end());
        }

        let spool = match plan.literals.take() {
            Some(s) => s,
            None => LiteralSpool::new()?,
        };
        let (nodes, mut segs, failed) = self.sweep_pclusters(
            fs, view, &pcs, &eligible, &need, &used, cfg, preset, &spool, stats,
        )?;
        plan.literals = Some(spool);

        // A member the packed bytes don't hash to is a mapping this
        // reader got wrong: drop every node that sliced it rather than
        // emit a slice that can't be true.
        let mut kept: Vec<(usize, PClusterNode)> = Vec::new();
        for (k, node) in nodes {
            let bad = node.inputs.iter().any(|input| match input {
                PcInput::Member { idx, .. } => failed.contains(idx),
                PcInput::Literal { .. } => false,
            });
            if bad {
                stats.verified -= 1;
            } else {
                kept.push((k, node));
            }
        }
        segs.retain(|s| match s {
            Seg::Tabled { idx, .. } => !failed.contains(idx),
            _ => true,
        });
        if kept.is_empty() && segs.is_empty() {
            return Ok(());
        }

        // Nodes take their place in the image's splice; the members
        // they slice move into the sources table.
        for (k, node) in kept {
            let pc = &pcs[k];
            segs.push(Seg::PCluster {
                pc: plan.pclusters.len(),
                at: 0,
                len: pc.plen,
                root_off: pc.pa,
            });
            plan.pclusters.push(node);
        }
        // Extract nodes minted for members no surviving node slices
        // would state an archive nothing fetches from.
        let keep = tabled_of(&segs, &plan.pclusters);
        let unused: Vec<usize> = plan
            .extracts
            .keys()
            .copied()
            .filter(|c| {
                !keep.contains(c)
                    && !plan.tabled.contains(c)
                    && covers.iter().any(|cv| cv.idx == *c)
                    && !referenced_as_leaf(plan, *c)
            })
            .collect();
        for c in unused {
            plan.extracts.remove(&c);
        }
        out.append(&mut segs);
        Ok(())
    }

    /// Pass two: files mkfs gave pclusters of their own — on the
    /// Fedora live image, the 375 biggest files, half its stored
    /// bytes. Each is self-contained (one member's bytes, in order),
    /// so files plan independently and in parallel: read the member
    /// back through the reader, require its digest, and re-encode or
    /// splice each of its pclusters.
    #[allow(clippy::too_many_arguments)]
    fn plan_own_pclusters(
        &mut self,
        i: usize,
        plan: &mut Plan,
        fs: &crate::erofs::Erofs,
        view: &View,
        files: &[crate::erofs::FileItem],
        by_path: &HashMap<&str, usize>,
        cfg: &crate::erofs::LzmaCfg,
        preset: &Mutex<Option<u32>>,
        out: &mut Vec<Seg>,
        stats: &mut PcStats,
    ) -> Result<()> {
        let mut todo: Vec<(usize, &crate::erofs::FileItem)> = Vec::new();
        for f in files {
            if f.plan.packed_whole().is_some() || f.plan.own_pclusters().is_empty() {
                continue;
            }
            let path = format!("{}!{}", self.members[i].path, f.path);
            let Some(&c) = by_path.get(path.as_str()) else {
                continue;
            };
            let m = &self.members[c];
            if m.size != f.size || m.size < IDENTITY_MIN_BYTES || m.digests.is_none() {
                continue;
            }
            if !self.direct_claimed(c) && !self.plan_extract(c, plan) {
                continue;
            }
            todo.push((c, f));
        }
        // Everything a file with no fetchable evidence stores is
        // literal, and says so in the tally rather than vanishing.
        let all: usize = files.iter().map(|f| f.plan.own_pclusters().len()).sum();
        let planned: usize = todo.iter().map(|(_, f)| f.plan.own_pclusters().len()).sum();
        stats.total += all;
        stats.uncovered += all - planned;
        if todo.is_empty() {
            return Ok(());
        }
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let out_all: Mutex<Vec<PlannedFile>> = Mutex::new(Vec::new());
        let failed: Mutex<Option<anyhow::Error>> = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..self.threads.min(todo.len()).max(1) {
                scope.spawn(|| loop {
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    if k >= todo.len() || failed.lock().unwrap().is_some() {
                        return;
                    }
                    let (c, f) = todo[k];
                    match plan_own_file(fs, view, f, c, &self.members[c], cfg, preset) {
                        Ok(v) => out_all.lock().unwrap().push(v),
                        Err(e) => *failed.lock().unwrap() = Some(e),
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    self.ticker
                        .update(1, 0, || format!("re-encoding files… {d}/{}", todo.len()));
                });
            }
        });
        if let Some(e) = failed.into_inner().unwrap() {
            return Err(e);
        }
        for (nodes, mut segs, st) in out_all.into_inner().unwrap() {
            stats.verified += st.verified;
            stats.verbatim += st.verbatim;
            stats.mismatch += st.mismatch;
            stats.margin += st.margin;
            stats.not_verbatim += st.not_verbatim;
            stats.unverified_members += st.unverified_members;
            for (node, pa) in nodes {
                out.push(Seg::PCluster {
                    pc: plan.pclusters.len(),
                    at: 0,
                    len: node.size,
                    root_off: pa,
                });
                plan.pclusters.push(node);
            }
            out.append(&mut segs);
        }
        // Members whose own pclusters produced nothing keep no extract
        // node unless something else references them.
        let keep = tabled_of(out, &plan.pclusters);
        let unused: Vec<usize> = plan
            .extracts
            .keys()
            .copied()
            .filter(|c| {
                !keep.contains(c)
                    && !plan.tabled.contains(c)
                    && todo.iter().any(|(t, _)| t == c)
                    && !referenced_as_leaf(plan, *c)
            })
            .collect();
        for c in unused {
            plan.extracts.remove(&c);
        }
        Ok(())
    }

    /// One pass over the packed stream: decode what's needed, verify
    /// that each covering member's bytes really are the packed bytes
    /// claimed for it, hand every compressed pcluster to the encoder
    /// pool, and splice the uncompressed ones straight in. Returns the
    /// nodes that came back byte-exact, the verbatim splices, and the
    /// members whose digests didn't check out.
    #[allow(clippy::too_many_arguments)]
    fn sweep_pclusters(
        &self,
        fs: &crate::erofs::Erofs,
        view: &View,
        pcs: &[crate::erofs::PCluster],
        eligible: &[Elig],
        need: &[bool],
        used: &[Cover],
        cfg: &crate::erofs::LzmaCfg,
        preset: &Mutex<Option<u32>>,
        spool: &LiteralSpool,
        stats: &mut PcStats,
    ) -> Result<Swept> {
        struct Job {
            k: usize,
            input: Vec<u8>,
            stored: Vec<u8>,
        }
        let jobs = std::sync::mpsc::sync_channel::<Job>(self.threads.max(1));
        let (tx, rx) = jobs;
        let rx = Mutex::new(rx);
        let out: Mutex<Vec<(usize, PClusterNode)>> = Mutex::new(Vec::new());
        let counts: Mutex<(usize, usize, usize)> = Mutex::new((0, 0, 0)); // ok, mismatch, margin
        let failed: Mutex<std::collections::HashSet<usize>> = Mutex::new(Default::default());
        let done = AtomicUsize::new(0);
        let want = eligible.iter().filter(|e| **e == Elig::Encode).count();
        let mut segs: Vec<Seg> = Vec::new();
        let mut verbatim = 0usize;
        let mut not_verbatim = 0usize;

        let mut result: Result<()> = Ok(());
        std::thread::scope(|scope| {
            for _ in 0..self.threads.max(1) {
                scope.spawn(|| loop {
                    let Ok(job) = rx.lock().unwrap().recv() else {
                        return;
                    };
                    let pc = &pcs[job.k];
                    // The first job settles the preset for the whole
                    // image (one compressor invocation built it); the
                    // rest reuse it, and only re-search if it fails.
                    let known = *preset.lock().unwrap();
                    let outcome = plan_pcluster(
                        pc,
                        &job.stored,
                        &job.input,
                        used,
                        known,
                        cfg.dict_size,
                        spool,
                    );
                    match outcome {
                        Ok(Some((node, p))) => {
                            *preset.lock().unwrap() = Some(p);
                            out.lock().unwrap().push((job.k, node));
                            counts.lock().unwrap().0 += 1;
                        }
                        Ok(None) => counts.lock().unwrap().1 += 1,
                        Err(e) if e.to_string() == MARGIN_SHORT => counts.lock().unwrap().2 += 1,
                        Err(_) => counts.lock().unwrap().1 += 1,
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    self.ticker
                        .update(1, 0, || format!("re-encoding pclusters… {d}/{want}"));
                });
            }
            result = (|| -> Result<()> {
                // Members hash as their bytes stream past; a cover
                // whose start was never decoded can't be checked at
                // all, so it never becomes a slice.
                let mut cursor = 0usize;
                let mut active: Vec<(usize, u64, sha2::Sha256)> = Vec::new();
                let mut cur: Option<Vec<u8>> = None;
                for k in 0..pcs.len() {
                    if !need[k] {
                        cur = None;
                        continue;
                    }
                    let pc = &pcs[k];
                    let bytes = match cur.take() {
                        Some(b) => b,
                        None => fs.decode_pcluster(pc)?,
                    };
                    let end = pc.la + bytes.len() as u64;
                    while cursor < used.len() && used[cursor].pstart < end {
                        let cv = &used[cursor];
                        if cv.pstart < pc.la {
                            // Its first bytes were never decoded.
                            failed.lock().unwrap().insert(cv.idx);
                        } else {
                            active.push((cursor, cv.pstart, sha2::Sha256::new()));
                        }
                        cursor += 1;
                    }
                    active.retain_mut(|(ci, pos, h)| {
                        let cv = &used[*ci];
                        let lo = (*pos - pc.la) as usize;
                        let hi = ((cv.end().min(end)) - pc.la) as usize;
                        if hi > lo {
                            h.update(&bytes[lo..hi]);
                            *pos = pc.la + hi as u64;
                        }
                        if *pos < cv.end() {
                            return true;
                        }
                        let got: [u8; 32] = h.clone().finalize().into();
                        if got
                            != self.members[cv.idx]
                                .digests
                                .as_ref()
                                .expect("digests")
                                .sha256
                        {
                            failed.lock().unwrap().insert(cv.idx);
                        }
                        false
                    });

                    match eligible[k] {
                        Elig::No => {}
                        Elig::Encode => {
                            let mut input = bytes;
                            if k + 1 < pcs.len() {
                                let next = fs.decode_pcluster(&pcs[k + 1])?;
                                let take = next.len().min(ENCODE_MARGIN);
                                input.extend_from_slice(&next[..take]);
                                cur = Some(next);
                            }
                            let stored = read_stored(view, pc)?;
                            if tx.send(Job { k, input, stored }).is_err() {
                                break;
                            }
                        }
                        Elig::Verbatim => {
                            // "Uncompressed" is a claim about the bytes,
                            // so it gets checked like any other: the
                            // stored bytes must BE the logical ones.
                            let stored = read_stored(view, pc)?;
                            if stored.len() >= bytes.len() && stored[..bytes.len()] == bytes[..] {
                                let n = segs.len();
                                splice_verbatim(pc, bytes.len() as u64, used, &mut segs);
                                if segs.len() > n {
                                    verbatim += 1;
                                }
                            } else {
                                // Stored some other way after all —
                                // rotated in place, or an algorithm
                                // this reader decodes but can't emit.
                                not_verbatim += 1;
                            }
                        }
                    }
                }
                // Covers past the last decoded pcluster never verified.
                for cv in used.iter().skip(cursor) {
                    failed.lock().unwrap().insert(cv.idx);
                }
                for (ci, _, _) in &active {
                    failed.lock().unwrap().insert(used[*ci].idx);
                }
                Ok(())
            })();
            drop(tx);
        });
        result?;
        let (ok, mismatch, margin) = counts.into_inner().unwrap();
        stats.verified = ok;
        stats.verbatim = verbatim;
        stats.not_verbatim = not_verbatim;
        stats.mismatch += mismatch;
        stats.margin += margin;
        let failed = failed.into_inner().unwrap();
        stats.unverified_members += failed.len();
        Ok((out.into_inner().unwrap(), segs, failed))
    }
}

/// Plan one file that keeps pclusters of its own. Its bytes are read
/// back through the reader and hashed as they pass: nothing is emitted
/// unless the member's digest comes back, because every node here
/// claims that these image bytes ARE that member's. Returns the nodes
/// with the image offsets they occupy, the verbatim splices, and a
/// tally.
fn plan_own_file(
    fs: &crate::erofs::Erofs,
    view: &View,
    f: &crate::erofs::FileItem,
    idx: usize,
    member: &Member,
    cfg: &crate::erofs::LzmaCfg,
    preset: &Mutex<Option<u32>>,
) -> Result<PlannedFile> {
    let mut stats = PcStats::default();
    let empty = (Vec::new(), Vec::new(), PcStats::default());
    let pcs = f.plan.own_pclusters();
    let Some(zp) = f.plan.zplan() else {
        return Ok(empty);
    };
    // The whole member is the cover: these pclusters hold its bytes
    // and nobody else's.
    let covers = [Cover {
        idx,
        pstart: 0,
        len: member.size,
    }];
    // The spool is only reachable when a node's input span isn't
    // covered, which can't happen with a whole-member cover.
    let spool = LiteralSpool::new()?;
    let mut reader = fs.zreader(zp);
    let mut hasher = sha2::Sha256::new();
    let mut window: Vec<u8> = Vec::new();
    let mut at = 0u64; // logical offset of window[0]
    let mut nodes: Vec<(PClusterNode, u64)> = Vec::new();
    let mut segs: Vec<Seg> = Vec::new();
    for pc in &pcs {
        // Everything up to this pcluster still has to stream past, so
        // the digest covers the whole member.
        let want = pc.la + pc.llen + ENCODE_MARGIN as u64;
        fill(&mut reader, &mut hasher, &mut window, at, want)?;
        if pc.la < at {
            return Ok(empty); // extents out of order — not a plan we make
        }
        let lo = (pc.la - at) as usize;
        if lo >= window.len() {
            continue;
        }
        let stored = read_stored(view, pc)?;
        if pc.lzma {
            // Read the shared preset into a local: a guard temporary in
            // the scrutinee would still be held inside the arms, and an
            // arm locks it again.
            let known = *preset.lock().unwrap();
            match plan_pcluster(
                pc,
                &stored,
                &window[lo..],
                &covers,
                known,
                cfg.dict_size,
                &spool,
            ) {
                Ok(Some((node, p))) => {
                    *preset.lock().unwrap() = Some(p);
                    stats.verified += 1;
                    nodes.push((node, pc.pa));
                }
                Ok(None) => stats.mismatch += 1,
                Err(e) if e.to_string() == MARGIN_SHORT => stats.margin += 1,
                Err(_) => stats.mismatch += 1,
            }
        } else {
            let logical = (pc.llen as usize).min(window.len() - lo);
            if stored.len() >= logical && stored[..logical] == window[lo..lo + logical] {
                let n = segs.len();
                splice_verbatim(pc, logical as u64, &covers, &mut segs);
                if segs.len() > n {
                    stats.verbatim += 1;
                }
            } else {
                stats.not_verbatim += 1;
            }
        }
        // Drop what the next pcluster can't need. `at` only advances
        // by what was really there: a short read at EOF must not leave
        // the window's offset ahead of the bytes in it.
        let keep = pc.la + pc.llen;
        if keep > at {
            let drop = ((keep - at) as usize).min(window.len());
            window.drain(..drop);
            at += drop as u64;
        }
    }
    // Whatever is left of the member still has to be hashed.
    fill(&mut reader, &mut hasher, &mut window, at, u64::MAX)?;
    let got: [u8; 32] = hasher.finalize().into();
    if got != member.digests.as_ref().expect("digests").sha256 {
        stats.unverified_members += 1;
        return Ok((Vec::new(), Vec::new(), stats));
    }
    Ok((nodes, segs, stats))
}

/// Read forward until the window covers [at, want), hashing what
/// passes — the member's digest is the proof that these bytes are
/// what the recipe says they are.
fn fill(
    reader: &mut impl Read,
    hasher: &mut sha2::Sha256,
    window: &mut Vec<u8>,
    at: u64,
    want: u64,
) -> Result<()> {
    let mut buf = [0u8; 1 << 16];
    while at + (window.len() as u64) < want {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        window.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

/// The bytes a pcluster occupies in the image.
fn read_stored(view: &View, pc: &crate::erofs::PCluster) -> Result<Vec<u8>> {
    let mut stored = vec![0u8; pc.plen as usize];
    ensure!(
        view.read_full_at(&mut stored, pc.pa)? == stored.len(),
        "truncated pcluster at {}",
        pc.pa
    );
    Ok(stored)
}

/// Place the members packed into an uncompressed pcluster directly in
/// the image's splice: its stored bytes ARE their bytes (just checked),
/// so no builder is involved at all. Runs shorter than an inline
/// literal aren't worth a slice, and anything uncovered simply stays a
/// gap for the normal literal machinery.
fn splice_verbatim(pc: &crate::erofs::PCluster, llen: u64, covers: &[Cover], segs: &mut Vec<Seg>) {
    let end = pc.la + llen;
    let mut pos = pc.la;
    for cv in covers {
        if cv.end() <= pos {
            continue;
        }
        if cv.pstart >= end {
            break;
        }
        let (lo, hi) = (cv.pstart.max(pos), cv.end().min(end));
        if lo >= hi {
            continue;
        }
        if hi - lo > INLINE_MAX {
            segs.push(Seg::Tabled {
                idx: cv.idx,
                from: lo - cv.pstart,
                len: hi - lo,
                at: 0, // assigned when merged into the image's build
                root_off: pc.pa + (lo - pc.la),
            });
        }
        pos = hi;
    }
}

/// Merge cover spans into a disjoint ascending union.
fn merge_spans(covers: &[Cover]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for c in covers {
        match out.last_mut() {
            Some(last) if c.pstart <= last.1 => last.1 = last.1.max(c.end()),
            _ => out.push((c.pstart, c.end())),
        }
    }
    out
}

/// Bytes of [at, at+len) the (ascending, disjoint) union covers.
fn overlap(union: &[(u64, u64)], at: u64, len: u64) -> u64 {
    let end = at + len;
    let start = union.partition_point(|&(_, e)| e <= at);
    let mut n = 0;
    for &(s, e) in &union[start..] {
        if s >= end {
            break;
        }
        n += e.min(end) - s.max(at);
    }
    n
}

const MARGIN_SHORT: &str = "encoder ran out of input before filling the pcluster";

/// Re-encode one stored pcluster and, when it comes back byte-exact,
/// tile the input span it consumed with the members that cover it.
/// `known` is the preset the image has already been shown to use; with
/// none, every preset is tried (mkfs runs one compressor config per
/// image, so the first answer settles it).
#[allow(clippy::too_many_arguments)]
fn plan_pcluster(
    pc: &crate::erofs::PCluster,
    stored: &[u8],
    stream: &[u8],
    covers: &[Cover],
    known: Option<u32>,
    dict_size: u32,
    spool: &LiteralSpool,
) -> Result<Option<(PClusterNode, u32)>> {
    let pad = crate::erofs::pcluster_padding(stored);
    ensure!(pad < stored.len(), "pcluster is all padding");
    let cap = stored.len() - pad;
    // Preset 6 is what mkfs.erofs defaults to; the rest of the ladder
    // and the extreme variants are the fallback.
    let presets: Vec<u32> = match known {
        Some(p) => vec![p],
        None => std::iter::once(6)
            .chain(0..=9u32)
            .chain((0..=9u32).map(|p| p | LZMA_PRESET_EXTREME))
            .collect(),
    };
    // How much input to hand the encoder. mkfs hands it the whole
    // remaining stream and lets the OUTPUT buffer end the pcluster, so
    // an encoder fed exactly the span can end its stream cleanly
    // instead and differ in the last few bytes. Whatever length is
    // used here is what the node records as its inputs, so `check`
    // re-encodes byte-identically by construction.
    let lengths: Vec<usize> = [pc.llen as usize, 1 << 12, 1 << 16, ENCODE_MARGIN]
        .iter()
        .scan(0usize, |acc, &n| {
            *acc = if *acc == 0 { n } else { pc.llen as usize + n };
            Some((*acc).min(stream.len()))
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut hit = None;
    let mut short = false;
    'search: for p in presets {
        for &fed in &lengths {
            let (out, consumed) =
                crate::erofs::microlzma_encode(&stream[..fed], cap, p, dict_size)?;
            if out.len() < cap && consumed == fed as u64 && fed < stream.len() {
                short = true; // ran out of input, not output: feed more
                continue;
            }
            let mut candidate = vec![0u8; pad];
            candidate.extend_from_slice(&out);
            candidate.resize(stored.len(), 0);
            if candidate == stored {
                hit = Some((p, fed as u64));
                break 'search;
            }
        }
    }
    let Some((preset, fed)) = hit else {
        if short {
            bail!("{MARGIN_SHORT}");
        }
        return Ok(None);
    };

    // Tile the span that was fed: one cover per byte, the rest literal.
    let mut inputs: Vec<PcInput> = Vec::new();
    let end = pc.la + fed;
    let mut pos = pc.la;
    let literal = |from: u64, to: u64, inputs: &mut Vec<PcInput>| -> Result<()> {
        let bytes = &stream[(from - pc.la) as usize..(to - pc.la) as usize];
        let len = to - from;
        let (spool_off, inline) = if len <= INLINE_MAX {
            (0, Some(bytes.to_vec()))
        } else {
            (spool.append(bytes)?, None)
        };
        inputs.push(PcInput::Literal {
            spool_off,
            len,
            residue_off: None,
            inline,
        });
        Ok(())
    };
    for cv in covers {
        if cv.end() <= pos {
            continue;
        }
        if cv.pstart >= end {
            break;
        }
        let lo = cv.pstart.max(pos);
        let hi = cv.end().min(end);
        if lo >= hi {
            continue;
        }
        if lo > pos {
            literal(pos, lo, &mut inputs)?;
        }
        inputs.push(PcInput::Member {
            idx: cv.idx,
            from: lo - cv.pstart,
            len: hi - lo,
        });
        pos = hi;
    }
    if pos < end {
        literal(pos, end, &mut inputs)?;
    }
    // A node whose inputs are all literal proves nothing and costs the
    // residue more than the stored bytes it replaces.
    if !inputs.iter().any(|i| matches!(i, PcInput::Member { .. })) {
        return Ok(None);
    }
    Ok(Some((
        PClusterNode {
            size: pc.plen,
            sha256: sha2::Sha256::digest(stored).into(),
            pad,
            preset,
            dict_size,
            inputs,
            name: format!("pcluster@{}", pc.pa),
        },
        preset,
    )))
}

/// Merge freshly planned segments into an already-planned build,
/// re-tiling its literal gaps around them.
fn splice_in(i: usize, plan: &mut Plan, extra: Vec<Seg>, _view: &View) -> Result<()> {
    let build = plan
        .builds
        .get_mut(&i)
        .context("erofs image has no build")?;
    let size = build.runs.iter().map(|&(_, _, l)| l).sum::<u64>();
    let mut segs: Vec<Seg> = std::mem::take(&mut build.segs)
        .into_iter()
        .filter(|s| !matches!(s, Seg::Gap { .. }))
        .collect();
    let mut taken = Intervals::default();
    for s in &segs {
        taken.insert(s.at(), s.len());
    }
    for mut s in extra {
        // Segments arrive in the image's own space: a pcluster's `pa`
        // is an offset into the image, which maps to this build's
        // logical space through its runs.
        let (at, root_off, len) = match &mut s {
            Seg::PCluster {
                at, root_off, len, ..
            }
            | Seg::Tabled {
                at, root_off, len, ..
            } => (at, root_off, len),
            _ => continue,
        };
        let Some(&(rlog, roff, _)) = build
            .runs
            .iter()
            .find(|&&(_, off, l)| off <= *root_off && *root_off + *len <= off + l)
        else {
            continue; // outside the image's own ranges — cannot happen
        };
        *at = rlog + (*root_off - roff);
        if !taken.admits(*at, *len) {
            continue;
        }
        taken.insert(*at, *len);
        segs.push(s);
    }
    segs.sort_by_key(|s| s.at());
    build.segs = tile_gaps(segs, size);
    Ok(())
}

/// Fill the space between accepted segments with literal gaps; the
/// tiling must come out exact or the plan is wrong.
fn tile_gaps(segs: Vec<Seg>, size: u64) -> Vec<Seg> {
    let mut tiled: Vec<Seg> = Vec::new();
    let mut pos = 0u64;
    for seg in segs {
        let at = seg.at();
        assert!(at >= pos, "overlapping splice segments survived planning");
        if at > pos {
            tiled.push(Seg::Gap {
                at: pos,
                len: at - pos,
                residue_off: None,
                inline: None,
            });
        }
        pos = at + seg.len();
        tiled.push(seg);
    }
    if pos < size {
        tiled.push(Seg::Gap {
            at: pos,
            len: size - pos,
            residue_off: None,
            inline: None,
        });
    }
    tiled
}

/// Discard a rejected subtree's plans (a parent refused the child on
/// extent overlap or a failed compressor search after recursion had
/// already planned it).
fn remove_plan_subtree(plan: &mut Plan, i: usize) {
    plan.extracts.remove(&i);
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

/// Hand a pcluster node's literal inputs to the residue, in the order
/// the node lists them — which is the order `check` will read them
/// back in, so the sidecar stays stream-ordered and compressible.
fn spill_pcluster(pc: usize, plan: &mut Plan, vs: &mut VerifyState) -> Result<()> {
    let Plan {
        pclusters,
        literals,
        ..
    } = plan;
    for input in pclusters[pc].inputs.iter_mut() {
        if let PcInput::Literal {
            spool_off,
            len,
            residue_off,
            inline,
        } = input
        {
            if inline.is_some() {
                continue;
            }
            *residue_off = Some(vs.residue.len);
            let spool = literals
                .as_ref()
                .context("pcluster literals without a spool")?;
            spool.read_at(*spool_off, *len, &mut |b| vs.residue.write(b))?;
        }
    }
    Ok(())
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
            Seg::Tabled { len, root_off, .. } => {
                // The bytes are the container's own; that they are also
                // the member's was proven at planning time, against the
                // member's digest.
                hash_root_range(&view, *root_off, *len, &mut buf, |b| h.update(b))
                    .with_context(|| format!("verbatim range at {root_off}"))?;
            }
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
            Seg::PCluster {
                pc, len, root_off, ..
            } => {
                // The node itself was proven at planning time (the
                // re-encode IS the comparison); what's left is to hash
                // the stored bytes in place and hand its literal
                // inputs to the residue, here, in document order.
                hash_root_range(&view, *root_off, *len, &mut buf, |b| h.update(b))
                    .with_context(|| format!("pcluster at {root_off}"))?;
                spill_pcluster(*pc, plan, vs)?;
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

/// A ref's claims: where THESE bytes are fetchable. Archive-interior
/// findings are excluded — their URL fetches the containing archive
/// (they surface as extract nodes, never as ref claims).
fn claims_json(findings: &[crate::finding::Finding]) -> Vec<Value> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for f in findings {
        if f.archive.is_some() {
            continue;
        }
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

/// The top-level sources table: one archive ref per distinct archive
/// the plan's extract nodes fetch from, plus member idx → table idx.
/// Claims are first-seen (every extract node carries its own witness
/// line; the table entry exists so the archive is stated once).
fn sources_json(
    plan: &Plan,
    members: &[Member],
    evidence: &[report::Evidence],
) -> (Vec<Value>, HashMap<usize, usize>, HashMap<usize, usize>) {
    let mut order: Vec<usize> = plan.extracts.keys().copied().collect();
    order.sort_unstable();
    let mut idx_of_digest: HashMap<String, usize> = HashMap::new();
    let mut sources = Vec::new();
    let mut src_of = HashMap::new();
    for i in order {
        let e = &plan.extracts[&i];
        let idx = *idx_of_digest
            .entry(e.archive.digest.clone())
            .or_insert_with(|| {
                sources.push(json!({ "ref": {
                    "digests": { "sha256": e.archive.digest },
                    "name": e.archive.name,
                    "claims": [{
                        "attestor": e.attestor,
                        "statement": e.statement,
                        "url": e.archive.url,
                    }],
                }}));
                sources.len() - 1
            });
        src_of.insert(i, idx);
    }
    // Members that only exist inside a compressed pcluster get their
    // node here too: several pclusters may slice one member, and a
    // slice needs a node to point at.
    let mut node_of = HashMap::new();
    for &i in &plan.tabled {
        node_of.insert(i, sources.len());
        sources.push(node_json(
            i,
            members,
            plan,
            evidence,
            &src_of,
            &HashMap::new(),
        ));
    }
    (sources, src_of, node_of)
}

/// One microlzma@0 node: the stored bytes of an erofs pcluster, as the
/// encoder run that produces them from member slices.
fn pcluster_json(
    node: &PClusterNode,
    members: &[Member],
    node_of: &HashMap<usize, usize>,
) -> Value {
    let inputs: Vec<Value> = node
        .inputs
        .iter()
        .map(|input| match input {
            PcInput::Member { idx, from, len } => {
                let source = node_of[idx];
                if *from == 0 && *len == members[*idx].size {
                    json!({ "source": source })
                } else {
                    json!({ "slice": { "source": source, "from": from, "len": len } })
                }
            }
            PcInput::Literal {
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
    let mut params = json!({
        "preset": node.preset & !LZMA_PRESET_EXTREME,
        "dict_size": node.dict_size,
        "pad": node.pad,
    });
    if node.preset & LZMA_PRESET_EXTREME != 0 {
        params["extreme"] = json!(true);
    }
    json!({ "build": {
        "builder": "microlzma@0",
        "name": node.name,
        "params": params,
        "output": { "sha256": hex_lower(&node.sha256), "size": node.size },
        "inputs": inputs,
    } })
}

fn node_json(
    i: usize,
    members: &[Member],
    plan: &Plan,
    evidence: &[report::Evidence],
    src_of: &HashMap<usize, usize>,
    node_of: &HashMap<usize, usize>,
) -> Value {
    let m = &members[i];
    if let Some(e) = plan.extracts.get(&i) {
        return json!({ "extract": {
            "name": leaf_name(m),
            "archive": { "source": src_of[&i] },
            "path": e.archive.path,
            "output": { "sha256": hex_lower(&m.digests.as_ref().expect("digests").sha256),
                        "size": m.size },
            "claims": [{
                "attestor": e.attestor,
                "statement": e.statement,
                "url": e.archive.url,
            }],
        } });
    }
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
            "inputs": [node_json(c.child, members, plan, evidence, src_of, node_of)],
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
                        let node = node_json(*idx, members, plan, evidence, src_of, node_of);
                        if *from == 0 && *len == members[*idx].size {
                            node
                        } else {
                            json!({ "slice": { "of": node, "from": from, "len": len } })
                        }
                    }
                    Seg::Tabled { idx, from, len, .. } => {
                        let source = node_of[idx];
                        if *from == 0 && *len == members[*idx].size {
                            json!({ "source": source })
                        } else {
                            json!({ "slice": { "source": source, "from": from, "len": len } })
                        }
                    }
                    Seg::PCluster { pc, .. } => {
                        pcluster_json(&plan.pclusters[*pc], members, node_of)
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
        doc["hdx_recipe"] == json!("0") || doc["hdx_recipe"] == json!("1"),
        "{}: not an hdx recipe (or an unknown version)",
        recipe.display()
    );
    let sources: Vec<Value> = doc["sources"].as_array().cloned().unwrap_or_default();

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
    collect_missing(root, &sources, &blobs, &mut missing)?;
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
        sources: &sources,
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
    /// The document's top-level sources table (`{"source": i}` nodes
    /// and `{"slice": {"source": i, …}}` index into it).
    sources: &'a [Value],
    residue: Option<Spool>,
    /// Builds materialized for slicing, by output sha256.
    built: HashMap<String, Spool>,
}

/// Follow `{"source": i}` indirections into the sources table.
fn resolve_source<'a>(node: &'a Value, sources: &'a [Value]) -> Result<&'a Value> {
    let mut n = node;
    for _ in 0..=sources.len() {
        let Some(i) = n["source"].as_u64() else {
            return Ok(n);
        };
        n = sources
            .get(i as usize)
            .with_context(|| format!("source index {i} out of range"))?;
    }
    bail!("source indirection loop in recipe")
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
    if node["extract"].is_object() {
        return Ok(node["extract"]["output"]["sha256"]
            .as_str()
            .context("extract without output sha256")?
            .to_string());
    }
    bail!("node is neither ref, build, nor extract")
}

fn node_name(node: &Value) -> String {
    node["ref"]["name"]
        .as_str()
        .or(node["build"]["name"].as_str())
        .or(node["extract"]["name"].as_str())
        .unwrap_or("?")
        .to_string()
}

fn collect_missing(
    node: &Value,
    sources: &[Value],
    blobs: &HashMap<String, PathBuf>,
    missing: &mut Vec<(String, String, Vec<String>)>,
) -> Result<()> {
    let node = resolve_source(node, sources)?;
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
        return Ok(());
    }
    if node["extract"].is_object() {
        // Either the extracted bytes themselves or the archive they
        // are attested to live in satisfies an extract node; when
        // neither is present, the ARCHIVE is what the claim URLs
        // fetch, so that's what gets reported.
        let e = &node["extract"];
        if let Some(sha) = e["output"]["sha256"].as_str() {
            if blobs.contains_key(sha) {
                return Ok(());
            }
        }
        return collect_missing(&e["archive"], sources, blobs, missing);
    }
    if node["build"].is_object() {
        let b = &node["build"];
        // A locally-present copy of the build's own output short-
        // circuits its whole subtree.
        if let Some(sha) = b["output"]["sha256"].as_str() {
            if blobs.contains_key(sha) {
                return Ok(());
            }
        }
        for input in b["inputs"].as_array().into_iter().flatten() {
            let sl = &input["slice"];
            let inner = if sl.is_object() {
                // A slice addresses an inline node (`"of"`) or a
                // sources-table entry (`"source"`).
                if sl["of"].is_object() {
                    &sl["of"]
                } else {
                    resolve_source(sl, sources)?
                }
            } else {
                input
            };
            if inner["literal"].is_object() {
                continue;
            }
            collect_missing(inner, sources, blobs, missing)?;
        }
    }
    Ok(())
}

/// Produce a node's bytes into `feed`, returning the byte count.
fn assemble(
    node: &Value,
    ctx: &mut CheckCtx,
    feed: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<u64> {
    let node = resolve_source(node, ctx.sources)?;
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
        let of = if sl["of"].is_object() {
            &sl["of"]
        } else {
            resolve_source(sl, ctx.sources)?
        };
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
    if node["extract"].is_object() {
        // The attested edge gets verified for real here: walk the
        // locally-present archive to the stated path and require the
        // output digest back. A local copy of the extracted bytes
        // short-circuits the walk, same as a build's output would.
        let e = &node["extract"];
        let name = node_name(node);
        let want = e["output"]["sha256"].as_str().context("extract sha256")?;
        let size = e["output"]["size"].as_u64().context("extract size")?;
        if ctx.blobs.contains_key(want) {
            let as_ref = json!({ "ref": { "digests": { "sha256": want },
                                          "name": e["name"] } });
            return assemble(&as_ref, ctx, feed);
        }
        let archive = resolve_source(&e["archive"], ctx.sources)?;
        let asha = node_sha256(archive)?;
        let apath = ctx
            .blobs
            .get(&asha)
            .with_context(|| format!("missing archive blob for {name}"))?;
        let path = e["path"].as_str().context("extract path")?;
        let mut h = sha2::Sha256::new();
        let mut n = 0u64;
        archive_extract(apath, path, &mut |b| {
            h.update(b);
            n += b.len() as u64;
            feed(b)
        })
        .with_context(|| format!("{name}: extracting {path} from {}", node_name(archive)))?;
        let got = hex_lower(&h.finalize());
        ensure!(
            got == want,
            "{name}: extracted bytes hash to {got}, recipe says {want} — stale attestation, or a different build of the archive?"
        );
        ensure!(n == size, "{name}: extracted {n} bytes, recipe says {size}");
        return Ok(n);
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
            "microlzma@0" => return assemble_microlzma(b, &sha, ctx, feed),
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

/// Rebuild a microlzma@0 node: concatenate its inputs — slices of the
/// files packed into this pcluster, plus whatever the residue carries
/// — and re-run the fixed-output MicroLZMA encoder with the recorded
/// parameters. mkfs.erofs' output is a function of those bytes and
/// those parameters, so the digest check is the whole proof.
fn assemble_microlzma(
    b: &Value,
    sha: &str,
    ctx: &mut CheckCtx,
    feed: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<u64> {
    let name = b["name"].as_str().unwrap_or("?").to_string();
    let p = &b["params"];
    let preset = p["preset"].as_u64().context("microlzma@0 preset")? as u32
        | if p["extreme"] == json!(true) {
            LZMA_PRESET_EXTREME
        } else {
            0
        };
    let dict_size = p["dict_size"].as_u64().context("microlzma@0 dict_size")? as u32;
    let pad = p["pad"].as_u64().unwrap_or(0) as usize;
    let size = b["output"]["size"]
        .as_u64()
        .context("microlzma@0 output size")?;
    ensure!(
        (pad as u64) < size && size <= crate::erofs::PCLUSTER_MAX_SIZE,
        "{name}: implausible pcluster ({size} bytes, {pad} padding)"
    );

    // A pcluster's input is bounded by the format (one pcluster's
    // logical span), so it assembles in memory.
    let mut input: Vec<u8> = Vec::new();
    for i in b["inputs"].as_array().context("build inputs")? {
        assemble(i, ctx, &mut |bytes| {
            input.extend_from_slice(bytes);
            Ok(())
        })?;
        // One pcluster's span, plus the lookahead a node may have been
        // fed past it (see the input ladder in plan_pcluster).
        ensure!(
            input.len() as u64 <= crate::erofs::PCLUSTER_MAX_DSIZE + ENCODE_MARGIN as u64,
            "{name}: pcluster inputs exceed the format's maximum span"
        );
    }
    // The node's inputs ARE the bytes mint handed the encoder — they
    // may run past what it consumed, on purpose: an encoder that runs
    // out of input ends its stream cleanly, which is not what mkfs
    // stored.
    let (out, _) = crate::erofs::microlzma_encode(&input, size as usize - pad, preset, dict_size)
        .with_context(|| format!("{name}: re-encoding"))?;
    let mut bytes = vec![0u8; pad];
    bytes.extend_from_slice(&out);
    bytes.resize(size as usize, 0);
    let got = hex_lower(&sha2::Sha256::digest(&bytes));
    ensure!(
        got == sha,
        "{name}: re-encoded pcluster hashes to {got}, recipe says {sha} — is this the same liblzma that minted it?"
    );
    feed(&bytes)?;
    Ok(size)
}

/// Stream one member's bytes out of a locally-present archive blob.
/// rpm only for now (the attested-extraction witnesses are rpm
/// repos); the format is sniffed, not declared — the grammar states
/// containment, and knowing how to open archives is check's job.
fn archive_extract(
    archive: &Path,
    member: &str,
    feed: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<()> {
    use std::io::{BufReader, Seek, SeekFrom};
    let mut f = std::fs::File::open(archive)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    ensure!(
        magic == [0xed, 0xab, 0xee, 0xdb],
        "not an rpm — hdx doesn't know how to extract from this archive"
    );
    f.seek(SeekFrom::Start(0))?;
    let mut r = BufReader::new(f);
    crate::peek_walk::skip_rpm_headers(&mut r).context("rpm header parse failed")?;
    // The payload is a compressed cpio; sniff the wrapper.
    let mut head = [0u8; 6];
    r.read_exact(&mut head)?;
    let src: Box<dyn Read> = Box::new(std::io::Cursor::new(head.to_vec()).chain(r));
    let mut payload: Box<dyn Read> = if head[..2] == [0x1f, 0x8b] {
        Box::new(flate2::read::MultiGzDecoder::new(src))
    } else if head == [0xfd, b'7', b'z', b'X', b'Z', 0x00] {
        Box::new(liblzma::read::XzDecoder::new_multi_decoder(src))
    } else if head[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(zstd::stream::read::Decoder::new(src)?)
    } else if head.starts_with(b"BZh") {
        Box::new(bzip2::read::MultiBzDecoder::new(src))
    } else if head.starts_with(b"070701") || head.starts_with(b"070702") {
        src
    } else {
        bail!("unrecognized rpm payload compression");
    };
    let want = member.trim_start_matches('/');
    loop {
        let mut hdr = [0u8; 110];
        payload
            .read_exact(&mut hdr)
            .context("rpm payload ended before the stated path")?;
        let Some((_mode, filesize, name)) =
            crate::peek_walk::cpio_header(&hdr, |buf| payload.read_exact(buf))?
        else {
            bail!("bad cpio member magic in rpm payload");
        };
        if name == "TRAILER!!!" {
            bail!("{member}: no such path in the rpm payload");
        }
        // Hardlinked content rides on ONE of its cpio entries; a
        // zero-length entry for the stated path fails the digest
        // check downstream, which is the honest outcome.
        if name.trim_start_matches('/') == want {
            let mut left = filesize;
            let mut buf = vec![0u8; 1 << 20];
            while left > 0 {
                let cap = (left as usize).min(buf.len());
                let n = payload.read(&mut buf[..cap])?;
                ensure!(n > 0, "rpm payload truncated mid-member");
                feed(&buf[..n])?;
                left -= n as u64;
            }
            return Ok(());
        }
        let skip = filesize + (4 - filesize % 4) % 4;
        let copied = std::io::copy(&mut Read::take(&mut payload, skip), &mut std::io::sink())?;
        ensure!(copied == skip, "rpm payload truncated");
    }
}

/// Materialize a node's bytes for random access (slices of rebuilt
/// containers), in RAM below CHECK_SPOOL_MAX, else in a temp file.
fn materialize(node: &Value, ctx: &mut CheckCtx) -> Result<Spool> {
    let node = resolve_source(node, ctx.sources)?;
    let size = node["build"]["output"]["size"]
        .as_u64()
        .or(node["ref"]["size"].as_u64())
        .or(node["extract"]["output"]["size"].as_u64())
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
    if node["extract"].is_object() {
        // Extracted bytes aren't fetchable as a whole file either —
        // jigdo has no extraction step, so they ride in the template.
        push_literal(
            out,
            node["extract"]["output"]["size"]
                .as_u64()
                .context("extract size")?,
        );
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
    ensure!(
        doc["hdx_recipe"] == json!("0") || doc["hdx_recipe"] == json!("1"),
        "not an hdx recipe (or an unknown version)"
    );
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
