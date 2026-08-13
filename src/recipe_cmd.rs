//! Recipes: reconstruction manifests minted from container descents
//! (splice@0 — the first rung). A recipe is a verified proof of
//! composition: the container's bytes are a deterministic splice of
//! member byte ranges — referenced by digest, with claim URLs where
//! the indexes know the bytes — plus literal gap bytes carried in a
//! residue sidecar. `check` rebuilds from locally-present blobs and
//! verifies byte-exactness; it never fetches — the claims tell you
//! where the missing members live.
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
}

struct Plan {
    /// Member idx → its build plan; members referenced but not built
    /// appear only as `Seg::Child` entries.
    builds: HashMap<usize, Build>,
    root: usize,
    root_src: usize,
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
            "100% by claimed reference — the indexes name these bytes; nothing to reconstruct\n→ {}",
            out.display()
        );
        report_summary(json_out, &doc, None, &line);
        return Ok(());
    }

    let mut plan = Plan {
        builds: HashMap::new(),
        root,
        root_src,
    };
    plan_build(root, &members, &kids, &evidence, &mut plan);
    ensure!(
        plan.builds.contains_key(&root),
        "no member of {} is reachable as a byte range — nothing beyond a trivial full-literal recipe",
        path.display()
    );

    // Verify: every ref re-read from its recorded ranges must
    // reproduce its digest, and every build re-spliced from its
    // segments must reproduce its own. The residue is written during
    // the splice pass (document order), so the sidecar is a byproduct
    // of the proof.
    let view = View::of_file(path)?;
    verify_refs(&view, &members, &plan, threads, &ticker)?;
    let residue = ResidueWriter::new(&residue_path(&doc_path(path)));
    let mut vs = VerifyState {
        view: &view,
        members: &members,
        residue,
        done: 0,
        ticker: &ticker,
    };
    verify_build(root, &mut plan, &mut vs)?;
    let residue = vs.residue.finish()?;
    ticker.clear();

    // Coverage: every byte belongs to exactly one leaf — a referenced
    // member's range or some build's literal gap.
    let total = members[root].size;
    let mut referenced = 0u64;
    let mut claimed = 0u64;
    let mut nrefs = 0usize;
    for b in plan.builds.values() {
        for seg in &b.segs {
            if let Seg::Child { idx, len, .. } = seg {
                if !plan.builds.contains_key(idx) {
                    referenced += len;
                    if !claims_of(*idx).is_empty() {
                        claimed += len;
                    }
                }
            }
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
        "residue": residue.as_ref().map(|r| json!({"sha256": hex_lower(&r.0), "size": r.1})),
        "coverage": {
            "total_bytes": total,
            "referenced_bytes": referenced,
            "claimed_bytes": claimed,
            "residue_bytes": total - referenced,
        },
    });
    let out = write_doc(path, &doc)?;

    let pct = |x: u64| 100.0 * x as f64 / total as f64;
    let mut line = format!(
        "{:.1}% by reference ({} of {}), {:.1}% with claim URLs",
        pct(referenced),
        human(referenced),
        human(total),
        pct(claimed),
    );
    match &residue {
        Some((_, sz)) => line.push_str(&format!(" · residue {}", human(*sz))),
        None => line.push_str(" · no residue"),
    }
    line.push_str(&format!(
        " · verified byte-exact\n→ {} ({} ref{}, {} build{})",
        out.display(),
        nrefs,
        s(nrefs),
        plan.builds.len(),
        s(plan.builds.len()),
    ));
    if referenced == 0 {
        line.push_str("\nnote: nothing referenced — this recipe is a full copy of the file");
    }
    report_summary(json_out, &doc, residue.as_ref().map(|r| r.1), &line);
    Ok(())
}

fn referenced_as_leaf(plan: &Plan, i: usize) -> bool {
    !plan.builds.contains_key(&i)
        && plan.builds.values().any(|b| {
            b.segs
                .iter()
                .any(|s| matches!(s, Seg::Child { idx, .. } if *idx == i))
        })
}

/// Plan member `i` as a build if any child survives as a byte range;
/// otherwise the caller keeps it as a plain ref. Claims stop descent:
/// a member the indexes already name is one line — its inside needs no
/// proof.
fn plan_build(
    i: usize,
    members: &[Member],
    kids: &[Vec<usize>],
    evidence: &[report::Evidence],
    plan: &mut Plan,
) -> bool {
    let Some(runs) = rangeable(members, plan.root_src, i) else {
        return false;
    };
    let runs = runs.to_vec();
    let mut segs: Vec<Seg> = Vec::new();
    let mut taken = Intervals::default();
    let mut dropped = 0usize;
    for &c in &kids[i] {
        let Some(cruns) = rangeable(members, plan.root_src, c) else {
            continue;
        };
        // Map the child's runs into this build's logical space; each
        // run lies inside one of our runs by construction (the child's
        // view was sliced from ours).
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
            continue;
        }
        for p in &pieces {
            if let Seg::Child { at, len, .. } = p {
                taken.insert(*at, *len);
            }
        }
        segs.extend(pieces);
        // A child the indexes name stays a ref; otherwise try to open
        // it as a build of its own.
        if evidence[c].0.iter().all(|f| f.claims.is_empty()) {
            plan_build(c, members, kids, evidence, plan);
        }
    }
    if segs.is_empty() && i != plan.root {
        return false;
    }
    segs.sort_by_key(|s| match s {
        Seg::Child { at, .. } | Seg::Gap { at, .. } => *at,
    });
    // Gaps between accepted segments become literals; the tiling must
    // come out exact or the plan is wrong.
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
        },
    );
    true
}

fn rangeable(members: &[Member], root_src: usize, i: usize) -> Option<&[(u64, u64, u64)]> {
    let m = &members[i];
    if m.size < IDENTITY_MIN_BYTES || m.digests.is_none() {
        return None;
    }
    m.extents
        .as_ref()
        .filter(|e| e.src == root_src)
        .map(|e| &e.runs[..])
}

// ------------------------------------------------------------ verifying

/// Re-read every referenced member's recorded ranges (logical order)
/// and require its sha256 back, in parallel.
fn verify_refs(
    view: &View,
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
                    let runs = m.extents.as_ref().expect("ref has extents");
                    let mut h = sha2::Sha256::new();
                    for &(_, off, len) in runs.runs.iter() {
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

/// Residue sidecar, created lazily on the first literal byte.
struct ResidueWriter {
    path: PathBuf,
    file: Option<std::fs::File>,
    hash: sha2::Sha256,
    len: u64,
}

impl ResidueWriter {
    fn new(path: &Path) -> ResidueWriter {
        ResidueWriter {
            path: path.to_path_buf(),
            file: None,
            hash: sha2::Sha256::new(),
            len: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.file.is_none() {
            self.file = Some(
                std::fs::File::create(&self.path)
                    .with_context(|| format!("create {}", self.path.display()))?,
            );
        }
        self.file.as_mut().unwrap().write_all(bytes)?;
        self.hash.update(bytes);
        self.len += bytes.len() as u64;
        Ok(())
    }

    fn finish(self) -> Result<Option<([u8; 32], u64)>> {
        match self.file {
            Some(f) => {
                f.sync_all().ok();
                Ok(Some((self.hash.finalize().into(), self.len)))
            }
            None => Ok(None),
        }
    }
}

struct VerifyState<'a> {
    view: &'a View,
    members: &'a [Member],
    residue: ResidueWriter,
    done: usize,
    ticker: &'a Ticker,
}

/// Re-splice build `i` from its segments and require its sha256 back;
/// literal gaps are captured (inline or into the residue) on the way
/// through. Child builds recurse at their position, so residue order
/// is document order.
fn verify_build(i: usize, plan: &mut Plan, vs: &mut VerifyState) -> Result<()> {
    let mut segs = std::mem::take(&mut plan.builds.get_mut(&i).expect("planned build").segs);
    let runs = vs.members[i]
        .extents
        .as_ref()
        .expect("build has extents")
        .runs
        .clone();
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    for seg in &mut segs {
        match seg {
            Seg::Child {
                idx, root_off, len, ..
            } => {
                hash_root_range(vs.view, *root_off, *len, &mut buf, |b| h.update(b))
                    .with_context(|| vs.members[*idx].path.clone())?;
                let idx = *idx;
                if plan.builds.contains_key(&idx) && !plan.builds[&idx].segs.is_empty() {
                    verify_build(idx, plan, vs)?;
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
                        let n = vs.view.read_full_at(&mut buf[..want], pos)?;
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

    // The residue sidecar sits next to the document.
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
            Some(bytes)
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
        residue: residue.as_deref(),
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
    residue: Option<&'a [u8]>,
    /// Builds materialized for slicing, by output sha256.
    built: HashMap<String, Spool>,
}

/// RAM-or-tempfile bytes for a rebuilt container a slice addresses.
enum Spool {
    Mem(Vec<u8>),
    File(std::fs::File),
}

impl Spool {
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
        let res = ctx.residue.context("recipe has literals but no residue")?;
        let lo = (off as usize).min(res.len());
        let hi = ((off + len) as usize).min(res.len());
        ensure!(hi - lo == len as usize, "literal outside the residue");
        feed(&res[lo..hi])?;
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
