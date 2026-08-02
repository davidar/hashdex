use crate::cache::Cache;
use crate::coord::{Coord, Scheme};
use crate::finding::Finding;
use crate::inverted::SourceIndex;
use std::collections::{HashMap, HashSet};

/// The graph walk: local resolution over inverted indexes + the
/// observation store. DESIGN.md's empirical bet made code — the walk is
/// shallow (2–3 hops) and narrow (5–15 coordinates), so closure is
/// computed live per query instead of materialized.
const MAX_HOPS: usize = 5;
const MAX_EVIDENCE: usize = 1000;

/// Weak digests are lookup keys, never merge keys (DESIGN.md hard
/// rule). Which schemes count as identity-grade is policy, not schema —
/// this const IS the current policy.
pub fn is_identity_grade(s: Scheme) -> bool {
    matches!(s, Scheme::Sha256 | Scheme::Sha512 | Scheme::Blake2s256)
}

/// One witnessed piece of evidence: a finding and the coordinate we
/// reached it through.
pub struct Evidence {
    pub found_at: Coord,
    pub finding: Finding,
}

/// Findings welded by shared identity-grade digests.
pub struct Cluster {
    pub findings: Vec<Finding>,
    /// Union of the cluster's coordinates, sorted.
    pub coords: Vec<Coord>,
    /// Whether this cluster carries any identity-grade coordinate.
    pub anchored: bool,
    /// Whether the queried coordinate is one of this cluster's coords.
    /// False = reached only through weak-digest links: related
    /// "consistent with" evidence, never same-content evidence.
    pub primary: bool,
}

pub struct WalkResult {
    pub clusters: Vec<Cluster>,
    /// Caps hit — evidence may be incomplete (mega-cluster guard).
    pub truncated: bool,
    /// The queried digest is weak and claimed by ≥2 anchored clusters
    /// that differ on identity-grade digests: a possible collision (or
    /// an honest ambiguity no single source could surface).
    pub collision: bool,
}

/// Fixpoint lookup: query local sources, follow co-observed
/// coordinates, repeat until nothing new (or caps).
pub fn walk(queried: &Coord, indexes: &[SourceIndex], cache: Option<&Cache>) -> Vec<Evidence> {
    let mut evidence: Vec<Evidence> = Vec::new();
    let mut seen_findings: HashSet<String> = HashSet::new();
    let mut visited: HashSet<Coord> = HashSet::new();
    let mut frontier = vec![queried.clone()];

    for _ in 0..MAX_HOPS {
        if frontier.is_empty() || evidence.len() >= MAX_EVIDENCE {
            break;
        }
        let mut next = Vec::new();
        for coord in frontier.drain(..) {
            if !visited.insert(coord.clone()) {
                continue;
            }
            let mut found: Vec<Finding> = Vec::new();
            for ix in indexes {
                found.extend(ix.lookup(&coord));
            }
            if let Some(cache) = cache {
                found.extend(cache.findings_for(&coord));
            }
            for finding in found {
                let key = serde_json::to_string(&finding).unwrap_or_default();
                if !seen_findings.insert(key) {
                    continue;
                }
                for c in &finding.coords {
                    if let Ok(c) = Coord::parse(c) {
                        if !visited.contains(&c) {
                            next.push(c);
                        }
                    }
                }
                evidence.push(Evidence {
                    found_at: coord.clone(),
                    finding,
                });
                if evidence.len() >= MAX_EVIDENCE {
                    break;
                }
            }
        }
        frontier = next;
    }
    evidence
}

/// Group evidence into identity clusters: union-find over findings,
/// merging ONLY where two findings share an identity-grade coordinate.
/// Weak-digest overlap never welds — such evidence stays in separate
/// clusters, surfaced as "consistent with" rather than "same bytes".
pub fn cluster(evidence: Vec<Evidence>, queried: &Coord) -> WalkResult {
    let n = evidence.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut Vec<usize>, i: usize) -> usize {
        if parent[i] != i {
            let root = find(parent, parent[i]);
            parent[i] = root;
        }
        parent[i]
    }
    fn union(parent: &mut Vec<usize>, a: usize, b: usize) {
        let (ra, rb) = (find(parent, a), find(parent, b));
        if ra != rb {
            parent[ra] = rb;
        }
    }

    // Effective coordinates of a finding: everything it co-observes,
    // plus the coordinate we reached it through.
    let coords_of = |e: &Evidence| -> Vec<Coord> {
        let mut v: Vec<Coord> = e
            .finding
            .coords
            .iter()
            .filter_map(|c| Coord::parse(c).ok())
            .collect();
        v.push(e.found_at.clone());
        v.sort_by(|a, b| (a.scheme.as_str(), &a.digest).cmp(&(b.scheme.as_str(), &b.digest)));
        v.dedup();
        v
    };

    let mut anchor: HashMap<Coord, usize> = HashMap::new();
    for (i, e) in evidence.iter().enumerate() {
        for c in coords_of(e) {
            if is_identity_grade(c.scheme) {
                match anchor.get(&c) {
                    Some(&j) => union(&mut parent, i, j),
                    None => {
                        anchor.insert(c, i);
                    }
                }
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }

    let mut clusters: Vec<Cluster> = Vec::new();
    for (_, members) in groups {
        let mut coords: Vec<Coord> = Vec::new();
        let mut findings = Vec::new();
        for &i in &members {
            coords.extend(coords_of(&evidence[i]));
        }
        coords.sort_by(|a, b| (a.scheme.as_str(), &a.digest).cmp(&(b.scheme.as_str(), &b.digest)));
        coords.dedup();
        let anchored = coords.iter().any(|c| is_identity_grade(c.scheme));
        let primary = coords.contains(queried);
        // preserve evidence order within the cluster
        let mut members = members;
        members.sort_unstable();
        for i in members {
            findings.push(evidence[i].finding.clone());
        }
        clusters.push(Cluster {
            findings,
            coords,
            anchored,
            primary,
        });
    }
    // Deterministic order: primary before related, anchored before
    // floating, then largest, then by first coordinate.
    clusters.sort_by(|a, b| {
        b.primary
            .cmp(&a.primary)
            .then(b.anchored.cmp(&a.anchored))
            .then(b.findings.len().cmp(&a.findings.len()))
            .then_with(|| {
                a.coords
                    .first()
                    .map(|c| c.to_string())
                    .cmp(&b.coords.first().map(|c| c.to_string()))
            })
    });

    let collision = !is_identity_grade(queried.scheme)
        && clusters
            .iter()
            .filter(|cl| cl.anchored && cl.primary)
            .count()
            >= 2;

    WalkResult {
        truncated: n >= MAX_EVIDENCE,
        collision,
        clusters,
    }
}
