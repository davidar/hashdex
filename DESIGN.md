# hashdex — design

*The canonical design: the inversion thesis, the collision-safe
identity model, scope and legal fences, and sizing. The verified
source inventory lives in [SOURCES.md](SOURCES.md).*

## One-liner

Given a hash — any hash, any scheme — return everything the world
already knows about it: what other coordinates the same content has,
who attests to what it is, what names point at it, and where you can
(probably) still get it.

No storage of content. No crawling of content. No new trust root. Pure
collation of indexes that already exist as side effects of other
people's work.

## Thesis

Content addressing won everywhere at the semantic layer (git, OCI
digests, Nix, ostree, WARC payload digests, sigstore, lockfiles) while
p2p *distribution* lost — availability is a public good with a
bystander problem, and HTTP keeps winning because a URL names a
responsible party. The stable architecture: **trust attaches to
hashes, availability attaches to named origins.**

So "one big content-addressed repo in the sky" already exists as a
mathematical object; everyone commits to it daily. What's missing is
porcelain: the *inverted* index. Forward indexes (name → hash) are
everywhere — every lockfile, SBOM, Packages file, CDX row. Almost
nobody maintains the inverse.

**How to build it: federate what's inverted, invert only the rest.**
We ingest nothing we don't have to. Per-shard decision rule, in
strict preference order:

1. **A live inverted index exists with usable terms → federate it.**
   Verified set as of 2026-08: deps.dev `GET /v3/query?hash.type=…`
   (md5/sha1/sha256/sha512 → npm, Cargo, Maven, NuGet, PyPI,
   RubyGems), CIRCL hashlookup (NSRL + distro + Windows corpora, +
   related-hash edges, + downloadable Bloom filter for negative
   checks), Software Heritage REST (all four hash types; 120/h anon,
   1200/h auth), snapshot.debian.org `/mr/file/<sha1>/info`, Rekor v1
   `/api/v1/index/retrieve`, VirusTotal/MalwareBazaar (opt-in keys).
2. **An inversion exists but not at interactive latency/cost
   (BigQuery: Rekor IndexKeys, PyPI) → periodically extract *their*
   inversion.** They did the join; we just materialize it.
3. **Only forward dumps exist → invert them ourselves** (the web
   archives, Wikimedia, and the registry/distro long tail deps.dev
   and CIRCL don't cover). See SOURCES.md for the verified inventory.
4. **Neither dumps nor inverse exists (OCI, IA-at-scale) →
   demand-driven probing only.**

**Every federated answer is cached as a witness co-observation** —
so the local evidence store densifies along the demand curve, which is the
original design ethos ("a hash gets richer the more people ask about
it") made mechanical. The web tier is the one corpus nobody has
inverted for anyone; that's where self-inversion is mandatory rather
than optional.

## The ancestor's grave, and the rule carved on it

hash-archive.org (Ben Trask, mid-2010s, defunct) had substantially
this vision and died of being **the hasher of record**: it fetched and
hashed content itself, so ingest scaled with the corpus, and new hash
algorithms meant re-fetching everything. The coverage obligation was
coupled to the corpus instead of to demand.

**Admission rule** (the generalized fix — every ingest decision passes
through it):

- Ingest cost must scale with |metadata|, never with |content|.
- Supporting a new hash algorithm must never imply re-fetching
  anything: new algorithms = new claim types accepted from that day
  forward, plus whatever holders backfill voluntarily.
- We index hashes other people computed as a side effect of their own
  work. We never assume a duty to hash the world.
- Allowed exceptions, both demand-driven and never corpus-coupled:
  users hashing their *own* files locally (`hdx coords`), and spot
  verification of specific URLs someone actually asked about.
- Corollary: completeness is explicitly a non-goal. The index is a
  gradually densifying graph, not a census. We happily ingest censuses
  *others* already ran; we never conduct one.

## Data model: two layers

We are mapping immutability onto a mutable world. Everything divides
by whether it can ever change meaning.

### Layer 1 — the evidence (source dumps + observation store)

The single primitive is the **witness co-observation**:

> attestor X held (or vouches for) a bytestring at time T, in context
> C (a URL, a package name@version, an archive item…), and reports its
> coordinates {scheme₁: digest₁, scheme₂: digest₂, …}.

One primitive, three jobs:

1. **Location evidence.** The context is a timestamped coordinate:
   `(url, observed-at)` never changes meaning even though the bare URL
   is mutable. A CDX row, a Packages stanza, a registry record are all
   witness co-observations.
2. **Crosswalk edges.** Any single-witness row carrying ≥2 digests of
   the same bytes is a cross-algorithm equivalence edge, minted
   without anyone touching content — Ubuntu Packages (4 algorithms),
   SWH contents (4 × 29B blobs), NSRL (4 × 1.5B rows), PyPI (3), etc.
   Byte-holding is only needed for *wrapper* schemes (git blob, NAR,
   OCI layer) and algorithms nobody publishes yet.
3. **Collision safety** — see the identity model below.

Also in layer 1: **derivation claims** ("NAR sha256:Y is the canonical
serialization of tree with git-hash X", "OCI layer digest Z is
gzip-of W") — computations attested by whoever ran them — and
third-party attestations relayed from transparency logs (rekor
entries, rebuilder verdicts, buildinfo files).

Attestors are always named. Where the upstream signs (Rekor, buildinfo,
F-Droid index), the signature rides along; unsigned shards (CDX,
BigQuery datasets) are wrapped as "hashdex observed shard S publishing
row R at time T" — accountability preserved, one hop removed.

Layer 1 is deliberately informal (decided 2026-08-02): it is the
source dumps we already hold — content-addressed by their own
digests — plus the durable observation store the CLI accumulates
(federated answers; hits never expire). No record format, no
commitment structure, no publishing machinery: hashdex collates
external sources, it is not a foundational ledger, and those become
worth designing only if the evidence layer itself ever becomes
something others mirror. Nothing is lost by deferring — dumps plus a
durable cache retain every fact, so a formal serialization stays a
transcoding job, not an archaeology job. Attribution still originates
here: evidence rows always name their attestor. What gets published
is layer 2.

**Edge-minting rule (strict):** only single-witness rows mint
equivalence edges. Joining *different* sources on (URL, time) — CDX's
sha1 with a distro index's sha256 for "the same" URL — is two
witnesses with a mutable world between them: at most a "plausibly
same" hint, never an identity edge. This corner must not be cut.

### Layer 2 — the views (mutable, derived, disposable)

Views contain **no new facts** — each is recomputable from layer 1
plus a policy, so none needs signatures or trust. These are the
product, and what we publish (membership filters, digest-sorted
coordinate shards, cluster indexes):

- **Identity clusters**: equivalence closure over co-observations,
  under the current closure policy (below).
- **Availability**: "this cluster is probably retrievable from these
  URLs." Derived from recent observations; **best-effort by design** —
  no standing commitment to verify liveness. Freshness checks happen
  in select cases only (a user asks; a curated shard warrants it) and
  are demand-driven, per the admission rule. Staleness is
  self-correcting: verification is one HTTP request away, by the
  client. Availability is advice, not attestation.
- **Admissibility**: which claims the default service serves —
  openly normative ("our definition of publicly accessible"). This is
  the trust-lens machinery with hashdex operating the default lens;
  anyone can run a different lens over the same dumps.

Precedent for the split: event log + materialized views; Rekor v2
deliberately keeping its search index outside the transparency log.
Availability wants freshness, attestation wants provenance — one
claims table would force each to wear the other's semantics.

## Identity under hash collisions

SHA-1 and MD5 collisions exist in the wild, and *honest* observations
of a collision pair would weld two identity clusters under naive
transitive closure: source A truthfully reports {sha1: X, sha256: A},
source B truthfully reports {sha1: X, sha256: B} — every claim true,
the inference false. MD5 collisions are cheap enough to make this a
deliberate cluster-welding attack that attestor trust cannot stop,
because nobody lied. The fix is structural:

- **Digests are never identity nodes; witnessed bytestrings are.**
  Digests are attributes of an anonymous witnessed object (the
  co-observation), not first-class entities that merge.
- **Merging requires sharing an identity-grade digest.** Weak digests
  (md5, sha1) are lookup keys, never merge keys.
- **Which algorithms are identity-grade is query-time closure policy,
  not ingest-time schema** — the same move as trust lenses. When
  sha256 eventually wobbles, demote it in policy and re-run closure
  over the same stored co-observations. No re-ingest, ever. (The
  collision problem and the new-algorithm problem land in the same
  slot — evidence the model is right.)
- Weak-only corpora (CDX is sha1-only; much of NSRL is md5/sha1)
  can never cause a merge; their claims attach to the weak digest and
  surface as "consistent with cluster(s) …" — explicitly ambiguous,
  which is honest rather than degraded.
- Free consequences: two clusters sharing a weak digest but differing
  on a strong one **is a detected collision**, emittable as a
  first-class claim (hashdex may be the only party joining sha1-keyed
  and sha256-keyed corpora at scale — positioned to notice collisions
  in the wild). And a collided-hash lookup returns *both* preimages'
  clusters — a better answer than any single shard can give.

## Hash Babel: wrappers and traps

Same bytes, many coordinates; and many wild hashes are not hashes of
the raw bytes at all. Nodes are (scheme, digest); schemes include
wrapper domains: git blob (`"blob <len>\0"+content`), SWHID, Nix NAR,
OCI compressed-layer digests, BitTorrent infohashes, CDC chunk trees.
Wrapper coordinates connect to raw coordinates only via derivation
claims computed by someone holding bytes.

Survey-confirmed traps (see SOURCES.md for details): Go sumdb H1 is a
dirhash of the *extracted* tree; Alpine APKINDEX's checksum covers
only the .apk control segment; Nix narinfo hashes live in the NAR
domain; Pixel transparency logs hash VBMeta, not the download;
OpenTimestamps commitments are nonce-blinded (unrecoverable — excluded
entirely); Packagist zipballs are unstable bytes. **Rule: never assume
a wild hash is of the raw bytes — verify the preimage definition per
source before ingest.**

CDC/chunking schemes (casync, restic, borg): out of scope for v1;
wrapper formats first.

## Scope

**Tier order: software artifacts → source code (SWH) → the static
web.** The fence is simultaneously the abuse fence, the legal fence,
and the cost fence — one line, three jobs.

**Web policy — stable static files only.** We want hashes where two
people could plausibly hold identical copies:

- MIME cut: drop `text/html` &co. (per-visit tokens and timestamps —
  ~70% of crawl rows); admit `application/*`, images, A/V, fonts,
  archives, wasm on sight.
- Recurrence rescue: admit *any* type whose digest recurs across
  crawls or URLs — demonstrated stability, computable from index
  metadata alone; rescues genuinely-static HTML.
- Full crawl history is **scanned** (cheaply, in place) as recurrence
  evidence but never **retained** as coverage — old crawls are mostly
  dead URLs.

History that is retained stays useful: archives transmute dead
location claims back into live ones via derivable replay URLs
(`web.archive.org/web/<ts>/<url>`; same pattern at Arquivo.pt,
snapshot.debian.org, old-releases.ubuntu.com, archive.archlinux.org).
The claim's attestor is its own resurrection path. Default answers are
"now"; full history behind an explicit flag — provenance queries
("where did this mystery PDF come from") are the flag's whole point.

OCI/container digests: no bulk source exists; defer, demand-driven
only. Naming ("what hash should I want") remains permanently out of
scope — hashdex answers "what is this hash," curators own names.

## Legal posture and redaction

Storing/serving hashes is not the liability surface; case law
(Grokster, Fung, TPB vs. VirusTotal/NSRL/CDX operating peacefully)
turns on a service's function and intent — magnet-link sites prove
"it's just hashes" is no defense, security/archival indexes prove
hash-serving per se is fine. Our shard selection *is* the fence: every
ingested shard resolves to legitimate named origins. DMCA 512(d)
(information location tools) + a registered agent is cheap armor.

Design consequences:

- Crosswalk and derivation edges are math: eternal, irrevocable,
  no takedown surface.
- Location claims are observations of the world, and the world
  contains lawyers: they need an off switch **in the publication
  layer**. The **redaction list** is the changelog of the default
  lens's admissibility predicate — signed, content-addressed, itself
  claims ("don't serve claim C, reason R, date D") — published
  alongside the dumps. Mirrors honoring it inherit safe-harbor
  hygiene; forks ignoring it own their own exposure, exactly where
  responsibility should sit.
- **Publication-layer requirement:** anything published carrying
  location claims must support *physical* removal, because
  suppression-only redaction won't satisfy a GDPR/court-order
  removal. Since we publish derived artifacts, this is nearly free:
  views are disposable by construction, so redaction = drop the row,
  rebuild the edition. (If a formal evidence dump ever ships,
  Rekor-style commitment/body separation is the known answer —
  decide it then, before that first dump.)

## Query architecture

The workload: (scheme, digest) → co-observations → other coordinates
→ fixpoint → claims for the cluster → lenses. The critical empirical
fact: **the walk is shallow and narrow** — a real file has ~5–15
coordinates and closure converges in 2–3 hops. This is not a
graph-database problem; it is point lookups with two rounds. No graph
engine, no server-side traversal.

**Resolution order** (each level falls through to the next, and every
hit at levels 2–3 is cached as a co-observation at level 1's edge):

0. **Prefilters — negative knowledge as a first-class layer.** A
   per-backend membership filter (Bloom/ribbon) consulted before any
   network call: most random hashes are in nobody's index, and with
   filters a miss costs zero queries instead of one per backend.
   Sources: CIRCL publishes its own (~700 MB / 298M sha1); deps.dev
   and Rekor filters are built from **digests-only** BigQuery column
   extracts (~240 MB / ~1.2 GB — far cheaper than full
   materialization); snapshot.d.o approximated from harvested
   Packages indexes; SWH-scale filters (29B contents) are
   **prefix-sharded and range-requested** from object storage like
   everything else, cached client-side, optionally synced whole for
   offline use. False positives cost one wasted query; staleness
   causes false negatives, so every filter carries its as-of edition
   and the rule is "filter says no → skip, unless `--thorough`",
   with append-heavy backends (Rekor) refreshed most often. Filters
   ship in the dumps — mirrors and CLI users inherit the
   don't-hammer behavior, which is how a popular hashdex avoids
   becoming its charity backends' biggest load problem.
1. **Local/self-inverted shards + overlay** — whatever we've
   materialized. Implemented as `hdx index`: per-source flat
   sorted-mmap coordinate indexes — fixed-width witness rows sorted
   by the primary digest, plus per-scheme digest→row files, 32-byte
   "HDXI" header, mmap + binary search + `madvise(Random)` — built
   from a forward dump by streaming external merge sort
   (laptop-scale even at 122M rows).
2. **Live federation adapters** — the verified inverted-index set
   (deps.dev query, CIRCL, SWH, snapshot.d.o, Rekor v1, opt-in VT).
3. **Demand-driven probes** — select cases only, per the admission
   rule.

**Closure is query-time policy, so locally it runs at query time.**
The walk computes it live: fixpoint over the inverted indexes + the
observation store (capped hops and evidence — the mega-cluster
guard), then union-find welding only on shared identity-grade
digests. Policy v1: identity-grade = {sha256, sha512, blake2s256};
md5/sha1/sha1_git are lookup keys, never merge keys. Clusters
containing the queried coordinate are *primary*; ones reached only
across weak links render as related, not identity-verified; only
clusters carrying a strong digest count as distinct contents; and a
weak digest claimed by two such clusters is a surfaced collision.
Since backends returning no crosswalk coordinates are common, their
unanchored findings never count as distinct contents.

**For published cluster indexes (if/when they ship), precompute that
same closure and ship the evidence.** Two artifacts: the
**coordinate index** ((scheme, digest) → cluster ID(s), plural for
weak digests — the collision case surfacing honestly) and the
**cluster store** (cluster → coordinates, claims, supporting
co-observations). Full resolution = two point lookups; because
cluster records carry their raw evidence (a few KB), exotic lenses
(different identity-grade or attestor policy) recompute client-side —
the precomputed cluster is a cache of the default policy, not a
betrayal of query-time policy.

**Physical layout: the published dataset is the database.** Both
artifacts are digest-prefix-partitioned, sorted parquet. The same
files serve three interfaces at zero marginal cost:

- `hdx` resolves via 2–3 HTTP range requests per hop (row-group stats +
  bloom filters; sub-second against object storage).
- **DuckDB is the analyst interface for free** — it range-reads remote
  parquet natively; Athena/BigQuery mount the same files for heavy
  joins. We publish files existing federation layers already speak.
- A thin stateless resolver does the same two hops for web/API users.

**The mutable inventory is deliberately tiny**: a delta overlay (new
claims + cached federation answers since the last edition, one small
DuckDB/SQLite file, LSM-style: static shards are the immutable level,
the overlay is L0, editions compact it); and a TTL'd availability
scratchpad (best-effort, advisory). No database server in the serving
path until proven necessary.

**Pathologies handled at build time**: mega-clusters (empty file,
jquery.min.js, LICENSE texts) get capped, paginated cluster records
with counts instead of exhaustive posting lists; weak-digest lookups
return all matching clusters, explicitly ambiguous, never an
arbitrary winner.

## Sizing and hosting

Full estimates in SOURCES.md; the shape:

| Tier | Rows | Sorted index |
|---|---|---|
| Software artifacts | ~1–2B | ~100–300 GB |
| Source (SWH) | ~25B | ~1.5–3 TB |
| Web (static-stable policy) | ~2–5B | ~200–500 GB |

Whole index ≈ **1–3 TB**. Three levers keep it hobby-priced:

1. **Query big sources in place** — CC-index and SWH live on AWS Open
   Data (Athena, ~$5/TB scanned: the historical CC extract is tens of
   dollars of one-time query); Rekor/PyPI/deps.dev live in BigQuery
   (1 TB/month free). Egress only the compacted results.
2. **Serve static, never run a database** — digest-sorted,
   prefix-sharded files on object storage; clients resolve via HTTP
   range requests (Go-sumdb / HIBP shape). Zero query compute, and
   prefix ranges give k-anonymity for free — the query-privacy
   question answers itself. R2-class hosting: single-digit $/mo for
   the software tier, ~$50/mo all-in.
3. **Dumps ride free open-data hosting** (Internet Archive — the
   Archive Team census precedent; Hugging Face; AWS Open Data /
   Source Cooperative as the endgame). Canonical dumps on free hosts;
   the landlord serves only the compact query index.

### Where ingestion runs

Principle: move compute to the data; egress only compacted results;
nothing large ever lands on a laptop.

- **BigQuery-resident sources** (deps.dev, Rekor IndexKeys, PyPI):
  extraction queries run in BigQuery on a personal GCP account —
  digest-column extracts fit the 1 TB/month free scan tier — results
  to GCS, download only the compacted MBs–GBs (filters, inversions).
- **AWS-resident sources** (CC index, SWH, EOT): Athena in us-east-1,
  CTAS into an own-bucket in the same region (no egress yet). Dedup /
  sort / prefix-bucketing can mostly be done *in* Athena SQL; where a
  real compaction pass is needed, an **ephemeral spot instance with
  NVMe in us-east-1 running DuckDB** — hours, not a standing server.
  Pay the egress toll once, on the final compacted parquet only
  (~$90/TB → tens of dollars for most tiers), landing in R2 where
  serving egress is free.
- **Plain-HTTP long tail** (crates/RubyGems dumps, distro indexes,
  NSRL, F-Droid…): GB-scale — any box. A monthly-billed Hetzner
  workbench (~€50–80/mo, big NVMe) rented per ingest campaign; it
  builds editions and compacts the overlay, and holds nothing
  unrebuildable.
- **Arquivo.pt (12 TiB CDXJ)**: never stored — CDXJ is line-oriented,
  so it's stream-filtered during download (static-MIME cut +
  digest/URL extraction on the fly, ~10× reduction), respecting their
  rate limits. The stability policy doubles as a streaming reducer.
- **The laptop**: development, `hdx`, QA. Nothing else.

One-time ingest costs are dominated by query fees (tens of dollars)
and the single egress of compacted tiers; standing costs are the R2
shards plus a workbench only while campaigns run.

## Sociology

- Verification can be decentralized because it's cheap;
  **responsibility cannot**, because it only exists when
  concentrated. Named attestors everywhere; no anonymous-swarm
  anything.
- The index needs a landlord (or dies like its ancestors) but must
  stay forkable on short notice — content-addressed dumps are a
  design requirement, not a nice-to-have. The landlord serves cache,
  not truth.
- Don't federate trust policy; federate claims. Curation is a
  separate, competitive layer — a "distro" is exactly this; let there
  be many.
- Agents change the maintenance economics: the thankless curation
  work (probing, refreshing, crosswalk expansion) that no volunteer
  identity ever formed around can run as nightshift background labor
  needing only direction, not identity or salary.

## Why now

- SBOM regulation (CRA etc.) gives the federated lookup liability
  pull for the first time; supply-chain incidents (xz) made
  provenance lookups an incident-response primitive.
- Reproducible-builds + sigstore matured: strong claims worth
  indexing now exist (reproduce.debian.net publishes
  rebuilt-identically attestations *today*).
- The dumps exist (SOURCES.md) — the acquisition problem is largely
  already solved by parties with bigger budgets.

## MVP ladder

1. **Federated CLI** (`hdx <hash>`) — the original notes' step 1,
   resurrected with an evidence-based backend list: hash normalizer +
   adapters for deps.dev query, CIRCL, SWH, snapshot.d.o, Rekor v1
   (+ opt-in VT), merged claims view. Every answer cached locally as
   witness co-observations (sqlite/duckdb). Includes the **filter
   harvest**: CIRCL's published Bloom + digests-only BigQuery
   extracts for deps.dev/Rekor, so the fan-out is prefiltered from
   day one. Near-zero ingest. `hdx coords <file>` batch mode from day
   one: hash your own disk, map it back to the world (the
   mystery-PDF demo).
2. **Cache → evidence store + first inversions**: harden the cache
   into the durable observation store (hits never expire, co-observed
   coordinates indexed); build digest-sorted coordinate indexes from
   dumps already held (fatcat first); the live walk resolves locally
   before touching the network. The index's early shape is literally
   the demand curve.
3. **First self-inversions, gap-driven**: BigQuery extracts (Rekor
   IndexKeys, PyPI) + whichever long-tail forward-only sources
   lookups actually miss (conda, F-Droid, Homebrew, Hackage, CPAN,
   distro indexes for crosswalk edges). Static prefix-shard serving
   starts here.
4. **SWH derived dataset** (contents parquet + origins — 29B blobs ×
   4 hashes) when cluster quality demands the bulk crosswalk, and the
   **web tier** under the static-stable policy (CC via Athena,
   Arquivo.pt, EOT, Wikimedia; IA lazily or via better channels if
   they open) — the one corpus nobody has inverted for anyone.
5. **Resolver service** — the CLI's resolution chain behind a thin
   stateless HTTP API over the same shards, only if lookups prove
   wanted.

## Non-goals

- Storing content. Ever.
- A new hash format, transport, blockchain, or token.
- Replacing any existing shard — we federate them and send them
  traffic.
- Completeness. Censuses die of the census.
- Names. Zooko's triangle is somebody else's problem.

## Open questions

- Claim spam / poisoning of observation-wrapped shards: signed
  attestors + lenses help; a rate/reputation model is eventually
  needed.
- Recurrence-filter tuning for the web tier (thresholds, window).
- abuse.ch licensing ambiguity post-Spamhaus; Internet Archive
  metadata-sweep etiquette.
