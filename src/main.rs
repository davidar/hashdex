use anyhow::Result;
use clap::{Parser, Subcommand};
use hashdex::coord::{Coord, Scheme};
use hashdex::resolve::{self, Options, Resolution};
use hashdex::{cache, coords_cmd, filter, filters_cmd, index_cmd, local_index, scan_cmd};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hdx",
    version,
    about = "Resolve any hash against the indexes the world already maintains",
    long_about = "Given a hash (hex, base32, SRI, SWHID, or scheme:hex), hdx asks the \n\
                  public inverted indexes what they know: deps.dev, CIRCL hashlookup, \n\
                  Software Heritage, snapshot.debian.org, Rekor, the fatcat scholarly \n\
                  index, and the release-tarballs index (Debian/Homebrew/Guix). \n\
                  Answers are cached locally as observations.\n\n\
                  Bare 64-hex is read as sha256 (use blake2s256:<hex> to override); \n\
                  bare 40-hex as sha1; 32-char base32 as CDX-style sha1."
)]
struct Cli {
    /// Hash to resolve (any common spelling)
    hash: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,

    /// Re-query backends even if cached
    #[arg(long, global = true)]
    refresh: bool,

    /// Skip the local cache entirely (no reads, no writes)
    #[arg(long, global = true)]
    no_cache: bool,

    /// Never touch the network: resolve from local indexes and the
    /// observation store only
    #[arg(long, global = true)]
    offline: bool,

    /// Per-backend timeout in seconds (fatcat's binary search over
    /// remote parquet pages legitimately takes ~10-20s when cold)
    #[arg(long, global = true, default_value_t = 45)]
    timeout: u64,

    /// Emit JSON instead of a table
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Compute every coordinate of local files (md5, sha1, sha256, sha512,
    /// blake2s256, git blob hash), optionally resolving them
    Coords {
        /// Files to hash
        files: Vec<PathBuf>,
        /// Also resolve the computed coordinates against the backends
        #[arg(long)]
        lookup: bool,
    },
    /// Scan directories: hash every file, check membership filters,
    /// and attribute what hdx can actually name (local indexes plus
    /// range reads over published datasets; --no-resolve for the pure
    /// membership census)
    Scan {
        /// Files or directories to scan
        paths: Vec<PathBuf>,
        /// Print per-file lines: unknown, known, or all
        /// (default: files with an attribution)
        #[arg(long, value_parser = ["unknown", "known", "all"])]
        list: Option<String>,
        /// Rehash every file even if the local index has a fresh entry
        #[arg(long)]
        rehash: bool,
        /// Membership only — the classic bloom-filter census: no
        /// resolution, no probes, fastest
        #[arg(long)]
        no_resolve: bool,
        /// Full citation blocks (URLs, several claims) instead of one
        /// compact attribution line per file
        #[arg(short, long)]
        verbose: bool,
        /// Probe every filter even for files a smaller filter already
        /// matched (full attribution; slower with bigger-than-RAM filters)
        #[arg(long)]
        probe_all: bool,
        /// Also tell third-party APIs (circl, depsdev, rekor, swh)
        /// about matched digests — dataset-transport backends like
        /// fatcat are probed by default and disclose nothing.
        /// Optionally restrict: --online=circl,swh
        #[arg(long, value_name = "BACKENDS", num_args = 0..=1,
              default_missing_value = "", require_equals = true,
              conflicts_with = "no_resolve")]
        online: Option<String>,
    },
    /// Find local files by digest (from the index hdx scan maintains)
    Locate {
        /// sha1 or sha256 hash (any common spelling)
        hash: String,
    },
    /// Manage local copies of the published claim datasets (fatcat,
    /// tarballs) — resolution range-reads them remotely by default; a
    /// pulled copy is faster and works offline
    Index {
        #[command(subcommand)]
        action: IndexAction,
    },
    /// Manage local membership filters
    Filters {
        #[command(subcommand)]
        action: FilterAction,
    },
}

#[derive(Subcommand)]
enum IndexAction {
    /// Download a dataset's published parquet for local + offline
    /// resolution (the local file IS the published file)
    Pull {
        /// Dataset name (see `hdx index list`)
        name: String,
    },
    /// List datasets and their local state
    List,
    /// Delete a dataset's local copy (resolution goes back to
    /// on-demand range reads)
    Rm {
        /// Dataset name
        name: String,
    },
}

#[derive(Subcommand)]
enum FilterAction {
    /// Download membership filters (no names: list what's available)
    Fetch {
        /// Filter names to fetch (e.g. fedora fatcat circl)
        names: Vec<String>,
        /// Fetch every published filter (except huge ones, e.g. the
        /// 70 GiB swh filter — name those explicitly)
        #[arg(long)]
        all: bool,
        /// Fetch NAME.SCHEME from an explicit URL instead of the registry
        #[arg(long, value_name = "URL")]
        from: Option<String>,
    },
    /// List installed filters
    List,
    /// Fold an installed filter to half its size by ORing the two halves
    /// of its bit array. Every key stays a member; the false-positive
    /// rate rises (roughly squaring the bits-set fraction — e.g. the
    /// 70 GiB swh filter folds to 35 GiB at ~2% FP instead of 0.01%).
    /// Re-download with `hdx filters fetch` to undo.
    Fold {
        /// Installed filter to fold: NAME, or NAME.SCHEME if ambiguous
        name: String,
    },
    /// Build a filter from files of hex digest lines (one per line)
    Build {
        /// Filter name (installs as <name>.<scheme>.bloom)
        name: String,
        /// Digest scheme the keys are in: md5, sha1, or sha256
        #[arg(value_parser = ["md5", "sha1", "sha256"])]
        scheme: String,
        /// Input files of hex digest lines
        files: Vec<PathBuf>,
        /// False-positive rate
        #[arg(long, default_value_t = 0.0001)]
        fpp: f64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let opts = Options {
        refresh: cli.refresh,
        no_cache: cli.no_cache,
        offline: cli.offline,
        timeout_secs: cli.timeout,
        only: None,
        progress: true,
    };
    let client = reqwest::Client::builder()
        .user_agent(format!("hashdex-hdx/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    match (&cli.command, &cli.hash) {
        (
            Some(Command::Scan {
                paths,
                list,
                rehash,
                no_resolve,
                verbose,
                probe_all,
                online,
            }),
            _,
        ) => {
            if paths.is_empty() {
                anyhow::bail!("hdx scan: no paths given");
            }
            if online.is_some() && cli.offline {
                eprintln!("note: --offline wins over --online; skipping network probes");
            }
            let filters = filter::load_all()?;
            if filters.is_empty() {
                eprintln!("note: no filters installed — run `hdx filters fetch` first");
            }
            let sopts = scan_cmd::ScanOptions {
                list: match list.as_deref() {
                    Some("unknown") => scan_cmd::ListMode::Unknown,
                    Some("known") => scan_cmd::ListMode::Known,
                    Some("all") => scan_cmd::ListMode::All,
                    None if !*no_resolve => scan_cmd::ListMode::Attributed,
                    _ => scan_cmd::ListMode::None,
                },
                json: cli.json,
                no_index: cli.no_cache,
                rehash: *rehash,
                resolve: !*no_resolve,
                verbose: *verbose,
                probe_all: *probe_all,
                online: match (online, cli.offline) {
                    (Some(list), false) => Some(
                        list.split(',')
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                    ),
                    _ => None,
                },
            };
            scan_cmd::scan(paths, &filters, &sopts, &client, &opts).await?;
        }
        (Some(Command::Locate { hash }), _) => {
            let coord = Coord::parse(hash)?;
            if !matches!(coord.scheme, Scheme::Sha1 | Scheme::Sha256) {
                anyhow::bail!(
                    "hdx locate: the local index keys on sha1/sha256 (got {})",
                    coord.scheme.as_str()
                );
            }
            let ix = local_index::LocalIndex::open()?;
            let hits = ix.locate(&coord.digest)?;
            if cli.json {
                for (path, size) in &hits {
                    println!("{}", serde_json::json!({"path": path, "size": size}));
                }
            } else {
                for (path, size) in &hits {
                    println!("{path} ({size} bytes)");
                }
            }
            if hits.is_empty() {
                let (n, _) = ix.stats()?;
                eprintln!(
                    "no local file with that digest ({n} files indexed; hdx scan to index more)"
                );
                std::process::exit(1);
            }
        }
        (Some(Command::Index { action }), _) => match action {
            IndexAction::Pull { name } => index_cmd::pull(&client, name).await?,
            IndexAction::List => index_cmd::list()?,
            IndexAction::Rm { name } => index_cmd::rm(name)?,
        },
        (Some(Command::Filters { action }), _) => match action {
            FilterAction::Fetch { names, all, from } => {
                filters_cmd::fetch(&client, names, *all, from.as_deref()).await?
            }
            FilterAction::List => filters_cmd::list()?,
            FilterAction::Fold { name } => filters_cmd::fold(name)?,
            FilterAction::Build {
                name,
                scheme,
                files,
                fpp,
            } => {
                if files.is_empty() {
                    anyhow::bail!("hdx filters build: no input files given");
                }
                let scheme = match scheme.as_str() {
                    "md5" => Scheme::Md5,
                    "sha1" => Scheme::Sha1,
                    _ => Scheme::Sha256,
                };
                filters_cmd::build(name, scheme, files, *fpp)?;
            }
        },
        (Some(Command::Coords { files, lookup }), _) => {
            if files.is_empty() {
                anyhow::bail!("hdx coords: no files given");
            }
            let record_cache = if cli.no_cache {
                None
            } else {
                cache::Cache::open().ok()
            };
            for path in files {
                let coords = coords_cmd::compute(path)?;
                // The six-scheme row is a witnessed co-observation of the
                // user's own bytes — the only local source of
                // sha1_git/blake2s256 crosswalk edges for the walk.
                if let Some(cache) = &record_cache {
                    coords_cmd::record(cache, path, &coords);
                }
                if cli.json {
                    let obj: serde_json::Value = serde_json::json!({
                        "file": path.display().to_string(),
                        "coords": coords.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    });
                    println!("{}", serde_json::to_string(&obj)?);
                } else {
                    println!("{}", path.display());
                    for c in &coords {
                        println!("  {:<11} {}", c.scheme.as_str(), c.hex());
                    }
                }
                if *lookup {
                    // sha256 covers every backend except the sha1-keyed
                    // snapshot farm; add sha1 for that one.
                    for c in coords
                        .iter()
                        .filter(|c| matches!(c.scheme, Scheme::Sha256 | Scheme::Sha1))
                    {
                        let res = resolve::resolve(&client, c, &opts).await?;
                        render(&res, cli.json, true);
                    }
                }
                if !cli.json {
                    println!();
                }
            }
        }
        (None, Some(hash)) => {
            let coord = Coord::parse(hash)?;
            let res = resolve::resolve(&client, &coord, &opts).await?;
            render(&res, cli.json, false);
            if res.clusters.is_empty() {
                std::process::exit(1);
            }
        }
        _ => {
            anyhow::bail!("usage: hdx <hash>  |  hdx coords <files>...  (see --help)");
        }
    }
    Ok(())
}

fn render(res: &Resolution, json: bool, nested: bool) {
    if json {
        let obj = serde_json::json!({
            "coordinate": res.coord.to_string(),
            "clusters": res.clusters.iter().map(|cl| serde_json::json!({
                "coords": cl.coords.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "findings": cl.findings,
                "primary": cl.primary,
                "anchored": cl.anchored,
            })).collect::<Vec<_>>(),
            "findings": res.clusters.iter().flat_map(|cl| cl.findings.iter()).collect::<Vec<_>>(),
            "collision": res.collision,
            "truncated": res.truncated,
            "misses": res.misses,
            "errors": res.errors.iter()
                .map(|(b, e)| serde_json::json!({"backend": b, "error": e}))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&obj).unwrap());
        return;
    }

    let indent = if nested { "  " } else { "" };
    println!("{indent}{}", res.coord);

    if res.clusters.is_empty() {
        if res.offline {
            println!("{indent}  no local results (offline — network backends not asked)");
        } else {
            println!("{indent}  no results ({} backends asked)", res.misses.len());
        }
    }
    // Only anchored clusters (ones carrying an identity-grade digest)
    // count as distinct contents. Unanchored evidence is just unwelded
    // claims about the queried digest — several backends returning
    // coords-less findings must not read as several contents.
    let distinct = res
        .clusters
        .iter()
        .filter(|c| c.primary && c.anchored)
        .count();
    if distinct > 1 {
        println!("{indent}  consistent with {distinct} distinct contents:");
    }
    if res.collision {
        println!(
            "{indent}  warning: this {} digest is claimed by contents that differ on \
             identity-grade digests (possible collision)",
            res.coord.scheme.as_str()
        );
    }

    let mut related_header = false;
    let mut content_no = 0;
    for cluster in &res.clusters {
        if !cluster.primary && !related_header {
            // Reached only through weak-digest links: worth showing,
            // never presented as evidence about the queried bytes.
            println!("{indent}  related via weak digests (not identity-verified):");
            related_header = true;
        }
        if cluster.primary && cluster.anchored && distinct > 1 {
            content_no += 1;
            println!("{indent}  content #{content_no}");
        }
        for f in &cluster.findings {
            for (i, claim) in f.claims.iter().enumerate() {
                let label = if i == 0 { f.backend.as_str() } else { "" };
                match &claim.url {
                    Some(url) => println!(
                        "{indent}  {label:<20} {}\n{indent}  {:<20} → {url}",
                        claim.statement, ""
                    ),
                    None => println!("{indent}  {label:<20} {}", claim.statement),
                }
            }
        }
        // The cluster's crosswalk view: every coordinate except the
        // queried one.
        let all: BTreeSet<String> = cluster
            .coords
            .iter()
            .map(|c| c.to_string())
            .filter(|c| *c != res.coord.to_string())
            .collect();
        if !all.is_empty() {
            println!(
                "{indent}  {:<20} {}",
                "coordinates",
                all.into_iter()
                    .collect::<Vec<_>>()
                    .join("\n                       ")
            );
        }
    }

    if res.truncated {
        println!("{indent}  (evidence truncated — mega-cluster cap hit)");
    }
    if !res.misses.is_empty() {
        println!(
            "{indent}  {:<20} {}",
            "no result from",
            res.misses.join(", ")
        );
    }
    for (backend, err) in &res.errors {
        println!("{indent}  {:<20} {backend}: {err}", "error");
    }
}
