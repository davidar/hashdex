mod backends;
mod cache;
mod coord;
mod coords_cmd;
mod filter;
mod filters_cmd;
mod finding;
mod local_index;
mod resolve;
mod scan_cmd;

use anyhow::Result;
use clap::{Parser, Subcommand};
use coord::{Coord, Scheme};
use resolve::{Options, Resolution};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hdx",
    version,
    about = "Resolve any hash against the indexes the world already maintains",
    long_about = "Given a hash (hex, base32, SRI, SWHID, or scheme:hex), hdx asks the \n\
                  public inverted indexes what they know: deps.dev, CIRCL hashlookup, \n\
                  Software Heritage, snapshot.debian.org, Rekor, and (with VT_API_KEY) \n\
                  VirusTotal. Answers are cached locally as observations.\n\n\
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

    /// Per-backend timeout in seconds
    #[arg(long, global = true, default_value_t = 15)]
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
    /// Scan directories: hash every file and check membership filters
    /// locally — which of these files are publicly known bytes?
    Scan {
        /// Files or directories to scan
        paths: Vec<PathBuf>,
        /// Print per-file lines: unknown, known, or all
        #[arg(long, value_parser = ["unknown", "known", "all"])]
        list: Option<String>,
        /// Rehash every file even if the local index has a fresh entry
        #[arg(long)]
        rehash: bool,
    },
    /// Find local files by digest (from the index hdx scan maintains)
    Locate {
        /// sha1 or sha256 hash (any common spelling)
        hash: String,
    },
    /// Manage local membership filters
    Filters {
        #[command(subcommand)]
        action: FilterAction,
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
        timeout_secs: cli.timeout,
    };
    let client = reqwest::Client::builder()
        .user_agent(format!("hashdex-hdx/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    match (&cli.command, &cli.hash) {
        (Some(Command::Scan { paths, list, rehash }), _) => {
            if paths.is_empty() {
                anyhow::bail!("hdx scan: no paths given");
            }
            let filters = filter::load_all()?;
            if filters.is_empty() {
                eprintln!("note: no filters installed — run `hdx filters fetch` first");
            }
            let opts = scan_cmd::ScanOptions {
                list: match list.as_deref() {
                    Some("unknown") => scan_cmd::ListMode::Unknown,
                    Some("known") => scan_cmd::ListMode::Known,
                    Some("all") => scan_cmd::ListMode::All,
                    _ => scan_cmd::ListMode::None,
                },
                json: cli.json,
                no_index: cli.no_cache,
                rehash: *rehash,
            };
            scan_cmd::scan(paths, &filters, &opts)?;
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
                eprintln!("no local file with that digest ({n} files indexed; hdx scan to index more)");
                std::process::exit(1);
            }
        }
        (Some(Command::Filters { action }), _) => match action {
            FilterAction::Fetch { names, all, from } => {
                filters_cmd::fetch(&client, names, *all, from.as_deref()).await?
            }
            FilterAction::List => filters_cmd::list()?,
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
            for path in files {
                let coords = coords_cmd::compute(path)?;
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
            if res.findings.is_empty() {
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
            "findings": res.findings,
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

    if res.findings.is_empty() {
        println!("{indent}  no results ({} backends asked)", res.misses.len());
    }
    for f in &res.findings {
        for (i, claim) in f.claims.iter().enumerate() {
            let label = if i == 0 { f.backend.as_str() } else { "" };
            match &claim.url {
                Some(url) => println!("{indent}  {label:<20} {}\n{indent}  {:<20} → {url}", claim.statement, ""),
                None => println!("{indent}  {label:<20} {}", claim.statement),
            }
        }
    }

    // Union of co-observed coordinates across findings: the crosswalk view.
    let all: BTreeSet<String> = res
        .findings
        .iter()
        .flat_map(|f| f.coords.iter().cloned())
        .filter(|c| *c != res.coord.to_string())
        .collect();
    if !all.is_empty() {
        println!("{indent}  {:<20} {}", "coordinates", all.into_iter().collect::<Vec<_>>().join("\n                       "));
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
