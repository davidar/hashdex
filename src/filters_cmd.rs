use crate::filter;
use anyhow::{Context, Result};
use futures::StreamExt;
use std::io::Write;

/// One downloadable filter file. `urls` are tried in order — mirrors
/// first, canonical host as fallback — so a missing mirror degrades to
/// slow rather than broken.
struct RegistryEntry {
    name: &'static str,
    scheme: &'static str,
    urls: &'static [&'static str],
    size: &'static str,
    source: &'static str,
    /// Excluded from `--all`; must be named explicitly.
    huge: bool,
}

const HF: &str = "https://huggingface.co/datasets/david-ar";

const REGISTRY: &[RegistryEntry] = &[
    RegistryEntry {
        name: "circl",
        scheme: "sha1",
        urls: &[
            // CIRCL's own host is very slow; mirror first (CC-BY-4.0).
            "https://huggingface.co/datasets/david-ar/circl-hashlookup-mirror/resolve/main/circl.sha1.bloom",
            "https://cra.circl.lu/hashlookup/hashlookup-full.bloom",
        ],
        size: "956 MiB",
        source: "CIRCL hashlookup: NSRL, Windows, distros (CC-BY-4.0)",
        huge: false,
    },
    RegistryEntry {
        name: "fedora",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/rpm-header-blooms/resolve/main/fedora.sha256.bloom"],
        size: "16 MiB",
        source: "Fedora repo metadata: per-file RPM FILEDIGESTS",
        huge: false,
    },
    RegistryEntry {
        name: "rpmfusion",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/rpm-header-blooms/resolve/main/rpmfusion.sha256.bloom"],
        size: "188 KiB",
        source: "RPM Fusion free+nonfree per-file digests",
        huge: false,
    },
    RegistryEntry {
        name: "vscode",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/rpm-header-blooms/resolve/main/vscode.sha256.bloom"],
        size: "288 KiB",
        source: "Microsoft VS Code yum repo per-file digests",
        huge: false,
    },
    RegistryEntry {
        name: "fatcat",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/fatcat-file-bloom/resolve/main/fatcat.sha1.bloom"],
        size: "279 MiB",
        source: "IA fatcat: 122M scholarly-file hashes (CC0)",
        huge: false,
    },
    RegistryEntry {
        name: "fatcat",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/fatcat-file-bloom/resolve/main/fatcat.sha256.bloom"],
        size: "279 MiB",
        source: "IA fatcat: 122M scholarly-file hashes (CC0)",
        huge: false,
    },
    RegistryEntry {
        name: "depsdev",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/depsdev-bloom/resolve/main/depsdev.sha1.bloom"],
        size: "395 MiB",
        source: "deps.dev package-file hashes (CC-BY-4.0)",
        huge: false,
    },
    RegistryEntry {
        name: "depsdev",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/depsdev-bloom/resolve/main/depsdev.sha256.bloom"],
        size: "395 MiB",
        source: "deps.dev package-file hashes (CC-BY-4.0)",
        huge: false,
    },
    RegistryEntry {
        name: "rekor",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/rekor-bloom/resolve/main/rekor.sha256.bloom"],
        size: "19 MiB",
        source: "Sigstore Rekor transparency-log subject digests",
        huge: false,
    },
    RegistryEntry {
        name: "cc",
        scheme: "sha1",
        urls: &["https://huggingface.co/datasets/david-ar/cc-document-bloom/resolve/main/cc.sha1.bloom"],
        size: "71 MiB",
        source: "Common Crawl document payload digests",
        huge: false,
    },
    RegistryEntry {
        name: "swh",
        scheme: "sha256",
        urls: &["https://huggingface.co/datasets/david-ar/swh-content-bloom/resolve/main/2026-06-04/swh.sha256.bloom"],
        size: "70 GiB",
        source: "Software Heritage: 29.3B archived file contents (CC-BY-4.0)",
        huge: true,
    },
];

/// Download membership filters into the cache dir. With no names, list
/// what's available. `--all` fetches everything except entries marked
/// huge (the 70 GiB SWH filter must be asked for by name). `--from`
/// fetches one name.scheme from an explicit URL instead of the registry.
pub async fn fetch(
    client: &reqwest::Client,
    names: &[String],
    all: bool,
    from: Option<&str>,
) -> Result<()> {
    let _ = HF; // referenced by docs; keeps the base URL greppable
    if let Some(url) = from {
        let [spec]: &[String; 1] = names
            .try_into()
            .map_err(|_| anyhow::anyhow!("--from needs exactly one NAME.SCHEME argument"))?;
        let (name, scheme) = spec
            .split_once('.')
            .context("--from target must be NAME.SCHEME, e.g. fedora.sha256")?;
        return fetch_one(client, name, scheme, &[url]).await;
    }
    if names.is_empty() && !all {
        println!("available filters (hdx filters fetch <name>... | --all):");
        for e in REGISTRY {
            println!(
                "  {:<10} {:<7} {:>8}  {}",
                e.name, e.scheme, e.size, e.source
            );
        }
        return Ok(());
    }
    let wanted: Vec<&RegistryEntry> = if all {
        REGISTRY
            .iter()
            .filter(|e| !e.huge || names.iter().any(|n| n == e.name))
            .collect()
    } else {
        let unknown: Vec<&String> = names
            .iter()
            .filter(|n| !REGISTRY.iter().any(|e| e.name == n.as_str()))
            .collect();
        if !unknown.is_empty() {
            anyhow::bail!(
                "unknown filter name(s): {} (run `hdx filters fetch` to list)",
                unknown
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        REGISTRY
            .iter()
            .filter(|e| names.iter().any(|n| n == e.name))
            .collect()
    };
    for e in &wanted {
        fetch_one(client, e.name, e.scheme, e.urls).await?;
    }
    Ok(())
}

async fn fetch_one(
    client: &reqwest::Client,
    name: &str,
    scheme: &str,
    urls: &[&str],
) -> Result<()> {
    let dir = filter::filters_dir();
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(format!("{name}.{scheme}.bloom"));
    if dest.exists() {
        eprintln!(
            "already installed: {} (delete to re-download)",
            dest.display()
        );
        return Ok(());
    }
    let part = dir.join(format!("{name}.{scheme}.bloom.part"));

    let mut last_err = None;
    for (i, url) in urls.iter().enumerate() {
        eprintln!("downloading {url}");
        // A bad mirror must not install garbage: parse the DCSO header
        // and bit-array length before accepting the file.
        let result = match download(client, url, &part).await {
            Ok(()) => filter::Bloom::open(&part)
                .map(|_| ())
                .context("downloaded file is not a valid bloom filter"),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                std::fs::rename(&part, &dest).context("finalize download")?;
                eprintln!("installed {}", dest.display());
                return Ok(());
            }
            Err(e) => {
                let _ = std::fs::remove_file(&part);
                if i + 1 < urls.len() {
                    eprintln!("  source failed ({e}); trying next");
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no sources for {name}.{scheme}")))
}

async fn download(client: &reqwest::Client, url: &str, part: &std::path::Path) -> Result<()> {
    let resp = client.get(url).send().await?.error_for_status()?;
    let total = resp.content_length().unwrap_or(0);
    let mut file = std::fs::File::create(part)?;
    let mut stream = resp.bytes_stream();
    let mut got: u64 = 0;
    let mut last_report: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)?;
        got += chunk.len() as u64;
        if got - last_report > 100 * 1024 * 1024 {
            last_report = got;
            if total > 0 {
                eprintln!("  {} / {} MiB", got >> 20, total >> 20);
            } else {
                eprintln!("  {} MiB", got >> 20);
            }
        }
    }
    file.flush()?;
    Ok(())
}

/// Build a `<name>.<scheme>.bloom` filter from files of hex digest lines
/// (one digest per line; blank lines and case ignored on input).
///
/// Key convention must match what `hdx scan` feeds `Bloom::check`:
/// sha1 keys are UPPERCASE hex (CIRCL's convention), everything else
/// lowercase hex.
pub fn build(
    name: &str,
    scheme: crate::coord::Scheme,
    inputs: &[std::path::PathBuf],
    fpp: f64,
) -> Result<()> {
    use crate::coord::Scheme;
    use std::io::BufRead;

    let hex_len = match scheme {
        Scheme::Md5 => 32,
        Scheme::Sha1 => 40,
        Scheme::Sha256 => 64,
        other => anyhow::bail!("filters build: unsupported scheme {}", other.as_str()),
    };
    let uppercase = matches!(scheme, Scheme::Sha1);

    // Pass 1: count valid lines so the filter can be sized.
    let mut n: u64 = 0;
    for path in inputs {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        for line in std::io::BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.len() == hex_len && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                n += 1;
            } else if !t.is_empty() {
                anyhow::bail!(
                    "{}: line {t:?} is not a {hex_len}-char hex digest",
                    path.display()
                );
            }
        }
    }
    if n == 0 {
        anyhow::bail!("filters build: no digests found in input");
    }

    let mut builder = crate::filter::BloomBuilder::new(n, fpp)?;
    eprintln!(
        "building {name}.{}.bloom: {n} keys, p={fpp}, {} MiB",
        scheme.as_str(),
        builder.size_bytes() >> 20
    );

    // Pass 2: insert.
    let mut done: u64 = 0;
    for path in inputs {
        let f = std::fs::File::open(path)?;
        for line in std::io::BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let key = if uppercase {
                t.to_ascii_uppercase()
            } else {
                t.to_ascii_lowercase()
            };
            builder.add(key.as_bytes());
            done += 1;
            if done.is_multiple_of(50_000_000) {
                eprintln!("  … {done}/{n}");
            }
        }
    }

    let dir = filter::filters_dir();
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(format!("{name}.{}.bloom", scheme.as_str()));
    builder.write(&dest)?;
    eprintln!("installed {}", dest.display());
    Ok(())
}

/// Fold an installed filter to half its size (see `filter::fold`).
/// Replaces the file; the original is re-downloadable via fetch.
pub fn fold(spec: &str) -> Result<()> {
    let filters = filter::load_all()?;
    let matched: Vec<_> = filters
        .iter()
        .filter(|f| f.name == spec || format!("{}.{}", f.name, f.scheme.as_str()) == spec)
        .collect();
    let f = match matched.as_slice() {
        [] => anyhow::bail!("no installed filter named {spec:?} (run `hdx filters list`)"),
        [f] => f,
        many => anyhow::bail!(
            "ambiguous: {spec} has {} installed filters — name one as NAME.SCHEME ({})",
            many.len(),
            many.iter()
                .map(|f| format!("{}.{}", f.name, f.scheme.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let fname = format!("{}.{}.bloom", f.name, f.scheme.as_str());
    let path = filter::filters_dir().join(&fname);
    let part = filter::filters_dir().join(format!("{fname}.fold.part"));
    let old_bytes = f.bytes;
    eprintln!(
        "folding {fname}: {} → ~{} (false positives rise; refetch to undo)…",
        human(old_bytes),
        human(crate::filter::HEADER_LEN as u64 + (old_bytes.saturating_sub(48)) / 2),
    );
    drop(filters); // release the mmap on the file we're about to replace
    let stats = filter::fold(&path, &part)?;
    std::fs::rename(&part, &path).context("finalize folded filter")?;
    let new_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "folded {fname}: {} → {} bits, {} → {}, fill {:.1}%, false-positive rate now ~{:.1e}",
        stats.m_old,
        stats.m_new,
        human(old_bytes),
        human(new_bytes),
        stats.fill * 100.0,
        stats.p_new
    );
    Ok(())
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

pub fn list() -> Result<()> {
    let filters = filter::load_all()?;
    if filters.is_empty() {
        println!(
            "no filters installed in {} — run `hdx filters fetch`",
            filter::filters_dir().display()
        );
        return Ok(());
    }
    for f in &filters {
        println!(
            "{:<12} keyed on {:<7} ~{} entries",
            f.name,
            f.scheme.as_str(),
            f.bloom.n_elements
        );
    }
    Ok(())
}
