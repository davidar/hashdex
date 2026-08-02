use crate::inverted;
use anyhow::Result;
use std::path::Path;

/// `hdx index build <source> <dump>`: self-invert a forward dump into
/// the flat sorted coordinate index resolution consults offline.
pub fn build(source_name: &str, input: &Path, chunk_mb: usize) -> Result<()> {
    let Some(spec) = inverted::source(source_name) else {
        anyhow::bail!(
            "unknown index source {source_name:?} (known: {})",
            inverted::SOURCES
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    inverted::build(spec, input, chunk_mb.max(1) << 20)
}

pub fn list() -> Result<()> {
    let indexes = inverted::open_all()?;
    if indexes.is_empty() {
        println!(
            "no indexes installed in {} — run `hdx index build <source> <dump>`",
            inverted::index_dir().display()
        );
        return Ok(());
    }
    for ix in &indexes {
        let schemes: Vec<&str> = ix.schemes().iter().map(|s| s.as_str()).collect();
        println!(
            "{:<12} {} rows, keyed on {}",
            ix.spec.name,
            ix.row_count(),
            schemes.join("/")
        );
    }
    Ok(())
}
