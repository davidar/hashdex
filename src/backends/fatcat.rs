use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

pub const NAME: &str = "fatcat";

/// The final fatcat bulk export (2024-02-18), republished as a
/// sha256-sorted parquet dataset; fatcat.wiki itself is offline, so the
/// claim URLs are the ones that still resolve: the wayback capture of
/// the hashed bytes first, then the DOI.
const DATASET: &str = "david-ar/fatcat-files";
const FILTER_URL: &str = "https://datasets-server.huggingface.co/filter";
const SHOWN: usize = 5;

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256)
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let col = match coord.scheme {
        Scheme::Md5 => "md5",
        Scheme::Sha1 => "sha1",
        Scheme::Sha256 => "sha256",
        _ => return Ok(None),
    };
    let hex: String = coord.digest.iter().map(|b| format!("{b:02x}")).collect();
    let resp = client
        .get(FILTER_URL)
        .query(&[
            ("dataset", DATASET),
            ("config", "default"),
            ("split", "train"),
            ("where", &format!("\"{col}\"='{hex}'")),
            ("limit", "10"),
        ])
        .send()
        .await?;
    // Any non-2xx (including "the dataset index is loading") is a
    // transport failure to report, never a miss.
    let body: Value = resp.error_for_status()?.json().await?;
    let rows = body["rows"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        return Ok(None);
    }
    let total = body["num_rows_total"].as_u64().unwrap_or(rows.len() as u64);

    let mut claims: Vec<Claim> = rows.iter().take(SHOWN).map(|r| claim(&r["row"])).collect();
    if total > SHOWN as u64 {
        claims.push(Claim::new(
            format!("… and {} more releases", total - SHOWN as u64),
            None,
        ));
    }
    // The dataset row is a single witness carrying all three digests —
    // exactly the multi-hash row the edge-minting rule admits.
    let coords = ["sha1", "sha256", "md5"]
        .iter()
        .filter_map(|s| {
            let hex = rows[0]["row"][*s].as_str()?;
            Some(format!("{s}:{hex}"))
        })
        .collect();
    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords,
    }))
}

fn claim(row: &Value) -> Claim {
    let mut statement = format!(
        "scholarly file: \"{}\"",
        row["title"].as_str().unwrap_or("(untitled)")
    );
    if let Some(year) = row["release_year"].as_i64() {
        statement.push_str(&format!(" ({year})"));
    }
    if let Some(venue) = row["container_name"].as_str() {
        statement.push_str(&format!(", {venue}"));
    }
    let doi = row["doi"].as_str();
    let arxiv = row["arxiv"].as_str();
    if let Some(doi) = doi {
        statement.push_str(&format!(", doi:{doi}"));
    } else if let Some(arxiv) = arxiv {
        statement.push_str(&format!(", arXiv:{arxiv}"));
    }
    let url = row["wayback_url"]
        .as_str()
        .map(str::to_string)
        .or_else(|| doi.map(|d| format!("https://doi.org/{d}")))
        .or_else(|| arxiv.map(|a| format!("https://arxiv.org/abs/{a}")));
    Claim::new(statement, url)
}
