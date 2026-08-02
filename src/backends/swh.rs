use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::Value;

pub const NAME: &str = "software-heritage";

pub fn supports(s: Scheme) -> bool {
    matches!(
        s,
        Scheme::Sha1 | Scheme::Sha256 | Scheme::Sha1Git | Scheme::Blake2s256
    )
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let url = format!(
        "https://archive.softwareheritage.org/api/1/content/{}:{}/",
        coord.scheme.as_str(),
        coord.hex()
    );
    let mut req = client.get(&url);
    // Anonymous quota is 120 req/h; a token raises it to 1200.
    if let Ok(token) = std::env::var("SWH_TOKEN") {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: Value = resp.error_for_status()?.json().await?;

    let swhid = body["swhid"].as_str().unwrap_or_default().to_string();
    let length = body["length"].as_u64().unwrap_or(0);
    let claims = vec![Claim::new(
        format!("archived source blob, {length} bytes"),
        Some(format!("https://archive.softwareheritage.org/{swhid}")),
    )];

    // SWH returns all four checksums per content: a 4-way co-observation.
    let mut coords = Vec::new();
    if let Some(checksums) = body["checksums"].as_object() {
        for (scheme, hex) in checksums {
            if let Some(hex) = hex.as_str() {
                coords.push(format!("{scheme}:{hex}"));
            }
        }
    }

    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords,
    }))
}
