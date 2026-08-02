use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::Value;

pub const NAME: &str = "snapshot.debian.org";

pub fn supports(s: Scheme) -> bool {
    // The snapshot farm is keyed by SHA-1 only.
    matches!(s, Scheme::Sha1)
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let hex = coord.hex();
    let url = format!("https://snapshot.debian.org/mr/file/{hex}/info");
    let resp = client.get(&url).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: Value = resp.error_for_status()?.json().await?;
    let results = body["result"].as_array().cloned().unwrap_or_default();
    if results.is_empty() {
        return Ok(None);
    }

    let total = results.len();
    let mut claims: Vec<Claim> = results
        .iter()
        .take(5)
        .filter_map(|r| {
            let name = r["name"].as_str()?;
            let path = r["path"].as_str()?;
            let archive = r["archive_name"].as_str().unwrap_or("debian");
            let first_seen = r["first_seen"].as_str().unwrap_or("");
            // Timestamped archive URL: the immutable coordinate that stays
            // dereferenceable after the mutable mirror moves on.
            let url =
                format!("https://snapshot.debian.org/archive/{archive}/{first_seen}{path}/{name}");
            Some(Claim::new(
                format!("{name} in {archive}{path} (first seen {first_seen})"),
                Some(url),
            ))
        })
        .collect();
    if total > 5 {
        claims.push(Claim::new(
            format!("… and {} more locations", total - 5),
            None,
        ));
    }
    claims.push(Claim::new(
        "raw bytes by hash",
        Some(format!("https://snapshot.debian.org/file/{hex}")),
    ));

    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords: vec![],
    }))
}
