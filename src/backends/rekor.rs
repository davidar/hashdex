use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};

pub const NAME: &str = "rekor";

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Sha1 | Scheme::Sha256 | Scheme::Sha512)
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let hex = coord.hex();
    let resp = client
        .post("https://rekor.sigstore.dev/api/v1/index/retrieve")
        .json(&json!({ "hash": format!("{}:{}", coord.scheme.as_str(), hex) }))
        .send()
        .await?
        .error_for_status()?;
    let body: Value = resp.json().await?;
    let uuids = body.as_array().cloned().unwrap_or_default();
    if uuids.is_empty() {
        return Ok(None);
    }
    let n = uuids.len();
    let claims = vec![Claim::new(
        format!(
            "{n} signing event{} in the transparency log",
            if n == 1 { "" } else { "s" }
        ),
        Some(format!("https://search.sigstore.dev/?hash={hex}")),
    )];
    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords: vec![],
        archive: None,
    }))
}
