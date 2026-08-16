use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::Value;

pub const NAME: &str = "circl-hashlookup";

pub fn supports(s: Scheme) -> bool {
    matches!(
        s,
        Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256 | Scheme::Sha512
    )
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let url = format!(
        "https://hashlookup.circl.lu/lookup/{}/{}",
        coord.scheme.as_str(),
        coord.hex()
    );
    let resp = client.get(&url).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: Value = resp.error_for_status()?.json().await?;
    if body.get("message").is_some() && body.get("FileName").is_none() {
        return Ok(None);
    }

    let mut claims = Vec::new();
    if let Some(name) = body["FileName"].as_str() {
        let size = body["FileSize"]
            .as_str()
            .map(|s| format!(", {s} bytes"))
            .unwrap_or_default();
        let db = body["db"]
            .as_str()
            .or_else(|| body["source"].as_str())
            .map(|d| format!(" [{d}]"))
            .unwrap_or_default();
        claims.push(Claim::new(format!("known file: {name}{size}{db}"), None));
    }
    if let Some(product) = body["ProductCode"]["ProductName"].as_str() {
        claims.push(Claim::new(format!("product: {product}"), None));
    }
    if let Some(n) = body["hashlookup:parent-total"].as_u64() {
        claims.push(Claim::new(
            format!("appears in {n} parent package(s)"),
            None,
        ));
    }
    if claims.is_empty() {
        claims.push(Claim::new("present in hashlookup corpus", None));
    }

    // CIRCL rows carry multiple digests for the same bytes: crosswalk
    // coordinates for free.
    let mut coords = Vec::new();
    for (key, scheme) in [
        ("MD5", "md5"),
        ("SHA-1", "sha1"),
        ("SHA-256", "sha256"),
        ("SHA-512", "sha512"),
    ] {
        if let Some(hex) = body[key].as_str() {
            coords.push(format!("{}:{}", scheme, hex.to_lowercase()));
        }
    }

    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords,
        archive: None,
    }))
}
