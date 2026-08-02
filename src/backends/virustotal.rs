use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::Value;

pub const NAME: &str = "virustotal";

/// Opt-in: only active when VT_API_KEY is set.
pub fn enabled() -> bool {
    std::env::var("VT_API_KEY").is_ok()
}

pub fn supports(s: Scheme) -> bool {
    matches!(s, Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256)
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let key = std::env::var("VT_API_KEY")?;
    let hex = coord.hex();
    let resp = client
        .get(format!("https://www.virustotal.com/api/v3/files/{hex}"))
        .header("x-apikey", key)
        .send()
        .await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: Value = resp.error_for_status()?.json().await?;
    let attrs = &body["data"]["attributes"];

    let mut claims = Vec::new();
    if let Some(name) = attrs["meaningful_name"].as_str() {
        claims.push(Claim::new(format!("known as: {name}"), None));
    }
    if let Some(desc) = attrs["type_description"].as_str() {
        claims.push(Claim::new(format!("type: {desc}"), None));
    }
    let stats = &attrs["last_analysis_stats"];
    if let (Some(mal), Some(und)) = (stats["malicious"].as_u64(), stats["undetected"].as_u64()) {
        claims.push(Claim::new(
            format!("analysis: {mal} malicious / {und} undetected"),
            Some(format!("https://www.virustotal.com/gui/file/{hex}")),
        ));
    }
    if claims.is_empty() {
        return Ok(None);
    }
    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords: vec![],
    }))
}
