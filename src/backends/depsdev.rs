use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::Result;
use data_encoding::BASE64;
use reqwest::Client;
use serde_json::Value;

pub const NAME: &str = "deps.dev";

pub fn supports(s: Scheme) -> bool {
    matches!(
        s,
        Scheme::Md5 | Scheme::Sha1 | Scheme::Sha256 | Scheme::Sha512
    )
}

pub async fn lookup(client: &Client, coord: &Coord) -> Result<Option<Finding>> {
    let hash_type = match coord.scheme {
        Scheme::Md5 => "MD5",
        Scheme::Sha1 => "SHA1",
        Scheme::Sha256 => "SHA256",
        Scheme::Sha512 => "SHA512",
        _ => return Ok(None),
    };
    let resp = client
        .get("https://api.deps.dev/v3/query")
        .query(&[
            ("hash.type", hash_type),
            ("hash.value", &BASE64.encode(&coord.digest)),
        ])
        .send()
        .await?;
    // deps.dev signals "no artifact with this hash" as a 404, not an empty
    // result set.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: Value = resp.error_for_status()?.json().await?;
    let results = body["results"].as_array().cloned().unwrap_or_default();
    if results.is_empty() {
        return Ok(None);
    }
    let total = results.len();
    let mut claims: Vec<Claim> = results
        .iter()
        .take(10)
        .filter_map(|r| {
            let vk = &r["version"]["versionKey"];
            let system = vk["system"].as_str()?;
            let name = vk["name"].as_str()?;
            let version = vk["version"].as_str()?;
            let published = r["version"]["publishedAt"]
                .as_str()
                .map(|p| format!(", published {}", &p[..10.min(p.len())]))
                .unwrap_or_default();
            Some(Claim::new(
                format!(
                    "{}: {}@{}{}",
                    system.to_lowercase(),
                    name,
                    version,
                    published
                ),
                registry_url(system, name, version),
            ))
        })
        .collect();
    if total > 10 {
        claims.push(Claim::new(
            format!("… and {} more results", total - 10),
            None,
        ));
    }
    Ok(Some(Finding {
        backend: NAME.into(),
        claims,
        coords: vec![],
    }))
}

fn registry_url(system: &str, name: &str, version: &str) -> Option<String> {
    match system {
        "CARGO" => Some(format!("https://crates.io/crates/{name}/{version}")),
        "NPM" => Some(format!("https://www.npmjs.com/package/{name}/v/{version}")),
        "PYPI" => Some(format!("https://pypi.org/project/{name}/{version}/")),
        "RUBYGEMS" => Some(format!(
            "https://rubygems.org/gems/{name}/versions/{version}"
        )),
        "NUGET" => Some(format!("https://www.nuget.org/packages/{name}/{version}")),
        "MAVEN" => name
            .split_once(':')
            .map(|(g, a)| format!("https://central.sonatype.com/artifact/{g}/{a}/{version}")),
        _ => None,
    }
}
