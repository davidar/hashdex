//! Browser range reads. Unlike the native backend, the post-redirect
//! CDN URL is NOT memoized: HF's xet-bridge signs each URL for the
//! exact Range header of the request that earned it (the policy
//! carries `ByteRange.ExpectedHeader`), so reusing it for any other
//! range is a guaranteed 403. The browser follows the resolve
//! redirect per request instead, on a kept-alive connection.

use anyhow::{anyhow, bail, Context, Result};
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

fn js_err(v: JsValue) -> anyhow::Error {
    anyhow!("{}", v.as_string().unwrap_or_else(|| format!("{v:?}")))
}

async fn fetch_with_range(url: &str, range: &str) -> Result<web_sys::Response> {
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    let headers = web_sys::Headers::new().map_err(js_err)?;
    headers.set("Range", range).map_err(js_err)?;
    init.set_headers(&headers);
    let window = web_sys::window().context("no window")?;
    let resp = JsFuture::from(window.fetch_with_str_and_init(url, &init))
        .await
        .map_err(js_err)?;
    resp.dyn_into::<web_sys::Response>()
        .map_err(|_| anyhow!("fetch returned a non-Response"))
}

async fn body_bytes(resp: &web_sys::Response) -> Result<Vec<u8>> {
    let buf = JsFuture::from(resp.array_buffer().map_err(js_err)?)
        .await
        .map_err(js_err)?;
    Ok(js_sys::Uint8Array::new(&buf).to_vec())
}

/// GET `range` from `url`. Returns the response only if the server
/// honored the range (206) or sent the whole file (200).
async fn ranged(url: &str, range: &str) -> Result<web_sys::Response> {
    let resp = fetch_with_range(url, range).await?;
    if resp.status() != 206 && resp.status() != 200 {
        bail!("HTTP {} for {url}", resp.status());
    }
    Ok(resp)
}

/// Plain GET returning parsed JSON (for the Hub revision API).
pub async fn get_json(url: &str) -> Result<serde_json::Value> {
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    let window = web_sys::window().context("no window")?;
    let resp = JsFuture::from(window.fetch_with_str_and_init(url, &init))
        .await
        .map_err(js_err)?;
    let resp: web_sys::Response = resp
        .dyn_into()
        .map_err(|_| anyhow!("fetch returned a non-Response"))?;
    if !resp.ok() {
        bail!("HTTP {} for {url}", resp.status());
    }
    Ok(serde_json::from_slice(&body_bytes(&resp).await?)?)
}

/// Read `[start, start+length)` of `url`.
pub async fn get_range(url: &str, start: u64, length: usize) -> Result<Vec<u8>> {
    let end = start + length as u64 - 1;
    let resp = ranged(url, &format!("bytes={start}-{end}")).await?;
    let mut body = body_bytes(&resp).await?;
    if resp.status() == 200 {
        // Server ignored the range and sent the whole file.
        let s = start as usize;
        if body.len() < s + length {
            bail!("short 200 body for {url}");
        }
        body = body[s..s + length].to_vec();
    } else if body.len() < length {
        bail!("short range read for {url}: got {} of {length}", body.len());
    }
    body.truncate(length);
    Ok(body)
}

/// Read the last `n` bytes of `url`. Returns (total file length,
/// offset the returned bytes start at, bytes) — the total comes from
/// Content-Range, which is how a cold open learns the file's size in
/// the same round trip that fetches the footer.
pub async fn get_suffix(url: &str, n: usize) -> Result<(u64, u64, Vec<u8>)> {
    let resp = ranged(url, &format!("bytes=-{n}")).await?;
    let body = body_bytes(&resp).await?;
    if resp.status() == 200 {
        // Whole file, shorter than the suffix or range-blind server.
        let total = body.len() as u64;
        let start = total.saturating_sub(n as u64);
        return Ok((total, start, body[start as usize..].to_vec()));
    }
    let cr = resp
        .headers()
        .get("content-range")
        .map_err(js_err)?
        .context("206 without Content-Range")?;
    // "bytes <start>-<end>/<total>"
    let (range_part, total) = cr
        .strip_prefix("bytes ")
        .and_then(|r| r.split_once('/'))
        .with_context(|| format!("unparseable Content-Range {cr:?}"))?;
    let total: u64 = total.parse().context("Content-Range total")?;
    let start: u64 = range_part
        .split_once('-')
        .context("Content-Range start")?
        .0
        .parse()?;
    Ok((total, start, body))
}
