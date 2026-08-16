use serde::{Deserialize, Serialize};

/// What one backend had to say about one coordinate. Serialized as-is into
/// the local cache; this is the proto-form of the witness co-observation
/// record (DESIGN.md layer 1) — formalized in the cache→ledger step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Named attestor, always shown to the user (DESIGN.md: an aggregator
    /// that hides attribution becomes the trust root it swore not to be).
    pub backend: String,
    pub claims: Vec<Claim>,
    /// Coordinates co-observed by this backend for the same bytes
    /// ("scheme:hex" strings) — free crosswalk edges.
    #[serde(default)]
    pub coords: Vec<String>,
    /// The witness's containment edge, when the statement is "an
    /// archive ships these bytes at a path" rather than "these bytes
    /// are this artifact": the claim URL fetches the ARCHIVE, not the
    /// bytes. The rendered claim keeps the human sentence; this is the
    /// machine half (recipe extract nodes consume it). NOT a
    /// co-observation — the archive digest names different bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<Archive>,
}

/// Where a witness says these bytes live inside a published archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archive {
    /// Digest scheme of the archive's own checksum (e.g. "sha256").
    pub scheme: String,
    /// The archive's checksum in lowercase hex.
    pub digest: String,
    /// Member path inside the archive, as the witness states it.
    pub path: String,
    /// Archive filename, for display and blob reporting.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub statement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Claim {
    pub fn new(statement: impl Into<String>, url: Option<String>) -> Claim {
        Claim {
            statement: statement.into(),
            url,
        }
    }
}
