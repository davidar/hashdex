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
