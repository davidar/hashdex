use anyhow::{anyhow, bail, Result};
use data_encoding::{BASE32, BASE64};
use std::fmt;

/// A hash scheme. The scheme is part of the coordinate: the same digest
/// bytes under a different scheme is a different coordinate (see DESIGN.md,
/// "Hash Babel"). `Sha1Git` is the git blob object hash (preimage includes
/// the "blob <len>\0" header), not sha1 of the raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha1Git,
    Blake2s256,
}

impl Scheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Md5 => "md5",
            Scheme::Sha1 => "sha1",
            Scheme::Sha256 => "sha256",
            Scheme::Sha512 => "sha512",
            Scheme::Sha1Git => "sha1_git",
            Scheme::Blake2s256 => "blake2s256",
        }
    }

    pub fn digest_len(&self) -> usize {
        match self {
            Scheme::Md5 => 16,
            Scheme::Sha1 | Scheme::Sha1Git => 20,
            Scheme::Sha256 | Scheme::Blake2s256 => 32,
            Scheme::Sha512 => 64,
        }
    }

    fn from_prefix(s: &str) -> Option<Scheme> {
        match s.to_ascii_lowercase().as_str() {
            "md5" => Some(Scheme::Md5),
            "sha1" | "sha-1" => Some(Scheme::Sha1),
            "sha256" | "sha-256" => Some(Scheme::Sha256),
            "sha512" | "sha-512" => Some(Scheme::Sha512),
            "sha1_git" | "sha1-git" | "git" => Some(Scheme::Sha1Git),
            "blake2s256" | "blake2s" => Some(Scheme::Blake2s256),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Coord {
    pub scheme: Scheme,
    pub digest: Vec<u8>,
}

impl Coord {
    pub fn new(scheme: Scheme, digest: Vec<u8>) -> Result<Coord> {
        if digest.len() != scheme.digest_len() {
            bail!(
                "digest length {} does not match scheme {} (expected {})",
                digest.len(),
                scheme.as_str(),
                scheme.digest_len()
            );
        }
        Ok(Coord { scheme, digest })
    }

    pub fn hex(&self) -> String {
        self.digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse any reasonable hash spelling:
    ///   - "sha256:<hex>", "sha1:<hex>", "md5:<hex>", "sha1_git:<hex>", ...
    ///   - SWHID: "swh:1:cnt:<hex>" (content = git blob hash)
    ///   - SRI: "sha512-<base64>", "sha256-<base64>", "sha1-<base64>"
    ///   - bare hex, length-disambiguated: 32=md5, 40=sha1, 64=sha256, 128=sha512
    ///   - bare base32 (32 chars, A-Z2-7): CDX-style sha1
    ///
    /// Bare 64-hex is ambiguous with blake2s256; we default to sha256 —
    /// use an explicit "blake2s256:" prefix for blake2.
    pub fn parse(input: &str) -> Result<Coord> {
        let s = input.trim();

        // SWHID content id
        if let Some(rest) = s.strip_prefix("swh:1:cnt:") {
            return Coord::new(Scheme::Sha1Git, decode_hex(rest)?);
        }

        // SRI: "sha512-<b64>" etc. (contains '-' before any ':')
        if let Some((prefix, b64)) = s.split_once('-') {
            if !s.contains(':') {
                if let Some(scheme) = Scheme::from_prefix(prefix) {
                    if let Ok(bytes) = BASE64.decode(b64.as_bytes()) {
                        if bytes.len() == scheme.digest_len() {
                            return Coord::new(scheme, bytes);
                        }
                    }
                }
            }
        }

        // "scheme:hex"
        if let Some((prefix, hex)) = s.split_once(':') {
            let scheme = Scheme::from_prefix(prefix)
                .ok_or_else(|| anyhow!("unknown hash scheme prefix: {prefix}"))?;
            return Coord::new(scheme, decode_hex(hex)?);
        }

        // bare base32 sha1 (CDX convention): exactly 32 chars from A-Z2-7
        if s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
            && !s.bytes().all(|b| b.is_ascii_hexdigit())
        {
            let bytes = BASE32
                .decode(s.as_bytes())
                .map_err(|e| anyhow!("invalid base32: {e}"))?;
            return Coord::new(Scheme::Sha1, bytes);
        }

        // bare hex, by length
        let bytes = decode_hex(s)?;
        let scheme = match bytes.len() {
            16 => Scheme::Md5,
            20 => Scheme::Sha1,
            32 => Scheme::Sha256,
            64 => Scheme::Sha512,
            n => bail!("cannot infer hash scheme from {n}-byte digest; use an explicit prefix like sha256:..."),
        };
        Coord::new(scheme, bytes)
    }
}

impl fmt::Display for Coord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme.as_str(), self.hex())
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("not valid hex: {s:?}");
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forms() {
        let c = Coord::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        assert_eq!(c.scheme, Scheme::Sha256);
        let c = Coord::parse("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert_eq!(c.scheme, Scheme::Sha1);
        let c = Coord::parse("swh:1:cnt:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391").unwrap();
        assert_eq!(c.scheme, Scheme::Sha1Git);
        // CDX base32 sha1 (empty payload digest per WARC convention)
        let c = Coord::parse("3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ").unwrap();
        assert_eq!(c.scheme, Scheme::Sha1);
        assert_eq!(c.hex(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn parse_bare_hex_by_length() {
        for (hex, scheme) in [
            ("900150983cd24fb0d6963f7d28e17f72", Scheme::Md5),
            ("a9993e364706816aba3e25717850c26c9cd0d89d", Scheme::Sha1),
            (
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Scheme::Sha256,
            ),
            (
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                Scheme::Sha512,
            ),
        ] {
            let c = Coord::parse(hex).unwrap();
            assert_eq!(c.scheme, scheme, "wrong scheme inferred for {hex}");
            assert_eq!(c.hex(), hex);
        }
        // uppercase hex and surrounding whitespace are accepted
        let c = Coord::parse("  A9993E364706816ABA3E25717850C26C9CD0D89D\n").unwrap();
        assert_eq!(c.scheme, Scheme::Sha1);
        assert_eq!(c.hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn parse_scheme_prefixes() {
        // bare 64-hex defaults to sha256; the explicit prefix flips it
        let hex = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
        assert_eq!(Coord::parse(hex).unwrap().scheme, Scheme::Sha256);
        let c = Coord::parse(&format!("blake2s256:{hex}")).unwrap();
        assert_eq!(c.scheme, Scheme::Blake2s256);
        let c = Coord::parse(&format!("blake2s:{hex}")).unwrap();
        assert_eq!(c.scheme, Scheme::Blake2s256);

        // prefix aliases and case-insensitivity
        let hex = "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f";
        for prefix in ["sha1_git", "sha1-git", "git"] {
            let c = Coord::parse(&format!("{prefix}:{hex}")).unwrap();
            assert_eq!(c.scheme, Scheme::Sha1Git);
        }
        for spelling in ["SHA-256", "sha-256", "Sha256"] {
            let c = Coord::parse(&format!(
                "{spelling}:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ))
            .unwrap();
            assert_eq!(c.scheme, Scheme::Sha256);
        }
        let c = Coord::parse("md5:900150983cd24fb0d6963f7d28e17f72").unwrap();
        assert_eq!(c.scheme, Scheme::Md5);
    }

    #[test]
    fn parse_sri() {
        let c = Coord::parse("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=").unwrap();
        assert_eq!(c.scheme, Scheme::Sha256);
        assert_eq!(
            c.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let c = Coord::parse(
            "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==",
        )
        .unwrap();
        assert_eq!(c.scheme, Scheme::Sha512);
    }

    #[test]
    fn parse_rejects() {
        // unknown prefix
        assert!(Coord::parse("sha3:ba7816bf8f01cfea414140de5dae2223").is_err());
        // digest length does not match the named scheme
        assert!(Coord::parse("sha256:a9993e364706816aba3e25717850c26c9cd0d89d").is_err());
        // odd-length and non-hex input
        assert!(Coord::parse("abc").is_err());
        assert!(Coord::parse("zz993e364706816aba3e25717850c26c9cd0d89d").is_err());
        // hex of a length no scheme uses
        assert!(Coord::parse("a9993e364706816aba3e25717850c26c").is_ok()); // 32 = md5
        assert!(Coord::parse("a9993e364706816aba3e25717850c2").is_err()); // 30
        assert!(Coord::parse("").is_err());
    }

    #[test]
    fn display_roundtrip() {
        for input in [
            "sha1:a9993e364706816aba3e25717850c26c9cd0d89d",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha1_git:f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f",
            "blake2s256:508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            "md5:900150983cd24fb0d6963f7d28e17f72",
        ] {
            let c = Coord::parse(input).unwrap();
            assert_eq!(c.to_string(), input);
            let again = Coord::parse(&c.to_string()).unwrap();
            assert_eq!(again, c);
        }
    }
}
