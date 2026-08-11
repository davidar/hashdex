//! The DCSO/hashlookup bloom filter format, transport-free: header
//! codec and membership hashing. `filter::Bloom` probes local mmaps
//! with this math; a remote prober can use [`bit_location`] to turn
//! each probe into an 8-byte range read instead.
//!
//! Layout, all little-endian u64: version(=1), n (capacity), p (fpp as
//! f64 bits), k (hash count), m (bit count), N (elements), then
//! ceil(m/64) u64 words of bit array, then arbitrary trailing data.
//!
//! Membership hashing (ported from DCSO/bloom, Go semantics preserved):
//!   h = FNV-1 64(value) % M            with M = 2^64 - 87
//!   repeat k times: h = (h *wrap* g) % M,  bit = h % m
//!   with g = 18446744073709550147.
//! The multiply wraps mod 2^64 before the % M, because that is what Go's
//! uint64 arithmetic does in the reference implementation. This was
//! verified byte-exact against CIRCL's live filter; do not "fix" it.
//!
//! CIRCL inserts SHA-1 digests as UPPERCASE HEX STRINGS.

use anyhow::{bail, Result};

pub const HEADER_LEN: usize = 48;
const MOD: u64 = 18_446_744_073_709_551_529; // 2^64 - 87
const G: u64 = 18_446_744_073_709_550_147;

/// The six-word DCSO header.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Header {
    pub version: u64,
    pub n_capacity: u64,
    pub p: f64,
    pub k: u64,
    pub m: u64,
    pub n_elements: u64,
}

impl Header {
    /// Parse and validate the leading [`HEADER_LEN`] bytes of a filter.
    /// `what` names the filter in errors (a path, a URL).
    pub fn parse(bytes: &[u8], what: &str) -> Result<Header> {
        if bytes.len() < HEADER_LEN {
            bail!("bloom filter too short: {what}");
        }
        let u64_at =
            |i: usize| -> u64 { u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()) };
        let version = u64_at(0);
        if version & 0xff != 1 {
            bail!("unsupported bloom filter version {version}");
        }
        Ok(Header {
            version,
            n_capacity: u64_at(1),
            p: f64::from_bits(u64_at(2)),
            k: u64_at(3),
            m: u64_at(4),
            n_elements: u64_at(5),
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        for (i, v) in [
            self.version,
            self.n_capacity,
            self.p.to_bits(),
            self.k,
            self.m,
            self.n_elements,
        ]
        .into_iter()
        .enumerate()
        {
            out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Bytes of bit array the header promises after itself.
    pub fn bits_len(&self) -> usize {
        self.m.div_ceil(64) as usize * 8
    }
}

pub fn fnv1_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h = h.wrapping_mul(0x100000001b3);
        h ^= b as u64;
    }
    h
}

/// The k bit positions a key probes, in probe order.
pub fn bit_positions(value: &[u8], k: u64, m: u64) -> impl Iterator<Item = u64> {
    let mut h = fnv1_64(value) % MOD;
    (0..k).map(move |_| {
        h = h.wrapping_mul(G) % MOD;
        h % m
    })
}

/// Where bit `bit` lives: the byte offset of its little-endian u64 word
/// from the start of the file, and the mask to test within that word.
pub fn bit_location(bit: u64) -> (u64, u64) {
    (HEADER_LEN as u64 + (bit >> 6) * 8, 1u64 << (bit & 63))
}

/// Membership test over any word-lookup function (an mmap, a byte
/// slice, a range-read cache): `word_at` receives a byte offset from
/// the start of the file and returns the little-endian u64 there.
pub fn check_with(value: &[u8], k: u64, m: u64, mut word_at: impl FnMut(u64) -> u64) -> bool {
    for bit in bit_positions(value, k, m) {
        let (off, mask) = bit_location(bit);
        if word_at(off) & mask == 0 {
            return false;
        }
    }
    true
}

/// m and k sized for `n` expected elements at false-positive rate `p`,
/// matching the DCSO reference sizing.
pub fn size_for(n: u64, p: f64) -> Result<(u64, u64)> {
    if n == 0 || !(p > 0.0 && p < 1.0) {
        bail!("bloom: need n > 0 and 0 < p < 1 (got n={n}, p={p})");
    }
    let ln2 = std::f64::consts::LN_2;
    let m = ((n as f64) * (-p.ln()) / (ln2 * ln2)).ceil() as u64;
    let k = ((m as f64 / n as f64) * ln2).round().max(1.0) as u64;
    Ok((m, k))
}
