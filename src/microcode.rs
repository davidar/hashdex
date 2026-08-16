//! Microcode archives — the `GenuineIntel.bin` and `AuthenticAMD.bin`
//! blobs a boot image's early cpio carries. Nobody publishes the
//! concatenation, so no index names one; everybody publishes the
//! pieces. The file is a bare run of self-delimiting entries with no
//! table of contents, so this reader hands back the entry boundaries
//! and nothing else.
//!
//! Which runs of consecutive entries were packaged as one published
//! file is NOT recoverable from the headers. Intel's extended
//! signature table lets one update serve several CPUs, so entries that
//! share a processor signature can still ship in different files (in
//! Fedora's blob, three entries carry signature 0x000806f8 and package
//! as `06-8f-07` and `06-8f-08`). The index knows the boundaries; the
//! header cannot tell you them. Callers search runs against the index
//! rather than modelling the packaging.

/// Whose layout a blob follows.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Vendor {
    Intel,
    Amd,
}

impl Vendor {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Vendor::Intel => "GenuineIntel",
            Vendor::Amd => "AuthenticAMD",
        }
    }
}

/// A blob with more entries than this is not one of these archives —
/// refusing keeps the caller's per-entry index probes bounded.
const MAX_ENTRIES: usize = 8192;

/// An Intel update is at most this big; the field is a u32 and a wrong
/// stride would otherwise "tile" a file in one absurd step.
const MAX_INTEL_ENTRY: u64 = 32 << 20;

const AMD_MAGIC: &[u8; 4] = b"DMA\0";

/// Whether these leading bytes could start a microcode archive —
/// cheap enough to run over every member before reading one whole.
pub(crate) fn looks_like(head: &[u8]) -> bool {
    head.starts_with(AMD_MAGIC) || intel_header(head, 0).is_some()
}

/// Entry boundaries as `(offset, len)`, in file order.
///
/// `None` unless the entries tile `bytes` exactly: a partial parse is
/// how a wrong stride becomes a wrong recipe, and a file that only
/// half-parses was never one of these archives.
pub(crate) fn split(bytes: &[u8]) -> Option<(Vendor, Vec<(u64, u64)>)> {
    let vendor = if bytes.starts_with(AMD_MAGIC) {
        Vendor::Amd
    } else if intel_header(bytes, 0).is_some() {
        Vendor::Intel
    } else {
        return None;
    };
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if out.len() >= MAX_ENTRIES {
            return None;
        }
        let len = match vendor {
            Vendor::Intel => intel_entry(bytes, pos)?,
            Vendor::Amd => amd_container(bytes, pos)?,
        };
        out.push((pos as u64, len));
        pos += len as usize;
    }
    (pos == bytes.len() && !out.is_empty()).then_some((vendor, out))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}

/// The total size an Intel header at `at` states, when the 48 bytes
/// there are one this reader is willing to believe: header and loader
/// revision 1, a BCD date, a one-byte processor-flags mask, and a
/// total size that is 1 KiB-aligned and holds the stated payload.
fn intel_header(b: &[u8], at: usize) -> Option<u64> {
    let h = b.get(at..at.checked_add(48)?)?;
    if u32_at(h, 0) != 1 || u32_at(h, 20) != 1 || u32_at(h, 24) > 0xff || !bcd_date(u32_at(h, 8)) {
        return None;
    }
    // Zero means the original fixed sizing: 2000 bytes of payload in a
    // 2048-byte entry.
    let data = match u32_at(h, 28) {
        0 => 2000,
        d => d as u64,
    };
    let total = match u32_at(h, 32) {
        0 => 2048,
        t => t as u64,
    };
    (total % 1024 == 0 && total <= MAX_INTEL_ENTRY && data + 48 <= total).then_some(total)
}

/// The same, once the entry must also fit in what is left of the blob.
fn intel_entry(b: &[u8], at: usize) -> Option<u64> {
    intel_header(b, at).filter(|&total| at as u64 + total <= b.len() as u64)
}

/// mmddyyyy in BCD, as Intel writes it.
fn bcd_date(d: u32) -> bool {
    let (month, day, year) = (d >> 24, (d >> 16) & 0xff, d & 0xffff);
    let bcd = |v: u32| (0..8).all(|i| (v >> (4 * i)) & 0xf <= 9);
    bcd(d)
        && (0x01..=0x12).contains(&month)
        && (0x01..=0x31).contains(&day)
        && (0x1990..=0x2099).contains(&year)
}

/// The length of the AMD container starting at `at`: the magic, then
/// type/size sections (0 = equivalence table, 1 = patch) until the
/// next container's magic or the end of the blob.
fn amd_container(b: &[u8], at: usize) -> Option<u64> {
    if !b[at..].starts_with(AMD_MAGIC) {
        return None;
    }
    let mut pos = at + 4;
    while pos < b.len() && !b[pos..].starts_with(AMD_MAGIC) {
        let h = b.get(pos..pos.checked_add(8)?)?;
        if u32_at(h, 0) > 1 {
            return None;
        }
        pos = pos.checked_add(8)?.checked_add(u32_at(h, 4) as usize)?;
        if pos > b.len() {
            return None;
        }
    }
    Some((pos - at) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal Intel header: `total` bytes, `total - 48` of payload.
    fn intel(total: usize, sig: u32) -> Vec<u8> {
        let mut e = vec![0u8; total];
        e[0..4].copy_from_slice(&1u32.to_le_bytes()); // header version
        e[8..12].copy_from_slice(&0x0610_1998u32.to_le_bytes()); // 06/10/1998
        e[12..16].copy_from_slice(&sig.to_le_bytes());
        e[20..24].copy_from_slice(&1u32.to_le_bytes()); // loader revision
        e[24] = 1; // processor flags
        e[28..32].copy_from_slice(&((total - 48) as u32).to_le_bytes());
        e[32..36].copy_from_slice(&(total as u32).to_le_bytes());
        for (i, b) in e[48..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        e
    }

    fn amd(sections: &[(u32, usize)]) -> Vec<u8> {
        let mut c = AMD_MAGIC.to_vec();
        for &(ty, size) in sections {
            c.extend_from_slice(&ty.to_le_bytes());
            c.extend_from_slice(&(size as u32).to_le_bytes());
            c.extend(std::iter::repeat_n(0xA5u8, size));
        }
        c
    }

    /// total_size is the stride, and zero means the original 2048.
    #[test]
    fn intel_entries_tile_by_total_size() {
        let mut blob = intel(2048, 0x0000_0650);
        blob[32..36].fill(0); // total_size 0 ⇒ 2048
        blob[28..32].fill(0); // data_size 0 ⇒ 2000
        blob.extend(intel(4096, 0x0000_0651));
        blob.extend(intel(2048, 0x0000_0652));
        let (vendor, entries) = split(&blob).expect("three entries");
        assert_eq!(vendor, Vendor::Intel);
        assert_eq!(entries, vec![(0, 2048), (2048, 4096), (6144, 2048)]);
        assert!(looks_like(&blob[..48]));
    }

    /// Anything that does not tile the blob exactly is refused: a
    /// partial parse is a wrong recipe waiting to happen.
    #[test]
    fn a_partial_parse_is_no_parse() {
        let mut blob = intel(2048, 0x0000_0650);
        blob.extend_from_slice(&[0xFFu8; 300]);
        assert!(split(&blob).is_none(), "trailing bytes are not an entry");

        let mut short = intel(4096, 0x0000_0650);
        short.truncate(3000);
        assert!(split(&short).is_none(), "entry runs past the end");

        let mut bad = intel(2048, 0x0000_0650);
        bad[32..36].copy_from_slice(&2000u32.to_le_bytes()); // unaligned
        assert!(split(&bad).is_none());

        assert!(split(&vec![0u8; 4096]).is_none(), "zeros are not entries");
        assert!(!looks_like(&[1, 0, 0, 0, 0, 0, 0, 0]));
    }

    /// Referee against real blobs, which are far too big to commit:
    /// `HDX_UCODE=a.bin,b.bin cargo test -- --ignored real_microcode`.
    #[test]
    #[ignore]
    fn real_microcode_archives_split() {
        for path in std::env::var("HDX_UCODE").expect("HDX_UCODE").split(',') {
            let bytes = std::fs::read(path).expect("read blob");
            let (vendor, entries) = split(&bytes).expect("splits");
            let covered: u64 = entries.iter().map(|e| e.1).sum();
            assert_eq!(covered, bytes.len() as u64);
            println!(
                "{path}: {} {} entries, {} bytes",
                vendor.name(),
                entries.len(),
                covered
            );
        }
    }

    /// AMD splits at the container magic; the sections inside one
    /// container are its own business.
    #[test]
    fn amd_splits_at_the_container_magic() {
        let mut blob = amd(&[(0, 32), (1, 96)]);
        blob.extend(amd(&[(0, 16), (1, 48), (1, 64)]));
        let first = 4 + 8 + 32 + 8 + 96;
        let (vendor, entries) = split(&blob).expect("two containers");
        assert_eq!(vendor, Vendor::Amd);
        assert_eq!(
            entries,
            vec![
                (0, first as u64),
                (first as u64, (blob.len() - first) as u64)
            ]
        );

        let mut over = amd(&[(0, 32)]);
        let n = over.len();
        over[n - 32 - 4..n - 32].copy_from_slice(&4096u32.to_le_bytes());
        assert!(split(&over).is_none(), "a section past the end is refused");
    }
}
