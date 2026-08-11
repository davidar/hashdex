use crate::coord::Scheme;
use crate::dcso::{self, Header, HEADER_LEN};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// mmap-backed reader for DCSO/hashlookup bloom filters (the format
/// CIRCL publishes hashlookup-full.bloom in). Format and membership
/// hashing live in [`crate::dcso`].
pub struct Bloom {
    k: u64,
    m: u64,
    mmap: memmap2::Mmap,
    pub n_elements: u64,
}

impl Bloom {
    pub fn open(path: &Path) -> Result<Bloom> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open bloom filter {}", path.display()))?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        // Probe positions are uniformly random by construction; default
        // readahead turns every 8-byte probe into a ~128 KiB read and
        // saturates the disk on filters bigger than RAM (the 70 GB SWH
        // filter made scans ~200x slower without this).
        let _ = mmap.advise(memmap2::Advice::Random);
        let h = Header::parse(&mmap, &path.display().to_string())?;
        if mmap.len() < HEADER_LEN + h.bits_len() {
            bail!(
                "bloom filter truncated: header says {} bits but file has {} bytes",
                h.m,
                mmap.len()
            );
        }
        Ok(Bloom {
            k: h.k,
            m: h.m,
            mmap,
            n_elements: h.n_elements,
        })
    }

    pub fn check(&self, value: &[u8]) -> bool {
        dcso::check_with(value, self.k, self.m, |off| {
            let off = off as usize;
            u64::from_le_bytes(self.mmap[off..off + 8].try_into().unwrap())
        })
    }
}

/// In-memory bloom filter under construction, written out in the same
/// DCSO format `Bloom::open` reads. Same hashing as `Bloom::check` —
/// keys inserted here are found there, bit-for-bit.
pub struct BloomBuilder {
    k: u64,
    m: u64,
    n_capacity: u64,
    p: f64,
    n_elements: u64,
    bits: Vec<u64>,
}

impl BloomBuilder {
    /// Size for `n` expected elements at false-positive rate `p`.
    pub fn new(n: u64, p: f64) -> Result<BloomBuilder> {
        let (m, k) = dcso::size_for(n, p)?;
        let words = m.div_ceil(64) as usize;
        Ok(BloomBuilder {
            k,
            m,
            n_capacity: n,
            p,
            n_elements: 0,
            bits: vec![0u64; words],
        })
    }

    pub fn add(&mut self, value: &[u8]) {
        for bit in dcso::bit_positions(value, self.k, self.m) {
            self.bits[(bit >> 6) as usize] |= 1u64 << (bit & 63);
        }
        self.n_elements += 1;
    }

    pub fn size_bytes(&self) -> usize {
        HEADER_LEN + self.bits.len() * 8
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let file = std::fs::File::create(path)
            .with_context(|| format!("create bloom filter {}", path.display()))?;
        let mut w = std::io::BufWriter::new(file);
        let header = Header {
            version: 1,
            n_capacity: self.n_capacity,
            p: self.p,
            k: self.k,
            m: self.m,
            n_elements: self.n_elements,
        };
        w.write_all(&header.to_bytes())?;
        for word in &self.bits {
            w.write_all(&word.to_le_bytes())?;
        }
        w.flush()?;
        Ok(())
    }
}

pub struct FoldStats {
    pub m_old: u64,
    pub m_new: u64,
    pub fill: f64,
    pub p_new: f64,
}

/// Halve a DCSO bloom filter in place-ish: OR the second half of the bit
/// array onto the first and halve `m` in the header. Sound because the
/// probe position is `h % m`, and for even m, `h % m ≡ h % (m/2)  (mod
/// m/2)` — every key inserted in the original is still found in the fold.
/// The price is a denser array: fill fraction f becomes ~1-(1-f)², so
/// the false-positive rate goes from f^k to roughly (2f)^k. The header's
/// p field is rewritten to the honest measured value, `fill^k`.
///
/// Streams src → dst (two sequential cursors over the mmap); never holds
/// the array in RAM.
pub fn fold(src: &Path, dst: &Path) -> Result<FoldStats> {
    use std::io::{Seek, SeekFrom, Write};

    let file =
        std::fs::File::open(src).with_context(|| format!("open bloom filter {}", src.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let _ = mmap.advise(memmap2::Advice::Sequential);
    let h = Header::parse(&mmap, &src.display().to_string())?;
    let (n, k, m, n_elements) = (h.n_capacity, h.k, h.m, h.n_elements);
    if m % 2 != 0 {
        bail!(
            "cannot fold: bit count m={m} is odd (folding needs the new size to divide the old; \
             this filter has already been folded or was built with an odd m)"
        );
    }
    let words_total = m.div_ceil(64) as usize;
    if mmap.len() < HEADER_LEN + words_total * 8 {
        bail!("bloom filter truncated: {}", src.display());
    }
    // Word i of the source bit array; out-of-range and tail bits beyond
    // m read as zero so trailing file data can't leak into the fold.
    let word = |i: usize| -> u64 {
        if i >= words_total {
            return 0;
        }
        let off = HEADER_LEN + i * 8;
        let mut w = u64::from_le_bytes(mmap[off..off + 8].try_into().unwrap());
        if i == words_total - 1 && m % 64 != 0 {
            w &= (1u64 << (m % 64)) - 1;
        }
        w
    };

    let m2 = m / 2;
    let words2 = m2.div_ceil(64) as usize;
    let out = std::fs::File::create(dst)
        .with_context(|| format!("create folded filter {}", dst.display()))?;
    let mut w = std::io::BufWriter::new(out);
    // Header placeholder; p is patched after the fill count is known.
    w.write_all(
        &Header {
            version: 1,
            n_capacity: n,
            p: 0.0,
            k,
            m: m2,
            n_elements,
        }
        .to_bytes(),
    )?;
    let mut ones: u64 = 0;
    for j in 0..words2 {
        // New bit i = old bit i | old bit i+m2. The low word is src word
        // j verbatim; the high word is 64 bits at bit offset m2 + 64j.
        let o = m2 + 64 * j as u64;
        let (wi, sh) = ((o / 64) as usize, (o % 64) as u32);
        let hi = if sh == 0 {
            word(wi)
        } else {
            (word(wi) >> sh) | (word(wi + 1) << (64 - sh))
        };
        let mut d = word(j) | hi;
        if j == words2 - 1 && m2 % 64 != 0 {
            d &= (1u64 << (m2 % 64)) - 1;
        }
        ones += d.count_ones() as u64;
        w.write_all(&d.to_le_bytes())?;
    }
    let fill = ones as f64 / m2 as f64;
    let p_new = fill.powi(k as i32);
    let mut out = w.into_inner()?;
    out.seek(SeekFrom::Start(16))?;
    out.write_all(&p_new.to_bits().to_le_bytes())?;
    out.flush()?;
    Ok(FoldStats {
        m_old: m,
        m_new: m2,
        fill,
        p_new,
    })
}

/// A named membership filter bound to the scheme it keys on.
pub struct NamedFilter {
    pub name: String,
    pub scheme: Scheme,
    pub bloom: Bloom,
    /// On-disk size; scan probes filters cheapest-first and can skip
    /// RAM-dwarfing ones once a file is already known.
    pub bytes: u64,
}

pub fn filters_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hashdex")
        .join("filters")
}

/// Load every installed filter. Convention: `<name>.<scheme>.bloom`.
pub fn load_all() -> Result<Vec<NamedFilter>> {
    let dir = filters_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        let parts: Vec<&str> = fname.split('.').collect();
        if parts.len() != 3 || parts[2] != "bloom" {
            continue;
        }
        let scheme = match parts[1] {
            "md5" => Scheme::Md5,
            "sha1" => Scheme::Sha1,
            "sha256" => Scheme::Sha256,
            _ => continue,
        };
        match Bloom::open(&path) {
            Ok(bloom) => out.push(NamedFilter {
                name: parts[0].to_string(),
                scheme,
                bloom,
                bytes: entry.metadata().map(|m| m.len()).unwrap_or(0),
            }),
            Err(e) => eprintln!("warning: skipping filter {fname}: {e}"),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_roundtrip() {
        let mut b = BloomBuilder::new(1000, 0.0001).unwrap();
        let keys: Vec<String> = (0..500).map(|i| format!("KEY{i:04}")).collect();
        for k in &keys {
            b.add(k.as_bytes());
        }
        let dir = std::env::temp_dir().join(format!("hdx-bloom-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.bloom");
        b.write(&path).unwrap();

        let bloom = Bloom::open(&path).unwrap();
        assert_eq!(bloom.n_elements, 500);
        for k in &keys {
            assert!(bloom.check(k.as_bytes()), "member {k} must be found");
        }
        let mut fp = 0;
        for i in 0..10_000 {
            if bloom.check(format!("ABSENT{i:05}").as_bytes()) {
                fp += 1;
            }
        }
        assert!(fp <= 5, "false-positive rate wildly off: {fp}/10000");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hdx-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Pins the on-disk format and the membership hashing bit-for-bit.
    /// The DCSO hashing was verified byte-exact against CIRCL's live
    /// filter (Go-semantics wrapping multiply — see module docs); if this
    /// golden digest changes, compatibility with every published filter
    /// breaks. Do not update the constant to make the test pass.
    #[test]
    fn dcso_format_golden() {
        let mut b = BloomBuilder::new(100, 0.01).unwrap();
        for key in [
            "A9993E364706816ABA3E25717850C26C9CD0D89D",
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            b.add(key.as_bytes());
        }
        let dir = tmp_dir("bloom-golden");
        let path = dir.join("g.bloom");
        b.write(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let digest: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(&bytes).into()
        };
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "593635f214df50af3fe42b41b3c86fa6ca6c79c312a66818ed748435982bc6ae",
            "DCSO filter bytes changed — this breaks compatibility with published filters"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fold_halves_and_preserves_members() {
        // n=1000, p=0.01 sizes to m=9586 (even, foldable once; the
        // half 4793 is odd, so a second fold must refuse).
        let mut b = BloomBuilder::new(1000, 0.01).unwrap();
        assert_eq!(b.m % 2, 0, "test premise: m must be even");
        let keys: Vec<String> = (0..1000).map(|i| format!("MEMBER{i:04}")).collect();
        for k in &keys {
            b.add(k.as_bytes());
        }
        let dir = tmp_dir("bloom-fold");
        let full = dir.join("full.bloom");
        b.write(&full).unwrap();

        let folded = dir.join("folded.bloom");
        let stats = fold(&full, &folded).unwrap();
        assert_eq!(stats.m_old, b.m);
        assert_eq!(stats.m_new, b.m / 2);
        assert!(stats.fill > 0.0 && stats.fill < 1.0);

        let bloom = Bloom::open(&folded).unwrap();
        assert_eq!(bloom.n_elements, 1000);
        assert_eq!(bloom.m, b.m / 2);
        for k in &keys {
            assert!(bloom.check(k.as_bytes()), "member {k} lost by fold");
        }
        // The fold trades size for false positives: the measured rate
        // must be elevated but nowhere near "everything matches".
        let fp = (0..10_000)
            .filter(|i| bloom.check(format!("ABSENT{i:05}").as_bytes()))
            .count();
        assert!(fp > 0, "fold with zero FPs at half size is implausible");
        assert!(
            fp < 5_000,
            "fold degenerated into match-everything: {fp}/10000"
        );
        // Header p was rewritten to the measured value.
        let bytes = std::fs::read(&folded).unwrap();
        let p = f64::from_bits(u64::from_le_bytes(bytes[16..24].try_into().unwrap()));
        assert!((p - stats.p_new).abs() < 1e-12);

        // Odd m refuses to fold.
        let err = match fold(&folded, &dir.join("f2.bloom")) {
            Ok(_) => panic!("folding an odd-m filter must fail"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("odd"), "unhelpful error: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn open_err(path: &Path) -> String {
        match Bloom::open(path) {
            Ok(_) => panic!("{} unexpectedly opened as a valid filter", path.display()),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn open_rejects_garbage() {
        let dir = tmp_dir("bloom-garbage");

        // too short to hold a header
        let short = dir.join("short.bloom");
        std::fs::write(&short, b"not a bloom").unwrap();
        assert!(open_err(&short).contains("too short"));

        // wrong version word
        let mut b = BloomBuilder::new(10, 0.01).unwrap();
        b.add(b"X");
        let good = dir.join("good.bloom");
        b.write(&good).unwrap();
        let mut bytes = std::fs::read(&good).unwrap();
        bytes[0] = 2;
        let badver = dir.join("badver.bloom");
        std::fs::write(&badver, &bytes).unwrap();
        assert!(open_err(&badver).contains("version"));

        // header intact but bit array cut off
        let full = std::fs::read(&good).unwrap();
        let truncated = dir.join("trunc.bloom");
        std::fs::write(&truncated, &full[..full.len() - 8]).unwrap();
        assert!(open_err(&truncated).contains("truncated"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
