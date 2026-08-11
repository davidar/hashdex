use crate::coord::{Coord, Scheme};
use crate::finding::{Claim, Finding};
use anyhow::{bail, Context, Result};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

/// Per-source inverted coordinate index: the self-inverted shard of a
/// forward-only dump (DESIGN.md resolution level 1). Flat sorted
/// fixed-width files, mmap + binary search — same aesthetic as the
/// bloom reader, and trivially convertible to published parquet.
///
/// Files per source in `~/.cache/hashdex/index/`:
///   `<name>.rows`          witness rows sorted by the primary digest
///   `<name>.<scheme>.idx`  (digest ‖ row_no u64 LE) sorted, for the
///                          other digests each row carries
///
/// Header (32 bytes, little-endian):
///   0..4  magic "HDXI"     4 version(=1)  5 kind(1=rows,2=idx)
///   6 scheme id            8..12 row_width u32   12..20 row_count u64
///   20..24 key_offset u32  24..28 key_len u32    rest zero
const MAGIC: &[u8; 4] = b"HDXI";
const HEADER_LEN: usize = 32;
const KIND_ROWS: u8 = 1;
const KIND_IDX: u8 = 2;
/// Ceiling on rows returned per lookup — mega-key guard.
const LOOKUP_CAP: usize = 100;

fn scheme_id(s: Scheme) -> u8 {
    match s {
        Scheme::Md5 => 1,
        Scheme::Sha1 => 2,
        Scheme::Sha256 => 3,
        Scheme::Sha512 => 4,
        Scheme::Sha1Git => 5,
        Scheme::Blake2s256 => 6,
    }
}

/// How to parse, sort, and render one source's rows. The layout is part
/// of the format: bump the header version if a spec ever changes.
pub struct SourceSpec {
    pub name: &'static str,
    pub row_width: usize,
    /// (scheme, offset): the digest the rows file is sorted by.
    pub primary: (Scheme, usize),
    /// Digests that get their own `.idx` files.
    pub secondary: &'static [(Scheme, usize)],
    /// Parse one TSV line into a row buffer of `row_width` bytes.
    pub parse_line: fn(&str, &mut [u8]) -> Result<()>,
    /// Render a row as a Finding (the attestor is the source).
    pub finding: fn(&[u8]) -> Finding,
}

/// fatcat file_hashes.tsv: file_uuid, release_uuid, sha1, sha256, md5.
/// Row layout: sha1(0..20) ‖ sha256(20..52) ‖ md5(52..68) ‖
/// file_uuid(68..84) ‖ release_uuid(84..100).
const FATCAT: SourceSpec = SourceSpec {
    name: "fatcat",
    row_width: 100,
    primary: (Scheme::Sha256, 20),
    secondary: &[(Scheme::Sha1, 0), (Scheme::Md5, 52)],
    parse_line: fatcat_parse,
    finding: fatcat_finding,
};

/// Release artifacts from distro package indexes (Debian sid Sources,
/// Homebrew formulae, Guix sources.json) — tools/release_tarballs.py
/// emits the TSV: witness, sha256, md5, name, version, filename, loc
/// ("-" = absent). Row layout: sha256(0..32) ‖ md5(32..48, zeros =
/// absent) ‖ witness(48) ‖ name(49..121) ‖ version(121..177) ‖
/// filename(177..305) ‖ loc(305..497). `loc` is the Debian pool
/// directory, the Homebrew upstream URL, or the Guix content-addressed
/// mirror URL.
const TARBALLS: SourceSpec = SourceSpec {
    name: "tarballs",
    row_width: 497,
    primary: (Scheme::Sha256, 0),
    secondary: &[(Scheme::Md5, 32)],
    parse_line: tarballs_parse,
    finding: tarballs_finding,
};

pub const SOURCES: &[SourceSpec] = &[FATCAT, TARBALLS];

pub fn source(name: &str) -> Option<&'static SourceSpec> {
    SOURCES.iter().find(|s| s.name == name)
}

fn fatcat_parse(line: &str, row: &mut [u8]) -> Result<()> {
    let mut fields = line.split('\t');
    let (Some(file_uuid), Some(release_uuid), Some(sha1), Some(sha256), Some(md5)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        bail!("expected 5 tab-separated fields");
    };
    hex_into(sha1, &mut row[0..20])?;
    hex_into(sha256, &mut row[20..52])?;
    hex_into(md5, &mut row[52..68])?;
    uuid_into(file_uuid, &mut row[68..84])?;
    if release_uuid.is_empty() {
        row[84..100].fill(0);
    } else {
        uuid_into(release_uuid, &mut row[84..100])?;
    }
    Ok(())
}

fn fatcat_finding(row: &[u8]) -> Finding {
    let ident = fatcat_ident(&row[68..84]);
    let release = &row[84..100];
    let statement = if release.iter().all(|&b| b == 0) {
        format!("scholarly file file_{ident}")
    } else {
        format!(
            "scholarly file file_{ident}, release release_{}",
            fatcat_ident(release)
        )
    };
    // No URL: fatcat.wiki is offline, and the wayback/DOI identifiers
    // live in the published dataset, not in these rows — the fatcat
    // network backend supplies them. The idents remain as join keys
    // into the raw dumps.
    Finding {
        backend: "fatcat".into(),
        claims: vec![Claim::new(statement, None)],
        coords: vec![
            format!("sha1:{}", hex(&row[0..20])),
            format!("sha256:{}", hex(&row[20..52])),
            format!("md5:{}", hex(&row[52..68])),
        ],
    }
}

const TARBALLS_WITNESSES: &[&str] = &["debian", "homebrew", "guix"];

fn tarballs_parse(line: &str, row: &mut [u8]) -> Result<()> {
    let mut fields = line.split('\t');
    let (
        Some(witness),
        Some(sha256),
        Some(md5),
        Some(name),
        Some(version),
        Some(filename),
        Some(loc),
    ) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    )
    else {
        bail!("expected 7 tab-separated fields");
    };
    let Some(w) = TARBALLS_WITNESSES.iter().position(|n| *n == witness) else {
        bail!("unknown witness {witness:?}");
    };
    hex_into(sha256, &mut row[0..32])?;
    if md5 == "-" {
        row[32..48].fill(0);
    } else {
        hex_into(md5, &mut row[32..48])?;
    }
    row[48] = w as u8 + 1;
    str_into(name, &mut row[49..121])?;
    str_into(version, &mut row[121..177])?;
    str_into(filename, &mut row[177..305])?;
    str_into(loc, &mut row[305..497])?;
    Ok(())
}

fn tarballs_finding(row: &[u8]) -> Finding {
    // Same renderer as the published-parquet lookups — one voice for
    // the source, whatever the storage.
    crate::tarballs::finding(&crate::tarballs::Row {
        witness: TARBALLS_WITNESSES[(row[48] as usize).saturating_sub(1).min(2)],
        name: &str_from(&row[49..121]),
        version: &str_from(&row[121..177]),
        filename: &str_from(&row[177..305]),
        loc: &str_from(&row[305..497]),
        sha256: hex(&row[0..32]),
        md5: row[32..48]
            .iter()
            .any(|&b| b != 0)
            .then(|| hex(&row[32..48])),
    })
}

/// NUL-pad `s` into `out`; a "-" field means absent (stored empty).
fn str_into(s: &str, out: &mut [u8]) -> Result<()> {
    let s = if s == "-" { "" } else { s };
    if s.len() > out.len() {
        bail!("field over {} bytes: {s:?}", out.len());
    }
    out[..s.len()].copy_from_slice(s.as_bytes());
    out[s.len()..].fill(0);
    Ok(())
}

fn str_from(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// fatcat entity ident: lowercase unpadded base32 of the UUID bytes.
fn fatcat_ident(uuid: &[u8]) -> String {
    data_encoding::BASE32_NOPAD
        .encode(uuid)
        .to_ascii_lowercase()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_into(s: &str, out: &mut [u8]) -> Result<()> {
    if s.len() != out.len() * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("bad hex field {s:?} (want {} chars)", out.len() * 2);
    }
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(())
}

fn uuid_into(s: &str, out: &mut [u8]) -> Result<()> {
    let compact: String = s.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 {
        bail!("bad uuid field {s:?}");
    }
    hex_into(&compact, out)
}

pub fn index_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hashdex")
        .join("index")
}

// ---------------------------------------------------------------- open

struct Table {
    mmap: memmap2::Mmap,
    row_width: usize,
    row_count: u64,
    key_offset: usize,
    key_len: usize,
}

impl Table {
    fn open(path: &Path, kind: u8, scheme: Scheme) -> Result<Table> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open index file {}", path.display()))?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        // Probes are random; without this, readahead turns each probe
        // into a ~128 KiB read (same lesson as Bloom::open).
        let _ = mmap.advise(memmap2::Advice::Random);
        if mmap.len() < HEADER_LEN {
            bail!("index file too short: {}", path.display());
        }
        if &mmap[0..4] != MAGIC {
            bail!("not an hdx index file: {}", path.display());
        }
        if mmap[4] != 1 {
            bail!("unsupported index version {}: {}", mmap[4], path.display());
        }
        if mmap[5] != kind || mmap[6] != scheme_id(scheme) {
            bail!("index file kind/scheme mismatch: {}", path.display());
        }
        let row_width = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize;
        let row_count = u64::from_le_bytes(mmap[12..20].try_into().unwrap());
        let key_offset = u32::from_le_bytes(mmap[20..24].try_into().unwrap()) as usize;
        let key_len = u32::from_le_bytes(mmap[24..28].try_into().unwrap()) as usize;
        if row_width == 0
            || key_offset + key_len > row_width
            || (mmap.len() - HEADER_LEN) as u64 / row_width as u64 != row_count
            || !(mmap.len() - HEADER_LEN).is_multiple_of(row_width)
        {
            bail!("index file truncated or corrupt: {}", path.display());
        }
        Ok(Table {
            mmap,
            row_width,
            row_count,
            key_offset,
            key_len,
        })
    }

    fn row(&self, i: u64) -> &[u8] {
        let off = HEADER_LEN + (i as usize) * self.row_width;
        &self.mmap[off..off + self.row_width]
    }

    fn key(&self, i: u64) -> &[u8] {
        &self.row(i)[self.key_offset..self.key_offset + self.key_len]
    }

    /// All rows whose key equals `digest`, capped.
    fn find(&self, digest: &[u8]) -> Vec<&[u8]> {
        if digest.len() != self.key_len || self.row_count == 0 {
            return Vec::new();
        }
        // lower bound
        let (mut lo, mut hi) = (0u64, self.row_count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.key(mid) < digest {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let mut out = Vec::new();
        while lo < self.row_count && self.key(lo) == digest && out.len() < LOOKUP_CAP {
            out.push(self.row(lo));
            lo += 1;
        }
        out
    }
}

pub struct SourceIndex {
    pub spec: &'static SourceSpec,
    rows: Table,
    idx: Vec<(Scheme, Table)>,
}

impl SourceIndex {
    pub fn row_count(&self) -> u64 {
        self.rows.row_count
    }

    pub fn schemes(&self) -> Vec<Scheme> {
        let mut v = vec![self.spec.primary.0];
        v.extend(self.idx.iter().map(|(s, _)| *s));
        v
    }

    /// Witness rows for this digest, rendered as findings.
    pub fn lookup(&self, coord: &Coord) -> Vec<Finding> {
        let rows: Vec<&[u8]> = if coord.scheme == self.spec.primary.0 {
            self.rows.find(&coord.digest)
        } else if let Some((scheme, table)) = self.idx.iter().find(|(s, _)| *s == coord.scheme) {
            // idx entry = digest ‖ row_no u64 LE → fetch the full row
            let dlen = scheme.digest_len();
            table
                .find(&coord.digest)
                .into_iter()
                .filter_map(|entry| {
                    let row_no = u64::from_le_bytes(entry[dlen..dlen + 8].try_into().ok()?);
                    (row_no < self.rows.row_count).then(|| self.rows.row(row_no))
                })
                .collect()
        } else {
            Vec::new()
        };
        rows.into_iter().map(|r| (self.spec.finding)(r)).collect()
    }
}

/// Load every installed index with a known source spec.
pub fn open_all() -> Result<Vec<SourceIndex>> {
    let dir = index_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        let Some(name) = fname.strip_suffix(".rows") else {
            continue;
        };
        let Some(spec) = source(name) else {
            eprintln!("warning: unknown index source {name}, skipping");
            continue;
        };
        match open_one(spec, &dir) {
            Ok(ix) => out.push(ix),
            Err(e) => eprintln!("warning: skipping index {name}: {e}"),
        }
    }
    out.sort_by_key(|ix| ix.spec.name);
    Ok(out)
}

fn open_one(spec: &'static SourceSpec, dir: &Path) -> Result<SourceIndex> {
    let rows = Table::open(
        &dir.join(format!("{}.rows", spec.name)),
        KIND_ROWS,
        spec.primary.0,
    )?;
    let mut idx = Vec::new();
    for (scheme, _) in spec.secondary {
        let path = dir.join(format!("{}.{}.idx", spec.name, scheme.as_str()));
        if path.exists() {
            idx.push((*scheme, Table::open(&path, KIND_IDX, *scheme)?));
        }
    }
    Ok(SourceIndex { spec, rows, idx })
}

// --------------------------------------------------------------- build

fn write_header(
    w: &mut impl Write,
    kind: u8,
    scheme: Scheme,
    row_width: usize,
    row_count: u64,
    key_offset: usize,
    key_len: usize,
) -> Result<()> {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = 1;
    h[5] = kind;
    h[6] = scheme_id(scheme);
    h[8..12].copy_from_slice(&(row_width as u32).to_le_bytes());
    h[12..20].copy_from_slice(&row_count.to_le_bytes());
    h[20..24].copy_from_slice(&(key_offset as u32).to_le_bytes());
    h[24..28].copy_from_slice(&(key_len as u32).to_le_bytes());
    w.write_all(&h)?;
    Ok(())
}

/// External merge sort of fixed-width rows keyed on a slice: buffer a
/// chunk, sort, spill a run; k-way merge at the end. The same machinery
/// sorts the rows file and each idx file.
struct ChunkSorter {
    row_width: usize,
    key_offset: usize,
    key_len: usize,
    chunk_rows: usize,
    buf: Vec<u8>,
    runs: Vec<PathBuf>,
    tmp_dir: PathBuf,
    tag: String,
    total: u64,
}

impl ChunkSorter {
    fn new(
        row_width: usize,
        key_offset: usize,
        key_len: usize,
        chunk_bytes: usize,
        tmp_dir: &Path,
        tag: &str,
    ) -> ChunkSorter {
        ChunkSorter {
            row_width,
            key_offset,
            key_len,
            chunk_rows: (chunk_bytes / row_width).max(2),
            buf: Vec::new(),
            runs: Vec::new(),
            tmp_dir: tmp_dir.to_path_buf(),
            tag: tag.to_string(),
            total: 0,
        }
    }

    fn add(&mut self, row: &[u8]) -> Result<()> {
        debug_assert_eq!(row.len(), self.row_width);
        self.buf.extend_from_slice(row);
        self.total += 1;
        if self.buf.len() / self.row_width >= self.chunk_rows {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let w = self.row_width;
        let n = self.buf.len() / w;
        let mut order: Vec<u32> = (0..n as u32).collect();
        let (buf, ko, kl) = (&self.buf, self.key_offset, self.key_len);
        order.sort_unstable_by(|&a, &b| {
            let ka = &buf[a as usize * w + ko..a as usize * w + ko + kl];
            let kb = &buf[b as usize * w + ko..b as usize * w + ko + kl];
            ka.cmp(kb).then_with(|| {
                buf[a as usize * w..(a as usize + 1) * w]
                    .cmp(&buf[b as usize * w..(b as usize + 1) * w])
            })
        });
        let path = self
            .tmp_dir
            .join(format!("{}-run-{}", self.tag, self.runs.len()));
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for i in order {
            out.write_all(&self.buf[i as usize * w..(i as usize + 1) * w])?;
        }
        out.flush()?;
        self.runs.push(path);
        self.buf.clear();
        Ok(())
    }

    /// Merge all runs into `dest` (header included). Consumes the sorter.
    fn finish(mut self, dest: &Path, kind: u8, scheme: Scheme) -> Result<u64> {
        self.spill()?;
        let mut out = std::io::BufWriter::new(std::fs::File::create(dest)?);
        write_header(
            &mut out,
            kind,
            scheme,
            self.row_width,
            self.total,
            self.key_offset,
            self.key_len,
        )?;

        struct RunReader {
            reader: std::io::BufReader<std::fs::File>,
            row: Vec<u8>,
            exhausted: bool,
        }
        impl RunReader {
            fn advance(&mut self) -> Result<()> {
                match self.reader.read_exact(&mut self.row) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        self.exhausted = true;
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }

        let mut readers = Vec::new();
        for path in &self.runs {
            let mut rr = RunReader {
                reader: std::io::BufReader::with_capacity(4 << 20, std::fs::File::open(path)?),
                row: vec![0u8; self.row_width],
                exhausted: false,
            };
            rr.advance()?;
            readers.push(rr);
        }

        // Max-heap with reversed ordering = min-heap on (key, whole row).
        struct HeapItem {
            key: Vec<u8>,
            run: usize,
        }
        impl PartialEq for HeapItem {
            fn eq(&self, other: &Self) -> bool {
                self.key == other.key && self.run == other.run
            }
        }
        impl Eq for HeapItem {}
        impl Ord for HeapItem {
            fn cmp(&self, other: &Self) -> Ordering {
                other.key.cmp(&self.key).then(other.run.cmp(&self.run))
            }
        }
        impl PartialOrd for HeapItem {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        let key_of = |row: &[u8]| row[self.key_offset..self.key_offset + self.key_len].to_vec();
        let mut heap = BinaryHeap::new();
        for (i, rr) in readers.iter().enumerate() {
            if !rr.exhausted {
                heap.push(HeapItem {
                    key: key_of(&rr.row),
                    run: i,
                });
            }
        }
        let mut written: u64 = 0;
        while let Some(item) = heap.pop() {
            let rr = &mut readers[item.run];
            out.write_all(&rr.row)?;
            written += 1;
            if written.is_multiple_of(10_000_000) {
                eprintln!("  … merged {written}/{} {}", self.total, self.tag);
            }
            rr.advance()?;
            if !rr.exhausted {
                heap.push(HeapItem {
                    key: key_of(&rr.row),
                    run: item.run,
                });
            }
        }
        out.flush()?;
        if written != self.total {
            bail!("merge wrote {written} rows, expected {}", self.total);
        }
        for path in &self.runs {
            let _ = std::fs::remove_file(path);
        }
        Ok(written)
    }
}

/// Build `<name>.rows` + secondary `.idx` files from a TSV dump
/// (gzip-decoded when the path ends in .gz). `chunk_bytes` bounds the
/// in-RAM sort buffer.
pub fn build(spec: &'static SourceSpec, input: &Path, chunk_bytes: usize) -> Result<()> {
    build_in(spec, input, chunk_bytes, &index_dir())
}

fn build_in(spec: &'static SourceSpec, input: &Path, chunk_bytes: usize, dir: &Path) -> Result<()> {
    let tmp = dir.join(format!("tmp-{}", spec.name));
    std::fs::create_dir_all(&tmp)?;

    let file = std::fs::File::open(input).with_context(|| format!("open {}", input.display()))?;
    let reader: Box<dyn Read> = if input.extension().is_some_and(|e| e == "gz") {
        Box::new(flate2::read::MultiGzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut reader = std::io::BufReader::with_capacity(8 << 20, reader);

    let (primary_scheme, key_offset) = spec.primary;
    let key_len = primary_scheme.digest_len();
    let mut rows_sorter = ChunkSorter::new(
        spec.row_width,
        key_offset,
        key_len,
        chunk_bytes,
        &tmp,
        "rows",
    );

    let mut row = vec![0u8; spec.row_width];
    let mut line = String::new();
    let mut lineno: u64 = 0;
    let mut skipped: u64 = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        lineno += 1;
        let trimmed = line.trim_end_matches('\n');
        if trimmed.is_empty() {
            continue;
        }
        match (spec.parse_line)(trimmed, &mut row) {
            Ok(()) => rows_sorter.add(&row)?,
            Err(e) => {
                skipped += 1;
                if skipped <= 10 {
                    eprintln!("warning: line {lineno}: {e}");
                }
            }
        }
        if lineno.is_multiple_of(10_000_000) {
            eprintln!("  … read {lineno} lines");
        }
    }
    if skipped > 0 {
        eprintln!("warning: skipped {skipped} malformed lines of {lineno}");
    }
    if rows_sorter.total == 0 {
        bail!("no valid rows in {}", input.display());
    }

    let rows_part = dir.join(format!("{}.rows.part", spec.name));
    let total = rows_sorter.finish(&rows_part, KIND_ROWS, primary_scheme)?;
    eprintln!("sorted {total} rows");

    // Second pass over the sorted rows: emit (digest ‖ row_no) entries
    // for each secondary scheme, external-sorted the same way.
    let mut idx_sorters: Vec<(Scheme, usize, ChunkSorter)> = spec
        .secondary
        .iter()
        .map(|(scheme, offset)| {
            let dlen = scheme.digest_len();
            (
                *scheme,
                *offset,
                ChunkSorter::new(dlen + 8, 0, dlen, chunk_bytes, &tmp, scheme.as_str()),
            )
        })
        .collect();
    {
        let mut rows_in =
            std::io::BufReader::with_capacity(8 << 20, std::fs::File::open(&rows_part)?);
        let mut header = [0u8; HEADER_LEN];
        rows_in.read_exact(&mut header)?;
        let mut row = vec![0u8; spec.row_width];
        let mut entry = Vec::new();
        for row_no in 0..total {
            rows_in.read_exact(&mut row)?;
            for (scheme, offset, sorter) in &mut idx_sorters {
                let dlen = scheme.digest_len();
                let digest = &row[*offset..*offset + dlen];
                // All-zero = the row doesn't carry this digest
                // (e.g. tarballs rows without an md5): no idx entry.
                if digest.iter().all(|&b| b == 0) {
                    continue;
                }
                entry.clear();
                entry.extend_from_slice(digest);
                entry.extend_from_slice(&row_no.to_le_bytes());
                sorter.add(&entry)?;
            }
        }
    }
    let mut parts = vec![(rows_part, dir.join(format!("{}.rows", spec.name)))];
    for (scheme, _, sorter) in idx_sorters {
        let part = dir.join(format!("{}.{}.idx.part", spec.name, scheme.as_str()));
        sorter.finish(&part, KIND_IDX, scheme)?;
        parts.push((
            part,
            dir.join(format!("{}.{}.idx", spec.name, scheme.as_str())),
        ));
    }

    // Install atomically only once every file built.
    for (part, dest) in parts {
        std::fs::rename(&part, &dest).context("finalize index")?;
    }
    let _ = std::fs::remove_dir_all(&tmp);
    eprintln!(
        "installed {} index: {total} rows ({} + {} idx files)",
        spec.name,
        dir.join(format!("{}.rows", spec.name)).display(),
        spec.secondary.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_A: &str = "f9c009bd-bd72-4029-9bc7-75a1226f8adc";
    const UUID_B: &str = "7b63c2c4-e17b-4af4-888c-0f17f42a1f94";

    /// digests of "abc" / "" — same vectors as tests/cli.rs
    const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";
    const SHA1_EMPTY: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const MD5_EMPTY: &str = "d41d8cd98f00b204e9800998ecf8427e";

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hdx-inv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_tiny(dir: &Path, tsv: &str, chunk_bytes: usize) -> SourceIndex {
        let input = dir.join("in.tsv");
        std::fs::write(&input, tsv).unwrap();
        build_in(&FATCAT, &input, chunk_bytes, dir).unwrap();
        open_one(&FATCAT, dir).unwrap()
    }

    #[test]
    fn build_and_lookup_all_schemes() {
        let dir = tmp_dir("roundtrip");
        // Two rows + one with empty release; tiny chunk forces the
        // multi-run merge path.
        let tsv = format!(
            "{UUID_A}\t{UUID_B}\t{SHA1_ABC}\t{SHA256_ABC}\t{MD5_ABC}\n\
             {UUID_B}\t\t{SHA1_EMPTY}\t{SHA256_EMPTY}\t{MD5_EMPTY}\n"
        );
        let ix = build_tiny(&dir, &tsv, 128);
        assert_eq!(ix.row_count(), 2);

        for coord in [
            format!("sha256:{SHA256_ABC}"),
            format!("sha1:{SHA1_ABC}"),
            format!("md5:{MD5_ABC}"),
        ] {
            let findings = ix.lookup(&Coord::parse(&coord).unwrap());
            assert_eq!(findings.len(), 1, "one row for {coord}");
            let f = &findings[0];
            assert_eq!(f.backend, "fatcat");
            assert!(f.coords.contains(&format!("sha256:{SHA256_ABC}")));
            assert!(f.coords.contains(&format!("sha1:{SHA1_ABC}")));
            assert!(f.coords.contains(&format!("md5:{MD5_ABC}")));
            assert!(f.claims[0].statement.contains("release_"));
            // fatcat.wiki is dead: rows render idents (join keys into the
            // dumps) but no URL — the network backend owns live links.
            assert!(f.claims[0].url.is_none());
            // ident: lowercase base32, 26 chars for 16 bytes
            let ident = f.claims[0]
                .statement
                .split("file_")
                .nth(1)
                .unwrap()
                .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
                .next()
                .unwrap();
            assert_eq!(ident.len(), 26);
        }

        // empty-release row renders without a release claim
        let f = &ix.lookup(&Coord::parse(&format!("sha256:{SHA256_EMPTY}")).unwrap())[0];
        assert!(!f.claims[0].statement.contains("release_"));

        // absent digest
        let none = ix.lookup(
            &Coord::parse(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
        );
        assert!(none.is_empty());
        // scheme the source doesn't carry
        let none = ix.lookup(&Coord::parse(&format!("sha512:{SHA256_ABC}{SHA256_ABC}")).unwrap());
        assert!(none.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn build_sorts_and_survives_many_chunks() {
        let dir = tmp_dir("chunks");
        // 300 synthetic rows in reverse digest order, chunk of ~4 rows:
        // exercises spill + k-way merge properly.
        let mut tsv = String::new();
        for i in (0..300u32).rev() {
            tsv.push_str(&format!(
                "{UUID_A}\t{UUID_B}\t{:040x}\t{:064x}\t{:032x}\n",
                i, i, i
            ));
        }
        let ix = build_tiny(&dir, &tsv, 400);
        assert_eq!(ix.row_count(), 300);
        for i in [0u32, 1, 42, 299] {
            let c = Coord::parse(&format!("sha256:{i:064x}")).unwrap();
            assert_eq!(ix.lookup(&c).len(), 1, "row {i} findable by sha256");
            let c = Coord::parse(&format!("sha1:{i:040x}")).unwrap();
            // Row 0's sha1 is all-zero, which the build treats as
            // digest-absent: no idx entry.
            let want = if i == 0 { 0 } else { 1 };
            assert_eq!(ix.lookup(&c).len(), want, "row {i} via sha1 idx");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn build_rejects_garbage_lines_and_empty_input() {
        let dir = tmp_dir("badinput");
        // malformed lines are skipped with a warning, good ones survive
        let tsv = format!(
            "not a real line\n\
             {UUID_A}\t{UUID_B}\tzzzz\t{SHA256_ABC}\t{MD5_ABC}\n\
             {UUID_A}\t{UUID_B}\t{SHA1_ABC}\t{SHA256_ABC}\t{MD5_ABC}\n"
        );
        let ix = build_tiny(&dir, &tsv, 1 << 20);
        assert_eq!(ix.row_count(), 1);

        // all-garbage input is an error, not an empty index
        let input = dir.join("empty.tsv");
        std::fs::write(&input, "junk\n").unwrap();
        assert!(build_in(&FATCAT, &input, 1 << 20, &dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tarballs_build_and_render() {
        let dir = tmp_dir("tarballs");
        // debian row (with md5 crosswalk), homebrew + guix (md5 absent),
        // one unknown witness (skipped), one overlong field (skipped)
        let long = "x".repeat(200);
        let tsv = format!(
            "debian\t{SHA256_ABC}\t{MD5_ABC}\thello\t2.12.3-1\thello_2.12.3.orig.tar.gz\tpool/main/h/hello\n\
             homebrew\t{SHA256_EMPTY}\t-\twget\t1.25.0\t-\thttps://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz\n\
             guix\t{SHA256_EMPTY}\t-\t-\t-\thello-2.12.3.tar.gz\thttps://bordeaux.guix.gnu.org/file/hello-2.12.3.tar.gz/sha256/086vqwk2wl8zfs47sq2xpjc9k066ilmb8z6dn0q6ymwjzlm196cd\n\
             pypi\t{SHA256_ABC}\t-\t-\t-\t-\t-\n\
             debian\t{SHA256_ABC}\t{MD5_ABC}\t{long}\t1\tf\tpool/main\n"
        );
        let input = dir.join("in.tsv");
        std::fs::write(&input, tsv).unwrap();
        build_in(&TARBALLS, &input, 1 << 20, &dir).unwrap();
        let ix = open_one(&TARBALLS, &dir).unwrap();
        assert_eq!(ix.row_count(), 3);

        let debian = ix.lookup(&Coord::parse(&format!("sha256:{SHA256_ABC}")).unwrap());
        assert_eq!(debian.len(), 1);
        assert_eq!(debian[0].backend, "debian");
        assert_eq!(
            debian[0].claims[0].statement,
            "Debian sid packages these bytes as hello_2.12.3.orig.tar.gz (source package hello 2.12.3-1)"
        );
        assert_eq!(
            debian[0].claims[0].url.as_deref(),
            Some("https://deb.debian.org/debian/pool/main/h/hello/hello_2.12.3.orig.tar.gz")
        );
        // single-witness multi-hash row: md5 co-observed
        assert!(debian[0].coords.contains(&format!("md5:{MD5_ABC}")));
        // …and findable through the md5 idx
        assert_eq!(
            ix.lookup(&Coord::parse(&format!("md5:{MD5_ABC}")).unwrap())
                .len(),
            1
        );

        let two = ix.lookup(&Coord::parse(&format!("sha256:{SHA256_EMPTY}")).unwrap());
        let backends: Vec<&str> = two.iter().map(|f| f.backend.as_str()).collect();
        assert!(backends.contains(&"homebrew") && backends.contains(&"guix"));
        for f in &two {
            // md5-less rows co-observe nothing beyond sha256
            assert_eq!(f.coords.len(), 1);
            assert!(f.claims[0].url.as_deref().unwrap().starts_with("https://"));
        }
        // absent md5 never lands in the idx: the all-zero key finds nothing
        let zero_md5 = Coord::parse(&format!("md5:{}", "0".repeat(32))).unwrap();
        assert!(ix.lookup(&zero_md5).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_rejects_corrupt_files() {
        let dir = tmp_dir("corrupt");
        let tsv = format!("{UUID_A}\t{UUID_B}\t{SHA1_ABC}\t{SHA256_ABC}\t{MD5_ABC}\n");
        build_tiny(&dir, &tsv, 1 << 20);
        let rows = dir.join("fatcat.rows");

        let good = std::fs::read(&rows).unwrap();
        // wrong magic
        let mut bad = good.clone();
        bad[0] = b'X';
        std::fs::write(&rows, &bad).unwrap();
        assert!(open_one(&FATCAT, &dir).is_err());
        // truncated rows
        std::fs::write(&rows, &good[..good.len() - 10]).unwrap();
        assert!(open_one(&FATCAT, &dir).is_err());
        // wrong version
        let mut bad = good.clone();
        bad[4] = 9;
        std::fs::write(&rows, &bad).unwrap();
        assert!(open_one(&FATCAT, &dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
