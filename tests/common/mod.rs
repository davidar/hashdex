//! Shared fixtures for the CLI test binaries: a scratch environment
//! that runs `hdx` with its own cache and datasets, the tiny published
//! datasets the resolution tests read, and the container fixtures the
//! scan and recipe tests walk. Each test binary uses a subset.
#![allow(dead_code)]

pub use std::path::{Path, PathBuf};
pub use std::process::{Command, Output};

// Digests of the bytes "abc" (verified against python hashlib / git).
pub const ABC_MD5: &str = "900150983cd24fb0d6963f7d28e17f72";
pub const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
pub const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
pub const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
pub const ABC_BLAKE2S: &str = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
pub const ABC_SHA1GIT: &str = "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f";

pub struct TestEnv {
    pub root: PathBuf,
}

impl TestEnv {
    pub fn new(tag: &str) -> TestEnv {
        let root = std::env::temp_dir().join(format!("hdx-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("cache")).unwrap();
        std::fs::create_dir_all(root.join("work")).unwrap();
        TestEnv { root }
    }

    pub fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    pub fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.work().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// A digest-list file OUTSIDE the scanned work dir. The real digest is
    /// padded with dummy keys: a bloom sized for a single key is only a
    /// couple of dozen bits and false-positives on practically anything.
    pub fn digest_list(&self, name: &str, digest: &str) -> PathBuf {
        let width = digest.len();
        let mut lines = String::new();
        for i in 0..500 {
            lines.push_str(&format!("{i:0width$x}\n"));
        }
        lines.push_str(digest);
        lines.push('\n');
        let path = self.root.join(name);
        std::fs::write(&path, lines).unwrap();
        path
    }

    pub fn hdx(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hdx"))
            .args(args)
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .output()
            .expect("failed to run hdx")
    }

    /// Like hdx(), but run from a working directory — for relative-path
    /// invocations.
    pub fn hdx_in(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hdx"))
            .args(args)
            .current_dir(cwd)
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .output()
            .expect("failed to run hdx")
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The scan summary is the one stdout JSON object with a "files" key.
pub fn scan_summary(out: &Output) -> serde_json::Value {
    stdout(out)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v.get("files").is_some())
        .expect("scan printed no JSON summary")
}

/// Install a tiny fatcat dataset into the env's cache — the exact
/// layout `hdx index pull` produces (data files keyed by first sha256
/// nibble, weak-digest maps, `revision` marker written last), written
/// as real sorted parquet so lookups exercise the one true read path.
pub fn install_fatcat_dataset(env: &TestEnv, rows: &[(&str, &str, &str)]) {
    use std::collections::BTreeMap;
    let root = env.root.join("cache/hashdex/datasets/fatcat");

    let mut by_nibble: BTreeMap<char, Vec<(&str, &str, &str)>> = BTreeMap::new();
    for r in rows {
        by_nibble
            .entry(r.1.chars().next().unwrap())
            .or_default()
            .push(*r);
    }
    for (nibble, mut rows) in by_nibble {
        rows.sort_by_key(|r| r.1);
        let path = root.join(format!("data/files-{nibble}.parquet"));
        write_parquet(
            &path,
            "message fatcat {
                required binary sha256 (UTF8);
                optional binary title (UTF8);
                optional int64 release_year;
                optional binary container_name (UTF8);
                optional binary doi (UTF8);
                optional binary arxiv (UTF8);
                optional binary wayback_url (UTF8);
                optional binary sha1 (UTF8);
                optional binary md5 (UTF8);
            }",
            vec![
                Col::req_str(rows.iter().map(|r| r.1.to_string()).collect()),
                Col::opt_str(
                    rows.iter()
                        .map(|r| Some(format!("Test Paper {}", &r.1[..8])))
                        .collect(),
                ),
                Col::opt_i64(rows.iter().map(|_| Some(2020)).collect()),
                Col::opt_str(rows.iter().map(|_| None).collect()),
                Col::opt_str(rows.iter().map(|_| None).collect()),
                Col::opt_str(rows.iter().map(|_| None).collect()),
                Col::opt_str(
                    rows.iter()
                        .map(|r| {
                            Some(format!(
                                "https://web.archive.org/web/2024/{}.pdf",
                                &r.1[..8]
                            ))
                        })
                        .collect(),
                ),
                Col::opt_str(rows.iter().map(|r| Some(r.0.to_string())).collect()),
                Col::opt_str(rows.iter().map(|r| Some(r.2.to_string())).collect()),
            ],
        );
    }

    for (map, key_of) in [("sha1", 0usize), ("md5", 2usize)] {
        let mut pairs: Vec<(String, String)> = rows
            .iter()
            .map(|r| {
                let key = if key_of == 0 { r.0 } else { r.2 };
                (key.to_string(), r.1.to_string())
            })
            .collect();
        pairs.sort();
        write_parquet(
            &root.join(format!("maps/{map}.parquet")),
            &format!(
                "message map {{
                    required binary {map} (UTF8);
                    required binary sha256 (UTF8);
                }}"
            ),
            vec![
                Col::req_str(pairs.iter().map(|p| p.0.clone()).collect()),
                Col::req_str(pairs.iter().map(|p| p.1.clone()).collect()),
            ],
        );
    }

    // Written last, same as a real pull: this marks the copy complete.
    std::fs::write(root.join("revision"), "test-fixture").unwrap();
}

/// A fixture install-media dataset: one table per key scheme, each
/// row co-stating whatever digests its (single) source document did.
/// Row: (witness, sha256, sha512, sha1, md5, filename, loc).
type MediaRow<'a> = (
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    &'a str,
    &'a str,
);

pub fn media_key<'a>(r: &MediaRow<'a>, scheme: &str) -> Option<&'a str> {
    match scheme {
        "sha256" => r.1,
        "sha512" => r.2,
        "sha1" => r.3,
        _ => r.4,
    }
}

pub fn install_media_dataset(env: &TestEnv, rows: &[MediaRow]) {
    let root = env.root.join("cache/hashdex/datasets/install-media");
    let key_of = media_key;
    for scheme in ["sha256", "sha512", "sha1", "md5"] {
        let mut keyed: Vec<&MediaRow> = rows
            .iter()
            .filter(|r| key_of(r, scheme).is_some())
            .collect();
        if keyed.is_empty() {
            continue;
        }
        keyed.sort_by_key(|r| key_of(r, scheme).unwrap());
        let opt = |vals: Vec<Option<&str>>| {
            Col::opt_str(vals.into_iter().map(|v| v.map(str::to_string)).collect())
        };
        write_parquet(
            &root.join(format!("data/media-{scheme}.parquet")),
            "message media {
                optional binary witness (UTF8);
                optional binary sha256 (UTF8);
                optional binary sha512 (UTF8);
                optional binary sha1 (UTF8);
                optional binary md5 (UTF8);
                optional binary name (UTF8);
                optional binary version (UTF8);
                optional binary filename (UTF8);
                optional binary loc (UTF8);
            }",
            vec![
                opt(keyed.iter().map(|r| Some(r.0)).collect()),
                opt(keyed.iter().map(|r| r.1).collect()),
                opt(keyed.iter().map(|r| r.2).collect()),
                opt(keyed.iter().map(|r| r.3).collect()),
                opt(keyed.iter().map(|r| r.4).collect()),
                opt(keyed.iter().map(|_| None).collect()),
                opt(keyed.iter().map(|_| None).collect()),
                opt(keyed.iter().map(|r| Some(r.5)).collect()),
                opt(keyed.iter().map(|r| Some(r.6)).collect()),
            ],
        );
    }
    // Written last, same as a real pull: this marks the copy complete.
    std::fs::write(root.join("revision"), "test-fixture").unwrap();
}

/// A fixture rpm-files dataset in the normalized layout: a
/// pkgid-sorted packages table plus nibble-sharded file tables whose
/// `pkg` column is the row index into it (every sha256 shard exists,
/// empty ones included — routing is static).
/// Package: (pkgid, witness, name, evr, location).
/// File: (digest, path, index into `packages`).
type RpmPkg<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);

pub fn install_rpm_files_dataset(
    env: &TestEnv,
    packages: &[RpmPkg],
    files: &[(&str, &str, usize)],
) {
    let root = env.root.join("cache/hashdex/datasets/rpm-files");
    let opt = |vals: Vec<Option<&str>>| {
        Col::opt_str(vals.into_iter().map(|v| v.map(str::to_string)).collect())
    };

    // packages.parquet sorted by pkgid; remember where each landed so
    // file rows can reference by row number.
    let mut order: Vec<usize> = (0..packages.len()).collect();
    order.sort_by_key(|&i| packages[i].0);
    let mut row_of = vec![0i64; packages.len()];
    for (row, &i) in order.iter().enumerate() {
        row_of[i] = row as i64;
    }
    let sorted: Vec<&RpmPkg> = order.iter().map(|&i| &packages[i]).collect();
    write_parquet(
        &root.join("data/packages.parquet"),
        "message packages {
            required binary pkgid (UTF8);
            optional binary scheme (UTF8);
            optional binary witness (UTF8);
            optional binary name (UTF8);
            optional binary evr (UTF8);
            optional binary arch (UTF8);
            optional binary location (UTF8);
        }",
        vec![
            Col::req_str(sorted.iter().map(|p| p.0.to_string()).collect()),
            opt(sorted.iter().map(|_| Some("sha256")).collect()),
            opt(sorted.iter().map(|p| Some(p.1)).collect()),
            opt(sorted.iter().map(|p| Some(p.2)).collect()),
            opt(sorted.iter().map(|p| Some(p.3)).collect()),
            opt(sorted.iter().map(|_| Some("x86_64")).collect()),
            opt(sorted.iter().map(|p| Some(p.4)).collect()),
        ],
    );

    let file_schema = "message files {
        required binary digest (UTF8);
        required binary path (UTF8);
        required int64 pkg;
    }";
    for nibble in "0123456789abcdef".chars() {
        let mut shard: Vec<&(&str, &str, usize)> =
            files.iter().filter(|f| f.0.starts_with(nibble)).collect();
        shard.sort_by_key(|f| f.0);
        write_parquet(
            &root.join(format!("data/files-sha256-{nibble}.parquet")),
            file_schema,
            vec![
                Col::req_str(shard.iter().map(|f| f.0.to_string()).collect()),
                Col::req_str(shard.iter().map(|f| f.1.to_string()).collect()),
                Col::req_i64(shard.iter().map(|f| row_of[f.2]).collect()),
            ],
        );
    }
    for weak in ["md5", "sha1"] {
        write_parquet(
            &root.join(format!("data/files-{weak}.parquet")),
            file_schema,
            vec![
                Col::req_str(vec![]),
                Col::req_str(vec![]),
                Col::req_i64(vec![]),
            ],
        );
    }
    // Written last, same as a real pull: this marks the copy complete.
    std::fs::write(root.join("revision"), "test-fixture").unwrap();
}

pub enum Col {
    Str(Vec<Option<String>>, bool),
    I64(Vec<Option<i64>>, bool),
}

impl Col {
    pub fn req_str(v: Vec<String>) -> Col {
        Col::Str(v.into_iter().map(Some).collect(), true)
    }
    pub fn opt_str(v: Vec<Option<String>>) -> Col {
        Col::Str(v, false)
    }
    pub fn opt_i64(v: Vec<Option<i64>>) -> Col {
        Col::I64(v, false)
    }
    pub fn req_i64(v: Vec<i64>) -> Col {
        Col::I64(v.into_iter().map(Some).collect(), true)
    }
}

/// One row group, columns in schema order, chunk statistics on (the
/// defaults) — all a sorted-parquet point lookup needs.
pub fn write_parquet(path: &Path, schema: &str, cols: Vec<Col>) {
    use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;
    use std::sync::Arc;

    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let schema = Arc::new(parse_message_type(schema).unwrap());
    let props = Arc::new(WriterProperties::builder().build());
    let file = std::fs::File::create(path).unwrap();
    let mut writer = SerializedFileWriter::new(file, schema, props).unwrap();
    let mut rg = writer.next_row_group().unwrap();
    for col in cols {
        let mut c = rg.next_column().unwrap().expect("more columns than schema");
        match col {
            Col::Str(vals, required) => {
                let present: Vec<ByteArray> = vals
                    .iter()
                    .flatten()
                    .map(|s| ByteArray::from(s.as_str()))
                    .collect();
                let defs: Vec<i16> = vals.iter().map(|v| v.is_some() as i16).collect();
                c.typed::<ByteArrayType>()
                    .write_batch(&present, (!required).then_some(&defs[..]), None)
                    .unwrap();
            }
            Col::I64(vals, required) => {
                let present: Vec<i64> = vals.iter().flatten().copied().collect();
                let defs: Vec<i16> = vals.iter().map(|v| v.is_some() as i16).collect();
                c.typed::<Int64Type>()
                    .write_batch(&present, (!required).then_some(&defs[..]), None)
                    .unwrap();
            }
        }
        c.close().unwrap();
    }
    rg.close().unwrap();
    writer.close().unwrap();
}

// Digests of b"the quick brown fox jumps over the lazy dog\n" (44
// bytes — content must exceed the sub-digest identity floor).
pub const FOX_MD5: &str = "1e280e1713df124d35709cf6138d9f91";
pub const FOX_SHA1: &str = "5d2781d78fa5a97b7bafa849fe933dfc9dc93eba";
pub const FOX_SHA256: &str = "1153a4080f1fcb04425aa0b841c2b14606fe6df25d9076d2a1face2d5af57129";
// Digests of b"\n": the ubiquitous single-newline file, 1 byte —
// genuinely present in fatcat via a botched deposit.
pub const NL_MD5: &str = "68b329da9893e34099c7d8ad5cb9c940";
pub const NL_SHA1: &str = "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc";
pub const NL_SHA256: &str = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";

/// Install a tiny ia-census dataset (data sharded by first sha1
/// nibble + md5 map), the layout `hdx index pull ia-census` produces.
pub fn install_census_dataset(env: &TestEnv, rows: &[(&str, &str, &str, &str)]) {
    use std::collections::BTreeMap;
    let root = env.root.join("cache/hashdex/datasets/ia-census");
    let mut by_nibble: BTreeMap<char, Vec<(&str, &str, &str, &str)>> = BTreeMap::new();
    for r in rows {
        by_nibble
            .entry(r.0.chars().next().unwrap())
            .or_default()
            .push(*r);
    }
    for (nibble, mut rows) in by_nibble {
        rows.sort_by_key(|r| r.0);
        write_parquet(
            &root.join(format!("data/census-{nibble}.parquet")),
            "message census {
                required binary sha1 (UTF8);
                required binary md5 (UTF8);
                required binary identifier (UTF8);
                required binary filename (UTF8);
            }",
            vec![
                Col::req_str(rows.iter().map(|r| r.0.to_string()).collect()),
                Col::req_str(rows.iter().map(|r| r.1.to_string()).collect()),
                Col::req_str(rows.iter().map(|r| r.2.to_string()).collect()),
                Col::req_str(rows.iter().map(|r| r.3.to_string()).collect()),
            ],
        );
    }
    let mut pairs: Vec<(String, String)> = rows
        .iter()
        .map(|r| (r.1.to_string(), r.0.to_string()))
        .collect();
    pairs.sort();
    write_parquet(
        &root.join("maps/md5.parquet"),
        "message map {
            required binary md5 (UTF8);
            required binary sha1 (UTF8);
        }",
        vec![
            Col::req_str(pairs.iter().map(|p| p.0.clone()).collect()),
            Col::req_str(pairs.iter().map(|p| p.1.clone()).collect()),
        ],
    );
    std::fs::write(root.join("revision"), "test-fixture").unwrap();
}

/// An uncompressed GNU tar — every member is a byte range of the root,
/// which is what splice recipes reference.
pub fn plain_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *bytes).unwrap();
    }
    b.into_inner().unwrap()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// A newc cpio archive of (path, bytes) entries — rpm-payload style.
pub fn newc_cpio(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut cpio = Vec::new();
    let header = |cpio: &mut Vec<u8>, mode: u32, filesize: usize, namesize: usize, ino: usize| {
        write!(
            cpio,
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            ino, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namesize, 0
        )
        .unwrap();
    };
    for (i, (name, bytes)) in entries.iter().enumerate() {
        let name_nul = format!("{name}\0");
        header(&mut cpio, 0o100644, bytes.len(), name_nul.len(), i + 1);
        cpio.extend_from_slice(name_nul.as_bytes());
        while cpio.len() % 4 != 0 {
            cpio.push(0);
        }
        cpio.extend_from_slice(bytes);
        while cpio.len() % 4 != 0 {
            cpio.push(0);
        }
    }
    let trailer = "TRAILER!!!\0";
    header(&mut cpio, 0, 0, trailer.len(), 0);
    cpio.extend_from_slice(trailer.as_bytes());
    while cpio.len() % 4 != 0 {
        cpio.push(0);
    }
    cpio
}

/// A minimal rpm: 96-byte lead (magic + zeros), empty signature and
/// main headers, gzip'd newc cpio payload — the exact shape the
/// header skip + payload sniff walk through.
pub fn fake_rpm(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut rpm = vec![0u8; 96];
    rpm[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    for _ in 0..2 {
        rpm.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01]); // header magic + version
        rpm.extend_from_slice(&[0; 4]); // reserved
        rpm.extend_from_slice(&0u32.to_be_bytes()); // nindex
        rpm.extend_from_slice(&0u32.to_be_bytes()); // hsize
    }
    let mut enc = flate2::write::GzEncoder::new(&mut rpm, flate2::Compression::default());
    enc.write_all(&newc_cpio(files)).unwrap();
    enc.finish().unwrap();
    rpm
}

/// (sha1, sha256, md5) of some bytes — a fixture-dataset row: refs
/// require claims now, so recipe tests register their members.
pub fn digest_row(bytes: &[u8]) -> (String, String, String) {
    let sha1 = {
        use sha1::Digest;
        format!("{:x}", sha1::Sha1::digest(bytes))
    };
    let md5 = {
        use md5::Digest;
        format!("{:x}", md5::Md5::digest(bytes))
    };
    (sha1, sha256_hex(bytes), md5)
}

/// Run the system's GNU gzip (what mint's compressor search and
/// check's rebuild shell out to — the gzip@0 tests need it on PATH).
pub fn system_gzip(args: &[&str], input: &[u8]) -> Vec<u8> {
    use std::io::{Read as _, Write as _};
    let mut child = std::process::Command::new("gzip")
        .args(args)
        .args(["-n", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("GNU gzip on PATH (required by the gzip@0 tests)");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn({
        let input = input.to_vec();
        move || stdin.write_all(&input)
    });
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    writer.join().unwrap().unwrap();
    assert!(child.wait().unwrap().success());
    out
}

/// Deterministic mixed-entropy payload: compressible runs with seeded
/// noise, long enough that rsyncable window resets actually fire.
/// Compress with the system zstd, STREAMED — a piped run states no
/// content size and frames multi-threaded, which is exactly what
/// dracut's `cpio | zstd` writes and what zstd@0 nodes reproduce.
pub fn system_zstd(args: &[&str], input: &[u8]) -> Vec<u8> {
    use std::io::{Read as _, Write as _};
    let mut child = std::process::Command::new("zstd")
        .args(args)
        .args(["-q", "-T0", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("zstd on PATH (required by the zstd@0 tests)");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn({
        let input = input.to_vec();
        move || stdin.write_all(&input)
    });
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    writer.join().unwrap().unwrap();
    assert!(child.wait().unwrap().success());
    out
}

/// A boot image the way dracut builds one: an uncompressed "early"
/// cpio (the microcode archive), zero padding to a block boundary,
/// then one compressed frame over the cpio that holds everything else.
/// 94% of a real initramfs lives past that first `TRAILER!!!`.
pub fn initramfs_shape(early: &[u8], frame: &[u8]) -> Vec<u8> {
    let mut out = early.to_vec();
    while !out.len().is_multiple_of(4096) {
        out.push(0);
    }
    out.extend_from_slice(frame);
    out
}

pub fn noisy_payload(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let b = (seed >> 33) as u8;
        let run = 1 + (seed >> 41) as usize % 32;
        for _ in 0..run.min(len - out.len()) {
            out.push(b);
        }
        if seed & 7 == 0 {
            out.push((seed >> 25) as u8);
        }
    }
    out.truncate(len);
    out
}

/// The tree inside `frag.erofs` (the rung-E fixture), regenerated
/// byte-for-byte. Its content is pseudo-TEXT, not random bytes:
/// mkfs.erofs stores incompressible data plain, and this fixture has
/// to produce real MicroLZMA pclusters.
pub fn frag_tree() -> Vec<(&'static str, Vec<u8>)> {
    // The generator the fixture was built with (see the doc comment on
    // erofs_recipe_rebuilds_pclusters_from_rpms): an LCG picking words.
    fn prose(seed: u64, n: usize) -> Vec<u8> {
        const WORDS: [&str; 16] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
            "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
        ];
        let (mut x, mut out) = (seed, Vec::new());
        while out.len() < n {
            x = (x.wrapping_mul(1103515245).wrapping_add(12345)) % (1 << 31);
            out.extend_from_slice(WORDS[((x >> 16) & 15) as usize].as_bytes());
            out.push(if (x >> 20) & 7 == 0 { b'\n' } else { b' ' });
        }
        out.truncate(n);
        out
    }
    let mut book = Vec::new();
    for i in 0..500 {
        book.extend_from_slice(
            format!(
                "the quick brown fox jumps over the lazy dog {:04}\n",
                i % 977
            )
            .as_bytes(),
        );
    }
    // Incompressible: mkfs stores its pclusters raw, which a recipe
    // splices rather than re-encodes.
    let mut noise = Vec::with_capacity(16_000);
    let mut x: u64 = 3;
    while noise.len() < 16_000 {
        x = (x.wrapping_mul(1103515245).wrapping_add(12345)) % (1 << 31);
        noise.push(((x >> 16) & 0xff) as u8);
    }
    let dup = prose(7, 8000);
    let mut tree: Vec<(&'static str, Vec<u8>)> = vec![
        ("book.txt", book),
        ("dup/a.bin", dup.clone()),
        ("dup/b.bin", dup),
        ("noise.bin", noise),
        ("span.bin", prose(1, 100_000)),
        ("tiny.txt", b"tiny fixture file\n".to_vec()),
    ];
    for (i, path) in [
        "small/s1.txt",
        "small/s2.txt",
        "small/s3.txt",
        "small/s4.txt",
        "small/s5.txt",
    ]
    .into_iter()
    .enumerate()
    {
        tree.push((
            path,
            format!("small file {}\n", i + 1).repeat(23).into_bytes(),
        ));
    }
    tree
}

pub fn erofs_fixture(env: &TestEnv, name: &str) -> PathBuf {
    let gz = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/data/erofs/{name}.erofs.gz")),
    )
    .unwrap();
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
    env.write(&format!("{name}.erofs"), &raw)
}

pub fn fat_fixture(env: &TestEnv, bits: &str) -> PathBuf {
    let gz = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/data/fat/fat{bits}.img.gz")),
    )
    .unwrap();
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
    env.write(&format!("fat{bits}.img"), &raw)
}

/// The files an EFI system partition holds, and their digests — the
/// same tree written into all three FAT widths.
pub const FAT_TRUTH: &[(&str, &str)] = &[
    (
        "EFI/BOOT/BOOTX64.EFI",
        "7a2d60e49176c95d98a3be63e400d8a16ed600327d7a7b4ea11ca5a89ce1eb92",
    ),
    (
        "EFI/BOOT/grub.cfg",
        "05831f8cbd6e1ad6156a52187ab448500cc1ba3ac9ddf530ab38111d4e235d5c",
    ),
    (
        "EFI/BOOT/grubx64.efi",
        "ee5b94d80871d6ed57a6cd311528870cfad7df9d8de33a17a0e9de089e20fe5b",
    ),
    (
        "EFI/fedora/a-rather-long-file-name.efi",
        "a048c89449bb671738ea5c4e97cac9fa8cad07a58f027d295cc4cfa42e527f8b",
    ),
];
