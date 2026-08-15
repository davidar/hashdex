//! End-to-end tests of the hdx CLI, covering everything that works
//! offline: coords minting, filter build/list, scan (including the local
//! index reuse path), locate, and argument validation. Each test gets its
//! own XDG_CACHE_HOME so nothing touches the real ~/.cache/hashdex and
//! tests can run in parallel.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The disarchive projection: referee-only test code (see its module
/// doc). Not part of the shipped crate.
mod disarchive;

// Digests of the bytes "abc" (verified against python hashlib / git).
const ABC_MD5: &str = "900150983cd24fb0d6963f7d28e17f72";
const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
const ABC_BLAKE2S: &str = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
const ABC_SHA1GIT: &str = "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f";

struct TestEnv {
    root: PathBuf,
}

impl TestEnv {
    fn new(tag: &str) -> TestEnv {
        let root = std::env::temp_dir().join(format!("hdx-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("cache")).unwrap();
        std::fs::create_dir_all(root.join("work")).unwrap();
        TestEnv { root }
    }

    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.work().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// A digest-list file OUTSIDE the scanned work dir. The real digest is
    /// padded with dummy keys: a bloom sized for a single key is only a
    /// couple of dozen bits and false-positives on practically anything.
    fn digest_list(&self, name: &str, digest: &str) -> PathBuf {
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

    fn hdx(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hdx"))
            .args(args)
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .output()
            .expect("failed to run hdx")
    }

    /// Like hdx(), but run from a working directory — for relative-path
    /// invocations.
    fn hdx_in(&self, cwd: &Path, args: &[&str]) -> Output {
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The scan summary is the one stdout JSON object with a "files" key.
fn scan_summary(out: &Output) -> serde_json::Value {
    stdout(out)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v.get("files").is_some())
        .expect("scan printed no JSON summary")
}

#[test]
fn coords_mints_all_six_schemes() {
    let env = TestEnv::new("coords");
    let file = env.write("abc.txt", b"abc");
    let out = env.hdx(&["coords", file.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    for (scheme, hex) in [
        ("md5", ABC_MD5),
        ("sha1", ABC_SHA1),
        ("sha256", ABC_SHA256),
        ("sha512", ABC_SHA512),
        ("blake2s256", ABC_BLAKE2S),
        ("sha1_git", ABC_SHA1GIT),
    ] {
        assert!(text.contains(hex), "missing {scheme} digest in:\n{text}");
        assert!(text.contains(scheme), "missing {scheme} label in:\n{text}");
    }

    // JSON mode: one object per file with scheme:hex coordinate strings
    let out = env.hdx(&["coords", file.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().next().unwrap()).unwrap();
    assert_eq!(v["file"], file.to_str().unwrap());
    let coords: Vec<String> = v["coords"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(coords.contains(&format!("sha256:{ABC_SHA256}")));
    assert!(coords.contains(&format!("sha1_git:{ABC_SHA1GIT}")));
    assert_eq!(coords.len(), 6);
}

#[test]
fn coords_argument_errors() {
    let env = TestEnv::new("coords-err");
    let out = env.hdx(&["coords"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no files"));

    let missing = env.work().join("does-not-exist");
    let out = env.hdx(&["coords", missing.to_str().unwrap()]);
    assert!(!out.status.success());
}

#[test]
fn no_args_prints_usage_error() {
    let env = TestEnv::new("noargs");
    let out = env.hdx(&[]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("usage"));
}

#[test]
fn unparseable_hash_is_an_error() {
    let env = TestEnv::new("badhash");
    // wrong length for any scheme — rejected before any network I/O
    let out = env.hdx(&["a9993e364706816aba3e25717850c2"]);
    assert!(!out.status.success());
    // unknown scheme prefix
    let out = env.hdx(&[&format!("sha3:{ABC_SHA256}")]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown hash scheme"));
}

/// The core offline pipeline: build filters from digest lists, scan a
/// directory against them, reuse the local index on rescan, and locate
/// files by digest afterwards.
#[test]
fn build_scan_locate_lifecycle() {
    let env = TestEnv::new("lifecycle");
    let work = env.work();
    let known = env.write("known.bin", b"abc");
    env.write("unknown.bin", b"bytes nobody has ever indexed, surely");
    env.write("empty.txt", b"");

    // Filter inputs deliberately use the "wrong" case: build must
    // normalize sha256 keys to lowercase and sha1 keys to UPPERCASE
    // (CIRCL's convention) for scan to find them.
    let sha256_list = env.digest_list("pub.sha256.txt", &ABC_SHA256.to_uppercase());
    let sha1_list = env.digest_list("pub1.sha1.txt", ABC_SHA1);

    let out = env.hdx(&["filters", "list"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no filters installed"));

    let out = env.hdx(&[
        "filters",
        "build",
        "pub",
        "sha256",
        sha256_list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let out = env.hdx(&[
        "filters",
        "build",
        "pub1",
        "sha1",
        sha1_list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = env.hdx(&["filters", "list"]);
    let text = stdout(&out);
    assert!(text.contains("pub") && text.contains("sha256"));
    assert!(text.contains("pub1") && text.contains("sha1"));

    // First scan: everything hashed, known.bin matches both filters,
    // empty files are skipped entirely.
    let out = env.hdx(&["scan", work.to_str().unwrap(), "--list", "all", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let summary = scan_summary(&out);
    assert_eq!(summary["known"], 1);
    assert_eq!(summary["hashed"], summary["files"]);
    assert_eq!(summary["from_index"], 0);
    assert_eq!(summary["per_filter"]["pub"], 1);
    assert_eq!(summary["per_filter"]["pub1"], 1);

    let text = stdout(&out);
    let file_line = |name: &str| -> serde_json::Value {
        text.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["path"].as_str().is_some_and(|p| p.ends_with(name)))
            .unwrap_or_else(|| panic!("no per-file line for {name} in:\n{text}"))
    };
    let k = file_line("known.bin");
    assert_eq!(k["known"], true);
    assert_eq!(k["sha1"], ABC_SHA1);
    assert_eq!(k["sha256"], ABC_SHA256);
    let names: Vec<&str> = k["filters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(names.contains(&"pub") && names.contains(&"pub1"));
    assert_eq!(file_line("unknown.bin")["known"], false);
    assert!(!text.contains("empty.txt"), "empty files must be skipped");

    // Rescan: unchanged files come from the index, nothing is rehashed.
    let out = env.hdx(&["scan", work.to_str().unwrap(), "--json"]);
    let summary = scan_summary(&out);
    assert_eq!(summary["hashed"], 0);
    assert_eq!(summary["from_index"], summary["files"]);
    assert_eq!(
        summary["known"], 1,
        "index reuse must not lose filter matches"
    );

    // A RELATIVE spelling of the same root must reuse the same index
    // entries — roots canonicalize before keying, so `scan .` and
    // `scan /abs/path` are one tree, not two.
    let out = env.hdx_in(&work, &["scan", ".", "--json"]);
    let summary = scan_summary(&out);
    assert_eq!(
        summary["hashed"], 0,
        "relative respelling rehashed: {summary}"
    );
    assert_eq!(summary["from_index"], summary["files"]);

    // --rehash bypasses the index.
    let out = env.hdx(&["scan", work.to_str().unwrap(), "--json", "--rehash"]);
    let summary = scan_summary(&out);
    assert_eq!(summary["from_index"], 0);

    // A modified file is rehashed; untouched ones still come from the index.
    env.write("unknown.bin", b"different content, different length now");
    let out = env.hdx(&["scan", work.to_str().unwrap(), "--json"]);
    let summary = scan_summary(&out);
    assert_eq!(summary["hashed"], 1);

    // locate: by sha256, by sha1, then a digest nothing local has.
    let out = env.hdx(&["locate", ABC_SHA256]);
    assert!(out.status.success());
    assert!(stdout(&out).contains(known.to_str().unwrap()));
    let out = env.hdx(&["locate", ABC_SHA1]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("known.bin"));

    let absent = "0000000000000000000000000000000000000000000000000000000000000000";
    let out = env.hdx(&["locate", absent]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no local file"));

    let out = env.hdx(&["locate", ABC_MD5]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("sha1/sha256"));
}

#[test]
fn scan_without_filters_reports_unknown() {
    let env = TestEnv::new("nofilters");
    env.write("a.bin", b"abc");
    let out = env.hdx(&["scan", env.work().to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    assert!(stderr(&out).contains("no filters installed"));
    let summary = scan_summary(&out);
    assert_eq!(summary["files"], 1);
    assert_eq!(summary["known"], 0);

    let out = env.hdx(&["scan"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no paths"));
}

#[test]
fn filters_build_rejects_bad_input() {
    let env = TestEnv::new("badbuild");
    let bad = env.write("bad.txt", b"nothex\n");
    let out = env.hdx(&["filters", "build", "x", "sha256", bad.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("hex digest"));

    // right characters, wrong length for the scheme
    let short = env.write("short.txt", format!("{ABC_SHA1}\n").as_bytes());
    let out = env.hdx(&["filters", "build", "x", "sha256", short.to_str().unwrap()]);
    assert!(!out.status.success());

    let empty = env.write("empty.txt", b"\n\n");
    let out = env.hdx(&["filters", "build", "x", "sha256", empty.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no digests"));

    let out = env.hdx(&["filters", "build", "x", "sha256"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no input files"));
}

/// Install a tiny fatcat dataset into the env's cache — the exact
/// layout `hdx index pull` produces (data files keyed by first sha256
/// nibble, weak-digest maps, `revision` marker written last), written
/// as real sorted parquet so lookups exercise the one true read path.
fn install_fatcat_dataset(env: &TestEnv, rows: &[(&str, &str, &str)]) {
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

fn media_key<'a>(r: &MediaRow<'a>, scheme: &str) -> Option<&'a str> {
    match scheme {
        "sha256" => r.1,
        "sha512" => r.2,
        "sha1" => r.3,
        _ => r.4,
    }
}

fn install_media_dataset(env: &TestEnv, rows: &[MediaRow]) {
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

fn install_rpm_files_dataset(env: &TestEnv, packages: &[RpmPkg], files: &[(&str, &str, usize)]) {
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

enum Col {
    Str(Vec<Option<String>>, bool),
    I64(Vec<Option<i64>>, bool),
}

impl Col {
    fn req_str(v: Vec<String>) -> Col {
        Col::Str(v.into_iter().map(Some).collect(), true)
    }
    fn opt_str(v: Vec<Option<String>>) -> Col {
        Col::Str(v, false)
    }
    fn opt_i64(v: Vec<Option<i64>>) -> Col {
        Col::I64(v, false)
    }
    fn req_i64(v: Vec<i64>) -> Col {
        Col::I64(v.into_iter().map(Some).collect(), true)
    }
}

/// One row group, columns in schema order, chunk statistics on (the
/// defaults) — all a sorted-parquet point lookup needs.
fn write_parquet(path: &Path, schema: &str, cols: Vec<Col>) {
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

#[test]
fn install_media_resolves_by_every_key_scheme() {
    let env = TestEnv::new("media");
    let (a256, a512, a1, amd5) = (
        "aa".repeat(32),
        "ab".repeat(64),
        "ac".repeat(20),
        "ad".repeat(16),
    );
    let b256 = "bb".repeat(32);
    install_media_dataset(
        &env,
        &[
            // one document co-stating four schemes (Qubes .DIGESTS)
            (
                "qubes",
                Some(a256.as_str()),
                Some(a512.as_str()),
                Some(a1.as_str()),
                Some(amd5.as_str()),
                "Qubes-R4.3.1-x86_64.iso",
                "https://ftp.qubes-os.org/iso/Qubes-R4.3.1-x86_64.iso.DIGESTS",
            ),
            // a plain sha256-only statement
            (
                "ubuntu",
                Some(b256.as_str()),
                None,
                None,
                None,
                "ubuntu-26.04-desktop-amd64.iso",
                "https://releases.ubuntu.com/26.04/SHA256SUMS",
            ),
        ],
    );

    // every scheme the row co-stated is a working lookup key, and the
    // answer carries the claim URL plus the co-witnessed coordinates
    for hash in [
        a256.clone(),
        format!("sha512:{a512}"),
        format!("sha1:{a1}"),
        format!("md5:{amd5}"),
    ] {
        let out = env.hdx(&["--offline", &hash]);
        assert!(out.status.success(), "offline miss for {hash}");
        let text = stdout(&out);
        assert!(
            text.contains("Qubes OS releases these bytes as Qubes-R4.3.1-x86_64.iso"),
            "no statement for {hash}:\n{text}"
        );
        assert!(
            text.contains("ftp.qubes-os.org"),
            "no claim URL for {hash}:\n{text}"
        );
        assert!(
            text.contains(&a256),
            "sha256 crosswalk missing for {hash}:\n{text}"
        );
    }

    let out = env.hdx(&["--offline", &b256]);
    let text = stdout(&out);
    assert!(
        text.contains("Ubuntu releases these bytes as ubuntu-26.04-desktop-amd64.iso"),
        "{text}"
    );
    assert!(text.contains("releases.ubuntu.com"), "{text}");
}

#[test]
fn rpm_files_resolves_file_and_package_rows() {
    let env = TestEnv::new("rpmfiles");
    let file256 = "aa".repeat(32);
    let pkg256 = "bb".repeat(32);
    let rpm_url = "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/Packages/b/bash-5.3.9-3.fc44.x86_64.rpm";
    install_rpm_files_dataset(
        &env,
        // the package (keyed by its pkgid in packages.parquet) …
        &[(&pkg256, "fedora-44", "bash", "5.3.9-3.fc44", rpm_url)],
        // … and a file row referencing it by row index
        &[(&file256, "/usr/bin/bash", 0)],
    );

    let out = env.hdx(&["--offline", &file256]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains(
            "Fedora 44 ships these bytes as /usr/bin/bash in bash-5.3.9-3.fc44.x86_64.rpm"
        ),
        "no file statement:\n{text}"
    );
    assert!(text.contains(rpm_url), "no claim URL:\n{text}");

    let out = env.hdx(&["--offline", &pkg256]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains(
            "Fedora 44 packages these bytes as bash-5.3.9-3.fc44.x86_64.rpm (bash 5.3.9-3.fc44)"
        ),
        "no package statement:\n{text}"
    );
}

#[test]
fn local_dataset_lifecycle_and_offline_resolve() {
    let env = TestEnv::new("dataset");
    // Nothing pulled: every dataset lists as remote.
    let out = env.hdx(&["index", "list"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("fatcat") && text.contains("tarballs"));
    assert!(text.contains("remote"), "unpulled must say remote:\n{text}");

    install_fatcat_dataset(&env, &[(ABC_SHA1, ABC_SHA256, ABC_MD5)]);
    let out = env.hdx(&["index", "list"]);
    assert!(stdout(&out).contains("local:"), "{}", stdout(&out));

    // resolve by each of the row's three schemes, fully offline —
    // the local copy carries the full citation and the wayback URL
    for hash in [
        ABC_SHA256.to_string(),
        format!("sha1:{ABC_SHA1}"),
        format!("md5:{ABC_MD5}"),
    ] {
        let out = env.hdx(&["--offline", &hash]);
        assert!(out.status.success(), "offline miss for {hash}");
        let text = stdout(&out);
        assert!(text.contains("fatcat"), "no attestor line in:\n{text}");
        assert!(text.contains("Test Paper"), "no citation in:\n{text}");
        assert!(
            text.contains("web.archive.org"),
            "no wayback claim URL in:\n{text}"
        );
        assert!(
            !text.contains("fatcat.wiki"),
            "dead URL resurfaced:\n{text}"
        );
        // crosswalk: the other coordinates surface
        assert!(text.contains(ABC_SHA1) || text.contains(ABC_MD5));
    }

    // unknown dataset names are rejected offline, before any network
    let out = env.hdx(&["index", "pull", "nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown dataset"));
    assert!(stderr(&out).contains("fatcat"));

    // verify rejects unknown names and never-pulled datasets before
    // touching the network
    let out = env.hdx(&["index", "verify", "nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown dataset"));
    let out = env.hdx(&["index", "verify", "tarballs"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no local copy"));

    // offline miss: exit 1, honest message
    let absent = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let out = env.hdx(&["--offline", absent]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("offline"));

    // rm drops the local copy; offline resolution loses the witness
    let out = env.hdx(&["index", "rm", "fatcat"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let out = env.hdx(&["--offline", ABC_SHA256]);
    assert!(!out.status.success(), "removed dataset still resolves");
    let out = env.hdx(&["index", "rm", "fatcat"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no local copy"));
}

/// The crosswalk demo: `hdx coords` records the six-scheme row of a
/// local file (the only sha1_git edge source), so an offline SWHID
/// query walks sha1_git → sha256 → the fatcat citation. Two hops, two
/// witnesses, welded by a shared identity-grade digest.
#[test]
fn walk_crosses_sources_offline() {
    let env = TestEnv::new("walk");
    install_fatcat_dataset(&env, &[(ABC_SHA1, ABC_SHA256, ABC_MD5)]);
    let file = env.write("abc.txt", b"abc");
    let out = env.hdx(&["coords", file.to_str().unwrap()]);
    assert!(out.status.success());

    let out = env.hdx(&["--offline", &format!("swh:1:cnt:{ABC_SHA1GIT}")]);
    assert!(
        out.status.success(),
        "SWHID did not resolve offline: {}",
        stdout(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("local-hash"),
        "missing local witness:\n{text}"
    );
    assert!(
        text.contains("fatcat"),
        "walk did not reach fatcat:\n{text}"
    );
    assert!(
        !text.contains("consistent with"),
        "shared sha256 must weld into ONE cluster:\n{text}"
    );
}

/// Two witness rows sharing only a weak digest must NOT weld: they
/// render as distinct contents, with a collision warning since they
/// disagree on identity-grade digests.
#[test]
fn weak_digest_ambiguity_is_honest() {
    let env = TestEnv::new("collision");
    let md5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (sha256_1, sha256_2) = ("1".repeat(64), "2".repeat(64));
    install_fatcat_dataset(
        &env,
        &[
            (&"3".repeat(40), &sha256_1, md5),
            (&"4".repeat(40), &sha256_2, md5),
        ],
    );
    let out = env.hdx(&["--offline", &format!("md5:{md5}")]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("consistent with 2 distinct contents"),
        "weak digest must not weld:\n{text}"
    );
    assert!(
        text.contains("possible collision"),
        "collision warning missing:\n{text}"
    );
    assert!(text.contains(&sha256_1) && text.contains(&sha256_2));

    // a strong-digest query touching one row stays a single cluster
    let out = env.hdx(&["--offline", &sha256_1]);
    assert!(out.status.success());
    assert!(!stdout(&out).contains("consistent with"));
}

// Digests of b"the quick brown fox jumps over the lazy dog\n" (44
// bytes — content must exceed the sub-digest identity floor).
const FOX_MD5: &str = "1e280e1713df124d35709cf6138d9f91";
const FOX_SHA1: &str = "5d2781d78fa5a97b7bafa849fe933dfc9dc93eba";
const FOX_SHA256: &str = "1153a4080f1fcb04425aa0b841c2b14606fe6df25d9076d2a1face2d5af57129";
// Digests of b"\n": the ubiquitous single-newline file, 1 byte —
// genuinely present in fatcat via a botched deposit.
const NL_MD5: &str = "68b329da9893e34099c7d8ad5cb9c940";
const NL_SHA1: &str = "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc";
const NL_SHA256: &str = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";

/// Scan resolves by default now: attributed files list themselves with
/// a compact claim line, and (with no network-mapped filters installed)
/// nothing touches the network. Files smaller than a sha256 digest are
/// never attributed — a digest can't identify content shorter than
/// itself, however many corpora register it.
#[test]
fn scan_resolves_by_default() {
    let env = TestEnv::new("scanresolve");
    install_fatcat_dataset(
        &env,
        &[
            (FOX_SHA1, FOX_SHA256, FOX_MD5),
            (NL_SHA1, NL_SHA256, NL_MD5),
        ],
    );
    env.write(
        "paper.pdf",
        b"the quick brown fox jumps over the lazy dog\n",
    );
    env.write("__init__.py", b"\n"); // sub-digest size: membership yes, identity no
    let out = env.hdx(&["scan", env.work().to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    let line = text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["path"].as_str().is_some_and(|p| p.ends_with("paper.pdf")))
        .expect("no per-file line (Attributed listing should include it)");
    let resolved = line["resolved"].as_array().expect("no resolved array");
    assert_eq!(resolved[0]["backend"], "fatcat");
    let summary = scan_summary(&out);
    assert_eq!(summary["attributed"], 1);

    // Text mode: one compact claim line per attributed file by default.
    // The newline file, though indexed under a real release, must not
    // appear — sub-digest content is unattributable.
    let out = env.hdx(&["scan", env.work().to_str().unwrap()]);
    let text = stdout(&out);
    assert!(text.contains("scholarly file"), "no claim line:\n{text}");
    assert!(text.contains("attributed"), "no attributed count:\n{text}");
    assert!(text.contains("paper.pdf"), "paper missing:\n{text}");
    assert!(
        !text.contains("__init__.py"),
        "sub-digest file attributed:\n{text}"
    );

    // --no-resolve is the classic census: summary only, no claims.
    let out = env.hdx(&["scan", env.work().to_str().unwrap(), "--no-resolve"]);
    let text = stdout(&out);
    assert!(!text.contains("scholarly file"), "census resolved:\n{text}");
    assert!(!text.contains("attributed"), "census attributed:\n{text}");
}

/// Scan attribution comes from primary clusters only: an index row
/// that shares nothing but a weak digest with the scanned file (the
/// file's own coords observation supplies the md5 hop) is about other
/// bytes and must not tag the file.
#[test]
fn scan_does_not_attribute_across_weak_digests() {
    let env = TestEnv::new("scanweak");
    // A fatcat row about DIFFERENT bytes that happens to share fox's md5.
    install_fatcat_dataset(&env, &[(&"9".repeat(40), &"8".repeat(64), FOX_MD5)]);
    let file = env.write("fox.txt", b"the quick brown fox jumps over the lazy dog\n");
    let out = env.hdx(&["coords", file.to_str().unwrap()]);
    assert!(out.status.success());

    let out = env.hdx(&["scan", env.work().to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        !text.contains("fatcat"),
        "md5-only row attributed to the file:\n{text}"
    );
}

/// Install a tiny ia-census dataset (data sharded by first sha1
/// nibble + md5 map), the layout `hdx index pull ia-census` produces.
fn install_census_dataset(env: &TestEnv, rows: &[(&str, &str, &str, &str)]) {
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

/// The weak-digest tier: a census row matching the file's sha1 (and
/// contradicting nothing) renders as "consistent (sha1)" with its
/// claim URL and counts separately from identified attributions — a
/// row that co-states a DIFFERENT sha256 alongside the matching sha1
/// describes other bytes and must stay silent.
#[test]
fn scan_weak_digest_consistent_tier() {
    let env = TestEnv::new("weaktier");
    // Filenames are stored percent-encoded, as in the real dump.
    install_census_dataset(
        &env,
        &[(
            FOX_SHA1,
            FOX_MD5,
            "fox-item.2016",
            "the%20fox%20%281%29%20%23video.mkv",
        )],
    );
    // A poisoned witness: matches fox's sha1 but claims different
    // sha256 bytes — the SHAttered shape, must not surface at all.
    install_fatcat_dataset(&env, &[(FOX_SHA1, &"7".repeat(64), &"6".repeat(32))]);
    env.write("fox.txt", b"the quick brown fox jumps over the lazy dog\n");

    let out = env.hdx(&["scan", env.work().to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("consistent (sha1): Internet Archive item fox-item.2016"),
        "no consistent-tier line:\n{text}"
    );
    // Statement decodes the stored name; the URL keeps it verbatim.
    assert!(
        text.contains("held these bytes as the fox (1) #video.mkv"),
        "statement not decoded:\n{text}"
    );
    assert!(
        text.contains("archive.org/download/fox-item.2016/the%20fox%20%281%29%20%23video.mkv"),
        "claim URL missing/re-encoded:\n{text}"
    );
    assert!(
        text.contains("1 consistent (weak digests only)"),
        "summary split missing:\n{text}"
    );
    assert!(
        !text.contains("fatcat") && !text.contains("scholarly"),
        "sha256-contradicted row surfaced:\n{text}"
    );

    // JSON: the tier is machine-readable and distinct from resolved.
    let out = env.hdx(&["scan", env.work().to_str().unwrap(), "--json"]);
    let text = stdout(&out);
    let line = text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["path"].as_str().is_some_and(|p| p.ends_with("fox.txt")))
        .expect("no per-file line for fox.txt");
    assert_eq!(line["consistent"][0]["backend"], "ia-census");
    assert_eq!(line["consistent"][0]["via"][0], "sha1");
    assert_eq!(line["resolved"].as_array().map(Vec::len), Some(0));
    let summary = scan_summary(&out);
    assert_eq!(summary["consistent"], 1);
    assert_eq!(summary["attributed"], 0);
    assert_eq!(summary["known"], 1);

    // Direct resolve by sha1 renders the census witness offline, and
    // the md5 map crosswalks to the same row.
    for hash in [format!("sha1:{FOX_SHA1}"), format!("md5:{FOX_MD5}")] {
        let out = env.hdx(&["--offline", &hash]);
        assert!(out.status.success(), "offline miss for {hash}");
        let text = stdout(&out);
        assert!(
            text.contains("Internet Archive item fox-item.2016"),
            "census witness missing for {hash}:\n{text}"
        );
    }
}

/// Naming a file directly must produce its per-file verdict even when
/// the only evidence is filter membership (no claims yet): a two-file
/// scan that prints nothing reads as "scan doesn't know these" when it
/// did. The summary also says why there are no claim lines.
#[test]
fn explicit_file_roots_always_listed() {
    let env = TestEnv::new("fileroot");
    let file = env.write("fox.txt", b"the quick brown fox jumps over the lazy dog\n");
    let list = env.digest_list("pub.sha256.txt", FOX_SHA256);
    let out = env.hdx(&["filters", "build", "pub", "sha256", list.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = env.hdx(&["scan", file.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("fox.txt"),
        "explicit file root not listed:\n{text}"
    );
    assert!(
        text.contains("membership only"),
        "no membership-only hint:\n{text}"
    );
    assert!(text.contains("--online"), "hint missing --online:\n{text}");
}

/// Mixed roots in one invocation: a directory (flat listing) and a
/// container file (tree section) share one member tree, one summary —
/// disk files and nested members counted separately.
#[test]
fn scan_mixes_directory_and_container_roots() {
    let env = TestEnv::new("mixedroots");
    let payload = b"mixed-roots payload: bytes the filter knows about\n";
    let payload_sha256 = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(payload);
        format!("{:x}", h.finalize())
    };
    // A directory root holding one loose copy of the payload…
    let dir = env.work().join("tree");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/loose.bin"), payload).unwrap();
    // …and a container-file root holding another.
    let tgz = {
        let mut tarball = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarball, flate2::Compression::default());
            let mut b = tar::Builder::new(enc);
            let mut h = tar::Header::new_gnu();
            h.set_size(payload.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "inside.bin", &payload[..]).unwrap();
            let enc = b.into_inner().unwrap();
            enc.finish().unwrap();
        }
        env.write("box.tar.gz", &tarball)
    };
    let list = env.digest_list("digests.txt", &payload_sha256);
    let out = env.hdx(&[
        "filters",
        "build",
        "mixsrc",
        "sha256",
        list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = env.hdx(&[
        "--offline",
        "scan",
        "--list",
        "known",
        dir.to_str().unwrap(),
        tgz.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    // Tree section: the container root, its wrapper, the tagged member.
    assert!(text.contains("box.tar.gz"), "{text}");
    assert!(text.contains("inside.bin"), "tree member missing:\n{text}");
    // Flat section: the loose disk file with its tag prefix.
    assert!(
        text.lines()
            .any(|l| l.starts_with("mixsrc") && l.contains("loose.bin")),
        "flat listing missing the disk file:\n{text}"
    );
    // Summary separates disk files from nested members.
    assert!(
        text.contains("2 files") && text.contains("nested member"),
        "summary should count disk files and nested members separately:\n{text}"
    );

    // JSON: summary object carries both tallies.
    let out = env.hdx(&[
        "--offline",
        "--json",
        "scan",
        dir.to_str().unwrap(),
        tgz.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let summary = scan_summary(&out);
    assert_eq!(summary["files"], 2, "disk files: loose.bin + box.tar.gz");
    assert!(
        summary["members"].as_u64().unwrap() >= 2,
        "nested members missing from summary: {summary}"
    );
}

/// Demand-driven descent policy for files discovered under directory
/// roots: by default only in-place-readable containers (zip here) are
/// entered, and only when unknown — a bloom-matched container stays
/// closed, a .tar.gz needs --deep, and --shallow keeps everything
/// closed.
#[test]
fn scan_descent_policy_notches() {
    use std::io::Write as _;
    let env = TestEnv::new("descent");
    let payload = b"descent-policy payload: bytes hiding inside containers\n";

    let tarball = |name: &str| {
        let mut buf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::default());
            let mut b = tar::Builder::new(enc);
            let mut h = tar::Header::new_gnu();
            h.set_size(payload.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, &payload[..]).unwrap();
            let enc = b.into_inner().unwrap();
            enc.finish().unwrap();
        }
        buf
    };
    let dir = env.work().join("tree");
    std::fs::create_dir_all(&dir).unwrap();
    // An unknown zip: cheap-descendable.
    let zip_bytes = {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        w.start_file("inside-zip.bin", opts).unwrap();
        w.write_all(payload).unwrap();
        w.finish().unwrap().into_inner()
    };
    std::fs::write(dir.join("mystery.zip"), &zip_bytes).unwrap();
    // An unknown .tar.gz: compressed wrapper, --deep territory.
    std::fs::write(dir.join("wrapped.tar.gz"), tarball("inside-tgz.bin")).unwrap();
    // A KNOWN tarball: its own sha256 is in a filter, so its identity
    // is settled and it must not be entered even by --deep.
    let known_tgz = tarball("inside-known.bin");
    let known_sha256 = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(&known_tgz);
        format!("{:x}", h.finalize())
    };
    std::fs::write(dir.join("known.tar.gz"), &known_tgz).unwrap();
    let list = env.digest_list("digests.txt", &known_sha256);
    let out = env.hdx(&[
        "filters",
        "build",
        "knownsrc",
        "sha256",
        list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    // Default (cheap): the zip opens, the wrappers stay closed.
    let out = env.hdx(&["--offline", "scan", "--list", "all", dir.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("inside-zip.bin"),
        "zip not descended:\n{text}"
    );
    assert!(
        !text.contains("inside-tgz.bin"),
        "cheap descent must not decompress a .tar.gz:\n{text}"
    );
    assert!(
        !text.contains("inside-known.bin"),
        "a filter-matched container must not be entered:\n{text}"
    );

    // --deep: the unknown wrapper opens too; the known one still not.
    let out = env.hdx(&[
        "--offline",
        "scan",
        "--deep",
        "--list",
        "all",
        dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("inside-tgz.bin"),
        "--deep must descend the .tar.gz:\n{text}"
    );
    assert!(
        !text.contains("inside-known.bin"),
        "demand-driven: known containers stay closed under --deep too:\n{text}"
    );

    // --shallow: nothing opens.
    let out = env.hdx(&[
        "--offline",
        "scan",
        "--shallow",
        "--list",
        "all",
        dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        !text.contains("inside-zip.bin"),
        "--shallow must not descend anything:\n{text}"
    );

    // Explicitly naming the known tarball still gets the full
    // hashoscope — pointing at it is the demand.
    let known_path = dir.join("known.tar.gz");
    let out = env.hdx(&["--offline", "scan", known_path.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("inside-known.bin"),
        "explicit file roots always descend:\n{text}"
    );

    // The flags exclude each other.
    let out = env.hdx(&["scan", "--deep", "--shallow", dir.to_str().unwrap()]);
    assert!(!out.status.success());
}

/// The content-addressed member cache: a descended container's member
/// tree replays on later scans without re-reading the container —
/// proven by corrupting the container's bytes in place (size and
/// mtime preserved, so the index still vouches for it) and watching
/// the members survive. Bloom matches are recomputed on replay
/// (a filter built AFTER the descent still tags cached members), and
/// --rehash forces a real re-read.
#[test]
fn scan_member_cache_replays_descents() {
    use std::io::Write as _;
    let env = TestEnv::new("membercache");
    let payload = b"member-cache payload: cached bytes with a late filter\n";
    let payload_sha256 = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(payload);
        format!("{:x}", h.finalize())
    };
    let dir = env.work().join("tree");
    std::fs::create_dir_all(&dir).unwrap();
    let zip_bytes = {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        w.start_file("cached-member.bin", opts).unwrap();
        w.write_all(payload).unwrap();
        w.finish().unwrap().into_inner()
    };
    let zpath = dir.join("box.zip");
    std::fs::write(&zpath, &zip_bytes).unwrap();

    // First scan: descends, lists the member, caches the tree.
    let out = env.hdx(&["--offline", "scan", "--list", "all", dir.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("cached-member.bin"),
        "{}",
        stdout(&out)
    );

    // A filter that knows the member arrives AFTER the descent.
    let list = env.digest_list("digests.txt", &payload_sha256);
    let out = env.hdx(&[
        "filters",
        "build",
        "latesrc",
        "sha256",
        list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    // Corrupt the container in place — same size, mtime restored — so
    // any attempt to actually re-read it would find zeros (not a zip).
    let mtime = std::fs::metadata(&zpath).unwrap().modified().unwrap();
    std::fs::write(&zpath, vec![0u8; zip_bytes.len()]).unwrap();
    let f = std::fs::File::options().write(true).open(&zpath).unwrap();
    f.set_modified(mtime).unwrap();
    drop(f);

    // Second scan: the member is still there (replay — the zeros were
    // never read) AND wears the late filter's tag (blooms recomputed).
    let out = env.hdx(&["--offline", "scan", "--list", "all", dir.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("cached-member.bin"),
        "cached descent did not replay:\n{text}"
    );
    assert!(
        text.contains("[latesrc]"),
        "replayed member missing the late filter's tag:\n{text}"
    );

    // --rehash forces the real read: zeros sniff as nothing, so the
    // member disappears.
    let out = env.hdx(&[
        "--offline",
        "scan",
        "--rehash",
        "--list",
        "all",
        dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        !text.contains("cached-member.bin"),
        "--rehash must re-read, not replay:\n{text}"
    );
}

#[test]
fn fetch_registry_works_offline() {
    let env = TestEnv::new("fetch");
    // no names: list the registry, no network
    let out = env.hdx(&["filters", "fetch"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    for name in [
        "circl",
        "rpm-files",
        "fatcat",
        "depsdev",
        "rekor",
        "swh",
        "tarballs",
        "ia-census",
    ] {
        assert!(text.contains(name), "registry listing missing {name}");
    }

    // unknown names are rejected before any download starts
    let out = env.hdx(&["filters", "fetch", "nosuchfilter"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown filter name"));

    // --from requires a NAME.SCHEME argument
    let out = env.hdx(&["filters", "fetch", "--from", "http://localhost:1/x.bloom"]);
    assert!(!out.status.success());
}

/// hdx's own cache (dumps, extracts, filters, local.db) must not pollute
/// scan metrics; an explicit scan root inside the cache still works.
#[test]
fn scan_excludes_own_cache_dir() {
    let env = TestEnv::new("owncache");
    env.write("real.txt", b"some real file");
    let cache_junk = env.root.join("cache/hashdex/extracts");
    std::fs::create_dir_all(&cache_junk).unwrap();
    std::fs::write(cache_junk.join("dump.tsv"), b"cached artifact bytes").unwrap();

    // A scan whose root contains the cache prunes the cache subtree.
    let out = env.hdx(&["scan", env.root.to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let summary = scan_summary(&out);
    assert_eq!(
        summary["files"], 1,
        "expected only work/real.txt: {summary}"
    );
    assert!(
        stderr(&out).contains("excluding hashdex's own cache"),
        "no exclusion notice: {}",
        stderr(&out)
    );

    // A root inside the cache is an explicit request — nothing is pruned.
    let out = env.hdx(&["scan", cache_junk.to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let summary = scan_summary(&out);
    assert_eq!(summary["files"], 1, "explicit cache scan saw: {summary}");
    assert!(!stderr(&out).contains("excluding hashdex's own cache"));
}

/// Unreadable files are a summary state at the end of the scan, not a
/// stream of warnings while it runs.
#[test]
#[cfg(unix)]
fn scan_reports_unreadable_at_end() {
    use std::os::unix::fs::PermissionsExt;
    let env = TestEnv::new("unreadable");
    env.write("ok.txt", b"readable");
    let locked = env.write("locked.txt", b"secret");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&locked).is_ok() {
        // Running as root (CAP_DAC_OVERRIDE): chmod 000 can't make the
        // file unreadable, so there is nothing to assert.
        return;
    }

    let out = env.hdx(&["scan", env.work().to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let summary = scan_summary(&out);
    assert_eq!(summary["files"], 1, "{summary}");
    assert_eq!(summary["unreadable"], 1, "{summary}");
    // The path appears in the end-of-scan detail, not as a warning line.
    assert!(
        stderr(&out).contains("locked.txt"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("warning: "),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn scan_online_conflicts_with_no_resolve() {
    let env = TestEnv::new("onlinearg");
    let out = env.hdx(&[
        "scan",
        env.work().to_str().unwrap(),
        "--no-resolve",
        "--online",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no-resolve"),
        "stderr: {}",
        stderr(&out)
    );
}

/// The hashoscope: scanning an explicitly named container file
/// descends gzip→tar and ar→gzip→tar chains, tags members against
/// filters, honors the identity floor, and reports containers it
/// cannot enter. Fixtures are built with the same crates the binary
/// uses — the test proves the walk, not the format libraries.
#[test]
fn scan_descends_container_roots() {
    use std::io::Write as _;
    let env = TestEnv::new("peek");

    // Member content with a known digest, plus a sub-floor member.
    let payload = b"hashoscope test payload: the bytes inside the container\n";
    let payload_sha256 = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(payload);
        format!("{:x}", h.finalize())
    };

    // t.tar.gz: dir/payload.txt (identifiable) + tiny (below floor)
    let tgz = {
        let mut tarball = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarball, flate2::Compression::default());
            let mut b = tar::Builder::new(enc);
            let mut h = tar::Header::new_gnu();
            h.set_size(payload.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "dir/payload.txt", &payload[..])
                .unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(2);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "dir/tiny", &b"a\n"[..]).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        env.write("t.tar.gz", &tarball)
    };

    // d.ar: deb-shaped — debian-binary + data.tar.gz (nested chain)
    let deb = {
        let mut inner = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut inner, flate2::Compression::default());
            let mut b = tar::Builder::new(enc);
            let mut h = tar::Header::new_gnu();
            h.set_size(payload.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "usr/share/doc/payload.txt", &payload[..])
                .unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let mut arbytes = Vec::new();
        {
            let mut b = ar::Builder::new(&mut arbytes);
            b.append(
                &ar::Header::new(b"debian-binary".to_vec(), 4),
                &b"2.0\n"[..],
            )
            .unwrap();
            b.append(
                &ar::Header::new(b"data.tar.gz".to_vec(), inner.len() as u64),
                &inner[..],
            )
            .unwrap();
        }
        env.write("d.ar", &arbytes)
    };

    // A filter that knows the payload digest (padded per the bloom
    // sizing gotcha), installed as "peeksrc".
    let list = env.digest_list("digests.txt", &payload_sha256);
    let out = env.hdx(&[
        "filters",
        "build",
        "peeksrc",
        "sha256",
        list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    // Tarball: container line, decompressed pseudo-member, tagged member,
    // floor member.
    let out = env.hdx(&["--offline", "scan", tgz.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("t.tar.gz"), "{text}");
    assert!(
        text.contains("t.tar —"),
        "no decompressed pseudo-member:\n{text}"
    );
    assert!(text.contains("payload.txt"), "{text}");
    assert!(text.contains("[peeksrc]"), "member not tagged:\n{text}");
    assert!(text.contains("below identity floor"), "{text}");
    // Container verdicts are recursive: the gz line rolls up leaves
    // from two levels down (the known payload + the sub-floor member).
    assert!(
        text.contains("(2 members: 1 known, 1 below floor)"),
        "no recursive rollup:\n{text}"
    );

    // Deb-shaped ar: the nested chain ar→gz→tar reaches the same bytes.
    // JSON mode emits one object per member (NDJSON) plus a summary.
    let out = env.hdx(&["--offline", "--json", "scan", deb.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let members: Vec<serde_json::Value> = stdout(&out)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|v: &serde_json::Value| v.get("depth").is_some())
        .collect();
    let deep = members
        .iter()
        .find(|m| {
            m["path"]
                .as_str()
                .unwrap()
                .ends_with("usr/share/doc/payload.txt")
        })
        .expect("nested member missing");
    assert_eq!(deep["depth"], 3, "ar→gz→tar should be three levels down");
    assert!(
        deep["filters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "peeksrc"),
        "nested member not tagged: {deep}"
    );
    assert!(
        deep["coords"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str().unwrap().contains(&payload_sha256)),
        "sha256 coordinate missing: {deep}"
    );

    // cpio (newc, hand-rolled parser): one file + trailer.
    let mut cpio = Vec::new();
    let name = b"member.txt\0";
    write!(
        cpio,
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        1,
        0o100644,
        0,
        0,
        1,
        0,
        payload.len(),
        0,
        0,
        0,
        0,
        name.len(),
        0
    )
    .unwrap();
    cpio.extend_from_slice(name);
    while (cpio.len()) % 4 != 0 {
        cpio.push(0);
    }
    cpio.extend_from_slice(payload);
    while (cpio.len()) % 4 != 0 {
        cpio.push(0);
    }
    let trailer = b"TRAILER!!!\0";
    write!(
        cpio,
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        trailer.len(),
        0
    )
    .unwrap();
    cpio.extend_from_slice(trailer);
    while cpio.len() % 4 != 0 {
        cpio.push(0);
    }
    let cpio_file = env.write("t.cpio", &cpio);
    let out = env.hdx(&["--offline", "scan", cpio_file.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("member.txt"), "{text}");
    assert!(
        text.contains("[peeksrc]"),
        "cpio member not tagged:\n{text}"
    );

    // iso9660 (hand-rolled walker): minimal image — PVD at sector 16
    // pointing at a root directory holding one file.
    let iso = {
        let mut img = vec![0u8; 22 * 2048];
        let pvd = 16 * 2048;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        let r = pvd + 156; // root record: lba 20, one sector, dir flag
        img[r] = 34;
        img[r + 2..r + 6].copy_from_slice(&20u32.to_le_bytes());
        img[r + 10..r + 14].copy_from_slice(&2048u32.to_le_bytes());
        img[r + 25] = 0x02;
        img[r + 32] = 1;
        let term = 17 * 2048;
        img[term] = 255;
        img[term + 1..term + 6].copy_from_slice(b"CD001");
        img[term + 6] = 1;
        let d = 20 * 2048; // root directory: one file record
        let name = b"PAYLOAD.TXT;1";
        img[d] = (33 + name.len()) as u8;
        img[d + 2..d + 6].copy_from_slice(&21u32.to_le_bytes());
        img[d + 10..d + 14].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        img[d + 32] = name.len() as u8;
        img[d + 33..d + 33 + name.len()].copy_from_slice(name);
        img[21 * 2048..21 * 2048 + payload.len()].copy_from_slice(payload);
        env.write("t.iso", &img)
    };
    let out = env.hdx(&["--offline", "scan", iso.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("PAYLOAD.TXT"), "iso member missing:\n{text}");
    assert!(text.contains("[peeksrc]"), "iso member not tagged:\n{text}");
}

/// Zips take three routes through the container walk: a seekable root walks the
/// central directory directly (stored entries as range views), a
/// stream-fed zip is walked speculatively from its local headers and
/// reconciled against the central directory, and a MISBEHAVED stream
/// zip (here: a local entry hidden from the central directory)
/// triggers one conservative re-descent that spools and trusts only
/// the central directory.
#[test]
fn scan_zip_speculative_and_conservative() {
    use std::io::Write as _;
    let env = TestEnv::new("peekzip");

    let payload = b"hashoscope zip payload: bytes the filter knows\n";
    let payload_sha256 = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(payload);
        format!("{:x}", h.finalize())
    };
    let list = env.digest_list("digests.txt", &payload_sha256);
    let out = env.hdx(&[
        "filters",
        "build",
        "peeksrc",
        "sha256",
        list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    // A well-formed zip: one stored entry (readable as a range view)
    // and one deflated entry (streamed).
    let zip_bytes = {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("stored.txt", stored).unwrap();
        w.write_all(payload).unwrap();
        let deflated = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        w.start_file("deflated.txt", deflated).unwrap();
        w.write_all(payload).unwrap();
        w.finish().unwrap().into_inner()
    };

    // Root zip = seekable: both entries attributed, no retry.
    let zip_file = env.write("t.zip", &zip_bytes);
    let out = env.hdx(&["--offline", "scan", zip_file.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("stored.txt"), "{text}");
    assert!(text.contains("deflated.txt"), "{text}");
    assert_eq!(
        text.matches("[peeksrc]").count(),
        2,
        "both zip entries should carry the filter tag:\n{text}"
    );

    // The same zip behind gzip = stream-fed: the speculative walk must
    // agree with the central directory and NOT trigger a re-descent.
    let zgz = {
        let mut gz = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        enc.write_all(&zip_bytes).unwrap();
        enc.finish().unwrap();
        env.write("t.zip.gz", &gz)
    };
    let out = env.hdx(&["--offline", "scan", zgz.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("stored.txt"), "{text}");
    assert!(text.contains("deflated.txt"), "{text}");
    assert!(
        !stderr(&out).contains("re-reading"),
        "well-formed stream zip must not retry: {}",
        stderr(&out)
    );

    // Misbehave: drop the second entry's central-directory record so a
    // local entry exists that the directory never mentions. The
    // speculative walk sees it, the reconcile fails, and the whole
    // root re-descends conservatively (central directory only).
    let tampered = {
        let eocd = zip_bytes.len() - 22;
        assert_eq!(&zip_bytes[eocd..eocd + 4], &[0x50, 0x4b, 0x05, 0x06]);
        let cd_size =
            u32::from_le_bytes(zip_bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
        let cd_off =
            u32::from_le_bytes(zip_bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let cd = &zip_bytes[cd_off..cd_off + cd_size];
        let second = 4 + cd[4..]
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .expect("second central record");
        let mut out = zip_bytes[..cd_off + second].to_vec();
        let mut eocd_rec = zip_bytes[eocd..].to_vec();
        eocd_rec[8..10].copy_from_slice(&1u16.to_le_bytes());
        eocd_rec[10..12].copy_from_slice(&1u16.to_le_bytes());
        eocd_rec[12..16].copy_from_slice(&(second as u32).to_le_bytes());
        out.extend_from_slice(&eocd_rec);
        out
    };
    let tgz = {
        let mut gz = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        enc.write_all(&tampered).unwrap();
        enc.finish().unwrap();
        env.write("bad.zip.gz", &gz)
    };
    let out = env.hdx(&["--offline", "scan", tgz.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("re-reading"),
        "hidden entry must trigger the conservative retry: {err}"
    );
    let text = stdout(&out);
    assert!(
        text.contains("stored.txt"),
        "central-directory entry missing after retry:\n{text}"
    );
    assert!(
        !text.contains("deflated.txt"),
        "hidden entry must not be listed as a member:\n{text}"
    );
}

/// A seek-needing container behind compression (here: an iso in gzip)
/// still works — it spools, and its members resolve as views over the
/// spool.
#[test]
fn scan_spools_streamed_iso() {
    use std::io::Write as _;
    let env = TestEnv::new("peekspool");

    let payload = b"hashoscope iso payload: bytes inside the image\n";
    // Minimal iso: PVD at sector 16, terminator, root dir with one file.
    let mut img = vec![0u8; 22 * 2048];
    let pvd = 16 * 2048;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    img[pvd + 6] = 1;
    let r = pvd + 156;
    img[r] = 34;
    img[r + 2..r + 6].copy_from_slice(&20u32.to_le_bytes());
    img[r + 10..r + 14].copy_from_slice(&2048u32.to_le_bytes());
    img[r + 25] = 0x02;
    img[r + 32] = 1;
    let term = 17 * 2048;
    img[term] = 255;
    img[term + 1..term + 6].copy_from_slice(b"CD001");
    img[term + 6] = 1;
    let d = 20 * 2048;
    let name = b"PAYLOAD.TXT;1";
    img[d] = (33 + name.len()) as u8;
    img[d + 2..d + 6].copy_from_slice(&21u32.to_le_bytes());
    img[d + 10..d + 14].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    img[d + 32] = name.len() as u8;
    img[d + 33..d + 33 + name.len()].copy_from_slice(name);
    img[21 * 2048..21 * 2048 + payload.len()].copy_from_slice(payload);

    let gz = {
        let mut gz = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        enc.write_all(&img).unwrap();
        enc.finish().unwrap();
        // The unwrapped pseudo-member is a stream, so the iso is
        // recognized by its name (the CD001 magic at 32769 is out of
        // sniffing reach for streams) and spooled to walk.
        env.write("image.iso.gz", &gz)
    };
    let out = env.hdx(&["--offline", "scan", gz.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("PAYLOAD.TXT"),
        "iso member missing through the spool path:\n{text}"
    );
}

/// A misbehaved zip inside a squashfs file triggers a LOCALIZED
/// conservative retry: the squashfs file is re-derivable on its own,
/// so only that one member is redone — the note names the member, not
/// the image — and its siblings keep their verdicts.
#[test]
fn scan_retry_is_localized_to_the_squashfs_file() {
    use std::io::Write as _;
    let env = TestEnv::new("peeksquash");

    let payload = b"hashoscope squashfs payload: known sibling bytes\n";
    let payload_sha256 = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(payload);
        format!("{:x}", h.finalize())
    };
    let list = env.digest_list("digests.txt", &payload_sha256);
    let out = env.hdx(&[
        "filters",
        "build",
        "peeksrc",
        "sha256",
        list.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    // A zip whose second entry is hidden from the central directory —
    // the same tampering as the stream test, this time nested inside a
    // squashfs file so the retry has a cheap boundary to catch at.
    let tampered_zip = {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        w.start_file("listed.txt", opts).unwrap();
        w.write_all(payload).unwrap();
        w.start_file("hidden.txt", opts).unwrap();
        w.write_all(b"the directory never heard of me").unwrap();
        let bytes = w.finish().unwrap().into_inner();
        let eocd = bytes.len() - 22;
        assert_eq!(&bytes[eocd..eocd + 4], &[0x50, 0x4b, 0x05, 0x06]);
        let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
        let cd_off = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let cd = &bytes[cd_off..cd_off + cd_size];
        let second = 4 + cd[4..]
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .expect("second central record");
        let mut t = bytes[..cd_off + second].to_vec();
        let mut eocd_rec = bytes[eocd..].to_vec();
        eocd_rec[8..10].copy_from_slice(&1u16.to_le_bytes());
        eocd_rec[10..12].copy_from_slice(&1u16.to_le_bytes());
        eocd_rec[12..16].copy_from_slice(&(second as u32).to_le_bytes());
        t.extend_from_slice(&eocd_rec);
        t
    };

    // squashfs: the tampered zip plus an honest sibling the filter
    // knows, written with the same crate the binary reads with.
    let squash = {
        let header = backhand::NodeHeader::new(0o644, 0, 0, 0);
        let mut w = backhand::FilesystemWriter::default();
        w.push_file(&tampered_zip[..], "bad.zip", header).unwrap();
        w.push_file(&payload[..], "sibling.txt", header).unwrap();
        let mut img = std::io::Cursor::new(Vec::new());
        w.write(&mut img).unwrap();
        env.write("t.squashfs", &img.into_inner())
    };

    let out = env.hdx(&["--offline", "scan", squash.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let err = stderr(&out);
    // The retry note names the squashfs member, not the image root.
    assert!(
        err.contains("re-reading") && err.contains("bad.zip"),
        "expected a localized retry note naming the member: {err}"
    );
    assert!(
        !err.contains(&format!("re-reading {} with spooling", squash.display())),
        "retry must not redo the whole image: {err}"
    );
    let text = stdout(&out);
    assert!(
        text.contains("listed.txt"),
        "central-directory entry missing after localized retry:\n{text}"
    );
    assert!(
        !text.contains("hidden.txt"),
        "hidden entry must not survive the conservative re-walk:\n{text}"
    );
    assert!(
        text.contains("sibling.txt") && text.contains("[peeksrc]"),
        "sibling verdicts must survive the retry:\n{text}"
    );
    // Exactly one member line for the zip — the abandoned first
    // attempt must not leave a duplicate.
    assert_eq!(
        text.matches("bad.zip —").count(),
        1,
        "discarded slots leaked into the listing:\n{text}"
    );
}

// ---------------------------------------------------------------- recipe

/// An uncompressed GNU tar — every member is a byte range of the root,
/// which is what splice recipes reference.
fn plain_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// (sha1, sha256, md5) of some bytes — a fixture-dataset row: refs
/// require claims now, so recipe tests register their members.
fn digest_row(bytes: &[u8]) -> (String, String, String) {
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

#[test]
fn recipe_splices_a_plain_tar() {
    let env = TestEnv::new("recipe-tar");
    let big = vec![0xA5u8; 5000];
    let mid: Vec<u8> = (0u8..=255).cycle().take(600).collect();
    let rows = [digest_row(&big), digest_row(&mid)];
    let rows: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_str()))
        .collect();
    install_fatcat_dataset(&env, &rows);
    let tarball = plain_tar(&[("a.bin", &big), ("tiny", b"tiny"), ("b.bin", &mid)]);
    let tar_path = env.write("demo.tar", &tarball);

    let out = env.hdx(&["--offline", "recipe", tar_path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("verified byte-exact"),
        "summary: {}",
        stdout(&out)
    );

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.recipe.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["hdx_recipe"], "0");
    assert_eq!(doc["source"]["sha256"], sha256_hex(&tarball).as_str());
    let build = &doc["root"]["build"];
    assert_eq!(build["builder"], "splice@0");
    let inputs = build["inputs"].as_array().unwrap();
    let refs: Vec<&str> = inputs
        .iter()
        .filter_map(|i| i["ref"]["name"].as_str())
        .collect();
    // The sub-floor member folds into the literals; the real payloads
    // are referenced in tar order.
    assert_eq!(refs, vec!["a.bin", "b.bin"]);
    assert!(inputs.iter().any(|i| i["literal"].is_object()));
    // Refs exist only through claims (the fixture dataset registers
    // the two payloads); residue = everything no claim URL fetches.
    let cov = &doc["coverage"];
    assert_eq!(cov["fetchable_bytes"].as_u64().unwrap(), 5600);
    assert_eq!(
        cov["fetchable_bytes"].as_u64().unwrap() + cov["residue_bytes"].as_u64().unwrap(),
        cov["total_bytes"].as_u64().unwrap()
    );

    // Rebuild from blobs matched by content — names are irrelevant.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("first"), &big).unwrap();
    std::fs::write(blobs.join("second"), &mid).unwrap();
    let rebuilt = env.work().join("rebuilt.tar");
    let recipe = env.work().join("demo.tar.recipe.json");
    let out = env.hdx(&[
        "recipe",
        "check",
        recipe.to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert!(stdout(&out).contains("rebuilt byte-exact"));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tarball);

    // A member absent from the blob dir fails the check by name and
    // digest; a tampered blob is the same case (matched by content).
    std::fs::remove_file(blobs.join("second")).unwrap();
    let out = env.hdx(&[
        "recipe",
        "check",
        recipe.to_str().unwrap(),
        blobs.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let se = stderr(&out);
    assert!(se.contains("missing: b.bin"), "stderr: {se}");
    assert!(se.contains(&sha256_hex(&mid)), "stderr: {se}");
    assert!(se.contains("web.archive.org"), "claim URL missing: {se}");
}

#[test]
fn recipe_nests_and_rebuilds_from_leaves() {
    let env = TestEnv::new("recipe-nest");
    let pay1 = vec![1u8; 700];
    let pay2 = vec![2u8; 800];
    let pay3 = vec![3u8; 900];
    // Leaves are claimed; the inner tar itself is not — it survives
    // as a build only because its subtree holds verified refs.
    let rows = [digest_row(&pay1), digest_row(&pay2), digest_row(&pay3)];
    let rows: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_str()))
        .collect();
    install_fatcat_dataset(&env, &rows);
    let inner = plain_tar(&[("inner-a.bin", &pay1), ("inner-b.bin", &pay2)]);
    let outer = plain_tar(&[("inner.tar", &inner), ("outer-c.bin", &pay3)]);
    let outer_path = env.write("outer.tar", &outer);

    let out = env.hdx(&["--offline", "recipe", outer_path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("outer.tar.recipe.json")).unwrap(),
    )
    .unwrap();
    // The inner tar is a build nested inside the root's splice, with
    // its own refs.
    let inputs = doc["root"]["build"]["inputs"].as_array().unwrap();
    let nested = inputs
        .iter()
        .find(|i| i["build"]["name"] == "inner.tar")
        .expect("inner tar must nest as a build");
    let nested_refs: Vec<&str> = nested["build"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["ref"]["name"].as_str())
        .collect();
    assert_eq!(nested_refs, vec!["inner-a.bin", "inner-b.bin"]);

    // The whole outer container rebuilds from leaf payloads alone —
    // no copy of inner.tar needed.
    let blobs = env.work().join("leaves");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("one"), &pay1).unwrap();
    std::fs::write(blobs.join("two"), &pay2).unwrap();
    std::fs::write(blobs.join("three"), &pay3).unwrap();
    let rebuilt = env.work().join("outer-rebuilt.tar");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("outer.tar.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), outer);
}

#[test]
fn recipe_wrapped_root_is_all_residue() {
    use std::io::Write as _;
    let env = TestEnv::new("recipe-tgz");
    let tarball = plain_tar(&[("inside.bin", &vec![7u8; 400])]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tarball).unwrap();
    let tgz = gz.finish().unwrap();
    let path = env.write("demo.tar.gz", &tgz);

    // Nothing behind the compressed wrapper is a byte range of the
    // root — the honest recipe is a full copy, and it says so.
    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("full literal copy"),
        "summary: {}",
        stdout(&out)
    );
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.gz.recipe.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["coverage"]["fetchable_bytes"], 0);
    assert_eq!(
        doc["coverage"]["residue_bytes"],
        doc["coverage"]["total_bytes"]
    );

    // Totality: even the trivial recipe rebuilds — from the residue
    // alone, with an empty blob dir.
    let blobs = env.work().join("empty");
    std::fs::create_dir_all(&blobs).unwrap();
    let rebuilt = env.work().join("rebuilt.tar.gz");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("demo.tar.gz.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tgz);
}

/// Run the system's GNU gzip (what mint's compressor search and
/// check's rebuild shell out to — the gzip@0 tests need it on PATH).
fn system_gzip(args: &[&str], input: &[u8]) -> Vec<u8> {
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
fn noisy_payload(len: usize, mut seed: u64) -> Vec<u8> {
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

#[test]
fn recipe_gzip_chain_mints_and_rebuilds() {
    let env = TestEnv::new("recipe-gzip");
    let pay1 = noisy_payload(40_000, 7);
    let pay2 = noisy_payload(25_000, 99);
    let rows = [digest_row(&pay1), digest_row(&pay2)];
    let rows: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_str()))
        .collect();
    install_fatcat_dataset(&env, &rows);
    let tarball = plain_tar(&[("one.bin", &pay1), ("two.bin", &pay2)]);
    let tgz = system_gzip(&["-9"], &tarball);
    let path = env.write("demo.tar.gz", &tgz);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("compressors: gnu-9"), "summary: {so}");
    assert!(so.contains("verified byte-exact"), "summary: {so}");

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.gz.recipe.json")).unwrap(),
    )
    .unwrap();
    let root = &doc["root"]["build"];
    assert_eq!(root["builder"], "gzip@0");
    assert_eq!(root["params"]["compressor"], "gnu-9");
    // `-n` to stdout writes the fixed 10-byte header.
    assert_eq!(
        root["params"]["header_hex"].as_str().unwrap().len(),
        20,
        "header: {}",
        root["params"]["header_hex"]
    );
    assert_eq!(root["output"]["sha256"], sha256_hex(&tgz).as_str());
    let inner = &root["inputs"][0]["build"];
    assert_eq!(inner["builder"], "splice@0");
    let refs: Vec<&str> = inner["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["ref"]["name"].as_str())
        .collect();
    assert_eq!(refs, vec!["one.bin", "two.bin"]);
    // Refs and literals live in the decompressed space now — the
    // coverage ratio is between them, not against the compressed size.
    let cov = &doc["coverage"];
    assert_eq!(cov["fetchable_bytes"].as_u64().unwrap(), 65_000);
    assert_eq!(cov["total_bytes"].as_u64().unwrap(), tgz.len() as u64);

    // The compressed root rebuilds from the leaf payloads alone.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("p1"), &pay1).unwrap();
    std::fs::write(blobs.join("p2"), &pay2).unwrap();
    let rebuilt = env.work().join("rebuilt.tar.gz");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("demo.tar.gz.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tgz);
}

#[test]
fn recipe_gzip_chains_nest() {
    // tar.gz inside tar.gz: the inner wrapper's compressor search and
    // splice run in the OUTER spool's coordinate space, not the root
    // file's — the whole space machinery in one fixture.
    let env = TestEnv::new("recipe-gzip-nest");
    let pay = noisy_payload(30_000, 3);
    let row = digest_row(&pay);
    install_fatcat_dataset(&env, &[(&row.0, &row.1, &row.2)]);
    let inner_tar = plain_tar(&[("leaf.bin", &pay)]);
    let inner_tgz = system_gzip(&["-9"], &inner_tar);
    let outer_tar = plain_tar(&[("inner.tar.gz", &inner_tgz)]);
    let outer_tgz = system_gzip(&["-6"], &outer_tar);
    let path = env.write("outer.tar.gz", &outer_tgz);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("outer.tar.gz.recipe.json")).unwrap(),
    )
    .unwrap();
    // gzip@0 → splice@0 → gzip@0 → splice@0 → ref, alternating spaces.
    let outer = &doc["root"]["build"];
    assert_eq!(outer["builder"], "gzip@0");
    assert_eq!(outer["params"]["compressor"], "gnu-6");
    let outer_splice = &outer["inputs"][0]["build"];
    assert_eq!(outer_splice["builder"], "splice@0");
    let inner = outer_splice["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["build"]["builder"] == "gzip@0")
        .expect("nested gzip@0 node");
    assert_eq!(inner["build"]["params"]["compressor"], "gnu-9");
    let inner_splice = &inner["build"]["inputs"][0]["build"];
    assert_eq!(inner_splice["builder"], "splice@0");
    assert_eq!(inner_splice["inputs"][1]["ref"]["name"], "leaf.bin");

    // The doubly-compressed root rebuilds from the one leaf payload.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("p"), &pay).unwrap();
    let rebuilt = env.work().join("rebuilt.tar.gz");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work()
            .join("outer.tar.gz.recipe.json")
            .to_str()
            .unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), outer_tgz);
}

#[test]
fn recipe_gzip_chain_finds_rsyncable() {
    let env = TestEnv::new("recipe-gzip-rsync");
    let pay = noisy_payload(120_000, 42);
    let row = digest_row(&pay);
    install_fatcat_dataset(&env, &[(&row.0, &row.1, &row.2)]);
    let tarball = plain_tar(&[("data.bin", &pay)]);
    let plain = system_gzip(&["-9"], &tarball);
    let rsync = system_gzip(&["-9", "--rsyncable"], &tarball);
    // The payload is long enough that the rolling-window resets fire —
    // otherwise this test would be telling us nothing.
    assert_ne!(plain, rsync, "payload too small to distinguish rsyncable");
    let path = env.write("demo.tar.gz", &rsync);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.gz.recipe.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        doc["root"]["build"]["params"]["compressor"],
        "gnu-9-rsyncable"
    );
}

#[test]
fn recipe_gzip_header_with_name_round_trips() {
    let env = TestEnv::new("recipe-gzip-name");
    let pay = noisy_payload(30_000, 5);
    let row = digest_row(&pay);
    install_fatcat_dataset(&env, &[(&row.0, &row.1, &row.2)]);
    let tarball = plain_tar(&[("file.bin", &pay)]);
    // Compress a real file WITHOUT -n: the header embeds the original
    // name and mtime. The recipe records those bytes verbatim and the
    // rebuild splices them back — the compressor never sees them.
    let inner = env.write("inner.tar", &tarball);
    let st = std::process::Command::new("gzip")
        .args(["-9", "inner.tar"])
        .current_dir(env.work())
        .status()
        .expect("GNU gzip on PATH");
    assert!(st.success());
    let tgz = std::fs::read(env.work().join("inner.tar.gz")).unwrap();
    drop(inner);

    let out = env.hdx(&[
        "--offline",
        "recipe",
        env.work().join("inner.tar.gz").to_str().unwrap(),
    ]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("inner.tar.gz.recipe.json")).unwrap(),
    )
    .unwrap();
    let header = doc["root"]["build"]["params"]["header_hex"]
        .as_str()
        .unwrap();
    assert!(header.len() > 20, "expected FNAME in header: {header}");
    assert!(
        header.contains(&data_encoding::HEXLOWER.encode(b"inner.tar")),
        "embedded name missing from header: {header}"
    );

    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("p"), &pay).unwrap();
    let rebuilt = env.work().join("rebuilt.tar.gz");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work()
            .join("inner.tar.gz.recipe.json")
            .to_str()
            .unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tgz);
}

#[test]
fn recipe_unreproducible_gzip_stays_literal() {
    use std::io::Write as _;
    let env = TestEnv::new("recipe-gzip-alien");
    // The member IS claimed — the chain fails only because no catalog
    // compressor reproduces a flate2-compressed stream. The planned
    // child subtree must be discarded, not half-kept.
    let pay = noisy_payload(20_000, 11);
    let row = digest_row(&pay);
    install_fatcat_dataset(&env, &[(&row.0, &row.1, &row.2)]);
    let tarball = plain_tar(&[("data.bin", &pay)]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
    gz.write_all(&tarball).unwrap();
    let tgz = gz.finish().unwrap();
    let path = env.write("demo.tar.gz", &tgz);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("full literal copy"),
        "summary: {}",
        stdout(&out)
    );
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.gz.recipe.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["coverage"]["fetchable_bytes"], 0);
    // Totality holds: rebuilds from residue alone.
    let blobs = env.work().join("empty");
    std::fs::create_dir_all(&blobs).unwrap();
    let rebuilt = env.work().join("rebuilt.tar.gz");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("demo.tar.gz.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tgz);
}

#[test]
fn recipe_disarchive_projection_matches_git() {
    let env = TestEnv::new("recipe-disarchive");
    // No dataset: the chain survives via the structural fallback
    // (gzip@0 over a literal tar), which is exactly what the
    // disarchive projection needs — its content store is SWH, not
    // our refs.
    let pay1 = noisy_payload(20_000, 21);
    let pay2 = noisy_payload(9_000, 22);
    let tarball = {
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |name: &str, mode: u32, data: &[u8]| {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(mode);
            h.set_mtime(1700000000);
            h.set_cksum();
            b.append_data(&mut h, name, data).unwrap();
        };
        add("pkg-1.0/README", 0o644, &pay1);
        add("pkg-1.0/bin/tool", 0o755, &pay2);
        b.into_inner().unwrap()
    };
    let tgz = system_gzip(&["-9"], &tarball);
    let path = env.write("pkg-1.0.tar.gz", &tgz);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    disarchive::emit(&env.work().join("pkg-1.0.tar.gz.recipe.json")).expect("emit failed");
    let sexp = std::fs::read_to_string(env.work().join("pkg-1.0.tar.gz.disarchive")).unwrap();
    assert!(sexp.contains("(compressor gnu-best)"), "sexp: {sexp}");
    assert!(sexp.contains("(name \"pkg-1.0.tar\")"), "sexp: {sexp}");
    assert!(
        sexp.contains(&sha256_hex(&tarball)),
        "tarball digest missing"
    );
    let swhid_hex = sexp
        .split("swh:1:dir:")
        .nth(1)
        .expect("swhid present")
        .chars()
        .take(40)
        .collect::<String>();

    // Independent oracle: extract the tar and let REAL git compute
    // the tree hash of the extraction directory.
    let extract = env.work().join("extract");
    std::fs::create_dir_all(&extract).unwrap();
    tar::Archive::new(&tarball[..]).unpack(&extract).unwrap();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&extract)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git on PATH");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    git(&["init", "-q", "."]);
    git(&["add", "-A"]);
    let tree = git(&["write-tree"]);
    assert_eq!(swhid_hex, tree, "our swh:1:dir must equal git's tree hash");
}

#[test]
fn recipe_disarchive_refuses_extension_headers() {
    let env = TestEnv::new("recipe-disarchive-ext");
    // A >100-char path forces a GNU long-name extension header,
    // which the projection's field model refuses rather than
    // guessing at.
    let long = format!("pkg-1.0/{}/file.bin", "d".repeat(120));
    let tarball = plain_tar(&[(long.as_str(), &noisy_payload(5000, 9))]);
    let tgz = system_gzip(&["-9"], &tarball);
    let path = env.write("long.tar.gz", &tgz);
    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let err = disarchive::emit(&env.work().join("long.tar.gz.recipe.json"))
        .expect_err("must refuse extension headers");
    assert!(
        format!("{err:#}").contains("extension headers"),
        "error: {err:#}"
    );
}

#[test]
fn recipe_of_claimed_file_is_one_ref() {
    use sha2::Digest as _;
    let env = TestEnv::new("recipe-claimed");
    let content = b"claimed-content: these exact bytes are indexed by the fixture dataset\n";
    let sha256 = sha256_hex(content);
    let sha1 = {
        let mut h = sha1::Sha1::new();
        h.update(content);
        format!("{:x}", h.finalize())
    };
    let md5 = {
        use md5::Digest as _;
        format!("{:x}", md5::Md5::digest(content))
    };
    install_fatcat_dataset(&env, &[(&sha1, &sha256, &md5)]);
    let path = env.write("paper.pdf", content);

    // The indexes name the whole file: one ref, no splice, no residue.
    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("100% fetchable"),
        "summary: {}",
        stdout(&out)
    );
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("paper.pdf.recipe.json")).unwrap(),
    )
    .unwrap();
    let r = &doc["root"]["ref"];
    assert_eq!(r["digests"]["sha256"], sha256.as_str());
    let url = r["claims"][0]["url"].as_str().unwrap();
    assert!(url.contains("web.archive.org"), "claim url: {url}");
    assert!(doc["residue"].is_null());
    assert!(!env.work().join("paper.pdf.recipe.residue").exists());
}

#[test]
fn recipe_jigdo_projection_round_trips() {
    use sha2::Digest as _;
    let env = TestEnv::new("recipe-jigdo");
    // One member the fixture dataset claims (it becomes a fetchable
    // part), one it doesn't (its bytes must ride in the template).
    let claimed: Vec<u8> = (0u8..=255).cycle().take(4000).collect();
    let unclaimed = vec![9u8; 3000];
    let sha256 = sha256_hex(&claimed);
    let sha1 = {
        let mut h = sha1::Sha1::new();
        h.update(&claimed);
        format!("{:x}", h.finalize())
    };
    let md5 = {
        use md5::Digest as _;
        format!("{:x}", md5::Md5::digest(&claimed))
    };
    install_fatcat_dataset(&env, &[(&sha1, &sha256, &md5)]);
    let tarball = plain_tar(&[("claimed.bin", &claimed), ("unclaimed.bin", &unclaimed)]);
    let tar_path = env.write("demo.tar", &tarball);

    let out = env.hdx(&["--offline", "recipe", tar_path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let out = env.hdx(&[
        "recipe",
        "jigdo",
        env.work().join("demo.tar.recipe.json").to_str().unwrap(),
    ]);
    assert!(out.status.success(), "emit failed: {}", stderr(&out));

    // The .jigdo names the claimed part (base64url sha256) against a
    // server prefix derived from its claim URL.
    let jigdo = std::fs::read_to_string(env.work().join("demo.tar.jigdo")).unwrap();
    let key = {
        let raw = sha2::Sha256::digest(&claimed);
        data_encoding::BASE64URL_NOPAD.encode(&raw)
    };
    assert!(jigdo.contains(&format!("{key}=S0:")), "jigdo: {jigdo}");
    assert!(jigdo.contains("[Servers]") && jigdo.contains("S0=https://"));

    // Independent template parse: inflate the DATA parts, walk DESC in
    // image order, splice literal bytes + the claimed file's bytes,
    // and require the original tar back.
    let template = std::fs::read(env.work().join("demo.tar.template")).unwrap();
    let head_end = template
        .windows(4)
        .position(|w| w == b"DATA")
        .expect("no DATA part");
    let mut pos = head_end;
    let mut literals: Vec<u8> = Vec::new();
    let mut desc: Option<&[u8]> = None;
    while pos < template.len() {
        let magic = &template[pos..pos + 4];
        let total = u64::from_le_bytes([
            template[pos + 4],
            template[pos + 5],
            template[pos + 6],
            template[pos + 7],
            template[pos + 8],
            template[pos + 9],
            0,
            0,
        ]) as usize;
        if magic == b"DATA" {
            let z = &template[pos + 16..pos + total];
            let mut dec = flate2::read::ZlibDecoder::new(z);
            std::io::Read::read_to_end(&mut dec, &mut literals).unwrap();
        } else if magic == b"DESC" {
            desc = Some(&template[pos..pos + total]);
        }
        pos += total;
    }
    let desc = desc.expect("no DESC part");
    let mut image: Vec<u8> = Vec::new();
    let mut lit_pos = 0usize;
    let mut p = 10; // 'DESC' + u48
    while p < desc.len() - 6 {
        let t = desc[p];
        p += 1;
        let len = u64::from_le_bytes([
            desc[p],
            desc[p + 1],
            desc[p + 2],
            desc[p + 3],
            desc[p + 4],
            desc[p + 5],
            0,
            0,
        ]) as usize;
        p += 6;
        match t {
            2 => {
                image.extend_from_slice(&literals[lit_pos..lit_pos + len]);
                lit_pos += len;
            }
            9 => {
                let sha = &desc[p + 8..p + 40];
                p += 40;
                assert_eq!(sha, &sha2::Sha256::digest(&claimed)[..], "part digest");
                assert_eq!(len, claimed.len());
                image.extend_from_slice(&claimed);
            }
            8 => {
                // image-info: sha256 + blocklen follow the length
                p += 32 + 4;
            }
            other => panic!("unexpected DESC entry type {other}"),
        }
    }
    assert_eq!(
        image, tarball,
        "spliced image differs from the original tar"
    );
}

/// erofs images in every on-disk shape mkfs.erofs 1.9.2 produces from
/// one source tree, walked to byte-verified member digests. Fixtures
/// (tests/data/erofs/*.erofs.gz) were built in a fedora:44 container:
///
///   mkfs.erofs -b4096                                  flat.erofs tree
///   mkfs.erofs -b4096 -zlzma -C65536 -Eall-fragments,dedupe lzma.erofs tree
///   mkfs.erofs -b4096 -zlz4                            lz4.erofs  tree
///   mkfs.erofs -b4096 -zlzma -Eztailpacking            ztail.erofs tree
///
/// covering flat/inline layouts, MicroLZMA all-fragments with a packed
/// inode + big pclusters + compacted-2B indexes (the Fedora live-media
/// shape), LZ4 with 0-padding, and ztailpacking. The tree holds a
/// symlink (must not become a member), a hardlink (two members, same
/// bytes), and a nested tar (must descend). Expected digests are
/// sha256sum of the source tree, recorded when the fixtures were made.
#[test]
fn scan_descends_erofs_images() {
    let truth: &[(&str, &str)] = &[
        (
            "book.txt",
            "f6351f5ead9a700e34275480b3856ea738122a7c57bdeb744a631251c069587a",
        ),
        (
            "data/rand.bin",
            "7854633f4266aa19ce3d7b3c3ea0d58f0a4ebceb3f5618374d6eba63e4d9e702",
        ),
        (
            "data/zeros.bin",
            "c35020473aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479",
        ),
        (
            "hello.txt",
            "bb41e76f3d49ab7c6cc614444cb221c27268be91164796372d307a44ad041f81",
        ),
        (
            "sub/deep/nested.tar",
            "8ed41d38b9fa75982df65a194ac8a02a54c20fd9f3ae5a3d01531c443c142410",
        ),
        (
            "sub/hardbook.txt",
            "f6351f5ead9a700e34275480b3856ea738122a7c57bdeb744a631251c069587a",
        ),
    ];
    let env = TestEnv::new("erofs");
    for img in ["flat", "lzma", "lz4", "ztail"] {
        let gz = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/data/erofs/{img}.erofs.gz")),
        )
        .unwrap();
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
        let path = env.write(&format!("{img}.erofs"), &raw);
        let out = env.hdx(&["--offline", "scan", "--json", path.to_str().unwrap()]);
        assert!(out.status.success(), "{img}: stderr: {}", stderr(&out));
        let mut got: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut container_kind = String::new();
        let mut nested_tar_children = 0;
        for line in stdout(&out).lines() {
            let Ok(o) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let p = o["path"].as_str().unwrap_or_default();
            match p.split_once('!') {
                None if p.ends_with(".erofs") => {
                    container_kind = o["kind"].as_str().unwrap_or_default().to_string();
                    assert!(o["note"].is_null(), "{img}: container note: {}", o["note"]);
                }
                Some((_, rel)) if o["depth"] == 1 => {
                    let sha = o["coords"]
                        .as_array()
                        .and_then(|c| {
                            c.iter()
                                .filter_map(|v| v.as_str())
                                .find_map(|s| s.strip_prefix("sha256:"))
                        })
                        .unwrap_or_default()
                        .to_string();
                    got.insert(rel.to_string(), sha);
                }
                Some((_, rel)) if rel.starts_with("sub/deep/nested.tar!") => {
                    nested_tar_children += 1;
                }
                _ => {}
            }
        }
        assert_eq!(container_kind, "erofs", "{img}: container kind");
        for (rel, want) in truth {
            assert_eq!(
                got.get(*rel).map(String::as_str),
                Some(*want),
                "{img}: digest of {rel}"
            );
        }
        // Exactly the six regular files — the symlink never becomes a
        // member — and the tar inside descended.
        assert_eq!(got.len(), truth.len(), "{img}: member set {:?}", got.keys());
        assert_eq!(nested_tar_children, 2, "{img}: nested tar members");
    }
}
