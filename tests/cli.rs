//! End-to-end tests of the hdx CLI, covering everything that works
//! offline: coords minting, filter build/list, scan (including the local
//! index reuse path), locate, and argument validation. Each test gets its
//! own XDG_CACHE_HOME so nothing touches the real ~/.cache/hashdex and
//! tests can run in parallel.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

enum Col {
    Str(Vec<Option<String>>, bool),
    I64(Vec<Option<i64>>),
}

impl Col {
    fn req_str(v: Vec<String>) -> Col {
        Col::Str(v.into_iter().map(Some).collect(), true)
    }
    fn opt_str(v: Vec<Option<String>>) -> Col {
        Col::Str(v, false)
    }
    fn opt_i64(v: Vec<Option<i64>>) -> Col {
        Col::I64(v)
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
            Col::I64(vals) => {
                let present: Vec<i64> = vals.iter().flatten().copied().collect();
                let defs: Vec<i16> = vals.iter().map(|v| v.is_some() as i16).collect();
                c.typed::<Int64Type>()
                    .write_batch(&present, Some(&defs), None)
                    .unwrap();
            }
        }
        c.close().unwrap();
    }
    rg.close().unwrap();
    writer.close().unwrap();
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

#[test]
fn fetch_registry_works_offline() {
    let env = TestEnv::new("fetch");
    // no names: list the registry, no network
    let out = env.hdx(&["filters", "fetch"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    for name in [
        "circl",
        "fedora",
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

/// The hashoscope: peek descends gzip→tar and ar→gzip→tar chains,
/// tags members against filters, honors the identity floor, and
/// reports containers it cannot enter. Fixtures are built with the
/// same crates the binary uses — the test proves the walk, not the
/// format libraries.
#[test]
fn peek_descends_containers() {
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
    let out = env.hdx(&["--offline", "peek", tgz.to_str().unwrap()]);
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
    let out = env.hdx(&["--offline", "--json", "peek", deb.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    let members = v["members"].as_array().unwrap();
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
    let out = env.hdx(&["--offline", "peek", cpio_file.to_str().unwrap()]);
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
    let out = env.hdx(&["--offline", "peek", iso.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("PAYLOAD.TXT"), "iso member missing:\n{text}");
    assert!(text.contains("[peeksrc]"), "iso member not tagged:\n{text}");

    // Errors: no files; a directory.
    let out = env.hdx(&["peek"]);
    assert!(!out.status.success());
    let out = env.hdx(&["--offline", "peek", env.work().to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a file"), "{}", stderr(&out));
}

/// Zips take three routes through peek: a seekable root walks the
/// central directory directly (stored entries as range views), a
/// stream-fed zip is walked speculatively from its local headers and
/// reconciled against the central directory, and a MISBEHAVED stream
/// zip (here: a local entry hidden from the central directory)
/// triggers one conservative re-descent that spools and trusts only
/// the central directory.
#[test]
fn peek_zip_speculative_and_conservative() {
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
    let out = env.hdx(&["--offline", "peek", zip_file.to_str().unwrap()]);
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
    let out = env.hdx(&["--offline", "peek", zgz.to_str().unwrap()]);
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
    let out = env.hdx(&["--offline", "peek", tgz.to_str().unwrap()]);
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
fn peek_spools_streamed_iso() {
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
    let out = env.hdx(&["--offline", "peek", gz.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("PAYLOAD.TXT"),
        "iso member missing through the spool path:\n{text}"
    );
}
