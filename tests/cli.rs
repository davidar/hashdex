//! End-to-end tests of the hdx CLI, covering everything that works
//! offline: coords minting, filter build/list, scan (including the local
//! index reuse path), locate, and argument validation. Each test gets its
//! own XDG_CACHE_HOME so nothing touches the real ~/.cache/hashdex and
//! tests can run in parallel.

use std::path::PathBuf;
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

#[test]
fn fetch_registry_works_offline() {
    let env = TestEnv::new("fetch");
    // no names: list the registry, no network
    let out = env.hdx(&["filters", "fetch"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    for name in ["circl", "fedora", "fatcat", "depsdev", "rekor", "swh"] {
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
