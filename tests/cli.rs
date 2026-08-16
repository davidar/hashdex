//! hdx's front door: coordinates, hash resolution, the dataset and
//! filter lifecycles, and the fetch registry.

mod common;
use common::*;

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
