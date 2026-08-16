//! `hdx scan`: what a disk walk reports, how far it descends into
//! containers, and the member trees the hashoscope produces.

mod common;
use common::*;

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

#[test]
fn scan_walks_past_a_cpio_trailer() {
    // A boot image is two archives: the microcode cpio, then a
    // compressed one holding everything dracut copied out of packages.
    // The walker used to stop at the first TRAILER!!! — 94% of the
    // file, invisible.
    let env = TestEnv::new("cpio-segments");
    let ucode = noisy_payload(9_000, 5);
    let one = noisy_payload(30_000, 6);
    let two = noisy_payload(12_000, 7);
    let early = newc_cpio(&[("kernel/x86/microcode/GenuineIntel.bin", &ucode)]);
    let body = newc_cpio(&[("usr/lib/one.bin", &one), ("usr/lib/two.bin", &two)]);
    let img = initramfs_shape(&early, &system_zstd(&["-15"], &body));
    let path = env.write("initramfs.img", &img);

    let names = |out: &Output| -> Vec<String> {
        stdout(out)
            .lines()
            .filter(|l| l.starts_with(' '))
            .filter_map(|l| l.trim().split(" — ").next().map(str::to_string))
            .filter(|n| !n.is_empty())
            .collect()
    };
    let out = env.hdx(&["--offline", "scan", path.to_str().unwrap()]);
    assert!(out.status.success(), "scan failed: {}", stderr(&out));
    let ranged = names(&out);
    for want in [
        "kernel/x86/microcode/GenuineIntel.bin",
        "segment-2",
        "segment-2~unpacked",
        "usr/lib/one.bin",
        "usr/lib/two.bin",
    ] {
        assert!(
            ranged.iter().any(|n| n == want),
            "{want} missing from {ranged:?}"
        );
    }

    // The same bytes streamed (inside a tar) must produce the same
    // member tree — the descent cache is content-addressed, so the two
    // arms are not allowed to disagree about what a file contains.
    let tarball = plain_tar(&[("initramfs.img", &img)]);
    let tpath = env.write("boot.tar", &tarball);
    let out = env.hdx(&["--offline", "scan", tpath.to_str().unwrap()]);
    assert!(out.status.success(), "scan failed: {}", stderr(&out));
    let mut streamed = names(&out);
    assert_eq!(streamed.first().map(String::as_str), Some("initramfs.img"));
    streamed.remove(0);
    assert_eq!(streamed, ranged);
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

// ------------------------------------------------------------------ fat

/// FAT in all three widths, walked to byte-verified member digests.
/// The 12-bit table packs two entries into three bytes, 16 and 32 are
/// flat arrays, and FAT32 keeps its root directory in a cluster chain
/// where the others use a fixed region — one tree through all three
/// paths. The long name (stored as fragments before its 8.3 entry)
/// must come back whole, and cluster runs must coalesce into the
/// ranges that hash to the source files.
///
/// Fixtures (tests/data/fat/fat{12,16,32}.img.gz) were built in the
/// fedora:44 container (dosfstools + mtools):
///
///   dd if=/dev/zero of=IMG bs=1024 count={1024,4096,34000}
///   mkfs.fat -F{12,16,32} -s1 -i DEADBEEF -n FIXTURE IMG
///   MTOOLS_SKIP_CHECK=1 mcopy -i IMG -s tree/EFI ::/EFI
///
/// (`-s1` keeps the images small enough to commit: FAT16 needs 4085
/// clusters and FAT32 needs 65525, whatever the payload.)
#[test]
fn scan_descends_fat_filesystems() {
    for bits in ["12", "16", "32"] {
        let env = TestEnv::new(&format!("fat{bits}"));
        let img = fat_fixture(&env, bits);
        let out = env.hdx(&[
            "--offline",
            "--json",
            "scan",
            "--list",
            "all",
            img.to_str().unwrap(),
        ]);
        assert!(out.status.success(), "FAT{bits}: {}", stderr(&out));
        let members: Vec<serde_json::Value> = stdout(&out)
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .collect();
        let root = members
            .iter()
            .find(|m| !m["path"].as_str().unwrap_or_default().contains('!'))
            .expect("root line");
        assert_eq!(root["kind"], "fat", "FAT{bits} not recognized");
        for (path, sha) in FAT_TRUTH {
            let m = members
                .iter()
                .find(|m| {
                    m["path"]
                        .as_str()
                        .is_some_and(|p| p.ends_with(&format!("!{path}")))
                })
                .unwrap_or_else(|| panic!("FAT{bits}: {path} missing"));
            let coords: Vec<&str> = m["coords"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap())
                .collect();
            assert!(
                coords.contains(&format!("sha256:{sha}").as_str()),
                "FAT{bits}: {path} hashed to {coords:?}"
            );
        }
    }
}

/// An EFI system partition on a hybrid ISO lives OUTSIDE the ISO9660
/// directory tree: the firmware finds it through the El Torito boot
/// catalog, and a walker that only reads directories never sees it at
/// all. Here a minimal ISO carries the FAT16 fixture as its EFI boot
/// image, and the walk has to reach the files inside it.
#[test]
fn iso_walks_the_el_torito_boot_image() {
    let env = TestEnv::new("el-torito");
    let esp = std::fs::read(fat_fixture(&env, "16")).unwrap();
    const SECTOR: usize = 2048;
    let cat_lba = 20usize;
    let esp_lba = 24usize;
    let mut img = vec![0u8; (esp_lba + esp.len().div_ceil(SECTOR)) * SECTOR];

    // Primary volume descriptor at sector 16, root directory at 22.
    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    img[pvd + 6] = 1;
    let r = pvd + 156;
    img[r] = 34;
    img[r + 2..r + 6].copy_from_slice(&22u32.to_le_bytes());
    img[r + 10..r + 14].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    img[r + 25] = 0x02;
    img[r + 32] = 1;

    // Boot record volume descriptor at 17, naming the catalog.
    let brvd = 17 * SECTOR;
    img[brvd] = 0;
    img[brvd + 1..brvd + 6].copy_from_slice(b"CD001");
    img[brvd + 6] = 1;
    img[brvd + 7..brvd + 30].copy_from_slice(b"EL TORITO SPECIFICATION");
    img[brvd + 71..brvd + 75].copy_from_slice(&(cat_lba as u32).to_le_bytes());
    let term = 18 * SECTOR;
    img[term] = 255;
    img[term + 1..term + 6].copy_from_slice(b"CD001");
    img[term + 6] = 1;

    // Boot catalog: validation entry, then an EFI section whose entry
    // points at the ESP (no emulation, length in 512-byte sectors).
    let cat = cat_lba * SECTOR;
    img[cat] = 0x01;
    img[cat + 30] = 0x55;
    img[cat + 31] = 0xAA;
    img[cat + 32] = 0x91; // final section header
    img[cat + 33] = 0xEF; // EFI platform
    img[cat + 34..cat + 36].copy_from_slice(&1u16.to_le_bytes());
    let e = cat + 64;
    img[e] = 0x88; // bootable
    img[e + 6..e + 8].copy_from_slice(&((esp.len() / 512) as u16).to_le_bytes());
    img[e + 8..e + 12].copy_from_slice(&(esp_lba as u32).to_le_bytes());

    // An ordinary file in the directory tree, so the ISO walk itself
    // still has something to find.
    let d = 22 * SECTOR;
    let name = b"README.TXT;1";
    let payload = b"an iso with an efi system partition\n";
    img[d] = (33 + name.len()) as u8;
    img[d + 2..d + 6].copy_from_slice(&23u32.to_le_bytes());
    img[d + 10..d + 14].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    img[d + 32] = name.len() as u8;
    img[d + 33..d + 33 + name.len()].copy_from_slice(name);
    img[23 * SECTOR..23 * SECTOR + payload.len()].copy_from_slice(payload);
    img[esp_lba * SECTOR..esp_lba * SECTOR + esp.len()].copy_from_slice(&esp);

    let iso = env.write("hybrid.iso", &img);
    let out = env.hdx(&["--offline", "scan", "--list", "all", iso.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("README.TXT"), "iso tree not walked:\n{text}");
    assert!(
        text.contains("el-torito/efi.img"),
        "boot image not reached:\n{text}"
    );
    for (path, _) in FAT_TRUTH {
        assert!(
            text.contains(path),
            "{path} inside the ESP not walked:\n{text}"
        );
    }
}
