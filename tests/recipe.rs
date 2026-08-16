//! `hdx recipe`: minting reconstruction manifests, rebuilding from
//! them, and the projections into stock tools' formats.

mod common;
mod disarchive;
use common::*;

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

/// A container the indexes name needs no reconstruction: its recipe is
/// the one reference that fetches it. `--from-parts` asks for the plan
/// anyway — the one that still works when the published copy is gone,
/// since the parts an artifact was built from outlive it.
#[test]
fn recipe_from_parts_plans_a_published_container() {
    let env = TestEnv::new("recipe-from-parts");
    let big = vec![0x3Cu8; 5000];
    let mid: Vec<u8> = (0u8..=255).cycle().take(600).collect();
    let tarball = plain_tar(&[("a.bin", &big), ("b.bin", &mid)]);
    // The container itself is witnessed, as well as its members.
    let rows = [digest_row(&big), digest_row(&mid), digest_row(&tarball)];
    let rows: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_str()))
        .collect();
    install_fatcat_dataset(&env, &rows);
    let tar_path = env.write("demo.tar", &tarball);

    let out = env.hdx(&["--offline", "recipe", tar_path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("nothing to reconstruct"),
        "a published container should resolve to one reference: {}",
        stdout(&out)
    );
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.recipe.json")).unwrap(),
    )
    .unwrap();
    assert!(doc["root"]["ref"].is_object(), "root should be a ref");

    let out = env.hdx(&[
        "--offline",
        "recipe",
        "--from-parts",
        tar_path.to_str().unwrap(),
    ]);
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
    let build = &doc["root"]["build"];
    assert_eq!(build["builder"], "splice@0");
    let refs: Vec<&str> = build["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["ref"]["name"].as_str())
        .collect();
    assert_eq!(refs, vec!["a.bin", "b.bin"]);
}

/// Members witnessed as archive-interior bytes (rpm-files FILEDIGESTS
/// rows) become extract nodes — "fetch this archive, extract this
/// path, expect this digest" — with the archive stated once in the
/// top-level sources table. check rebuilds through a real rpm→cpio
/// walk, from the extracted bytes directly, and reports the ARCHIVE
/// (the fetchable thing) when neither is on hand.
#[test]
fn recipe_extracts_attested_archive_members() {
    let env = TestEnv::new("recipe-extract");
    let tool: Vec<u8> = (0u8..=255).cycle().take(1200).collect();
    let readme = vec![0x5Au8; 900];
    let rpm = fake_rpm(&[("usr/bin/tool", &tool), ("usr/share/doc/README", &readme)]);
    let pkgid = sha256_hex(&rpm);
    let rpm_url = "https://dl.example.org/pool/t/tool-1.0-1.fc44.x86_64.rpm";
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "tool", "1.0-1.fc44", rpm_url)],
        &[
            (&sha256_hex(&tool), "/usr/bin/tool", 0),
            (&sha256_hex(&readme), "/usr/share/doc/README", 0),
        ],
    );
    let tarball = plain_tar(&[("tool.bin", &tool), ("readme.txt", &readme)]);
    let tar_path = env.write("demo.tar", &tarball);

    let out = env.hdx(&["--offline", "recipe", tar_path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("2 extracts from 1 archive"),
        "summary: {text}"
    );

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("demo.tar.recipe.json")).unwrap(),
    )
    .unwrap();
    // New grammar forms bump the version so an older hdx bails.
    assert_eq!(doc["hdx_recipe"], "1");
    let sources = doc["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1, "one rpm, stated once: {sources:?}");
    let aref = &sources[0]["ref"];
    assert_eq!(aref["digests"]["sha256"], pkgid.as_str());
    assert_eq!(aref["name"], "tool-1.0-1.fc44.x86_64.rpm");
    assert_eq!(aref["claims"][0]["url"], rpm_url);
    let inputs = doc["root"]["build"]["inputs"].as_array().unwrap();
    let extracts: Vec<&serde_json::Value> =
        inputs.iter().filter(|i| i["extract"].is_object()).collect();
    assert_eq!(extracts.len(), 2, "inputs: {inputs:?}");
    let e = &extracts[0]["extract"];
    assert_eq!(e["name"], "tool.bin");
    assert_eq!(e["path"], "/usr/bin/tool");
    assert_eq!(e["archive"]["source"], 0);
    assert_eq!(e["output"]["sha256"], sha256_hex(&tool).as_str());
    assert_eq!(e["output"]["size"], 1200);
    assert_eq!(e["claims"][0]["attestor"], "fedora");
    // Both members are archive-fetchable; the tar metadata is residue.
    assert_eq!(doc["coverage"]["fetchable_bytes"].as_u64().unwrap(), 2100);

    // Route 1: the rpm blob — a real rpm→cpio walk per member.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("some.rpm"), &rpm).unwrap();
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
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tarball);

    // Route 2: the extracted bytes on hand, no rpm needed.
    std::fs::remove_file(blobs.join("some.rpm")).unwrap();
    std::fs::write(blobs.join("a"), &tool).unwrap();
    std::fs::write(blobs.join("b"), &readme).unwrap();
    let out = env.hdx(&[
        "recipe",
        "check",
        recipe.to_str().unwrap(),
        blobs.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));

    // Route 3: neither — the report names the archive and its URL.
    std::fs::remove_file(blobs.join("a")).unwrap();
    std::fs::remove_file(blobs.join("b")).unwrap();
    let out = env.hdx(&[
        "recipe",
        "check",
        recipe.to_str().unwrap(),
        blobs.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let se = stderr(&out);
    assert!(se.contains("tool-1.0-1.fc44.x86_64.rpm"), "stderr: {se}");
    assert!(se.contains(&pkgid), "stderr: {se}");
    assert!(se.contains(rpm_url), "stderr: {se}");

    // A stale attestation dies at the walk, never silently: point an
    // extract node at a path the rpm doesn't ship and re-check.
    let mut bad = doc.clone();
    let idx = bad["root"]["build"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .position(|i| i["extract"].is_object())
        .unwrap();
    bad["root"]["build"]["inputs"][idx]["extract"]["path"] = serde_json::json!("/usr/bin/other");
    let bad_path = env.write(
        "bad.recipe.json",
        serde_json::to_string(&bad).unwrap().as_bytes(),
    );
    std::fs::copy(
        env.work().join("demo.tar.recipe.residue"),
        env.work().join("bad.recipe.residue"),
    )
    .unwrap();
    std::fs::write(blobs.join("some.rpm"), &rpm).unwrap();
    let out = env.hdx(&[
        "recipe",
        "check",
        bad_path.to_str().unwrap(),
        blobs.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no such path"),
        "stderr: {}",
        stderr(&out)
    );
}

/// A single file the witness places whole inside an archive mints as
/// one extract node — the recipe IS the attestation.
#[test]
fn recipe_single_file_is_one_extract_node() {
    let env = TestEnv::new("recipe-extract1");
    let tool: Vec<u8> = (0u8..=255)
        .cycle()
        .map(|b| b.wrapping_mul(37))
        .take(800)
        .collect();
    let rpm = fake_rpm(&[("usr/bin/tool", &tool)]);
    let pkgid = sha256_hex(&rpm);
    let rpm_url = "https://dl.example.org/pool/t/tool-1.0-1.fc44.x86_64.rpm";
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "tool", "1.0-1.fc44", rpm_url)],
        &[(&sha256_hex(&tool), "/usr/bin/tool", 0)],
    );
    let path = env.write("tool.bin", &tool);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("100% fetchable"),
        "summary: {}",
        stdout(&out)
    );
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("tool.bin.recipe.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["hdx_recipe"], "1");
    assert!(doc["root"]["extract"].is_object(), "doc: {doc}");
    assert_eq!(doc["sources"].as_array().unwrap().len(), 1);

    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("the.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.bin");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("tool.bin.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), tool);
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
fn recipe_boot_image_mints_a_zstd_node() {
    let env = TestEnv::new("recipe-zstd");
    let ucode = noisy_payload(9_000, 5);
    let one = noisy_payload(40_000, 6);
    let two = noisy_payload(25_000, 7);
    let rows = [digest_row(&one), digest_row(&two)];
    let rows: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_str()))
        .collect();
    install_fatcat_dataset(&env, &rows);
    let early = newc_cpio(&[("kernel/x86/microcode/GenuineIntel.bin", &ucode)]);
    let body = newc_cpio(&[("usr/lib/one.bin", &one), ("usr/lib/two.bin", &two)]);
    let img = initramfs_shape(&early, &piped_zstd(15, None, &body));
    let path = env.write("initramfs.img", &img);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("compressors: zstd-15"), "summary: {so}");
    assert!(so.contains("verified byte-exact"), "summary: {so}");

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("initramfs.img.recipe.json")).unwrap(),
    )
    .unwrap();
    let root = &doc["root"]["build"];
    assert_eq!(root["builder"], "splice@0");
    let frame = root["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["build"]["builder"] == "zstd@0")
        .expect("a zstd@0 node for the compressed segment");
    assert_eq!(frame["build"]["params"]["level"], 15);
    assert_eq!(frame["build"]["name"], "segment-2");
    let inner = &frame["build"]["inputs"][0]["build"];
    assert_eq!(inner["builder"], "splice@0");
    let refs: Vec<&str> = inner["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["ref"]["name"].as_str())
        .collect();
    assert_eq!(refs, vec!["usr/lib/one.bin", "usr/lib/two.bin"]);

    // The image rebuilds from the two payloads and the sidecar: the
    // microcode archive is machine-made and stays literal, the frame
    // is re-encoded.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("one"), &one).unwrap();
    std::fs::write(blobs.join("two"), &two).unwrap();
    let rebuilt = env.work().join("rebuilt.img");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work()
            .join("initramfs.img.recipe.json")
            .to_str()
            .unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), img);
}

#[test]
fn recipe_unreproducible_zstd_stays_literal() {
    // `--long` widens the window, which the frame header states and no
    // catalog run reproduces. The wrapper stays literal — honestly —
    // and the recipe still rebuilds byte-exact from the sidecar.
    let env = TestEnv::new("recipe-zstd-alien");
    let one = noisy_payload(40_000, 6);
    let row = digest_row(&one);
    install_fatcat_dataset(&env, &[(&row.0, &row.1, &row.2)]);
    let early = newc_cpio(&[("kernel/x86/microcode/GenuineIntel.bin", &one)]);
    let body = newc_cpio(&[("usr/lib/one.bin", &one)]);
    let img = initramfs_shape(&early, &piped_zstd(15, Some(27), &body));
    let path = env.write("initramfs.img", &img);

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("initramfs.img.recipe.json")).unwrap(),
    )
    .unwrap();
    assert!(
        !doc.to_string().contains("zstd@0"),
        "a frame no catalog run reproduces must not earn a node"
    );
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("one"), &one).unwrap();
    let rebuilt = env.work().join("rebuilt.img");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work()
            .join("initramfs.img.recipe.json")
            .to_str()
            .unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(std::fs::read(&rebuilt).unwrap(), img);
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

/// Rung E: an all-fragments erofs image is a splice of its own stored
/// pclusters, and each pcluster is a MicroLZMA run over the files
/// packed into it — files an rpm witness places inside a published
/// package. Nothing in that chain is taken on faith: mint re-encodes
/// every pcluster and compares bytes, and `check` rebuilds the image
/// from the rpm alone.
///
/// The fixture (tests/data/erofs/frag.erofs.gz) was built in the
/// fedora:44 container (erofs-utils 1.9.2) over the tree `frag_tree()`
/// regenerates:
///
///   mkfs.erofs -b4096 -zlzma -C8192 \
///              -Eall-fragments,fragdedupe,dedupe frag.erofs tree
///
/// which yields 5 stored pclusters over a 150,013-byte packed stream:
/// several files share one pcluster, `span.bin` and the deduplicated
/// `dup/{a,b}.bin` pair straddle pcluster boundaries, `noise.bin` is
/// incompressible so mkfs stores one pcluster raw (spliced, not
/// re-encoded), and `tiny.txt` (18 bytes) sits below the identity
/// floor, so it can only be literal.
#[test]
fn erofs_recipe_rebuilds_pclusters_from_rpms() {
    let env = TestEnv::new("recipe-erofs");
    let image = erofs_fixture(&env, "frag");
    let tree = frag_tree();

    // One rpm ships the whole tree; the witness states a digest per
    // path, which is what earns each member an extract node.
    let rpm_files: Vec<(String, Vec<u8>)> = tree
        .iter()
        .map(|(p, b)| (format!("opt/frag/{p}"), b.clone()))
        .collect();
    let rpm = fake_rpm(
        &rpm_files
            .iter()
            .map(|(p, b)| (p.as_str(), &b[..]))
            .collect::<Vec<_>>(),
    );
    let pkgid = sha256_hex(&rpm);
    let rpm_url = "https://dl.example.org/pool/f/frag-1.0-1.fc44.x86_64.rpm";
    let digests: Vec<String> = tree.iter().map(|(_, b)| sha256_hex(b)).collect();
    let paths: Vec<String> = tree.iter().map(|(p, _)| format!("/opt/frag/{p}")).collect();
    let rows: Vec<(&str, &str, usize)> = digests
        .iter()
        .zip(&paths)
        .map(|(d, p)| (d.as_str(), p.as_str(), 0))
        .collect();
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "frag", "1.0-1.fc44", rpm_url)],
        &rows,
    );

    let out = env.hdx(&["--offline", "recipe", image.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("erofs: 5/5 pclusters rebuilt byte-exact"),
        "summary: {text}"
    );
    assert!(text.contains("verified byte-exact"), "summary: {text}");

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("frag.erofs.recipe.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["hdx_recipe"], "1");
    let inputs = doc["root"]["build"]["inputs"].as_array().unwrap();
    let nodes: Vec<&serde_json::Value> = inputs
        .iter()
        .filter(|i| i["build"]["builder"] == "microlzma@0")
        .collect();
    assert_eq!(
        nodes.len(),
        4,
        "one node per compressed pcluster: {inputs:?}"
    );
    let params = &nodes[0]["build"]["params"];
    assert_eq!(params["preset"], 6);
    assert!(
        params["dict_size"].as_u64().unwrap().is_power_of_two(),
        "dict_size read from the image: {params}"
    );
    assert!(
        params["pad"].as_u64().is_some(),
        "padding recorded: {params}"
    );

    // Inputs are slices of the sources table, which carries the
    // extract nodes — a member split across two pclusters is sliced by
    // both, and stated once.
    let sources = doc["sources"].as_array().unwrap();
    assert_eq!(sources[0]["ref"]["digests"]["sha256"], pkgid.as_str());
    assert_eq!(sources[0]["ref"]["claims"][0]["url"], rpm_url);
    let span_idx = sources
        .iter()
        .position(|s| s["extract"]["path"] == "/opt/frag/span.bin")
        .expect("span.bin has an extract node in the sources table");
    assert_eq!(sources[span_idx]["extract"]["archive"]["source"], 0);
    let mut slices: Vec<(u64, u64)> = nodes
        .iter()
        .flat_map(|n| n["build"]["inputs"].as_array().unwrap())
        .filter(|i| i["slice"]["source"] == span_idx || i["source"] == span_idx)
        .map(|i| {
            (
                i["slice"]["from"].as_u64().unwrap_or(0),
                i["slice"]["len"].as_u64().unwrap_or(100_000),
            )
        })
        .collect();
    assert!(
        slices.len() > 1,
        "span.bin straddles pcluster boundaries: {slices:?}"
    );
    slices.sort();
    let mut at = 0;
    for (from, len) in &slices {
        assert_eq!(*from, at, "span.bin's slices tile it exactly: {slices:?}");
        at += len;
    }
    assert_eq!(at, 100_000, "span.bin's slices tile it exactly: {slices:?}");

    // noise.bin is incompressible, so mkfs stored its pcluster raw:
    // those bytes are spliced straight out of the sources table, with
    // no builder in between.
    let noise_idx = sources
        .iter()
        .position(|s| s["extract"]["path"] == "/opt/frag/noise.bin")
        .expect("noise.bin has an extract node");
    assert!(
        inputs
            .iter()
            .any(|i| i["slice"]["source"] == noise_idx || i["source"] == noise_idx),
        "a verbatim pcluster splices noise.bin directly: {inputs:?}"
    );

    // tiny.txt is below the identity floor: its bytes stay literal,
    // and so do the image's own metadata blocks.
    let cov = &doc["coverage"];
    // Every packed byte but tiny.txt's 18 (150,013 - 18).
    assert_eq!(cov["fetchable_bytes"].as_u64().unwrap(), 149_995);
    assert!(
        (4_096..4_200).contains(&cov["residue_bytes"].as_u64().unwrap()),
        "residue is the superblock, inodes and tiny.txt: {cov}"
    );

    // Route 1: the rpm alone rebuilds the image, byte for byte.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("frag.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.erofs");
    let recipe = env.work().join("frag.erofs.recipe.json");
    let out = env.hdx(&[
        "recipe",
        "check",
        recipe.to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(
        std::fs::read(&rebuilt).unwrap(),
        std::fs::read(&image).unwrap(),
        "rebuilt image differs"
    );

    // Route 2: without the rpm, the report names it and its URL.
    std::fs::remove_file(blobs.join("frag.rpm")).unwrap();
    let out = env.hdx(&[
        "recipe",
        "check",
        recipe.to_str().unwrap(),
        blobs.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let se = stderr(&out);
    assert!(se.contains(rpm_url), "stderr: {se}");

    // A slice that points at the wrong bytes cannot pass: the encoder
    // is fed something else, and the pcluster's digest says so.
    let mut bad = doc.clone();
    let (node, victim) = bad["root"]["build"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, i)| i["build"]["builder"] == "microlzma@0")
        .find_map(|(n, i)| {
            let at = i["build"]["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .position(|s| s["slice"]["from"].as_u64().is_some_and(|f| f > 0))?;
            Some((n, at))
        })
        .expect("a sliced input");
    bad["root"]["build"]["inputs"][node]["build"]["inputs"][victim]["slice"]["from"] =
        serde_json::json!(1);
    let bad_path = env.write(
        "bad.recipe.json",
        serde_json::to_string(&bad).unwrap().as_bytes(),
    );
    std::fs::copy(
        env.work().join("frag.erofs.recipe.residue"),
        env.work().join("bad.recipe.residue"),
    )
    .unwrap();
    std::fs::write(blobs.join("frag.rpm"), &rpm).unwrap();
    let out = env.hdx(&[
        "recipe",
        "check",
        bad_path.to_str().unwrap(),
        blobs.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("re-encoded pcluster hashes to"),
        "stderr: {}",
        stderr(&out)
    );
}

/// The other half of rung E: files mkfs did NOT pack into fragments
/// keep pclusters of their own (on the Fedora live image, the 375
/// biggest files — half its stored bytes). Same node type, but every
/// input is a slice of one member, and the member is read back through
/// the reader and required to hash to its digest before anything is
/// emitted. Fixture: the same tree as frag.erofs, built without
/// fragments —
///
///   mkfs.erofs -b4096 -zlzma -C8192 own.erofs tree
#[test]
fn erofs_recipe_rebuilds_a_file_s_own_pclusters() {
    let env = TestEnv::new("recipe-erofs-own");
    let image = erofs_fixture(&env, "own");
    let tree = frag_tree();
    let rpm_files: Vec<(String, Vec<u8>)> = tree
        .iter()
        .map(|(p, b)| (format!("opt/frag/{p}"), b.clone()))
        .collect();
    let rpm = fake_rpm(
        &rpm_files
            .iter()
            .map(|(p, b)| (p.as_str(), &b[..]))
            .collect::<Vec<_>>(),
    );
    let pkgid = sha256_hex(&rpm);
    let rpm_url = "https://dl.example.org/pool/f/frag-1.0-1.fc44.x86_64.rpm";
    let digests: Vec<String> = tree.iter().map(|(_, b)| sha256_hex(b)).collect();
    let paths: Vec<String> = tree.iter().map(|(p, _)| format!("/opt/frag/{p}")).collect();
    let rows: Vec<(&str, &str, usize)> = digests
        .iter()
        .zip(&paths)
        .map(|(d, p)| (d.as_str(), p.as_str(), 0))
        .collect();
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "frag", "1.0-1.fc44", rpm_url)],
        &rows,
    );

    let out = env.hdx(&["--offline", "recipe", image.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("own.erofs.recipe.json")).unwrap(),
    )
    .unwrap();
    let inputs = doc["root"]["build"]["inputs"].as_array().unwrap();
    let nodes: Vec<&serde_json::Value> = inputs
        .iter()
        .filter(|i| i["build"]["builder"] == "microlzma@0")
        .collect();
    assert!(
        nodes.len() > 1,
        "several files, several pclusters each: {}",
        stdout(&out)
    );
    // Every input of every node is a slice of exactly one member — no
    // packed inode is involved.
    let sources = doc["sources"].as_array().unwrap();
    for n in &nodes {
        for input in n["build"]["inputs"].as_array().unwrap() {
            let src = input["slice"]["source"]
                .as_u64()
                .or(input["source"].as_u64())
                .unwrap_or_else(|| panic!("unexpected pcluster input {input}"));
            assert!(
                sources[src as usize]["extract"].is_object(),
                "input points at an extract node: {input}"
            );
        }
    }
    assert!(
        doc["coverage"]["fetchable_bytes"].as_u64().unwrap() > 140_000,
        "most of the tree is fetchable: {}",
        doc["coverage"]
    );

    // And the rpm alone rebuilds the image.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("frag.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.erofs");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("own.erofs.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(
        std::fs::read(&rebuilt).unwrap(),
        std::fs::read(&image).unwrap(),
        "rebuilt image differs"
    );
}

/// A file too big to pack keeps pclusters of its own AND a tail in
/// the packed inode, and that tail is bytes of a member like any
/// other: the packed sweep splices it from the RANGE of the file it
/// belongs to. The proof is the file pass's read-back — the same
/// reader walks the packed extent to produce the digest, so a digest
/// that comes back proves where the tail's bytes belong.
///
/// The fixture (tests/data/erofs/tail.erofs.gz) is `frag_tree()` built
/// in the fedora:44 container with tail packing but NOT whole-file
/// packing:
///
///   mkfs.erofs -b4096 -zlzma -C8192 -Efragments tail.erofs tree
///
/// which packs 9 small files whole and leaves two partly packed:
/// `span.bin` keeps pclusters to 52,203 and packs the 47,797 bytes
/// past it, and incompressible `noise.bin` packs its last 7,808. Both
/// tails together are more than half the packed stream.
#[test]
fn erofs_recipe_splices_a_file_s_packed_tail() {
    let env = TestEnv::new("recipe-erofs-tail");
    let image = erofs_fixture(&env, "tail");
    let tree = frag_tree();
    let rpm_files: Vec<(String, Vec<u8>)> = tree
        .iter()
        .map(|(p, b)| (format!("opt/frag/{p}"), b.clone()))
        .collect();
    let rpm = fake_rpm(
        &rpm_files
            .iter()
            .map(|(p, b)| (p.as_str(), &b[..]))
            .collect::<Vec<_>>(),
    );
    let pkgid = sha256_hex(&rpm);
    let rpm_url = "https://dl.example.org/pool/f/frag-1.0-1.fc44.x86_64.rpm";
    let digests: Vec<String> = tree.iter().map(|(_, b)| sha256_hex(b)).collect();
    let paths: Vec<String> = tree.iter().map(|(p, _)| format!("/opt/frag/{p}")).collect();
    let rows: Vec<(&str, &str, usize)> = digests
        .iter()
        .zip(&paths)
        .map(|(d, p)| (d.as_str(), p.as_str(), 0))
        .collect();
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "frag", "1.0-1.fc44", rpm_url)],
        &rows,
    );

    let out = env.hdx(&["--offline", "recipe", image.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));

    // Every pcluster is either rebuilt or accounted for by a named
    // reason. Covering a span thinly is what packed tails made common
    // — a member's last bytes can end a few dozen into a pcluster that
    // is otherwise nobody's — and that case used to be counted
    // nowhere, so this arithmetic silently didn't close. (It closes
    // only when no member was dropped, which the note would say.)
    let note = stdout(&out);
    let line = note
        .lines()
        .find(|l| l.starts_with("erofs: "))
        .unwrap_or_else(|| panic!("no erofs note: {note}"));
    assert!(!line.contains("dropped"), "note: {line}");
    let (rebuilt, total) = line["erofs: ".len()..]
        .split_once(' ')
        .and_then(|(n, _)| n.split_once('/'))
        .map(|(a, b)| (a.parse::<u64>().unwrap(), b.parse::<u64>().unwrap()))
        .unwrap();
    let literal: u64 = [
        "no fetchable members",
        "stored, but not verbatim",
        "covered too thinly to slice",
        "re-encoded differently",
        "input margin too small",
    ]
    .iter()
    .filter_map(|why| {
        let at = line.find(why)?;
        line[..at]
            .rsplit(&[' ', '('][..])
            .nth(1)?
            .parse::<u64>()
            .ok()
    })
    .sum();
    assert_eq!(rebuilt + literal, total, "unaccounted pclusters: {line}");

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("tail.erofs.recipe.json")).unwrap(),
    )
    .unwrap();

    // The source that stands for span.bin, and every slice of it any
    // pcluster node takes.
    let sources = doc["sources"].as_array().unwrap();
    let span = sources
        .iter()
        .position(|s| s["extract"]["path"].as_str() == Some("/opt/frag/span.bin"))
        .expect("span.bin has an extract node") as u64;
    let mut slices: Vec<(u64, u64)> = Vec::new();
    for node in doc["root"]["build"]["inputs"].as_array().unwrap() {
        if node["build"]["builder"] != "microlzma@0" {
            continue;
        }
        for input in node["build"]["inputs"].as_array().unwrap() {
            let sl = &input["slice"];
            if sl["source"].as_u64() == Some(span) {
                slices.push((sl["from"].as_u64().unwrap(), sl["len"].as_u64().unwrap()));
            } else if input["source"].as_u64() == Some(span) {
                slices.push((0, 100_000));
            }
        }
    }
    assert!(
        slices.iter().any(|&(from, _)| from >= 52_203),
        "the packed tail is sliced from where the file's own pclusters stop: {slices:?}"
    );
    // Both halves of the file are reached — its own pclusters and its
    // tail — so nearly all of it is fetchable.
    assert!(
        slices.iter().any(|&(from, _)| from < 52_203),
        "its own pclusters slice the file too: {slices:?}"
    );
    // Both halves of both partly-packed files are reached, so nearly
    // all of the ~158 KB tree is fetchable: 149,995 bytes against
    // 90,589 when only whole-packed files could cover a pcluster, and
    // a residue of 4,114 against 20,027.
    assert!(
        doc["coverage"]["fetchable_bytes"].as_u64().unwrap() > 145_000,
        "coverage: {}",
        doc["coverage"]
    );
    assert!(
        doc["coverage"]["residue_bytes"].as_u64().unwrap() < 10_000,
        "coverage: {}",
        doc["coverage"]
    );

    // And the rpm alone rebuilds the image, tail slices included.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("frag.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.erofs");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("tail.erofs.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(
        std::fs::read(&rebuilt).unwrap(),
        std::fs::read(&image).unwrap(),
        "rebuilt image differs"
    );
}

/// Rung G: an image's pclusters may hold bytes of a member nothing
/// fetches — a boot image the filesystem ships, which this recipe
/// knows how to REBUILD (early cpio literal, zstd@0 over a splice of
/// the modules dracut copied from packages). The build joins the
/// sources table beside the extract nodes, and the pclusters slice its
/// output: MicroLZMA ones over the compressible microcode archive,
/// verbatim ones over the incompressible frame.
///
/// The fixture (tests/data/erofs/boot.erofs.gz) was built in the
/// fedora:44 container over `boot_tree()`:
///
///   mkfs.erofs -b4096 -zlzma -C8192 boot.erofs tree
#[test]
fn erofs_recipe_rebuilds_a_boot_image_it_ships() {
    let env = TestEnv::new("recipe-erofs-boot");
    let image = erofs_fixture(&env, "boot");
    // Only the modules INSIDE the boot image are witnessed; the image
    // itself, the microcode archive and os-release are not.
    let modules = boot_modules();
    let rpm = fake_rpm(
        &modules
            .iter()
            .map(|(p, b)| (*p, &b[..]))
            .collect::<Vec<_>>(),
    );
    let pkgid = sha256_hex(&rpm);
    let rpm_url = "https://dl.example.org/pool/k/kernel-modules-6.19-1.fc44.x86_64.rpm";
    let digests: Vec<String> = modules.iter().map(|(_, b)| sha256_hex(b)).collect();
    let paths: Vec<String> = modules.iter().map(|(p, _)| format!("/{p}")).collect();
    let rows: Vec<(&str, &str, usize)> = digests
        .iter()
        .zip(&paths)
        .map(|(d, p)| (d.as_str(), p.as_str(), 0))
        .collect();
    install_rpm_files_dataset(
        &env,
        &[(
            &pkgid,
            "fedora-44",
            "kernel-modules",
            "6.19-1.fc44",
            rpm_url,
        )],
        &rows,
    );

    let out = env.hdx(&["--offline", "recipe", image.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("boot.erofs.recipe.json")).unwrap(),
    )
    .unwrap();
    let sources = doc["sources"].as_array().unwrap();
    // The boot image is in the table as a build of its own — a zstd@0
    // node over the splice that reaches the rpm.
    let built = sources
        .iter()
        .find(|s| s["build"]["name"] == "boot/initramfs.img")
        .expect("the boot image is a source in its own right");
    let frame = built["build"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["build"]["builder"] == "zstd@0")
        .expect("a zstd@0 node for the image's compressed segment");
    assert_eq!(frame["build"]["params"]["level"], 15);
    let inner = frame["build"]["inputs"][0]["build"]["inputs"]
        .as_array()
        .unwrap();
    assert_eq!(
        inner.iter().filter(|i| i["extract"].is_object()).count(),
        2,
        "both modules come out of the rpm: {inner:?}"
    );

    // The image's own splice slices that build — both ways a pcluster
    // can hold a member's bytes.
    let inputs = doc["root"]["build"]["inputs"].as_array().unwrap();
    let sliced = |v: &serde_json::Value| -> bool {
        v["slice"]["source"]
            .as_u64()
            .or(v["source"].as_u64())
            .is_some_and(|s| sources[s as usize]["build"]["name"] == "boot/initramfs.img")
    };
    let verbatim = inputs.iter().filter(|i| sliced(i)).count();
    let nodes: Vec<&serde_json::Value> = inputs
        .iter()
        .filter(|i| i["build"]["builder"] == "microlzma@0")
        .collect();
    assert!(verbatim > 0, "stored pclusters splice the rebuilt image");
    assert!(
        nodes
            .iter()
            .any(|n| n["build"]["inputs"].as_array().unwrap().iter().any(sliced)),
        "a MicroLZMA pcluster re-encodes the rebuilt image's bytes"
    );

    // And the one rpm rebuilds the whole filesystem: the modules are
    // extracted, the boot image re-assembled and re-compressed, its
    // pclusters re-encoded, the image spliced.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("kernel-modules.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.erofs");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("boot.erofs.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(
        std::fs::read(&rebuilt).unwrap(),
        std::fs::read(&image).unwrap(),
        "rebuilt image differs"
    );
}

/// The same image, nested — the case where an erofs image is NOT the
/// root file. A pcluster's `pa` is an offset into the image, and where
/// the image is the root those are the same number as the root offset;
/// one layer of container between them and they are not. A recipe that
/// merges pcluster segments by the wrong one still reproduces the
/// CONTAINER's bytes at mint (it reads them from the same place it
/// wrote them), so only a rebuild catches it: this test mints through a
/// tar and rebuilds from the rpm.
#[test]
fn erofs_recipe_of_a_nested_image_places_its_pclusters() {
    let env = TestEnv::new("recipe-erofs-nested");
    let image = erofs_fixture(&env, "boot");
    let raw = std::fs::read(&image).unwrap();
    std::fs::remove_file(&image).unwrap();
    let tarball = plain_tar(&[("boot.erofs", &raw)]);
    let path = env.write("outer.tar", &tarball);

    let modules = boot_modules();
    let rpm = fake_rpm(
        &modules
            .iter()
            .map(|(p, b)| (*p, &b[..]))
            .collect::<Vec<_>>(),
    );
    let pkgid = sha256_hex(&rpm);
    let url = "https://dl.example.org/pool/k/kernel-modules-6.19-1.fc44.x86_64.rpm";
    let digests: Vec<String> = modules.iter().map(|(_, b)| sha256_hex(b)).collect();
    let paths: Vec<String> = modules.iter().map(|(p, _)| format!("/{p}")).collect();
    let rows: Vec<(&str, &str, usize)> = digests
        .iter()
        .zip(&paths)
        .map(|(d, p)| (d.as_str(), p.as_str(), 0))
        .collect();
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "kernel-modules", "6.19-1.fc44", url)],
        &rows,
    );

    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("outer.tar.recipe.json")).unwrap(),
    )
    .unwrap();
    assert!(
        doc.to_string().contains("microlzma@0"),
        "the nested image still earns pcluster nodes: {}",
        stdout(&out)
    );

    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("kernel-modules.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.tar");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("outer.tar.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(
        std::fs::read(&rebuilt).unwrap(),
        tarball,
        "rebuilt tar differs"
    );
}

/// Writes a fixture tree for the container that builds the images.
/// Ignored: run it when a tree changes, then rebuild the image (the
/// mkfs invocations are on the tests above).
///
///   HDX_FIXTURE_DIR=/tmp/tree cargo test -- --ignored dump_fixture_tree
#[test]
#[ignore]
fn dump_fixture_tree() {
    let which = std::env::var("HDX_FIXTURE_TREE").unwrap_or_else(|_| "boot".into());
    dump_tree(&match which.as_str() {
        "frag" => frag_tree(),
        _ => boot_tree(),
    });
}

/// An image whose pclusters this hdx can't reproduce mints anyway —
/// as an honest literal recipe, with no microlzma nodes and no error.
#[test]
fn erofs_recipe_of_lz4_image_stays_literal() {
    let env = TestEnv::new("recipe-erofs-lz4");
    let image = erofs_fixture(&env, "lz4");
    let out = env.hdx(&["--offline", "recipe", image.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("lz4.erofs.recipe.json")).unwrap(),
    )
    .unwrap();
    let text = serde_json::to_string(&doc).unwrap();
    assert!(!text.contains("microlzma"), "recipe: {text}");
    assert_eq!(doc["hdx_recipe"], "0");
}

/// A microcode archive is a bare concatenation of files the distros
/// publish — no table of contents, no per-entry names. Mint splits it
/// at the entry headers and asks the index which runs of consecutive
/// entries are published files, longest run first: the packaging is
/// NOT in the headers (one signature can serve several packages), so
/// the index decides the boundaries and everything it doesn't name
/// stays literal.
#[test]
fn recipe_splices_a_microcode_archive() {
    let env = TestEnv::new("recipe-ucode");
    let (blob, entries) = intel_ucode(&[2048, 4096, 2048, 2048]);
    // What the rpm ships: entry 0 alone, entries 1+2 as one file, and
    // — as a decoy — entry 1 on its own, which the longest-run rule
    // must not take. Entry 3 has no witness at all.
    let pair = [entries[1].clone(), entries[2].clone()].concat();
    let files: Vec<(&str, &[u8])> = vec![
        ("usr/lib/firmware/intel-ucode/06-8f-06", &entries[0]),
        ("usr/lib/firmware/intel-ucode/06-8f-07", &pair),
        ("usr/lib/firmware/intel-ucode/06-8f-08", &entries[1]),
    ];
    let rpm = fake_rpm(&files);
    let pkgid = sha256_hex(&rpm);
    let url = "https://dl.example.org/pool/m/microcode_ctl-2.1-1.fc44.x86_64.rpm";
    let digests: Vec<String> = files.iter().map(|(_, b)| sha256_hex(b)).collect();
    let paths: Vec<String> = files.iter().map(|(p, _)| format!("/{p}")).collect();
    let rows: Vec<(&str, &str, usize)> = digests
        .iter()
        .zip(&paths)
        .map(|(d, p)| (d.as_str(), p.as_str(), 0))
        .collect();
    install_rpm_files_dataset(
        &env,
        &[(&pkgid, "fedora-44", "microcode_ctl", "2.1-1.fc44", url)],
        &rows,
    );

    let early = newc_cpio(&[("kernel/x86/microcode/GenuineIntel.bin", &blob)]);
    let path = env.write("early.cpio", &early);
    let out = env.hdx(&["--offline", "recipe", path.to_str().unwrap()]);
    assert!(out.status.success(), "mint failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("microcode: 3/4 entries in 1 archive matched 2 published files"),
        "summary: {text}"
    );
    assert!(text.contains("(1 no witness — literal)"), "summary: {text}");

    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.work().join("early.cpio.recipe.json")).unwrap(),
    )
    .unwrap();
    let ucode = doc["root"]["build"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["build"]["name"] == "kernel/x86/microcode/GenuineIntel.bin")
        .unwrap_or_else(|| panic!("no blob build: {doc:#}"))["build"]
        .clone();
    assert_eq!(ucode["builder"], "splice@0");
    assert_eq!(ucode["output"]["sha256"], sha256_hex(&blob).as_str());
    let inputs = ucode["inputs"].as_array().unwrap();
    let names: Vec<&str> = inputs
        .iter()
        .filter_map(|i| i["extract"]["name"].as_str())
        .collect();
    assert_eq!(names, vec!["06-8f-06", "06-8f-07"], "inputs: {inputs:?}");
    // The 6 KiB run beat the 2 KiB decoy inside it.
    assert_eq!(inputs[1]["extract"]["output"]["size"], 6144);
    let literal: u64 = inputs
        .iter()
        .filter_map(|i| i["literal"]["len"].as_u64())
        .sum();
    assert_eq!(literal, 2048, "only the unwitnessed entry: {inputs:?}");

    // And it rebuilds: check walks the rpm for the two extracts.
    let blobs = env.work().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join("microcode_ctl.rpm"), &rpm).unwrap();
    let rebuilt = env.work().join("rebuilt.cpio");
    let out = env.hdx(&[
        "recipe",
        "check",
        env.work().join("early.cpio.recipe.json").to_str().unwrap(),
        blobs.to_str().unwrap(),
        "--output",
        rebuilt.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "check failed: {}", stderr(&out));
    assert_eq!(
        std::fs::read(&rebuilt).unwrap(),
        early,
        "rebuilt cpio differs"
    );
}
