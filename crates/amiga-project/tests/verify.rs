//! Milestone 2: verification reads, reports, and writes nothing.
//!
//! The acceptance criterion is four claims, and each has a test: every source
//! and object hash verifies against the real fixture, nothing unreadable is
//! skipped silently, no symbolic link is followed, and nothing is written.

use std::path::{Path, PathBuf};

use amiga_project::verify::{Bindings, NoRecovery, ObjectStatus, SourceStatus, build_inventory};
use amiga_project::{load, verify};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/contract")
}

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("amiga-verify-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    root
}

#[test]
fn every_source_and_object_verifies_against_the_real_fixture() {
    let root = fixture();
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let bindings = Bindings::new(&root);
    let report = verify(&loaded.project, &bindings, &NoRecovery);

    assert!(
        !report.contradicted(),
        "sources: {:?}\nobjects: {:?}",
        report.sources,
        report.objects
    );
    // Four file sources plus the directory source, all pinned and all present.
    assert_eq!(report.verified_sources(), 5, "{:?}", report.sources);
    // Five objects use range selectors and are recoverable without a parser;
    // the sixth lives inside the directory source, whose members Milestone 2
    // pins through the inventory rather than recovering.
    assert_eq!(report.verified_objects(), 5, "{:?}", report.objects);
    assert_eq!(
        report.objects["object:installed/levels"],
        ObjectStatus::ParentUnavailable
    );
}

#[test]
fn verification_writes_nothing() {
    // The whole report is a claim about what was there. A verify that changed
    // anything would make it a claim about what it left behind.
    let root = fixture();
    let before = snapshot(&root);
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let _ = verify(&loaded.project, &Bindings::new(&root), &NoRecovery);
    assert_eq!(before, snapshot(&root), "verification changed the project");
}

/// Every path under `root` with its size, so a test can prove nothing moved.
fn snapshot(root: &Path) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    fn walk(root: &Path, at: &Path, entries: &mut Vec<(String, u64)>) {
        for entry in std::fs::read_dir(at).unwrap_or_else(|error| panic!("{error}")) {
            let entry = entry.unwrap_or_else(|error| panic!("{error}"));
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, entries);
            } else {
                let relative = path.strip_prefix(root).unwrap().display().to_string();
                let size = entry.metadata().unwrap().len();
                entries.push((relative, size));
            }
        }
    }
    walk(root, root, &mut entries);
    entries.sort();
    entries
}

#[test]
fn a_source_this_machine_cannot_find_is_reported_rather_than_skipped() {
    // A project is meant to open without its private media. What must not
    // happen is a report that says "all good" because it only checked what it
    // could reach.
    let root = fixture();
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    // Bindings rooted somewhere the media is not.
    let elsewhere = scratch("unbound");
    let report = verify(&loaded.project, &Bindings::new(&elsewhere), &NoRecovery);

    assert_eq!(report.verified_sources(), 0);
    assert!(
        report
            .sources
            .values()
            .all(|status| matches!(status, SourceStatus::Missing { .. })),
        "{:?}",
        report.sources
    );
    // Missing media is not a contradiction: nothing disagreed with the project.
    assert!(!report.contradicted());
    // And every object says why it could not be attempted, rather than being
    // absent from the report.
    assert_eq!(report.objects.len(), loaded.project.sources.objects.len());
    assert!(
        report
            .objects
            .values()
            .all(|status| *status == ObjectStatus::ParentUnavailable)
    );
    let _ = std::fs::remove_dir_all(&elsewhere);
}

#[test]
fn changed_bytes_contradict_the_project_and_name_both_digests() {
    let root = scratch("changed");
    // Copy just enough of the fixture to rebind one source at wrong bytes.
    std::fs::create_dir_all(root.join("original")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(root.join("original/disk1.adf"), b"not the disk")
        .unwrap_or_else(|error| panic!("{error}"));

    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let bindings = Bindings::new(fixture()).bind("source:disk-1", root.join("original/disk1.adf"));
    let report = verify(&loaded.project, &bindings, &NoRecovery);

    assert!(report.contradicted());
    let SourceStatus::Mismatch {
        expected, actual, ..
    } = &report.sources["source:disk-1"]
    else {
        panic!("expected a mismatch: {:?}", report.sources["source:disk-1"]);
    };
    assert_ne!(expected, actual);
    assert_eq!(expected.len(), 64);
    // The object derived from it could not be attempted, and says so rather
    // than reporting a mismatch it never actually computed.
    assert_eq!(
        report.objects["object:disk-1/s/main"],
        ObjectStatus::ParentUnavailable
    );
    // The other disks still verify: one bad source does not poison the report.
    assert!(report.sources["source:disk-2"].is_verified());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_wrong_size_beside_a_right_digest_is_reported_as_a_size_disagreement() {
    // Verification tests two things, so it must be able to report either one.
    // Reporting a wrong `size` as a digest mismatch printed the same digest
    // twice under a heading that said they differed, and never mentioned the
    // field that actually disagreed.
    let root = scratch("wrong-size");
    copy_tree(&fixture(), &root);

    let sources_path = root.join("analysis/sources.json");
    let mut sources: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sources_path).unwrap()).unwrap();
    for source in sources["sources"].as_array_mut().unwrap() {
        if source["id"] == "source:disk-1" {
            source["size"] = serde_json::json!(40_000);
        }
    }
    for object in sources["objects"].as_array_mut().unwrap() {
        if object["id"] == "object:assets/palette" {
            object["size"] = serde_json::json!(9);
        }
    }
    std::fs::write(
        &sources_path,
        serde_json::to_string_pretty(&sources).unwrap(),
    )
    .unwrap();

    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let report = verify(&loaded.project, &Bindings::new(&root), &NoRecovery);

    assert_eq!(
        report.sources["source:disk-1"],
        SourceStatus::SizeMismatch {
            path: root.join("original/disk1.adf"),
            expected: Some(40_000),
            actual: 40_960,
        },
        "{:?}",
        report.sources["source:disk-1"]
    );
    assert_eq!(
        report.objects["object:assets/palette"],
        ObjectStatus::SizeMismatch {
            expected: 9,
            actual: 8,
        },
        "{:?}",
        report.objects["object:assets/palette"]
    );
    // It is still a contradiction: the document is wrong about bytes that are
    // not. And a source that fails this way is not usable as a parent, so the
    // objects derived from it say why rather than being scored against it.
    assert!(report.contradicted());
    assert_eq!(
        report.objects["object:disk-1/s/main"],
        ObjectStatus::ParentUnavailable
    );
    // One wrong field does not poison the rest of the report.
    assert!(report.sources["source:disk-2"].is_verified());
    assert!(report.objects["object:assets/jingle"].is_verified());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_file_source_that_records_no_size_is_named_rather_than_called_a_mismatch() {
    // `load` refuses such a document — `SOURCE_PIN_MISSING` is fatal — so the
    // pin is dropped in memory here: `verify` is public and takes a `Project`
    // whoever built it, and its report must stay honest for one that skipped
    // validation. What must not happen is a digest heading over two identical
    // digests when the disagreement is an absent field.
    let root = fixture();
    let mut loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    for source in &mut loaded.project.sources.sources {
        if source.id == "source:disk-1" {
            source.size = None;
        }
    }

    let report = verify(&loaded.project, &Bindings::new(&root), &NoRecovery);
    assert_eq!(
        report.sources["source:disk-1"],
        SourceStatus::SizeMismatch {
            path: root.join("original/disk1.adf"),
            expected: None,
            actual: 40_960,
        },
        "{:?}",
        report.sources["source:disk-1"]
    );
}

#[test]
fn a_selector_past_the_end_of_its_parent_is_reported_not_panicked() {
    let root = scratch("out-of-range");
    let project = fixture();
    let mut sources: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join("analysis/sources.json")).unwrap(),
    )
    .unwrap();
    for object in sources["objects"].as_array_mut().unwrap() {
        if object["id"] == "object:disk-1/s/main" {
            object["selector"]["offset"] = serde_json::json!(u64::from(u32::MAX));
        }
    }
    // Load the project as-is, then verify with the doctored document in place.
    copy_tree(&project, &root);
    std::fs::write(
        root.join("analysis/sources.json"),
        serde_json::to_string_pretty(&sources).unwrap(),
    )
    .unwrap();

    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let report = verify(&loaded.project, &Bindings::new(&root), &NoRecovery);
    assert_eq!(
        report.objects["object:disk-1/s/main"],
        ObjectStatus::SelectorOutOfRange
    );
    assert!(report.contradicted());
    let _ = std::fs::remove_dir_all(&root);
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|error| panic!("{error}"));
    for entry in std::fs::read_dir(from).unwrap_or_else(|error| panic!("{error}")) {
        let entry = entry.unwrap_or_else(|error| panic!("{error}"));
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap_or_else(|error| panic!("{error}"));
        }
    }
}

#[test]
fn an_object_needing_a_parser_says_so_rather_than_being_left_out() {
    // `NoRecovery` refuses every container selector. The report must carry an
    // explicit `Unrecoverable`, not simply be shorter.
    let selector = amiga_project::document::Selector::Lha {
        member: "game.exe".to_owned(),
        method: None,
        crc16: None,
    };
    let result = amiga_project::verify::Recover::recover(&NoRecovery, &selector, b"");
    assert!(result.is_err());
}

/// IFF ByteRun1, implemented here rather than borrowed from `amiga-compress`.
///
/// The format crate depends on no codec, and a test that reached for one would
/// prove the two agree with each other rather than that the recorded recipe
/// means what the schema says it means.
fn byte_run1(packed: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < packed.len() {
        let control = packed[cursor] as i8;
        cursor += 1;
        if control >= 0 {
            let count = control as usize + 1;
            output.extend_from_slice(&packed[cursor..cursor + count]);
            cursor += count;
        } else if control != i8::MIN {
            let count = (1 - i32::from(control)) as usize;
            output.resize(output.len() + count, packed[cursor]);
            cursor += 1;
        }
    }
    output
}

/// A recoverer that runs the one codec this test records.
struct ByteRun1Recovery;

impl amiga_project::Recover for ByteRun1Recovery {
    fn recover(
        &self,
        selector: &amiga_project::document::Selector,
        container: &[u8],
    ) -> Result<Vec<u8>, String> {
        use amiga_project::document::{Codec, Selector};
        match selector {
            Selector::Decompressed {
                codec: Codec::ByteRun1 {},
                ..
            } => Ok(byte_run1(container)),
            other => Err(format!("no decoder for a `{}` selector", other.container())),
        }
    }

    fn recover_bounded(
        &self,
        selector: &amiga_project::document::Selector,
        container: &[u8],
        _inputs: &std::collections::BTreeMap<&str, &[u8]>,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        // Synthetic decoder: every encoded byte can expand to at most 128 bytes.
        if (container.len() as u64).saturating_mul(128) > maximum_bytes {
            return Err("test decoder output allowance is too small".to_owned());
        }
        self.recover(selector, container)
    }
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn a_decompressed_object_is_re_derived_from_its_parent_rather_than_read_back() {
    // The point of recording a recipe: nothing but the pinned source and the
    // record exists on disk, and the object still verifies. A project whose
    // intermediate files were deleted is recoverable, not unreproducible.
    let root = scratch("decompressed");
    copy_tree(&fixture(), &root);

    // Copy 3 literals, then replicate 'Z' four times.
    let packed: [u8; 6] = [0x02, b'A', b'B', b'C', 0xfd, b'Z'];
    let plain = byte_run1(&packed);
    assert_eq!(
        plain, b"ABCZZZZ",
        "the hand-written stream says what it means"
    );
    std::fs::write(root.join("original/packed.bin"), packed)
        .unwrap_or_else(|error| panic!("{error}"));

    let sources_path = root.join("analysis/sources.json");
    let mut sources: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sources_path).unwrap()).unwrap();
    sources["sources"]
        .as_array_mut()
        .expect("the fixture has sources")
        .push(json_source("source:packed", packed.len(), &digest(&packed)));
    sources["objects"]
        .as_array_mut()
        .expect("the fixture has objects")
        .push(serde_json::json!({
            "id": "object:packed/unpacked",
            "kind": "decompressed",
            "parent_id": "source:packed",
            "selector": { "container": "decompressed", "codec": { "name": "byte_run1" } },
            "size": plain.len(),
            "sha256": digest(&plain),
        }));
    std::fs::write(
        &sources_path,
        serde_json::to_string_pretty(&sources).unwrap(),
    )
    .unwrap();

    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let bindings = Bindings::new(&root);

    let report = verify(&loaded.project, &bindings, &ByteRun1Recovery);
    assert!(report.sources["source:packed"].is_verified());
    assert_eq!(
        report.objects["object:packed/unpacked"],
        ObjectStatus::Verified,
        "{:?}",
        report.objects["object:packed/unpacked"]
    );
    assert!(!report.contradicted());

    // Without the decoder the same object is reported, never dropped, and the
    // reason names what was missing.
    let refused = verify(&loaded.project, &bindings, &NoRecovery);
    let ObjectStatus::Unrecoverable { reason } = &refused.objects["object:packed/unpacked"] else {
        panic!(
            "a missing decoder must be stated: {:?}",
            refused.objects["object:packed/unpacked"]
        );
    };
    assert!(reason.contains("decompressed"), "{reason}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_recipe_that_produces_other_bytes_is_a_mismatch_rather_than_a_pass() {
    // The digest is what makes the recipe an authority. A recorded codec that
    // decodes to something else must contradict the project.
    let root = scratch("wrong-recipe");
    copy_tree(&fixture(), &root);
    let packed: [u8; 6] = [0x02, b'A', b'B', b'C', 0xfd, b'Z'];
    std::fs::write(root.join("original/packed.bin"), packed)
        .unwrap_or_else(|error| panic!("{error}"));

    let sources_path = root.join("analysis/sources.json");
    let mut sources: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sources_path).unwrap()).unwrap();
    sources["sources"].as_array_mut().unwrap().push(json_source(
        "source:packed",
        packed.len(),
        &digest(&packed),
    ));
    sources["objects"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "object:packed/unpacked",
            "kind": "decompressed",
            "parent_id": "source:packed",
            "selector": { "container": "decompressed", "codec": { "name": "byte_run1" } },
            // The size and digest of bytes this recipe does not produce.
            "size": 7,
            "sha256": digest(b"ABCZZZY"),
        }));
    std::fs::write(
        &sources_path,
        serde_json::to_string_pretty(&sources).unwrap(),
    )
    .unwrap();

    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let report = verify(&loaded.project, &Bindings::new(&root), &ByteRun1Recovery);
    let ObjectStatus::Mismatch { expected, actual } = &report.objects["object:packed/unpacked"]
    else {
        panic!(
            "expected a mismatch: {:?}",
            report.objects["object:packed/unpacked"]
        );
    };
    assert_ne!(expected, actual);
    assert!(report.contradicted());
    let _ = std::fs::remove_dir_all(&root);
}

fn json_source(id: &str, size: usize, sha256: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "kind": "file",
        "media_type": "binary",
        "display_name": "A packed blob",
        "size": size,
        "sha256": sha256,
        "locations": [{ "kind": "project_relative", "path": "original/packed.bin" }],
    })
}

#[test]
fn the_inventory_walk_records_a_symlink_instead_of_following_it() {
    let root = scratch("symlink");
    std::fs::write(root.join("real.txt"), b"real bytes").unwrap_or_else(|error| panic!("{error}"));
    let outside = root
        .join("..")
        .join(format!("amiga-verify-outside-{}", std::process::id()));
    std::fs::write(&outside, b"NOT PROJECT BYTES").unwrap_or_else(|error| panic!("{error}"));

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("escape.txt"))
        .unwrap_or_else(|error| panic!("{error}"));

    let tree = build_inventory(&root).unwrap_or_else(|error| panic!("{error}"));
    let paths: Vec<&str> = tree.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(paths, ["real.txt"], "a link was read as project bytes");

    #[cfg(unix)]
    {
        assert_eq!(tree.omitted.len(), 1, "the link was skipped silently");
        assert_eq!(tree.omitted[0].path, "escape.txt");
        assert_eq!(tree.omitted[0].reason, "symlink");
    }

    let _ = std::fs::remove_file(&outside);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_inventory_walk_sorts_and_hashes_the_same_tree_the_same_way() {
    let root = scratch("inventory");
    std::fs::create_dir_all(root.join("b/c")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(root.join("z.txt"), b"z").unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(root.join("a.txt"), b"a").unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(root.join("b/c/nested.txt"), b"n").unwrap_or_else(|error| panic!("{error}"));

    let first = build_inventory(&root).unwrap_or_else(|error| panic!("{error}"));
    let paths: Vec<&str> = first.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(paths, ["a.txt", "b/c/nested.txt", "z.txt"]);

    // The hash is a property of the tree, not of the order the filesystem
    // happened to hand entries back.
    let second = build_inventory(&root).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(first.tree_sha256(), second.tree_sha256());

    // And it is the one the library's own function computes.
    assert_eq!(
        first.tree_sha256(),
        amiga_project::tree_sha256(
            &first
                .files
                .iter()
                .map(|file| (file.path.clone(), file.size, file.sha256.clone()))
                .collect::<Vec<_>>()
        )
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_fixture_directory_source_matches_its_checked_in_inventory() {
    // The acceptance criterion for a directory source: what is on disk hashes
    // to what the project pins.
    let root = fixture();
    let walked =
        build_inventory(&root.join("original/installed")).unwrap_or_else(|error| panic!("{error}"));
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let inventory = &loaded.project.inventories["source:installed-tree"];
    assert_eq!(walked.tree_sha256(), inventory.tree_sha256);
    assert_eq!(walked.files.len(), inventory.files.len());
    for (walked, pinned) in walked.files.iter().zip(&inventory.files) {
        assert_eq!(walked.path, pinned.path);
        assert_eq!(walked.sha256, pinned.sha256);
    }
}

fn byte_budget_project(
    root: &Path,
    source_count: usize,
    object_count: usize,
) -> (amiga_project::Project, Bindings) {
    use amiga_project::document::{Selector, SourceKind};
    let mut project = load(&fixture()).unwrap().project;
    std::fs::write(root.join("bytes.bin"), b"12345678").unwrap();
    let source = project
        .sources
        .sources
        .iter()
        .find(|s| s.kind == SourceKind::File)
        .unwrap()
        .clone();
    let object = project.sources.objects[0].clone();
    project.sources.sources.clear();
    project.sources.objects.clear();
    let mut bindings = Bindings::new(root);
    for i in 0..source_count {
        let mut next = source.clone();
        next.id = format!("source:bytes-{i}");
        next.sha256 = Some(digest(b"12345678"));
        next.size = Some(8);
        bindings = bindings.bind(next.id.clone(), root.join("bytes.bin"));
        project.sources.sources.push(next);
    }
    for i in 0..object_count {
        let mut next = object.clone();
        next.id = format!("object:bytes-{i}");
        next.parent_id = if i == 0 {
            "source:bytes-0".to_owned()
        } else {
            format!("object:bytes-{}", i - 1)
        };
        next.selector = Some(Selector::Range {
            offset: 0,
            length: 8,
        });
        next.sha256 = digest(b"12345678");
        next.size = 8;
        project.sources.objects.push(next);
    }
    (project, bindings)
}

#[test]
fn source_reads_are_bounded_even_when_the_recorded_size_lies() {
    use amiga_project::verify::{VerificationLimits, verify_with_limits};
    let root = scratch("byte-limit");
    let (mut project, bindings) = byte_budget_project(&root, 1, 0);
    project.sources.sources[0].size = Some(1);
    let limits = VerificationLimits {
        maximum_source_bytes: 4,
        ..VerificationLimits::default()
    };
    let report = verify_with_limits(&project, &bindings, &NoRecovery, limits);
    let SourceStatus::Unreadable { reason, .. } = &report.sources["source:bytes-0"] else {
        panic!("{report:?}");
    };
    assert!(reason.contains("4-byte verification budget"));
    assert_eq!(std::fs::read(root.join("bytes.bin")).unwrap(), b"12345678");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn many_small_sources_share_an_actual_input_and_retention_budget() {
    use amiga_project::verify::{VerificationLimits, verify_with_limits};
    let root = scratch("aggregate-source-limit");
    let (project, bindings) = byte_budget_project(&root, 3, 0);
    for limits in [
        VerificationLimits {
            maximum_total_source_bytes: 16,
            ..VerificationLimits::default()
        },
        VerificationLimits {
            maximum_retained_bytes: 16,
            ..VerificationLimits::default()
        },
    ] {
        let report = verify_with_limits(&project, &bindings, &NoRecovery, limits);
        assert_eq!(report.verified_sources(), 2, "{report:?}");
        assert!(matches!(
            report.sources["source:bytes-2"],
            SourceStatus::Unreadable { .. }
        ));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn derived_objects_share_retention_with_sources_and_refuse_before_recovery() {
    use amiga_project::verify::{VerificationLimits, verify_with_limits};
    let root = scratch("graph-byte-limit");
    let (mut project, bindings) = byte_budget_project(&root, 1, 3);
    let limits = VerificationLimits {
        maximum_retained_bytes: 24,
        ..VerificationLimits::default()
    };
    let report = verify_with_limits(&project, &bindings, &NoRecovery, limits);
    assert_eq!(report.verified_objects(), 2, "{report:?}");
    assert!(matches!(
        report.objects["object:bytes-2"],
        ObjectStatus::Unrecoverable { .. }
    ));
    // A small recorded size cannot make an oversized actual range fit.
    project.sources.objects[0].size = 1;
    let report = verify_with_limits(
        &project,
        &bindings,
        &NoRecovery,
        VerificationLimits {
            maximum_object_bytes: 4,
            ..VerificationLimits::default()
        },
    );
    assert_eq!(report.verified_objects(), 0);
    assert!(matches!(
        report.objects["object:bytes-0"],
        ObjectStatus::Unrecoverable { .. }
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn directory_source_verification_uses_the_same_actual_byte_limits() {
    use amiga_project::document::SourceKind;
    use amiga_project::verify::{VerificationLimits, verify_with_limits};
    let root = scratch("directory-byte-limit");
    std::fs::write(root.join("one"), b"123").unwrap();
    std::fs::write(root.join("two"), b"456").unwrap();
    let mut project = load(&fixture()).unwrap().project;
    let mut source = project
        .sources
        .sources
        .iter()
        .find(|s| s.kind == SourceKind::Directory)
        .unwrap()
        .clone();
    source.tree_sha256 = Some(build_inventory(&root).unwrap().tree_sha256());
    let bindings = Bindings::new(&root).bind(source.id.clone(), &root);
    let id = source.id.clone();
    project.sources.sources = vec![source];
    project.sources.objects.clear();
    for limits in [
        VerificationLimits {
            maximum_source_bytes: 2,
            ..VerificationLimits::default()
        },
        VerificationLimits {
            maximum_total_source_bytes: 5,
            ..VerificationLimits::default()
        },
    ] {
        let report = verify_with_limits(&project, &bindings, &NoRecovery, limits);
        assert!(
            matches!(report.sources[&id], SourceStatus::Unreadable { .. }),
            "{report:?}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inventory_nesting_is_bounded_even_when_directories_are_empty() {
    use amiga_project::verify::MAX_INVENTORY_DEPTH;
    let root = scratch("depth-limit");
    let mut deepest = root.clone();
    for _ in 0..MAX_INVENTORY_DEPTH {
        deepest = deepest.join("d");
        std::fs::create_dir(&deepest).unwrap();
    }
    assert!(build_inventory(&root).unwrap().files.is_empty());
    std::fs::create_dir(deepest.join("one-too-many")).unwrap();
    assert!(
        build_inventory(&root)
            .unwrap_err()
            .contains("nesting exceeds")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_root_is_refused_by_both_inventory_and_verification() {
    let root = scratch("root-link");
    let target = root.join("directory");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("bytes"), b"private bytes").unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    for spelling in [&link, &link.join(""), &link.join(".")] {
        assert!(
            build_inventory(spelling)
                .unwrap_err()
                .contains("symbolic link")
        );
    }
    let mut project = load(&fixture()).unwrap().project;
    let source = project
        .sources
        .sources
        .iter_mut()
        .find(|source| source.kind == amiga_project::document::SourceKind::Directory)
        .unwrap();
    source.tree_sha256 = Some(build_inventory(&target).unwrap().tree_sha256());
    let id = source.id.clone();
    let bindings = Bindings::new(fixture()).bind(id.clone(), &link);
    let report = verify(&project, &bindings, &NoRecovery);
    assert!(
        matches!(&report.sources[&id], SourceStatus::Unreadable { reason, .. } if reason.contains("symbolic link"))
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_file_source_root_link_is_refused_before_reading() {
    let root = scratch("file-root-link");
    let mut project = load(&fixture()).unwrap().project;
    let source = project
        .sources
        .sources
        .iter()
        .find(|source| source.kind == amiga_project::document::SourceKind::File)
        .unwrap();
    let bindings = Bindings::new(fixture());
    let original = bindings.locate(&project, &source.id).unwrap();
    let link = root.join("file");
    std::os::unix::fs::symlink(original, &link).unwrap();
    let id = source.id.clone();
    project.sources.sources.retain(|source| source.id == id);
    let bindings = bindings.bind(id.clone(), &link);
    let report = verify(&project, &bindings, &NoRecovery);
    assert!(
        matches!(&report.sources[&id], SourceStatus::Unreadable { reason, .. } if reason.contains("symbolic link"))
    );
    std::fs::remove_dir_all(root).unwrap();
}
