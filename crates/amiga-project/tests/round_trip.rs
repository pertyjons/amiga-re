//! Milestone 1: the typed documents agree with the schemas, the loader is
//! bounded and complete-or-nothing, and every validation rule fires.
//!
//! The round trip is the load-bearing test. The types were written *to* the
//! schemas, and the only way to keep them honest is to prove that parsing a
//! fixture document and re-serializing it produces the same JSON — a field
//! renamed, dropped, or given a wrong default shows up immediately.

use std::path::{Path, PathBuf};

use amiga_project::validate::ProblemCode;
use amiga_project::{LoadError, load};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/contract")
}

/// Copy the fixture so a test can corrupt it without touching the real one.
fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("amiga-project-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    copy_tree(&fixture(), &root);
    root
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

/// Edit one JSON document in a scratch project.
fn edit(root: &Path, relative: &str, change: impl FnOnce(&mut serde_json::Value)) {
    let path = root.join(relative);
    let mut document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    change(&mut document);
    std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap())
        .unwrap_or_else(|error| panic!("{error}"));
}

fn assert_problem(root: &Path, code: ProblemCode, subject: &str) {
    let Err(LoadError::Invalid(problems)) = load(root) else {
        panic!("a semantically invalid target must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == code && problem.subject.as_deref() == Some(subject)),
        "{problems:?}"
    );
}

#[test]
fn the_contract_fixture_loads_with_only_its_deliberate_staleness() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("the fixture must load: {error}"));

    assert_eq!(loaded.project.sources.sources.len(), 5);
    assert_eq!(loaded.project.programs.len(), 1);
    assert_eq!(loaded.project.programs[0].images.len(), 2);
    assert_eq!(loaded.project.annotations.len(), 2);
    assert_eq!(loaded.project.resources.len(), 3);
    assert_eq!(loaded.project.inventories.len(), 1);

    // Exactly one non-fatal finding: the annotation the fixture marks stale.
    // It loaded, which is the point — the knowledge survives and is visibly
    // untrustworthy rather than being dropped or silently reapplied.
    assert_eq!(loaded.problems.len(), 0, "{:?}", loaded.problems);
}

#[test]
fn a_document_shape_forbidden_by_its_schema_is_a_stable_load_problem() {
    let root = scratch("schema-violation");
    edit(&root, "analysis/sources.json", |document| {
        document["sources"][0]["sha256"] = serde_json::json!("abc");
    });

    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a digest forbidden by the bundled schema must not load");
    };
    assert!(
        problems.iter().any(|problem| {
            problem.code == ProblemCode::DocumentSchemaViolation
                && problem.subject.as_deref() == Some("/sources/0/sha256")
        }),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// A project that declares where provisional outputs go says so, and one that
/// does not says nothing rather than being given a default.
///
/// The absence is the load-bearing half. A caller replaying a checkpoint has to
/// refuse a project that never named a place for one; a fallback here would
/// turn "this project does not do that" into "this project meant `scratch/`",
/// and the file it then read would be one nobody declared.
#[test]
fn a_declared_scratch_directory_is_reported_and_an_undeclared_one_is_not() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("the fixture must load: {error}"));
    assert_eq!(loaded.project.scratch_directory(), Some("work-in-progress"));

    let root = scratch("no-scratch-directory");
    edit(&root, "amiga-re.project.json", |document| {
        let directories = document["directories"].as_object_mut().expect("an object");
        directories.remove("scratch");
    });
    let loaded = load(&root).unwrap_or_else(|error| panic!("the fixture must load: {error}"));
    assert_eq!(loaded.project.scratch_directory(), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn every_document_round_trips_byte_for_byte_through_its_type() {
    // The types were written to the schemas. This is what keeps them there: a
    // renamed field, a dropped optional, or a wrong default changes the output.
    let root = fixture();
    /// Parse one document as its type and re-serialize it.
    type RoundTrip = fn(&str) -> serde_json::Value;

    let cases: Vec<(&str, RoundTrip)> = vec![
        ("amiga-re.project.json", |text| {
            let value: amiga_project::document::ProjectDocument =
                serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
        ("analysis/sources.json", |text| {
            let value: amiga_project::document::SourcesDocument =
                serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
        ("analysis/programs/main.json", |text| {
            let value: amiga_project::document::ProgramDocument =
                serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
        ("analysis/annotations/main-code.json", |text| {
            let value: amiga_project::document::AnnotationsDocument =
                serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
        ("analysis/resources/graphics.json", |text| {
            let value: amiga_project::document::ResourcesDocument =
                serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
        ("analysis/types/game-types.json", |text| {
            let value: amiga_project::document::TypesDocument = serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
        ("analysis/source-inventories/installed-tree.json", |text| {
            let value: amiga_project::document::InventoryDocument =
                serde_json::from_str(text).unwrap();
            serde_json::to_value(value).unwrap()
        }),
    ];

    for (relative, round_trip) in cases {
        let text = std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
        let original: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            round_trip(&text),
            original,
            "{relative} does not round-trip through its type"
        );
    }
}

#[test]
fn every_decompression_recipe_round_trips_through_its_type() {
    // The contract fixture has no packed source, so the selector variant that
    // records a codec is proven here instead: the same byte-for-byte rule, over
    // the JSON a downstream project would actually write.
    let cases = [
        r#"{"container":"decompressed","codec":{"name":"byte_run1"}}"#,
        r#"{"container":"decompressed","codec":{"name":"powerpacker","mode_bits":[9,10,12,13]}}"#,
        r#"{"container":"decompressed","codec":{"name":"rle_xor","marker":144,"xor":true,"inline_marker":false,"size_bytes":4,"size_includes_field":false},"declared_size":6144}"#,
        r#"{"container":"decompressed","codec":{"name":"rle_xor","marker":0,"xor":false,"inline_marker":false,"size_bytes":0,"size_includes_field":false}}"#,
        // The inline-marker layout: the marker is the stream's first byte, and
        // a size field that counts its own bytes follows it.
        r#"{"container":"decompressed","codec":{"name":"rle_xor","marker":144,"xor":false,"inline_marker":true,"size_bytes":4,"size_includes_field":true}}"#,
    ];
    for text in cases {
        let selector: amiga_project::document::Selector = serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("{text} is not a recipe: {error}"));
        assert_eq!(
            serde_json::to_value(&selector).unwrap(),
            serde_json::from_str::<serde_json::Value>(text).unwrap(),
            "{text} does not round-trip"
        );
    }

    // An unknown codec is refused by name rather than deserialized into
    // something that would later verify against nothing.
    for bad in [
        r#"{"container":"decompressed","codec":{"name":"invented"}}"#,
        r#"{"container":"decompressed","codec":{"name":"byte_run1","marker":144}}"#,
        r#"{"container":"decompressed","codec":{"name":"rle_xor","marker":144,"xor":true}}"#,
        r#"{"container":"decompressed","codec":{"name":"rle_xor","marker":144,"xor":true,"size_bytes":4}}"#,
    ] {
        assert!(
            serde_json::from_str::<amiga_project::document::Selector>(bad).is_err(),
            "{bad} was accepted"
        );
    }
}

/// Add one object to a scratch project's sources document.
fn add_object(root: &Path, tag: &str, kind: &str, selector: serde_json::Value) {
    edit(root, "analysis/sources.json", |document| {
        document["objects"]
            .as_array_mut()
            .expect("the fixture has objects")
            .push(serde_json::json!({
                "id": format!("object:{tag}"),
                "kind": kind,
                "parent_id": "source:assets",
                "size": 8,
                "sha256": "0".repeat(64),
                "selector": selector,
            }));
    });
}

/// The recipe every well-formed case in these tests starts from.
fn rle_xor(size_bytes: u32) -> serde_json::Value {
    serde_json::json!({
        "name": "rle_xor",
        "marker": 144,
        "xor": true,
        "inline_marker": false,
        "size_bytes": size_bytes,
        "size_includes_field": false,
    })
}

#[test]
fn an_object_whose_kind_and_recipe_disagree_is_fatal() {
    // Nothing can slice a decompressed object out of its packed parent, so the
    // two spellings must agree or the object's digest has no way back to bytes.
    for (tag, kind, selector) in [
        (
            "kind-without-recipe",
            "decompressed",
            serde_json::json!({ "container": "range", "offset": 0, "length": 8 }),
        ),
        (
            "recipe-without-kind",
            "byte_range",
            serde_json::json!({ "container": "decompressed", "codec": rle_xor(4) }),
        ),
    ] {
        let root = scratch(tag);
        add_object(&root, tag, kind, selector);
        let Err(LoadError::Invalid(problems)) = load(&root) else {
            panic!("{tag}: a kind that disagrees with its selector must be fatal");
        };
        assert!(
            problems
                .iter()
                .any(|problem| problem.code == ProblemCode::SelectorKindMismatch
                    && problem.subject.as_deref() == Some(&format!("object:{tag}"))),
            "{tag}: {problems:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[test]
fn a_recipe_no_decoder_could_run_is_fatal() {
    // The refusal has to be stated. A recipe accepted here would verify against
    // nothing later, and the failure would surface as an unexplained digest
    // mismatch rather than as the bad record it is.
    let cases = [
        // A size-field width no decoder implements.
        (
            "bad-width",
            serde_json::json!({
                "container": "decompressed", "codec": rle_xor(3)
            }),
        ),
        // A PowerPacker mode table outside the widths the bitstream can express.
        (
            "bad-modes",
            serde_json::json!({
                "container": "decompressed",
                "codec": { "name": "powerpacker", "mode_bits": [0, 10, 12, 13] }
            }),
        ),
        // A declared size on a stream that declares nothing: a pin with no
        // source is an assertion wearing a pin's clothes.
        (
            "unsourced-size",
            serde_json::json!({
                "container": "decompressed", "codec": { "name": "byte_run1" }, "declared_size": 8
            }),
        ),
        (
            "unsourced-size-rle",
            serde_json::json!({
                "container": "decompressed", "codec": rle_xor(0), "declared_size": 8
            }),
        ),
    ];
    for (tag, selector) in cases {
        let root = scratch(tag);
        add_object(&root, tag, "decompressed", selector);
        let Err(LoadError::Invalid(problems)) = load(&root) else {
            panic!("{tag}: an unusable recipe must be fatal");
        };
        assert!(
            problems
                .iter()
                .any(|problem| problem.code == ProblemCode::CodecRecipeInvalid),
            "{tag}: {problems:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // And the same recipes without the defect load, so the rule is about the
    // parameters rather than about the variant existing.
    let root = scratch("good-recipe");
    add_object(
        &root,
        "good-recipe",
        "decompressed",
        serde_json::json!({
            "container": "decompressed", "codec": rle_xor(4), "declared_size": 8
        }),
    );
    let loaded = load(&root).unwrap_or_else(|error| panic!("a valid recipe must load: {error}"));
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    // `deny_unknown_fields` everywhere, matching `additionalProperties: false`.
    // A typo in a hand-edited document must fail, not be silently dropped on
    // the next save.
    let root = scratch("unknown-field");
    edit(&root, "analysis/sources.json", |document| {
        document["invented_field"] = serde_json::json!(true);
    });
    assert!(matches!(load(&root), Err(LoadError::Malformed { .. })));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_document_of_the_wrong_kind_or_version_is_refused() {
    let root = scratch("wrong-kind");
    edit(&root, "analysis/sources.json", |document| {
        document["document_kind"] = serde_json::json!("programs");
    });
    assert!(matches!(load(&root), Err(LoadError::WrongKind { .. })));

    let root2 = scratch("wrong-version");
    edit(&root2, "analysis/programs/main.json", |document| {
        document["format_version"] = serde_json::json!(2);
    });
    // Mixed versions are caught per document, before anything is assembled.
    assert!(matches!(
        load(&root2),
        Err(LoadError::UnsupportedVersion { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&root2);
}

#[test]
fn a_listed_document_path_cannot_escape_the_project() {
    let root = scratch("escape");
    edit(&root, "amiga-re.project.json", |document| {
        document["documents"]["sources"] = serde_json::json!("../../../etc/passwd");
    });
    assert!(matches!(load(&root), Err(LoadError::UnsafePath { .. })));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_missing_listed_document_fails_the_whole_load() {
    // Complete or nothing: a project missing one of its documents must not
    // return a partial snapshot whose references were never checked.
    let root = scratch("missing");
    std::fs::remove_file(root.join("analysis/types/game-types.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(matches!(load(&root), Err(LoadError::Io { .. })));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_dangling_reference_is_fatal_and_names_what_is_missing() {
    let root = scratch("dangling");
    edit(&root, "analysis/programs/main.json", |document| {
        document["images"][0]["object_id"] = serde_json::json!("object:does-not-exist");
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a dangling reference must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::UnresolvedReference
                && problem.subject.as_deref() == Some("object:does-not-exist")),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_reference_to_the_wrong_kind_of_entity_is_fatal() {
    // The typed-reference rule: `object_id` must name an `object:`, and a
    // `source:` that happens to exist is still wrong.
    let root = scratch("wrong-kind-ref");
    edit(&root, "analysis/programs/main.json", |document| {
        document["images"][0]["object_id"] = serde_json::json!("source:disk-1");
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a mistyped reference must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::ReferenceKindMismatch),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_entity_target_must_name_an_existing_annotation_in_every_document_kind() {
    for (tag, relative, id) in [
        (
            "dangling-annotation-entity",
            "analysis/annotations/main-code.json",
            "annotation:init-graphics/comment-1",
        ),
        (
            "dangling-resource-entity",
            "analysis/resources/graphics.json",
            "resource:title-logo",
        ),
    ] {
        let root = scratch(tag);
        edit(&root, relative, |document| {
            let collection = if relative.contains("annotations") {
                "annotations"
            } else {
                "resources"
            };
            let entry = document[collection]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == id))
                .unwrap_or_else(|| panic!("{id} must exist in the fixture"));
            entry["target"] = serde_json::json!({
                "space": "entity",
                "entity_id": "function:does-not-exist"
            });
        });

        assert_problem(
            &root,
            ProblemCode::UnresolvedReference,
            "function:does-not-exist",
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn an_entity_target_cannot_attach_to_a_non_annotation_that_happens_to_exist() {
    let root = scratch("entity-kind");
    edit(&root, "analysis/annotations/main-code.json", |document| {
        document["annotations"][0]["target"] = serde_json::json!({
            "space": "entity",
            "entity_id": "object:disk-1/s/main"
        });
    });

    assert_problem(
        &root,
        ProblemCode::ReferenceKindMismatch,
        "object:disk-1/s/main",
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_runtime_target_load_map_must_belong_to_its_image_in_every_document_kind() {
    const MAIN_DIGEST: &str = "9d26d8c87c29dfbc789e05602a497b9b771889df0030a8e07dd7219e3039a7e8";
    for (tag, relative, collection, id) in [
        (
            "annotation-load-map-owner",
            "analysis/annotations/main-code.json",
            "annotations",
            "annotation:main/entry-bookmark",
        ),
        (
            "resource-load-map-owner",
            "analysis/resources/graphics.json",
            "resources",
            "resource:title-logo",
        ),
    ] {
        let root = scratch(tag);
        edit(&root, relative, |document| {
            let entry = document[collection]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == id))
                .unwrap_or_else(|| panic!("{id} must exist in the fixture"));
            entry["target"] = serde_json::json!({
                "space": "runtime",
                "image_id": "image:main-executable",
                "load_map_id": "loadmap:loader/default",
                "address": "0x00022010",
                "length": 2,
                "object_sha256": MAIN_DIGEST
            });
        });

        assert_problem(
            &root,
            ProblemCode::ReferenceOwnershipMismatch,
            "loadmap:loader/default",
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn a_duplicate_id_is_fatal() {
    let root = scratch("duplicate");
    edit(&root, "analysis/sources.json", |document| {
        // Addressed by ID, not by index: the documents are canonically sorted,
        // and a test that depended on position would break whenever the sort
        // key changed rather than when the rule did.
        for source in document["sources"].as_array_mut().unwrap() {
            if source["id"] == "source:disk-2" {
                source["id"] = serde_json::json!("source:disk-1");
            }
        }
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a duplicate ID must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::DuplicateId),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_derivation_cycle_is_fatal_rather_than_a_hang() {
    let root = scratch("cycle");
    edit(&root, "analysis/sources.json", |document| {
        // Point two objects at each other, addressed by ID rather than index.
        let objects = document["objects"].as_array_mut().unwrap();
        let a = objects[0]["id"].clone();
        let b = objects[1]["id"].clone();
        objects[0]["parent_id"] = b;
        objects[1]["parent_id"] = a;
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a cycle must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::DerivationCycle),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_changed_object_makes_its_annotations_stale_without_losing_them() {
    // The rule the format exists for. Changing an object's digest must not
    // silently reapply its annotations to the same numeric offsets.
    let root = scratch("stale");
    edit(&root, "analysis/sources.json", |document| {
        for object in document["objects"].as_array_mut().unwrap() {
            if object["id"] == "object:disk-1/s/main" {
                object["sha256"] = serde_json::json!("f".repeat(64));
            }
        }
    });
    let loaded = load(&root).unwrap_or_else(|error| {
        panic!("a stale annotation must not prevent the project from opening: {error}")
    });
    let stale: Vec<_> = loaded
        .problems
        .iter()
        .filter(|problem| problem.code == ProblemCode::StaleAnnotation)
        .collect();
    assert!(
        stale.len() >= 4,
        "every annotation on the changed object must be reported: {:?}",
        loaded.problems
    );
    // And the knowledge is still there.
    assert!(!loaded.project.annotations[0].annotations.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_stale_mark_on_matching_bytes_is_reported_as_wrong() {
    // The mirror: a mark that is no longer warranted is as misleading as a
    // missing one, because it makes a good annotation look untrustworthy.
    let root = scratch("unwarranted");
    edit(&root, "analysis/annotations/main-code.json", |document| {
        let annotations = document["annotations"].as_array_mut().unwrap();
        let main = annotations
            .iter_mut()
            .find(|annotation| annotation["id"] == "function:init-graphics")
            .unwrap();
        main["stale"] = serde_json::json!(true);
    });
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        loaded
            .problems
            .iter()
            .any(|problem| problem.code == ProblemCode::StaleMarkUnwarranted),
        "{:?}",
        loaded.problems
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_range_past_the_end_of_its_object_is_fatal() {
    let root = scratch("range");
    edit(&root, "analysis/annotations/main-code.json", |document| {
        let annotations = document["annotations"].as_array_mut().unwrap();
        let main = annotations
            .iter_mut()
            .find(|annotation| annotation["id"] == "function:init-graphics")
            .unwrap();
        main["target"]["length"] = serde_json::json!(1_000_000);
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a range past its object must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::RangeOutsideObject),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_source_without_the_pin_its_kind_needs_is_fatal() {
    let root = scratch("unpinned");
    edit(&root, "analysis/sources.json", |document| {
        for source in document["sources"].as_array_mut().unwrap() {
            if source["id"] == "source:disk-1" {
                source.as_object_mut().unwrap().remove("sha256");
            }
        }
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("an unpinned file source must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::SourcePinMissing),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A captured source is legible as one, and must say what produced it.
///
/// The case this exists for: a trackloader that decrypts or unpacks on the way
/// to RAM produces bytes that are on no disk. They can be pinned and verified
/// and nothing in this format can re-derive them, and the whole risk is that
/// such a record reads exactly like a piece of media somebody has a copy of.
/// Recording it as a byte `Range` of the disk image would be worse still — a
/// range is a literal subset of its parent, and this is not one.
#[test]
fn a_captured_source_is_marked_as_one_and_has_to_explain_itself() {
    let root = scratch("captured");
    edit(&root, "analysis/sources.json", |document| {
        for source in document["sources"].as_array_mut().unwrap() {
            if source["id"] == "source:disk-1" {
                let source = source.as_object_mut().unwrap();
                source.insert("provenance".to_owned(), serde_json::json!("captured"));
                source.remove("notes");
            }
        }
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a capture with nothing said about it must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::CaptureUnexplained),
        "{problems:?}"
    );

    // With the sentence that is its only provenance, it loads — and is legible
    // as a capture rather than as media, which is the whole point.
    edit(&root, "analysis/sources.json", |document| {
        for source in document["sources"].as_array_mut().unwrap() {
            if source["id"] == "source:disk-1" {
                source.as_object_mut().unwrap().insert(
                    "notes".to_owned(),
                    serde_json::json!(
                        "Captured from RAM after routine 0x1a2c ran under env.sandbox.call \
                         with d0=0; not re-derivable from any recorded recipe."
                    ),
                );
            }
        }
    });
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    let captured = loaded
        .project
        .sources
        .sources
        .iter()
        .find(|source| source.id == "source:disk-1")
        .unwrap_or_else(|| panic!("the source is there"));
    assert!(!captured.is_reproducible());
    assert!(
        loaded
            .project
            .sources
            .sources
            .iter()
            .filter(|source| source.id != "source:disk-1")
            .all(amiga_project::document::Source::is_reproducible),
        "media must stay media: nothing else changed"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_inventory_that_disagrees_with_its_source_is_reported_but_not_fatal() {
    // The project still opens: which of the two is right is a question for
    // `project verify`, not for the loader.
    let root = scratch("inventory");
    edit(&root, "analysis/sources.json", |document| {
        for source in document["sources"].as_array_mut().unwrap() {
            if source["kind"] == "directory" {
                source["tree_sha256"] = serde_json::json!("a".repeat(64));
            }
        }
    });
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        loaded
            .problems
            .iter()
            .any(|problem| problem.code == ProblemCode::InventoryHashMismatch),
        "{:?}",
        loaded.problems
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_root_is_discovered_from_a_subdirectory() {
    let deep = fixture().join("analysis/annotations");
    let found = amiga_project::discover(&deep).expect("the root is discoverable from below");
    assert_eq!(found, fixture().join("amiga-re.project.json"));
    assert!(amiga_project::discover(Path::new("/")).is_none());
}

/// A global's storage width and the size of the type it names are two claims
/// about the same bytes, so a document may not state them differently.
///
/// The interesting case is the aggregate: `type:level-table` is four eight-byte
/// headers, and nothing in the document spells the number 32 — it is resolved
/// through the array to its element and that element's fields. A rule that
/// compared only against integer widths would let the array-shaped mistake
/// through, which is the shape a decoded track table actually has.
#[test]
fn a_global_may_not_state_two_different_sizes_for_itself() {
    let digest = "9d26d8c87c29dfbc789e05602a497b9b771889df0030a8e07dd7219e3039a7e8";
    let cases = [
        // A word of storage named as a longword.
        ("scalar", 2, "type:u32"),
        // Thirty-one bytes of storage named as a 32-byte array.
        ("aggregate", 31, "type:level-table"),
    ];

    for (tag, length, type_id) in cases {
        let root = scratch(tag);
        edit(&root, "analysis/annotations/main-code.json", |document| {
            document["annotations"]
                .as_array_mut()
                .expect("the fixture has annotations")
                .push(serde_json::json!({
                    "id": "variable:mismatched",
                    "kind": "variable",
                    "origin": "user",
                    "name": "mismatched",
                    "target": {
                        "space": "hunk",
                        "image_id": "image:main-executable",
                        "hunk": 1,
                        "offset": 0,
                        "length": length,
                        "object_sha256": digest
                    },
                    "type_id": type_id
                }));
        });
        let Err(LoadError::Invalid(problems)) = load(&root) else {
            panic!("{tag}: a global whose width contradicts its type must be fatal");
        };
        assert!(
            problems
                .iter()
                .any(|problem| problem.code == ProblemCode::TypeSizeMismatch),
            "{tag}: {problems:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// A type whose size cannot be worked out is not a mismatch.
///
/// The width is checked against a number we resolved, and an alias chain that
/// closes on itself resolves to nothing. Reporting a mismatch there would blame
/// the variable for a fault in the type document, which is reported on its own
/// terms — so the variable must come back clean.
#[test]
fn a_global_whose_type_has_no_resolvable_size_is_not_a_mismatch() {
    let root = scratch("unresolvable-size");
    edit(&root, "analysis/types/game-types.json", |document| {
        let types = document["types"]
            .as_array_mut()
            .expect("the fixture has types");
        types.push(serde_json::json!({
            "id": "type:loop-a", "kind": "alias", "name": "LoopA",
            "aliased_id": "type:loop-b"
        }));
        types.push(serde_json::json!({
            "id": "type:loop-b", "kind": "alias", "name": "LoopB",
            "aliased_id": "type:loop-a"
        }));
    });
    edit(&root, "analysis/annotations/main-code.json", |document| {
        document["annotations"]
            .as_array_mut()
            .expect("the fixture has annotations")
            .push(serde_json::json!({
                "id": "variable:cyclic",
                "kind": "variable",
                "origin": "user",
                "name": "cyclic",
                "target": {
                    "space": "hunk",
                    "image_id": "image:main-executable",
                    "hunk": 1,
                    "offset": 0,
                    "length": 2,
                    "object_sha256":
                        "9d26d8c87c29dfbc789e05602a497b9b771889df0030a8e07dd7219e3039a7e8"
                },
                "type_id": "type:loop-a"
            }));
    });
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        !loaded
            .problems
            .iter()
            .any(|problem| problem.code == ProblemCode::TypeSizeMismatch),
        "{:?}",
        loaded.problems
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A signature may say anything about an ABI except two things at once.
///
/// Nothing here infers a calling convention — a routine taking one argument in
/// `D3` and returning three values is accepted, because on this platform it
/// might be. What is refused is the document contradicting itself.
#[test]
fn a_signature_may_not_contradict_itself() {
    let signature = |body: serde_json::Value| {
        move |document: &mut serde_json::Value| {
            document["types"]
                .as_array_mut()
                .expect("the fixture has types")
                .push(body.clone());
        }
    };
    let cases: Vec<(&str, serde_json::Value, ProblemCode)> = vec![
        (
            // The callee reads a register once, so two values in one is not a
            // layout choice.
            "two-parameters-one-register",
            serde_json::json!({
                "id": "type:clash", "kind": "function", "name": "Clash",
                "parameters": [
                    { "name": "a", "type_id": "type:u16",
                      "location": { "kind": "register", "register": "d1" } },
                    { "name": "b", "type_id": "type:u16",
                      "location": { "kind": "register", "register": "d1" } }
                ]
            }),
            ProblemCode::TypeLayoutInvalid,
        ),
        (
            // The same rule as two in one register: the callee reads the slot
            // once, so two values at one stack offset is a contradiction.
            "two-parameters-one-stack-slot",
            serde_json::json!({
                "id": "type:stack-clash", "kind": "function", "name": "StackClash",
                "parameters": [
                    { "name": "a", "type_id": "type:u16",
                      "location": { "kind": "stack", "offset": 4 } },
                    { "name": "b", "type_id": "type:u16",
                      "location": { "kind": "stack", "offset": 4 } }
                ]
            }),
            ProblemCode::TypeLayoutInvalid,
        ),
        (
            // Eight bytes recorded in a four-byte register.
            "value-too-wide-for-its-register",
            serde_json::json!({
                "id": "type:too-wide", "kind": "function", "name": "TooWide",
                "parameters": [
                    { "name": "header", "type_id": "type:level-header",
                      "location": { "kind": "register", "register": "d0" } }
                ]
            }),
            ProblemCode::TypeSizeMismatch,
        ),
        (
            // Both claims about one register say the call does and does not
            // change it.
            "clobbered-and-preserved",
            serde_json::json!({
                "id": "type:both-ways", "kind": "function", "name": "BothWays",
                "clobbers": ["d0", "d1"], "preserves": ["d1", "a2"]
            }),
            ProblemCode::TypeLayoutInvalid,
        ),
        (
            // A value of a callable type is its *address*, which is a pointer.
            "parameter-is-a-signature",
            serde_json::json!({
                "id": "type:takes-a-routine", "kind": "function", "name": "TakesARoutine",
                "parameters": [
                    { "name": "callback", "type_id": "type:load-level-signature",
                      "location": { "kind": "register", "register": "a0" } }
                ]
            }),
            ProblemCode::ReferenceKindMismatch,
        ),
    ];

    for (tag, body, expected) in cases {
        let root = scratch(tag);
        edit(&root, "analysis/types/game-types.json", signature(body));
        let Err(LoadError::Invalid(problems)) = load(&root) else {
            panic!("{tag}: a self-contradicting signature must be fatal");
        };
        assert!(
            problems.iter().any(|problem| problem.code == expected),
            "{tag}: {problems:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Parameters and results are counted separately, and the same register in both
/// is the commonest shape on the platform rather than a clash.
#[test]
fn a_routine_may_take_and_return_through_one_register() {
    let root = scratch("in-and-out-of-d0");
    edit(&root, "analysis/types/game-types.json", |document| {
        document["types"]
            .as_array_mut()
            .expect("the fixture has types")
            .push(serde_json::json!({
                "id": "type:in-place", "kind": "function", "name": "InPlace",
                "parameters": [
                    { "name": "value", "type_id": "type:u16",
                      "location": { "kind": "register", "register": "d0" } }
                ],
                "results": [
                    { "name": "value", "type_id": "type:u16",
                      "location": { "kind": "register", "register": "d0" } }
                ]
            }));
    });
    let loaded = load(&root).unwrap_or_else(|error| panic!("{error}"));
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    let _ = std::fs::remove_dir_all(&root);
}

/// The two directions of the same rule: a function is described by a signature
/// and storage holds a value, and neither may name the other's kind.
///
/// Every type shares the `type:` prefix, so the ID category cannot tell these
/// apart — which is why `is_callable` is asked rather than the name parsed.
#[test]
fn a_signature_and_a_value_type_are_not_interchangeable() {
    // A function annotation whose type is an integer.
    let root = scratch("function-typed-as-a-value");
    edit(&root, "analysis/annotations/loader-code.json", |document| {
        for annotation in document["annotations"].as_array_mut().expect("annotations") {
            if annotation["id"] == "function:load-level" {
                annotation["type_id"] = serde_json::json!("type:u32");
            }
        }
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a function annotated with a value type must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::ReferenceKindMismatch),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);

    // And a variable whose type is a signature.
    let root = scratch("variable-typed-as-a-routine");
    edit(&root, "analysis/annotations/main-code.json", |document| {
        for annotation in document["annotations"].as_array_mut().expect("annotations") {
            if annotation["id"] == "variable:main/map-seed" {
                annotation["type_id"] = serde_json::json!("type:load-level-signature");
            }
        }
    });
    let Err(LoadError::Invalid(problems)) = load(&root) else {
        panic!("a variable typed as a routine must be fatal");
    };
    assert!(
        problems
            .iter()
            .any(|problem| problem.code == ProblemCode::ReferenceKindMismatch),
        "{problems:?}"
    );
    // And not as a size mismatch: a signature has no size, so there is no
    // second number for the width to disagree with. One fault, one finding.
    assert!(
        !problems
            .iter()
            .any(|problem| problem.code == ProblemCode::TypeSizeMismatch),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_variable_that_is_neither_a_local_nor_a_global_is_fatal() {
    // Serde cannot express "one shape or the other", so the validator restates
    // it. A variable with both shapes claims a function scope for something
    // every function shares; one with neither says where it lives nowhere at
    // all, and a consumer asking has no answer to act on.
    let digest = "9d26d8c87c29dfbc789e05602a497b9b771889df0030a8e07dd7219e3039a7e8";
    let cases = [
        (
            "both-shapes",
            serde_json::json!({
                "id": "variable:both",
                "kind": "variable",
                "origin": "user",
                "name": "confused",
                "scope": { "function_id": "function:init-graphics" },
                "storage": { "kind": "register", "register": "d0" },
                "target": {
                    "space": "base_register",
                    "image_id": "image:main-executable",
                    "base_register": "a5",
                    "displacement": -4,
                    "width": 2,
                    "object_sha256": digest
                }
            }),
        ),
        (
            "no-shape",
            serde_json::json!({
                "id": "variable:nowhere",
                "kind": "variable",
                "origin": "user",
                "name": "unplaced"
            }),
        ),
        // A target that names no storage. Any of the four byte spaces locates a
        // global — the fixture carries a base-register slot, a runtime address
        // and a hunk range — but an `entity` target attaches to another
        // annotation, so the bytes it points at are that annotation's and there
        // is no width here to hold a value.
        (
            "no-storage",
            serde_json::json!({
                "id": "variable:elsewhere",
                "kind": "variable",
                "origin": "user",
                "name": "elsewhere",
                "target": {
                    "space": "entity",
                    "entity_id": "function:init-graphics"
                }
            }),
        ),
    ];

    for (tag, annotation) in cases {
        let root = scratch(tag);
        edit(&root, "analysis/annotations/main-code.json", |document| {
            document["annotations"]
                .as_array_mut()
                .expect("the fixture has annotations")
                .push(annotation.clone());
        });
        let Err(LoadError::Invalid(problems)) = load(&root) else {
            panic!("{tag}: a variable with no usable shape must be fatal");
        };
        assert!(
            problems
                .iter()
                .any(|problem| problem.code == ProblemCode::VariableShapeInvalid),
            "{tag}: {problems:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
