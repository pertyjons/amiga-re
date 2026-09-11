//! Milestone 4: edits are reviewed, deterministic, and refuse to overwrite a
//! document that changed while they were being reviewed.

use std::path::{Path, PathBuf};

use amiga_project::edit::{Edit, EditError, EditPlan};

const ANNOTATIONS: &str = "analysis/annotations/main-code.json";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/contract")
}

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("amiga-edit-{tag}-{}", std::process::id()));
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

const RESOURCES: &str = "analysis/resources/graphics.json";

/// The contract fixture's index, as a plan reads it.
///
/// Assembled here rather than loaded so a test can name a document the project
/// does not list — which is how the "nowhere to put it" refusals are reached.
fn documents() -> amiga_project::document::DocumentIndex {
    amiga_project::document::DocumentIndex {
        sources: "analysis/sources.json".to_owned(),
        programs: vec!["analysis/programs/main.json".to_owned()],
        annotations: vec![
            ANNOTATIONS.to_owned(),
            "analysis/annotations/loader-code.json".to_owned(),
        ],
        resources: vec![
            RESOURCES.to_owned(),
            "analysis/resources/audio.json".to_owned(),
            "analysis/resources/data.json".to_owned(),
        ],
        types: vec!["analysis/types/game-types.json".to_owned()],
    }
}

#[test]
fn preparing_an_edit_writes_nothing() {
    let root = scratch("prepare");
    let before = std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap();

    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Rename {
            id: "function:init-graphics".to_owned(),
            name: "open_graphics".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    // Previewing is also read-only, and it is what a review dialog shows.
    let preview = plan.preview().unwrap_or_else(|error| panic!("{error}"));
    assert!(preview[ANNOTATIONS].contains("open_graphics"));
    assert_eq!(
        std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap(),
        before,
        "preparing or previewing an edit wrote to the project"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn applying_a_rename_changes_the_name_and_nothing_else() {
    let root = scratch("rename");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Rename {
            id: "function:init-graphics".to_owned(),
            name: "open_graphics".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    // The project still loads, and the rename is there.
    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let index = amiga_project::Index::build(&loaded.project);
    assert_eq!(
        index.at("image:main-executable", 0, 0).function,
        Some("open_graphics")
    );
    // The other image is untouched.
    assert_eq!(
        index.at("image:level-loader", 0, 0).function,
        Some("load_level")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_document_that_changed_since_review_refuses_the_write() {
    // The optimistic-concurrency check: this is what stops one person's rename
    // from silently discarding another's.
    let root = scratch("conflict");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Rename {
            id: "function:init-graphics".to_owned(),
            name: "open_graphics".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    // Someone else writes the document while the plan is being reviewed.
    let path = root.join(ANNOTATIONS);
    let mut document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    document["annotations"][0]["notes"] = serde_json::json!("edited by someone else");
    let theirs = serde_json::to_string_pretty(&document).unwrap();
    std::fs::write(&path, &theirs).unwrap();

    assert!(matches!(plan.apply(), Err(EditError::Conflict { .. })));
    // Their edit survives untouched: a refused plan writes nothing.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), theirs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_conflict_in_one_document_prevents_writing_any_of_them() {
    // Every document is computed before any is replaced, so a plan spanning two
    // files cannot half-apply.
    let root = scratch("atomic");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![
            Edit::Rename {
                id: "function:init-graphics".to_owned(),
                name: "open_graphics".to_owned(),
            },
            Edit::Rename {
                id: "function:load-level".to_owned(),
                name: "read_level".to_owned(),
            },
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let loader = root.join("analysis/annotations/loader-code.json");
    let before_main = std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap();
    std::fs::write(
        &loader,
        "{\"document_kind\":\"annotations\",\"format_version\":1,\"annotations\":[]}",
    )
    .unwrap();

    assert!(matches!(plan.apply(), Err(EditError::Conflict { .. })));
    assert_eq!(
        std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap(),
        before_main,
        "the first document was written before the second conflicted"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A write that fails part-way puts back the documents it had already replaced.
///
/// The conflict test above proves a *malformed* plan writes nothing, which was
/// always true. This is the other half: a plan that validated, started
/// installing, and then hit a directory it could not write into. Both documents
/// have to be what they were, because a plan spans documents that index each
/// other and a project holding a mixture of two changesets is one nothing in
/// the format can tell from a consistent one.
#[test]
fn a_write_that_fails_part_way_restores_the_documents_it_had_replaced() {
    let root = scratch("rollback");
    // A plan spanning both halves, so it writes into two directories and one of
    // them can be made to refuse.
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![
            Edit::Rename {
                id: "function:init-graphics".to_owned(),
                name: "open_graphics".to_owned(),
            },
            Edit::DefineResource {
                resource: palette("resource:rollback-palette"),
            },
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let before: Vec<(PathBuf, String)> = [
        ANNOTATIONS,
        "analysis/annotations/loader-code.json",
        RESOURCES,
    ]
    .iter()
    .map(|relative| {
        let path = root.join(relative);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}"));
        (path, text)
    })
    .collect();

    // A directory nothing may create or unlink in. The annotation documents
    // sort first and install cleanly; this one is where the plan stops, which
    // is the shape a disk filling up half-way has.
    let resources = root.join("analysis/resources");
    let mut locked = std::fs::metadata(&resources)
        .unwrap_or_else(|error| panic!("{error}"))
        .permissions();
    locked.set_readonly(true);
    std::fs::set_permissions(&resources, locked).unwrap_or_else(|error| panic!("{error}"));

    let failed = plan.apply().expect_err("the resource write must fail");
    assert!(matches!(failed, EditError::Install { .. }), "{failed:?}");

    let mut writable = std::fs::metadata(&resources)
        .unwrap_or_else(|error| panic!("{error}"))
        .permissions();
    #[expect(
        clippy::permissions_set_readonly_false,
        reason = "restoring the fixture so the assertions can read it"
    )]
    writable.set_readonly(false);
    std::fs::set_permissions(&resources, writable).unwrap_or_else(|error| panic!("{error}"));

    for (path, text) in before {
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}")),
            text,
            "{} holds neither the old changeset nor the new one",
            path.display()
        );
    }
    // And the project still loads, which is the property a mixture would cost.
    amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_rebase_records_the_new_digest_and_drops_the_stale_mark() {
    // A rebase is the one thing that clears staleness, and only a person can
    // assert it: nothing rebases automatically.
    let root = scratch("rebase");
    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let current = loaded
        .project
        .sources
        .objects
        .iter()
        .find(|object| object.id == "object:disk-1/s/main")
        .expect("the object")
        .sha256
        .clone();

    // Before: the stale annotation resolves nowhere.
    let index = amiga_project::Index::build(&loaded.project);
    assert!(index.at("image:main-executable", 0, 4).is_empty());
    assert_eq!(index.stale().len(), 1);

    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Rebase {
            id: "annotation:main/stale-note".to_owned(),
            object_sha256: current,
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    // After: it resolves, and nothing is stale.
    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let index = amiga_project::Index::build(&loaded.project);
    assert_eq!(
        index.at("image:main-executable", 0, 4).symbols,
        vec!["old_entry_point"]
    );
    assert!(index.stale().is_empty());
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_comment_can_be_added_to_an_existing_entity() {
    let root = scratch("comment");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Comment {
            id: "annotation:init-graphics/comment-2".to_owned(),
            on: amiga_project::edit::CommentSubject::Entity {
                entity_id: "function:init-graphics".to_owned(),
            },
            placement: "after".to_owned(),
            text: "Returns zero when the library is unavailable.".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let index = amiga_project::Index::build(&loaded.project);
    let resolved = index.at("image:main-executable", 0, 0);
    assert_eq!(resolved.comments.len(), 2);
    assert!(
        resolved
            .comments
            .iter()
            .any(|comment| comment.placement == "after")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_edit_naming_something_that_does_not_exist_is_refused_before_anything_is_read_twice() {
    let root = scratch("unknown");
    for edit in [
        Edit::Rename {
            id: "function:invented".to_owned(),
            name: "x".to_owned(),
        },
        Edit::Rebase {
            id: "symbol:invented".to_owned(),
            object_sha256: "0".repeat(64),
        },
        Edit::Comment {
            id: "annotation:new".to_owned(),
            on: amiga_project::edit::CommentSubject::Entity {
                entity_id: "function:invented".to_owned(),
            },
            placement: "before".to_owned(),
            text: "x".to_owned(),
        },
    ] {
        assert!(matches!(
            EditPlan::prepare(&root, &documents(), vec![edit]),
            Err(EditError::UnknownSubject { .. })
        ));
    }
    // And an ID that already exists cannot be reused.
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::Comment {
                id: "function:init-graphics".to_owned(),
                on: amiga_project::edit::CommentSubject::Entity {
                    entity_id: "function:init-graphics".to_owned()
                },
                placement: "before".to_owned(),
                text: "x".to_owned(),
            }]
        ),
        Err(EditError::DuplicateId { .. })
    ));
    // A comment is not renameable; only functions and symbols are.
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::Rename {
                id: "annotation:init-graphics/comment-1".to_owned(),
                name: "x".to_owned(),
            }]
        ),
        Err(EditError::NotRenameable { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_applied_edit_leaves_the_document_in_canonical_form() {
    // The formatter is what makes an edit a small diff rather than a rewrite.
    let root = scratch("canonical");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Rename {
            id: "function:init-graphics".to_owned(),
            name: "open_graphics".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    let text = std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        amiga_project::format_document(&value),
        text,
        "an applied edit did not leave the document formatted"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_checked_in_fixture_is_already_canonical() {
    // A fixture that is not in canonical form would make every edit test's
    // "leaves it formatted" assertion vacuously true on the first write.
    for relative in [
        "analysis/sources.json",
        "analysis/programs/main.json",
        "analysis/annotations/main-code.json",
        "analysis/annotations/loader-code.json",
        "analysis/resources/graphics.json",
        "analysis/types/game-types.json",
    ] {
        let text = std::fs::read_to_string(fixture().join(relative))
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            amiga_project::format_document(&value),
            text,
            "{relative} is not in canonical form"
        );
    }
}

// --- creating knowledge about bytes ------------------------------------------
//
// The capability the format was missing. `Comment` could always create a
// comment, but only about an annotation that already existed, so nothing could
// say "these bytes are a bitmap" — which is what classifying a region is.

fn object_target() -> amiga_project::document::Target {
    amiga_project::document::Target::Object {
        object_id: "object:assets/title-pixels".to_owned(),
        offset: 0,
        length: 16,
        object_sha256: "9047f384250347de3a519258915b4a5fca6d5ce7070a3023fccc2f04205bbb85"
            .to_owned(),
    }
}

#[test]
fn a_region_annotation_about_bytes_can_be_created_and_read_back() {
    let root = scratch("annotate");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Annotate {
            id: "annotation:title-pixels".to_owned(),
            kind: "region".to_owned(),
            target: object_target(),
            name: None,
            classification: Some("image".to_owned()),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    let text =
        std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap_or_else(|error| panic!("{error}"));
    let document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    let created = document["annotations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|annotation| annotation["id"] == "annotation:title-pixels")
        .unwrap_or_else(|| panic!("the region was not written: {text}"));
    assert_eq!(created["kind"], "region");
    assert_eq!(created["classification"], "image");
    // Byte-addressed, so it goes stale with its object like every other.
    assert_eq!(created["target"]["space"], "object");
    assert_eq!(created["target"]["object_id"], "object:assets/title-pixels");

    // It lands in exactly one document, not in every one the plan touched.
    let other = std::fs::read_to_string(root.join("analysis/annotations/loader-code.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!other.contains("annotation:title-pixels"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_edit_cannot_write_a_region_classification_the_schema_forbids() {
    let root = scratch("invalid-region-classification");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Annotate {
            id: "annotation:title-pixels".to_owned(),
            kind: "region".to_owned(),
            target: object_target(),
            name: None,
            classification: Some("bitmap".to_owned()),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let error = plan
        .preview()
        .expect_err("the schema-invalid edit must not produce a preview");
    assert!(
        matches!(
            &error,
            amiga_project::edit::EditError::SchemaViolation { .. }
        ),
        "{error}"
    );
    assert!(error.to_string().contains("DOCUMENT_SCHEMA_VIOLATION"));
    assert!(
        !std::fs::read_to_string(root.join(ANNOTATIONS))
            .unwrap_or_else(|error| panic!("{error}"))
            .contains("annotation:title-pixels")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_comment_can_be_about_a_byte_range_rather_than_an_annotation() {
    let root = scratch("comment-bytes");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::Comment {
            id: "annotation:why-a-bitmap".to_owned(),
            on: amiga_project::edit::CommentSubject::Bytes(Box::new(object_target())),
            placement: "before".to_owned(),
            text: "Two planes, and the palette is right after it.".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    let text =
        std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap_or_else(|error| panic!("{error}"));
    let document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    let created = document["annotations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|annotation| annotation["id"] == "annotation:why-a-bitmap")
        .unwrap_or_else(|| panic!("the comment was not written: {text}"));
    // The thing the entity-only form could not express.
    assert_eq!(created["target"]["space"], "object");
    assert_eq!(created["target"]["length"], 16);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_annotation_can_be_removed_and_an_unknown_one_cannot() {
    let root = scratch("remove");

    // A name a comment is about cannot simply go: removing it would leave the
    // comment pointing at nothing. Refused rather than cascaded, because
    // cascading would delete a person's reasoning along with the name.
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::Remove {
                id: "function:init-graphics".to_owned(),
            }],
        ),
        Err(amiga_project::EditError::StillReferenced { .. })
    ));

    // Removing the comment first is what makes the name removable.
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![
            Edit::Remove {
                id: "annotation:init-graphics/comment-1".to_owned(),
            },
            // A variable names its owning function, which is the second way one
            // annotation can be about another.
            Edit::Remove {
                id: "variable:init-graphics/library-base".to_owned(),
            },
            Edit::Remove {
                id: "function:init-graphics".to_owned(),
            },
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));
    let text =
        std::fs::read_to_string(root.join(ANNOTATIONS)).unwrap_or_else(|error| panic!("{error}"));
    assert!(!text.contains("\"function:init-graphics\""), "{text}");

    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::Remove {
                id: "function:invented".to_owned(),
            }],
        ),
        Err(amiga_project::EditError::UnknownSubject { .. })
    ));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_annotation_kind_the_format_does_not_define_is_refused() {
    let root = scratch("kind");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::Annotate {
                id: "annotation:thing".to_owned(),
                kind: "invented".to_owned(),
                target: object_target(),
                name: None,
                classification: None,
            }],
        ),
        Err(amiga_project::EditError::UnknownKind { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

/// A palette resource over the fixture's own object, so a plan that defines it
/// verifies against bytes the project describes.
fn palette(id: &str) -> amiga_project::document::Resource {
    amiga_project::document::Resource::Palette {
        id: id.to_owned(),
        name: "A palette".to_owned(),
        target: object_target(),
        format: "rgb4".to_owned(),
        count: 4,
        export: None,
        notes: None,
    }
}

fn image_reading(palette_id: Option<&str>) -> amiga_project::document::Resource {
    amiga_project::document::Resource::Image {
        id: "resource:new-logo".to_owned(),
        name: "New logo".to_owned(),
        target: object_target(),
        format: "planar".to_owned(),
        width: 8,
        height: 8,
        planes: 2,
        plane_order: None,
        palette_resource_id: palette_id.map(ToOwned::to_owned),
        export: None,
        notes: None,
    }
}

#[test]
fn a_resource_and_the_palette_it_reads_can_be_defined_in_one_plan() {
    // One thought, not two edits that have to be ordered by hand: a resource
    // this plan defines is a valid reference target inside it.
    let root = scratch("define-resource");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![
            Edit::DefineResource {
                resource: palette("resource:new-palette"),
            },
            Edit::DefineResource {
                resource: image_reading(Some("resource:new-palette")),
            },
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    // Only the resources documents are touched. An annotation edit and a
    // resource edit have no reason to widen each other's conflict check.
    assert!(
        plan.expects()
            .keys()
            .all(|path| path.contains("/resources/")),
        "{:?}",
        plan.expects().keys().collect::<Vec<_>>()
    );

    plan.apply().unwrap_or_else(|error| panic!("{error}"));
    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let ids: Vec<&str> = loaded
        .project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .map(|resource| resource.id().as_str())
        .collect();
    assert!(ids.contains(&"resource:new-palette"), "{ids:?}");
    assert!(ids.contains(&"resource:new-logo"), "{ids:?}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_resource_reference_is_checked_by_kind_where_it_is_written() {
    // The ID resolves; the decode still cannot run. Refused here rather than
    // discovered at export.
    let root = scratch("resource-kind");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineResource {
                resource: image_reading(Some("resource:title-logo")),
            }],
        ),
        Err(EditError::WrongReferenceKind {
            expected: "palette",
            ..
        })
    ));
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineResource {
                resource: image_reading(Some("resource:nothing-here")),
            }],
        ),
        Err(EditError::DanglingReference { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_resource_id_must_carry_the_prefix_the_format_uses() {
    let root = scratch("resource-prefix");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineResource {
                resource: palette("image:new-palette"),
            }],
        ),
        Err(EditError::WrongResourceIdKind { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_resource_an_artifact_was_made_from_is_not_removed_behind_its_back() {
    // Cascading would delete the record of a file that still exists, which is
    // the dangling state in the other direction.
    let root = scratch("resource-artifact");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::RemoveResource {
                id: "resource:title-logo".to_owned(),
            }],
        ),
        Err(EditError::ResourceHasArtifact { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn updating_a_resource_replaces_it_where_it_already_lives() {
    // Not moved to the primary document with the original left behind, which
    // is what "define" would do.
    let root = scratch("update-resource");
    let corrected = amiga_project::document::Resource::Palette {
        id: "resource:title-palette".to_owned(),
        name: "Title palette".to_owned(),
        target: object_target(),
        format: "rgb4".to_owned(),
        count: 16,
        export: None,
        notes: None,
    };
    EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::UpdateResource {
            resource: corrected,
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"))
    .apply()
    .unwrap_or_else(|error| panic!("{error}"));

    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let palettes: Vec<&amiga_project::document::Resource> = loaded
        .project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .filter(|resource| resource.id() == "resource:title-palette")
        .collect();
    assert_eq!(palettes.len(), 1, "the resource was duplicated");
    assert!(
        matches!(
            palettes[0],
            amiga_project::document::Resource::Palette { count: 16, .. }
        ),
        "{:?}",
        palettes[0]
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn updating_a_resource_that_does_not_exist_is_refused() {
    let root = scratch("update-unknown");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::UpdateResource {
                resource: palette("resource:not-here"),
            }],
        ),
        Err(EditError::UnknownResource { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

// --- types -------------------------------------------------------------------
//
// The half of the vocabulary that had a reader and a validator and no writer:
// `Resource::Table` named its record layout through `type_id` and nothing in the
// workspace could produce the `TypeDefinition` that id pointed at.

const TYPES: &str = "analysis/types/game-types.json";

fn integer(
    id: &str,
    name: &str,
    size: u8,
    signed: bool,
) -> amiga_project::document::TypeDefinition {
    amiga_project::document::TypeDefinition::Integer {
        id: id.to_owned(),
        name: name.to_owned(),
        size,
        signed,
        byte_order: "big".to_owned(),
        notes: None,
    }
}

fn types_of(
    project: &amiga_project::document::Project,
) -> Vec<&amiga_project::document::TypeDefinition> {
    project
        .types
        .iter()
        .flat_map(|document| &document.types)
        .collect()
}

#[test]
fn a_type_can_be_defined_and_read_back() {
    let root = scratch("define-type");
    EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::DefineType {
            definition: Box::new(integer("type:i8", "i8", 1, true)),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"))
    .apply()
    .unwrap_or_else(|error| panic!("{error}"));

    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let defined = types_of(&loaded.project)
        .into_iter()
        .find(|definition| definition.id() == "type:i8")
        .unwrap_or_else(|| panic!("the type was not written"));
    assert_eq!(defined.kind(), "integer");
    let _ = std::fs::remove_dir_all(&root);
}

/// The whole point of the entry: a table resource and the struct it decodes
/// through are one thought, so they go in one plan.
#[test]
fn a_table_and_the_record_type_it_decodes_through_can_be_defined_in_one_plan() {
    use amiga_core::record::parse_layout;

    let root = scratch("table-with-type");
    let layout = parse_layout("u16,u16,ptr,char[16]").expect("a layout");
    let record = amiga_project::record_type::definitions_for_layout(
        "type:record.enemies",
        "enemy_record",
        &layout,
    );
    let mut edits: Vec<Edit> = record
        .definitions
        .iter()
        // The fixture already defines `type:u16`; redefining it would be a
        // duplicate id, which is exactly the refusal that check exists for.
        .filter(|definition| definition.id() != "type:u16")
        .map(|definition| Edit::DefineType {
            definition: Box::new(definition.clone()),
        })
        .collect();
    edits.push(Edit::DefineResource {
        resource: amiga_project::document::Resource::Table {
            id: "resource:enemies".to_owned(),
            name: "enemies".to_owned(),
            target: object_target(),
            row_count: 12,
            row_stride: 24,
            type_id: Some(record.struct_id.clone()),
            notes: None,
            export: None,
        },
    });

    EditPlan::prepare(&root, &documents(), edits)
        .unwrap_or_else(|error| panic!("{error}"))
        .apply()
        .unwrap_or_else(|error| panic!("{error}"));

    // Reloaded from disk, and decoded from the stored type alone — no layout
    // string anywhere in this half of the test.
    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let stored = types_of(&loaded.project);
    let by_id = |id: &str| {
        stored
            .iter()
            .copied()
            .find(|definition| definition.id() == id)
    };
    let structure = by_id("type:record.enemies").unwrap_or_else(|| panic!("the struct is missing"));
    assert_eq!(
        amiga_project::record_type::layout_of(structure, &by_id)
            .unwrap_or_else(|error| panic!("{error}")),
        layout
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_table_naming_a_type_the_project_does_not_define_is_refused_where_it_is_written() {
    let root = scratch("table-dangling-type");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineResource {
                resource: amiga_project::document::Resource::Table {
                    id: "resource:ghosts".to_owned(),
                    name: "ghosts".to_owned(),
                    target: object_target(),
                    row_count: 1,
                    row_stride: 2,
                    type_id: Some("type:not-defined".to_owned()),
                    notes: None,
                    export: None,
                },
            }],
        ),
        Err(EditError::DanglingReference { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

/// A `type_id` that resolves to something that is not a type is the failure the
/// kind check exists for — an ID check alone would let it through.
#[test]
fn a_table_whose_type_id_names_a_resource_is_refused_by_kind() {
    let root = scratch("table-wrong-kind");
    let prepared = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::DefineResource {
            resource: amiga_project::document::Resource::Table {
                id: "resource:ghosts".to_owned(),
                name: "ghosts".to_owned(),
                target: object_target(),
                row_count: 1,
                row_stride: 2,
                type_id: Some("resource:title-palette".to_owned()),
                notes: None,
                export: None,
            },
        }],
    );
    assert!(
        matches!(
            prepared,
            Err(EditError::WrongReferenceKind {
                expected: "type",
                ..
            })
        ),
        "{prepared:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_struct_whose_field_points_at_nothing_is_refused() {
    let root = scratch("struct-dangling-field");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineType {
                definition: Box::new(amiga_project::document::TypeDefinition::Struct {
                    id: "type:record.broken".to_owned(),
                    name: "broken".to_owned(),
                    size: 2,
                    fields: vec![amiga_project::document::Field {
                        name: "first".to_owned(),
                        offset: 0,
                        type_id: "type:never-defined".to_owned(),
                        notes: None,
                    }],
                    notes: None,
                }),
            }],
        ),
        Err(EditError::DanglingReference { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn defining_a_type_twice_is_refused() {
    let root = scratch("duplicate-type");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineType {
                definition: Box::new(integer("type:u16", "u16", 2, false)),
            }],
        ),
        Err(EditError::DuplicateId { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_type_id_must_carry_the_prefix_the_format_uses() {
    let root = scratch("type-prefix");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::DefineType {
                definition: Box::new(integer("u16", "u16", 2, false)),
            }],
        ),
        Err(EditError::WrongTypeIdKind { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn updating_a_type_replaces_it_where_it_already_lives() {
    let root = scratch("update-type");
    EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::UpdateType {
            definition: Box::new(integer("type:s16", "int16", 2, true)),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"))
    .apply()
    .unwrap_or_else(|error| panic!("{error}"));

    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let matching: Vec<_> = types_of(&loaded.project)
        .into_iter()
        .filter(|definition| definition.id() == "type:s16")
        .collect();
    assert_eq!(matching.len(), 1, "the type was duplicated");
    assert!(
        matches!(
            matching[0],
            amiga_project::document::TypeDefinition::Integer { name, .. } if name == "int16"
        ),
        "{:?}",
        matching[0]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn updating_a_type_that_does_not_exist_is_refused() {
    let root = scratch("update-unknown-type");
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::UpdateType {
                definition: Box::new(integer("type:not-here", "nope", 2, false)),
            }],
        ),
        Err(EditError::UnknownType { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_type_can_be_removed_and_an_unknown_one_cannot() {
    let root = scratch("remove-type");
    // Defined here rather than picked from the fixture: every type the fixture
    // ships is read by something, which is the refusal the next test is about.
    EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::DefineType {
            definition: Box::new(integer("type:i8", "i8", 1, true)),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"))
    .apply()
    .unwrap_or_else(|error| panic!("{error}"));

    EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RemoveType {
            id: "type:i8".to_owned(),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"))
    .apply()
    .unwrap_or_else(|error| panic!("{error}"));

    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        !types_of(&loaded.project)
            .iter()
            .any(|definition| definition.id() == "type:i8")
    );

    assert!(matches!(
        EditPlan::prepare(
            &root,
            &documents(),
            vec![Edit::RemoveType {
                id: "type:i8".to_owned(),
            }],
        ),
        Err(EditError::UnknownType { .. })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

/// Refused rather than cascaded, like every other reference this format checks:
/// a struct whose field type vanished decodes nothing.
#[test]
fn a_type_another_type_points_at_is_not_removed_behind_its_back() {
    let root = scratch("remove-referenced-type");
    let refused = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RemoveType {
            id: "type:u16".to_owned(),
        }],
    );
    assert!(
        matches!(refused, Err(EditError::StillReferenced { .. })),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The same, for the resource side: removing the type a table decodes through
/// would leave that table unable to decode.
#[test]
fn a_type_a_table_decodes_through_is_not_removed_behind_its_back() {
    use amiga_core::record::parse_layout;

    let root = scratch("remove-read-type");
    let layout = parse_layout("u8").expect("a layout");
    let record =
        amiga_project::record_type::definitions_for_layout("type:record.rows", "rows", &layout);
    let mut edits: Vec<Edit> = record
        .definitions
        .iter()
        .filter(|definition| definition.id() != "type:u8")
        .map(|definition| Edit::DefineType {
            definition: Box::new(definition.clone()),
        })
        .collect();
    edits.push(Edit::DefineResource {
        resource: amiga_project::document::Resource::Table {
            id: "resource:rows".to_owned(),
            name: "rows".to_owned(),
            target: object_target(),
            row_count: 4,
            row_stride: 1,
            type_id: Some(record.struct_id.clone()),
            notes: None,
            export: None,
        },
    });
    EditPlan::prepare(&root, &documents(), edits)
        .unwrap_or_else(|error| panic!("{error}"))
        .apply()
        .unwrap_or_else(|error| panic!("{error}"));

    let refused = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RemoveType {
            id: "type:record.rows".to_owned(),
        }],
    );
    assert!(
        matches!(refused, Err(EditError::TypeStillRead { .. })),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A type edit rewrites the type documents and no others, so its conflict check
/// covers exactly what it can change.
#[test]
fn a_type_edit_expects_only_the_type_documents() {
    let root = scratch("type-scope");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::DefineType {
            definition: Box::new(integer("type:i8", "i8", 1, true)),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        plan.expects().keys().cloned().collect::<Vec<_>>(),
        vec![TYPES.to_owned()]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_type_has_nowhere_to_go_in_a_project_that_lists_no_type_document() {
    let root = scratch("no-type-document");
    let mut index = documents();
    index.types.clear();
    assert!(matches!(
        EditPlan::prepare(
            &root,
            &index,
            vec![Edit::DefineType {
                definition: Box::new(integer("type:i8", "i8", 1, true)),
            }],
        ),
        Err(EditError::NoTypeDocument)
    ));
    let _ = std::fs::remove_dir_all(&root);
}

const SOURCES: &str = "analysis/sources.json";

/// A source as a caller composes one: pinned by size and digest, and with a
/// recorded location so the bytes can be found again.
fn media_source(id: &str) -> amiga_project::document::Source {
    amiga_project::document::Source {
        id: id.to_owned(),
        kind: amiga_project::document::SourceKind::File,
        media_type: None,
        display_name: "Disk 4".to_owned(),
        size: Some(901_120),
        sha256: Some("a".repeat(64)),
        inventory: None,
        tree_sha256: None,
        locations: vec![amiga_project::document::Location::ProjectRelative {
            path: "original/disk4.adf".to_owned(),
        }],
        provenance: amiga_project::document::Provenance::Media,
        notes: None,
    }
}

/// The scope that did not exist. A project's sources document was written once
/// by `project.init` and by nothing afterwards, so bytes that came into
/// existence later had to be added by editing JSON by hand.
#[test]
fn a_registered_source_joins_the_sources_document() {
    let root = scratch("register-source");
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RegisterSource {
            source: Box::new(media_source("source:disk4")),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    // The plan reads and rewrites the sources document, and only it: an edit
    // that also rewrote every annotation document would widen the conflict
    // check for no reason.
    assert_eq!(
        plan.expects().keys().collect::<Vec<_>>(),
        vec![SOURCES],
        "a source edit read documents it cannot change"
    );

    plan.apply().unwrap_or_else(|error| panic!("{error}"));
    let written = std::fs::read_to_string(root.join(SOURCES)).unwrap();
    assert!(written.contains("source:disk4"), "{written}");
    // And the project still loads, which is the check that the document is a
    // document rather than JSON that happens to parse.
    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        loaded
            .project
            .sources
            .sources
            .iter()
            .any(|source| source.id == "source:disk4")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_source_cannot_reuse_an_id_or_take_the_wrong_prefix() {
    let root = scratch("register-source-ids");
    let existing = amiga_project::load(&root)
        .unwrap_or_else(|error| panic!("{error}"))
        .project
        .sources
        .sources
        .first()
        .map(|source| source.id.clone())
        .unwrap_or_else(|| panic!("the fixture lists no source"));

    let duplicate = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RegisterSource {
            source: Box::new(media_source(&existing)),
        }],
    );
    assert!(
        matches!(duplicate, Err(EditError::DuplicateId { id }) if id == existing),
        "a source reused an id"
    );

    let misprefixed = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RegisterSource {
            source: Box::new(media_source("object:disk4")),
        }],
    );
    assert!(
        matches!(misprefixed, Err(EditError::WrongSourceIdKind { .. })),
        "a source took an id from another namespace"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A capture is bytes nothing can obtain again, so the sentence naming what
/// produced them is the only provenance they will ever have. Refused where it
/// is written rather than discovered at the next load.
#[test]
fn a_capture_without_a_note_is_refused() {
    let root = scratch("register-capture-note");
    let mut source = media_source("source:framebuffer");
    source.provenance = amiga_project::document::Provenance::Captured;

    for notes in [None, Some(String::new()), Some("   ".to_owned())] {
        let mut attempt = source.clone();
        attempt.notes = notes.clone();
        assert!(
            matches!(
                EditPlan::prepare(
                    &root,
                    &documents(),
                    vec![Edit::RegisterSource {
                        source: Box::new(attempt)
                    }],
                ),
                Err(EditError::CaptureUnexplained { .. })
            ),
            "a capture explained by {notes:?} was accepted"
        );
    }

    source.notes = Some("env.sandbox.call over hunk 0 entry 0x40".to_owned());
    let plan = EditPlan::prepare(
        &root,
        &documents(),
        vec![Edit::RegisterSource {
            source: Box::new(source),
        }],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    plan.apply().unwrap_or_else(|error| panic!("{error}"));

    let loaded = amiga_project::load(&root).unwrap_or_else(|error| panic!("{error}"));
    let registered = loaded
        .project
        .sources
        .sources
        .iter()
        .find(|source| source.id == "source:framebuffer")
        .unwrap_or_else(|| panic!("the capture was not registered"));
    assert!(
        !registered.is_reproducible(),
        "a capture was recorded as reproducible media"
    );
    let _ = std::fs::remove_dir_all(&root);
}
