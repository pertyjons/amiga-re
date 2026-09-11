//! Operations Milestone 5: the versioned project format, reachable through the
//! shared API.

use std::path::{Path, PathBuf};

use amiga_operations::{
    DiagnosticCode, ExecutionContext, FilesystemSourceResolver, InMemorySourceResolver,
    OperationRequestDocument, ProjectArguments, ProjectLocator, RequestEnvelope, ResolvedSource,
    Router, SourceName, Status,
};

/// The project crate's contract fixture, addressed relative to a root the
/// adapter chooses — exactly as a source is.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../amiga-project/fixtures")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the project fixtures are readable: {error}"))
}

fn request(document: OperationRequestDocument, project: Option<&str>) -> RequestEnvelope {
    let mut envelope = RequestEnvelope::read(document);
    envelope.project = project.map(|path| ProjectLocator::Path {
        path: path.to_owned(),
    });
    envelope
}

#[test]
fn checking_the_contract_fixture_reports_a_clean_project() {
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let check = outcome.project_check().expect("the check ran");
    assert_eq!(check.name, "Contract fixture");
    assert_eq!(check.sources, 5);
    assert_eq!(check.objects, 6);
    assert!(check.annotations >= 7);
    assert!(check.problems.is_empty(), "{:?}", check.problems);
}

#[test]
fn project_check_refuses_a_document_the_bundled_schema_forbids() {
    let base = std::env::temp_dir().join(format!(
        "amiga-operations-project-schema-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    copy_tree(&root(), &base);
    let path = base.join("contract/analysis/sources.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}"));
    let mut document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    document["sources"][0]["sha256"] = serde_json::json!("abc");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let resolver = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.project_check().is_none());
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("DOCUMENT_SCHEMA_VIOLATION")
                && diagnostic.message.contains("/sources/0/sha256")
        }),
        "{:?}",
        outcome.diagnostics
    );

    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn verifying_the_contract_fixture_finds_no_contradiction() {
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let verify = outcome.project_verify().expect("the verify ran");
    assert_eq!(verify.verified_sources, 5);
    // Every source and object appears, including the ones that could not be
    // attempted: nothing is skipped silently at the API boundary either.
    assert_eq!(verify.sources.len(), 5);
    assert_eq!(verify.objects.len(), 6);
    assert!(verify.objects.iter().all(|object| !object.contradicted));
    // `verified` and `contradicted` are not opposites, and the wire keeps them
    // apart: the directory-source member is neither.
    assert!(
        verify
            .objects
            .iter()
            .any(|object| !object.verified && !object.contradicted),
        "{:?}",
        verify.objects
    );
}

/// A project whose only object is decompressed from its parent, written to a
/// temporary directory with the bytes to back it.
///
/// Built rather than checked in because the packed stream is the point: the
/// operation has to *run* the recorded recipe and compare what it produced, so
/// the stream and the pin have to agree by construction.
fn packed_project(tag: &str, declared_size: u32, marker: u32) -> PathBuf {
    // A 4-byte big-endian size field, then "AB", then (marker 0x90, 2, 'C')
    // expanding to "CCC", then "D" — all XORed with each byte's own index.
    let mut stream = 6_u32.to_be_bytes().to_vec();
    stream.extend_from_slice(&[b'A', b'B', 0x90, 2, b'C', b'D']);
    let packed: Vec<u8> = stream
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ (index as u8))
        .collect();

    let base = std::env::temp_dir().join(format!("amiga-operations-{tag}-{}", std::process::id()));
    let root = base.join("packed");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(root.join("original")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::create_dir_all(root.join("analysis")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(root.join("original/packed.bin"), &packed)
        .unwrap_or_else(|error| panic!("{error}"));

    let digest = amiga_core::sha256;
    std::fs::write(
        root.join("amiga-re.project.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "project",
            "format_version": 1,
            "project": { "id": "project:packed", "name": "Packed demo" },
            "documents": { "sources": "analysis/sources.json" }
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(
        root.join("analysis/sources.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "sources",
            "format_version": 1,
            "sources": [{
                "id": "source:packed",
                "kind": "file",
                "media_type": "binary",
                "display_name": "A packed blob",
                "size": packed.len(),
                "sha256": digest(&packed),
                "locations": [{ "kind": "project_relative", "path": "original/packed.bin" }]
            }],
            "objects": [{
                "id": "object:packed/unpacked",
                "kind": "decompressed",
                "parent_id": "source:packed",
                "selector": {
                    "container": "decompressed",
                    "codec": {
                        "name": "rle_xor",
                        "marker": marker,
                        "xor": true,
                        "inline_marker": false,
                        "size_bytes": 4,
                        "size_includes_field": false
                    },
                    "declared_size": declared_size
                },
                "size": 6,
                "sha256": digest(b"ABCCCD")
            }]
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    base
}

fn verify_packed(base: &Path) -> amiga_operations::OperationOutcome {
    let resolver = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&resolver);
    Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("packed"),
        ),
        &context,
    )
}

#[test]
fn the_router_re_derives_a_decompressed_object_rather_than_refusing_it() {
    // The divergence this closes: recovery used not to be supplied here, so a
    // project the command line verified came back through the router with every
    // recoverable object unrecoverable — and therefore contradicted.
    let base = packed_project("verify-packed", 6, 0x90);
    let outcome = verify_packed(&base);

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let verify = outcome.project_verify().expect("the verify ran");
    assert_eq!(verify.verified_objects, 1);
    assert_eq!(verify.objects[0].status, "verified");
    assert!(!verify.objects[0].contradicted);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_router_contradicts_a_recipe_that_produces_other_bytes() {
    // The digest is what makes the recipe an authority. A wrong marker decodes
    // the same stream into something else, and the status vocabulary has to say
    // which of the failures this is.
    let base = packed_project("verify-wrong-marker", 6, 0x91);
    let outcome = verify_packed(&base);

    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ProjectContradicted),
        "{:?}",
        outcome.diagnostics
    );
    let verify = outcome.project_verify().expect("the verify still reports");
    assert_eq!(verify.objects[0].status, "mismatch");
    assert!(verify.objects[0].contradicted);
    // The pinned and recovered digests are both named, shortened for reading.
    assert!(
        verify.objects[0].detail.contains("pinned"),
        "{:?}",
        verify.objects[0]
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_router_refuses_a_declared_size_the_stream_disagrees_with() {
    // A stated refusal, distinguishable from a mismatch: the recipe is wrong,
    // not the bytes.
    let base = packed_project("verify-bad-declared", 7, 0x90);
    let outcome = verify_packed(&base);

    assert_eq!(outcome.status, Status::Error);
    let verify = outcome.project_verify().expect("the verify still reports");
    assert_eq!(verify.objects[0].status, "unrecoverable");
    assert_eq!(
        verify.objects[0].detail,
        "the record declares 7 output byte(s) but the stream declares 6"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_recorded_size_the_bytes_disagree_with_is_not_reported_as_a_digest_mismatch() {
    // The recipe and digest are correct, but the recorded size is not. The diagnostic
    // must name the two sizes that disagree rather than printing the same digest twice.
    let base = packed_project("verify-wrong-size", 6, 0x90);
    let sources = base.join("packed/analysis/sources.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sources).unwrap_or_else(|error| panic!("{error}")))
            .unwrap_or_else(|error| panic!("{error}"));
    document["objects"][0]["size"] = serde_json::json!(7);
    std::fs::write(&sources, serde_json::to_vec_pretty(&document).unwrap())
        .unwrap_or_else(|error| panic!("{error}"));

    let outcome = verify_packed(&base);
    assert_eq!(outcome.status, Status::Error);
    let verify = outcome.project_verify().expect("the verify still reports");
    assert_eq!(verify.objects[0].status, "size_mismatch");
    assert!(verify.objects[0].contradicted);
    let detail = &verify.objects[0].detail;
    assert!(detail.contains('7') && detail.contains('6'), "{detail}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_verified_entity_carries_a_code_a_frontend_can_match_on() {
    // Prose is for a person; the code is the contract. Every status the report
    // can carry has to be one of the documented codes, or a frontend rendering
    // by code would silently fall through to a default.
    const CODES: &[&str] = &[
        "verified",
        "unbound",
        "missing",
        "unreadable",
        "mismatch",
        "size_mismatch",
        "parent_unavailable",
        "selector_out_of_range",
        "unrecoverable",
    ];
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    let verify = outcome.project_verify().expect("the verify ran");
    for entity in verify.sources.iter().chain(&verify.objects) {
        assert!(CODES.contains(&entity.status), "{entity:?}");
        assert!(!entity.detail.is_empty(), "{entity:?}");
    }
}

#[test]
fn a_project_operation_without_a_project_locator_is_refused() {
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            None,
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::RequestProjectRequired
    );
    // Refused before any work ran, which is how automation tells it from a
    // project that failed to load.
    assert_eq!(outcome.exit_code(), 2);
}

#[test]
fn a_non_project_operation_carrying_a_project_locator_is_refused() {
    // The mirror. A locator on an operation that takes none is a request that
    // means something the toolkit will not do, and silently ignoring it would
    // hide the caller's mistake.
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ContainerAdfList(amiga_operations::AdfListArguments::new(
                "contract/original/disk1.adf",
            )),
            Some("contract"),
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::RequestProjectUnsupported
    );
}

#[test]
fn a_project_locator_obeys_the_same_path_rules_as_a_source() {
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    for escaping in ["../escape", "/absolute", "contract/../../escape"] {
        let outcome = Router::execute(
            &request(
                OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
                Some(escaping),
            ),
            &context,
        );
        assert_eq!(outcome.status, Status::Error, "{escaping}");
        assert_eq!(
            outcome.diagnostics[0].code,
            DiagnosticCode::RequestSourceNameInvalid,
            "{escaping}"
        );
    }
}

#[test]
fn a_context_with_no_directory_cannot_locate_a_project() {
    // An in-memory resolver serves bytes, not locations. A project needs a
    // directory, and the operation says so rather than inventing one.
    let name = SourceName::parse("bytes.bin").expect("a relative name");
    let resolver =
        InMemorySourceResolver::new(ResolvedSource::new(name, std::sync::Arc::from(&b""[..])));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::ProjectUnreadable
    );
}

#[test]
fn the_two_project_operations_have_different_request_digests() {
    // Same project, different question: the digest identifies what was asked
    // for, and asking two things must not look like asking one twice.
    let resolver = FilesystemSourceResolver::new(root());
    let context = ExecutionContext::new(&resolver);
    let check = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    let verify = Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    assert_ne!(
        check.normalized_request_sha256,
        verify.normalized_request_sha256
    );
}

// --- project.edit ------------------------------------------------------------

/// A copy of the contract fixture, so an edit test writes to its own tree.
fn edit_workspace(name: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "amiga-operations-edit-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    copy_tree(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../amiga-project/fixtures/contract"),
        &base.join("contract"),
    );
    base
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
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

fn edit_envelope(mode: amiga_operations::ExecutionMode) -> amiga_operations::RequestEnvelope {
    let mut envelope = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ProjectEdit(
            amiga_operations::ProjectEditArguments::new(vec![
                amiga_operations::ProjectEdit::Rename {
                    id: "function:init-graphics".to_owned(),
                    name: "setup_display".to_owned(),
                },
            ]),
        ),
    );
    envelope.project = Some(amiga_operations::ProjectLocator::Path {
        path: "contract".to_owned(),
    });
    envelope.execution.mode = mode;
    envelope
}

#[test]
fn preparing_an_edit_writes_nothing() {
    let base = edit_workspace("prepare");
    let document = base.join("contract/analysis/annotations/main-code.json");
    let before = std::fs::read(&document).unwrap_or_else(|error| panic!("{error}"));

    let resolver = amiga_operations::FilesystemSourceResolver::new(&base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let outcome = amiga_operations::Router::execute(
        &edit_envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );

    assert_eq!(
        outcome.status,
        amiga_operations::Status::Prepared,
        "{:?}",
        outcome.diagnostics
    );
    let plan = outcome.project_edit().expect("a plan");
    assert!(!plan.committed);
    assert!(plan.written.is_empty());
    assert!(
        plan.documents.iter().any(|entry| entry.changed),
        "the plan changes nothing: {:?}",
        plan.documents
    );
    assert_eq!(
        std::fs::read(&document).unwrap_or_else(|error| panic!("{error}")),
        before,
        "preparing wrote to the project"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn committing_a_stale_plan_is_refused() {
    // The plan digest asks "is this the plan you reviewed?". A digest that was
    // never this request's answer must not authorize a write.
    let base = edit_workspace("stale");
    let document = base.join("contract/analysis/annotations/main-code.json");
    let before = std::fs::read(&document).unwrap_or_else(|error| panic!("{error}"));

    let resolver = amiga_operations::FilesystemSourceResolver::new(&base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let outcome = amiga_operations::Router::execute(
        &edit_envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: "0".repeat(64),
        }),
        &context,
    );

    assert_eq!(outcome.status, amiga_operations::Status::Conflict);
    assert!(
        outcome.diagnostics.iter().any(
            |diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::OutputPlanChanged
        ),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(
        std::fs::read(&document).unwrap_or_else(|error| panic!("{error}")),
        before,
        "a refused commit wrote to the project"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_reviewed_plan_commits_and_reports_what_it_wrote() {
    let base = edit_workspace("commit");
    let resolver = amiga_operations::FilesystemSourceResolver::new(&base);
    let context = amiga_operations::ExecutionContext::new(&resolver);

    let prepared = amiga_operations::Router::execute(
        &edit_envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    let digest = prepared.project_edit().expect("a plan").plan_sha256.clone();

    let committed = amiga_operations::Router::execute(
        &edit_envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest,
        }),
        &context,
    );
    assert_eq!(
        committed.status,
        amiga_operations::Status::Success,
        "{:?}",
        committed.diagnostics
    );
    let applied = committed.project_edit().expect("a plan");
    assert!(applied.committed);
    assert!(!applied.written.is_empty());
    let text = std::fs::read_to_string(base.join("contract/analysis/annotations/main-code.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("setup_display"), "the rename did not land");

    let _ = std::fs::remove_dir_all(&base);
}

/// A project whose media lives outside its own root, with no project-relative
/// location to find it by. Returns the temporary base and the source's absolute
/// host path.
fn project_with_external_media(tag: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let bytes = b"outside the project root".to_vec();
    let base = std::env::temp_dir().join(format!("amiga-operations-{tag}-{}", std::process::id()));
    let root = base.join("proj");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(root.join("analysis")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::create_dir_all(base.join("media")).unwrap_or_else(|error| panic!("{error}"));
    let media = base.join("media/disk.bin");
    std::fs::write(&media, &bytes).unwrap_or_else(|error| panic!("{error}"));

    std::fs::write(
        root.join("amiga-re.project.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "project",
            "format_version": 1,
            "project": { "id": "project:external", "name": "External media" },
            "documents": { "sources": "analysis/sources.json" }
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(
        root.join("analysis/sources.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "sources",
            "format_version": 1,
            // No `locations`: the project genuinely does not know where this
            // machine keeps the file, which is the case the bindings exist for.
            "sources": [{
                "id": "source:disk-1",
                "kind": "file",
                "media_type": "binary",
                "display_name": "Disk 1",
                "size": bytes.len(),
                "sha256": amiga_core::sha256(&bytes)
            }]
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    (base, media, bytes)
}

fn verify_external(base: &Path) -> amiga_operations::OperationOutcome {
    let resolver = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&resolver);
    Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("proj"),
        ),
        &context,
    )
}

#[test]
fn media_outside_the_root_verifies_only_once_this_machine_says_where_it_is() {
    let (base, media, _) = project_with_external_media("external-media");

    // Without bindings the project is not wrong, it is merely incomplete here:
    // the source is unbound, and nothing pretends to have checked it.
    let outcome = verify_external(&base);
    let verify = outcome.project_verify().expect("the verify ran");
    assert_eq!(verify.sources.len(), 1);
    assert_eq!(verify.sources[0].status, "unbound");
    assert!(!verify.sources[0].verified);
    assert!(
        !verify.sources[0].contradicted,
        "absent media must not read as a contradiction"
    );

    // The documented escape hatch, now actually read.
    std::fs::create_dir_all(base.join("proj/.amiga-re")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(
        base.join("proj/.amiga-re/local.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "local",
            "format_version": 1,
            "bindings": { "source:disk-1": media.to_string_lossy() }
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let outcome = verify_external(&base);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let verify = outcome.project_verify().expect("the verify ran");
    assert_eq!(verify.sources[0].status, "verified");
    assert!(verify.sources[0].verified);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_broken_bindings_file_warns_and_leaves_the_source_unbound() {
    let (base, _, _) = project_with_external_media("external-broken");
    std::fs::create_dir_all(base.join("proj/.amiga-re")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("proj/.amiga-re/local.json"), b"{ not json")
        .unwrap_or_else(|error| panic!("{error}"));

    let outcome = verify_external(&base);
    // The project still loads: a machine-local file is not project truth.
    let verify = outcome.project_verify().expect("the verify ran");
    assert_eq!(verify.sources[0].status, "unbound");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::LocalBindingsUnreadable),
        "a dropped override must say so: {:?}",
        outcome.diagnostics
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_region_can_be_classified_through_the_operation_boundary() {
    // `Edit::Comment` existed in the library and was reachable from no frontend,
    // and no edit at all could create an annotation about *bytes*. Both are what
    // this exercises: the request vocabulary, not the crate behind it.
    let base =
        std::env::temp_dir().join(format!("amiga-operations-annotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    copy_tree(&root(), &base);

    let resolver = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&resolver);
    // No digest is supplied: the request names the bytes, and the operation
    // pins them to what the project says that object is.
    let target = amiga_operations::ProjectEditTarget::Object {
        object_id: "object:assets/title-pixels".to_owned(),
        offset: 0,
        length: 16,
    };

    let edits = vec![
        amiga_operations::ProjectEdit::Annotate {
            id: "annotation:title-pixels".to_owned(),
            kind: "region".to_owned(),
            target,
            name: None,
            classification: Some("image".to_owned()),
        },
        amiga_operations::ProjectEdit::Comment {
            id: "annotation:why-a-bitmap".to_owned(),
            target: amiga_operations::ProjectEditTarget::Entity {
                entity_id: "annotation:title-pixels".to_owned(),
            },
            placement: "before".to_owned(),
            text: "Two planes; the palette follows it.".to_owned(),
        },
    ];
    let envelope = |mode| {
        let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectEdit(
            amiga_operations::ProjectEditArguments::new(edits.clone()),
        ));
        envelope.project = Some(ProjectLocator::Path {
            path: "contract".to_owned(),
        });
        envelope.execution.mode = mode;
        envelope
    };

    let prepared = Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let plan = prepared.project_edit().expect("a plan");
    let committed = Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan_sha256.clone(),
        }),
        &context,
    );
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );

    // Reloading is the real assertion: the project must still be one.
    let checked = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    assert_eq!(checked.status, Status::Success, "{:?}", checked.diagnostics);
    let text = std::fs::read_to_string(base.join("contract/analysis/annotations/main-code.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("annotation:title-pixels"), "{text}");
    assert!(text.contains("annotation:why-a-bitmap"), "{text}");

    let _ = std::fs::remove_dir_all(&base);
}

// --- project.annotations, object scope ---------------------------------------

/// Classify two ranges of one object and comment on one of them.
///
/// Written through the operation boundary rather than into the document, so the
/// listing below is reading back what a frontend would actually have produced.
fn classified_object(tag: &str) -> (PathBuf, FilesystemSourceResolver) {
    let base = std::env::temp_dir().join(format!(
        "amiga-operations-object-annotations-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    copy_tree(&root(), &base);

    let resolver = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&resolver);
    let object = |offset, length| amiga_operations::ProjectEditTarget::Object {
        object_id: "object:assets/title-pixels".to_owned(),
        offset,
        length,
    };
    let edits = vec![
        // Deliberately out of file order: the listing sorts, and a test that
        // wrote them in order could not tell sorting from luck.
        amiga_operations::ProjectEdit::Annotate {
            id: "annotation:title-palette".to_owned(),
            kind: "region".to_owned(),
            target: object(12, 4),
            name: None,
            classification: Some("palette".to_owned()),
        },
        amiga_operations::ProjectEdit::Annotate {
            id: "annotation:title-pixels".to_owned(),
            kind: "region".to_owned(),
            target: object(0, 12),
            name: None,
            classification: Some("image".to_owned()),
        },
        amiga_operations::ProjectEdit::Comment {
            id: "annotation:why-a-bitmap".to_owned(),
            target: object(0, 12),
            placement: "before".to_owned(),
            text: "Two planes; the palette follows it.".to_owned(),
        },
    ];
    let envelope = |mode| {
        let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectEdit(
            amiga_operations::ProjectEditArguments::new(edits.clone()),
        ));
        envelope.project = Some(ProjectLocator::Path {
            path: "contract".to_owned(),
        });
        envelope.execution.mode = mode;
        envelope
    };
    let prepared = Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    let plan = prepared.project_edit().expect("a plan");
    let committed = Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan_sha256.clone(),
        }),
        &context,
    );
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );
    (base, resolver)
}

fn ask_about(
    resolver: &FilesystemSourceResolver,
    arguments: amiga_operations::ProjectAnnotationsArguments,
) -> amiga_operations::OperationOutcome {
    let context = ExecutionContext::new(resolver);
    Router::execute(
        &request(
            OperationRequestDocument::ProjectAnnotations(arguments),
            Some("contract"),
        ),
        &context,
    )
}

#[test]
fn an_object_reports_every_claim_made_about_its_bytes() {
    // Recorded knowledge must be readable by object as well as by image. A project
    // created by this toolkit can contain objects without any program image.
    let (base, resolver) = classified_object("list");
    let outcome = ask_about(
        &resolver,
        amiga_operations::ProjectAnnotationsArguments::object("object:assets/title-pixels"),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let annotations = outcome.project_annotations().expect("the listing ran");

    assert_eq!(
        annotations.object.as_deref(),
        Some("object:assets/title-pixels")
    );
    assert_eq!(annotations.image, None);
    assert_eq!(annotations.range_total, 3);
    assert!(!annotations.ranges_truncated);
    // File order, not document order: the palette was written first.
    let listed: Vec<(&str, u64, &str)> = annotations
        .ranges
        .iter()
        .map(|range| (range.id.as_str(), range.offset, range.label.as_str()))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("annotation:title-pixels", 0, "image"),
            (
                "annotation:why-a-bitmap",
                0,
                "Two planes; the palette follows it."
            ),
            ("annotation:title-palette", 12, "palette"),
        ],
        "{:?}",
        annotations.ranges
    );

    let comment = &annotations.ranges[1];
    assert_eq!(comment.kind, "comment");
    assert_eq!(comment.placement.as_deref(), Some("before"));
    // Every one of them was established against the object as it is, so every
    // one is trustworthy — which is what makes `established: false` mean
    // something when it appears.
    assert!(annotations.ranges.iter().all(|range| range.established));
    assert!(annotations.ranges.iter().all(|range| !range.marked_stale));
    assert!(
        annotations
            .ranges
            .iter()
            .all(|range| range.origin == "user")
    );
    // Hunk-space knowledge does not leak into an object's answer, and the
    // reverse holds too.
    assert!(annotations.locations.is_empty());
    assert!(annotations.locals.is_empty());
    assert!(annotations.globals.is_empty());
    assert!(
        annotations
            .objects
            .iter()
            .any(|id| id == "object:assets/title-pixels")
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_annotation_whose_bytes_moved_is_listed_in_place_and_marked() {
    // The property the digest is carried for, and the reason object scope does
    // not copy image scope's exclusion: nothing is resolved here, so hiding the
    // annotation would hide the one row the reader has to act on.
    let (base, resolver) = classified_object("stale");
    let document = base.join("contract/analysis/annotations/main-code.json");
    let text = std::fs::read_to_string(&document).unwrap_or_else(|error| panic!("{error}"));
    let mut value: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    let annotations = value["annotations"]
        .as_array_mut()
        .expect("the document lists annotations");
    for annotation in annotations.iter_mut() {
        if annotation["id"] == "annotation:title-pixels" {
            annotation["target"]["object_sha256"] = serde_json::Value::String("0".repeat(64));
        }
    }
    std::fs::write(&document, value.to_string()).unwrap_or_else(|error| panic!("{error}"));

    let outcome = ask_about(
        &resolver,
        amiga_operations::ProjectAnnotationsArguments::object("object:assets/title-pixels"),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let annotations = outcome.project_annotations().expect("the listing ran");
    assert_eq!(annotations.range_total, 3, "the row is listed, not dropped");
    let moved = annotations
        .ranges
        .iter()
        .find(|range| range.id == "annotation:title-pixels")
        .expect("the annotation is still reported");
    assert!(!moved.established);
    assert!(
        annotations
            .ranges
            .iter()
            .filter(|range| range.id != "annotation:title-pixels")
            .all(|range| range.established),
        "only the one that moved is unestablished"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_unknown_object_is_refused_with_the_objects_that_do_exist() {
    let (base, resolver) = classified_object("unknown");
    let outcome = ask_about(
        &resolver,
        amiga_operations::ProjectAnnotationsArguments::object("object:not-here"),
    );
    assert_eq!(outcome.status, Status::Error);
    let message = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.is_error())
        .map(|diagnostic| diagnostic.message.clone())
        .unwrap_or_default();
    assert!(message.contains("object:not-here"), "{message}");
    // The list of what is here travels with the refusal, so the caller is not
    // sent back to ask a second question.
    assert!(message.contains("object:assets/title-pixels"), "{message}");

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn naming_both_scopes_or_neither_is_refused() {
    // Two questions, and one answer cannot be about both address spaces.
    let (base, resolver) = classified_object("scope");
    let both = amiga_operations::ProjectAnnotationsArguments {
        image: Some("image:main-executable".to_owned()),
        object: Some("object:assets/title-pixels".to_owned()),
        maximum_locations: None,
    };
    let outcome = ask_about(&resolver, both);
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RequestArgumentOutOfRange),
        "{:?}",
        outcome.diagnostics
    );

    let neither = amiga_operations::ProjectAnnotationsArguments::default();
    let outcome = ask_about(&resolver, neither);
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RequestArgumentOutOfRange),
        "{:?}",
        outcome.diagnostics
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_image_still_answers_in_hunk_space_and_reports_no_ranges() {
    // The scope split must not have quietly changed what image scope says.
    let resolver = FilesystemSourceResolver::new(root());
    let outcome = ask_about(
        &resolver,
        amiga_operations::ProjectAnnotationsArguments::image("image:main-executable"),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let annotations = outcome.project_annotations().expect("the listing ran");
    assert_eq!(annotations.image.as_deref(), Some("image:main-executable"));
    assert_eq!(annotations.object, None);
    assert!(!annotations.locations.is_empty());
    assert!(annotations.ranges.is_empty());
    // The deliberately stale fixture annotation is still excluded from every
    // lookup and listed apart, because image scope resolves *through* it.
    assert!(
        annotations
            .stale
            .iter()
            .any(|id| id == "annotation:main/stale-note"),
        "{:?}",
        annotations.stale
    );
}

// --- project.describe, resources ---------------------------------------------

fn describe(resolver: &FilesystemSourceResolver) -> amiga_operations::ProjectDescribeResult {
    let context = ExecutionContext::new(resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectDescribe(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome
        .project_describe()
        .expect("the describe ran")
        .clone()
}

#[test]
fn a_project_reports_each_resource_with_the_range_it_decodes() {
    let described = describe(&FilesystemSourceResolver::new(root()));
    let image = described
        .resources
        .iter()
        .find(|resource| resource.id == "resource:title-logo")
        .expect("the fixture records an image resource");
    assert_eq!(image.kind, "image");
    assert_eq!(image.name, "Title logo");
    assert_eq!(image.target.space(), "object");
    assert_eq!(
        image.target,
        amiga_operations::ProjectResourceTarget::Object {
            object_id: "object:assets/title-pixels".to_owned(),
            offset: 0,
            length: 16,
            object_sha256: "9047f384250347de3a519258915b4a5fca6d5ce7070a3023fccc2f04205bbb85"
                .to_owned(),
        }
    );
    // Defaulted per kind rather than left absent: an image exports as a PNG,
    // and a frontend should not have to know the default to render the row.
    assert_eq!(image.export_media_type, "image/png");

    // A resource nothing has produced yet is the ordinary state, and it is not
    // an error — the Export surface renders it as "never exported".
    let palette = described
        .resources
        .iter()
        .find(|resource| resource.id == "resource:title-palette")
        .expect("the fixture records a palette resource");
    assert!(palette.artifacts.is_empty());
    assert_eq!(described.resource_count, described.resources.len() as u64);
}

#[test]
fn project_describe_preserves_every_resource_target_variant() {
    let base = std::env::temp_dir().join(format!(
        "amiga-operations-resource-targets-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    copy_tree(&root(), &base);
    let path = base.join("contract/analysis/resources/data.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}"));
    let mut document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    let resources = document["resources"]
        .as_array_mut()
        .expect("the fixture lists resources");
    let digest = "9d26d8c87c29dfbc789e05602a497b9b771889df0030a8e07dd7219e3039a7e8";
    for (id, target) in [
        (
            "resource:hunk-target",
            serde_json::json!({
                "space": "hunk", "image_id": "image:main-executable", "hunk": 1,
                "offset": 3, "length": 5, "object_sha256": digest
            }),
        ),
        (
            "resource:runtime-target",
            serde_json::json!({
                "space": "runtime", "image_id": "image:main-executable",
                "load_map_id": "loadmap:main/default", "address": "0x00022010",
                "length": 2, "object_sha256": digest
            }),
        ),
        (
            "resource:base-target",
            serde_json::json!({
                "space": "base_register", "image_id": "image:main-executable",
                "base_register": "a5", "displacement": -8, "width": 4,
                "object_sha256": digest
            }),
        ),
        (
            "resource:entity-target",
            serde_json::json!({
                "space": "entity", "entity_id": "function:init-graphics"
            }),
        ),
    ] {
        resources.push(serde_json::json!({
            "id": id,
            "kind": "opaque",
            "name": id,
            "target": target
        }));
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let described = describe(&FilesystemSourceResolver::new(base.clone()));
    let target = |id: &str| {
        &described
            .resources
            .iter()
            .find(|resource| resource.id == id)
            .unwrap_or_else(|| panic!("{id} was omitted"))
            .target
    };
    assert_eq!(
        target("resource:hunk-target"),
        &amiga_operations::ProjectResourceTarget::Hunk {
            image_id: "image:main-executable".to_owned(),
            hunk: 1,
            offset: 3,
            length: 5,
            object_sha256: digest.to_owned(),
        }
    );
    assert_eq!(
        target("resource:runtime-target"),
        &amiga_operations::ProjectResourceTarget::Runtime {
            image_id: "image:main-executable".to_owned(),
            load_map_id: "loadmap:main/default".to_owned(),
            address: "0x00022010".to_owned(),
            length: 2,
            object_sha256: digest.to_owned(),
        }
    );
    assert_eq!(
        target("resource:base-target"),
        &amiga_operations::ProjectResourceTarget::BaseRegister {
            image_id: "image:main-executable".to_owned(),
            base_register: "a5".to_owned(),
            displacement: -8,
            width: 4,
            object_sha256: digest.to_owned(),
        }
    );
    assert_eq!(
        target("resource:entity-target"),
        &amiga_operations::ProjectResourceTarget::Entity {
            entity_id: "function:init-graphics".to_owned(),
        }
    );
    for id in [
        "resource:hunk-target",
        "resource:runtime-target",
        "resource:base-target",
        "resource:entity-target",
    ] {
        assert!(
            described
                .resources
                .iter()
                .find(|resource| resource.id == id)
                .expect("the resource was described")
                .target_resolved,
            "{id} should attach to project structure"
        );
    }

    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn an_artifact_stops_being_current_when_the_palette_its_image_uses_changes() {
    // The property the artifact key exists for, through the API this time: an
    // image's output follows from the palette it names, so editing the palette
    // must invalidate the image. A key computed over bare IDs would say the
    // PNG is still current while the project says something different.
    let base = std::env::temp_dir().join(format!(
        "amiga-operations-resource-currency-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    copy_tree(&root(), &base);
    let resolver = FilesystemSourceResolver::new(base.clone());
    let graphics = base.join("contract/analysis/resources/graphics.json");

    // The fixture pins a placeholder key, so the artifact starts out stale.
    assert!(
        !describe(&resolver)
            .resources
            .iter()
            .find(|resource| resource.id == "resource:title-logo")
            .expect("the image resource")
            .artifacts[0]
            .current
    );

    // Record the key the project's current recipe actually produces.
    let loaded = amiga_project::load(&base.join("contract")).expect("the fixture loads");
    let resource = loaded
        .project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .find(|resource| resource.id().as_str() == "resource:title-logo")
        .expect("the image resource");
    let key = amiga_project::recipe::artifact_key(&loaded.project, resource, "amiga-re", "0.1.0")
        .expect("the recipe normalizes");

    let write_key = |key: &str| {
        let text = std::fs::read_to_string(&graphics).unwrap_or_else(|error| panic!("{error}"));
        let mut value: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
        value["artifacts"][0]["recipe_key"] = serde_json::Value::String(key.to_owned());
        std::fs::write(&graphics, value.to_string()).unwrap_or_else(|error| panic!("{error}"));
    };
    write_key(&key);
    assert!(
        describe(&resolver)
            .resources
            .iter()
            .find(|resource| resource.id == "resource:title-logo")
            .expect("the image resource")
            .artifacts[0]
            .current,
        "the artifact the current recipe produced must read as current"
    );

    // Now edit the *palette* the image names, and nothing else.
    let text = std::fs::read_to_string(&graphics).unwrap_or_else(|error| panic!("{error}"));
    let mut value: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    for resource in value["resources"]
        .as_array_mut()
        .expect("the document lists resources")
    {
        if resource["id"] == "resource:title-palette" {
            resource["count"] = serde_json::json!(2);
        }
    }
    std::fs::write(&graphics, value.to_string()).unwrap_or_else(|error| panic!("{error}"));

    assert!(
        !describe(&resolver)
            .resources
            .iter()
            .find(|resource| resource.id == "resource:title-logo")
            .expect("the image resource")
            .artifacts[0]
            .current,
        "editing the referenced palette must invalidate the image's output"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A project whose one source is a capture: bytes that exist because something
/// produced them, and that nothing in the format can produce again.
fn captured_project(tag: &str, notes: Option<&str>) -> PathBuf {
    // The bytes a loader would have left in RAM. Deliberately not a subset of
    // anything the project holds — that is the whole reason they cannot be a
    // `Range` of the disk image.
    let stage = b"DECRYPTED STAGE".to_vec();

    let base = std::env::temp_dir().join(format!("amiga-operations-{tag}-{}", std::process::id()));
    let root = base.join("captured");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(root.join("original")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::create_dir_all(root.join("analysis")).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(root.join("original/stage.bin"), &stage)
        .unwrap_or_else(|error| panic!("{error}"));

    std::fs::write(
        root.join("amiga-re.project.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "project",
            "format_version": 1,
            "project": { "id": "project:captured", "name": "Captured demo" },
            "documents": { "sources": "analysis/sources.json" }
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let mut source = serde_json::json!({
        "id": "source:stage",
        "kind": "file",
        "media_type": "binary",
        "display_name": "A loader's decrypted stage",
        "size": stage.len(),
        "sha256": amiga_core::sha256(&stage),
        "provenance": "captured",
        "locations": [{ "kind": "project_relative", "path": "original/stage.bin" }]
    });
    if let Some(notes) = notes {
        source["notes"] = serde_json::json!(notes);
    }
    std::fs::write(
        root.join("analysis/sources.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "sources",
            "format_version": 1,
            "sources": [source],
        }))
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    base
}

/// A capture verifies, and the report says what that verification is worth.
///
/// The trap this closes: a trackloader that decrypts, de-interleaves or unpacks
/// on the way to RAM produces bytes that are on no disk. They can be pinned and
/// checked against themselves, and nothing in the format can re-derive them —
/// so a record of one reads exactly like a piece of media somebody has a copy
/// of unless the report says otherwise. Designing a recipe that references a
/// routine, its inputs and a memory region is deliberately not attempted here;
/// making the difference visible is.
#[test]
fn a_captured_source_verifies_and_is_reported_as_not_reproducible() {
    let base = captured_project(
        "captured",
        Some(
            "Read out of RAM at 0x21000 after the boot loader's routine at 0x1a2c ran; \
             no recorded recipe reproduces it.",
        ),
    );
    let resolver = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&resolver);

    let described = Router::execute(
        &request(
            OperationRequestDocument::ProjectDescribe(ProjectArguments::default()),
            Some("captured"),
        ),
        &context,
    );
    let describe = described.project_describe().expect("the describe ran");
    assert_eq!(describe.sources.len(), 1);
    assert!(
        !describe.sources[0].reproducible,
        "a capture must not be reported as reproducible media"
    );

    let verified = Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("captured"),
        ),
        &context,
    );
    assert_eq!(
        verified.status,
        Status::Success,
        "{:?}",
        verified.diagnostics
    );
    let verify = verified.project_verify().expect("the verify ran");
    assert_eq!(verify.sources.len(), 1);
    // It verifies — the bytes are the ones recorded — and the detail says what
    // that does and does not prove, rather than leaving a reader to infer it
    // from a document they may never open.
    assert_eq!(verify.sources[0].status, "verified");
    assert!(verify.sources[0].verified);
    assert!(!verify.sources[0].contradicted);
    assert!(
        verify.sources[0].detail.contains("not reproducible"),
        "{}",
        verify.sources[0].detail
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A capture that says nothing about what produced it does not load.
#[test]
fn a_capture_with_no_account_of_itself_is_refused_by_name() {
    let base = captured_project("captured-mute", None);
    let resolver = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &request(
            OperationRequestDocument::ProjectCheck(ProjectArguments::default()),
            Some("captured"),
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Error, "{:?}", outcome.diagnostics);
    let reported = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(reported.contains("CAPTURE_UNEXPLAINED"), "{reported}");

    let _ = std::fs::remove_dir_all(&base);
}

/// The write that closes the loop `env.sandbox.call` opens.
///
/// A capture — bytes a routine left in RAM, on no disk and re-derivable by
/// nothing this format can express — could be *described* by the format and
/// written by no operation, so recording one meant editing JSON by hand. That is
/// the shape of vocabulary the project's own rule warns about: one nothing
/// writes into gets used wrongly or not at all.
#[test]
fn a_capture_is_registered_as_a_source_and_verifies_as_one() {
    let base = edit_workspace("register-capture");
    let bytes = b"a framebuffer the routine left behind".to_vec();
    let sha256 = amiga_core::sha256(&bytes);
    std::fs::create_dir_all(base.join("contract/decoded"))
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("contract/decoded/framebuffer.bin"), &bytes)
        .unwrap_or_else(|error| panic!("{error}"));

    let resolver = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&resolver);
    let capture = |notes: &str, sha256: &str| amiga_operations::ProjectEdit::RegisterCapture {
        id: "source:framebuffer".to_owned(),
        name: "Title framebuffer".to_owned(),
        size: bytes.len() as u64,
        sha256: sha256.to_owned(),
        notes: notes.to_owned(),
        path: Some("decoded/framebuffer.bin".to_owned()),
    };
    let envelope = |edit, mode| {
        let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectEdit(
            amiga_operations::ProjectEditArguments::new(vec![edit]),
        ));
        envelope.project = Some(ProjectLocator::Path {
            path: "contract".to_owned(),
        });
        envelope.execution.mode = mode;
        envelope
    };

    // A capture that says nothing about what produced it is refused. The note
    // is the only provenance such bytes will ever have.
    let unexplained = Router::execute(
        &envelope(
            capture("  ", &sha256),
            amiga_operations::ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(unexplained.status, Status::Error);
    assert!(
        unexplained
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("what produced it")),
        "{:?}",
        unexplained.diagnostics
    );

    // Nor is a pin the bytes contradict written and left for `project.verify`
    // to discover.
    let wrong_digest = Router::execute(
        &envelope(
            capture("env.sandbox.call over hunk 0", &"b".repeat(64)),
            amiga_operations::ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(wrong_digest.status, Status::Error);
    assert!(
        wrong_digest
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("hashes to")),
        "{:?}",
        wrong_digest.diagnostics
    );

    let notes = "env.sandbox.call: \"framebuffer\" — [0x40000..+0x25) of the final memory";
    let prepared = Router::execute(
        &envelope(
            capture(notes, &sha256),
            amiga_operations::ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let plan = prepared.project_edit().expect("a plan");
    let committed = Router::execute(
        &envelope(
            capture(notes, &sha256),
            amiga_operations::ExecutionMode::CommitReviewed {
                approved_plan_sha256: plan.plan_sha256.clone(),
            },
        ),
        &context,
    );
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );

    // The project still loads, and the capture verifies — against itself, which
    // is all a capture can ever be verified against.
    let verified = Router::execute(
        &request(
            OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
            Some("contract"),
        ),
        &context,
    );
    assert_eq!(
        verified.status,
        Status::Success,
        "{:?}",
        verified.diagnostics
    );
    let report = verified.project_verify().expect("the verify ran");
    let registered = report
        .sources
        .iter()
        .find(|source| source.id == "source:framebuffer")
        .unwrap_or_else(|| panic!("{:?}", report.sources));
    assert!(registered.verified, "{registered:?}");
    // And says what a capture is, rather than leaving a reader to work it out
    // from the document: a digest match proves these are the recorded bytes and
    // nothing in this format can produce them again.
    assert!(
        registered.detail.contains("not reproducible"),
        "a capture was reported as if it were media somebody has a copy of: {registered:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn project_verification_enforces_context_source_and_graph_byte_limits() {
    use amiga_operations::OperationLimits;
    for limits in [
        OperationLimits::default().with_maximum_input_bytes(1),
        OperationLimits::default().with_maximum_total_input_bytes(1),
        OperationLimits::default().with_maximum_total_recovered_bytes(1),
    ] {
        let resolver = FilesystemSourceResolver::new(root());
        let context = ExecutionContext::new(&resolver).with_limits(limits);
        let outcome = Router::execute(
            &request(
                OperationRequestDocument::ProjectVerify(ProjectArguments::default()),
                Some("contract"),
            ),
            &context,
        );
        let report = outcome.project_verify().unwrap();
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.contradicted && source.detail.contains("verification budget")),
            "{outcome:?}"
        );
        assert!(report.objects.iter().all(|object| !object.verified));
    }
}

#[test]
fn a_failed_edit_install_is_an_error_rather_than_an_approval_conflict() {
    let base = edit_workspace("install-failure");
    let resolver = FilesystemSourceResolver::new(&base);
    let context = ExecutionContext::new(&resolver);
    let prepared = Router::execute(
        &edit_envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    let digest = prepared.project_edit().unwrap().plan_sha256.clone();
    let document = base.join("contract/analysis/annotations/main-code.json");
    let before = std::fs::read(&document).unwrap();
    // A regular file at the staging directory path makes staging fail on all
    // platforms, even when tests run with elevated filesystem permissions.
    std::fs::write(base.join("contract/.amiga-re-staging"), b"occupied").unwrap();
    let outcome = Router::execute(
        &edit_envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest,
        }),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::OutputDestinationRefused)
    );
    assert_eq!(std::fs::read(&document).unwrap(), before);
    std::fs::remove_dir_all(base).unwrap();
}
