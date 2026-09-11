//! `project.init` — the write path that lets a project exist at all.

use std::path::{Path, PathBuf};

use amiga_operations::{
    DiagnosticCode, ExecutionContext, ExecutionMode, FilesystemDestinationResolver,
    FilesystemSourceResolver, MediaPolicy, OperationLimits, OperationRequestDocument,
    ProjectArguments, ProjectInitArguments, ProjectLocator, RequestEnvelope, Router, Status,
};

/// A scratch directory holding two source files, cleaned up by the caller.
fn workspace(tag: &str) -> PathBuf {
    let base =
        std::env::temp_dir().join(format!("amiga-project-init-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("disk1.adf"), b"first disk bytes")
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("loader"), b"second file bytes")
        .unwrap_or_else(|error| panic!("{error}"));
    base
}

/// An envelope for `document` in `mode`.
fn envelope(document: OperationRequestDocument, mode: ExecutionMode) -> RequestEnvelope {
    let mut envelope = RequestEnvelope::read(document);
    envelope.execution.mode = mode;
    envelope
}

fn init_request(sources: Vec<String>, media: MediaPolicy) -> OperationRequestDocument {
    OperationRequestDocument::ProjectInit(
        ProjectInitArguments::new("Demo project", "proj", sources).with_media(media),
    )
}

/// Prepare, then commit the plan the prepare produced.
fn create(base: &Path, media: MediaPolicy) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = init_request(vec!["disk1.adf".to_owned(), "loader".to_owned()], media);

    let mut envelope = RequestEnvelope::read(document.clone());
    envelope.execution.mode = ExecutionMode::Prepare;
    let prepared = Router::execute(&envelope, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let plan = prepared.project_init().expect("a plan");
    assert!(!plan.committed);
    assert!(plan.written.is_empty(), "prepare must write nothing");
    let digest = plan.plan.plan_sha256.clone();

    envelope = RequestEnvelope::read(document);
    envelope.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    Router::execute(&envelope, &context)
}

fn check(base: &Path) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectCheck(
        ProjectArguments::default(),
    ));
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    Router::execute(&envelope, &context)
}

fn verify(base: &Path) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectVerify(
        ProjectArguments::default(),
    ));
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    Router::execute(&envelope, &context)
}

#[test]
fn a_created_project_loads_verifies_and_has_somewhere_to_put_knowledge() {
    let base = workspace("round-trip");
    let created = create(&base, MediaPolicy::Copy);
    assert_eq!(created.status, Status::Success, "{:?}", created.diagnostics);
    let init = created.project_init().expect("a plan");
    assert!(init.committed);
    assert_eq!(init.sources.len(), 2);

    // The root is written last, so an interrupted init leaves a directory that
    // does not announce itself as a project.
    assert_eq!(
        init.written.last().map(String::as_str),
        Some("amiga-re.project.json"),
        "the root document must be the final write: {:?}",
        init.written
    );

    // It loads.
    let checked = check(&base);
    assert_eq!(checked.status, Status::Success, "{:?}", checked.diagnostics);
    let report = checked.project_check().expect("the check ran");
    assert_eq!(report.name, "Demo project");
    assert_eq!(report.sources, 2);
    assert_eq!(report.objects, 2);

    // And the documents the edit path will need exist, because `EditPlan` can
    // modify a document set and cannot grow one.
    assert!(
        base.join("proj/analysis/annotations/main.json").is_file(),
        "an annotation would have nowhere to go"
    );
    assert!(
        base.join("proj/analysis/resources/main.json").is_file(),
        "a resource would have nowhere to go"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn every_object_a_new_project_declares_can_be_recovered() {
    let base = workspace("verify");
    let created = create(&base, MediaPolicy::Copy);
    assert_eq!(created.status, Status::Success, "{:?}", created.diagnostics);

    let verified = verify(&base);
    assert_eq!(
        verified.status,
        Status::Success,
        "{:?}",
        verified.diagnostics
    );
    let report = verified.project_verify().expect("the verify ran");
    assert_eq!(report.verified_sources, 2);
    // The assertion that would have caught a selector-less whole-file object:
    // `verify` reports one as unrecoverable, so a project created without a
    // `range` selector would fail its own verification the moment it was made.
    assert_eq!(report.verified_objects, 2);
    for object in &report.objects {
        assert_eq!(object.status, "verified", "{object:?}");
        assert!(!object.contradicted, "{object:?}");
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_second_init_refuses_rather_than_replacing_what_is_there() {
    let base = workspace("no-replace");
    assert_eq!(create(&base, MediaPolicy::Copy).status, Status::Success);

    // Refused at `prepare`, not at commit: a caller learns immediately rather
    // than after reviewing a plan that could never have been applied.
    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let again = Router::execute(
        &envelope(
            init_request(
                vec!["disk1.adf".to_owned(), "loader".to_owned()],
                MediaPolicy::Copy,
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(again.status, Status::Error);
    assert!(
        again
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::OutputDestinationRefused),
        "{:?}",
        again.diagnostics
    );
    // Replacing needs staging and rollback: the old root would otherwise stay in
    // place indexing a mixture of two document sets.
    let checked = check(&base);
    assert_eq!(checked.status, Status::Success, "{:?}", checked.diagnostics);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn media_kept_in_place_outside_the_root_is_bound_to_this_machine() {
    let base = workspace("in-place");
    let created = create(&base, MediaPolicy::InPlace);
    assert_eq!(created.status, Status::Success, "{:?}", created.diagnostics);
    let init = created.project_init().expect("a plan");

    // The sources live beside the project rather than under it, so no
    // project-relative location describes them and a local binding must.
    assert!(
        init.sources.iter().all(|source| source.bound_locally),
        "{:?}",
        init.sources
    );
    assert!(base.join("proj/.amiga-re/local.json").is_file());

    // And that binding is what makes verification possible at all.
    let verified = verify(&base);
    let report = verified.project_verify().expect("the verify ran");
    assert_eq!(
        report.verified_sources, 2,
        "the bindings were written but not honoured: {:?}",
        report.sources
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn two_sources_that_derive_one_identity_are_refused() {
    let base = workspace("duplicate-id");
    // Distinct file names whose ids converge under the lossy conversion.
    std::fs::write(base.join("a b"), b"one").unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("a-b"), b"two").unwrap_or_else(|error| panic!("{error}"));

    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let request = envelope(
        init_request(vec!["a b".to_owned(), "a-b".to_owned()], MediaPolicy::Copy),
        ExecutionMode::Prepare,
    );
    let outcome = Router::execute(&request, &context);

    assert_eq!(outcome.status, Status::Error, "{:?}", outcome.diagnostics);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("derive the id")),
        "{:?}",
        outcome.diagnostics
    );
    // Refused before anything was written, so the destination is untouched.
    assert!(!base.join("proj").exists());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn naming_one_source_twice_is_refused_rather_than_deduplicated() {
    let base = workspace("repeated");
    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let request = envelope(
        init_request(
            vec!["disk1.adf".to_owned(), "disk1.adf".to_owned()],
            MediaPolicy::Copy,
        ),
        ExecutionMode::Prepare,
    );
    let outcome = Router::execute(&request, &context);

    assert_eq!(outcome.status, Status::Error, "{:?}", outcome.diagnostics);
    assert!(!base.join("proj").exists());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn exceeding_an_aggregate_ceiling_refuses_the_whole_plan() {
    let base = workspace("limits");
    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());

    // One source over the count ceiling. Refused in normalization, before a
    // single file is opened.
    let context = ExecutionContext::new(&sources)
        .with_destinations(&destinations)
        .with_limits(OperationLimits::default().with_maximum_sources(1));
    let outcome = Router::execute(
        &envelope(
            init_request(
                vec!["disk1.adf".to_owned(), "loader".to_owned()],
                MediaPolicy::Copy,
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::LimitExceeded),
        "{:?}",
        outcome.diagnostics
    );

    // And one byte over the aggregate byte ceiling, which cannot be known until
    // the sources are resolved.
    let context = ExecutionContext::new(&sources)
        .with_destinations(&destinations)
        .with_limits(OperationLimits::default().with_maximum_total_input_bytes(20));
    let outcome = Router::execute(
        &envelope(
            init_request(
                vec!["disk1.adf".to_owned(), "loader".to_owned()],
                MediaPolicy::Copy,
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::LimitExceeded),
        "{:?}",
        outcome.diagnostics
    );
    // Never a truncated project: a destination that looks complete and is not
    // is the worst outcome for a preservation tool.
    assert!(!base.join("proj").exists());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_stale_approval_conflicts_rather_than_writing() {
    let base = workspace("stale-approval");
    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);

    let outcome = Router::execute(
        &envelope(
            init_request(
                vec!["disk1.adf".to_owned(), "loader".to_owned()],
                MediaPolicy::Copy,
            ),
            ExecutionMode::CommitReviewed {
                // Well-formed but wrong: a malformed digest is refused by
                // argument validation, which would test the wrong thing.
                approved_plan_sha256: "a".repeat(64),
            },
        ),
        &context,
    );

    assert_eq!(
        outcome.status,
        Status::Conflict,
        "{:?}",
        outcome.diagnostics
    );
    assert!(!base.join("proj").exists(), "a conflict must write nothing");

    let _ = std::fs::remove_dir_all(&base);
}

// --- extraction --------------------------------------------------------------

/// A workspace whose sources are a real ADF, a real LHA and a plain blob.
fn carrier_workspace(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "amiga-project-extract-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));

    let adf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../amiga-project/fixtures");
    // The ADF fixture the project crate ships, if it is there; otherwise the
    // test still exercises the LHA and opaque branches.
    if let Ok(bytes) = std::fs::read(adf.join("media/disk.adf")) {
        std::fs::write(base.join("disk.adf"), bytes).unwrap_or_else(|error| panic!("{error}"));
    }
    std::fs::write(base.join("blob.bin"), b"not a container at all")
        .unwrap_or_else(|error| panic!("{error}"));
    base
}

#[test]
fn extraction_turns_carriers_into_objects_that_recover_from_their_parent() {
    let base = carrier_workspace("round-trip");
    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);

    // A project holding one plain blob: no carrier to take apart, which is the
    // case that must be *reported* rather than silently producing nothing.
    let document = OperationRequestDocument::ProjectInit(ProjectInitArguments::new(
        "Carriers",
        "proj",
        vec!["blob.bin".to_owned()],
    ));
    let prepared = Router::execute(
        &envelope(document.clone(), ExecutionMode::Prepare),
        &context,
    );
    let digest = prepared
        .project_init()
        .expect("a plan")
        .plan
        .plan_sha256
        .clone();
    let created = Router::execute(
        &envelope(
            document,
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: digest,
            },
        ),
        &context,
    );
    assert_eq!(created.status, Status::Success, "{:?}", created.diagnostics);

    let extract = |mode| {
        let mut request = RequestEnvelope::read(OperationRequestDocument::ProjectExtract(
            amiga_operations::ProjectExtractArguments::default(),
        ));
        request.project = Some(ProjectLocator::Path {
            path: "proj".to_owned(),
        });
        request.execution.mode = mode;
        Router::execute(&request, &context)
    };

    let planned = extract(ExecutionMode::Prepare);
    assert_eq!(
        planned.status,
        Status::Prepared,
        "{:?}",
        planned.diagnostics
    );
    let plan = planned.project_extract().expect("a plan");
    assert!(!plan.committed);
    // The blob is not a container, and that is stated rather than left as an
    // absence a reader would take for "covered".
    assert_eq!(plan.carriers.len(), 1);
    assert_eq!(plan.carriers[0].kind, "opaque");
    assert!(plan.carriers[0].detail.is_some());

    let committed = extract(ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan.plan_sha256.clone(),
    });
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );

    // Whatever it did, the project still loads and still verifies: an extraction
    // that left the documents describing objects it did not write would show up
    // here.
    let checked = check(&base);
    assert_eq!(checked.status, Status::Success, "{:?}", checked.diagnostics);
    let verified = verify(&base);
    let report = verified.project_verify().expect("the verify ran");
    for object in &report.objects {
        assert!(!object.contradicted, "{object:?}");
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn extracting_an_lha_gives_every_member_a_selector_that_reproduces_it() {
    let base = carrier_workspace("lha");
    // A stored single-member archive, built here so the test needs no fixture.
    let mut body = Vec::new();
    body.extend_from_slice(b"-lh0-");
    let payload = b"member bytes";
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(0x20);
    body.push(0);
    let name = b"graphics/title.iff";
    body.push(name.len() as u8);
    body.extend_from_slice(name);
    // The real CRC of the payload: `read` refuses a member whose stored CRC
    // disagrees, which is the archive doing its job rather than a test detail.
    body.extend_from_slice(&amiga_lha::crc16(payload).to_le_bytes());
    let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    let mut archive = vec![body.len() as u8, checksum];
    archive.extend_from_slice(&body);
    archive.extend_from_slice(payload);
    archive.push(0);
    std::fs::write(base.join("assets.lha"), &archive).unwrap_or_else(|error| panic!("{error}"));

    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = OperationRequestDocument::ProjectInit(ProjectInitArguments::new(
        "Assets",
        "proj",
        vec!["assets.lha".to_owned()],
    ));
    let prepared = Router::execute(
        &envelope(document.clone(), ExecutionMode::Prepare),
        &context,
    );
    let digest = prepared
        .project_init()
        .expect("a plan")
        .plan
        .plan_sha256
        .clone();
    assert_eq!(
        Router::execute(
            &envelope(
                document,
                ExecutionMode::CommitReviewed {
                    approved_plan_sha256: digest
                }
            ),
            &context
        )
        .status,
        Status::Success
    );

    let extract = |mode| {
        let mut request = RequestEnvelope::read(OperationRequestDocument::ProjectExtract(
            amiga_operations::ProjectExtractArguments::default(),
        ));
        request.project = Some(ProjectLocator::Path {
            path: "proj".to_owned(),
        });
        request.execution.mode = mode;
        Router::execute(&request, &context)
    };
    let planned = extract(ExecutionMode::Prepare);
    let plan = planned.project_extract().expect("a plan");
    assert_eq!(plan.carriers[0].kind, "lha", "{:?}", plan.carriers);
    assert_eq!(plan.carriers[0].members, 1, "{:?}", plan.carriers);
    assert_eq!(plan.objects.len(), 1);

    let committed = extract(ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan.plan_sha256.clone(),
    });
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );

    // The member is on disk...
    let materialised = base.join("proj").join(&plan.objects[0].path);
    assert!(materialised.is_file(), "{materialised:?}");

    // ...and, the point of the whole design, the object recovers from its parent
    // through its selector, so the file is a convenience rather than the only
    // copy. Deleting it must not break verification.
    std::fs::remove_file(&materialised).unwrap_or_else(|error| panic!("{error}"));
    let verified = verify(&base);
    let report = verified.project_verify().expect("the verify ran");
    assert_eq!(
        report.verified_objects, 2,
        "the member must recover from the archive: {:?}",
        report.objects
    );

    let _ = std::fs::remove_dir_all(&base);
}

// --- programs and images ------------------------------------------------------
//
// Until this landed, the only thing in the workspace that could produce a
// `Program` and an `Image` was the legacy `project migrate` importer — so four
// shipped capabilities depended on it: `Target::Hunk`, `Target::Runtime`,
// `Target::BaseRegister`, and `project.annotations`' image-scoped listing, each
// of which names an `image_id`. A HUNK source needs no importer and no guessing.

/// A two-hunk HUNK executable: 16 bytes of code, then 8 of data.
///
/// Two hunks rather than one, so the nominal load map has a second segment whose
/// base is derived from the first's size rather than being zero as well.
fn two_hunk_executable() -> Vec<u8> {
    let code: [u8; 16] = [
        0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e,
        0x75,
    ];
    let data: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    let (code_longwords, data_longwords) = (code.len() as u32 / 4, data.len() as u32 / 4);

    let mut bytes = Vec::new();
    for value in [
        0x0000_03f3_u32, // HUNK_HEADER
        0,               // no resident library names
        2,               // table size
        0,               // first hunk
        1,               // last hunk
        code_longwords,
        data_longwords,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&code_longwords.to_be_bytes());
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes.extend_from_slice(&0x0000_03ea_u32.to_be_bytes()); // HUNK_DATA
    bytes.extend_from_slice(&data_longwords.to_be_bytes());
    bytes.extend_from_slice(&data);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// A workspace holding one HUNK executable and one file that is not one.
fn executable_workspace(tag: &str) -> PathBuf {
    let base =
        std::env::temp_dir().join(format!("amiga-project-image-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("game"), two_hunk_executable())
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("disk1.adf"), b"not an executable at all")
        .unwrap_or_else(|error| panic!("{error}"));
    base
}

/// Init over the executable workspace, naming both files.
fn create_with_executable(base: &Path) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = init_request(
        vec!["game".to_owned(), "disk1.adf".to_owned()],
        MediaPolicy::Copy,
    );

    let mut envelope = RequestEnvelope::read(document.clone());
    envelope.execution.mode = ExecutionMode::Prepare;
    let prepared = Router::execute(&envelope, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let digest = prepared
        .project_init()
        .expect("a plan")
        .plan
        .plan_sha256
        .clone();

    envelope = RequestEnvelope::read(document);
    envelope.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    Router::execute(&envelope, &context)
}

fn describe(base: &Path) -> amiga_operations::ProjectDescribeResult {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectDescribe(
        ProjectArguments::default(),
    ));
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    let outcome = Router::execute(&envelope, &context);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome.project_describe().expect("a description").clone()
}

#[test]
fn a_source_that_is_a_hunk_executable_becomes_an_image_whose_object_it_is() {
    let base = executable_workspace("image");
    let outcome = create_with_executable(&base);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);

    let description = describe(&base);
    assert_eq!(description.programs.len(), 1, "{:?}", description.programs);
    let images = &description.programs[0].images;
    assert_eq!(
        images.len(),
        1,
        "only the executable is an image: {images:?}"
    );
    let image = &images[0];

    // The image's object is the source's own whole-file object, at the digest
    // the project pinned it by — not a second object describing the same bytes.
    let object = description
        .objects
        .iter()
        .find(|object| object.id == image.object_id)
        .unwrap_or_else(|| panic!("the image names an object that does not exist: {image:?}"));
    let source = description
        .sources
        .iter()
        .find(|source| source.id == object.parent_id)
        .unwrap_or_else(|| panic!("the object names a source that does not exist: {object:?}"));
    assert_eq!(Some(&object.sha256), source.sha256.as_ref());
    assert_eq!(source.display_name, "game");
    assert_eq!(source.size, Some(object.size));
    assert_eq!(source.locations.len(), 1);
    assert!(
        source.locations[0].starts_with("original/"),
        "the copied source must expose its project-relative reopen hint: {source:?}"
    );

    // Two hunks, and the second's base is the first's allocation size — derived
    // from the parse, not from a person.
    let map = image
        .load_maps
        .first()
        .unwrap_or_else(|| panic!("an image with no load map: {image:?}"));
    assert_eq!(
        map.segments
            .iter()
            .map(|segment| (segment.hunk, segment.runtime_base.as_str()))
            .collect::<Vec<_>>(),
        vec![(0, "0x00000000"), (1, "0x00000010")]
    );

    // And the project still loads and verifies with the document in it.
    let checked = check(&base);
    assert_eq!(checked.status, Status::Success, "{:?}", checked.diagnostics);
    let checked = checked.project_check().expect("the check ran");
    assert!(checked.problems.is_empty(), "{:?}", checked.problems);
    let verified = verify(&base);
    assert_eq!(
        verified.status,
        Status::Success,
        "{:?}",
        verified.diagnostics
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A project says what it knows. Inventing a program for a disk image would be
/// the opposite of what the format is for.
#[test]
fn a_source_that_is_not_an_executable_gets_no_program_and_no_document() {
    let base = workspace("no-image");
    let outcome = create(&base, MediaPolicy::Copy);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);

    let description = describe(&base);
    assert!(
        description.programs.is_empty(),
        "{:?}",
        description.programs
    );
    // Not an empty document either: a project with no programs and one whose
    // programs document is empty are the same claim, and the shorter one does
    // not pretend the question was asked and answered.
    assert!(!base.join("proj/analysis/programs/main.json").exists());

    let _ = std::fs::remove_dir_all(&base);
}

/// The point of the whole entry: hunk space now has a producer, so an
/// annotation can be made in it and a rebase can resolve the image it names.
#[test]
fn a_hunk_space_annotation_can_be_made_against_an_inited_image_and_rebased() {
    use amiga_operations::{ProjectEdit, ProjectEditArguments, ProjectEditTarget};

    let base = executable_workspace("hunk-annotation");
    assert_eq!(
        create_with_executable(&base).status,
        Status::Success,
        "the init failed"
    );
    let image_id = describe(&base).programs[0].images[0].id.clone();

    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = OperationRequestDocument::ProjectEdit(ProjectEditArguments::new(vec![
        ProjectEdit::Annotate {
            id: "function:start".to_owned(),
            kind: "function".to_owned(),
            target: ProjectEditTarget::Hunk {
                image_id: image_id.clone(),
                hunk: 0,
                offset: 0,
                length: 16,
            },
            name: Some("start".to_owned()),
            classification: None,
        },
    ]));

    let mut envelope = RequestEnvelope::read(document.clone());
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    envelope.execution.mode = ExecutionMode::Prepare;
    let prepared = Router::execute(&envelope, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "a hunk-space annotation was refused: {:?}",
        prepared.diagnostics
    );
    let digest = prepared.project_edit().expect("a plan").plan_sha256.clone();

    envelope = RequestEnvelope::read(document);
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    envelope.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    let committed = Router::execute(&envelope, &context);
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );

    // `project.annotations` indexes strictly by image, so this listing had no
    // producible input before an init could write one.
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectAnnotations(
        amiga_operations::ProjectAnnotationsArguments::image(image_id.clone()),
    ));
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    let listed = Router::execute(&envelope, &ExecutionContext::new(&sources));
    assert_eq!(listed.status, Status::Success, "{:?}", listed.diagnostics);
    let listed = listed.project_annotations().expect("a listing");
    // An image scope reports hunk-space *locations*, which is the whole point:
    // `ranges` is the object-scope shape, and a hunk offset is not a file one.
    assert_eq!(listed.images, vec![image_id.clone()]);
    assert!(
        listed.locations.iter().any(|location| {
            location.hunk == 0
                && location.offset == 0
                && location.function.as_deref() == Some("start")
        }),
        "{listed:?}"
    );

    // And a rebase resolves the object through the image the annotation names,
    // which is the path that had no writer at all.
    let document = OperationRequestDocument::ProjectEdit(ProjectEditArguments::new(vec![
        ProjectEdit::Rebase {
            id: "function:start".to_owned(),
        },
    ]));
    let mut envelope = RequestEnvelope::read(document);
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    envelope.execution.mode = ExecutionMode::Prepare;
    let rebased = Router::execute(&envelope, &context);
    assert_eq!(
        rebased.status,
        Status::Prepared,
        "the rebase could not resolve the image: {:?}",
        rebased.diagnostics
    );

    let _ = std::fs::remove_dir_all(&base);
}

// --- comments about annotations ----------------------------------------------

/// Prepare and commit `edits` against the project at `proj`.
fn edit(
    base: &Path,
    edits: Vec<amiga_operations::ProjectEdit>,
) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document =
        OperationRequestDocument::ProjectEdit(amiga_operations::ProjectEditArguments::new(edits));

    let mut prepare = RequestEnvelope::read(document.clone());
    prepare.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    prepare.execution.mode = ExecutionMode::Prepare;
    let prepared = Router::execute(&prepare, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let digest = prepared.project_edit().expect("a plan").plan_sha256.clone();

    let mut commit = RequestEnvelope::read(document);
    commit.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    commit.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    Router::execute(&commit, &context)
}

/// Both comment forms exist because they are different acts, and object scope
/// used to report only one of them — so a comment written about a *name* was
/// invisible to anything reading that listing.
#[test]
fn a_comment_about_an_annotation_is_reported_under_it_and_carries_no_range() {
    use amiga_operations::{ProjectEdit, ProjectEditTarget};

    let base = workspace("entity-comment");
    assert_eq!(create(&base, MediaPolicy::Copy).status, Status::Success);
    // Read from the project rather than spelled here: the id derivation is the
    // init's business, and a test that restated it would pin it twice.
    let object = describe(&base)
        .objects
        .first()
        .unwrap_or_else(|| panic!("a new project has objects"))
        .id
        .clone();

    let target = ProjectEditTarget::Object {
        object_id: object.clone(),
        offset: 0,
        length: 4,
    };
    let committed = edit(
        &base,
        vec![
            ProjectEdit::Annotate {
                id: "annotation:header".to_owned(),
                kind: "region".to_owned(),
                target: target.clone(),
                name: None,
                classification: Some("data".to_owned()),
            },
            // About the annotation: follows it through a rename or a rebase.
            ProjectEdit::Comment {
                id: "annotation:header/why".to_owned(),
                target: ProjectEditTarget::Entity {
                    entity_id: "annotation:header".to_owned(),
                },
                placement: "before".to_owned(),
                text: "Four bytes of magic.".to_owned(),
            },
            // About the bytes: goes stale when they move.
            ProjectEdit::Comment {
                id: "annotation:header/bytes".to_owned(),
                target,
                placement: "inline".to_owned(),
                text: "The first longword.".to_owned(),
            },
        ],
    );
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );

    let sources = FilesystemSourceResolver::new(base.clone());
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectAnnotations(
        amiga_operations::ProjectAnnotationsArguments::object(object),
    ));
    envelope.project = Some(ProjectLocator::Path {
        path: "proj".to_owned(),
    });
    let listed = Router::execute(&envelope, &ExecutionContext::new(&sources));
    assert_eq!(listed.status, Status::Success, "{:?}", listed.diagnostics);
    let listed = listed.project_annotations().expect("a listing");

    // The byte comment is a range of its own: it names bytes, so it has some.
    assert!(
        listed
            .ranges
            .iter()
            .any(|range| range.id == "annotation:header/bytes" && range.length == 4),
        "{listed:?}"
    );
    // The entity comment is not, and appears under what it is about instead.
    assert!(
        !listed
            .ranges
            .iter()
            .any(|range| range.id == "annotation:header/why"),
        "an entity comment was given a range it does not have: {listed:?}"
    );
    let region = listed
        .ranges
        .iter()
        .find(|range| range.id == "annotation:header")
        .unwrap_or_else(|| panic!("{listed:?}"));
    assert_eq!(
        region
            .about
            .iter()
            .map(|comment| (comment.id.as_str(), comment.text.as_str()))
            .collect::<Vec<_>>(),
        vec![("annotation:header/why", "Four bytes of magic.")]
    );
    // And nothing else collects it: it is about that annotation, not about
    // every annotation over the same bytes.
    assert!(
        listed
            .ranges
            .iter()
            .filter(|range| range.id != "annotation:header")
            .all(|range| range.about.is_empty()),
        "{listed:?}"
    );

    let _ = std::fs::remove_dir_all(&base);
}
