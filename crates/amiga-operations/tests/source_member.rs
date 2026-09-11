//! Naming a member inside a container as an operation's source.
//!
//! `SourceLocator` had exactly one variant, so every analysis took a whole file
//! and inspecting twelve files on a disk meant writing twelve files out and
//! re-opening each. The project format was already ahead of it: an `Object`
//! carries a `Selector`, and `ContainerRecovery` already turned one into bytes
//! in memory — so the format could say "this object is `S/startup-sequence`
//! inside volume.adf" and nothing that analysed bytes could accept the sentence.
//!
//! The property every test here checks is the same one: reading a member by
//! selector must produce exactly what reading the extracted file produces.

use std::path::PathBuf;

use amiga_operations::{
    DiagnosticCode, ExecutionContext, ExecutionMode, FilesystemDestinationResolver,
    FilesystemSourceResolver, OperationRequestDocument, RequestEnvelope, Router, SourceLocator,
    SourceSurveyArguments, Status,
};
use amiga_project::document::Selector;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

const VOLUME: &str = "fixtures/volume.adf";
const MEMBER: &str = "S/startup-sequence";

fn member_locator() -> SourceLocator {
    SourceLocator::file(VOLUME).member(Selector::Adf {
        path: MEMBER.to_owned(),
        header_block: None,
    })
}

fn run(document: OperationRequestDocument) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(crate_root());
    let context = ExecutionContext::new(&sources);
    Router::execute(&RequestEnvelope::read(document), &context)
}

/// Extract the volume to a scratch directory and return the recovered member's
/// path, so a test can compare against what the two-step route produces.
fn extract_member(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("amiga-re-member-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));

    let sources = FilesystemSourceResolver::new(crate_root());
    let destinations = FilesystemDestinationResolver::new(&root);
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = OperationRequestDocument::ContainerAdfExtract(
        amiga_operations::ContainerExtractArguments::new(VOLUME, "recovered"),
    );

    let mut prepare = RequestEnvelope::read(document.clone());
    prepare.execution.mode = ExecutionMode::Prepare;
    let prepared = Router::execute(&prepare, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let digest = prepared
        .container_extract()
        .expect("a plan")
        .plan
        .plan_sha256
        .clone();

    let mut commit = RequestEnvelope::read(document);
    commit.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    let committed = Router::execute(&commit, &context);
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );
    root.join("recovered").join(MEMBER)
}

/// The property the whole entry exists for, for a survey.
#[test]
fn surveying_a_member_by_selector_matches_surveying_the_extracted_file() {
    let extracted = extract_member("survey");
    let bytes = std::fs::read(&extracted).unwrap_or_else(|error| panic!("{error}"));

    let by_selector = run(OperationRequestDocument::SourceSurvey(
        SourceSurveyArguments {
            source: member_locator(),
            ..SourceSurveyArguments::new(VOLUME)
        },
    ));
    assert_eq!(
        by_selector.status,
        Status::Success,
        "{:?}",
        by_selector.diagnostics
    );
    let by_selector = by_selector.source_survey().expect("a survey");

    // The pin covers the *recovered* bytes, not the volume's: that is what the
    // operation read, and a result citing the container's digest would be
    // reproducible only by someone who already knew which member was meant.
    assert_eq!(by_selector.source.size, bytes.len() as u64);
    assert_eq!(by_selector.source.sha256, amiga_core::sha256(&bytes));

    // And the regions are the extracted file's, not the volume's.
    let extracted_relative = extracted
        .strip_prefix(std::env::temp_dir())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| panic!("the extraction landed outside the scratch root"));
    let sources = FilesystemSourceResolver::new(std::env::temp_dir());
    let context = ExecutionContext::new(&sources);
    let by_file = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new(extracted_relative),
        )),
        &context,
    );
    assert_eq!(by_file.status, Status::Success, "{:?}", by_file.diagnostics);
    let by_file = by_file.source_survey().expect("a survey");

    assert_eq!(by_selector.source.sha256, by_file.source.sha256);
    assert_eq!(by_selector.regions, by_file.regions);

    let _ = std::fs::remove_dir_all(extracted.ancestors().nth(3).unwrap_or(&extracted));
}

/// The same, for an operation that decodes rather than classifies.
#[test]
fn decoding_a_member_by_selector_matches_decoding_the_extracted_file() {
    let extracted = extract_member("bitmap");
    let bytes = std::fs::read(&extracted).unwrap_or_else(|error| panic!("{error}"));

    // The member is 28 bytes; two bitplanes of 8×14 pixels reads all of them.
    let arguments = |source: SourceLocator| amiga_operations::BitmapDecodeArguments {
        source,
        ..amiga_operations::BitmapDecodeArguments::new(VOLUME, 8, 14, 2)
    };
    let by_selector = run(OperationRequestDocument::GraphicsBitmapDecode(arguments(
        member_locator(),
    )));
    assert_eq!(
        by_selector.status,
        Status::Success,
        "{:?}",
        by_selector.diagnostics
    );
    let by_selector = by_selector.graphics_bitmap_decode().expect("a decode");
    assert_eq!(by_selector.source.sha256, amiga_core::sha256(&bytes));

    let extracted_relative = extracted
        .strip_prefix(std::env::temp_dir())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| panic!("the extraction landed outside the scratch root"));
    let sources = FilesystemSourceResolver::new(std::env::temp_dir());
    let context = ExecutionContext::new(&sources);
    let by_file = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapDecode(arguments(
            SourceLocator::file(extracted_relative),
        ))),
        &context,
    );
    assert_eq!(by_file.status, Status::Success, "{:?}", by_file.diagnostics);
    let by_file = by_file.graphics_bitmap_decode().expect("a decode");

    assert_eq!(by_selector.indices, by_file.indices);
    assert_eq!(by_selector.source.sha256, by_file.source.sha256);

    let _ = std::fs::remove_dir_all(extracted.ancestors().nth(3).unwrap_or(&extracted));
}

/// A selector that recovers nothing must refuse, never quietly hand back the
/// container — which would analyse a disk image and report it as the member.
#[test]
fn a_selector_that_names_nothing_refuses_rather_than_falling_back_to_the_parent() {
    let outcome = run(OperationRequestDocument::SourceSurvey(
        SourceSurveyArguments {
            source: SourceLocator::file(VOLUME).member(Selector::Adf {
                path: "S/no-such-file".to_owned(),
                header_block: None,
            }),
            ..SourceSurveyArguments::new(VOLUME)
        },
    ));
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::SourceUnreadable),
        "{:?}",
        outcome.diagnostics
    );
    assert!(
        outcome.result.is_none(),
        "the container was surveyed anyway"
    );
}

/// The ceiling covers both ends. A small archive can hold a large member, and a
/// caller that set a limit meant the bytes the operation would read.
#[test]
fn the_byte_ceiling_applies_to_the_recovered_member_and_not_only_to_its_container() {
    let sources = FilesystemSourceResolver::new(crate_root());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments {
                source: member_locator(),
                // Large enough for the volume, smaller than the 28-byte member.
                maximum_input_bytes: Some(16),
                ..SourceSurveyArguments::new(VOLUME)
            },
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::SourceTooLarge),
        "{:?}",
        outcome.diagnostics
    );
}

/// A `range` is arithmetic, not a container: every operation that reads part of
/// a source already takes an offset and a length, and accepting one here would
/// give the same question two spellings.
#[test]
fn a_range_selector_is_refused_because_it_names_no_member() {
    let outcome = run(OperationRequestDocument::SourceSurvey(
        SourceSurveyArguments {
            source: SourceLocator::file(VOLUME).member(Selector::Range {
                offset: 0,
                length: 4,
            }),
            ..SourceSurveyArguments::new(VOLUME)
        },
    ));
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RequestMalformed),
        "{:?}",
        outcome.diagnostics
    );
}

/// Two requests differing only in which member they read are two questions, and
/// the digest that identifies a request has to say so.
#[test]
fn two_members_of_one_container_do_not_share_a_request_digest() {
    let survey = |member: &str| {
        run(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments {
                source: SourceLocator::file(VOLUME).member(Selector::Adf {
                    path: member.to_owned(),
                    header_block: None,
                }),
                ..SourceSurveyArguments::new(VOLUME)
            },
        ))
        .normalized_request_sha256
    };
    let whole = run(OperationRequestDocument::SourceSurvey(
        SourceSurveyArguments::new(VOLUME),
    ))
    .normalized_request_sha256;

    let startup = survey(MEMBER);
    let readme = survey("readme.txt");
    assert!(startup.is_some());
    assert_ne!(startup, readme);
    assert_ne!(startup, whole);
}
