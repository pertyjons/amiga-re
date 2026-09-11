//! `container.adf.list` end to end, and the properties it shares with
//! `source.survey`: one envelope, one digest rule, one cap-and-total shape.

use std::path::{Path, PathBuf};

use amiga_operations::{
    AdfEntryKind, AdfListArguments, DiagnosticCode, ExecutionContext, FilesystemSourceResolver,
    OperationLimits, OperationRequestDocument, RequestEnvelope, ResponseEnvelope, Router, Status,
};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn crate_root_resolver() -> FilesystemSourceResolver {
    FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_dir().join(name))
        .unwrap_or_else(|error| panic!("fixture {name} is readable: {error}"))
}

fn request_fixture() -> RequestEnvelope {
    serde_json::from_str(&read_fixture("container.adf.list.request.json"))
        .expect("the request fixture parses as a request envelope")
}

#[test]
fn the_json_protocol_round_trip_matches_the_response_fixture() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let request = request_fixture();

    let outcome = Router::execute(&request, &context);
    let response = ResponseEnvelope::from_outcome(&outcome, request.request_id.as_deref());
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&response).expect("the response serializes")
    );

    let path = fixture_dir().join("container.adf.list.response.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &actual).expect("the response fixture is writable");
        return;
    }
    let expected = read_fixture("container.adf.list.response.json");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&actual).expect("actual is JSON"),
        serde_json::from_str::<serde_json::Value>(&expected).expect("expected is JSON"),
        "response differs from the fixture (run with UPDATE_GOLDEN=1 after auditing the change)"
    );
}

#[test]
fn the_volume_and_its_entries_are_reported_with_canonical_paths() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(&request_fixture(), &context);
    let listing = outcome.container_adf_list().expect("the listing ran");

    assert_eq!(outcome.status, Status::Success);
    assert_eq!(listing.volume.name, "AmigaRe");
    assert_eq!(listing.volume.filesystem, "ofs");
    assert_eq!(listing.volume.block_size, 512);
    assert_eq!(listing.volume.root_block, 10);

    let paths: Vec<&str> = listing
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["S", "S/stale", "S/startup-sequence", "readme.txt"],
        "paths are volume-relative and `/`-separated"
    );
    assert!(paths.iter().all(|path| !path.starts_with('/')));

    let directory = &listing.entries[0];
    assert_eq!(directory.kind, AdfEntryKind::Directory);
    assert_eq!(directory.header_block, 2);

    let startup = &listing.entries[2];
    assert_eq!(startup.kind, AdfEntryKind::File);
    assert_eq!(startup.size, 28);
    assert_eq!(listing.entry_total, 4);
    assert!(!listing.entries_truncated);
}

#[test]
fn tolerated_inconsistencies_are_reported_as_warnings_with_their_block() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(&request_fixture(), &context);

    // The fixture has an invalid boot-block checksum and a file declared empty
    // that still holds a data pointer. Both are recovered, and both are said so.
    //
    // The two carry *different* codes: a consumer acts on the code, never on the
    // message, so two distinct inconsistencies must be distinguishable without
    // parsing prose.
    let tolerated: Vec<&amiga_operations::Diagnostic> = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            matches!(
                diagnostic.code,
                DiagnosticCode::ContainerAdfBootChecksumInvalid
                    | DiagnosticCode::ContainerAdfEmptyFileWithDataPointer
            )
        })
        .collect();
    assert_eq!(tolerated.len(), 2, "{:?}", outcome.diagnostics);
    assert!(tolerated.iter().all(|diagnostic| !diagnostic.is_error()));
    assert_eq!(
        tolerated[0].code,
        DiagnosticCode::ContainerAdfBootChecksumInvalid
    );
    assert_eq!(tolerated[0].entity_id.as_deref(), Some("block:0"));
    assert_eq!(
        tolerated[1].code,
        DiagnosticCode::ContainerAdfEmptyFileWithDataPointer
    );
    assert_eq!(tolerated[1].entity_id.as_deref(), Some("block:7"));
    assert_ne!(tolerated[0].code, tolerated[1].code);

    // Warnings never suppress the result.
    assert_eq!(outcome.status, Status::Success);
    assert!(outcome.container_adf_list().is_some());
}

#[test]
fn a_capped_entry_list_reports_the_total_it_was_capped_from() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let capped = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("fixtures/volume.adf").with_maximum_entries(2),
        )),
        &context,
    );

    let listing = capped.container_adf_list().expect("the listing ran");
    assert_eq!(listing.entries.len(), 2);
    assert_eq!(listing.entry_total, 4);
    assert!(listing.entries_truncated);
    assert!(
        capped
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ResultEntriesTruncated),
        "truncation must be reported, never silent"
    );
}

#[test]
fn a_source_that_is_not_a_volume_fails_without_a_result() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("fixtures/sample.bin"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::ContainerAdfUnreadable
    );
    assert_eq!(outcome.exit_code(), 1);
}

#[test]
fn the_two_operations_share_one_envelope_and_one_digest_rule() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let listing = Router::execute(&request_fixture(), &context);
    let survey = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            amiga_operations::SourceSurveyArguments::new("fixtures/volume.adf"),
        )),
        &context,
    );

    // Same source, same envelope, different operation — so the digest that
    // identifies "what was asked for" must differ.
    assert!(listing.normalized_request_sha256.is_some());
    assert_ne!(
        listing.normalized_request_sha256,
        survey.normalized_request_sha256
    );

    // The same request twice is the same digest, defaults materialized or not.
    let explicit = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("fixtures/volume.adf")
                .with_maximum_input_bytes(amiga_operations::limits::DEFAULT_MAXIMUM_INPUT_BYTES)
                .with_maximum_entries(amiga_operations::limits::DEFAULT_MAXIMUM_ENTRIES),
        )),
        &context,
    );
    assert_eq!(
        listing.normalized_request_sha256,
        explicit.normalized_request_sha256
    );
}

#[test]
fn an_oversized_volume_is_refused_before_it_is_parsed() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver)
        .with_limits(OperationLimits::default().with_maximum_input_bytes(1024));

    let outcome = Router::execute(&request_fixture(), &context);

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::SourceTooLarge)
    );
}
