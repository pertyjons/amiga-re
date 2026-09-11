//! `source.survey` end to end: the JSON protocol, the in-process Rust API, and
//! the bounds that refuse a request before any source is opened.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use amiga_operations::{
    DiagnosticCode, ExecutionContext, FilesystemSourceResolver, InMemorySourceResolver,
    OperationLimits, OperationRequestDocument, PROTOCOL_VERSION, RequestEnvelope, ResolvedSource,
    ResponseEnvelope, Router, SourceName, SourceSurveyArguments, Status,
};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// A resolver rooted at the crate directory, so `fixtures/sample.bin` in a
/// request document resolves without the document naming a host path.
fn crate_root_resolver() -> FilesystemSourceResolver {
    FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_dir().join(name))
        .unwrap_or_else(|error| panic!("fixture {name} is readable: {error}"))
}

fn request_fixture() -> RequestEnvelope {
    serde_json::from_str(&read_fixture("source.survey.request.json"))
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

    let path = fixture_dir().join("source.survey.response.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &actual).expect("the response fixture is writable");
        return;
    }
    let expected = read_fixture("source.survey.response.json");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&actual).expect("actual is JSON"),
        serde_json::from_str::<serde_json::Value>(&expected).expect("expected is JSON"),
        "response differs from the fixture (run with UPDATE_GOLDEN=1 after auditing the change)"
    );
}

#[test]
fn the_json_and_rust_paths_produce_the_same_result() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let from_json = Router::execute(&request_fixture(), &context);
    let from_rust = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new("fixtures/sample.bin")
                .with_minimum_string_length(6)
                .with_maximum_regions(4096),
        )),
        &context,
    );

    // The request id differs; nothing the digest covers does.
    assert_eq!(
        from_json.normalized_request_sha256,
        from_rust.normalized_request_sha256
    );

    let json_survey = from_json.source_survey().expect("the survey ran");
    let rust_survey = from_rust.source_survey().expect("the survey ran");
    assert_eq!(json_survey.source, rust_survey.source);
    assert_eq!(json_survey.regions, rust_survey.regions);
    assert_eq!(json_survey.region_total, rust_survey.region_total);
    assert_eq!(json_survey.copper_lists, rust_survey.copper_lists);
}

#[test]
fn an_in_memory_source_surveys_identically_to_the_same_bytes_on_disk() {
    let bytes: Arc<[u8]> =
        Arc::from(std::fs::read(fixture_dir().join("sample.bin")).expect("the sample is readable"));

    let on_disk = crate_root_resolver();
    let held = InMemorySourceResolver::new(ResolvedSource::new(
        SourceName::parse("fixtures/sample.bin").expect("a relative name"),
        Arc::clone(&bytes),
    ));

    let request = request_fixture();
    let from_disk = Router::execute(&request, &ExecutionContext::new(&on_disk));
    let from_memory = Router::execute(&request, &ExecutionContext::new(&held));

    let disk_survey = from_disk.source_survey().expect("the survey ran");
    let memory_survey = from_memory.source_survey().expect("the survey ran");
    assert_eq!(disk_survey.source, memory_survey.source);
    assert_eq!(disk_survey.regions, memory_survey.regions);
    assert_eq!(
        from_disk.normalized_request_sha256,
        from_memory.normalized_request_sha256
    );
}

#[test]
fn a_capped_region_list_reports_the_total_it_was_capped_from() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let complete = Router::execute(&request_fixture(), &context);
    let total = complete
        .source_survey()
        .expect("the survey ran")
        .region_total;
    assert!(total > 1, "the sample must produce several regions");

    let capped = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new("fixtures/sample.bin")
                .with_minimum_string_length(6)
                .with_maximum_regions(1),
        )),
        &context,
    );

    let survey = capped.source_survey().expect("the survey ran");
    assert_eq!(survey.regions.len(), 1);
    assert_eq!(survey.region_total, total);
    assert!(survey.regions_truncated);
    assert_eq!(capped.status, Status::Success);
    assert!(
        capped
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ResultRegionsTruncated),
        "truncation must be reported, never silent"
    );
}

#[test]
fn an_oversized_source_is_refused_rather_than_surveyed_as_a_prefix() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver)
        .with_limits(OperationLimits::default().with_maximum_input_bytes(16));

    let outcome = Router::execute(&request_fixture(), &context);

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(outcome.diagnostics[0].code, DiagnosticCode::LimitReduced);
    assert_eq!(outcome.diagnostics[1].code, DiagnosticCode::SourceTooLarge);
    // The operation ran and failed; the request itself was valid.
    assert_eq!(outcome.exit_code(), 1);
}

#[test]
fn a_missing_source_fails_without_a_result() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new("fixtures/absent.bin"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(outcome.diagnostics[0].code, DiagnosticCode::SourceMissing);
    assert_eq!(outcome.exit_code(), 1);
}

#[test]
fn an_escaping_source_path_is_refused_with_the_invalid_request_exit_code() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new("../../etc/passwd"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.normalized_request_sha256.is_none());
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::RequestSourceNameInvalid
    );
    assert_eq!(outcome.exit_code(), 2);
}

#[test]
fn a_malformed_request_document_is_rejected_by_the_parser() {
    let unknown_field = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "request": {
            "operation": "source.survey",
            "arguments": { "source": { "kind": "file", "path": "sample.bin" }, "min_string": 6 }
        }
    });
    assert!(
        serde_json::from_value::<RequestEnvelope>(unknown_field).is_err(),
        "an unknown argument must not be silently ignored"
    );

    let unknown_operation = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "request": { "operation": "source.divine", "arguments": {} }
    });
    assert!(serde_json::from_value::<RequestEnvelope>(unknown_operation).is_err());
}
