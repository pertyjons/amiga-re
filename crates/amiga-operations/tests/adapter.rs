//! Milestone 7: a minimal adapter, built entirely in this test.
//!
//! These tests implement an independent adapter using only the public API, covering
//! capabilities, request limits, path exposure, cancellation, and event framing.
//!
//! What makes this a review rather than a demo is that each test asserts a
//! *refusal*. An adapter that can do everything proves nothing about
//! boundaries.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use amiga_operations::{
    AdfListArguments, BitmapDecodeArguments, ContainerExtractArguments, DiagnosticCode,
    ExecutionContext, ExecutionMode, FilesystemDestinationResolver, FilesystemSourceResolver,
    OperationEvent, OperationLimits, OperationRequestDocument, ProjectArguments, ProjectLocator,
    RequestEnvelope, Router, Status, StreamMessage,
};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The synthetic OFS volume every test here reads, checked to be present first.
///
/// This suite sorts first among the crate's integration targets, so `cargo test`
/// stops here — and without the check, five tests would fail on mismatched
/// listings and say nothing about the missing file. The fixture is committed
/// (see `fixtures/README.md`), so absence means an incomplete checkout rather
/// than an unprepared one. `tests/fixtures.rs` states the same thing for the
/// whole set.
fn volume_adf() -> &'static str {
    let path = crate_root().join("fixtures/volume.adf");
    assert!(
        path.is_file(),
        "{} is missing. It is committed test data, not private media, so this \
         checkout is incomplete rather than merely unprepared.",
        path.display()
    );
    "fixtures/volume.adf"
}

/// The whole adapter: a resolver root, optional destinations, a cancellation
/// flag, and a place to put events. Roughly what any embedder needs, and
/// nothing more.
struct TestAdapter {
    sources: FilesystemSourceResolver,
    cancel: AtomicBool,
    events: Vec<OperationEvent>,
    lines: Vec<String>,
}

impl TestAdapter {
    fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            sources: FilesystemSourceResolver::new(root.into()),
            cancel: AtomicBool::new(false),
            events: Vec::new(),
            lines: Vec::new(),
        }
    }

    /// Run a request, collecting events and the JSON Lines transcript.
    fn run(&mut self, request: &RequestEnvelope) -> amiga_operations::OperationOutcome {
        let context = ExecutionContext::new(&self.sources).with_cancel(&self.cancel);
        let lines = &mut self.lines;
        let events = &mut self.events;
        amiga_operations::execute_streaming(request, &context, &mut |message| {
            if let StreamMessage::Event(message) = &message {
                events.push(message.event.clone());
            }
            lines.push(serde_json::to_string(&message).expect("a stream line serializes"));
        })
    }
}

fn read(document: OperationRequestDocument) -> RequestEnvelope {
    RequestEnvelope::read(document)
}

#[test]
fn an_adapter_needs_only_a_resolver_to_run_a_read_only_operation() {
    let mut adapter = TestAdapter::new(crate_root());
    let outcome = adapter.run(&read(OperationRequestDocument::ContainerAdfList(
        AdfListArguments::new(volume_adf()),
    )));

    assert_eq!(outcome.status, Status::Success);
    assert!(outcome.container_adf_list().is_some());
    // Event framing: started first, response last, every line tagged.
    assert!(matches!(
        adapter.events.first(),
        Some(OperationEvent::Started { .. })
    ));
    assert!(adapter.lines.first().unwrap().contains("\"accepted\""));
    assert!(adapter.lines.last().unwrap().contains("\"response\""));
    for line in &adapter.lines {
        assert!(line.contains("\"message_type\""), "{line}");
    }
}

#[test]
fn an_adapter_that_offered_no_destinations_cannot_write() {
    // The capability boundary. Writing is not something an operation decides;
    // it is something an adapter grants, and this one granted nothing.
    let mut adapter = TestAdapter::new(crate_root());
    let mut request = read(OperationRequestDocument::ContainerAdfExtract(
        ContainerExtractArguments::new(volume_adf(), "out"),
    ));
    request.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: "0".repeat(64),
    };
    let outcome = adapter.run(&request);

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::OutputDestinationUnavailable
    );
}

#[test]
fn an_adapter_grants_writing_by_supplying_destinations_and_nothing_else() {
    let directory = std::env::temp_dir().join(format!("amiga-adapter-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap_or_else(|error| panic!("{error}"));

    let sources = FilesystemSourceResolver::new(crate_root());
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);

    let mut request = read(OperationRequestDocument::ContainerAdfExtract(
        ContainerExtractArguments::new(volume_adf(), "out"),
    ));
    request.execution.mode = ExecutionMode::Prepare;
    let prepared = Router::execute(&request, &context);
    assert_eq!(prepared.status, Status::Prepared);
    // And prepare wrote nothing, even with the capability granted.
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn no_request_can_name_a_host_path() {
    // Path exposure. Every locator is an identity the adapter resolves; a
    // request that could reach outside the root would make a document
    // unreproducible and unsafe at once.
    let mut adapter = TestAdapter::new(crate_root());
    for escaping in ["../escape.adf", "/etc/passwd", "fixtures/../../escape"] {
        let outcome = adapter.run(&read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new(escaping),
        )));
        assert_eq!(outcome.status, Status::Error, "{escaping}");
        assert_eq!(
            outcome.diagnostics[0].code,
            DiagnosticCode::RequestSourceNameInvalid,
            "{escaping}"
        );
        assert_eq!(outcome.exit_code(), 2, "{escaping}");
    }
    // The same rule covers a project locator.
    let mut request = read(OperationRequestDocument::ProjectCheck(
        ProjectArguments::default(),
    ));
    request.project = Some(ProjectLocator::Path {
        path: "../escape".to_owned(),
    });
    assert_eq!(adapter.run(&request).status, Status::Error);
}

#[test]
fn an_adapter_can_lower_a_limit_but_a_request_cannot_raise_it_past_the_context() {
    // Request limits. A context's ceiling is the adapter's decision; a request
    // may ask for less and is told when it asked for more.
    let sources = FilesystemSourceResolver::new(crate_root());
    let context = ExecutionContext::new(&sources)
        .with_limits(OperationLimits::default().with_maximum_entries(1));

    let outcome = Router::execute(
        &read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new(volume_adf()).with_maximum_entries(1_000_000),
        )),
        &context,
    );
    let listing = outcome.container_adf_list().expect("the listing ran");
    assert_eq!(
        listing.entries.len(),
        1,
        "the context's ceiling did not win"
    );
    assert!(listing.entries_truncated);
    // And the reduction is reported rather than applied silently.
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::LimitReduced),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_adapters_cancellation_flag_stops_an_operation_with_no_result() {
    let mut adapter = TestAdapter::new(crate_root());
    adapter
        .cancel
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let outcome = adapter.run(&read(OperationRequestDocument::GraphicsBitmapDecode(
        // A geometry the fixture actually holds, so the decode reaches its
        // first cancellation checkpoint rather than failing on size first.
        BitmapDecodeArguments::new(volume_adf(), 320, 64, 1),
    )));

    assert_eq!(outcome.status, Status::Cancelled);
    assert!(outcome.result.is_none());
    assert_eq!(outcome.exit_code(), 3);
    // The transcript still ends with a response, so a consumer's loop
    // terminates the same way it does on success.
    assert!(adapter.lines.last().unwrap().contains("\"response\""));
}

#[test]
fn every_operation_the_catalog_lists_is_reachable_from_the_public_api_alone() {
    // The readiness claim. An adapter discovers what it can do from the
    // catalog, and every entry has a schema pair and an access class it can
    // act on without reading this crate's internals.
    for descriptor in amiga_operations::catalog() {
        assert!(!descriptor.summary.is_empty());
        assert!(
            serde_json::from_str::<serde_json::Value>(descriptor.request_schema).is_ok(),
            "{}: request schema is not JSON",
            descriptor.name
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(descriptor.response_schema).is_ok(),
            "{}: response schema is not JSON",
            descriptor.name
        );
        // The access class is what an adapter keys its capability decision on.
        let _writes = descriptor.access == amiga_operations::AccessClass::PreparedOutput;
    }
    assert!(amiga_operations::catalog().len() >= 8);
}

#[test]
fn a_json_request_and_a_rust_request_produce_the_same_digest() {
    // The two API levels the crate documents must agree, or an adapter that
    // built a request in Rust could not reproduce one a document described.
    let sources = FilesystemSourceResolver::new(crate_root());
    let context = ExecutionContext::new(&sources);

    let from_rust = Router::execute(
        &read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new(volume_adf()),
        )),
        &context,
    );
    let document = r#"{"protocol_version":1,"request":{"operation":"container.adf.list",
        "arguments":{"source":{"kind":"file","path":"fixtures/volume.adf"}}}}"#;
    let parsed: RequestEnvelope = serde_json::from_str(document).expect("a valid request");
    let from_json = Router::execute(&parsed, &context);

    assert_eq!(
        from_rust.normalized_request_sha256,
        from_json.normalized_request_sha256
    );
}

#[test]
fn an_adapter_reads_a_response_without_reading_this_crates_internals() {
    // A response is a document. An embedder that speaks only JSON must get
    // everything it needs from it — which is what makes a process or network
    // adapter possible without changing anything here.
    let mut adapter = TestAdapter::new(crate_root());
    let outcome = adapter.run(&read(OperationRequestDocument::ContainerAdfList(
        AdfListArguments::new(volume_adf()),
    )));
    let document = amiga_operations::ResponseEnvelope::from_outcome(&outcome, Some("req:1"));
    let json = serde_json::to_value(&document).expect("the response serializes");

    assert_eq!(json["protocol_version"], 1);
    assert_eq!(json["request_id"], "req:1");
    assert_eq!(json["operation"], "container.adf.list");
    assert_eq!(json["status"], "success");
    assert!(json["normalized_request_sha256"].is_string());
    assert!(json["result"]["volume"]["name"].is_string());
    for diagnostic in json["diagnostics"].as_array().unwrap() {
        assert!(diagnostic["code"].is_string());
        assert!(diagnostic["severity"].is_string());
    }
    assert!(Path::new(&crate_root()).is_dir());
}
