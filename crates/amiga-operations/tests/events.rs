//! Events: ordered at phase boundaries, bounded in volume, and never the
//! authoritative answer.

use std::path::{Path, PathBuf};

use amiga_operations::{
    AdfListArguments, CollectingSink, EventSink, ExecutionContext, FilesystemSourceResolver,
    OperationEvent, OperationLimits, OperationRequestDocument, RequestEnvelope, Router,
    SourceSurveyArguments, Status,
};

fn crate_root_resolver() -> FilesystemSourceResolver {
    FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn an_operation_reports_started_first_and_phases_in_order() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let mut sink = CollectingSink::default();

    let outcome = Router::execute_with_events(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("fixtures/volume.adf"),
        )),
        &context,
        &mut sink,
    );
    assert_eq!(outcome.status, Status::Success);

    // `Started` is first and appears exactly once, so a consumer has a definite
    // beginning to hang a display on.
    assert!(matches!(
        sink.events().first(),
        Some(OperationEvent::Started { .. })
    ));
    assert_eq!(
        sink.events()
            .iter()
            .filter(|event| matches!(event, OperationEvent::Started { .. }))
            .count(),
        1
    );

    // Phases arrive in the order the handler reaches them, not in whatever
    // order the work happened to finish.
    let phases: Vec<&str> = sink
        .events()
        .iter()
        .filter_map(|event| match event {
            OperationEvent::Progress { phase, .. } => Some(*phase),
            _ => None,
        })
        .collect();
    assert_eq!(phases, ["open_volume", "walk_directories"]);
}

#[test]
fn the_same_run_reports_the_same_events_every_time() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
        AdfListArguments::new("fixtures/volume.adf"),
    ));

    let mut first = CollectingSink::default();
    let _ = Router::execute_with_events(&request, &context, &mut first);
    let mut second = CollectingSink::default();
    let _ = Router::execute_with_events(&request, &context, &mut second);

    assert_eq!(first.events(), second.events(), "event order is not stable");
}

#[test]
fn a_diagnostic_event_matches_the_diagnostic_on_the_response() {
    // The fixture has two tolerated inconsistencies. They must be reported as
    // events *and* on the response: an event exists so a caller learns sooner,
    // never so it learns something the response omits.
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let mut sink = CollectingSink::default();

    let outcome = Router::execute_with_events(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("fixtures/volume.adf"),
        )),
        &context,
        &mut sink,
    );

    let reported: Vec<&amiga_operations::Diagnostic> = sink
        .events()
        .iter()
        .filter_map(|event| match event {
            OperationEvent::Diagnostic { diagnostic } => Some(diagnostic),
            _ => None,
        })
        .collect();
    assert_eq!(reported.len(), 2);
    for diagnostic in reported {
        assert!(
            outcome.diagnostics.contains(diagnostic),
            "an event reported a diagnostic the response does not carry: {diagnostic:?}"
        );
    }
}

#[test]
fn a_capped_result_reports_the_cap_as_an_event_too() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let mut sink = CollectingSink::default();

    let _ = Router::execute_with_events(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new("fixtures/volume.adf").with_maximum_regions(1),
        )),
        &context,
        &mut sink,
    );

    assert!(
        sink.events().iter().any(|event| matches!(
            event,
            OperationEvent::Diagnostic { diagnostic }
                if diagnostic.code == amiga_operations::DiagnosticCode::ResultRegionsTruncated
        )),
        "a capped survey did not report the cap while running: {:?}",
        sink.events()
    );
}

#[test]
fn a_refused_request_reports_no_events_at_all() {
    // Nothing started, so there is nothing to report progress about; the
    // response's diagnostics are the whole story.
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let mut sink = CollectingSink::default();

    let outcome = Router::execute_with_events(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("../escape.adf"),
        )),
        &context,
        &mut sink,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(sink.events().is_empty(), "{:?}", sink.events());
    assert!(!outcome.diagnostics.is_empty());
}

#[test]
fn an_operation_that_fails_still_reports_that_it_started() {
    let resolver = crate_root_resolver();
    let context = ExecutionContext::new(&resolver);
    let mut sink = CollectingSink::default();

    let outcome = Router::execute_with_events(
        &RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
            AdfListArguments::new("fixtures/sample.bin"),
        )),
        &context,
        &mut sink,
    );

    assert_eq!(outcome.status, Status::Error);
    // The request was accepted and the work began; it is the *work* that
    // failed, and a consumer that saw `Started` must see the response too.
    assert_eq!(sink.events().len(), 1);
    assert!(matches!(sink.events()[0], OperationEvent::Started { .. }));
}

#[test]
fn event_volume_is_bounded_however_many_a_handler_emits() {
    // The bound lives in the router's wrapper, so this holds for any handler
    // without each one having to remember it.
    let mut sink = CollectingSink::default();
    {
        let mut bounded = amiga_operations::BoundedSink::new(&mut sink);
        for completed in 0..(amiga_operations::MAX_EVENTS as u64 * 3) {
            bounded.emit(OperationEvent::Progress {
                phase: "flood",
                completed,
                total: None,
            });
        }
    }
    assert_eq!(sink.events().len(), amiga_operations::MAX_EVENTS + 1);
    assert!(matches!(
        sink.events().last(),
        Some(OperationEvent::Truncated { .. })
    ));
}

#[test]
fn a_cancelled_operation_reports_no_result_however_far_it_got() {
    let resolver = crate_root_resolver();
    let cancel = std::sync::atomic::AtomicBool::new(true);
    let context = ExecutionContext::new(&resolver)
        .with_cancel(&cancel)
        .with_limits(OperationLimits::default());
    let mut sink = CollectingSink::default();

    let outcome = Router::execute_with_events(
        &RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
            SourceSurveyArguments::new("fixtures/volume.adf"),
        )),
        &context,
        &mut sink,
    );

    assert_eq!(outcome.status, Status::Cancelled);
    assert!(
        outcome.result.is_none(),
        "a cancelled operation produced an authoritative result"
    );
    assert_eq!(outcome.exit_code(), 3);
    // It still reported that it started, so a consumer's display does not hang
    // on a request that never announced itself.
    assert!(matches!(
        sink.events().first(),
        Some(OperationEvent::Started { .. })
    ));
    assert!(fixture("volume.adf").is_file());
}

#[test]
fn pre_cancelled_requests_start_but_never_resolve_sources_or_report_progress() {
    let resolver = crate_root_resolver();
    let cancel = std::sync::atomic::AtomicBool::new(true);
    let context = ExecutionContext::new(&resolver).with_cancel(&cancel);
    let mut sink = CollectingSink::default();
    let request = RequestEnvelope::read(OperationRequestDocument::ContainerAdfList(
        AdfListArguments::new("missing.adf"),
    ));
    let outcome = Router::execute_with_events(&request, &context, &mut sink);
    assert_eq!(outcome.status, Status::Cancelled);
    assert!(outcome.result.is_none());
    assert!(outcome.diagnostics.is_empty());
    assert_eq!(sink.events().len(), 1);
    assert!(matches!(sink.events()[0], OperationEvent::Started { .. }));
    let normalized = amiga_operations::normalize(&request, context.limits()).unwrap();
    let direct = Router::execute_normalized(&normalized.request, &context);
    assert_eq!(direct.status, Status::Cancelled);
    assert!(direct.result.is_none());
    assert_eq!(
        direct.normalized_request_sha256,
        outcome.normalized_request_sha256
    );
}
