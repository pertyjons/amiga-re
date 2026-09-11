//! `source.carve` — write one byte range of a source as its own file.
//!
//! The simplest `prepared_output` operation, and the one that most needed a
//! home: carving a selected range out of a source is what a person does dozens
//! of times while identifying an unknown format, and it was the last write path
//! a frontend still implemented for itself.
//!
//! It stops at bytes deliberately. What the range *is* — a bitmap, a sample, a
//! table — is a separate decision with its own operation; a carve that guessed
//! would be a decode nobody asked for.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedCarve, NormalizedMode};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{CarveResult, OperationOutcome, OperationResult, SourcePin};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedCarve,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::SourceCarve,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // The range is checked against the bytes that were actually resolved, not
    // against the size the caller believed: a carve past the end must refuse
    // rather than write a short file that looks like the range it names.
    let end = match request.offset.checked_add(request.length) {
        Some(end) => end,
        None => {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "offset + length overflows".to_owned(),
                )
                .at("$.request.arguments.length"),
            );
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let Some(bytes) = source.bytes().get(request.offset..end) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "range {}..{end} lies outside the {}-byte source",
                    request.offset,
                    source.size()
                ),
            )
            .at("$.request.arguments.offset"),
        );
        return outcome(Status::Error, diagnostics, None);
    };
    let bytes = bytes.to_vec();
    let length = bytes.len() as u64;
    events.emit(OperationEvent::Progress {
        phase: "carve_range",
        completed: bytes.len() as u64,
        total: Some(bytes.len() as u64),
    });

    let pin = SourcePin {
        size: source.size(),
        sha256: source.sha256().to_owned(),
    };
    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::File,
        request.policy,
        vec![PlannedOutput {
            path: request.file_name.clone(),
            size: bytes.len() as u64,
            sha256: amiga_core::sha256(&bytes),
        }],
        Vec::new(),
    );
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::SourceCarve(CarveResult {
            source: pin.clone(),
            offset: request.offset as u64,
            length,
            plan,
            committed,
        }))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(plan, false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "a carve reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this carve, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    // The range is in the manifest as well as the digest: a carved file whose
    // provenance does not say where it came from cannot be re-derived.
    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::SourceCarve.as_str(),
        "source": { "name": request.source.display_name(), "size": pin.size, "sha256": pin.sha256 },
        "offset": request.offset,
        "length": bytes.len(),
        "files": [{ "path": request.file_name, "sha256": amiga_core::sha256(&bytes) }],
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let write_plan = match amiga_core::ExtractionPlan::new(
        vec![amiga_core::PlannedFile {
            path: std::path::PathBuf::from(&request.file_name),
            bytes,
        }],
        Vec::new(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // A single named file into a directory this toolkit does not own: the policy
    // governs that file and its manifest, and nothing else in the directory is
    // read, written, or removed. Owning the directory — which is what `commit`
    // does — would refuse an ordinary output path for existing, and make
    // `create_only` mean "only into an empty folder".
    match write_plan.commit_file(
        &destination.join(&request.file_name),
        request.policy.permits_replacement(),
        &manifest,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, result(plan, true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, result(plan, false))
        }
    }
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
