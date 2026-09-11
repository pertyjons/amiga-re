//! `analysis.hunk.normalize.*` and `provenance.manifest.*` — the two writes
//! whose subject is a *derived* file rather than a decoded one.
//!
//! Normalizing rewrites a one-file loader's compact relocation records as
//! standard ones. It refuses an image that already parses rather than rewriting
//! it: the compact and the ordinary layouts differ by where a count sits, so
//! reading an ordinary image as compact shifts every record after the first and
//! produces a file that looks finished and is not. The rewrite's own re-parse is
//! what turns that into a refusal, and the hunk and relocation counts reported
//! here exist only because that re-parse succeeded.
//!
//! A provenance manifest is thinner still — a name, a size, and a digest — but
//! it is a file this toolkit writes, so it goes through the same reviewed plan
//! as every other. The read half is what `manifest` with no destination prints.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{
    NormalizedHunkNormalize, NormalizedHunkNormalizeExport, NormalizedManifest,
    NormalizedManifestExport, NormalizedMode,
};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    HunkNormalizeExportResult, HunkNormalizeResult, ManifestExportResult, ManifestResult,
    OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn hunk_normalize(
    request: &NormalizedHunkNormalize,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, normalized) = normalize(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::AnalysisHunkNormalize,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: normalized.map(|(summary, _)| OperationResult::AnalysisHunkNormalize(summary)),
    }
}

pub(crate) fn manifest(
    request: &NormalizedManifest,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, described) = describe(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::ProvenanceManifest,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: described.map(|(summary, _)| OperationResult::ProvenanceManifest(summary)),
    }
}

pub(crate) fn hunk_normalize_export(
    request: &NormalizedHunkNormalizeExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisHunkNormalizeExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let destination = match resolve_destination(context, &request.destination) {
        Ok(path) => path,
        Err(diagnostic) => {
            let mut diagnostics = diagnostics;
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, diagnostics, normalized) =
        normalize(&request.normalize, context, diagnostics, events);
    let Some((summary, bytes)) = normalized else {
        return outcome(status, diagnostics, None);
    };

    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::File,
        request.policy,
        vec![PlannedOutput {
            path: request.file_name.clone(),
            size: bytes.len() as u64,
            sha256: summary.normalized_sha256.clone(),
        }],
        Vec::new(),
    );
    let provenance = serde_json::json!({
        "format_version": 1,
        "operation": OperationName::AnalysisHunkNormalizeExport.as_str(),
        "source": { "size": summary.source.size, "sha256": summary.source.sha256 },
        "segments": summary.segments,
        "relocations": summary.relocations,
        "files": [{ "path": request.file_name, "sha256": summary.normalized_sha256 }],
    });
    let result = move |plan: WritePlan, committed| {
        Some(OperationResult::AnalysisHunkNormalizeExport(
            HunkNormalizeExportResult {
                normalized: summary.clone(),
                plan,
                committed,
            },
        ))
    };

    commit(
        &plan,
        mode,
        &destination,
        &request.file_name,
        request.policy,
        bytes,
        &provenance,
        diagnostics,
        &result,
        outcome,
    )
}

pub(crate) fn manifest_export(
    request: &NormalizedManifestExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::ProvenanceManifestExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let destination = match resolve_destination(context, &request.destination) {
        Ok(path) => path,
        Err(diagnostic) => {
            let mut diagnostics = diagnostics;
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, mut diagnostics, described) =
        describe(&request.manifest, context, diagnostics, events);
    let Some((summary, _)) = described else {
        return outcome(status, diagnostics, None);
    };

    // The manifest *is* the file, so it is serialized once and both the plan's
    // digest and the bytes written come from that one value. Serializing twice
    // is how a plan ends up describing something other than what lands.
    let document = serde_json::json!({
        "format_version": 1,
        "path": summary.name,
        "size": summary.source.size,
        "sha256": summary.source.sha256,
    });
    let bytes = match serde_json::to_vec_pretty(&document) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
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
    let result = move |plan: WritePlan, committed| {
        Some(OperationResult::ProvenanceManifestExport(
            ManifestExportResult {
                manifest: summary.clone(),
                plan,
                committed,
            },
        ))
    };

    commit(
        &plan,
        mode,
        &destination,
        &request.file_name,
        request.policy,
        bytes,
        &document,
        diagnostics,
        &result,
        outcome,
    )
}

type Produced<T> = (Status, Vec<Diagnostic>, Option<(T, Vec<u8>)>);

fn normalize(
    request: &NormalizedHunkNormalize,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Produced<HunkNormalizeResult> {
    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return (Status::Error, diagnostics, None);
        }
    };

    // An image that already parses is refused rather than rewritten: there is
    // nothing to normalize, and "rewriting" it would mean reading ordinary
    // records as compact ones and shifting every record after the first.
    if amiga_hunk::Executable::parse(source.bytes()).is_ok() {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::AnalysisHunkAlreadyNormal,
            "the source already parses as an ordinary HUNK executable; nothing to normalize",
        ));
        return (Status::Error, diagnostics, None);
    }

    let bytes = match amiga_hunk::normalize(source.bytes()) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AnalysisHunkUnreadable,
                error.to_string(),
            ));
            return (Status::Error, diagnostics, None);
        }
    };
    // `amiga_hunk::normalize` already re-parses its own output — that re-parse
    // is what makes a bad rewrite a refusal — so this cannot fail. It is done
    // again only to read the counts out of it.
    let Ok(executable) = amiga_hunk::Executable::parse(&bytes) else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::AnalysisHunkUnreadable,
            "the normalized image did not parse",
        ));
        return (Status::Error, diagnostics, None);
    };
    events.emit(OperationEvent::Progress {
        phase: "rewrite_relocations",
        completed: bytes.len() as u64,
        total: Some(bytes.len() as u64),
    });

    let summary = HunkNormalizeResult {
        source: pin(&source),
        normalized_bytes: bytes.len() as u64,
        normalized_sha256: amiga_core::sha256(&bytes),
        segments: executable.segments.len() as u64,
        relocations: executable.relocations.len() as u64,
    };
    (Status::Success, diagnostics, Some((summary, bytes)))
}

fn describe(
    request: &NormalizedManifest,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Produced<ManifestResult> {
    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return (Status::Error, diagnostics, None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "pin_source",
        completed: source.size(),
        total: Some(source.size()),
    });

    let summary = ManifestResult {
        source: pin(&source),
        name: request.source.display_name(),
    };
    (Status::Success, diagnostics, Some((summary, Vec::new())))
}

fn pin(source: &crate::source::ResolvedSource) -> SourcePin {
    SourcePin {
        size: source.size(),
        sha256: source.sha256().to_owned(),
    }
}

fn resolve_destination(
    context: &ExecutionContext<'_>,
    destination: &crate::output::DestinationName,
) -> Result<std::path::PathBuf, Diagnostic> {
    context
        .destinations()
        .resolve(destination)
        .map_err(|error| {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            Diagnostic::error(code, error.to_string())
        })
}

/// The prepare/approve/write dance both exports here share.
#[expect(
    clippy::too_many_arguments,
    reason = "one shared reviewed write parameterized by everything that differs between the two exports"
)]
fn commit(
    plan: &WritePlan,
    mode: &NormalizedMode,
    destination: &std::path::Path,
    file_name: &str,
    policy: crate::output::OutputPolicy,
    bytes: Vec<u8>,
    provenance: &serde_json::Value,
    mut diagnostics: Vec<Diagnostic>,
    result: &dyn Fn(WritePlan, bool) -> Option<OperationResult>,
    outcome: impl Fn(Status, Vec<Diagnostic>, Option<OperationResult>) -> OperationOutcome,
) -> OperationOutcome {
    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(plan.clone(), false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this output, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan.clone(), false));
    }

    let provenance = match serde_json::to_vec_pretty(provenance) {
        Ok(provenance) => provenance,
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
            path: std::path::PathBuf::from(file_name),
            bytes,
        }],
        Vec::new(),
    ) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    match write_plan.commit_file(
        &destination.join(file_name),
        policy.permits_replacement(),
        &provenance,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, result(plan.clone(), true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, result(plan.clone(), false))
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
