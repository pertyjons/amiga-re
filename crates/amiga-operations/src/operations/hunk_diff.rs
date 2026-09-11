//! `analysis.hunk.diff` and `analysis.hunk.diff.export` — compare two HUNK
//! executables, and write that comparison as a reviewed artifact.
//!
//! Split the same way `graphics.bitmap.decode` and `graphics.bitmap.export`
//! are, and for the same reason: comparing is a read, and writing the answer
//! down is a separate authorization. The export composes the read rather than
//! re-implementing it, so the file a frontend writes and the answer it prints
//! can never disagree about the same two images.
//!
//! The export uses the same comparison handler as the read-only operation. Its reviewed
//! write plan, provenance manifest, and overwrite policy come from the shared output
//! layer.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedHunkDiff, NormalizedHunkDiffExport, NormalizedMode};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::{HunkDiffFormat, OperationName};
use crate::response::{
    ByteRangeReport, HunkDiffEntry, HunkDiffExportResult, HunkDiffResult, HunkPresence,
    OperationOutcome, OperationResult, RelocationReport, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedHunkDiff,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, result) = compare(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::AnalysisHunkDiff,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: result.map(OperationResult::AnalysisHunkDiff),
    }
}

/// Compare the two images, returning the status, the diagnostics, and the
/// report when there is one.
///
/// Separate from [`run`] so the export can reach the comparison without going
/// through an outcome addressed to the other operation name.
fn compare(
    request: &NormalizedHunkDiff,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> (Status, Vec<Diagnostic>, Option<HunkDiffResult>) {
    let mut resolve = |name: &crate::normalize::NormalizedSource, path: &str| match context
        .resolve_source(name, request.maximum_input_bytes)
    {
        Ok(source) => Some(source),
        Err(error) => {
            diagnostics
                .push(Diagnostic::error(source_error_code(&error), error.to_string()).at(path));
            None
        }
    };
    // Both sides are resolved before either is parsed, so a request naming one
    // missing image reports that rather than a parse failure on the other.
    let (Some(source_a), Some(source_b)) = (
        resolve(&request.a, "$.request.arguments.a"),
        resolve(&request.b, "$.request.arguments.b"),
    ) else {
        return (Status::Error, diagnostics, None);
    };

    let parsed_a = parse(source_a.bytes(), "a", &mut diagnostics);
    let parsed_b = parse(source_b.bytes(), "b", &mut diagnostics);
    let (Some(executable_a), Some(executable_b)) = (parsed_a, parsed_b) else {
        return (Status::Error, diagnostics, None);
    };

    events.emit(OperationEvent::Progress {
        phase: "parse_executables",
        completed: source_a.size().saturating_add(source_b.size()),
        total: Some(source_a.size().saturating_add(source_b.size())),
    });

    let compared = amiga_hunk::diff(&executable_a, &executable_b);
    events.emit(OperationEvent::Progress {
        phase: "compare_hunks",
        completed: compared.hunks.len() as u64,
        total: Some(compared.hunks.len() as u64),
    });

    // Every hunk present in either image is reported, including the identical
    // ones. A result that silently omitted them would make "this hunk is not
    // listed" mean both "unchanged" and "absent from both".
    let hunks: Vec<HunkDiffEntry> = compared
        .hunks
        .iter()
        .map(|hunk| {
            let ranges_total = hunk.changed_ranges.len();
            let ranges_truncated = ranges_total > request.maximum_entries;
            if ranges_truncated {
                diagnostics.push(
                    Diagnostic::warning(
                        DiagnosticCode::ResultEntriesTruncated,
                        format!(
                            "hunk {} has {ranges_total} changed ranges; reporting the first {}",
                            hunk.index, request.maximum_entries
                        ),
                    )
                    .about(format!("hunk:{}", hunk.index)),
                );
            }
            HunkDiffEntry {
                index: hunk.index,
                presence: match hunk.presence {
                    amiga_hunk::HunkPresence::Both => HunkPresence::Both,
                    amiga_hunk::HunkPresence::OnlyA => HunkPresence::OnlyA,
                    amiga_hunk::HunkPresence::OnlyB => HunkPresence::OnlyB,
                },
                unchanged: hunk.is_unchanged(),
                kind_a: hunk.kind_a.map(|kind| kind.to_string()),
                kind_b: hunk.kind_b.map(|kind| kind.to_string()),
                allocation_a: hunk.allocation_a.map(|size| size as u64),
                allocation_b: hunk.allocation_b.map(|size| size as u64),
                changed_ranges: hunk
                    .changed_ranges
                    .iter()
                    .take(request.maximum_entries)
                    .map(|range| ByteRangeReport {
                        start: range.start,
                        length: range.len,
                    })
                    .collect(),
                changed_range_total: ranges_total,
                changed_ranges_truncated: ranges_truncated,
                added_relocations: relocations(&hunk.added_relocations),
                removed_relocations: relocations(&hunk.removed_relocations),
            }
        })
        .collect();

    let result = HunkDiffResult {
        a: SourcePin {
            size: source_a.size(),
            sha256: source_a.sha256().to_owned(),
        },
        b: SourcePin {
            size: source_b.size(),
            sha256: source_b.sha256().to_owned(),
        },
        identical: compared.is_empty(),
        changed_hunks: hunks.iter().filter(|hunk| !hunk.unchanged).count(),
        hunks,
    };
    (Status::Success, diagnostics, Some(result))
}

pub(crate) fn export(
    request: &NormalizedHunkDiffExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisHunkDiffExport,
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

    // The comparison is the read operation's, run through its own code path:
    // one set of bounds, one set of diagnostics, one answer.
    let (status, diagnostics, compared) = compare(&request.diff, context, diagnostics, events);
    let Some(compared) = compared else {
        return outcome(status, diagnostics, None);
    };
    let mut diagnostics = diagnostics;

    let bytes = match request.format {
        HunkDiffFormat::Json => match serde_json::to_vec_pretty(&serde_json::json!({
            "schema": OperationName::AnalysisHunkDiffExport.as_str(),
            "format_version": 1,
            "a": {
                "name": request.diff.a.display_name(),
                "size": compared.a.size,
                "sha256": compared.a.sha256,
            },
            "b": {
                "name": request.diff.b.display_name(),
                "size": compared.b.size,
                "sha256": compared.b.sha256,
            },
            "identical": compared.identical,
            "changed_hunks": compared.changed_hunks,
            "hunks": compared.hunks,
        })) {
            Ok(bytes) => bytes,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::AnalysisReportEncodeFailed,
                    error.to_string(),
                ));
                return outcome(Status::Error, diagnostics, None);
            }
        },
        HunkDiffFormat::Text => render_text(
            &compared,
            &request.diff.a.display_name(),
            &request.diff.b.display_name(),
        )
        .into_bytes(),
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
        Some(OperationResult::AnalysisHunkDiffExport(
            HunkDiffExportResult {
                a: compared.a.clone(),
                b: compared.b.clone(),
                identical: compared.identical,
                changed_hunks: compared.changed_hunks,
                format: request.format,
                plan,
                committed,
            },
        ))
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
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this comparison, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    // Both pins are in the manifest. A recorded comparison of two images
    // nobody can identify afterwards is a claim rather than a record.
    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::AnalysisHunkDiffExport.as_str(),
        "sources": [
            { "name": request.diff.a.display_name(), "size": compared.a.size, "sha256": compared.a.sha256 },
            { "name": request.diff.b.display_name(), "size": compared.b.size, "sha256": compared.b.sha256 },
        ],
        "format": request.format.as_str(),
        "files": [{ "path": request.file_name, "sha256": amiga_core::sha256(&bytes) }],
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AnalysisReportEncodeFailed,
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

/// The human-readable rendering, for the callers that want a report to read
/// rather than to parse.
fn render_text(result: &HunkDiffResult, name_a: &str, name_b: &str) -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    let _ = writeln!(text, "diff A={name_a} B={name_b}");
    let _ = writeln!(text, "A sha256 {}", result.a.sha256);
    let _ = writeln!(text, "B sha256 {}", result.b.sha256);
    if result.identical {
        let _ = writeln!(text, "the two images are structurally identical");
        return text;
    }
    for hunk in result.hunks.iter().filter(|hunk| !hunk.unchanged) {
        let _ = writeln!(
            text,
            "hunk {} {} A={} B={}",
            hunk.index,
            hunk.presence.as_str(),
            side(hunk.kind_a.as_deref(), hunk.allocation_a),
            side(hunk.kind_b.as_deref(), hunk.allocation_b),
        );
        for range in &hunk.changed_ranges {
            let _ = writeln!(
                text,
                "  changed {:#x}..{:#x} ({} bytes)",
                range.start,
                range.start.saturating_add(range.length),
                range.length,
            );
        }
        if hunk.changed_ranges_truncated {
            let _ = writeln!(
                text,
                "  ... {} further changed ranges are not listed",
                hunk.changed_range_total - hunk.changed_ranges.len(),
            );
        }
        for relocation in &hunk.added_relocations {
            let _ = writeln!(
                text,
                "  +reloc {:#x} -> hunk {}",
                relocation.source_offset, relocation.target_hunk,
            );
        }
        for relocation in &hunk.removed_relocations {
            let _ = writeln!(
                text,
                "  -reloc {:#x} -> hunk {}",
                relocation.source_offset, relocation.target_hunk,
            );
        }
    }
    text
}

fn side(kind: Option<&str>, allocation: Option<u64>) -> String {
    match (kind, allocation) {
        (Some(kind), Some(allocation)) => format!("{kind}/{allocation}"),
        _ => "absent".to_owned(),
    }
}

/// Parse one side, reporting a refusal against the argument that named it.
fn parse<'bytes>(
    bytes: &'bytes [u8],
    side: &'static str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<amiga_hunk::Executable<'bytes>> {
    match amiga_hunk::Executable::parse(bytes) {
        Ok(executable) => Some(executable),
        Err(error) => {
            diagnostics.push(
                Diagnostic::error(DiagnosticCode::AnalysisHunkUnreadable, error.to_string())
                    .at(format!("$.request.arguments.{side}")),
            );
            None
        }
    }
}

fn relocations(relocations: &[amiga_hunk::Relocation]) -> Vec<RelocationReport> {
    relocations
        .iter()
        .map(|relocation| RelocationReport {
            source_offset: relocation.source_offset,
            target_hunk: relocation.target_hunk,
        })
        .collect()
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
