//! `analysis.hunk.list` — what a LoadSeg image's hunks are, and what relocates
//! into what.
//!
//! The response includes relocation sites as well as counts, so consumers can identify
//! which hunk each pointer targets without parsing the image again.
//!
//! A relocation site whose stored pointer cannot be read is reported with no
//! offset rather than dropped. An unreadable site is a fact about the image, and
//! a list that silently held one fewer entry than the file declares would be the
//! kind of quiet loss this toolkit exists to avoid.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedHunkList;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    HunkListResult, HunkRelocation, HunkSegment, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedHunkList,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisHunkList,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            let code = match error {
                SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let executable = match amiga_hunk::Executable::parse(source.bytes()) {
        Ok(executable) => executable,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AnalysisHunkUnreadable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "parse_hunks",
        completed: executable.segments.len() as u64,
        total: Some(executable.segments.len() as u64),
    });

    let mut truncated_any = false;
    let segments = executable
        .segments
        .iter()
        .map(|segment| {
            let sites: Vec<&amiga_hunk::Relocation> = executable
                .relocations
                .iter()
                .filter(|relocation| relocation.source_hunk == segment.index)
                .collect();
            let total = sites.len();
            let truncated = total > request.maximum_relocations;
            truncated_any |= truncated;
            HunkSegment {
                index: segment.index,
                kind: segment.kind.to_string(),
                allocation_bytes: segment.allocation_size as u64,
                file_offset: segment.file_offset as u64,
                file_bytes: segment.bytes.len() as u64,
                relocations: sites
                    .into_iter()
                    .take(request.maximum_relocations)
                    .map(|relocation| HunkRelocation {
                        source_hunk: relocation.source_hunk,
                        source_offset: relocation.source_offset,
                        target_hunk: relocation.target_hunk,
                        stored_offset: executable.stored_pointer(relocation),
                    })
                    .collect(),
                // The true total, always: a capped list that read as a complete
                // one would make a heavily relocated hunk look simple.
                relocation_total: total as u64,
                relocations_truncated: truncated,
            }
        })
        .collect();

    if truncated_any {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "at least one hunk has more than {} relocations; each reports its true total",
                request.maximum_relocations
            ),
        ));
    }

    let result = HunkListResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        first_hunk: executable.first_hunk,
        last_hunk: executable.last_hunk,
        segments,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisHunkList(result)),
    )
}
