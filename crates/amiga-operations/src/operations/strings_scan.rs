//! `analysis.strings.scan` — printable runs, and where they sit.
//!
//! The substring filter is part of the *request* rather than something a caller
//! applies to the answer. Filtering a capped list afterwards would silently drop
//! matches the scan found and the cap discarded, so a caller who asked for
//! "strings containing `disk`" would get fewer than exist for a reason nothing
//! in the response explains. Filtering first and capping second makes the
//! reported total mean what it says.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedStringsScan;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    FoundString, OperationOutcome, OperationResult, SourcePin, StringsScanResult,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedStringsScan,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisStringsScan,
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

    // Parsing the image only when a hunk was named: a data file that is not a
    // HUNK executable is a perfectly ordinary thing to scan, and refusing it
    // because it does not parse would answer a question nobody asked.
    let region: &[u8] = match request.hunk {
        None => source.bytes(),
        Some(index) => {
            let executable = match amiga_hunk::Executable::parse(source.bytes()) {
                Ok(executable) => executable,
                Err(error) => {
                    diagnostics.push(
                        Diagnostic::error(
                            DiagnosticCode::AnalysisHunkUnreadable,
                            error.to_string(),
                        )
                        .at("$.request.arguments.hunk"),
                    );
                    return outcome(Status::Error, diagnostics, None);
                }
            };
            match executable.segment(index) {
                Some(segment) => {
                    // Borrowed from the source, not the executable, so the
                    // parse can be dropped: the bytes are the same range.
                    let start = segment.file_offset;
                    let end = start.saturating_add(segment.bytes.len());
                    match source.bytes().get(start..end) {
                        Some(bytes) => bytes,
                        None => {
                            diagnostics.push(Diagnostic::error(
                                DiagnosticCode::AnalysisHunkUnreadable,
                                format!("hunk {index}'s bytes lie outside the source"),
                            ));
                            return outcome(Status::Error, diagnostics, None);
                        }
                    }
                }
                None => {
                    diagnostics.push(
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            format!("the image has no hunk {index}"),
                        )
                        .at("$.request.arguments.hunk"),
                    );
                    return outcome(Status::Error, diagnostics, None);
                }
            }
        }
    };

    let found = amiga_core::scan_strings(region, request.minimum_length);
    events.emit(OperationEvent::Progress {
        phase: "scan_strings",
        completed: region.len() as u64,
        total: Some(region.len() as u64),
    });

    // Filter first, cap second. The other order would report a total that
    // counted strings the filter would have excluded.
    let matching: Vec<&amiga_core::FoundString> = found
        .iter()
        .filter(|string| {
            request
                .contains
                .as_ref()
                .is_none_or(|needle| string.text.contains(needle.as_str()))
        })
        .collect();
    let total = matching.len();
    let truncated = total > request.maximum_strings;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{total} strings match; {} are reported",
                request.maximum_strings
            ),
        ));
    }

    let result = StringsScanResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        scanned_bytes: region.len() as u64,
        strings: matching
            .into_iter()
            .take(request.maximum_strings)
            .map(|string| FoundString {
                offset: string.offset as u64,
                text: string.text.clone(),
            })
            .collect(),
        string_total: total as u64,
        strings_truncated: truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisStringsScan(result)),
    )
}
