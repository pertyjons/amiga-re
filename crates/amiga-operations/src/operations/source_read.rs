//! `source.read` — a window of bytes, so no command fetches its own data.
//!
//! The smallest operation in the catalog, and the one that closes the boundary:
//! `dump` renders a hex-and-ASCII view, and the columns, the address frame, and
//! the relocation marking are display — but the bytes under them are not the
//! frontend's to go and get.
//!
//! Naming a hunk does one thing a raw file read cannot: it reports which
//! offsets inside the window a relocation sits at. That is what makes a hex
//! view of code readable rather than a wall of digits, and it is a fact about
//! the image rather than a rendering choice.
//!
//! A window that runs past the end is reported *short* rather than refused. A
//! reader looking at the tail of a file is asking an ordinary question, and
//! refusing it would make the last screen of every file unviewable.

use std::fmt::Write as _;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedSourceRead;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{OperationOutcome, OperationResult, SourcePin, SourceReadResult};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedSourceRead,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::SourceRead,
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

    // Parsing the image only when a hunk was named: a data file is an ordinary
    // thing to look at, and refusing it because it does not parse would answer
    // a question nobody asked.
    let (region, relocation_sites) = match request.hunk {
        None => {
            let Some(region) = source.bytes().get(request.offset as usize..) else {
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::SourceRangeOutsideSource,
                        format!(
                            "offset {:#x} is past the end of the {}-byte source",
                            request.offset,
                            source.size()
                        ),
                    )
                    .at("$.request.arguments.offset"),
                );
                return outcome(Status::Error, diagnostics, None);
            };
            (region, Vec::new())
        }
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
            let Some(segment) = executable.segment(index) else {
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!("the image has no hunk {index}"),
                    )
                    .at("$.request.arguments.hunk"),
                );
                return outcome(Status::Error, diagnostics, None);
            };
            let Some(region) = segment.bytes.get(request.offset as usize..) else {
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::SourceRangeOutsideSource,
                        format!(
                            "offset {:#x} is past the end of hunk {index}'s {} bytes",
                            request.offset,
                            segment.bytes.len()
                        ),
                    )
                    .at("$.request.arguments.offset"),
                );
                return outcome(Status::Error, diagnostics, None);
            };
            let end = request.offset.saturating_add(request.length);
            let window = request.offset..end;
            let sites: Vec<u32> = executable
                .relocations
                .iter()
                .filter(|relocation| {
                    relocation.source_hunk == index && window.contains(&relocation.source_offset)
                })
                .map(|relocation| relocation.source_offset - request.offset)
                .collect();
            (region, sites)
        }
    };

    // Short rather than refused: the tail of a file is an ordinary place to
    // look, and a window clipped there is what the source holds.
    let bytes = &region[..region.len().min(request.length as usize)];
    if bytes.len() < request.length as usize {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultRegionsTruncated,
            format!(
                "the window asked for {} bytes; the source holds {} from that offset",
                request.length,
                bytes.len()
            ),
        ));
    }
    events.emit(OperationEvent::Progress {
        phase: "read_window",
        completed: bytes.len() as u64,
        total: Some(bytes.len() as u64),
    });

    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    let result = SourceReadResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        offset: request.offset,
        length: bytes.len() as u64,
        bytes: hex,
        relocation_sites,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::SourceRead(result)),
    )
}
