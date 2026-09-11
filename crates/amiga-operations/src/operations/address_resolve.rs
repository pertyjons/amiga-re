//! `analysis.address.resolve` — one number, read in every frame it could be in.
//!
//! A reverse engineer holds three coordinate systems at once: the address the
//! MC68000 sees, the offset within a hunk, and the position in the file on
//! disk. A number copied out of a listing, a debugger, or a hex editor carries
//! no record of which one it came from, and *that* is the question this answers.
//!
//! So every reading is reported rather than the one the caller meant. Answering
//! only the requested frame would assume what the caller is trying to find out,
//! and a wrong assumption here looks exactly like a right one: a plausible
//! address in the wrong frame is how a reader ends up annotating the wrong byte.
//!
//! Naming the result — the symbol at an address, the label of an offset — stays
//! in the frontend. Symbol tables are its configuration, not a fact about these
//! bytes.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::normalize::NormalizedAddressResolve;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    AddressFrames, AddressResolveResult, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedAddressResolve,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisAddressResolve,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    // The anchor is resolved first: without it two of the three readings still
    // have an answer, but a named image that cannot be read is a failure rather
    // than a reason to answer a narrower question than was asked.
    let mut pin = None;
    let mut hunk = None;
    let mut file_offset = None;
    let mut hunk_bytes = None;
    if let Some(anchor) = &request.anchor {
        let source = match context.resolve_source(&anchor.source, request.maximum_input_bytes) {
            Ok(source) => source,
            Err(error) => {
                let code = match error {
                    SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                    SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                    SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
                };
                diagnostics.push(
                    Diagnostic::error(code, error.to_string()).at("$.request.arguments.anchor"),
                );
                return outcome(Status::Error, diagnostics, None);
            }
        };
        let executable = match amiga_hunk::Executable::parse(source.bytes()) {
            Ok(executable) => executable,
            Err(error) => {
                diagnostics.push(
                    Diagnostic::error(DiagnosticCode::AnalysisHunkUnreadable, error.to_string())
                        .at("$.request.arguments.anchor.source"),
                );
                return outcome(Status::Error, diagnostics, None);
            }
        };
        let Some(segment) = executable.segment(anchor.hunk) else {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("the image has no hunk {}", anchor.hunk),
                )
                .at("$.request.arguments.anchor.hunk"),
            );
            return outcome(Status::Error, diagnostics, None);
        };
        pin = Some(SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        });
        hunk = Some(anchor.hunk);
        file_offset = Some(segment.file_offset as u64);
        hunk_bytes = Some(segment.bytes.len() as u64);
    }

    let value = request.value;
    let origin = request.origin;
    // A whole-file position exists only with an anchor. Whether it lands inside
    // the anchored hunk is a separate question, answered by `hunk_bytes` beside
    // it: the arithmetic is what was asked for, and refusing to report a
    // position just past the hunk would hide the near-miss that says the frame
    // was wrong.
    let whole_file = |hunk_relative: u32| -> Option<u64> {
        file_offset.and_then(|start| start.checked_add(u64::from(hunk_relative)))
    };

    // Read as a runtime address: below the mapped origin it is not an offset
    // into this hunk at all, which is a fact worth reporting rather than a
    // difference to compute anyway and get wrong.
    let from_absolute = value.checked_sub(origin);
    let as_absolute = AddressFrames {
        absolute: Some(value),
        hunk_relative: from_absolute,
        whole_file: from_absolute.and_then(whole_file),
    };

    let as_hunk_relative = AddressFrames {
        absolute: origin.checked_add(value),
        hunk_relative: Some(value),
        whole_file: whole_file(value),
    };

    let as_whole_file = file_offset.map(|start| {
        let from_file = u64::from(value)
            .checked_sub(start)
            .and_then(|offset| u32::try_from(offset).ok());
        AddressFrames {
            absolute: from_file.and_then(|offset| origin.checked_add(offset)),
            hunk_relative: from_file,
            whole_file: Some(u64::from(value)),
        }
    });

    let result = AddressResolveResult {
        source: pin,
        value,
        origin,
        hunk,
        hunk_file_offset: file_offset,
        hunk_bytes,
        as_absolute,
        as_hunk_relative,
        as_whole_file,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisAddressResolve(result)),
    )
}
