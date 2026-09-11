//! `compress.powerpacker.*` and `compress.rle-xor.*` — decompress a packed
//! stream, and write what it decoded to.
//!
//! Split into a decode and an export for the same reason the sample and bitmap
//! pairs are: asking what a stream holds is a read, and writing a copy of it is
//! a separate authorization. Two codecs share one result shape because the
//! answer has the same shape either way — how many bytes came out, and what
//! their digest is — and the outcome's `operation` already names which was run.
//!
//! ## Why the recipe is never guessed
//!
//! Neither format is self-describing. A headerless PowerPacker stream stores its
//! four offset widths *outside* the data, and a position-XOR RLE stream may or
//! may not carry its marker and its size field inline. A wrong recipe does not
//! fail — it produces plausible bytes that are not the original. Both operations
//! therefore require the layout in the request, refuse a size field width the
//! format does not use, and report a declared size that disagrees with what came
//! out as a warning rather than swallowing it.
//!
//! ## Why the decode does not return the bytes
//!
//! A decoded level or bitmap is routinely megabytes. A frontend deciding whether
//! a recipe is right needs the shape and a digest, not the payload; the export
//! is what puts bytes anywhere. Returning them through a response envelope would
//! make the cheap question as expensive as the write.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{
    NormalizedMode, NormalizedPowerpacker, NormalizedPowerpackerExport, NormalizedRleXor,
    NormalizedRleXorExport,
};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{CompressDecodeResult, OperationOutcome, OperationResult, SourcePin};
use crate::source::SourceError;

/// What one decode produced: the summary that is reported, and the bytes an
/// export writes.
struct Decoded {
    summary: CompressDecodeResult,
    bytes: Vec<u8>,
}

pub(crate) fn powerpacker(
    request: &NormalizedPowerpacker,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, decoded) = decode_powerpacker(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::CompressPowerpackerDecode,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: decoded.map(|decoded| OperationResult::CompressDecode(decoded.summary)),
    }
}

pub(crate) fn rle_xor(
    request: &NormalizedRleXor,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, decoded) = decode_rle_xor(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::CompressRleXorDecode,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: decoded.map(|decoded| OperationResult::CompressDecode(decoded.summary)),
    }
}

pub(crate) fn powerpacker_export(
    request: &NormalizedPowerpackerExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    export(
        OperationName::CompressPowerpackerExport,
        &request.destination,
        &request.file_name,
        request.policy,
        mode,
        context,
        digest,
        |context, diagnostics, events| {
            decode_powerpacker(&request.decode, context, diagnostics, events)
        },
        events,
        diagnostics,
    )
}

pub(crate) fn rle_xor_export(
    request: &NormalizedRleXorExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    export(
        OperationName::CompressRleXorExport,
        &request.destination,
        &request.file_name,
        request.policy,
        mode,
        context,
        digest,
        |context, diagnostics, events| {
            decode_rle_xor(&request.decode, context, diagnostics, events)
        },
        events,
        diagnostics,
    )
}

/// Read the packed region both codecs start from.
///
/// Returns the bytes from `offset` onward, or the diagnostic that explains why
/// there are none: an offset past the end is a fact about the request, not a
/// failure of the codec, so it is refused before the codec is asked.
fn packed_region(
    source: &crate::source::ResolvedSource,
    offset: usize,
) -> Result<&[u8], Diagnostic> {
    let bytes = source.bytes();
    bytes.get(offset..).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SourceRangeOutsideSource,
            format!(
                "the packed stream starts at {offset} in a {}-byte source",
                bytes.len()
            ),
        )
        .at("$.request.arguments.offset")
    })
}

fn pin(source: &crate::source::ResolvedSource) -> SourcePin {
    SourcePin {
        size: source.size(),
        sha256: source.sha256().to_owned(),
    }
}

fn decode_powerpacker(
    request: &NormalizedPowerpacker,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> (Status, Vec<Diagnostic>, Option<Decoded>) {
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
    let region = match packed_region(&source, request.offset) {
        Ok(region) => region,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return (Status::Error, diagnostics, None);
        }
    };

    let maximum_output_bytes = usize::try_from(request.maximum_output_bytes).unwrap_or(usize::MAX);
    let bytes = match amiga_compress::decode_embedded_powerpacker_bounded(
        region,
        request.modes,
        maximum_output_bytes,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            let code = if matches!(
                error,
                amiga_compress::PowerPackerError::OutputLimitExceeded { .. }
            ) {
                DiagnosticCode::LimitExceeded
            } else {
                DiagnosticCode::CompressStreamUnreadable
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return (Status::Error, diagnostics, None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "decode_stream",
        completed: bytes.len() as u64,
        total: Some(bytes.len() as u64),
    });

    let summary = CompressDecodeResult {
        source: pin(&source),
        offset: request.offset as u64,
        packed_bytes: region.len() as u64,
        decoded_bytes: bytes.len() as u64,
        decoded_sha256: amiga_core::sha256(&bytes),
        declared_size: None,
    };
    (
        Status::Success,
        diagnostics,
        Some(Decoded { summary, bytes }),
    )
}

fn decode_rle_xor(
    request: &NormalizedRleXor,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> (Status, Vec<Diagnostic>, Option<Decoded>) {
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
    let region = match packed_region(&source, request.offset) {
        Ok(region) => region,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return (Status::Error, diagnostics, None);
        }
    };

    let maximum_output_bytes = usize::try_from(request.maximum_output_bytes).unwrap_or(usize::MAX);
    let decoded = match amiga_compress::decode_rle_xor_bounded(
        region,
        request.layout,
        maximum_output_bytes,
    ) {
        Ok(decoded) => decoded,
        Err(error) => {
            let code = if matches!(error, amiga_compress::RleXorError::OutputTooLarge { .. }) {
                DiagnosticCode::LimitExceeded
            } else {
                DiagnosticCode::CompressStreamUnreadable
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return (Status::Error, diagnostics, None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "decode_stream",
        completed: decoded.data.len() as u64,
        total: Some(decoded.data.len() as u64),
    });

    // A size field that disagrees with what came out is a fact about the stream
    // worth surfacing, and the decoded bytes are still the decoded bytes: the
    // field is a claim about them, not their definition.
    if let Some(declared) = decoded.declared_size
        && declared as usize != decoded.data.len()
    {
        let diagnostic = Diagnostic::warning(
            DiagnosticCode::CompressDeclaredSizeMismatch,
            format!(
                "the leading size field declares {declared} bytes and the stream decoded to {}",
                decoded.data.len()
            ),
        );
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }

    let summary = CompressDecodeResult {
        source: pin(&source),
        offset: request.offset as u64,
        packed_bytes: region.len() as u64,
        decoded_bytes: decoded.data.len() as u64,
        decoded_sha256: amiga_core::sha256(&decoded.data),
        declared_size: decoded.declared_size.map(u64::from),
    };
    (
        Status::Success,
        diagnostics,
        Some(Decoded {
            summary,
            bytes: decoded.data,
        }),
    )
}

/// The shared reviewed write both exports use.
///
/// One implementation, because the only thing that differs between them is
/// which decode produced the bytes. Two copies of a prepare/commit dance is how
/// two operations end up disagreeing about when a plan is stale.
#[expect(
    clippy::too_many_arguments,
    reason = "one shared write path parameterized by everything that differs between the two exports"
)]
fn export(
    operation: OperationName,
    destination_name: &crate::output::DestinationName,
    file_name: &str,
    policy: crate::output::OutputPolicy,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    digest: String,
    decode: impl FnOnce(
        &ExecutionContext<'_>,
        Vec<Diagnostic>,
        &mut BoundedSink<'_>,
    ) -> (Status, Vec<Diagnostic>, Option<Decoded>),
    events: &mut BoundedSink<'_>,
    diagnostics: Vec<Diagnostic>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(destination_name) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            let mut diagnostics = diagnostics;
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, mut diagnostics, decoded) = decode(context, diagnostics, events);
    let Some(decoded) = decoded else {
        return outcome(status, diagnostics, None);
    };

    let plan = WritePlan::new(
        destination_name,
        crate::output::DestinationKind::File,
        policy,
        vec![PlannedOutput {
            path: file_name.to_owned(),
            size: decoded.bytes.len() as u64,
            sha256: decoded.summary.decoded_sha256.clone(),
        }],
        Vec::new(),
    );
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::CompressExport(
            crate::response::CompressExportResult {
                decoded: decoded.summary.clone(),
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
                "the approved plan {approved} no longer describes this stream, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": operation.as_str(),
        "source": {
            "size": decoded.summary.source.size,
            "sha256": decoded.summary.source.sha256,
        },
        "offset": decoded.summary.offset,
        "packed_bytes": decoded.summary.packed_bytes,
        "decoded_bytes": decoded.summary.decoded_bytes,
        "declared_size": decoded.summary.declared_size,
        "files": [{
            "path": file_name,
            "sha256": decoded.summary.decoded_sha256,
        }],
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
            path: std::path::PathBuf::from(file_name),
            bytes: decoded.bytes.clone(),
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

    // One named file into a directory this toolkit does not own, exactly as the
    // sample and bitmap exports do: the policy governs that file and its
    // manifest, and nothing else in the directory is read, written, or removed.
    match write_plan.commit_file(
        &destination.join(file_name),
        policy.permits_replacement(),
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
