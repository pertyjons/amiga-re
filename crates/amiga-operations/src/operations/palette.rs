//! `graphics.palette.decode` and `graphics.palette.export` — read a run of
//! Amiga `$0RGB` colour words, and draw them as a swatch sheet.
//!
//! Nothing marks where a palette starts or how long it is, so both are the
//! caller's claim. A word whose high nibble is not zero is **counted, not
//! refused**: a table with one stray entry is still the table, and the count is
//! what tells a caller guessing at an offset whether the guess was good. Refusing
//! would throw away the answer along with the evidence.
//!
//! The result carries both encodings of every colour — the stored word and the
//! 8-bit triple it expands to — because deriving one from the other separately
//! in each frontend is how two of them end up showing different colours.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedMode, NormalizedPalette, NormalizedPaletteExport};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, PaletteExportResult, PaletteResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedPalette,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, decoded) = decode(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::GraphicsPaletteDecode,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: decoded.map(OperationResult::GraphicsPaletteDecode),
    }
}

pub(crate) fn export(
    request: &NormalizedPaletteExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::GraphicsPaletteExport,
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
            let mut diagnostics = diagnostics;
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, mut diagnostics, decoded) = decode(&request.decode, context, diagnostics, events);
    let Some(summary) = decoded else {
        return outcome(status, diagnostics, None);
    };

    let Some(image) =
        amiga_hw::palette::swatches(summary.colors_rgb4.len(), request.block, request.columns)
    else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::GraphicsOutputTooLarge,
                "the swatch geometry does not describe a drawable sheet",
            )
            .at("$.request.arguments.block"),
        );
        return outcome(Status::Error, diagnostics, None);
    };
    let palette: Vec<u8> = summary
        .colors_rgb8
        .iter()
        .flat_map(|color| color.iter().copied())
        .collect();
    let png = match amiga_hw::encode_indexed_png(&image, &palette, None) {
        Ok(png) => png,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::GraphicsEncodeFailed,
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
            size: png.len() as u64,
            sha256: amiga_core::sha256(&png),
        }],
        Vec::new(),
    );
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::GraphicsPaletteExport(
            PaletteExportResult {
                palette: summary.clone(),
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
                "the approved plan {approved} no longer describes this palette, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::GraphicsPaletteExport.as_str(),
        "source": { "size": summary.source.size, "sha256": summary.source.sha256 },
        "offset": summary.offset,
        "count": summary.colors_rgb4.len(),
        "invalid_words": summary.invalid_words,
        "colors_rgb4": summary
            .colors_rgb4
            .iter()
            .map(|word| format!("{word:#05x}"))
            .collect::<Vec<_>>(),
        "files": [{ "path": request.file_name, "sha256": amiga_core::sha256(&png) }],
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
            bytes: png,
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

fn decode(
    request: &NormalizedPalette,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> (Status, Vec<Diagnostic>, Option<PaletteResult>) {
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

    let bytes = source.bytes();
    // Two bytes per colour. The multiply is checked because `count` is the
    // caller's and the sum decides a slice bound.
    let Some(needed) = request.count.checked_mul(2) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "the palette length overflows",
            )
            .at("$.request.arguments.count"),
        );
        return (Status::Error, diagnostics, None);
    };
    let end = match request.offset.checked_add(needed) {
        Some(end) => end,
        None => {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::SourceRangeOutsideSource,
                    "the palette's offset plus its length overflows",
                )
                .at("$.request.arguments.offset"),
            );
            return (Status::Error, diagnostics, None);
        }
    };
    let Some(region) = bytes.get(request.offset..end) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "the palette [{}..{end}) lies outside the {}-byte source",
                    request.offset,
                    bytes.len()
                ),
            )
            .at("$.request.arguments.offset"),
        );
        return (Status::Error, diagnostics, None);
    };

    let colors_rgb4: Vec<u16> = region
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_be_bytes([word[0], word[1]]))
        .collect();
    let invalid = colors_rgb4
        .iter()
        .filter(|word| !amiga_hw::palette::is_rgb4(**word))
        .count();
    if invalid > 0 {
        // A count, not a refusal: the caller guessing at an offset needs it to
        // judge the guess, and a table with one stray entry is still the table.
        let diagnostic = Diagnostic::warning(
            DiagnosticCode::GraphicsPaletteWordInvalid,
            format!(
                "{invalid} of {} words are not $0RGB colours",
                colors_rgb4.len()
            ),
        );
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }
    events.emit(OperationEvent::Progress {
        phase: "read_palette",
        completed: colors_rgb4.len() as u64,
        total: Some(colors_rgb4.len() as u64),
    });

    let result = PaletteResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        offset: request.offset as u64,
        colors_rgb8: colors_rgb4
            .iter()
            .map(|word| amiga_hw::rgb4_to_rgb8(*word))
            .collect(),
        colors_rgb4,
        invalid_words: invalid as u64,
    };
    (Status::Success, diagnostics, Some(result))
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
