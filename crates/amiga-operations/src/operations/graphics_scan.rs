//! `graphics.palette.scan`, `hardware.copper.scan`, and
//! `hardware.copper.decode` — finding display data in bytes that declare
//! nothing.
//!
//! All three are searches for structure a file does not announce, so all three
//! echo the criteria that found it: the palette scan its run length, the Copper
//! decode its offset. A candidate whose criteria are invisible can be neither
//! judged nor reproduced, which is the same rule `analysis.pointers.scan` and
//! `audio.pcm.scan` follow.
//!
//! Colours travel in both encodings — the `$0RGB` word the hardware holds and
//! the 8-bit-per-channel expansion a display needs. Deriving one from the other
//! separately in each frontend is how two of them end up showing different
//! colours, which is why `graphics.palette.decode` already reports both.
//!
//! Register *names* are in the answer rather than in whichever frontend renders
//! it. That is the call `env.boot.trace` made and for the same reason: a name is
//! hardware knowledge, not configuration.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedCopperDecode, NormalizedCopperScan, NormalizedPaletteScan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    CopperBitplanePointer, CopperDecodeResult, CopperInstruction, CopperListSummary, CopperOp,
    CopperPalette, CopperScanResult, OperationOutcome, OperationResult, PaletteScanResult,
    PaletteTable, SourcePin,
};
use crate::source::{ResolvedSource, SourceError};

/// Resolve the source, returning the diagnostic to report rather than pushing
/// it, so each scan keeps its own outcome shape.
fn resolve(
    source: &crate::normalize::NormalizedSource,
    maximum_input_bytes: u64,
    context: &ExecutionContext<'_>,
) -> Result<ResolvedSource, Diagnostic> {
    context
        .resolve_source(source, maximum_input_bytes)
        .map_err(|error| {
            let code = match error {
                SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
            };
            Diagnostic::error(code, error.to_string())
        })
}

/// One decoded instruction in the response's vocabulary.
///
/// Shared with `hardware.copper.references`, which decodes the same streams —
/// two mappings of one decoder's output is how two operations end up naming the
/// same register differently.
pub(crate) fn as_response_instruction(
    instruction: &amiga_hw::CopperInstruction,
) -> CopperInstruction {
    CopperInstruction {
        offset: instruction.offset,
        op: as_response_op(instruction),
    }
}

pub(crate) fn as_response_op(instruction: &amiga_hw::CopperInstruction) -> CopperOp {
    match instruction.op {
        amiga_hw::CopperOp::Move { register, value } => CopperOp::Move {
            register,
            value,
            name: amiga_hw::register_name(register),
            // Only for a colour register: expanding an arbitrary write would
            // claim every `MOVE` writes a colour.
            rgb8: amiga_hw::is_color_register(register)
                .then(|| amiga_hw::rgb4_to_rgb8(value & 0x0fff)),
        },
        amiga_hw::CopperOp::Wait {
            vpos,
            hpos,
            vmask,
            hmask,
            blitter_finish_disable,
        } => CopperOp::Wait {
            vpos,
            hpos,
            vmask,
            hmask,
            blitter_finish_disable,
            terminator: instruction.is_terminator(),
        },
        amiga_hw::CopperOp::Skip {
            vpos,
            hpos,
            vmask,
            hmask,
            blitter_finish_disable,
        } => CopperOp::Skip {
            vpos,
            hpos,
            vmask,
            hmask,
            blitter_finish_disable,
        },
    }
}

fn refused(name: OperationName, diagnostics: Vec<Diagnostic>, digest: String) -> OperationOutcome {
    OperationOutcome {
        operation: name,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    }
}

pub(crate) fn palette(
    request: &NormalizedPaletteScan,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return refused(OperationName::GraphicsPaletteScan, diagnostics, digest);
        }
    };

    let found = amiga_hw::palette::scan(source.bytes(), request.minimum_colours);
    events.emit(OperationEvent::Progress {
        phase: "scan_palettes",
        completed: source.size(),
        total: Some(source.size()),
    });

    let total = found.len();
    let truncated = total > request.maximum_tables;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{total} palette tables were found; {} are reported",
                request.maximum_tables
            ),
        ));
    }

    let result = PaletteScanResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        minimum_colours: request.minimum_colours as u64,
        tables: found
            .iter()
            .take(request.maximum_tables)
            .map(|table| PaletteTable {
                offset: table.offset,
                rgb12: table.colors.clone(),
                rgb8: table.rgb8(),
            })
            .collect(),
        table_total: total as u64,
        tables_truncated: truncated,
    };
    OperationOutcome {
        operation: OperationName::GraphicsPaletteScan,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::GraphicsPaletteScan(result)),
    }
}

pub(crate) fn copper_scan(
    request: &NormalizedCopperScan,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return refused(OperationName::HardwareCopperScan, diagnostics, digest);
        }
    };

    let found = amiga_hw::scan(source.bytes());
    events.emit(OperationEvent::Progress {
        phase: "scan_copper",
        completed: source.size(),
        total: Some(source.size()),
    });

    let total = found.len();
    let truncated = total > request.maximum_lists;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{total} Copper lists were found; {} are reported",
                request.maximum_lists
            ),
        ));
    }

    let result = CopperScanResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        lists: found
            .iter()
            .take(request.maximum_lists)
            .map(|list| CopperListSummary {
                start: list.start,
                end: list.end,
                instruction_count: list.instruction_count as u64,
                palettes: list
                    .palettes
                    .iter()
                    .map(|palette| CopperPalette {
                        start_offset: palette.start_offset,
                        first_colour: palette.first_color,
                        rgb12: palette.rgb12.clone(),
                        rgb8: palette.rgb8.clone(),
                    })
                    .collect(),
                bitplane_pointers: list
                    .bitplane_pointers
                    .iter()
                    .map(|pointer| CopperBitplanePointer {
                        plane: pointer.plane,
                        high_offset: pointer.high_offset,
                        low_offset: pointer.low_offset,
                        address: pointer.address,
                        points_inside_image: pointer.points_inside_image,
                    })
                    .collect(),
            })
            .collect(),
        list_total: total as u64,
        lists_truncated: truncated,
    };
    OperationOutcome {
        operation: OperationName::HardwareCopperScan,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::HardwareCopperScan(result)),
    }
}

pub(crate) fn copper_decode(
    request: &NormalizedCopperDecode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return refused(OperationName::HardwareCopperDecode, diagnostics, digest);
        }
    };
    if u64::from(request.offset) > source.size() {
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
        return refused(OperationName::HardwareCopperDecode, diagnostics, digest);
    }

    let found = amiga_hw::copper::decode(source.bytes(), request.offset as usize);
    events.emit(OperationEvent::Progress {
        phase: "decode_copper",
        completed: found.len() as u64,
        total: Some(found.len() as u64),
    });

    let total = found.len();
    let truncated = total > request.maximum_instructions;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{total} instructions decoded; {} are reported",
                request.maximum_instructions
            ),
        ));
    }

    let result = CopperDecodeResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        offset: request.offset,
        instructions: found
            .iter()
            .take(request.maximum_instructions)
            .map(as_response_instruction)
            .collect(),
        instruction_total: total as u64,
        instructions_truncated: truncated,
    };
    OperationOutcome {
        operation: OperationName::HardwareCopperDecode,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::HardwareCopperDecode(result)),
    }
}
