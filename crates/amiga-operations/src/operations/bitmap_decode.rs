//! `graphics.bitmap.decode` — read a planar region as palette indices.
//!
//! The result contains palette indices. Colour mapping, hidden planes, and transparency
//! presentation belong to the caller; the command line can convert these indices into a
//! PNG using a chosen palette.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedBitmapDecode;
use crate::protocol::Status;
use crate::request::{BitmapShape, BobMask, OperationName, PlaneOrder};
use crate::response::{BitmapDecodeResult, OperationOutcome, OperationResult, SourcePin};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedBitmapDecode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let failed = |diagnostics: Vec<Diagnostic>| OperationOutcome {
        operation: OperationName::GraphicsBitmapDecode,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result: None,
    };

    // The output bound is checked from the declared geometry, before the source
    // is opened and long before anything is allocated: the cost of a planar
    // decode is its output, and a few kilobytes of input can ask for gigabytes.
    let pixels = match output_pixels(request) {
        Ok(pixels) => pixels,
        Err(message) => {
            diagnostics.push(
                Diagnostic::error(DiagnosticCode::RequestArgumentOutOfRange, message)
                    .at("$.request.arguments"),
            );
            return failed(diagnostics);
        }
    };
    if pixels > request.maximum_output_pixels {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::GraphicsOutputTooLarge,
                format!(
                    "the requested geometry decodes to {pixels} pixels, above the \
                     {}-pixel limit",
                    request.maximum_output_pixels
                ),
            )
            .at("$.request.arguments"),
        );
        return failed(diagnostics);
    }

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return failed(diagnostics);
        }
    };

    let Some(data) = source.bytes().get(request.offset..) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::GraphicsOffsetOutsideSource,
                format!(
                    "offset {:#x} is past the end of a {}-byte source",
                    request.offset,
                    source.size()
                ),
            )
            .at("$.request.arguments.offset"),
        );
        return failed(diagnostics);
    };
    events.emit(OperationEvent::Progress {
        phase: "resolve_source",
        completed: source.size(),
        total: Some(source.size()),
    });

    let order = match request.plane_order {
        PlaneOrder::Contiguous => amiga_hw::PlaneOrder::Contiguous,
        PlaneOrder::Interleaved => amiga_hw::PlaneOrder::Interleaved,
        PlaneOrder::ByteInterleaved => {
            amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Byte)
        }
        PlaneOrder::WordInterleaved => {
            amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Word)
        }
        PlaneOrder::LongwordInterleaved => {
            amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Longword)
        }
    };
    let decoded = match request.shape {
        BitmapShape::Bitmap => amiga_hw::deinterleave_cancellable(
            data,
            request.width,
            request.height,
            request.planes,
            order,
            &context.cancel(),
        )
        .map(|image| (image, None)),
        BitmapShape::GlyphSheet => amiga_hw::GlyphSheet {
            glyph_width: request.width,
            glyph_height: request.height,
            planes: request.planes,
            order,
            count: request.glyph_count,
            columns: request.glyph_columns,
            gap: request.glyph_gap,
            separator: 0,
        }
        .render_cancellable(data, &context.cancel())
        .map(|image| (image, None)),
        BitmapShape::Bob => amiga_hw::Bob {
            width: request.width,
            height: request.height,
            planes: request.planes,
            order,
            mask: match request.bob_mask {
                BobMask::None => amiga_hw::BobMask::None,
                BobMask::Interleaved => amiga_hw::BobMask::Interleaved,
                BobMask::Separate { offset } => amiga_hw::BobMask::Separate { offset },
                BobMask::ColorKey { index } => amiga_hw::BobMask::ColorKey { index },
            },
        }
        .extract(data)
        .map(|bob| (bob.image, Some(bob.opaque))),
    };

    let (image, opaque) = match decoded {
        Ok(decoded) => decoded,
        // Cancellation is an outcome, not a failure: no result, and a status a
        // caller can tell apart from "the geometry was wrong".
        Err(amiga_hw::PlanarError::Cancelled) => {
            return OperationOutcome {
                operation: OperationName::GraphicsBitmapDecode,
                status: Status::Cancelled,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
        Err(error) => {
            diagnostics.push(
                Diagnostic::error(DiagnosticCode::GraphicsPlanarUndecodable, error.to_string())
                    .at("$.request.arguments"),
            );
            return failed(diagnostics);
        }
    };

    events.emit(OperationEvent::Progress {
        phase: "decode_planes",
        completed: image.pixels.len() as u64,
        total: Some(image.pixels.len() as u64),
    });

    OperationOutcome {
        operation: OperationName::GraphicsBitmapDecode,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::GraphicsBitmapDecode(BitmapDecodeResult {
            source: SourcePin {
                size: source.size(),
                sha256: source.sha256().to_owned(),
            },
            width: image.width,
            height: image.height,
            planes: image.planes,
            indices: image.pixels,
            opaque,
        })),
    }
}

/// How many pixels the declared geometry decodes to.
///
/// Computed with checked arithmetic from the request alone, so an overflowing
/// contact sheet is refused as a bad request rather than discovered as a failed
/// allocation.
fn output_pixels(request: &NormalizedBitmapDecode) -> Result<usize, String> {
    let overflow = || "the requested geometry overflows".to_owned();
    match request.shape {
        BitmapShape::Bitmap | BitmapShape::Bob => request
            .width
            .checked_mul(request.height)
            .ok_or_else(overflow),
        BitmapShape::GlyphSheet => {
            let columns = request.glyph_columns.min(request.glyph_count);
            let rows = request.glyph_count.div_ceil(request.glyph_columns.max(1));
            let extent = |count: usize, size: usize| {
                count
                    .checked_mul(size)
                    .and_then(|span| {
                        count
                            .saturating_sub(1)
                            .checked_mul(request.glyph_gap)
                            .and_then(|gaps| span.checked_add(gaps))
                    })
                    .ok_or_else(overflow)
            };
            let width = extent(columns, request.width)?;
            let height = extent(rows, request.height)?;
            width.checked_mul(height).ok_or_else(overflow)
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
