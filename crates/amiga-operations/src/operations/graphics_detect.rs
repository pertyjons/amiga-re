//! `graphics.ilbm.decode` and `graphics.bitmap.detect` — what an image *is*,
//! before anything writes it out.
//!
//! The ILBM decode returns the form's description and not its pixels. The
//! indices are `graphics.bitmap.export`'s to write, and sending a megapixel
//! buffer back through a response envelope would make the cheap question — is
//! this the image I am looking for — as expensive as the export. It is the same
//! call `compress.*.decode` made about decoded bytes.
//!
//! HAM, HAM8 and Extra-Halfbrite stay refused by name, by the decoder this
//! calls. A decode that returned flat indices for those would describe an image
//! that looks plausible and is wrong, which is worse than saying no.
//!
//! Geometry detection derives width candidates here so callers can investigate bitmap
//! dimensions without repeating the arithmetic. Incorrect candidates would send a
//! reader looking for a bitmap that is not there.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedBitmapDetect, NormalizedIlbmDecode};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    BitmapDetectResult, EntropyBlock, GeometryCandidate, IlbmDecodeResult, IlbmMasking,
    OperationOutcome, OperationResult, RegionClass, SourcePin, StrideScore,
};
use crate::source::{ResolvedSource, SourceError};

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

fn refused(name: OperationName, diagnostics: Vec<Diagnostic>, digest: String) -> OperationOutcome {
    OperationOutcome {
        operation: name,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    }
}

pub(crate) fn ilbm(
    request: &NormalizedIlbmDecode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return refused(OperationName::GraphicsIlbmDecode, diagnostics, digest);
        }
    };

    let decoded = match amiga_iff::decode_ilbm(source.bytes()) {
        Ok(decoded) => decoded,
        Err(error) => {
            // HAM, HAM8 and EHB arrive here, refused by name. Precision is the
            // point: a decode that produced flat indices for them would look
            // plausible and be wrong.
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::GraphicsPlanarUndecodable,
                error.to_string(),
            ));
            return refused(OperationName::GraphicsIlbmDecode, diagnostics, digest);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "decode_ilbm",
        completed: source.size(),
        total: Some(source.size()),
    });

    // Tolerated inconsistencies become warning diagnostics rather than the
    // frontend's `eprintln!`: a caller reading the response should see what the
    // decode had to forgive.
    for warning in &decoded.warnings {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::GraphicsPlanarUndecodable,
            warning.message.clone(),
        ));
    }

    let result = IlbmDecodeResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        width: decoded.image.width as u32,
        height: decoded.image.height as u32,
        planes: decoded.image.planes,
        indexable_colours: 1_u64 << decoded.image.planes,
        masking: match decoded.masking {
            amiga_iff::Masking::None => IlbmMasking::None,
            amiga_iff::Masking::HasMask => IlbmMasking::MaskPlane,
            amiga_iff::Masking::HasTransparentColor => IlbmMasking::TransparentColour,
            amiga_iff::Masking::Lasso => IlbmMasking::Lasso,
        },
        transparent_colour: decoded.transparent_color,
        has_mask: decoded.mask.is_some(),
        viewport_mode: decoded.viewport_mode,
        aspect: [decoded.aspect.0, decoded.aspect.1],
        palette: decoded.palette,
    };
    OperationOutcome {
        operation: OperationName::GraphicsIlbmDecode,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::GraphicsIlbmDecode(result)),
    }
}

pub(crate) fn detect(
    request: &NormalizedBitmapDetect,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return refused(OperationName::GraphicsBitmapDetect, diagnostics, digest);
        }
    };

    let start = request.offset as usize;
    let region = match request.length {
        Some(length) => start
            .checked_add(length as usize)
            .and_then(|end| source.bytes().get(start..end)),
        None => source.bytes().get(start..),
    };
    let Some(region) = region else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                match request.length {
                    Some(length) => format!(
                        "region [{:#x}..+{length:#x}) is outside the {}-byte source",
                        request.offset,
                        source.size()
                    ),
                    None => format!(
                        "offset {:#x} is past the end of the {}-byte source",
                        request.offset,
                        source.size()
                    ),
                },
            )
            .at("$.request.arguments.offset"),
        );
        return refused(OperationName::GraphicsBitmapDetect, diagnostics, digest);
    };

    let mut blocks = amiga_hw::detect::entropy_map(region, request.block as usize);
    // The map scores the region, but a reader names bytes by their place in the
    // file. Shifting here means no frontend has to add the region start back on.
    for block in &mut blocks {
        block.offset = block.offset.wrapping_add(request.offset);
    }
    events.emit(OperationEvent::Progress {
        phase: "entropy_map",
        completed: region.len() as u64,
        total: Some(region.len() as u64),
    });

    // Only over a bounded region. Autocorrelation over an unbounded tail
    // measures whatever follows the bitmap as much as the bitmap, so it is not
    // run rather than run and disclaimed.
    let scores = match request.length {
        None => Vec::new(),
        Some(_) => amiga_hw::detect::autocorrelate(region, 1, request.maximum_stride),
    };
    let geometry = scores
        .first()
        .map(|best| amiga_hw::detect::geometry_candidates(best.stride))
        .unwrap_or_default();

    let block_total = blocks.len();
    let stride_total = scores.len();
    let blocks_truncated = block_total > request.maximum_blocks;
    let strides_truncated = stride_total > request.maximum_strides;
    if blocks_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultRegionsTruncated,
            format!(
                "the region scores {block_total} blocks; {} are reported",
                request.maximum_blocks
            ),
        ));
    }
    if strides_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{stride_total} strides were scored; {} are reported",
                request.maximum_strides
            ),
        ));
    }

    let result = BitmapDetectResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        offset: request.offset,
        length: region.len() as u64,
        block: request.block,
        blocks: blocks
            .iter()
            .take(request.maximum_blocks)
            .map(|block| EntropyBlock {
                offset: block.offset,
                length: block.len as u64,
                entropy: block.entropy,
                class: match block.class {
                    amiga_hw::RegionClass::Sparse => RegionClass::Sparse,
                    amiga_hw::RegionClass::CodeOrBitmap => RegionClass::CodeOrBitmap,
                    amiga_hw::RegionClass::Packed => RegionClass::Packed,
                },
            })
            .collect(),
        block_total: block_total as u64,
        blocks_truncated,
        strides: scores
            .iter()
            .take(request.maximum_strides)
            .map(|score| StrideScore {
                stride: score.stride,
                score: score.score,
            })
            .collect(),
        stride_total: stride_total as u64,
        strides_truncated,
        // Derived from the best stride whether or not it survived the cap: the
        // candidate widths are the answer someone is actually after.
        geometry: geometry
            .into_iter()
            .map(|(planes, width)| GeometryCandidate {
                planes,
                width: width as u64,
            })
            .collect(),
    };
    OperationOutcome {
        operation: OperationName::GraphicsBitmapDetect,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::GraphicsBitmapDetect(result)),
    }
}
