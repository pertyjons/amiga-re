//! `graphics.bitmap.compare` — which pixels two images disagree about, and how.
//!
//! A digest over two framebuffers says they differ and nothing else. This says
//! how many pixels, inside what rectangle, in what connected regions, and
//! which palette index was substituted for which — and it answers separately in
//! **index space** and in **colour space**, because the two are different
//! questions. Two images can agree pixel for pixel and still look different,
//! which is a palette disagreement; and a port whose palette came out in a
//! different order differs in every pixel while being wholly correct, which the
//! substitution table is what shows.
//!
//! ## What is refused
//!
//! Differing dimensions, because a comparison that resampled one image to the
//! other would report the resampler's rounding as a difference in the picture.
//! An unpinned validity mask, because a mask decides what the comparison
//! *ignores*: an unpinned one could turn a failing comparison into a passing one
//! and leave nothing in the record to say it had.

use std::collections::BTreeMap;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{
    NormalizedBitmapCompare, NormalizedBitmapCompareExport, NormalizedComparedBitmap,
    NormalizedMode,
};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    BitmapCompareExportResult, BitmapCompareResult, DifferingRegion, IndexSubstitution,
    OperationOutcome, OperationResult, PixelBounds, PixelSourceComparison, SourcePin,
};

/// The colour a heatmap paints a differing pixel.
const DIFFERENT: [u8; 3] = [0xff, 0x00, 0x60];
/// The colour it paints a pixel the mask excluded.
const EXCLUDED: [u8; 3] = [0x30, 0x30, 0x30];

/// What one comparison produced: the result, and the two images an export
/// writes.
type Compared = (BitmapCompareResult, Vec<(String, Vec<u8>)>);

pub(crate) fn run(
    request: &NormalizedBitmapCompare,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::GraphicsBitmapCompare,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match compare(request, context, &mut diagnostics, events, "heatmap.png") {
        Ok((result, _)) => outcome(
            Status::Success,
            diagnostics,
            Some(OperationResult::GraphicsBitmapCompare(result)),
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

/// Read both images, compare the cropped rectangle, and render the two images
/// an export writes.
#[expect(
    clippy::too_many_lines,
    reason = "one comparison, told in order: read, walk, tally, render — splitting it would \
              hide which of the two spaces each tally belongs to"
)]
fn compare(
    request: &NormalizedBitmapCompare,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
    file_name: &str,
) -> Result<Compared, Diagnostic> {
    let (a_pin, a_indices) = indices(&request.a, request.maximum_input_bytes, context, "a")?;
    let (b_pin, b_indices) = indices(&request.b, request.maximum_input_bytes, context, "b")?;
    let source_planes = match (&request.a.pixel_sources, &request.b.pixel_sources) {
        (Some(a), Some(b)) => Some((
            pixel_sources(
                a,
                request.a.width,
                request.a.height,
                request.maximum_input_bytes,
                context,
                "a",
            )?,
            pixel_sources(
                b,
                request.b.width,
                request.b.height,
                request.maximum_input_bytes,
                context,
                "b",
            )?,
        )),
        _ => None,
    };
    let crop = request.crop;

    let mask = match &request.mask {
        None => None,
        Some(mask) => {
            let resolved = context
                .resolve_source(&mask.source, mask.maximum_input_bytes)
                .map_err(|error| {
                    Diagnostic::error(DiagnosticCode::SourceUnreadable, error.to_string())
                })?;
            if resolved.sha256() != mask.sha256 {
                return Err(Diagnostic::error(
                    DiagnosticCode::SourceDigestMismatch,
                    format!(
                        "the validity mask {} hashes to {}, not the pinned {}; a mask that \
                         changed under a comparison would silently change what it ignored",
                        mask.source.display_name(),
                        resolved.sha256(),
                        mask.sha256
                    ),
                )
                .at("$.request.arguments.mask.sha256"));
            }
            let needed = crop.width.saturating_mul(crop.height);
            let bytes = resolved
                .bytes()
                .get(mask.offset..mask.offset.saturating_add(needed))
                .ok_or_else(|| {
                    Diagnostic::error(
                        DiagnosticCode::SourceRangeOutsideSource,
                        format!(
                            "the validity mask holds {} bytes from offset {}, and the \
                             compared rectangle is {}x{} = {needed} pixels",
                            resolved.bytes().len().saturating_sub(mask.offset),
                            mask.offset,
                            crop.width,
                            crop.height
                        ),
                    )
                    .at("$.request.arguments.mask")
                })?
                .to_vec();
            Some(bytes)
        }
    };

    // Colour space is only a question when both sides say what their colours
    // are. With one palette and one bare index list, a pixel holding index 1
    // would compare `palette[1]` against the number 1 and differ for a reason
    // that is about the request rather than about the pictures — so the colour
    // answer mirrors the index answer, and says why.
    let compare_colours = !request.a.palette.is_empty() && !request.b.palette.is_empty();
    if !compare_colours && (!request.a.palette.is_empty() || !request.b.palette.is_empty()) {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::GraphicsPaletteWordInvalid,
            "only one side states a palette, so the two were compared in index space \
             alone: resolving one side's indices through a palette and the other's \
             through nothing would report a difference about the request rather than \
             about the pictures",
        ));
    }

    events.emit(OperationEvent::Progress {
        phase: "compare",
        completed: 0,
        total: Some((crop.width * crop.height) as u64),
    });

    let mut compared_pixels = 0_u64;
    let mut masked_pixels = 0_u64;
    let mut differing_pixels = 0_u64;
    let mut differing_colour_pixels = 0_u64;
    let mut differing_source_pixels = 0_u64;
    let mut substitutions: BTreeMap<(u8, u8), u64> = BTreeMap::new();
    let mut bounds: Option<(usize, usize, usize, usize)> = None;
    // One byte per compared pixel: 0 excluded, 1 same, 2 different. Used for the
    // connected-region walk and for the heatmap, so the two cannot disagree
    // about which pixels differed.
    let mut marks = vec![0_u8; crop.width * crop.height];

    for row in 0..crop.height {
        for column in 0..crop.width {
            let at = row * crop.width + column;
            if mask.as_ref().is_some_and(|mask| mask[at] == 0) {
                masked_pixels += 1;
                continue;
            }
            compared_pixels += 1;
            let left = sample(&a_indices, &request.a, crop.x + column, crop.y + row);
            let right = sample(&b_indices, &request.b, crop.x + column, crop.y + row);
            let same_index = left == right;
            if !same_index {
                differing_pixels += 1;
                marks[at] = 2;
                *substitutions
                    .entry((left.unwrap_or(0), right.unwrap_or(0)))
                    .or_default() += 1;
                bounds = Some(match bounds {
                    None => (column, row, column, row),
                    Some((x0, y0, x1, y1)) => {
                        (x0.min(column), y0.min(row), x1.max(column), y1.max(row))
                    }
                });
            } else {
                marks[at] = 1;
            }
            let differs_in_colour = if compare_colours {
                colour(&request.a, left) != colour(&request.b, right)
            } else {
                !same_index
            };
            if differs_in_colour {
                differing_colour_pixels += 1;
            }
            if let Some(((_, left_sources), (_, right_sources))) = &source_planes
                && sample(left_sources, &request.a, crop.x + column, crop.y + row)
                    != sample(right_sources, &request.b, crop.x + column, crop.y + row)
            {
                differing_source_pixels += 1;
            }
        }
    }

    let regions = connected_regions(&marks, crop.width, crop.height, (crop.x, crop.y));
    let regions_total = regions.len() as u64;
    let substitutions_total = substitutions.len() as u64;
    // Ordered by how much of the picture each explains, because that is what
    // separates a recoloured image from a redrawn one: a handful of
    // substitutions covering every differing pixel is a palette permutation.
    let mut ordered: Vec<IndexSubstitution> = substitutions
        .into_iter()
        .map(|((from, to), pixels)| IndexSubstitution { from, to, pixels })
        .collect();
    ordered.sort_by(|left, right| {
        right
            .pixels
            .cmp(&left.pixels)
            .then(left.from.cmp(&right.from))
            .then(left.to.cmp(&right.to))
    });
    let substitutions_truncated = ordered.len() > request.maximum_entries;
    ordered.truncate(request.maximum_entries);
    let mut ordered_regions = regions;
    ordered_regions.sort_by_key(|region| std::cmp::Reverse(region.pixels));
    let regions_truncated = ordered_regions.len() > request.maximum_entries;
    ordered_regions.truncate(request.maximum_entries);
    if substitutions_truncated || regions_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{substitutions_total} substitution(s) and {regions_total} region(s) were \
                 found; {} of each are reported",
                request.maximum_entries
            ),
        ));
    }

    let result = BitmapCompareResult {
        a: a_pin,
        b: b_pin,
        compared: PixelBounds {
            x: crop.x as u64,
            y: crop.y as u64,
            width: crop.width as u64,
            height: crop.height as u64,
        },
        compared_pixels,
        masked_pixels,
        identical: differing_pixels == 0,
        colours_identical: differing_colour_pixels == 0,
        // The finding a reader of a port most wants: the picture is the same and
        // only the palette moved.
        palette_only: differing_pixels == 0 && differing_colour_pixels > 0,
        differing_pixels,
        differing_colour_pixels,
        pixel_sources: source_planes.map(|((a, _), (b, _))| PixelSourceComparison {
            a,
            b,
            identical: differing_source_pixels == 0,
            differing_pixels: differing_source_pixels,
        }),
        // `bounds` is accumulated from `column`/`row`, which count from the
        // crop's own corner; `compared` above is in the image's coordinates.
        // The crop origin is what puts the two in one frame.
        differing_bounds: bounds.map(|(x0, y0, x1, y1)| PixelBounds {
            x: (crop.x + x0) as u64,
            y: (crop.y + y0) as u64,
            width: (x1 - x0 + 1) as u64,
            height: (y1 - y0 + 1) as u64,
        }),
        substitutions: ordered,
        substitutions_total,
        substitutions_truncated,
        regions: ordered_regions,
        regions_total,
        regions_truncated,
    };

    let heatmap = render_heatmap(&marks, crop.width, crop.height)?;
    let overlay = render_overlay(&marks, &a_indices, &request.a, crop)?;
    Ok((
        result,
        vec![
            (file_name.to_owned(), heatmap),
            (format!("{file_name}.overlay.png"), overlay),
        ],
    ))
}

/// Read and validate one raw source plane written by frame capture.
fn pixel_sources(
    source: &crate::normalize::NormalizedSource,
    width: usize,
    height: usize,
    maximum_input_bytes: u64,
    context: &ExecutionContext<'_>,
    side: &'static str,
) -> Result<(SourcePin, Vec<u8>), Diagnostic> {
    let resolved = context
        .resolve_source(source, maximum_input_bytes)
        .map_err(|error| Diagnostic::error(DiagnosticCode::SourceUnreadable, error.to_string()))?;
    let needed = width.saturating_mul(height);
    let bytes = resolved.bytes().get(..needed).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SourceRangeOutsideSource,
            format!(
                "pixel-source plane {side} holds {} bytes, but its {width}x{height} image \
                 needs {needed}",
                resolved.bytes().len()
            ),
        )
        .at(format!("$.request.arguments.{side}.pixel_sources"))
    })?;
    if let Some((offset, value)) = bytes
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| *byte > 8)
    {
        return Err(Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            format!(
                "pixel-source plane {side} has code {value} at byte {offset}; zero means \
                 playfield and 1-8 mean sprite channels 0-7"
            ),
        )
        .at(format!("$.request.arguments.{side}.pixel_sources")));
    }
    Ok((
        SourcePin {
            size: resolved.size(),
            sha256: resolved.sha256().to_owned(),
        },
        bytes.to_vec(),
    ))
}

/// One image's palette indices, one byte per pixel.
///
/// Planar sources are deinterleaved exactly as `graphics.bitmap.decode` does, so
/// the two operations cannot come to read one layout differently.
fn indices(
    bitmap: &NormalizedComparedBitmap,
    maximum_input_bytes: u64,
    context: &ExecutionContext<'_>,
    side: &'static str,
) -> Result<(SourcePin, Vec<u8>), Diagnostic> {
    let resolved = context
        .resolve_source(&bitmap.source, maximum_input_bytes)
        .map_err(|error| Diagnostic::error(DiagnosticCode::SourceUnreadable, error.to_string()))?;
    let pin = SourcePin {
        size: resolved.size(),
        sha256: resolved.sha256().to_owned(),
    };
    let bytes = resolved.bytes().get(bitmap.offset..).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::GraphicsOffsetOutsideSource,
            format!(
                "image {side} starts at offset {}, outside its {} bytes",
                bitmap.offset,
                resolved.bytes().len()
            ),
        )
        .at(format!("$.request.arguments.{side}.offset"))
    })?;
    let pixels = match bitmap.planes {
        Some(planes) => {
            amiga_hw::deinterleave(
                bytes,
                bitmap.width,
                bitmap.height,
                planes,
                plane_order(bitmap.plane_order),
            )
            .map_err(|error| {
                Diagnostic::error(DiagnosticCode::GraphicsPlanarUndecodable, error.to_string())
                    .at(format!("$.request.arguments.{side}"))
            })?
            .pixels
        }
        // Already one index per byte, which is what a decoded frame's indices
        // are. Short is a refusal rather than a black margin: a comparison that
        // padded would report the padding as agreement.
        None => bytes
            .get(..bitmap.width.saturating_mul(bitmap.height))
            .ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::GraphicsOffsetOutsideSource,
                    format!(
                        "image {side} is {}x{} = {} pixels and holds {} bytes from its \
                         offset; padding it would report the padding as agreement",
                        bitmap.width,
                        bitmap.height,
                        bitmap.width * bitmap.height,
                        bytes.len()
                    ),
                )
                .at(format!("$.request.arguments.{side}"))
            })?
            .to_vec(),
    };
    Ok((pin, pixels))
}

/// The index at `(x, y)` of the first image's coordinates, through this side's
/// alignment.
///
/// `None` when the alignment moves the sample outside the image, which is
/// compared as a difference rather than as a match: a pixel that is not there is
/// not the same as a pixel that agrees.
fn sample(pixels: &[u8], bitmap: &NormalizedComparedBitmap, x: usize, y: usize) -> Option<u8> {
    let x = i64::try_from(x).ok()? + i64::from(bitmap.align.0);
    let y = i64::try_from(y).ok()? + i64::from(bitmap.align.1);
    let x = usize::try_from(x).ok()?;
    let y = usize::try_from(y).ok()?;
    if x >= bitmap.width || y >= bitmap.height {
        return None;
    }
    pixels.get(y * bitmap.width + x).copied()
}

/// The colour one index resolves to on this side.
///
/// Only asked when both sides state a palette; an index the palette does not
/// reach resolves to black, which is what the hardware would show for a colour
/// register nothing wrote.
fn colour(bitmap: &NormalizedComparedBitmap, index: Option<u8>) -> Option<u16> {
    let index = index?;
    Some(
        bitmap
            .palette
            .get(usize::from(index))
            .copied()
            .unwrap_or_default(),
    )
}

const fn plane_order(order: crate::request::PlaneOrder) -> amiga_hw::PlaneOrder {
    match order {
        crate::request::PlaneOrder::Contiguous => amiga_hw::PlaneOrder::Contiguous,
        crate::request::PlaneOrder::Interleaved => amiga_hw::PlaneOrder::Interleaved,
        crate::request::PlaneOrder::ByteInterleaved => {
            amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Byte)
        }
        crate::request::PlaneOrder::WordInterleaved => {
            amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Word)
        }
        crate::request::PlaneOrder::LongwordInterleaved => {
            amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Longword)
        }
    }
}

/// Connected runs of differing pixels, four-connected.
///
/// Four rather than eight, because a diagonal touch is not a shared edge: two
/// sprites that meet at a corner are two findings, and merging them would report
/// one region a reader could not locate.
/// The walk is in the crop's own coordinates, because that is the shape `marks`
/// has; `origin` is the crop's position in the image, added where the bounds
/// become a reported rectangle so that every rectangle in the response is in one
/// frame — the image's, which is the frame a reader opens the image with.
fn connected_regions(
    marks: &[u8],
    width: usize,
    height: usize,
    origin: (usize, usize),
) -> Vec<DifferingRegion> {
    let mut seen = vec![false; marks.len()];
    let mut regions = Vec::new();
    let mut stack = Vec::new();
    for start in 0..marks.len() {
        if marks[start] != 2 || seen[start] {
            continue;
        }
        seen[start] = true;
        stack.push(start);
        let (mut x0, mut y0) = (width, height);
        let (mut x1, mut y1) = (0_usize, 0_usize);
        let mut pixels = 0_u64;
        while let Some(at) = stack.pop() {
            let (x, y) = (at % width, at / width);
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
            pixels += 1;
            let push = |next: usize, stack: &mut Vec<usize>, seen: &mut Vec<bool>| {
                if marks[next] == 2 && !seen[next] {
                    seen[next] = true;
                    stack.push(next);
                }
            };
            if x > 0 {
                push(at - 1, &mut stack, &mut seen);
            }
            if x + 1 < width {
                push(at + 1, &mut stack, &mut seen);
            }
            if y > 0 {
                push(at - width, &mut stack, &mut seen);
            }
            if y + 1 < height {
                push(at + width, &mut stack, &mut seen);
            }
        }
        regions.push(DifferingRegion {
            bounds: PixelBounds {
                x: (origin.0 + x0) as u64,
                y: (origin.1 + y0) as u64,
                width: (x1 - x0 + 1) as u64,
                height: (y1 - y0 + 1) as u64,
            },
            pixels,
        });
    }
    regions
}

/// A three-colour picture of what differed: black where the images agree, one
/// colour where they do not, and a third where the mask excluded the pixel.
///
/// The excluded pixels are painted rather than left black on purpose: a mask
/// that hid half the image would otherwise produce a heatmap indistinguishable
/// from a clean comparison.
fn render_heatmap(marks: &[u8], width: usize, height: usize) -> Result<Vec<u8>, Diagnostic> {
    let mut rgba = vec![0_u8; width * height * 4];
    for (at, mark) in marks.iter().enumerate() {
        let colour = match mark {
            2 => DIFFERENT,
            0 => EXCLUDED,
            _ => [0, 0, 0],
        };
        rgba[at * 4] = colour[0];
        rgba[at * 4 + 1] = colour[1];
        rgba[at * 4 + 2] = colour[2];
        rgba[at * 4 + 3] = 0xff;
    }
    amiga_hw::encode_rgba_png(width, height, &rgba)
        .map_err(|error| Diagnostic::error(DiagnosticCode::GraphicsEncodeFailed, error.to_string()))
}

/// The first image in its own colours, with the differing pixels painted over.
///
/// What a person actually looks at: a heatmap says *where*, and an overlay says
/// where **in the picture**, which is the difference between "row 118 differs"
/// and "the horizon differs".
fn render_overlay(
    marks: &[u8],
    pixels: &[u8],
    bitmap: &NormalizedComparedBitmap,
    crop: crate::request::PixelRect,
) -> Result<Vec<u8>, Diagnostic> {
    let mut rgba = vec![0_u8; crop.width * crop.height * 4];
    for row in 0..crop.height {
        for column in 0..crop.width {
            let at = row * crop.width + column;
            let colour = if marks[at] == 2 {
                DIFFERENT
            } else {
                let index = sample(pixels, bitmap, crop.x + column, crop.y + row);
                match colour(bitmap, index) {
                    Some(word) if !bitmap.palette.is_empty() => amiga_hw::rgb4_to_rgb8(word),
                    // No palette: the index itself as a grey, which is a
                    // rendering rather than a claim about colour — and is
                    // labelled as such by the record's own empty palette.
                    _ => {
                        let grey = index.unwrap_or(0);
                        [grey, grey, grey]
                    }
                }
            };
            rgba[at * 4] = colour[0];
            rgba[at * 4 + 1] = colour[1];
            rgba[at * 4 + 2] = colour[2];
            rgba[at * 4 + 3] = 0xff;
        }
    }
    amiga_hw::encode_rgba_png(crop.width, crop.height, &rgba)
        .map_err(|error| Diagnostic::error(DiagnosticCode::GraphicsEncodeFailed, error.to_string()))
}

pub(crate) fn export(
    request: &NormalizedBitmapCompareExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::GraphicsBitmapCompareExport,
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

    let (comparison, images) = match compare(
        &request.compare,
        context,
        &mut diagnostics,
        events,
        &request.file_name,
    ) {
        Ok(compared) => compared,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let files: Vec<PlannedOutput> = images
        .iter()
        .map(|(name, bytes)| PlannedOutput {
            path: name.clone(),
            size: bytes.len() as u64,
            sha256: amiga_core::sha256(bytes),
        })
        .collect();
    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::DirectoryContents,
        request.policy,
        files,
        Vec::new(),
    );
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::GraphicsBitmapCompareExport(
            BitmapCompareExportResult {
                comparison: comparison.clone(),
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
                "the approved plan {approved} no longer describes this comparison, which \
                 now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    // Both sides pinned, and the findings beside them: a heatmap is only
    // evidence next to which two images produced it.
    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::GraphicsBitmapCompareExport.as_str(),
        "a": { "size": comparison.a.size, "sha256": comparison.a.sha256 },
        "b": { "size": comparison.b.size, "sha256": comparison.b.sha256 },
        "compared": comparison.compared,
        "compared_pixels": comparison.compared_pixels,
        "masked_pixels": comparison.masked_pixels,
        "identical": comparison.identical,
        "colours_identical": comparison.colours_identical,
        "differing_pixels": comparison.differing_pixels,
        "differing_bounds": comparison.differing_bounds,
        "normalized_request_sha256": digest,
        "files": plan
            .files
            .iter()
            .map(|file| serde_json::json!({ "path": file.path, "sha256": file.sha256 }))
            .collect::<Vec<_>>(),
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
    let staged = images
        .into_iter()
        .map(|(name, bytes)| amiga_core::PlannedFile {
            path: std::path::PathBuf::from(name),
            bytes,
        })
        .collect();
    let write_plan = match amiga_core::ExtractionPlan::new(staged, Vec::new()) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let manifest_name = format!("{}.manifest.json", request.file_name);
    match write_plan.commit_into(
        &destination,
        request.policy.permits_replacement(),
        &manifest_name,
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
