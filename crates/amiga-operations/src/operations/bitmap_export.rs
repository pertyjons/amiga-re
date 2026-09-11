//! `graphics.bitmap.export` — write a decoded planar region as an indexed PNG.
//!
//! The second `prepared_output` operation, and deliberately built as a
//! composition rather than a copy: it normalizes to the same
//! [`NormalizedBitmapDecode`] the decode operation uses, runs the same handler
//! logic through [`super::bitmap_decode`], and only then adds a palette and an
//! encoder. Two ways to decode the same planar bytes would eventually disagree.
//!
//! The palette is what this operation adds over the decode. A decode stops at
//! indices because colors are separate knowledge; an *export* has to commit to
//! some, so it takes them explicitly or falls back to a documented grayscale
//! ramp — and records which it used in the plan, since a different palette is a
//! different PNG and must therefore be a different plan digest.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedBitmapExport, NormalizedMode};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{BitmapExportResult, OperationOutcome, OperationResult, SourcePin};

pub(crate) fn run(
    request: &NormalizedBitmapExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::GraphicsBitmapExport,
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

    // The decode is the decode operation's, run through its handler rather than
    // reimplemented: one set of bounds, one set of diagnostics, one answer.
    let decoded = super::bitmap_decode::run(
        &request.decode,
        context,
        diagnostics.clone(),
        digest.clone(),
        events,
    );
    let image = match decoded.status {
        Status::Success => match decoded.graphics_bitmap_decode() {
            Some(image) => image.clone(),
            None => {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::GraphicsPlanarUndecodable,
                    "the decode succeeded without producing an image".to_owned(),
                ));
                return outcome(Status::Error, diagnostics, None);
            }
        },
        // Every way the decode can fail is already a decided status with decided
        // diagnostics; carrying them through unchanged is what keeps
        // `graphics.bitmap.export` and `graphics.bitmap.decode` telling the same
        // story about the same bytes.
        status => return outcome(status, decoded.diagnostics, None),
    };

    let color_count = 1_usize << u32::from(image.planes);
    let palette = match &request.palette {
        Some(colors) if colors.len() < color_count => {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!(
                        "the palette has {} colors but {} planes address {color_count}",
                        colors.len(),
                        image.planes
                    ),
                )
                .at("$.request.arguments.palette"),
            );
            return outcome(Status::Error, diagnostics, None);
        }
        Some(colors) => colors[..color_count].to_vec(),
        // A documented ramp rather than an arbitrary one: an export with no
        // palette is still legible, and the plan records that this is what it
        // used.
        None => grayscale(color_count),
    };

    let rgb: Vec<u8> = palette
        .iter()
        .flat_map(|color| amiga_hw::rgb4_to_rgb8(*color))
        .collect();
    let indexed = amiga_hw::IndexedImage {
        width: image.width,
        height: image.height,
        planes: image.planes,
        pixels: image.indices.clone(),
    };
    // A bob's mask becomes PNG transparency, which is the only place the two
    // shapes differ once the pixels exist.
    let alpha: Option<Vec<u8>> = None;
    let png = match amiga_hw::encode_indexed_png(&indexed, &rgb, alpha.as_deref()) {
        Ok(png) => png,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::GraphicsEncodeFailed,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "encode_png",
        completed: png.len() as u64,
        total: Some(png.len() as u64),
    });

    let file_name = request.file_name.clone();
    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::File,
        request.policy,
        vec![PlannedOutput {
            path: file_name.clone(),
            size: png.len() as u64,
            sha256: amiga_core::sha256(&png),
        }],
        Vec::new(),
    );
    let pin = SourcePin {
        size: image.source.size,
        sha256: image.source.sha256.clone(),
    };
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::GraphicsBitmapExport(BitmapExportResult {
            source: pin.clone(),
            width: image.width,
            height: image.height,
            palette: palette.clone(),
            plan,
            committed,
        }))
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
                "the approved plan {approved} no longer describes this export, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "source": { "size": pin.size, "sha256": pin.sha256 },
        "width": image.width,
        "height": image.height,
        "planes": image.planes,
        "palette": palette,
        "files": [{ "path": file_name, "sha256": amiga_core::sha256(&png) }],
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::GraphicsEncodeFailed,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let write_plan = match amiga_core::ExtractionPlan::new(
        vec![amiga_core::PlannedFile {
            path: std::path::PathBuf::from(&file_name),
            bytes: png,
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

    // A single named file into a directory this toolkit does not own: the policy
    // governs that file and its manifest, and nothing else in the directory is
    // read, written, or removed. Owning the directory — which is what `commit`
    // does — would refuse an ordinary output path for existing, and make
    // `create_only` mean "only into an empty folder".
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
            outcome(Status::Conflict, diagnostics, None)
        }
    }
}

/// An evenly spaced gray ramp over `count` entries, as RGB4.
///
/// The fallback when a request supplies no palette. Documented rather than
/// arbitrary so that an export with no colors is reproducible: the same request
/// always produces the same PNG, which is what makes the plan digest mean
/// anything.
fn grayscale(count: usize) -> Vec<u16> {
    (0..count)
        .map(|index| {
            let level = if count <= 1 {
                0
            } else {
                (index * 15 / (count - 1)) as u16
            };
            (level << 8) | (level << 4) | level
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grayscale_ramp_spans_black_to_white() {
        let ramp = grayscale(4);
        assert_eq!(ramp.len(), 4);
        assert_eq!(ramp[0], 0x000, "the first entry is black");
        assert_eq!(ramp[3], 0xfff, "the last entry is white");
        // Monotonic, so a higher index is never darker.
        assert!(ramp.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn a_single_entry_ramp_does_not_divide_by_zero() {
        assert_eq!(grayscale(1), vec![0]);
    }
}
