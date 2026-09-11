//! `analysis.code.fixed-point` — the arithmetic idioms an Amiga game is built
//! from.
//!
//! An MC68000 has no floating point, so a game's positions, velocities, and
//! angles are integers with an implied binary point. Recovering the Q scale is
//! what turns `MULS D1,D0 ; ASR #8,D0` from two instructions into a
//! multiplication of two 8.8 numbers — and getting it wrong makes every derived
//! value wrong by a power of two.
//!
//! So a shift by a register rather than an immediate reports *no* fractional
//! bit count. The scale is not statically known there, and a guess would be
//! indistinguishable from a fact in the response.
//!
//! Three lists, because they are three different observations: an idiom pairs
//! an operation with its normalizing shift, a clamp bounds a register, and a
//! scale records where a register acquires a known Q. A caller reading a
//! routine wants all three at the offsets they happen.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedCodeFixedPoint;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    ClampHint, ClampKind, CodeFixedPointResult, FixedPointHint, FixedPointKind, FixedPointScale,
    OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedCodeFixedPoint,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisCodeFixedPoint,
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
    let hunk = match super::code::locate(source.bytes(), request.hunk, &request.entries) {
        Ok(hunk) => hunk,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let analysis = hunk.analyze(&request.entries, request.origin);
    events.emit(OperationEvent::Progress {
        phase: "scan_fixed_point",
        completed: analysis.instructions.len() as u64,
        total: Some(analysis.instructions.len() as u64),
    });

    let hints = amiga_disasm::fixed_point_hints(&analysis);
    let clamps = amiga_disasm::clamp_hints(&analysis);
    let scales = amiga_disasm::fixed_point_scales(&analysis);

    let cap = request.maximum_hints;
    let (hint_total, clamp_total, scale_total) = (hints.len(), clamps.len(), scales.len());
    let truncated = hint_total > cap || clamp_total > cap || scale_total > cap;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!("more than {cap} hints were found; each list reports its true total"),
        ));
    }

    let result = CodeFixedPointResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        origin: request.origin,
        entries: request.entries.clone(),
        hints: hints
            .iter()
            .take(cap)
            .map(|hint| FixedPointHint {
                site: hint.site,
                shift_site: hint.shift_site,
                kind: match hint.kind {
                    amiga_disasm::FixedPointKind::ScaledMultiply => FixedPointKind::ScaledMultiply,
                    amiga_disasm::FixedPointKind::ScaledDivide => FixedPointKind::ScaledDivide,
                },
                register: hint.register,
                // Absent for a register-count shift, where the scale is not
                // statically known. A guessed Q reads exactly like a known one.
                fractional_bits: hint.fractional_bits,
            })
            .collect(),
        hint_total: hint_total as u64,
        clamps: clamps
            .iter()
            .take(cap)
            .map(|clamp| ClampHint {
                site: clamp.site,
                assign_site: clamp.assign_site,
                register: clamp.register,
                size: clamp.size,
                bound: clamp.bound,
                kind: match clamp.kind {
                    amiga_disasm::ClampKind::Lower => ClampKind::Lower,
                    amiga_disasm::ClampKind::Upper => ClampKind::Upper,
                },
            })
            .collect(),
        clamp_total: clamp_total as u64,
        scales: scales
            .iter()
            .take(cap)
            .map(|scale| FixedPointScale {
                site: scale.site,
                register: scale.register,
                fractional_bits: scale.fractional_bits,
            })
            .collect(),
        scale_total: scale_total as u64,
        truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisCodeFixedPoint(result)),
    )
}
