//! `analysis.code.globals` — where a program keeps its variables.
//!
//! Three conventions, reported together rather than selected by a mode. A
//! small-data program reaches its globals as displacements from A5; one copied
//! to a fixed address reaches them as absolute longs; and either may reach a
//! table through an address register it built. A caller *guessing* which
//! convention a binary follows wants to see which one actually appears, and
//! answering only the one they asked about would confirm the guess instead of
//! testing it.
//!
//! The derived pass is the exception: it propagates address registers through
//! straight-line code, which is work nobody should pay for unless they asked.
//!
//! Whether a stored constant points into the image is decided here, because it
//! needs the image's bounds — which the operation has and a frontend would have
//! to re-derive from the origin and the hunk length. The *grouping* of accesses
//! into slots stays in the frontend: one reader wants them by slot with counts,
//! another wants them in address order, and both are renderings of this list.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedCodeGlobals;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    AbsoluteGlobalAccess, BaseRelativeAccess, CodeGlobalsResult, DerivedGlobalAccess,
    DerivedTarget, GlobalAccessKind, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) const fn access_kind(kind: amiga_disasm::AccessKind) -> GlobalAccessKind {
    match kind {
        amiga_disasm::AccessKind::Read => GlobalAccessKind::Read,
        amiga_disasm::AccessKind::Write => GlobalAccessKind::Write,
        amiga_disasm::AccessKind::Modify => GlobalAccessKind::Modify,
        amiga_disasm::AccessKind::Address => GlobalAccessKind::Address,
        amiga_disasm::AccessKind::Other => GlobalAccessKind::Other,
    }
}

pub(crate) fn run(
    request: &NormalizedCodeGlobals,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisCodeGlobals,
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
        phase: "collect_globals",
        completed: analysis.instructions.len() as u64,
        total: Some(analysis.instructions.len() as u64),
    });

    // A written constant plausibly holds a pointer when it lands inside the
    // loaded image. Zero never does: it is the commonest constant in any
    // program and calling it a pointer would make almost every slot look like
    // one.
    let points_into_image = |value: Option<u32>| match value {
        None | Some(0) => false,
        Some(value) => match request.origin {
            Some(origin) => value
                .checked_sub(origin)
                .is_some_and(|offset| offset < hunk.hunk_bytes),
            None => value < hunk.hunk_bytes,
        },
    };

    let relative = amiga_disasm::global_accesses(&analysis, request.base_register, request.origin);
    // Absolute accesses are only identifiable against a place: "inside the
    // image" means nothing until the image has one. Without an origin the list
    // is empty rather than guessed at from offset zero.
    let absolute = match request.origin {
        None => Vec::new(),
        Some(origin) => amiga_disasm::absolute_accesses(&analysis, origin, hunk.hunk_bytes),
    };
    let derived = request.derived.then(|| {
        amiga_disasm::derived_accesses(
            &analysis,
            amiga_disasm::ValueOptions {
                image_origin: request.origin,
            },
        )
    });

    let cap = request.maximum_accesses;
    let base_relative_total = relative.len();
    let absolute_total = absolute.len();
    let derived_total = derived.as_ref().map_or(0, Vec::len);
    let truncated = base_relative_total > cap || absolute_total > cap || derived_total > cap;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!("more than {cap} accesses were found; each list reports its true total"),
        ));
    }

    let result = CodeGlobalsResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        origin: request.origin,
        entries: request.entries.clone(),
        base_register: request.base_register,
        hunk_bytes: u64::from(hunk.hunk_bytes),
        base_relative: relative
            .iter()
            .take(cap)
            .map(|access| BaseRelativeAccess {
                site: access.site,
                displacement: i32::from(access.offset),
                size: access.size,
                kind: access_kind(access.kind),
                value: access.value,
                library_base: access.library_base,
                value_points_into_image: points_into_image(access.value),
            })
            .collect(),
        base_relative_total: base_relative_total as u64,
        absolute: absolute
            .iter()
            .take(cap)
            .map(|access| AbsoluteGlobalAccess {
                site: access.site,
                address: access.address,
                offset: request
                    .origin
                    .and_then(|origin| access.address.checked_sub(origin)),
                size: access.size,
                kind: access_kind(access.kind),
                value: access.value,
                library_base: access.library_base,
                value_points_into_image: points_into_image(access.value),
            })
            .collect(),
        absolute_total: absolute_total as u64,
        derived: derived.map(|accesses| {
            accesses
                .iter()
                .take(cap)
                .map(|access| DerivedGlobalAccess {
                    site: access.site,
                    register: access.register,
                    target: match access.target {
                        amiga_disasm::DerivedTarget::Exact(address) => {
                            DerivedTarget::Exact { address }
                        }
                        amiga_disasm::DerivedTarget::Range { start, end } => {
                            DerivedTarget::Range { start, end }
                        }
                        amiga_disasm::DerivedTarget::Unknown => DerivedTarget::Unknown,
                    },
                    size: access.size,
                    kind: access_kind(access.kind),
                })
                .collect()
        }),
        derived_total: derived_total as u64,
        truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisCodeGlobals(result)),
    )
}
