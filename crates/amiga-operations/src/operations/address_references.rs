//! `analysis.address.references` — what the code names, and what names an
//! address.
//!
//! Two modes because they are one question asked from either end. Without a
//! target it reports every address the instructions name; with one it reports
//! only the sites naming that address. A mode flag on one request beats two
//! operations that differ by an `Option`, and it is what stops the two from
//! being answered by different traversals — which is exactly what they were.
//!
//! Naming a target also brings in the image's relocations, because a stored
//! pointer is a reference too, and it is searched across the *whole* image
//! rather than the analyzed hunk: a pointer to this address is a reference to
//! it wherever it sits. Without a target there is nothing to match a relocation
//! against, and the full list is `analysis.hunk.list`'s answer already.
//!
//! A reference's target is reported in the frame its addressing mode uses — an
//! encoded absolute address, or a hunk offset for a PC-relative operand — and
//! the kind travels with it, because the two are not interchangeable and a
//! consumer that mixed them would compare an address against an offset.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedAddressReferences;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    AddressReferencesResult, CodeReference, HunkRelocation, OperationOutcome, OperationResult,
    ReferenceKind, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedAddressReferences,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisAddressReferences,
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
    let found = amiga_disasm::references(&analysis);
    events.emit(OperationEvent::Progress {
        phase: "collect_references",
        completed: found.len() as u64,
        total: Some(found.len() as u64),
    });

    // Filter before the cap, for the reason every filtered scan here does: a
    // total counting references the filter would have excluded would say more
    // exist than the question has answers.
    let matching: Vec<&amiga_disasm::Reference> = found
        .iter()
        .filter(|reference| {
            request
                .target
                .is_none_or(|target| reference.target == target)
        })
        .collect();
    let reference_total = matching.len();
    let references_truncated = reference_total > request.maximum_references;

    let relocation_hits: Vec<&amiga_hunk::Relocation> = match request.target {
        None => Vec::new(),
        Some(target) => hunk
            .executable
            .relocations
            .iter()
            .filter(|relocation| hunk.executable.stored_pointer(relocation) == Some(target))
            .collect(),
    };
    let relocation_total = relocation_hits.len();
    let relocations_truncated = relocation_total > request.maximum_references;

    if references_truncated || relocations_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "more than {} references match; each list reports its true total",
                request.maximum_references
            ),
        ));
    }

    let result = AddressReferencesResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        target: request.target,
        origin: request.origin,
        entries: request.entries.clone(),
        references: matching
            .into_iter()
            .take(request.maximum_references)
            .map(|reference| CodeReference {
                site: reference.site,
                kind: match reference.kind {
                    amiga_disasm::RefKind::Absolute => ReferenceKind::Absolute,
                    amiga_disasm::RefKind::AbsoluteShort => ReferenceKind::AbsoluteShort,
                    amiga_disasm::RefKind::PcRelative => ReferenceKind::PcRelative,
                },
                target: reference.target,
                target_address: match reference.kind {
                    // Either absolute operand already names a runtime address —
                    // the short one sign-extended, which is why the two kinds
                    // stay apart while this reading does not.
                    amiga_disasm::RefKind::Absolute | amiga_disasm::RefKind::AbsoluteShort => {
                        Some(reference.target)
                    }
                    amiga_disasm::RefKind::PcRelative => request
                        .origin
                        .and_then(|origin| origin.checked_add(reference.target)),
                },
            })
            .collect(),
        reference_total: reference_total as u64,
        references_truncated,
        relocations: relocation_hits
            .into_iter()
            .take(request.maximum_references)
            .map(|relocation| HunkRelocation {
                source_hunk: relocation.source_hunk,
                source_offset: relocation.source_offset,
                target_hunk: relocation.target_hunk,
                stored_offset: hunk.executable.stored_pointer(relocation),
            })
            .collect(),
        relocation_total: relocation_total as u64,
        relocations_truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisAddressReferences(result)),
    )
}
