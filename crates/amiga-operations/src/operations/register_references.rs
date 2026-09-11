//! `hardware.register.references` — which instructions touch which chip
//! registers.
//!
//! Two kinds of knowledge meet here, and both belong in the answer. Which
//! instruction touches which register is analysis; what that register *is* —
//! its name, and the subsystem it belongs to — is hardware fact. Leaving the
//! second to whichever frontend renders the first is how two of them end up
//! disagreeing about whether `$09a` is an interrupt register.
//!
//! There is no subsystem filter. Unlike `analysis.strings.scan`'s `contains`,
//! narrowing here decides nothing about which accesses survive a cap: every
//! access names its subsystem, so filtering is a display choice over a list
//! that is already complete.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedRegisterReferences;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, RegisterAccessForm, RegisterReference,
    RegisterReferencesResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedRegisterReferences,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::HardwareRegisterReferences,
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
    let mut accesses = amiga_disasm::register_accesses(&analysis, amiga_hw::CUSTOM_BASE);
    // By register then site, so every access to one register groups together —
    // which is the order the question is asked in.
    accesses.sort_by_key(|access| (access.offset, access.site));
    events.emit(OperationEvent::Progress {
        phase: "collect_register_accesses",
        completed: accesses.len() as u64,
        total: Some(accesses.len() as u64),
    });

    let total = accesses.len();
    let truncated = total > request.maximum_accesses;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{total} register accesses were found; {} are reported",
                request.maximum_accesses
            ),
        ));
    }

    let result = RegisterReferencesResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        origin: request.origin,
        entries: request.entries.clone(),
        custom_base: amiga_hw::CUSTOM_BASE,
        accesses: accesses
            .iter()
            .take(request.maximum_accesses)
            .map(|access| RegisterReference {
                site: access.site,
                offset: access.offset,
                name: amiga_hw::register_name(access.offset),
                subsystem: amiga_hw::subsystem(access.offset),
                form: match access.form {
                    amiga_disasm::AccessForm::Absolute => RegisterAccessForm::Absolute,
                    amiga_disasm::AccessForm::BaseRelative => RegisterAccessForm::BaseRelative,
                },
                kind: super::code_globals::access_kind(access.kind),
            })
            .collect(),
        access_total: total as u64,
        accesses_truncated: truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::HardwareRegisterReferences(result)),
    )
}
