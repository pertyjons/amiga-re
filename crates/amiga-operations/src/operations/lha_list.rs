//! `container.lha.list` — what an LHA archive says it holds.
//!
//! This existed as an asymmetry rather than a gap: `container.lha.extract` has
//! been in the catalog since the operation API landed, so the archive one
//! command could extract was one the other could only describe outside the
//! vocabulary. A caller could ask for the write and not for the question that
//! decides whether to make it.
//!
//! The method id is reported verbatim rather than mapped to
//! supported/unsupported. A caller deciding whether an extraction will work
//! needs to know *which* method, and `-lh2-` staying an honest name is what
//! keeps the extractor's refusal precise rather than a shrug.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedLhaList;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{LhaListResult, LhaMember, OperationOutcome, OperationResult, SourcePin};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedLhaList,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::ContainerLhaList,
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

    let archive = match amiga_lha::Archive::parse(source.bytes()) {
        Ok(archive) => archive,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ContainerUnreadable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let entries = archive.entries();
    events.emit(OperationEvent::Progress {
        phase: "parse_members",
        completed: entries.len() as u64,
        total: Some(entries.len() as u64),
    });

    let total = entries.len();
    let truncated = total > request.maximum_members;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the archive holds {total} members; {} are reported",
                request.maximum_members
            ),
        ));
    }

    let result = LhaListResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        members: entries
            .iter()
            .take(request.maximum_members)
            .map(|entry| LhaMember {
                name: entry.name().to_owned(),
                method: entry.method_str(),
                compressed_size: u64::from(entry.compressed_size()),
                original_size: u64::from(entry.original_size()),
                crc16: entry.crc16(),
                header_level: entry.header_level(),
                directory: entry.is_directory(),
            })
            .collect(),
        member_total: total as u64,
        members_truncated: truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::ContainerLhaList(result)),
    )
}
