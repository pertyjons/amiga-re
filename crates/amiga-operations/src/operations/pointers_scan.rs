//! `analysis.pointers.scan` — runs of numbers that look like they address this
//! hunk.
//!
//! Nothing in an image marks a jump table, so a table is found by the only
//! evidence there is: consecutive entries that all decode to addresses inside
//! the hunk. That makes every table a *candidate*, and the request's origin and
//! minimum run length are the claim being tested. Both travel back in the
//! result, because a candidate whose criteria are not visible cannot be judged.
//!
//! Entry offsets are derived from the complete target set here so a caller can seed
//! control-flow analysis without accidentally using only a capped display list.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedPointerScan;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, PointerEncoding, PointerScanResult, PointerTable, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedPointerScan,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisPointersScan,
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

    let executable = match amiga_hunk::Executable::parse(source.bytes()) {
        Ok(executable) => executable,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AnalysisHunkUnreadable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let Some(segment) = executable.segment(request.hunk) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("the image has no hunk {}", request.hunk),
            )
            .at("$.request.arguments.hunk"),
        );
        return outcome(Status::Error, diagnostics, None);
    };

    let Ok(hunk_bytes) = u32::try_from(segment.bytes.len()) else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::AnalysisHunkUnreadable,
            format!(
                "hunk {} holds {} bytes, more than an address can span",
                request.hunk,
                segment.bytes.len()
            ),
        ));
        return outcome(Status::Error, diagnostics, None);
    };
    // The target window is what makes a number "plausible", so an origin that
    // puts the end of the hunk past the end of the address space is refused
    // rather than clamped: a clamped window would silently accept fewer targets
    // than the request describes.
    let Some(target_end) = request.origin.checked_add(hunk_bytes) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "hunk {} mapped at {:#x} runs past the end of the address space",
                    request.hunk, request.origin
                ),
            )
            .at("$.request.arguments.origin"),
        );
        return outcome(Status::Error, diagnostics, None);
    };

    let encoding = request
        .word_scale
        .map_or(amiga_core::pointers::PointerEncoding::Long, |scale| {
            amiga_core::pointers::PointerEncoding::ScaledWord(scale)
        });
    let found = amiga_core::pointers::scan(
        segment.bytes,
        request.origin,
        target_end,
        request.origin,
        encoding,
        request.minimum_entries,
    );
    events.emit(OperationEvent::Progress {
        phase: "scan_pointers",
        completed: segment.bytes.len() as u64,
        total: Some(segment.bytes.len() as u64),
    });

    // Derived from every table found, before either cap: the seeds a caller
    // analyzes from must not depend on how much of the answer fit in the
    // response. Odd targets are dropped because an MC68000 cannot fetch an
    // instruction from one — a table of odd targets is data, not code.
    let mut entries = std::collections::BTreeSet::new();
    for table in &found {
        for target in &table.targets {
            if let Some(offset) = target.checked_sub(request.origin)
                && offset < hunk_bytes
                && offset.is_multiple_of(2)
            {
                entries.insert(offset);
            }
        }
    }

    let table_total = found.len();
    let tables_truncated = table_total > request.maximum_tables;
    let mut targets_truncated_any = false;
    let tables: Vec<PointerTable> = found
        .iter()
        .take(request.maximum_tables)
        .map(|table| {
            let total = table.targets.len();
            let truncated = total > request.maximum_targets;
            targets_truncated_any |= truncated;
            PointerTable {
                offset: table.offset,
                encoding: match table.encoding {
                    amiga_core::pointers::PointerEncoding::Long => PointerEncoding::Long,
                    amiga_core::pointers::PointerEncoding::ScaledWord(_) => {
                        PointerEncoding::ScaledWord
                    }
                },
                // The span is read from the whole run, so a capped list never
                // understates which part of the hunk a table addresses.
                target_lowest: table
                    .targets
                    .iter()
                    .min()
                    .copied()
                    .unwrap_or(request.origin),
                target_highest: table
                    .targets
                    .iter()
                    .max()
                    .copied()
                    .unwrap_or(request.origin),
                targets: table
                    .targets
                    .iter()
                    .take(request.maximum_targets)
                    .copied()
                    .collect(),
                target_total: total as u64,
                targets_truncated: truncated,
            }
        })
        .collect();

    if tables_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{table_total} tables match; {} are reported",
                request.maximum_tables
            ),
        ));
    }
    if targets_truncated_any {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "at least one table holds more than {} targets; each reports its true total",
                request.maximum_targets
            ),
        ));
    }

    // Bounded on its own terms, not by the per-table target cap: the targets
    // are what a table shows and these are what a caller analyzes from, so
    // narrowing the display must not narrow the analysis.
    let entry_offset_total = entries.len();
    let entry_offsets_truncated = entry_offset_total > request.maximum_entry_offsets;
    if entry_offsets_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{entry_offset_total} distinct entry offsets were derived; {} are reported",
                request.maximum_entry_offsets
            ),
        ));
    }

    let result = PointerScanResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        origin: request.origin,
        scanned_bytes: u64::from(hunk_bytes),
        tables,
        table_total: table_total as u64,
        tables_truncated,
        entry_offsets: entries
            .iter()
            .take(request.maximum_entry_offsets)
            .copied()
            .collect(),
        entry_offset_total: entry_offset_total as u64,
        entry_offsets_truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisPointersScan(result)),
    )
}
