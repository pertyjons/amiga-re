//! `analysis.table.summarize` — what a fixed-layout table's columns hold, and
//! where several tables disagree.
//!
//! `analysis.table.decode` answers "what do these bytes decode to". This
//! answers the two questions a reader asks next and had to leave the toolkit
//! for: *which values does this column actually take*, and *where does this
//! table differ from that one*. Both were external sorting or a throwaway
//! program, and both are questions about the same decode.
//!
//! **One layout over every source, decided once.** Comparing a column between
//! two tables only means anything if they were read the same way, and two
//! separate `decode` requests cannot promise that — one of them could carry a
//! different offset, a different `maximum_rows`, or a layout that differs in a
//! field width nobody looked at twice. Here the record is normalized once and
//! every table is read through it.
//!
//! **Every count is exact and every list is capped.** "This column holds three
//! distinct values" is a fact about the table; the same sentence under a cap
//! that also bounded the counting would be a fact about the request. So
//! `distinct_total` and `differing_total` are counted over everything read, and
//! only the lists beside them are cut.

use std::collections::BTreeMap;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedTableSummarize;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, SourcePin, TableColumnComparison, TableColumnSummary,
    TableField, TableRowDifference, TableSummarizeResult, TableSummary, TableValueCount,
};

pub(crate) fn run(
    request: &NormalizedTableSummarize,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let failed = |diagnostics: Vec<Diagnostic>| OperationOutcome {
        operation: OperationName::AnalysisTableSummarize,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result: None,
    };

    // The record before any source, as `decode` does: a layout that describes
    // nothing should cost nothing to refuse, however many tables were named.
    let layout = match super::table_decode::record_layout_for(
        &request.record,
        context,
        "$.request.arguments.layout",
    ) {
        Ok(layout) => layout,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return failed(diagnostics);
        }
    };
    let record_size = amiga_core::record::record_size(&layout);
    let produces_values = layout
        .iter()
        .any(|field| !matches!(field, amiga_core::record::FieldType::Pad(_)));
    if record_size == 0 || !produces_values {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "the layout produces no fields, so it describes no columns",
            )
            .at("$.request.arguments.layout"),
        );
        return failed(diagnostics);
    }
    let offsets = column_offsets(&layout);

    let mut tables = Vec::with_capacity(request.sources.len());
    // Kept beside the summaries because a comparison needs the values row by
    // row, which a summary has already collapsed.
    let mut decoded: Vec<Vec<Vec<TableField>>> = Vec::with_capacity(request.sources.len());

    for (index, name) in request.sources.iter().enumerate() {
        if amiga_core::Cancel::is_cancelled(context.cancel()) {
            return OperationOutcome {
                operation: OperationName::AnalysisTableSummarize,
                status: Status::Cancelled,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
        let source = match context.resolve_source(name, request.maximum_input_bytes) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.push(
                    Diagnostic::error(
                        super::table_decode::source_error_code(&error),
                        error.to_string(),
                    )
                    .at(format!("$.request.arguments.sources[{index}]")),
                );
                return failed(diagnostics);
            }
        };
        let bytes = source.bytes();
        if request.offset > bytes.len() {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::SourceRangeOutsideSource,
                    format!(
                        "the table starts at {} in a {}-byte source",
                        request.offset,
                        bytes.len()
                    ),
                )
                .at(format!("$.request.arguments.sources[{index}]")),
            );
            return failed(diagnostics);
        }
        let available = bytes
            .len()
            .saturating_sub(request.offset)
            .saturating_div(record_size);
        let to_read = request.rows.min(available).min(request.maximum_rows);

        let mut rows = Vec::with_capacity(to_read);
        for row in 0..to_read {
            let start = request.offset + row * record_size;
            let Some(region) = bytes.get(start..start + record_size) else {
                break;
            };
            let mut reader = amiga_core::Reader::new(region);
            match amiga_core::record::read_record(&mut reader, &layout) {
                Ok(values) => rows.push(
                    values
                        .iter()
                        .map(super::table_decode::field)
                        .collect::<Vec<_>>(),
                ),
                Err(error) => {
                    diagnostics.push(Diagnostic::error(
                        DiagnosticCode::AnalysisRecordUnreadable,
                        format!("row {row} at {start:#x}: {error}"),
                    ));
                    return failed(diagnostics);
                }
            }
        }

        // Said per table, because a table that ran short is a fact about *that*
        // source and a reader comparing two of them needs to know which one.
        if request.rows > available {
            diagnostics.push(
                Diagnostic::warning(
                    DiagnosticCode::ResultEntriesTruncated,
                    format!(
                        "{}: the region holds {available} whole rows of {record_size} bytes, \
                         not the {} asked for",
                        name.parent.as_str(),
                        request.rows
                    ),
                )
                .at(format!("$.request.arguments.sources[{index}]")),
            );
        } else if request.rows > request.maximum_rows {
            diagnostics.push(
                Diagnostic::warning(
                    DiagnosticCode::ResultEntriesTruncated,
                    format!(
                        "{}: reading the first {} of {} rows",
                        name.parent.as_str(),
                        request.maximum_rows,
                        request.rows
                    ),
                )
                .at(format!("$.request.arguments.sources[{index}]")),
            );
        }

        tables.push(TableSummary {
            source: SourcePin {
                size: source.size(),
                sha256: source.sha256().to_owned(),
            },
            rows_read: rows.len() as u64,
            row_total: available as u64,
            columns: summarize(&rows, &offsets, request.maximum_values),
        });
        decoded.push(rows);
        events.emit(OperationEvent::Progress {
            phase: "decode_tables",
            completed: (index + 1) as u64,
            total: Some(request.sources.len() as u64),
        });
    }

    // The shortest table decides how far a comparison reaches: a row one table
    // does not have is not a disagreement about a value, and reporting it as
    // one would turn "this table is shorter" into a difference per column.
    let compared_rows = decoded.iter().map(Vec::len).min().unwrap_or(0);
    if decoded.len() > 1 && decoded.iter().any(|rows| rows.len() != compared_rows) {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the tables hold different numbers of rows; comparing the first {compared_rows}"
            ),
        ));
    }
    let comparisons = if decoded.len() > 1 {
        compare(
            &decoded,
            &offsets,
            compared_rows,
            request.maximum_differences,
        )
    } else {
        Vec::new()
    };

    OperationOutcome {
        operation: OperationName::AnalysisTableSummarize,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::AnalysisTableSummarize(
            TableSummarizeResult {
                record_size: record_size as u64,
                offset: request.offset as u64,
                tables,
                comparisons,
                compared_rows: compared_rows as u64,
            },
        )),
    }
}

/// Where each value-producing field starts inside one record.
///
/// A `pad` consumes bytes and produces no value, so the column index and the
/// field index part company as soon as a layout has one. Reporting the byte
/// offset alongside is what lets a reader find the column in a hex dump without
/// recounting the layout by hand.
fn column_offsets(layout: &[amiga_core::record::FieldType]) -> Vec<u64> {
    let mut offsets = Vec::new();
    let mut at = 0_u64;
    for field in layout {
        let width = amiga_core::record::record_size(std::slice::from_ref(field)) as u64;
        if !matches!(field, amiga_core::record::FieldType::Pad(_)) {
            offsets.push(at);
        }
        at = at.saturating_add(width);
    }
    offsets
}

/// Per column: how many distinct values, the most frequent of them, and the
/// numeric extremes where the column has any.
fn summarize(
    rows: &[Vec<TableField>],
    offsets: &[u64],
    maximum_values: usize,
) -> Vec<TableColumnSummary> {
    let columns = rows.first().map_or(0, Vec::len);
    (0..columns)
        .map(|column| {
            let mut counts: BTreeMap<&TableField, u64> = BTreeMap::new();
            for row in rows {
                if let Some(value) = row.get(column) {
                    *counts.entry(value).or_default() += 1;
                }
            }
            let distinct_total = counts.len() as u64;
            // Most frequent first, then by value: a total order, so two runs
            // over the same bytes report the same list.
            let mut ordered: Vec<(&TableField, u64)> = counts.into_iter().collect();
            ordered.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
            let values_truncated = ordered.len() > maximum_values;
            let numeric: Vec<i64> = rows
                .iter()
                .filter_map(|row| row.get(column).and_then(numeric_value))
                .collect();
            TableColumnSummary {
                column: column as u32,
                field_offset: offsets.get(column).copied().unwrap_or(0),
                distinct_total,
                values: ordered
                    .into_iter()
                    .take(maximum_values)
                    .map(|(value, count)| TableValueCount {
                        value: value.clone(),
                        count,
                    })
                    .collect(),
                values_truncated,
                minimum: numeric.iter().min().copied(),
                maximum: numeric.iter().max().copied(),
            }
        })
        .collect()
}

/// Per column, the rows where at least two tables hold different values.
fn compare(
    decoded: &[Vec<Vec<TableField>>],
    offsets: &[u64],
    compared_rows: usize,
    maximum_differences: usize,
) -> Vec<TableColumnComparison> {
    let columns = offsets.len();
    (0..columns)
        .map(|column| {
            let mut differences = Vec::new();
            let mut differing_total = 0_u64;
            for row in 0..compared_rows {
                let values: Vec<TableField> = decoded
                    .iter()
                    .filter_map(|table| table.get(row).and_then(|fields| fields.get(column)))
                    .cloned()
                    .collect();
                if values.len() < decoded.len() || values.windows(2).all(|pair| pair[0] == pair[1])
                {
                    continue;
                }
                differing_total += 1;
                if differences.len() < maximum_differences {
                    differences.push(TableRowDifference {
                        row: row as u64,
                        values,
                    });
                }
            }
            TableColumnComparison {
                column: column as u32,
                identical: differing_total == 0,
                differing_total,
                differences,
            }
        })
        .collect()
}

/// A column's value as a number, where it is one.
///
/// Text and bytes are deliberately not numbers: a minimum over them would be a
/// fact about an encoding rather than about the data. A pointer is, because
/// "the lowest address this table points at" is a real question.
const fn numeric_value(value: &TableField) -> Option<i64> {
    match value {
        TableField::Unsigned(value) | TableField::Pointer(value) => Some(*value as i64),
        TableField::Signed(value) => Some(*value as i64),
        TableField::Text(_) | TableField::Bytes(_) => None,
    }
}
