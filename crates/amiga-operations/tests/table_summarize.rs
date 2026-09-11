//! `analysis.table.summarize`: what a column holds, and where two tables differ.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, InMemorySourceResolver, OperationOutcome, OperationRequestDocument,
    RequestEnvelope, ResolvedSource, Router, SourceName, Status, TableField,
    TableSummarizeArguments,
};

/// Four records of `u16,u16,ptr`. The second column is the same value in every
/// row — the repeated descriptor a summary exists to make visible — and `rows`
/// says which values the first column takes.
fn table(rows: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (first, second, pointer) in rows {
        bytes.extend_from_slice(&first.to_be_bytes());
        bytes.extend_from_slice(&second.to_be_bytes());
        bytes.extend_from_slice(&pointer.to_be_bytes());
    }
    bytes
}

fn run(arguments: TableSummarizeArguments, tables: &[(&str, Vec<u8>)]) -> OperationOutcome {
    let sources: Vec<ResolvedSource> = tables
        .iter()
        .map(|(name, bytes)| {
            ResolvedSource::new(
                SourceName::parse(name).expect("a valid name"),
                Arc::from(bytes.clone()),
            )
        })
        .collect();
    let resolver = InMemorySourceResolver::holding(sources);
    let context = ExecutionContext::new(&resolver);
    let request =
        RequestEnvelope::read(OperationRequestDocument::AnalysisTableSummarize(arguments));
    Router::execute(&request, &context)
}

const ROWS_A: &[(u16, u16, u32)] = &[
    (1, 7, 0x0002_0000),
    (2, 7, 0x0002_0000),
    (1, 7, 0x0002_0010),
    (5, 7, 0x0002_0000),
];

#[test]
fn a_column_reports_its_distinct_values_with_their_frequencies() {
    let outcome = run(
        TableSummarizeArguments::new(["a.bin"], "u16,u16,ptr", 4),
        &[("a.bin", table(ROWS_A))],
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let summary = outcome
        .analysis_table_summarize()
        .expect("a summary is produced");
    assert_eq!(summary.record_size, 8);
    assert_eq!(summary.tables.len(), 1);
    let columns = &summary.tables[0].columns;
    assert_eq!(columns.len(), 3);

    // Most frequent first: `1` twice, then `2` and `5` once each, ordered by
    // value so the list is the same on every run.
    assert_eq!(columns[0].distinct_total, 3);
    assert_eq!(
        columns[0]
            .values
            .iter()
            .map(|entry| (entry.value.clone(), entry.count))
            .collect::<Vec<_>>(),
        vec![
            (TableField::Unsigned(1), 2),
            (TableField::Unsigned(2), 1),
            (TableField::Unsigned(5), 1),
        ]
    );
    assert_eq!(columns[0].minimum, Some(1));
    assert_eq!(columns[0].maximum, Some(5));

    // The repeated descriptor, which is what a person scanning a guessed layout
    // is looking for: one value, four times.
    assert_eq!(columns[1].distinct_total, 1);
    assert_eq!(columns[1].values[0].count, 4);

    // Byte offsets inside the record, so a column can be found in a hex dump
    // without recounting the layout.
    assert_eq!(
        columns
            .iter()
            .map(|column| column.field_offset)
            .collect::<Vec<_>>(),
        vec![0, 2, 4]
    );

    // One source: there is nothing to compare it with, and an empty comparison
    // list says so rather than a list of columns all marked identical.
    assert!(summary.comparisons.is_empty());
}

/// A capped list beside an exact count. "This column holds three distinct
/// values" is a fact about the table; the same sentence under a cap that also
/// bounded the counting would be a fact about the request.
#[test]
fn a_capped_value_list_still_reports_the_true_distinct_count() {
    let outcome = run(
        TableSummarizeArguments::new(["a.bin"], "u16,u16,ptr", 4).with_maximum_values(1),
        &[("a.bin", table(ROWS_A))],
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let summary = outcome.analysis_table_summarize().expect("a summary");
    let column = &summary.tables[0].columns[0];
    assert_eq!(column.values.len(), 1);
    assert!(column.values_truncated);
    assert_eq!(
        column.distinct_total, 3,
        "the count was capped with the list"
    );
}

/// The question the wishlist entry is actually about: the same column across
/// two sandbox memory exports, and where they disagree.
#[test]
fn two_tables_are_compared_column_by_column() {
    let mut rows_b = ROWS_A.to_vec();
    rows_b[1].0 = 9; // the first column differs in row 1 …
    rows_b[3].2 = 0x0002_00f0; // … and the pointer in row 3.
    let outcome = run(
        TableSummarizeArguments::new(["a.bin", "b.bin"], "u16,u16,ptr", 4),
        &[("a.bin", table(ROWS_A)), ("b.bin", table(&rows_b))],
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let summary = outcome.analysis_table_summarize().expect("a summary");
    assert_eq!(summary.compared_rows, 4);
    assert_eq!(summary.comparisons.len(), 3);

    assert!(!summary.comparisons[0].identical);
    assert_eq!(summary.comparisons[0].differing_total, 1);
    assert_eq!(summary.comparisons[0].differences[0].row, 1);
    assert_eq!(
        summary.comparisons[0].differences[0].values,
        vec![TableField::Unsigned(2), TableField::Unsigned(9)],
        "the values come back in the order the request named the tables"
    );

    // The column both tables agree on says so as a boolean, which a capped
    // difference list could never establish.
    assert!(summary.comparisons[1].identical);
    assert_eq!(summary.comparisons[1].differing_total, 0);

    assert_eq!(summary.comparisons[2].differing_total, 1);
    assert_eq!(summary.comparisons[2].differences[0].row, 3);
}

/// A row one table does not have is not a disagreement about a value. Reporting
/// it as one would turn "this table is shorter" into a difference in every
/// column, which is exactly the noise an external diff produces.
#[test]
fn a_shorter_table_bounds_the_comparison_rather_than_differing_everywhere() {
    let outcome = run(
        TableSummarizeArguments::new(["a.bin", "short.bin"], "u16,u16,ptr", 4),
        &[("a.bin", table(ROWS_A)), ("short.bin", table(&ROWS_A[..2]))],
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let summary = outcome.analysis_table_summarize().expect("a summary");
    assert_eq!(summary.compared_rows, 2);
    assert!(
        summary
            .comparisons
            .iter()
            .all(|comparison| comparison.identical),
        "the rows the shorter table does not have were read as differences"
    );
    // The true row counts are still reported per table, and the difference is
    // a stated warning rather than a silently shorter comparison.
    assert_eq!(summary.tables[0].row_total, 4);
    assert_eq!(summary.tables[1].row_total, 2);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("different numbers of rows")),
        "{:?}",
        outcome.diagnostics
    );
}
