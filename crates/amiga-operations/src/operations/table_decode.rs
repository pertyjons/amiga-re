//! `analysis.table.decode` — read a byte region as an array of fixed-layout
//! records.
//!
//! Amiga games keep menus, level tables, and entity arrays as arrays of C-like
//! structs, and identifying one is guesswork until the layout happens to line
//! up. That makes this a *read* in the strongest sense: it will be run over and
//! over with a slightly different layout, so it must be cheap to refuse, and it
//! must never be ambiguous about why a guess did not fit.
//!
//! Two refusals are therefore distinct. A layout that does not parse is a bad
//! request, reported before anything is read. A layout that parses but runs
//! past the end of the source is a bad *guess*: the rows that did fit are
//! returned, the true count is reported, and a diagnostic says the region ended
//! — which is exactly the feedback that makes the next guess better.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedRecordLayout, NormalizedTableDecode};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, SourcePin, TableDecodeResult, TableField, TableRow,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedTableDecode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let failed = |diagnostics: Vec<Diagnostic>| OperationOutcome {
        operation: OperationName::AnalysisTableDecode,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result: None,
    };

    // The record is established before the source is opened: a layout that
    // cannot describe anything, or a type the project does not define, should
    // cost nothing to refuse.
    let layout = match record_layout(request, context) {
        Ok(layout) => layout,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return failed(diagnostics);
        }
    };
    let record_size = amiga_core::record::record_size(&layout);
    // Two ways a parseable layout still describes nothing: it consumes no
    // bytes, or it consumes bytes and produces no values. The second is easy to
    // reach by accident — `pad[4]` is a valid field — and rows of no fields are
    // not an answer anyone can use.
    let produces_values = layout
        .iter()
        .any(|field| !matches!(field, amiga_core::record::FieldType::Pad(_)));
    if record_size == 0 || !produces_values {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "the layout produces no fields, so it describes no rows",
            )
            .at("$.request.arguments.layout"),
        );
        return failed(diagnostics);
    }

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
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
            .at("$.request.arguments.offset"),
        );
        return failed(diagnostics);
    }

    // How many rows the region can hold, before deciding how many to report.
    let available = bytes
        .len()
        .saturating_sub(request.offset)
        .saturating_div(record_size);
    let requested = request.rows;
    let rows_to_read = requested.min(available).min(request.maximum_rows);

    let mut rows = Vec::with_capacity(rows_to_read);
    for index in 0..rows_to_read {
        if amiga_core::Cancel::is_cancelled(context.cancel()) {
            return OperationOutcome {
                operation: OperationName::AnalysisTableDecode,
                status: Status::Cancelled,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
        let start = request.offset + index * record_size;
        let Some(region) = bytes.get(start..start + record_size) else {
            break;
        };
        let mut reader = amiga_core::Reader::new(region);
        match amiga_core::record::read_record(&mut reader, &layout) {
            Ok(values) => rows.push(TableRow {
                offset: start as u64,
                fields: values.iter().map(field).collect(),
            }),
            Err(error) => {
                // A record that does not read after the bounds already checked
                // out is a real inconsistency, not a guess that ran long.
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::AnalysisRecordUnreadable,
                    format!("row {index} at {start:#x}: {error}"),
                ));
                return failed(diagnostics);
            }
        }
    }
    events.emit(OperationEvent::Progress {
        phase: "decode_rows",
        completed: rows.len() as u64,
        total: Some(rows_to_read as u64),
    });

    if requested > available {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::ResultEntriesTruncated,
                format!(
                    "the region holds {available} whole rows of {record_size} bytes, \
                     not the {requested} asked for"
                ),
            )
            .at("$.request.arguments.rows"),
        );
    } else if requested > request.maximum_rows {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::ResultEntriesTruncated,
                format!(
                    "reporting the first {} of {requested} rows",
                    request.maximum_rows
                ),
            )
            .at("$.request.arguments.rows"),
        );
    }

    OperationOutcome {
        operation: OperationName::AnalysisTableDecode,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::AnalysisTableDecode(TableDecodeResult {
            source: SourcePin {
                size: source.size(),
                sha256: source.sha256().to_owned(),
            },
            record_size: record_size as u64,
            rows,
            row_total: available,
            offset: request.offset as u64,
        })),
    }
}

/// The record layout this request decodes with, however it was spelled.
///
/// A layout string parses on its own. A `type_id` is resolved through the project and
/// converted to a layout with `amiga_project::record_type`. This shares the mapping
/// used to register table resources, so a stored type is sufficient to decode a
/// resource without an additional layout string.
fn record_layout(
    request: &NormalizedTableDecode,
    context: &ExecutionContext<'_>,
) -> Result<Vec<amiga_core::record::FieldType>, Diagnostic> {
    record_layout_for(&request.record, context, "$.request.arguments.layout")
}

/// The same, for any request carrying a record spelling — `summarize` reads its
/// layout through this, so the two operations cannot come to resolve a stored
/// type differently.
pub(crate) fn record_layout_for(
    record: &NormalizedRecordLayout,
    context: &ExecutionContext<'_>,
    layout_path: &str,
) -> Result<Vec<amiga_core::record::FieldType>, Diagnostic> {
    let (type_id, project) = match record {
        NormalizedRecordLayout::Layout(layout) => {
            return amiga_core::record::parse_layout(layout).map_err(|error| {
                Diagnostic::error(DiagnosticCode::RequestArgumentOutOfRange, error.to_string())
                    .at(layout_path)
            });
        }
        NormalizedRecordLayout::Type { type_id, project } => (type_id, project),
    };

    let Some(root) = context
        .resolver()
        .root()
        .map(|root| root.join(project.path.as_str()))
    else {
        return Err(Diagnostic::error(
            DiagnosticCode::ProjectUnreadable,
            "this context serves no directory, so no project can be located",
        )
        .at("$.project"));
    };
    let loaded = amiga_project::load(&root).map_err(|error| {
        Diagnostic::error(DiagnosticCode::ProjectUnreadable, error.to_string()).at("$.project")
    })?;
    let defined: Vec<&amiga_project::document::TypeDefinition> = loaded
        .project
        .types
        .iter()
        .flat_map(|document| &document.types)
        .collect();
    let by_id = |id: &str| defined.iter().copied().find(|entry| entry.id() == id);
    let Some(definition) = by_id(type_id) else {
        return Err(Diagnostic::error(
            DiagnosticCode::ProjectContradicted,
            format!("no type {type_id} in this project"),
        )
        .at("$.request.arguments.type_id"));
    };
    amiga_project::record_type::layout_of(definition, &by_id).map_err(|error| {
        Diagnostic::error(DiagnosticCode::ProjectContradicted, error.to_string())
            .at("$.request.arguments.type_id")
    })
}

/// One decoded value, in the wire vocabulary.
///
/// A pointer stays distinct from an unsigned integer even though both are 32
/// bits: which fields are pointers is most of what identifying a table is for.
pub(crate) fn field(value: &amiga_core::record::FieldValue) -> TableField {
    match value {
        amiga_core::record::FieldValue::Unsigned(value) => TableField::Unsigned(*value),
        amiga_core::record::FieldValue::Signed(value) => TableField::Signed(*value),
        amiga_core::record::FieldValue::Pointer(value) => TableField::Pointer(*value),
        amiga_core::record::FieldValue::Text(text) => TableField::Text(text.clone()),
        amiga_core::record::FieldValue::Bytes(bytes) => TableField::Bytes(bytes.clone()),
    }
}

pub(crate) const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
