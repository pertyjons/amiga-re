//! `analysis.table.decode`: what a guessed layout is told about itself.

use std::sync::Arc;

use amiga_operations::{
    DiagnosticCode, ExecutionContext, InMemorySourceResolver, OperationRequestDocument,
    RequestEnvelope, ResolvedSource, Router, SourceName, Status, TableDecodeArguments, TableField,
};

/// Four records of `u16,u16,ptr` — eight bytes each — then four trailing bytes
/// that are not a whole record.
fn table() -> Vec<u8> {
    let mut bytes = Vec::new();
    for index in 0..4_u16 {
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&(index * 10).to_be_bytes());
        bytes.extend_from_slice(&(0x0002_0000 + u32::from(index)).to_be_bytes());
    }
    bytes.extend_from_slice(&[0xff; 4]);
    bytes
}

fn run(arguments: TableDecodeArguments, bytes: Vec<u8>) -> amiga_operations::OperationOutcome {
    let name = SourceName::parse("table.bin").expect("a valid name");
    let resolver = InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)));
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::AnalysisTableDecode(arguments));
    Router::execute(&request, &context)
}

#[test]
fn a_layout_that_fits_decodes_every_field_by_its_own_kind() {
    let outcome = run(
        TableDecodeArguments::new("table.bin", "u16,u16,ptr", 4),
        table(),
    );
    assert_eq!(outcome.status, Status::Success);
    let result = outcome
        .analysis_table_decode()
        .expect("a decode produces a table");
    assert_eq!(result.record_size, 8);
    assert_eq!(result.rows.len(), 4);
    assert_eq!(result.rows[2].offset, 16);
    // A pointer stays a pointer rather than collapsing into an integer: which
    // fields are pointers is most of what identifying a table is for.
    assert_eq!(
        result.rows[2].fields,
        vec![
            TableField::Unsigned(2),
            TableField::Unsigned(20),
            TableField::Pointer(0x0002_0002),
        ]
    );
}

#[test]
fn a_region_shorter_than_the_request_reports_what_it_actually_holds() {
    // The trailing four bytes are not a whole record. Asking for six rows must
    // return the four that exist and say so, because that is the feedback that
    // makes the next guess better.
    let outcome = run(
        TableDecodeArguments::new("table.bin", "u16,u16,ptr", 6),
        table(),
    );
    assert_eq!(outcome.status, Status::Success);
    let result = outcome.analysis_table_decode().expect("a table");
    assert_eq!(result.rows.len(), 4);
    assert_eq!(result.row_total, 4);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| !diagnostic.is_error() && diagnostic.message.contains("4 whole rows")),
        "the short region was not reported: {:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_unparseable_layout_is_a_bad_request_not_a_failed_read() {
    let outcome = run(
        TableDecodeArguments::new("table.bin", "u16,nonsense[4]", 1),
        table(),
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.exit_code(),
        2,
        "a refused request has its own exit code"
    );
}

#[test]
fn a_layout_of_only_padding_describes_no_rows() {
    // `pad[4]` reads bytes and produces no values, so a table of it would be
    // an infinite number of empty rows. Refusing is the only honest answer.
    let outcome = run(TableDecodeArguments::new("table.bin", "pad[4]", 4), table());
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("no rows")),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_offset_past_the_end_is_refused_rather_than_returning_nothing() {
    // "Zero rows" and "you are looking outside the file" are different answers,
    // and only one of them tells the user their offset is wrong.
    let outcome = run(
        TableDecodeArguments::new("table.bin", "u16,u16,ptr", 1).with_offset(4096),
        table(),
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::SourceRangeOutsideSource),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn a_row_cap_truncates_and_says_so() {
    let outcome = run(
        TableDecodeArguments::new("table.bin", "u16,u16,ptr", 4).with_maximum_rows(2),
        table(),
    );
    assert_eq!(outcome.status, Status::Success);
    let result = outcome.analysis_table_decode().expect("a table");
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.row_total, 4, "the true count survives the cap");
}

#[test]
fn a_cancelled_decode_yields_no_partial_table() {
    // Cancellation is an outcome, not a smaller result: a half-decoded table
    // that looked complete would be worse than no table.
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    let name = SourceName::parse("table.bin").expect("a valid name");
    let resolver = InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(table())));
    let context = ExecutionContext::new(&resolver).with_cancel(&cancelled);
    let request = RequestEnvelope::read(OperationRequestDocument::AnalysisTableDecode(
        TableDecodeArguments::new("table.bin", "u16,u16,ptr", 4),
    ));
    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Cancelled);
    assert!(outcome.result.is_none());
}

// --- decoding through a type the project defines ------------------------------
//
// The other half of `Resource::Table`'s `type_id`. The format has always let a
// table name its record layout by pointing at a struct; until now nothing could
// decode through the thing it pointed at, so the layout lived twice — once as a
// type nobody read, and once as a string in the request.

use amiga_operations::{FilesystemSourceResolver, ProjectLocator};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../amiga-project/fixtures")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the project fixtures are readable: {error}"))
}

/// `analysis.table.decode` against the contract fixture, optionally naming a
/// project.
fn against_fixture(
    arguments: TableDecodeArguments,
    project: Option<&str>,
) -> amiga_operations::OperationOutcome {
    let resolver = FilesystemSourceResolver::new(fixtures());
    let context = ExecutionContext::new(&resolver);
    let mut request =
        RequestEnvelope::read(OperationRequestDocument::AnalysisTableDecode(arguments));
    request.project = project.map(|path| ProjectLocator::Path {
        path: path.to_owned(),
    });
    Router::execute(&request, &context)
}

const LEVELS: &str = "contract/original/installed/data/levels.tbl";

/// The round trip the entry exists to close: the fixture's `type:level-header`
/// decodes the same rows the layout string it describes would.
#[test]
fn a_stored_type_decodes_the_rows_its_layout_string_would() {
    let through_type = against_fixture(
        TableDecodeArguments::through_type(LEVELS, "type:level-header", 4),
        Some("contract"),
    );
    assert_eq!(
        through_type.status,
        Status::Success,
        "{:?}",
        through_type.diagnostics
    );
    let named = through_type
        .analysis_table_decode()
        .expect("a decode produces a table");

    // `type:level-header` is id/width/height as `u16`, then `flags`, whose type
    // is an enum over `u16` — an enum's stored value is its base type's, so it
    // reads as one.
    let spelled_out = against_fixture(
        TableDecodeArguments::new(LEVELS, "u16,u16,u16,u16", 4),
        None,
    );
    assert_eq!(
        spelled_out.status,
        Status::Success,
        "{:?}",
        spelled_out.diagnostics
    );
    let spelled = spelled_out
        .analysis_table_decode()
        .expect("a decode produces a table");

    assert_eq!(named.record_size, 8);
    assert_eq!(named.record_size, spelled.record_size);
    assert_eq!(named.row_total, spelled.row_total);
    assert_eq!(named.rows, spelled.rows);
}

/// The two spellings mean the same rows and are still two different questions:
/// a stored type is resolved against a particular project, so the digest that
/// identifies the request has to say which.
#[test]
fn the_two_spellings_of_one_record_do_not_share_a_request_digest() {
    let named = against_fixture(
        TableDecodeArguments::through_type(LEVELS, "type:level-header", 4),
        Some("contract"),
    );
    let spelled = against_fixture(
        TableDecodeArguments::new(LEVELS, "u16,u16,u16,u16", 4),
        None,
    );
    assert_ne!(
        named.normalized_request_sha256,
        spelled.normalized_request_sha256
    );
}

#[test]
fn a_type_the_project_does_not_define_is_refused_rather_than_guessed_at() {
    let outcome = against_fixture(
        TableDecodeArguments::through_type(LEVELS, "type:not-here", 4),
        Some("contract"),
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ProjectContradicted),
        "{:?}",
        outcome.diagnostics
    );
}

/// A struct is not the only thing a `type:` id can name, and the ones that are
/// not refuse rather than decoding as something adjacent.
#[test]
fn a_type_that_is_not_a_struct_cannot_describe_a_record() {
    let outcome = against_fixture(
        TableDecodeArguments::through_type(LEVELS, "type:u16", 4),
        Some("contract"),
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ProjectContradicted),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn naming_a_type_without_naming_a_project_is_refused() {
    let outcome = against_fixture(
        TableDecodeArguments::through_type(LEVELS, "type:level-header", 4),
        None,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RequestProjectRequired),
        "{:?}",
        outcome.diagnostics
    );
}

/// Two spellings of one thing, so a request carrying both would have to decide
/// which wins. It refuses instead.
#[test]
fn giving_both_a_layout_and_a_type_is_refused() {
    let mut arguments = TableDecodeArguments::new(LEVELS, "u16,u16,u16,u16", 4);
    arguments.type_id = Some("type:level-header".to_owned());
    let outcome = against_fixture(arguments, Some("contract"));
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RequestMalformed),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn giving_neither_a_layout_nor_a_type_is_refused() {
    let mut arguments = TableDecodeArguments::new(LEVELS, "u16", 4);
    arguments.layout = None;
    let outcome = against_fixture(arguments, None);
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RequestMalformed),
        "{:?}",
        outcome.diagnostics
    );
}
