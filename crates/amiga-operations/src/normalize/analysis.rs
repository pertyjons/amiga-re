//! The normalized `analysis.*` requests, and what filling their defaults decides.
use super::*;

/// The address register the small-data convention uses. A5 by convention, and
/// the convention is what makes a displacement from it a global rather than an
/// arbitrary offset from an arbitrary pointer.
const DEFAULT_BASE_REGISTER: u8 = 5;

/// Consecutive plausible entries a run needs before it is reported as a table.
///
/// Three, because two in-range longwords in a row happen by accident in
/// ordinary data and three do so far less often. Low enough to find the short
/// jump tables a loader actually holds, and the caller can raise it.
const DEFAULT_MINIMUM_POINTER_ENTRIES: usize = 3;

/// The file name a normalized image uses when the request names none.
const DEFAULT_NORMALIZED_FILE_NAME: &str = "normalized.exe";

fn validate_code_region(
    region: CodeRegion,
    hunk: Option<u32>,
    expected_sha256: Option<&str>,
) -> Result<(), Vec<Diagnostic>> {
    if region != CodeRegion::Hunk && hunk.is_some() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "hunk applies only to the hunk code region",
            )
            .at("$.request.arguments.hunk"),
        ]);
    }
    if region == CodeRegion::Raw && expected_sha256.is_none() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                "raw code must carry expected_sha256 so the unframed bytes are pinned",
            )
            .at("$.request.arguments.expected_sha256"),
        ]);
    }
    if let Some(digest) = expected_sha256
        && (digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                "expected_sha256 must be exactly 64 hexadecimal characters",
            )
            .at("$.request.arguments.expected_sha256"),
        ]);
    }
    Ok(())
}

/// Fully resolved `analysis.code.facts` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCodeFacts {
    pub source: NormalizedSource,
    pub region: CodeRegion,
    pub hunk: u32,
    pub expected_sha256: Option<String>,
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub base_register: u8,
    pub default_library: Option<String>,
    pub library_vectors: Vec<crate::request::LibraryVector>,
    pub maximum_facts: usize,
    pub maximum_instructions: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.code.globals` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCodeGlobals {
    pub source: NormalizedSource,
    pub hunk: u32,
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub base_register: u8,
    pub derived: bool,
    pub maximum_accesses: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.code.fixed-point` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCodeFixedPoint {
    pub source: NormalizedSource,
    pub hunk: u32,
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub maximum_hints: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.code.callgraph` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCodeCallgraph {
    pub source: NormalizedSource,
    pub hunk: u32,
    /// Never empty, for the reason every traversal here says so: a graph built
    /// from no entry points would report a hunk with no functions in it.
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub maximum_nodes: usize,
    pub maximum_edges: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.address.references` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAddressReferences {
    pub source: NormalizedSource,
    pub hunk: u32,
    pub target: Option<u32>,
    /// Never empty: a traversal from nothing would report a hunk that makes no
    /// references rather than one nobody looked at.
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub maximum_references: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.code.disassemble` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCodeDisassemble {
    pub source: NormalizedSource,
    pub region: CodeRegion,
    pub hunk: u32,
    pub expected_sha256: Option<String>,
    pub mode: CodeDisassembleMode,
    /// Linear mode only. `None` for `end` means "to the end of the hunk",
    /// which cannot be resolved until the hunk is read.
    pub start: u32,
    pub end: Option<u32>,
    /// Flow mode only, never empty: an entry list of nothing would traverse
    /// nothing and report a hunk with no code in it.
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub maximum_instructions: usize,
    pub maximum_edges: usize,
    pub maximum_input_bytes: u64,
}

/// A resolved whole-file anchor: which image, and which hunk within it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHunkAnchor {
    pub source: NormalizedSource,
    pub hunk: u32,
}

/// Fully resolved `analysis.address.resolve` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAddressResolve {
    pub value: u32,
    pub origin: u32,
    pub anchor: Option<NormalizedHunkAnchor>,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.pointers.scan` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPointerScan {
    pub source: NormalizedSource,
    pub hunk: u32,
    pub origin: u32,
    pub minimum_entries: usize,
    /// `None` reads absolute longwords; `Some(scale)` reads unsigned words
    /// multiplied by `scale` and added to the origin.
    pub word_scale: Option<u32>,
    pub maximum_tables: usize,
    pub maximum_targets: usize,
    pub maximum_entry_offsets: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.strings.scan` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedStringsScan {
    pub source: NormalizedSource,
    pub hunk: Option<u32>,
    pub minimum_length: usize,
    pub contains: Option<String>,
    pub maximum_strings: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.hunk.list` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHunkList {
    pub source: NormalizedSource,
    pub maximum_relocations: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.hunk.normalize` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHunkNormalize {
    pub source: NormalizedSource,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.hunk.normalize.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHunkNormalizeExport {
    pub normalize: NormalizedHunkNormalize,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// Fully resolved `analysis.table.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTableDecode {
    pub source: NormalizedSource,
    pub record: NormalizedRecordLayout,
    pub offset: usize,
    pub rows: usize,
    pub maximum_rows: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `analysis.table.summarize` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTableSummarize {
    /// At least one, and in the order the request named them: a comparison
    /// reports one value per table and the reader matches them up by position.
    pub sources: Vec<NormalizedSource>,
    pub record: NormalizedRecordLayout,
    pub offset: usize,
    pub rows: usize,
    pub maximum_rows: usize,
    pub maximum_values: usize,
    pub maximum_differences: usize,
    pub maximum_input_bytes: u64,
}

/// How a table decode was told what one record looks like.
///
/// Two spellings of one thing, kept apart rather than collapsed into a string
/// with a prefix: a layout is self-contained, and a type is a reference into a
/// project that has to be loaded and resolved. A caller reading this enum can
/// see which of the two a request will do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedRecordLayout {
    /// Spelled out in the request, e.g. `u16,u16,ptr,char[16]`.
    Layout(String),
    /// Named: a `type:` id the project resolves to a struct.
    Type {
        type_id: String,
        project: NormalizedProject,
    },
}

/// Fully resolved `analysis.hunk.diff` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHunkDiff {
    pub a: NormalizedSource,
    pub b: NormalizedSource,
    pub maximum_input_bytes: u64,
    /// Cap on the changed ranges reported per hunk.
    pub maximum_entries: usize,
}

/// Fully resolved `analysis.hunk.diff.export` arguments.
///
/// Holds the comparison's own normalized form rather than a copy of its fields,
/// so the two operations cannot drift apart about what a diff means.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHunkDiffExport {
    pub diff: NormalizedHunkDiff,
    pub destination: DestinationName,
    pub file_name: String,
    pub format: HunkDiffFormat,
    pub policy: OutputPolicy,
}

/// The canonical form of one comparison, shared by the read and the export so
/// the same two images under the same bounds digest the same either way.
pub(super) fn hunk_diff_document(diff: &NormalizedHunkDiff) -> Value {
    json!({
        "a": diff.a.canonical(),
        "b": diff.b.canonical(),
        "maximum_input_bytes": diff.maximum_input_bytes,
        "maximum_changed_ranges": diff.maximum_entries,
    })
}

/// The canonical form of one `analysis.hunk.diff.export`.
pub(super) fn hunk_diff_export_document(export: &NormalizedHunkDiffExport) -> Value {
    json!({
        "diff": hunk_diff_document(&export.diff),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "format": export.format,
        "policy": export.policy,
    })
}

/// The canonical form of one `analysis.table.decode`.
///
/// The record spelling is part of the digest, and the two spellings are distinct
/// in it: a stored type is resolved against a particular project, so two requests
/// differing only in which project they read are two different questions.
pub(super) fn table_decode_document(table: &NormalizedTableDecode) -> Value {
    match &table.record {
        NormalizedRecordLayout::Layout(layout) => json!({
            "source": table.source.canonical(),
            "layout": layout,
            "offset": table.offset,
            "rows": table.rows,
            "maximum_rows": table.maximum_rows,
            "maximum_input_bytes": table.maximum_input_bytes,
        }),
        NormalizedRecordLayout::Type { type_id, project } => json!({
            "source": table.source.canonical(),
            "project": project.path.as_str(),
            "type_id": type_id,
            "offset": table.offset,
            "rows": table.rows,
            "maximum_rows": table.maximum_rows,
            "maximum_input_bytes": table.maximum_input_bytes,
        }),
    }
}

/// The canonical form of one `analysis.table.summarize`.
pub(super) fn table_summarize_document(table: &NormalizedTableSummarize) -> Value {
    let sources: Vec<_> = table
        .sources
        .iter()
        .map(NormalizedSource::canonical)
        .collect();
    // The order the sources were named is part of the question: a comparison
    // reports one value per table by position, so two orders are two different
    // answers.
    let mut document = json!({
        "sources": sources,
        "offset": table.offset,
        "rows": table.rows,
        "maximum_rows": table.maximum_rows,
        "maximum_values": table.maximum_values,
        "maximum_differences": table.maximum_differences,
        "maximum_input_bytes": table.maximum_input_bytes,
    });
    match &table.record {
        NormalizedRecordLayout::Layout(layout) => {
            document["layout"] = json!(layout);
        }
        NormalizedRecordLayout::Type { type_id, project } => {
            document["type_id"] = json!(type_id);
            document["project"] = json!(project.path.as_str());
        }
    }
    document
}

/// The canonical form of one `analysis.hunk.normalize`.
pub(super) fn hunk_normalize_document(normalize: &NormalizedHunkNormalize) -> Value {
    source_only_document(&normalize.source, normalize.maximum_input_bytes)
}

/// The canonical form of one `analysis.hunk.normalize.export`.
pub(super) fn hunk_normalize_export_document(export: &NormalizedHunkNormalizeExport) -> Value {
    json!({
        "normalize": hunk_normalize_document(&export.normalize),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one `analysis.strings.scan`.
pub(super) fn strings_scan_document(scan: &NormalizedStringsScan) -> Value {
    json!({
        "source": scan.source.canonical(),
        "hunk": scan.hunk,
        "minimum_length": scan.minimum_length,
        "contains": scan.contains,
        "maximum_strings": scan.maximum_strings,
        "maximum_input_bytes": scan.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.address.resolve`.
///
/// The anchor is nested because it is optional as a whole: a request with no
/// anchor asks about a bare value, and spelling its two halves as absent
/// siblings would make that the same document as one that named an anchor with
/// nothing in it.
pub(super) fn address_resolve_document(resolve: &NormalizedAddressResolve) -> Value {
    json!({
        "value": resolve.value,
        "origin": resolve.origin,
        "anchor": resolve.anchor.as_ref().map(|anchor| json!({
            "source": anchor.source.canonical(),
            "hunk": anchor.hunk,
        })),
        "maximum_input_bytes": resolve.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.pointers.scan`.
pub(super) fn pointers_scan_document(scan: &NormalizedPointerScan) -> Value {
    json!({
        "source": scan.source.canonical(),
        "hunk": scan.hunk,
        "origin": scan.origin,
        "minimum_entries": scan.minimum_entries,
        "word_scale": scan.word_scale,
        "maximum_tables": scan.maximum_tables,
        "maximum_targets": scan.maximum_targets,
        "maximum_entry_offsets": scan.maximum_entry_offsets,
        "maximum_input_bytes": scan.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.code.disassemble`.
pub(super) fn code_disassemble_document(disassemble: &NormalizedCodeDisassemble) -> Value {
    json!({
        "source": disassemble.source.canonical(),
        "region": disassemble.region,
        "hunk": disassemble.hunk,
        "expected_sha256": disassemble.expected_sha256,
        "mode": disassemble.mode,
        "start": disassemble.start,
        "end": disassemble.end,
        "entries": disassemble.entries,
        "origin": disassemble.origin,
        "maximum_instructions": disassemble.maximum_instructions,
        "maximum_edges": disassemble.maximum_edges,
        "maximum_input_bytes": disassemble.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.address.references`.
pub(super) fn address_references_document(references: &NormalizedAddressReferences) -> Value {
    json!({
        "source": references.source.canonical(),
        "hunk": references.hunk,
        "target": references.target,
        "entries": references.entries,
        "origin": references.origin,
        "maximum_references": references.maximum_references,
        "maximum_input_bytes": references.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.code.callgraph`.
pub(super) fn code_callgraph_document(graph: &NormalizedCodeCallgraph) -> Value {
    json!({
        "source": graph.source.canonical(),
        "hunk": graph.hunk,
        "entries": graph.entries,
        "origin": graph.origin,
        "maximum_nodes": graph.maximum_nodes,
        "maximum_edges": graph.maximum_edges,
        "maximum_input_bytes": graph.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.code.facts`.
pub(super) fn code_facts_document(facts: &NormalizedCodeFacts) -> Value {
    json!({
        "source": facts.source.canonical(),
        "region": facts.region,
        "hunk": facts.hunk,
        "expected_sha256": facts.expected_sha256,
        "entries": facts.entries,
        "origin": facts.origin,
        "base_register": facts.base_register,
        "default_library": facts.default_library,
        "library_vectors": facts.library_vectors,
        "maximum_facts": facts.maximum_facts,
        "maximum_instructions": facts.maximum_instructions,
        "maximum_input_bytes": facts.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.code.globals`.
pub(super) fn code_globals_document(globals: &NormalizedCodeGlobals) -> Value {
    json!({
        "source": globals.source.canonical(),
        "hunk": globals.hunk,
        "entries": globals.entries,
        "origin": globals.origin,
        "base_register": globals.base_register,
        "derived": globals.derived,
        "maximum_accesses": globals.maximum_accesses,
        "maximum_input_bytes": globals.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.code.fixed-point`.
pub(super) fn code_fixed_point_document(fixed: &NormalizedCodeFixedPoint) -> Value {
    json!({
        "source": fixed.source.canonical(),
        "hunk": fixed.hunk,
        "entries": fixed.entries,
        "origin": fixed.origin,
        "maximum_hints": fixed.maximum_hints,
        "maximum_input_bytes": fixed.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.hunk.list`.
pub(super) fn hunk_list_document(list: &NormalizedHunkList) -> Value {
    json!({
        "source": list.source.canonical(),
        "maximum_relocations": list.maximum_relocations,
        "maximum_input_bytes": list.maximum_input_bytes,
    })
}

/// Resolve comparison arguments, shared by the read and the export.
pub(super) fn normalize_hunk_diff(
    arguments: &crate::request::HunkDiffArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedHunkDiff, Vec<Diagnostic>> {
    let a = normalize_named_source(&arguments.a, "$.request.arguments.a.path")?;
    let b = normalize_named_source(&arguments.b, "$.request.arguments.b.path")?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let maximum_entries = normalize_count(
        arguments.maximum_changed_ranges,
        limits.maximum_entries(),
        "maximum_changed_ranges",
        "changed ranges",
        diagnostics,
    )?;
    Ok(NormalizedHunkDiff {
        a,
        b,
        maximum_input_bytes,
        maximum_entries,
    })
}

/// Validate a project locator into a resolver-relative identity.
///
/// The same rules a source name obeys: a project root is a location the adapter
/// resolves, and a request that could name an absolute path would be
/// unreproducible on another machine.
/// The record spelling a table request carries: a layout string, or a type the
/// project defines.
///
/// **Exactly one of the two.** Refused here rather than at the handler, because
/// "which of these two describes the record" is a question about the request and
/// not about the bytes — and shared between `decode` and `summarize`, because a
/// summarize whose layout rules differed from a decode's would compare columns
/// against a table nobody could decode the same way.
pub(super) fn normalize_record_layout(
    layout: Option<&str>,
    type_id: Option<&str>,
    envelope: &crate::protocol::RequestEnvelope,
) -> Result<NormalizedRecordLayout, Vec<Diagnostic>> {
    match (layout, type_id) {
        (Some(layout), None) => Ok(NormalizedRecordLayout::Layout(layout.to_owned())),
        (None, Some(type_id)) => {
            let Ok(project) = normalize_project(envelope.project.as_ref()) else {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestProjectRequired,
                        "`type_id` names a type a project defines; name one in `project`, \
                         or give `layout` instead",
                    )
                    .at("$.project"),
                ]);
            };
            Ok(NormalizedRecordLayout::Type {
                type_id: type_id.to_owned(),
                project,
            })
        }
        (Some(_), Some(_)) => Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                "`layout` and `type_id` are two spellings of one record; give one",
            )
            .at("$.request.arguments"),
        ]),
        (None, None) => Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                "a table request needs a record: give `layout` or `type_id`",
            )
            .at("$.request.arguments"),
        ]),
    }
}

/// Fill in what an `analysis.hunk.diff` request left unsaid.
pub(super) fn hunk_diff(
    arguments: &crate::request::HunkDiffArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AnalysisHunkDiff(normalize_hunk_diff(
        arguments,
        limits,
        diagnostics,
    )?))
}

/// Fill in what an `analysis.hunk.diff.export` request left unsaid.
pub(super) fn hunk_diff_export(
    arguments: &crate::request::HunkDiffExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let diff = normalize_hunk_diff(&arguments.diff, limits, diagnostics)?;
    let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    let format = arguments.format.unwrap_or_default();
    let file_name = arguments
        .file_name
        .clone()
        .unwrap_or_else(|| format.default_file_name().to_owned());
    if DestinationName::parse(&file_name).is_err() || file_name.contains('/') {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestSourceNameInvalid,
                "file_name must be one relative path component",
            )
            .at("$.request.arguments.file_name"),
        ]);
    }

    Ok(NormalizedOperation::AnalysisHunkDiffExport(
        NormalizedHunkDiffExport {
            diff,
            destination,
            file_name,
            format,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `analysis.table.decode` request left unsaid.
pub(super) fn table_decode(
    arguments: &crate::request::TableDecodeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    if arguments.rows == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "rows must be at least 1; a table of no rows is not a question",
            )
            .at("$.request.arguments.rows"),
        ]);
    }
    let maximum_rows = normalize_count(
        arguments.maximum_rows,
        limits.maximum_entries(),
        "maximum_rows",
        "rows",
        diagnostics,
    )?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;

    let record = normalize_record_layout(
        arguments.layout.as_deref(),
        arguments.type_id.as_deref(),
        envelope,
    )?;

    Ok(NormalizedOperation::AnalysisTableDecode(
        NormalizedTableDecode {
            source,
            record,
            offset: arguments.offset.unwrap_or(0),
            rows: arguments.rows,
            maximum_rows,
            maximum_input_bytes,
        },
    ))
}

/// Fill in what an `analysis.table.summarize` request left unsaid.
pub(super) fn table_summarize(
    arguments: &crate::request::TableSummarizeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    // A summary of nothing is not a question, and neither is a summary
    // of no rows.
    if arguments.sources.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "sources must name at least one table",
            )
            .at("$.request.arguments.sources"),
        ]);
    }
    if arguments.rows == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "rows must be at least 1; a table of no rows is not a question",
            )
            .at("$.request.arguments.rows"),
        ]);
    }
    // The cap on how many tables one request may compare is the shared
    // entry cap: each is a whole source read into memory, and the
    // comparison is over all of them at once.
    if arguments.sources.len() > limits.maximum_entries() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "sources names {} tables; this context compares at most {}",
                    arguments.sources.len(),
                    limits.maximum_entries()
                ),
            )
            .at("$.request.arguments.sources"),
        ]);
    }
    let mut sources = Vec::with_capacity(arguments.sources.len());
    for source in &arguments.sources {
        sources.push(normalize_source(source)?);
    }
    let maximum_rows = normalize_count(
        arguments.maximum_rows,
        limits.maximum_entries(),
        "maximum_rows",
        "rows",
        diagnostics,
    )?;
    let maximum_values = normalize_count(
        arguments.maximum_values,
        limits.maximum_entries(),
        "maximum_values",
        "values",
        diagnostics,
    )?;
    let maximum_differences = normalize_count(
        arguments.maximum_differences,
        limits.maximum_entries(),
        "maximum_differences",
        "differences",
        diagnostics,
    )?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let record = normalize_record_layout(
        arguments.layout.as_deref(),
        arguments.type_id.as_deref(),
        envelope,
    )?;

    Ok(NormalizedOperation::AnalysisTableSummarize(
        NormalizedTableSummarize {
            sources,
            record,
            offset: arguments.offset.unwrap_or(0),
            rows: arguments.rows,
            maximum_rows,
            maximum_values,
            maximum_differences,
            maximum_input_bytes,
        },
    ))
}

/// Fill in what an `analysis.strings.scan` request left unsaid.
pub(super) fn strings_scan(
    arguments: &crate::request::StringsScanArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let minimum_length = arguments
        .minimum_length
        .unwrap_or(amiga_core::strings::DEFAULT_MIN_LENGTH);
    if minimum_length == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "minimum_length must be at least 1; a run of zero characters is \
                 every position in the file",
            )
            .at("$.request.arguments.minimum_length"),
        ]);
    }
    Ok(NormalizedOperation::AnalysisStringsScan(
        NormalizedStringsScan {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk,
            minimum_length,
            contains: arguments.contains.clone(),
            maximum_strings: normalize_count(
                arguments.maximum_strings,
                limits.maximum_entries(),
                "maximum_strings",
                "strings",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.address.resolve` request left unsaid.
pub(super) fn address_resolve(
    arguments: &crate::request::AddressResolveArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AnalysisAddressResolve(
        NormalizedAddressResolve {
            value: arguments.value,
            origin: arguments.origin,
            anchor: match &arguments.anchor {
                None => None,
                Some(anchor) => Some(NormalizedHunkAnchor {
                    source: normalize_named_source(
                        &anchor.source,
                        "$.request.arguments.anchor.source.path",
                    )?,
                    hunk: anchor.hunk.unwrap_or(0),
                }),
            },
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.pointers.scan` request left unsaid.
pub(super) fn pointers_scan(
    arguments: &crate::request::PointerScanArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    // A scale of zero decodes every word to the origin, so every run of
    // words would read as a table pointing at one address. Refused
    // before a source is opened: the answer would be noise wearing the
    // shape of a result.
    if arguments.word_scale == Some(0) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "word_scale must be at least 1; a scale of zero decodes every word \
                 to the origin",
            )
            .at("$.request.arguments.word_scale"),
        ]);
    }
    if arguments.minimum_entries == Some(0) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "minimum_entries must be at least 1; a run of zero entries is every \
                 position in the hunk",
            )
            .at("$.request.arguments.minimum_entries"),
        ]);
    }
    Ok(NormalizedOperation::AnalysisPointersScan(
        NormalizedPointerScan {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk.unwrap_or(0),
            origin: arguments.origin.unwrap_or(0),
            minimum_entries: arguments
                .minimum_entries
                .unwrap_or(DEFAULT_MINIMUM_POINTER_ENTRIES),
            word_scale: arguments.word_scale,
            maximum_tables: normalize_count(
                arguments.maximum_tables,
                limits.maximum_entries(),
                "maximum_tables",
                "tables",
                diagnostics,
            )?,
            maximum_targets: normalize_count(
                arguments.maximum_targets,
                limits.maximum_entries(),
                "maximum_targets",
                "targets",
                diagnostics,
            )?,
            maximum_entry_offsets: normalize_count(
                arguments.maximum_entry_offsets,
                limits.maximum_entries(),
                "maximum_entry_offsets",
                "entry offsets",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.code.disassemble` request left unsaid.
pub(super) fn code_disassemble(
    arguments: &crate::request::CodeDisassembleArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    if arguments.region == CodeRegion::BootBlock {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "analysis.code.disassemble accepts hunk or raw code, not a boot block",
            )
            .at("$.request.arguments.region"),
        ]);
    }
    validate_code_region(
        arguments.region,
        arguments.hunk,
        arguments.expected_sha256.as_deref(),
    )?;
    // An odd start cannot be an instruction boundary: the MC68000
    // fetches on word boundaries and raises an address error otherwise.
    // Refused here rather than by the decoder, so the reason names the
    // argument rather than the sweep.
    let start = arguments.start.unwrap_or(0);
    if !start.is_multiple_of(2) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("start {start:#x} is odd; an instruction begins on a word boundary"),
            )
            .at("$.request.arguments.start"),
        ]);
    }
    if let Some(end) = arguments.end
        && end < start
    {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("end {end:#x} is below start {start:#x}"),
            )
            .at("$.request.arguments.end"),
        ]);
    }
    let entries = default_entries(&arguments.entries);
    Ok(NormalizedOperation::AnalysisCodeDisassemble(
        NormalizedCodeDisassemble {
            source: normalize_source(&arguments.source)?,
            region: arguments.region,
            hunk: arguments.hunk.unwrap_or(0),
            expected_sha256: arguments.expected_sha256.clone(),
            mode: arguments.mode,
            start,
            end: arguments.end,
            entries,
            origin: arguments.origin,
            maximum_instructions: normalize_count(
                arguments.maximum_instructions,
                limits.maximum_entries(),
                "maximum_instructions",
                "instructions",
                diagnostics,
            )?,
            maximum_edges: normalize_count(
                arguments.maximum_edges,
                limits.maximum_entries(),
                "maximum_edges",
                "edges",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.address.references` request left unsaid.
pub(super) fn address_references(
    arguments: &crate::request::AddressReferencesArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let entries = default_entries(&arguments.entries);
    Ok(NormalizedOperation::AnalysisAddressReferences(
        NormalizedAddressReferences {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk.unwrap_or(0),
            target: arguments.target,
            entries,
            origin: arguments.origin,
            maximum_references: normalize_count(
                arguments.maximum_references,
                limits.maximum_entries(),
                "maximum_references",
                "references",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.code.callgraph` request left unsaid.
pub(super) fn code_callgraph(
    arguments: &crate::request::CodeCallgraphArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let entries = default_entries(&arguments.entries);
    Ok(NormalizedOperation::AnalysisCodeCallgraph(
        NormalizedCodeCallgraph {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk.unwrap_or(0),
            entries,
            origin: arguments.origin,
            maximum_nodes: normalize_count(
                arguments.maximum_nodes,
                limits.maximum_entries(),
                "maximum_nodes",
                "nodes",
                diagnostics,
            )?,
            maximum_edges: normalize_count(
                arguments.maximum_edges,
                limits.maximum_entries(),
                "maximum_edges",
                "edges",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.code.facts` request left unsaid.
pub(super) fn code_facts(
    arguments: &crate::request::CodeFactsArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let base_register = arguments.base_register.unwrap_or(DEFAULT_BASE_REGISTER);
    if base_register > 7 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("base_register {base_register} is not an address register (A0-A7)"),
            )
            .at("$.request.arguments.base_register"),
        ]);
    }
    validate_code_region(
        arguments.region,
        arguments.hunk,
        arguments.expected_sha256.as_deref(),
    )?;
    Ok(NormalizedOperation::AnalysisCodeFacts(
        NormalizedCodeFacts {
            source: normalize_source(&arguments.source)?,
            region: arguments.region,
            hunk: arguments.hunk.unwrap_or(0),
            expected_sha256: arguments.expected_sha256.clone(),
            entries: default_entries(&arguments.entries),
            origin: arguments.origin,
            base_register,
            default_library: arguments.default_library.clone(),
            library_vectors: arguments.library_vectors.clone(),
            maximum_facts: normalize_count(
                arguments.maximum_facts,
                limits.maximum_entries(),
                "maximum_facts",
                "facts",
                diagnostics,
            )?,
            maximum_instructions: normalize_count(
                arguments.maximum_instructions,
                limits.maximum_entries(),
                "maximum_instructions",
                "instructions",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.code.globals` request left unsaid.
pub(super) fn code_globals(
    arguments: &crate::request::CodeGlobalsArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let base_register = arguments.base_register.unwrap_or(DEFAULT_BASE_REGISTER);
    // A0-A7 is the whole address-register file; anything else names no
    // register, and a scan through it would report nothing for a reason
    // the caller could not see.
    if base_register > 7 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("base_register {base_register} is not an address register (A0-A7)"),
            )
            .at("$.request.arguments.base_register"),
        ]);
    }
    Ok(NormalizedOperation::AnalysisCodeGlobals(
        NormalizedCodeGlobals {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk.unwrap_or(0),
            entries: default_entries(&arguments.entries),
            origin: arguments.origin,
            base_register,
            derived: arguments.derived,
            maximum_accesses: normalize_count(
                arguments.maximum_accesses,
                limits.maximum_entries(),
                "maximum_accesses",
                "accesses",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.code.fixed-point` request left unsaid.
pub(super) fn code_fixed_point(
    arguments: &crate::request::CodeFixedPointArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AnalysisCodeFixedPoint(
        NormalizedCodeFixedPoint {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk.unwrap_or(0),
            entries: default_entries(&arguments.entries),
            origin: arguments.origin,
            maximum_hints: normalize_count(
                arguments.maximum_hints,
                limits.maximum_entries(),
                "maximum_hints",
                "hints",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.hunk.list` request left unsaid.
pub(super) fn hunk_list(
    arguments: &crate::request::HunkListArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AnalysisHunkList(NormalizedHunkList {
        source: normalize_source(&arguments.source)?,
        maximum_relocations: normalize_count(
            arguments.maximum_relocations,
            limits.maximum_entries(),
            "maximum_relocations",
            "relocations",
            diagnostics,
        )?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    }))
}

/// Fill in what an `analysis.hunk.normalize` request left unsaid.
pub(super) fn hunk_normalize(
    arguments: &crate::request::HunkNormalizeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AnalysisHunkNormalize(
        NormalizedHunkNormalize {
            source: normalize_source(&arguments.source)?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.hunk.normalize.export` request left unsaid.
pub(super) fn hunk_normalize_export(
    arguments: &crate::request::HunkNormalizeExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let normalize = NormalizedHunkNormalize {
        source: normalize_source(&arguments.normalize.source)?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.normalize.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    };
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_NORMALIZED_FILE_NAME,
    )?;
    Ok(NormalizedOperation::AnalysisHunkNormalizeExport(
        NormalizedHunkNormalizeExport {
            normalize,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fully resolved `analysis.state.snapshot` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedStateSnapshot {
    pub project: NormalizedProject,
    pub image: Option<String>,
    pub regions: Vec<NormalizedStateRegion>,
    pub registers: Option<crate::response::SandboxRegisters>,
    pub hunk_bases: Vec<crate::request::HunkBase>,
    pub maximum_fields: usize,
    pub maximum_input_bytes: u64,
}

/// One resolved memory range a snapshot reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedStateRegion {
    pub address: u32,
    pub source: NormalizedSource,
    pub sha256: Option<String>,
    pub offset: u32,
    pub length: Option<u32>,
}

/// Fully resolved `analysis.state.compare` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedStateCompare {
    pub snapshots: Vec<NormalizedSource>,
    pub maximum_differences: usize,
    pub maximum_input_bytes: u64,
}

/// The canonical form of one `analysis.state.snapshot`.
pub(super) fn state_snapshot_document(snapshot: &NormalizedStateSnapshot) -> Value {
    json!({
        "project": snapshot.project.path.as_str(),
        "image": snapshot.image,
        "regions": snapshot.regions
            .iter()
            .map(|region| json!({
                "address": region.address,
                "source": region.source.canonical(),
                "sha256": region.sha256,
                "offset": region.offset,
                "length": region.length,
            }))
            .collect::<Vec<_>>(),
        // The register file is part of the question: a base-register global's
        // address is a register plus a displacement, so two snapshots taken
        // with different A5 describe different bytes.
        "registers": snapshot.registers.as_ref().map(|registers| json!({
            "d": registers.d,
            "a": registers.a,
            "usp": registers.usp,
            "ssp": registers.ssp,
            "pc": registers.pc,
            "sr": registers.sr,
        })),
        "hunk_bases": snapshot.hunk_bases
            .iter()
            .map(|base| json!({ "hunk": base.hunk, "address": base.address }))
            .collect::<Vec<_>>(),
        "maximum_fields": snapshot.maximum_fields,
        "maximum_input_bytes": snapshot.maximum_input_bytes,
    })
}

/// The canonical form of one `analysis.state.compare`.
///
/// The order is part of the question rather than a detail of how it was asked:
/// a difference reports one value per snapshot positionally, so two requests
/// naming the same files in a different order produce answers a reader cannot
/// interchange.
pub(super) fn state_compare_document(compare: &NormalizedStateCompare) -> Value {
    json!({
        "snapshots": compare.snapshots
            .iter()
            .map(NormalizedSource::canonical)
            .collect::<Vec<_>>(),
        "maximum_differences": compare.maximum_differences,
        "maximum_input_bytes": compare.maximum_input_bytes,
    })
}

/// Fields reported when the request names no cap.
const DEFAULT_REPORTED_FIELDS: usize = 4096;

/// Differences reported when the request names no cap.
const DEFAULT_REPORTED_STATE_DIFFERENCES: usize = 256;

/// Fill in what an `analysis.state.snapshot` request left unsaid.
pub(super) fn state_snapshot(
    arguments: &crate::request::StateSnapshotArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let project = super::normalize_project(envelope.project.as_ref())?;
    if arguments.regions.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a snapshot needs at least one region of memory; one with none would \
                 report every variable as unreadable",
            )
            .at("$.request.arguments.regions"),
        ]);
    }
    let mut regions = Vec::with_capacity(arguments.regions.len());
    for (index, region) in arguments.regions.iter().enumerate() {
        let at = |field: &str| format!("$.request.arguments.regions[{index}].{field}");
        if region.length == Some(0) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "a region must cover at least one byte",
                )
                .at(at("length")),
            ]);
        }
        if let Some(sha256) = &region.sha256
            && (sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "a pinned region states a 64-character lowercase hex SHA-256",
                )
                .at(at("sha256")),
            ]);
        }
        regions.push(NormalizedStateRegion {
            address: region.address,
            source: normalize_named_source(&region.source, "$.request.arguments.regions")?,
            sha256: region.sha256.clone(),
            offset: region.offset.unwrap_or(0),
            length: region.length,
        });
    }
    Ok(NormalizedOperation::AnalysisStateSnapshot(
        NormalizedStateSnapshot {
            project,
            image: arguments.image.clone(),
            regions,
            registers: arguments.registers,
            hunk_bases: arguments.hunk_bases.clone(),
            maximum_fields: normalize_count(
                arguments.maximum_fields.or(Some(DEFAULT_REPORTED_FIELDS)),
                limits.maximum_entries(),
                "maximum_fields",
                "fields",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `analysis.state.compare` request left unsaid.
pub(super) fn state_compare(
    arguments: &crate::request::StateCompareArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    if arguments.snapshots.len() < 2 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a comparison needs at least two snapshots; one compared against nothing \
                 has no answer",
            )
            .at("$.request.arguments.snapshots"),
        ]);
    }
    let mut snapshots = Vec::with_capacity(arguments.snapshots.len());
    for snapshot in &arguments.snapshots {
        snapshots.push(normalize_named_source(
            snapshot,
            "$.request.arguments.snapshots",
        )?);
    }
    Ok(NormalizedOperation::AnalysisStateCompare(
        NormalizedStateCompare {
            snapshots,
            maximum_differences: arguments
                .maximum_differences
                .unwrap_or(DEFAULT_REPORTED_STATE_DIFFERENCES),
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}
