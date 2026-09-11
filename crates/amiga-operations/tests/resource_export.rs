//! `project.resource.export` over every resource kind and every target space.
//!
//! The export path was real and narrower than the vocabulary it served: it
//! resolved an `object` target only, and produced a file for five of the nine
//! resource kinds. The three it refused — `table`, `code` and `copper` — have
//! decoders in this workspace that nothing routed here, and the two target
//! spaces it refused are arithmetic the project already knows how to do.
//!
//! Two properties are asserted throughout, and they are the ones that make the
//! widening worth having rather than merely larger:
//!
//! **A listing is the routed operation's answer.** Every instruction, row and
//! Copper op in an exported file has to be one `analysis.code.disassemble`,
//! `analysis.table.decode` or `hardware.copper.decode` produced from the same
//! bytes. A second decoder that agreed with the first today is the divergence
//! this whole layer exists to prevent.
//!
//! **A target space is a way of naming bytes, not of choosing them.** The same
//! range named as an object range, a hunk offset and a runtime address must
//! export the same file.

use std::path::{Path, PathBuf};

use amiga_operations::{
    ExecutionContext, ExecutionMode, FilesystemDestinationResolver, FilesystemSourceResolver,
    InMemorySourceResolver, MediaPolicy, OperationRequestDocument, ProjectEdit,
    ProjectEditArguments, ProjectEditTarget, ProjectInitArguments, ProjectLocator, RequestEnvelope,
    ResolvedSource, ResourceExportArguments, Router, SourceName, Status,
};

/// Where hunk zero's bytes start in the images this file builds.
///
/// Eight header longwords, then the `HUNK_CODE` tag and its size: the layout
/// `amiga-hunk`'s own `parses_a_minimal_code_hunk` pins.
const CODE_FILE_OFFSET: u64 = 32;

/// A one-hunk LoadSeg image whose CODE hunk holds `code`.
///
/// The code is padded to a longword, because a hunk's size is declared in
/// longwords and a parser that read a short one would be reading the header of
/// whatever follows.
fn image(code: &[u8]) -> Vec<u8> {
    let mut body = code.to_vec();
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let longwords = (body.len() / 4) as u32;
    let mut bytes = Vec::new();
    for word in [
        0x03f3_u32, // HUNK_HEADER
        0,          // no resident library names
        1,          // one hunk in the table
        0,          // first hunk
        0,          // last hunk
        longwords,  // allocation, in longwords
        0x03e9,     // HUNK_CODE
        longwords,  // size, in longwords
    ] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&0x03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// The CODE hunk's contents: instructions, then a Copper list, then a table.
///
/// One hunk rather than three files, so that every target space below names a
/// range of one image and the spaces are the only thing that differs.
fn code_hunk() -> Vec<u8> {
    let mut bytes = Vec::new();
    // 0x00: `moveq #1,d0` then `rts` — eight bytes of unambiguous MC68000.
    bytes.extend_from_slice(&0x7001_u16.to_be_bytes());
    bytes.extend_from_slice(&0x4e75_u16.to_be_bytes());
    bytes.extend_from_slice(&0x7002_u16.to_be_bytes());
    bytes.extend_from_slice(&0x4e75_u16.to_be_bytes());
    // 0x08: a Copper list — two colour writes and the terminating wait.
    for word in [
        0x0180_u16, 0x0f00, // COLOR00 = red
        0x0182, 0x00f0, // COLOR01 = green
        0xffff, 0xfffe, // WAIT for a beam that never comes
    ] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    // 0x14: four records of `u16,u16`.
    for record in 0..4_u16 {
        bytes.extend_from_slice(&record.to_be_bytes());
        bytes.extend_from_slice(&(record * 10).to_be_bytes());
    }
    bytes
}

const CODE_OFFSET: u64 = 0x00;
const CODE_LENGTH: u64 = 0x08;
const COPPER_OFFSET: u64 = 0x08;
const COPPER_LENGTH: u64 = 0x0c;
const TABLE_OFFSET: u64 = 0x14;
const TABLE_LENGTH: u64 = 0x10;

/// A scratch project holding one program image, with every resource below
/// defined against it.
fn project(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("amiga-re-export-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("program.bin"), image(&code_hunk()))
        .unwrap_or_else(|error| panic!("{error}"));

    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = OperationRequestDocument::ProjectInit(
        ProjectInitArguments::new("Export fixture", "work", vec!["program.bin".to_owned()])
            .with_media(MediaPolicy::Copy),
    );
    commit(&context, document);
    base
}

/// Prepare a write, then commit exactly the plan the prepare produced.
fn commit(
    context: &ExecutionContext<'_>,
    document: OperationRequestDocument,
) -> amiga_operations::OperationOutcome {
    // `project.init` creates the project rather than running against one, so it
    // is the one write here that must not carry a locator.
    let locate = |envelope: &mut RequestEnvelope| {
        if !matches!(envelope.request, OperationRequestDocument::ProjectInit(_)) {
            envelope.project = Some(ProjectLocator::Path {
                path: "work".to_owned(),
            });
        }
    };
    let mut prepare = RequestEnvelope::read(document.clone());
    prepare.execution.mode = ExecutionMode::Prepare;
    locate(&mut prepare);
    let prepared = Router::execute(&prepare, context);
    assert!(
        matches!(prepared.status, Status::Success | Status::Prepared),
        "{:?}",
        prepared.diagnostics
    );
    let digest = plan_digest(&prepared);

    let mut envelope = RequestEnvelope::read(document);
    envelope.execution.mode = ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    locate(&mut envelope);
    let committed = Router::execute(&envelope, context);
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );
    committed
}

/// The plan digest a prepared write reported, whichever write it was.
fn plan_digest(outcome: &amiga_operations::OperationOutcome) -> String {
    if let Some(init) = outcome.project_init() {
        return init.plan.plan_sha256.clone();
    }
    if let Some(edit) = outcome.project_edit() {
        return edit.plan_sha256.clone();
    }
    if let Some(export) = outcome.project_resource_export() {
        return export.plan.plan_sha256.clone();
    }
    panic!("the prepared write reported no plan: {:?}", outcome.status);
}

/// Apply `edits` to the project at `base`.
fn edit(base: &Path, edits: Vec<ProjectEdit>) {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    commit(
        &context,
        OperationRequestDocument::ProjectEdit(ProjectEditArguments::new(edits)),
    );
}

/// Export `resource` and return the file's contents as text.
fn export(base: &Path, resource: &str) -> String {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let outcome = commit(
        &context,
        OperationRequestDocument::ProjectResourceExport(ResourceExportArguments::new(resource)),
    );
    let written = outcome.project_resource_export().expect("an export");
    assert!(written.committed);
    let bytes = std::fs::read(base.join("work").join(&written.path))
        .unwrap_or_else(|error| panic!("{} is unreadable: {error}", written.path));
    assert_eq!(bytes.len() as u64, written.size);
    assert_eq!(amiga_core::sha256(&bytes), written.sha256);
    String::from_utf8(bytes).unwrap_or_else(|error| panic!("a listing is text: {error}"))
}

/// Run one read-only operation over `bytes`, exactly as the export does.
fn decode(bytes: &[u8], document: OperationRequestDocument) -> amiga_operations::OperationOutcome {
    let name = SourceName::parse("resource").expect("a usable name");
    let resolver = InMemorySourceResolver::new(ResolvedSource::new(name, bytes.into()));
    let context = ExecutionContext::new(&resolver);
    Router::execute(&RequestEnvelope::read(document), &context)
}

/// The object id `project.init` gave the one source.
fn object_id() -> String {
    "object:program.bin/whole".to_owned()
}

fn image_id() -> String {
    "image:program.bin".to_owned()
}

fn load_map_id() -> String {
    "loadmap:program.bin/nominal".to_owned()
}

/// Define one resource of `kind` over `target`, with `parameters`.
fn define(
    id: &str,
    kind: &str,
    target: ProjectEditTarget,
    parameters: serde_json::Map<String, serde_json::Value>,
) -> ProjectEdit {
    ProjectEdit::DefineResource {
        id: id.to_owned(),
        kind: kind.to_owned(),
        name: id.to_owned(),
        target,
        parameters,
        export_media_type: None,
        notes: None,
    }
}

fn parameters(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// A `code` resource exports the listing `analysis.code.disassemble` produces.
#[test]
fn a_code_resource_exports_the_listing_the_disassembler_produces() {
    let base = project("code");
    edit(
        &base,
        vec![define(
            "resource:entry",
            "code",
            ProjectEditTarget::Hunk {
                image_id: image_id(),
                hunk: 0,
                offset: CODE_OFFSET,
                length: CODE_LENGTH,
            },
            parameters(&[("architecture", serde_json::json!("mc68000"))]),
        )],
    );
    let listing = export(&base, "resource:entry");

    // Every instruction line is one the operation reported, in its order.
    let bytes = image(&code_hunk());
    let decoded = decode(
        &bytes,
        OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("resource")
                .in_hunk(0)
                .over_range(CODE_OFFSET as u32, Some((CODE_OFFSET + CODE_LENGTH) as u32)),
        ),
    );
    let expected = decoded
        .analysis_code_disassemble()
        .unwrap_or_else(|| panic!("{:?}", decoded.diagnostics));
    assert!(
        !expected.instructions.is_empty(),
        "the fixture must decode to something"
    );
    let rows: Vec<&str> = listing
        .lines()
        .filter(|line| !line.starts_with(';'))
        .collect();
    assert_eq!(rows.len(), expected.instructions.len());
    for (row, instruction) in rows.iter().zip(&expected.instructions) {
        assert!(
            row.contains(&instruction.text),
            "{row:?} does not carry {:?}",
            instruction.text
        );
        assert!(row.contains(&instruction.bytes), "{row:?}");
    }
    // The header says which bytes were read, so a reader can check them.
    assert!(listing.contains("resource:entry"), "{listing}");
    assert!(listing.contains("hunk 0"), "{listing}");

    let _ = std::fs::remove_dir_all(&base);
}

/// A `copper` resource exports what `hardware.copper.decode` decoded.
#[test]
fn a_copper_resource_exports_what_the_copper_decoder_decoded() {
    let base = project("copper");
    edit(
        &base,
        vec![define(
            "resource:palette-list",
            "copper",
            ProjectEditTarget::Hunk {
                image_id: image_id(),
                hunk: 0,
                offset: COPPER_OFFSET,
                length: COPPER_LENGTH,
            },
            parameters(&[]),
        )],
    );
    let listing = export(&base, "resource:palette-list");

    let hunk = code_hunk();
    let region = &hunk[COPPER_OFFSET as usize..(COPPER_OFFSET + COPPER_LENGTH) as usize];
    let decoded = decode(
        region,
        OperationRequestDocument::HardwareCopperDecode(
            amiga_operations::CopperDecodeArguments::new("resource"),
        ),
    );
    let expected = decoded
        .hardware_copper_decode()
        .unwrap_or_else(|| panic!("{:?}", decoded.diagnostics));
    let rows: Vec<&str> = listing
        .lines()
        .filter(|line| !line.starts_with(';'))
        .collect();
    assert_eq!(rows.len(), expected.instructions.len());
    // The register names are the hardware map's, which is what makes a Copper
    // listing readable rather than a column of hex.
    assert!(listing.contains("COLOR00"), "{listing}");
    assert!(listing.contains("MOVE"), "{listing}");
    assert!(listing.contains("WAIT"), "{listing}");

    let _ = std::fs::remove_dir_all(&base);
}

/// A `table` resource exports the rows `analysis.table.decode` decoded through
/// the type the resource names.
#[test]
fn a_table_resource_exports_the_rows_its_record_type_decodes() {
    let base = project("table");
    edit(
        &base,
        vec![
            ProjectEdit::DefineType {
                definition: serde_json::json!({
                    "kind": "integer",
                    "id": "type:u16",
                    "name": "u16",
                    "size": 2,
                    "signed": false,
                    "byte_order": "big",
                })
                .as_object()
                .expect("an object")
                .clone(),
            },
            ProjectEdit::DefineType {
                definition: serde_json::json!({
                    "kind": "struct",
                    "id": "type:record.levels",
                    "name": "levels",
                    "size": 4,
                    "fields": [
                        { "name": "index", "type_id": "type:u16", "offset": 0 },
                        { "name": "score", "type_id": "type:u16", "offset": 2 },
                    ],
                })
                .as_object()
                .expect("an object")
                .clone(),
            },
        ],
    );
    edit(
        &base,
        vec![define(
            "resource:levels",
            "table",
            ProjectEditTarget::Hunk {
                image_id: image_id(),
                hunk: 0,
                offset: TABLE_OFFSET,
                length: TABLE_LENGTH,
            },
            parameters(&[
                ("row_count", serde_json::json!(4)),
                ("row_stride", serde_json::json!(4)),
                ("type_id", serde_json::json!("type:record.levels")),
            ]),
        )],
    );
    let listing = export(&base, "resource:levels");

    let rows: Vec<&str> = listing
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), 4, "{listing}");
    // The fourth record is `(3, 30)`, which is the decode and not a coincidence
    // of the bytes being read as something else.
    assert!(rows[3].contains("3  30"), "{listing}");
    assert!(listing.contains("type:record.levels"), "{listing}");

    let _ = std::fs::remove_dir_all(&base);
}

/// The same bytes named three ways export the same file.
///
/// An object range, a hunk offset and a runtime address are three spellings of
/// one location. A target space that resolved to different bytes would produce
/// a file that is confidently wrong — which is why the two new spaces are
/// asserted against the one that already worked rather than against a listing
/// written out by hand.
#[test]
fn every_target_space_names_the_same_bytes() {
    let base = project("spaces");
    edit(
        &base,
        vec![
            define(
                "resource:by-object",
                "code",
                ProjectEditTarget::Object {
                    object_id: object_id(),
                    offset: CODE_FILE_OFFSET + CODE_OFFSET,
                    length: CODE_LENGTH,
                },
                parameters(&[("architecture", serde_json::json!("mc68000"))]),
            ),
            define(
                "resource:by-hunk",
                "code",
                ProjectEditTarget::Hunk {
                    image_id: image_id(),
                    hunk: 0,
                    offset: CODE_OFFSET,
                    length: CODE_LENGTH,
                },
                parameters(&[("architecture", serde_json::json!("mc68000"))]),
            ),
            define(
                "resource:by-runtime",
                "code",
                ProjectEditTarget::Runtime {
                    image_id: image_id(),
                    load_map_id: load_map_id(),
                    // Hunk zero's nominal base, which `project.init` wrote.
                    address: "0x00000000".to_owned(),
                    length: CODE_LENGTH,
                },
                parameters(&[("architecture", serde_json::json!("mc68000"))]),
            ),
        ],
    );

    let instructions = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| !line.starts_with(';'))
            .map(str::to_owned)
            .collect()
    };
    let by_object = instructions(&export(&base, "resource:by-object"));
    let by_hunk = instructions(&export(&base, "resource:by-hunk"));
    let by_runtime = instructions(&export(&base, "resource:by-runtime"));

    assert!(
        !by_object.is_empty(),
        "the fixture must decode to something"
    );
    assert_eq!(by_object, by_hunk, "a hunk offset named other bytes");
    assert_eq!(by_object, by_runtime, "a runtime address named other bytes");

    let _ = std::fs::remove_dir_all(&base);
}

/// A `table` with no record type is refused by name rather than written out as
/// bytes.
///
/// A file of undifferentiated bytes from a resource that claims to be a table
/// would be worse than a refusal: it would look like a successful export of
/// something that was never decoded.
#[test]
fn a_table_with_no_record_type_is_refused_rather_than_dumped() {
    let base = project("typeless");
    edit(
        &base,
        vec![define(
            "resource:untyped",
            "table",
            ProjectEditTarget::Hunk {
                image_id: image_id(),
                hunk: 0,
                offset: TABLE_OFFSET,
                length: TABLE_LENGTH,
            },
            parameters(&[
                ("row_count", serde_json::json!(4)),
                ("row_stride", serde_json::json!(4)),
            ]),
        )],
    );

    let sources = FilesystemSourceResolver::new(base.clone());
    let destinations = FilesystemDestinationResolver::new(base.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ProjectResourceExport(
        ResourceExportArguments::new("resource:untyped"),
    ));
    envelope.execution.mode = ExecutionMode::Prepare;
    envelope.project = Some(ProjectLocator::Path {
        path: "work".to_owned(),
    });
    let outcome = Router::execute(&envelope, &context);
    assert_eq!(outcome.status, Status::Error);
    let message = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(message.contains("type_id"), "{message}");

    let _ = std::fs::remove_dir_all(&base);
}
