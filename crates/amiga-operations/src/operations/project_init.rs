//! `project.init` — create a project document set from chosen source files.
//!
//! The write path the format never had. Every reader was built and every
//! document kind specified, but the only code that produced a document set was
//! the legacy `amiga-re.toml` import: a project could be read, edited and
//! verified, and could not be started.
//!
//! Three decisions are worth stating here rather than leaving to the reader.
//!
//! **Every document the edit path will ever touch is created here, empty.**
//! `EditPlan` reads each document it is given and writes only what it read, so
//! it can modify a document set and cannot grow one. A project created without
//! an `annotations`, `resources` or `types` document would leave the first
//! annotation, the first resource and the first type definition with nowhere to
//! go, and the fix would be smuggling document *creation* into the edit path —
//! losing exactly the conflict check that path exists for.
//!
//! **A whole-file object still carries a selector.** `Selector::Range { 0, size
//! }`, never `None`: `verify` reports a selector-less object as unrecoverable,
//! so omitting it would make every new project fail its own verification the
//! moment it was created.
//!
//! **There is no replace, and that is now a decision rather than a
//! limitation.** Writing a fresh set root-last is safe because nothing
//! announces the project until the root exists. Replacing one was originally
//! unsafe for a second reason — the old root would stay in place while its
//! documents were overwritten one at a time, so a failure halfway left a root
//! indexing a mixture of two sets — and that reason is gone: every write is
//! staged under its destination and installed with renames, and a failure
//! part-way through puts back what it had already replaced
//! (`amiga_core::install`).
//!
//! What is left is the reason that never depended on the write path: discarding
//! a reviewed project is a decision a person should make deliberately, and the
//! deliberate act is removing the directory. A `--replace` flag would move that
//! decision into a request argument, where it becomes something a script can do
//! by accident to the wrong path — and the whole tree, not one file. So the
//! refusal stands and names the remedy, rather than offering a flag that reads
//! as "delete my repository". Do not re-derive the opposite decision merely
//! from the fact that staging now exists.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedMode, NormalizedProjectInit};
use crate::output::{DestinationKind, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::{MediaPolicy, OperationName};
use crate::response::{InitializedSource, OperationOutcome, OperationResult, ProjectInitResult};
use crate::source::SourceError;

/// The root document's file name, and the file whose presence means "a project
/// already lives here".
const ROOT_DOCUMENT: &str = crate::PROJECT_ROOT_DOCUMENT;
const SOURCES_DOCUMENT: &str = "analysis/sources.json";
const ANNOTATIONS_DOCUMENT: &str = "analysis/annotations/main.json";
const RESOURCES_DOCUMENT: &str = "analysis/resources/main.json";
const TYPES_DOCUMENT: &str = "analysis/types/main.json";
const PROGRAMS_DOCUMENT: &str = "analysis/programs/main.json";

/// One source, resolved and pinned, with everything the documents need.
struct PreparedSource {
    id: String,
    object_id: String,
    display_name: String,
    size: u64,
    sha256: String,
    /// Project-relative location to record, when there is one.
    location: Option<String>,
    /// Host path to bind locally, when the source stays outside the root.
    local_binding: Option<String>,
    /// The bytes to copy in, under `MediaPolicy::Copy`.
    copy_to: Option<(String, Vec<u8>)>,
    /// The loadable image this source is, when it is one.
    ///
    /// `None` for a source that does not parse as a HUNK executable — a disk
    /// image, a sample, a raw stage — and that is not a failure. A project says
    /// what it knows; inventing a program for bytes that are not one would be
    /// the opposite of what the format is for.
    image: Option<PreparedImage>,
}

/// A HUNK executable's layout, as the parse reports it.
struct PreparedImage {
    /// Allocation size of each segment, in hunk order.
    ///
    /// The allocation size rather than the file size: a BSS hunk occupies
    /// memory and no file bytes, and a nominal layout that skipped it would put
    /// every later hunk at the wrong address.
    segments: Vec<u64>,
}

pub(crate) fn run(
    request: &NormalizedProjectInit,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::ProjectInit,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let fail = |code, message: String, diagnostics: &mut Vec<Diagnostic>| {
        diagnostics.push(Diagnostic::error(code, message));
        diagnostics.clone()
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                crate::output::DestinationError::Unavailable => {
                    DiagnosticCode::OutputDestinationUnavailable
                }
                crate::output::DestinationError::Unusable { .. } => {
                    DiagnosticCode::OutputDestinationUnusable
                }
            };
            return outcome(
                Status::Error,
                fail(code, error.to_string(), &mut diagnostics),
                None,
            );
        }
    };

    // Checked before anything is read, because it is the cheapest refusal and
    // the one a caller is most likely to hit.
    if destination.join(ROOT_DOCUMENT).exists() {
        return outcome(
            Status::Error,
            fail(
                DiagnosticCode::OutputDestinationRefused,
                format!(
                    "a project already exists at {:?}; `project.init` does not replace one. \
                     Remove that project directory yourself if you mean to discard it: \
                     replacing a reviewed project is a deliberate act rather than a flag",
                    request.destination.as_str()
                ),
                &mut diagnostics,
            ),
            None,
        );
    }

    let prepared = match prepare_sources(request, context, &destination, &diagnostics) {
        Ok(prepared) => prepared,
        Err(outcome_diagnostics) => return outcome(Status::Error, outcome_diagnostics, None),
    };
    events.emit(OperationEvent::Progress {
        phase: "resolve_sources",
        completed: prepared.len() as u64,
        total: Some(prepared.len() as u64),
    });

    let project_id = format!("project:{}", amiga_project::safe_component(&request.name));
    let documents = build_documents(request, &project_id, &prepared);

    // Every file the plan would write, documents and copied media alike. The
    // root is in here too: it is written last, but it is reviewed with the rest.
    let mut files: Vec<(String, Vec<u8>)> = documents.clone();
    for source in &prepared {
        if let Some((path, bytes)) = &source.copy_to {
            files.push((path.clone(), bytes.clone()));
        }
    }
    if let Some(bindings) = local_bindings_document(&prepared) {
        files.push((crate::local::LOCAL_BINDINGS_PATH.to_owned(), bindings));
    }

    // The guarantee the digest suffix only makes probable: two sources whose
    // ids convert to one directory would silently share it.
    let mut seen = BTreeSet::new();
    for (path, _) in &files {
        if !seen.insert(path.clone()) {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::OutputDestinationRefused,
                    format!("two planned outputs claim {path:?}"),
                    &mut diagnostics,
                ),
                None,
            );
        }
    }

    let plan = WritePlan::new(
        &request.destination,
        DestinationKind::Directory,
        crate::output::OutputPolicy::CreateOnly,
        files
            .iter()
            .map(|(path, bytes)| PlannedOutput {
                path: path.clone(),
                size: bytes.len() as u64,
                sha256: amiga_core::sha256(bytes),
            })
            .collect(),
        Vec::new(),
    );

    let result = |committed, written| {
        Some(OperationResult::ProjectInit(ProjectInitResult {
            project_id: project_id.clone(),
            name: request.name.clone(),
            media: request.media,
            sources: prepared
                .iter()
                .map(|source| InitializedSource {
                    id: source.id.clone(),
                    object_id: source.object_id.clone(),
                    display_name: source.display_name.clone(),
                    size: source.size,
                    sha256: source.sha256.clone(),
                    location: source.location.clone(),
                    bound_locally: source.local_binding.is_some(),
                })
                .collect(),
            plan: plan.clone(),
            committed,
            written,
        }))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(false, Vec::new()));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::RequestExecutionModeUnsupported,
                    "`project.init` writes; ask for `prepare` or `commit_reviewed`".to_owned(),
                    &mut diagnostics,
                ),
                None,
            );
        }
    };

    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this project, which now has \
                 digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(false, Vec::new()));
    }

    match commit(&destination, &files) {
        Ok(written) => {
            events.emit(OperationEvent::Progress {
                phase: "commit",
                completed: written.len() as u64,
                total: Some(files.len() as u64),
            });
            outcome(Status::Success, diagnostics, result(true, written))
        }
        Err(error) => outcome(
            Status::Conflict,
            fail(
                DiagnosticCode::OutputDestinationRefused,
                error,
                &mut diagnostics,
            ),
            None,
        ),
    }
}

/// Resolve, pin and place every source.
fn prepare_sources(
    request: &NormalizedProjectInit,
    context: &ExecutionContext<'_>,
    destination: &Path,
    diagnostics: &[Diagnostic],
) -> Result<Vec<PreparedSource>, Vec<Diagnostic>> {
    let limits = context.limits();
    let mut prepared: Vec<PreparedSource> = Vec::with_capacity(request.sources.len());
    let mut ids = BTreeSet::new();
    let mut total_bytes = 0_u64;

    for name in &request.sources {
        let resolved = context
            .resolver()
            .resolve(name, request.maximum_input_bytes)
            .map_err(|error| {
                let code = match error {
                    SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                    SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                    SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
                };
                let mut carried = diagnostics.to_vec();
                carried.push(Diagnostic::error(code, error.to_string()));
                carried
            })?;

        // The aggregate ceiling, which the per-source one cannot express: a
        // hundred legal sources are still an illegal amount of memory.
        total_bytes = total_bytes.saturating_add(resolved.size());
        if total_bytes > limits.maximum_total_input_bytes() {
            let mut carried = diagnostics.to_vec();
            carried.push(Diagnostic::error(
                DiagnosticCode::LimitExceeded,
                format!(
                    "the chosen sources total at least {total_bytes} bytes, over the ceiling \
                     of {}; register fewer, or raise the context's `maximum_total_input_bytes`",
                    limits.maximum_total_input_bytes()
                ),
            ));
            return Err(carried);
        }

        let display_name = name
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or(name.as_str())
            .to_owned();
        let id = format!("source:{}", amiga_project::safe_component(&display_name));
        if !ids.insert(id.clone()) {
            let mut carried = diagnostics.to_vec();
            carried.push(Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                format!(
                    "two sources derive the id {id:?}; rename one, because a project cannot \
                     hold two things under one identity"
                ),
            ));
            return Err(carried);
        }
        let component = amiga_project::path_component(&id);

        let (location, local_binding, copy_to) = match request.media {
            MediaPolicy::Copy => {
                let path = format!("original/{component}/{display_name}");
                (
                    Some(path.clone()),
                    None,
                    Some((path, resolved.bytes().to_vec())),
                )
            }
            MediaPolicy::InPlace => match in_place_location(context, name, destination) {
                InPlace::UnderRoot(relative) => (Some(relative), None, None),
                InPlace::Outside(host) => (None, Some(host), None),
            },
        };

        // Whether this source *is* a loadable image, asked of the bytes rather
        // than of a person. A whole-file HUNK executable needs no new
        // vocabulary and no guessing: its whole-file object is the image, and
        // the parse reports every segment's allocation size. Anything that does
        // not parse gets no program and says nothing about one.
        let image = amiga_hunk::Executable::parse(resolved.bytes())
            .ok()
            .map(|executable| PreparedImage {
                segments: executable
                    .segments
                    .iter()
                    .map(|segment| segment.allocation_size as u64)
                    .collect(),
            })
            .filter(|image| !image.segments.is_empty());

        prepared.push(PreparedSource {
            object_id: format!("object:{}/whole", amiga_project::safe_component(&id)),
            id,
            display_name,
            size: resolved.size(),
            sha256: resolved.sha256().to_owned(),
            location,
            local_binding,
            copy_to,
            image,
        });
    }

    prepared.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(prepared)
}

/// Where an `in_place` source sits relative to the project root.
enum InPlace {
    /// Under the root, so a project-relative location describes it on any
    /// machine.
    UnderRoot(String),
    /// Outside it, so only this machine can say where it is.
    Outside(String),
}

fn in_place_location(
    context: &ExecutionContext<'_>,
    name: &crate::source::SourceName,
    destination: &Path,
) -> InPlace {
    let host = context.resolver().root().map_or_else(
        || PathBuf::from(name.as_str()),
        |root| root.join(name.as_str()),
    );
    match host.strip_prefix(destination) {
        Ok(relative) => InPlace::UnderRoot(relative.to_string_lossy().replace('\\', "/")),
        Err(_) => InPlace::Outside(host.to_string_lossy().into_owned()),
    }
}

/// The four documents, as `(path, bytes)` in write order — root last.
fn build_documents(
    request: &NormalizedProjectInit,
    project_id: &str,
    sources: &[PreparedSource],
) -> Vec<(String, Vec<u8>)> {
    let sources_document = json!({
        "$schema": "schema/sources.schema.json",
        "document_kind": "sources",
        "format_version": amiga_project::FORMAT_VERSION,
        "sources": sources
            .iter()
            .map(|source| {
                let mut value = json!({
                    "id": source.id,
                    "kind": "file",
                    "display_name": source.display_name,
                    "size": source.size,
                    "sha256": source.sha256,
                });
                if let (Some(location), Some(map)) = (&source.location, value.as_object_mut()) {
                    map.insert(
                        "locations".to_owned(),
                        json!([{ "kind": "project_relative", "path": location }]),
                    );
                }
                value
            })
            .collect::<Vec<_>>(),
        "objects": sources
            .iter()
            .map(|source| json!({
                "id": source.object_id,
                "kind": "whole_source",
                "parent_id": source.id,
                // Never `None`: an object with no selector verifies as
                // unrecoverable, so a project created without one would fail
                // its own verification immediately.
                "selector": { "container": "range", "offset": 0, "length": source.size },
                "size": source.size,
                "sha256": source.sha256,
            }))
            .collect::<Vec<_>>(),
    });

    let empty = |kind: &str, field: &str, schema: &str| {
        json!({
            "$schema": schema,
            "document_kind": kind,
            "format_version": amiga_project::FORMAT_VERSION,
            field: [],
        })
    };

    let programs = programs_document(request, sources);

    let root = json!({
        "$schema": "analysis/schema/project.schema.json",
        "document_kind": "project",
        "format_version": amiga_project::FORMAT_VERSION,
        "project": { "id": project_id, "name": request.name },
        "documents": {
            "sources": SOURCES_DOCUMENT,
            "programs": if programs.is_some() { vec![PROGRAMS_DOCUMENT] } else { Vec::new() },
            "annotations": [ANNOTATIONS_DOCUMENT],
            "resources": [RESOURCES_DOCUMENT],
            "types": [TYPES_DOCUMENT],
        },
        "directories": {
            "original": "original",
            "extracted": "extracted",
            "decoded": "decoded",
            // Declared by every new project, because a role nothing writes is
            // a role nobody uses: `project.edit` has no scope for the root
            // document, so a project that did not state this at creation could
            // only gain it by hand-editing the one document the format keeps
            // small. Declaring where provisional outputs go costs nothing —
            // none of these four directories is created here — and it is what
            // lets `call --poke-artifact` replay a checkpoint by name.
            "scratch": "work-in-progress",
        },
    });

    let encode = |value: &serde_json::Value| amiga_project::format_document(value).into_bytes();
    let mut documents = vec![
        (SOURCES_DOCUMENT.to_owned(), encode(&sources_document)),
        (
            ANNOTATIONS_DOCUMENT.to_owned(),
            encode(&empty(
                "annotations",
                "annotations",
                "../schema/annotations.schema.json",
            )),
        ),
        (
            RESOURCES_DOCUMENT.to_owned(),
            encode(&empty(
                "resources",
                "resources",
                "../schema/resources.schema.json",
            )),
        ),
        (
            TYPES_DOCUMENT.to_owned(),
            encode(&empty("types", "types", "../schema/types.schema.json")),
        ),
    ];
    // Before the root, like every other document: the root is what announces
    // the project, so nothing it indexes may be written after it.
    if let Some(programs) = &programs {
        documents.push((PROGRAMS_DOCUMENT.to_owned(), encode(programs)));
    }
    documents.push((ROOT_DOCUMENT.to_owned(), encode(&root)));
    documents
}

/// The `programs` document, when any source is a loadable image.
///
/// A HUNK executable needs no new vocabulary and no guessing: its whole-file
/// object *is* the image, and the parse reports every segment's allocation
/// size. What it does *not* report is where those segments land in memory —
/// AmigaDOS `LoadSeg` allocates each one wherever it can, so a relocatable
/// executable has no inherent runtime address at all.
///
/// So the load map written here is nominal and says so in its name: hunk 0 at
/// zero and each later hunk after the one before it. It exists because the
/// runtime frame needs *a* map before anything can be said in it, and because
/// stating a layout a reader can see is nominal is better than leaving runtime
/// space with no producer. An observed layout — from a boot trace, or from a
/// person who knows where the loader puts it — is a second map beside this one,
/// which is exactly why a load map is named rather than assumed unique.
///
/// `None` when no source parses as an executable, and the root then indexes no
/// programs document rather than an empty one: a project with no programs and a
/// project whose programs document is empty are the same claim, and writing the
/// shorter one avoids pretending the question was asked and answered.
fn programs_document(
    request: &NormalizedProjectInit,
    sources: &[PreparedSource],
) -> Option<serde_json::Value> {
    let images: Vec<serde_json::Value> = sources
        .iter()
        .filter_map(|source| {
            let image = source.image.as_ref()?;
            let component = amiga_project::safe_component(&source.id);
            let mut base: u64 = 0;
            let segments: Vec<serde_json::Value> = image
                .segments
                .iter()
                .enumerate()
                .map(|(hunk, size)| {
                    let segment = json!({
                        "hunk": hunk as u32,
                        "runtime_base": format!("{base:#010x}"),
                    });
                    base = base.saturating_add(*size);
                    segment
                })
                .collect();
            Some(json!({
                "id": format!("image:{component}"),
                "object_id": source.object_id,
                "format": "hunk",
                "architecture": "mc68000",
                "load_maps": [{
                    "id": format!("loadmap:{component}/nominal"),
                    "name": "Nominal contiguous layout",
                    "segments": segments,
                    // A HUNK executable's entry is the first byte of its first
                    // hunk. Under the nominal layout that is address zero.
                    "entry_points": [{ "address": "0x00000000", "role": "program_entry" }],
                }],
            }))
        })
        .collect();
    if images.is_empty() {
        return None;
    }
    Some(json!({
        "$schema": "../schema/program.schema.json",
        "document_kind": "program",
        "format_version": amiga_project::FORMAT_VERSION,
        "id": "program:main",
        "name": request.name,
        "notes": "Written by `project.init` from the HUNK parse of each source that is an \
                  executable. Every load map here is the nominal contiguous layout derived from \
                  segment sizes, not an address anyone observed: a relocatable executable has no \
                  inherent runtime base. Record an observed layout as a second load map rather \
                  than by editing this one.",
        "images": images,
    }))
}

/// The machine-local bindings document, when any source needs one.
fn local_bindings_document(sources: &[PreparedSource]) -> Option<Vec<u8>> {
    let mut document = crate::local::LocalBindings::new();
    for source in sources {
        if let Some(host) = &source.local_binding {
            document = document.with_binding(source.id.clone(), host.clone());
        }
    }
    if document.bindings.is_empty() {
        return None;
    }
    serde_json::to_vec_pretty(&document).ok()
}

/// Write every file, root last.
///
/// A failure partway leaves a directory with no root document, which does not
/// present itself as a project — the outcome the ordering exists to produce.
fn commit(destination: &Path, files: &[(String, Vec<u8>)]) -> Result<Vec<String>, String> {
    let mut ordered: Vec<&(String, Vec<u8>)> = files.iter().collect();
    ordered.sort_by_key(|(path, _)| (path == ROOT_DOCUMENT, path.clone()));

    let mut written = Vec::with_capacity(ordered.len());
    for (path, bytes) in ordered {
        let target = destination.join(path);
        amiga_core::safepath::prepare_output_file(&target, false)
            .map_err(|error| format!("{path}: {error}"))?;
        std::fs::write(&target, bytes).map_err(|error| format!("{path}: {error}"))?;
        written.push(path.clone());
    }
    Ok(written)
}
