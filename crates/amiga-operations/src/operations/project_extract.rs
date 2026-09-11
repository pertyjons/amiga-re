//! `project.extract` — take a project's registered carriers apart, into it.
//!
//! The step between "these files are mine" and "I can look inside them". Every
//! recovered member becomes an `Object` carrying the selector that reproduces
//! it, so the materialised file under `extracted/` is a convenience rather than
//! the only copy: delete the directory and `project.verify` still recovers
//! every object from its parent.
//!
//! **Extraction is not one operation, because a disk is not one thing.** Four
//! carrier cases, and the distinction that matters is where a name came from.
//! An LHA member name is read verbatim from an archive header, so it may not
//! declare a directory; an ADF path is assembled by the filesystem walk from
//! validated directory blocks, so it keeps its hierarchy. A HUNK executable
//! needs no extraction at all — the whole-file object already is the object.
//! And an ADF without a `DOS` tag has no filesystem to enumerate, so it
//! enumerates nothing and says so rather than appearing to have been covered.
//!
//! **Files first, documents last.** Neither write path is transactional, so the
//! ordering decides what a failure leaves behind: unreferenced bytes under
//! `extracted/`, which are inert, rather than a sources document naming objects
//! whose files were never written.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::json;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedMode, NormalizedProjectExtract};
use crate::output::{DestinationKind, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    CarrierReport, ExtractedObject, OperationOutcome, OperationResult, ProjectExtractResult,
};

/// One member recovered from a carrier, with everything the object needs.
struct Recovered {
    id: String,
    parent_id: String,
    kind: &'static str,
    selector: serde_json::Value,
    path: String,
    bytes: Vec<u8>,
}

pub(crate) fn run(
    request: &NormalizedProjectExtract,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::ProjectExtract,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let fail = |code, message: String, diagnostics: &mut Vec<Diagnostic>| {
        diagnostics.push(Diagnostic::error(code, message));
        diagnostics.clone()
    };

    let Some(root) = context
        .resolver()
        .root()
        .map(|root| root.join(request.project.path.as_str()))
    else {
        return outcome(
            Status::Error,
            fail(
                DiagnosticCode::ProjectUnreadable,
                "this context serves no directory, so no project can be located".to_owned(),
                &mut diagnostics,
            ),
            None,
        );
    };
    let loaded = match amiga_project::load(&root) {
        Ok(loaded) => loaded,
        Err(error) => {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::ProjectUnreadable,
                    error.to_string(),
                    &mut diagnostics,
                ),
                None,
            );
        }
    };

    let (bindings, binding_diagnostics) = crate::local::load_bindings(&root);
    diagnostics.extend(binding_diagnostics);

    let wanted: BTreeSet<&str> = request.sources.iter().map(String::as_str).collect();
    let limits = context.limits();
    let mut carriers = Vec::new();
    let mut recovered: Vec<Recovered> = Vec::new();
    let mut recovered_bytes = 0_u64;

    for source in &loaded.project.sources.sources {
        if !wanted.is_empty() && !wanted.contains(source.id.as_str()) {
            continue;
        }
        if source.kind != amiga_project::document::SourceKind::File {
            carriers.push(CarrierReport {
                source_id: source.id.clone(),
                kind: "opaque",
                members: 0,
                detail: Some("a directory source has no carrier to take apart".to_owned()),
            });
            continue;
        }

        let Some(path) = bindings.locate(&loaded.project, &source.id) else {
            carriers.push(CarrierReport {
                source_id: source.id.clone(),
                kind: "opaque",
                members: 0,
                detail: Some(
                    "this machine does not say where the media is; bind it in \
                     .amiga-re/local.json"
                        .to_owned(),
                ),
            });
            continue;
        };
        let bytes = match read_bounded(&path, request.maximum_input_bytes) {
            Ok(bytes) => bytes,
            Err(reason) => {
                carriers.push(CarrierReport {
                    source_id: source.id.clone(),
                    kind: "opaque",
                    members: 0,
                    detail: Some(reason),
                });
                continue;
            }
        };
        // The pinned digest is the identity. Extracting from bytes that are not
        // the ones the project pinned would produce objects describing a file
        // nobody registered.
        let actual = amiga_core::sha256(&bytes);
        if source
            .sha256
            .as_deref()
            .is_some_and(|pinned| pinned != actual)
        {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::ProjectContradicted,
                    format!(
                        "{} is {actual} on disk, not the {} the project pins; \
                         extraction would describe bytes nobody registered",
                        source.id,
                        source.sha256.clone().unwrap_or_default()
                    ),
                    &mut diagnostics,
                ),
                None,
            );
        }

        let (report, members) = match take_apart(
            source,
            &bytes,
            limits
                .maximum_total_recovered_bytes()
                .saturating_sub(recovered_bytes),
        ) {
            Ok(result) => result,
            Err(error) => {
                return outcome(
                    Status::Error,
                    fail(DiagnosticCode::LimitExceeded, error, &mut diagnostics),
                    None,
                );
            }
        };
        for member in &members {
            recovered_bytes = recovered_bytes.saturating_add(member.bytes.len() as u64);
        }
        carriers.push(report);
        recovered.extend(members);

        if recovered.len() > limits.maximum_objects() {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::LimitExceeded,
                    format!(
                        "the carriers hold more than {} members; extraction refuses the whole \
                         plan rather than covering part of it",
                        limits.maximum_objects()
                    ),
                    &mut diagnostics,
                ),
                None,
            );
        }
        if recovered_bytes > limits.maximum_total_recovered_bytes() {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::LimitExceeded,
                    format!(
                        "the carriers recover more than {} bytes; extraction refuses the whole \
                         plan rather than truncating it",
                        limits.maximum_total_recovered_bytes()
                    ),
                    &mut diagnostics,
                ),
                None,
            );
        }
    }

    events.emit(OperationEvent::Progress {
        phase: "recover_members",
        completed: recovered.len() as u64,
        total: Some(recovered.len() as u64),
    });

    recovered.sort_by(|left, right| left.id.cmp(&right.id));
    carriers.sort_by(|left, right| left.source_id.cmp(&right.source_id));

    // Ids and paths both have to be unique, and neither is guaranteed by
    // construction: two carriers can hold members whose names converge.
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for member in &recovered {
        if !ids.insert(member.id.as_str()) {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::OutputDestinationRefused,
                    format!("two recovered members claim the id {:?}", member.id),
                    &mut diagnostics,
                ),
                None,
            );
        }
        if !paths.insert(member.path.as_str()) {
            return outcome(
                Status::Error,
                fail(
                    DiagnosticCode::OutputDestinationRefused,
                    format!("two recovered members claim the path {:?}", member.path),
                    &mut diagnostics,
                ),
                None,
            );
        }
    }

    let sources_path = loaded.project.root.documents.sources.clone();
    let updated = match rewrite_sources(&root, &sources_path, &recovered) {
        Ok(updated) => updated,
        Err(reason) => {
            return outcome(
                Status::Error,
                fail(DiagnosticCode::ProjectUnreadable, reason, &mut diagnostics),
                None,
            );
        }
    };

    let mut files: Vec<(String, Vec<u8>)> = recovered
        .iter()
        .map(|member| (member.path.clone(), member.bytes.clone()))
        .collect();
    files.push((sources_path.clone(), updated));

    // Descriptive rather than resolved: this operation writes into the project
    // it was given, not into an adapter's output root, so the destination names
    // the project for the reviewer's benefit.
    let Some(label) = destination_label(request.project.path.as_str()) else {
        return outcome(
            Status::Error,
            fail(
                DiagnosticCode::RequestSourceNameInvalid,
                format!(
                    "{:?} has no last component a write plan can name",
                    request.project.path.as_str()
                ),
                &mut diagnostics,
            ),
            None,
        );
    };
    let plan = WritePlan::new(
        &label,
        DestinationKind::Directory,
        crate::output::OutputPolicy::ReplaceMatchingProvenance,
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

    let objects: Vec<ExtractedObject> = recovered
        .iter()
        .map(|member| ExtractedObject {
            id: member.id.clone(),
            parent_id: member.parent_id.clone(),
            kind: member.kind.to_owned(),
            size: member.bytes.len() as u64,
            sha256: amiga_core::sha256(&member.bytes),
            path: member.path.clone(),
        })
        .collect();

    let result = |committed, written| {
        Some(OperationResult::ProjectExtract(ProjectExtractResult {
            carriers: carriers.clone(),
            objects: objects.clone(),
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
                    "`project.extract` writes; ask for `prepare` or `commit_reviewed`".to_owned(),
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
                "the approved plan {approved} no longer describes this extraction, which now \
                 has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(false, Vec::new()));
    }

    match commit(&root, &files, &sources_path) {
        Ok(written) => outcome(Status::Success, diagnostics, result(true, written)),
        Err(reason) => outcome(
            Status::Conflict,
            fail(
                DiagnosticCode::OutputDestinationRefused,
                reason,
                &mut diagnostics,
            ),
            None,
        ),
    }
}

/// The project path as a destination name, for the plan's own record.
///
/// A project path may have several components while a destination name is one,
/// so the last component names it. `None` when even that is not a usable
/// destination name — which the caller turns into a refusal rather than a
/// panic, because "cannot happen" is not something this layer gets to assume
/// about a string that came in from a request.
fn destination_label(path: &str) -> Option<crate::output::DestinationName> {
    let last = path.rsplit('/').next().unwrap_or(path);
    crate::output::DestinationName::parse(last).ok()
}

/// Read `path`, refusing anything over `ceiling` rather than reading a prefix.
fn read_bounded(path: &Path, ceiling: u64) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.len() > ceiling {
        return Err(format!(
            "{} is {} bytes, over the {ceiling}-byte ceiling",
            path.display(),
            metadata.len()
        ));
    }
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Classify a carrier and recover what it holds.
fn take_apart(
    source: &amiga_project::document::Source,
    bytes: &[u8],
    mut remaining_bytes: u64,
) -> Result<(CarrierReport, Vec<Recovered>), String> {
    let component = amiga_project::path_component(&source.id);
    let report = |kind, members: u64, detail: Option<String>| CarrierReport {
        source_id: source.id.clone(),
        kind,
        members,
        detail,
    };

    // A HUNK executable is already the object the whole-file record describes.
    if amiga_hunk::Executable::parse(bytes).is_ok() {
        return Ok((
            report(
                "hunk",
                0,
                Some("a HUNK executable is already its own object".to_owned()),
            ),
            Vec::new(),
        ));
    }

    // An LHA parse that enumerated *nothing* is not evidence of an archive, and
    // claiming the carrier here is how an AmigaDOS volume came back as
    // `[lha]: 0 member(s)` with `nothing to extract` and a zero exit. The
    // archive ends at the first zero byte that does not begin a level-2 header,
    // so any file starting with one parses as an empty archive — and a volume
    // with an unbootable boot block starts with 512 of them. So the branch below
    // commits only when it recovered something, or when it found members it
    // could not recover, which is evidence too. An archive that genuinely holds
    // nothing is answered further down, after the containers that can still
    // enumerate have had their turn.
    let mut empty_archive = false;
    if let Ok(archive) = amiga_lha::Archive::parse(bytes) {
        let mut members = Vec::new();
        let mut skipped = 0_u64;
        for entry in archive.entries() {
            if entry.is_directory() {
                continue;
            }
            // Archive hierarchy is retained only through the component-wise
            // validator. A rejected member is counted rather than materialized
            // under a path whose meaning could differ across hosts.
            let Ok(safe) = amiga_core::safe_archive_path(entry.name()) else {
                skipped += 1;
                continue;
            };
            let data = match archive.read(entry, amiga_lha::OutputLimit::new(remaining_bytes)) {
                Ok(data) => data,
                Err(error @ amiga_lha::LhaError::OutputLimitExceeded { .. }) => {
                    return Err(error.to_string());
                }
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            remaining_bytes -= data.len() as u64;
            let name = safe.to_string_lossy().into_owned();
            members.push(Recovered {
                id: format!(
                    "object:{}/{}",
                    amiga_project::safe_component(&source.id),
                    amiga_project::safe_component(&name)
                ),
                parent_id: source.id.clone(),
                kind: "container_member",
                selector: json!({
                    "container": "lha",
                    "member": entry.name(),
                    "method": entry.method_str(),
                }),
                path: format!("extracted/{component}/{name}"),
                bytes: data,
            });
        }
        let detail = (skipped > 0).then(|| {
            format!("{skipped} member(s) could not be recovered and are not in this plan")
        });
        let count = members.len() as u64;
        if count > 0 || skipped > 0 {
            return Ok((report("lha", count, detail), members));
        }
        empty_archive = true;
    }

    if let Ok(image) = amiga_adf::Image::open(bytes) {
        let mut members = Vec::new();
        for entry in image
            .entries()
            .iter()
            .filter(|entry| entry.kind == amiga_adf::EntryKind::File)
        {
            if u64::from(entry.size.get()) > remaining_bytes {
                return Err(format!(
                    "{} exceeds the remaining {remaining_bytes}-byte recovery budget",
                    entry.path.display()
                ));
            }
            let Ok(data) = image.read_file(entry) else {
                continue;
            };
            remaining_bytes = remaining_bytes
                .checked_sub(data.len() as u64)
                .ok_or_else(|| "ADF output exceeds the recovery budget".to_owned())?;
            // Assembled by the filesystem walk from validated directory blocks,
            // so its hierarchy is kept — unlike an archive-provided name.
            let name = entry.path.to_string_lossy().replace('\\', "/");
            members.push(Recovered {
                id: format!(
                    "object:{}/{}",
                    amiga_project::safe_component(&source.id),
                    amiga_project::safe_component(&name)
                ),
                parent_id: source.id.clone(),
                kind: "container_member",
                selector: json!({
                    "container": "adf",
                    "path": name,
                    "header_block": entry.header_block.get(),
                }),
                path: format!("extracted/{component}/{name}"),
                bytes: data,
            });
        }
        let count = members.len() as u64;
        return Ok((report("adf", count, None), members));
    }

    // A real archive that holds nothing, answered after the containers that can
    // enumerate have declined it — so the reading is "this archive is empty"
    // rather than "this file begins with a zero byte".
    if empty_archive {
        return Ok((
            report(
                "lha",
                0,
                Some("an LHA archive with no members to recover".to_owned()),
            ),
            Vec::new(),
        ));
    }

    // No filesystem to walk. Reported rather than skipped, and deliberately not
    // booted: running a disk's own loader is a separate act a person decides on.
    let non_dos = amiga_adf::Bootblock::parse(bytes).is_ok_and(|boot| !boot.is_dos());
    if non_dos {
        return Ok((
            report(
                "adf_non_dos",
                0,
                Some(
                    "a custom-boot disk has no filesystem to enumerate; what its loader reads \
                     is found by `env.boot.trace`, which is a separate, explicitly confirmed act"
                        .to_owned(),
                ),
            ),
            Vec::new(),
        ));
    }
    Ok((
        report(
            "opaque",
            0,
            Some("not a container this build can take apart".to_owned()),
        ),
        Vec::new(),
    ))
}

/// The sources document with the recovered objects added.
fn rewrite_sources(
    root: &Path,
    relative: &str,
    recovered: &[Recovered],
) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(root.join(relative))
        .map_err(|error| format!("{relative}: {error}"))?;
    let mut document: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("{relative}: {error}"))?;

    let objects = document
        .get_mut("objects")
        .and_then(serde_json::Value::as_array_mut);
    let mut existing = match objects {
        Some(objects) => std::mem::take(objects),
        None => Vec::new(),
    };
    let known: BTreeSet<String> = existing
        .iter()
        .filter_map(|object| object["id"].as_str().map(str::to_owned))
        .collect();

    for member in recovered {
        if known.contains(&member.id) {
            // Re-extracting must not append a second record for one object: the
            // plan would then grow without bound across runs.
            continue;
        }
        existing.push(json!({
            "id": member.id,
            "kind": member.kind,
            "parent_id": member.parent_id,
            "selector": member.selector,
            "size": member.bytes.len(),
            "sha256": amiga_core::sha256(&member.bytes),
        }));
    }
    if let Some(map) = document.as_object_mut() {
        map.insert("objects".to_owned(), serde_json::Value::Array(existing));
    }
    Ok(amiga_project::format_document(&document).into_bytes())
}

/// Write every file, the sources document last.
///
/// A failure partway leaves unreferenced bytes under `extracted/` and a
/// documents set that is exactly what it was — inert, rather than a project
/// naming objects whose files were never written.
fn commit(
    root: &Path,
    files: &[(String, Vec<u8>)],
    sources_path: &str,
) -> Result<Vec<String>, String> {
    let mut ordered: Vec<&(String, Vec<u8>)> = files.iter().collect();
    ordered.sort_by_key(|(path, _)| (path == sources_path, path.clone()));

    let mut written = Vec::with_capacity(ordered.len());
    for (path, bytes) in ordered {
        let target = root.join(path);
        amiga_core::safepath::prepare_output_file(&target, true)
            .map_err(|error| format!("{path}: {error}"))?;
        std::fs::write(&target, bytes).map_err(|error| format!("{path}: {error}"))?;
        written.push(path.clone());
    }
    Ok(written)
}
