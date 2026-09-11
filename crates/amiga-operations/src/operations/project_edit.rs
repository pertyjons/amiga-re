//! `project.edit` — reviewed changes to a project's annotations.
//!
//! The project format already refused to overwrite a document that changed
//! since it was read. That was the right rule reached by a second mechanism;
//! it is the operation API's `prepare` / `commit_reviewed` now, so an edit is
//! authorized exactly the way every other write in this toolkit is.
//!
//! Two checks, not one, and they answer different questions. The plan digest
//! asks "is this the plan you reviewed?"; the per-document digests ask "are the
//! documents still what the plan was built from?". An edit made while a review
//! was open fails the second even when the first passes, which is the case the
//! whole mechanism exists for.
//!
//! A rebase names only the annotation. *Which* object it rebases onto, and at
//! what digest, is a fact about the project and is derived here — letting a
//! caller supply it would let two callers rebase one annotation onto two
//! different digests and both be accepted.
//!
//! The same holds for a target a new annotation names. A request says "object
//! X, offset, length"; the digest that target is established against is looked
//! up here, so a caller cannot pin an annotation to bytes this project does not
//! describe.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedMode, NormalizedProjectEdit};
use crate::protocol::Status;
use crate::request::{OperationName, ProjectEdit, ProjectEditTarget};
use crate::response::{
    EditedDocument, FormattedDocument, ImportAmbiguity, OperationOutcome, OperationResult,
    ProjectEditResult, ProjectFormatResult, ProjectMigrateResult, ResolvedRebase, SourcePin,
};

pub(crate) fn run(
    request: &NormalizedProjectEdit,
    context: &ExecutionContext<'_>,
    mode: &NormalizedMode,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let refused = |diagnostics, digest| OperationOutcome {
        operation: OperationName::ProjectEdit,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    };
    let Some(root) = context
        .resolver()
        .root()
        .map(|root| root.join(request.project.path.as_str()))
    else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::ProjectUnreadable,
            "this context serves no directory, so no project can be located",
        ));
        return refused(diagnostics, digest);
    };
    let loaded = match amiga_project::load(&root) {
        Ok(loaded) => loaded,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ProjectUnreadable,
                error.to_string(),
            ));
            return refused(diagnostics, digest);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "load_project",
        completed: 1,
        total: Some(1),
    });

    let mut edits = Vec::with_capacity(request.edits.len());
    let mut rebases = Vec::new();
    for edit in &request.edits {
        match edit {
            ProjectEdit::Rename { id, name } => edits.push(amiga_project::Edit::Rename {
                id: id.clone(),
                name: name.clone(),
            }),
            ProjectEdit::Annotate {
                id,
                kind,
                target,
                name,
                classification,
            } => {
                // An annotation *about an annotation* is a comment, and the
                // format has a variant for it. Refused here rather than written
                // as a `region` with no bytes behind it.
                if let ProjectEditTarget::Entity { entity_id } = target {
                    diagnostics.push(
                        Diagnostic::error(
                            DiagnosticCode::RequestMalformed,
                            format!(
                                "an annotation is about bytes, not about {entity_id}; \
                                 comment on it instead"
                            ),
                        )
                        .at("$.request.arguments.edits"),
                    );
                    return refused(diagnostics, digest);
                }
                match resolve_target(&loaded, target) {
                    Ok(target) => edits.push(amiga_project::Edit::Annotate {
                        id: id.clone(),
                        kind: kind.clone(),
                        target,
                        name: name.clone(),
                        classification: classification.clone(),
                    }),
                    Err(reason) => {
                        diagnostics.push(
                            Diagnostic::error(DiagnosticCode::ProjectContradicted, reason)
                                .at("$.request.arguments.edits"),
                        );
                        return refused(diagnostics, digest);
                    }
                }
            }
            ProjectEdit::Comment {
                id,
                target,
                placement,
                text,
            } => {
                let subject = match target {
                    ProjectEditTarget::Entity { entity_id } => {
                        amiga_project::edit::CommentSubject::Entity {
                            entity_id: entity_id.clone(),
                        }
                    }
                    bytes => match resolve_target(&loaded, bytes) {
                        Ok(target) => amiga_project::edit::CommentSubject::Bytes(Box::new(target)),
                        Err(reason) => {
                            diagnostics.push(
                                Diagnostic::error(DiagnosticCode::ProjectContradicted, reason)
                                    .at("$.request.arguments.edits"),
                            );
                            return refused(diagnostics, digest);
                        }
                    },
                };
                edits.push(amiga_project::Edit::Comment {
                    id: id.clone(),
                    on: subject,
                    placement: placement.clone(),
                    text: text.clone(),
                });
            }
            ProjectEdit::Remove { id } => {
                edits.push(amiga_project::Edit::Remove { id: id.clone() });
            }
            ProjectEdit::DefineResource {
                id,
                kind,
                name,
                target,
                parameters,
                export_media_type,
                notes,
            }
            | ProjectEdit::UpdateResource {
                id,
                kind,
                name,
                target,
                parameters,
                export_media_type,
                notes,
            } => {
                let target = match resolve_target(&loaded, target) {
                    Ok(target) => target,
                    Err(reason) => {
                        diagnostics.push(
                            Diagnostic::error(DiagnosticCode::ProjectContradicted, reason)
                                .at("$.request.arguments.edits"),
                        );
                        return refused(diagnostics, digest);
                    }
                };
                let resource = match build_resource(
                    id,
                    kind,
                    name,
                    &target,
                    parameters,
                    export_media_type.as_deref(),
                    notes.as_deref(),
                ) {
                    Ok(resource) => resource,
                    Err(reason) => {
                        diagnostics.push(
                            Diagnostic::error(DiagnosticCode::RequestMalformed, reason)
                                .at("$.request.arguments.edits"),
                        );
                        return refused(diagnostics, digest);
                    }
                };
                edits.push(if matches!(edit, ProjectEdit::DefineResource { .. }) {
                    amiga_project::Edit::DefineResource { resource }
                } else {
                    amiga_project::Edit::UpdateResource { resource }
                });
            }
            ProjectEdit::RemoveResource { id } => {
                edits.push(amiga_project::Edit::RemoveResource { id: id.clone() });
            }
            ProjectEdit::DefineType { definition } | ProjectEdit::UpdateType { definition } => {
                let parsed: amiga_project::document::TypeDefinition =
                    match serde_json::from_value(serde_json::Value::Object(definition.clone())) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            diagnostics.push(
                                Diagnostic::error(
                                    DiagnosticCode::RequestMalformed,
                                    format!(
                                        "a type definition this format does not define: {error}"
                                    ),
                                )
                                .at("$.request.arguments.edits"),
                            );
                            return refused(diagnostics, digest);
                        }
                    };
                let definition = Box::new(parsed);
                edits.push(if matches!(edit, ProjectEdit::DefineType { .. }) {
                    amiga_project::Edit::DefineType { definition }
                } else {
                    amiga_project::Edit::UpdateType { definition }
                });
            }
            ProjectEdit::RemoveType { id } => {
                edits.push(amiga_project::Edit::RemoveType { id: id.clone() });
            }
            ProjectEdit::RemoveArtifact { id } => {
                edits.push(amiga_project::Edit::RemoveArtifact { id: id.clone() });
            }
            ProjectEdit::RegisterCapture {
                id,
                name,
                size,
                sha256,
                notes,
                path,
            } => match capture_source(&root, id, name, *size, sha256, notes, path.as_deref()) {
                Ok(source) => edits.push(amiga_project::Edit::RegisterSource {
                    source: Box::new(source),
                }),
                Err(reason) => {
                    diagnostics.push(
                        Diagnostic::error(DiagnosticCode::ProjectContradicted, reason)
                            .at("$.request.arguments.edits"),
                    );
                    return refused(diagnostics, digest);
                }
            },
            ProjectEdit::Rebase { id } => match rebase_target(&loaded, id) {
                Ok((object_id, object_sha256)) => {
                    edits.push(amiga_project::Edit::Rebase {
                        id: id.clone(),
                        object_sha256: object_sha256.clone(),
                    });
                    rebases.push(ResolvedRebase {
                        id: id.clone(),
                        object_id,
                        object_sha256,
                    });
                }
                Err(reason) => {
                    diagnostics.push(
                        Diagnostic::error(DiagnosticCode::ProjectContradicted, reason)
                            .at("$.request.arguments.edits"),
                    );
                    return refused(diagnostics, digest);
                }
            },
        }
    }

    let documents = loaded.project.root.documents.clone();
    let plan = match amiga_project::EditPlan::prepare(&root, &documents, edits) {
        Ok(plan) => plan,
        Err(error) => {
            diagnostics.push(
                Diagnostic::error(DiagnosticCode::ProjectContradicted, error.to_string())
                    .at("$.request.arguments.edits"),
            );
            return refused(diagnostics, digest);
        }
    };
    let preview = match plan.preview() {
        Ok(preview) => preview,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ProjectContradicted,
                error.to_string(),
            ));
            return refused(diagnostics, digest);
        }
    };

    let mut described: Vec<EditedDocument> = preview
        .iter()
        .map(|(path, text)| {
            let current = std::fs::read_to_string(root.join(path)).unwrap_or_default();
            EditedDocument {
                path: path.clone(),
                expected_sha256: plan.expects().get(path).cloned().unwrap_or_default(),
                size: text.len() as u64,
                // A plan may touch a document without changing it — a rename to
                // the name it already has. Reported as unchanged rather than
                // counted as a change.
                changed: *text != current,
            }
        })
        .collect();
    described.sort_by(|left, right| left.path.cmp(&right.path));

    // The digest covers what the caller reviewed: the edits, what a rebase
    // resolved to, the documents, and the digests those documents are expected
    // to be at.
    let canonical = serde_json::json!({
        "edits": request.edits,
        "rebases": rebases
            .iter()
            .map(|rebase: &ResolvedRebase| serde_json::json!({
                "id": rebase.id,
                "object_id": rebase.object_id,
                "object_sha256": rebase.object_sha256,
            }))
            .collect::<Vec<_>>(),
        "documents": described
            .iter()
            .map(|document| serde_json::json!({
                "path": document.path,
                "expected_sha256": document.expected_sha256,
                "size": document.size,
                "changed": document.changed,
            }))
            .collect::<Vec<_>>(),
    });
    let plan_sha256 = amiga_core::sha256(canonical.to_string().as_bytes());

    let (committed, written) = match mode {
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "`project.edit` writes; ask for `prepare` or `commit_reviewed`",
            ));
            return refused(diagnostics, digest);
        }
        NormalizedMode::Prepare => (false, Vec::new()),
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => {
            if *approved_plan_sha256 != plan_sha256 {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::OutputPlanChanged,
                    format!(
                        "the approved plan {approved_plan_sha256} is not the plan this request \
                         produces ({plan_sha256})"
                    ),
                ));
                let mut outcome = refused(diagnostics, digest);
                outcome.status = Status::Conflict;
                outcome.result = Some(OperationResult::ProjectEdit(ProjectEditResult {
                    rebases,
                    documents: described,
                    plan_sha256,
                    committed: false,
                    written: Vec::new(),
                }));
                return outcome;
            }
            match plan.apply() {
                Ok(changed) => (true, changed),
                Err(error) => {
                    let conflict = matches!(error, amiga_project::EditError::Conflict { .. });
                    diagnostics.push(Diagnostic::error(
                        if conflict {
                            DiagnosticCode::OutputPlanChanged
                        } else {
                            DiagnosticCode::OutputDestinationRefused
                        },
                        error.to_string(),
                    ));
                    let mut outcome = refused(diagnostics, digest);
                    if conflict {
                        outcome.status = Status::Conflict;
                    }
                    return outcome;
                }
            }
        }
    };

    let result = ProjectEditResult {
        rebases,
        documents: described,
        plan_sha256,
        committed,
        written,
    };
    OperationOutcome {
        operation: OperationName::ProjectEdit,
        status: if committed {
            Status::Success
        } else {
            Status::Prepared
        },
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectEdit(result)),
    }
}

/// The source a `register_capture` records, with the bytes checked against the
/// pin before anything is written.
///
/// **The check is here rather than left to `project.verify`.** Registering a
/// capture whose file is absent, the wrong length, or a different digest would
/// write a document that contradicts itself the moment it is read, and the
/// recover-then-modify rule this toolkit follows everywhere else says to find
/// that out first. A registration with no path claims nothing about a file and
/// so has nothing to check.
fn capture_source(
    root: &std::path::Path,
    id: &str,
    name: &str,
    size: u64,
    sha256: &str,
    notes: &str,
    path: Option<&str>,
) -> Result<amiga_project::document::Source, String> {
    let mut locations = Vec::new();
    if let Some(path) = path {
        // The same rule the format applies to a location it reads: a project
        // path is relative, has ordinary components, and never escapes the root.
        if !amiga_project::validate::is_safe_relative(path) {
            return Err(format!(
                "{path} is not a project-relative path with ordinary components"
            ));
        }
        let full = root.join(path);
        amiga_core::safepath::reject_symlink(&full).map_err(|error| error.to_string())?;
        let bytes = std::fs::read(&full)
            .map_err(|error| format!("the capture at {path} could not be read: {error}"))?;
        if bytes.len() as u64 != size {
            return Err(format!(
                "the capture at {path} is {} bytes where the registration says {size}",
                bytes.len()
            ));
        }
        let actual = amiga_core::sha256(&bytes);
        if actual != sha256 {
            return Err(format!(
                "the capture at {path} hashes to {actual}, not the registered {sha256}"
            ));
        }
        locations.push(amiga_project::document::Location::ProjectRelative {
            path: path.to_owned(),
        });
    }
    Ok(amiga_project::document::Source {
        id: id.to_owned(),
        kind: amiga_project::document::SourceKind::File,
        media_type: None,
        display_name: name.to_owned(),
        size: Some(size),
        sha256: Some(sha256.to_owned()),
        inventory: None,
        tree_sha256: None,
        locations,
        // Not the caller's to choose: these bytes are on no disk, and the whole
        // point of the variant is that they are recorded as what they are.
        provenance: amiga_project::document::Provenance::Captured,
        notes: Some(notes.to_owned()),
    })
}

/// The object a rebase pins to, and its digest: the object behind the image the
/// annotation targets.
fn rebase_target(loaded: &amiga_project::Loaded, id: &str) -> Result<(String, String), String> {
    let mut image_id = None;
    for document in &loaded.project.annotations {
        for annotation in &document.annotations {
            if annotation.id() != id {
                continue;
            }
            if let Some(target) = annotation.target()
                && let Some(image) = target.image_id()
            {
                image_id = Some(image.clone());
            }
        }
    }
    let image_id =
        image_id.ok_or_else(|| format!("{id} does not target an image this project describes"))?;
    let object_id = image_object(loaded, &image_id)?;
    let sha256 = object_digest(loaded, &object_id)?;
    Ok((object_id, sha256))
}

/// Fill in the digest a request left out, so the annotation it creates is
/// established against bytes this project actually describes.
fn resolve_target(
    loaded: &amiga_project::Loaded,
    target: &ProjectEditTarget,
) -> Result<amiga_project::document::Target, String> {
    use amiga_project::document::Target;
    Ok(match target {
        ProjectEditTarget::Object {
            object_id,
            offset,
            length,
        } => Target::Object {
            object_sha256: object_digest(loaded, object_id)?,
            object_id: object_id.clone(),
            offset: *offset,
            length: *length,
        },
        ProjectEditTarget::Hunk {
            image_id,
            hunk,
            offset,
            length,
        } => Target::Hunk {
            object_sha256: object_digest(loaded, &image_object(loaded, image_id)?)?,
            image_id: image_id.clone(),
            hunk: *hunk,
            offset: *offset,
            length: *length,
        },
        ProjectEditTarget::Runtime {
            image_id,
            load_map_id,
            address,
            length,
        } => Target::Runtime {
            object_sha256: object_digest(loaded, &image_object(loaded, image_id)?)?,
            image_id: image_id.clone(),
            load_map_id: load_map_id.clone(),
            address: address.clone(),
            length: *length,
        },
        ProjectEditTarget::BaseRegister {
            image_id,
            base_register,
            displacement,
            width,
        } => Target::BaseRegister {
            object_sha256: object_digest(loaded, &image_object(loaded, image_id)?)?,
            image_id: image_id.clone(),
            base_register: base_register.clone(),
            displacement: *displacement,
            width: *width,
        },
        // Handled by every caller before it gets here: an entity target has no
        // object, so there is no digest to derive.
        ProjectEditTarget::Entity { entity_id } => {
            return Err(format!("{entity_id} names an annotation, not bytes"));
        }
    })
}

/// Assemble one typed resource from the request's kind, target and parameters.
///
/// The parameters are handed to the same deserializer that reads a resources
/// document, so a missing `width` or an unknown field is refused here rather
/// than written into a document nothing can load. That is also why the request
/// does not restate the nine resource shapes: the schema is the definition, and
/// a second copy would be a second thing to keep in step.
fn build_resource(
    id: &str,
    kind: &str,
    name: &str,
    target: &amiga_project::document::Target,
    parameters: &serde_json::Map<String, serde_json::Value>,
    export_media_type: Option<&str>,
    notes: Option<&str>,
) -> Result<amiga_project::document::Resource, String> {
    let mut value = serde_json::Map::new();
    for (key, parameter) in parameters {
        // The fields this operation decides are not the caller's to smuggle in
        // through the parameter bag.
        if matches!(
            key.as_str(),
            "id" | "kind" | "name" | "target" | "export" | "notes"
        ) {
            return Err(format!(
                "{key} is named by the edit itself, not by its parameters"
            ));
        }
        value.insert(key.clone(), parameter.clone());
    }
    value.insert("id".to_owned(), serde_json::Value::String(id.to_owned()));
    value.insert(
        "kind".to_owned(),
        serde_json::Value::String(kind.to_owned()),
    );
    value.insert(
        "name".to_owned(),
        serde_json::Value::String(name.to_owned()),
    );
    value.insert(
        "target".to_owned(),
        serde_json::to_value(target).map_err(|error| error.to_string())?,
    );
    if let Some(media_type) = export_media_type {
        value.insert(
            "export".to_owned(),
            serde_json::json!({ "media_type": media_type }),
        );
    }
    if let Some(notes) = notes {
        value.insert(
            "notes".to_owned(),
            serde_json::Value::String(notes.to_owned()),
        );
    }
    serde_json::from_value(serde_json::Value::Object(value))
        .map_err(|error| format!("this is not a usable {kind} resource: {error}"))
}

/// The object whose bytes an image is.
fn image_object(loaded: &amiga_project::Loaded, image_id: &str) -> Result<String, String> {
    loaded
        .project
        .programs
        .iter()
        .flat_map(|program| &program.images)
        .find(|candidate| candidate.id == image_id)
        .map(|candidate| candidate.object_id.clone())
        .ok_or_else(|| format!("no image {image_id} in this project"))
}

/// What an object's bytes are pinned at.
fn object_digest(loaded: &amiga_project::Loaded, object_id: &str) -> Result<String, String> {
    loaded
        .project
        .sources
        .objects
        .iter()
        .find(|object| object.id == object_id)
        .map(|object| object.sha256.clone())
        .ok_or_else(|| format!("no object {object_id} in this project"))
}

/// `project.format` — canonical form for every document a project names.
///
/// A write like any other: `prepare` reports which documents differ from
/// canonical form and writes nothing, `commit_reviewed` re-derives the same
/// plan and rewrites only what the plan named. `project format --check` is
/// simply the prepared half, which is what makes "check" and "fix" provably the
/// same computation rather than two that agree by habit.
///
/// Every document reports the digest of its canonical bytes, formatted or not.
/// That is what says two runs of the formatter produced the same answer — the
/// property a canonicalizer exists to have.
pub(crate) fn format(
    request: &crate::normalize::NormalizedProject,
    context: &ExecutionContext<'_>,
    mode: &NormalizedMode,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let refused = |diagnostics, digest| OperationOutcome {
        operation: OperationName::ProjectFormat,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    };
    let Some(root) = context
        .resolver()
        .root()
        .map(|root| root.join(request.path.as_str()))
    else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::ProjectUnreadable,
            "this context serves no directory, so no project can be located",
        ));
        return refused(diagnostics, digest);
    };
    let loaded = match amiga_project::load(&root) {
        Ok(loaded) => loaded,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ProjectUnreadable,
                error.to_string(),
            ));
            return refused(diagnostics, digest);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "load_project",
        completed: 1,
        total: Some(1),
    });

    let index = &loaded.project.root.documents;
    let mut paths = vec![index.sources.clone()];
    for list in [
        &index.programs,
        &index.annotations,
        &index.resources,
        &index.types,
    ] {
        paths.extend(list.iter().cloned());
    }

    let mut documents = Vec::with_capacity(paths.len());
    let mut canonical_text = Vec::with_capacity(paths.len());
    for relative in paths {
        let path = root.join(&relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::ProjectUnreadable,
                    format!("failed to read {relative}: {error}"),
                ));
                return refused(diagnostics, digest);
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::ProjectUnreadable,
                    format!("{relative} is not valid JSON: {error}"),
                ));
                return refused(diagnostics, digest);
            }
        };
        let formatted = amiga_project::format_document(&value);
        documents.push(FormattedDocument {
            path: relative.clone(),
            size: formatted.len() as u64,
            sha256: amiga_core::sha256(formatted.as_bytes()),
            canonical: formatted == text,
        });
        canonical_text.push((relative, formatted));
    }

    let unformatted = documents.iter().filter(|entry| !entry.canonical).count() as u64;
    let canonical = serde_json::json!({
        "documents": documents
            .iter()
            .map(|entry| serde_json::json!({
                "path": entry.path,
                "sha256": entry.sha256,
                "canonical": entry.canonical,
            }))
            .collect::<Vec<_>>(),
    });
    let plan_sha256 = amiga_core::sha256(canonical.to_string().as_bytes());

    let (committed, written) = match mode {
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "`project.format` writes; ask for `prepare` or `commit_reviewed`",
            ));
            return refused(diagnostics, digest);
        }
        NormalizedMode::Prepare => (false, Vec::new()),
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => {
            if *approved_plan_sha256 != plan_sha256 {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::OutputPlanChanged,
                    format!(
                        "the approved plan {approved_plan_sha256} is not the plan this request \
                         produces ({plan_sha256})"
                    ),
                ));
                let mut outcome = refused(diagnostics, digest);
                outcome.status = Status::Conflict;
                outcome.result = Some(OperationResult::ProjectFormat(ProjectFormatResult {
                    documents,
                    unformatted,
                    plan_sha256,
                    committed: false,
                    written: Vec::new(),
                }));
                return outcome;
            }
            let mut written = Vec::new();
            for ((relative, formatted), entry) in canonical_text.iter().zip(&documents) {
                if entry.canonical {
                    continue;
                }
                if let Err(error) = std::fs::write(root.join(relative), formatted.as_bytes()) {
                    diagnostics.push(Diagnostic::error(
                        DiagnosticCode::OutputDestinationRefused,
                        format!("failed to write {relative}: {error}"),
                    ));
                    return refused(diagnostics, digest);
                }
                written.push(relative.clone());
            }
            (true, written)
        }
    };

    let result = ProjectFormatResult {
        documents,
        unformatted,
        plan_sha256,
        committed,
        written,
    };
    OperationOutcome {
        operation: OperationName::ProjectFormat,
        status: if committed {
            Status::Success
        } else {
            Status::Prepared
        },
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectFormat(result)),
    }
}

/// `project.migrate` — a legacy `amiga-re.toml` converted into project
/// documents.
///
/// The config is named as a **source**, never read from a host path. It is a
/// legacy document being converted — bytes with a digest — which is what
/// separates this from `config show`, whose subject is the same file *as this
/// frontend's settings*. One is a question about bytes; the other is not.
///
/// Two destination shapes, because an import lands in two different kinds of
/// place. A fresh project is a directory this toolkit owns, and the ordinary
/// whole-tree plan applies. An import beside the config it came from lands in a
/// repository — where staging a replacement of the whole directory would ask a
/// user to authorize replacing all their work — so it writes the named files
/// and touches nothing else.
///
/// The ambiguities are first-class in the result, not diagnostics only. A
/// legacy config says things the project format has no single place for, and a
/// caller deciding whether to commit an import is deciding about exactly those.
pub(crate) fn migrate(
    request: &crate::normalize::NormalizedProjectMigrate,
    context: &ExecutionContext<'_>,
    mode: &NormalizedMode,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let refused = |diagnostics, digest| OperationOutcome {
        operation: OperationName::ProjectMigrate,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    };
    let source = match context.resolve_source(&request.config, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            let code = match error {
                crate::source::SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                crate::source::SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                crate::source::SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return refused(diagnostics, digest);
        }
    };
    let text = match std::str::from_utf8(source.bytes()) {
        Ok(text) => text,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::SourceUnreadable,
                format!("the config is not UTF-8: {error}"),
            ));
            return refused(diagnostics, digest);
        }
    };
    let config = match amiga_core::Config::from_toml(text) {
        Ok(config) => config,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::SourceUnreadable,
                error.to_string(),
            ));
            return refused(diagnostics, digest);
        }
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
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return refused(diagnostics, digest);
        }
    };

    let image = request
        .image
        .as_ref()
        .map(|(id, media)| amiga_project::migrate::ImportedImage {
            id: id.as_str(),
            media: media.as_str(),
        });
    // The importer resolves config-relative paths against the config's own
    // directory, which is where it sits — not where the import will land.
    let config_directory = destination.clone();
    let imported = amiga_project::migrate::import(&config, &request.name, image, &config_directory);
    events.emit(OperationEvent::Progress {
        phase: "import_config",
        completed: imported.documents.len() as u64,
        total: Some(imported.documents.len() as u64),
    });

    let ambiguities: Vec<ImportAmbiguity> = imported
        .ambiguities
        .iter()
        .map(|ambiguity| ImportAmbiguity {
            field: ambiguity.field.to_string(),
            message: ambiguity.message.to_string(),
        })
        .collect();
    for ambiguity in &ambiguities {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ProjectHasProblems,
            format!("ambiguous: {}: {}", ambiguity.field, ambiguity.message),
        ));
    }

    // Canonical form from the start, so the first commit is already the form
    // every later edit produces.
    let files: Vec<amiga_core::PlannedFile> = imported
        .documents
        .iter()
        .map(|(path, document)| amiga_core::PlannedFile {
            path: std::path::PathBuf::from(path),
            bytes: amiga_project::format_document(document).into_bytes(),
        })
        .collect();
    // Built either way: it is what validates every relative path, rejects a
    // duplicate, and refuses a file that is also a directory.
    let staged = match amiga_core::ExtractionPlan::new(files, Vec::new()) {
        Ok(staged) => staged,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return refused(diagnostics, digest);
        }
    };

    let kind = if request.in_place {
        crate::output::DestinationKind::DirectoryContents
    } else {
        crate::output::DestinationKind::Directory
    };
    let plan = crate::output::WritePlan::new(
        &request.destination,
        kind,
        request.policy,
        staged
            .files()
            .iter()
            .map(|file| crate::output::PlannedOutput {
                path: file.path.to_string_lossy().replace('\\', "/"),
                size: file.bytes.len() as u64,
                sha256: amiga_core::sha256(&file.bytes),
            })
            .collect(),
        Vec::new(),
    );

    let pin = SourcePin {
        size: source.size(),
        sha256: source.sha256().to_owned(),
    };
    let committed = match mode {
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "`project.migrate` writes; ask for `prepare` or `commit_reviewed`",
            ));
            return refused(diagnostics, digest);
        }
        NormalizedMode::Prepare => false,
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => {
            if !plan.is_approved_by(approved_plan_sha256) {
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::OutputPlanChanged,
                    format!(
                        "the approved plan {approved_plan_sha256} is not the plan this request \
                         produces ({})",
                        plan.plan_sha256
                    ),
                ));
                let mut outcome = refused(diagnostics, digest);
                outcome.status = Status::Conflict;
                outcome.result = Some(OperationResult::ProjectMigrate(ProjectMigrateResult {
                    source: pin,
                    ambiguities,
                    plan,
                    committed: false,
                }));
                return outcome;
            }
            let manifest = import_manifest(&request.config, &ambiguities, &plan);
            let written = if request.in_place {
                staged.commit_into(
                    &destination,
                    request.policy.permits_replacement(),
                    IMPORT_MANIFEST_NAME,
                    &manifest,
                )
            } else {
                staged.commit(
                    &destination,
                    request.policy.permits_replacement(),
                    IMPORT_MANIFEST_NAME,
                    &manifest,
                )
            };
            match written {
                Ok(_) => true,
                Err(error) => {
                    diagnostics.push(Diagnostic::error(
                        DiagnosticCode::OutputDestinationRefused,
                        error.to_string(),
                    ));
                    return refused(diagnostics, digest);
                }
            }
        }
    };

    OperationOutcome {
        operation: OperationName::ProjectMigrate,
        status: if committed {
            Status::Success
        } else {
            Status::Prepared
        },
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectMigrate(ProjectMigrateResult {
            source: pin,
            ambiguities,
            plan,
            committed,
        })),
    }
}

/// The provenance document an owned-directory import writes beside its files.
const IMPORT_MANIFEST_NAME: &str = "import-manifest.json";

fn import_manifest(
    config: &crate::normalize::NormalizedSource,
    ambiguities: &[ImportAmbiguity],
    plan: &crate::output::WritePlan,
) -> Vec<u8> {
    // Serialized once, so the bytes written are the bytes the plan describes.
    serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "imported_from": config.display_name(),
        "ambiguities": ambiguities,
        "files": plan.files,
    }))
    .unwrap_or_default()
}
