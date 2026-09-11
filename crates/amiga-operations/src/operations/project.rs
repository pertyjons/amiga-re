//! `project.check` and `project.verify` — the versioned project format,
//! reachable through the shared API.
//!
//! Both are read-only, and both report rather than refuse. A project with a
//! stale annotation or absent media is a project that *opened*, which is the
//! property the format exists for; turning either into an error would make the
//! operations useless on exactly the machines that need them.
//!
//! The project's location arrives through the envelope's `project` locator, not
//! through arguments, so every project-backed operation names it the same way.
//! It resolves like a source name: an identity the adapter interprets, never a
//! host path, so a request stays reproducible on another machine.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode, Severity};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{
    AnnotationScope, NormalizedProject, NormalizedProjectAnnotations, NormalizedProjectInventory,
};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    AnnotatedGlobal, AnnotatedLocal, AnnotatedLocation, AnnotatedRange, AnnotationComment,
    InventoryFile, LocalStorage, OmittedEntry, OperationOutcome, OperationResult,
    ProjectAnnotationsResult, ProjectArtifact, ProjectCheckResult, ProjectDescribeResult,
    ProjectImage, ProjectInventoryResult, ProjectLoadMap, ProjectLoadSegment, ProjectObject,
    ProjectProblem, ProjectProgram, ProjectResource, ProjectSource, ProjectSourceSet,
    ProjectVerifyResult, VerifiedEntity,
};

pub(crate) fn check(
    request: &NormalizedProject,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let Some(root) = project_root(context, request) else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::ProjectUnreadable,
            "this context serves no directory, so no project can be located",
        ));
        return OperationOutcome {
            operation: OperationName::ProjectCheck,
            status: Status::Error,
            diagnostics,
            normalized_request_sha256: Some(digest),
            result: None,
        };
    };
    let loaded = match amiga_project::load(&root) {
        Ok(loaded) => loaded,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ProjectUnreadable,
                error.to_string(),
            ));
            return OperationOutcome {
                operation: OperationName::ProjectCheck,
                status: Status::Error,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "load_project",
        completed: 1,
        total: Some(1),
    });

    // Every problem is reported as a warning diagnostic *and* in the typed
    // result. The diagnostic is for a caller that reads only diagnostics; the
    // result is for one that wants the codes without matching on prose.
    let problems: Vec<ProjectProblem> = loaded
        .problems
        .iter()
        .map(|problem| ProjectProblem {
            code: problem.code.as_str(),
            subject: problem.subject.clone(),
            message: problem.message.clone(),
        })
        .collect();
    for problem in &loaded.problems {
        let diagnostic = Diagnostic::new_with_severity(
            DiagnosticCode::ProjectHasProblems,
            Severity::Warning,
            problem.to_string(),
        );
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }

    OperationOutcome {
        operation: OperationName::ProjectCheck,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectCheck(ProjectCheckResult {
            name: loaded.project.root.project.name.clone(),
            sources: loaded.project.sources.sources.len(),
            objects: loaded.project.sources.objects.len(),
            annotations: loaded
                .project
                .annotations
                .iter()
                .map(|document| document.annotations.len())
                .sum(),
            problems,
        })),
    }
}

pub(crate) fn verify(
    request: &NormalizedProject,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let Some(root) = project_root(context, request) else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::ProjectUnreadable,
            "this context serves no directory, so no project can be located",
        ));
        return OperationOutcome {
            operation: OperationName::ProjectVerify,
            status: Status::Error,
            diagnostics,
            normalized_request_sha256: Some(digest),
            result: None,
        };
    };
    let loaded = match amiga_project::load(&root) {
        Ok(loaded) => loaded,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ProjectUnreadable,
                error.to_string(),
            ));
            return OperationOutcome {
                operation: OperationName::ProjectVerify,
                status: Status::Error,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
    };

    // Recovery is supplied, because this crate is where a build's actual
    // capability set lives: an object the toolkit can recover must be recovered
    // here too, or the router would report a project the command line verifies
    // as contradicted. What this build cannot recover still comes back as a
    // stated reason, never as a shorter report.
    // Machine-local overrides, so a project whose media lives outside its root
    // verifies on the machine that holds it. Anything wrong with the file is a
    // warning that travels with the report: the project still loaded, and a
    // source whose override was dropped reports as unbound rather than silently
    // resolving somewhere else.
    let (bindings, binding_diagnostics) = crate::local::load_bindings(&root);
    diagnostics.extend(binding_diagnostics);

    let recovery = crate::recovery::ContainerRecovery::from_limits(context.limits());
    let report = amiga_project::verify::verify_with_limits(
        &loaded.project,
        &bindings,
        &recovery,
        context.limits().verification_limits(),
    );
    events.emit(OperationEvent::Progress {
        phase: "verify_sources",
        completed: report.verified_sources() as u64,
        total: Some(report.sources.len() as u64),
    });

    let sources: Vec<VerifiedEntity> = report
        .sources
        .iter()
        .map(|(id, status)| {
            let (code, mut detail) = describe_source(status);
            // A captured source verifies exactly as media does and means less
            // by it: the digest says these are the bytes that were recorded and
            // nothing here can produce them again. Said in the report rather
            // than left for a reader to work out from the document.
            let captured = loaded
                .project
                .sources
                .sources
                .iter()
                .any(|source| &source.id == id && !source.is_reproducible());
            if captured {
                detail.push_str(
                    "; captured evidence — verifiable against itself and not reproducible \
                     by anything in this format",
                );
            }
            VerifiedEntity {
                id: id.clone(),
                status: code,
                verified: status.is_verified(),
                contradicted: status.contradicts(),
                detail,
            }
        })
        .collect();
    let objects: Vec<VerifiedEntity> = report
        .objects
        .iter()
        .map(|(id, status)| {
            let (code, detail) = describe_object(status);
            VerifiedEntity {
                id: id.clone(),
                status: code,
                verified: status.is_verified(),
                contradicted: status.contradicts(),
                detail,
            }
        })
        .collect();

    // Artifacts are checked here rather than beside the sources, because they
    // are not project truth: they record what was made, and the three answers
    // they can give carry three different weights.
    let artifacts = verify_artifacts(&loaded.project, &root, context.limits());
    let artifact_contradicted = artifacts.iter().any(|artifact| artifact.contradicted);

    // A contradiction is an error; absent media is not. That distinction is the
    // whole point of the status vocabulary, and collapsing it here would undo
    // it at the API boundary.
    let status = if report.contradicted() || artifact_contradicted {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::ProjectContradicted,
            "the bytes on disk contradict what the project pins",
        ));
        Status::Error
    } else {
        Status::Success
    };

    OperationOutcome {
        operation: OperationName::ProjectVerify,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectVerify(ProjectVerifyResult {
            verified_sources: report.verified_sources(),
            verified_objects: report.verified_objects(),
            sources,
            objects,
            artifacts,
        })),
    }
}

/// Check every recorded artifact against the bytes on disk.
///
/// `Artifact.sha256` is only worth recording if something compares it, and
/// nothing did. This is that comparison, and it deliberately produces three
/// different answers rather than one: a missing file is regenerable, a stale
/// recipe key is the normal state after an edit, and only a digest that
/// disagrees is a contradiction.
///
/// Same symlink discipline as every other read here. A path that escapes the
/// project root or is reached through a link is refused rather than read: an
/// artifact record must not be able to make a verify open `/etc/shadow` and
/// report its digest.
fn verify_artifacts(
    project: &amiga_project::document::Project,
    root: &std::path::Path,
    limits: crate::limits::OperationLimits,
) -> Vec<crate::response::VerifiedArtifact> {
    use crate::response::VerifiedArtifact;

    // Artifact reads have their own aggregate allowance, separate from the
    // source/derivation pass, using the same context input-byte limits.
    let mut remaining = limits.maximum_total_input_bytes();
    let mut checked = Vec::new();
    for document in &project.resources {
        for artifact in &document.artifacts {
            let resource = project
                .resources
                .iter()
                .flat_map(|other| &other.resources)
                .find(|candidate| candidate.id() == &artifact.resource_id);
            let current = resource
                .is_some_and(|resource| amiga_project::is_current(project, resource, artifact));

            let target = root.join(&artifact.path);
            let (status, present, contradicted, detail) =
                match read_artifact(root, &target, limits.maximum_input_bytes(), &mut remaining) {
                    Err(reason) => ("refused", false, true, reason),
                    Ok(None) => (
                        "missing",
                        false,
                        false,
                        "not on disk; the project is intact and it can be remade".to_owned(),
                    ),
                    Ok(Some(digest)) => {
                        if digest == artifact.sha256 {
                            if current {
                                (
                                    "current",
                                    true,
                                    false,
                                    "the file is what it says".to_owned(),
                                )
                            } else {
                                (
                                    "stale",
                                    true,
                                    false,
                                    "the recipe changed since it was made; re-export to refresh it"
                                        .to_owned(),
                                )
                            }
                        } else {
                            (
                                "mismatch",
                                false,
                                true,
                                format!(
                                    "the record pins {}, and the file is {}",
                                    short(&artifact.sha256),
                                    short(&digest)
                                ),
                            )
                        }
                    }
                };
            checked.push(VerifiedArtifact {
                id: artifact.id.clone(),
                resource_id: artifact.resource_id.clone(),
                path: artifact.path.clone(),
                status,
                present,
                current,
                contradicted,
                detail,
            });
        }
    }
    checked
}

/// An artifact's streamed digest, or `None` when the file is simply not there.
///
/// `Err` reports an unsafe path, unreadable file, or exhausted byte allowance.
fn read_artifact(
    root: &std::path::Path,
    target: &std::path::Path,
    maximum: u64,
    remaining: &mut u64,
) -> Result<Option<String>, String> {
    if !target.starts_with(root) || target.components().any(|part| part.as_os_str() == "..") {
        return Err("the recorded path leaves the project root".to_owned());
    }
    // Every ancestor as well as the file: a link anywhere on the way is the
    // same escape as a link at the end.
    let mut ancestor = target;
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symbolic link", ancestor.display()));
            }
            Ok(metadata) if ancestor == target && !metadata.is_file() => {
                return Err("artifact is not a regular file".to_owned());
            }
            _ => {}
        }
        if ancestor == root {
            break;
        }
        match ancestor.parent() {
            Some(parent) => ancestor = parent,
            None => break,
        }
    }
    match std::fs::File::open(target) {
        Ok(file) => {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() {
                return Err("artifact is not a regular file".to_owned());
            }
            let limit = maximum.min(*remaining);
            if metadata.len() > limit {
                return Err(format!(
                    "artifact exceeds the available {limit}-byte verification budget"
                ));
            }
            hash_artifact(file, maximum, remaining).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// Hash actual bytes in fixed storage. Metadata is only an early refusal;
/// a growing or inconsistently sized file must still obey the read allowance.
fn hash_artifact(
    mut reader: impl std::io::Read,
    maximum: u64,
    remaining: &mut u64,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let limit = maximum.min(*remaining);
    let mut consumed = 0_u64;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let allowance = limit - consumed;
        let width = usize::try_from(allowance.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = match reader.read(&mut buffer[..width]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(|error| error.to_string())?,
        };
        if count == 0 {
            return Ok(hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect());
        }
        *remaining = remaining.saturating_sub(count as u64);
        if count as u64 > allowance {
            return Err(format!(
                "artifact exceeds the available {limit}-byte verification budget"
            ));
        }
        consumed += count as u64;
        hash.update(&buffer[..count]);
    }
}

/// One source status as a stable code and a sentence.
///
/// Shared status text lets the CLI and downstream tools report the same source state
/// using stable codes and a human-readable explanation.
fn describe_source(status: &amiga_project::SourceStatus) -> (&'static str, String) {
    use amiga_project::SourceStatus as S;
    match status {
        S::Verified => ("verified", "the bytes on disk match the pin".to_owned()),
        S::Unbound => (
            "unbound",
            "unbound (this machine has no path for it)".to_owned(),
        ),
        S::Missing { path } => ("missing", format!("missing at {}", path.display())),
        S::Unreadable { path, reason } => (
            "unreadable",
            format!("unreadable at {}: {reason}", path.display()),
        ),
        S::Mismatch {
            path,
            expected,
            actual,
        } => (
            "mismatch",
            format!(
                "at {}: pinned {}, found {}",
                path.display(),
                short(expected),
                short(actual)
            ),
        ),
        S::SizeMismatch {
            path,
            expected,
            actual,
        } => (
            "size_mismatch",
            match expected {
                Some(expected) => format!(
                    "at {}: the bytes match the pin, but the record says {expected} byte(s) \
                     and the file is {actual}",
                    path.display()
                ),
                None => format!(
                    "at {}: the bytes match the pin, and the record states no size; \
                     the file is {actual} byte(s)",
                    path.display()
                ),
            },
        ),
    }
}

/// One object status as a stable code and a sentence.
fn describe_object(status: &amiga_project::ObjectStatus) -> (&'static str, String) {
    use amiga_project::ObjectStatus as S;
    match status {
        S::Verified => (
            "verified",
            "reproduced from verified inputs and matches its pin".to_owned(),
        ),
        S::ParentUnavailable => (
            "parent_unavailable",
            "not attempted (a parent or recipe input is unavailable)".to_owned(),
        ),
        S::SelectorOutOfRange => (
            "selector_out_of_range",
            "the selector runs past its parent".to_owned(),
        ),
        S::Unrecoverable { reason } => ("unrecoverable", reason.clone()),
        S::Mismatch { expected, actual } => (
            "mismatch",
            format!("pinned {}, recovered {}", short(expected), short(actual)),
        ),
        S::SizeMismatch { expected, actual } => (
            "size_mismatch",
            format!(
                "the recovered bytes match the pin, but the record says {expected} byte(s) \
                 and {actual} were recovered"
            ),
        ),
    }
}

/// A digest shortened for reading, without assuming it is one.
///
/// A digest reaches here from a hand-edited document, and no validation rule
/// pins its length. Slicing it blind would turn a typo in a project file into a
/// panic in whichever frontend rendered it first.
fn short(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

/// The host directory the project locator names.
///
/// `None` when the adapter's resolver has no directory — an in-memory one, say.
/// The operation refuses rather than inventing a root.
/// `project.describe` — what a project says it is about.
///
/// A summary rather than the documents: every id, every digest, and every count
/// a reader needs to decide whether this is the right project and what it
/// covers, without loading five documents to find out. The rendering — which
/// columns, which order, what goes to standard error — stays with the caller.
///
/// Problems the load tolerated travel in the result. A project that opened with
/// problems is still a project that opened, which is the property the format
/// exists for.
pub(crate) fn describe(
    request: &NormalizedProject,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let refused = |diagnostics, digest| OperationOutcome {
        operation: OperationName::ProjectDescribe,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    };
    let Some(root) = project_root(context, request) else {
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
    for problem in &loaded.problems {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ProjectHasProblems,
            problem.to_string(),
        ));
    }

    let project = &loaded.project;
    let result = ProjectDescribeResult {
        id: project.root.project.id.clone(),
        name: project.root.project.name.clone(),
        notes: project.root.project.notes.clone(),
        sources: project
            .sources
            .sources
            .iter()
            .map(|source| ProjectSource {
                id: source.id.clone(),
                kind: format!("{:?}", source.kind).to_lowercase(),
                display_name: source.display_name.clone(),
                size: source.size,
                // A file's own digest, else a directory tree's. Which of the
                // two it is travels beside it, because a tree digest answers a
                // different question from a file's.
                sha256: source.sha256.clone().or_else(|| source.tree_sha256.clone()),
                tree: source.sha256.is_none() && source.tree_sha256.is_some(),
                locations: source
                    .locations
                    .iter()
                    .map(|location| match location {
                        amiga_project::document::Location::ProjectRelative { path } => path.clone(),
                    })
                    .collect(),
                reproducible: source.is_reproducible(),
            })
            .collect(),
        source_sets: project
            .sources
            .source_sets
            .iter()
            .map(|set| ProjectSourceSet {
                id: set.id.clone(),
                member_count: set.members.len() as u64,
            })
            .collect(),
        objects: project
            .sources
            .objects
            .iter()
            .map(|object| ProjectObject {
                id: object.id.clone(),
                parent_id: object.parent_id.clone(),
                size: object.size,
                sha256: object.sha256.clone(),
                derivation: match &object.selector {
                    None => None,
                    Some(amiga_project::document::Selector::Decompressed { codec, .. }) => {
                        Some(codec.name().to_owned())
                    }
                    Some(selector) => Some(selector.container().to_owned()),
                },
            })
            .collect(),
        programs: project
            .programs
            .iter()
            .map(|program| ProjectProgram {
                id: program.id.clone(),
                name: program.name.clone(),
                images: program
                    .images
                    .iter()
                    .map(|image| ProjectImage {
                        id: image.id.clone(),
                        object_id: image.object_id.clone(),
                        load_maps: image
                            .load_maps
                            .iter()
                            .map(|map| ProjectLoadMap {
                                id: map.id.clone(),
                                segments: map
                                    .segments
                                    .iter()
                                    .map(|segment| ProjectLoadSegment {
                                        hunk: segment.hunk,
                                        runtime_base: segment.runtime_base.clone(),
                                    })
                                    .collect(),
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        annotation_count: project
            .annotations
            .iter()
            .map(|document| document.annotations.len() as u64)
            .sum(),
        resource_count: project
            .resources
            .iter()
            .map(|document| document.resources.len() as u64)
            .sum(),
        resources: described_resources(project),
        type_count: project
            .types
            .iter()
            .map(|document| document.types.len() as u64)
            .sum(),
        types: project
            .types
            .iter()
            .flat_map(|document| &document.types)
            .map(|definition| crate::response::ProjectType {
                id: definition.id().clone(),
                kind: definition.kind().to_owned(),
                name: definition.name().to_owned(),
            })
            .collect(),
        problems: loaded.problems.iter().map(ToString::to_string).collect(),
    };
    OperationOutcome {
        operation: OperationName::ProjectDescribe,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectDescribe(result)),
    }
}

/// Every resource the project records, with the artifact it produced.
///
/// A resource is the *recipe* — these bytes are a 320×256 four-plane image with
/// that palette — and the artifact is what running it once made. Reported
/// together because the question anyone asks about a resource is "has this been
/// exported, and does the file still follow from what the project says now",
/// and answering it from two places would mean joining them in every frontend.
///
/// Currency is `recipe::is_current`'s answer, not a re-derivation: it compares
/// the artifact's recorded `recipe_key` against the key the project's *current*
/// recipe produces, dependencies resolved. A resource whose palette was edited
/// invalidates its image, which is the property that key exists for.
///
/// Nothing here reads the artifact's file. Whether the bytes on disk are still
/// the recorded ones is `project.verify`'s question, and it needs disk access
/// this operation deliberately does not take.
fn described_resources(project: &amiga_project::Project) -> Vec<ProjectResource> {
    let artifacts: Vec<&amiga_project::document::Artifact> = project
        .resources
        .iter()
        .flat_map(|document| &document.artifacts)
        .collect();
    let mut described = Vec::new();
    for document in &project.resources {
        for resource in &document.resources {
            described.push(ProjectResource {
                id: resource.id().to_string(),
                kind: resource.kind(),
                name: resource_name(resource).to_owned(),
                target: resource.target().into(),
                target_resolved: resource_target_resolves(project, resource.target()),
                export_media_type: resource.export_profile().media_type,
                artifacts: artifacts
                    .iter()
                    .filter(|artifact| artifact.resource_id.as_str() == resource.id().as_str())
                    .map(|artifact| ProjectArtifact {
                        id: artifact.id.clone(),
                        path: artifact.path.clone(),
                        media_type: artifact.media_type.clone(),
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                        recipe_key: artifact.recipe_key.clone(),
                        current: amiga_project::recipe::is_current(project, resource, artifact),
                    })
                    .collect(),
            });
        }
    }
    described
}

fn resource_target_resolves(
    project: &amiga_project::Project,
    target: &amiga_project::document::Target,
) -> bool {
    use amiga_project::document::Target;

    let image = |id: &str| {
        project
            .programs
            .iter()
            .flat_map(|program| &program.images)
            .find(|image| image.id.as_str() == id)
    };
    match target {
        Target::Object { object_id, .. } => project
            .sources
            .objects
            .iter()
            .any(|object| object.id.as_str() == object_id.as_str()),
        Target::Hunk { image_id, .. } | Target::BaseRegister { image_id, .. } => {
            image(image_id.as_str()).is_some()
        }
        Target::Runtime {
            image_id,
            load_map_id,
            ..
        } => image(image_id.as_str()).is_some_and(|image| {
            image
                .load_maps
                .iter()
                .any(|map| map.id.as_str() == load_map_id.as_str())
        }),
        Target::Entity { entity_id } => project
            .annotations
            .iter()
            .flat_map(|document| &document.annotations)
            .any(|annotation| annotation.id().as_str() == entity_id.as_str()),
    }
}

/// A resource's reviewed name, which every kind carries.
fn resource_name(resource: &amiga_project::document::Resource) -> &str {
    use amiga_project::document::Resource as R;
    match resource {
        R::Image { name, .. }
        | R::Palette { name, .. }
        | R::Audio { name, .. }
        | R::Table { name, .. }
        | R::Text { name, .. }
        | R::Code { name, .. }
        | R::Copper { name, .. }
        | R::Data { name, .. }
        | R::Opaque { name, .. } => name,
    }
}

/// `project.annotations` — the reviewed knowledge about one image or one
/// object.
///
/// The whole point of the format, reachable at last: names a person recorded,
/// the comments they wrote, the regions they classified, and the locals and
/// base-register globals they identified.
///
/// **Two scopes, because a project holds two kinds of thing.** An *image* is a
/// loaded program, so its knowledge is resolved through `amiga_project::Index`
/// into hunk offsets — the index's answer rather than a second traversal that
/// could disagree with it. An *object* is bytes derived from a source, so its
/// knowledge is every annotation targeting those bytes, in file order. The
/// second scope is not a convenience: a project `project.init` created has
/// objects and no image at all, so image scope alone would leave every project
/// this toolkit can create unable to report what is known about it.
///
/// Stale annotations are excluded from every *image* lookup and listed
/// separately. That list is project-wide rather than per image, because the
/// index excludes them before it knows which image asked — and a stale
/// annotation is not knowledge about anywhere. Object scope reports them in
/// place instead, marked: the caller asked what is recorded about these bytes,
/// and "there is an annotation here you have to rebase" is the answer, not an
/// omission.
pub(crate) fn annotations(
    request: &NormalizedProjectAnnotations,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let refused = |diagnostics, digest| OperationOutcome {
        operation: OperationName::ProjectAnnotations,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    };
    let Some(root) = project_root(context, &request.project) else {
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

    let images: Vec<String> = loaded
        .project
        .programs
        .iter()
        .flat_map(|program| &program.images)
        .map(|image| image.id.clone())
        .collect();
    let objects: Vec<String> = loaded
        .project
        .sources
        .objects
        .iter()
        .map(|object| object.id.clone())
        .collect();

    let image = match &request.scope {
        AnnotationScope::Object(object) => {
            let Some(described) = loaded
                .project
                .sources
                .objects
                .iter()
                .find(|candidate| candidate.id.as_str() == object.as_str())
            else {
                // The list of what *is* here travels with the refusal, so a
                // caller who named the wrong object is not sent back to ask a
                // second question.
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!(
                            "no object {object:?} in this project; it derives {}",
                            objects.join(", ")
                        ),
                    )
                    .at("$.request.arguments.object"),
                );
                return refused(diagnostics, digest);
            };
            let established = described.sha256.clone();
            return object_annotations(
                request,
                &loaded.project,
                object,
                &established,
                images,
                objects,
                diagnostics,
                digest,
            );
        }
        AnnotationScope::Image(image) => image,
    };
    if !images.contains(image) {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "no image {image:?} in this project; it describes {}",
                    images.join(", ")
                ),
            )
            .at("$.request.arguments.image"),
        );
        return refused(diagnostics, digest);
    }

    let index = amiga_project::Index::build(&loaded.project);

    // Walk the annotations of this image in document order, then sort, so the
    // result is the index's answer at each offset rather than a traversal that
    // could disagree with it.
    let mut located: Vec<(u32, u64)> = Vec::new();
    for document in &loaded.project.annotations {
        for annotation in &document.annotations {
            if let Some(amiga_project::document::Target::Hunk {
                image_id,
                hunk,
                offset,
                ..
            }) = annotation.target()
                && image_id.as_str() == image.as_str()
            {
                located.push((*hunk, *offset));
            }
        }
    }
    located.sort_unstable();
    located.dedup();

    let mut locations = Vec::new();
    for (hunk, offset) in located {
        let resolved = index.at(image, hunk, offset);
        if resolved.is_empty() {
            continue;
        }
        locations.push(AnnotatedLocation {
            hunk,
            offset,
            function: resolved.function.map(str::to_owned),
            symbols: resolved
                .symbols
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            regions: resolved
                .regions
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            bookmarks: resolved
                .bookmarks
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            comments: resolved
                .comments
                .iter()
                .map(|comment| AnnotationComment {
                    placement: comment.placement.to_owned(),
                    text: comment.text.to_owned(),
                })
                .collect(),
        });
    }

    let mut locals = Vec::new();
    for document in &loaded.project.annotations {
        for annotation in &document.annotations {
            let amiga_project::document::Annotation::Function {
                id, name, target, ..
            } = annotation
            else {
                continue;
            };
            if target
                .image_id()
                .is_none_or(|owner| owner.as_str() != image.as_str())
            {
                continue;
            }
            for local in index.locals(id) {
                locals.push(AnnotatedLocal {
                    function_id: id.to_string(),
                    function_name: name.clone(),
                    name: local.name.to_owned(),
                    storage: match local.storage {
                        amiga_project::LocalStorage::Register(register) => LocalStorage::Register {
                            register: register.to_owned(),
                        },
                        amiga_project::LocalStorage::Stack { base, displacement } => {
                            LocalStorage::Stack {
                                base: base.to_owned(),
                                displacement,
                            }
                        }
                    },
                    lifetime: local.lifetime.map(|(start, end)| [start, end]),
                });
            }
        }
    }

    let location_total = locations.len();
    let locations_truncated = location_total > request.maximum_locations;
    if locations_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{location_total} annotated locations were found; {} are reported",
                request.maximum_locations
            ),
        ));
    }

    let result = ProjectAnnotationsResult {
        image: Some(image.clone()),
        object: None,
        images,
        objects,
        locations: locations
            .into_iter()
            .take(request.maximum_locations)
            .collect(),
        location_total: location_total as u64,
        locations_truncated,
        // Empty rather than absent: an image's knowledge lives in hunk space,
        // and reporting object ranges here would mix two address spaces in one
        // answer, which is the confusion the scope split exists to prevent.
        ranges: Vec::new(),
        range_total: 0,
        ranges_truncated: false,
        locals,
        globals: index
            .globals(image)
            .into_iter()
            .map(|global| AnnotatedGlobal {
                name: global.name.to_owned(),
                base: global.base.to_owned(),
                displacement: global.displacement,
                width: global.width,
            })
            .collect(),
        stale: index.stale().iter().map(ToString::to_string).collect(),
    };
    OperationOutcome {
        operation: OperationName::ProjectAnnotations,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectAnnotations(result)),
    }
}

/// Every annotation targeting one object's bytes, in file order.
///
/// No index lookup, and deliberately so: `amiga_project::Index` resolves hunk
/// offsets within a loaded image, and an object is bytes before anything loads
/// them. What a caller asking about an object wants is the list of claims made
/// about those bytes — each with the range it covers, who made it, and whether
/// the bytes it was established against are still the object's — which is the
/// document read straight, sorted.
///
/// A stale annotation is reported in place with `established: false` rather
/// than being lifted into a separate list. The image scope excludes stale
/// annotations because it resolves *through* them, and a resolved offset backed
/// by moved bytes would be a wrong answer; here nothing is resolved, so hiding
/// the annotation would only hide the thing the reader has to act on.
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is a distinct fact the answer needs, and grouping \
              them into a struct used by one caller would hide rather than \
              simplify"
)]
fn object_annotations(
    request: &NormalizedProjectAnnotations,
    project: &amiga_project::Project,
    object: &str,
    established: &str,
    images: Vec<String>,
    objects: Vec<String>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
) -> OperationOutcome {
    // Comments about an annotation rather than about bytes, keyed by what they
    // are about. Collected first so that a comment written in a document read
    // after the annotation it is about still lands under it: nothing orders the
    // documents, and a single pass would report a comment only when it happened
    // to come second.
    let mut about: std::collections::BTreeMap<String, Vec<crate::response::EntityComment>> =
        std::collections::BTreeMap::new();
    for document in &project.annotations {
        for annotation in &document.annotations {
            let (Some(amiga_project::document::Target::Entity { entity_id }), true) = (
                annotation.target(),
                matches!(
                    annotation,
                    amiga_project::document::Annotation::Comment { .. }
                ),
            ) else {
                continue;
            };
            let amiga_project::document::Annotation::Comment {
                placement, text, ..
            } = annotation
            else {
                continue;
            };
            about
                .entry(entity_id.clone())
                .or_default()
                .push(crate::response::EntityComment {
                    id: annotation.id().to_string(),
                    origin: origin_code(annotation_origin(annotation)).to_owned(),
                    placement: placement.clone(),
                    text: text.clone(),
                });
        }
    }
    for comments in about.values_mut() {
        comments.sort_by(|left, right| left.id.cmp(&right.id));
    }

    let mut ranges = Vec::new();
    for document in &project.annotations {
        for annotation in &document.annotations {
            let Some(amiga_project::document::Target::Object {
                object_id,
                offset,
                length,
                object_sha256,
            }) = annotation.target()
            else {
                continue;
            };
            if object_id.as_str() != object {
                continue;
            }
            ranges.push(AnnotatedRange {
                id: annotation.id().to_string(),
                kind: annotation_kind(annotation).to_owned(),
                origin: origin_code(annotation_origin(annotation)).to_owned(),
                offset: *offset,
                length: *length,
                label: annotation_label(annotation),
                placement: match annotation {
                    amiga_project::document::Annotation::Comment { placement, .. } => {
                        Some(placement.clone())
                    }
                    _ => None,
                },
                notes: annotation_notes(annotation),
                confidence: annotation_confidence(annotation),
                marked_stale: annotation.is_stale(),
                established: object_sha256.as_str() == established,
                about: about.get(annotation.id()).cloned().unwrap_or_default(),
            });
        }
    }
    // File order, then id: two annotations may cover the same bytes, and a
    // listing whose order depended on which document happened to be read first
    // would move under the reader between two runs that changed nothing.
    ranges.sort_by(|left, right| {
        (left.offset, left.length, &left.id).cmp(&(right.offset, right.length, &right.id))
    });

    let range_total = ranges.len();
    let ranges_truncated = range_total > request.maximum_locations;
    if ranges_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{range_total} annotated ranges were found; {} are reported",
                request.maximum_locations
            ),
        ));
    }

    let result = ProjectAnnotationsResult {
        image: None,
        object: Some(object.to_owned()),
        images,
        objects,
        locations: Vec::new(),
        location_total: 0,
        locations_truncated: false,
        ranges: ranges.into_iter().take(request.maximum_locations).collect(),
        range_total: range_total as u64,
        ranges_truncated,
        // Locals are scoped to a function in an image and globals to a base
        // register in one, so neither exists in object space. Empty is the
        // truthful answer rather than an omission.
        locals: Vec::new(),
        globals: Vec::new(),
        stale: Vec::new(),
    };
    OperationOutcome {
        operation: OperationName::ProjectAnnotations,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectAnnotations(result)),
    }
}

/// The `kind` discriminant an annotation serializes as.
const fn annotation_kind(annotation: &amiga_project::document::Annotation) -> &'static str {
    use amiga_project::document::Annotation as A;
    match annotation {
        A::Function { .. } => "function",
        A::Symbol { .. } => "symbol",
        A::Comment { .. } => "comment",
        A::Variable { .. } => "variable",
        A::Region { .. } => "region",
        A::Bookmark { .. } => "bookmark",
    }
}

/// What the annotation says, in one string, by kind.
///
/// A name for the kinds that name something, the classification for a region,
/// the text for a comment. One field rather than five optional ones: every
/// consumer wants "what does this say here", and a shape that forced each of
/// them to know which field their kind uses would push the same match into
/// every frontend.
fn annotation_label(annotation: &amiga_project::document::Annotation) -> String {
    use amiga_project::document::Annotation as A;
    match annotation {
        A::Function { name, .. }
        | A::Symbol { name, .. }
        | A::Variable { name, .. }
        | A::Bookmark { name, .. } => name.clone(),
        A::Comment { text, .. } => text.clone(),
        A::Region { classification, .. } => classification.clone(),
    }
}

const fn annotation_origin(
    annotation: &amiga_project::document::Annotation,
) -> amiga_project::document::Origin {
    use amiga_project::document::Annotation as A;
    match annotation {
        A::Function { origin, .. }
        | A::Symbol { origin, .. }
        | A::Comment { origin, .. }
        | A::Variable { origin, .. }
        | A::Region { origin, .. }
        | A::Bookmark { origin, .. } => *origin,
    }
}

/// The stable code an origin serializes as, so a frontend renders the document's
/// own word rather than a re-phrasing of it.
const fn origin_code(origin: amiga_project::document::Origin) -> &'static str {
    use amiga_project::document::Origin as O;
    match origin {
        O::User => "user",
        O::Imported => "imported",
        O::ReviewedAnalysis => "reviewed_analysis",
    }
}

fn annotation_notes(annotation: &amiga_project::document::Annotation) -> Option<String> {
    use amiga_project::document::Annotation as A;
    match annotation {
        A::Function { notes, .. }
        | A::Symbol { notes, .. }
        | A::Comment { notes, .. }
        | A::Variable { notes, .. }
        | A::Region { notes, .. }
        | A::Bookmark { notes, .. } => notes.clone(),
    }
}

fn annotation_confidence(annotation: &amiga_project::document::Annotation) -> Option<String> {
    use amiga_project::document::Annotation as A;
    match annotation {
        A::Function { confidence, .. }
        | A::Symbol { confidence, .. }
        | A::Comment { confidence, .. }
        | A::Variable { confidence, .. }
        | A::Region { confidence, .. }
        | A::Bookmark { confidence, .. } => confidence.clone(),
    }
}

/// `project.inventory` — the tree a directory source would pin.
///
/// It walks *media*, not a project, which is why the directory is an argument
/// rather than the envelope's project locator: naming it there would claim a
/// project is present. The identity is validated exactly as a source name is,
/// because it is the same kind of thing.
///
/// The tree digest is computed over every file the walk found, not over the
/// reported ones. A cap is about the response; letting it change the digest
/// would make the pin depend on how much of the answer fit.
pub(crate) fn inventory(
    request: &NormalizedProjectInventory,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let refused = |diagnostics, digest| OperationOutcome {
        operation: OperationName::ProjectInventory,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: None,
    };
    let Some(root) = context.resolver().root() else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::ProjectUnreadable,
            "this context serves no directory, so no tree can be walked",
        ));
        return refused(diagnostics, digest);
    };
    let tree = match amiga_project::build_inventory(&root.join(request.directory.as_str())) {
        Ok(tree) => tree,
        Err(reason) => {
            diagnostics.push(
                Diagnostic::error(DiagnosticCode::SourceUnreadable, reason)
                    .at("$.request.arguments.directory"),
            );
            return refused(diagnostics, digest);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "walk_tree",
        completed: tree.files.len() as u64,
        total: Some(tree.files.len() as u64),
    });

    // Computed before the cap, so the pin does not depend on the response size.
    let tree_sha256 = tree.tree_sha256();
    let file_total = tree.files.len();
    let files_truncated = file_total > request.maximum_files;
    if files_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the tree holds {file_total} files; {} are reported",
                request.maximum_files
            ),
        ));
    }
    // Omissions are warnings as well as result entries: a tree digest that
    // quietly excluded something would pin fewer bytes than the directory
    // holds, and nothing in it would say so.
    for omitted in &tree.omitted {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ContainerMemberSkipped,
            format!("omitted ({}): {}", omitted.reason, omitted.path),
        ));
    }

    let result = ProjectInventoryResult {
        directory: request.directory.as_str().to_owned(),
        files: tree
            .files
            .iter()
            .take(request.maximum_files)
            .map(|file| InventoryFile {
                path: file.path.clone(),
                size: file.size,
                sha256: file.sha256.clone(),
            })
            .collect(),
        file_total: file_total as u64,
        files_truncated,
        omitted: tree
            .omitted
            .iter()
            .map(|omitted| OmittedEntry {
                path: omitted.path.clone(),
                reason: omitted.reason.clone(),
            })
            .collect(),
        tree_sha256,
    };
    OperationOutcome {
        operation: OperationName::ProjectInventory,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ProjectInventory(result)),
    }
}

fn project_root(
    context: &ExecutionContext<'_>,
    request: &NormalizedProject,
) -> Option<std::path::PathBuf> {
    Some(context.resolver().root()?.join(request.path.as_str()))
}

#[cfg(test)]
mod artifact_tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::path::{Path, PathBuf};

    fn scratch(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("amiga-artifact-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn hashing_charges_actual_bytes_even_on_limit_failure() {
        let mut total = 10;
        let mut reader = Cursor::new(b"123456789");
        assert!(
            hash_artifact(&mut reader, 4, &mut total)
                .unwrap_err()
                .contains("budget")
        );
        assert_eq!(reader.position(), 5);
        assert_eq!(total, 5);
        assert_eq!(
            hash_artifact(Cursor::new(b"12345"), 5, &mut total).unwrap(),
            amiga_core::sha256(b"12345")
        );
        assert_eq!(total, 0);
        assert_eq!(
            hash_artifact(Cursor::new(b""), 0, &mut total).unwrap(),
            amiga_core::sha256(b"")
        );
    }

    #[test]
    fn artifact_checks_refuse_sparse_files_and_bound_aggregate_reads() {
        let root = scratch("limits");
        let sparse = root.join("sparse");
        std::fs::File::create(&sparse)
            .unwrap()
            .set_len(1 << 32)
            .unwrap();
        let mut total = 8;
        assert!(
            read_artifact(&root, &sparse, 4, &mut total)
                .unwrap_err()
                .contains("budget")
        );
        assert_eq!(
            total, 8,
            "metadata refusal must not read the sparse payload"
        );
        for name in ["one", "two", "three"] {
            let path = root.join(name);
            std::fs::write(&path, b"1234").unwrap();
            let result = read_artifact(&root, &path, 4, &mut total);
            if name == "three" {
                assert!(result.unwrap_err().contains("budget"));
            } else {
                assert_eq!(result.unwrap(), Some(amiga_core::sha256(b"1234")));
            }
        }
        assert_eq!(total, 0);
        assert_eq!(
            read_artifact(&root, &root.join("missing"), 4, &mut total).unwrap(),
            None
        );
        assert!(read_artifact(&root, &root, 4, &mut total).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_file_sizes_do_not_override_actual_stream_limits() {
        let root = scratch("growth");
        let path = root.join("bytes");
        std::fs::write(&path, b"1234").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 4);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"5")
            .unwrap();
        assert!(
            hash_artifact(file, 4, &mut 4)
                .unwrap_err()
                .contains("budget")
        );
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 5);
        std::fs::write(&path, b"12").unwrap();
        let mut total = 5;
        assert_eq!(
            hash_artifact(file, 5, &mut total).unwrap(),
            amiga_core::sha256(b"12")
        );
        assert_eq!(total, 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn artifact_links_at_the_file_parent_and_root_are_refused() {
        let root = scratch("symlinks");
        let directory = root.join("directory");
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("bytes");
        std::fs::write(&file, b"1234").unwrap();
        let file_link = root.join("file-link");
        let dir_link = root.join("dir-link");
        std::os::unix::fs::symlink(&file, &file_link).unwrap();
        std::os::unix::fs::symlink(&directory, &dir_link).unwrap();
        for (base, path) in [
            (&root, file_link),
            (&root, dir_link.join("bytes")),
            (&dir_link, dir_link.join("bytes")),
        ] {
            assert!(
                read_artifact(base, &path, 4, &mut 4)
                    .unwrap_err()
                    .contains("symbolic link")
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_reports_preserve_current_stale_mismatch_and_refusal_states() {
        let root = scratch("report");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../amiga-project/fixtures/contract");
        let mut project = amiga_project::load(&fixture).unwrap().project;
        let document_index = project
            .resources
            .iter()
            .position(|doc| !doc.artifacts.is_empty())
            .unwrap();
        let artifact = &project.resources[document_index].artifacts[0];
        let resource = project
            .resources
            .iter()
            .flat_map(|doc| &doc.resources)
            .find(|resource| resource.id() == &artifact.resource_id)
            .unwrap();
        let key =
            amiga_project::recipe::artifact_key(&project, resource, "amiga-re", "0.1.0").unwrap();
        let artifact = &mut project.resources[document_index].artifacts[0];
        artifact.recipe_key = key;
        artifact.sha256 = amiga_core::sha256(b"1234");
        let path = root.join(&artifact.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"1234").unwrap();
        let limits = crate::limits::OperationLimits::default();
        let report = verify_artifacts(&project, &root, limits);
        assert_eq!(report[0].status, "current");
        project.resources[document_index].artifacts[0].recipe_key = "0".repeat(64);
        assert_eq!(verify_artifacts(&project, &root, limits)[0].status, "stale");
        std::fs::write(&path, b"4321").unwrap();
        assert_eq!(
            verify_artifacts(&project, &root, limits)[0].status,
            "mismatch"
        );
        let report = verify_artifacts(&project, &root, limits.with_maximum_input_bytes(3));
        assert_eq!(report[0].status, "refused");
        assert!(report[0].contradicted);
        assert!(report[0].detail.contains("budget"));
        std::fs::write(&path, b"1234").unwrap();
        let artifact = project.resources[document_index].artifacts[0].clone();
        for index in 1..3 {
            let mut another = artifact.clone();
            another.id = format!("artifact:budget-{index}");
            project.resources[document_index].artifacts.push(another);
        }
        let report = verify_artifacts(
            &project,
            &root,
            limits
                .with_maximum_input_bytes(4)
                .with_maximum_total_input_bytes(8),
        );
        assert_eq!(
            report
                .iter()
                .map(|artifact| artifact.status)
                .collect::<Vec<_>>(),
            ["stale", "stale", "refused"]
        );
        assert!(report[2].detail.contains("0-byte"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
