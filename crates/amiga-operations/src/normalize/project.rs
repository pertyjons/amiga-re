//! The normalized `project.*` requests, and what filling their defaults decides.
use super::*;

/// Fully resolved `project.migrate` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectMigrate {
    pub config: NormalizedSource,
    pub name: String,
    pub image: Option<(String, String)>,
    pub destination: DestinationName,
    pub in_place: bool,
    pub policy: OutputPolicy,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `project.edit` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectEdit {
    pub project: NormalizedProject,
    pub edits: Vec<crate::request::ProjectEdit>,
}

/// Fully resolved `project.inventory` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectInventory {
    /// Validated the way a source name is, because it is the same kind of
    /// thing: an identity the adapter resolves, never a host path.
    pub directory: SourceName,
    pub maximum_files: usize,
}

/// Fully resolved `project.annotations` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectAnnotations {
    pub project: NormalizedProject,
    pub scope: AnnotationScope,
    pub maximum_locations: usize,
}

/// What one `project.annotations` request is about.
///
/// Two questions rather than two spellings of one: an image resolves knowledge
/// through the index into hunk offsets, and an object lists the annotations
/// targeting its bytes. Normalizing to an enum is what makes "exactly one" a
/// property of the type rather than a rule the operation has to re-check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnnotationScope {
    Image(String),
    Object(String),
}

/// Fully resolved container-extraction arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectExtract {
    pub project: NormalizedProject,
    /// Empty means every registered source.
    pub sources: Vec<String>,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `project.resource.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedResourceExport {
    pub project: NormalizedProject,
    pub resource: String,
    pub policy: crate::output::OutputPolicy,
}

/// Fully resolved `project.init` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectInit {
    pub name: String,
    pub destination: DestinationName,
    pub sources: Vec<SourceName>,
    pub media: crate::request::MediaPolicy,
    pub maximum_input_bytes: u64,
}

/// The canonical form of an operation whose only argument is the project.
///
/// Shared by `check`, `verify`, `describe` and `format`: each of the four asks a
/// different question, but each asks it of the whole project and of nothing
/// else, so which one was asked is carried by the operation name alone.
pub(super) fn project_document(project: &NormalizedProject) -> Value {
    json!({ "project": project.path.as_str() })
}

/// The canonical form of one `project.init`.
pub(super) fn init_document(init: &NormalizedProjectInit) -> Value {
    json!({
        "name": init.name,
        "destination": init.destination.as_str(),
        "sources": init.sources
            .iter()
            .map(|source| source.as_str())
            .collect::<Vec<_>>(),
        "media": init.media,
        "maximum_input_bytes": init.maximum_input_bytes,
    })
}

/// The canonical form of one `project.extract`.
pub(super) fn extract_document(extract: &NormalizedProjectExtract) -> Value {
    json!({
        "project": extract.project.path.as_str(),
        "sources": extract.sources,
        "maximum_input_bytes": extract.maximum_input_bytes,
    })
}

/// The canonical form of one `project.resource.export`.
pub(super) fn resource_export_document(export: &NormalizedResourceExport) -> Value {
    json!({
        "project": export.project.path.as_str(),
        "resource": export.resource,
        "policy": export.policy,
    })
}

/// The canonical form of one `project.migrate`.
pub(super) fn migrate_document(migrate: &NormalizedProjectMigrate) -> Value {
    json!({
        "config": migrate.config.canonical(),
        "name": migrate.name,
        "image": migrate.image.as_ref().map(|(id, media)| json!({
            "id": id,
            "media": media,
        })),
        "destination": migrate.destination.as_str(),
        "in_place": migrate.in_place,
        "policy": migrate.policy,
        "maximum_input_bytes": migrate.maximum_input_bytes,
    })
}

/// The canonical form of one `project.edit`.
pub(super) fn edit_document(edit: &NormalizedProjectEdit) -> Value {
    json!({
        "project": edit.project.path.as_str(),
        "edits": edit.edits,
    })
}

/// The canonical form of one `project.inventory`.
///
/// A directory rather than a project: the operation surveys a tree that is not
/// one yet, which is what makes it the only `project.*` operation with no
/// project in its digest.
pub(super) fn inventory_document(inventory: &NormalizedProjectInventory) -> Value {
    json!({
        "directory": inventory.directory.as_str(),
        "maximum_files": inventory.maximum_files,
    })
}

/// The canonical form of one `project.annotations`.
///
/// The scope is spelled as the key it was asked under rather than as a tagged
/// pair, so an image request and an object request naming the same string are
/// two different digests.
pub(super) fn annotations_document(annotations: &NormalizedProjectAnnotations) -> Value {
    match &annotations.scope {
        AnnotationScope::Image(image) => json!({
            "project": annotations.project.path.as_str(),
            "image": image,
            "maximum_locations": annotations.maximum_locations,
        }),
        AnnotationScope::Object(object) => json!({
            "project": annotations.project.path.as_str(),
            "object": object,
            "maximum_locations": annotations.maximum_locations,
        }),
    }
}

/// Resolve `project.init` arguments.
///
/// The source *count* is checked here rather than in the handler, because it is
/// a property of the request rather than of anything on disk: refusing it before
/// a single file is opened is the earliest honest point. The aggregate byte
/// ceiling cannot be checked yet — sizes are not known until the sources are
/// resolved — so the handler enforces that one.
pub(super) fn normalize_project_init(
    arguments: &crate::request::ProjectInitArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedProjectInit, Vec<Diagnostic>> {
    if arguments.name.trim().is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                "a project needs a display name; its id is derived from one",
            )
            .at("$.request.arguments.name"),
        ]);
    }
    if arguments.sources.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestMalformed,
                "a project needs at least one source; an empty one has nothing to verify",
            )
            .at("$.request.arguments.sources"),
        ]);
    }
    if arguments.sources.len() > limits.maximum_sources() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::LimitExceeded,
                format!(
                    "{} sources exceeds the ceiling of {}; register fewer, or raise the \
                     context's `maximum_sources`",
                    arguments.sources.len(),
                    limits.maximum_sources()
                ),
            )
            .at("$.request.arguments.sources"),
        ]);
    }

    let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    let mut sources = Vec::with_capacity(arguments.sources.len());
    for (index, source) in arguments.sources.iter().enumerate() {
        sources.push(SourceName::parse(source).map_err(|error| {
            vec![
                Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                    .at(format!("$.request.arguments.sources[{index}]")),
            ]
        })?);
    }
    // Two sources naming one file would produce two sources with one digest and
    // one output path. Refused here rather than deduplicated, because which of
    // the two the caller meant to drop is not this layer's guess to make.
    let mut seen = std::collections::BTreeSet::new();
    for source in &sources {
        if !seen.insert(source.as_str()) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestMalformed,
                    format!("source {:?} is named twice", source.as_str()),
                )
                .at("$.request.arguments.sources"),
            ]);
        }
    }

    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedProjectInit {
        name: arguments.name.clone(),
        destination,
        sources,
        media: arguments.media,
        maximum_input_bytes,
    })
}

/// Fill in what an `project.migrate` request left unsaid.
pub(super) fn migrate(
    arguments: &crate::request::ProjectMigrateArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::ProjectMigrate(
        NormalizedProjectMigrate {
            config: normalize_named_source(&arguments.config, "$.request.arguments.config.path")?,
            name: arguments.name.clone(),
            image: arguments
                .image
                .as_ref()
                .map(|image| (image.id.clone(), image.media.clone())),
            destination: DestinationName::parse(&arguments.destination).map_err(|error| {
                vec![
                    Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                        .at("$.request.arguments.destination"),
                ]
            })?,
            in_place: arguments.in_place,
            policy: arguments.policy.unwrap_or_default(),
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `project.edit` request left unsaid.
pub(super) fn edit(
    arguments: &crate::request::ProjectEditArguments,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    // An empty edit list would prepare a plan that changes nothing and
    // commit it, which reads as "the edit was applied".
    if arguments.edits.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "edits must name at least one change; an empty plan that commits reads \
                 as an edit that was applied",
            )
            .at("$.request.arguments.edits"),
        ]);
    }
    Ok(NormalizedOperation::ProjectEdit(NormalizedProjectEdit {
        project: normalize_project(envelope.project.as_ref())?,
        edits: arguments.edits.clone(),
    }))
}

/// Fill in what an `project.inventory` request left unsaid.
pub(super) fn inventory(
    arguments: &crate::request::ProjectInventoryArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::ProjectInventory(
        NormalizedProjectInventory {
            directory: SourceName::parse(&arguments.directory).map_err(|error| {
                vec![
                    Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                        .at("$.request.arguments.directory"),
                ]
            })?,
            maximum_files: normalize_count(
                arguments.maximum_files,
                limits.maximum_entries(),
                "maximum_files",
                "files",
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `project.annotations` request left unsaid.
pub(super) fn annotations(
    arguments: &crate::request::ProjectAnnotationsArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let named = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    // Exactly one scope. Neither is not "everything" — an offset means
    // nothing until you say what it is an offset into — and both would
    // be two questions answered as one.
    let scope = match (named(&arguments.image), named(&arguments.object)) {
        (Some(image), None) => AnnotationScope::Image(image),
        (None, Some(object)) => AnnotationScope::Object(object),
        (Some(_), Some(_)) => {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "name an image or an object, not both: they are different \
                     questions, and one answer cannot be about both address spaces",
                )
                .at("$.request.arguments.object"),
            ]);
        }
        (None, None) => {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "name the image or the object to report knowledge about; an \
                     offset means nothing until you say what it is an offset into",
                )
                .at("$.request.arguments.image"),
            ]);
        }
    };
    Ok(NormalizedOperation::ProjectAnnotations(
        NormalizedProjectAnnotations {
            project: normalize_project(envelope.project.as_ref())?,
            scope,
            maximum_locations: normalize_count(
                arguments.maximum_locations,
                limits.maximum_entries(),
                "maximum_locations",
                "locations",
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `project.resource.export` request left unsaid.
pub(super) fn resource_export(
    arguments: &crate::request::ResourceExportArguments,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    if arguments.resource.trim().is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "an export names the resource it produces",
            )
            .at("$.request.arguments.resource"),
        ]);
    }
    Ok(NormalizedOperation::ProjectResourceExport(
        NormalizedResourceExport {
            project: normalize_project(envelope.project.as_ref())?,
            resource: arguments.resource.clone(),
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `project.extract` request left unsaid.
pub(super) fn extract(
    arguments: &crate::request::ProjectExtractArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
    envelope: &RequestEnvelope,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedOperation::ProjectExtract(
        NormalizedProjectExtract {
            project: normalize_project(envelope.project.as_ref())?,
            sources: arguments.sources.clone(),
            maximum_input_bytes,
        },
    ))
}
