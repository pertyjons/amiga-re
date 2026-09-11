//! Bounded, read-only loading of a complete project.
//!
//! Two properties matter more than convenience here.
//!
//! **Complete or nothing.** [`load`] returns a [`Project`] only after every
//! listed document has been read, parsed, and validated together. A partially
//! loaded project would let a caller act on knowledge whose references were
//! never checked, which is exactly what the format's reference discipline
//! exists to prevent.
//!
//! **Only what the root lists.** A document is loaded because the root names
//! it, never because it was found under `analysis/`. A stray JSON file an
//! editor left behind must not become project truth.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use jsonschema::{Registry, Validator};
use serde_json::{Value, json};
use thiserror::Error;

use crate::document::{
    AnnotationsDocument, InventoryDocument, ProgramDocument, Project, ProjectDocument,
    ResourcesDocument, SourcesDocument, TypesDocument,
};
use crate::validate::{Problem, ProblemCode, is_safe_relative, validate};
use crate::{FORMAT_VERSION, schemas};

/// The largest single document this loader will read.
///
/// Generous for hand-edited metadata and small enough that a corrupt or hostile
/// file fails immediately instead of being read into memory. Documents are JSON
/// describing bytes, never the bytes themselves, so nothing legitimate
/// approaches this.
pub const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

/// The most documents one project may list, across all kinds.
pub const MAX_DOCUMENTS: usize = 16 * 1024;

/// Schema findings retained from one document.
///
/// A hostile array can violate the same item rule millions of times. The
/// document is invalid after the first one; retaining a useful prefix keeps
/// the refusal bounded without weakening it.
pub const MAX_SCHEMA_PROBLEMS: usize = 1024;

/// The canonical name of the root document.
pub const ROOT_FILE_NAME: &str = "amiga-re.project.json";

/// Why a project could not be loaded.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is {size} bytes, above the {MAX_DOCUMENT_BYTES}-byte document limit")]
    TooLarge { path: String, size: u64 },
    #[error("{path} is not a well-formed {kind} document: {source}")]
    Malformed {
        path: String,
        kind: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path} declares format_version {found}; this build serves {FORMAT_VERSION}")]
    UnsupportedVersion { path: String, found: u32 },
    #[error("{path} declares document_kind {found:?}; {expected:?} was expected")]
    WrongKind {
        path: String,
        expected: &'static str,
        found: String,
    },
    #[error("{path} is not a usable project-relative document path")]
    UnsafePath { path: String },
    #[error("the project lists {count} documents, above the {MAX_DOCUMENTS} limit")]
    TooManyDocuments { count: usize },
    #[error("the project has {} problem(s): {}", .0.len(), render(.0))]
    Invalid(Vec<Problem>),
    #[error("the bundled project schemas could not be prepared: {message}")]
    SchemaUnavailable { message: String },
}

fn render(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// A loaded project together with the non-fatal findings it carries.
///
/// Non-fatal findings — a stale annotation, an inventory whose hash has drifted
/// — are returned rather than raised, because the whole point of detecting them
/// is that the project still opens and the user can see what needs attention.
#[derive(Debug)]
pub struct Loaded {
    pub project: Project,
    pub problems: Vec<Problem>,
}

/// Read `path`, or the root document inside it if it is a directory.
///
/// # Errors
/// Returns [`LoadError`] if any listed document is missing, oversized,
/// malformed, of the wrong kind or version, or if the assembled project fails
/// any fatal semantic rule.
pub fn load(path: &Path) -> Result<Loaded, LoadError> {
    let root_path = if path.is_dir() {
        path.join(ROOT_FILE_NAME)
    } else {
        path.to_path_buf()
    };
    let base = root_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let root: ProjectDocument = read_document(&root_path, "project")?;
    let index = &root.documents;
    let listed = 1
        + index.programs.len()
        + index.annotations.len()
        + index.resources.len()
        + index.types.len();
    if listed > MAX_DOCUMENTS {
        return Err(LoadError::TooManyDocuments { count: listed });
    }

    let sources: SourcesDocument = read_listed(&base, &index.sources, "sources")?;

    // Inventories are referenced by their source, not by the root: the root
    // lists document *kinds*, and an inventory belongs to the directory source
    // it describes.
    let mut inventories = BTreeMap::new();
    for source in &sources.sources {
        if let Some(relative) = &source.inventory {
            let inventory: InventoryDocument = read_listed(&base, relative, "inventory")?;
            inventories.insert(source.id.clone(), inventory);
        }
    }

    let mut programs = Vec::new();
    for relative in &index.programs {
        programs.push(read_listed::<ProgramDocument>(&base, relative, "program")?);
    }
    let mut annotations = Vec::new();
    for relative in &index.annotations {
        annotations.push(read_listed::<AnnotationsDocument>(
            &base,
            relative,
            "annotations",
        )?);
    }
    let mut resources = Vec::new();
    for relative in &index.resources {
        resources.push(read_listed::<ResourcesDocument>(
            &base,
            relative,
            "resources",
        )?);
    }
    let mut types = Vec::new();
    for relative in &index.types {
        types.push(read_listed::<TypesDocument>(&base, relative, "types")?);
    }

    let project = Project {
        root,
        sources,
        inventories,
        programs,
        annotations,
        resources,
        types,
    };

    // Validate the assembled whole, never a document at a time: uniqueness and
    // reference resolution are properties of the project, not of any one file.
    let problems = validate(&project);
    if problems.iter().any(Problem::is_fatal) {
        return Err(LoadError::Invalid(
            problems.into_iter().filter(Problem::is_fatal).collect(),
        ));
    }
    Ok(Loaded { project, problems })
}

/// Read one document the root listed, checking its path first.
fn read_listed<T: DocumentHeader + serde::de::DeserializeOwned>(
    base: &Path,
    relative: &str,
    kind: &'static str,
) -> Result<T, LoadError> {
    if !is_safe_relative(relative) {
        return Err(LoadError::UnsafePath {
            path: relative.to_owned(),
        });
    }
    read_document(&base.join(relative), kind)
}

fn read_document<T: DocumentHeader + serde::de::DeserializeOwned>(
    path: &Path,
    kind: &'static str,
) -> Result<T, LoadError> {
    let display = path.display().to_string();
    // Check the size before reading, so an oversized document is refused rather
    // than read and then rejected.
    let metadata = std::fs::metadata(path).map_err(|source| LoadError::Io {
        path: display.clone(),
        source,
    })?;
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(LoadError::TooLarge {
            path: display,
            size: metadata.len(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: display.clone(),
        source,
    })?;
    let document: T = serde_json::from_str(&text).map_err(|source| LoadError::Malformed {
        path: display.clone(),
        kind,
        source,
    })?;
    if document.format_version() != FORMAT_VERSION {
        return Err(LoadError::UnsupportedVersion {
            path: display,
            found: document.format_version(),
        });
    }
    if document.document_kind() != kind {
        return Err(LoadError::WrongKind {
            path: display,
            expected: kind,
            found: document.document_kind().to_owned(),
        });
    }
    Ok(document)
}

pub(crate) fn validate_document_schema(
    path: &str,
    kind: &str,
    value: &Value,
) -> Result<Vec<Problem>, LoadError> {
    let validators = schema_validators().map_err(|message| LoadError::SchemaUnavailable {
        message: message.to_owned(),
    })?;
    let Some(validator) = validators.get(kind) else {
        return Err(LoadError::SchemaUnavailable {
            message: format!("no bundled validator exists for document kind {kind:?}"),
        });
    };
    Ok(validator
        .iter_errors(value)
        .take(MAX_SCHEMA_PROBLEMS)
        .map(|error| {
            Problem::new(
                ProblemCode::DocumentSchemaViolation,
                Some(error.instance_path().as_str()),
                format!("{path} violates the {kind} schema: {error}"),
            )
        })
        .collect())
}

fn schema_validators() -> Result<&'static BTreeMap<&'static str, Validator>, &'static str> {
    static VALIDATORS: OnceLock<Result<BTreeMap<&'static str, Validator>, String>> =
        OnceLock::new();
    VALIDATORS
        .get_or_init(build_schema_validators)
        .as_ref()
        .map_err(String::as_str)
}

fn build_schema_validators() -> Result<BTreeMap<&'static str, Validator>, String> {
    let documents: Vec<(String, Value)> = schemas::ALL
        .iter()
        .map(|(_, schema)| {
            let value: Value = serde_json::from_str(schema).map_err(|error| error.to_string())?;
            let id = value["$id"]
                .as_str()
                .ok_or_else(|| "a bundled schema has no $id".to_owned())?
                .to_owned();
            Ok((id, value))
        })
        .collect::<Result<_, String>>()?;
    let registry = Registry::new()
        .extend(documents)
        .map_err(|error| error.to_string())?
        .prepare()
        .map_err(|error| error.to_string())?;
    let mut validators = BTreeMap::new();
    for kind in [
        "project",
        "sources",
        "inventory",
        "program",
        "annotations",
        "resources",
        "types",
    ] {
        let schema = schemas::for_document_kind(kind)
            .ok_or_else(|| format!("no bundled schema exists for document kind {kind:?}"))?;
        let value: Value = serde_json::from_str(schema).map_err(|error| error.to_string())?;
        let id = value["$id"]
            .as_str()
            .ok_or_else(|| format!("the {kind} schema has no $id"))?;
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&json!({ "$ref": id }))
            .map_err(|error| error.to_string())?;
        validators.insert(kind, validator);
    }
    Ok(validators)
}

/// The two fields every project document repeats.
///
/// Repeated rather than inferred from the file name, so a document moved or
/// listed under the wrong key is caught instead of being reinterpreted.
pub trait DocumentHeader {
    fn document_kind(&self) -> &str;
    fn format_version(&self) -> u32;
}

macro_rules! header {
    ($($type:ty),+ $(,)?) => {
        $(impl DocumentHeader for $type {
            fn document_kind(&self) -> &str { &self.document_kind }
            fn format_version(&self) -> u32 { self.format_version }
        })+
    };
}

header!(
    ProjectDocument,
    SourcesDocument,
    InventoryDocument,
    ProgramDocument,
    AnnotationsDocument,
    ResourcesDocument,
    TypesDocument,
);

/// Find the project root at or above `start`.
///
/// Mirrors how `amiga-re.toml` is discovered today, so opening a project from a
/// subdirectory works the way the rest of the toolkit already does.
#[must_use]
pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        let candidate = directory.join(ROOT_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = directory.parent();
    }
    None
}

/// The problem code a load error would report, for adapters that want one
/// vocabulary rather than two.
#[must_use]
pub fn error_code(error: &LoadError) -> ProblemCode {
    match error {
        LoadError::Invalid(problems) => problems
            .first()
            .map_or(ProblemCode::DocumentKindMismatch, |problem| problem.code),
        LoadError::UnsupportedVersion { .. } => ProblemCode::FormatVersionMixed,
        LoadError::WrongKind { .. } => ProblemCode::DocumentKindMismatch,
        LoadError::UnsafePath { .. } => ProblemCode::UnsafePath,
        _ => ProblemCode::DocumentKindMismatch,
    }
}
