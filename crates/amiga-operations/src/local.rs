//! Machine-local source bindings: `.amiga-re/local.json`.
//!
//! A project document never contains a host path. `Location` has one variant,
//! `ProjectRelative`, and it is documented as a hint rather than an identity —
//! the identity is the digest. That is what lets a project open on a machine
//! that keeps its media somewhere else, and it leaves one question unanswered:
//! *where*, on this machine, is that media?
//!
//! This file is the answer, and it lives here rather than in `amiga-project`
//! for the same reason source resolution does: the format crate must stay free
//! of host-path policy, and a project root is something the operation layer
//! already knows. `amiga_project::Bindings` provides `bind` and `locate`; this
//! module is what fills one from disk.
//!
//! It is deliberately outside the project's document set. It is not indexed by
//! the root document, it is not part of what a digest covers, and it is
//! git-ignored, because a path that is true on one machine is noise on every
//! other.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::diagnostics::{Diagnostic, DiagnosticCode};

/// Where the bindings live, relative to the project root.
pub const LOCAL_BINDINGS_PATH: &str = ".amiga-re/local.json";

/// The `document_kind` a bindings document declares.
pub const LOCAL_BINDINGS_KIND: &str = "local";

/// The format version this build writes and understands.
pub const LOCAL_BINDINGS_VERSION: u32 = 1;

/// One machine's answer to "where is this source kept here?".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBindings {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    /// Source ID to host path. Absolute or relative to the project root.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, String>,
}

impl LocalBindings {
    /// An empty document of the current kind and version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: None,
            document_kind: LOCAL_BINDINGS_KIND.to_owned(),
            format_version: LOCAL_BINDINGS_VERSION,
            bindings: BTreeMap::new(),
        }
    }

    /// Record that `id` lives at `path` on this machine.
    #[must_use]
    pub fn with_binding(mut self, id: impl Into<String>, path: impl Into<String>) -> Self {
        self.bindings.insert(id.into(), path.into());
        self
    }
}

/// Read `.amiga-re/local.json` under `root` into project bindings.
///
/// A missing file is the normal case and produces no diagnostic: most projects
/// keep their media under their own root and need no overrides.
///
/// Everything that *is* wrong produces a warning and is then skipped, rather
/// than failing the operation. The project itself is still readable, and a
/// source whose override was dropped reports as unbound — a stated outcome the
/// caller can act on. Silently ignoring a malformed override would leave the
/// same outcome with no way to tell why.
///
/// A binding is refused when its path is reached through a symbolic link, on
/// the same terms as every other path this toolkit reads: a link here could
/// redirect verification at bytes the project never named.
#[must_use]
pub fn load_bindings(root: &Path) -> (amiga_project::Bindings, Vec<Diagnostic>) {
    let mut bindings = amiga_project::Bindings::new(root);
    let mut diagnostics = Vec::new();
    let path = root.join(LOCAL_BINDINGS_PATH);

    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (bindings, diagnostics);
        }
        Err(error) => {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::LocalBindingsUnreadable,
                format!("{LOCAL_BINDINGS_PATH} could not be read: {error}"),
            ));
            return (bindings, diagnostics);
        }
    };

    let document: LocalBindings = match serde_json::from_str(&text) {
        Ok(document) => document,
        Err(error) => {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::LocalBindingsUnreadable,
                format!("{LOCAL_BINDINGS_PATH} is not a usable bindings document: {error}"),
            ));
            return (bindings, diagnostics);
        }
    };

    if document.document_kind != LOCAL_BINDINGS_KIND {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::LocalBindingsUnreadable,
            format!(
                "{LOCAL_BINDINGS_PATH} declares document_kind {:?}, expected {LOCAL_BINDINGS_KIND:?}",
                document.document_kind
            ),
        ));
        return (bindings, diagnostics);
    }
    if document.format_version != LOCAL_BINDINGS_VERSION {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::LocalBindingsUnreadable,
            format!(
                "{LOCAL_BINDINGS_PATH} declares format_version {}, this build understands {LOCAL_BINDINGS_VERSION}",
                document.format_version
            ),
        ));
        return (bindings, diagnostics);
    }

    for (id, bound) in document.bindings {
        // Resolve relative to the project root so a binding has the same meaning on
        // machines that keep media beside the project.
        let resolved = root.join(&bound);
        if let Err(error) = amiga_core::safepath::reject_symlink(&resolved) {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::LocalBindingsUnreadable,
                format!("{LOCAL_BINDINGS_PATH} binds {id} through a symbolic link: {error}"),
            ));
            continue;
        }
        bindings = bindings.bind(id, resolved);
    }

    (bindings, diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "amiga-operations-local-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join(".amiga-re")).unwrap_or_else(|error| panic!("{error}"));
        path
    }

    fn write(root: &Path, text: &str) {
        std::fs::write(root.join(LOCAL_BINDINGS_PATH), text)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn a_missing_file_is_the_normal_case_and_says_nothing() {
        let root =
            std::env::temp_dir().join(format!("amiga-operations-absent-{}", std::process::id()));
        let (_, diagnostics) = load_bindings(&root);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn a_binding_resolves_relative_to_the_project_root() {
        let root = root("relative");
        std::fs::write(root.join("disk.adf"), b"bytes").unwrap_or_else(|error| panic!("{error}"));
        write(
            &root,
            r#"{"document_kind":"local","format_version":1,
                "bindings":{"source:disk-1":"disk.adf"}}"#,
        );
        let (bindings, diagnostics) = load_bindings(&root);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        // An empty project still resolves a bound ID: a binding wins over the
        // project's hint, so it does not need one to exist.
        let project = empty_project();
        assert_eq!(
            bindings.locate(&project, "source:disk-1"),
            Some(root.join("disk.adf"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_malformed_document_warns_and_binds_nothing() {
        let root = root("malformed");
        write(&root, "{ not json");
        let (bindings, diagnostics) = load_bindings(&root);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics[0].code, DiagnosticCode::LocalBindingsUnreadable);
        assert_eq!(bindings.locate(&empty_project(), "source:disk-1"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_future_version_warns_rather_than_guessing() {
        let root = root("version");
        write(
            &root,
            r#"{"document_kind":"local","format_version":99,
                "bindings":{"source:disk-1":"disk.adf"}}"#,
        );
        let (bindings, diagnostics) = load_bindings(&root);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(bindings.locate(&empty_project(), "source:disk-1"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_binding_through_a_symbolic_link_is_refused() {
        let root = root("symlink");
        std::fs::write(root.join("real.adf"), b"bytes").unwrap_or_else(|error| panic!("{error}"));
        std::os::unix::fs::symlink(root.join("real.adf"), root.join("link.adf"))
            .unwrap_or_else(|error| panic!("{error}"));
        write(
            &root,
            r#"{"document_kind":"local","format_version":1,
                "bindings":{"source:disk-1":"link.adf"}}"#,
        );
        let (bindings, diagnostics) = load_bindings(&root);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics[0].code, DiagnosticCode::LocalBindingsUnreadable);
        // Refused, not silently followed: the source reports unbound instead.
        assert_eq!(bindings.locate(&empty_project(), "source:disk-1"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A project with no sources at all.
    ///
    /// Enough for these tests: a *bound* ID resolves out of the binding map
    /// before the project is consulted, and an unbound one has to find no source
    /// here, which is exactly what an empty list gives.
    fn empty_project() -> amiga_project::Project {
        use amiga_project::document::{
            DocumentIndex, Project, ProjectDocument, ProjectIdentity, SourcesDocument,
        };
        Project {
            root: ProjectDocument {
                schema: None,
                document_kind: "project".to_owned(),
                format_version: 1,
                project: ProjectIdentity {
                    id: "project:test".to_owned(),
                    name: "Test".to_owned(),
                    notes: None,
                },
                documents: DocumentIndex {
                    sources: "analysis/sources.json".to_owned(),
                    programs: Vec::new(),
                    annotations: Vec::new(),
                    resources: Vec::new(),
                    types: Vec::new(),
                },
                directories: None,
                extensions: None,
            },
            sources: SourcesDocument {
                schema: None,
                document_kind: "sources".to_owned(),
                format_version: 1,
                sources: Vec::new(),
                source_sets: Vec::new(),
                objects: Vec::new(),
                extensions: None,
            },
            inventories: BTreeMap::new(),
            programs: Vec::new(),
            annotations: Vec::new(),
            resources: Vec::new(),
            types: Vec::new(),
        }
    }
}
