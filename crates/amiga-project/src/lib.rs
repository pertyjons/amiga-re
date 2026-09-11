//! The versioned `amiga-re` reverse-engineering project format.
//!
//! Milestone 0 settled the contract: eight hand-written Draft 2020-12 schemas
//! and a synthetic fixture proven against them. Milestone 1 adds the read-only
//! core — typed documents written *to* those schemas, a bounded loader, and the
//! semantic rules JSON Schema cannot express.
//!
//! The ordering was deliberate. A serde struct written first would quietly
//! become the contract and leave the schema describing it; written second, the
//! types are answerable to a document that was reviewed on its own terms, and
//! `tests/round_trip.rs` is what proves they still agree.
//!
//! The schemas are compiled in and selected by `format_version`. A loader must
//! never fetch or execute a schema a project names; the `$schema` URIs in the
//! fixture are relative paths for editors and offline validation, and
//! `analysis/schema/` holds *copies* a project emits, never the authority.

/// The bundled schemas, with the file names their `$ref`s resolve against.
///
/// The layout is load-bearing: emitting this set to `analysis/schema/` must
/// preserve it, or the references stop resolving offline — which is the only
/// reason to emit it.
pub mod schemas {
    /// Identities, digests, addresses, targets, and path safety.
    pub const COMMON: &str = include_str!("../schemas/v1/common.schema.json");
    /// The root document: identity, the document list, and directory roles.
    pub const PROJECT: &str = include_str!("../schemas/v1/project.schema.json");
    /// Sources, source sets, and the object derivation graph.
    pub const SOURCES: &str = include_str!("../schemas/v1/sources.schema.json");
    /// One directory source's pinned inventory.
    pub const INVENTORY: &str = include_str!("../schemas/v1/inventory.schema.json");
    /// One program: images, hunks, and named load maps.
    pub const PROGRAM: &str = include_str!("../schemas/v1/program.schema.json");
    /// Reviewed knowledge attached to locations and entities.
    pub const ANNOTATIONS: &str = include_str!("../schemas/v1/annotations.schema.json");
    /// Named bytes and their decode recipes, plus generated artifacts.
    pub const RESOURCES: &str = include_str!("../schemas/v1/resources.schema.json");
    /// Types used by annotations and resource layouts.
    pub const TYPES: &str = include_str!("../schemas/v1/types.schema.json");
    /// One machine's source bindings. Not part of the project's document set:
    /// nothing indexes it, no digest covers it, and it is git-ignored.
    pub const LOCAL: &str = include_str!("../schemas/v1/local.schema.json");

    /// Every schema with the file name it must be written out as.
    pub const ALL: &[(&str, &str)] = &[
        ("common.schema.json", COMMON),
        ("project.schema.json", PROJECT),
        ("sources.schema.json", SOURCES),
        ("inventory.schema.json", INVENTORY),
        ("program.schema.json", PROGRAM),
        ("annotations.schema.json", ANNOTATIONS),
        ("resources.schema.json", RESOURCES),
        ("types.schema.json", TYPES),
        ("local.schema.json", LOCAL),
    ];

    /// The schema for one `document_kind`.
    ///
    /// Exhaustive over the kinds version 1 defines, so a new document kind
    /// cannot be added without deciding which schema validates it.
    #[must_use]
    pub fn for_document_kind(kind: &str) -> Option<&'static str> {
        match kind {
            "project" => Some(PROJECT),
            "sources" => Some(SOURCES),
            "inventory" => Some(INVENTORY),
            "program" => Some(PROGRAM),
            "annotations" => Some(ANNOTATIONS),
            "resources" => Some(RESOURCES),
            "types" => Some(TYPES),
            "local" => Some(LOCAL),
            _ => None,
        }
    }
}

pub mod document;
pub mod edit;
pub mod format;
pub mod layout;
pub mod load;
pub mod migrate;
pub mod recipe;
pub mod record_type;
pub mod resolve;
pub mod validate;
pub mod verify;

pub use document::Project;
pub use edit::{Edit, EditError, EditPlan};
pub use format::format_document;
pub use layout::{POINTER_SIZE, TypeSizes};
pub use load::{LoadError, Loaded, discover, load};
pub use recipe::{
    RecipeError, artifact_key, artifact_path, extension_for, is_current, normalized_recipe,
    path_component, safe_component,
};
pub use resolve::{Index, Local, LocalStorage, Resolved};
pub use validate::{Problem, ProblemCode, validate};
pub use verify::{
    Bindings, ObjectStatus, Recover, SourceStatus, VerifyReport, build_inventory, verify,
};

/// The contract version this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// The canonical directory tree hash.
///
/// SHA-256 over `path\0size\0sha256\n` for each regular file, in sorted path
/// order. Settled in Milestone 0 rather than left to the first implementation:
/// a tree hash that two tools compute differently is worse than none, and the
/// framing separators exist so that a path ending in a digit cannot be confused
/// with the size that follows it.
#[must_use]
pub fn tree_sha256(files: &[(String, u64, String)]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut sorted: Vec<&(String, u64, String)> = files.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (path, size, sha256) in sorted {
        hasher.update(format!("{path}\0{size}\0{sha256}\n").as_bytes());
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_document_kind_has_a_schema() {
        for kind in [
            "project",
            "sources",
            "inventory",
            "program",
            "annotations",
            "resources",
            "types",
            // Not one of the project's own documents, but it is a document this
            // build reads and therefore one it must be able to describe.
            "local",
        ] {
            assert!(
                schemas::for_document_kind(kind).is_some(),
                "{kind} has no schema"
            );
        }
        assert!(schemas::for_document_kind("invented").is_none());
    }

    #[test]
    fn the_tree_hash_does_not_depend_on_directory_order() {
        let one = ("a/x".to_owned(), 1, "aa".to_owned());
        let two = ("b/y".to_owned(), 2, "bb".to_owned());
        assert_eq!(
            tree_sha256(&[one.clone(), two.clone()]),
            tree_sha256(&[two.clone(), one.clone()]),
        );
    }

    #[test]
    fn the_tree_hash_separates_a_path_from_the_size_that_follows_it() {
        // Without framing, ("a", 12, ...) and ("a1", 2, ...) would hash the
        // same bytes. The separators are why they do not.
        assert_ne!(
            tree_sha256(&[("a".to_owned(), 12, "cc".to_owned())]),
            tree_sha256(&[("a1".to_owned(), 2, "cc".to_owned())]),
        );
    }
}
