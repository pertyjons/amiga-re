//! How many bytes a type occupies.
//!
//! Asked whenever a document states a width and a type in the same breath — a
//! global variable's storage, a table's row stride, a function parameter's
//! register. Two numbers that must agree are two numbers that can disagree, so
//! the size is resolved here once and compared rather than trusted twice.
//!
//! A size is `None` when the format does not know it, and that is a fact rather
//! than a failure to compute: a type that names nothing, a chain of aliases
//! that closes on itself, or an array whose element count overflows what a
//! `u64` can hold. Every caller treats an unknown size as "nothing to compare
//! against" — reporting a mismatch against a size we could not work out would
//! blame the document for our own gap.

use std::collections::{BTreeMap, BTreeSet};

use crate::document::{Project, TypeDefinition};

/// The width of a 68000 address, and therefore of every pointer this format can
/// describe.
///
/// `address_space` says which frame a pointer's value is read in, never how
/// wide it is: every space the format can name is addressed by the same 32-bit
/// register file. A pointer that was not four bytes would be a different
/// architecture, which [`Image::architecture`](crate::document::Image) records
/// separately.
pub const POINTER_SIZE: u64 = 4;

/// Every type a project defines, indexed so its size can be resolved.
///
/// Built once per validation pass rather than per lookup: resolving one size
/// walks a chain of aliases and elements, and rebuilding the index at each step
/// would make a document with many types quadratic in the number of them.
#[derive(Clone, Debug)]
pub struct TypeSizes<'a> {
    definitions: BTreeMap<&'a str, &'a TypeDefinition>,
}

impl<'a> TypeSizes<'a> {
    /// Index every type across all of a project's type documents.
    ///
    /// A duplicate ID keeps the first definition. Declaring one twice is
    /// already [`ProblemCode::DuplicateId`](crate::validate::ProblemCode), and
    /// choosing the later one here would make the size depend on document
    /// order — a second, quieter symptom of a fault that is reported plainly.
    #[must_use]
    pub fn of(project: &'a Project) -> Self {
        let mut definitions: BTreeMap<&'a str, &'a TypeDefinition> = BTreeMap::new();
        for document in &project.types {
            for definition in &document.types {
                definitions.entry(definition.id()).or_insert(definition);
            }
        }
        Self { definitions }
    }

    /// The size in bytes of the type `id` names, if the project defines one and
    /// its size can be worked out.
    #[must_use]
    pub fn size_of(&self, id: &str) -> Option<u64> {
        self.resolve(id, &mut BTreeSet::new())
    }

    /// Whether the project defines a type under this ID at all.
    ///
    /// Separate from [`Self::size_of`] because the two answer different
    /// questions: a type that exists and whose size is unknown must not be
    /// reported as a dangling reference.
    #[must_use]
    pub fn is_defined(&self, id: &str) -> bool {
        self.definitions.contains_key(id)
    }

    /// The type `id` names, if the project defines one.
    #[must_use]
    pub fn definition(&self, id: &str) -> Option<&'a TypeDefinition> {
        self.definitions.get(id).copied()
    }

    fn resolve(&self, id: &str, seen: &mut BTreeSet<&'a str>) -> Option<u64> {
        let (&key, &definition) = self.definitions.get_key_value(id)?;
        // A chain that revisits a type has no size, and asking for one would
        // not terminate. `check_types` reports the cycle itself; the job here is
        // only to stop walking it.
        if !seen.insert(key) {
            return None;
        }
        let size = match definition {
            TypeDefinition::Integer { size, .. } => Some(u64::from(*size)),
            TypeDefinition::Pointer { .. } => Some(POINTER_SIZE),
            TypeDefinition::Array {
                element_id, count, ..
            } => self
                .resolve(element_id, seen)
                .and_then(|element| element.checked_mul(u64::from(*count))),
            TypeDefinition::Struct { size, .. } => Some(*size),
            TypeDefinition::Enum { base_id, .. } => self.resolve(base_id, seen),
            TypeDefinition::Alias { aliased_id, .. } => self.resolve(aliased_id, seen),
            // Code is not storage. A routine occupies bytes, but they are not
            // bytes anything holds a *value* of this type in, and answering
            // with the routine's own length would make a variable typed as a
            // function look like a legal one.
            TypeDefinition::Function { .. } => None,
        };
        // Backtrack, so a type reached twice by two different paths resolves
        // both times. Only a type reached from *itself* is a cycle.
        seen.remove(key);
        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{
        DocumentIndex, ProjectDocument, ProjectIdentity, SourcesDocument, TypesDocument,
    };

    fn project(types: Vec<TypeDefinition>) -> Project {
        Project {
            root: ProjectDocument {
                schema: None,
                document_kind: "project".to_owned(),
                format_version: crate::FORMAT_VERSION,
                project: ProjectIdentity {
                    id: "project:t".to_owned(),
                    name: "t".to_owned(),
                    notes: None,
                },
                documents: DocumentIndex {
                    sources: "analysis/sources.json".to_owned(),
                    ..DocumentIndex::default()
                },
                directories: None,
                extensions: None,
            },
            sources: SourcesDocument {
                schema: None,
                document_kind: "sources".to_owned(),
                format_version: crate::FORMAT_VERSION,
                sources: Vec::new(),
                source_sets: Vec::new(),
                objects: Vec::new(),
                extensions: None,
            },
            inventories: BTreeMap::new(),
            programs: Vec::new(),
            annotations: Vec::new(),
            resources: Vec::new(),
            types: vec![TypesDocument {
                schema: None,
                document_kind: "types".to_owned(),
                format_version: crate::FORMAT_VERSION,
                types,
                extensions: None,
            }],
        }
    }

    fn integer(id: &str, size: u8) -> TypeDefinition {
        TypeDefinition::Integer {
            id: id.to_owned(),
            name: id.to_owned(),
            size,
            signed: false,
            byte_order: "big".to_owned(),
            notes: None,
        }
    }

    #[test]
    fn a_size_is_resolved_through_aliases_enums_and_arrays() {
        let project = project(vec![
            integer("type:u16", 2),
            TypeDefinition::Enum {
                id: "type:flags".to_owned(),
                name: "Flags".to_owned(),
                base_id: "type:u16".to_owned(),
                members: Vec::new(),
                notes: None,
            },
            TypeDefinition::Alias {
                id: "type:word".to_owned(),
                name: "Word".to_owned(),
                aliased_id: "type:flags".to_owned(),
                notes: None,
            },
            TypeDefinition::Array {
                id: "type:table".to_owned(),
                name: "Table".to_owned(),
                element_id: "type:word".to_owned(),
                count: 8,
                notes: None,
            },
        ]);
        let sizes = TypeSizes::of(&project);
        assert_eq!(sizes.size_of("type:u16"), Some(2));
        assert_eq!(sizes.size_of("type:flags"), Some(2));
        assert_eq!(sizes.size_of("type:word"), Some(2));
        assert_eq!(sizes.size_of("type:table"), Some(16));
    }

    #[test]
    fn a_pointer_is_four_bytes_whatever_it_points_at() {
        let project = project(vec![
            integer("type:u8", 1),
            TypeDefinition::Pointer {
                id: "type:ptr".to_owned(),
                name: "Ptr".to_owned(),
                pointee_id: "type:u8".to_owned(),
                address_space: "runtime".to_owned(),
                notes: None,
            },
        ]);
        assert_eq!(
            TypeSizes::of(&project).size_of("type:ptr"),
            Some(POINTER_SIZE)
        );
    }

    /// A pointer to a type the project never defines still has a size: the
    /// pointer is four bytes regardless, and the dangling `pointee_id` is
    /// `check_types`' problem to report rather than a reason to give up here.
    #[test]
    fn a_pointer_to_an_undefined_type_still_has_a_size() {
        let project = project(vec![TypeDefinition::Pointer {
            id: "type:ptr".to_owned(),
            name: "Ptr".to_owned(),
            pointee_id: "type:missing".to_owned(),
            address_space: "runtime".to_owned(),
            notes: None,
        }]);
        assert_eq!(
            TypeSizes::of(&project).size_of("type:ptr"),
            Some(POINTER_SIZE)
        );
    }

    #[test]
    fn an_alias_cycle_has_no_size_rather_than_no_answer() {
        let project = project(vec![
            TypeDefinition::Alias {
                id: "type:a".to_owned(),
                name: "A".to_owned(),
                aliased_id: "type:b".to_owned(),
                notes: None,
            },
            TypeDefinition::Alias {
                id: "type:b".to_owned(),
                name: "B".to_owned(),
                aliased_id: "type:a".to_owned(),
                notes: None,
            },
        ]);
        assert_eq!(TypeSizes::of(&project).size_of("type:a"), None);
    }

    /// The backtrack in `resolve` is what makes this work: `pair` reaches
    /// `type:u16` twice, and a visited set that never cleared would call the
    /// second visit a cycle and lose the size.
    #[test]
    fn a_type_reached_twice_by_different_paths_is_not_a_cycle() {
        let project = project(vec![
            integer("type:u16", 2),
            TypeDefinition::Struct {
                id: "type:pair".to_owned(),
                name: "Pair".to_owned(),
                size: 4,
                fields: vec![
                    crate::document::Field {
                        name: "x".to_owned(),
                        offset: 0,
                        type_id: "type:u16".to_owned(),
                        notes: None,
                    },
                    crate::document::Field {
                        name: "y".to_owned(),
                        offset: 2,
                        type_id: "type:u16".to_owned(),
                        notes: None,
                    },
                ],
                notes: None,
            },
            TypeDefinition::Array {
                id: "type:pairs".to_owned(),
                name: "Pairs".to_owned(),
                element_id: "type:pair".to_owned(),
                count: 3,
                notes: None,
            },
        ]);
        let sizes = TypeSizes::of(&project);
        assert_eq!(sizes.size_of("type:pair"), Some(4));
        assert_eq!(sizes.size_of("type:pairs"), Some(12));
    }

    #[test]
    fn an_array_whose_total_size_overflows_has_no_size() {
        let project = project(vec![
            integer("type:big", u8::MAX),
            TypeDefinition::Array {
                id: "type:huge".to_owned(),
                name: "Huge".to_owned(),
                element_id: "type:big".to_owned(),
                count: u32::MAX,
                notes: None,
            },
            TypeDefinition::Array {
                id: "type:huger".to_owned(),
                name: "Huger".to_owned(),
                element_id: "type:huge".to_owned(),
                count: u32::MAX,
                notes: None,
            },
            TypeDefinition::Array {
                id: "type:hugest".to_owned(),
                name: "Hugest".to_owned(),
                element_id: "type:huger".to_owned(),
                count: u32::MAX,
                notes: None,
            },
        ]);
        assert_eq!(TypeSizes::of(&project).size_of("type:hugest"), None);
    }

    #[test]
    fn an_undefined_type_has_no_size_and_is_not_defined() {
        let project = project(vec![integer("type:u8", 1)]);
        let sizes = TypeSizes::of(&project);
        assert_eq!(sizes.size_of("type:missing"), None);
        assert!(!sizes.is_defined("type:missing"));
        assert!(sizes.is_defined("type:u8"));
    }
}
