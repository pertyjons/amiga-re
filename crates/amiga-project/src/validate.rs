//! Stable diagnostics, and the rules JSON Schema cannot express.
//!
//! The schemas settle shape: closed objects, tagged unions, patterns, bounds.
//! What they cannot say is that an ID is unique across *documents*, that a
//! reference resolves to the right kind of thing, that the object graph has no
//! cycle, or that an annotated range lies inside the object it names. Those are
//! here, and they are the same rules `tests/contract.rs` proved against the
//! fixture in Milestone 0 — moved into the library, which is what Milestone 1
//! is for.
//!
//! Every finding carries a stable [`ProblemCode`]. As in `amiga-operations`,
//! the code is the machine contract and the human message is not: a consumer
//! deciding whether to offer a rebase must not have to parse prose.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::document::{
    AbiLocation, Annotation, Id, Project, Resource, SourceKind, Target, TypeDefinition,
};
use crate::layout::{POINTER_SIZE, TypeSizes};

/// Why a project was refused, or what is wrong with one that loaded.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
    /// A document's JSON shape violates the bundled schema for its declared
    /// kind and format version.
    DocumentSchemaViolation,
    /// A document declares a `format_version` this build does not serve, or two
    /// documents of one project declare different ones.
    FormatVersionMixed,
    /// A document declares a `document_kind` that does not match where the root
    /// listed it.
    DocumentKindMismatch,
    /// An ID is declared by two entities.
    DuplicateId,
    /// An ID does not match the required grammar.
    MalformedId,
    /// A typed reference names nothing.
    UnresolvedReference,
    /// A typed reference resolves to the wrong kind of entity.
    ReferenceKindMismatch,
    /// Two individually valid references cannot be used together because one
    /// does not belong to the other.
    ReferenceOwnershipMismatch,
    /// The object derivation graph has a cycle, or a chain that never reaches a
    /// source.
    DerivationCycle,
    /// A path is absolute, escapes the project, or is otherwise unusable.
    UnsafePath,
    /// A source's pin does not match its kind: a file without a digest, or a
    /// directory without an inventory.
    SourcePinMissing,
    /// A directory source and its inventory disagree about the tree hash.
    InventoryHashMismatch,
    /// An annotation's recorded object digest no longer matches, and the
    /// annotation is not marked stale. It must be rebased explicitly.
    StaleAnnotation,
    /// An annotation is marked stale but its digest still matches, so the mark
    /// is wrong.
    StaleMarkUnwarranted,
    /// An object's `kind` and its `selector` describe different derivations.
    SelectorKindMismatch,
    /// A decompression recipe names a parameter its codec cannot accept, or a
    /// declared size its stream cannot have carried.
    CodecRecipeInvalid,
    /// A byte range runs past the end of the object it names.
    RangeOutsideObject,
    /// A struct field lies outside its declared size, or two fields overlap.
    TypeLayoutInvalid,
    /// A variable is neither a function-scoped local nor a located global, or
    /// claims to be both.
    VariableShapeInvalid,
    /// A located annotation's storage width and the size of the type it names
    /// are two different numbers.
    ///
    /// Both are reviewed claims about the same bytes, so the disagreement is
    /// the finding: silently preferring either one would make a listing render
    /// a width the document does not state.
    TypeSizeMismatch,
    /// A captured source records nothing about what produced it.
    ///
    /// Captured bytes cannot be re-derived by anything in this format, so the
    /// note saying which routine, which inputs and which trace made them is the
    /// only provenance they will ever have. A capture without one is an
    /// unexplained digest wearing the shape of evidence.
    CaptureUnexplained,
}

impl ProblemCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DocumentSchemaViolation => "DOCUMENT_SCHEMA_VIOLATION",
            Self::FormatVersionMixed => "FORMAT_VERSION_MIXED",
            Self::DocumentKindMismatch => "DOCUMENT_KIND_MISMATCH",
            Self::DuplicateId => "DUPLICATE_ID",
            Self::MalformedId => "MALFORMED_ID",
            Self::UnresolvedReference => "UNRESOLVED_REFERENCE",
            Self::ReferenceKindMismatch => "REFERENCE_KIND_MISMATCH",
            Self::ReferenceOwnershipMismatch => "REFERENCE_OWNERSHIP_MISMATCH",
            Self::DerivationCycle => "DERIVATION_CYCLE",
            Self::UnsafePath => "UNSAFE_PATH",
            Self::SourcePinMissing => "SOURCE_PIN_MISSING",
            Self::InventoryHashMismatch => "INVENTORY_HASH_MISMATCH",
            Self::CaptureUnexplained => "CAPTURE_UNEXPLAINED",
            Self::StaleAnnotation => "STALE_ANNOTATION",
            Self::StaleMarkUnwarranted => "STALE_MARK_UNWARRANTED",
            Self::SelectorKindMismatch => "SELECTOR_KIND_MISMATCH",
            Self::CodecRecipeInvalid => "CODEC_RECIPE_INVALID",
            Self::RangeOutsideObject => "RANGE_OUTSIDE_OBJECT",
            Self::TypeLayoutInvalid => "TYPE_LAYOUT_INVALID",
            Self::VariableShapeInvalid => "VARIABLE_SHAPE_INVALID",
            Self::TypeSizeMismatch => "TYPE_SIZE_MISMATCH",
        }
    }

    /// Whether this problem makes the project unusable rather than merely
    /// imperfect.
    ///
    /// A stale annotation is *not* fatal: the whole point of detecting one is
    /// that the knowledge survives and is visibly untrustworthy. A dangling
    /// reference is fatal, because nothing downstream can act on it.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        !matches!(
            self,
            Self::StaleAnnotation | Self::StaleMarkUnwarranted | Self::InventoryHashMismatch
        )
    }
}

impl fmt::Display for ProblemCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One finding about a project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Problem {
    pub code: ProblemCode,
    /// The entity the problem is about, or a JSON pointer for a document-shape
    /// violation.
    pub subject: Option<Id>,
    pub message: String,
}

impl Problem {
    pub(crate) fn new(
        code: ProblemCode,
        subject: Option<&str>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            subject: subject.map(str::to_owned),
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        self.code.is_fatal()
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subject {
            Some(subject) => write!(formatter, "{}: {subject}: {}", self.code, self.message),
            None => write!(formatter, "{}: {}", self.code, self.message),
        }
    }
}

/// The kinds an ID prefix may declare.
const KINDS: &[&str] = &[
    "project",
    "source",
    "set",
    "object",
    "program",
    "image",
    "loadmap",
    "function",
    "symbol",
    "variable",
    "type",
    "resource",
    "annotation",
    "artifact",
];

/// The kind prefix of `id`, if it has a valid one.
#[must_use]
pub fn id_kind(id: &str) -> Option<&str> {
    let (kind, rest) = id.split_once(':')?;
    if !KINDS.contains(&kind) || rest.is_empty() {
        return None;
    }
    let valid = rest.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._/-".contains(c));
    valid.then_some(kind)
}

/// Whether `path` is a usable project-relative path.
///
/// The same rule the `relativePath` schema definition states, restated here so
/// a document that reached the loader without schema validation still cannot
/// carry an escaping path.
#[must_use]
pub fn is_safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

/// Every semantic rule, run over a fully loaded project.
///
/// Returns findings rather than the first failure: a project with three
/// dangling references should report three, not send the user round the loop
/// three times.
#[must_use]
pub fn validate(project: &Project) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut ids: BTreeMap<String, &'static str> = BTreeMap::new();

    let declare = |id: &str, problems: &mut Vec<Problem>, ids: &mut BTreeMap<String, &str>| {
        match id_kind(id) {
            None => problems.push(Problem::new(
                ProblemCode::MalformedId,
                Some(id),
                "an ID needs a known kind prefix and a lowercase name",
            )),
            Some(kind) => {
                // `id_kind` returns a borrow of `id`; store the static kind so
                // the index outlives the loop.
                let owned = KINDS.iter().find(|known| **known == kind).copied();
                if let Some(kind) = owned
                    && ids.insert(id.to_owned(), kind).is_some()
                {
                    problems.push(Problem::new(
                        ProblemCode::DuplicateId,
                        Some(id),
                        "this ID is declared more than once",
                    ));
                }
            }
        }
    };

    declare(&project.root.project.id, &mut problems, &mut ids);
    for source in &project.sources.sources {
        declare(&source.id, &mut problems, &mut ids);
    }
    for set in &project.sources.source_sets {
        declare(&set.id, &mut problems, &mut ids);
    }
    for object in &project.sources.objects {
        declare(&object.id, &mut problems, &mut ids);
    }
    for program in &project.programs {
        declare(&program.id, &mut problems, &mut ids);
        for image in &program.images {
            declare(&image.id, &mut problems, &mut ids);
            for map in &image.load_maps {
                declare(&map.id, &mut problems, &mut ids);
            }
        }
    }
    for document in &project.annotations {
        for annotation in &document.annotations {
            declare(annotation.id(), &mut problems, &mut ids);
        }
    }
    for document in &project.resources {
        for resource in &document.resources {
            declare(resource.id(), &mut problems, &mut ids);
        }
        for artifact in &document.artifacts {
            declare(&artifact.id, &mut problems, &mut ids);
        }
    }
    for document in &project.types {
        for definition in &document.types {
            declare(definition.id(), &mut problems, &mut ids);
        }
    }

    let targets = TargetIndex::of(project, &ids);
    let mut reference =
        |id: &str, expected: &str, context: &str, problems: &mut Vec<Problem>| match ids.get(id) {
            None => problems.push(Problem::new(
                ProblemCode::UnresolvedReference,
                Some(id),
                format!("{context} names an entity that does not exist"),
            )),
            Some(kind) if *kind != expected => problems.push(Problem::new(
                ProblemCode::ReferenceKindMismatch,
                Some(id),
                format!("{context} needs a {expected}, but this is a {kind}"),
            )),
            Some(_) => {}
        };

    let sizes = TypeSizes::of(project);

    check_sources(project, &mut reference, &mut problems);
    check_programs(project, &mut reference, &mut problems);
    check_annotations(project, &targets, &mut reference, &sizes, &mut problems);
    check_resources(project, &targets, &mut reference, &mut problems);
    check_types(project, &mut reference, &sizes, &mut problems);
    check_derivation_graph(project, &mut problems);
    check_ranges(project, &mut problems);
    check_document_schemas(project, &mut problems);

    problems.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| left.subject.cmp(&right.subject))
    });
    problems
}

fn check_document_schemas(project: &Project, problems: &mut Vec<Problem>) {
    check_document_schema("project", "project document", &project.root, problems);
    check_document_schema("sources", "sources document", &project.sources, problems);
    for (source, inventory) in &project.inventories {
        check_document_schema(
            "inventory",
            &format!("inventory for {source}"),
            inventory,
            problems,
        );
    }
    for (index, program) in project.programs.iter().enumerate() {
        check_document_schema(
            "program",
            &format!("program document {index}"),
            program,
            problems,
        );
    }
    for (index, annotations) in project.annotations.iter().enumerate() {
        check_document_schema(
            "annotations",
            &format!("annotations document {index}"),
            annotations,
            problems,
        );
    }
    for (index, resources) in project.resources.iter().enumerate() {
        check_document_schema(
            "resources",
            &format!("resources document {index}"),
            resources,
            problems,
        );
    }
    for (index, types) in project.types.iter().enumerate() {
        check_document_schema("types", &format!("types document {index}"), types, problems);
    }
}

fn check_document_schema(
    kind: &'static str,
    label: &str,
    document: &impl serde::Serialize,
    problems: &mut Vec<Problem>,
) {
    let value = match serde_json::to_value(document) {
        Ok(value) => value,
        Err(error) => {
            problems.push(Problem::new(
                ProblemCode::DocumentSchemaViolation,
                None,
                format!("{label} could not be serialized for schema validation: {error}"),
            ));
            return;
        }
    };
    match crate::load::validate_document_schema(label, kind, &value) {
        Ok(found) => problems.extend(found),
        Err(error) => problems.push(Problem::new(
            ProblemCode::DocumentSchemaViolation,
            None,
            error.to_string(),
        )),
    }
}

type Reference<'a> = dyn FnMut(&str, &str, &str, &mut Vec<Problem>) + 'a;

/// Cross-document facts needed to validate compound target references.
struct TargetIndex<'a> {
    declared: &'a BTreeMap<String, &'static str>,
    annotations: BTreeSet<&'a str>,
    load_map_owners: BTreeMap<&'a str, Option<&'a str>>,
}

impl<'a> TargetIndex<'a> {
    fn of(project: &'a Project, declared: &'a BTreeMap<String, &'static str>) -> Self {
        let annotations = project
            .annotations
            .iter()
            .flat_map(|document| &document.annotations)
            .map(|annotation| annotation.id().as_str())
            .collect();
        let mut load_map_owners = BTreeMap::new();
        for image in project.programs.iter().flat_map(|program| &program.images) {
            for map in &image.load_maps {
                load_map_owners
                    .entry(map.id.as_str())
                    .and_modify(|owner| *owner = None)
                    .or_insert(Some(image.id.as_str()));
            }
        }
        Self {
            declared,
            annotations,
            load_map_owners,
        }
    }

    fn check_entity(&self, entity_id: &str, problems: &mut Vec<Problem>) {
        if id_kind(entity_id).is_none() {
            problems.push(Problem::new(
                ProblemCode::MalformedId,
                Some(entity_id),
                "an entity target names a malformed ID",
            ));
            return;
        }
        match self.declared.get(entity_id) {
            None => problems.push(Problem::new(
                ProblemCode::UnresolvedReference,
                Some(entity_id),
                "an entity target names an annotation that does not exist",
            )),
            Some(kind) if !self.annotations.contains(entity_id) => {
                problems.push(Problem::new(
                    ProblemCode::ReferenceKindMismatch,
                    Some(entity_id),
                    format!("an entity target needs an annotation, but this is a {kind}"),
                ));
            }
            Some(_) => {}
        }
    }

    fn check_runtime(&self, image_id: &str, load_map_id: &str, problems: &mut Vec<Problem>) {
        // Let the ordinary reference checks own absent and mistyped IDs. The
        // ownership question is meaningful only once both halves are valid.
        if self.declared.get(image_id) != Some(&"image")
            || self.declared.get(load_map_id) != Some(&"loadmap")
        {
            return;
        }
        let Some(Some(owner)) = self.load_map_owners.get(load_map_id) else {
            return;
        };
        if *owner != image_id {
            problems.push(Problem::new(
                ProblemCode::ReferenceOwnershipMismatch,
                Some(load_map_id),
                format!(
                    "a runtime target pairs {image_id} with {load_map_id}, but that load map \
                     belongs to {owner}"
                ),
            ));
        }
    }
}

fn check_sources(project: &Project, reference: &mut Reference<'_>, problems: &mut Vec<Problem>) {
    for source in &project.sources.sources {
        let pinned = match source.kind {
            SourceKind::File => source.size.is_some() && source.sha256.is_some(),
            SourceKind::Directory => source.inventory.is_some() && source.tree_sha256.is_some(),
        };
        if !pinned {
            problems.push(Problem::new(
                ProblemCode::SourcePinMissing,
                Some(&source.id),
                match source.kind {
                    SourceKind::File => "a file source needs both `size` and `sha256`",
                    SourceKind::Directory => {
                        "a directory source needs both `inventory` and `tree_sha256`"
                    }
                },
            ));
        }
        // Captured bytes are not on any disk and nothing here can make them
        // again, so the sentence saying what produced them is required rather
        // than encouraged: without it the record is an unexplained digest that
        // reads exactly like a piece of media somebody has a copy of.
        if !source.is_reproducible()
            && source
                .notes
                .as_deref()
                .is_none_or(|notes| notes.trim().is_empty())
        {
            problems.push(Problem::new(
                ProblemCode::CaptureUnexplained,
                Some(&source.id),
                "a captured source needs `notes` saying what produced it: nothing in this \
                 format can re-derive these bytes, so that sentence is their only provenance",
            ));
        }
        for location in &source.locations {
            let crate::document::Location::ProjectRelative { path } = location;
            if !is_safe_relative(path) {
                problems.push(Problem::new(
                    ProblemCode::UnsafePath,
                    Some(&source.id),
                    format!("location {path:?} is not a usable project-relative path"),
                ));
            }
        }
        // A directory source's inventory must agree with it about the tree.
        if let (Some(expected), Some(inventory)) = (
            source.tree_sha256.as_ref(),
            project.inventories.get(&source.id),
        ) && &inventory.tree_sha256 != expected
        {
            problems.push(Problem::new(
                ProblemCode::InventoryHashMismatch,
                Some(&source.id),
                "the source and its inventory disagree about the tree hash",
            ));
        }
    }
    for set in &project.sources.source_sets {
        for member in &set.members {
            reference(&member.source_id, "source", "a set member", problems);
        }
    }
    for object in &project.sources.objects {
        // A parent is a source or another object; the graph check below proves
        // it terminates.
        if !matches!(id_kind(&object.parent_id), Some("source" | "object")) {
            problems.push(Problem::new(
                ProblemCode::ReferenceKindMismatch,
                Some(&object.id),
                "an object's parent must be a source or another object",
            ));
        }
        check_derivation_record(object, problems);
    }
}

/// One object's `kind` and selector agree, and its decompression recipe names
/// parameters a decoder can accept.
///
/// The kind/selector pairing is checked for `decompressed` and deliberately
/// nowhere else. A container member recovered by a plain byte range is
/// legitimate — the contract fixture's disks are too structurally minimal to
/// walk as volumes, and say so in their notes — but nothing can slice a
/// decompressed object out of its packed parent, so there a disagreement means
/// the object cannot be reproduced at all.
fn check_derivation_record(object: &crate::document::Object, problems: &mut Vec<Problem>) {
    use crate::document::{Codec, Selector};

    if let Some(Selector::Sandbox { export, inputs }) = &object.selector
        && (!is_safe_relative(export)
            || inputs.is_empty()
            || inputs.len() > 16
            || inputs.keys().any(|name| !is_safe_relative(name)))
    {
        problems.push(Problem::new(
            ProblemCode::DocumentSchemaViolation,
            Some(&object.id),
            "sandbox exports and input names must be safe relative names, with 1..=16 inputs",
        ));
    }
    if (object.kind == "sandbox_export")
        != matches!(object.selector, Some(Selector::Sandbox { .. }))
    {
        problems.push(Problem::new(
            ProblemCode::SelectorKindMismatch,
            Some(&object.id),
            "kind sandbox_export requires a sandbox selector, and vice versa",
        ));
    }

    let recipe = match &object.selector {
        Some(Selector::Decompressed {
            codec,
            declared_size,
        }) => Some((codec, declared_size)),
        _ => None,
    };
    if (object.kind == "decompressed") != recipe.is_some() {
        problems.push(Problem::new(
            ProblemCode::SelectorKindMismatch,
            Some(&object.id),
            if recipe.is_some() {
                format!(
                    "a `decompressed` selector needs kind \"decompressed\", not {:?}",
                    object.kind
                )
            } else {
                "kind \"decompressed\" needs a `decompressed` selector naming the codec \
                 that produced it"
                    .to_owned()
            },
        ));
    }
    let Some((codec, declared_size)) = recipe else {
        return;
    };

    let mut invalid = |message: String| {
        problems.push(Problem::new(
            ProblemCode::CodecRecipeInvalid,
            Some(&object.id),
            message,
        ));
    };
    // The bounds the decoders themselves enforce, restated so a document that
    // reached the loader without schema validation still cannot carry a recipe
    // that only fails once someone tries to run it.
    match codec {
        Codec::Powerpacker { mode_bits } => {
            if let Some(bits) = mode_bits
                .iter()
                .copied()
                .find(|bits| !(1..=31).contains(bits))
            {
                invalid(format!("mode-table width {bits} is outside 1..=31"));
            }
        }
        Codec::ByteRun1 {} => {}
        Codec::RleXor {
            size_bytes,
            size_includes_field,
            ..
        } => {
            if !matches!(size_bytes, 0 | 2 | 4) {
                invalid(format!(
                    "a leading size field is 0, 2, or 4 bytes wide, not {size_bytes}"
                ));
            }
            if *size_includes_field && *size_bytes == 0 {
                invalid(
                    "`size_includes_field` needs a size field to count; the recipe declares \
                     none"
                        .to_owned(),
                );
            }
        }
    }
    if declared_size.is_some() && !codec.declares_output_size() {
        invalid(format!(
            "a {} stream carries no output size, so `declared_size` has nothing to \
             have come from",
            codec.name()
        ));
    }
}

fn check_programs(project: &Project, reference: &mut Reference<'_>, problems: &mut Vec<Problem>) {
    for program in &project.programs {
        if let Some(set) = &program.source_set_id {
            reference(set, "set", "a program's source set", problems);
        }
        for image in &program.images {
            reference(&image.object_id, "object", "an image's object", problems);
        }
    }
}

/// A located annotation's storage and the type it names describe the same
/// bytes, so they must state the same width.
///
/// Silent unless *both* numbers exist. A target that covers no bytes has
/// nothing to compare, and a type whose size cannot be resolved — undefined, or
/// reached through a cycle — is already reported by
/// [`ProblemCode::UnresolvedReference`] or [`check_types`]. Reporting a
/// mismatch against a size we failed to work out would blame the document for
/// this function's own gap.
fn check_storage_size(
    id: &Id,
    target: Option<&Target>,
    type_id: &Id,
    sizes: &TypeSizes<'_>,
    context: &str,
    problems: &mut Vec<Problem>,
) {
    let Some(stored) = target.and_then(Target::byte_length) else {
        return;
    };
    let Some(declared) = sizes.size_of(type_id) else {
        return;
    };
    if stored != declared {
        problems.push(Problem::new(
            ProblemCode::TypeSizeMismatch,
            Some(id),
            format!(
                "{context} occupies {stored} bytes of storage but names {type_id}, \
                 which is {declared} bytes"
            ),
        ));
    }
}

fn check_annotations(
    project: &Project,
    targets: &TargetIndex<'_>,
    reference: &mut Reference<'_>,
    sizes: &TypeSizes<'_>,
    problems: &mut Vec<Problem>,
) {
    for document in &project.annotations {
        if let Some(scope) = &document.scope {
            if let Some(program) = &scope.program_id {
                reference(program, "program", "an annotation scope", problems);
            }
            if let Some(image) = &scope.image_id {
                reference(image, "image", "an annotation scope", problems);
            }
        }
        for annotation in &document.annotations {
            if let Some(target) = annotation.target() {
                check_target(target, targets, reference, problems);
            }
            // A function's signature. The reference was unchecked until the
            // type vocabulary had something for it to point at — there was no
            // callable kind, so every value it could name was the wrong one and
            // checking would only have said so.
            if let Annotation::Function {
                id,
                type_id: Some(type_id),
                ..
            } = annotation
            {
                reference(type_id, "type", "a function's signature", problems);
                if sizes
                    .definition(type_id)
                    .is_some_and(|definition| !definition.is_callable())
                {
                    problems.push(Problem::new(
                        ProblemCode::ReferenceKindMismatch,
                        Some(id),
                        format!(
                            "a function's signature must be a callable type, and \
                             {type_id} is a {} type",
                            sizes
                                .definition(type_id)
                                .map_or("unknown", TypeDefinition::kind)
                        ),
                    ));
                }
            }
            if let Annotation::Variable {
                id,
                scope,
                storage,
                target,
                type_id,
                lifetime,
                ..
            } = annotation
            {
                // One shape or the other, never both and never neither. A local
                // needs its function scope so a reused register is not named for
                // the whole program; a global has no function to be scoped to,
                // and inventing one would put a wrong ID in a field other tools
                // resolve.
                //
                // A global is located by *any* target that names bytes — a
                // base-register slot, and equally an object offset, a hunk
                // offset, or a runtime address, which is how a program that
                // keeps its shared state at absolute addresses says so.
                // `byte_length` is the test rather than a list of spaces,
                // because covering no bytes is exactly what disqualifies an
                // `entity` target: it attaches to another annotation, and
                // storage that is somewhere else is not storage.
                match (scope, storage, target) {
                    (Some(scope), Some(_), None) => {
                        reference(
                            &scope.function_id,
                            "function",
                            "a variable's scope",
                            problems,
                        );
                    }
                    (None, None, Some(target)) if target.byte_length().is_some() => {}
                    (None, None, Some(other)) => problems.push(Problem::new(
                        ProblemCode::VariableShapeInvalid,
                        Some(id),
                        format!(
                            "a variable with no function scope is a global, and a `{}` \
                             target names no storage to hold one",
                            other.space()
                        ),
                    )),
                    _ => problems.push(Problem::new(
                        ProblemCode::VariableShapeInvalid,
                        Some(id),
                        "a variable is either a function-scoped local (`scope` and \
                         `storage`) or a located global (`target`), not both and not \
                         neither",
                    )),
                }
                if let Some(type_id) = type_id {
                    reference(type_id, "type", "a variable's type", problems);
                    check_storage_size(
                        id,
                        target.as_deref(),
                        type_id,
                        sizes,
                        "a variable",
                        problems,
                    );
                    // Storage holds values, and a routine is not a value. A
                    // variable that holds one holds its *address*, which is a
                    // pointer to the signature rather than the signature.
                    if sizes
                        .definition(type_id)
                        .is_some_and(TypeDefinition::is_callable)
                    {
                        problems.push(Problem::new(
                            ProblemCode::ReferenceKindMismatch,
                            Some(id),
                            format!(
                                "a variable names the signature {type_id}, but storage \
                                 holds a value — a variable holding a routine holds a \
                                 pointer to one"
                            ),
                        ));
                    }
                }
                if let Some(lifetime) = lifetime {
                    check_target(&lifetime.start, targets, reference, problems);
                    check_target(&lifetime.end, targets, reference, problems);
                }
            }
        }
    }
}

/// Check that a resource reference names the *kind* of resource it needs.
///
/// Silent when the ID does not resolve at all: `reference` has already reported
/// that, and a second problem for the same cause would make one mistake look
/// like two.
fn check_resource_kind(
    kinds: &BTreeMap<&str, &'static str>,
    id: &str,
    expected: &str,
    context: &str,
    problems: &mut Vec<Problem>,
) {
    let Some(actual) = kinds.get(id) else {
        return;
    };
    if *actual != expected {
        problems.push(Problem::new(
            ProblemCode::ReferenceKindMismatch,
            Some(id),
            format!("{context} needs a {expected} resource, but this is a {actual} resource"),
        ));
    }
}

fn check_target(
    target: &Target,
    targets: &TargetIndex<'_>,
    reference: &mut Reference<'_>,
    problems: &mut Vec<Problem>,
) {
    match target {
        Target::Object { object_id, .. } => {
            reference(object_id, "object", "a target", problems);
        }
        Target::Hunk { image_id, .. } => {
            reference(image_id, "image", "a target", problems);
        }
        Target::Runtime {
            image_id,
            load_map_id,
            ..
        } => {
            reference(image_id, "image", "a target", problems);
            reference(load_map_id, "loadmap", "a target", problems);
            targets.check_runtime(image_id, load_map_id, problems);
        }
        Target::BaseRegister { image_id, .. } => {
            reference(image_id, "image", "a target", problems);
        }
        Target::Entity { entity_id } => {
            targets.check_entity(entity_id, problems);
        }
    }
}

fn check_resources(
    project: &Project,
    targets: &TargetIndex<'_>,
    reference: &mut Reference<'_>,
    problems: &mut Vec<Problem>,
) {
    // Every resource shares the `resource:` prefix, so the ID category cannot
    // tell an image from a palette. A reference that needs one specific kind is
    // checked against this, after `reference` has established the ID resolves at
    // all — otherwise a dangling reference would be reported twice.
    let resource_kinds: BTreeMap<&str, &'static str> = project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .map(|resource| (resource.id().as_str(), resource.kind()))
        .collect();

    for document in &project.resources {
        for resource in &document.resources {
            check_target(resource.target(), targets, reference, problems);
            match resource {
                Resource::Image {
                    palette_resource_id: Some(palette),
                    ..
                } => {
                    reference(palette, "resource", "an image's palette", problems);
                    check_resource_kind(
                        &resource_kinds,
                        palette,
                        "palette",
                        "an image's palette",
                        problems,
                    );
                }
                Resource::Table {
                    type_id: Some(type_id),
                    ..
                }
                | Resource::Data {
                    type_id: Some(type_id),
                    ..
                } => reference(type_id, "type", "a resource's type", problems),
                Resource::Code {
                    load_map_id: Some(map),
                    ..
                } => reference(map, "loadmap", "a code resource's load map", problems),
                _ => {}
            }
        }
        for artifact in &document.artifacts {
            reference(
                &artifact.resource_id,
                "resource",
                "an artifact's resource",
                problems,
            );
            if !is_safe_relative(&artifact.path) {
                problems.push(Problem::new(
                    ProblemCode::UnsafePath,
                    Some(&artifact.id),
                    format!("artifact path {:?} is not usable", artifact.path),
                ));
            }
        }
    }
}

/// A signature's locations are consistent, and each value fits where it is put.
///
/// Every rule here is a contradiction between two things the document says,
/// which is the only kind of mistake a format can catch about a reviewed ABI.
/// Nothing infers a calling convention: a routine that takes one argument in
/// `D3` and returns three values is as valid as any other, because on this
/// platform it might be.
fn check_signature(
    definition: &TypeDefinition,
    reference: &mut Reference<'_>,
    sizes: &TypeSizes<'_>,
    problems: &mut Vec<Problem>,
) {
    let TypeDefinition::Function {
        id,
        parameters,
        results,
        clobbers,
        preserves,
        ..
    } = definition
    else {
        return;
    };
    for (side, values) in [("parameter", parameters), ("result", results)] {
        // Two values in one place is a contradiction rather than a layout
        // choice: the callee reads it once. Parameters and results are counted
        // separately, because a routine taking its argument in `D0` and
        // returning through `D0` is the commonest shape there is.
        //
        // Exact collision only. Two stack values whose *extents* overlap — one
        // four bytes at offset 0 and one at offset 2 — is also wrong, and
        // checking it needs every parameter's size to be resolvable, so a
        // signature naming one undefined type would go unchecked while looking
        // checked. Left for a real example to settle rather than guessed at.
        let mut occupied: BTreeMap<String, &str> = BTreeMap::new();
        for value in values {
            reference(&value.type_id, "type", "a signature's value", problems);
            let place = match &value.location {
                AbiLocation::Register { register } => register.clone(),
                AbiLocation::Stack { offset } => format!("the stack at {offset}"),
            };
            if let Some(first) = occupied.insert(place.clone(), value.name.as_str()) {
                problems.push(Problem::new(
                    ProblemCode::TypeLayoutInvalid,
                    Some(id),
                    format!(
                        "{side}s {first:?} and {:?} are both in {place}, which holds \
                         one of them",
                        value.name
                    ),
                ));
            }
            // A register is four bytes. A value that does not fit was recorded
            // somewhere it cannot be, and the size comes from the type rather
            // than from a width the parameter restates — which is why the
            // parameter has no width of its own to disagree with.
            if let (AbiLocation::Register { register }, Some(size)) =
                (&value.location, sizes.size_of(&value.type_id))
                && size > POINTER_SIZE
            {
                problems.push(Problem::new(
                    ProblemCode::TypeSizeMismatch,
                    Some(id),
                    format!(
                        "{side} {:?} is {size} bytes and is recorded in {register}, which \
                         holds {POINTER_SIZE}",
                        value.name
                    ),
                ));
            }
            // A signature is a call, and a call is not a value: a routine
            // taking another routine takes its *address*, which is a pointer.
            if sizes
                .definition(&value.type_id)
                .is_some_and(TypeDefinition::is_callable)
            {
                problems.push(Problem::new(
                    ProblemCode::ReferenceKindMismatch,
                    Some(id),
                    format!(
                        "{side} {:?} names the signature {}, but a value of a callable \
                         type is its address — a pointer to one",
                        value.name, value.type_id
                    ),
                ));
            }
        }
    }

    // Claiming both about one register says the call does and does not change
    // it. Only checkable when both lists are present; `None` is unknown, and
    // an unknown does not contradict anything.
    if let (Some(clobbers), Some(preserves)) = (clobbers, preserves) {
        let preserved: BTreeSet<&str> = preserves.iter().map(String::as_str).collect();
        for register in clobbers {
            if preserved.contains(register.as_str()) {
                problems.push(Problem::new(
                    ProblemCode::TypeLayoutInvalid,
                    Some(id),
                    format!("{register} is recorded as both clobbered and preserved"),
                ));
            }
        }
    }
}

fn check_types(
    project: &Project,
    reference: &mut Reference<'_>,
    sizes: &TypeSizes<'_>,
    problems: &mut Vec<Problem>,
) {
    for document in &project.types {
        for definition in &document.types {
            match definition {
                TypeDefinition::Pointer { pointee_id, .. } => {
                    reference(pointee_id, "type", "a pointer's pointee", problems);
                }
                TypeDefinition::Array { element_id, .. } => {
                    reference(element_id, "type", "an array's element", problems);
                }
                TypeDefinition::Enum { base_id, .. } => {
                    reference(base_id, "type", "an enum's base", problems);
                }
                TypeDefinition::Alias { aliased_id, .. } => {
                    reference(aliased_id, "type", "an alias target", problems);
                }
                TypeDefinition::Struct {
                    id, size, fields, ..
                } => {
                    let mut seen: BTreeSet<u64> = BTreeSet::new();
                    for field in fields {
                        reference(&field.type_id, "type", "a struct field", problems);
                        if field.offset >= *size {
                            problems.push(Problem::new(
                                ProblemCode::TypeLayoutInvalid,
                                Some(id),
                                format!(
                                    "field {:?} is at offset {} but the struct is {size} bytes",
                                    field.name, field.offset
                                ),
                            ));
                        }
                        if !seen.insert(field.offset) {
                            problems.push(Problem::new(
                                ProblemCode::TypeLayoutInvalid,
                                Some(id),
                                format!("two fields share offset {}", field.offset),
                            ));
                        }
                    }
                }
                TypeDefinition::Function { .. } => {
                    check_signature(definition, reference, sizes, problems);
                }
                TypeDefinition::Integer { .. } => {}
            }
        }
    }
}

/// Every derivation chain reaches a source without revisiting an object.
fn check_derivation_graph(project: &Project, problems: &mut Vec<Problem>) {
    let sources: BTreeSet<&str> = project
        .sources
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    let objects: BTreeMap<_, _> = project
        .sources
        .objects
        .iter()
        .map(|object| (object.id.as_str(), object))
        .collect();
    let mut remaining = BTreeMap::new();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (&id, object) in &objects {
        let mut dependencies = BTreeSet::from([object.parent_id.as_str()]);
        if let Some(selector) = &object.selector {
            dependencies.extend(selector.dependencies());
        }
        let mut count = 0_usize;
        for dependency in dependencies {
            if objects.contains_key(dependency) {
                count += 1;
                children.entry(dependency).or_default().push(id);
            } else if !sources.contains(dependency) {
                problems.push(Problem::new(
                    ProblemCode::UnresolvedReference,
                    Some(id),
                    format!("the derivation graph has no input {dependency}"),
                ));
            }
        }
        remaining.insert(id, count);
    }
    // Kahn's algorithm avoids recursion and repeated traversal of shared inputs.
    let mut ready: Vec<_> = remaining
        .iter()
        .filter_map(|(&id, &n)| (n == 0).then_some(id))
        .collect();
    while let Some(id) = ready.pop() {
        if let Some(dependents) = children.get(id) {
            for child in dependents {
                if let Some(count) = remaining.get_mut(child) {
                    *count -= 1;
                    if *count == 0 {
                        ready.push(child);
                    }
                }
            }
        }
    }
    for (id, count) in remaining {
        if count != 0 {
            problems.push(Problem::new(
                ProblemCode::DerivationCycle,
                Some(id),
                "the derivation depends on an object cycle",
            ));
        }
    }
}

/// Byte ranges lie inside their object, and staleness is detected rather than
/// silently reapplied.
///
/// This is the rule the format exists for. An annotation whose recorded digest
/// no longer matches the object it names is reported, never resolved: the same
/// numeric offset in new bytes is almost certainly something else.
fn check_ranges(project: &Project, problems: &mut Vec<Problem>) {
    let object_size: BTreeMap<&str, u64> = project
        .sources
        .objects
        .iter()
        .map(|object| (object.id.as_str(), object.size))
        .collect();
    let object_digest: BTreeMap<&str, &str> = project
        .sources
        .objects
        .iter()
        .map(|object| (object.id.as_str(), object.sha256.as_str()))
        .collect();
    let image_object: BTreeMap<&str, &str> = project
        .programs
        .iter()
        .flat_map(|program| &program.images)
        .map(|image| (image.id.as_str(), image.object_id.as_str()))
        .collect();

    for document in &project.annotations {
        for annotation in &document.annotations {
            if let Some(target) = annotation.target() {
                check_one_range(
                    annotation.id(),
                    target,
                    annotation.is_stale(),
                    &object_size,
                    &object_digest,
                    &image_object,
                    problems,
                );
            }
        }
    }
    for document in &project.resources {
        for resource in &document.resources {
            check_one_range(
                resource.id(),
                resource.target(),
                false,
                &object_size,
                &object_digest,
                &image_object,
                problems,
            );
        }
    }
}

/// One target: does it still describe the bytes it was written against, and
/// does it lie inside them?
fn check_one_range(
    id: &str,
    target: &Target,
    marked_stale: bool,
    object_size: &BTreeMap<&str, u64>,
    object_digest: &BTreeMap<&str, &str>,
    image_object: &BTreeMap<&str, &str>,
    problems: &mut Vec<Problem>,
) {
    let object = match target {
        Target::Object { object_id, .. } => object_id.as_str(),
        Target::Hunk { image_id, .. }
        | Target::Runtime { image_id, .. }
        | Target::BaseRegister { image_id, .. } => match image_object.get(image_id.as_str()) {
            Some(object) => object,
            None => return,
        },
        Target::Entity { .. } => return,
    };
    let (Some(recorded), Some(current)) = (target.object_sha256(), object_digest.get(object))
    else {
        return;
    };

    if recorded == current {
        if marked_stale {
            problems.push(Problem::new(
                ProblemCode::StaleMarkUnwarranted,
                Some(id),
                "marked stale, but its object digest still matches",
            ));
        }
    } else {
        if !marked_stale {
            problems.push(Problem::new(
                ProblemCode::StaleAnnotation,
                Some(id),
                "its object digest no longer matches; rebase it explicitly \
                 rather than trusting the offset",
            ));
        }
        // A stale target's offsets describe bytes that no longer exist, so
        // range-checking them would report a second, misleading problem.
        return;
    }

    if let (Target::Object { offset, length, .. } | Target::Hunk { offset, length, .. }, Some(size)) =
        (target, object_size.get(object))
        && offset.saturating_add(*length) > *size
    {
        problems.push(Problem::new(
            ProblemCode::RangeOutsideObject,
            Some(id),
            format!(
                "the range ends at {} but the object is {size} bytes",
                offset + length
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_needs_a_known_kind_and_a_lowercase_name() {
        assert_eq!(id_kind("source:disk-1"), Some("source"));
        assert_eq!(id_kind("object:disk-1/s/main"), Some("object"));
        for bad in [
            "nokind",
            "Source:x",
            "source:",
            "source:X",
            "invented:x",
            "source:-leading",
            "source:has space",
        ] {
            assert_eq!(id_kind(bad), None, "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_path_must_stay_inside_the_project() {
        assert!(is_safe_relative("analysis/sources.json"));
        for bad in [
            "",
            "/absolute",
            "../escape",
            "a/../../escape",
            "a//b",
            "./x",
        ] {
            assert!(!is_safe_relative(bad), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_resource_reference_must_name_the_kind_it_needs() {
        let kinds = BTreeMap::from([
            ("resource:title-palette", "palette"),
            ("resource:theme-music", "audio"),
        ]);

        // The right kind raises nothing.
        let mut problems = Vec::new();
        check_resource_kind(
            &kinds,
            "resource:title-palette",
            "palette",
            "an image's palette",
            &mut problems,
        );
        assert!(problems.is_empty(), "{problems:?}");

        // The wrong kind is a mismatch, not a missing reference: every resource
        // shares the `resource:` prefix, so the ID category cannot catch this.
        let mut problems = Vec::new();
        check_resource_kind(
            &kinds,
            "resource:theme-music",
            "palette",
            "an image's palette",
            &mut problems,
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].code, ProblemCode::ReferenceKindMismatch);

        // An ID that resolves to nothing is silent here, because the reference
        // check already reported it. One mistake must not read as two.
        let mut problems = Vec::new();
        check_resource_kind(
            &kinds,
            "resource:missing",
            "palette",
            "an image's palette",
            &mut problems,
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn only_the_recoverable_problems_are_non_fatal() {
        // A stale annotation is the format working, not the project being
        // broken: the knowledge survives and is visibly untrustworthy.
        assert!(!ProblemCode::StaleAnnotation.is_fatal());
        assert!(!ProblemCode::StaleMarkUnwarranted.is_fatal());
        assert!(!ProblemCode::InventoryHashMismatch.is_fatal());
        // A dangling reference is not: nothing downstream can act on it.
        assert!(ProblemCode::UnresolvedReference.is_fatal());
        assert!(ProblemCode::ReferenceOwnershipMismatch.is_fatal());
        assert!(ProblemCode::DerivationCycle.is_fatal());
        assert!(ProblemCode::DuplicateId.is_fatal());
        assert!(ProblemCode::DocumentSchemaViolation.is_fatal());
        // Nor is a derivation nothing can reproduce: an object whose kind and
        // selector disagree, or whose recipe no decoder accepts, has a digest
        // with no way back to the bytes it claims.
        assert!(ProblemCode::SelectorKindMismatch.is_fatal());
        assert!(ProblemCode::CodecRecipeInvalid.is_fatal());
        // Nor is a variable that is neither a local nor a global: a consumer
        // asking where it lives has no answer to act on.
        assert!(ProblemCode::VariableShapeInvalid.is_fatal());
        // Nor is a storage width that contradicts the type it names. Both are
        // reviewed claims about the same bytes, and a consumer asking how wide
        // the variable is would have to pick one and be wrong half the time.
        assert!(ProblemCode::TypeSizeMismatch.is_fatal());
    }
}
