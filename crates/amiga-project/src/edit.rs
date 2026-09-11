//! Typed, reviewed edits with optimistic concurrency.
//!
//! An edit is prepared, reviewed, and only then committed — the same shape
//! `amiga-operations` uses for writing files, for the same reason. Between
//! deciding to rename a function and writing the rename, someone else may have
//! renamed it, another tool may have rewritten the document, or the bytes the
//! annotation describes may have changed. Each of those must refuse the write,
//! not overwrite it.
//!
//! The mechanism is a digest per document. An [`EditPlan`] records what every
//! document it touched looked like when the edit was computed;
//! [`EditPlan::apply`] re-reads them and refuses unless they still match. A
//! caller cannot skip the check, because the plan carries no bytes to write —
//! only the edits and the digests they were computed against.
//!
//! Every document a plan writes goes through [`crate::format`], so an edit
//! produces one canonical form rather than whatever the writer happened to
//! emit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

use crate::format::format_document;

/// One change to a project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Edit {
    /// Give a function or symbol a new name.
    Rename { id: String, name: String },
    /// Attach a comment to an entity or to a range of bytes.
    Comment {
        /// The new annotation's own ID.
        id: String,
        /// What it is about.
        on: CommentSubject,
        placement: String,
        text: String,
    },
    /// Accept that an annotation's object has changed, and record its new
    /// digest.
    ///
    /// Explicit by design: a rebase asserts that the offsets still mean what
    /// they meant, which is a judgement only a person can make. Nothing rebases
    /// automatically.
    Rebase { id: String, object_sha256: String },
    /// Create an annotation about a range of bytes.
    ///
    /// The variant the format was missing. `Comment` could always create a
    /// *comment*, but only about an annotation that already existed, so nothing
    /// could say "these bytes are a bitmap" — which is what classifying a region
    /// is, and the whole point of a reverse-engineering project.
    Annotate {
        /// The new annotation's own ID.
        id: String,
        /// `function`, `symbol`, `region` or `bookmark`.
        kind: String,
        /// What it is about. Byte-addressed, so it goes stale with its object.
        target: crate::document::Target,
        /// The name, for a `function` or `symbol`.
        name: Option<String>,
        /// What the bytes are, for a `region`.
        classification: Option<String>,
    },
    /// Delete an annotation.
    Remove { id: String },
    /// Record what a range of bytes decodes to, and how.
    ///
    /// The other half of classifying: `Annotate` says "these bytes are a
    /// bitmap", and this says "320×256, four planes, with that palette" — which
    /// is what makes an export reproducible instead of a one-off file in a
    /// directory.
    DefineResource { resource: crate::document::Resource },
    /// Replace a resource with a corrected one, under the same ID.
    UpdateResource { resource: crate::document::Resource },
    /// Delete a resource.
    RemoveResource { id: String },
    /// Record that a file was produced from a resource.
    ///
    /// What makes an export live: the file is written first, and this is the
    /// write that says it exists, what it is, and which recipe made it.
    RecordArtifact {
        artifact: Box<crate::document::Artifact>,
    },
    /// Forget a produced file.
    ///
    /// Removes the record only. The file is reported as removable and left
    /// alone: nothing in this toolkit deletes an artifact behind a person's
    /// back.
    RemoveArtifact { id: String },
    /// Record what a record looks like: the field layout a decoded table's rows
    /// have, as the format defines it.
    ///
    /// The missing producer. `Resource::Table` has always named its record
    /// layout through `type_id`, and nothing in the workspace could write the
    /// `TypeDefinition` that ID points at — so a table resource carried its
    /// layout as prose in `notes`, which a person can read and no code can act
    /// on.
    DefineType {
        definition: Box<crate::document::TypeDefinition>,
    },
    /// Replace a type with a corrected one, under the same ID.
    UpdateType {
        definition: Box<crate::document::TypeDefinition>,
    },
    /// Delete a type.
    RemoveType { id: String },
    /// Register an external input: a file or directory the project pins.
    ///
    /// The scope nothing could write into. Every other document a project holds
    /// was editable and the sources document — the root of the whole derivation
    /// graph — was written once by `project.init` and never again, so bytes that
    /// came into existence after that had to be added by editing JSON by hand.
    ///
    /// The whole [`Source`](crate::document::Source) arrives rather than a set
    /// of fields, because a source *is* its pinned identity and splitting it
    /// would put half of it under this crate's control and half under the
    /// caller's. What this edit adds is the two things a hand-written document
    /// does not get: the ID checks, and the refusal below.
    ///
    /// **A capture must say what produced it.** A
    /// [`Provenance::Captured`](crate::document::Provenance::Captured) source is
    /// bytes no one can obtain again, so the sentence naming what made them is
    /// the only provenance they will ever have — and it is refused here, where
    /// it is written, rather than at the next load.
    RegisterSource {
        source: Box<crate::document::Source>,
    },
}

/// What a comment is about.
///
/// Both forms stay, and neither is a special case of the other: commenting on a
/// selection and commenting on a name someone already recorded are different
/// acts, and collapsing them would lose one of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommentSubject {
    /// An annotation that already exists.
    Entity { entity_id: String },
    /// A range of bytes, named directly.
    Bytes(Box<crate::document::Target>),
}

impl Edit {
    /// The annotation or resource this edit is about.
    #[must_use]
    pub fn subject(&self) -> &str {
        match self {
            Self::Rename { id, .. }
            | Self::Comment { id, .. }
            | Self::Rebase { id, .. }
            | Self::Annotate { id, .. }
            | Self::Remove { id }
            | Self::RemoveResource { id }
            | Self::RemoveArtifact { id }
            | Self::RemoveType { id } => id,
            Self::DefineResource { resource } | Self::UpdateResource { resource } => resource.id(),
            Self::RecordArtifact { artifact } => &artifact.id,
            Self::DefineType { definition } | Self::UpdateType { definition } => definition.id(),
            Self::RegisterSource { source } => &source.id,
        }
    }

    /// Which document list this edit writes into.
    ///
    /// A plan only reads and re-writes the documents it can actually change:
    /// an annotation edit that also rewrote every resources document would
    /// widen both the conflict check and the diff for no reason.
    const fn scope(&self) -> Scope {
        match self {
            Self::Rename { .. }
            | Self::Comment { .. }
            | Self::Rebase { .. }
            | Self::Annotate { .. }
            | Self::Remove { .. } => Scope::Annotations,
            Self::DefineResource { .. }
            | Self::UpdateResource { .. }
            | Self::RemoveResource { .. }
            | Self::RecordArtifact { .. }
            | Self::RemoveArtifact { .. } => Scope::Resources,
            Self::DefineType { .. } | Self::UpdateType { .. } | Self::RemoveType { .. } => {
                Scope::Types
            }
            Self::RegisterSource { .. } => Scope::Sources,
        }
    }
}

/// Which of a project's editable document lists an edit belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    Annotations,
    Resources,
    Types,
    Sources,
}

/// Why an edit could not be prepared or applied.
#[derive(Debug, Error)]
pub enum EditError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid JSON: {source}")]
    Malformed {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path} would violate its document schema: {problem}")]
    SchemaViolation { path: String, problem: String },
    /// The changeset could not be staged or installed.
    ///
    /// Boxed because the installer's own error carries a boxed cause of its
    /// own, and a caller reading the chain wants the whole of it: whether the
    /// destination was left as it was is the first thing it says.
    #[error("the edit could not be installed: {source}")]
    Install {
        #[source]
        source: Box<amiga_core::InstallError>,
    },
    #[error("no annotation {id} in this project")]
    UnknownSubject { id: String },
    #[error("{id} is a {kind}, which cannot be renamed")]
    NotRenameable { id: String, kind: String },
    #[error("{id} already exists; an edit must not reuse an ID")]
    DuplicateId { id: String },
    #[error("{kind} is not an annotation kind this format defines")]
    UnknownKind { kind: String },
    #[error("a {kind} annotation needs an id starting `{expected}:`, not {id}")]
    WrongIdKind {
        id: String,
        kind: String,
        expected: &'static str,
    },
    /// A plan that creates an annotation needs somewhere to put it, and this
    /// project lists no annotation document at all.
    #[error("this project lists no annotation document, so an annotation has nowhere to go")]
    NoAnnotationDocument,
    /// The same, for the document Milestone 0's `project.init` creates empty
    /// precisely so this cannot happen.
    #[error("this project lists no resource document, so a resource has nowhere to go")]
    NoResourceDocument,
    #[error("no resource {id} in this project")]
    UnknownResource { id: String },
    #[error("no type {id} in this project")]
    UnknownType { id: String },
    #[error("a type needs an id starting `type:`, not {id}")]
    WrongTypeIdKind { id: String },
    /// Removing a type a resource decodes through would leave that resource
    /// unable to decode. Refused where it is written, like every other
    /// reference this format checks.
    #[error("{id} cannot be removed while {reader} decodes through it; change that first")]
    TypeStillRead { id: String, reader: String },
    /// The document Milestone 0's `project.init` creates empty precisely so a
    /// type definition has somewhere to go.
    #[error("this project lists no type document, so a type has nowhere to go")]
    NoTypeDocument,
    #[error("a source needs an id starting `source:`, not {id}")]
    WrongSourceIdKind { id: String },
    /// A capture is bytes nothing can obtain again, so the sentence saying what
    /// produced it is the only provenance it will ever have. Refused where it is
    /// written; `validate` refuses the same document at load, and neither is
    /// redundant — this one names the edit rather than the document.
    #[error("{id} is a capture and must say what produced it, and its notes are empty")]
    CaptureUnexplained { id: String },
    #[error("no artifact {id} in this project")]
    UnknownArtifact { id: String },
    #[error("a resource needs an id starting `resource:`, not {id}")]
    WrongResourceIdKind { id: String },
    /// A reference the decode needs, to something the project does not define.
    /// Refused where it is written rather than discovered at export.
    #[error("{id} references {reference}, which this project does not define")]
    DanglingReference { id: String, reference: String },
    /// The same reference resolving to the wrong *kind*. Every resource shares
    /// the `resource:` prefix, so an image whose palette points at an audio
    /// resource passes an ID check and is still a decode that cannot run.
    #[error("{id} references {reference}, whose kind is {found} where {expected} is needed")]
    WrongReferenceKind {
        id: String,
        reference: String,
        expected: &'static str,
        found: String,
    },
    /// Removing a resource an artifact was produced from would leave a record
    /// of a file with nothing to say what it was made from.
    #[error("{id} cannot be removed while {artifact} was produced from it; remove that first")]
    ResourceHasArtifact { id: String, artifact: String },
    /// Removing an annotation another one is about would leave a comment
    /// pointing at nothing.
    #[error("{id} cannot be removed while {referrer} is about it; remove that first")]
    StillReferenced { id: String, referrer: String },
    /// The optimistic-concurrency check. Someone else wrote the document
    /// between preparing the plan and applying it.
    #[error("{path} changed since the edit was prepared: expected {expected}, found {actual}")]
    Conflict {
        path: String,
        expected: String,
        actual: String,
    },
}

/// A complete, reviewable set of changes.
///
/// Carries the edits and the digest of every document they were computed
/// against — never the bytes to write, so applying it must re-derive them and
/// therefore must re-check.
#[derive(Clone, Debug)]
pub struct EditPlan {
    root: PathBuf,
    /// Where a newly created annotation goes: the first document the project
    /// lists. `None` only for a plan that creates no annotation.
    primary: Option<String>,
    /// The same, for a newly defined resource.
    primary_resources: Option<String>,
    /// The same, for a newly defined type.
    primary_types: Option<String>,
    /// The project's one sources document, when this plan writes it.
    primary_sources: Option<String>,
    /// Document path -> its digest when the plan was prepared.
    seen: BTreeMap<String, String>,
    edits: Vec<Edit>,
}

impl EditPlan {
    /// What this plan would change.
    #[must_use]
    pub fn edits(&self) -> &[Edit] {
        &self.edits
    }

    /// The documents it touches, with the digests it expects to find.
    #[must_use]
    pub const fn expects(&self) -> &BTreeMap<String, String> {
        &self.seen
    }

    /// Prepare `edits` against the project rooted at `root`.
    ///
    /// Reads the document lists the edits can change — annotations, resources,
    /// or both — and the type and program documents a resource reference has to
    /// be checked against. Writes nothing.
    ///
    /// The read set follows the edits rather than the index: a plan that only
    /// renames a function has no business re-writing every resources document,
    /// and a conflict check over documents it cannot change would refuse edits
    /// for no reason.
    ///
    /// # Errors
    /// Returns [`EditError`] when a document cannot be read, an edit names an
    /// annotation or resource that does not exist, an edit would reuse an ID, or
    /// a resource reference is dangling or of the wrong kind.
    pub fn prepare(
        root: &Path,
        documents: &crate::document::DocumentIndex,
        edits: Vec<Edit>,
    ) -> Result<Self, EditError> {
        let scopes: Vec<Scope> = edits.iter().map(Edit::scope).collect();
        let mut seen = BTreeMap::new();
        let mut known: BTreeMap<String, String> = BTreeMap::new();
        // Which annotation is about which, so a removal cannot leave a comment
        // pointing at nothing.
        let mut referrers: BTreeMap<String, String> = BTreeMap::new();
        let annotation_documents: &[String] = if scopes.contains(&Scope::Annotations) {
            &documents.annotations
        } else {
            &[]
        };
        for relative in annotation_documents {
            let (text, value) = read(root, relative)?;
            seen.insert(relative.clone(), digest(&text));
            for annotation in value["annotations"].as_array().into_iter().flatten() {
                if let (Some(id), Some(kind)) =
                    (annotation["id"].as_str(), annotation["kind"].as_str())
                {
                    known.insert(id.to_owned(), kind.to_owned());
                    // The two ways one annotation names another: a comment's
                    // entity target, and a variable's owning function. Field
                    // names rather than a blind string scan, so a comment whose
                    // *text* mentions an id does not become a false refusal.
                    for subject in [
                        annotation["target"]["entity_id"].as_str(),
                        annotation["function_id"].as_str(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        referrers.insert(subject.to_owned(), id.to_owned());
                    }
                }
            }
        }

        // The resource half, read on the same terms: only when an edit could
        // change it. `kinds` answers "is that ID a palette", which is what a
        // reference check needs and what an ID alone cannot say; `produced`
        // answers "was anything made from it".
        let mut kinds: BTreeMap<String, String> = BTreeMap::new();
        let mut resource_referrers: BTreeMap<String, String> = BTreeMap::new();
        let mut produced: BTreeMap<String, String> = BTreeMap::new();
        let mut recorded: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let resource_documents: &[String] = if scopes.contains(&Scope::Resources) {
            &documents.resources
        } else {
            &[]
        };
        for relative in resource_documents {
            let (text, value) = read(root, relative)?;
            seen.insert(relative.clone(), digest(&text));
            for resource in value["resources"].as_array().into_iter().flatten() {
                if let (Some(id), Some(kind)) = (resource["id"].as_str(), resource["kind"].as_str())
                {
                    kinds.insert(id.to_owned(), kind.to_owned());
                    // One resource naming another, so removing a palette an
                    // image reads is a refusal rather than a broken decode.
                    if let Some(palette) = resource["palette_resource_id"].as_str() {
                        resource_referrers.insert(palette.to_owned(), id.to_owned());
                    }
                }
            }
            for artifact in value["artifacts"].as_array().into_iter().flatten() {
                if let (Some(id), Some(resource)) =
                    (artifact["id"].as_str(), artifact["resource_id"].as_str())
                {
                    produced.insert(resource.to_owned(), id.to_owned());
                    recorded.insert(id.to_owned());
                }
            }
        }

        // Type documents are read on two different terms. A resource edit reads
        // them to check a `type_id` and never writes them, so their digests stay
        // out of its conflict check; a type edit reads *and rewrites* them, so
        // they are in `seen` and a concurrent write is a conflict.
        let writes_types = scopes.contains(&Scope::Types);
        let mut references: BTreeMap<String, String> = BTreeMap::new();
        // The type ids this project already defines, so a definition cannot
        // reuse one and a reference cannot dangle.
        let mut type_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // One type naming another: a struct's fields, an array's element, a
        // pointer's pointee, an enum's base, an alias's target.
        let mut type_referrers: BTreeMap<String, String> = BTreeMap::new();
        let type_documents: &[String] = if writes_types { &documents.types } else { &[] };
        if writes_types || scopes.contains(&Scope::Resources) {
            for relative in &documents.types {
                let (text, value) = read(root, relative)?;
                if writes_types {
                    seen.insert(relative.clone(), digest(&text));
                }
                for definition in value["types"].as_array().into_iter().flatten() {
                    let Some(id) = definition["id"].as_str() else {
                        continue;
                    };
                    references.insert(id.to_owned(), "type".to_owned());
                    type_ids.insert(id.to_owned());
                    if writes_types {
                        for referenced in type_references(definition) {
                            type_referrers.insert(referenced, id.to_owned());
                        }
                    }
                }
            }
        }

        // What reads which type, so removing a type something decodes through
        // is a refusal rather than a table or a variable that no longer decodes.
        // Both lists are read without being written, the mirror of the paragraph
        // above: a type edit rewrites neither, so their digests are not part of
        // this plan's conflict check.
        let mut type_readers: BTreeMap<String, String> = BTreeMap::new();
        if writes_types {
            for (list, field) in [
                (&documents.resources, "resources"),
                (&documents.annotations, "annotations"),
            ] {
                for relative in list {
                    let (_, value) = read(root, relative)?;
                    for entry in value[field].as_array().into_iter().flatten() {
                        if let (Some(id), Some(type_id)) =
                            (entry["id"].as_str(), entry["type_id"].as_str())
                        {
                            type_readers.insert(type_id.to_owned(), id.to_owned());
                        }
                    }
                }
            }
        }

        // The sources document, read only when an edit can change it. There is
        // exactly one — the index names it as a string, not a list — so there is
        // no primary to choose, only whether this plan writes it at all.
        //
        // Object IDs are collected beside source IDs because the two share one
        // namespace in the derivation graph: an object naming its parent looks
        // one ID up, and a source that reused an object's ID would make that
        // lookup answer with the wrong thing.
        let mut source_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let writes_sources = scopes.contains(&Scope::Sources);
        if writes_sources {
            let relative = &documents.sources;
            let (text, value) = read(root, relative)?;
            seen.insert(relative.clone(), digest(&text));
            for list in ["sources", "objects", "source_sets"] {
                for entry in value[list].as_array().into_iter().flatten() {
                    if let Some(id) = entry["id"].as_str() {
                        source_ids.insert(id.to_owned());
                    }
                }
            }
        }

        if scopes.contains(&Scope::Resources) {
            for relative in &documents.programs {
                let (_, value) = read(root, relative)?;
                for image in value["images"].as_array().into_iter().flatten() {
                    for map in image["load_maps"].as_array().into_iter().flatten() {
                        if let Some(id) = map["id"].as_str() {
                            references.insert(id.to_owned(), "load map".to_owned());
                        }
                    }
                }
            }
        }

        // A plan applies as one unit, so a referrer this plan also removes is
        // not a referrer afterwards. Checking against the documents alone would
        // refuse "remove the comment and the name it is about", which is exactly
        // the sequence a person needs.
        // Likewise for creation: an annotation this plan creates is a valid
        // subject for a comment in the same plan. Checking only what is on disk
        // would refuse "classify this region, and say why", which is one
        // thought, not two.
        let created: BTreeMap<&str, &str> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::Annotate { id, kind, .. } => Some((id.as_str(), kind.as_str())),
                Edit::Comment { id, .. } => Some((id.as_str(), "comment")),
                _ => None,
            })
            .collect();

        let removed: BTreeMap<&str, ()> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::Remove { id } => Some((id.as_str(), ())),
                _ => None,
            })
            .collect();

        // The same unit rule for resources: "here is the palette, and here is
        // the image that reads it" is one thought, so a resource this plan
        // defines is a valid reference target within it.
        let defined: BTreeMap<&str, &str> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::DefineResource { resource } | Edit::UpdateResource { resource } => {
                    Some((resource.id().as_str(), resource.kind()))
                }
                _ => None,
            })
            .collect();
        let dropped: BTreeMap<&str, ()> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::RemoveResource { id } => Some((id.as_str(), ())),
                _ => None,
            })
            .collect();
        // Re-exporting an unchanged resource produces the same key and
        // therefore the same artifact id, and the export replaces the record in
        // one plan. Without this the second export of an unedited resource
        // would refuse itself.
        let forgotten: BTreeMap<&str, ()> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::RemoveArtifact { id } => Some((id.as_str(), ())),
                _ => None,
            })
            .collect();

        // The same unit rule again, for types. "Here is the record layout, and
        // here is the table that reads it" is one thought, and a struct's own
        // fields point at the primitives defined alongside it in the same plan,
        // so a type this plan defines is a valid reference target within it.
        let typed: std::collections::BTreeSet<&str> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::DefineType { definition } | Edit::UpdateType { definition } => {
                    Some(definition.id().as_str())
                }
                _ => None,
            })
            .collect();
        let untyped: std::collections::BTreeSet<&str> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::RemoveType { id } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        // "Here is the record layout, and here is the table that decodes
        // through it" is one plan, so a resource's `type_id` may name a type
        // this plan defines. Without this the caller would have to write the
        // types, apply, and only then write the table.
        for id in &typed {
            references.insert((*id).to_owned(), "type".to_owned());
        }

        for edit in &edits {
            match edit {
                Edit::Rename { id, .. } => match known.get(id) {
                    None => {
                        return Err(EditError::UnknownSubject { id: id.clone() });
                    }
                    Some(kind) if kind != "function" && kind != "symbol" => {
                        return Err(EditError::NotRenameable {
                            id: id.clone(),
                            kind: kind.clone(),
                        });
                    }
                    Some(_) => {}
                },
                Edit::Rebase { id, .. } => {
                    if !known.contains_key(id) {
                        return Err(EditError::UnknownSubject { id: id.clone() });
                    }
                }
                Edit::Comment { id, on, .. } => {
                    if known.contains_key(id) {
                        return Err(EditError::DuplicateId { id: id.clone() });
                    }
                    if !id.starts_with("annotation:") {
                        return Err(EditError::WrongIdKind {
                            id: id.clone(),
                            kind: "comment".to_owned(),
                            expected: "annotation",
                        });
                    }
                    // Only the entity form has a subject to check. A byte target
                    // names an object, and whether *that* resolves is the
                    // validator's question about the project, not this plan's
                    // about the annotations it is editing.
                    if let CommentSubject::Entity { entity_id } = on
                        && !known.contains_key(entity_id)
                        && !created.contains_key(entity_id.as_str())
                    {
                        return Err(EditError::UnknownSubject {
                            id: entity_id.clone(),
                        });
                    }
                }
                Edit::Annotate { id, kind, .. } => {
                    if known.contains_key(id) {
                        return Err(EditError::DuplicateId { id: id.clone() });
                    }
                    let Some(expected) = id_prefix_for(kind) else {
                        return Err(EditError::UnknownKind { kind: kind.clone() });
                    };
                    // Checked where it is written rather than discovered at the
                    // next load: the ID grammar has its own kind vocabulary, and
                    // `region:` is not in it however natural it reads.
                    if !id.starts_with(&format!("{expected}:")) {
                        return Err(EditError::WrongIdKind {
                            id: id.clone(),
                            kind: kind.clone(),
                            expected,
                        });
                    }
                }
                Edit::Remove { id } => {
                    if !known.contains_key(id) {
                        return Err(EditError::UnknownSubject { id: id.clone() });
                    }
                    // Refuse rather than cascade. Cascading would silently
                    // delete a person's reasoning along with the name it was
                    // about, which is the more expensive mistake of the two —
                    // and the one they cannot undo by reading the refusal.
                    if let Some(referrer) = referrers.get(id)
                        && !removed.contains_key(referrer.as_str())
                    {
                        return Err(EditError::StillReferenced {
                            id: id.clone(),
                            referrer: referrer.clone(),
                        });
                    }
                }
                Edit::DefineResource { resource } => {
                    if kinds.contains_key(resource.id()) {
                        return Err(EditError::DuplicateId {
                            id: resource.id().clone(),
                        });
                    }
                    check_resource(resource, &kinds, &defined, &references)?;
                }
                Edit::UpdateResource { resource } => {
                    if !kinds.contains_key(resource.id()) {
                        return Err(EditError::UnknownResource {
                            id: resource.id().clone(),
                        });
                    }
                    check_resource(resource, &kinds, &defined, &references)?;
                }
                Edit::RemoveResource { id } => {
                    if !kinds.contains_key(id) {
                        return Err(EditError::UnknownResource { id: id.clone() });
                    }
                    // Refused, never cascaded, for the same reason a name with
                    // a comment about it is: the artifact record names a file
                    // that still exists, and deleting the record would leave
                    // bytes on disk nothing can explain.
                    if let Some(artifact) = produced.get(id) {
                        return Err(EditError::ResourceHasArtifact {
                            id: id.clone(),
                            artifact: artifact.clone(),
                        });
                    }
                    if let Some(referrer) = resource_referrers.get(id)
                        && !dropped.contains_key(referrer.as_str())
                    {
                        return Err(EditError::StillReferenced {
                            id: id.clone(),
                            referrer: referrer.clone(),
                        });
                    }
                }
                Edit::RecordArtifact { artifact } => {
                    if recorded.contains(&artifact.id)
                        && !forgotten.contains_key(artifact.id.as_str())
                    {
                        return Err(EditError::DuplicateId {
                            id: artifact.id.clone(),
                        });
                    }
                    // An artifact records what a resource produced, so a record
                    // whose resource is not there describes a file nothing can
                    // explain.
                    if !kinds.contains_key(&artifact.resource_id)
                        && !defined.contains_key(artifact.resource_id.as_str())
                    {
                        return Err(EditError::UnknownResource {
                            id: artifact.resource_id.clone(),
                        });
                    }
                }
                Edit::RemoveArtifact { id } => {
                    if !recorded.contains(id) {
                        return Err(EditError::UnknownArtifact { id: id.clone() });
                    }
                }
                Edit::DefineType { definition } => {
                    if type_ids.contains(definition.id()) {
                        return Err(EditError::DuplicateId {
                            id: definition.id().clone(),
                        });
                    }
                    check_type(definition, &type_ids, &typed)?;
                }
                Edit::UpdateType { definition } => {
                    if !type_ids.contains(definition.id()) {
                        return Err(EditError::UnknownType {
                            id: definition.id().clone(),
                        });
                    }
                    check_type(definition, &type_ids, &typed)?;
                }
                Edit::RemoveType { id } => {
                    if !type_ids.contains(id) {
                        return Err(EditError::UnknownType { id: id.clone() });
                    }
                    // Refused, never cascaded, for the same reason a resource
                    // an artifact was produced from is: a table whose `type_id`
                    // resolves to nothing is a table that no longer decodes,
                    // and the person who removed the type is the one who can
                    // say what should happen to it.
                    if let Some(reader) = type_readers.get(id) {
                        return Err(EditError::TypeStillRead {
                            id: id.clone(),
                            reader: reader.clone(),
                        });
                    }
                    // A type another type points at, on the same terms.
                    if let Some(referrer) = type_referrers.get(id)
                        && !untyped.contains(referrer.as_str())
                    {
                        return Err(EditError::StillReferenced {
                            id: id.clone(),
                            referrer: referrer.clone(),
                        });
                    }
                }
                Edit::RegisterSource { source } => {
                    if source_ids.contains(&source.id) {
                        return Err(EditError::DuplicateId {
                            id: source.id.clone(),
                        });
                    }
                    if !source.id.starts_with("source:") {
                        return Err(EditError::WrongSourceIdKind {
                            id: source.id.clone(),
                        });
                    }
                    // Whitespace is not an explanation. A caller that meant to
                    // compose a sentence and composed nothing gets a refusal
                    // rather than a source whose only provenance is a space.
                    if !source.is_reproducible()
                        && source
                            .notes
                            .as_deref()
                            .is_none_or(|notes| notes.trim().is_empty())
                    {
                        return Err(EditError::CaptureUnexplained {
                            id: source.id.clone(),
                        });
                    }
                }
            }
        }

        // A creating edit has no existing annotation to locate it by, so the
        // plan names one document up front: the first the project lists. A rule
        // stated once here beats each call site guessing.
        let creates = edits
            .iter()
            .any(|edit| matches!(edit, Edit::Annotate { .. } | Edit::Comment { .. }));
        let primary = annotation_documents.first().cloned();
        if creates && primary.is_none() {
            return Err(EditError::NoAnnotationDocument);
        }
        let defines = edits
            .iter()
            .any(|edit| matches!(edit, Edit::DefineResource { .. }));
        let primary_resources = resource_documents.first().cloned();
        if defines && primary_resources.is_none() {
            return Err(EditError::NoResourceDocument);
        }
        let types = edits
            .iter()
            .any(|edit| matches!(edit, Edit::DefineType { .. }));
        let primary_types = type_documents.first().cloned();
        if types && primary_types.is_none() {
            return Err(EditError::NoTypeDocument);
        }

        Ok(Self {
            root: root.to_path_buf(),
            seen,
            edits,
            primary,
            primary_resources,
            primary_types,
            primary_sources: writes_sources.then(|| documents.sources.clone()),
        })
    }

    /// Compute what each touched document would become, without writing.
    ///
    /// Re-reads and re-checks every digest first, so a preview is as
    /// authoritative as a commit — and a caller that only previews still learns
    /// about a conflict.
    ///
    /// # Errors
    /// Returns [`EditError::Conflict`] when a document changed since the plan
    /// was prepared.
    pub fn preview(&self) -> Result<BTreeMap<String, String>, EditError> {
        let mut written = BTreeMap::new();
        for (relative, expected) in &self.seen {
            let (text, mut value) = read(&self.root, relative)?;
            let actual = digest(&text);
            if &actual != expected {
                return Err(EditError::Conflict {
                    path: relative.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
            let is_primary = Primary {
                annotations: self.primary.as_deref() == Some(relative.as_str()),
                resources: self.primary_resources.as_deref() == Some(relative.as_str()),
                types: self.primary_types.as_deref() == Some(relative.as_str()),
                sources: self.primary_sources.as_deref() == Some(relative.as_str()),
            };
            for edit in &self.edits {
                apply_to(&mut value, edit, is_primary);
            }
            let kind = value["document_kind"].as_str().ok_or_else(|| {
                EditError::SchemaViolation {
                    path: relative.clone(),
                    problem: "DOCUMENT_SCHEMA_VIOLATION: /document_kind: the field is missing or is not a string"
                        .to_owned(),
                }
            })?;
            let violations = crate::load::validate_document_schema(relative, kind, &value)
                .map_err(|error| EditError::SchemaViolation {
                    path: relative.clone(),
                    problem: error.to_string(),
                })?;
            if let Some(problem) = violations.first() {
                return Err(EditError::SchemaViolation {
                    path: relative.clone(),
                    problem: problem.to_string(),
                });
            }
            written.insert(relative.clone(), format_document(&value));
        }
        Ok(written)
    }

    /// Apply the plan, writing each touched document in canonical form.
    ///
    /// The whole changeset is staged under the project root and installed with
    /// renames, so a failure part-way through leaves every document as it was.
    /// A plan spans documents that index each other — a root over the documents
    /// it names, an artifact record over the resource it belongs to — and a
    /// project holding a mixture of two changesets is one nothing in the format
    /// can tell from a consistent one.
    ///
    /// # Errors
    /// Returns [`EditError::Conflict`] when a document changed since the plan
    /// was prepared, and [`EditError::Install`] when the changeset could not be
    /// staged or installed. In both cases **nothing is written**, except in the
    /// one case [`amiga_core::InstallError::RolledBackPartially`] reports by
    /// name: the undo itself failing.
    pub fn apply(&self) -> Result<Vec<String>, EditError> {
        // Compute everything first. A partial write would leave the project in
        // a state neither the old nor the new plan describes.
        let written = self.preview()?;
        let staged = amiga_core::StagedChangeset::stage(
            &self.root,
            written
                .into_iter()
                .map(|(relative, text)| (PathBuf::from(&relative), text.into_bytes())),
        )
        .map_err(|source| EditError::Install {
            source: Box::new(source),
        })?;
        let installed = staged.install().map_err(|source| EditError::Install {
            source: Box::new(source),
        })?;
        Ok(installed
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect())
    }
}

/// Whether this document is the one a creating edit writes into, per list.
///
/// A flag per list rather than one: a plan may create an annotation, a resource
/// and the type that resource decodes through at once, and they land in three
/// different documents.
#[derive(Clone, Copy, Debug)]
struct Primary {
    annotations: bool,
    resources: bool,
    types: bool,
    /// There is exactly one sources document, so this is not "which of them"
    /// but "is this it" — the same flag doing a simpler job.
    sources: bool,
}

/// Apply one edit to one document, in place. Silently does nothing when the
/// edit's subject is not in this document — a plan spans several.
fn apply_to(document: &mut Value, edit: &Edit, is_primary: Primary) {
    match edit {
        Edit::Rename { id, name } => {
            for annotation in document
                .get_mut("annotations")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                if annotation["id"] == *id {
                    annotation["name"] = Value::String(name.clone());
                }
            }
        }
        Edit::Rebase { id, object_sha256 } => {
            for annotation in document
                .get_mut("annotations")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                if annotation["id"] == *id {
                    annotation["target"]["object_sha256"] = Value::String(object_sha256.clone());
                    // A rebase is the assertion that made the mark unnecessary,
                    // so it removes it rather than leaving a contradiction.
                    if let Some(map) = annotation.as_object_mut() {
                        map.remove("stale");
                    }
                }
            }
        }
        Edit::Comment {
            id,
            on,
            placement,
            text,
        } => {
            let target = match on {
                // An entity comment lands beside the annotation it is about, so
                // the two travel together when a document is split or moved.
                CommentSubject::Entity { entity_id } => {
                    let targets_here = document["annotations"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|annotation| annotation["id"] == *entity_id);
                    if !targets_here {
                        return;
                    }
                    serde_json::json!({ "space": "entity", "entity_id": entity_id })
                }
                // A byte comment has no annotation to sit beside, so it goes to
                // the plan's primary document like any other creation.
                CommentSubject::Bytes(target) => {
                    if !is_primary.annotations {
                        return;
                    }
                    serde_json::to_value(target.as_ref()).unwrap_or(Value::Null)
                }
            };
            if target.is_null() {
                return;
            }
            if let Some(annotations) = document
                .get_mut("annotations")
                .and_then(Value::as_array_mut)
            {
                annotations.push(serde_json::json!({
                    "id": id,
                    "kind": "comment",
                    "origin": "user",
                    "target": target,
                    "placement": placement,
                    "text": text,
                }));
            }
        }
        Edit::Annotate {
            id,
            kind,
            target,
            name,
            classification,
        } => {
            if !is_primary.annotations {
                return;
            }
            let Ok(target) = serde_json::to_value(target) else {
                return;
            };
            let mut annotation = serde_json::json!({
                "id": id,
                "kind": kind,
                "origin": "user",
                "target": target,
            });
            if let Some(map) = annotation.as_object_mut() {
                if let Some(name) = name {
                    map.insert("name".to_owned(), Value::String(name.clone()));
                }
                if let Some(classification) = classification {
                    map.insert(
                        "classification".to_owned(),
                        Value::String(classification.clone()),
                    );
                }
            }
            if let Some(annotations) = document
                .get_mut("annotations")
                .and_then(Value::as_array_mut)
            {
                annotations.push(annotation);
            }
        }
        Edit::Remove { id } => {
            if let Some(annotations) = document
                .get_mut("annotations")
                .and_then(Value::as_array_mut)
            {
                annotations.retain(|annotation| annotation["id"] != *id);
            }
        }
        Edit::DefineResource { resource } => {
            if !is_primary.resources {
                return;
            }
            let Ok(value) = serde_json::to_value(resource) else {
                return;
            };
            if let Some(resources) = document.get_mut("resources").and_then(Value::as_array_mut) {
                resources.push(value);
            }
        }
        Edit::UpdateResource { resource } => {
            // Replaced in place, wherever it lives: a corrected resource must
            // not move to the primary document and leave the original behind.
            let Ok(value) = serde_json::to_value(resource) else {
                return;
            };
            if let Some(resources) = document.get_mut("resources").and_then(Value::as_array_mut) {
                for existing in resources.iter_mut() {
                    if existing["id"] == *resource.id() {
                        *existing = value.clone();
                    }
                }
            }
        }
        Edit::RemoveResource { id } => {
            if let Some(resources) = document.get_mut("resources").and_then(Value::as_array_mut) {
                resources.retain(|resource| resource["id"] != *id);
            }
        }
        Edit::RecordArtifact { artifact } => {
            if !is_primary.resources {
                return;
            }
            let Ok(value) = serde_json::to_value(artifact.as_ref()) else {
                return;
            };
            // The array is optional in the schema, so a document that has never
            // recorded one has no key to push onto.
            let Some(map) = document.as_object_mut() else {
                return;
            };
            map.entry("artifacts")
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Some(artifacts) = map["artifacts"].as_array_mut() {
                artifacts.push(value);
            }
        }
        Edit::RemoveArtifact { id } => {
            if let Some(artifacts) = document.get_mut("artifacts").and_then(Value::as_array_mut) {
                artifacts.retain(|artifact| artifact["id"] != *id);
            }
        }
        Edit::DefineType { definition } => {
            if !is_primary.types {
                return;
            }
            let Ok(value) = serde_json::to_value(definition.as_ref()) else {
                return;
            };
            if let Some(types) = document.get_mut("types").and_then(Value::as_array_mut) {
                types.push(value);
            }
        }
        Edit::UpdateType { definition } => {
            // Replaced in place, wherever it lives, for the same reason a
            // corrected resource is: moving it to the primary document would
            // leave the original behind and define the id twice.
            let Ok(value) = serde_json::to_value(definition.as_ref()) else {
                return;
            };
            if let Some(types) = document.get_mut("types").and_then(Value::as_array_mut) {
                for existing in types.iter_mut() {
                    if existing["id"] == *definition.id() {
                        *existing = value.clone();
                    }
                }
            }
        }
        Edit::RemoveType { id } => {
            if let Some(types) = document.get_mut("types").and_then(Value::as_array_mut) {
                types.retain(|definition| definition["id"] != *id);
            }
        }
        Edit::RegisterSource { source } => {
            if !is_primary.sources {
                return;
            }
            let Ok(value) = serde_json::to_value(source.as_ref()) else {
                return;
            };
            if let Some(sources) = document.get_mut("sources").and_then(Value::as_array_mut) {
                sources.push(value);
            }
        }
    }
}

/// Check one resource's references before it is written.
///
/// Both halves matter and they answer different questions. Existence says the
/// ID resolves; kind says it resolves to something the decode can use. An image
/// whose palette points at an audio resource passes the first and is a decode
/// that cannot run, and it should be refused where it is written rather than
/// discovered at export.
fn check_resource(
    resource: &crate::document::Resource,
    kinds: &BTreeMap<String, String>,
    defined: &BTreeMap<&str, &str>,
    references: &BTreeMap<String, String>,
) -> Result<(), EditError> {
    use crate::document::Resource;

    let id = resource.id();
    if !id.starts_with("resource:") {
        return Err(EditError::WrongResourceIdKind { id: id.clone() });
    }
    let resolve = |reference: &str, expected: &'static str| -> Result<(), EditError> {
        // A resource this plan defines counts: "here is the palette, and here
        // is the image that reads it" is one thought, not two edits that have
        // to be ordered by hand.
        let found = kinds
            .get(reference)
            .map(String::as_str)
            .or_else(|| defined.get(reference).copied())
            .or_else(|| references.get(reference).map(String::as_str));
        let Some(found) = found else {
            return Err(EditError::DanglingReference {
                id: id.clone(),
                reference: reference.to_owned(),
            });
        };
        if found == expected {
            Ok(())
        } else {
            Err(EditError::WrongReferenceKind {
                id: id.clone(),
                reference: reference.to_owned(),
                expected,
                found: found.to_owned(),
            })
        }
    };

    match resource {
        Resource::Image {
            palette_resource_id: Some(palette),
            ..
        } => resolve(palette, "palette"),
        Resource::Table {
            type_id: Some(type_id),
            ..
        }
        | Resource::Data {
            type_id: Some(type_id),
            ..
        } => resolve(type_id, "type"),
        Resource::Code {
            load_map_id: Some(map),
            ..
        } => resolve(map, "load map"),
        _ => Ok(()),
    }
}

/// Every type id one definition names.
///
/// Field names rather than a blind scan of the object's strings, so a type
/// whose *notes* mention an id does not become a false refusal — the same rule
/// the annotation half follows.
fn type_references(definition: &Value) -> Vec<String> {
    let mut referenced: Vec<String> = ["pointee_id", "element_id", "base_id", "aliased_id"]
        .into_iter()
        .filter_map(|key| definition[key].as_str().map(str::to_owned))
        .collect();
    for field in definition["fields"].as_array().into_iter().flatten() {
        if let Some(id) = field["type_id"].as_str() {
            referenced.push(id.to_owned());
        }
    }
    referenced
}

/// Check one type's references before it is written.
///
/// The same discipline as [`check_resource`], and for the same reason: a struct
/// whose field points at a type nobody defined is a decode that cannot run, and
/// it should be refused where it is written rather than discovered when someone
/// tries to read a table through it. Kind is not checked here because every
/// reference a type makes is to another type — the `type:` prefix carries the
/// whole answer.
fn check_type(
    definition: &crate::document::TypeDefinition,
    type_ids: &std::collections::BTreeSet<String>,
    typed: &std::collections::BTreeSet<&str>,
) -> Result<(), EditError> {
    let id = definition.id();
    if !id.starts_with("type:") {
        return Err(EditError::WrongTypeIdKind { id: id.clone() });
    }
    let Ok(value) = serde_json::to_value(definition) else {
        return Ok(());
    };
    for reference in type_references(&value) {
        // A type this plan defines counts, so a struct and the primitives its
        // fields point at can be written in one plan rather than in an order a
        // caller has to work out.
        if !type_ids.contains(&reference) && !typed.contains(reference.as_str()) {
            return Err(EditError::DanglingReference {
                id: id.clone(),
                reference,
            });
        }
    }
    Ok(())
}

/// The ID prefix an annotation of `kind` must carry.
///
/// The format's ID grammar has its own kind vocabulary, which is not the
/// annotation-kind vocabulary: a `region` and a `bookmark` are both
/// `annotation:`, while a `function` and a `symbol` name themselves. `None` for
/// a kind this format does not define.
const fn id_prefix_for(kind: &str) -> Option<&'static str> {
    match kind.as_bytes() {
        b"function" => Some("function"),
        b"symbol" => Some("symbol"),
        b"region" | b"bookmark" => Some("annotation"),
        _ => None,
    }
}

fn read(root: &Path, relative: &str) -> Result<(String, Value), EditError> {
    let path = root.join(relative);
    let text = std::fs::read_to_string(&path).map_err(|source| EditError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let value = serde_json::from_str(&text).map_err(|source| EditError::Malformed {
        path: path.display().to_string(),
        source,
    })?;
    Ok((text, value))
}

fn digest(text: &str) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
