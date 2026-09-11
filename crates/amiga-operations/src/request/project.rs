//! Arguments for the `project.*` operations: creating a project, filling it,
//! editing its documents, and producing files from what it records.
use super::*;

/// The image a legacy config's `[base]` describes, for an import.
///
/// Both halves or neither. An id with no media names an object that does not
/// exist, so the importer is told nothing rather than half a decision.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedImage {
    pub id: String,
    /// Which source media the image's bytes come from.
    pub media: String,
}

/// Arguments for `project.migrate`.
///
/// The config is named as a **source**, not read from a host path. It is a
/// legacy document being converted — bytes with a digest — which is what
/// separates this from `config show`, whose subject is the same file *as this
/// frontend's settings*.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMigrateArguments {
    pub config: SourceLocator,
    /// The name the imported project takes.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImportedImage>,
    /// Where the documents go. A directory this toolkit owns when the import
    /// creates a project, or one it only writes into when the import lands
    /// beside the config it came from.
    pub destination: String,
    /// True to write into a directory this toolkit does not own, leaving
    /// everything else there alone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_place: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ProjectMigrateArguments {
    #[must_use]
    pub fn new(
        config: impl Into<String>,
        name: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        Self {
            config: SourceLocator::file(config),
            name: name.into(),
            image: None,
            destination: destination.into(),
            in_place: false,
            policy: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub fn with_image(mut self, id: impl Into<String>, media: impl Into<String>) -> Self {
        self.image = Some(ImportedImage {
            id: id.into(),
            media: media.into(),
        });
        self
    }

    #[must_use]
    pub const fn into_existing_directory(mut self) -> Self {
        self.in_place = true;
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// One reviewed change to a project's annotations.
///
/// A rebase names only the annotation. *Which* object it rebases onto and at
/// what digest is a fact about the project, derived where the project is —
/// letting a caller supply it would let two callers rebase the same annotation
/// onto two different digests and both be accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "edit")]
pub enum ProjectEdit {
    /// Give a function or symbol a new name.
    Rename { id: String, name: String },
    /// Accept that an annotation's object has changed, recording its digest.
    Rebase { id: String },
    /// Create an annotation about a range of bytes.
    Annotate {
        id: String,
        /// `function`, `symbol`, `region` or `bookmark`.
        kind: String,
        target: ProjectEditTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        classification: Option<String>,
    },
    /// Attach a comment to an entity or to a range of bytes.
    ///
    /// Reachable at last: this existed in the library and was exposed by no
    /// frontend, which is how a capability and its callers drift apart.
    Comment {
        id: String,
        /// What it is about: a range of bytes, or the annotation that already
        /// names them.
        target: ProjectEditTarget,
        placement: String,
        text: String,
    },
    /// Delete an annotation.
    Remove { id: String },
    /// Record how a range of bytes decodes.
    ///
    /// The resource carries its own target, and that target's digest is
    /// derived here for the same reason an annotation's is.
    DefineResource {
        id: String,
        /// `image`, `palette`, `audio`, `table`, `text`, `code`, `copper`,
        /// `data` or `opaque`.
        kind: String,
        name: String,
        target: ProjectEditTarget,
        /// The parameters that decode it, as the resources schema spells them
        /// for this kind — `width`, `planes`, `count`, `encoding`, …
        ///
        /// A free-form object rather than nine typed variants repeated from
        /// `amiga_project::document::Resource`: the schema is the definition,
        /// and a second copy of it here would be a second thing to keep in
        /// step. It is validated by deserializing into the typed resource
        /// before anything is written, so an unknown or missing field is a
        /// refusal rather than a document nobody can load.
        #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
        parameters: serde_json::Map<String, serde_json::Value>,
        /// What an export produces. Defaulted per kind when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export_media_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    /// Replace a resource with a corrected one, under the same ID.
    UpdateResource {
        id: String,
        kind: String,
        name: String,
        target: ProjectEditTarget,
        #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
        parameters: serde_json::Map<String, serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export_media_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    /// Delete a resource.
    RemoveResource { id: String },
    /// Record what a record looks like: a type the project's own vocabulary
    /// defines, which a table resource's `type_id` can then name.
    ///
    /// The definition arrives whole rather than split into `id`/`kind`/
    /// `parameters` the way a resource does, because a type needs nothing
    /// derived from the project — no target, and therefore no digest. It is
    /// validated by deserializing into `amiga_project::document::TypeDefinition`
    /// before anything is written, so an unknown or missing field is a refusal
    /// rather than a document nobody can load.
    DefineType {
        definition: serde_json::Map<String, serde_json::Value>,
    },
    /// Replace a type with a corrected one, under the same ID.
    UpdateType {
        definition: serde_json::Map<String, serde_json::Value>,
    },
    /// Delete a type.
    RemoveType { id: String },
    /// Forget a produced file.
    ///
    /// Removes the record only. The file is left alone and reported as
    /// removable: nothing in this toolkit deletes an artifact behind a person's
    /// back.
    RemoveArtifact { id: String },
    /// Register bytes that exist because a capture produced them.
    ///
    /// The write that closes the loop `env.sandbox.call` opens. That operation
    /// reports what a routine changed and what it left in a named range, and
    /// until now turning either into a project source meant writing JSON by
    /// hand — a vocabulary nothing writes into gets used wrongly or not at all.
    ///
    /// **The provenance is not a caller's to choose.** These bytes are on no
    /// disk and nothing in this format can re-derive them, so the source is
    /// recorded as `captured` and the note saying what produced it is required.
    /// `env.sandbox.call` composes that sentence and reports it beside each
    /// exported range, so the note a caller passes is one the toolkit wrote from
    /// the recipe rather than prose that happens to be true.
    ///
    /// There is deliberately no selector. A capture is not derived from a parent
    /// and recording it as a `range` would produce an object that verifies
    /// against bytes it is not.
    RegisterCapture {
        /// The source's own id, which must start `source:`.
        id: String,
        /// What to call it in a listing.
        name: String,
        /// The bytes' length, checked against the file when `path` names one.
        size: u64,
        sha256: String,
        /// What produced these bytes. Required, and refused when it is empty.
        notes: String,
        /// Where the bytes were written, relative to the project root. Omitted
        /// registers the pin alone, which verifies as unbound rather than as
        /// verified — honest, and usually not what a caller wants.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
}

/// Where an annotation points, named without a digest.
///
/// Every byte target in the project format carries the digest of the object it
/// was established against, and that digest is a fact about the project rather
/// than something a caller knows. It is derived where the project is, exactly
/// as a rebase's is: letting a caller supply it would let two callers annotate
/// the same bytes against two different digests and both be accepted, and would
/// let a target be pinned to bytes the project does not describe at all.
///
/// The variants mirror [`amiga_project::document::Target`] minus that one field,
/// including the `space` tag, so a request reads the way the document it
/// produces does.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "space", deny_unknown_fields)]
pub enum ProjectEditTarget {
    Object {
        object_id: String,
        offset: u64,
        length: u64,
    },
    Hunk {
        image_id: String,
        hunk: u32,
        offset: u64,
        length: u64,
    },
    Runtime {
        image_id: String,
        load_map_id: String,
        address: String,
        length: u64,
    },
    BaseRegister {
        image_id: String,
        base_register: String,
        displacement: i32,
        width: u8,
    },
    /// An annotation that already exists, for a comment about a name rather
    /// than about bytes. It carries no digest and cannot: it goes stale with
    /// the annotation it is about, which is the correct behaviour.
    Entity { entity_id: String },
}

/// Arguments for `project.edit`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectEditArguments {
    /// Applied together: one plan, one set of expected digests, one commit.
    /// Splitting them into separate requests would let a document change
    /// between two edits that were meant to land as a unit.
    pub edits: Vec<ProjectEdit>,
}

impl ProjectEditArguments {
    #[must_use]
    pub fn new(edits: Vec<ProjectEdit>) -> Self {
        Self { edits }
    }
}

/// Arguments for `project.inventory`.
///
/// The directory is an argument rather than the envelope's project locator,
/// because the thing being inventoried is *media* — the tree a directory source
/// would pin — and not a project. Naming it through the project locator would
/// claim a project is there.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectInventoryArguments {
    /// Resolver-relative identity of the directory to walk.
    pub directory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_files: Option<usize>,
}

impl ProjectInventoryArguments {
    #[must_use]
    pub fn new(directory: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
            maximum_files: None,
        }
    }
}

/// Arguments for `project.annotations`.
///
/// The scope is an argument rather than a locator because a project describes
/// several of each, and reviewed knowledge is only meaningful about one of
/// them: an offset means nothing until you say what it is an offset into.
///
/// **Exactly one scope**, and the two are different questions rather than two
/// spellings of one. An *image* is a loaded program, so its knowledge is
/// resolved through the index to hunk offsets — what is at hunk 0 offset 4.
/// An *object* is bytes a project derived from a source, so its knowledge is
/// the annotations targeting those bytes, in file order, each with the digest
/// it was established against. A project can hold objects and no image at all,
/// which is the ordinary state of one built by `project.init`, and asking about
/// an image there would have no answer.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAnnotationsArguments {
    /// Which of the project's images to resolve against, in hunk space.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Which of the project's objects to list annotations for, in file space.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_locations: Option<usize>,
}

impl ProjectAnnotationsArguments {
    /// Ask about one image, resolved through the index to hunk offsets.
    #[must_use]
    pub fn image(image: impl Into<String>) -> Self {
        Self {
            image: Some(image.into()),
            object: None,
            maximum_locations: None,
        }
    }

    /// Ask about one object, as the annotations targeting its bytes.
    #[must_use]
    pub fn object(object: impl Into<String>) -> Self {
        Self {
            image: None,
            object: Some(object.into()),
            maximum_locations: None,
        }
    }
}

/// Arguments for the project operations.
///
/// Empty on purpose: *which* project is the envelope's `project` locator, not an
/// argument, because it is the same field every future project-backed operation
/// will use. Putting it here would make each operation spell the project
/// differently.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectArguments {}

/// What happens to the media a project registers.
///
/// There is no third option. A source with neither a project-relative location
/// nor a local binding verifies as unbound next session, which is the "the
/// decision did not survive" failure the project format exists to prevent — so
/// the caller states which of these it wants and the operation guarantees one
/// of them holds.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaPolicy {
    /// Copy each source into the project's `original/` directory.
    ///
    /// The project is then self-contained: it verifies on any machine that has
    /// the directory, with no state outside it.
    #[default]
    Copy,
    /// Leave each source where it is.
    ///
    /// A source already under the project root gets a project-relative
    /// location. One outside it gets a `.amiga-re/local.json` binding, which is
    /// true on this machine and nowhere else — the trade this option is.
    InPlace,
}

/// Arguments for `project.extract`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectExtractArguments {
    /// Which registered sources to extract. Empty means every one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ProjectExtractArguments {
    #[must_use]
    pub fn for_sources(sources: Vec<String>) -> Self {
        Self {
            sources,
            maximum_input_bytes: None,
        }
    }
}

/// Arguments for `project.resource.export`.
///
/// One argument, and deliberately so: everything else an export needs — the
/// bytes, the recipe, the encoding, the destination — is already in the
/// project. A caller that could pass a width or an extension would be able to
/// produce a file the record claiming to reproduce it does not describe.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceExportArguments {
    /// The resource to turn back into bytes.
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl ResourceExportArguments {
    #[must_use]
    pub fn new(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            policy: None,
        }
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `project.init`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectInitArguments {
    /// The project's display name.
    pub name: String,
    /// Where the project is created, as an identity the adapter resolves
    /// against its own output root — never a host path.
    pub destination: String,
    /// The sources to register, as identities the resolver resolves.
    pub sources: Vec<String>,
    #[serde(default)]
    pub media: MediaPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ProjectInitArguments {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        destination: impl Into<String>,
        sources: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            destination: destination.into(),
            sources,
            media: MediaPolicy::Copy,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_media(mut self, media: MediaPolicy) -> Self {
        self.media = media;
        self
    }
}
