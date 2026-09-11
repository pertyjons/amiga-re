//! The typed project documents.
//!
//! Written *to* the schemas rather than the other way round: every struct is
//! `deny_unknown_fields`, matching `additionalProperties: false`, and every
//! tagged union uses the same discriminant its schema does. The round-trip test
//! is what proves the two agree — a type that drifted from its schema would
//! accept a document the schema refuses, which is the failure mode this
//! ordering exists to prevent.
//!
//! Numbers stay numbers and addresses stay strings, exactly as the format says:
//! JSON has no hex integer syntax, and an address parsed on load would lose the
//! spelling a reviewer reads.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A project-wide identity. Validated on load, not merely deserialized.
pub type Id = String;
/// A lowercase 64-character SHA-256.
pub type Sha256 = String;

/// The root document: identity, the documents that make up the project, and
/// the roles of its directories.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    pub project: ProjectIdentity,
    pub documents: DocumentIndex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directories: Option<Directories>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub id: Id,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Every authoritative document, listed explicitly.
///
/// A loader never discovers metadata by walking `analysis/` and accepting what
/// it finds: a stray JSON file left by an editor must not become project truth.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentIndex {
    pub sources: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
}

/// What each of a project's directories is for.
///
/// Every role is optional and every path is project-relative, so a project that
/// keeps one tree and a project that keeps five describe themselves the same
/// way.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Directories {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports: Option<String>,
    /// Where provisional outputs live — a sandbox export, a checkpoint,
    /// anything a run wrote that is not reviewed knowledge yet.
    ///
    /// The other four roles name where *inputs* and *reviewed* outputs are;
    /// this one exists because a project that forbids provisional files beside
    /// its private source media still has to put them somewhere, and a tool
    /// that reads one back should read it from a place the project declared
    /// rather than from wherever a caller happened to point it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scratch: Option<String>,
}

// --- sources -----------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    pub sources: Vec<Source>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_sets: Vec<SourceSet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<Object>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// One external input.
///
/// `size`/`sha256` for a file, `inventory`/`tree_sha256` for a directory. Both
/// are optional here and required by the schema's conditional, because serde
/// cannot express "required depending on `kind`"; [`validate`](crate::validate()) restates
/// it so a document that skipped schema validation still cannot get through.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: Id,
    pub kind: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_sha256: Option<Sha256>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    /// Whether these bytes can be obtained again from outside the project.
    ///
    /// Omitted means [`Provenance::Media`], which is what every source written
    /// before this field existed is: something somebody still has a copy of.
    #[serde(default, skip_serializing_if = "Provenance::is_media")]
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl Source {
    /// Whether the bytes this source pins could be obtained again.
    ///
    /// A digest match says the same thing for both kinds — these are the bytes
    /// that were recorded — and only one of them can be checked against a world
    /// outside the project. See [`Provenance`] for why the difference is
    /// recorded rather than inferred.
    #[must_use]
    pub const fn is_reproducible(&self) -> bool {
        self.provenance.is_media()
    }
}

/// Where a source's bytes came from, and therefore what verifying one proves.
///
/// The format's derivation graph is rooted in sources and says how every object
/// below one is recovered. It says nothing about how a *source* came to exist,
/// because until now there was only one answer: somebody had the file.
///
/// A trackloader may decrypt, de-interleave or unpack on the way to RAM. Such
/// bytes are not a literal range of their disk image. When a complete bounded
/// execution recipe is available, represent the result as an object using
/// [`Selector::Sandbox`]. Otherwise an imported capture remains evidence whose
/// bytes can be checked but whose creation this project cannot replay.
///
/// The distinction is explicit: no capture becomes reproducible merely because
/// a digest matches, and no RAM-transformed output is a [`Selector::Range`].
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Original media: a disk image, an archive, a file that exists elsewhere.
    /// The project pins its digest and claims nothing about how it was made,
    /// because it was not made here.
    #[default]
    Media,
    /// Bytes that exist because a capture produced them — a trackloader's output
    /// read out of RAM, the memory a routine changed under `env.sandbox.call`.
    ///
    /// Verifiable against themselves; this source records no executable recipe.
    /// `notes` must explain the capture. A reviewed replayable derivation should
    /// instead be recorded as an object using [`Selector::Sandbox`].
    Captured,
}

impl Provenance {
    /// Whether this is ordinary media, which is the default and the common case.
    #[must_use]
    pub const fn is_media(&self) -> bool {
        matches!(self, Self::Media)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    File,
    Directory,
}

/// Where a source has been seen. A hint, never the identity — that is the
/// digest — so a project whose media has moved still opens.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Location {
    ProjectRelative { path: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSet {
    pub id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub members: Vec<SetMember>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetMember {
    pub source_id: Id,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u32>,
}

/// A reproducible byte stream. Objects form an acyclic derivation graph rooted
/// in sources.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub id: Id,
    pub kind: String,
    pub parent_id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<Selector>,
    pub size: u64,
    pub sha256: Sha256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// How an object is recovered from its parent — located inside it, or derived
/// from the whole of it — carrying format-specific identity where the format
/// offers it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "container", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    Adf {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_block: Option<u32>,
    },
    Lha {
        member: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        crc16: Option<u16>,
    },
    Range {
        offset: u64,
        length: u64,
    },
    /// One named export of the immutable sandbox recipe held by the parent.
    ///
    /// Input names are the recipe's source identities; their values name
    /// checksum-verified sources or objects in this project's derivation graph.
    /// The operation layer validates and executes the recipe document. The
    /// format crate deliberately carries no copy of the execution vocabulary.
    Sandbox {
        export: String,
        inputs: BTreeMap<String, Id>,
    },
    /// Decompressed from the whole of its parent.
    ///
    /// The recipe, not a note about one: parent bytes plus this record reproduce
    /// the object, which is what makes a deleted intermediate file recoverable
    /// rather than merely unverifiable.
    Decompressed {
        codec: Codec,
        /// The output size the stream itself declares, where it carries one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        declared_size: Option<u64>,
    },
}

impl Selector {
    /// The `container` discriminant this selector serializes as.
    ///
    /// Present so a refusal can name what it refused. A recoverer that said only
    /// "unsupported" would leave the reader to guess which of an object's two
    /// halves it meant.
    #[must_use]
    pub const fn container(&self) -> &'static str {
        match self {
            Self::Adf { .. } => "adf",
            Self::Lha { .. } => "lha",
            Self::Range { .. } => "range",
            Self::Sandbox { .. } => "sandbox",
            Self::Decompressed { .. } => "decompressed",
        }
    }

    /// Additional graph dependencies, beyond an object's parent.
    pub(crate) fn dependencies(&self) -> impl Iterator<Item = &str> {
        let inputs = match self {
            Self::Sandbox { inputs, .. } => Some(inputs),
            _ => None,
        };
        inputs
            .into_iter()
            .flat_map(|inputs| inputs.values().map(String::as_str))
    }
}

/// A decoder and every parameter it requires.
///
/// The vocabulary is drawn from what `amiga-compress` implements, so a codec
/// this build cannot run is refused by name at load rather than recorded as an
/// unlabelled digest. Nothing here is optional: a parameter left to a default
/// would decode to different bytes on a build whose default differed, and the
/// point of writing the recipe down is that it does not.
///
/// The parameter *values* are title-specific and belong to the project that
/// records them; only the vocabulary for stating them is here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "name", rename_all = "snake_case", deny_unknown_fields)]
pub enum Codec {
    /// Headerless PowerPacker, with the loader's four-entry mode table.
    Powerpacker { mode_bits: [u8; 4] },
    /// IFF ByteRun1 / PackBits. Wholly described by its stream.
    ByteRun1 {},
    /// Position-XOR + escape-marker run-length.
    ///
    /// `inline_marker` and `size_includes_field` are layout, not decoration:
    /// a stream that carries its marker as its first byte decodes without error
    /// under the out-of-band layout and produces bytes that were never in the
    /// original, so which one it is has to be recorded.
    RleXor {
        marker: u8,
        xor: bool,
        inline_marker: bool,
        size_bytes: u8,
        size_includes_field: bool,
    },
}

impl Codec {
    /// The `name` discriminant this codec serializes as.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Powerpacker { .. } => "powerpacker",
            Self::ByteRun1 {} => "byte_run1",
            Self::RleXor { .. } => "rle_xor",
        }
    }

    /// Whether this codec's stream carries its own output size.
    ///
    /// What decides whether a `declared_size` has a source. Recording one for a
    /// stream that declares nothing would turn a pin back into an assertion,
    /// which is the failure this whole record exists to end.
    #[must_use]
    pub const fn declares_output_size(&self) -> bool {
        match self {
            // The trailer's high 24 bits are the output size.
            Self::Powerpacker { .. } => true,
            Self::ByteRun1 {} => false,
            Self::RleXor { size_bytes, .. } => *size_bytes != 0,
        }
    }
}

// --- inventory ---------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    pub source_id: Id,
    pub tree_sha256: Sha256,
    pub files: Vec<InventoryFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<OmittedFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryFile {
    pub path: String,
    pub size: u64,
    pub sha256: Sha256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OmittedFile {
    pub path: String,
    pub reason: String,
}

// --- programs ----------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    pub id: Id,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_set_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub images: Vec<Image>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub id: Id,
    pub object_id: Id,
    pub format: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_maps: Vec<LoadMap>,
}

/// A named mapping from hunks to runtime addresses.
///
/// Named because no single address is universally true for a relocatable
/// executable: alternate versions, boot-loaded regions, and overlays each need
/// their own, and an unnamed one would silently claim to be the only reading.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadMap {
    pub id: Id,
    pub name: String,
    pub segments: Vec<Segment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_points: Vec<EntryPoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub hunk: u32,
    pub runtime_base: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPoint {
    pub address: String,
    pub role: String,
}

// --- annotations -------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnnotationsDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AnnotationScope>,
    pub annotations: Vec<Annotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnnotationScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<Id>,
}

/// Where an annotation applies.
///
/// Tagged by `space` so a file offset, a hunk offset, and a runtime address can
/// never be confused. Every byte target carries the object digest it was
/// established against: if the bytes change the annotation is stale and must be
/// rebased explicitly, never silently reapplied to the same number.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "space", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Object {
        object_id: Id,
        offset: u64,
        length: u64,
        object_sha256: Sha256,
    },
    Hunk {
        image_id: Id,
        hunk: u32,
        offset: u64,
        length: u64,
        object_sha256: Sha256,
    },
    Runtime {
        image_id: Id,
        load_map_id: Id,
        address: String,
        length: u64,
        object_sha256: Sha256,
    },
    /// A small-data global at a base-register displacement.
    ///
    /// A location in the loaded program rather than a range in the file, so it
    /// carries a width instead of an offset and a length. It is a byte target
    /// like the others in every way that matters: it names an image and the
    /// digest it was established against, and goes stale with them.
    BaseRegister {
        image_id: Id,
        base_register: String,
        displacement: i32,
        width: u8,
        object_sha256: Sha256,
    },
    Entity {
        entity_id: Id,
    },
}

impl Target {
    /// The `space` discriminant this target serializes as.
    ///
    /// Present so a refusal can name what it refused, as [`Selector::container`]
    /// does: "a target does not name a global" leaves the reader to guess which
    /// of five spaces they wrote.
    #[must_use]
    pub const fn space(&self) -> &'static str {
        match self {
            Self::Object { .. } => "object",
            Self::Hunk { .. } => "hunk",
            Self::Runtime { .. } => "runtime",
            Self::BaseRegister { .. } => "base_register",
            Self::Entity { .. } => "entity",
        }
    }

    /// The image this target lives in, when it names one.
    #[must_use]
    pub const fn image_id(&self) -> Option<&Id> {
        match self {
            Self::Hunk { image_id, .. }
            | Self::Runtime { image_id, .. }
            | Self::BaseRegister { image_id, .. } => Some(image_id),
            Self::Object { .. } | Self::Entity { .. } => None,
        }
    }

    /// How many bytes this target covers, when it names storage at all.
    ///
    /// The four byte spaces spell their width differently — a range carries a
    /// `length`, a base-register slot carries the access `width` — and a caller
    /// comparing storage against a type's size needs one number rather than
    /// four cases. `None` is what distinguishes an [`Entity`](Self::Entity)
    /// target, which attaches to another annotation and covers no bytes of its
    /// own; that is the test a variable's global shape is decided by.
    #[must_use]
    pub const fn byte_length(&self) -> Option<u64> {
        match self {
            Self::Object { length, .. }
            | Self::Hunk { length, .. }
            | Self::Runtime { length, .. } => Some(*length),
            Self::BaseRegister { width, .. } => Some(*width as u64),
            Self::Entity { .. } => None,
        }
    }

    /// The object digest this target was established against, when it is a byte
    /// range rather than a reference to another entity.
    #[must_use]
    pub const fn object_sha256(&self) -> Option<&Sha256> {
        match self {
            Self::Object { object_sha256, .. }
            | Self::Hunk { object_sha256, .. }
            | Self::Runtime { object_sha256, .. }
            | Self::BaseRegister { object_sha256, .. } => Some(object_sha256),
            Self::Entity { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Annotation {
    Function {
        id: Id,
        origin: Origin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        target: Target,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        noreturn: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stale: Option<bool>,
    },
    Symbol {
        id: Id,
        origin: Origin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        target: Target,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stale: Option<bool>,
    },
    Comment {
        id: Id,
        origin: Origin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        target: Target,
        placement: String,
        text: String,
    },
    /// A named variable: either a function-scoped local, or a global every
    /// function shares.
    ///
    /// The two shapes are mutually exclusive and neither is optional in
    /// practice: a local is `scope` + `storage`, a base-register global is a
    /// `target` in the `base_register` space. Serde cannot express "one or the
    /// other", so all three are optional here and [`validate`](crate::validate()) restates
    /// the rule — a variable with both, or with neither, is refused.
    Variable {
        id: Id,
        origin: Origin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<VariableScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        storage: Option<Storage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<Box<Target>>,
        /// Boxed: a lifetime is two targets, and inlining them here made this
        /// variant twice the size of every other annotation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lifetime: Option<Box<Lifetime>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stale: Option<bool>,
    },
    Region {
        id: Id,
        origin: Origin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        target: Target,
        classification: String,
    },
    Bookmark {
        id: Id,
        origin: Origin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        target: Target,
        name: String,
    },
}

impl Annotation {
    #[must_use]
    pub const fn id(&self) -> &Id {
        match self {
            Self::Function { id, .. }
            | Self::Symbol { id, .. }
            | Self::Comment { id, .. }
            | Self::Variable { id, .. }
            | Self::Region { id, .. }
            | Self::Bookmark { id, .. } => id,
        }
    }

    /// The target, for the kinds that have one. A *local* variable is scoped to
    /// a function rather than targeted at bytes; a base-register global has a
    /// target like any other annotation, which is what lets it go stale.
    #[must_use]
    pub fn target(&self) -> Option<&Target> {
        match self {
            Self::Function { target, .. }
            | Self::Symbol { target, .. }
            | Self::Comment { target, .. }
            | Self::Region { target, .. }
            | Self::Bookmark { target, .. } => Some(target),
            Self::Variable { target, .. } => target.as_deref(),
        }
    }

    /// Whether the author has recorded that this annotation no longer matches
    /// the bytes it was established against.
    ///
    /// Carried by `function`, `symbol` and `variable`, and by neither of the
    /// two questions a reader is likely to ask about that set.
    ///
    /// **Why not on [`Target`], where the evidence is.** Staleness is detected
    /// from a target's `object_sha256`, so it looks as though the flag belongs
    /// there and every kind would inherit it. It does not: a *local* variable
    /// has no target at all — it is a `scope` plus a `storage` — and a variable
    /// with a `lifetime` has two, which would let one annotation be half stale
    /// and leave `is_stale` folding several answers into the one boolean a
    /// consumer needs. The flag is the author's judgement about the *claim*, and
    /// there is one claim per annotation.
    ///
    /// **Why not on `comment`, `region` and `bookmark`.** Those three are read
    /// in place; nothing resolves them by name. The three that carry the flag
    /// are the ones that give a location a name, and
    /// [`Index::build`](crate::resolve::Index::build) keeps a stale one out of
    /// the index — because a name resolving to an address the bytes no longer
    /// hold is a confidently wrong answer, which is worse than no answer.
    /// Dropping a *comment* for the same reason would remove the note sitting
    /// beside the code that changed, which is the one a reader wants most.
    ///
    /// The match below is exhaustive rather than ending in a wildcard, so a
    /// seventh annotation kind cannot inherit either answer by omission.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        match self {
            Self::Function { stale, .. }
            | Self::Symbol { stale, .. }
            | Self::Variable { stale, .. } => matches!(stale, Some(true)),
            Self::Comment { .. } | Self::Region { .. } | Self::Bookmark { .. } => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    User,
    Imported,
    ReviewedAnalysis,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariableScope {
    pub function_id: Id,
}

/// A register or stack variable needs its function scope, so a reused register
/// is not given one name for the whole program.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Storage {
    Register {
        register: String,
    },
    Stack {
        base_register: String,
        displacement: i32,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetime {
    pub start: Target,
    pub end: Target,
}

// --- resources ---------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    pub resources: Vec<Resource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// How a resource's decoded bytes leave the project.
///
/// A resource says how to read *source* bytes and says nothing about what an
/// export produces, so a PNG and a raw RGBA dump of one image would otherwise
/// be indistinguishable — same recipe, same key, two different files. The
/// profile is what makes them two recipes.
///
/// Optional on every resource, and defaulted per kind by
/// [`Resource::export_profile`], so the common case stays one decision. When an
/// encoder eventually takes parameters — a PNG bit depth, a WAV sample format —
/// they belong here beside the media type, because they change the output and
/// therefore have to change the key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportProfile {
    /// What an export of this resource is, e.g. `image/png`.
    pub media_type: String,
}

/// A resource says what bytes *are* and how to decode them — never what the
/// decoded bytes are. That is what makes an export reproducible.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    Image {
        id: Id,
        name: String,
        target: Target,
        format: String,
        width: u32,
        height: u32,
        planes: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plane_order: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        palette_resource_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Palette {
        id: Id,
        name: String,
        target: Target,
        format: String,
        count: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Audio {
        id: Id,
        name: String,
        target: Target,
        encoding: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channels: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sample_rate: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Table {
        id: Id,
        name: String,
        target: Target,
        row_count: u32,
        row_stride: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Text {
        id: Id,
        name: String,
        target: Target,
        encoding: String,
        termination: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Code {
        id: Id,
        name: String,
        target: Target,
        architecture: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        load_map_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Copper {
        id: Id,
        name: String,
        target: Target,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Data {
        id: Id,
        name: String,
        target: Target,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Opaque {
        id: Id,
        name: String,
        target: Target,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export: Option<ExportProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
}

impl Resource {
    #[must_use]
    pub const fn id(&self) -> &Id {
        match self {
            Self::Image { id, .. }
            | Self::Palette { id, .. }
            | Self::Audio { id, .. }
            | Self::Table { id, .. }
            | Self::Text { id, .. }
            | Self::Code { id, .. }
            | Self::Copper { id, .. }
            | Self::Data { id, .. }
            | Self::Opaque { id, .. } => id,
        }
    }

    #[must_use]
    pub const fn target(&self) -> &Target {
        match self {
            Self::Image { target, .. }
            | Self::Palette { target, .. }
            | Self::Audio { target, .. }
            | Self::Table { target, .. }
            | Self::Text { target, .. }
            | Self::Code { target, .. }
            | Self::Copper { target, .. }
            | Self::Data { target, .. }
            | Self::Opaque { target, .. } => target,
        }
    }

    /// What an export of this resource produces, stored or defaulted.
    ///
    /// The default is per kind rather than global: an image exports as a PNG
    /// and a sample as a WAV, and requiring every resource to spell that out
    /// would make the common case a decision nobody has an opinion about.
    /// Whatever this returns is what the artifact key covers, so a stored
    /// profile that happens to equal the default keys identically to an omitted
    /// one.
    #[must_use]
    pub fn export_profile(&self) -> ExportProfile {
        let stored = match self {
            Self::Image { export, .. }
            | Self::Palette { export, .. }
            | Self::Audio { export, .. }
            | Self::Table { export, .. }
            | Self::Text { export, .. }
            | Self::Code { export, .. }
            | Self::Copper { export, .. }
            | Self::Data { export, .. }
            | Self::Opaque { export, .. } => export,
        };
        stored.clone().unwrap_or_else(|| ExportProfile {
            media_type: self.default_media_type().to_owned(),
        })
    }

    /// What this kind of resource exports as when nothing says otherwise.
    #[must_use]
    pub const fn default_media_type(&self) -> &'static str {
        match self {
            Self::Image { .. } | Self::Palette { .. } => "image/png",
            Self::Audio { .. } => "audio/wav",
            // A listing, a decoded table, or extracted strings are read by a
            // person; bytes nothing has interpreted are not.
            Self::Table { .. } | Self::Text { .. } | Self::Code { .. } | Self::Copper { .. } => {
                "text/plain"
            }
            Self::Data { .. } | Self::Opaque { .. } => "application/octet-stream",
        }
    }

    /// The `kind` discriminant this resource serializes as.
    ///
    /// Present for the same reason [`Selector::container`] and [`Target::space`]
    /// are: every resource shares the `resource:` ID prefix, so a reference that
    /// needs a *palette* specifically cannot be checked by ID category alone,
    /// and a refusal has to be able to name what it got instead.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Image { .. } => "image",
            Self::Palette { .. } => "palette",
            Self::Audio { .. } => "audio",
            Self::Table { .. } => "table",
            Self::Text { .. } => "text",
            Self::Code { .. } => "code",
            Self::Copper { .. } => "copper",
            Self::Data { .. } => "data",
            Self::Opaque { .. } => "opaque",
        }
    }
}

/// Generated output. Never the authority for its source data: it records what
/// was made, from what, by what, so it can be remade or discarded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: Id,
    pub resource_id: Id,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    /// The digest of the **output file**, which is what a provenance record
    /// needs and what a verify compares against the bytes on disk.
    pub sha256: Sha256,
    /// The [`crate::recipe::artifact_key`] this output was produced from.
    ///
    /// Its own field, because one field cannot be both the recipe fingerprint
    /// and the file checksum: `is_current` used to compare `sha256` against the
    /// key, which made the two meanings collide in the one place both are
    /// needed at once.
    pub recipe_key: Sha256,
    pub produced_by: ProducedBy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedBy {
    pub tool: String,
    pub version: String,
}

// --- types -------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypesDocument {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub document_kind: String,
    pub format_version: u32,
    pub types: Vec<TypeDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Byte order is always explicit. Amiga data is big-endian, but a format that
/// inferred it from the host would silently produce different results on
/// different machines.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeDefinition {
    Integer {
        id: Id,
        name: String,
        size: u8,
        signed: bool,
        byte_order: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Pointer {
        id: Id,
        name: String,
        pointee_id: Id,
        address_space: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Array {
        id: Id,
        name: String,
        element_id: Id,
        count: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Struct {
        id: Id,
        name: String,
        size: u64,
        fields: Vec<Field>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Enum {
        id: Id,
        name: String,
        base_id: Id,
        members: Vec<EnumMember>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    Alias {
        id: Id,
        name: String,
        aliased_id: Id,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    /// A callable signature: what a routine is passed, what it hands back, and
    /// where each of those lives.
    ///
    /// Every location is explicit because an Amiga game has no ABI to fall back
    /// on. A C compiler's calling convention is a *rule* a reader may assume; a
    /// hand-written routine's register assignment is an *observation*, and a
    /// format that inferred one from the other would put a confident wrong
    /// answer where a reviewer had recorded nothing at all.
    ///
    /// A function has no size, and [`TypeSizes`](crate::layout::TypeSizes)
    /// answers `None` for one: code is not storage. A variable holding a
    /// routine's address is a [`Pointer`](Self::Pointer) whose `pointee_id`
    /// names this, which is a different claim and the one that is true.
    Function {
        id: Id,
        name: String,
        /// In call order, which is the order a reader writes the arguments —
        /// not an order the locations imply, since registers have none.
        ///
        /// Empty means the routine takes nothing, and it is a claim: a
        /// signature is written by somebody who worked the contract out. What
        /// stays unknown is stated in `notes`, or by not attaching a type yet.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        parameters: Vec<Parameter>,
        /// Several, because a 68000 routine routinely returns two — a value in
        /// `D0` and a pointer in `A0` — and folding that into one result would
        /// lose whichever the caller happened not to ask about.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        results: Vec<Parameter>,
        /// Registers a call may leave holding something else.
        ///
        /// `None` is *unknown* and an empty list is *nothing*, and the
        /// difference is the whole reason this is optional. A caller that
        /// treated an unreviewed routine as clobbering nothing would keep a
        /// value across a call that destroyed it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clobbers: Option<Vec<String>>,
        /// Registers a call is known to leave untouched. `None` is unknown, as
        /// for `clobbers`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preserves: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
}

/// One argument or result: what it is, and where the machine keeps it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    pub name: String,
    /// Width, signedness and pointer address space all come from here rather
    /// than being restated, so a parameter cannot describe a different integer
    /// from the type it names.
    pub type_id: Id,
    pub location: AbiLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Where a routine expects to find one value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AbiLocation {
    /// A data or address register: `d0`–`d7`, `a0`–`a6`.
    ///
    /// `a7` is not one. It is the stack pointer, and a routine that took an
    /// argument "in A7" is taking it on the stack — which is the other variant,
    /// and says where.
    Register { register: String },
    /// A byte offset from the stack pointer as the callee sees it on entry.
    ///
    /// Stated from entry rather than from a frame pointer the routine may never
    /// establish: every 68000 routine has a return address at `(a7)` whether or
    /// not it builds a frame, so entry is the one reference point that always
    /// exists.
    Stack { offset: u64 },
}

impl AbiLocation {
    /// The `kind` discriminant this location serializes as.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Register { .. } => "register",
            Self::Stack { .. } => "stack",
        }
    }
}

impl TypeDefinition {
    #[must_use]
    pub const fn id(&self) -> &Id {
        match self {
            Self::Integer { id, .. }
            | Self::Pointer { id, .. }
            | Self::Array { id, .. }
            | Self::Struct { id, .. }
            | Self::Enum { id, .. }
            | Self::Alias { id, .. }
            | Self::Function { id, .. } => id,
        }
    }

    /// The readable label. Never an identity — that is [`Self::id`].
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Integer { name, .. }
            | Self::Pointer { name, .. }
            | Self::Array { name, .. }
            | Self::Struct { name, .. }
            | Self::Enum { name, .. }
            | Self::Alias { name, .. }
            | Self::Function { name, .. } => name,
        }
    }

    /// The `kind` tag this definition serializes as.
    ///
    /// The same spelling the schema's `const` uses, so a message naming a kind
    /// names what a reader will find in the document.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Integer { .. } => "integer",
            Self::Pointer { .. } => "pointer",
            Self::Array { .. } => "array",
            Self::Struct { .. } => "struct",
            Self::Enum { .. } => "enum",
            Self::Alias { .. } => "alias",
            Self::Function { .. } => "function",
        }
    }

    /// Whether this is a callable signature rather than a value layout.
    ///
    /// The test a reference goes through: a function annotation's `type_id`
    /// needs one of these and a variable's needs anything but, because storage
    /// holds values and a routine is not a value. Asking by kind rather than by
    /// ID prefix is what makes that checkable — every type shares the `type:`
    /// prefix, so the category alone cannot tell them apart.
    #[must_use]
    pub const fn is_callable(&self) -> bool {
        matches!(self, Self::Function { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub offset: u64,
    pub type_id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnumMember {
    pub name: String,
    pub value: i64,
}

// --- the loaded whole --------------------------------------------------------

/// Every document of one project, loaded and indexed.
///
/// Produced only after the *complete* snapshot loads and validates: a partially
/// loaded project would let a caller act on knowledge whose references have not
/// been checked, which is the failure the format's whole reference discipline
/// exists to prevent.
#[derive(Clone, Debug)]
pub struct Project {
    pub root: ProjectDocument,
    pub sources: SourcesDocument,
    /// Directory inventories, keyed by the source they belong to.
    pub inventories: BTreeMap<Id, InventoryDocument>,
    pub programs: Vec<ProgramDocument>,
    pub annotations: Vec<AnnotationsDocument>,
    pub resources: Vec<ResourcesDocument>,
    pub types: Vec<TypesDocument>,
}

impl Project {
    /// The project-relative directory this project declares for provisional
    /// outputs, if it declares one.
    ///
    /// `None` is a fact about the project rather than a default to substitute:
    /// a caller reading a provisional file back must refuse rather than guess a
    /// path the project never named, so there is no fallback here to make that
    /// mistake easy.
    #[must_use]
    pub fn scratch_directory(&self) -> Option<&str> {
        self.root
            .directories
            .as_ref()?
            .scratch
            .as_deref()
            .filter(|path| !path.is_empty())
    }
}
