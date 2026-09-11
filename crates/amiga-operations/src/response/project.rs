//! Results of the `project.*` operations.
use super::*;

/// Something a legacy config said that the project format has no single place
/// for.
///
/// First-class in the result rather than a diagnostic only: a caller deciding
/// whether to commit an import is deciding about exactly these.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ImportAmbiguity {
    /// The config field it came from.
    pub field: String,
    pub message: String,
}

/// The `project.migrate` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectMigrateResult {
    /// The config the import read, pinned. An import is a derivation, and a
    /// derivation names what it derived from.
    pub source: SourcePin,
    pub ambiguities: Vec<ImportAmbiguity>,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// One document and whether canonical form differs from what is on disk.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FormattedDocument {
    /// Path relative to the project root.
    pub path: String,
    /// Bytes canonical form occupies.
    pub size: u64,
    /// Digest of the canonical bytes. Present for every document, formatted or
    /// not: it is what says the two runs of a formatter agreed.
    pub sha256: String,
    /// Whether the file on disk already is canonical form.
    pub canonical: bool,
}

/// What one registered source turned out to be.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CarrierReport {
    pub source_id: String,
    /// `hunk`, `lha`, `adf`, `adf_non_dos` or `opaque`.
    pub kind: &'static str,
    pub members: u64,
    /// Why a carrier enumerated nothing, when it did not. Reported rather than
    /// left blank: a plan that quietly covered less than it was asked to would
    /// read as complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One object a `project.extract` plan would add.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ExtractedObject {
    pub id: String,
    pub parent_id: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    /// Where the bytes are materialised, relative to the project root. The
    /// selector is what reproduces them, so this file can be deleted and remade.
    pub path: String,
}

/// The `project.extract` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectExtractResult {
    pub carriers: Vec<CarrierReport>,
    pub objects: Vec<ExtractedObject>,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
    pub written: Vec<String>,
}

/// The `project.resource.export` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ResourceExportResult {
    pub resource_id: String,
    /// The artifact record this export writes, named after its recipe key so a
    /// re-export never occupies the previous output's path.
    pub artifact_id: String,
    pub media_type: String,
    pub recipe_key: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Records this export replaces. Their files are reported, never deleted:
    /// nothing in this toolkit removes an artifact behind a person's back.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub superseded: Vec<SupersededArtifact>,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// An artifact record a new export replaces, and the file it still names.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SupersededArtifact {
    pub id: String,
    pub path: String,
}

/// One source a `project.init` plan would register.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct InitializedSource {
    pub id: String,
    /// The whole-file object derived from it.
    ///
    /// It carries a `range` selector covering the entire source rather than no
    /// selector at all: `verify` reports a selector-less object as
    /// unrecoverable, so a project created without one would fail its own
    /// verification the moment it was made.
    pub object_id: String,
    pub display_name: String,
    pub size: u64,
    pub sha256: String,
    /// The project-relative path recorded for this source, when one is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Whether this source needed a machine-local binding instead.
    pub bound_locally: bool,
}

/// The `project.init` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectInitResult {
    pub project_id: String,
    pub name: String,
    pub media: crate::request::MediaPolicy,
    /// Every source, in id order.
    pub sources: Vec<InitializedSource>,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
    /// Paths actually written, relative to the destination. Empty for a
    /// prepared plan.
    pub written: Vec<String>,
}

/// The `project.format` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectFormatResult {
    /// Every document the project's index names, in index order.
    pub documents: Vec<FormattedDocument>,
    /// Documents that are not in canonical form.
    pub unformatted: u64,
    pub plan_sha256: String,
    pub committed: bool,
    /// Documents actually rewritten. Empty for a prepared plan, and empty for a
    /// commit that found everything already canonical.
    pub written: Vec<String>,
}

/// One document the edit would rewrite, or did.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct EditedDocument {
    /// Path relative to the project root.
    pub path: String,
    /// The digest the plan expects to find there. Re-checked at commit, so an
    /// edit made while the review was open is refused rather than discarded.
    pub expected_sha256: String,
    /// Bytes the rewritten document would occupy.
    pub size: u64,
    /// Whether the rewrite would actually change anything. A plan that touches
    /// a document without changing it is reported as such rather than counted
    /// as a change.
    pub changed: bool,
}

/// What a rebase resolved to.
///
/// Reported because the operation derives it: a caller reviewing the plan needs
/// to see *which* object the annotation is being pinned to and at what digest,
/// and that is the whole content of a rebase.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ResolvedRebase {
    /// The annotation being rebased.
    pub id: String,
    pub object_id: String,
    pub object_sha256: String,
}

/// The `project.edit` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectEditResult {
    /// One entry per rebase in the request, in request order.
    pub rebases: Vec<ResolvedRebase>,
    /// Every document the plan covers, in path order.
    pub documents: Vec<EditedDocument>,
    /// Digest of the plan itself: the edits, the documents, and the digests
    /// they are expected to be at. What `commit_reviewed` authorizes against.
    pub plan_sha256: String,
    /// True once the documents have been written. False for a prepared plan,
    /// which writes nothing.
    pub committed: bool,
    /// Documents actually rewritten. Empty for a prepared plan.
    pub written: Vec<String>,
}

/// One file the walk pinned.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct InventoryFile {
    /// Path relative to the walked directory, so the inventory means the same
    /// thing wherever the tree is mounted.
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// One entry the walk deliberately left out, and why.
///
/// Reported rather than silently skipped: a tree digest that quietly excluded
/// something would pin fewer bytes than the directory holds, and nothing in it
/// would say so.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct OmittedEntry {
    pub path: String,
    pub reason: String,
}

/// The `project.inventory` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectInventoryResult {
    pub directory: String,
    pub files: Vec<InventoryFile>,
    pub file_total: u64,
    pub files_truncated: bool,
    pub omitted: Vec<OmittedEntry>,
    /// The digest a directory source would pin. Computed over every file the
    /// walk found, not over the reported ones: a cap is about the response, and
    /// letting it change the digest would make the pin depend on how much of
    /// the answer fit.
    pub tree_sha256: String,
}

/// One comment and where it goes relative to the location it is attached to.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AnnotationComment {
    pub placement: String,
    pub text: String,
}

/// Everything the project says about one hunk offset.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AnnotatedLocation {
    pub hunk: u32,
    pub offset: u64,
    /// The function whose entry is exactly here, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    pub symbols: Vec<String>,
    pub regions: Vec<String>,
    pub bookmarks: Vec<String>,
    pub comments: Vec<AnnotationComment>,
}

/// Where a local variable lives.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "storage")]
pub enum LocalStorage {
    Register { register: String },
    Stack { base: String, displacement: i32 },
}

/// One local variable, under the function that scopes it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AnnotatedLocal {
    /// The scoping function's annotation id.
    pub function_id: String,
    /// The scoping function's reviewed name.
    pub function_name: String,
    pub name: String,
    #[serde(flatten)]
    pub storage: LocalStorage,
    /// The hunk offsets the variable is live across, when the project records
    /// them. Absent means the whole function — weaker knowledge, presented as
    /// such rather than as a range that covers everything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<[u64; 2]>,
}

/// One named small-data global.
///
/// It belongs to no function and therefore to no offset: a location in the
/// loaded program rather than a place in the file. Reporting it under a hunk
/// offset would invent one.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AnnotatedGlobal {
    pub name: String,
    /// The address register the displacement is taken from, e.g. `a5`.
    pub base: String,
    pub displacement: i32,
    /// The access width in bytes.
    pub width: u8,
}

/// One annotation targeting a range of an object's bytes.
///
/// The object-space counterpart of [`AnnotatedLocation`], and deliberately not
/// the same shape. A location is *resolved*: the index answers "what is at hunk
/// 0 offset 4" by folding every annotation that covers it into one row. A range
/// is the claim itself — its own id, its own bounds, and the digest it was
/// established against — because the caller that asks about an object is the
/// one that edits it, and rename, rebase and remove all name an annotation
/// rather than an offset.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AnnotatedRange {
    pub id: String,
    /// `region`, `comment`, `function`, `symbol`, `bookmark` or `variable`.
    pub kind: String,
    /// `user`, `imported` or `reviewed_analysis` — the document's own word for
    /// where this knowledge came from, not a re-phrasing of it.
    pub origin: String,
    pub offset: u64,
    pub length: u64,
    /// What it says: a name, a region's classification, or a comment's text.
    pub label: String,
    /// Where a comment sits relative to what it is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// Whether the document marks it stale. Only `function` and `symbol` carry
    /// the flag, so this is not the general staleness answer — `established`
    /// is.
    pub marked_stale: bool,
    /// Whether the digest it was established against is still the object's.
    ///
    /// `false` means the bytes moved under it: the same numeric offset in new
    /// bytes is almost certainly something else, so it is knowledge to rebase
    /// or remove rather than knowledge to trust.
    pub established: bool,
    /// Comments written about *this annotation* rather than about bytes.
    ///
    /// The format has both comment forms because they are different acts, and
    /// an entity comment is the one that survives: it follows the function
    /// through a rename or a rebase, because it names the annotation and not an
    /// offset. Reported under what it is about rather than beside it, and
    /// carrying no offset of its own — giving it the range of the thing it
    /// comments on would make two different claims look alike.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub about: Vec<EntityComment>,
}

/// One comment about an annotation.
///
/// No offset and no length, deliberately: an entity comment has no range, and
/// the whole reason to write one instead of a byte comment is that it does not
/// go stale when the bytes move.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct EntityComment {
    pub id: String,
    /// `user`, `imported` or `reviewed_analysis`.
    pub origin: String,
    /// Where it sits relative to what it is about.
    pub placement: String,
    pub text: String,
}

/// The `project.annotations` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectAnnotationsResult {
    /// The image this answer is about, when the request named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The object this answer is about, when the request named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Every image the project describes, so a caller that named the wrong one
    /// can be told which are right without asking a second question.
    pub images: Vec<String>,
    /// Every object it derives, for the same reason.
    pub objects: Vec<String>,
    /// Locations in offset order, each carrying everything the project says
    /// there. Image scope only.
    pub locations: Vec<AnnotatedLocation>,
    pub location_total: u64,
    pub locations_truncated: bool,
    /// Annotations targeting the object's bytes, in file order. Object scope
    /// only.
    pub ranges: Vec<AnnotatedRange>,
    pub range_total: u64,
    pub ranges_truncated: bool,
    pub locals: Vec<AnnotatedLocal>,
    pub globals: Vec<AnnotatedGlobal>,
    /// Annotations excluded from every lookup above because they no longer
    /// resolve. Project-wide rather than per image: the index excludes them
    /// before it knows which image asked, which is the right order — a stale
    /// annotation is not knowledge about anywhere.
    pub stale: Vec<String>,
}

/// One source a project pins.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectSource {
    pub id: String,
    pub kind: String,
    /// The project-authored name shown to a person. Unlike a location, this is
    /// stable when the project moves.
    pub display_name: String,
    /// File size when this source is a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The digest the project pins it by — a file's own, or a directory tree's.
    /// Absent when the project pins none, which is a fact about the project
    /// rather than a hole to fill in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Whether that digest covers a directory tree rather than one file.
    pub tree: bool,
    /// Project-relative location hints, as recorded in the project document.
    ///
    /// These are not identity (the digest is), and do not include local host
    /// bindings. A frontend may use one to reopen copied-in media relative to
    /// the project root without parsing project documents itself.
    pub locations: Vec<String>,
    /// Whether these bytes could be obtained again from outside the project.
    ///
    /// False for a *captured* source: bytes that exist because a capture
    /// produced them — a trackloader's output read out of RAM, the memory a
    /// routine changed under a sandbox call. Such a source is pinned and
    /// verifiable against itself and nothing in the format can re-derive it,
    /// which is a different guarantee from the one every other source gives.
    /// Reported rather than inferred, so a reader is told instead of assuming
    /// the stronger reading.
    pub reproducible: bool,
}

/// One object a project derives from a source.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectObject {
    pub id: String,
    pub parent_id: String,
    pub size: u64,
    /// What the object's bytes are pinned at.
    ///
    /// The digest lets a caller identify which project object matches bytes it already
    /// holds, including the object associated with a program image.
    pub sha256: String,
    /// *How* it is derived, not only from what: a decompressed object and a
    /// byte range of the same parent are different claims, and a summary that
    /// showed them identically would hide the one that needs a decoder to
    /// check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,
}

/// One load map: which hunk sits at which runtime address.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectLoadMap {
    pub id: String,
    pub segments: Vec<ProjectLoadSegment>,
}

/// One hunk's place in a load map.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectLoadSegment {
    pub hunk: u32,
    /// The address as the document spells it. Kept verbatim rather than parsed
    /// to a number: the project format is what defines the spelling, and a
    /// summary that reformatted it would no longer quote the document.
    pub runtime_base: String,
}

/// One image a program is built from.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectImage {
    pub id: String,
    pub object_id: String,
    pub load_maps: Vec<ProjectLoadMap>,
}

/// One program a project describes.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectProgram {
    pub id: String,
    pub name: String,
    pub images: Vec<ProjectImage>,
}

/// The `project.describe` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectDescribeResult {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub sources: Vec<ProjectSource>,
    /// Named groups of sources, by id and member count.
    pub source_sets: Vec<ProjectSourceSet>,
    pub objects: Vec<ProjectObject>,
    pub programs: Vec<ProjectProgram>,
    pub annotation_count: u64,
    pub resource_count: u64,
    /// Every resource, with the artifacts it has produced.
    pub resources: Vec<ProjectResource>,
    pub type_count: u64,
    /// Every type the project defines, beside the count that was already here.
    ///
    /// The count answers "does this project define types"; the list answers
    /// "which", which is what a caller about to define one needs. Type
    /// identities are canonical and shared — every `u16` field in every table
    /// in a project points at one `type:u16` — so a frontend writing a record
    /// layout has to know which of the primitives are already there, or it
    /// would redefine one and be refused for a duplicate id.
    pub types: Vec<ProjectType>,
    /// Non-fatal problems the load tolerated. A project that opened with
    /// problems is still a project that opened, which is the property the
    /// format exists for.
    pub problems: Vec<String>,
}

/// One type a project defines.
///
/// Identity and kind, not the whole definition: this answers "what does this
/// project already have", and a caller that needs a struct's fields decodes
/// through it with `analysis.table.decode` rather than reassembling it here.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectType {
    pub id: String,
    /// `integer`, `pointer`, `array`, `struct`, `enum` or `alias`.
    pub kind: String,
    pub name: String,
}

/// The exact address-space-qualified target of a project resource.
///
/// This deliberately mirrors the project format's five target variants rather
/// than translating them into an apparent file range. A HUNK offset, runtime
/// address, base-register slot, and entity identity are different claims even
/// when two of their numeric fields happen to match.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "space", rename_all = "snake_case")]
pub enum ProjectResourceTarget {
    Object {
        object_id: String,
        offset: u64,
        length: u64,
        object_sha256: String,
    },
    Hunk {
        image_id: String,
        hunk: u32,
        offset: u64,
        length: u64,
        object_sha256: String,
    },
    Runtime {
        image_id: String,
        load_map_id: String,
        address: String,
        length: u64,
        object_sha256: String,
    },
    BaseRegister {
        image_id: String,
        base_register: String,
        displacement: i32,
        width: u8,
        object_sha256: String,
    },
    Entity {
        entity_id: String,
    },
}

impl ProjectResourceTarget {
    /// The serialized address-space discriminant.
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
}

impl From<&amiga_project::document::Target> for ProjectResourceTarget {
    fn from(target: &amiga_project::document::Target) -> Self {
        use amiga_project::document::Target;

        match target {
            Target::Object {
                object_id,
                offset,
                length,
                object_sha256,
            } => Self::Object {
                object_id: object_id.to_string(),
                offset: *offset,
                length: *length,
                object_sha256: object_sha256.to_string(),
            },
            Target::Hunk {
                image_id,
                hunk,
                offset,
                length,
                object_sha256,
            } => Self::Hunk {
                image_id: image_id.to_string(),
                hunk: *hunk,
                offset: *offset,
                length: *length,
                object_sha256: object_sha256.to_string(),
            },
            Target::Runtime {
                image_id,
                load_map_id,
                address,
                length,
                object_sha256,
            } => Self::Runtime {
                image_id: image_id.to_string(),
                load_map_id: load_map_id.to_string(),
                address: address.clone(),
                length: *length,
                object_sha256: object_sha256.to_string(),
            },
            Target::BaseRegister {
                image_id,
                base_register,
                displacement,
                width,
                object_sha256,
            } => Self::BaseRegister {
                image_id: image_id.to_string(),
                base_register: base_register.clone(),
                displacement: *displacement,
                width: *width,
                object_sha256: object_sha256.to_string(),
            },
            Target::Entity { entity_id } => Self::Entity {
                entity_id: entity_id.to_string(),
            },
        }
    }
}

/// One resource a project records: how a range of bytes decodes.
///
/// The recipe, not the output. Its artifacts are reported beside it because the
/// question anyone asks about a resource is "has this been exported, and does
/// the file still follow from what the project says now" — and answering that
/// from two operations would mean joining them in every frontend.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectResource {
    pub id: String,
    /// `image`, `palette`, `audio`, `table`, `text`, `code`, `copper`, `data`
    /// or `opaque`.
    pub kind: &'static str,
    pub name: String,
    /// Its complete address-space-qualified locator.
    pub target: ProjectResourceTarget,
    /// Whether every identity needed to place the target resolves in this
    /// project, including a runtime target's load map within its named image.
    pub target_resolved: bool,
    /// What an export produces, stored on the resource or defaulted per kind.
    pub export_media_type: String,
    pub artifacts: Vec<ProjectArtifact>,
}

/// One recorded output of a resource.
///
/// `current` is the recipe question — does this file still follow from what the
/// project says now — answered over the *resolved* dependency graph, so editing
/// an image's palette invalidates the image. It is not the file question:
/// whether the bytes on disk are still the recorded ones needs disk access, and
/// that is `project.verify`'s answer rather than this one.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectArtifact {
    pub id: String,
    /// Project-relative, as the document spells it.
    pub path: String,
    pub media_type: String,
    pub size: u64,
    /// The digest of the output file the record pins.
    pub sha256: String,
    /// The recipe fingerprint it was produced from.
    pub recipe_key: String,
    pub current: bool,
}

/// A named group of sources.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectSourceSet {
    pub id: String,
    pub member_count: u64,
}

/// The `project.check` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectCheckResult {
    pub name: String,
    pub sources: usize,
    pub objects: usize,
    pub annotations: usize,
    /// Every problem, by stable code. A project that opened with problems is
    /// still a success: the problems are the answer, not a failure to give one.
    pub problems: Vec<ProjectProblem>,
}

/// One problem, carried through with the code `amiga-project` assigned it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectProblem {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub message: String,
}

/// The `project.verify` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ProjectVerifyResult {
    pub verified_sources: usize,
    pub verified_objects: usize,
    pub sources: Vec<VerifiedEntity>,
    pub objects: Vec<VerifiedEntity>,
    /// What each recorded artifact's file is doing, if anything.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<VerifiedArtifact>,
}

/// One recorded artifact, checked against the bytes on disk.
///
/// The three answers carry different weights and the status says which.
/// `Artifact` is documented as never the authority for its source data — it
/// records what was made, from what, by what, so it can be remade or discarded
/// — and that decides the reading:
///
/// - **`missing`** is not a failure. The project is intact and the output is
///   regenerable, so deleting `decoded/` stays a safe thing to do.
/// - **`mismatch`** is a contradiction. The document asserts bytes the file does
///   not have, and something outside the project changed them. This is the loud
///   one.
/// - **`stale`** is expected and informational: the normal state after editing a
///   resource, and exactly what an Export surface renders as "needs re-export".
///
/// A verify that treated all three as errors would make a green project
/// impossible for anyone who cleans a generated directory, which is the fastest
/// way to teach people to ignore it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct VerifiedArtifact {
    pub id: String,
    pub resource_id: String,
    pub path: String,
    /// `current`, `stale`, `missing`, `mismatch`, `unreadable`, or `refused`.
    pub status: &'static str,
    /// Whether the file's digest is the one the record pins.
    pub present: bool,
    /// Whether the recipe that made it is still the project's recipe.
    pub current: bool,
    pub contradicted: bool,
    pub detail: String,
}

/// One source or object, and what verification found.
///
/// `verified` and `contradicted` are separate booleans rather than one enum on
/// the wire, because they are not opposites: an unbound source is neither.
///
/// `status` is the machine contract and `detail` is not, the same division
/// [`ProjectProblem`] makes: a frontend deciding how to present a mismatch must
/// not have to parse prose, and prose that a frontend parsed could never be
/// improved.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct VerifiedEntity {
    pub id: String,
    /// A stable code: `verified`, `unbound`, `missing`, `unreadable`,
    /// `mismatch`, `size_mismatch`, `parent_unavailable`,
    /// `selector_out_of_range`, or `unrecoverable`.
    pub status: &'static str,
    pub verified: bool,
    pub contradicted: bool,
    pub detail: String,
}
