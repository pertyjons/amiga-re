//! The internal normalized request and its digest.
//!
//! Normalization is the boundary between the wire types and everything else. A
//! [`NormalizedRequest`] carries no serde and no protocol version: it exists so
//! internals can be refactored without moving a serialized field. Every default
//! is materialized here, so a handler never has to know what a default was.
//!
//! Three matches stay here and stay exhaustive, because each is a question that
//! has to be answered for *every* operation and adding one has to fail
//! compilation until it is: [`normalize`] resolves the arguments,
//! [`NormalizedOperation::name`] says which operation it is, and
//! `NormalizedOperation::canonical_arguments` says what its digest is made of.
//! What each arm *decides* is in the module for its operation-name prefix,
//! beside that domain's normalized types, defaults, helpers and document
//! builders — so an argument added there and left out of the digest is a change
//! to two functions in one file rather than to two files that nobody reads
//! together.
//!
//! What is left here is what is decided once for every operation regardless of
//! domain: the protocol version, whether the operation takes a project, which
//! execution modes its access class allows, and the source, destination, limit
//! and project resolution the domains share. And what a `graphics.bitmap.decode`
//! request means is read in one file rather than found among sixty-five others.

use serde_json::{Map, Value, json};

use crate::descriptor::{AccessClass, descriptor};
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::limits::{EffectiveLimit, OperationLimits};
use crate::output::{DestinationName, OutputPolicy};
use crate::protocol::{ExecutionMode, PROTOCOL_VERSION, RequestEnvelope};
use crate::request::{
    BitmapShape, BobMask, CodeDisassembleMode, CodeRegion, HardwareRegisterListArguments,
    HunkDiffFormat, OperationName, OperationRequestDocument, PlaneOrder, SourceLocator,
};
use crate::source::SourceName;

mod analysis;
mod audio;
mod compress;
mod container;
mod environment;
mod graphics;
mod hardware;
mod project;
mod provenance;
mod source;

pub use analysis::*;
pub use audio::*;
pub use compress::*;
pub use container::*;
pub use environment::*;
pub use graphics::*;
pub use hardware::*;
pub use project::*;
pub use provenance::*;
pub use source::*;

/// The entry offsets a traversal starts from, sorted and deduplicated.
///
/// Here rather than in one domain because two of them traverse code: an
/// `analysis.code.*` request and a `hardware.*.references` request both start
/// from a set of entry offsets, and they have to start from the same one.
///
/// Never empty: a traversal from nothing reports a hunk with no code in it,
/// which is a wrong answer rather than an empty one.
fn default_entries(entries: &[u32]) -> Vec<u32> {
    if entries.is_empty() {
        return vec![0];
    }
    let mut entries = entries.to_vec();
    entries.sort_unstable();
    entries.dedup();
    entries
}

/// A validated request with every default made explicit.
#[must_use]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRequest {
    mode: NormalizedMode,
    operation: NormalizedOperation,
}

/// What the request authorizes, reduced to the modes an operation offers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedMode {
    Read,
    /// Build a complete write plan and write nothing.
    Prepare,
    /// Commit the plan whose digest is this, and only if it still matches.
    CommitReviewed {
        approved_plan_sha256: String,
    },
}

/// Fully resolved project-operation arguments: the project's location, and
/// nothing else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProject {
    /// The project root, as an identity the resolver interprets — never a host
    /// path, on the same terms as a source.
    pub path: SourceName,
}

/// One operation with fully resolved arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedOperation {
    SourceSurvey(NormalizedSourceSurvey),
    ContainerAdfList(NormalizedAdfList),
    GraphicsBitmapDecode(NormalizedBitmapDecode),
    ContainerExtract(NormalizedContainerExtract),
    ProjectInit(NormalizedProjectInit),
    ProjectExtract(NormalizedProjectExtract),
    ProjectResourceExport(NormalizedResourceExport),
    GraphicsBitmapExport(NormalizedBitmapExport),
    GraphicsBitmapCompare(NormalizedBitmapCompare),
    GraphicsBitmapCompareExport(NormalizedBitmapCompareExport),
    ProjectCheck(NormalizedProject),
    ProjectVerify(NormalizedProject),
    AnalysisHunkDiff(NormalizedHunkDiff),
    AnalysisHunkDiffExport(NormalizedHunkDiffExport),
    SourceCarve(NormalizedCarve),
    AnalysisTableDecode(NormalizedTableDecode),
    AnalysisTableSummarize(NormalizedTableSummarize),
    AudioSampleDecode(NormalizedAudioSample),
    AudioSampleExport(NormalizedAudioSampleExport),
    CompressPowerpackerDecode(NormalizedPowerpacker),
    CompressPowerpackerExport(NormalizedPowerpackerExport),
    CompressRleXorDecode(NormalizedRleXor),
    CompressRleXorExport(NormalizedRleXorExport),
    AudioPcmDecode(NormalizedPcm),
    AudioPcmExport(NormalizedPcmExport),
    AudioModuleDecode(NormalizedModule),
    AudioModuleExport(NormalizedModuleExport),
    AnalysisHunkNormalize(NormalizedHunkNormalize),
    AnalysisHunkNormalizeExport(NormalizedHunkNormalizeExport),
    ProvenanceManifest(NormalizedManifest),
    ProvenanceManifestExport(NormalizedManifestExport),
    GraphicsPaletteDecode(NormalizedPalette),
    GraphicsPaletteExport(NormalizedPaletteExport),
    EnvSandboxRun(NormalizedSandboxRun),
    EnvBootInfo(NormalizedBootInfo),
    EnvSandboxCall(NormalizedSandboxCall),
    EnvSandboxCallExport(NormalizedSandboxCallExport),
    EnvSandboxMatrix(NormalizedSandboxMatrix),
    EnvSandboxTimeline(NormalizedSandboxTimeline),
    EnvSandboxTimelineExport(NormalizedSandboxTimelineExport),
    EnvSandboxSlice(NormalizedSandboxSlice),
    EnvFrameCapture(NormalizedFrameCapture),
    EnvFrameCaptureExport(NormalizedFrameCaptureExport),
    EnvSandboxCompare(NormalizedSandboxCompare),
    EnvSandboxMatrixExport(NormalizedSandboxMatrixExport),
    EnvBootTrace(NormalizedBootTrace),
    EnvBootTraceExport(NormalizedBootTraceExport),
    AnalysisHunkList(NormalizedHunkList),
    AnalysisStringsScan(NormalizedStringsScan),
    AnalysisAddressResolve(NormalizedAddressResolve),
    AnalysisPointersScan(NormalizedPointerScan),
    AnalysisCodeDisassemble(NormalizedCodeDisassemble),
    AnalysisAddressReferences(NormalizedAddressReferences),
    AnalysisCodeCallgraph(NormalizedCodeCallgraph),
    AnalysisCodeGlobals(NormalizedCodeGlobals),
    AnalysisCodeFixedPoint(NormalizedCodeFixedPoint),
    AnalysisStateSnapshot(NormalizedStateSnapshot),
    AnalysisStateCompare(NormalizedStateCompare),
    ContainerLhaList(NormalizedLhaList),
    HardwareRegisterList,
    AudioPcmScan(NormalizedPcmScan),
    AudioModuleScan(NormalizedModuleScan),
    GraphicsPaletteScan(NormalizedPaletteScan),
    HardwareCopperScan(NormalizedCopperScan),
    HardwareCopperDecode(NormalizedCopperDecode),
    GraphicsIlbmDecode(NormalizedIlbmDecode),
    GraphicsBitmapDetect(NormalizedBitmapDetect),
    HardwareRegisterReferences(NormalizedRegisterReferences),
    HardwareCopperReferences(NormalizedCopperReferences),
    ProjectDescribe(NormalizedProject),
    ProjectAnnotations(NormalizedProjectAnnotations),
    ProjectInventory(NormalizedProjectInventory),
    ProjectEdit(NormalizedProjectEdit),
    ProjectFormat(NormalizedProject),
    ProjectMigrate(NormalizedProjectMigrate),
    AnalysisCodeFacts(NormalizedCodeFacts),
    SourceRead(NormalizedSourceRead),
}

impl NormalizedOperation {
    /// Which operation this is, for anything that needs the name without
    /// caring about the arguments.
    #[must_use]
    pub fn name(&self) -> OperationName {
        match self {
            Self::SourceSurvey(_) => OperationName::SourceSurvey,
            Self::ContainerAdfList(_) => OperationName::ContainerAdfList,
            Self::GraphicsBitmapDecode(_) => OperationName::GraphicsBitmapDecode,
            Self::ContainerExtract(extract) => extract.kind.operation(),
            Self::ProjectInit(_) => OperationName::ProjectInit,
            Self::ProjectExtract(_) => OperationName::ProjectExtract,
            Self::ProjectResourceExport(_) => OperationName::ProjectResourceExport,
            Self::GraphicsBitmapExport(_) => OperationName::GraphicsBitmapExport,
            Self::GraphicsBitmapCompare(_) => OperationName::GraphicsBitmapCompare,
            Self::GraphicsBitmapCompareExport(_) => OperationName::GraphicsBitmapCompareExport,
            Self::ProjectCheck(_) => OperationName::ProjectCheck,
            Self::ProjectVerify(_) => OperationName::ProjectVerify,
            Self::AnalysisHunkDiff(_) => OperationName::AnalysisHunkDiff,
            Self::AnalysisHunkDiffExport(_) => OperationName::AnalysisHunkDiffExport,
            Self::SourceCarve(_) => OperationName::SourceCarve,
            Self::AnalysisTableDecode(_) => OperationName::AnalysisTableDecode,
            Self::AnalysisTableSummarize(_) => OperationName::AnalysisTableSummarize,
            Self::AudioSampleDecode(_) => OperationName::AudioSampleDecode,
            Self::AudioSampleExport(_) => OperationName::AudioSampleExport,
            Self::CompressPowerpackerDecode(_) => OperationName::CompressPowerpackerDecode,
            Self::CompressPowerpackerExport(_) => OperationName::CompressPowerpackerExport,
            Self::CompressRleXorDecode(_) => OperationName::CompressRleXorDecode,
            Self::CompressRleXorExport(_) => OperationName::CompressRleXorExport,
            Self::AudioPcmDecode(_) => OperationName::AudioPcmDecode,
            Self::AudioPcmExport(_) => OperationName::AudioPcmExport,
            Self::AudioModuleDecode(_) => OperationName::AudioModuleDecode,
            Self::AudioModuleExport(_) => OperationName::AudioModuleExport,
            Self::AnalysisHunkNormalize(_) => OperationName::AnalysisHunkNormalize,
            Self::AnalysisHunkNormalizeExport(_) => OperationName::AnalysisHunkNormalizeExport,
            Self::ProvenanceManifest(_) => OperationName::ProvenanceManifest,
            Self::ProvenanceManifestExport(_) => OperationName::ProvenanceManifestExport,
            Self::GraphicsPaletteDecode(_) => OperationName::GraphicsPaletteDecode,
            Self::GraphicsPaletteExport(_) => OperationName::GraphicsPaletteExport,
            Self::EnvSandboxRun(_) => OperationName::EnvSandboxRun,
            Self::EnvBootInfo(_) => OperationName::EnvBootInfo,
            Self::EnvSandboxCall(_) => OperationName::EnvSandboxCall,
            Self::EnvSandboxCallExport(_) => OperationName::EnvSandboxCallExport,
            Self::EnvSandboxMatrix(_) => OperationName::EnvSandboxMatrix,
            Self::EnvSandboxTimeline(_) => OperationName::EnvSandboxTimeline,
            Self::EnvSandboxTimelineExport(_) => OperationName::EnvSandboxTimelineExport,
            Self::EnvSandboxSlice(_) => OperationName::EnvSandboxSlice,
            Self::EnvFrameCapture(_) => OperationName::EnvFrameCapture,
            Self::EnvFrameCaptureExport(_) => OperationName::EnvFrameCaptureExport,
            Self::EnvSandboxCompare(_) => OperationName::EnvSandboxCompare,
            Self::EnvSandboxMatrixExport(_) => OperationName::EnvSandboxMatrixExport,
            Self::EnvBootTrace(_) => OperationName::EnvBootTrace,
            Self::EnvBootTraceExport(_) => OperationName::EnvBootTraceExport,
            Self::AnalysisHunkList(_) => OperationName::AnalysisHunkList,
            Self::AnalysisStringsScan(_) => OperationName::AnalysisStringsScan,
            Self::AnalysisAddressResolve(_) => OperationName::AnalysisAddressResolve,
            Self::AnalysisPointersScan(_) => OperationName::AnalysisPointersScan,
            Self::AnalysisCodeDisassemble(_) => OperationName::AnalysisCodeDisassemble,
            Self::AnalysisAddressReferences(_) => OperationName::AnalysisAddressReferences,
            Self::AnalysisCodeCallgraph(_) => OperationName::AnalysisCodeCallgraph,
            Self::AnalysisCodeGlobals(_) => OperationName::AnalysisCodeGlobals,
            Self::AnalysisCodeFixedPoint(_) => OperationName::AnalysisCodeFixedPoint,
            Self::AnalysisStateSnapshot(_) => OperationName::AnalysisStateSnapshot,
            Self::AnalysisStateCompare(_) => OperationName::AnalysisStateCompare,
            Self::ContainerLhaList(_) => OperationName::ContainerLhaList,
            Self::HardwareRegisterList => OperationName::HardwareRegisterList,
            Self::AudioPcmScan(_) => OperationName::AudioPcmScan,
            Self::AudioModuleScan(_) => OperationName::AudioModuleScan,
            Self::GraphicsPaletteScan(_) => OperationName::GraphicsPaletteScan,
            Self::HardwareCopperScan(_) => OperationName::HardwareCopperScan,
            Self::HardwareCopperDecode(_) => OperationName::HardwareCopperDecode,
            Self::GraphicsIlbmDecode(_) => OperationName::GraphicsIlbmDecode,
            Self::GraphicsBitmapDetect(_) => OperationName::GraphicsBitmapDetect,
            Self::HardwareRegisterReferences(_) => OperationName::HardwareRegisterReferences,
            Self::HardwareCopperReferences(_) => OperationName::HardwareCopperReferences,
            Self::ProjectDescribe(_) => OperationName::ProjectDescribe,
            Self::ProjectAnnotations(_) => OperationName::ProjectAnnotations,
            Self::ProjectInventory(_) => OperationName::ProjectInventory,
            Self::ProjectEdit(_) => OperationName::ProjectEdit,
            Self::ProjectFormat(_) => OperationName::ProjectFormat,
            Self::ProjectMigrate(_) => OperationName::ProjectMigrate,
            Self::AnalysisCodeFacts(_) => OperationName::AnalysisCodeFacts,
            Self::SourceRead(_) => OperationName::SourceRead,
        }
    }

    /// The `arguments` half of the canonical document, for the digest.
    ///
    /// Exhaustive here for the same reason [`normalize`]'s match is: what an
    /// operation's identity is made of has to be stated for every operation, and
    /// adding one must fail compilation until it is. *Which* fields make up that
    /// identity is a fact about the operation, so it is decided in that domain's
    /// module beside the type whose fields it names — an argument added there and
    /// left out of the digest is the mistake this arrangement is meant to make
    /// visible, and it is only visible when the two are read side by side.
    fn canonical_arguments(&self) -> Value {
        match self {
            Self::SourceSurvey(survey) => source::survey_document(survey),
            Self::ContainerAdfList(list) => container::adf_list_document(list),
            Self::GraphicsBitmapDecode(decode) => graphics::bitmap_decode_document(decode),
            Self::ProjectExtract(extract) => project::extract_document(extract),
            Self::ProjectResourceExport(export) => project::resource_export_document(export),
            Self::ProjectInit(init) => project::init_document(init),
            Self::ContainerExtract(extract) => container::container_extract_document(extract),
            Self::GraphicsBitmapExport(export) => graphics::bitmap_export_document(export),
            Self::GraphicsBitmapCompare(compare) => graphics::bitmap_compare_document(compare),
            Self::GraphicsBitmapCompareExport(export) => {
                graphics::bitmap_compare_export_document(export)
            }
            Self::AnalysisHunkDiff(diff) => analysis::hunk_diff_document(diff),
            Self::AnalysisHunkDiffExport(export) => analysis::hunk_diff_export_document(export),
            Self::SourceCarve(carve) => source::carve_document(carve),
            Self::AnalysisTableDecode(table) => analysis::table_decode_document(table),
            Self::AnalysisTableSummarize(table) => analysis::table_summarize_document(table),
            Self::AudioSampleDecode(sample) => audio::audio_sample_document(sample),
            Self::AudioSampleExport(export) => audio::sample_export_document(export),
            Self::CompressPowerpackerDecode(decode) => compress::powerpacker_document(decode),
            Self::CompressPowerpackerExport(export) => {
                compress::powerpacker_export_document(export)
            }
            Self::CompressRleXorDecode(decode) => compress::rle_xor_document(decode),
            Self::CompressRleXorExport(export) => compress::rle_xor_export_document(export),
            Self::AudioPcmDecode(decode) => audio::pcm_document(decode),
            Self::AudioPcmExport(export) => audio::pcm_export_document(export),
            Self::AudioModuleDecode(decode) => audio::module_document(decode),
            Self::AudioModuleExport(export) => audio::module_export_document(export),
            Self::AnalysisHunkNormalize(normalize) => analysis::hunk_normalize_document(normalize),
            Self::AnalysisHunkNormalizeExport(export) => {
                analysis::hunk_normalize_export_document(export)
            }
            Self::ProvenanceManifest(manifest) => provenance::manifest_document(manifest),
            Self::ProvenanceManifestExport(export) => provenance::manifest_export_document(export),
            Self::GraphicsPaletteDecode(decode) => graphics::palette_document(decode),
            Self::GraphicsPaletteExport(export) => graphics::palette_export_document(export),
            Self::EnvSandboxRun(run) => environment::sandbox_run_document(run),
            Self::EnvSandboxCall(call) => environment::sandbox_call_document(call),
            Self::EnvSandboxCallExport(export) => environment::sandbox_call_export_document(export),
            Self::EnvSandboxMatrix(matrix) => environment::sandbox_matrix_document(matrix),
            Self::EnvSandboxTimeline(timeline) => environment::sandbox_timeline_document(timeline),
            Self::EnvSandboxTimelineExport(export) => {
                environment::sandbox_timeline_export_document(export)
            }
            Self::EnvSandboxSlice(slice) => environment::sandbox_slice_document(slice),
            Self::EnvFrameCapture(capture) => environment::frame_capture_document(capture),
            Self::EnvFrameCaptureExport(export) => {
                environment::frame_capture_export_document(export)
            }
            Self::EnvSandboxCompare(compare) => environment::sandbox_compare_document(compare),
            Self::EnvSandboxMatrixExport(export) => {
                environment::sandbox_matrix_export_document(export)
            }
            Self::AnalysisStringsScan(scan) => analysis::strings_scan_document(scan),
            Self::AnalysisAddressResolve(resolve) => analysis::address_resolve_document(resolve),
            Self::AnalysisPointersScan(scan) => analysis::pointers_scan_document(scan),
            Self::AnalysisCodeDisassemble(disassemble) => {
                analysis::code_disassemble_document(disassemble)
            }
            Self::AnalysisAddressReferences(references) => {
                analysis::address_references_document(references)
            }
            Self::AnalysisCodeCallgraph(graph) => analysis::code_callgraph_document(graph),
            Self::SourceRead(read) => source::read_document(read),
            Self::AnalysisCodeFacts(facts) => analysis::code_facts_document(facts),
            Self::AnalysisCodeGlobals(globals) => analysis::code_globals_document(globals),
            Self::AnalysisCodeFixedPoint(fixed) => analysis::code_fixed_point_document(fixed),
            Self::AnalysisStateSnapshot(snapshot) => analysis::state_snapshot_document(snapshot),
            Self::AnalysisStateCompare(compare) => analysis::state_compare_document(compare),
            Self::ContainerLhaList(list) => container::lha_list_document(list),
            // The one operation with nothing to say: the register map is this
            // build's own, so every request for it is the same request.
            Self::HardwareRegisterList => json!({}),
            Self::AudioPcmScan(scan) => audio::pcm_scan_document(scan),
            Self::AudioModuleScan(scan) => audio::module_scan_document(scan),
            Self::GraphicsPaletteScan(scan) => graphics::palette_scan_document(scan),
            Self::HardwareCopperScan(scan) => hardware::copper_scan_document(scan),
            Self::HardwareCopperDecode(decode) => hardware::copper_decode_document(decode),
            Self::GraphicsIlbmDecode(decode) => graphics::ilbm_decode_document(decode),
            Self::GraphicsBitmapDetect(detect) => graphics::bitmap_detect_document(detect),
            Self::HardwareRegisterReferences(references) => {
                hardware::register_references_document(references)
            }
            Self::HardwareCopperReferences(references) => {
                hardware::copper_references_document(references)
            }
            Self::AnalysisHunkList(list) => analysis::hunk_list_document(list),
            Self::EnvBootTrace(trace) => environment::boot_trace_document(trace),
            Self::EnvBootTraceExport(export) => environment::boot_trace_export_document(export),
            Self::EnvBootInfo(info) => environment::boot_info_document(info),
            Self::ProjectCheck(project)
            | Self::ProjectVerify(project)
            | Self::ProjectDescribe(project)
            | Self::ProjectFormat(project) => project::project_document(project),
            Self::ProjectMigrate(migrate) => project::migrate_document(migrate),
            Self::ProjectEdit(edit) => project::edit_document(edit),
            Self::ProjectInventory(inventory) => project::inventory_document(inventory),
            Self::ProjectAnnotations(annotations) => project::annotations_document(annotations),
        }
    }
}

/// One input source, resolved to the file it ultimately comes from and the
/// chain of members to recover out of it.
///
/// A plain file has an empty chain, which is the common case and costs nothing.
/// A member carries the selectors in the order they are applied — outermost
/// first — so recovering means reading the parent once and handing each selector
/// to the recoverer in turn, exactly as `project.verify` walks a derivation.
///
/// The parent is a [`SourceName`] because that is what a resolver resolves; the
/// selectors are the project format's own vocabulary, because a selector carries
/// no project-derived digest and describing them twice is how two spellings of
/// "the member `s/startup-sequence`" come to disagree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSource {
    pub parent: SourceName,
    pub members: Vec<amiga_project::document::Selector>,
}

impl NormalizedSource {
    /// A whole file, with no member inside it.
    #[must_use]
    pub const fn file(parent: SourceName) -> Self {
        Self {
            parent,
            members: Vec::new(),
        }
    }

    /// The source a locator names, validated exactly as a request's own is.
    ///
    /// Public so an adapter holding a locator can recover its bytes through
    /// [`ExecutionContext::resolve_source`] without routing an operation that would
    /// only return those bytes. Listing a container and recovering a member are
    /// separate questions; the shared recoverer handles the latter.
    ///
    /// [`ExecutionContext::resolve_source`]: crate::context::ExecutionContext::resolve_source
    ///
    /// # Errors
    /// Returns the same diagnostics a request carrying this locator would: an
    /// unusable source name, or a `range` selector, which names a byte range
    /// rather than a member.
    pub fn locate(locator: &SourceLocator) -> Result<Self, Vec<Diagnostic>> {
        normalize_source_at(locator, "$.source")
    }

    /// Whether this names bytes inside a container rather than a whole file.
    #[must_use]
    pub const fn is_member(&self) -> bool {
        !self.members.is_empty()
    }

    /// The identity to report bytes recovered through this under.
    ///
    /// The parent's name with each member appended, so a pin and a diagnostic
    /// say which bytes they are about rather than naming the container they came
    /// out of.
    #[must_use]
    pub fn display_name(&self) -> String {
        let mut name = self.parent.as_str().to_owned();
        for member in &self.members {
            name.push('!');
            name.push_str(&member_label(member));
        }
        name
    }

    /// This source as the request document spelled it, for the request digest.
    ///
    /// The *whole* chain, not the parent alone: two requests reading two
    /// different members of one disk are two different questions, and a digest
    /// that could not tell them apart would identify them as one.
    #[must_use]
    pub fn canonical(&self) -> serde_json::Value {
        let mut value = json!({ "kind": "file", "path": self.parent.as_str() });
        for member in &self.members {
            value = json!({
                "kind": "member",
                "parent": value,
                "selector": member,
            });
        }
        value
    }
}

/// What one selector names, for a name a person reads.
fn member_label(selector: &amiga_project::document::Selector) -> String {
    use amiga_project::document::Selector;
    match selector {
        Selector::Adf { path, .. } => path.clone(),
        Selector::Lha { member, .. } => member.clone(),
        Selector::Decompressed { codec, .. } => codec.name().to_owned(),
        Selector::Range { offset, length } => format!("{offset}+{length}"),
        Selector::Sandbox { export, .. } => export.clone(),
    }
}

impl NormalizedRequest {
    /// What the request authorizes.
    #[must_use]
    pub const fn mode(&self) -> &NormalizedMode {
        &self.mode
    }

    #[must_use]
    pub const fn operation(&self) -> &NormalizedOperation {
        &self.operation
    }

    #[must_use]
    pub fn operation_name(&self) -> OperationName {
        self.operation.name()
    }

    /// The canonical document the request digest covers.
    ///
    /// Includes everything that changes which bytes are read or written, and
    /// nothing else: no request id, no event preference, no transport detail.
    /// `serde_json` orders object keys, so serializing this is deterministic.
    #[must_use]
    pub fn canonical_document(&self) -> Value {
        // The approved digest is deliberately *not* in the canonical document.
        // It authorizes a write; it does not change what would be written, and
        // including it would make prepare and commit produce different request
        // digests for the same work.
        let mode = match self.mode {
            NormalizedMode::Read => json!({ "kind": "read" }),
            NormalizedMode::Prepare | NormalizedMode::CommitReviewed { .. } => {
                json!({ "kind": "write" })
            }
        };
        let mut document = Map::new();
        document.insert("mode".to_owned(), mode);
        document.insert(
            "operation".to_owned(),
            Value::from(self.operation.name().as_str()),
        );
        document.insert("arguments".to_owned(), self.operation.canonical_arguments());
        Value::Object(document)
    }

    /// The SHA-256 of the canonical document.
    #[must_use]
    pub fn digest(&self) -> String {
        amiga_core::sha256(self.canonical_document().to_string().as_bytes())
    }
}

/// The canonical form of an operation whose only inputs are a source and a
/// bound. Shared by the two that have nothing else to configure.
fn source_only_document(source: &NormalizedSource, maximum_input_bytes: u64) -> Value {
    json!({
        "source": source.canonical(),
        "maximum_input_bytes": maximum_input_bytes,
    })
}

/// A successful normalization, with any non-fatal findings it produced.
#[derive(Clone, Debug)]
pub struct Normalized {
    pub request: NormalizedRequest,
    pub diagnostics: Vec<Diagnostic>,
}

/// Validate `envelope` and resolve every default against `limits`.
///
/// # Errors
/// Returns the refusing diagnostics when the request cannot be executed. No
/// source is opened and no work is scheduled before this succeeds.
pub fn normalize(
    envelope: &RequestEnvelope,
    limits: OperationLimits,
) -> Result<Normalized, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();

    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestProtocolVersionUnsupported,
                format!(
                    "protocol version {} is not supported; this build serves version {PROTOCOL_VERSION}",
                    envelope.protocol_version
                ),
            )
            .at("$.protocol_version"),
        ]);
    }

    // A project locator is required by the project operations and refused by
    // every other. Deciding it here rather than per handler keeps "does this
    // operation take a project" one fact declared beside the operation.
    //
    // One operation sits between the two. `analysis.table.decode` reads bytes,
    // not a project — but it may be told what a record looks like by naming a
    // struct the project defines, and then it has to read the project to
    // resolve it. So it *accepts* a locator without needing one, and refusing
    // its request for carrying one would make the stored-type spelling
    // unreachable. Which of the two it was given is checked where the arguments
    // are, not here.
    let wants_project = matches!(
        envelope.request,
        OperationRequestDocument::ProjectCheck(_)
            | OperationRequestDocument::ProjectVerify(_)
            | OperationRequestDocument::ProjectDescribe(_)
            | OperationRequestDocument::ProjectAnnotations(_)
            | OperationRequestDocument::ProjectEdit(_)
            | OperationRequestDocument::ProjectFormat(_)
            | OperationRequestDocument::ProjectExtract(_)
            | OperationRequestDocument::ProjectResourceExport(_)
            // A snapshot reads a project's types and annotations and nothing
            // else names them, so it needs one exactly as the project
            // operations do.
            | OperationRequestDocument::AnalysisStateSnapshot(_)
    );
    let accepts_project = matches!(
        envelope.request,
        OperationRequestDocument::AnalysisTableDecode(_)
            | OperationRequestDocument::AnalysisTableSummarize(_)
    );
    match (
        &envelope.project,
        wants_project || accepts_project,
        wants_project,
    ) {
        (Some(_), false, _) => {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestProjectUnsupported,
                    format!(
                        "`{}` does not run against a project; omit `project`",
                        envelope.request.operation_name()
                    ),
                )
                .at("$.project"),
            ]);
        }
        (None, _, true) => {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestProjectRequired,
                    format!(
                        "`{}` runs against a project; name one in `project`",
                        envelope.request.operation_name()
                    ),
                )
                .at("$.project"),
            ]);
        }
        _ => {}
    }

    // `events` is deliberately not validated against anything: both modes are
    // servable. `final_only` is not a restriction on the operation, only on
    // what the adapter does with what it reports — a handler emits the same
    // events either way, and a caller that asked for none gets a sink that
    // discards them. Nothing about the request's meaning changes, which is why
    // `events` stays out of the digest.

    // What an operation may be asked to do is its declared access class, not a
    // fact restated at each handler.
    let described = descriptor(envelope.request.operation_name());
    let mode = match (described.access, &envelope.execution.mode) {
        (AccessClass::ReadOnly, ExecutionMode::Read) => NormalizedMode::Read,
        (AccessClass::ReadOnly, ExecutionMode::Prepare | ExecutionMode::CommitReviewed { .. }) => {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestExecutionModeUnsupported,
                    format!(
                        "`{}` is {} and accepts only the `read` execution mode",
                        described.name,
                        described.access.as_str()
                    ),
                )
                .at("$.execution.mode"),
            ]);
        }
        (AccessClass::PreparedOutput, ExecutionMode::Prepare) => NormalizedMode::Prepare,
        (
            AccessClass::PreparedOutput,
            ExecutionMode::CommitReviewed {
                approved_plan_sha256,
            },
        ) => {
            // The digest is the whole authorization, so an empty or malformed
            // one is refused here rather than failing to match a real plan
            // later and reading as a conflict.
            if approved_plan_sha256.len() != 64
                || !approved_plan_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        "approved_plan_sha256 must be a lowercase 64-character hex digest",
                    )
                    .at("$.execution.mode.approved_plan_sha256"),
                ]);
            }
            NormalizedMode::CommitReviewed {
                approved_plan_sha256: approved_plan_sha256.clone(),
            }
        }
        (AccessClass::PreparedOutput, ExecutionMode::Read) => {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestExecutionModeUnsupported,
                    format!(
                        "`{}` writes files and accepts only `prepare` and \
                         `commit_reviewed`; there is nothing to report without one",
                        described.name
                    ),
                )
                .at("$.execution.mode"),
            ]);
        }
    };

    let operation = match &envelope.request {
        OperationRequestDocument::SourceSurvey(arguments) => {
            source::survey(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ContainerAdfList(arguments) => {
            container::adf_list(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsBitmapDecode(arguments) => {
            graphics::bitmap_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsBitmapExport(arguments) => {
            graphics::bitmap_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsBitmapCompare(arguments) => {
            graphics::bitmap_compare(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsBitmapCompareExport(arguments) => {
            graphics::bitmap_compare_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisHunkDiff(arguments) => {
            analysis::hunk_diff(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisHunkDiffExport(arguments) => {
            analysis::hunk_diff_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::SourceCarve(arguments) => {
            source::carve(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisTableDecode(arguments) => {
            analysis::table_decode(arguments, limits, &mut diagnostics, envelope)?
        }
        OperationRequestDocument::AnalysisTableSummarize(arguments) => {
            analysis::table_summarize(arguments, limits, &mut diagnostics, envelope)?
        }
        OperationRequestDocument::AudioSampleDecode(arguments) => {
            audio::sample_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AudioSampleExport(arguments) => {
            audio::sample_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ProjectCheck(_) => {
            NormalizedOperation::ProjectCheck(normalize_project(envelope.project.as_ref())?)
        }
        OperationRequestDocument::ProjectDescribe(_) => {
            NormalizedOperation::ProjectDescribe(normalize_project(envelope.project.as_ref())?)
        }
        OperationRequestDocument::ProjectMigrate(arguments) => {
            project::migrate(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ProjectFormat(_) => {
            NormalizedOperation::ProjectFormat(normalize_project(envelope.project.as_ref())?)
        }
        OperationRequestDocument::ProjectEdit(arguments) => project::edit(arguments, envelope)?,
        OperationRequestDocument::ProjectInventory(arguments) => {
            project::inventory(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ProjectAnnotations(arguments) => {
            project::annotations(arguments, limits, &mut diagnostics, envelope)?
        }
        OperationRequestDocument::ProjectVerify(_) => {
            NormalizedOperation::ProjectVerify(normalize_project(envelope.project.as_ref())?)
        }
        OperationRequestDocument::ProjectInit(arguments) => NormalizedOperation::ProjectInit(
            normalize_project_init(arguments, limits, &mut diagnostics)?,
        ),
        OperationRequestDocument::ProjectResourceExport(arguments) => {
            project::resource_export(arguments, envelope)?
        }
        OperationRequestDocument::ProjectExtract(arguments) => {
            project::extract(arguments, limits, &mut diagnostics, envelope)?
        }
        OperationRequestDocument::ContainerAdfExtract(arguments) => {
            normalize_container_extract(ContainerKind::Adf, arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ContainerLhaExtract(arguments) => {
            normalize_container_extract(ContainerKind::Lha, arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::CompressPowerpackerDecode(arguments) => {
            compress::powerpacker_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::CompressPowerpackerExport(arguments) => {
            compress::powerpacker_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::CompressRleXorDecode(arguments) => {
            compress::rle_xor_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxCall(arguments) => NormalizedOperation::EnvSandboxCall(
            normalize_sandbox_call(arguments, limits, &mut diagnostics)?,
        ),
        OperationRequestDocument::EnvSandboxCallExport(arguments) => {
            environment::sandbox_call_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxMatrix(arguments) => {
            environment::sandbox_matrix(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxTimeline(arguments) => {
            environment::sandbox_timeline(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxTimelineExport(arguments) => {
            environment::sandbox_timeline_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxSlice(arguments) => {
            environment::sandbox_slice(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvFrameCapture(arguments) => {
            environment::frame_capture(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvFrameCaptureExport(arguments) => {
            environment::frame_capture_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxCompare(arguments) => {
            environment::sandbox_compare(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxMatrixExport(arguments) => {
            environment::sandbox_matrix_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvBootInfo(arguments) => {
            environment::boot_info(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisStringsScan(arguments) => {
            analysis::strings_scan(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisAddressResolve(arguments) => {
            analysis::address_resolve(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisPointersScan(arguments) => {
            analysis::pointers_scan(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisCodeDisassemble(arguments) => {
            analysis::code_disassemble(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisAddressReferences(arguments) => {
            analysis::address_references(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisCodeCallgraph(arguments) => {
            analysis::code_callgraph(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::SourceRead(arguments) => {
            source::read(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisCodeFacts(arguments) => {
            analysis::code_facts(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisCodeGlobals(arguments) => {
            analysis::code_globals(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisCodeFixedPoint(arguments) => {
            analysis::code_fixed_point(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisStateSnapshot(arguments) => {
            analysis::state_snapshot(arguments, limits, &mut diagnostics, envelope)?
        }
        OperationRequestDocument::AnalysisStateCompare(arguments) => {
            analysis::state_compare(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ContainerLhaList(arguments) => {
            container::lha_list(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::HardwareRegisterList(HardwareRegisterListArguments {}) => {
            NormalizedOperation::HardwareRegisterList
        }
        OperationRequestDocument::AudioPcmScan(arguments) => {
            audio::pcm_scan(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AudioModuleScan(arguments) => {
            audio::module_scan(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsPaletteScan(arguments) => {
            graphics::palette_scan(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::HardwareCopperScan(arguments) => {
            hardware::copper_scan(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::HardwareCopperDecode(arguments) => {
            hardware::copper_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsIlbmDecode(arguments) => {
            graphics::ilbm_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsBitmapDetect(arguments) => {
            graphics::bitmap_detect(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::HardwareRegisterReferences(arguments) => {
            hardware::register_references(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::HardwareCopperReferences(arguments) => {
            hardware::copper_references(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisHunkList(arguments) => {
            analysis::hunk_list(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvBootTrace(arguments) => NormalizedOperation::EnvBootTrace(
            normalize_boot_trace(arguments, limits, &mut diagnostics)?,
        ),
        OperationRequestDocument::EnvBootTraceExport(arguments) => {
            environment::boot_trace_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::EnvSandboxRun(arguments) => NormalizedOperation::EnvSandboxRun(
            normalize_sandbox_run(arguments, limits, &mut diagnostics)?,
        ),
        OperationRequestDocument::GraphicsPaletteDecode(arguments) => {
            graphics::palette_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::GraphicsPaletteExport(arguments) => {
            graphics::palette_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisHunkNormalize(arguments) => {
            analysis::hunk_normalize(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AnalysisHunkNormalizeExport(arguments) => {
            analysis::hunk_normalize_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ProvenanceManifest(arguments) => {
            provenance::manifest(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::ProvenanceManifestExport(arguments) => {
            provenance::manifest_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AudioPcmDecode(arguments) => {
            NormalizedOperation::AudioPcmDecode(normalize_pcm(arguments, limits, &mut diagnostics)?)
        }
        OperationRequestDocument::AudioPcmExport(arguments) => {
            audio::pcm_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AudioModuleDecode(arguments) => {
            audio::module_decode(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::AudioModuleExport(arguments) => {
            audio::module_export(arguments, limits, &mut diagnostics)?
        }
        OperationRequestDocument::CompressRleXorExport(arguments) => {
            compress::rle_xor_export(arguments, limits, &mut diagnostics)?
        }
    };

    Ok(Normalized {
        request: NormalizedRequest { mode, operation },
        diagnostics,
    })
}

/// Resolve a `destination` + optional `file_name` into the pair every
/// single-file export uses.
///
/// One place, because the rule is the same everywhere and stating it per
/// operation is how two exports end up disagreeing about whether a `/` in a
/// file name is a directory or a refusal.
fn normalize_single_file_destination(
    destination: &str,
    file_name: Option<&str>,
    default_file_name: &str,
) -> Result<(DestinationName, String), Vec<Diagnostic>> {
    let destination = DestinationName::parse(destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    let file_name = file_name.map_or_else(|| default_file_name.to_owned(), ToOwned::to_owned);
    if DestinationName::parse(&file_name).is_err() || file_name.contains('/') {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestSourceNameInvalid,
                "file_name must be one relative path component",
            )
            .at("$.request.arguments.file_name"),
        ]);
    }
    Ok((destination, file_name))
}

/// Validate a source locator that is not spelled `source`, reporting against
/// the argument that actually carries it.
fn normalize_named_source(
    locator: &SourceLocator,
    json_path: &'static str,
) -> Result<NormalizedSource, Vec<Diagnostic>> {
    normalize_source_at(locator, json_path)
}

/// Validate a source locator into a canonical identity.
fn normalize_source(locator: &SourceLocator) -> Result<NormalizedSource, Vec<Diagnostic>> {
    normalize_source_at(locator, "$.request.arguments.source.path")
}

/// The same, reporting against `json_path` — for the operations whose second
/// source is not called `source`.
fn normalize_source_at(
    locator: &SourceLocator,
    json_path: &'static str,
) -> Result<NormalizedSource, Vec<Diagnostic>> {
    match locator {
        SourceLocator::File { path } => {
            let parent = SourceName::parse(path).map_err(|error| {
                vec![
                    Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                        .at(json_path),
                ]
            })?;
            Ok(NormalizedSource {
                parent,
                members: Vec::new(),
            })
        }
        SourceLocator::Member { parent, selector } => {
            let mut resolved = normalize_source_at(parent, json_path)?;
            // A `range` is arithmetic, not a container, and the format takes
            // those itself rather than asking a recoverer to do them. Refused
            // here rather than at the recoverer, which would report it as an
            // unsupported container and mean something else.
            if matches!(selector, amiga_project::document::Selector::Range { .. }) {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestMalformed,
                        "a `range` selector names a byte range, not a member; every operation \
                         that reads part of a source already takes an offset and a length",
                    )
                    .at(json_path),
                ]);
            }
            if matches!(selector, amiga_project::document::Selector::Sandbox { .. }) {
                return Err(vec![Diagnostic::error(DiagnosticCode::RequestMalformed,
                    "a sandbox derivation requires verified project inputs, not a member locator")
                    .at(json_path)]);
            }
            resolved.members.push(selector.clone());
            Ok(resolved)
        }
    }
}

/// Resolve the input-size bound against the context's own ceiling.
fn normalize_input_bytes(
    requested: Option<u64>,
    ceiling: u64,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<u64, Vec<Diagnostic>> {
    if requested == Some(0) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "maximum_input_bytes must be at least 1",
            )
            .at("$.request.arguments.maximum_input_bytes"),
        ]);
    }
    let effective = EffectiveLimit::resolve(requested, ceiling);
    if effective.reduced {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "maximum_input_bytes reduced to the {} bytes this context allows",
                    effective.value
                ),
            )
            .at("$.request.arguments.maximum_input_bytes"),
        );
    }
    Ok(effective.value)
}

/// Resolve a decompressed-output bound against the context's own ceiling.
fn normalize_output_bytes(
    requested: Option<u64>,
    ceiling: u64,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<u64, Vec<Diagnostic>> {
    if requested == Some(0) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "maximum_output_bytes must be at least 1",
            )
            .at("$.request.arguments.maximum_output_bytes"),
        ]);
    }
    let effective = EffectiveLimit::resolve(requested, ceiling);
    if effective.reduced {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "maximum_output_bytes reduced to the {} bytes this context allows",
                    effective.value
                ),
            )
            .at("$.request.arguments.maximum_output_bytes"),
        );
    }
    Ok(effective.value)
}

/// Resolve a result-count bound against the context's own ceiling.
///
/// `field` names the request argument and `noun` names what is being counted,
/// so one implementation serves every capped collection without either message
/// becoming generic enough to be useless.
fn normalize_count(
    requested: Option<usize>,
    ceiling: usize,
    field: &str,
    noun: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<usize, Vec<Diagnostic>> {
    if requested == Some(0) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("{field} must be at least 1"),
            )
            .at(format!("$.request.arguments.{field}")),
        ]);
    }
    let effective = EffectiveLimit::resolve(requested, ceiling);
    if effective.reduced {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "{field} reduced to the {} {noun} this context allows",
                    effective.value
                ),
            )
            .at(format!("$.request.arguments.{field}")),
        );
    }
    Ok(effective.value)
}

fn normalize_project(
    locator: Option<&crate::protocol::ProjectLocator>,
) -> Result<NormalizedProject, Vec<Diagnostic>> {
    let Some(crate::protocol::ProjectLocator::Path { path }) = locator else {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestProjectRequired,
                "this operation runs against a project",
            )
            .at("$.project"),
        ]);
    };
    SourceName::parse(path)
        .map(|path| NormalizedProject { path })
        .map_err(|error| {
            vec![
                Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                    .at("$.project.path"),
            ]
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ExecutionOptions;
    use crate::request::SourceSurveyArguments;

    fn envelope(arguments: SourceSurveyArguments) -> RequestEnvelope {
        RequestEnvelope::read(OperationRequestDocument::SourceSurvey(arguments))
    }

    #[test]
    fn omitted_arguments_are_materialized_from_documented_defaults() {
        let normalized = normalize(
            &envelope(SourceSurveyArguments::new("sample.bin")),
            OperationLimits::default(),
        )
        .expect("a minimal request normalizes");

        let NormalizedOperation::SourceSurvey(survey) = normalized.request.operation() else {
            panic!("source.survey normalizes to a survey");
        };
        assert_eq!(
            survey.minimum_string_length,
            amiga_analysis::DEFAULT_SURVEY_MIN_STRING_LENGTH
        );
        assert_eq!(
            survey.maximum_input_bytes,
            crate::limits::DEFAULT_MAXIMUM_INPUT_BYTES
        );
        assert_eq!(
            survey.maximum_regions,
            crate::limits::DEFAULT_MAXIMUM_REGIONS
        );
        assert!(normalized.diagnostics.is_empty());
    }

    #[test]
    fn the_digest_covers_the_normalized_request_and_not_its_transport() {
        let plain = envelope(SourceSurveyArguments::new("sample.bin"));
        let correlated = envelope(
            SourceSurveyArguments::new("sample.bin")
                .with_minimum_string_length(amiga_analysis::DEFAULT_SURVEY_MIN_STRING_LENGTH),
        )
        .with_request_id("request:anything");

        let plain = normalize(&plain, OperationLimits::default()).expect("normalizes");
        let correlated = normalize(&correlated, OperationLimits::default()).expect("normalizes");

        // A materialized default and an explicit one are the same request, and
        // the correlation id is not part of what was asked for.
        assert_eq!(plain.request.digest(), correlated.request.digest());

        let different = normalize(
            &envelope(SourceSurveyArguments::new("sample.bin").with_minimum_string_length(4)),
            OperationLimits::default(),
        )
        .expect("normalizes");
        assert_ne!(plain.request.digest(), different.request.digest());
    }

    #[test]
    fn a_request_limit_above_the_context_ceiling_is_reduced_and_reported() {
        let limits = OperationLimits::default().with_maximum_regions(16);
        let normalized = normalize(
            &envelope(SourceSurveyArguments::new("sample.bin").with_maximum_regions(4096)),
            limits,
        )
        .expect("normalizes");

        let NormalizedOperation::SourceSurvey(survey) = normalized.request.operation() else {
            panic!("source.survey normalizes to a survey");
        };
        assert_eq!(survey.maximum_regions, 16);
        assert_eq!(normalized.diagnostics.len(), 1);
        assert_eq!(normalized.diagnostics[0].code, DiagnosticCode::LimitReduced);
    }

    #[test]
    fn a_request_is_refused_before_any_source_is_opened() {
        let unsafe_path = normalize(
            &envelope(SourceSurveyArguments::new("../../etc/passwd")),
            OperationLimits::default(),
        )
        .expect_err("an escaping path is refused");
        assert_eq!(
            unsafe_path[0].code,
            DiagnosticCode::RequestSourceNameInvalid
        );

        let mut future = envelope(SourceSurveyArguments::new("sample.bin"));
        future.protocol_version = PROTOCOL_VERSION + 1;
        assert_eq!(
            normalize(&future, OperationLimits::default()).expect_err("refused")[0].code,
            DiagnosticCode::RequestProtocolVersionUnsupported
        );

        let mut writing = envelope(SourceSurveyArguments::new("sample.bin"));
        writing.execution = ExecutionOptions {
            mode: ExecutionMode::Prepare,
            events: crate::protocol::EventMode::FinalOnly,
        };
        assert_eq!(
            normalize(&writing, OperationLimits::default()).expect_err("refused")[0].code,
            DiagnosticCode::RequestExecutionModeUnsupported
        );

        // Both event modes are servable, and asking for events changes nothing
        // about what is asked for — so the two normalize to the same digest.
        let mut streaming = envelope(SourceSurveyArguments::new("sample.bin"));
        streaming.execution = ExecutionOptions {
            mode: ExecutionMode::Read,
            events: crate::protocol::EventMode::Stream,
        };
        assert_eq!(
            normalize(&streaming, OperationLimits::default())
                .expect("streaming events are servable")
                .request
                .digest(),
            normalize(
                &envelope(SourceSurveyArguments::new("sample.bin")),
                OperationLimits::default()
            )
            .expect("the default mode is servable")
            .request
            .digest()
        );

        let zero = normalize(
            &envelope(SourceSurveyArguments::new("sample.bin").with_minimum_string_length(0)),
            OperationLimits::default(),
        )
        .expect_err("a zero threshold is refused");
        assert_eq!(zero[0].code, DiagnosticCode::RequestArgumentOutOfRange);
    }
}
