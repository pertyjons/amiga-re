//! The operation catalog: metadata over the statically compiled request enum.
//!
//! Not a runtime plugin registry. Every operation is a variant the compiler
//! knows about, and [`descriptor`] is an exhaustive match, so a new variant
//! cannot be added without deciding its metadata.
//!
//! The descriptor carries what something already reads. `cancellable` and
//! `emits_progress` are still absent, now for a different reason: every
//! operation is both, so a flag would be a constant. They arrive when an
//! operation exists that is neither. A project requirement is recorded because
//! the project operations do accept one.

use crate::request::OperationName;

/// What an operation is permitted to change outside the process.
///
/// The match in [`normalize`](crate::normalize()) is exhaustive over this, so adding
/// `ProjectEdit` will fail to compile until the execution modes that class
/// accepts are decided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessClass {
    /// Reads and reports. Nothing outside the process may change.
    ReadOnly,
    /// Produces external files, but only through a plan the caller reviewed
    /// and authorized by digest. Accepts `prepare` and `commit_reviewed`, and
    /// refuses `read`: there is no useful answer to "run this extraction but
    /// tell me nothing about what it would write".
    PreparedOutput,
}

impl AccessClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::PreparedOutput => "prepared_output",
        }
    }
}

/// Everything the toolkit knows about one operation besides how to run it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    pub name: OperationName,
    /// One line, imperative, suitable for a command listing.
    pub summary: &'static str,
    pub access: AccessClass,
    /// The bundled JSON Schema for this operation's arguments.
    pub request_schema: &'static str,
    /// The bundled JSON Schema for this operation's result payload.
    pub response_schema: &'static str,
}

/// The metadata for `name`.
///
/// Exhaustive by construction: this is the compiler-enforced half of "every
/// request variant has metadata and a handler".
#[must_use]
pub const fn descriptor(name: OperationName) -> &'static OperationDescriptor {
    match name {
        OperationName::SourceSurvey => &SOURCE_SURVEY,
        OperationName::ContainerAdfList => &CONTAINER_ADF_LIST,
        OperationName::GraphicsBitmapDecode => &GRAPHICS_BITMAP_DECODE,
        OperationName::ContainerAdfExtract => &CONTAINER_ADF_EXTRACT,
        OperationName::ContainerLhaExtract => &CONTAINER_LHA_EXTRACT,
        OperationName::GraphicsBitmapExport => &GRAPHICS_BITMAP_EXPORT,
        OperationName::GraphicsBitmapCompare => &GRAPHICS_BITMAP_COMPARE,
        OperationName::GraphicsBitmapCompareExport => &GRAPHICS_BITMAP_COMPARE_EXPORT,
        OperationName::ProjectCheck => &PROJECT_CHECK,
        OperationName::ProjectVerify => &PROJECT_VERIFY,
        OperationName::AnalysisHunkDiff => &ANALYSIS_HUNK_DIFF,
        OperationName::AnalysisHunkDiffExport => &ANALYSIS_HUNK_DIFF_EXPORT,
        OperationName::SourceCarve => &SOURCE_CARVE,
        OperationName::AnalysisTableDecode => &ANALYSIS_TABLE_DECODE,
        OperationName::AnalysisTableSummarize => &ANALYSIS_TABLE_SUMMARIZE,
        OperationName::AudioSampleDecode => &AUDIO_SAMPLE_DECODE,
        OperationName::AudioSampleExport => &AUDIO_SAMPLE_EXPORT,
        OperationName::CompressPowerpackerDecode => &COMPRESS_POWERPACKER_DECODE,
        OperationName::CompressPowerpackerExport => &COMPRESS_POWERPACKER_EXPORT,
        OperationName::CompressRleXorDecode => &COMPRESS_RLE_XOR_DECODE,
        OperationName::CompressRleXorExport => &COMPRESS_RLE_XOR_EXPORT,
        OperationName::AudioPcmDecode => &AUDIO_PCM_DECODE,
        OperationName::AudioPcmExport => &AUDIO_PCM_EXPORT,
        OperationName::AudioModuleDecode => &AUDIO_MODULE_DECODE,
        OperationName::AudioModuleExport => &AUDIO_MODULE_EXPORT,
        OperationName::AnalysisHunkNormalize => &ANALYSIS_HUNK_NORMALIZE,
        OperationName::AnalysisHunkNormalizeExport => &ANALYSIS_HUNK_NORMALIZE_EXPORT,
        OperationName::ProvenanceManifest => &PROVENANCE_MANIFEST,
        OperationName::ProvenanceManifestExport => &PROVENANCE_MANIFEST_EXPORT,
        OperationName::GraphicsPaletteDecode => &GRAPHICS_PALETTE_DECODE,
        OperationName::GraphicsPaletteExport => &GRAPHICS_PALETTE_EXPORT,
        OperationName::EnvSandboxRun => &ENV_SANDBOX_RUN,
        OperationName::EnvBootInfo => &ENV_BOOT_INFO,
        OperationName::EnvSandboxCall => &ENV_SANDBOX_CALL,
        OperationName::EnvSandboxCallExport => &ENV_SANDBOX_CALL_EXPORT,
        OperationName::EnvSandboxMatrix => &ENV_SANDBOX_MATRIX,
        OperationName::EnvSandboxTimeline => &ENV_SANDBOX_TIMELINE,
        OperationName::EnvSandboxTimelineExport => &ENV_SANDBOX_TIMELINE_EXPORT,
        OperationName::EnvSandboxSlice => &ENV_SANDBOX_SLICE,
        OperationName::EnvFrameCapture => &ENV_FRAME_CAPTURE,
        OperationName::EnvFrameCaptureExport => &ENV_FRAME_CAPTURE_EXPORT,
        OperationName::EnvSandboxCompare => &ENV_SANDBOX_COMPARE,
        OperationName::EnvSandboxMatrixExport => &ENV_SANDBOX_MATRIX_EXPORT,
        OperationName::EnvBootTrace => &ENV_BOOT_TRACE,
        OperationName::EnvBootTraceExport => &ENV_BOOT_TRACE_EXPORT,
        OperationName::AnalysisHunkList => &ANALYSIS_HUNK_LIST,
        OperationName::AnalysisStringsScan => &ANALYSIS_STRINGS_SCAN,
        OperationName::AnalysisAddressResolve => &ANALYSIS_ADDRESS_RESOLVE,
        OperationName::AnalysisPointersScan => &ANALYSIS_POINTERS_SCAN,
        OperationName::AnalysisCodeDisassemble => &ANALYSIS_CODE_DISASSEMBLE,
        OperationName::AnalysisAddressReferences => &ANALYSIS_ADDRESS_REFERENCES,
        OperationName::AnalysisCodeCallgraph => &ANALYSIS_CODE_CALLGRAPH,
        OperationName::AnalysisCodeGlobals => &ANALYSIS_CODE_GLOBALS,
        OperationName::AnalysisCodeFixedPoint => &ANALYSIS_CODE_FIXED_POINT,
        OperationName::AnalysisStateSnapshot => &ANALYSIS_STATE_SNAPSHOT,
        OperationName::AnalysisStateCompare => &ANALYSIS_STATE_COMPARE,
        OperationName::ContainerLhaList => &CONTAINER_LHA_LIST,
        OperationName::HardwareRegisterList => &HARDWARE_REGISTER_LIST,
        OperationName::AudioPcmScan => &AUDIO_PCM_SCAN,
        OperationName::AudioModuleScan => &AUDIO_MODULE_SCAN,
        OperationName::GraphicsPaletteScan => &GRAPHICS_PALETTE_SCAN,
        OperationName::HardwareCopperScan => &HARDWARE_COPPER_SCAN,
        OperationName::HardwareCopperDecode => &HARDWARE_COPPER_DECODE,
        OperationName::GraphicsIlbmDecode => &GRAPHICS_ILBM_DECODE,
        OperationName::GraphicsBitmapDetect => &GRAPHICS_BITMAP_DETECT,
        OperationName::HardwareRegisterReferences => &HARDWARE_REGISTER_REFERENCES,
        OperationName::HardwareCopperReferences => &HARDWARE_COPPER_REFERENCES,
        OperationName::ProjectDescribe => &PROJECT_DESCRIBE,
        OperationName::ProjectAnnotations => &PROJECT_ANNOTATIONS,
        OperationName::ProjectInventory => &PROJECT_INVENTORY,
        OperationName::ProjectEdit => &PROJECT_EDIT,
        OperationName::ProjectInit => &PROJECT_INIT,
        OperationName::ProjectExtract => &PROJECT_EXTRACT,
        OperationName::ProjectResourceExport => &PROJECT_RESOURCE_EXPORT,
        OperationName::ProjectFormat => &PROJECT_FORMAT,
        OperationName::ProjectMigrate => &PROJECT_MIGRATE,
        OperationName::AnalysisCodeFacts => &ANALYSIS_CODE_FACTS,
        OperationName::SourceRead => &SOURCE_READ,
    }
}

static SOURCE_READ: OperationDescriptor = OperationDescriptor {
    name: OperationName::SourceRead,
    summary: "Read a window of a source's bytes, with the relocations inside it.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/source.read.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/source.read.response.schema.json"),
};

static ANALYSIS_CODE_FACTS: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisCodeFacts,
    summary: "Compose every code analysis into one fact list, with the instructions it is about.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.code.facts.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.code.facts.response.schema.json"
    ),
};

static PROJECT_MIGRATE: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectMigrate,
    summary: "Convert a legacy config into project documents through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/project.migrate.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.migrate.response.schema.json"),
};

static PROJECT_FORMAT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectFormat,
    summary: "Bring every document a project names into canonical form.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/project.format.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.format.response.schema.json"),
};

static PROJECT_EXTRACT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectExtract,
    summary: "Extract a project's registered carriers into it, through a plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/project.extract.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.extract.response.schema.json"),
};

static PROJECT_RESOURCE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectResourceExport,
    summary: "Produce a resource's file from the project alone, and record that it exists.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/project.resource.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/project.resource.export.response.schema.json"
    ),
};

static PROJECT_INIT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectInit,
    summary: "Create a project document set from chosen source files, through a plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/project.init.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.init.response.schema.json"),
};

static PROJECT_EDIT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectEdit,
    summary: "Apply reviewed changes to a project's annotations through a plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/project.edit.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.edit.response.schema.json"),
};

static PROJECT_INVENTORY: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectInventory,
    summary: "Walk a directory and report the inventory a directory source would pin.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/project.inventory.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/project.inventory.response.schema.json"
    ),
};

static PROJECT_ANNOTATIONS: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectAnnotations,
    summary: "Report a project's reviewed knowledge about one image or one object.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/project.annotations.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/project.annotations.response.schema.json"
    ),
};

static PROJECT_DESCRIBE: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectDescribe,
    summary: "Summarize a project: its sources, objects, programs, and counts.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/project.describe.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.describe.response.schema.json"),
};

static HARDWARE_COPPER_REFERENCES: OperationDescriptor = OperationDescriptor {
    name: OperationName::HardwareCopperReferences,
    summary: "Trace the CPU writes that patch a runtime copy of a Copper list.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/hardware.copper.references.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/hardware.copper.references.response.schema.json"
    ),
};

static HARDWARE_REGISTER_REFERENCES: OperationDescriptor = OperationDescriptor {
    name: OperationName::HardwareRegisterReferences,
    summary: "Report every custom-chip register a hunk's code touches, and how.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/hardware.register.references.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/hardware.register.references.response.schema.json"
    ),
};

static GRAPHICS_ILBM_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsIlbmDecode,
    summary: "Describe an ILBM form: geometry, masking, viewport mode, and palette.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.ilbm.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.ilbm.decode.response.schema.json"
    ),
};

static GRAPHICS_BITMAP_DETECT: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsBitmapDetect,
    summary: "Score a region's entropy and row strides to suggest a bitmap's geometry.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.detect.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.detect.response.schema.json"
    ),
};

static GRAPHICS_PALETTE_SCAN: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsPaletteScan,
    summary: "Find runs of $0RGB colour words that score as palette tables.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.palette.scan.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.palette.scan.response.schema.json"
    ),
};

static HARDWARE_COPPER_SCAN: OperationDescriptor = OperationDescriptor {
    name: OperationName::HardwareCopperScan,
    summary: "Find plausible Copper lists and the palettes and pointers each carries.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/hardware.copper.scan.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/hardware.copper.scan.response.schema.json"
    ),
};

static HARDWARE_COPPER_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::HardwareCopperDecode,
    summary: "Decode a Copper stream instruction by instruction from an offset.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/hardware.copper.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/hardware.copper.decode.response.schema.json"
    ),
};

static AUDIO_PCM_SCAN: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioPcmScan,
    summary: "Find runs of bytes that score like raw 8-bit signed PCM.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/audio.pcm.scan.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/audio.pcm.scan.response.schema.json"),
};

static AUDIO_MODULE_SCAN: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioModuleScan,
    summary: "Find tracker modules by signature and report what each declares.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/audio.module.scan.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/audio.module.scan.response.schema.json"
    ),
};

static CONTAINER_LHA_LIST: OperationDescriptor = OperationDescriptor {
    name: OperationName::ContainerLhaList,
    summary: "List an LHA archive's members and the method each is stored with.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/container.lha.list.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/container.lha.list.response.schema.json"
    ),
};

static HARDWARE_REGISTER_LIST: OperationDescriptor = OperationDescriptor {
    name: OperationName::HardwareRegisterList,
    summary: "Report the custom-chip register map this build knows.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/hardware.register.list.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/hardware.register.list.response.schema.json"
    ),
};

static ANALYSIS_CODE_GLOBALS: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisCodeGlobals,
    summary: "Map the base-relative, absolute, and derived accesses a hunk's code makes.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.code.globals.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.code.globals.response.schema.json"
    ),
};

static ANALYSIS_CODE_FIXED_POINT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisCodeFixedPoint,
    summary: "Report fixed-point multiply and divide idioms, saturating clamps, and Q scales.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.code.fixed-point.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.code.fixed-point.response.schema.json"
    ),
};

static ANALYSIS_CODE_CALLGRAPH: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisCodeCallgraph,
    summary: "Reduce a CODE hunk's control flow to its functions and the calls between them.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.code.callgraph.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.code.callgraph.response.schema.json"
    ),
};

static ANALYSIS_ADDRESS_REFERENCES: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisAddressReferences,
    summary: "Report the addresses a hunk's code names, or the sites that name one address.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.address.references.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.address.references.response.schema.json"
    ),
};

static ANALYSIS_CODE_DISASSEMBLE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisCodeDisassemble,
    summary: "Decode a CODE hunk or pinned raw image, by sweep or control flow.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.code.disassemble.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.code.disassemble.response.schema.json"
    ),
};

static ANALYSIS_ADDRESS_RESOLVE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisAddressResolve,
    summary: "Report one number in its absolute, hunk-relative, and whole-file frames.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.address.resolve.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.address.resolve.response.schema.json"
    ),
};

static ANALYSIS_POINTERS_SCAN: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisPointersScan,
    summary: "Find runs of plausible in-hunk pointers and report what they address.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.pointers.scan.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.pointers.scan.response.schema.json"
    ),
};

static ANALYSIS_STRINGS_SCAN: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisStringsScan,
    summary: "Find printable runs in a source and report where they sit.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.strings.scan.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.strings.scan.response.schema.json"
    ),
};

static ANALYSIS_HUNK_LIST: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisHunkList,
    summary: "List a LoadSeg image's hunks and the relocations between them.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/analysis.hunk.list.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.list.response.schema.json"
    ),
};

static ENV_BOOT_TRACE: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvBootTrace,
    summary: "Boot a floppy in a seeded Amiga and report the calls, writes, and reads it made.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.boot.trace.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/env.boot.trace.response.schema.json"),
};

static ENV_BOOT_TRACE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvBootTraceExport,
    summary: "Write a boot run's served track reads through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/env.boot.trace.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.boot.trace.export.response.schema.json"
    ),
};

static ENV_SANDBOX_CALL: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxCall,
    summary: "Invoke one routine to RTS and report a diffable input/output record.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.sandbox.call.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/env.sandbox.call.response.schema.json"),
};

static ENV_SANDBOX_CALL_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxCallExport,
    summary: "Write a routine's golden record through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.call.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.call.export.response.schema.json"
    ),
};

static ENV_SANDBOX_MATRIX: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxMatrix,
    summary: "Run a named set of sandbox calls that share one recipe and vary its inputs.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.sandbox.matrix.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.matrix.response.schema.json"
    ),
};

static ANALYSIS_STATE_SNAPSHOT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisStateSnapshot,
    summary: "Decode a machine's memory through a project's reviewed types and globals.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.state.snapshot.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.state.snapshot.response.schema.json"
    ),
};

static ANALYSIS_STATE_COMPARE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisStateCompare,
    summary: "Compare state snapshots field by field.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.state.compare.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.state.compare.response.schema.json"
    ),
};

static GRAPHICS_BITMAP_COMPARE: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsBitmapCompare,
    summary: "Compare two decoded images in palette-index space and in colour space.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.compare.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.compare.response.schema.json"
    ),
};

static GRAPHICS_BITMAP_COMPARE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsBitmapCompareExport,
    summary: "Write a comparison's heatmap and overlay through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.compare.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.compare.export.response.schema.json"
    ),
};

static ENV_FRAME_CAPTURE: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvFrameCapture,
    summary: "Reconstruct the frame the display hardware would have shown after a run.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.frame.capture.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/env.frame.capture.response.schema.json"
    ),
};

static ENV_FRAME_CAPTURE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvFrameCaptureExport,
    summary: "Write a captured frame as indexed and RGBA PNGs through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/env.frame.capture.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.frame.capture.export.response.schema.json"
    ),
};

static ENV_SANDBOX_SLICE: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxSlice,
    summary: "Follow one value backwards through the instructions that produced it.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.sandbox.slice.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.slice.response.schema.json"
    ),
};

static ENV_SANDBOX_TIMELINE: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxTimeline,
    summary: "Run a sequence of sandbox steps over one evolving machine state.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.timeline.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.timeline.response.schema.json"
    ),
};

static ENV_SANDBOX_TIMELINE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxTimelineExport,
    summary: "Write each step of a sandbox timeline's checkpointed ranges through a reviewed \
              write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.timeline.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.timeline.export.response.schema.json"
    ),
};

static ENV_SANDBOX_COMPARE: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxCompare,
    summary: "Compare golden call records by what they were given and what they did.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.compare.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.compare.response.schema.json"
    ),
};

static ENV_SANDBOX_MATRIX_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxMatrixExport,
    summary: "Write each case of a sandbox sweep's exported ranges through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.matrix.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/env.sandbox.matrix.export.response.schema.json"
    ),
};

static ENV_BOOT_INFO: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvBootInfo,
    summary: "Report what a floppy's boot block declares about itself.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.boot.info.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/env.boot.info.response.schema.json"),
};

static ENV_SANDBOX_RUN: OperationDescriptor = OperationDescriptor {
    name: OperationName::EnvSandboxRun,
    summary: "Execute one CODE hunk under stated bounds and report how it stopped.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/env.sandbox.run.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/env.sandbox.run.response.schema.json"),
};

static GRAPHICS_PALETTE_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsPaletteDecode,
    summary: "Read a run of Amiga $0RGB colour words and report both encodings of each.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.palette.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.palette.decode.response.schema.json"
    ),
};

static GRAPHICS_PALETTE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsPaletteExport,
    summary: "Draw a palette as a swatch PNG through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.palette.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.palette.export.response.schema.json"
    ),
};

static ANALYSIS_HUNK_NORMALIZE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisHunkNormalize,
    summary: "Report what rewriting a one-file loader's compact relocations would produce.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.normalize.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.normalize.response.schema.json"
    ),
};

static ANALYSIS_HUNK_NORMALIZE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisHunkNormalizeExport,
    summary: "Write a normalized HUNK image through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.normalize.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.normalize.export.response.schema.json"
    ),
};

static PROVENANCE_MANIFEST: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProvenanceManifest,
    summary: "Report the name, size, and SHA-256 a provenance manifest would record.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/provenance.manifest.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/provenance.manifest.response.schema.json"
    ),
};

static PROVENANCE_MANIFEST_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProvenanceManifestExport,
    summary: "Write a provenance manifest through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/provenance.manifest.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/provenance.manifest.export.response.schema.json"
    ),
};

static AUDIO_PCM_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioPcmDecode,
    summary: "Read a raw 8-bit signed PCM region and summarize it with a bounded envelope.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/audio.pcm.decode.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/audio.pcm.decode.response.schema.json"),
};

static AUDIO_PCM_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioPcmExport,
    summary: "Write a raw PCM region as a WAV file through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/audio.pcm.export.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/audio.pcm.export.response.schema.json"),
};

static AUDIO_MODULE_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioModuleDecode,
    summary: "Read a ProTracker/SoundTracker module and report its layout and sample slots.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/audio.module.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/audio.module.decode.response.schema.json"
    ),
};

static AUDIO_MODULE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioModuleExport,
    summary: "Write a tracker module out as its own file through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/audio.module.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/audio.module.export.response.schema.json"
    ),
};

static COMPRESS_POWERPACKER_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::CompressPowerpackerDecode,
    summary: "Decompress a headerless PowerPacker stream and report what it holds.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/compress.powerpacker.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/compress.powerpacker.decode.response.schema.json"
    ),
};

static COMPRESS_POWERPACKER_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::CompressPowerpackerExport,
    summary: "Write a decompressed PowerPacker stream through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/compress.powerpacker.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/compress.powerpacker.export.response.schema.json"
    ),
};

static COMPRESS_RLE_XOR_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::CompressRleXorDecode,
    summary: "Decompress a position-XOR marker-RLE stream and report what it holds.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/compress.rle-xor.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/compress.rle-xor.decode.response.schema.json"
    ),
};

static COMPRESS_RLE_XOR_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::CompressRleXorExport,
    summary: "Write a decompressed position-XOR marker-RLE stream through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/compress.rle-xor.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/compress.rle-xor.export.response.schema.json"
    ),
};

/// Every operation this build serves, in catalog order.
#[must_use]
pub fn catalog() -> Vec<&'static OperationDescriptor> {
    OperationName::ALL.iter().copied().map(descriptor).collect()
}

static SOURCE_SURVEY: OperationDescriptor = OperationDescriptor {
    name: OperationName::SourceSurvey,
    summary: "Classify a source into one ordered, non-overlapping map of typed regions.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/source.survey.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/source.survey.response.schema.json"),
};

static CONTAINER_ADF_LIST: OperationDescriptor = OperationDescriptor {
    name: OperationName::ContainerAdfList,
    summary: "List an AmigaDOS volume and the files and directories it contains.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/container.adf.list.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/container.adf.list.response.schema.json"
    ),
};

static GRAPHICS_BITMAP_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsBitmapDecode,
    summary: "Decode a planar region into one palette index per pixel.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.decode.response.schema.json"
    ),
};

static CONTAINER_ADF_EXTRACT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ContainerAdfExtract,
    summary: "Recover an AmigaDOS volume's files through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/container.adf.extract.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/container.adf.extract.response.schema.json"
    ),
};

static CONTAINER_LHA_EXTRACT: OperationDescriptor = OperationDescriptor {
    name: OperationName::ContainerLhaExtract,
    summary: "Recover an LHA archive's members through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/container.lha.extract.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/container.lha.extract.response.schema.json"
    ),
};

static GRAPHICS_BITMAP_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::GraphicsBitmapExport,
    summary: "Export a decoded planar region as an indexed PNG through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/graphics.bitmap.export.response.schema.json"
    ),
};

static PROJECT_CHECK: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectCheck,
    summary: "Load a versioned project and report every problem by stable code.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/project.check.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.check.response.schema.json"),
};

static PROJECT_VERIFY: OperationDescriptor = OperationDescriptor {
    name: OperationName::ProjectVerify,
    summary: "Verify a project's sources and objects against the bytes on disk.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/project.verify.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/project.verify.response.schema.json"),
};

static ANALYSIS_HUNK_DIFF: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisHunkDiff,
    summary: "Compare two HUNK executables hunk by hunk, byte range by byte range.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!("../schemas/v1/operations/analysis.hunk.diff.request.schema.json"),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.diff.response.schema.json"
    ),
};

static ANALYSIS_HUNK_DIFF_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisHunkDiffExport,
    summary: "Write a HUNK comparison as a report through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.diff.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.hunk.diff.export.response.schema.json"
    ),
};

static SOURCE_CARVE: OperationDescriptor = OperationDescriptor {
    name: OperationName::SourceCarve,
    summary: "Write one byte range of a source as its own file through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!("../schemas/v1/operations/source.carve.request.schema.json"),
    response_schema: include_str!("../schemas/v1/operations/source.carve.response.schema.json"),
};

static ANALYSIS_TABLE_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisTableDecode,
    summary: "Read a byte region as an array of fixed-layout big-endian records.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.table.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.table.decode.response.schema.json"
    ),
};

static ANALYSIS_TABLE_SUMMARIZE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AnalysisTableSummarize,
    summary: "Summarize a fixed-layout table's columns and compare them across several sources.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/analysis.table.summarize.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/analysis.table.summarize.response.schema.json"
    ),
};

static AUDIO_SAMPLE_DECODE: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioSampleDecode,
    summary: "Read an IFF 8SVX sample and summarize it with a bounded waveform envelope.",
    access: AccessClass::ReadOnly,
    request_schema: include_str!(
        "../schemas/v1/operations/audio.sample.decode.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/audio.sample.decode.response.schema.json"
    ),
};

static AUDIO_SAMPLE_EXPORT: OperationDescriptor = OperationDescriptor {
    name: OperationName::AudioSampleExport,
    summary: "Write an IFF 8SVX sample as a WAV file through a reviewed write plan.",
    access: AccessClass::PreparedOutput,
    request_schema: include_str!(
        "../schemas/v1/operations/audio.sample.export.request.schema.json"
    ),
    response_schema: include_str!(
        "../schemas/v1/operations/audio.sample.export.response.schema.json"
    ),
};

/// The bundled envelope schemas, selected by protocol version and never fetched
/// from anywhere a request could name.
pub mod schemas {
    /// Shapes the other documents reference: identities, digests, bounds.
    pub const COMMON: &str = include_str!("../schemas/v1/common.schema.json");
    /// The request envelope, including every operation as a tagged variant.
    pub const REQUEST: &str = include_str!("../schemas/v1/request.schema.json");
    /// The response envelope.
    pub const RESPONSE: &str = include_str!("../schemas/v1/response.schema.json");
    /// One diagnostic, referenced by the response envelope.
    pub const DIAGNOSTIC: &str = include_str!("../schemas/v1/diagnostic.schema.json");
    /// One event, as a JSON Lines stream carries it.
    pub const EVENT: &str = include_str!("../schemas/v1/event.schema.json");

    /// Immutable project sandbox recipe, reusing the operation request schema.
    pub const SANDBOX_RECIPE: &str = include_str!("../schemas/v1/sandbox-recipe.schema.json");

    /// Every shared schema with the file name its `$ref`s resolve against.
    ///
    /// An emitter that writes these out must preserve the layout, or the
    /// emitted set stops resolving offline — which is the only reason to emit
    /// it at all. Per-operation schemas are not here: they come from the
    /// catalog, so a new operation cannot be forgotten by this list.
    pub const ALL: &[(&str, &str)] = &[
        ("common.schema.json", COMMON),
        ("request.schema.json", REQUEST),
        ("response.schema.json", RESPONSE),
        ("diagnostic.schema.json", DIAGNOSTIC),
        ("event.schema.json", EVENT),
        ("sandbox-recipe.schema.json", SANDBOX_RECIPE),
    ];
}
