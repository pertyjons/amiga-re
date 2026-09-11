//! The typed operation request, as it appears on the wire.
//!
//! Routing matches this enum exhaustively; it never inspects arbitrary JSON.
//! Every argument that may be omitted is an `Option` here and is materialized
//! into an explicit value by [`normalize`](crate::normalize()) before any handler sees it.
//!
//! The exhaustive roots stay in this module — [`OperationName`],
//! [`OperationRequestDocument`] and the [`SourceLocator`] every domain names its
//! source with — so adding an operation still fails compilation until every
//! decision is made. The arguments themselves are grouped by the operation-name
//! prefix they belong to, and re-exported here: `amiga_operations::…` paths are
//! unchanged by the grouping.

use std::fmt;

use serde::{Deserialize, Serialize};

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

/// The stable dotted name of one operation.
///
/// Lowercase ASCII, not a display label. Version 1 defines no aliases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationName {
    SourceSurvey,
    ContainerAdfList,
    GraphicsBitmapDecode,
    ContainerAdfExtract,
    ContainerLhaExtract,
    GraphicsBitmapExport,
    GraphicsBitmapCompare,
    GraphicsBitmapCompareExport,
    ProjectCheck,
    ProjectVerify,
    AnalysisHunkDiff,
    AnalysisHunkDiffExport,
    SourceCarve,
    AnalysisTableDecode,
    AnalysisTableSummarize,
    AudioSampleDecode,
    AudioSampleExport,
    CompressPowerpackerDecode,
    CompressPowerpackerExport,
    CompressRleXorDecode,
    CompressRleXorExport,
    AudioPcmDecode,
    AudioPcmExport,
    AudioModuleDecode,
    AudioModuleExport,
    AnalysisHunkNormalize,
    AnalysisHunkNormalizeExport,
    ProvenanceManifest,
    ProvenanceManifestExport,
    GraphicsPaletteDecode,
    GraphicsPaletteExport,
    EnvSandboxRun,
    EnvBootInfo,
    EnvSandboxCall,
    EnvSandboxCallExport,
    EnvSandboxMatrix,
    EnvSandboxTimeline,
    EnvSandboxTimelineExport,
    EnvSandboxSlice,
    EnvFrameCapture,
    EnvFrameCaptureExport,
    EnvSandboxCompare,
    EnvSandboxMatrixExport,
    EnvBootTrace,
    EnvBootTraceExport,
    AnalysisHunkList,
    AnalysisStringsScan,
    AnalysisAddressResolve,
    AnalysisPointersScan,
    AnalysisCodeDisassemble,
    AnalysisAddressReferences,
    AnalysisCodeCallgraph,
    AnalysisCodeGlobals,
    AnalysisCodeFixedPoint,
    AnalysisStateSnapshot,
    AnalysisStateCompare,
    ContainerLhaList,
    HardwareRegisterList,
    AudioPcmScan,
    AudioModuleScan,
    GraphicsPaletteScan,
    HardwareCopperScan,
    HardwareCopperDecode,
    GraphicsIlbmDecode,
    GraphicsBitmapDetect,
    HardwareRegisterReferences,
    HardwareCopperReferences,
    ProjectDescribe,
    ProjectAnnotations,
    ProjectInventory,
    ProjectEdit,
    ProjectFormat,
    ProjectMigrate,
    AnalysisCodeFacts,
    SourceRead,
    ProjectInit,
    ProjectExtract,
    ProjectResourceExport,
}

impl Serialize for OperationName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl OperationName {
    /// Every operation this build serves, in catalog order.
    ///
    /// Kept complete by `descriptor_covers_every_operation` in the catalog
    /// tests, which cannot compile without an arm per variant.
    pub const ALL: &'static [Self] = &[
        Self::SourceSurvey,
        Self::ContainerAdfList,
        Self::GraphicsBitmapDecode,
        Self::ContainerAdfExtract,
        Self::ContainerLhaExtract,
        Self::GraphicsBitmapExport,
        Self::ProjectCheck,
        Self::ProjectVerify,
        Self::AnalysisHunkDiff,
        Self::AnalysisHunkDiffExport,
        Self::SourceCarve,
        Self::AnalysisTableDecode,
        Self::AnalysisTableSummarize,
        Self::AudioSampleDecode,
        Self::AudioSampleExport,
        Self::CompressPowerpackerDecode,
        Self::CompressPowerpackerExport,
        Self::CompressRleXorDecode,
        Self::CompressRleXorExport,
        Self::AudioPcmDecode,
        Self::AudioPcmExport,
        Self::AudioModuleDecode,
        Self::AudioModuleExport,
        Self::AnalysisHunkNormalize,
        Self::AnalysisHunkNormalizeExport,
        Self::ProvenanceManifest,
        Self::ProvenanceManifestExport,
        Self::GraphicsPaletteDecode,
        Self::GraphicsPaletteExport,
        Self::EnvSandboxRun,
        Self::EnvBootInfo,
        Self::EnvSandboxCall,
        Self::EnvSandboxCallExport,
        Self::EnvBootTrace,
        Self::EnvBootTraceExport,
        Self::AnalysisHunkList,
        Self::AnalysisStringsScan,
        Self::AnalysisAddressResolve,
        Self::AnalysisPointersScan,
        Self::AnalysisCodeDisassemble,
        Self::AnalysisAddressReferences,
        Self::AnalysisCodeCallgraph,
        Self::AnalysisCodeGlobals,
        Self::AnalysisCodeFixedPoint,
        Self::ContainerLhaList,
        Self::HardwareRegisterList,
        Self::AudioPcmScan,
        Self::AudioModuleScan,
        Self::GraphicsPaletteScan,
        Self::HardwareCopperScan,
        Self::HardwareCopperDecode,
        Self::GraphicsIlbmDecode,
        Self::GraphicsBitmapDetect,
        Self::HardwareRegisterReferences,
        Self::HardwareCopperReferences,
        Self::ProjectDescribe,
        Self::ProjectAnnotations,
        Self::ProjectInventory,
        Self::ProjectEdit,
        Self::ProjectFormat,
        Self::ProjectMigrate,
        Self::AnalysisCodeFacts,
        Self::SourceRead,
        Self::ProjectInit,
        Self::ProjectExtract,
        Self::ProjectResourceExport,
        Self::EnvSandboxMatrix,
        Self::EnvSandboxCompare,
        Self::EnvSandboxMatrixExport,
        Self::EnvSandboxTimeline,
        Self::AnalysisStateSnapshot,
        Self::AnalysisStateCompare,
        Self::EnvFrameCapture,
        Self::EnvFrameCaptureExport,
        Self::GraphicsBitmapCompare,
        Self::GraphicsBitmapCompareExport,
        Self::EnvSandboxSlice,
        Self::EnvSandboxTimelineExport,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceSurvey => "source.survey",
            Self::ContainerAdfList => "container.adf.list",
            Self::GraphicsBitmapDecode => "graphics.bitmap.decode",
            Self::ContainerAdfExtract => "container.adf.extract",
            Self::ContainerLhaExtract => "container.lha.extract",
            Self::GraphicsBitmapExport => "graphics.bitmap.export",
            Self::GraphicsBitmapCompare => "graphics.bitmap.compare",
            Self::GraphicsBitmapCompareExport => "graphics.bitmap.compare.export",
            Self::ProjectCheck => "project.check",
            Self::ProjectVerify => "project.verify",
            Self::AnalysisHunkDiff => "analysis.hunk.diff",
            Self::AnalysisHunkDiffExport => "analysis.hunk.diff.export",
            Self::SourceCarve => "source.carve",
            Self::AnalysisTableDecode => "analysis.table.decode",
            Self::AnalysisTableSummarize => "analysis.table.summarize",
            Self::AudioSampleDecode => "audio.sample.decode",
            Self::AudioSampleExport => "audio.sample.export",
            Self::CompressPowerpackerDecode => "compress.powerpacker.decode",
            Self::CompressPowerpackerExport => "compress.powerpacker.export",
            Self::CompressRleXorDecode => "compress.rle-xor.decode",
            Self::CompressRleXorExport => "compress.rle-xor.export",
            Self::AudioPcmDecode => "audio.pcm.decode",
            Self::AudioPcmExport => "audio.pcm.export",
            Self::AudioModuleDecode => "audio.module.decode",
            Self::AudioModuleExport => "audio.module.export",
            Self::AnalysisHunkNormalize => "analysis.hunk.normalize",
            Self::AnalysisHunkNormalizeExport => "analysis.hunk.normalize.export",
            Self::ProvenanceManifest => "provenance.manifest",
            Self::ProvenanceManifestExport => "provenance.manifest.export",
            Self::GraphicsPaletteDecode => "graphics.palette.decode",
            Self::GraphicsPaletteExport => "graphics.palette.export",
            Self::EnvSandboxRun => "env.sandbox.run",
            Self::EnvBootInfo => "env.boot.info",
            Self::EnvSandboxCall => "env.sandbox.call",
            Self::EnvSandboxCallExport => "env.sandbox.call.export",
            Self::EnvSandboxMatrix => "env.sandbox.matrix",
            Self::EnvSandboxTimeline => "env.sandbox.timeline",
            Self::EnvSandboxTimelineExport => "env.sandbox.timeline.export",
            Self::EnvSandboxSlice => "env.sandbox.slice",
            Self::EnvFrameCapture => "env.frame.capture",
            Self::EnvFrameCaptureExport => "env.frame.capture.export",
            Self::EnvSandboxCompare => "env.sandbox.compare",
            Self::EnvSandboxMatrixExport => "env.sandbox.matrix.export",
            Self::EnvBootTrace => "env.boot.trace",
            Self::EnvBootTraceExport => "env.boot.trace.export",
            Self::AnalysisHunkList => "analysis.hunk.list",
            Self::AnalysisStringsScan => "analysis.strings.scan",
            Self::AnalysisAddressResolve => "analysis.address.resolve",
            Self::AnalysisPointersScan => "analysis.pointers.scan",
            Self::AnalysisCodeDisassemble => "analysis.code.disassemble",
            Self::AnalysisAddressReferences => "analysis.address.references",
            Self::AnalysisCodeCallgraph => "analysis.code.callgraph",
            Self::AnalysisCodeGlobals => "analysis.code.globals",
            Self::AnalysisCodeFixedPoint => "analysis.code.fixed-point",
            Self::AnalysisStateSnapshot => "analysis.state.snapshot",
            Self::AnalysisStateCompare => "analysis.state.compare",
            Self::ContainerLhaList => "container.lha.list",
            Self::HardwareRegisterList => "hardware.register.list",
            Self::AudioPcmScan => "audio.pcm.scan",
            Self::AudioModuleScan => "audio.module.scan",
            Self::GraphicsPaletteScan => "graphics.palette.scan",
            Self::HardwareCopperScan => "hardware.copper.scan",
            Self::HardwareCopperDecode => "hardware.copper.decode",
            Self::GraphicsIlbmDecode => "graphics.ilbm.decode",
            Self::GraphicsBitmapDetect => "graphics.bitmap.detect",
            Self::HardwareRegisterReferences => "hardware.register.references",
            Self::HardwareCopperReferences => "hardware.copper.references",
            Self::ProjectDescribe => "project.describe",
            Self::ProjectAnnotations => "project.annotations",
            Self::ProjectInventory => "project.inventory",
            Self::ProjectEdit => "project.edit",
            Self::ProjectFormat => "project.format",
            Self::ProjectMigrate => "project.migrate",
            Self::AnalysisCodeFacts => "analysis.code.facts",
            Self::SourceRead => "source.read",
            Self::ProjectInit => "project.init",
            Self::ProjectExtract => "project.extract",
            Self::ProjectResourceExport => "project.resource.export",
        }
    }
}

impl fmt::Display for OperationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One operation and its arguments.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", content = "arguments", deny_unknown_fields)]
pub enum OperationRequestDocument {
    #[serde(rename = "source.survey")]
    SourceSurvey(SourceSurveyArguments),
    #[serde(rename = "container.adf.list")]
    ContainerAdfList(AdfListArguments),
    #[serde(rename = "graphics.bitmap.decode")]
    GraphicsBitmapDecode(BitmapDecodeArguments),
    #[serde(rename = "container.adf.extract")]
    ContainerAdfExtract(ContainerExtractArguments),
    #[serde(rename = "container.lha.extract")]
    ContainerLhaExtract(ContainerExtractArguments),
    #[serde(rename = "graphics.bitmap.export")]
    GraphicsBitmapExport(BitmapExportArguments),
    #[serde(rename = "graphics.bitmap.compare")]
    GraphicsBitmapCompare(BitmapCompareArguments),
    #[serde(rename = "graphics.bitmap.compare.export")]
    GraphicsBitmapCompareExport(BitmapCompareExportArguments),
    #[serde(rename = "project.check")]
    ProjectCheck(ProjectArguments),
    #[serde(rename = "project.verify")]
    ProjectVerify(ProjectArguments),
    #[serde(rename = "analysis.hunk.diff")]
    AnalysisHunkDiff(HunkDiffArguments),
    #[serde(rename = "analysis.hunk.diff.export")]
    AnalysisHunkDiffExport(HunkDiffExportArguments),
    #[serde(rename = "source.carve")]
    SourceCarve(CarveArguments),
    #[serde(rename = "analysis.table.decode")]
    AnalysisTableDecode(TableDecodeArguments),
    #[serde(rename = "analysis.table.summarize")]
    AnalysisTableSummarize(TableSummarizeArguments),
    #[serde(rename = "audio.sample.decode")]
    AudioSampleDecode(AudioSampleArguments),
    #[serde(rename = "audio.sample.export")]
    AudioSampleExport(AudioSampleExportArguments),
    #[serde(rename = "compress.powerpacker.decode")]
    CompressPowerpackerDecode(PowerpackerArguments),
    #[serde(rename = "compress.powerpacker.export")]
    CompressPowerpackerExport(PowerpackerExportArguments),
    #[serde(rename = "compress.rle-xor.decode")]
    CompressRleXorDecode(RleXorArguments),
    #[serde(rename = "compress.rle-xor.export")]
    CompressRleXorExport(RleXorExportArguments),
    #[serde(rename = "audio.pcm.decode")]
    AudioPcmDecode(PcmArguments),
    #[serde(rename = "audio.pcm.export")]
    AudioPcmExport(PcmExportArguments),
    #[serde(rename = "audio.module.decode")]
    AudioModuleDecode(ModuleArguments),
    #[serde(rename = "audio.module.export")]
    AudioModuleExport(ModuleExportArguments),
    #[serde(rename = "analysis.hunk.normalize")]
    AnalysisHunkNormalize(HunkNormalizeArguments),
    #[serde(rename = "analysis.hunk.normalize.export")]
    AnalysisHunkNormalizeExport(HunkNormalizeExportArguments),
    #[serde(rename = "provenance.manifest")]
    ProvenanceManifest(ManifestArguments),
    #[serde(rename = "provenance.manifest.export")]
    ProvenanceManifestExport(ManifestExportArguments),
    #[serde(rename = "graphics.palette.decode")]
    GraphicsPaletteDecode(PaletteArguments),
    #[serde(rename = "graphics.palette.export")]
    GraphicsPaletteExport(PaletteExportArguments),
    #[serde(rename = "env.sandbox.run")]
    EnvSandboxRun(SandboxRunArguments),
    #[serde(rename = "env.boot.info")]
    EnvBootInfo(BootInfoArguments),
    #[serde(rename = "env.sandbox.call")]
    EnvSandboxCall(SandboxCallArguments),
    #[serde(rename = "env.sandbox.call.export")]
    EnvSandboxCallExport(SandboxCallExportArguments),
    #[serde(rename = "env.sandbox.matrix")]
    EnvSandboxMatrix(SandboxMatrixArguments),
    #[serde(rename = "env.sandbox.timeline")]
    EnvSandboxTimeline(SandboxTimelineArguments),
    #[serde(rename = "env.sandbox.timeline.export")]
    EnvSandboxTimelineExport(SandboxTimelineExportArguments),
    #[serde(rename = "env.sandbox.slice")]
    EnvSandboxSlice(SandboxSliceArguments),
    #[serde(rename = "env.frame.capture")]
    EnvFrameCapture(FrameCaptureArguments),
    #[serde(rename = "env.frame.capture.export")]
    EnvFrameCaptureExport(FrameCaptureExportArguments),
    #[serde(rename = "env.sandbox.compare")]
    EnvSandboxCompare(SandboxCompareArguments),
    #[serde(rename = "env.sandbox.matrix.export")]
    EnvSandboxMatrixExport(SandboxMatrixExportArguments),
    #[serde(rename = "env.boot.trace")]
    EnvBootTrace(BootTraceArguments),
    #[serde(rename = "env.boot.trace.export")]
    EnvBootTraceExport(BootTraceExportArguments),
    #[serde(rename = "analysis.hunk.list")]
    AnalysisHunkList(HunkListArguments),
    #[serde(rename = "analysis.strings.scan")]
    AnalysisStringsScan(StringsScanArguments),
    #[serde(rename = "analysis.address.resolve")]
    AnalysisAddressResolve(AddressResolveArguments),
    #[serde(rename = "analysis.pointers.scan")]
    AnalysisPointersScan(PointerScanArguments),
    #[serde(rename = "analysis.code.disassemble")]
    AnalysisCodeDisassemble(CodeDisassembleArguments),
    #[serde(rename = "analysis.address.references")]
    AnalysisAddressReferences(AddressReferencesArguments),
    #[serde(rename = "analysis.code.callgraph")]
    AnalysisCodeCallgraph(CodeCallgraphArguments),
    #[serde(rename = "analysis.code.globals")]
    AnalysisCodeGlobals(CodeGlobalsArguments),
    #[serde(rename = "analysis.code.fixed-point")]
    AnalysisCodeFixedPoint(CodeFixedPointArguments),
    #[serde(rename = "analysis.state.snapshot")]
    AnalysisStateSnapshot(StateSnapshotArguments),
    #[serde(rename = "analysis.state.compare")]
    AnalysisStateCompare(StateCompareArguments),
    #[serde(rename = "container.lha.list")]
    ContainerLhaList(LhaListArguments),
    #[serde(rename = "hardware.register.list")]
    HardwareRegisterList(HardwareRegisterListArguments),
    #[serde(rename = "audio.pcm.scan")]
    AudioPcmScan(PcmScanArguments),
    #[serde(rename = "audio.module.scan")]
    AudioModuleScan(ModuleScanArguments),
    #[serde(rename = "graphics.palette.scan")]
    GraphicsPaletteScan(PaletteScanArguments),
    #[serde(rename = "hardware.copper.scan")]
    HardwareCopperScan(CopperScanArguments),
    #[serde(rename = "hardware.copper.decode")]
    HardwareCopperDecode(CopperDecodeArguments),
    #[serde(rename = "graphics.ilbm.decode")]
    GraphicsIlbmDecode(IlbmDecodeArguments),
    #[serde(rename = "graphics.bitmap.detect")]
    GraphicsBitmapDetect(BitmapDetectArguments),
    #[serde(rename = "hardware.register.references")]
    HardwareRegisterReferences(RegisterReferencesArguments),
    #[serde(rename = "hardware.copper.references")]
    HardwareCopperReferences(CopperReferencesArguments),
    #[serde(rename = "project.describe")]
    ProjectDescribe(ProjectArguments),
    #[serde(rename = "project.annotations")]
    ProjectAnnotations(ProjectAnnotationsArguments),
    #[serde(rename = "project.inventory")]
    ProjectInventory(ProjectInventoryArguments),
    #[serde(rename = "project.edit")]
    ProjectEdit(ProjectEditArguments),
    #[serde(rename = "project.format")]
    ProjectFormat(ProjectArguments),
    #[serde(rename = "project.migrate")]
    ProjectMigrate(ProjectMigrateArguments),
    #[serde(rename = "analysis.code.facts")]
    AnalysisCodeFacts(CodeFactsArguments),
    #[serde(rename = "source.read")]
    SourceRead(SourceReadArguments),
    #[serde(rename = "project.init")]
    ProjectInit(ProjectInitArguments),
    #[serde(rename = "project.extract")]
    ProjectExtract(ProjectExtractArguments),
    #[serde(rename = "project.resource.export")]
    ProjectResourceExport(ResourceExportArguments),
}

impl OperationRequestDocument {
    #[must_use]
    pub const fn operation_name(&self) -> OperationName {
        match self {
            Self::SourceSurvey(_) => OperationName::SourceSurvey,
            Self::ContainerAdfList(_) => OperationName::ContainerAdfList,
            Self::GraphicsBitmapDecode(_) => OperationName::GraphicsBitmapDecode,
            Self::ContainerAdfExtract(_) => OperationName::ContainerAdfExtract,
            Self::ContainerLhaExtract(_) => OperationName::ContainerLhaExtract,
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
            Self::HardwareRegisterList(_) => OperationName::HardwareRegisterList,
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
            Self::ProjectInit(_) => OperationName::ProjectInit,
            Self::ProjectExtract(_) => OperationName::ProjectExtract,
            Self::ProjectResourceExport(_) => OperationName::ProjectResourceExport,
        }
    }
}

/// How a caller names one input source.
///
/// The path is an identity a resolver interprets, never a host path: a request
/// document must stay reproducible on another machine.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceLocator {
    File {
        path: String,
    },
    /// Bytes recovered from inside another source.
    ///
    /// The project format could always say "this object is `s/startup-sequence`
    /// inside disk1.adf", and nothing that analysed bytes could accept that
    /// sentence — so inspecting twelve files on a disk meant writing twelve
    /// files out and re-opening each. `Selector` is the format's own vocabulary
    /// rather than a second one: a selector names a member and carries no
    /// project-derived digest, so it is the same question asked of a request.
    ///
    /// `parent` is a locator rather than a path so that chains work the way the
    /// format's own derivation graph does — a PowerPacked file inside an LHA
    /// member inside an ADF is three selectors, not a special case.
    Member {
        parent: Box<SourceLocator>,
        selector: amiga_project::document::Selector,
    },
}

impl SourceLocator {
    /// A source named by a resolver-relative identity.
    #[must_use]
    pub fn file(path: impl Into<String>) -> Self {
        Self::File { path: path.into() }
    }

    /// The member `selector` names inside this source.
    #[must_use]
    pub fn member(self, selector: amiga_project::document::Selector) -> Self {
        Self::Member {
            parent: Box::new(self),
            selector,
        }
    }
}
