//! Typed operation results, as the in-process API returns them.
//!
//! These are internal types holding domain values. The serialized contract is
//! [`crate::document`], built from these.
//!
//! [`OperationOutcome`], the exhaustive [`OperationResult`] and the
//! [`SourcePin`] every result carries stay in this module; the per-operation
//! results are grouped by their operation-name prefix and re-exported here, so
//! no public path changes.

use crate::diagnostics::Diagnostic;
use crate::protocol::{EXIT_INVALID_REQUEST, Status};
use crate::request::OperationName;

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

/// What one operation produced, whether or not it succeeded.
#[derive(Clone, Debug)]
pub struct OperationOutcome {
    pub operation: OperationName,
    pub status: Status,
    pub diagnostics: Vec<Diagnostic>,
    /// Absent only when the request was refused before normalization finished.
    pub normalized_request_sha256: Option<String>,
    pub result: Option<OperationResult>,
}

impl OperationOutcome {
    /// A refusal carrying the diagnostics that explain it.
    #[must_use]
    pub fn refused(operation: OperationName, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            operation,
            status: Status::Error,
            diagnostics,
            normalized_request_sha256: None,
            result: None,
        }
    }

    /// The process exit code for this outcome.
    ///
    /// A request refused before any work ran is distinguished from an operation
    /// that ran and failed, so automation can tell a bad request from a bad
    /// input without parsing anything.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.status == Status::Error
            && self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.is_error() && diagnostic.code.is_request_validation())
        {
            return EXIT_INVALID_REQUEST;
        }
        self.status.exit_code()
    }

    /// The `project.check` result.
    #[must_use]
    pub fn project_check(&self) -> Option<&ProjectCheckResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectCheck(check) => Some(check),
            _ => None,
        }
    }

    /// The `project.verify` result.
    #[must_use]
    pub fn project_verify(&self) -> Option<&ProjectVerifyResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectVerify(verify) => Some(verify),
            _ => None,
        }
    }

    /// The `graphics.bitmap.export` plan, whether it was committed or only
    /// prepared.
    #[must_use]
    pub fn graphics_bitmap_export(&self) -> Option<&BitmapExportResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsBitmapExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `graphics.bitmap.compare` result.
    #[must_use]
    pub fn graphics_bitmap_compare(&self) -> Option<&BitmapCompareResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsBitmapCompare(compare) => Some(compare),
            _ => None,
        }
    }

    /// The `graphics.bitmap.compare.export` plan.
    #[must_use]
    pub fn graphics_bitmap_compare_export(&self) -> Option<&BitmapCompareExportResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsBitmapCompareExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `analysis.hunk.diff` comparison, when that is what ran.
    #[must_use]
    pub fn analysis_hunk_diff(&self) -> Option<&HunkDiffResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisHunkDiff(diff) => Some(diff),
            _ => None,
        }
    }

    /// The `analysis.hunk.diff.export` plan, whether it was committed or only
    /// prepared.
    #[must_use]
    pub fn analysis_hunk_diff_export(&self) -> Option<&HunkDiffExportResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisHunkDiffExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `audio.sample.decode` result.
    #[must_use]
    pub fn audio_sample_decode(&self) -> Option<&AudioSampleResult> {
        match self.result.as_ref()? {
            OperationResult::AudioSampleDecode(sample) => Some(sample),
            _ => None,
        }
    }

    /// The `audio.sample.export` plan, whether it was committed or only
    /// prepared.
    #[must_use]
    pub fn audio_sample_export(&self) -> Option<&AudioSampleExportResult> {
        match self.result.as_ref()? {
            OperationResult::AudioSampleExport(export) => Some(export),
            _ => None,
        }
    }

    /// The summary from either `compress.*.decode`.
    ///
    /// One accessor for both codecs: the answer has the same shape whichever
    /// stream produced it, and the operation name in the outcome already says
    /// which was asked.
    #[must_use]
    pub fn compress_decode(&self) -> Option<&CompressDecodeResult> {
        match self.result.as_ref()? {
            OperationResult::CompressDecode(decoded) => Some(decoded),
            _ => None,
        }
    }

    /// The `compress.*.export` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn compress_export(&self) -> Option<&CompressExportResult> {
        match self.result.as_ref()? {
            OperationResult::CompressExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `audio.pcm.decode` result.
    #[must_use]
    pub fn audio_pcm_decode(&self) -> Option<&PcmDecodeResult> {
        match self.result.as_ref()? {
            OperationResult::AudioPcmDecode(pcm) => Some(pcm),
            _ => None,
        }
    }

    /// The `audio.pcm.export` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn audio_pcm_export(&self) -> Option<&PcmExportResult> {
        match self.result.as_ref()? {
            OperationResult::AudioPcmExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `audio.module.decode` result.
    #[must_use]
    pub fn audio_module_decode(&self) -> Option<&ModuleResult> {
        match self.result.as_ref()? {
            OperationResult::AudioModuleDecode(module) => Some(module),
            _ => None,
        }
    }

    /// The `audio.module.export` plan, whether it was committed or only
    /// prepared.
    #[must_use]
    pub fn audio_module_export(&self) -> Option<&ModuleExportResult> {
        match self.result.as_ref()? {
            OperationResult::AudioModuleExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `analysis.hunk.normalize` result.
    #[must_use]
    pub fn analysis_hunk_normalize(&self) -> Option<&HunkNormalizeResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisHunkNormalize(normalized) => Some(normalized),
            _ => None,
        }
    }

    /// The `analysis.hunk.normalize.export` plan.
    #[must_use]
    pub fn analysis_hunk_normalize_export(&self) -> Option<&HunkNormalizeExportResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisHunkNormalizeExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `provenance.manifest` result.
    #[must_use]
    pub fn provenance_manifest(&self) -> Option<&ManifestResult> {
        match self.result.as_ref()? {
            OperationResult::ProvenanceManifest(manifest) => Some(manifest),
            _ => None,
        }
    }

    /// The `provenance.manifest.export` plan.
    #[must_use]
    pub fn provenance_manifest_export(&self) -> Option<&ManifestExportResult> {
        match self.result.as_ref()? {
            OperationResult::ProvenanceManifestExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `graphics.palette.decode` result.
    #[must_use]
    pub fn graphics_palette_decode(&self) -> Option<&PaletteResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsPaletteDecode(palette) => Some(palette),
            _ => None,
        }
    }

    /// The `graphics.palette.export` plan.
    #[must_use]
    pub fn graphics_palette_export(&self) -> Option<&PaletteExportResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsPaletteExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `env.sandbox.run` result.
    #[must_use]
    pub fn env_sandbox_run(&self) -> Option<&SandboxRunResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxRun(run) => Some(run),
            _ => None,
        }
    }

    /// The `env.boot.info` result.
    #[must_use]
    pub fn env_boot_info(&self) -> Option<&BootInfoResult> {
        match self.result.as_ref()? {
            OperationResult::EnvBootInfo(info) => Some(info),
            _ => None,
        }
    }

    /// The `env.sandbox.call` record.
    #[must_use]
    pub fn env_sandbox_call(&self) -> Option<&SandboxCallResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxCall(record) => Some(record),
            _ => None,
        }
    }

    /// The `env.sandbox.call.export` plan.
    #[must_use]
    pub fn env_sandbox_call_export(&self) -> Option<&SandboxCallExportResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxCallExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `env.sandbox.matrix` result.
    #[must_use]
    pub fn env_sandbox_matrix(&self) -> Option<&SandboxMatrixResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxMatrix(matrix) => Some(matrix),
            _ => None,
        }
    }

    /// The `env.sandbox.timeline` result.
    #[must_use]
    pub fn env_sandbox_timeline(&self) -> Option<&SandboxTimelineResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxTimeline(timeline) => Some(timeline),
            _ => None,
        }
    }

    /// The `env.sandbox.slice` result.
    #[must_use]
    pub fn env_sandbox_slice(&self) -> Option<&SandboxSliceResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxSlice(slice) => Some(slice),
            _ => None,
        }
    }

    /// The `env.frame.capture` result.
    #[must_use]
    pub fn env_frame_capture(&self) -> Option<&FrameCaptureResult> {
        match self.result.as_ref()? {
            OperationResult::EnvFrameCapture(frame) => Some(frame),
            _ => None,
        }
    }

    /// The `env.frame.capture.export` plan.
    #[must_use]
    pub fn env_frame_capture_export(&self) -> Option<&FrameCaptureExportResult> {
        match self.result.as_ref()? {
            OperationResult::EnvFrameCaptureExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `env.sandbox.compare` result.
    #[must_use]
    pub fn env_sandbox_compare(&self) -> Option<&SandboxCompareResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxCompare(compare) => Some(compare),
            _ => None,
        }
    }

    /// The `env.sandbox.timeline.export` plan.
    #[must_use]
    pub fn env_sandbox_timeline_export(&self) -> Option<&SandboxTimelineExportResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxTimelineExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `env.sandbox.matrix.export` plan.
    #[must_use]
    pub fn env_sandbox_matrix_export(&self) -> Option<&SandboxMatrixExportResult> {
        match self.result.as_ref()? {
            OperationResult::EnvSandboxMatrixExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `env.boot.trace` result.
    #[must_use]
    pub fn env_boot_trace(&self) -> Option<&BootTraceResult> {
        match self.result.as_ref()? {
            OperationResult::EnvBootTrace(trace) => Some(trace),
            _ => None,
        }
    }

    /// The `env.boot.trace.export` plan.
    #[must_use]
    pub fn env_boot_trace_export(&self) -> Option<&BootTraceExportResult> {
        match self.result.as_ref()? {
            OperationResult::EnvBootTraceExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `analysis.hunk.list` result.
    #[must_use]
    pub fn analysis_hunk_list(&self) -> Option<&HunkListResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisHunkList(list) => Some(list),
            _ => None,
        }
    }

    /// The `analysis.strings.scan` result.
    #[must_use]
    pub fn analysis_strings_scan(&self) -> Option<&StringsScanResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisStringsScan(scan) => Some(scan),
            _ => None,
        }
    }

    /// The `analysis.address.resolve` result.
    #[must_use]
    pub fn analysis_address_resolve(&self) -> Option<&AddressResolveResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisAddressResolve(resolved) => Some(resolved),
            _ => None,
        }
    }

    /// The `analysis.pointers.scan` result.
    #[must_use]
    pub fn analysis_pointers_scan(&self) -> Option<&PointerScanResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisPointersScan(scan) => Some(scan),
            _ => None,
        }
    }

    /// The `analysis.code.disassemble` result.
    #[must_use]
    pub fn analysis_code_disassemble(&self) -> Option<&CodeDisassembleResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisCodeDisassemble(disassembled) => Some(disassembled),
            _ => None,
        }
    }

    /// The `analysis.address.references` result.
    #[must_use]
    pub fn analysis_address_references(&self) -> Option<&AddressReferencesResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisAddressReferences(references) => Some(references),
            _ => None,
        }
    }

    /// The `analysis.code.callgraph` result.
    #[must_use]
    pub fn analysis_code_callgraph(&self) -> Option<&CodeCallgraphResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisCodeCallgraph(graph) => Some(graph),
            _ => None,
        }
    }

    /// The `analysis.code.globals` result.
    #[must_use]
    pub fn analysis_code_globals(&self) -> Option<&CodeGlobalsResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisCodeGlobals(globals) => Some(globals),
            _ => None,
        }
    }

    /// The `analysis.state.snapshot` result.
    #[must_use]
    pub fn analysis_state_snapshot(&self) -> Option<&StateSnapshotResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisStateSnapshot(snapshot) => Some(snapshot),
            _ => None,
        }
    }

    /// The `analysis.state.compare` result.
    #[must_use]
    pub fn analysis_state_compare(&self) -> Option<&StateCompareResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisStateCompare(compare) => Some(compare),
            _ => None,
        }
    }

    /// The `analysis.code.fixed-point` result.
    #[must_use]
    pub fn analysis_code_fixed_point(&self) -> Option<&CodeFixedPointResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisCodeFixedPoint(fixed) => Some(fixed),
            _ => None,
        }
    }

    /// The `container.lha.list` result.
    #[must_use]
    pub fn container_lha_list(&self) -> Option<&LhaListResult> {
        match self.result.as_ref()? {
            OperationResult::ContainerLhaList(list) => Some(list),
            _ => None,
        }
    }

    /// The `hardware.register.list` result.
    #[must_use]
    pub fn hardware_register_list(&self) -> Option<&HardwareRegisterListResult> {
        match self.result.as_ref()? {
            OperationResult::HardwareRegisterList(list) => Some(list),
            _ => None,
        }
    }

    /// The `audio.pcm.scan` result.
    #[must_use]
    pub fn audio_pcm_scan(&self) -> Option<&PcmScanResult> {
        match self.result.as_ref()? {
            OperationResult::AudioPcmScan(scan) => Some(scan),
            _ => None,
        }
    }

    /// The `audio.module.scan` result.
    #[must_use]
    pub fn audio_module_scan(&self) -> Option<&ModuleScanResult> {
        match self.result.as_ref()? {
            OperationResult::AudioModuleScan(scan) => Some(scan),
            _ => None,
        }
    }

    /// The `graphics.palette.scan` result.
    #[must_use]
    pub fn graphics_palette_scan(&self) -> Option<&PaletteScanResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsPaletteScan(scan) => Some(scan),
            _ => None,
        }
    }

    /// The `hardware.copper.scan` result.
    #[must_use]
    pub fn hardware_copper_scan(&self) -> Option<&CopperScanResult> {
        match self.result.as_ref()? {
            OperationResult::HardwareCopperScan(scan) => Some(scan),
            _ => None,
        }
    }

    /// The `hardware.copper.decode` result.
    #[must_use]
    pub fn hardware_copper_decode(&self) -> Option<&CopperDecodeResult> {
        match self.result.as_ref()? {
            OperationResult::HardwareCopperDecode(decode) => Some(decode),
            _ => None,
        }
    }

    /// The `graphics.ilbm.decode` result.
    #[must_use]
    pub fn graphics_ilbm_decode(&self) -> Option<&IlbmDecodeResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsIlbmDecode(decode) => Some(decode),
            _ => None,
        }
    }

    /// The `graphics.bitmap.detect` result.
    #[must_use]
    pub fn graphics_bitmap_detect(&self) -> Option<&BitmapDetectResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsBitmapDetect(detect) => Some(detect),
            _ => None,
        }
    }

    /// The `hardware.register.references` result.
    #[must_use]
    pub fn hardware_register_references(&self) -> Option<&RegisterReferencesResult> {
        match self.result.as_ref()? {
            OperationResult::HardwareRegisterReferences(references) => Some(references),
            _ => None,
        }
    }

    /// The `hardware.copper.references` result.
    #[must_use]
    pub fn hardware_copper_references(&self) -> Option<&CopperReferencesResult> {
        match self.result.as_ref()? {
            OperationResult::HardwareCopperReferences(references) => Some(references),
            _ => None,
        }
    }

    /// The `project.describe` result.
    #[must_use]
    pub fn project_describe(&self) -> Option<&ProjectDescribeResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectDescribe(described) => Some(described),
            _ => None,
        }
    }

    /// The `project.annotations` result.
    #[must_use]
    pub fn project_annotations(&self) -> Option<&ProjectAnnotationsResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectAnnotations(annotations) => Some(annotations),
            _ => None,
        }
    }

    /// The `project.inventory` result.
    #[must_use]
    pub fn project_inventory(&self) -> Option<&ProjectInventoryResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectInventory(inventory) => Some(inventory),
            _ => None,
        }
    }

    /// The `project.edit` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn project_edit(&self) -> Option<&ProjectEditResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectEdit(edit) => Some(edit),
            _ => None,
        }
    }

    /// The `project.extract` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn project_extract(&self) -> Option<&ProjectExtractResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectExtract(extract) => Some(extract),
            _ => None,
        }
    }

    /// The `project.resource.export` plan, committed or only prepared.
    #[must_use]
    pub fn project_resource_export(&self) -> Option<&ResourceExportResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectResourceExport(export) => Some(export),
            _ => None,
        }
    }

    /// The `project.init` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn project_init(&self) -> Option<&ProjectInitResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectInit(init) => Some(init),
            _ => None,
        }
    }

    /// The `project.format` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn project_format(&self) -> Option<&ProjectFormatResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectFormat(format) => Some(format),
            _ => None,
        }
    }

    /// The `project.migrate` result.
    #[must_use]
    pub fn project_migrate(&self) -> Option<&ProjectMigrateResult> {
        match self.result.as_ref()? {
            OperationResult::ProjectMigrate(migrate) => Some(migrate),
            _ => None,
        }
    }

    /// The `analysis.code.facts` result.
    #[must_use]
    pub fn analysis_code_facts(&self) -> Option<&CodeFactsResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisCodeFacts(facts) => Some(facts),
            _ => None,
        }
    }

    /// The `source.read` result.
    #[must_use]
    pub fn source_read(&self) -> Option<&SourceReadResult> {
        match self.result.as_ref()? {
            OperationResult::SourceRead(read) => Some(read),
            _ => None,
        }
    }

    /// The `analysis.table.decode` result.
    #[must_use]
    pub fn analysis_table_decode(&self) -> Option<&TableDecodeResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisTableDecode(table) => Some(table),
            _ => None,
        }
    }

    /// The `analysis.table.summarize` result, when that is what ran and it
    /// succeeded.
    #[must_use]
    pub fn analysis_table_summarize(&self) -> Option<&TableSummarizeResult> {
        match self.result.as_ref()? {
            OperationResult::AnalysisTableSummarize(table) => Some(table),
            _ => None,
        }
    }

    /// The `source.carve` plan, whether it was committed or only prepared.
    #[must_use]
    pub fn source_carve(&self) -> Option<&CarveResult> {
        match self.result.as_ref()? {
            OperationResult::SourceCarve(carve) => Some(carve),
            _ => None,
        }
    }

    /// A container extraction's plan, whether it was committed or only prepared.
    #[must_use]
    pub fn container_extract(&self) -> Option<&ContainerExtractResult> {
        match self.result.as_ref()? {
            OperationResult::ContainerExtract(extract) => Some(extract),
            _ => None,
        }
    }

    /// The `graphics.bitmap.decode` result, when that is what ran and it
    /// succeeded.
    #[must_use]
    pub fn graphics_bitmap_decode(&self) -> Option<&BitmapDecodeResult> {
        match self.result.as_ref()? {
            OperationResult::GraphicsBitmapDecode(decode) => Some(decode),
            OperationResult::SourceSurvey(_)
            | OperationResult::ContainerAdfList(_)
            | OperationResult::ContainerExtract(_)
            | OperationResult::GraphicsBitmapExport(_)
            | OperationResult::GraphicsBitmapCompare(_)
            | OperationResult::GraphicsBitmapCompareExport(_)
            | OperationResult::ProjectCheck(_)
            | OperationResult::ProjectVerify(_)
            | OperationResult::AnalysisHunkDiff(_)
            | OperationResult::AnalysisHunkDiffExport(_)
            | OperationResult::SourceCarve(_)
            | OperationResult::AnalysisTableDecode(_)
            | OperationResult::AnalysisTableSummarize(_)
            | OperationResult::AudioSampleDecode(_)
            | OperationResult::AudioSampleExport(_)
            | OperationResult::CompressDecode(_)
            | OperationResult::CompressExport(_)
            | OperationResult::AudioPcmDecode(_)
            | OperationResult::AudioPcmExport(_)
            | OperationResult::AudioModuleDecode(_)
            | OperationResult::AudioModuleExport(_)
            | OperationResult::AnalysisHunkNormalize(_)
            | OperationResult::AnalysisHunkNormalizeExport(_)
            | OperationResult::ProvenanceManifest(_)
            | OperationResult::ProvenanceManifestExport(_)
            | OperationResult::GraphicsPaletteDecode(_)
            | OperationResult::GraphicsPaletteExport(_)
            | OperationResult::EnvSandboxRun(_)
            | OperationResult::EnvBootInfo(_)
            | OperationResult::EnvSandboxCall(_)
            | OperationResult::EnvSandboxCallExport(_)
            | OperationResult::EnvSandboxMatrix(_)
            | OperationResult::EnvSandboxTimeline(_)
            | OperationResult::EnvSandboxTimelineExport(_)
            | OperationResult::EnvSandboxSlice(_)
            | OperationResult::EnvFrameCapture(_)
            | OperationResult::EnvFrameCaptureExport(_)
            | OperationResult::EnvSandboxCompare(_)
            | OperationResult::EnvSandboxMatrixExport(_)
            | OperationResult::EnvBootTrace(_)
            | OperationResult::EnvBootTraceExport(_)
            | OperationResult::AnalysisHunkList(_)
            | OperationResult::AnalysisStringsScan(_)
            | OperationResult::AnalysisAddressResolve(_)
            | OperationResult::AnalysisPointersScan(_)
            | OperationResult::AnalysisCodeDisassemble(_)
            | OperationResult::AnalysisAddressReferences(_)
            | OperationResult::AnalysisCodeCallgraph(_)
            | OperationResult::AnalysisCodeGlobals(_)
            | OperationResult::AnalysisCodeFixedPoint(_)
            | OperationResult::AnalysisStateSnapshot(_)
            | OperationResult::AnalysisStateCompare(_)
            | OperationResult::ContainerLhaList(_)
            | OperationResult::HardwareRegisterList(_)
            | OperationResult::AudioPcmScan(_)
            | OperationResult::AudioModuleScan(_)
            | OperationResult::GraphicsPaletteScan(_)
            | OperationResult::HardwareCopperScan(_)
            | OperationResult::HardwareCopperDecode(_)
            | OperationResult::GraphicsIlbmDecode(_)
            | OperationResult::GraphicsBitmapDetect(_)
            | OperationResult::HardwareRegisterReferences(_)
            | OperationResult::HardwareCopperReferences(_)
            | OperationResult::ProjectDescribe(_)
            | OperationResult::ProjectAnnotations(_)
            | OperationResult::ProjectInventory(_)
            | OperationResult::ProjectEdit(_)
            | OperationResult::ProjectFormat(_)
            | OperationResult::ProjectMigrate(_)
            | OperationResult::AnalysisCodeFacts(_)
            | OperationResult::SourceRead(_)
            | OperationResult::ProjectInit(_)
            | OperationResult::ProjectExtract(_)
            | OperationResult::ProjectResourceExport(_) => None,
        }
    }

    /// The `source.survey` result, when that is what ran and it succeeded.
    #[must_use]
    pub fn source_survey(&self) -> Option<&SourceSurveyResult> {
        match self.result.as_ref()? {
            OperationResult::SourceSurvey(result) => Some(result),
            OperationResult::ContainerAdfList(_)
            | OperationResult::GraphicsBitmapDecode(_)
            | OperationResult::ContainerExtract(_)
            | OperationResult::GraphicsBitmapExport(_)
            | OperationResult::GraphicsBitmapCompare(_)
            | OperationResult::GraphicsBitmapCompareExport(_)
            | OperationResult::ProjectCheck(_)
            | OperationResult::ProjectVerify(_)
            | OperationResult::AnalysisHunkDiff(_)
            | OperationResult::AnalysisHunkDiffExport(_)
            | OperationResult::SourceCarve(_)
            | OperationResult::AnalysisTableDecode(_)
            | OperationResult::AnalysisTableSummarize(_)
            | OperationResult::AudioSampleDecode(_)
            | OperationResult::AudioSampleExport(_)
            | OperationResult::CompressDecode(_)
            | OperationResult::CompressExport(_)
            | OperationResult::AudioPcmDecode(_)
            | OperationResult::AudioPcmExport(_)
            | OperationResult::AudioModuleDecode(_)
            | OperationResult::AudioModuleExport(_)
            | OperationResult::AnalysisHunkNormalize(_)
            | OperationResult::AnalysisHunkNormalizeExport(_)
            | OperationResult::ProvenanceManifest(_)
            | OperationResult::ProvenanceManifestExport(_)
            | OperationResult::GraphicsPaletteDecode(_)
            | OperationResult::GraphicsPaletteExport(_)
            | OperationResult::EnvSandboxRun(_)
            | OperationResult::EnvBootInfo(_)
            | OperationResult::EnvSandboxCall(_)
            | OperationResult::EnvSandboxCallExport(_)
            | OperationResult::EnvSandboxMatrix(_)
            | OperationResult::EnvSandboxTimeline(_)
            | OperationResult::EnvSandboxTimelineExport(_)
            | OperationResult::EnvSandboxSlice(_)
            | OperationResult::EnvFrameCapture(_)
            | OperationResult::EnvFrameCaptureExport(_)
            | OperationResult::EnvSandboxCompare(_)
            | OperationResult::EnvSandboxMatrixExport(_)
            | OperationResult::EnvBootTrace(_)
            | OperationResult::EnvBootTraceExport(_)
            | OperationResult::AnalysisHunkList(_)
            | OperationResult::AnalysisStringsScan(_)
            | OperationResult::AnalysisAddressResolve(_)
            | OperationResult::AnalysisPointersScan(_)
            | OperationResult::AnalysisCodeDisassemble(_)
            | OperationResult::AnalysisAddressReferences(_)
            | OperationResult::AnalysisCodeCallgraph(_)
            | OperationResult::AnalysisCodeGlobals(_)
            | OperationResult::AnalysisCodeFixedPoint(_)
            | OperationResult::AnalysisStateSnapshot(_)
            | OperationResult::AnalysisStateCompare(_)
            | OperationResult::ContainerLhaList(_)
            | OperationResult::HardwareRegisterList(_)
            | OperationResult::AudioPcmScan(_)
            | OperationResult::AudioModuleScan(_)
            | OperationResult::GraphicsPaletteScan(_)
            | OperationResult::HardwareCopperScan(_)
            | OperationResult::HardwareCopperDecode(_)
            | OperationResult::GraphicsIlbmDecode(_)
            | OperationResult::GraphicsBitmapDetect(_)
            | OperationResult::HardwareRegisterReferences(_)
            | OperationResult::HardwareCopperReferences(_)
            | OperationResult::ProjectDescribe(_)
            | OperationResult::ProjectAnnotations(_)
            | OperationResult::ProjectInventory(_)
            | OperationResult::ProjectEdit(_)
            | OperationResult::ProjectFormat(_)
            | OperationResult::ProjectMigrate(_)
            | OperationResult::AnalysisCodeFacts(_)
            | OperationResult::SourceRead(_)
            | OperationResult::ProjectInit(_)
            | OperationResult::ProjectExtract(_)
            | OperationResult::ProjectResourceExport(_) => None,
        }
    }

    /// The `container.adf.list` result, when that is what ran and it succeeded.
    #[must_use]
    pub fn container_adf_list(&self) -> Option<&AdfListResult> {
        match self.result.as_ref()? {
            OperationResult::ContainerAdfList(result) => Some(result),
            OperationResult::SourceSurvey(_)
            | OperationResult::GraphicsBitmapDecode(_)
            | OperationResult::ContainerExtract(_)
            | OperationResult::GraphicsBitmapExport(_)
            | OperationResult::GraphicsBitmapCompare(_)
            | OperationResult::GraphicsBitmapCompareExport(_)
            | OperationResult::ProjectCheck(_)
            | OperationResult::ProjectVerify(_)
            | OperationResult::AnalysisHunkDiff(_)
            | OperationResult::AnalysisHunkDiffExport(_)
            | OperationResult::SourceCarve(_)
            | OperationResult::AnalysisTableDecode(_)
            | OperationResult::AnalysisTableSummarize(_)
            | OperationResult::AudioSampleDecode(_)
            | OperationResult::AudioSampleExport(_)
            | OperationResult::CompressDecode(_)
            | OperationResult::CompressExport(_)
            | OperationResult::AudioPcmDecode(_)
            | OperationResult::AudioPcmExport(_)
            | OperationResult::AudioModuleDecode(_)
            | OperationResult::AudioModuleExport(_)
            | OperationResult::AnalysisHunkNormalize(_)
            | OperationResult::AnalysisHunkNormalizeExport(_)
            | OperationResult::ProvenanceManifest(_)
            | OperationResult::ProvenanceManifestExport(_)
            | OperationResult::GraphicsPaletteDecode(_)
            | OperationResult::GraphicsPaletteExport(_)
            | OperationResult::EnvSandboxRun(_)
            | OperationResult::EnvBootInfo(_)
            | OperationResult::EnvSandboxCall(_)
            | OperationResult::EnvSandboxCallExport(_)
            | OperationResult::EnvSandboxMatrix(_)
            | OperationResult::EnvSandboxTimeline(_)
            | OperationResult::EnvSandboxTimelineExport(_)
            | OperationResult::EnvSandboxSlice(_)
            | OperationResult::EnvFrameCapture(_)
            | OperationResult::EnvFrameCaptureExport(_)
            | OperationResult::EnvSandboxCompare(_)
            | OperationResult::EnvSandboxMatrixExport(_)
            | OperationResult::EnvBootTrace(_)
            | OperationResult::EnvBootTraceExport(_)
            | OperationResult::AnalysisHunkList(_)
            | OperationResult::AnalysisStringsScan(_)
            | OperationResult::AnalysisAddressResolve(_)
            | OperationResult::AnalysisPointersScan(_)
            | OperationResult::AnalysisCodeDisassemble(_)
            | OperationResult::AnalysisAddressReferences(_)
            | OperationResult::AnalysisCodeCallgraph(_)
            | OperationResult::AnalysisCodeGlobals(_)
            | OperationResult::AnalysisCodeFixedPoint(_)
            | OperationResult::AnalysisStateSnapshot(_)
            | OperationResult::AnalysisStateCompare(_)
            | OperationResult::ContainerLhaList(_)
            | OperationResult::HardwareRegisterList(_)
            | OperationResult::AudioPcmScan(_)
            | OperationResult::AudioModuleScan(_)
            | OperationResult::GraphicsPaletteScan(_)
            | OperationResult::HardwareCopperScan(_)
            | OperationResult::HardwareCopperDecode(_)
            | OperationResult::GraphicsIlbmDecode(_)
            | OperationResult::GraphicsBitmapDetect(_)
            | OperationResult::HardwareRegisterReferences(_)
            | OperationResult::HardwareCopperReferences(_)
            | OperationResult::ProjectDescribe(_)
            | OperationResult::ProjectAnnotations(_)
            | OperationResult::ProjectInventory(_)
            | OperationResult::ProjectEdit(_)
            | OperationResult::ProjectFormat(_)
            | OperationResult::ProjectMigrate(_)
            | OperationResult::AnalysisCodeFacts(_)
            | OperationResult::SourceRead(_)
            | OperationResult::ProjectInit(_)
            | OperationResult::ProjectExtract(_)
            | OperationResult::ProjectResourceExport(_) => None,
        }
    }
}

/// One shaped result per operation.
#[derive(Clone, Debug)]
pub enum OperationResult {
    SourceSurvey(SourceSurveyResult),
    ContainerAdfList(AdfListResult),
    GraphicsBitmapDecode(BitmapDecodeResult),
    ContainerExtract(ContainerExtractResult),
    GraphicsBitmapExport(BitmapExportResult),
    GraphicsBitmapCompare(BitmapCompareResult),
    GraphicsBitmapCompareExport(BitmapCompareExportResult),
    ProjectCheck(ProjectCheckResult),
    ProjectVerify(ProjectVerifyResult),
    AnalysisHunkDiff(HunkDiffResult),
    AnalysisHunkDiffExport(HunkDiffExportResult),
    SourceCarve(CarveResult),
    AnalysisTableDecode(TableDecodeResult),
    AnalysisTableSummarize(TableSummarizeResult),
    AudioSampleDecode(AudioSampleResult),
    AudioSampleExport(AudioSampleExportResult),
    CompressDecode(CompressDecodeResult),
    CompressExport(CompressExportResult),
    AudioPcmDecode(PcmDecodeResult),
    AudioPcmExport(PcmExportResult),
    AudioModuleDecode(ModuleResult),
    AudioModuleExport(ModuleExportResult),
    AnalysisHunkNormalize(HunkNormalizeResult),
    AnalysisHunkNormalizeExport(HunkNormalizeExportResult),
    ProvenanceManifest(ManifestResult),
    ProvenanceManifestExport(ManifestExportResult),
    GraphicsPaletteDecode(PaletteResult),
    GraphicsPaletteExport(PaletteExportResult),
    EnvSandboxRun(SandboxRunResult),
    EnvBootInfo(BootInfoResult),
    EnvSandboxCall(SandboxCallResult),
    EnvSandboxCallExport(SandboxCallExportResult),
    EnvSandboxMatrix(SandboxMatrixResult),
    EnvSandboxTimeline(SandboxTimelineResult),
    EnvSandboxTimelineExport(SandboxTimelineExportResult),
    EnvSandboxSlice(SandboxSliceResult),
    EnvFrameCapture(FrameCaptureResult),
    EnvFrameCaptureExport(FrameCaptureExportResult),
    EnvSandboxCompare(SandboxCompareResult),
    EnvSandboxMatrixExport(SandboxMatrixExportResult),
    EnvBootTrace(BootTraceResult),
    EnvBootTraceExport(BootTraceExportResult),
    AnalysisHunkList(HunkListResult),
    AnalysisStringsScan(StringsScanResult),
    AnalysisAddressResolve(AddressResolveResult),
    AnalysisPointersScan(PointerScanResult),
    AnalysisCodeDisassemble(CodeDisassembleResult),
    AnalysisAddressReferences(AddressReferencesResult),
    AnalysisCodeCallgraph(CodeCallgraphResult),
    AnalysisCodeGlobals(CodeGlobalsResult),
    AnalysisCodeFixedPoint(CodeFixedPointResult),
    AnalysisStateSnapshot(StateSnapshotResult),
    AnalysisStateCompare(StateCompareResult),
    ContainerLhaList(LhaListResult),
    HardwareRegisterList(HardwareRegisterListResult),
    AudioPcmScan(PcmScanResult),
    AudioModuleScan(ModuleScanResult),
    GraphicsPaletteScan(PaletteScanResult),
    HardwareCopperScan(CopperScanResult),
    HardwareCopperDecode(CopperDecodeResult),
    GraphicsIlbmDecode(IlbmDecodeResult),
    GraphicsBitmapDetect(BitmapDetectResult),
    HardwareRegisterReferences(RegisterReferencesResult),
    HardwareCopperReferences(CopperReferencesResult),
    ProjectDescribe(ProjectDescribeResult),
    ProjectAnnotations(ProjectAnnotationsResult),
    ProjectInventory(ProjectInventoryResult),
    ProjectEdit(ProjectEditResult),
    ProjectFormat(ProjectFormatResult),
    ProjectMigrate(ProjectMigrateResult),
    ProjectInit(ProjectInitResult),
    ProjectExtract(ProjectExtractResult),
    ProjectResourceExport(ResourceExportResult),
    AnalysisCodeFacts(CodeFactsResult),
    SourceRead(SourceReadResult),
}

/// The bytes an operation actually read, pinned so the result is reproducible.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SourcePin {
    pub size: u64,
    pub sha256: String,
}
