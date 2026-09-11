//! The response as it crosses a process boundary.
//!
//! Serialize only. Responses are produced here and consumed by other programs;
//! nothing in this toolkit deserializes one, so no round-trip obligation is
//! implied by these types.

use serde::Serialize;

use crate::diagnostics::Diagnostic;
use crate::protocol::{PROTOCOL_VERSION, Status};
use crate::request::OperationName;
use crate::response::{
    AdfListResult, BitmapDecodeResult, BitmapExportResult, ContainerExtractResult,
    HunkDiffExportResult, OperationOutcome, OperationResult, SourceSurveyResult,
};

/// One operation response.
#[derive(Clone, Debug, Serialize)]
pub struct ResponseEnvelope {
    pub protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub operation: OperationName,
    pub status: Status,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_request_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultDocument>,
}

impl ResponseEnvelope {
    /// Serialize `outcome`, echoing the caller's correlation id.
    #[must_use]
    pub fn from_outcome(outcome: &OperationOutcome, request_id: Option<&str>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.map(str::to_owned),
            operation: outcome.operation,
            status: outcome.status,
            diagnostics: outcome.diagnostics.clone(),
            normalized_request_sha256: outcome.normalized_request_sha256.clone(),
            result: outcome.result.as_ref().map(ResultDocument::from),
        }
    }
}

/// The shaped payload of one result.
///
/// Untagged: the envelope's `operation` field already names the operation, and
/// emitting a second nested tag would make the same fact appear twice.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ResultDocument {
    SourceSurvey(SourceSurveyDocument),
    ContainerAdfList(AdfListDocument),
    GraphicsBitmapDecode(BitmapDecodeDocument),
    ContainerExtract(ContainerExtractDocument),
    GraphicsBitmapExport(BitmapExportDocument),
    GraphicsBitmapCompare(crate::response::BitmapCompareResult),
    GraphicsBitmapCompareExport(crate::response::BitmapCompareExportResult),
    // These two need no separate document type: their results carry only
    // counts, IDs, and codes, so the wire shape *is* the result shape.
    ProjectCheck(crate::response::ProjectCheckResult),
    ProjectVerify(crate::response::ProjectVerifyResult),
    // The comparison's own result types are the wire shape: they hold counts,
    // offsets, and digests, with nothing a document could usefully reshape.
    AnalysisHunkDiff(crate::response::HunkDiffResult),
    AnalysisHunkDiffExport(HunkDiffExportDocument),
    SourceCarve(CarveDocument),
    // The decode's own result is the wire shape: offsets, sizes, and typed
    // field values, with nothing a document could usefully reshape.
    AnalysisTableDecode(crate::response::TableDecodeResult),
    // Likewise: counts, offsets and typed values, already in the wire shape.
    AnalysisTableSummarize(crate::response::TableSummarizeResult),
    AudioSampleDecode(crate::response::AudioSampleResult),
    AudioSampleExport(AudioSampleExportDocument),
    // Both compress results are already the wire shape: counts, offsets, and
    // digests, plus a `WritePlan` that serializes as the wire wants it.
    CompressDecode(crate::response::CompressDecodeResult),
    CompressExport(crate::response::CompressExportResult),
    // Likewise for the raw-PCM and tracker-module pairs: envelopes, counts,
    // digests, and a `WritePlan` that already serializes as the wire wants it.
    AudioPcmDecode(crate::response::PcmDecodeResult),
    AudioPcmExport(crate::response::PcmExportResult),
    AudioModuleDecode(crate::response::ModuleResult),
    AudioModuleExport(crate::response::ModuleExportResult),
    AnalysisHunkNormalize(crate::response::HunkNormalizeResult),
    AnalysisHunkNormalizeExport(crate::response::HunkNormalizeExportResult),
    ProvenanceManifest(crate::response::ManifestResult),
    ProvenanceManifestExport(crate::response::ManifestExportResult),
    GraphicsPaletteDecode(crate::response::PaletteResult),
    GraphicsPaletteExport(crate::response::PaletteExportResult),
    EnvSandboxRun(crate::response::SandboxRunResult),
    EnvBootInfo(crate::response::BootInfoResult),
    EnvSandboxCall(crate::response::SandboxCallResult),
    EnvSandboxCallExport(crate::response::SandboxCallExportResult),
    EnvSandboxMatrix(crate::response::SandboxMatrixResult),
    EnvSandboxTimeline(crate::response::SandboxTimelineResult),
    EnvSandboxTimelineExport(crate::response::SandboxTimelineExportResult),
    EnvSandboxSlice(crate::response::SandboxSliceResult),
    EnvFrameCapture(crate::response::FrameCaptureResult),
    EnvFrameCaptureExport(crate::response::FrameCaptureExportResult),
    EnvSandboxCompare(crate::response::SandboxCompareResult),
    EnvSandboxMatrixExport(crate::response::SandboxMatrixExportResult),
    EnvBootTrace(crate::response::BootTraceResult),
    EnvBootTraceExport(crate::response::BootTraceExportResult),
    AnalysisHunkList(crate::response::HunkListResult),
    AnalysisStringsScan(crate::response::StringsScanResult),
    AnalysisAddressResolve(crate::response::AddressResolveResult),
    AnalysisPointersScan(crate::response::PointerScanResult),
    AnalysisCodeDisassemble(crate::response::CodeDisassembleResult),
    AnalysisAddressReferences(crate::response::AddressReferencesResult),
    AnalysisCodeCallgraph(crate::response::CodeCallgraphResult),
    AnalysisCodeGlobals(crate::response::CodeGlobalsResult),
    AnalysisCodeFixedPoint(crate::response::CodeFixedPointResult),
    AnalysisStateSnapshot(crate::response::StateSnapshotResult),
    AnalysisStateCompare(crate::response::StateCompareResult),
    ContainerLhaList(crate::response::LhaListResult),
    HardwareRegisterList(crate::response::HardwareRegisterListResult),
    AudioPcmScan(crate::response::PcmScanResult),
    AudioModuleScan(crate::response::ModuleScanResult),
    GraphicsPaletteScan(crate::response::PaletteScanResult),
    HardwareCopperScan(crate::response::CopperScanResult),
    HardwareCopperDecode(crate::response::CopperDecodeResult),
    GraphicsIlbmDecode(crate::response::IlbmDecodeResult),
    GraphicsBitmapDetect(crate::response::BitmapDetectResult),
    HardwareRegisterReferences(crate::response::RegisterReferencesResult),
    HardwareCopperReferences(crate::response::CopperReferencesResult),
    ProjectDescribe(crate::response::ProjectDescribeResult),
    ProjectAnnotations(crate::response::ProjectAnnotationsResult),
    ProjectInventory(crate::response::ProjectInventoryResult),
    ProjectEdit(crate::response::ProjectEditResult),
    ProjectFormat(crate::response::ProjectFormatResult),
    ProjectMigrate(crate::response::ProjectMigrateResult),
    ProjectInit(crate::response::ProjectInitResult),
    ProjectExtract(crate::response::ProjectExtractResult),
    ProjectResourceExport(crate::response::ResourceExportResult),
    AnalysisCodeFacts(crate::response::CodeFactsResult),
    SourceRead(crate::response::SourceReadResult),
}

/// The `audio.sample.export` payload.
#[derive(Clone, Debug, Serialize)]
pub struct AudioSampleExportDocument {
    pub sample: crate::response::AudioSampleResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

impl From<&crate::response::AudioSampleExportResult> for AudioSampleExportDocument {
    fn from(result: &crate::response::AudioSampleExportResult) -> Self {
        Self {
            sample: result.sample.clone(),
            plan: result.plan.clone(),
            committed: result.committed,
        }
    }
}

/// The `source.carve` payload.
#[derive(Clone, Debug, Serialize)]
pub struct CarveDocument {
    pub source: SourcePinDocument,
    pub offset: u64,
    pub length: u64,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

impl From<&crate::response::CarveResult> for CarveDocument {
    fn from(result: &crate::response::CarveResult) -> Self {
        Self {
            source: SourcePinDocument {
                size: result.source.size,
                sha256: result.source.sha256.clone(),
            },
            offset: result.offset,
            length: result.length,
            plan: result.plan.clone(),
            committed: result.committed,
        }
    }
}

/// The `analysis.hunk.diff.export` payload.
#[derive(Clone, Debug, Serialize)]
pub struct HunkDiffExportDocument {
    pub a: SourcePinDocument,
    pub b: SourcePinDocument,
    pub identical: bool,
    pub changed_hunks: usize,
    pub format: crate::request::HunkDiffFormat,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

impl From<&HunkDiffExportResult> for HunkDiffExportDocument {
    fn from(result: &HunkDiffExportResult) -> Self {
        Self {
            a: SourcePinDocument {
                size: result.a.size,
                sha256: result.a.sha256.clone(),
            },
            b: SourcePinDocument {
                size: result.b.size,
                sha256: result.b.sha256.clone(),
            },
            identical: result.identical,
            changed_hunks: result.changed_hunks,
            format: result.format,
            plan: result.plan.clone(),
            committed: result.committed,
        }
    }
}

/// The `graphics.bitmap.export` payload.
#[derive(Clone, Debug, Serialize)]
pub struct BitmapExportDocument {
    pub source: SourcePinDocument,
    pub width: usize,
    pub height: usize,
    /// The RGB4 colors the PNG was written with, including the grayscale ramp
    /// an export with no palette argument fell back to.
    pub palette: Vec<u16>,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

impl From<&BitmapExportResult> for BitmapExportDocument {
    fn from(result: &BitmapExportResult) -> Self {
        Self {
            source: SourcePinDocument {
                size: result.source.size,
                sha256: result.source.sha256.clone(),
            },
            width: result.width,
            height: result.height,
            palette: result.palette.clone(),
            plan: result.plan.clone(),
            committed: result.committed,
        }
    }
}

/// A container extraction's payload.
///
/// `WritePlan` already serializes exactly as the wire wants it, so this adds
/// only what the plan does not carry: which bytes it was derived from, and
/// whether it was committed.
#[derive(Clone, Debug, Serialize)]
pub struct ContainerExtractDocument {
    pub source: SourcePinDocument,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
    pub unreadable: Vec<crate::response::UnreadableMember>,
}

impl From<&ContainerExtractResult> for ContainerExtractDocument {
    fn from(result: &ContainerExtractResult) -> Self {
        Self {
            source: SourcePinDocument {
                size: result.source.size,
                sha256: result.source.sha256.clone(),
            },
            plan: result.plan.clone(),
            committed: result.committed,
            unreadable: result.unreadable.clone(),
        }
    }
}

/// The `graphics.bitmap.decode` payload.
///
/// `indices` and `opaque` are hex strings rather than JSON arrays. One byte per
/// pixel as `[0,0,1,...]` costs several characters per pixel and is unreadable
/// at any real size; hex is compact, and the pixel count is already bounded by
/// `maximum_output_pixels`.
#[derive(Clone, Debug, Serialize)]
pub struct BitmapDecodeDocument {
    pub source: SourcePinDocument,
    pub width: usize,
    pub height: usize,
    pub planes: u8,
    /// One palette index per pixel, row-major, hex-encoded.
    pub indices: String,
    /// `bob` only: `01` where a pixel is opaque and `00` where it is not, in
    /// the same order as `indices`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
}

impl From<&BitmapDecodeResult> for BitmapDecodeDocument {
    fn from(result: &BitmapDecodeResult) -> Self {
        Self {
            source: SourcePinDocument {
                size: result.source.size,
                sha256: result.source.sha256.clone(),
            },
            width: result.width,
            height: result.height,
            planes: result.planes,
            indices: hex_encode(&result.indices),
            opaque: result.opaque.as_ref().map(|mask| {
                hex_encode(
                    &mask
                        .iter()
                        .map(|opaque| u8::from(*opaque))
                        .collect::<Vec<u8>>(),
                )
            }),
        }
    }
}

/// Lowercase hex, written here rather than pulled in as a dependency: the
/// crate needs exactly this and nothing else the encoding crates offer.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

impl From<&OperationResult> for ResultDocument {
    fn from(result: &OperationResult) -> Self {
        match result {
            OperationResult::SourceSurvey(survey) => Self::SourceSurvey(survey.into()),
            OperationResult::ContainerAdfList(listing) => Self::ContainerAdfList(listing.into()),
            OperationResult::GraphicsBitmapDecode(decode) => {
                Self::GraphicsBitmapDecode(decode.into())
            }
            OperationResult::ContainerExtract(extract) => Self::ContainerExtract(extract.into()),
            OperationResult::GraphicsBitmapExport(export) => {
                Self::GraphicsBitmapExport(export.into())
            }
            OperationResult::GraphicsBitmapCompare(compare) => {
                Self::GraphicsBitmapCompare(compare.clone())
            }
            OperationResult::GraphicsBitmapCompareExport(export) => {
                Self::GraphicsBitmapCompareExport(export.clone())
            }
            OperationResult::ProjectCheck(check) => Self::ProjectCheck(check.clone()),
            OperationResult::ProjectVerify(verify) => Self::ProjectVerify(verify.clone()),
            OperationResult::AnalysisHunkDiff(diff) => Self::AnalysisHunkDiff(diff.clone()),
            OperationResult::AnalysisHunkDiffExport(export) => {
                Self::AnalysisHunkDiffExport(export.into())
            }
            OperationResult::SourceCarve(carve) => Self::SourceCarve(carve.into()),
            OperationResult::AnalysisTableDecode(table) => Self::AnalysisTableDecode(table.clone()),
            OperationResult::AnalysisTableSummarize(table) => {
                Self::AnalysisTableSummarize(table.clone())
            }
            OperationResult::AudioSampleDecode(sample) => Self::AudioSampleDecode(sample.clone()),
            OperationResult::AudioSampleExport(export) => Self::AudioSampleExport(export.into()),
            OperationResult::CompressDecode(decoded) => Self::CompressDecode(decoded.clone()),
            OperationResult::CompressExport(export) => Self::CompressExport(export.clone()),
            OperationResult::AudioPcmDecode(pcm) => Self::AudioPcmDecode(pcm.clone()),
            OperationResult::AudioPcmExport(export) => Self::AudioPcmExport(export.clone()),
            OperationResult::AudioModuleDecode(module) => Self::AudioModuleDecode(module.clone()),
            OperationResult::AudioModuleExport(export) => Self::AudioModuleExport(export.clone()),
            OperationResult::AnalysisHunkNormalize(normalized) => {
                Self::AnalysisHunkNormalize(normalized.clone())
            }
            OperationResult::AnalysisHunkNormalizeExport(export) => {
                Self::AnalysisHunkNormalizeExport(export.clone())
            }
            OperationResult::ProvenanceManifest(manifest) => {
                Self::ProvenanceManifest(manifest.clone())
            }
            OperationResult::ProvenanceManifestExport(export) => {
                Self::ProvenanceManifestExport(export.clone())
            }
            OperationResult::GraphicsPaletteDecode(palette) => {
                Self::GraphicsPaletteDecode(palette.clone())
            }
            OperationResult::GraphicsPaletteExport(export) => {
                Self::GraphicsPaletteExport(export.clone())
            }
            OperationResult::EnvSandboxRun(run) => Self::EnvSandboxRun(run.clone()),
            OperationResult::EnvBootInfo(info) => Self::EnvBootInfo(info.clone()),
            OperationResult::EnvSandboxCall(record) => Self::EnvSandboxCall(record.clone()),
            OperationResult::EnvSandboxMatrix(matrix) => Self::EnvSandboxMatrix(matrix.clone()),
            OperationResult::EnvSandboxTimeline(timeline) => {
                Self::EnvSandboxTimeline(timeline.clone())
            }
            OperationResult::EnvSandboxTimelineExport(export) => {
                Self::EnvSandboxTimelineExport(export.clone())
            }
            OperationResult::EnvSandboxSlice(slice) => Self::EnvSandboxSlice(slice.clone()),
            OperationResult::EnvFrameCapture(frame) => Self::EnvFrameCapture(frame.clone()),
            OperationResult::EnvFrameCaptureExport(export) => {
                Self::EnvFrameCaptureExport(export.clone())
            }
            OperationResult::EnvSandboxCompare(compare) => Self::EnvSandboxCompare(compare.clone()),
            OperationResult::EnvSandboxMatrixExport(export) => {
                Self::EnvSandboxMatrixExport(export.clone())
            }
            OperationResult::EnvSandboxCallExport(export) => {
                Self::EnvSandboxCallExport(export.clone())
            }
            OperationResult::AnalysisHunkList(list) => Self::AnalysisHunkList(list.clone()),
            OperationResult::AnalysisStringsScan(scan) => Self::AnalysisStringsScan(scan.clone()),
            OperationResult::AnalysisAddressResolve(resolved) => {
                Self::AnalysisAddressResolve(resolved.clone())
            }
            OperationResult::AnalysisPointersScan(scan) => Self::AnalysisPointersScan(scan.clone()),
            OperationResult::AnalysisCodeDisassemble(disassembled) => {
                Self::AnalysisCodeDisassemble(disassembled.clone())
            }
            OperationResult::AnalysisAddressReferences(references) => {
                Self::AnalysisAddressReferences(references.clone())
            }
            OperationResult::AnalysisCodeCallgraph(graph) => {
                Self::AnalysisCodeCallgraph(graph.clone())
            }
            OperationResult::AnalysisCodeGlobals(globals) => {
                Self::AnalysisCodeGlobals(globals.clone())
            }
            OperationResult::AnalysisCodeFixedPoint(fixed) => {
                Self::AnalysisCodeFixedPoint(fixed.clone())
            }
            OperationResult::AnalysisStateSnapshot(snapshot) => {
                Self::AnalysisStateSnapshot(snapshot.clone())
            }
            OperationResult::AnalysisStateCompare(compare) => {
                Self::AnalysisStateCompare(compare.clone())
            }
            OperationResult::ContainerLhaList(list) => Self::ContainerLhaList(list.clone()),
            OperationResult::HardwareRegisterList(list) => Self::HardwareRegisterList(list.clone()),
            OperationResult::AudioPcmScan(scan) => Self::AudioPcmScan(scan.clone()),
            OperationResult::AudioModuleScan(scan) => Self::AudioModuleScan(scan.clone()),
            OperationResult::GraphicsPaletteScan(scan) => Self::GraphicsPaletteScan(scan.clone()),
            OperationResult::HardwareCopperScan(scan) => Self::HardwareCopperScan(scan.clone()),
            OperationResult::HardwareCopperDecode(decode) => {
                Self::HardwareCopperDecode(decode.clone())
            }
            OperationResult::GraphicsIlbmDecode(decode) => Self::GraphicsIlbmDecode(decode.clone()),
            OperationResult::GraphicsBitmapDetect(detect) => {
                Self::GraphicsBitmapDetect(detect.clone())
            }
            OperationResult::HardwareRegisterReferences(references) => {
                Self::HardwareRegisterReferences(references.clone())
            }
            OperationResult::HardwareCopperReferences(references) => {
                Self::HardwareCopperReferences(references.clone())
            }
            OperationResult::ProjectDescribe(described) => Self::ProjectDescribe(described.clone()),
            OperationResult::ProjectAnnotations(annotations) => {
                Self::ProjectAnnotations(annotations.clone())
            }
            OperationResult::ProjectInventory(inventory) => {
                Self::ProjectInventory(inventory.clone())
            }
            OperationResult::ProjectEdit(edit) => Self::ProjectEdit(edit.clone()),
            OperationResult::ProjectFormat(format) => Self::ProjectFormat(format.clone()),
            OperationResult::ProjectInit(init) => Self::ProjectInit(init.clone()),
            OperationResult::ProjectExtract(extract) => Self::ProjectExtract(extract.clone()),
            OperationResult::ProjectResourceExport(export) => {
                Self::ProjectResourceExport(export.clone())
            }
            OperationResult::ProjectMigrate(migrate) => Self::ProjectMigrate(migrate.clone()),
            OperationResult::AnalysisCodeFacts(facts) => Self::AnalysisCodeFacts(facts.clone()),
            OperationResult::SourceRead(read) => Self::SourceRead(read.clone()),
            OperationResult::EnvBootTrace(trace) => Self::EnvBootTrace(trace.clone()),
            OperationResult::EnvBootTraceExport(export) => Self::EnvBootTraceExport(export.clone()),
        }
    }
}

/// The bytes the operation read.
#[derive(Clone, Debug, Serialize)]
pub struct SourcePinDocument {
    pub size: u64,
    pub sha256: String,
}

/// The `source.survey` payload.
#[derive(Clone, Debug, Serialize)]
pub struct SourceSurveyDocument {
    pub source: SourcePinDocument,
    pub regions: Vec<SurveyRegionDocument>,
    pub region_total: usize,
    pub regions_truncated: bool,
    pub copper_lists: Vec<amiga_hw::CopperList>,
}

impl From<&SourceSurveyResult> for SourceSurveyDocument {
    fn from(result: &SourceSurveyResult) -> Self {
        Self {
            source: SourcePinDocument {
                size: result.source.size,
                sha256: result.source.sha256.clone(),
            },
            regions: result
                .regions
                .iter()
                .map(SurveyRegionDocument::from)
                .collect(),
            region_total: result.region_total,
            regions_truncated: result.regions_truncated,
            copper_lists: result.copper_lists.clone(),
        }
    }
}

/// One typed region in source-offset order.
///
/// `entropy` and `palette` are emitted even when absent: a consumer reading
/// them positionally must see that the field was considered and did not apply.
#[derive(Clone, Debug, Serialize)]
pub struct SurveyRegionDocument {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    pub detail: String,
    pub entropy: Option<f32>,
    pub palette: Option<Vec<u16>>,
}

/// The `container.adf.list` payload.
#[derive(Clone, Debug, Serialize)]
pub struct AdfListDocument {
    pub source: SourcePinDocument,
    pub volume: AdfVolumeDocument,
    pub entries: Vec<AdfEntryDocument>,
    pub entry_total: usize,
    pub entries_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdfVolumeDocument {
    pub name: String,
    pub filesystem: &'static str,
    pub block_size: u32,
    pub root_block: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdfEntryDocument {
    pub path: String,
    pub kind: &'static str,
    pub size: u32,
    pub header_block: u32,
}

impl From<&AdfListResult> for AdfListDocument {
    fn from(result: &AdfListResult) -> Self {
        Self {
            source: SourcePinDocument {
                size: result.source.size,
                sha256: result.source.sha256.clone(),
            },
            volume: AdfVolumeDocument {
                name: result.volume.name.clone(),
                filesystem: result.volume.filesystem,
                block_size: result.volume.block_size,
                root_block: result.volume.root_block,
            },
            entries: result
                .entries
                .iter()
                .map(|entry| AdfEntryDocument {
                    path: entry.path.clone(),
                    kind: entry.kind.as_str(),
                    size: entry.size,
                    header_block: entry.header_block,
                })
                .collect(),
            entry_total: result.entry_total,
            entries_truncated: result.entries_truncated,
        }
    }
}

impl From<&amiga_analysis::SurveyRegion> for SurveyRegionDocument {
    fn from(region: &amiga_analysis::SurveyRegion) -> Self {
        Self {
            start: region.start,
            end: region.end,
            kind: region.kind.as_str(),
            detail: region.detail.clone(),
            entropy: region.entropy,
            palette: region.palette.clone(),
        }
    }
}
