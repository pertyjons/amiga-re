//! The typed operation API for the amiga-re CLI and downstream tools.
//!
//! One request vocabulary, one router, one result shape. The CLI parses its inputs and
//! renders its outputs; this crate executes the operation with shared defaults, limits,
//! and diagnostics that downstream tools can also use directly.
//!
//! Two API levels exist and are deliberately distinct:
//!
//! 1. the in-process Rust API — [`protocol::RequestEnvelope`],
//!    [`context::ExecutionContext`], [`router::Router`], and
//!    [`response::OperationOutcome`];
//! 2. the JSON protocol — the serialized shapes in [`protocol`], [`request`],
//!    and [`document`], versioned by [`protocol::PROTOCOL_VERSION`] and
//!    documented by the Draft 2020-12 schemas bundled in [`descriptor::schemas`].
//!
//! [`descriptor::catalog`] is metadata over the statically compiled request
//! enum, not a runtime registry: adding an operation without deciding its
//! summary, access class, and schemas does not compile.
//!
//! Wire types carry serde and a protocol version; the normalized internal
//! request in [`normalize`](mod@normalize) carries neither. Keeping them apart is what lets
//! internals be refactored without moving a serialized field.
//!
//! ```
//! use amiga_operations::{
//!     ExecutionContext, InMemorySourceResolver, OperationRequestDocument, RequestEnvelope,
//!     ResolvedSource, Router, SourceName, SourceSurveyArguments,
//! };
//!
//! let name = SourceName::parse("sample.bin").expect("a relative name");
//! let resolver = InMemorySourceResolver::new(ResolvedSource::new(
//!     name,
//!     std::sync::Arc::from(b"HELLO WORLD".as_slice()),
//! ));
//! let context = ExecutionContext::new(&resolver);
//! let request = RequestEnvelope::read(OperationRequestDocument::SourceSurvey(
//!     SourceSurveyArguments::new("sample.bin"),
//! ));
//!
//! let outcome = Router::execute(&request, &context);
//! let survey = outcome.source_survey().expect("the survey ran");
//! assert_eq!(survey.source.size, 11);
//! ```

pub mod context;
pub mod descriptor;
pub mod diagnostics;
pub mod document;
pub mod events;
pub mod limits;
pub mod local;
pub mod normalize;
mod operations;
pub mod output;
pub mod protocol;
pub mod record_type;
pub mod recovery;
pub mod reference;
pub mod request;
pub mod response;
pub mod router;
pub mod sandbox_recipe;
pub mod source;
pub mod stream;

/// The canonical name of a project's root document.
///
/// Re-exported rather than spelled again. Recognising a project directory is
/// the format's question, not a frontend's, and two spellings of one file name
/// is how a frontend comes to look for a project this toolkit does not write.
pub const PROJECT_ROOT_DOCUMENT: &str = amiga_project::load::ROOT_FILE_NAME;

/// The root document at or above `start`, for an adapter deciding which
/// project a file it was handed belongs to.
///
/// The format's own walk, re-exported for the same reason the file name is: an
/// adapter that implemented the search itself would eventually search
/// differently from the loader that has to find the same project.
pub use amiga_project::discover as discover_project;

/// Which member of a container, in the project format's own vocabulary.
///
/// Re-exported because [`SourceLocator::member`] takes one: an adapter that can
/// name a member in a request would otherwise have to depend on the format crate
/// to spell the name.
pub use amiga_project::document::Selector;

pub use context::ExecutionContext;
pub use descriptor::{AccessClass, OperationDescriptor, catalog, descriptor};
pub use diagnostics::{Diagnostic, DiagnosticCode, Severity};
pub use document::ResponseEnvelope;
pub use events::{BoundedSink, CollectingSink, EventSink, MAX_EVENTS, NoEvents, OperationEvent};
pub use limits::{
    DEFAULT_MAXIMUM_OUTPUT_BYTES, DEFAULT_SURVEY_MIN_STRING_LENGTH,
    MAXIMUM_SANDBOX_BLIT_WORDS_CEILING, MAXIMUM_SANDBOX_STEPS_CEILING, OperationLimits,
};
pub use local::load_bindings;
pub use normalize::{
    ContainerKind, Normalized, NormalizedAddressReferences, NormalizedAddressResolve,
    NormalizedAdfList, NormalizedAudioSample, NormalizedAudioSampleExport, NormalizedBitmapCompare,
    NormalizedBitmapCompareExport, NormalizedBitmapDecode, NormalizedBitmapExport,
    NormalizedBlitterMode, NormalizedBootInfo, NormalizedBootTrace, NormalizedBootTraceExport,
    NormalizedCarve, NormalizedCodeCallgraph, NormalizedCodeDisassemble,
    NormalizedContainerExtract, NormalizedCustomChips, NormalizedFrameCapture,
    NormalizedFrameCaptureExport, NormalizedHunkAnchor, NormalizedHunkDiff,
    NormalizedHunkDiffExport, NormalizedHunkList, NormalizedHunkNormalize,
    NormalizedHunkNormalizeExport, NormalizedManifest, NormalizedManifestExport,
    NormalizedMatrixCase, NormalizedMode, NormalizedModule, NormalizedModuleExport,
    NormalizedOperation, NormalizedPalette, NormalizedPaletteExport, NormalizedPcm,
    NormalizedPcmExport, NormalizedPointerScan, NormalizedPowerpacker, NormalizedPowerpackerExport,
    NormalizedRequest, NormalizedRleXor, NormalizedRleXorExport, NormalizedSandboxCall,
    NormalizedSandboxCallExport, NormalizedSandboxMatrix, NormalizedSandboxRun,
    NormalizedSandboxSlice, NormalizedSandboxTimeline, NormalizedSource, NormalizedSourceSurvey,
    NormalizedStateCompare, NormalizedStateSnapshot, NormalizedStringsScan, NormalizedTableDecode,
    NormalizedTimelineStep, normalize,
};
pub use output::{
    DestinationError, DestinationName, DestinationResolver, FilesystemDestinationResolver,
    NoDestinations, OutputPolicy, PlannedOutput, WritePlan,
};
pub use protocol::{
    EventMode, ExecutionMode, ExecutionOptions, PROTOCOL_VERSION, ProjectLocator, RequestEnvelope,
    Status,
};
pub use recovery::ContainerRecovery;
pub use request::{
    AddressReferencesArguments, AddressResolveArguments, AdfListArguments, AudioSampleArguments,
    AudioSampleExportArguments, BitmapCompareArguments, BitmapCompareExportArguments,
    BitmapDecodeArguments, BitmapDetectArguments, BitmapExportArguments, BitmapShape, BlitterDma,
    BlitterMode, BlitterOptions, BobMask, BootInfoArguments, BootTraceArguments,
    BootTraceExportArguments, CarveArguments, Chipset, CodeCallgraphArguments,
    CodeDisassembleArguments, CodeDisassembleMode, CodeFactsArguments, CodeFixedPointArguments,
    CodeGlobalsArguments, CodeRegion, ComparedBitmap, ContainerExtractArguments,
    CopperDecodeArguments, CopperReferencesArguments, CopperScanArguments, CopperTemplate,
    CustomChips, FrameCaptureArguments, FrameCaptureExportArguments, HardwareRegisterListArguments,
    HunkAnchor, HunkBase, HunkDiffArguments, HunkDiffExportArguments, HunkDiffFormat,
    HunkListArguments, HunkNormalizeArguments, HunkNormalizeExportArguments, IlbmDecodeArguments,
    InterruptFrame, LhaListArguments, LibraryVector, ManifestArguments, ManifestExportArguments,
    MappedRegion, MediaPolicy, MemoryExport, MemorySeed, ModuleArguments, ModuleExportArguments,
    ModuleScanArguments, OperationName, OperationRequestDocument, PaletteArguments,
    PaletteExportArguments, PaletteScanArguments, PcmArguments, PcmExportArguments,
    PcmScanArguments, PixelOffset, PixelRect, PlaneOrder, PointerScanArguments,
    PowerpackerArguments, PowerpackerExportArguments, ProjectAnnotationsArguments,
    ProjectArguments, ProjectEdit, ProjectEditArguments, ProjectEditTarget,
    ProjectExtractArguments, ProjectInitArguments, ProjectInventoryArguments,
    ProjectMigrateArguments, RegisterReferencesArguments, ResourceExportArguments, RleXorArguments,
    RleXorExportArguments, SandboxCallArguments, SandboxCallExportArguments,
    SandboxCompareArguments, SandboxMatrixArguments, SandboxMatrixCase,
    SandboxMatrixExportArguments, SandboxRunArguments, SandboxSliceArguments,
    SandboxTimelineArguments, SandboxTimelineExportArguments, ScheduledInterrupt, SeedArtifact,
    SeedRange, SliceSeedArgument, SourceLocator, SourceReadArguments, SourceSurveyArguments,
    StackRegion, StateCompareArguments, StateRegion, StateSnapshotArguments, StringsScanArguments,
    TableDecodeArguments, TableSummarizeArguments, TimelineStep, ValidityMask, VectorArgument,
    WatchAccess, WatchRange,
};
pub use response::{
    AbsoluteGlobalAccess, AccessDirection, AddressFrames, AddressReferencesResult,
    AddressResolveResult, AdfEntry, AdfEntryKind, AdfListResult, AdfVolume, AnnotatedRange,
    AudioSampleExportResult, AudioSampleResult, BaseRelativeAccess, BitmapCompareExportResult,
    BitmapCompareResult, BitmapDecodeResult, BitmapDetectResult, BitmapExportResult, BootExecCall,
    BootInfoResult, BootTraceExportResult, BootTraceResult, ByteRangeReport, CallgraphEdge,
    CallgraphNode, CarrierReport, CarveResult, ChipWrite, ClampHint, ClampKind, CodeCallEdge,
    CodeCallgraphResult, CodeCoverage, CodeDisassembleResult, CodeExternalFlow, CodeExternalKind,
    CodeFactsResult, CodeFixedPointResult, CodeFlowEdge, CodeFlowFacts, CodeFlowKind,
    CodeGlobalsResult, CodeReference, CodeUnresolvedFlow, CompareDifference, ComparedRecord,
    ComparedSnapshot, CompressDecodeResult, CompressExportResult, ContainerExtractResult,
    CopperBitplanePointer, CopperChange, CopperDecodeResult, CopperEffectiveList,
    CopperInstruction, CopperListSummary, CopperOp, CopperPalette, CopperPatchSite,
    CopperPatchWrite, CopperReferencesResult, CopperScanResult, CopperWord, DerivedGlobalAccess,
    DerivedTarget, DisassembledInstruction, DivergentStep, EditedDocument, EntropyBlock,
    ExtractedObject, FixedPointHint, FixedPointKind, FixedPointScale, FormattedDocument,
    FoundString, FrameCaptureExportResult, FrameCaptureResult, FrameInterval, FrameRegisters,
    GeometryCandidate, GlobalAccessKind, HardwareRegister, HardwareRegisterListResult,
    HunkDiffEntry, HunkDiffExportResult, HunkDiffResult, HunkListResult, HunkNormalizeExportResult,
    HunkNormalizeResult, HunkPresence, HunkRelocation, HunkSegment, IlbmDecodeResult, IlbmMasking,
    InitializedSource, InventoryFile, LhaListResult, LhaMember, LocalStorage, ManifestExportResult,
    ManifestResult, MatrixCaseOutcome, MatrixRegionDigest, ModuleExportResult, ModuleResult,
    ModuleSample, ModuleScanResult, OperationOutcome, OperationResult, PaletteExportResult,
    PaletteResult, PaletteScanResult, PaletteTable, PcmDecodeResult, PcmExportResult, PcmRegion,
    PcmScanResult, PixelSourceComparison, PointerEncoding, PointerScanResult, PointerTable,
    ProjectAnnotationsResult, ProjectArtifact, ProjectCheckResult, ProjectDescribeResult,
    ProjectEditResult, ProjectExtractResult, ProjectFormatResult, ProjectInitResult,
    ProjectInventoryResult, ProjectObject, ProjectResource, ProjectResourceTarget, ProjectSource,
    ProjectVerifyResult, ReferenceKind, RegionClass, RegisterAccessForm, RegisterReference,
    RegisterReferencesResult, RelocationReport, ResourceExportResult, SandboxAccess, SandboxBlit,
    SandboxBlitRefusal, SandboxBlitterConfig, SandboxCallExportResult, SandboxCallResult,
    SandboxChipObservation, SandboxCompareResult, SandboxCustomChips, SandboxExportResult,
    SandboxInterruptDelivery, SandboxMatrixCaseResult, SandboxMatrixExportResult,
    SandboxMatrixResult, SandboxRegionResult, SandboxRegisterDelta, SandboxRegisters,
    SandboxRunResult, SandboxSeedOrigin, SandboxSeedResult, SandboxStep, SandboxStop,
    SandboxTimelineExportResult, SandboxTimelineResult, SandboxTimelineStepResult, SandboxWrite,
    ServedRead, SliceStepResult, SliceStopResult, SourcePin, SourceReadResult, SourceSurveyResult,
    StateCompareResult, StateDifference, StateField, StateRegionPin, StateSnapshotResult,
    StateValue, StringsScanResult, SupersededArtifact, TableColumnComparison, TableColumnSummary,
    TableDecodeResult, TableField, TableRow, TableRowDifference, TableSummarizeResult,
    TableSummary, TableValueCount, TimelineCheckpoint, TimelineStepOutcome, TraceComparison,
    TraceDivergence, UnreachedRun, UnreadableMember, VerifiedArtifact, VerifiedEntity,
    WaveformBucket,
};
pub use router::Router;
pub use source::{
    FilesystemSourceResolver, InMemorySourceResolver, ResolvedSource, SourceError, SourceName,
    SourceNameError, SourceResolver, split_host_path, split_host_paths,
};
pub use stream::{AcceptedMessage, StreamMessage, execute_streaming};
