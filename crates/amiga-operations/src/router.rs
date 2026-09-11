//! Exhaustive dispatch from a request to the handler that serves it.

use crate::context::ExecutionContext;
use crate::events::{BoundedSink, EventSink, NoEvents, OperationEvent};
use crate::normalize::{NormalizedOperation, NormalizedRequest, normalize};
use crate::operations::{
    address_references, address_resolve, adf_list, audio_raw, audio_sample, audio_scan,
    bitmap_decode, bitmap_export, carve, code_callgraph, code_disassemble, code_facts,
    code_fixed_point, code_globals, compress, container_extract, copper_references,
    graphics_detect, graphics_scan, hardware_registers, hunk_diff, hunk_list, lha_list, palette,
    pointers_scan, project, project_edit, project_extract, project_init, project_resource_export,
    provenance, register_references, sandbox, source_read, source_survey, strings_scan,
    table_decode, table_summarize,
};
use crate::protocol::RequestEnvelope;
use crate::response::OperationOutcome;

/// Executes requests. Stateless: everything an operation needs arrives through
/// its request and its [`ExecutionContext`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Router;

impl Router {
    /// Validate, normalize, and execute `envelope`.
    ///
    /// A refused request never reaches a handler, so no source is opened and no
    /// work is scheduled for a request that cannot run.
    #[must_use]
    pub fn execute(envelope: &RequestEnvelope, context: &ExecutionContext<'_>) -> OperationOutcome {
        Self::execute_with_events(envelope, context, &mut NoEvents)
    }

    /// Validate, normalize, and execute `envelope`, reporting progress to
    /// `events` as the operation reaches its own phase boundaries.
    ///
    /// The sink is passed here rather than held on the context because a
    /// context is immutable for the duration of an execution and a sink is not.
    /// Every event is delivered before the returned outcome, so a consumer may
    /// treat the response as the end of the exchange.
    #[must_use]
    pub fn execute_with_events(
        envelope: &RequestEnvelope,
        context: &ExecutionContext<'_>,
        events: &mut dyn EventSink,
    ) -> OperationOutcome {
        // Bounded here, once, so no handler can forget the budget and the
        // truncation notice is emitted in exactly one place.
        let mut events = BoundedSink::new(events);
        match normalize(envelope, context.limits()) {
            Ok(normalized) => Self::execute_normalized_with(
                &normalized.request,
                context,
                normalized.diagnostics,
                &mut events,
            ),
            // A refused request never started, so it reports no events either:
            // the response's diagnostics are the whole story.
            Err(diagnostics) => {
                OperationOutcome::refused(envelope.request.operation_name(), diagnostics)
            }
        }
    }

    /// Execute an already-normalized request.
    ///
    /// The in-process entry point for callers that built a request in Rust and
    /// have nothing to validate.
    #[must_use]
    pub fn execute_normalized(
        request: &NormalizedRequest,
        context: &ExecutionContext<'_>,
    ) -> OperationOutcome {
        Self::execute_normalized_with(
            request,
            context,
            Vec::new(),
            &mut BoundedSink::new(&mut NoEvents),
        )
    }

    pub(crate) fn execute_normalized_with(
        request: &NormalizedRequest,
        context: &ExecutionContext<'_>,
        diagnostics: Vec<crate::diagnostics::Diagnostic>,
        events: &mut BoundedSink<'_>,
    ) -> OperationOutcome {
        // Emitted here rather than at each entry point, so every path that
        // executes an operation announces it and the two framings cannot
        // disagree about where a run begins.
        events.emit(OperationEvent::Started {
            operation: request.operation().name(),
        });
        let digest = request.digest();
        if context.cancel().is_cancelled() {
            return OperationOutcome {
                operation: request.operation().name(),
                status: crate::protocol::Status::Cancelled,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
        match request.operation() {
            NormalizedOperation::SourceSurvey(survey) => {
                source_survey::run(survey, context, diagnostics, digest, events)
            }
            NormalizedOperation::ContainerAdfList(listing) => {
                adf_list::run(listing, context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsBitmapDecode(decode) => {
                bitmap_decode::run(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectCheck(project_request) => {
                project::check(project_request, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectInit(init) => {
                project_init::run(init, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectExtract(extract) => project_extract::run(
                extract,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::ProjectResourceExport(export) => project_resource_export::run(
                export,
                context,
                request.mode(),
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::ProjectVerify(project_request) => {
                project::verify(project_request, context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsBitmapExport(export) => {
                bitmap_export::run(export, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsBitmapCompare(compare) => {
                crate::operations::bitmap_compare::run(
                    compare,
                    context,
                    diagnostics,
                    digest,
                    events,
                )
            }
            NormalizedOperation::GraphicsBitmapCompareExport(export) => {
                crate::operations::bitmap_compare::export(
                    export,
                    request.mode(),
                    context,
                    diagnostics,
                    digest,
                    events,
                )
            }
            NormalizedOperation::AnalysisHunkDiff(diff) => {
                hunk_diff::run(diff, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisHunkDiffExport(export) => {
                hunk_diff::export(export, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::AudioSampleDecode(sample) => {
                audio_sample::run(sample, context, diagnostics, digest, events)
            }
            NormalizedOperation::AudioSampleExport(export) => {
                audio_sample::export(export, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisTableDecode(table) => {
                table_decode::run(table, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisTableSummarize(table) => {
                table_summarize::run(table, context, diagnostics, digest, events)
            }
            NormalizedOperation::SourceCarve(request_carve) => carve::run(
                request_carve,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::ContainerExtract(extract) => container_extract::run(
                extract,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::CompressPowerpackerDecode(decode) => {
                compress::powerpacker(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::CompressPowerpackerExport(export) => compress::powerpacker_export(
                export,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::CompressRleXorDecode(decode) => {
                compress::rle_xor(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::CompressRleXorExport(export) => compress::rle_xor_export(
                export,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::AudioPcmDecode(decode) => {
                audio_raw::pcm(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::AudioPcmExport(export) => {
                audio_raw::pcm_export(export, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::AudioModuleDecode(decode) => {
                audio_raw::module(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::AudioModuleExport(export) => audio_raw::module_export(
                export,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::AnalysisHunkNormalize(normalize) => {
                provenance::hunk_normalize(normalize, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisHunkNormalizeExport(export) => {
                provenance::hunk_normalize_export(
                    export,
                    request.mode(),
                    context,
                    diagnostics,
                    digest,
                    events,
                )
            }
            NormalizedOperation::ProvenanceManifest(manifest) => {
                provenance::manifest(manifest, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProvenanceManifestExport(export) => provenance::manifest_export(
                export,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::GraphicsPaletteDecode(decode) => {
                palette::run(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsPaletteExport(export) => {
                palette::export(export, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvSandboxRun(run) => {
                sandbox::run(run, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvBootInfo(info) => {
                sandbox::boot_info(info, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisStringsScan(scan) => {
                strings_scan::run(scan, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisAddressResolve(resolve) => {
                address_resolve::run(resolve, context, diagnostics, digest)
            }
            NormalizedOperation::AnalysisPointersScan(scan) => {
                pointers_scan::run(scan, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisCodeDisassemble(disassemble) => {
                code_disassemble::run(disassemble, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisAddressReferences(references) => {
                address_references::run(references, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisCodeCallgraph(graph) => {
                code_callgraph::run(graph, context, diagnostics, digest, events)
            }
            NormalizedOperation::SourceRead(read) => {
                source_read::run(read, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisCodeFacts(facts) => {
                code_facts::run(facts, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisCodeGlobals(globals) => {
                code_globals::run(globals, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisStateSnapshot(snapshot) => {
                crate::operations::state::snapshot(snapshot, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisStateCompare(compare) => {
                crate::operations::state::compare(compare, context, diagnostics, digest, events)
            }
            NormalizedOperation::AnalysisCodeFixedPoint(fixed) => {
                code_fixed_point::run(fixed, context, diagnostics, digest, events)
            }
            NormalizedOperation::ContainerLhaList(list) => {
                lha_list::run(list, context, diagnostics, digest, events)
            }
            NormalizedOperation::HardwareRegisterList => {
                hardware_registers::run(diagnostics, digest)
            }
            NormalizedOperation::AudioPcmScan(scan) => {
                audio_scan::pcm(scan, context, diagnostics, digest, events)
            }
            NormalizedOperation::AudioModuleScan(scan) => {
                audio_scan::module(scan, context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsPaletteScan(scan) => {
                graphics_scan::palette(scan, context, diagnostics, digest, events)
            }
            NormalizedOperation::HardwareCopperScan(scan) => {
                graphics_scan::copper_scan(scan, context, diagnostics, digest, events)
            }
            NormalizedOperation::HardwareCopperDecode(decode) => {
                graphics_scan::copper_decode(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsIlbmDecode(decode) => {
                graphics_detect::ilbm(decode, context, diagnostics, digest, events)
            }
            NormalizedOperation::GraphicsBitmapDetect(detect) => {
                graphics_detect::detect(detect, context, diagnostics, digest, events)
            }
            NormalizedOperation::HardwareRegisterReferences(references) => {
                register_references::run(references, context, diagnostics, digest, events)
            }
            NormalizedOperation::HardwareCopperReferences(references) => {
                copper_references::run(references, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectDescribe(project) => {
                project::describe(project, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectAnnotations(annotations) => {
                project::annotations(annotations, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectInventory(inventory) => {
                project::inventory(inventory, context, diagnostics, digest, events)
            }
            NormalizedOperation::ProjectEdit(edit) => {
                project_edit::run(edit, context, request.mode(), diagnostics, digest, events)
            }
            NormalizedOperation::ProjectMigrate(migrate) => project_edit::migrate(
                migrate,
                context,
                request.mode(),
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::ProjectFormat(project_request) => project_edit::format(
                project_request,
                context,
                request.mode(),
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::AnalysisHunkList(list) => {
                hunk_list::run(list, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvBootTrace(trace) => {
                sandbox::boot_trace(trace, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvBootTraceExport(export) => sandbox::boot_trace_export(
                export,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::EnvSandboxCall(call) => {
                sandbox::call_run(call, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvSandboxCallExport(export) => {
                sandbox::call_export(export, request.mode(), context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvSandboxMatrix(matrix) => {
                sandbox::matrix(matrix, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvSandboxTimeline(timeline) => {
                sandbox::timeline(timeline, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvSandboxTimelineExport(export) => sandbox::timeline_export(
                export,
                request.mode(),
                context,
                diagnostics,
                digest,
                events,
            ),
            NormalizedOperation::EnvSandboxSlice(slice) => {
                crate::operations::slice::run(slice, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvFrameCapture(capture) => {
                crate::operations::frame::capture(capture, context, diagnostics, digest, events)
            }
            NormalizedOperation::EnvFrameCaptureExport(export) => {
                crate::operations::frame::capture_export(
                    export,
                    request.mode(),
                    context,
                    diagnostics,
                    digest,
                    events,
                )
            }
            NormalizedOperation::EnvSandboxCompare(compare) => {
                crate::operations::sandbox_compare::run(
                    compare,
                    context,
                    diagnostics,
                    digest,
                    events,
                )
            }
            NormalizedOperation::EnvSandboxMatrixExport(export) => {
                sandbox::matrix_export(export, request.mode(), context, diagnostics, digest, events)
            }
        }
    }
}
