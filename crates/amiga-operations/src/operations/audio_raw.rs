//! `audio.pcm.*` and `audio.module.*` — the two audio formats that are not IFF.
//!
//! Raw Paula PCM has no header at all: the region bounds and the playback rate
//! are the caller's claim about bytes that look the same either way. A tracker
//! module has one, but it is found by pattern rather than declared, so its
//! offset is the caller's claim too. Both decodes therefore echo the request
//! back beside a digest of exactly the bytes it selected — which is what makes a
//! guess checkable instead of merely plausible.
//!
//! The PCM decode reports the same bounded min/max envelope as `audio.sample.decode`,
//! giving identical waveform measurements whether samples arrive as 8SVX or raw bytes.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{
    NormalizedMode, NormalizedModule, NormalizedModuleExport, NormalizedPcm, NormalizedPcmExport,
};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    ModuleExportResult, ModuleResult, ModuleSample, OperationOutcome, OperationResult,
    PcmDecodeResult, PcmExportResult, SourcePin, WaveformBucket,
};
use crate::source::SourceError;

pub(crate) fn pcm(
    request: &NormalizedPcm,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, decoded) = decode_pcm(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::AudioPcmDecode,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: decoded.map(|(summary, _)| OperationResult::AudioPcmDecode(summary)),
    }
}

pub(crate) fn module(
    request: &NormalizedModule,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, decoded) = decode_module(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::AudioModuleDecode,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: decoded.map(|(summary, _)| OperationResult::AudioModuleDecode(summary)),
    }
}

pub(crate) fn pcm_export(
    request: &NormalizedPcmExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AudioPcmExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match resolve_destination(context, &request.destination) {
        Ok(path) => path,
        Err(diagnostic) => {
            let mut diagnostics = diagnostics;
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, mut diagnostics, decoded) =
        decode_pcm(&request.decode, context, diagnostics, events);
    let Some((summary, region)) = decoded else {
        return outcome(status, diagnostics, None);
    };

    // The WAV header states the rate the request stated. Nothing in raw PCM
    // could contradict it, which is exactly why the request has to carry it.
    let pcm: Vec<i8> = region
        .iter()
        .map(|byte| i8::from_ne_bytes([*byte]))
        .collect();
    let wav = match amiga_iff::encode_pcm(&pcm, request.decode.sample_rate) {
        Ok(wav) => wav,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AudioEncodeFailed,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::File,
        request.policy,
        vec![PlannedOutput {
            path: request.file_name.clone(),
            size: wav.len() as u64,
            sha256: amiga_core::sha256(&wav),
        }],
        Vec::new(),
    );
    let manifest = serde_json::json!({
        "format_version": 1,
        "operation": OperationName::AudioPcmExport.as_str(),
        "source": { "size": summary.source.size, "sha256": summary.source.sha256 },
        "offset": summary.offset,
        "frames": summary.frames,
        "sample_rate": summary.sample_rate,
        "region_sha256": summary.region_sha256,
        "files": [{ "path": request.file_name, "sha256": amiga_core::sha256(&wav) }],
    });
    let result = move |plan: WritePlan, committed| {
        Some(OperationResult::AudioPcmExport(PcmExportResult {
            pcm: summary.clone(),
            plan,
            committed,
        }))
    };

    commit(
        &plan,
        mode,
        &destination,
        &request.file_name,
        request.policy,
        wav,
        &manifest,
        diagnostics,
        &result,
        outcome,
    )
}

pub(crate) fn module_export(
    request: &NormalizedModuleExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AudioModuleExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match resolve_destination(context, &request.destination) {
        Ok(path) => path,
        Err(diagnostic) => {
            let mut diagnostics = diagnostics;
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, diagnostics, decoded) =
        decode_module(&request.decode, context, diagnostics, events);
    let Some((summary, region)) = decoded else {
        return outcome(status, diagnostics, None);
    };

    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::File,
        request.policy,
        vec![PlannedOutput {
            path: request.file_name.clone(),
            size: region.len() as u64,
            sha256: summary.module_sha256.clone(),
        }],
        Vec::new(),
    );
    let manifest = serde_json::json!({
        "format_version": 1,
        "operation": OperationName::AudioModuleExport.as_str(),
        "source": { "size": summary.source.size, "sha256": summary.source.sha256 },
        "offset": summary.offset,
        "length": summary.total_bytes,
        "title": summary.title,
        "signature": summary.signature,
        "channels": summary.channels,
        "files": [{ "path": request.file_name, "sha256": summary.module_sha256 }],
    });
    let result = move |plan: WritePlan, committed| {
        Some(OperationResult::AudioModuleExport(ModuleExportResult {
            module: summary.clone(),
            plan,
            committed,
        }))
    };

    commit(
        &plan,
        mode,
        &destination,
        &request.file_name,
        request.policy,
        region,
        &manifest,
        diagnostics,
        &result,
        outcome,
    )
}

/// Resolve the output root, turning a resolver refusal into its diagnostic.
fn resolve_destination(
    context: &ExecutionContext<'_>,
    destination: &crate::output::DestinationName,
) -> Result<std::path::PathBuf, Diagnostic> {
    context
        .destinations()
        .resolve(destination)
        .map_err(|error| {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            Diagnostic::error(code, error.to_string())
        })
}

/// The prepare/approve/write dance both exports here share.
#[expect(
    clippy::too_many_arguments,
    reason = "one shared reviewed write parameterized by everything that differs between the two exports"
)]
fn commit(
    plan: &WritePlan,
    mode: &NormalizedMode,
    destination: &std::path::Path,
    file_name: &str,
    policy: crate::output::OutputPolicy,
    bytes: Vec<u8>,
    manifest: &serde_json::Value,
    mut diagnostics: Vec<Diagnostic>,
    result: &dyn Fn(WritePlan, bool) -> Option<OperationResult>,
    outcome: impl Fn(Status, Vec<Diagnostic>, Option<OperationResult>) -> OperationOutcome,
) -> OperationOutcome {
    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(plan.clone(), false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this output, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan.clone(), false));
    }

    let manifest = match serde_json::to_vec_pretty(manifest) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let write_plan = match amiga_core::ExtractionPlan::new(
        vec![amiga_core::PlannedFile {
            path: std::path::PathBuf::from(file_name),
            bytes,
        }],
        Vec::new(),
    ) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // One named file into a directory this toolkit does not own, as every other
    // single-file export does.
    match write_plan.commit_file(
        &destination.join(file_name),
        policy.permits_replacement(),
        &manifest,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, result(plan.clone(), true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, result(plan.clone(), false))
        }
    }
}

type Decoded<T> = (Status, Vec<Diagnostic>, Option<(T, Vec<u8>)>);

fn decode_pcm(
    request: &NormalizedPcm,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Decoded<PcmDecodeResult> {
    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return (Status::Error, diagnostics, None);
        }
    };

    let bytes = source.bytes();
    let end = match request.offset.checked_add(request.length) {
        Some(end) => end,
        None => {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::SourceRangeOutsideSource,
                    "the region's offset plus its length overflows",
                )
                .at("$.request.arguments.length"),
            );
            return (Status::Error, diagnostics, None);
        }
    };
    let Some(region) = bytes.get(request.offset..end) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "the region [{}..{end}) lies outside the {}-byte source",
                    request.offset,
                    bytes.len()
                ),
            )
            .at("$.request.arguments.offset"),
        );
        return (Status::Error, diagnostics, None);
    };
    events.emit(OperationEvent::Progress {
        phase: "read_region",
        completed: region.len() as u64,
        total: Some(region.len() as u64),
    });

    let pcm: Vec<i8> = region
        .iter()
        .map(|byte| i8::from_ne_bytes([*byte]))
        .collect();
    let envelope = envelope(&pcm, request.maximum_buckets);
    let bucket_frames = if envelope.is_empty() {
        0
    } else {
        pcm.len().div_ceil(envelope.len()) as u64
    };

    let summary = PcmDecodeResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        offset: request.offset as u64,
        frames: pcm.len() as u64,
        sample_rate: u32::from(request.sample_rate),
        region_sha256: amiga_core::sha256(region),
        envelope,
        bucket_frames,
    };
    (
        Status::Success,
        diagnostics,
        Some((summary, region.to_vec())),
    )
}

fn decode_module(
    request: &NormalizedModule,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Decoded<ModuleResult> {
    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return (Status::Error, diagnostics, None);
        }
    };

    let bytes = source.bytes();
    let Some(parsed) = amiga_iff::tracker::parse_at(bytes, request.offset) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::AudioModuleUnreadable,
                format!("no valid tracker module at offset {}", request.offset),
            )
            .at("$.request.arguments.offset"),
        );
        return (Status::Error, diagnostics, None);
    };
    // `parse_at` guarantees the whole module lies within the source, so this
    // range cannot be out of bounds — but it is taken through `get` anyway,
    // because a guarantee restated as an index is a guarantee that can rot.
    let Some(region) = bytes.get(request.offset..request.offset + parsed.total_len) else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::AudioModuleUnreadable,
            "the module the parser accepted runs past the end of the source",
        ));
        return (Status::Error, diagnostics, None);
    };
    events.emit(OperationEvent::Progress {
        phase: "parse_module",
        completed: region.len() as u64,
        total: Some(region.len() as u64),
    });

    let summary = ModuleResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        offset: request.offset as u64,
        title: parsed.title.clone(),
        signature: parsed.signature.clone(),
        channels: u32::from(parsed.channels),
        song_length: u32::from(parsed.song_length),
        pattern_count: parsed.pattern_count as u64,
        total_bytes: parsed.total_len as u64,
        module_sha256: amiga_core::sha256(region),
        // Every slot, including the empty ones: a tracker addresses samples by
        // slot number, so dropping the unused ones would renumber the rest.
        samples: parsed
            .samples
            .iter()
            .enumerate()
            .map(|(index, sample)| ModuleSample {
                slot: index as u32 + 1,
                name: sample.name.clone(),
                length: sample.length,
                volume: u32::from(sample.volume),
                finetune: u32::from(sample.finetune),
                repeat_start: sample.repeat_start,
                repeat_length: sample.repeat_length,
            })
            .collect(),
    };
    (
        Status::Success,
        diagnostics,
        Some((summary, region.to_vec())),
    )
}

/// Reduce `pcm` to at most `buckets` min/max pairs.
///
/// Min *and* max, not an average: averaging a waveform toward zero is how a
/// loud sample ends up looking like silence. Identical to the 8SVX decode's,
/// deliberately — the same data drawn the same way.
fn envelope(pcm: &[i8], buckets: usize) -> Vec<WaveformBucket> {
    if pcm.is_empty() || buckets == 0 {
        return Vec::new();
    }
    let buckets = buckets.min(pcm.len());
    let per_bucket = pcm.len().div_ceil(buckets);
    pcm.chunks(per_bucket)
        .map(|chunk| WaveformBucket {
            minimum: chunk.iter().copied().min().unwrap_or(0),
            maximum: chunk.iter().copied().max().unwrap_or(0),
        })
        .collect()
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
