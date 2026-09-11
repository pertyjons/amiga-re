//! `audio.sample.decode` and `audio.sample.export` — read an IFF 8SVX sample,
//! and write it out as WAV.
//!
//! Split for the same reason the bitmap and comparison pairs are: reading a
//! sample is a read, and writing a converted copy of it is a separate
//! authorization. The export composes the decode rather than parsing the sample
//! a second time.
//!
//! ## Why the result is an envelope
//!
//! A waveform column represents a range of sample frames. The decode reports a bounded
//! min/max envelope so consumers can inspect the shape without holding or transferring
//! the complete sample body. Export still writes every frame; the envelope never
//! replaces the sample.
//!
//! Nothing here plays anything. Decoding and WAV conversion are
//! device-independent by design; a playback device belongs to whatever frontend
//! chooses to have one.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedAudioSample, NormalizedAudioSampleExport, NormalizedMode};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    AudioSampleResult, OperationOutcome, OperationResult, SourcePin, WaveformBucket,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedAudioSample,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (status, diagnostics, decoded) = decode(request, context, diagnostics, events);
    OperationOutcome {
        operation: OperationName::AudioSampleDecode,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: decoded.map(|(result, _)| OperationResult::AudioSampleDecode(result)),
    }
}

/// Parse the sample and summarize it, returning the PCM beside the summary so
/// the export does not have to parse it again.
#[expect(
    clippy::type_complexity,
    reason = "one return of status, diagnostics, and an optional result-with-PCM"
)]
fn decode(
    request: &NormalizedAudioSample,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> (
    Status,
    Vec<Diagnostic>,
    Option<(AudioSampleResult, Vec<i8>)>,
) {
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
    let Some(region) = bytes.get(request.offset..) else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "the sample starts at {} in a {}-byte source",
                    request.offset,
                    bytes.len()
                ),
            )
            .at("$.request.arguments.offset"),
        );
        return (Status::Error, diagnostics, None);
    };

    let sample = match amiga_iff::parse_8svx(region) {
        Ok(sample) => sample,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AudioSampleUnreadable,
                error.to_string(),
            ));
            return (Status::Error, diagnostics, None);
        }
    };
    let pcm = sample.pcm().to_vec();
    events.emit(OperationEvent::Progress {
        phase: "parse_sample",
        completed: pcm.len() as u64,
        total: Some(pcm.len() as u64),
    });

    // The rate is whatever the VHDR declared; `parse_8svx` already refuses the
    // zero that a malformed header produces, so nothing here has to guess one.
    let sample_rate = sample.sample_rate().get();

    let envelope = envelope(&pcm, request.maximum_buckets);
    let bucket_frames = if envelope.is_empty() {
        0
    } else {
        pcm.len().div_ceil(envelope.len()) as u64
    };
    let result = AudioSampleResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        name: sample.name().to_owned(),
        sample_rate: u32::from(sample_rate),
        frames: pcm.len() as u64,
        one_shot_frames: u64::from(sample.one_shot().get()),
        loop_frames: u64::from(sample.loop_length().get()),
        volume: sample.volume().get(),
        envelope,
        bucket_frames,
        form_bytes: sample.form_bytes() as u64,
    };
    (Status::Success, diagnostics, Some((result, pcm)))
}

/// Reduce `pcm` to at most `buckets` min/max pairs.
///
/// Min *and* max, not an average: averaging a waveform toward zero is how a
/// loud sample ends up looking like silence, and the whole point of the
/// envelope is recognizing the shape.
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

pub(crate) fn export(
    request: &NormalizedAudioSampleExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AudioSampleExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            let mut diagnostics = diagnostics;
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (status, mut diagnostics, decoded) = decode(&request.decode, context, diagnostics, events);
    let Some((summary, pcm)) = decoded else {
        return outcome(status, diagnostics, None);
    };

    // A WAV header states a rate, and the only rate available is the one the
    // sample declared: inventing one would put a number in the file that the
    // source never gave. The parse already refused zero, so this only guards
    // the width.
    let Ok(sample_rate) = u16::try_from(summary.sample_rate) else {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::AudioEncodeFailed,
            format!(
                "a rate of {} does not fit a WAV header",
                summary.sample_rate
            ),
        ));
        return outcome(Status::Error, diagnostics, None);
    };
    let wav = match amiga_iff::encode_pcm(&pcm, sample_rate) {
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
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::AudioSampleExport(
            crate::response::AudioSampleExportResult {
                sample: summary.clone(),
                plan,
                committed,
            },
        ))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(plan, false));
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
                "the approved plan {approved} no longer describes this sample, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::AudioSampleExport.as_str(),
        "source": {
            "name": request.decode.source.display_name(),
            "size": summary.source.size,
            "sha256": summary.source.sha256,
        },
        "offset": request.decode.offset,
        "sample": {
            "name": summary.name,
            "sample_rate": summary.sample_rate,
            "frames": summary.frames,
            "loop_frames": summary.loop_frames,
        },
        "files": [{ "path": request.file_name, "sha256": amiga_core::sha256(&wav) }],
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::AudioEncodeFailed,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let write_plan = match amiga_core::ExtractionPlan::new(
        vec![amiga_core::PlannedFile {
            path: std::path::PathBuf::from(&request.file_name),
            bytes: wav,
        }],
        Vec::new(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // A single named file into a directory this toolkit does not own: the policy
    // governs that file and its manifest, and nothing else in the directory is
    // read, written, or removed. Owning the directory — which is what `commit`
    // does — would refuse an ordinary output path for existing, and make
    // `create_only` mean "only into an empty folder".
    match write_plan.commit_file(
        &destination.join(&request.file_name),
        request.policy.permits_replacement(),
        &manifest,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, result(plan, true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, result(plan, false))
        }
    }
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_keeps_both_extremes_of_every_bucket() {
        // Averaging would turn this into silence, which is exactly the failure
        // the min/max pair exists to prevent.
        let pcm: Vec<i8> = (0..100)
            .map(|index| if index % 2 == 0 { 100 } else { -100 })
            .collect();
        let buckets = envelope(&pcm, 10);
        assert_eq!(buckets.len(), 10);
        assert!(buckets.iter().all(|bucket| bucket.minimum == -100));
        assert!(buckets.iter().all(|bucket| bucket.maximum == 100));
    }

    #[test]
    fn an_envelope_never_invents_buckets_for_a_short_sample() {
        let buckets = envelope(&[1, 2, 3], 64);
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0].minimum, 1);
        assert!(envelope(&[], 64).is_empty());
    }
}
