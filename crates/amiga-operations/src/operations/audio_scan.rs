//! `audio.pcm.scan` and `audio.module.scan` — finding audio in bytes that
//! declare nothing.
//!
//! Raw Paula PCM has no header at all, so a "region" is not something a file
//! says is there. It is what a set of thresholds accepted, which makes every
//! region a *candidate* — and the thresholds travel back in the result for the
//! same reason the pointer scan's origin does: a candidate whose criteria are
//! invisible can be neither judged nor reproduced. The per-region amplitude and
//! smoothness travel for the other half of that: they are the evidence.
//!
//! A tracker module *does* declare itself, by signature, so its scan needs no
//! thresholds. Both live here because they answer the same shape of question
//! about the same file, and a caller sweeping an unknown disk asks both.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedModuleScan, NormalizedPcmScan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    FoundModule, ModuleScanResult, OperationOutcome, OperationResult, PcmRegion, PcmScanResult,
    SourcePin,
};
use crate::source::{ResolvedSource, SourceError};

/// Resolve the source, returning the diagnostic to report rather than pushing
/// it, so each scan keeps its own outcome shape.
fn resolve(
    source: &crate::normalize::NormalizedSource,
    maximum_input_bytes: u64,
    context: &ExecutionContext<'_>,
) -> Result<ResolvedSource, Diagnostic> {
    context
        .resolve_source(source, maximum_input_bytes)
        .map_err(|error| {
            let code = match error {
                SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
            };
            Diagnostic::error(code, error.to_string())
        })
}

pub(crate) fn pcm(
    request: &NormalizedPcmScan,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return OperationOutcome {
                operation: OperationName::AudioPcmScan,
                status: Status::Error,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
    };

    let found = amiga_iff::scan_pcm(
        source.bytes(),
        amiga_iff::ScanParams {
            block: request.block,
            min_len: request.minimum_length,
            ..amiga_iff::ScanParams::default()
        },
    );
    events.emit(OperationEvent::Progress {
        phase: "scan_pcm",
        completed: source.size(),
        total: Some(source.size()),
    });

    let total = found.len();
    let truncated = total > request.maximum_regions;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultRegionsTruncated,
            format!(
                "{total} candidate regions were found; {} are reported",
                request.maximum_regions
            ),
        ));
    }

    let result = PcmScanResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        block: request.block as u64,
        minimum_length: request.minimum_length as u64,
        regions: found
            .iter()
            .take(request.maximum_regions)
            .map(|region| PcmRegion {
                offset: region.offset as u64,
                length: region.len as u64,
                mean_amplitude: region.mean_amplitude,
                smoothness: region.smoothness,
            })
            .collect(),
        region_total: total as u64,
        regions_truncated: truncated,
    };
    OperationOutcome {
        operation: OperationName::AudioPcmScan,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::AudioPcmScan(result)),
    }
}

pub(crate) fn module(
    request: &NormalizedModuleScan,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match resolve(&request.source, request.maximum_input_bytes, context) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return OperationOutcome {
                operation: OperationName::AudioModuleScan,
                status: Status::Error,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
    };

    let found = amiga_iff::tracker::scan(source.bytes());
    events.emit(OperationEvent::Progress {
        phase: "scan_modules",
        completed: source.size(),
        total: Some(source.size()),
    });

    let total = found.len();
    let truncated = total > request.maximum_modules;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{total} modules were found; {} are reported",
                request.maximum_modules
            ),
        ));
    }

    let result = ModuleScanResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        modules: found
            .iter()
            .take(request.maximum_modules)
            .map(|module| FoundModule {
                offset: module.offset,
                title: module.title.clone(),
                signature: module.signature.clone(),
                channels: module.channels,
                song_length: module.song_length,
                pattern_count: module.pattern_count as u64,
                // A count, not a slot list: the slots themselves are
                // `audio.module.decode`'s answer, which reports all 31 because
                // a tracker addresses samples by slot number.
                used_samples: module.used_samples() as u64,
                total_length: module.total_len as u64,
            })
            .collect(),
        module_total: total as u64,
        modules_truncated: truncated,
    };
    OperationOutcome {
        operation: OperationName::AudioModuleScan,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::AudioModuleScan(result)),
    }
}
