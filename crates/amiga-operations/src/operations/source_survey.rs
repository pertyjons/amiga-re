//! `source.survey` — classify a source into ordered typed regions.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedSourceSurvey;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{OperationOutcome, OperationResult, SourcePin, SourceSurveyResult};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedSourceSurvey,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return OperationOutcome {
                operation: OperationName::SourceSurvey,
                status: Status::Error,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
    };

    // Phase boundaries the operation itself controls, so the order is
    // deterministic without the locators having to report anything.
    events.emit(OperationEvent::Progress {
        phase: "resolve_source",
        completed: source.size(),
        total: Some(source.size()),
    });

    // The survey is the most expensive read-only operation in the toolkit, so
    // it is the one that must stop promptly. A cancelled survey reports no
    // result at all: a partial region map is indistinguishable from a complete
    // map of a featureless file.
    let survey = match amiga_analysis::survey_detailed_cancellable(
        source.bytes(),
        request.minimum_string_length,
        &context.cancel(),
    ) {
        Ok(survey) => survey,
        Err(amiga_core::Cancelled) => {
            return OperationOutcome {
                operation: OperationName::SourceSurvey,
                status: Status::Cancelled,
                diagnostics,
                normalized_request_sha256: Some(digest),
                result: None,
            };
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "locate_regions",
        completed: survey.regions.len() as u64,
        total: None,
    });
    let region_total = survey.regions.len();
    let regions_truncated = region_total > request.maximum_regions;
    let mut regions = survey.regions;
    if regions_truncated {
        regions.truncate(request.maximum_regions);
        let diagnostic = Diagnostic::warning(
            DiagnosticCode::ResultRegionsTruncated,
            format!(
                "reporting the first {} of {region_total} regions",
                request.maximum_regions
            ),
        );
        // Reported as an event as well as on the response: a caller watching a
        // long survey should learn its list was capped before it ends.
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }

    OperationOutcome {
        operation: OperationName::SourceSurvey,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::SourceSurvey(SourceSurveyResult {
            source: SourcePin {
                size: source.size(),
                sha256: source.sha256().to_owned(),
            },
            regions,
            region_total,
            regions_truncated,
            copper_lists: survey.copper_lists,
        })),
    }
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
