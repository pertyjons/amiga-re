//! The normalized `source.*` requests, and what filling their defaults decides.
use super::*;

/// Shortest printable run a survey may be asked for.
const MIN_STRING_LENGTH_FLOOR: usize = 1;

/// Longest printable run a survey may be asked for. Beyond this threshold the setting
/// stops discriminating and only costs scan time.
const MIN_STRING_LENGTH_CEILING: usize = 1024;

/// Bytes a read returns when the request names no length. Matches the command
/// line's own `dump` default.
const DEFAULT_READ_LENGTH: u32 = 256;

/// The file name a carve uses when the request names none.
const DEFAULT_CARVE_FILE_NAME: &str = "carve.bin";

/// Fully resolved `source.read` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSourceRead {
    pub source: NormalizedSource,
    pub hunk: Option<u32>,
    pub offset: u32,
    pub length: u32,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `source.carve` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCarve {
    pub source: NormalizedSource,
    pub offset: usize,
    pub length: usize,
    pub destination: DestinationName,
    pub file_name: String,
    pub maximum_input_bytes: u64,
    pub policy: OutputPolicy,
}

/// Fully resolved `source.survey` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSourceSurvey {
    pub source: NormalizedSource,
    pub minimum_string_length: usize,
    pub maximum_input_bytes: u64,
    pub maximum_regions: usize,
}

/// The canonical form of one `source.survey`.
pub(super) fn survey_document(survey: &NormalizedSourceSurvey) -> Value {
    json!({
        "source": survey.source.canonical(),
        "minimum_string_length": survey.minimum_string_length,
        "maximum_input_bytes": survey.maximum_input_bytes,
        "maximum_regions": survey.maximum_regions,
    })
}

/// The canonical form of one `source.carve`.
pub(super) fn carve_document(carve: &NormalizedCarve) -> Value {
    json!({
        "source": carve.source.canonical(),
        "offset": carve.offset,
        "length": carve.length,
        "destination": carve.destination.as_str(),
        "file_name": carve.file_name,
        "maximum_input_bytes": carve.maximum_input_bytes,
        "policy": carve.policy,
    })
}

/// The canonical form of one `source.read`.
pub(super) fn read_document(read: &NormalizedSourceRead) -> Value {
    json!({
        "source": read.source.canonical(),
        "hunk": read.hunk,
        "offset": read.offset,
        "length": read.length,
        "maximum_input_bytes": read.maximum_input_bytes,
    })
}

/// Fill in what an `source.survey` request left unsaid.
pub(super) fn survey(
    arguments: &crate::request::SourceSurveyArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;

    let minimum_string_length = arguments
        .minimum_string_length
        .unwrap_or(amiga_analysis::DEFAULT_SURVEY_MIN_STRING_LENGTH);
    if !(MIN_STRING_LENGTH_FLOOR..=MIN_STRING_LENGTH_CEILING).contains(&minimum_string_length) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "minimum_string_length must be between {MIN_STRING_LENGTH_FLOOR} and {MIN_STRING_LENGTH_CEILING}"
                ),
            )
            .at("$.request.arguments.minimum_string_length"),
        ]);
    }

    let input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let regions = normalize_count(
        arguments.maximum_regions,
        limits.maximum_regions(),
        "maximum_regions",
        "regions",
        diagnostics,
    )?;

    Ok(NormalizedOperation::SourceSurvey(NormalizedSourceSurvey {
        source,
        minimum_string_length,
        maximum_input_bytes: input_bytes,
        maximum_regions: regions,
    }))
}

/// Fill in what an `source.carve` request left unsaid.
pub(super) fn carve(
    arguments: &crate::request::CarveArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    if arguments.length == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "length must be at least 1; an empty carve writes nothing",
            )
            .at("$.request.arguments.length"),
        ]);
    }
    let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    let file_name = arguments
        .file_name
        .clone()
        .unwrap_or_else(|| DEFAULT_CARVE_FILE_NAME.to_owned());
    if DestinationName::parse(&file_name).is_err() || file_name.contains('/') {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestSourceNameInvalid,
                "file_name must be one relative path component",
            )
            .at("$.request.arguments.file_name"),
        ]);
    }
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;

    Ok(NormalizedOperation::SourceCarve(NormalizedCarve {
        source,
        offset: arguments.offset,
        length: arguments.length,
        destination,
        file_name,
        maximum_input_bytes,
        policy: arguments.policy.unwrap_or_default(),
    }))
}

/// Fill in what an `source.read` request left unsaid.
pub(super) fn read(
    arguments: &crate::request::SourceReadArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let length = arguments.length.unwrap_or(DEFAULT_READ_LENGTH);
    // A window of nothing is not a view of anything, and reporting it
    // as a successful read of zero bytes would answer a question the
    // caller cannot have meant.
    if length == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "length must be at least 1; a window of no bytes is not a view",
            )
            .at("$.request.arguments.length"),
        ]);
    }
    Ok(NormalizedOperation::SourceRead(NormalizedSourceRead {
        source: normalize_source(&arguments.source)?,
        hunk: arguments.hunk,
        offset: arguments.offset.unwrap_or(0),
        length,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    }))
}
