//! The normalized `audio.*` requests, and what filling their defaults decides.
use super::*;

/// Block size the PCM scan scores the image in, and the shortest merged region
/// it reports. Both are `amiga_iff::ScanParams`'s own defaults, named here so
/// the canonical request spells them out rather than leaving them implied.
const DEFAULT_PCM_SCAN_BLOCK: usize = 1024;
const DEFAULT_PCM_SCAN_MINIMUM_LENGTH: usize = 2048;

/// How many envelope buckets a request gets when it names no number.
///
/// A few hundred columns is what a waveform is actually drawn at; asking for
/// more transfers detail nobody can see.
const DEFAULT_WAVEFORM_BUCKETS: usize = 512;

/// The file name a sample export uses when the request names none.
const DEFAULT_SAMPLE_FILE_NAME: &str = "sample.wav";

/// The file name a module export uses when the request names none.
const DEFAULT_MODULE_FILE_NAME: &str = "module.mod";

/// Fully resolved `audio.pcm.scan` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPcmScan {
    pub source: NormalizedSource,
    pub block: usize,
    pub minimum_length: usize,
    pub maximum_regions: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `audio.module.scan` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedModuleScan {
    pub source: NormalizedSource,
    pub maximum_modules: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `audio.pcm.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPcm {
    pub source: NormalizedSource,
    pub offset: usize,
    pub length: usize,
    pub sample_rate: u16,
    pub maximum_buckets: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `audio.pcm.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPcmExport {
    pub decode: NormalizedPcm,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// Fully resolved `audio.module.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedModule {
    pub source: NormalizedSource,
    pub offset: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `audio.module.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedModuleExport {
    pub decode: NormalizedModule,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// Fully resolved `audio.sample.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAudioSample {
    pub source: NormalizedSource,
    pub offset: usize,
    pub maximum_buckets: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `audio.sample.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAudioSampleExport {
    pub decode: NormalizedAudioSample,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// The canonical form of one sample read, shared by the decode and the export.
pub(super) fn audio_sample_document(sample: &NormalizedAudioSample) -> Value {
    json!({
        "source": sample.source.canonical(),
        "offset": sample.offset,
        "maximum_buckets": sample.maximum_buckets,
        "maximum_input_bytes": sample.maximum_input_bytes,
    })
}

/// The canonical form of one raw-PCM read, shared by the decode and the export.
///
/// The rate is part of it because it is part of what gets written: the same
/// bytes exported at two rates are two different WAV files.
pub(super) fn pcm_document(decode: &NormalizedPcm) -> Value {
    json!({
        "source": decode.source.canonical(),
        "offset": decode.offset,
        "length": decode.length,
        "sample_rate": decode.sample_rate,
        "maximum_buckets": decode.maximum_buckets,
        "maximum_input_bytes": decode.maximum_input_bytes,
    })
}

/// The canonical form of one tracker-module read.
pub(super) fn module_document(decode: &NormalizedModule) -> Value {
    json!({
        "source": decode.source.canonical(),
        "offset": decode.offset,
        "maximum_input_bytes": decode.maximum_input_bytes,
    })
}

/// The canonical form of one sample export.
pub(super) fn sample_export_document(export: &NormalizedAudioSampleExport) -> Value {
    json!({
        "decode": audio_sample_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one raw-PCM export.
pub(super) fn pcm_export_document(export: &NormalizedPcmExport) -> Value {
    json!({
        "decode": pcm_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one tracker-module export.
pub(super) fn module_export_document(export: &NormalizedModuleExport) -> Value {
    json!({
        "decode": module_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one `audio.pcm.scan`.
pub(super) fn pcm_scan_document(scan: &NormalizedPcmScan) -> Value {
    json!({
        "source": scan.source.canonical(),
        "block": scan.block,
        "minimum_length": scan.minimum_length,
        "maximum_regions": scan.maximum_regions,
        "maximum_input_bytes": scan.maximum_input_bytes,
    })
}

/// The canonical form of one `audio.module.scan`.
pub(super) fn module_scan_document(scan: &NormalizedModuleScan) -> Value {
    json!({
        "source": scan.source.canonical(),
        "maximum_modules": scan.maximum_modules,
        "maximum_input_bytes": scan.maximum_input_bytes,
    })
}

/// Resolve sample arguments, shared by the decode and the export.
pub(super) fn normalize_audio_sample(
    arguments: &crate::request::AudioSampleArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedAudioSample, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    let maximum_buckets = normalize_count(
        arguments.maximum_buckets.or(Some(DEFAULT_WAVEFORM_BUCKETS)),
        limits.maximum_entries(),
        "maximum_buckets",
        "waveform buckets",
        diagnostics,
    )?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedAudioSample {
        source,
        offset: arguments.offset.unwrap_or(0),
        maximum_buckets,
        maximum_input_bytes,
    })
}

/// Resolve raw-PCM arguments, shared by the decode and the export.
///
/// A zero-length region is refused here rather than producing an empty WAV: a
/// caller who meant a region gave a bound that describes none, and a zero-byte
/// output would look like a successful export of silence.
pub(super) fn normalize_pcm(
    arguments: &crate::request::PcmArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedPcm, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    if arguments.length == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "length must be at least one sample",
            )
            .at("$.request.arguments.length"),
        ]);
    }
    if arguments.sample_rate == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "sample_rate must be at least 1 Hz; every consumer divides by it",
            )
            .at("$.request.arguments.sample_rate"),
        ]);
    }
    let maximum_buckets = normalize_count(
        arguments.maximum_buckets.or(Some(DEFAULT_WAVEFORM_BUCKETS)),
        limits.maximum_entries(),
        "maximum_buckets",
        "waveform buckets",
        diagnostics,
    )?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedPcm {
        source,
        offset: arguments.offset,
        length: arguments.length,
        sample_rate: arguments.sample_rate,
        maximum_buckets,
        maximum_input_bytes,
    })
}

/// Resolve tracker-module arguments, shared by the decode and the export.
pub(super) fn normalize_module(
    arguments: &crate::request::ModuleArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedModule, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedModule {
        source,
        offset: arguments.offset.unwrap_or(0),
        maximum_input_bytes,
    })
}

/// Fill in what an `audio.sample.decode` request left unsaid.
pub(super) fn sample_decode(
    arguments: &crate::request::AudioSampleArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AudioSampleDecode(
        normalize_audio_sample(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what an `audio.sample.export` request left unsaid.
pub(super) fn sample_export(
    arguments: &crate::request::AudioSampleExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_audio_sample(&arguments.decode, limits, diagnostics)?;
    let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    let file_name = arguments
        .file_name
        .clone()
        .unwrap_or_else(|| DEFAULT_SAMPLE_FILE_NAME.to_owned());
    if DestinationName::parse(&file_name).is_err() || file_name.contains('/') {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestSourceNameInvalid,
                "file_name must be one relative path component",
            )
            .at("$.request.arguments.file_name"),
        ]);
    }

    Ok(NormalizedOperation::AudioSampleExport(
        NormalizedAudioSampleExport {
            decode,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `audio.pcm.scan` request left unsaid.
pub(super) fn pcm_scan(
    arguments: &crate::request::PcmScanArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let block = arguments.block.unwrap_or(DEFAULT_PCM_SCAN_BLOCK);
    // A block of one byte has no step to measure, so smoothness — the
    // statistic that separates a waveform from noise — would be
    // undefined for every block and every region would score the same.
    if block < 2 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "block must be at least 2; a single byte has no step between samples \
                 to measure",
            )
            .at("$.request.arguments.block"),
        ]);
    }
    Ok(NormalizedOperation::AudioPcmScan(NormalizedPcmScan {
        source: normalize_source(&arguments.source)?,
        block,
        minimum_length: arguments
            .minimum_length
            .unwrap_or(DEFAULT_PCM_SCAN_MINIMUM_LENGTH),
        maximum_regions: normalize_count(
            arguments.maximum_regions,
            limits.maximum_regions(),
            "maximum_regions",
            "regions",
            diagnostics,
        )?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    }))
}

/// Fill in what an `audio.module.scan` request left unsaid.
pub(super) fn module_scan(
    arguments: &crate::request::ModuleScanArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AudioModuleScan(NormalizedModuleScan {
        source: normalize_source(&arguments.source)?,
        maximum_modules: normalize_count(
            arguments.maximum_modules,
            limits.maximum_entries(),
            "maximum_modules",
            "modules",
            diagnostics,
        )?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    }))
}

/// Fill in what an `audio.pcm.export` request left unsaid.
pub(super) fn pcm_export(
    arguments: &crate::request::PcmExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_pcm(&arguments.decode, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_SAMPLE_FILE_NAME,
    )?;
    Ok(NormalizedOperation::AudioPcmExport(NormalizedPcmExport {
        decode,
        destination,
        file_name,
        policy: arguments.policy.unwrap_or_default(),
    }))
}

/// Fill in what an `audio.module.decode` request left unsaid.
pub(super) fn module_decode(
    arguments: &crate::request::ModuleArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::AudioModuleDecode(normalize_module(
        arguments,
        limits,
        diagnostics,
    )?))
}

/// Fill in what an `audio.module.export` request left unsaid.
pub(super) fn module_export(
    arguments: &crate::request::ModuleExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_module(&arguments.decode, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_MODULE_FILE_NAME,
    )?;
    Ok(NormalizedOperation::AudioModuleExport(
        NormalizedModuleExport {
            decode,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}
