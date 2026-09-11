//! The normalized `compress.*` requests, and what filling their defaults decides.
use super::*;

/// The file name a decompression export uses when the request names none.
///
/// Deliberately not derived from the source: a packed stream says nothing about
/// what it holds, and inventing `level1.bin` from `level1.pp` would state a
/// relationship the bytes do not.
const DEFAULT_DECODED_FILE_NAME: &str = "decoded.bin";

/// Fully resolved `compress.powerpacker.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPowerpacker {
    pub source: NormalizedSource,
    pub modes: [u8; 4],
    pub offset: usize,
    pub maximum_input_bytes: u64,
    pub maximum_output_bytes: u64,
}

/// Fully resolved `compress.powerpacker.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPowerpackerExport {
    pub decode: NormalizedPowerpacker,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// Fully resolved `compress.rle-xor.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRleXor {
    pub source: NormalizedSource,
    pub layout: amiga_compress::RleXorParams,
    pub offset: usize,
    pub maximum_input_bytes: u64,
    pub maximum_output_bytes: u64,
}

/// Fully resolved `compress.rle-xor.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRleXorExport {
    pub decode: NormalizedRleXor,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// The canonical form of one PowerPacker read, shared by the decode and the
/// export.
pub(super) fn powerpacker_document(decode: &NormalizedPowerpacker) -> Value {
    json!({
        "source": decode.source.canonical(),
        "modes": decode.modes,
        "offset": decode.offset,
        "maximum_input_bytes": decode.maximum_input_bytes,
        "maximum_output_bytes": decode.maximum_output_bytes,
    })
}

/// The canonical form of one position-XOR RLE read.
///
/// Every layout field is here because every one of them changes the decoded
/// bytes. Two streams that differ only in `inline_marker` decode to different
/// output without either failing, so a digest that omitted it would call two
/// different results the same request.
pub(super) fn rle_xor_document(decode: &NormalizedRleXor) -> Value {
    json!({
        "source": decode.source.canonical(),
        "marker": decode.layout.marker,
        "xor": decode.layout.xor,
        "inline_marker": decode.layout.inline_marker,
        "size_bytes": decode.layout.size_bytes,
        "size_includes_field": decode.layout.size_includes_field,
        "offset": decode.offset,
        "maximum_input_bytes": decode.maximum_input_bytes,
        "maximum_output_bytes": decode.maximum_output_bytes,
    })
}

/// The canonical form of one PowerPacker export.
pub(super) fn powerpacker_export_document(export: &NormalizedPowerpackerExport) -> Value {
    json!({
        "decode": powerpacker_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one position-XOR RLE export.
pub(super) fn rle_xor_export_document(export: &NormalizedRleXorExport) -> Value {
    json!({
        "decode": rle_xor_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// Resolve PowerPacker arguments, shared by the decode and the export.
pub(super) fn normalize_powerpacker(
    arguments: &crate::request::PowerpackerArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedPowerpacker, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let maximum_output_bytes = normalize_output_bytes(
        arguments.maximum_output_bytes,
        limits.maximum_output_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedPowerpacker {
        source,
        modes: arguments.modes,
        offset: arguments.offset.unwrap_or(0),
        maximum_input_bytes,
        maximum_output_bytes,
    })
}

/// Resolve position-XOR RLE arguments, shared by the decode and the export.
///
/// The size-field width is checked here rather than in the codec so a bad
/// request is refused before a source is opened. Zero means "no field"; the
/// only widths the format uses are two and four bytes, and a stated three would
/// be a request nobody can satisfy rather than a stream nobody can read.
pub(super) fn normalize_rle_xor(
    arguments: &crate::request::RleXorArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedRleXor, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    if !matches!(arguments.size_bytes, 0 | 2 | 4) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "size_bytes must be 0, 2, or 4; got {}",
                    arguments.size_bytes
                ),
            )
            .at("$.request.arguments.size_bytes"),
        ]);
    }
    if arguments.size_includes_field && arguments.size_bytes == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "size_includes_field describes a size field the request says is absent",
            )
            .at("$.request.arguments.size_includes_field"),
        ]);
    }
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let maximum_output_bytes = normalize_output_bytes(
        arguments.maximum_output_bytes,
        limits.maximum_output_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedRleXor {
        source,
        layout: amiga_compress::RleXorParams {
            marker: arguments.marker,
            xor: arguments.xor,
            inline_marker: arguments.inline_marker,
            size_bytes: arguments.size_bytes,
            size_includes_field: arguments.size_includes_field,
        },
        offset: arguments.offset.unwrap_or(0),
        maximum_input_bytes,
        maximum_output_bytes,
    })
}

/// Fill in what an `compress.powerpacker.decode` request left unsaid.
pub(super) fn powerpacker_decode(
    arguments: &crate::request::PowerpackerArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::CompressPowerpackerDecode(
        normalize_powerpacker(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what an `compress.powerpacker.export` request left unsaid.
pub(super) fn powerpacker_export(
    arguments: &crate::request::PowerpackerExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_powerpacker(&arguments.decode, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_DECODED_FILE_NAME,
    )?;
    Ok(NormalizedOperation::CompressPowerpackerExport(
        NormalizedPowerpackerExport {
            decode,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `compress.rle-xor.decode` request left unsaid.
pub(super) fn rle_xor_decode(
    arguments: &crate::request::RleXorArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::CompressRleXorDecode(
        normalize_rle_xor(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what an `compress.rle-xor.export` request left unsaid.
pub(super) fn rle_xor_export(
    arguments: &crate::request::RleXorExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_rle_xor(&arguments.decode, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_DECODED_FILE_NAME,
    )?;
    Ok(NormalizedOperation::CompressRleXorExport(
        NormalizedRleXorExport {
            decode,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}
