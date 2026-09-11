//! The normalized `hardware.*` requests, and what filling their defaults decides.
use super::*;

/// Fully resolved `hardware.copper.references` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCopperReferences {
    pub source: NormalizedSource,
    pub hunk: u32,
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub pointer_register: u8,
    /// The template's own source, resolved to the code's when the request
    /// named none.
    pub template_source: NormalizedSource,
    pub template_offset: u32,
    /// Where the list is when the routine runs, when the request said.
    pub template_address: Option<u32>,
    pub apply: bool,
    pub maximum_writes: usize,
    pub maximum_instructions: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `hardware.register.references` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRegisterReferences {
    pub source: NormalizedSource,
    pub hunk: u32,
    pub entries: Vec<u32>,
    pub origin: Option<u32>,
    pub maximum_accesses: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `hardware.copper.scan` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCopperScan {
    pub source: NormalizedSource,
    pub maximum_lists: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `hardware.copper.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCopperDecode {
    pub source: NormalizedSource,
    pub offset: u32,
    pub maximum_instructions: usize,
    pub maximum_input_bytes: u64,
}

/// The canonical form of one `hardware.copper.scan`.
pub(super) fn copper_scan_document(scan: &NormalizedCopperScan) -> Value {
    json!({
        "source": scan.source.canonical(),
        "maximum_lists": scan.maximum_lists,
        "maximum_input_bytes": scan.maximum_input_bytes,
    })
}

/// The canonical form of one `hardware.copper.decode`.
pub(super) fn copper_decode_document(decode: &NormalizedCopperDecode) -> Value {
    json!({
        "source": decode.source.canonical(),
        "offset": decode.offset,
        "maximum_instructions": decode.maximum_instructions,
        "maximum_input_bytes": decode.maximum_input_bytes,
    })
}

/// The canonical form of one `hardware.register.references`.
pub(super) fn register_references_document(references: &NormalizedRegisterReferences) -> Value {
    json!({
        "source": references.source.canonical(),
        "hunk": references.hunk,
        "entries": references.entries,
        "origin": references.origin,
        "maximum_accesses": references.maximum_accesses,
        "maximum_input_bytes": references.maximum_input_bytes,
    })
}

/// The canonical form of one `hardware.copper.references`.
///
/// The template is a nested object rather than three sibling keys, because the
/// three are one thing — which list the writes are read against — and a request
/// that named a different template is a different question about the same code.
pub(super) fn copper_references_document(references: &NormalizedCopperReferences) -> Value {
    json!({
        "source": references.source.canonical(),
        "hunk": references.hunk,
        "entries": references.entries,
        "origin": references.origin,
        "pointer_register": references.pointer_register,
        "template": {
            "source": references.template_source.canonical(),
            "offset": references.template_offset,
            "address": references.template_address,
        },
        "apply": references.apply,
        "maximum_writes": references.maximum_writes,
        "maximum_instructions": references.maximum_instructions,
        "maximum_input_bytes": references.maximum_input_bytes,
    })
}

/// Fill in what an `hardware.copper.scan` request left unsaid.
pub(super) fn copper_scan(
    arguments: &crate::request::CopperScanArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::HardwareCopperScan(
        NormalizedCopperScan {
            source: normalize_source(&arguments.source)?,
            maximum_lists: normalize_count(
                arguments.maximum_lists,
                limits.maximum_entries(),
                "maximum_lists",
                "lists",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `hardware.copper.decode` request left unsaid.
pub(super) fn copper_decode(
    arguments: &crate::request::CopperDecodeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let offset = arguments.offset.unwrap_or(0);
    // A Copper instruction is a longword pair read on a word boundary;
    // decoding from an odd offset would produce a plausible stream the
    // hardware never sees.
    if !offset.is_multiple_of(2) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "offset {offset:#x} is odd; a Copper instruction begins on a word \
                     boundary"
                ),
            )
            .at("$.request.arguments.offset"),
        ]);
    }
    Ok(NormalizedOperation::HardwareCopperDecode(
        NormalizedCopperDecode {
            source: normalize_source(&arguments.source)?,
            offset,
            maximum_instructions: normalize_count(
                arguments.maximum_instructions,
                limits.maximum_entries(),
                "maximum_instructions",
                "instructions",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `hardware.register.references` request left unsaid.
pub(super) fn register_references(
    arguments: &crate::request::RegisterReferencesArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::HardwareRegisterReferences(
        NormalizedRegisterReferences {
            source: normalize_source(&arguments.source)?,
            hunk: arguments.hunk.unwrap_or(0),
            entries: default_entries(&arguments.entries),
            origin: arguments.origin,
            maximum_accesses: normalize_count(
                arguments.maximum_accesses,
                limits.maximum_entries(),
                "maximum_accesses",
                "accesses",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `hardware.copper.references` request left unsaid.
pub(super) fn copper_references(
    arguments: &crate::request::CopperReferencesArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    if arguments.pointer_register > 7 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "pointer_register {} is not an address register (A0-A7)",
                    arguments.pointer_register
                ),
            )
            .at("$.request.arguments.pointer_register"),
        ]);
    }
    // The pointer register's value is read *at* the entry, so an
    // unnamed entry leaves the writes with no origin to be measured
    // from. Defaulting to offset zero would silently measure them from
    // the wrong place, which is worse than refusing.
    if arguments.entries.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "entries must name the patch routine's entry; the pointer register's \
                 value is read there, so without one the writes have no origin",
            )
            .at("$.request.arguments.entries"),
        ]);
    }
    let source = normalize_source(&arguments.source)?;
    let template_source = match &arguments.template.source {
        Some(locator) => {
            normalize_named_source(locator, "$.request.arguments.template.source.path")?
        }
        None => source.clone(),
    };
    Ok(NormalizedOperation::HardwareCopperReferences(
        NormalizedCopperReferences {
            source,
            hunk: arguments.hunk.unwrap_or(0),
            entries: default_entries(&arguments.entries),
            origin: arguments.origin,
            pointer_register: arguments.pointer_register,
            template_source,
            template_offset: arguments.template.offset.unwrap_or(0),
            template_address: arguments.template.address,
            apply: arguments.apply,
            maximum_writes: normalize_count(
                arguments.maximum_writes,
                limits.maximum_entries(),
                "maximum_writes",
                "writes",
                diagnostics,
            )?,
            maximum_instructions: normalize_count(
                arguments.maximum_instructions,
                limits.maximum_entries(),
                "maximum_instructions",
                "instructions",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}
