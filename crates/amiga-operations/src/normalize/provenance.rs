//! The normalized `provenance.*` requests, and what filling their defaults decides.
use super::*;

/// The file name a provenance manifest uses when the request names none.
const DEFAULT_MANIFEST_FILE_NAME: &str = "manifest.json";

/// Fully resolved `provenance.manifest` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedManifest {
    pub source: NormalizedSource,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `provenance.manifest.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedManifestExport {
    pub manifest: NormalizedManifest,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// The canonical form of one `provenance.manifest`.
pub(super) fn manifest_document(manifest: &NormalizedManifest) -> Value {
    source_only_document(&manifest.source, manifest.maximum_input_bytes)
}

/// The canonical form of one `provenance.manifest.export`.
pub(super) fn manifest_export_document(export: &NormalizedManifestExport) -> Value {
    json!({
        "manifest": manifest_document(&export.manifest),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// Fill in what an `provenance.manifest` request left unsaid.
pub(super) fn manifest(
    arguments: &crate::request::ManifestArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::ProvenanceManifest(
        NormalizedManifest {
            source: normalize_source(&arguments.source)?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `provenance.manifest.export` request left unsaid.
pub(super) fn manifest_export(
    arguments: &crate::request::ManifestExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let manifest = NormalizedManifest {
        source: normalize_source(&arguments.manifest.source)?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.manifest.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    };
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_MANIFEST_FILE_NAME,
    )?;
    Ok(NormalizedOperation::ProvenanceManifestExport(
        NormalizedManifestExport {
            manifest,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}
