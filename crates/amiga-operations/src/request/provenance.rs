//! Arguments for the `provenance.*` operations: what a manifest pins, and where
//! an exported one is written.
use super::*;

/// Arguments for `provenance.manifest`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ManifestArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }
}

/// Arguments for `provenance.manifest.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestExportArguments {
    #[serde(flatten)]
    pub manifest: ManifestArguments,
    /// Directory the manifest goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl ManifestExportArguments {
    #[must_use]
    pub fn new(manifest: ManifestArguments, destination: impl Into<String>) -> Self {
        Self {
            manifest,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}
