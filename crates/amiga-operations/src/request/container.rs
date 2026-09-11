//! Arguments for the `container.*` operations: listing and extracting the
//! members of an ADF volume or an LHA archive.
use super::*;

/// Arguments for `container.lha.list`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LhaListArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_members: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl LhaListArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_members: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_members(mut self, members: usize) -> Self {
        self.maximum_members = Some(members);
        self
    }
}

/// Arguments for `container.adf.extract` and `container.lha.extract`.
///
/// One shape for both: which container is being read is the operation name, not
/// an argument, and everything else about a reviewed extraction is identical.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerExtractArguments {
    pub source: SourceLocator,
    /// Where the recovered files go, as an identity the adapter resolves
    /// against its own output root — never a host path.
    pub destination: String,
    /// What may happen to a destination that already exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ContainerExtractArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            destination: destination.into(),
            policy: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `container.adf.list`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdfListArguments {
    pub source: SourceLocator,
    /// Refuse the source outright when it is larger than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    /// Cap the reported entry list at this many entries. The response always
    /// reports the true total beside the capped list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_entries: Option<usize>,
}

impl AdfListArguments {
    /// List `path` with every documented default.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::File { path: path.into() },
            maximum_input_bytes: None,
            maximum_entries: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }

    #[must_use]
    pub const fn with_maximum_entries(mut self, entries: usize) -> Self {
        self.maximum_entries = Some(entries);
        self
    }
}
