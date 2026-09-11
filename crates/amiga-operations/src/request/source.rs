//! Arguments for the `source.*` operations: reading, surveying and carving the
//! bytes a request names, before anything has been said about what they are.
use super::*;

/// Arguments for `source.read`.
///
/// The last operation the plan needed, and the smallest: a window of bytes,
/// named the way every other request names its source. It exists so no command
/// reaches a domain crate for *data* — a hex view is presentation, and the
/// bytes under it are not the frontend's to fetch.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReadArguments {
    pub source: SourceLocator,
    /// Read the window out of this hunk's bytes rather than the whole file.
    /// Relocation sites inside the window are reported with it, which is the
    /// one thing a raw file read cannot say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the window starts, in whichever frame `hunk` selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl SourceReadArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            offset: None,
            length: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub const fn window(mut self, offset: u32, length: u32) -> Self {
        self.offset = Some(offset);
        self.length = Some(length);
        self
    }
}

/// Arguments for `source.carve`.
///
/// A range and a destination. What the bytes *are* is a separate decision with
/// its own operation: a carve that guessed would be a decode nobody asked for.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CarveArguments {
    pub source: SourceLocator,
    /// Byte offset of the range within the source.
    pub offset: usize,
    /// Length of the range in bytes.
    pub length: usize,
    /// Directory the carved file goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl CarveArguments {
    #[must_use]
    pub fn new(
        source: impl Into<String>,
        offset: usize,
        length: usize,
        destination: impl Into<String>,
    ) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset,
            length,
            destination: destination.into(),
            file_name: None,
            maximum_input_bytes: None,
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

/// Arguments for `source.survey`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSurveyArguments {
    pub source: SourceLocator,
    /// Minimum printable-run length the string locator reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_string_length: Option<usize>,
    /// Refuse the source outright when it is larger than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    /// Cap the reported region list at this many entries. The response always
    /// reports the true total beside the capped list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_regions: Option<usize>,
}

impl SourceSurveyArguments {
    /// Survey `path` with every documented default.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::File { path: path.into() },
            minimum_string_length: None,
            maximum_input_bytes: None,
            maximum_regions: None,
        }
    }

    #[must_use]
    pub const fn with_minimum_string_length(mut self, length: usize) -> Self {
        self.minimum_string_length = Some(length);
        self
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }

    #[must_use]
    pub const fn with_maximum_regions(mut self, regions: usize) -> Self {
        self.maximum_regions = Some(regions);
        self
    }
}
