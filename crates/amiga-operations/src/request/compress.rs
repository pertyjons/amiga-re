//! Arguments for the `compress.*` operations: the headerless decompressors and
//! their export halves.
use super::*;

/// Arguments for `compress.powerpacker.decode`.
///
/// The mode table is four bytes and has no safe default: PowerPacker's offset
/// widths are stored *outside* a headerless stream, so a wrong table decodes to
/// plausible-looking rubbish rather than to an error. Requiring it is what keeps
/// this from guessing.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PowerpackerArguments {
    pub source: SourceLocator,
    /// The four offset-width modes, most significant first.
    pub modes: [u8; 4],
    /// Byte offset the packed stream starts at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    /// Refuse the decode before allocating more than this many output bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_output_bytes: Option<u64>,
}

impl PowerpackerArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, modes: [u8; 4]) -> Self {
        Self {
            source: SourceLocator::file(source),
            modes,
            offset: None,
            maximum_input_bytes: None,
            maximum_output_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }

    #[must_use]
    pub const fn with_maximum_output_bytes(mut self, bytes: u64) -> Self {
        self.maximum_output_bytes = Some(bytes);
        self
    }
}

/// Arguments for `compress.powerpacker.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PowerpackerExportArguments {
    #[serde(flatten)]
    pub decode: PowerpackerArguments,
    /// Directory the decoded file goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl PowerpackerExportArguments {
    #[must_use]
    pub fn new(decode: PowerpackerArguments, destination: impl Into<String>) -> Self {
        Self {
            decode,
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

/// Arguments for `compress.rle-xor.decode`.
///
/// Every field of the layout is explicit because the format is a family rather
/// than one encoding: two streams that differ only in whether the marker is
/// stored inline decode to different bytes without either failing, so a default
/// would silently pick one of them.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RleXorArguments {
    pub source: SourceLocator,
    /// The run-marker byte. Ignored when `inline_marker` is set, except as a
    /// cross-check against what the stream carries.
    pub marker: u8,
    /// Whether literal bytes are XOR-ed with their position.
    #[serde(default = "default_true")]
    pub xor: bool,
    /// Whether the stream carries its marker in its first byte.
    #[serde(default)]
    pub inline_marker: bool,
    /// Width in bytes of the leading decoded-size field, or zero for none.
    #[serde(default)]
    pub size_bytes: u8,
    /// Whether that size field counts its own bytes.
    #[serde(default)]
    pub size_includes_field: bool,
    /// Byte offset the packed stream starts at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    /// Refuse the decode before its output would grow past this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_output_bytes: Option<u64>,
}

const fn default_true() -> bool {
    true
}

impl RleXorArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, marker: u8) -> Self {
        Self {
            source: SourceLocator::file(source),
            marker,
            xor: true,
            inline_marker: false,
            size_bytes: 0,
            size_includes_field: false,
            offset: None,
            maximum_input_bytes: None,
            maximum_output_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_xor(mut self, xor: bool) -> Self {
        self.xor = xor;
        self
    }

    #[must_use]
    pub const fn with_inline_marker(mut self, inline: bool) -> Self {
        self.inline_marker = inline;
        self
    }

    #[must_use]
    pub const fn with_size_field(mut self, bytes: u8, includes_field: bool) -> Self {
        self.size_bytes = bytes;
        self.size_includes_field = includes_field;
        self
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }

    #[must_use]
    pub const fn with_maximum_output_bytes(mut self, bytes: u64) -> Self {
        self.maximum_output_bytes = Some(bytes);
        self
    }
}

/// Arguments for `compress.rle-xor.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RleXorExportArguments {
    #[serde(flatten)]
    pub decode: RleXorArguments,
    /// Directory the decoded file goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl RleXorExportArguments {
    #[must_use]
    pub fn new(decode: RleXorArguments, destination: impl Into<String>) -> Self {
        Self {
            decode,
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
