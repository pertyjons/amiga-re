//! Arguments for the `audio.*` operations: 8SVX samples, raw PCM, and tracker
//! modules.
use super::*;

/// Arguments for `audio.pcm.scan`.
///
/// Every threshold is in the request and travels back in the result. Raw Paula
/// PCM has no header, so a "region" is not something the file declares — it is
/// what these numbers accepted, and a candidate whose criteria are invisible
/// cannot be judged or reproduced.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PcmScanArguments {
    pub source: SourceLocator,
    /// Block size in bytes used to score the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<usize>,
    /// Shortest merged region to report, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_regions: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl PcmScanArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            block: None,
            minimum_length: None,
            maximum_regions: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_block(mut self, block: usize) -> Self {
        self.block = Some(block);
        self
    }

    #[must_use]
    pub const fn with_minimum_length(mut self, length: usize) -> Self {
        self.minimum_length = Some(length);
        self
    }
}

/// Arguments for `audio.module.scan`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleScanArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_modules: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ModuleScanArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_modules: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_modules(mut self, modules: usize) -> Self {
        self.maximum_modules = Some(modules);
        self
    }
}

/// Arguments for `audio.pcm.decode`.
///
/// Raw Paula PCM has no header at all: the region bounds and the playback rate
/// are the caller's claim about bytes that look the same either way. Both are
/// therefore required rather than defaulted from anything in the source.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PcmArguments {
    pub source: SourceLocator,
    /// Byte offset of the first sample.
    pub offset: usize,
    /// Number of sample bytes.
    pub length: usize,
    /// Playback rate in Hz. Stated, never guessed: nothing in the bytes says it.
    pub sample_rate: u16,
    /// How many min/max pairs the waveform envelope is reduced to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_buckets: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl PcmArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, offset: usize, length: usize, sample_rate: u16) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset,
            length,
            sample_rate,
            maximum_buckets: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_buckets(mut self, buckets: usize) -> Self {
        self.maximum_buckets = Some(buckets);
        self
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }
}

/// Arguments for `audio.pcm.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PcmExportArguments {
    #[serde(flatten)]
    pub decode: PcmArguments,
    /// Directory the WAV goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl PcmExportArguments {
    #[must_use]
    pub fn new(decode: PcmArguments, destination: impl Into<String>) -> Self {
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

/// Arguments for `audio.module.decode`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleArguments {
    pub source: SourceLocator,
    /// Byte offset of the module's first byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl ModuleArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset: None,
            maximum_input_bytes: None,
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
}

/// Arguments for `audio.module.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleExportArguments {
    #[serde(flatten)]
    pub decode: ModuleArguments,
    /// Directory the module goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl ModuleExportArguments {
    #[must_use]
    pub fn new(decode: ModuleArguments, destination: impl Into<String>) -> Self {
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

/// Arguments for `audio.sample.decode`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AudioSampleArguments {
    pub source: SourceLocator,
    /// Byte offset of the IFF FORM within the source, for a sample carved out
    /// of a larger file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// How many min/max pairs the waveform envelope is reduced to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_buckets: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl AudioSampleArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset: None,
            maximum_buckets: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_buckets(mut self, buckets: usize) -> Self {
        self.maximum_buckets = Some(buckets);
        self
    }
}

/// Arguments for `audio.sample.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AudioSampleExportArguments {
    #[serde(flatten)]
    pub decode: AudioSampleArguments,
    /// Directory the WAV goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl AudioSampleExportArguments {
    #[must_use]
    pub fn new(decode: AudioSampleArguments, destination: impl Into<String>) -> Self {
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
