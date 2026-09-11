//! Results of the `audio.*` operations.
use super::*;

/// One run of bytes that scores like raw Paula PCM.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub struct PcmRegion {
    pub offset: u64,
    pub length: u64,
    /// Mean absolute sample amplitude over the region, 0..=128.
    pub mean_amplitude: f32,
    /// Mean absolute step between consecutive samples, relative to amplitude.
    /// Lower is smoother and more waveform-like. Reported beside the amplitude
    /// because the two together are the evidence — a region is a *candidate*,
    /// and a candidate whose score is hidden cannot be judged.
    pub smoothness: f32,
}

/// The `audio.pcm.scan` result.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct PcmScanResult {
    pub source: SourcePin,
    /// The thresholds the scan applied, echoed because raw PCM has no header:
    /// a region is not something the file declares, it is what these numbers
    /// accepted.
    pub block: u64,
    pub minimum_length: u64,
    pub regions: Vec<PcmRegion>,
    pub region_total: u64,
    pub regions_truncated: bool,
}

/// One tracker module found by signature.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FoundModule {
    pub offset: u32,
    pub title: String,
    /// The four-byte format signature, e.g. `M.K.`.
    pub signature: String,
    pub channels: u8,
    /// Entries used in the pattern order table.
    pub song_length: u8,
    pub pattern_count: u64,
    /// Sample slots carrying data. The slots themselves are
    /// `audio.module.decode`'s answer, which reports all 31 — a tracker
    /// addresses samples by slot number, so a scan counting only the used ones
    /// is a summary and not a renumbering.
    pub used_samples: u64,
    /// Total module length in bytes: header, patterns, and sample PCM.
    pub total_length: u64,
}

/// The `audio.module.scan` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ModuleScanResult {
    pub source: SourcePin,
    pub modules: Vec<FoundModule>,
    pub module_total: u64,
    pub modules_truncated: bool,
}

/// The `audio.pcm.decode` result.
///
/// The same bounded envelope `audio.sample.decode` reports, because it is the
/// same question about the same kind of data: a waveform is drawn a few hundred
/// columns wide and each column is a range. Raw PCM has no header, so
/// everything else here is the request's claim echoed back with the bytes
/// pinned — which is exactly what makes it checkable.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PcmDecodeResult {
    pub source: SourcePin,
    /// Byte offset the region was read from.
    pub offset: u64,
    /// Frames in the region. One byte per frame: this is 8-bit signed mono.
    pub frames: u64,
    /// Playback rate the request stated.
    pub sample_rate: u32,
    /// SHA-256 of the region, so a caller can compare two guesses at the same
    /// sample without holding either.
    pub region_sha256: String,
    pub envelope: Vec<WaveformBucket>,
    /// Frames each envelope bucket summarizes.
    pub bucket_frames: u64,
}

/// The `audio.pcm.export` result: the same summary, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PcmExportResult {
    pub pcm: PcmDecodeResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// One sample slot of a tracker module.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ModuleSample {
    /// One-based slot number, as a tracker displays it.
    pub slot: u32,
    pub name: String,
    /// Length in bytes. Zero means the slot is unused.
    pub length: u32,
    pub volume: u32,
    pub finetune: u32,
    pub repeat_start: u32,
    pub repeat_length: u32,
}

/// The `audio.module.decode` result.
///
/// Every unused slot is reported too, with a zero length. A tracker addresses
/// samples by slot number, so dropping the empty ones would renumber the rest.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ModuleResult {
    pub source: SourcePin,
    /// Byte offset the module starts at.
    pub offset: u64,
    pub title: String,
    /// The four-character format signature, e.g. `M.K.` or `6CHN`.
    pub signature: String,
    pub channels: u32,
    pub song_length: u32,
    pub pattern_count: u64,
    /// Total bytes the module occupies, header through sample data.
    pub total_bytes: u64,
    /// SHA-256 of exactly those bytes.
    pub module_sha256: String,
    pub samples: Vec<ModuleSample>,
}

/// The `audio.module.export` result: the same summary, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ModuleExportResult {
    pub module: ModuleResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `audio.sample.decode` result.
///
/// Carries a bounded envelope rather than the samples: a waveform is drawn a
/// few hundred columns wide, and each column is a range. The export writes
/// every frame — the envelope is a view of the sample, never a substitute.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AudioSampleResult {
    pub source: SourcePin,
    /// The `NAME` chunk, empty when the file carries none.
    pub name: String,
    /// Frames per second, as the `VHDR` declares it.
    pub sample_rate: u32,
    /// Frames in the body.
    pub frames: u64,
    /// Frames of the one-shot (non-repeating) part.
    pub one_shot_frames: u64,
    /// Frames of the repeating part; zero when the sample does not loop.
    pub loop_frames: u64,
    pub volume: u32,
    pub envelope: Vec<WaveformBucket>,
    /// Frames each bucket summarizes.
    pub bucket_frames: u64,
    /// Bytes the whole `FORM` occupies from the requested offset, header
    /// included, as its own length field declares it.
    ///
    /// Reported because a caller that wants to record *where this sample is* —
    /// a project resource, a carve — otherwise has to re-parse the container to
    /// find out, and the form already says.
    pub form_bytes: u64,
}

/// One column of a waveform: the extremes of the frames it covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WaveformBucket {
    pub minimum: i8,
    pub maximum: i8,
}

/// The `audio.sample.export` result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioSampleExportResult {
    pub sample: AudioSampleResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}
