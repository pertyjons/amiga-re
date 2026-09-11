//! IFF (EA85) container reading, 8SVX sample decoding, ILBM image decoding, and
//! WAV export.
//!
//! [`Iff::parse`] reads any IFF `FORM`; [`parse_8svx`] decodes an 8SVX sound
//! form into a [`Sample`]; [`encode_wav`] writes that sample as a WAV file;
//! [`ilbm::decode`] decodes an ILBM image into palette indices and its palette.

pub mod container;
pub mod ilbm;
pub mod pcm;
pub mod svx;
pub mod tracker;
pub mod wav;

use thiserror::Error;

pub use container::{Chunk, Iff, id_string};
pub use ilbm::{Ilbm, IlbmError, IlbmWarning, IlbmWarningKind, Masking, decode as decode_ilbm};
pub use pcm::{PcmRegion, ScanParams, scan as scan_pcm};
pub use svx::{AmigaVolume, LoopLength, Sample, SampleCount, SampleRate, parse_8svx};
pub use wav::{encode_pcm, encode_wav};

/// A failure while reading an IFF container or decoding a sample.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IffError {
    #[error("input is not an IFF FORM")]
    NotForm,
    #[error("IFF FORM size is outside the input")]
    FormOutOfBounds,
    #[error("IFF chunk {id} is truncated")]
    TruncatedChunk { id: String },
    #[error("expected IFF FORM type {expected}, found {found}")]
    UnexpectedFormType { expected: String, found: String },
    #[error("required IFF chunk {id} is missing")]
    MissingChunk { id: String },
    #[error("duplicate IFF chunk {id}")]
    DuplicateChunk { id: String },
    #[error("8SVX sample rate is zero")]
    ZeroSampleRate,
    #[error("unsupported 8SVX compression method {method}")]
    UnsupportedCompression { method: u8 },
    #[error("8SVX declares {declared} sample bytes but BODY has {actual}")]
    SampleLengthMismatch { declared: u64, actual: usize },
    #[error("sample is too large to encode as WAV")]
    WavTooLarge,
}
