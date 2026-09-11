//! IFF 8SVX sampled-sound decoding.
//!
//! Handles uncompressed mono 8-bit samples: it reads the `VHDR` and `BODY`
//! chunks the format requires, validates that the declared one-shot and repeat
//! lengths match the body, and exposes the raw signed PCM. Fibonacci-delta
//! compression is rejected.
//!
//! `NAME` is read when present and is not required. The 8SVX specification
//! lists only `VHDR` and `BODY` as mandatory, and a sample ripped from a game —
//! this toolkit's usual input — routinely carries neither a name nor an author.
//! Demanding one turned an ordinary file into an unreadable one.

use crate::IffError;
use crate::container::{Iff, id_string, read_u32};

/// Samples per second (playback rate) of a sample.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SampleRate(u16);

impl SampleRate {
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Length in samples of the one-shot (non-repeating) portion.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SampleCount(u32);

impl SampleCount {
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Length in samples of the repeat (looped) portion.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LoopLength(u32);

impl LoopLength {
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The 0..=64 Amiga hardware volume stored in the `VHDR`.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AmigaVolume(u32);

impl AmigaVolume {
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A decoded 8SVX sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sample {
    name: String,
    sample_rate: SampleRate,
    one_shot: SampleCount,
    loop_length: LoopLength,
    volume: AmigaVolume,
    pcm: Vec<i8>,
    form_bytes: usize,
}

impl Sample {
    /// The `NAME` chunk, empty when the file carries none.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn sample_rate(&self) -> SampleRate {
        self.sample_rate
    }

    pub fn one_shot(&self) -> SampleCount {
        self.one_shot
    }

    pub fn loop_length(&self) -> LoopLength {
        self.loop_length
    }

    pub fn volume(&self) -> AmigaVolume {
        self.volume
    }

    #[must_use]
    pub fn pcm(&self) -> &[i8] {
        &self.pcm
    }

    /// How many bytes the whole `FORM` occupies, header included.
    ///
    /// The form's own declaration, not the length of the buffer it was parsed
    /// from: a sample carved out of a larger file is exactly this long, and
    /// anything recording where it *is* needs the file's answer rather than a
    /// guess at one.
    #[must_use]
    pub const fn form_bytes(&self) -> usize {
        self.form_bytes
    }
}

/// Parse a standalone IFF 8SVX `FORM`.
///
/// # Errors
/// Returns [`IffError`] if the input is not an 8SVX form, a required chunk is
/// missing or duplicated, the compression method is unsupported, or the declared
/// sample length does not match the `BODY`.
pub fn parse_8svx(bytes: &[u8]) -> Result<Sample, IffError> {
    let iff = Iff::parse(bytes)?;
    if &iff.form_type != b"8SVX" {
        return Err(IffError::UnexpectedFormType {
            expected: id_string(b"8SVX"),
            found: id_string(&iff.form_type),
        });
    }

    let mut vhdr = None;
    let mut name = None;
    let mut body = None;
    for chunk in &iff.chunks {
        match &chunk.id {
            b"VHDR" => set_once(&mut vhdr, chunk.data, "VHDR")?,
            b"NAME" => set_once(&mut name, chunk.data, "NAME")?,
            b"BODY" => set_once(&mut body, chunk.data, "BODY")?,
            _ => {}
        }
    }

    let vhdr = vhdr.ok_or(IffError::MissingChunk { id: "VHDR".into() })?;
    if vhdr.len() < 20 {
        return Err(IffError::TruncatedChunk { id: "VHDR".into() });
    }
    let sample_rate = u16::from_be_bytes([vhdr[12], vhdr[13]]);
    if sample_rate == 0 {
        return Err(IffError::ZeroSampleRate);
    }
    let compression = vhdr[15];
    if compression != 0 {
        return Err(IffError::UnsupportedCompression {
            method: compression,
        });
    }
    let one_shot = read_u32(vhdr, 0);
    let repeat = read_u32(vhdr, 4);
    let declared = u64::from(one_shot) + u64::from(repeat);
    let body = body.ok_or(IffError::MissingChunk { id: "BODY".into() })?;
    if declared != body.len() as u64 {
        return Err(IffError::SampleLengthMismatch {
            declared,
            actual: body.len(),
        });
    }
    // Optional by the specification, so absence is not an error: an unnamed
    // sample reports an empty name, which is what the operation layer has always
    // documented it would.
    let name = name.map(amiga_core::latin1_cstr).unwrap_or_default();

    Ok(Sample {
        name,
        sample_rate: SampleRate(sample_rate),
        one_shot: SampleCount(one_shot),
        loop_length: LoopLength(repeat),
        volume: AmigaVolume(read_u32(vhdr, 16)),
        pcm: body.iter().map(|byte| i8::from_ne_bytes([*byte])).collect(),
        form_bytes: iff.form_bytes,
    })
}

fn set_once<'a>(
    target: &mut Option<&'a [u8]>,
    value: &'a [u8],
    chunk: &'static str,
) -> Result<(), IffError> {
    if target.replace(value).is_some() {
        return Err(IffError::DuplicateChunk { id: chunk.into() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_wav;

    fn form_8svx(compression: u8) -> Vec<u8> {
        form_8svx_named(compression, Some(b"TEST"))
    }

    fn form_8svx_named(compression: u8, name: Option<&[u8]>) -> Vec<u8> {
        let mut form = b"8SVX".to_vec();
        append_chunk(
            &mut form,
            b"VHDR",
            &[
                0,
                0,
                0,
                4, // one-shot samples
                0,
                0,
                0,
                0, // repeat samples
                0,
                0,
                0,
                0, // samples per cycle
                0x20,
                0xab, // samples/sec = 8363
                1,
                compression, // octaves, compression
                0,
                1,
                0,
                0, // volume = 0x00010000
            ],
        );
        if let Some(name) = name {
            append_chunk(&mut form, b"NAME", name);
        }
        append_chunk(&mut form, b"BODY", &[0x80, 0xff, 0, 0x7f]);
        let mut iff = b"FORM".to_vec();
        iff.extend_from_slice(&(form.len() as u32).to_be_bytes());
        iff.extend_from_slice(&form);
        iff
    }

    fn append_chunk(form: &mut Vec<u8>, id: &[u8; 4], data: &[u8]) {
        form.extend_from_slice(id);
        form.extend_from_slice(&(data.len() as u32).to_be_bytes());
        form.extend_from_slice(data);
        if !data.len().is_multiple_of(2) {
            form.push(0);
        }
    }

    #[test]
    fn parses_uncompressed_mono_sample() {
        let sample = parse_8svx(&form_8svx(0)).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(sample.name(), "TEST");
        assert_eq!(sample.sample_rate().get(), 8_363);
        assert_eq!(sample.one_shot().get(), 4);
        assert_eq!(sample.loop_length().get(), 0);
        assert_eq!(sample.pcm(), &[i8::MIN, -1, 0, i8::MAX]);

        let wav = encode_wav(&sample).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[36..40], b"data");
        assert_eq!(&wav[44..], &[0, 127, 128, 255]);
    }

    #[test]
    fn parses_a_sample_that_carries_no_name() {
        // Only `VHDR` and `BODY` are required by the format, and a sample ripped
        // from a game usually has nothing else. It must decode rather than come
        // back as unreadable, and it must still export.
        let sample =
            parse_8svx(&form_8svx_named(0, None)).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(sample.name(), "");
        assert_eq!(sample.sample_rate().get(), 8_363);
        assert_eq!(sample.pcm(), &[i8::MIN, -1, 0, i8::MAX]);

        let wav = encode_wav(&sample).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(&wav[44..], &[0, 127, 128, 255]);
    }

    #[test]
    fn still_refuses_a_sample_with_no_body() {
        // Dropping the `NAME` requirement must not drop the two the format does
        // state: an empty name is a fact about the file, a missing body is not.
        let mut form = b"8SVX".to_vec();
        append_chunk(&mut form, b"NAME", b"TEST");
        let mut iff = b"FORM".to_vec();
        iff.extend_from_slice(&(form.len() as u32).to_be_bytes());
        iff.extend_from_slice(&form);
        assert_eq!(
            parse_8svx(&iff),
            Err(IffError::MissingChunk { id: "VHDR".into() })
        );
    }

    #[test]
    fn rejects_compressed_eight_svx() {
        assert_eq!(
            parse_8svx(&form_8svx(1)),
            Err(IffError::UnsupportedCompression { method: 1 })
        );
    }
}
