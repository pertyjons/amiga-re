//! Minimal WAV (RIFF/PCM) export for decoded samples.

use crate::IffError;
use crate::svx::Sample;

/// Encode `sample` as an 8-bit unsigned mono WAV file.
///
/// Amiga PCM is signed; WAV 8-bit PCM is unsigned, so each byte is biased by
/// `0x80`.
///
/// # Errors
/// Returns [`IffError::WavTooLarge`] if the sample does not fit a 32-bit RIFF
/// size field.
pub fn encode_wav(sample: &Sample) -> Result<Vec<u8>, IffError> {
    encode_pcm(sample.pcm(), sample.sample_rate().get())
}

/// Encode raw signed 8-bit mono `pcm` played at `sample_rate` Hz as a WAV file.
///
/// This is the container `encode_wav` uses, exposed for raw Paula PCM that was
/// never wrapped in an 8SVX form. Amiga PCM is signed; WAV 8-bit PCM is
/// unsigned, so each byte is biased by `0x80`.
///
/// # Errors
/// Returns [`IffError::WavTooLarge`] if the sample does not fit a 32-bit RIFF
/// size field.
pub fn encode_pcm(pcm: &[i8], sample_rate: u16) -> Result<Vec<u8>, IffError> {
    let data_size = u32::try_from(pcm.len()).map_err(|_| IffError::WavTooLarge)?;
    let padding = data_size & 1;
    let riff_size = 36_u32
        .checked_add(data_size)
        .and_then(|size| size.checked_add(padding))
        .ok_or(IffError::WavTooLarge)?;
    let capacity = usize::try_from(riff_size)
        .ok()
        .and_then(|size| size.checked_add(8))
        .ok_or(IffError::WavTooLarge)?;
    let mut wav = Vec::with_capacity(capacity);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16_u32.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1_u16.to_le_bytes()); // mono
    wav.extend_from_slice(&u32::from(sample_rate).to_le_bytes());
    wav.extend_from_slice(&u32::from(sample_rate).to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes()); // block align
    wav.extend_from_slice(&8_u16.to_le_bytes()); // bits per sample
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_size.to_le_bytes());
    wav.extend(pcm.iter().map(|value| value.to_ne_bytes()[0] ^ 0x80));
    if padding != 0 {
        wav.push(0);
    }
    Ok(wav)
}
