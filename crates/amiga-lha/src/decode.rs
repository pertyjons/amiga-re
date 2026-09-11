//! Payload-only adapter over delharc 0.8.0 (MIT OR Apache-2.0).
//!
//! Archive framing and CRC verification remain in `Archive`. Passing only the
//! member's compressed slice prevents decoder read-ahead into the next header.
//! Delharc supplies the Huffman trees and initialized sliding dictionaries.
//! Output stops at the declared length, including midway through a match.

use delharc::decode::{Decoder, DecoderAny};
use delharc::header::CompressionMethod;

use crate::LhaError;

fn compression_method(id: &[u8; 5]) -> Option<CompressionMethod> {
    match id {
        b"-lh1-" => Some(CompressionMethod::Lh1),
        b"-lh4-" => Some(CompressionMethod::Lh4),
        b"-lh5-" => Some(CompressionMethod::Lh5),
        b"-lh6-" => Some(CompressionMethod::Lh6),
        b"-lh7-" => Some(CompressionMethod::Lh7),
        _ => None,
    }
}

pub(crate) fn supports(id: &[u8; 5]) -> bool {
    compression_method(id).is_some()
}

pub(crate) fn decompress(
    id: &[u8; 5],
    payload: &[u8],
    original_size: usize,
    name: &str,
) -> Result<Vec<u8>, LhaError> {
    let method = compression_method(id).ok_or_else(|| LhaError::UnsupportedMethod {
        method: amiga_core::latin1(id),
    })?;
    let malformed = |detail: String| LhaError::MalformedStream {
        name: name.to_owned(),
        detail,
    };
    let mut decoder = DecoderAny::new_from_compression(method, payload);
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    // Grow only after decoding bytes: a truncated input with a large declared
    // length must not trigger an upfront allocation of that entire length.
    while output.len() < original_size {
        let count = buffer.len().min(original_size - output.len());
        decoder
            .fill_buffer(&mut buffer[..count])
            .map_err(|error| malformed(error.to_string()))?;
        output
            .try_reserve(count)
            .map_err(|error| malformed(format!("cannot allocate decoded output: {error}")))?;
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}
