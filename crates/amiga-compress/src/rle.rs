//! IFF ByteRun1 (PackBits) run-length decoding.
//!
//! This is the standard run-length scheme used by compressed IFF ILBM `BODY`
//! chunks and by Apple PackBits. A signed control byte `n` means:
//!
//! - `0..=127`: copy the next `n + 1` bytes literally;
//! - `-127..=-1`: output the next byte `1 - n` times (2..=128 copies);
//! - `-128`: no operation.

use thiserror::Error;

/// A failure while decoding a ByteRun1 stream.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RleError {
    #[error("ByteRun1 stream is truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("ByteRun1 output exceeded the {limit}-byte limit")]
    OutputTooLarge { limit: usize },
}

/// Decode an IFF ByteRun1 / PackBits stream, refusing to produce more than
/// `limit` bytes.
///
/// A replicate run turns two input bytes into up to 128 output bytes, so a
/// caller that knows how large the result must be should say so rather than
/// letting a malformed stream decide how much memory to take. The limit is a
/// refusal, never a truncation: a stream that wants more is an error, because a
/// silently clipped image is worse than none.
///
/// # Errors
/// Returns [`RleError::Truncated`] if a literal run or a replicate byte extends
/// past the end of `input`, and [`RleError::OutputTooLarge`] if the stream
/// decodes to more than `limit` bytes.
pub fn decode_byte_run1_bounded(input: &[u8], limit: usize) -> Result<Vec<u8>, RleError> {
    let decoded = decode_byte_run1_inner(input, Some(limit))?;
    Ok(decoded)
}

/// Decode an IFF ByteRun1 / PackBits stream.
///
/// # Errors
/// Returns [`RleError::Truncated`] if a literal run or a replicate byte extends
/// past the end of `input`.
pub fn decode_byte_run1(input: &[u8]) -> Result<Vec<u8>, RleError> {
    decode_byte_run1_inner(input, None)
}

fn decode_byte_run1_inner(input: &[u8], limit: Option<usize>) -> Result<Vec<u8>, RleError> {
    // The limit is checked *before* each run is appended, so a hostile stream
    // never gets to allocate the memory it asked for and then be rejected.
    let grow = |output: &mut Vec<u8>, count: usize| -> Result<(), RleError> {
        if let Some(limit) = limit
            && output
                .len()
                .checked_add(count)
                .is_none_or(|end| end > limit)
        {
            return Err(RleError::OutputTooLarge { limit });
        }
        Ok(())
    };
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let control = input[cursor] as i8;
        cursor += 1;
        if control >= 0 {
            let count = control as usize + 1;
            let end = cursor
                .checked_add(count)
                .filter(|end| *end <= input.len())
                .ok_or(RleError::Truncated { offset: cursor })?;
            grow(&mut output, count)?;
            output.extend_from_slice(&input[cursor..end]);
            cursor = end;
        } else if control != i8::MIN {
            let count = usize::try_from(1 - i32::from(control)).unwrap_or_default();
            let byte = *input
                .get(cursor)
                .ok_or(RleError::Truncated { offset: cursor })?;
            cursor += 1;
            grow(&mut output, count)?;
            output.resize(output.len() + count, byte);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_a_literal_run() {
        // control 2 => copy 3 literal bytes.
        assert_eq!(
            decode_byte_run1(&[2, b'a', b'b', b'c']),
            Ok(b"abc".to_vec())
        );
    }

    #[test]
    fn replicates_a_byte() {
        // control -3 (0xFD) => output next byte 1 - (-3) = 4 times.
        assert_eq!(decode_byte_run1(&[0xfd, b'z']), Ok(b"zzzz".to_vec()));
    }

    #[test]
    fn treats_minus_128_as_no_op() {
        assert_eq!(decode_byte_run1(&[0x80, 0, b'a']), Ok(b"a".to_vec()));
    }

    #[test]
    fn mixes_literal_and_replicate_runs() {
        let stream = [1, b'X', b'Y', 0xfe, b'!']; // "XY" then "!" x3
        assert_eq!(decode_byte_run1(&stream), Ok(b"XY!!!".to_vec()));
    }

    #[test]
    fn rejects_a_truncated_literal_run() {
        assert_eq!(
            decode_byte_run1(&[5, b'a']),
            Err(RleError::Truncated { offset: 1 })
        );
    }
}
