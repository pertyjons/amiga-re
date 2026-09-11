//! Headerless PowerPacker stream decompression.
//!
//! This decodes the raw PowerPacker bitstream used by self-decompressing
//! executables, where the four-entry mode table lives in the loader rather than
//! in a `PP20` file header. Bits are consumed backwards from the end of the
//! stream. Standard `PP20`-headered files are not handled here.
//!
//! The token grammar, backward word/bit order, and match bounds were compared
//! with Teemu Suutari's [Ancient PowerPacker decoder](https://github.com/temisu/ancient/blob/d52dc0c1eec35f14e0da78dd48836ac9542f2f0f/src/PPDecompressor.cpp)
//! (BSD-2-Clause). See `docs/powerpacker-reference-check.md` for the pinned
//! sources, framing differences, and reproducible differential tests. This
//! comparison imports no Ancient implementation code.

use thiserror::Error;

const TRAILER_SIZE: usize = 4;
const MAX_OUTPUT_SIZE: usize = 64 * 1024 * 1024;

/// Decode a headerless PowerPacker stream given the loader's `mode_bits` table.
///
/// # Errors
/// Returns [`PowerPackerError`] if the mode table or sizes are invalid, the
/// bitstream is truncated, or a decoded run/match would fall outside the output.
pub fn decode_embedded_powerpacker(
    packed: &[u8],
    mode_bits: [u8; 4],
) -> Result<Vec<u8>, PowerPackerError> {
    decode_embedded_powerpacker_inner(packed, mode_bits, None)
}

/// Decode a headerless PowerPacker stream without allocating more than
/// `maximum_output_size` decoded bytes.
///
/// The stream declares its decoded size in the trailer. This entry point checks
/// that declaration against both the caller's bound and the codec's absolute
/// safety ceiling before allocating the output buffer.
///
/// # Errors
/// Returns [`PowerPackerError`] if the mode table or sizes are invalid, the
/// declared output exceeds either limit, the bitstream is truncated, or a
/// decoded run/match would fall outside the output.
pub fn decode_embedded_powerpacker_bounded(
    packed: &[u8],
    mode_bits: [u8; 4],
    maximum_output_size: usize,
) -> Result<Vec<u8>, PowerPackerError> {
    decode_embedded_powerpacker_inner(packed, mode_bits, Some(maximum_output_size))
}

fn decode_embedded_powerpacker_inner(
    packed: &[u8],
    mode_bits: [u8; 4],
    maximum_output_size: Option<usize>,
) -> Result<Vec<u8>, PowerPackerError> {
    if mode_bits.into_iter().any(|bits| !(1..=31).contains(&bits)) {
        return Err(PowerPackerError::InvalidModeBits { mode_bits });
    }
    if packed.len() < TRAILER_SIZE + 4 || !packed.len().is_multiple_of(4) {
        return Err(PowerPackerError::InvalidPackedSize { size: packed.len() });
    }

    let trailer_offset = packed.len() - TRAILER_SIZE;
    let trailer = read_u32(packed, trailer_offset)?;
    let output_size = usize::try_from(trailer >> 8)
        .map_err(|_| PowerPackerError::OutputTooLarge { size: usize::MAX })?;
    let initial_skip = (trailer & 0xff) as u8;
    if output_size == 0 {
        return Err(PowerPackerError::OutputTooLarge { size: output_size });
    }
    if let Some(limit) = maximum_output_size
        && output_size > limit
    {
        return Err(PowerPackerError::OutputLimitExceeded {
            size: output_size,
            limit,
        });
    }
    if output_size > MAX_OUTPUT_SIZE {
        return Err(PowerPackerError::OutputTooLarge { size: output_size });
    }
    if initial_skip >= 32 {
        return Err(PowerPackerError::InvalidInitialSkip { bits: initial_skip });
    }

    let mut bits = BackwardBits::new(&packed[..trailer_offset]);
    bits.read(u32::from(initial_skip))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| PowerPackerError::AllocationFailed { size: output_size })?;
    output.resize(output_size, 0_u8);
    let mut cursor = output_size;

    while cursor != 0 {
        if bits.read(1)? == 0 {
            let mut count = 1_usize;
            loop {
                let extension = bits.read(2)?;
                count = count
                    .checked_add(extension as usize)
                    .ok_or(PowerPackerError::CountOverflow)?;
                // An extension need not terminate before its length is known
                // to be impossible. Stop here instead of scanning more input.
                if count > cursor {
                    return Err(PowerPackerError::LiteralExceedsOutput {
                        count,
                        remaining: cursor,
                    });
                }
                if extension != 3 {
                    break;
                }
            }
            for _ in 0..count {
                cursor -= 1;
                output[cursor] = bits.read(8)? as u8;
            }
        }

        if cursor == 0 {
            break;
        }

        let mode = bits.read(2)? as usize;
        let (count, distance) = if mode == 3 {
            if cursor < 5 {
                return Err(PowerPackerError::MatchExceedsOutput {
                    count: 5,
                    remaining: cursor,
                });
            }
            let distance_bits = if bits.read(1)? == 0 {
                7
            } else {
                u32::from(mode_bits[mode])
            };
            let distance = checked_distance(bits.read(distance_bits)?)?;
            let mut count = 5_usize;
            loop {
                let extension = bits.read(3)?;
                count = count
                    .checked_add(extension as usize)
                    .ok_or(PowerPackerError::CountOverflow)?;
                if count > cursor {
                    return Err(PowerPackerError::MatchExceedsOutput {
                        count,
                        remaining: cursor,
                    });
                }
                if extension != 7 {
                    break;
                }
            }
            (count, distance)
        } else {
            (
                mode + 2,
                checked_distance(bits.read(u32::from(mode_bits[mode]))?)?,
            )
        };
        copy_match(&mut output, &mut cursor, distance, count)?;
    }

    Ok(output)
}

fn checked_distance(encoded: u32) -> Result<usize, PowerPackerError> {
    (encoded as usize)
        .checked_add(1)
        .ok_or(PowerPackerError::CountOverflow)
}

fn copy_match(
    output: &mut [u8],
    cursor: &mut usize,
    distance: usize,
    count: usize,
) -> Result<(), PowerPackerError> {
    if count > *cursor {
        return Err(PowerPackerError::MatchExceedsOutput {
            count,
            remaining: *cursor,
        });
    }
    let furthest_source = cursor
        .checked_add(distance)
        .and_then(|value| value.checked_sub(1))
        .ok_or(PowerPackerError::InvalidDistance {
            distance,
            remaining: *cursor,
            output_size: output.len(),
        })?;
    if furthest_source >= output.len() {
        return Err(PowerPackerError::InvalidDistance {
            distance,
            remaining: *cursor,
            output_size: output.len(),
        });
    }
    for _ in 0..count {
        let source = *cursor + distance - 1;
        *cursor -= 1;
        output[*cursor] = output[source];
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PowerPackerError> {
    let word = offset
        .checked_add(4)
        .and_then(|end| bytes.get(offset..end))
        .ok_or(PowerPackerError::TruncatedBitstream)?;
    Ok(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
}

struct BackwardBits<'a> {
    bytes: &'a [u8],
    offset: usize,
    buffer: u32,
    available: u8,
}

impl<'a> BackwardBits<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: bytes.len(),
            buffer: 0,
            available: 0,
        }
    }

    fn read(&mut self, count: u32) -> Result<u32, PowerPackerError> {
        if count > 32 {
            return Err(PowerPackerError::InvalidBitCount { count });
        }
        let mut result = 0_u32;
        for _ in 0..count {
            if self.available == 0 {
                self.offset = self
                    .offset
                    .checked_sub(4)
                    .ok_or(PowerPackerError::TruncatedBitstream)?;
                self.buffer = read_u32(self.bytes, self.offset)?;
                self.available = 32;
            }
            result = (result << 1) | (self.buffer & 1);
            self.buffer >>= 1;
            self.available -= 1;
        }
        Ok(result)
    }
}

/// A failure while decoding a PowerPacker stream.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PowerPackerError {
    #[error("could not allocate {size} bytes for PowerPacker output")]
    AllocationFailed { size: usize },
    #[error("packed stream size {size} is not a valid sequence of 32-bit words")]
    InvalidPackedSize { size: usize },
    #[error("PowerPacker output size {size} is zero or exceeds the safety limit")]
    OutputTooLarge { size: usize },
    #[error("PowerPacker output size {size} exceeds the {limit}-byte limit")]
    OutputLimitExceeded { size: usize, limit: usize },
    #[error("PowerPacker initial bit skip {bits} is not below 32")]
    InvalidInitialSkip { bits: u8 },
    #[error("invalid PowerPacker mode table {mode_bits:?}")]
    InvalidModeBits { mode_bits: [u8; 4] },
    #[error("PowerPacker bitstream ended before output was complete")]
    TruncatedBitstream,
    #[error("PowerPacker requested invalid bit count {count}")]
    InvalidBitCount { count: u32 },
    #[error("PowerPacker length or distance overflowed")]
    CountOverflow,
    #[error("literal run of {count} bytes exceeds {remaining} remaining output bytes")]
    LiteralExceedsOutput { count: usize, remaining: usize },
    #[error("match of {count} bytes exceeds {remaining} remaining output bytes")]
    MatchExceedsOutput { count: usize, remaining: usize },
    #[error(
        "match distance {distance} is invalid with {remaining} bytes remaining in {output_size}-byte output"
    )]
    InvalidDistance {
        distance: usize,
        remaining: usize,
        output_size: usize,
    },
}

#[cfg(test)]
#[path = "powerpacker_tests.rs"]
mod tests;
