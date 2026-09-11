//! Expanding a one-file loader's compact relocation records into standard ones.
//!
//! Some self-contained Amiga releases begin with a perfectly ordinary
//! `HUNK_HEADER`, allocation table, and primary `CODE` / `DATA` / `BSS` records,
//! and then carry `HUNK_RELOC32` payloads encoded for their own bundled loader
//! rather than for `LoadSeg`. Everything downstream of [`crate::Executable`] —
//! `hunk list`, the disassembler, the semantic report — is therefore blind to
//! such an image, not because the container is unusual but because one record
//! type inside it is packed.
//!
//! # The compact encoding
//!
//! All values are big-endian. A `HUNK_RELOC32` payload is a sequence of groups,
//! terminated by a zero count:
//!
//! | Field | Size | Meaning |
//! |---|---:|---|
//! | `count` | 16 bits | Number of offsets in this group; zero ends the record |
//! | `target_hunk` | 16 bits | The hunk the relocations point into |
//! | `first_offset` | 32 bits | The first byte offset within the source hunk |
//! | `delta[count - 1]` | variable | Word-scaled differences from the previous offset |
//!
//! A nonzero delta byte encodes `byte * 2`. A zero byte is an escape followed by
//! a 24-bit value encoding `value * 2`. Each group starts on an even address; the
//! skipped alignment byte is **not** required to be zero and may hold residual
//! data, so it is discarded rather than checked.
//!
//! # The encodings are not distinguishable, so nothing guesses
//!
//! A compact group opens with a 16-bit count where a standard record opens with a
//! 32-bit one. Reading an *ordinary* image as compact therefore takes the high
//! half of its count as a group terminator and shifts everything after it — and
//! reading a compact image as ordinary does the mirror. No flag anywhere says
//! which one a file carries.
//!
//! So [`normalize`] does not sniff, and it is deliberately **not idempotent**: it
//! must only be handed an image already known to be compact. What it does instead
//! is prove its own output — the result has to parse as an ordinary
//! [`crate::Executable`], or it is refused. A caller that does not know which
//! encoding it holds should try [`crate::Executable::parse`] first: an image that
//! already parses needs nothing done to it.
//!
//! # What this does not do
//!
//! Nothing here knows a title. Load addresses, hunk counts, entry points, and
//! relocation totals are properties of one image and stay in the project that
//! owns it; only the structure above lives here.

use amiga_core::{Reader, ReaderError};
use thiserror::Error;

use crate::{
    HUNK_BSS, HUNK_CODE, HUNK_DATA, HUNK_END, HUNK_HEADER, HUNK_RELOC32, TAG_MASK, words_to_bytes,
};

/// Why a one-file image could not be normalized.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum OnefileError {
    #[error(transparent)]
    Reader(#[from] ReaderError),
    #[error("expected tag {expected:#x} at the start of the image, found {actual:#x}")]
    UnexpectedTag { expected: u32, actual: u32 },
    #[error("the header declares the invalid hunk range {first}..={last}")]
    InvalidHunkRange { first: u32, last: u32 },
    #[error("the hunk table declares {declared} entries but the range needs {expected}")]
    TableSizeMismatch { declared: u32, expected: u32 },
    #[error("a size or offset calculation overflowed")]
    SizeOverflow,
    #[error("unsupported primary hunk tag {tag:#x}")]
    UnsupportedPrimaryHunk { tag: u32 },
    #[error("unsupported trailing hunk tag {tag:#x}")]
    UnsupportedTrailingHunk { tag: u32 },
    #[error("hunk {hunk} holds {data_size} bytes, above its {allocation_size}-byte allocation")]
    SegmentExceedsAllocation {
        hunk: u32,
        data_size: usize,
        allocation_size: usize,
    },
    #[error("a relocation targets hunk {target_hunk}, which the header does not declare")]
    InvalidRelocationTarget { target_hunk: u32 },
    #[error(
        "a relocation in hunk {hunk} at {offset:#x} is misaligned or outside its \
         {source_size}-byte allocation"
    )]
    InvalidRelocationOffset {
        hunk: u32,
        offset: u32,
        source_size: usize,
    },
    #[error("{count} unexpected byte(s) after the last hunk, at offset {offset:#x}")]
    TrailingBytes { offset: usize, count: usize },
    #[error(
        "the rewritten image does not parse as a HUNK executable ({0}); the input was \
         probably not compact to begin with"
    )]
    NotNormalizable(String),
}

/// Rewrite `input`'s compact relocation records as standard `HUNK_RELOC32` ones.
///
/// Every count, offset, and target hunk is checked against the declared hunk
/// table before it reaches the output: a relocation that named a hunk the header
/// does not declare, or an offset outside the hunk it patches, would produce a
/// file that parses and then relocates over something else.
///
/// `input` must already be known to carry the compact encoding — see the module
/// documentation for why nothing here can tell. The result is checked against
/// [`crate::Executable::parse`] before it is returned, so an image that was not
/// compact comes back as an error rather than as a plausible, shifted file.
///
/// # Errors
/// Returns [`OnefileError`] if the image is not a HUNK executable, its header is
/// self-contradictory, it carries a hunk type this rewriter does not handle, a
/// relocation is out of range or misaligned, bytes remain after the last hunk, or
/// the rewritten result does not parse.
pub fn normalize(input: &[u8]) -> Result<Vec<u8>, OnefileError> {
    let output = rewrite(input)?;
    // The rewrite's own proof. Reading an ordinary image as compact shifts every
    // record after the first count, and this is what turns that into a refusal
    // instead of a file that looks finished.
    crate::Executable::parse(&output)
        .map_err(|error| OnefileError::NotNormalizable(error.to_string()))?;
    Ok(output)
}

fn rewrite(input: &[u8]) -> Result<Vec<u8>, OnefileError> {
    let mut reader = Reader::new(input);
    let mut output = Vec::with_capacity(input.len());

    let tag = reader.u32()?;
    if tag != HUNK_HEADER {
        return Err(OnefileError::UnexpectedTag {
            expected: HUNK_HEADER,
            actual: tag,
        });
    }
    write_u32(&mut output, tag);

    // Resident library names, which LoadSeg ignores and this copies through.
    loop {
        let name_words = copy_u32(&mut reader, &mut output)?;
        if name_words == 0 {
            break;
        }
        let length = words_to_bytes(name_words).map_err(|_| OnefileError::SizeOverflow)?;
        output.extend_from_slice(reader.take(length)?);
    }

    let table_size = copy_u32(&mut reader, &mut output)?;
    let first_hunk = copy_u32(&mut reader, &mut output)?;
    let last_hunk = copy_u32(&mut reader, &mut output)?;
    let expected = last_hunk
        .checked_sub(first_hunk)
        .and_then(|distance| distance.checked_add(1))
        .ok_or(OnefileError::InvalidHunkRange {
            first: first_hunk,
            last: last_hunk,
        })?;
    if table_size != expected {
        return Err(OnefileError::TableSizeMismatch {
            declared: table_size,
            expected,
        });
    }

    let table_len = usize::try_from(table_size).map_err(|_| OnefileError::SizeOverflow)?;
    let mut allocations = Vec::with_capacity(table_len);
    for _ in 0..table_len {
        let allocation = copy_u32(&mut reader, &mut output)?;
        allocations
            .push(words_to_bytes(allocation & TAG_MASK).map_err(|_| OnefileError::SizeOverflow)?);
    }

    for (position, allocation_size) in allocations.into_iter().enumerate() {
        let source_hunk = u32::try_from(position)
            .ok()
            .and_then(|index| first_hunk.checked_add(index))
            .ok_or(OnefileError::SizeOverflow)?;
        let primary = copy_u32(&mut reader, &mut output)? & TAG_MASK;
        let data_size = match primary {
            HUNK_CODE | HUNK_DATA | HUNK_BSS => words_to_bytes(copy_u32(&mut reader, &mut output)?)
                .map_err(|_| OnefileError::SizeOverflow)?,
            tag => return Err(OnefileError::UnsupportedPrimaryHunk { tag }),
        };
        if data_size > allocation_size {
            return Err(OnefileError::SegmentExceedsAllocation {
                hunk: source_hunk,
                data_size,
                allocation_size,
            });
        }
        // A BSS hunk declares a size and stores no bytes.
        if primary != HUNK_BSS {
            output.extend_from_slice(reader.take(data_size)?);
        }

        loop {
            let tag = reader.u32()? & TAG_MASK;
            write_u32(&mut output, tag);
            match tag {
                HUNK_RELOC32 => expand_relocations(
                    &mut reader,
                    &mut output,
                    source_hunk,
                    allocation_size,
                    first_hunk,
                    last_hunk,
                )?,
                HUNK_END => break,
                tag => return Err(OnefileError::UnsupportedTrailingHunk { tag }),
            }
        }
    }

    // Bytes after the last hunk mean the image is not what it was read as, and a
    // rewrite that silently dropped them would produce a shorter file that looks
    // complete.
    if reader.position() != input.len() {
        return Err(OnefileError::TrailingBytes {
            offset: reader.position(),
            count: input.len().saturating_sub(reader.position()),
        });
    }
    Ok(output)
}

fn expand_relocations(
    reader: &mut Reader<'_>,
    output: &mut Vec<u8>,
    source_hunk: u32,
    source_size: usize,
    first_hunk: u32,
    last_hunk: u32,
) -> Result<(), OnefileError> {
    loop {
        align_word(reader)?;
        let count = reader.u16()?;
        if count == 0 {
            write_u32(output, 0);
            return Ok(());
        }
        let target_hunk = u32::from(reader.u16()?);
        if !(first_hunk..=last_hunk).contains(&target_hunk) {
            return Err(OnefileError::InvalidRelocationTarget { target_hunk });
        }
        let mut offset = reader.u32()?;
        write_u32(output, u32::from(count));
        write_u32(output, target_hunk);
        validate_offset(source_hunk, offset, source_size)?;
        write_u32(output, offset);

        for _ in 1..count {
            let first = reader.u8()?;
            // Zero is the escape, not a zero delta: two relocations cannot share
            // an offset, so a real delta is never zero.
            let encoded = if first == 0 {
                let bytes = reader.take(3)?;
                u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
            } else {
                u32::from(first)
            };
            let delta = encoded.checked_mul(2).ok_or(OnefileError::SizeOverflow)?;
            offset = offset
                .checked_add(delta)
                .ok_or(OnefileError::SizeOverflow)?;
            validate_offset(source_hunk, offset, source_size)?;
            write_u32(output, offset);
        }
    }
}

/// A relocation patches a longword, so it must be word-aligned and its whole
/// four bytes must lie inside the hunk it belongs to.
fn validate_offset(hunk: u32, offset: u32, source_size: usize) -> Result<(), OnefileError> {
    let end = usize::try_from(offset)
        .ok()
        .and_then(|value| value.checked_add(4))
        .ok_or(OnefileError::SizeOverflow)?;
    if !offset.is_multiple_of(2) || end > source_size {
        return Err(OnefileError::InvalidRelocationOffset {
            hunk,
            offset,
            source_size,
        });
    }
    Ok(())
}

/// Skip an alignment byte, without inspecting it.
///
/// The padding is documented as possibly holding residual data, so requiring it
/// to be zero would refuse valid images.
fn align_word(reader: &mut Reader<'_>) -> Result<(), OnefileError> {
    if !reader.position().is_multiple_of(2) {
        reader.u8()?;
    }
    Ok(())
}

fn copy_u32(reader: &mut Reader<'_>, output: &mut Vec<u8>) -> Result<u32, OnefileError> {
    let value = reader.u32()?;
    write_u32(output, value);
    Ok(value)
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Executable;

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// A one-hunk header allocating `allocation_words` longwords.
    fn header(allocation_words: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [HUNK_HEADER, 0, 1, 0, 0, allocation_words] {
            push_u32(&mut bytes, value);
        }
        bytes
    }

    /// The compact image the round-trip test normalizes: one four-longword CODE
    /// hunk with three relocations at 0, 4, and 8 — the second reached by a short
    /// delta and the third by the 24-bit escape.
    fn compact_image() -> Vec<u8> {
        let mut input = header(4);
        push_u32(&mut input, HUNK_CODE);
        push_u32(&mut input, 4);
        input.extend_from_slice(&[0; 16]);
        push_u32(&mut input, HUNK_RELOC32);
        input.extend_from_slice(&3_u16.to_be_bytes()); // count
        input.extend_from_slice(&0_u16.to_be_bytes()); // target hunk
        push_u32(&mut input, 0); // first offset
        input.push(2); // short delta: +4
        input.extend_from_slice(&[0, 0, 0, 2]); // escaped delta: +4
        input.push(0xa5); // alignment byte, deliberately not zero
        input.extend_from_slice(&0_u16.to_be_bytes()); // end of groups
        push_u32(&mut input, HUNK_END);
        input
    }

    /// The same image written with ordinary relocation records, by hand.
    fn ordinary_image() -> Vec<u8> {
        let mut expected = header(4);
        push_u32(&mut expected, HUNK_CODE);
        push_u32(&mut expected, 4);
        expected.extend_from_slice(&[0; 16]);
        push_u32(&mut expected, HUNK_RELOC32);
        push_u32(&mut expected, 3);
        push_u32(&mut expected, 0);
        for offset in [0_u32, 4, 8] {
            push_u32(&mut expected, offset);
        }
        push_u32(&mut expected, 0);
        push_u32(&mut expected, HUNK_END);
        expected
    }

    #[test]
    fn a_normalized_image_equals_the_ordinary_one_and_parses_as_it() {
        // The acceptance criterion is the round trip, not the record count: the
        // output has to be the file an ordinary assembler would have written, and
        // `Executable::parse` has to agree about every relocation in it.
        let normalized =
            normalize(&compact_image()).unwrap_or_else(|error| panic!("should normalize: {error}"));
        assert_eq!(normalized, ordinary_image(), "byte-for-byte");

        let from_compact = Executable::parse(&normalized).unwrap_or_else(|error| panic!("{error}"));
        let ordinary = ordinary_image();
        let from_ordinary = Executable::parse(&ordinary).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(from_compact.relocations, from_ordinary.relocations);
        assert_eq!(from_compact.segments.len(), from_ordinary.segments.len());
        let offsets: Vec<u32> = from_compact
            .relocations
            .iter()
            .map(|relocation| relocation.source_offset)
            .collect();
        assert_eq!(offsets, [0, 4, 8]);
    }

    #[test]
    fn an_ordinary_image_is_refused_rather_than_shifted() {
        // The property that matters most here, and the one that surprised this
        // module into existence: the two encodings are not distinguishable, so
        // normalizing an ordinary image reads its 32-bit count as a 16-bit one and
        // shifts everything after it. That must be an error, never output.
        let ordinary = ordinary_image();
        let result = normalize(&ordinary);
        assert!(
            result.is_err(),
            "an ordinary image was rewritten instead of refused"
        );
        // And the honest way to ask "does this need normalizing?" is whether it
        // already parses.
        assert!(Executable::parse(&ordinary).is_ok());
        assert!(Executable::parse(&compact_image()).is_err());
    }

    #[test]
    fn rejects_a_relocation_outside_its_source_hunk() {
        let mut input = header(1);
        push_u32(&mut input, HUNK_BSS);
        push_u32(&mut input, 1);
        push_u32(&mut input, HUNK_RELOC32);
        input.extend_from_slice(&1_u16.to_be_bytes());
        input.extend_from_slice(&0_u16.to_be_bytes());
        push_u32(&mut input, 2); // 2 + 4 > the 4-byte allocation
        assert!(matches!(
            normalize(&input),
            Err(OnefileError::InvalidRelocationOffset { .. })
        ));
    }

    #[test]
    fn rejects_a_relocation_into_a_hunk_the_header_does_not_declare() {
        let mut input = header(4);
        push_u32(&mut input, HUNK_CODE);
        push_u32(&mut input, 4);
        input.extend_from_slice(&[0; 16]);
        push_u32(&mut input, HUNK_RELOC32);
        input.extend_from_slice(&1_u16.to_be_bytes());
        input.extend_from_slice(&7_u16.to_be_bytes()); // only hunk 0 exists
        push_u32(&mut input, 0);
        assert!(matches!(
            normalize(&input),
            Err(OnefileError::InvalidRelocationTarget { target_hunk: 7 })
        ));
    }

    #[test]
    fn rejects_a_truncated_record_table() {
        let mut input = header(4);
        push_u32(&mut input, HUNK_CODE);
        push_u32(&mut input, 4);
        input.extend_from_slice(&[0; 16]);
        push_u32(&mut input, HUNK_RELOC32);
        input.extend_from_slice(&4_u16.to_be_bytes()); // four offsets promised
        input.extend_from_slice(&0_u16.to_be_bytes());
        push_u32(&mut input, 0);
        input.push(2); // one delta supplied, then nothing
        assert!(matches!(normalize(&input), Err(OnefileError::Reader(_))));
    }

    #[test]
    fn rejects_a_delta_chain_that_overflows() {
        let mut input = header(4);
        push_u32(&mut input, HUNK_CODE);
        push_u32(&mut input, 4);
        input.extend_from_slice(&[0; 16]);
        push_u32(&mut input, HUNK_RELOC32);
        input.extend_from_slice(&2_u16.to_be_bytes());
        input.extend_from_slice(&0_u16.to_be_bytes());
        push_u32(&mut input, u32::MAX - 2);
        input.push(0xff);
        // The first offset is already outside the hunk, so this is refused before
        // the addition; the point is that neither path panics.
        assert!(matches!(
            normalize(&input),
            Err(OnefileError::InvalidRelocationOffset { .. } | OnefileError::SizeOverflow)
        ));
    }

    #[test]
    fn rejects_a_header_whose_table_size_disagrees_with_its_range() {
        let mut input = Vec::new();
        for value in [HUNK_HEADER, 0, 5_u32, 0, 0, 4] {
            push_u32(&mut input, value);
        }
        assert!(matches!(
            normalize(&input),
            Err(OnefileError::TableSizeMismatch {
                declared: 5,
                expected: 1
            })
        ));
    }

    #[test]
    fn rejects_bytes_after_the_last_hunk() {
        let mut input = compact_image();
        input.extend_from_slice(b"junk");
        assert!(matches!(
            normalize(&input),
            Err(OnefileError::TrailingBytes { count: 4, .. })
        ));
    }

    #[test]
    fn rejects_something_that_is_not_a_hunk_executable() {
        assert!(matches!(
            normalize(b"not a hunk file"),
            Err(OnefileError::UnexpectedTag { .. })
        ));
    }
}
