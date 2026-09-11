//! A small, bounds-checked, big-endian cursor reader.
//!
//! Amiga container formats (HUNK, IFF, LHA) are big-endian and full of
//! offset/length fields. Every project consolidated here previously carried its
//! own near-identical reader; this is the single canonical version.

use thiserror::Error;

/// Failure while reading past the end of, or outside, the input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReaderError {
    /// A read needed more bytes than remain in the input.
    #[error("input truncated at offset {offset:#x}: need {needed} bytes, have {available}")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    /// A seek targeted a position beyond the end of the input.
    #[error("seek to {position:#x} is outside the {len}-byte input")]
    OutOfRange { position: usize, len: usize },
}

/// A forward cursor over a byte slice, reading big-endian integers.
///
/// The reader borrows its input and never copies; slice-returning methods hand
/// back sub-slices of the original buffer.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader positioned at the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// The current cursor offset from the start of the input.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.cursor
    }

    /// The total length of the input.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the input is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The number of bytes between the cursor and the end of the input.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    /// Move the cursor to an absolute `position` (which may equal the length).
    pub fn set_position(&mut self, position: usize) -> Result<(), ReaderError> {
        if position > self.bytes.len() {
            return Err(ReaderError::OutOfRange {
                position,
                len: self.bytes.len(),
            });
        }
        self.cursor = position;
        Ok(())
    }

    /// Borrow the next `length` bytes without advancing the cursor.
    pub fn peek(&self, length: usize) -> Result<&'a [u8], ReaderError> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ReaderError::Truncated {
                offset: self.cursor,
                needed: length,
                available: self.remaining(),
            })?;
        Ok(&self.bytes[self.cursor..end])
    }

    /// Borrow and consume the next `length` bytes.
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], ReaderError> {
        let slice = self.peek(length)?;
        self.cursor += length;
        Ok(slice)
    }

    /// Skip `length` bytes.
    pub fn skip(&mut self, length: usize) -> Result<(), ReaderError> {
        self.take(length)?;
        Ok(())
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, ReaderError> {
        Ok(self.take(1)?[0])
    }

    /// Peek a big-endian `u16` without advancing.
    pub fn peek_u16(&self) -> Result<u16, ReaderError> {
        let bytes = self.peek(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, ReaderError> {
        let value = self.peek_u16()?;
        self.cursor += 2;
        Ok(value)
    }

    /// Peek a big-endian `u32` without advancing.
    pub fn peek_u32(&self) -> Result<u32, ReaderError> {
        let bytes = self.peek(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, ReaderError> {
        let value = self.peek_u32()?;
        self.cursor += 4;
        Ok(value)
    }

    /// Read a big-endian `u32` at an absolute `offset` without moving the cursor.
    pub fn u32_at(&self, offset: usize) -> Result<u32, ReaderError> {
        let end = offset
            .checked_add(4)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ReaderError::Truncated {
                offset,
                needed: 4,
                available: self.bytes.len().saturating_sub(offset),
            })?;
        let word = &self.bytes[offset..end];
        Ok(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_integers_in_sequence() {
        let mut reader = Reader::new(&[0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xff]);
        assert_eq!(
            reader.u32().unwrap_or_else(|error| panic!("{error}")),
            0x1234_5678
        );
        assert_eq!(
            reader.u16().unwrap_or_else(|error| panic!("{error}")),
            0xabcd
        );
        assert_eq!(reader.u8().unwrap_or_else(|error| panic!("{error}")), 0xff);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn take_borrows_without_copying_and_advances() {
        let data = [1, 2, 3, 4];
        let mut reader = Reader::new(&data);
        let slice = reader.take(3).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(slice, &[1, 2, 3]);
        assert_eq!(reader.position(), 3);
    }

    #[test]
    fn reports_truncation_with_context() {
        let mut reader = Reader::new(&[0, 0]);
        assert_eq!(
            reader.u32(),
            Err(ReaderError::Truncated {
                offset: 0,
                needed: 4,
                available: 2,
            })
        );
    }

    #[test]
    fn rejects_a_seek_past_the_end() {
        let mut reader = Reader::new(&[0, 0]);
        assert_eq!(
            reader.set_position(3),
            Err(ReaderError::OutOfRange {
                position: 3,
                len: 2
            })
        );
        assert!(reader.set_position(2).is_ok());
    }

    #[test]
    fn random_access_does_not_move_the_cursor() {
        let reader = Reader::new(&[0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            reader.u32_at(4).unwrap_or_else(|error| panic!("{error}")),
            0xdead_beef
        );
        assert_eq!(reader.position(), 0);
    }
}
