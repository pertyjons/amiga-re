//! Bounds-checked, read-only parsing of Amiga LoadSeg/HUNK executables.
//!
//! Parses the `HUNK_HEADER` container, the allocation table, the `CODE`/`DATA`/
//! `BSS` segments, and the trailing `RELOC32`/`SYMBOL`/`DEBUG` records, borrowing
//! segment bytes from the input without copying. Object files, overlays, and
//! load-file variants beyond plain LoadSeg executables are out of scope.
//!
//! [`onefile`] handles one variant that is *nearly* in scope: a self-contained
//! release whose container is ordinary but whose relocation records are packed
//! for its own loader. It rewrites them as standard ones so the rest of this
//! crate, and everything built on it, can read the image.

use amiga_core::{Reader, ReaderError};
use thiserror::Error;

pub mod diff;
pub mod onefile;

pub use diff::{ByteRange, ExecutableDiff, HunkDiff, HunkPresence, diff};
pub use onefile::{OnefileError, normalize};

const HUNK_UNIT: u32 = 0x03e7;
const HUNK_NAME: u32 = 0x03e8;
const HUNK_CODE: u32 = 0x03e9;
const HUNK_DATA: u32 = 0x03ea;
const HUNK_BSS: u32 = 0x03eb;
const HUNK_RELOC32: u32 = 0x03ec;
const HUNK_SYMBOL: u32 = 0x03f0;
const HUNK_DEBUG: u32 = 0x03f1;
const HUNK_END: u32 = 0x03f2;
const HUNK_HEADER: u32 = 0x03f3;

/// Masks off the two memory-attribute flag bits Amiga stores in hunk sizes/tags.
const TAG_MASK: u32 = 0x3fff_ffff;

/// The kind of a primary hunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentKind {
    Code,
    Data,
    Bss,
}

impl std::fmt::Display for SegmentKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Code => "CODE",
            Self::Data => "DATA",
            Self::Bss => "BSS",
        })
    }
}

/// One loaded segment. For `Bss`, `bytes` is empty and `allocation_size` gives
/// the zero-initialized run length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment<'a> {
    pub index: u32,
    pub kind: SegmentKind,
    pub allocation_size: usize,
    pub file_offset: usize,
    pub bytes: &'a [u8],
}

/// A 32-bit relocation: patch `source_offset` within `source_hunk` by the load
/// address of `target_hunk`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Relocation {
    pub source_hunk: u32,
    pub source_offset: u32,
    pub target_hunk: u32,
}

/// A parsed HUNK executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Executable<'a> {
    pub first_hunk: u32,
    pub last_hunk: u32,
    pub segments: Vec<Segment<'a>>,
    pub relocations: Vec<Relocation>,
}

impl<'a> Executable<'a> {
    /// Parse a HUNK executable from `bytes`.
    ///
    /// # Errors
    /// Returns a [`HunkError`] if the input is not a HUNK executable, is
    /// truncated, uses an unsupported hunk type, or fails an internal
    /// consistency check (table size, allocation bounds, relocation bounds, or
    /// trailing bytes).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HunkError> {
        let (executable, consumed) = Self::parse_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(HunkError::TrailingBytes {
                offset: consumed,
                count: bytes.len() - consumed,
            });
        }
        Ok(executable)
    }

    /// Parse one HUNK executable at the start of `bytes`.
    ///
    /// The returned length identifies the complete validated executable while
    /// allowing callers to retain unrelated bytes that follow it. Use
    /// [`Self::parse`] when trailing bytes must be rejected.
    ///
    /// # Errors
    /// Returns a [`HunkError`] if the prefix is not a complete, supported HUNK
    /// executable or fails an internal consistency check.
    pub fn parse_prefix(bytes: &'a [u8]) -> Result<(Self, usize), HunkError> {
        let mut reader = Reader::new(bytes);
        if reader.u32()? != HUNK_HEADER {
            return Err(HunkError::NotExecutable);
        }
        // Optional resident library name list, terminated by a zero-length name.
        loop {
            let words = reader.u32()?;
            if words == 0 {
                break;
            }
            skip_words(&mut reader, words)?;
        }
        let table_size = reader.u32()?;
        let first_hunk = reader.u32()?;
        let last_hunk = reader.u32()?;
        let expected = last_hunk
            .checked_sub(first_hunk)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(HunkError::InvalidHunkRange {
                first: first_hunk,
                last: last_hunk,
            })?;
        if table_size != expected {
            return Err(HunkError::TableSizeMismatch {
                declared: table_size,
                expected,
            });
        }
        let table_len = usize::try_from(table_size).map_err(|_| HunkError::SizeOverflow)?;
        let allocation_table_bytes = table_len.checked_mul(4).ok_or(HunkError::SizeOverflow)?;
        reader.peek(allocation_table_bytes)?;
        let mut allocations = Vec::with_capacity(table_len);
        for _ in 0..table_len {
            allocations.push(words_to_bytes(reader.u32()? & TAG_MASK)?);
        }

        let mut segments = Vec::with_capacity(table_len);
        let mut relocations = Vec::new();
        for (position, allocation_size) in allocations.into_iter().enumerate() {
            skip_metadata(&mut reader)?;
            let tag = reader.u32()? & TAG_MASK;
            let (kind, data_size) = match tag {
                HUNK_CODE => (SegmentKind::Code, words_to_bytes(reader.u32()?)?),
                HUNK_DATA => (SegmentKind::Data, words_to_bytes(reader.u32()?)?),
                HUNK_BSS => (SegmentKind::Bss, words_to_bytes(reader.u32()?)?),
                other => return Err(HunkError::UnsupportedPrimaryHunk { tag: other }),
            };
            if data_size > allocation_size {
                return Err(HunkError::SegmentExceedsAllocation {
                    data_size,
                    allocation_size,
                });
            }
            let file_offset = reader.position();
            let segment_bytes = if kind == SegmentKind::Bss {
                &bytes[file_offset..file_offset]
            } else {
                reader.take(data_size)?
            };
            let index = first_hunk
                .checked_add(u32::try_from(position).map_err(|_| HunkError::SizeOverflow)?)
                .ok_or(HunkError::SizeOverflow)?;
            segments.push(Segment {
                index,
                kind,
                allocation_size,
                file_offset,
                bytes: segment_bytes,
            });
            relocations.extend(read_trailing_records(
                &mut reader,
                index,
                allocation_size,
                first_hunk,
                last_hunk,
            )?);
        }
        let consumed = reader.position();
        Ok((
            Self {
                first_hunk,
                last_hunk,
                segments,
                relocations,
            },
            consumed,
        ))
    }

    /// The segment with the given hunk `index`, if present.
    #[must_use]
    pub fn segment(&self, index: u32) -> Option<&Segment<'a>> {
        self.segments.iter().find(|segment| segment.index == index)
    }

    /// The big-endian 32-bit pointer stored at a relocation's site: the offset
    /// into its target hunk that the relocation points at. Returns `None` if the
    /// source hunk is missing or the site lies outside its bytes.
    #[must_use]
    pub fn stored_pointer(&self, relocation: &Relocation) -> Option<u32> {
        let segment = self.segment(relocation.source_hunk)?;
        Reader::new(segment.bytes)
            .u32_at(relocation.source_offset as usize)
            .ok()
    }
}

fn skip_metadata(reader: &mut Reader<'_>) -> Result<(), HunkError> {
    loop {
        let tag = reader.peek_u32()? & TAG_MASK;
        if tag != HUNK_NAME && tag != HUNK_UNIT {
            return Ok(());
        }
        reader.u32()?;
        let words = reader.u32()?;
        skip_words(reader, words)?;
    }
}

fn read_trailing_records(
    reader: &mut Reader<'_>,
    source_hunk: u32,
    source_size: usize,
    first_hunk: u32,
    last_hunk: u32,
) -> Result<Vec<Relocation>, HunkError> {
    let mut relocations = Vec::new();
    loop {
        let tag = reader.u32()? & TAG_MASK;
        match tag {
            HUNK_END => return Ok(relocations),
            HUNK_RELOC32 => loop {
                let count = reader.u32()?;
                if count == 0 {
                    break;
                }
                let target_hunk = reader.u32()?;
                if !(first_hunk..=last_hunk).contains(&target_hunk) {
                    return Err(HunkError::InvalidRelocationTarget { target_hunk });
                }
                for _ in 0..count {
                    let source_offset = reader.u32()?;
                    let end = usize::try_from(source_offset)
                        .ok()
                        .and_then(|offset| offset.checked_add(4))
                        .ok_or(HunkError::SizeOverflow)?;
                    if !source_offset.is_multiple_of(2) || end > source_size {
                        return Err(HunkError::InvalidRelocationOffset {
                            source_hunk,
                            source_offset,
                            source_size,
                        });
                    }
                    relocations.push(Relocation {
                        source_hunk,
                        source_offset,
                        target_hunk,
                    });
                }
            },
            HUNK_SYMBOL => loop {
                let words = reader.u32()?;
                if words == 0 {
                    break;
                }
                skip_words(reader, words)?;
                reader.u32()?;
            },
            HUNK_DEBUG => {
                let words = reader.u32()?;
                skip_words(reader, words)?;
            }
            other => return Err(HunkError::UnsupportedTrailingHunk { tag: other }),
        }
    }
}

fn skip_words(reader: &mut Reader<'_>, words: u32) -> Result<(), HunkError> {
    reader.skip(words_to_bytes(words)?)?;
    Ok(())
}

fn words_to_bytes(words: u32) -> Result<usize, HunkError> {
    usize::try_from(words)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(HunkError::SizeOverflow)
}

/// A failure while parsing a HUNK executable.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum HunkError {
    #[error("input is not an Amiga HUNK executable")]
    NotExecutable,
    #[error("invalid hunk range {first}..={last}")]
    InvalidHunkRange { first: u32, last: u32 },
    #[error("hunk table declares {declared} entries, expected {expected}")]
    TableSizeMismatch { declared: u32, expected: u32 },
    #[error("hunk size overflows the host address space")]
    SizeOverflow,
    #[error(transparent)]
    Reader(#[from] ReaderError),
    #[error("unsupported primary hunk tag {tag:#x}")]
    UnsupportedPrimaryHunk { tag: u32 },
    #[error("unsupported trailing hunk tag {tag:#x}")]
    UnsupportedTrailingHunk { tag: u32 },
    #[error("relocation targets nonexistent hunk {target_hunk}")]
    InvalidRelocationTarget { target_hunk: u32 },
    #[error(
        "relocation in hunk {source_hunk} at {source_offset:#x} lies outside its {source_size}-byte allocation"
    )]
    InvalidRelocationOffset {
        source_hunk: u32,
        source_offset: u32,
        source_size: usize,
    },
    #[error("segment data has {data_size} bytes but its allocation has {allocation_size}")]
    SegmentExceedsAllocation {
        data_size: usize,
        allocation_size: usize,
    },
    #[error("{count} unexpected trailing bytes at file offset {offset:#x}")]
    TrailingBytes { offset: usize, count: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_word(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn executable_with_relocation(source_offset: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [
            HUNK_HEADER,
            0,
            1,
            0,
            0,
            1,
            HUNK_CODE,
            1,
            0,
            HUNK_RELOC32,
            1,
            0,
            source_offset,
            0,
            HUNK_END,
        ] {
            push_word(&mut bytes, word);
        }
        bytes
    }

    #[test]
    fn parses_a_minimal_code_hunk() {
        let bytes = [
            0, 0, 3, 0xf3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3,
            0xe9, 0, 0, 0, 1, 0x4e, 0x75, 0, 0, 0, 0, 3, 0xf2,
        ];
        let executable = Executable::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(executable.first_hunk, 0);
        assert_eq!(executable.segments.len(), 1);
        assert_eq!(executable.segments[0].kind, SegmentKind::Code);
        assert_eq!(executable.segments[0].bytes, [0x4e, 0x75, 0, 0]);
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(matches!(
            Executable::parse(&[0, 0, 3, 0xf3]),
            Err(HunkError::Reader(ReaderError::Truncated { .. }))
        ));
    }

    #[test]
    fn rejects_data_larger_than_its_allocation() {
        let bytes = [
            0, 0, 3, 0xf3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3,
            0xe9, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(
            Executable::parse(&bytes),
            Err(HunkError::SegmentExceedsAllocation { .. })
        ));
    }

    #[test]
    fn rejects_an_allocation_table_that_cannot_fit_before_allocating() {
        let mut bytes = Vec::new();
        for word in [HUNK_HEADER, 0, u32::MAX, 0, u32::MAX - 1] {
            push_word(&mut bytes, word);
        }
        assert!(matches!(
            Executable::parse(&bytes),
            Err(HunkError::Reader(ReaderError::Truncated { .. }))
        ));
    }

    #[test]
    fn parses_relocation_source_and_target_hunks() {
        let bytes = executable_with_relocation(0);
        let executable = Executable::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            executable.relocations,
            [Relocation {
                source_hunk: 0,
                source_offset: 0,
                target_hunk: 0,
            }]
        );
    }

    #[test]
    fn rejects_a_relocation_outside_its_source_allocation() {
        let bytes = executable_with_relocation(4);
        assert_eq!(
            Executable::parse(&bytes),
            Err(HunkError::InvalidRelocationOffset {
                source_hunk: 0,
                source_offset: 4,
                source_size: 4,
            })
        );
    }

    #[test]
    fn rejects_unexpected_trailing_bytes() {
        let mut bytes = executable_with_relocation(0);
        let executable_len = bytes.len();
        push_word(&mut bytes, 0);
        assert!(matches!(
            Executable::parse(&bytes),
            Err(HunkError::TrailingBytes { .. })
        ));
        let (executable, consumed) =
            Executable::parse_prefix(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(consumed, executable_len);
        assert_eq!(executable.segments.len(), 1);
    }

    #[test]
    fn dereferences_a_relocation_to_its_stored_pointer() {
        let bytes = executable_with_relocation(0);
        let executable = Executable::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let relocation = executable.relocations[0];
        assert!(executable.segment(0).is_some());
        assert!(executable.segment(9).is_none());
        assert_eq!(executable.stored_pointer(&relocation), Some(0));
    }
}
