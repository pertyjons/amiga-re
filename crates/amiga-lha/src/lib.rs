//! LHA/LZH archive reading.
//!
//! An LHA archive is a flat sequence of `[header][compressed data]` entries,
//! ended by a zero header-size byte or by end of input.
//!
//! Scope:
//! - **Header levels 0, 1, and 2** are parsed, including the level 0/1 header
//!   checksum and the stored per-file CRC-16. Level 3 returns
//!   [`LhaError::UnsupportedHeaderLevel`], which names the level so a caller
//!   learns which archiver produced the file rather than that "LHA" failed.
//!
//!   Levels 1 and 2 are not a different format: the header is split, and what
//!   the base header does not carry is carried by a chain of extension headers,
//!   each prefixed by the size of the *next* one and terminated by a zero size.
//!   The compression methods are unchanged, so every member is read by the same
//!   decoders whatever level named it. Two consequences worth stating, because
//!   they are where a level-0 assumption would quietly survive:
//!   - a level 1 base header's `skip size` counts the extension headers as well
//!     as the compressed data, so the member's own size is that field minus the
//!     bytes the extensions took; and
//!   - an extension header may **replace** the name the base header stated
//!     (type `0x01`) and may prefix a directory to it (type `0x02`, whose
//!     separator is `0xff` rather than `/`). A level 2 base header states no
//!     name at all, so there the extension headers are the only source.
//! - Stored entries (`-lh0-`) and directory entries (`-lhd-`) are read directly.
//! - Compressed entries (`-lh1-`, `-lh4-` through `-lh7-`) are decoded by
//!   delharc, using only the member's compressed byte range. Every file is
//!   length-checked and CRC-16 verified after decoding.
//! - `-lh2-`, `-lh3-`, and other unsupported methods can be listed, but
//!   [`Archive::read`] returns [`LhaError::UnsupportedMethod`].
//!
//! [`Entry::is_readable`] is how a caller asks which members this build can
//! actually produce. A member whose recovered bytes do not match its stored
//! CRC-16 is an error. CRC-16 is an integrity check, not proof that every
//! possible decoding error will be detected.

mod decode;

use thiserror::Error;

/// Immutable metadata for a single archive member.
///
/// Reading requires the original reference from [`Archive::entries`]. Cloned
/// metadata and entries from another archive are rejected, even for identical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Five-byte method id, e.g. `*b"-lh5-"`.
    method: [u8; 5],
    /// Entry name with any `\` path separators normalized to `/`.
    name: String,
    compressed_size: u32,
    original_size: u32,
    /// CRC-16 of the uncompressed file, as stored in the header.
    crc16: u16,
    header_level: u8,
    data_offset: usize,
    index: usize,
}

impl Entry {
    /// The normalized member name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The five-byte compression method identifier.
    #[must_use]
    pub fn method(&self) -> &[u8; 5] {
        &self.method
    }

    /// The compressed payload size in bytes.
    #[must_use]
    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// The declared recovered size in bytes.
    #[must_use]
    pub fn original_size(&self) -> u32 {
        self.original_size
    }

    /// The stored CRC-16 of the recovered file.
    #[must_use]
    pub fn crc16(&self) -> u16 {
        self.crc16
    }

    /// The archive header level (0, 1, or 2).
    #[must_use]
    pub fn header_level(&self) -> u8 {
        self.header_level
    }

    /// The method id as a string, e.g. `"-lh5-"`.
    #[must_use]
    pub fn method_str(&self) -> String {
        amiga_core::latin1(&self.method)
    }

    /// Whether this entry is a directory marker (`-lhd-`).
    #[must_use]
    pub fn is_directory(&self) -> bool {
        &self.method == b"-lhd-"
    }

    /// Whether this entry's data is stored uncompressed and can be read now.
    #[must_use]
    pub fn is_stored(&self) -> bool {
        &self.method == b"-lh0-" || self.is_directory()
    }

    /// Whether [`Archive::read`] can produce this entry's bytes.
    ///
    /// True for stored and directory entries, `-lh1-`, and `-lh4-` through
    /// `-lh7-`. Other compression methods are unsupported.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.is_stored() || decode::supports(&self.method)
    }
}

/// Maximum number of recovered file bytes permitted by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct OutputLimit(u64);

impl OutputLimit {
    /// Set an explicit byte ceiling; zero allows only empty file output.
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// The byte ceiling.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// A parsed archive, borrowing the source bytes.
#[derive(Clone, Debug)]
pub struct Archive<'a> {
    bytes: &'a [u8],
    entries: Vec<Entry>,
}

impl<'a> Archive<'a> {
    /// Parse all entry headers in `bytes`.
    ///
    /// # Errors
    /// Returns [`LhaError`] if the archive is truncated, a header checksum fails,
    /// a header uses a level this cut does not yet support, or the stream ends
    /// before naming a member while bytes remain — see [`LhaError::NotAnArchive`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self, LhaError> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            if ends_archive(bytes, pos) {
                // **A file is not an empty archive merely because it starts with
                // a zero byte.** The stream ends at the first such byte, so
                // *anything* beginning with one parsed as a valid archive with no
                // members — an AmigaDOS volume with an unbootable boot block
                // starts with 512 of them, and `lha list` answered "0 member(s)"
                // for a whole disk image. A genuinely empty archive is its
                // terminator and nothing else; unconsumed bytes after it say the
                // file is something this parser was handed by mistake.
                if entries.is_empty() && pos + 1 < bytes.len() {
                    return Err(LhaError::NotAnArchive {
                        offset: pos,
                        trailing: bytes.len() - pos - 1,
                    });
                }
                break;
            }
            let level = *bytes
                .get(pos + 20)
                .ok_or(LhaError::Truncated { offset: pos })?;
            let mut member = match level {
                0 => parse_level0(bytes, pos)?,
                1 => parse_level1(bytes, pos)?,
                2 => parse_level2(bytes, pos)?,
                level => return Err(LhaError::UnsupportedHeaderLevel { level }),
            };
            pos = member.next;
            member.entry.index = entries.len();
            entries.push(member.entry);
        }
        Ok(Self { bytes, entries })
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The raw compressed bytes of an entry borrowed from this archive.
    ///
    /// # Errors
    /// Returns [`LhaError::InvalidEntry`] for foreign or cloned metadata and
    /// [`LhaError::Truncated`] for an invalid or overflowing payload range.
    pub fn compressed_bytes(&self, entry: &Entry) -> Result<&'a [u8], LhaError> {
        if !self
            .entries
            .get(entry.index)
            .is_some_and(|owned| std::ptr::eq(owned, entry))
        {
            return Err(LhaError::InvalidEntry);
        }
        let invalid_range = || LhaError::Truncated {
            offset: entry.data_offset,
        };
        let size = usize::try_from(entry.compressed_size).map_err(|_| invalid_range())?;
        let end = entry
            .data_offset
            .checked_add(size)
            .ok_or_else(invalid_range)?;
        self.bytes
            .get(entry.data_offset..end)
            .ok_or_else(invalid_range)
    }

    /// Decompress `entry` within `limit` and verify its length and CRC-16.
    ///
    /// The limit bounds returned file bytes, not decoder working memory. Both
    /// the declared size and the actual stored payload are checked before any
    /// output is allocated. Directory markers return no file bytes.
    ///
    /// # Errors
    /// Returns [`LhaError::InvalidEntry`] for metadata not borrowed from this
    /// archive, [`LhaError::OutputLimitExceeded`] before exceeding the budget,
    /// or a format, allocation, size, or CRC error without returning partial data.
    pub fn read(&self, entry: &Entry, limit: OutputLimit) -> Result<Vec<u8>, LhaError> {
        let payload = self.compressed_bytes(entry)?;
        if entry.is_directory() {
            return Ok(Vec::new());
        }
        let required = if entry.is_stored() {
            u64::from(entry.original_size).max(payload.len() as u64)
        } else {
            u64::from(entry.original_size)
        };
        if required > limit.bytes() {
            return Err(LhaError::OutputLimitExceeded {
                name: entry.name.clone(),
                required,
                limit: limit.bytes(),
            });
        }
        let original_size =
            usize::try_from(entry.original_size).map_err(|_| LhaError::SizeMismatch {
                name: entry.name.clone(),
                declared: entry.original_size,
                actual: usize::MAX,
            })?;
        let data = if entry.is_stored() {
            if payload.len() != original_size {
                return Err(LhaError::SizeMismatch {
                    name: entry.name.clone(),
                    declared: entry.original_size,
                    actual: payload.len(),
                });
            }
            let mut data = Vec::new();
            data.try_reserve_exact(payload.len())
                .map_err(|error| LhaError::MalformedStream {
                    name: entry.name.clone(),
                    detail: format!("output allocation failed: {error}"),
                })?;
            data.extend_from_slice(payload);
            data
        } else {
            decode::decompress(&entry.method, payload, original_size, &entry.name)?
        };
        let computed = crc16(&data);
        if computed != entry.crc16 {
            return Err(LhaError::CrcMismatch {
                name: entry.name.clone(),
                stored: entry.crc16,
                computed,
            });
        }
        Ok(data)
    }
}

/// One parsed member header and where the next one begins.
struct Member {
    entry: Entry,
    next: usize,
}

/// Extension header type carrying the member's file name.
const EXTENSION_FILENAME: u8 = 0x01;
/// Extension header type carrying the directory the member sits in.
const EXTENSION_DIRECTORY: u8 = 0x02;

/// Whether the archive ends at `pos`.
///
/// A zero first byte terminates an archive of level 0 or 1 headers, where that
/// byte is a one-byte header size. A level 2 header instead begins with the low
/// byte of a little-endian *total* size, which is zero for every header whose
/// size is a multiple of 256 — so there a zero byte is only a terminator when
/// what follows is not a header. The level byte and the shape of the method id
/// decide, because those are the two fields the padding after a terminator
/// cannot plausibly supply.
fn ends_archive(bytes: &[u8], pos: usize) -> bool {
    if bytes[pos] != 0 {
        return false;
    }
    let level_two = bytes.get(pos + 20) == Some(&2);
    let method_shaped = bytes.get(pos + 2) == Some(&b'-')
        && bytes.get(pos + 6) == Some(&b'-')
        && bytes[pos + 1] > 0;
    !(level_two && method_shaped)
}

/// A level 0 header: everything in one block, data straight after it.
fn parse_level0(bytes: &[u8], pos: usize) -> Result<Member, LhaError> {
    let header_size = usize::from(bytes[pos]);
    let header_end = header_end(bytes, pos, header_size)?;
    let header = &bytes[pos + 2..header_end];
    verify_checksum(header, bytes[pos + 1], pos)?;

    // Fields are relative to offset 2 (the start of `header`).
    if header.len() < 22 {
        return Err(LhaError::Truncated { offset: pos });
    }
    let name_len = usize::from(header[19]);
    let name_end = 20_usize
        .checked_add(name_len)
        .filter(|end| end + 2 <= header.len())
        .ok_or(LhaError::Truncated { offset: pos })?;

    member(
        bytes,
        Fields {
            method: method_of(header),
            name: normalize_name(&header[20..name_end]),
            compressed_size: le_u32(header, 5),
            original_size: le_u32(header, 9),
            crc16: le_u16(header, name_end),
            header_level: 0,
            data_offset: header_end,
        },
    )
}

/// A level 1 header: a level 0 header whose trailing fields are replaced by a
/// chain of extension headers, with the data after the chain.
fn parse_level1(bytes: &[u8], pos: usize) -> Result<Member, LhaError> {
    let header_size = usize::from(bytes[pos]);
    let header_end = header_end(bytes, pos, header_size)?;
    let header = &bytes[pos + 2..header_end];
    verify_checksum(header, bytes[pos + 1], pos)?;

    if header.len() < 25 {
        return Err(LhaError::Truncated { offset: pos });
    }
    let name_len = usize::from(header[19]);
    // Name, then the file CRC-16, the OS identifier, and the size of the first
    // extension header: 5 bytes of fixed tail after a 20-byte fixed head.
    if 25_usize.saturating_add(name_len) > header.len() {
        return Err(LhaError::Truncated { offset: pos });
    }
    let skip_size = le_u32(header, 5);
    let extensions = walk_extensions(
        bytes,
        header_end,
        usize::from(le_u16(header, 23 + name_len)),
    )?;

    // `skip size` covers the extension headers as well as the data, so the
    // member's own compressed size is what is left of it.
    let extension_bytes = u32::try_from(extensions.total).unwrap_or(u32::MAX);
    let compressed_size =
        skip_size
            .checked_sub(extension_bytes)
            .ok_or_else(|| LhaError::MalformedHeader {
                offset: pos,
                detail: format!(
                    "the level 1 skip size of {skip_size} is smaller than the {extension_bytes} \
                 bytes of extension headers it has to count"
                ),
            })?;

    member(
        bytes,
        Fields {
            method: method_of(header),
            name: extensions.path(normalize_name(&header[20..20 + name_len])),
            compressed_size,
            original_size: le_u32(header, 9),
            crc16: le_u16(header, 20 + name_len),
            header_level: 1,
            data_offset: extensions.end,
        },
    )
}

/// A level 2 header: a two-byte total size covering the base header and every
/// extension header, with the name carried only by the extensions.
fn parse_level2(bytes: &[u8], pos: usize) -> Result<Member, LhaError> {
    // No header checksum byte at offset 1: level 2 replaced it with a CRC-16 of
    // the whole header in the `0x00` extension header. It is not verified here.
    // Its extent varies between writers, and refusing an archive on a check this
    // build cannot calibrate against a real level 2 archive would reject good
    // media; the per-member CRC-16, which cannot be fooled by a misread header,
    // is the check that decides whether a decode is right.
    let total = usize::from(le_u16(bytes, pos));
    if total < 26 {
        return Err(LhaError::MalformedHeader {
            offset: pos,
            detail: format!("a level 2 header of {total} bytes is shorter than its own fields"),
        });
    }
    let data_offset = pos
        .checked_add(total)
        .filter(|end| *end <= bytes.len())
        .ok_or(LhaError::Truncated { offset: pos })?;
    if bytes.len() < pos + 26 {
        return Err(LhaError::Truncated { offset: pos });
    }

    let extensions = walk_extensions(bytes, pos + 26, usize::from(le_u16(bytes, pos + 24)))?;
    if extensions.end > data_offset {
        return Err(LhaError::MalformedHeader {
            offset: pos,
            detail: format!(
                "the extension headers end at {} but the level 2 total size of {total} puts the \
                 data at {data_offset}",
                extensions.end
            ),
        });
    }
    let name = extensions.path(String::new());
    if name.is_empty() {
        return Err(LhaError::MalformedHeader {
            offset: pos,
            detail: "a level 2 header names its member only in an extension header, and this \
                     one carries neither a file name nor a directory"
                .to_owned(),
        });
    }

    member(
        bytes,
        Fields {
            method: [
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
            ],
            name,
            compressed_size: le_u32(bytes, pos + 7),
            original_size: le_u32(bytes, pos + 11),
            crc16: le_u16(bytes, pos + 21),
            header_level: 2,
            data_offset,
        },
    )
}

/// The fields every level produces, however it spells them.
struct Fields {
    method: [u8; 5],
    name: String,
    compressed_size: u32,
    original_size: u32,
    crc16: u16,
    header_level: u8,
    data_offset: usize,
}

/// Turn parsed fields into an entry, after checking the data is really there.
fn member(bytes: &[u8], fields: Fields) -> Result<Member, LhaError> {
    let next = fields
        .data_offset
        .checked_add(usize::try_from(fields.compressed_size).unwrap_or(usize::MAX))
        .filter(|end| *end <= bytes.len())
        .ok_or(LhaError::Truncated {
            offset: fields.data_offset,
        })?;
    Ok(Member {
        entry: Entry {
            method: fields.method,
            name: fields.name,
            compressed_size: fields.compressed_size,
            original_size: fields.original_size,
            crc16: fields.crc16,
            header_level: fields.header_level,
            data_offset: fields.data_offset,
            index: 0,
        },
        next,
    })
}

/// Where a level 0 or level 1 base header ends, given its size byte.
fn header_end(bytes: &[u8], pos: usize, header_size: usize) -> Result<usize, LhaError> {
    pos.checked_add(2)
        .and_then(|start| start.checked_add(header_size))
        .filter(|end| *end <= bytes.len())
        .ok_or(LhaError::Truncated { offset: pos })
}

fn method_of(header: &[u8]) -> [u8; 5] {
    [header[0], header[1], header[2], header[3], header[4]]
}

/// What a chain of extension headers said.
struct Extensions {
    /// Bytes the whole chain occupied.
    total: usize,
    /// Where the chain — and so the member's data — ends.
    end: usize,
    name: Option<String>,
    directory: Option<String>,
}

impl Extensions {
    /// The member's path: the extension name if there was one, else the name
    /// the base header stated, under whichever directory an extension named.
    fn path(&self, base: String) -> String {
        let name = self.name.clone().unwrap_or(base);
        match &self.directory {
            Some(directory) => format!("{directory}{name}"),
            None => name,
        }
    }
}

/// Walk the chain of extension headers starting at `start`, whose first member
/// is `first` bytes long.
///
/// Each extension header states the size of the *next* one in its own last two
/// bytes, and a zero size ends the chain. The walk therefore always advances by
/// at least three bytes and is bounded by the archive, so a self-referential
/// chain cannot loop.
fn walk_extensions(bytes: &[u8], start: usize, first: usize) -> Result<Extensions, LhaError> {
    let mut cursor = start;
    let mut size = first;
    let mut total = 0_usize;
    let mut name = None;
    let mut directory = None;
    while size != 0 {
        if size < 3 {
            return Err(LhaError::MalformedHeader {
                offset: cursor,
                detail: format!(
                    "an extension header of {size} bytes cannot hold both its type and the size \
                     of the next one"
                ),
            });
        }
        let end = cursor
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or(LhaError::Truncated { offset: cursor })?;
        let extension = &bytes[cursor..end];
        let content = &extension[1..size - 2];
        match extension[0] {
            EXTENSION_FILENAME => name = Some(normalize_name(content)),
            EXTENSION_DIRECTORY => directory = Some(normalize_directory(content)),
            // Every other type — the header CRC, timestamps, permissions —
            // describes the member rather than naming it, and is skipped by
            // its own size rather than by a guess at its contents.
            _ => {}
        }
        total = total.saturating_add(size);
        size = usize::from(u16::from_le_bytes([
            extension[size - 2],
            extension[size - 1],
        ]));
        cursor = end;
    }
    Ok(Extensions {
        total,
        end: cursor,
        name,
        directory,
    })
}

fn verify_checksum(header: &[u8], expected: u8, offset: usize) -> Result<(), LhaError> {
    let computed = header
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    if computed != expected {
        return Err(LhaError::HeaderChecksum {
            offset,
            expected,
            computed,
        });
    }
    Ok(())
}

fn normalize_name(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if *byte == b'\\' {
                '/'
            } else {
                char::from(*byte)
            }
        })
        .collect()
}

/// A directory from an extension header, as a prefix a file name can be
/// appended to.
///
/// Its separator is `0xff` rather than `/`, and it normally already ends with
/// one; a writer that omits the trailing separator would otherwise glue the
/// directory to the file name.
fn normalize_directory(bytes: &[u8]) -> String {
    let mut text: String = bytes
        .iter()
        .map(|byte| match byte {
            0xff | b'\\' => '/',
            other => char::from(*other),
        })
        .collect();
    if !text.is_empty() && !text.ends_with('/') {
        text.push('/');
    }
    text
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// CRC-16/ARC (reflected, polynomial `0xA001`, initial value `0`) as used by
/// LHA for its per-file checksum.
#[must_use]
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xa001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// A failure while reading an LHA archive.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum LhaError {
    #[error("entry metadata does not belong to this archive")]
    InvalidEntry,
    #[error("{name}: {required} output bytes exceed the {limit}-byte budget")]
    OutputLimitExceeded {
        name: String,
        required: u64,
        limit: u64,
    },
    #[error("archive is truncated at offset {offset}")]
    Truncated { offset: usize },
    /// The stream ended before naming a single member, with bytes still to come.
    ///
    /// Distinct from [`LhaError::Truncated`], which is a header running off the
    /// end: this is a file that is not an archive at all. Reported rather than
    /// tolerated because an empty archive and a misidentified file are the same
    /// thing to every caller that asks what a container holds.
    #[error(
        "not an LHA archive: the stream ends at offset {offset} without naming a member, with \
         {trailing} byte(s) after it"
    )]
    NotAnArchive { offset: usize, trailing: usize },
    #[error("header checksum at offset {offset} is {computed:#04x}, expected {expected:#04x}")]
    HeaderChecksum {
        offset: usize,
        expected: u8,
        computed: u8,
    },
    #[error("unsupported LHA header level {level}")]
    UnsupportedHeaderLevel { level: u8 },
    /// The header parses far enough to be read and then contradicts itself.
    /// Distinct from [`LhaError::Truncated`], which is a header that ran off the
    /// end of the file: this one is inside the file and still cannot be true.
    #[error("the header at offset {offset} is malformed: {detail}")]
    MalformedHeader { offset: usize, detail: String },
    #[error("unsupported compression method {method}")]
    UnsupportedMethod { method: String },
    /// The member's compressed stream does not decode. Carries what was wrong
    /// rather than only which member, because a malformed archive is usually
    /// diagnosed by *how* it is malformed.
    #[error("member {name} has a malformed compressed stream: {detail}")]
    MalformedStream { name: String, detail: String },
    #[error("CRC-16 mismatch for {name}: header {stored:#06x}, computed {computed:#06x}")]
    CrcMismatch {
        name: String,
        stored: u16,
        computed: u16,
    },
    #[error("entry {name} size mismatch: header says {declared}, data has {actual}")]
    SizeMismatch {
        name: String,
        declared: u32,
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn level0_entry(method: &[u8; 5], name: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(method);
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed size
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // original size
        body.extend_from_slice(&0_u32.to_le_bytes()); // timestamp
        body.push(0x20); // attribute
        body.push(0); // header level 0
        body.push(name.len() as u8);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&crc16(payload).to_le_bytes());

        let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        let mut entry = vec![body.len() as u8, checksum];
        entry.extend_from_slice(&body);
        entry.extend_from_slice(payload);
        entry
    }

    /// One extension header, with its trailing next-size word left at zero for
    /// [`chain`] to fill in.
    fn extension(kind: u8, content: &[u8]) -> Vec<u8> {
        let mut header = vec![kind];
        header.extend_from_slice(content);
        header.extend_from_slice(&0_u16.to_le_bytes());
        header
    }

    /// Link extension headers so each states the size of the next, and return
    /// the chain's bytes together with the size of the first one.
    fn chain(mut headers: Vec<Vec<u8>>) -> (Vec<u8>, u16) {
        let sizes: Vec<u16> = headers.iter().map(|header| header.len() as u16).collect();
        for (index, header) in headers.iter_mut().enumerate() {
            let next = sizes.get(index + 1).copied().unwrap_or(0);
            let end = header.len();
            header[end - 2..].copy_from_slice(&next.to_le_bytes());
        }
        let first = sizes.first().copied().unwrap_or(0);
        (headers.concat(), first)
    }

    fn level1_entry(
        method: &[u8; 5],
        base_name: &str,
        extensions: Vec<Vec<u8>>,
        payload: &[u8],
    ) -> Vec<u8> {
        let (extensions, first) = chain(extensions);
        let mut body = Vec::new();
        body.extend_from_slice(method);
        // Skip size: the data *and* every extension header.
        body.extend_from_slice(&((payload.len() + extensions.len()) as u32).to_le_bytes());
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes()); // timestamp
        body.push(0x20); // attribute
        body.push(1); // header level 1
        body.push(base_name.len() as u8);
        body.extend_from_slice(base_name.as_bytes());
        body.extend_from_slice(&crc16(payload).to_le_bytes());
        body.push(b'A'); // OS identifier
        body.extend_from_slice(&first.to_le_bytes());

        let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        let mut entry = vec![body.len() as u8, checksum];
        entry.extend_from_slice(&body);
        entry.extend_from_slice(&extensions);
        entry.extend_from_slice(payload);
        entry
    }

    fn level2_entry(method: &[u8; 5], extensions: Vec<Vec<u8>>, payload: &[u8]) -> Vec<u8> {
        let (extensions, first) = chain(extensions);
        let mut entry = Vec::new();
        entry.extend_from_slice(&((26 + extensions.len()) as u16).to_le_bytes());
        entry.extend_from_slice(method);
        entry.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        entry.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        entry.extend_from_slice(&0_u32.to_le_bytes()); // timestamp
        entry.push(0); // reserved
        entry.push(2); // header level 2
        entry.extend_from_slice(&crc16(payload).to_le_bytes());
        entry.push(b'A'); // OS identifier
        entry.extend_from_slice(&first.to_le_bytes());
        entry.extend_from_slice(&extensions);
        entry.extend_from_slice(payload);
        entry
    }

    /// A directory extension header, spelled the way the format spells one:
    /// `0xff` separators, and a trailing one.
    fn directory_extension(path: &str) -> Vec<u8> {
        let content: Vec<u8> = path
            .bytes()
            .map(|byte| if byte == b'/' { 0xff } else { byte })
            .collect();
        extension(EXTENSION_DIRECTORY, &content)
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(entry);
        }
        bytes.push(0); // terminator
        bytes
    }

    #[test]
    fn only_original_entry_references_can_select_payloads() {
        let bytes = archive(&[level0_entry(b"-lh0-", "file", b"abc")]);
        let first = Archive::parse(&bytes).unwrap();
        let second = Archive::parse(&bytes).unwrap();
        let cloned_archive = first.clone();
        let cloned_entry = first.entries()[0].clone();
        for entry in [
            &second.entries()[0],
            &cloned_archive.entries()[0],
            &cloned_entry,
        ] {
            assert!(matches!(
                first.compressed_bytes(entry),
                Err(LhaError::InvalidEntry)
            ));
            assert!(matches!(
                first.read(entry, OutputLimit::new(3)),
                Err(LhaError::InvalidEntry)
            ));
        }
        assert_eq!(first.compressed_bytes(&first.entries()[0]).unwrap(), b"abc");
        assert_eq!(
            cloned_archive
                .read(&cloned_archive.entries()[0], OutputLimit::new(3))
                .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn invalid_and_overflowing_ranges_return_errors() {
        let bytes = archive(&[level0_entry(b"-lh0-", "file", b"abc")]);
        for offset in [bytes.len(), usize::MAX - 1, usize::MAX] {
            let mut archive = Archive::parse(&bytes).unwrap();
            archive.entries[0].data_offset = offset;
            let entry = &archive.entries()[0];
            assert!(matches!(
                archive.compressed_bytes(entry),
                Err(LhaError::Truncated { .. })
            ));
            assert!(matches!(
                archive.read(entry, OutputLimit::new(3)),
                Err(LhaError::Truncated { .. })
            ));
        }
        let mut archive = Archive::parse(&bytes).unwrap();
        archive.entries[0].index = usize::MAX;
        assert!(matches!(
            archive.read(&archive.entries()[0], OutputLimit::new(3)),
            Err(LhaError::InvalidEntry)
        ));
    }

    #[test]
    fn stored_members_check_actual_and_declared_sizes_before_copying() {
        let bytes = archive(&[level0_entry(b"-lh0-", "file", b"abc")]);
        for declared in [0, 1, 3, u32::MAX] {
            let mut archive = Archive::parse(&bytes).unwrap();
            archive.entries[0].original_size = declared;
            assert!(matches!(
                archive.read(&archive.entries()[0], OutputLimit::new(2)),
                Err(LhaError::OutputLimitExceeded { .. })
            ));
        }
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(
            archive
                .read(&archive.entries()[0], OutputLimit::new(3))
                .unwrap(),
            b"abc"
        );
        let bytes = super::tests::archive(&[level0_entry(b"-lh0-", "empty", b"")]);
        let archive = Archive::parse(&bytes).unwrap();
        assert!(
            archive
                .read(&archive.entries()[0], OutputLimit::new(0))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn directory_markers_still_require_owned_metadata() {
        let bytes = archive(&[level0_entry(b"-lhd-", "dir", b"")]);
        let archive = Archive::parse(&bytes).unwrap();
        let entry = &archive.entries()[0];
        assert!(archive.read(entry, OutputLimit::new(0)).unwrap().is_empty());
        assert!(matches!(
            archive.read(&entry.clone(), OutputLimit::new(0)),
            Err(LhaError::InvalidEntry)
        ));
    }

    #[test]
    fn crc16_matches_the_standard_check_vector() {
        assert_eq!(crc16(b"123456789"), 0xbb3d);
    }

    #[test]
    fn lists_and_reads_a_stored_entry() {
        let payload = b"stored payload bytes";
        let bytes = archive(&[level0_entry(b"-lh0-", "readme.txt", payload)]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(archive.entries().len(), 1);

        let entry = &archive.entries()[0];
        assert_eq!(entry.name, "readme.txt");
        assert_eq!(entry.method_str(), "-lh0-");
        assert_eq!(entry.original_size as usize, payload.len());

        let recovered = archive
            .read(entry, OutputLimit::new(64 * 1024 * 1024))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovered, payload);
    }

    #[test]
    fn normalizes_backslash_paths_and_iterates_multiple_entries() {
        let bytes = archive(&[
            level0_entry(b"-lh0-", "dir\\one.dat", b"one"),
            level0_entry(b"-lh0-", "two.dat", b"twobytes"),
        ]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(archive.entries().len(), 2);
        assert_eq!(archive.entries()[0].name, "dir/one.dat");
        assert_eq!(archive.entries()[1].name, "two.dat");
    }

    #[test]
    fn the_remaining_adaptive_methods_are_still_reported_as_unsupported() {
        // `-lh1-` is implemented; `-lh2-` and `-lh3-` are different again, and
        // reading them must say so rather than guess. Listing them is fine.
        for method in [b"-lh2-", b"-lh3-"] {
            let bytes = archive(&[level0_entry(method, "packed.bin", b"not really packed")]);
            let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
            let entry = &archive.entries()[0];
            assert!(
                !entry.is_readable(),
                "{} is not implemented",
                amiga_core::latin1(&entry.method)
            );
            assert!(matches!(
                archive.read(entry, OutputLimit::new(64 * 1024 * 1024)),
                Err(LhaError::UnsupportedMethod { .. })
            ));
        }
    }

    #[test]
    fn an_adaptive_huffman_member_that_does_not_decode_is_a_stream_error() {
        // The same distinction the static methods make: bytes that are not a
        // valid `-lh1-` stream fail as a malformed stream, never as "this build
        // cannot read that method".
        let bytes = archive(&[level0_entry(b"-lh1-", "packed.bin", b"not really packed")]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &archive.entries()[0];
        assert!(entry.is_readable());
        assert!(matches!(
            archive.read(entry, OutputLimit::new(64 * 1024 * 1024)),
            Err(LhaError::MalformedStream { .. } | LhaError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn a_static_huffman_member_that_does_not_decode_is_a_stream_error() {
        // Bytes that are not a valid `-lh5-` stream must fail as a malformed
        // stream, distinguishable from "this build cannot read that method".
        let bytes = archive(&[level0_entry(b"-lh5-", "packed.bin", b"not really packed")]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &archive.entries()[0];
        assert!(entry.is_readable());
        assert!(
            matches!(
                archive.read(entry, OutputLimit::new(64 * 1024 * 1024)),
                Err(LhaError::MalformedStream { .. } | LhaError::SizeMismatch { .. })
            ),
            "{:?}",
            archive.read(entry, OutputLimit::new(64 * 1024 * 1024))
        );
    }

    #[test]
    fn rejects_a_bad_header_checksum() {
        let mut bytes = archive(&[level0_entry(b"-lh0-", "a.txt", b"data")]);
        bytes[1] ^= 0xff; // corrupt the checksum byte
        assert!(matches!(
            Archive::parse(&bytes),
            Err(LhaError::HeaderChecksum { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_header_levels() {
        let mut bytes = archive(&[level0_entry(b"-lh0-", "a.txt", b"data")]);
        bytes[2 + 18] = 3; // header level field (offset 20) -> level 3
        assert!(matches!(
            Archive::parse(&bytes),
            Err(LhaError::UnsupportedHeaderLevel { level: 3 })
        ));
    }

    #[test]
    fn a_level_1_member_is_named_and_sized_past_its_extension_headers() {
        // The name an extension header states replaces the base header's, the
        // directory is prefixed to it, and the data begins after the chain
        // rather than after the base header — which is the whole delta.
        let payload = b"level one payload";
        let bytes = archive(&[level1_entry(
            b"-lh0-",
            "SHORT.TXT",
            vec![
                directory_extension("dev/misc/"),
                extension(EXTENSION_FILENAME, b"the-real-name.txt"),
            ],
            payload,
        )]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(archive.entries().len(), 1);

        let entry = &archive.entries()[0];
        assert_eq!(entry.header_level, 1);
        assert_eq!(entry.name, "dev/misc/the-real-name.txt");
        assert_eq!(entry.compressed_size as usize, payload.len());
        assert_eq!(
            archive
                .read(entry, OutputLimit::new(64 * 1024 * 1024))
                .unwrap_or_else(|error| panic!("{error}")),
            payload
        );
    }

    #[test]
    fn a_level_1_member_without_a_name_extension_keeps_its_base_header_name() {
        // Two members in a row, so the walk past the extension headers has to
        // land exactly on the second header: an off-by-one in the skip-size
        // arithmetic shows up here and nowhere else.
        let bytes = archive(&[
            level1_entry(b"-lh0-", "first.dat", Vec::new(), b"one"),
            level1_entry(
                b"-lh0-",
                "second.dat",
                vec![directory_extension("sub")],
                b"twobytes",
            ),
        ]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(archive.entries().len(), 2);
        assert_eq!(archive.entries()[0].name, "first.dat");
        // The directory extension carried no trailing separator; one is added
        // rather than gluing the two names together.
        assert_eq!(archive.entries()[1].name, "sub/second.dat");
        assert_eq!(
            archive
                .read(&archive.entries()[1], OutputLimit::new(64 * 1024 * 1024))
                .unwrap_or_else(|error| panic!("{error}")),
            b"twobytes"
        );
    }

    #[test]
    fn a_level_1_skip_size_that_cannot_cover_its_extensions_is_malformed() {
        let mut bytes = archive(&[level1_entry(
            b"-lh0-",
            "a.txt",
            vec![extension(EXTENSION_FILENAME, b"b.txt")],
            b"data",
        )]);
        // Skip size sits at file offset 2 + 5, and the checksum has to follow.
        bytes[7..11].copy_from_slice(&0_u32.to_le_bytes());
        let header_size = usize::from(bytes[0]);
        let checksum = bytes[2..2 + header_size]
            .iter()
            .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[1] = checksum;
        assert!(
            matches!(
                Archive::parse(&bytes),
                Err(LhaError::MalformedHeader { .. })
            ),
            "{:?}",
            Archive::parse(&bytes)
        );
    }

    #[test]
    fn a_level_2_member_is_named_only_by_its_extension_headers() {
        let payload = b"level two payload";
        let bytes = archive(&[level2_entry(
            b"-lh0-",
            vec![
                extension(EXTENSION_FILENAME, b"named.bin"),
                directory_extension("data/"),
            ],
            payload,
        )]);
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &archive.entries()[0];
        assert_eq!(entry.header_level, 2);
        assert_eq!(entry.name, "data/named.bin");
        assert_eq!(
            archive
                .read(entry, OutputLimit::new(64 * 1024 * 1024))
                .unwrap_or_else(|error| panic!("{error}")),
            payload
        );
    }

    #[test]
    fn a_level_2_header_naming_nothing_is_malformed_rather_than_nameless() {
        let bytes = archive(&[level2_entry(b"-lh0-", Vec::new(), b"data")]);
        assert!(matches!(
            Archive::parse(&bytes),
            Err(LhaError::MalformedHeader { .. })
        ));
    }

    #[test]
    fn a_level_2_header_whose_size_is_a_multiple_of_256_is_not_the_terminator() {
        // The one place a level 2 archive and a level 0/1 archive disagree about
        // what a zero first byte means. Total size 256 puts a zero in the byte
        // an archive of level 0 headers would read as "no more members".
        let name = extension(EXTENSION_FILENAME, b"padded.bin");
        let padding = extension(0x00, &vec![0_u8; 230 - name.len() - 3]);
        assert_eq!(name.len() + padding.len(), 230);

        let bytes = archive(&[level2_entry(b"-lh0-", vec![name, padding], b"payload")]);
        assert_eq!(bytes[0], 0, "the size word's low byte is what is at stake");
        let archive = Archive::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(archive.entries()[0].name, "padded.bin");
        assert_eq!(
            archive
                .read(&archive.entries()[0], OutputLimit::new(64 * 1024 * 1024))
                .unwrap_or_else(|error| panic!("{error}")),
            b"payload"
        );
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    /// A file is not an empty archive merely because it begins with a zero byte.
    ///
    /// The stream ends at the first zero that does not begin a level-2 header, so
    /// *any* such file parsed as a valid archive with no members — and an
    /// AmigaDOS volume with an unbootable boot block begins with 512 of them.
    /// `lha list` answered "0 member(s)" for a whole disk image, and the project
    /// carrier classifier picked LHA over the ADF reader for the same reason.
    #[test]
    fn a_file_that_names_no_member_is_not_an_empty_archive() {
        let disk_image = vec![0_u8; 10_240];
        match Archive::parse(&disk_image) {
            Err(LhaError::NotAnArchive { offset, trailing }) => {
                assert_eq!(offset, 0);
                assert_eq!(trailing, 10_239);
            }
            other => panic!("a disk image parsed as an archive: {other:?}"),
        }

        // A genuinely empty archive is its terminator and nothing else, and it
        // still parses — the rule is about the bytes that follow, not about
        // emptiness.
        let empty = [0_u8];
        let archive = Archive::parse(&empty).unwrap_or_else(|error| panic!("{error}"));
        assert!(archive.entries().is_empty());
    }
}
