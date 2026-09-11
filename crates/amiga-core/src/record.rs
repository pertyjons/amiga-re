//! Decoding a byte region as an array of fixed-layout, big-endian records.
//!
//! Amiga games store menus, level tables, and entity arrays as arrays of C-like
//! structs. A layout is written as a comma-separated field list, e.g.
//! `u16,u16,u32ptr,char[16]`, and read big-endian:
//!
//! - `u8`/`u16`/`u32`, `i8`/`i16`/`i32`: scalar integers;
//! - `ptr` (alias `u32ptr`): a 32-bit value flagged as a pointer;
//! - `char[N]`: `N` bytes decoded as a NUL-terminated Latin-1 string;
//! - `bytes[N]`: `N` raw bytes;
//! - `pad[N]`: `N` bytes skipped (produces no value).

use thiserror::Error;

use crate::reader::{Reader, ReaderError};
use crate::strings::latin1_cstr;

/// A field type in a record layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    I8,
    I16,
    I32,
    /// A 32-bit pointer.
    Ptr,
    /// A NUL-terminated Latin-1 string in `N` bytes.
    Char(usize),
    /// `N` raw bytes.
    Bytes(usize),
    /// `N` skipped bytes.
    Pad(usize),
}

impl FieldType {
    /// The size of this field in bytes.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::U8 | Self::I8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::Ptr => 4,
            Self::Char(n) | Self::Bytes(n) | Self::Pad(n) => n,
        }
    }
}

/// A decoded field value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldValue {
    Unsigned(u32),
    Signed(i32),
    Pointer(u32),
    Text(String),
    Bytes(Vec<u8>),
}

/// The total size in bytes of one record described by `layout`.
#[must_use]
pub fn record_size(layout: &[FieldType]) -> usize {
    layout.iter().map(|field| field.size()).sum()
}

/// Parse a layout spec such as `"u16,u16,u32ptr,char[16]"`.
///
/// # Errors
/// Returns [`LayoutError`] for an empty spec, an unknown field type, or a
/// malformed array length.
pub fn parse_layout(spec: &str) -> Result<Vec<FieldType>, LayoutError> {
    let fields = spec
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(parse_field)
        .collect::<Result<Vec<_>, _>>()?;
    if fields.is_empty() {
        return Err(LayoutError::Empty);
    }
    Ok(fields)
}

fn parse_field(token: &str) -> Result<FieldType, LayoutError> {
    match token {
        "u8" => Ok(FieldType::U8),
        "u16" => Ok(FieldType::U16),
        "u32" => Ok(FieldType::U32),
        "i8" => Ok(FieldType::I8),
        "i16" => Ok(FieldType::I16),
        "i32" => Ok(FieldType::I32),
        "ptr" | "u32ptr" => Ok(FieldType::Ptr),
        _ => {
            if let Some(length) = array_length(token, "char") {
                Ok(FieldType::Char(length?))
            } else if let Some(length) = array_length(token, "bytes") {
                Ok(FieldType::Bytes(length?))
            } else if let Some(length) = array_length(token, "pad") {
                Ok(FieldType::Pad(length?))
            } else {
                Err(LayoutError::UnknownField(token.to_owned()))
            }
        }
    }
}

fn array_length(token: &str, prefix: &str) -> Option<Result<usize, LayoutError>> {
    let inner = token
        .strip_prefix(prefix)?
        .strip_prefix('[')?
        .strip_suffix(']')?;
    Some(
        inner
            .parse::<usize>()
            .map_err(|_| LayoutError::BadLength(token.to_owned())),
    )
}

/// Read one record from `reader` according to `layout`. `Pad` fields advance the
/// reader without producing a value.
///
/// # Errors
/// Returns [`ReaderError`] if the record extends past the input.
pub fn read_record(
    reader: &mut Reader<'_>,
    layout: &[FieldType],
) -> Result<Vec<FieldValue>, ReaderError> {
    let mut values = Vec::with_capacity(layout.len());
    for field in layout {
        match *field {
            FieldType::U8 => values.push(FieldValue::Unsigned(u32::from(reader.u8()?))),
            FieldType::U16 => values.push(FieldValue::Unsigned(u32::from(reader.u16()?))),
            FieldType::U32 => values.push(FieldValue::Unsigned(reader.u32()?)),
            FieldType::I8 => values.push(FieldValue::Signed(i32::from(reader.u8()? as i8))),
            FieldType::I16 => values.push(FieldValue::Signed(i32::from(reader.u16()? as i16))),
            FieldType::I32 => values.push(FieldValue::Signed(reader.u32()? as i32)),
            FieldType::Ptr => values.push(FieldValue::Pointer(reader.u32()?)),
            FieldType::Char(n) => values.push(FieldValue::Text(latin1_cstr(reader.take(n)?))),
            FieldType::Bytes(n) => values.push(FieldValue::Bytes(reader.take(n)?.to_vec())),
            FieldType::Pad(n) => reader.skip(n)?,
        }
    }
    Ok(values)
}

/// A failure while parsing a record layout.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum LayoutError {
    #[error("layout has no fields")]
    Empty,
    #[error("unknown field type {0:?}")]
    UnknownField(String),
    #[error("invalid array length in {0:?}")]
    BadLength(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_layout_and_sizes_it() {
        let layout =
            parse_layout("u16, u16, u32ptr, char[16]").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            layout,
            [
                FieldType::U16,
                FieldType::U16,
                FieldType::Ptr,
                FieldType::Char(16)
            ]
        );
        assert_eq!(record_size(&layout), 24);
    }

    #[test]
    fn rejects_bad_layouts() {
        assert_eq!(parse_layout(""), Err(LayoutError::Empty));
        assert!(matches!(
            parse_layout("u17"),
            Err(LayoutError::UnknownField(_))
        ));
        assert!(matches!(
            parse_layout("char[x]"),
            Err(LayoutError::BadLength(_))
        ));
    }

    #[test]
    fn reads_a_record() {
        let layout =
            parse_layout("u16,i16,ptr,char[6],pad[2]").unwrap_or_else(|error| panic!("{error}"));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0102_u16.to_be_bytes());
        bytes.extend_from_slice(&(-2_i16).to_be_bytes());
        bytes.extend_from_slice(&0x0001_2000_u32.to_be_bytes());
        bytes.extend_from_slice(b"HI\0\0\0\0");
        bytes.extend_from_slice(&[0xaa, 0xbb]); // padding, skipped
        let mut reader = Reader::new(&bytes);
        let values = read_record(&mut reader, &layout).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            values,
            vec![
                FieldValue::Unsigned(0x0102),
                FieldValue::Signed(-2),
                FieldValue::Pointer(0x0001_2000),
                FieldValue::Text("HI".to_owned()),
            ]
        );
    }
}
