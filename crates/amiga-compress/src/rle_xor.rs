//! Position-XOR + escape-marker run-length decoding.
//!
//! A generic two-layer transform used by several Amiga runtimes to pack their
//! resources:
//!
//! 1. a **position XOR** obfuscation — each byte is XORed with its own buffer
//!    index (`byte ^ (index & 0xFF)`), which is its own inverse; and
//! 2. an **escape-marker run-length** stream — an optional leading big-endian
//!    size field, then a body in which a chosen marker byte introduces a
//!    `(marker, count, value)` triple expanding to `count + 1` copies of
//!    `value`, and any other byte is a literal.
//!
//! The marker byte, whether the XOR layer is present, the width of the leading
//! size field, and where the marker itself is kept are all parameters, since
//! they are title-specific.
//!
//! **Where the marker lives is part of the layout.** Some titles keep it out of
//! band, and the body starts at the size field; others store it as the stream's
//! *first byte*, so the body starts one byte later than any size-field width can
//! express. Decoding the second as the first silently succeeds — the leading
//! marker is consumed as the first `(marker, count, value)` triple and expands
//! to a run that was never in the original — which is why the layout is stated
//! rather than guessed. Two inline layouts are observed and both are
//! expressible: a marker with no size field at all, and a marker followed by a
//! big-endian size that counts its own bytes.

use thiserror::Error;

/// Parameters describing a specific title's variant of the transform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RleXorParams {
    /// The escape byte that introduces a run.
    ///
    /// Stated even when [`Self::inline_marker`] is set, where it becomes a
    /// cross-check rather than the source: a recipe whose marker the stream
    /// contradicts is not the recipe that produced these bytes.
    pub marker: u8,
    /// Whether the position-XOR layer is present.
    pub xor: bool,
    /// Whether the stream's first byte is the escape marker, with everything
    /// else — the size field, if any, and then the body — following it.
    pub inline_marker: bool,
    /// Width of the leading big-endian size field: 0 (none), 2, or 4 bytes.
    pub size_bytes: u8,
    /// Whether the size field counts its own bytes as well as the output.
    ///
    /// Where it does, the declared output is the field minus its own width. A
    /// cross-check that assumed otherwise would reject a correct stream.
    pub size_includes_field: bool,
}

/// The result of [`decode`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RleXorDecoded {
    /// The decompressed bytes.
    pub data: Vec<u8>,
    /// The value of the leading size field, if one was configured.
    pub declared_size: Option<u32>,
}

/// A failure while decoding a position-XOR + RLE stream.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RleXorError {
    #[error("stream is truncated: {what} at offset {offset} needs more bytes")]
    Truncated { what: &'static str, offset: usize },
    #[error("unsupported size-field width {width} (expected 0, 2, or 4)")]
    BadSizeWidth { width: u8 },
    #[error("the stream's first byte is {found:#04x}, but the recipe states marker {stated:#04x}")]
    MarkerMismatch { stated: u8, found: u8 },
    #[error("a size field that counts its own bytes needs a size field")]
    SizeIncludesAbsentField,
    #[error("the {width}-byte size field declares {declared}, less than its own width")]
    SizeBelowFieldWidth { declared: u32, width: u8 },
    #[error("decoded output would exceed the {limit}-byte limit")]
    OutputTooLarge { limit: usize },
}

/// Decode `packed` under `params`: undo the position XOR (if configured), take
/// the inline marker and the leading size field (if configured), then expand the
/// escape-marker run-length body.
///
/// # Errors
/// Returns [`RleXorError::BadSizeWidth`] if `size_bytes` is not 0, 2, or 4,
/// [`RleXorError::SizeIncludesAbsentField`] if `size_includes_field` is set
/// without one, [`RleXorError::MarkerMismatch`] if an inline marker is not the
/// stated one, [`RleXorError::SizeBelowFieldWidth`] if a self-counting field
/// declares less than its own width, and [`RleXorError::Truncated`] if the
/// marker, the size field, or a run runs past the end of the stream.
pub fn decode(packed: &[u8], params: RleXorParams) -> Result<RleXorDecoded, RleXorError> {
    decode_inner(packed, params, None)
}

/// Decode `packed` like [`decode`], refusing to grow the decoded output beyond
/// `limit` bytes.
///
/// The limit is checked before every literal or run is appended. The stream's
/// declared size is not trusted as a substitute because it may be absent or
/// incorrect.
///
/// # Errors
/// Returns [`RleXorError::OutputTooLarge`] before an append would exceed
/// `limit`, in addition to the errors returned by [`decode`].
pub fn decode_bounded(
    packed: &[u8],
    params: RleXorParams,
    limit: usize,
) -> Result<RleXorDecoded, RleXorError> {
    decode_inner(packed, params, Some(limit))
}

fn decode_inner(
    packed: &[u8],
    params: RleXorParams,
    limit: Option<usize>,
) -> Result<RleXorDecoded, RleXorError> {
    if !matches!(params.size_bytes, 0 | 2 | 4) {
        return Err(RleXorError::BadSizeWidth {
            width: params.size_bytes,
        });
    }
    if params.size_includes_field && params.size_bytes == 0 {
        return Err(RleXorError::SizeIncludesAbsentField);
    }

    // Layer 1: position XOR is length-preserving and self-inverse.
    let stream: Vec<u8> = if params.xor {
        packed
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ (index as u8))
            .collect()
    } else {
        packed.to_vec()
    };

    // The inline marker, where the layout carries one. Stating it as well makes
    // this a cross-check: a stream whose first byte is a different escape byte
    // is not the stream this recipe describes, and decoding it anyway would
    // produce plausible bytes and a wrong digest.
    let mut cursor = 0;
    if params.inline_marker {
        let found = *stream.first().ok_or(RleXorError::Truncated {
            what: "inline marker",
            offset: 0,
        })?;
        if found != params.marker {
            return Err(RleXorError::MarkerMismatch {
                stated: params.marker,
                found,
            });
        }
        cursor = 1;
    }

    // Leading size field, after the inline marker where there is one.
    let declared_size = match params.size_bytes {
        2 => {
            let field = stream
                .get(cursor..cursor + 2)
                .ok_or(RleXorError::Truncated {
                    what: "size field",
                    offset: cursor,
                })?;
            let value = u32::from(u16::from_be_bytes([field[0], field[1]]));
            cursor += 2;
            Some(value)
        }
        4 => {
            let field = stream
                .get(cursor..cursor + 4)
                .ok_or(RleXorError::Truncated {
                    what: "size field",
                    offset: cursor,
                })?;
            let value = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
            cursor += 4;
            Some(value)
        }
        _ => None,
    };
    // A field that counts itself declares the output plus its own width, so the
    // output it states is the difference. Reported as the output size either
    // way, because that is what a caller cross-checks against.
    let declared_size = match declared_size {
        Some(declared) if params.size_includes_field => {
            Some(declared.checked_sub(u32::from(params.size_bytes)).ok_or(
                RleXorError::SizeBelowFieldWidth {
                    declared,
                    width: params.size_bytes,
                },
            )?)
        }
        other => other,
    };

    // Layer 2: escape-marker run-length. The declared size is deliberately not
    // trusted for pre-allocation; the output grows as it is produced.
    let mut data = Vec::new();
    while cursor < stream.len() {
        let byte = stream[cursor];
        cursor += 1;
        if byte == params.marker {
            let count = *stream.get(cursor).ok_or(RleXorError::Truncated {
                what: "run count",
                offset: cursor,
            })?;
            let value = *stream.get(cursor + 1).ok_or(RleXorError::Truncated {
                what: "run value",
                offset: cursor + 1,
            })?;
            cursor += 2;
            let end = checked_output_end(data.len(), usize::from(count) + 1, limit)?;
            data.resize(end, value);
        } else {
            checked_output_end(data.len(), 1, limit)?;
            data.push(byte);
        }
    }

    Ok(RleXorDecoded {
        data,
        declared_size,
    })
}

fn checked_output_end(
    current: usize,
    additional: usize,
    limit: Option<usize>,
) -> Result<usize, RleXorError> {
    let error_limit = limit.unwrap_or(usize::MAX);
    let end = current
        .checked_add(additional)
        .ok_or(RleXorError::OutputTooLarge { limit: error_limit })?;
    if limit.is_some_and(|limit| end > limit) {
        return Err(RleXorError::OutputTooLarge { limit: error_limit });
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: RleXorParams = RleXorParams {
        marker: 0x90,
        xor: false,
        inline_marker: false,
        size_bytes: 0,
        size_includes_field: false,
    };

    #[test]
    fn expands_literals_and_runs() {
        // "AB", then (marker,2,'C') -> "CCC", then "D".
        let stream = [b'A', b'B', 0x90, 2, b'C', b'D'];
        let decoded = decode(&stream, PLAIN).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded.data, b"ABCCCD");
        assert_eq!(decoded.declared_size, None);
    }

    #[test]
    fn undoes_the_position_xor() {
        let plain = [b'A', b'B', 0x90, 2, b'C', b'D'];
        let packed: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ (index as u8))
            .collect();
        let params = RleXorParams { xor: true, ..PLAIN };
        let decoded = decode(&packed, params).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded.data, b"ABCCCD");
    }

    #[test]
    fn reads_a_leading_size_field() {
        let mut stream = 6_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(&[b'A', b'B', 0x90, 2, b'C', b'D']);
        let params = RleXorParams {
            size_bytes: 4,
            ..PLAIN
        };
        let decoded = decode(&stream, params).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded.declared_size, Some(6));
        assert_eq!(decoded.data, b"ABCCCD");
    }

    #[test]
    fn rejects_a_truncated_run() {
        assert_eq!(
            decode(&[b'A', 0x90, 2], PLAIN),
            Err(RleXorError::Truncated {
                what: "run value",
                offset: 3,
            })
        );
    }

    #[test]
    fn bounded_decode_accepts_output_at_the_limit() {
        let decoded = decode_bounded(&[b'A', 0x90, 2, b'B'], PLAIN, 4)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded.data, b"ABBB");
    }

    #[test]
    fn bounded_decode_refuses_a_literal_before_it_exceeds_the_limit() {
        assert_eq!(
            decode_bounded(b"AB", PLAIN, 1),
            Err(RleXorError::OutputTooLarge { limit: 1 })
        );
    }

    #[test]
    fn bounded_decode_refuses_a_run_before_it_exceeds_the_limit() {
        assert_eq!(
            decode_bounded(&[b'A', 0x90, u8::MAX, b'B'], PLAIN, 256),
            Err(RleXorError::OutputTooLarge { limit: 256 })
        );
    }

    #[test]
    fn reads_a_marker_the_stream_carries_as_its_first_byte() {
        // Variant 1: marker at 0, body from 1, no size field. Decoding this as
        // an out-of-band marker succeeds and is wrong — the leading marker is
        // eaten as a run — so the two layouts must be stated apart.
        let stream = [0x90, b'A', b'B', 0x90, 2, b'C', b'D'];
        let inline = RleXorParams {
            inline_marker: true,
            ..PLAIN
        };
        let decoded = decode(&stream, inline).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded.data, b"ABCCCD");
        assert_eq!(decoded.declared_size, None);

        // The same bytes under the out-of-band layout: no error, and 70 bytes
        // where the original had 6 — the leading marker took 'A' as a count and
        // 'B' as a value. A valid-looking image and a wrong digest, which is the
        // failure this flag exists to make statable.
        let wrong = decode(&stream, PLAIN).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(wrong.data.len(), 70);
        assert_ne!(wrong.data, decoded.data);
    }

    #[test]
    fn a_self_counting_size_field_declares_the_output_without_its_own_bytes() {
        // Variant 2: marker at 0, a big-endian u32 at 1..5 that counts itself,
        // body from 5. The declared output is 10 - 4 = 6.
        let mut stream = vec![0x90];
        stream.extend_from_slice(&10_u32.to_be_bytes());
        stream.extend_from_slice(&[b'A', b'B', 0x90, 2, b'C', b'D']);
        let params = RleXorParams {
            inline_marker: true,
            size_bytes: 4,
            size_includes_field: true,
            ..PLAIN
        };
        let decoded = decode(&stream, params).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded.data, b"ABCCCD");
        assert_eq!(
            decoded.declared_size,
            Some(6),
            "a cross-check against the field itself would reject a correct stream"
        );
    }

    #[test]
    fn an_inline_marker_the_recipe_contradicts_is_refused() {
        let stream = [0x91, b'A', b'B'];
        let params = RleXorParams {
            inline_marker: true,
            ..PLAIN
        };
        assert_eq!(
            decode(&stream, params),
            Err(RleXorError::MarkerMismatch {
                stated: 0x90,
                found: 0x91,
            })
        );
    }

    #[test]
    fn a_self_counting_field_below_its_own_width_is_refused_not_wrapped() {
        let mut stream = vec![0x90];
        stream.extend_from_slice(&3_u32.to_be_bytes());
        let params = RleXorParams {
            inline_marker: true,
            size_bytes: 4,
            size_includes_field: true,
            ..PLAIN
        };
        assert_eq!(
            decode(&stream, params),
            Err(RleXorError::SizeBelowFieldWidth {
                declared: 3,
                width: 4,
            })
        );
    }

    #[test]
    fn a_self_counting_field_needs_a_field_to_count() {
        let params = RleXorParams {
            size_includes_field: true,
            ..PLAIN
        };
        assert_eq!(
            decode(&[], params),
            Err(RleXorError::SizeIncludesAbsentField)
        );
    }

    #[test]
    fn rejects_an_unsupported_size_width() {
        let params = RleXorParams {
            size_bytes: 3,
            ..PLAIN
        };
        assert_eq!(
            decode(&[], params),
            Err(RleXorError::BadSizeWidth { width: 3 })
        );
    }
}
