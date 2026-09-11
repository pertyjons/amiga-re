//! A generic IFF (EA85) `FORM` container reader.
//!
//! Reads the top-level `FORM`, its type, and its chunks, honoring the mandatory
//! even-byte chunk padding. All fields are big-endian. Nested containers
//! (`CAT `/`LIST`) are not interpreted here — a nested `FORM` is returned as an
//! ordinary chunk whose data can be parsed again.

use crate::IffError;

/// One IFF chunk: a four-byte id and its (unpadded) payload, borrowed from the
/// input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chunk<'a> {
    pub id: [u8; 4],
    pub data: &'a [u8],
}

/// A parsed top-level IFF `FORM`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Iff<'a> {
    pub form_type: [u8; 4],
    pub chunks: Vec<Chunk<'a>>,
    /// The whole form, header included, as its own length field declares it.
    ///
    /// A form carved out of a larger file is exactly this long, and anything
    /// recording where it *is* — a project resource, a carve — needs the file's
    /// own answer rather than a caller's guess at one.
    pub form_bytes: usize,
}

impl<'a> Iff<'a> {
    /// Parse the top-level `FORM` in `bytes`.
    ///
    /// # Errors
    /// Returns [`IffError`] if the input is not a `FORM`, or if the declared form
    /// or a chunk size runs past the input.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IffError> {
        if bytes.len() < 12 || &bytes[..4] != b"FORM" {
            return Err(IffError::NotForm);
        }
        let form_payload =
            usize::try_from(read_u32(bytes, 4)).map_err(|_| IffError::FormOutOfBounds)?;
        let form_end = form_payload
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or(IffError::FormOutOfBounds)?;
        let form_type = [bytes[8], bytes[9], bytes[10], bytes[11]];

        let mut cursor = 12;
        let mut chunks = Vec::new();
        while cursor < form_end {
            if cursor + 8 > form_end {
                return Err(IffError::TruncatedChunk {
                    id: id_string(b"????"),
                });
            }
            let id = [
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ];
            let size = usize::try_from(read_u32(bytes, cursor + 4))
                .map_err(|_| IffError::TruncatedChunk { id: id_string(&id) })?;
            let data_start = cursor + 8;
            let data_end = data_start
                .checked_add(size)
                .filter(|end| *end <= form_end)
                .ok_or(IffError::TruncatedChunk { id: id_string(&id) })?;
            chunks.push(Chunk {
                id,
                data: &bytes[data_start..data_end],
            });
            cursor = data_end
                .checked_add(size & 1)
                .filter(|next| *next <= form_end)
                .ok_or(IffError::TruncatedChunk { id: id_string(&id) })?;
        }
        Ok(Self {
            form_type,
            chunks,
            form_bytes: form_end,
        })
    }

    /// The first chunk with the given `id`, if present.
    #[must_use]
    pub fn chunk(&self, id: &[u8; 4]) -> Option<&Chunk<'a>> {
        self.chunks.iter().find(|chunk| &chunk.id == id)
    }
}

/// Render a four-byte IFF id as a readable string (control bytes shown as `.`).
#[must_use]
pub fn id_string(id: &[u8; 4]) -> String {
    id.iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_form_type_and_chunks_with_padding() {
        // FORM containing TYPE, then chunk "AB" with 3 bytes (needs one pad).
        let mut form = b"TYPE".to_vec();
        form.extend_from_slice(b"AB\0\0"); // id "AB\0\0"
        form.extend_from_slice(&3_u32.to_be_bytes());
        form.extend_from_slice(&[1, 2, 3, 0]); // 3 data bytes + 1 pad
        let mut iff = b"FORM".to_vec();
        iff.extend_from_slice(&(form.len() as u32).to_be_bytes());
        iff.extend_from_slice(&form);

        let parsed = Iff::parse(&iff).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&parsed.form_type, b"TYPE");
        assert_eq!(parsed.chunks.len(), 1);
        assert_eq!(parsed.chunks[0].data, &[1, 2, 3]);
    }

    #[test]
    fn rejects_non_form_input() {
        assert!(matches!(Iff::parse(b"NOTFORM...."), Err(IffError::NotForm)));
    }

    #[test]
    fn rejects_a_chunk_that_overruns_the_form() {
        let mut form = b"TYPE".to_vec();
        form.extend_from_slice(b"DATA");
        form.extend_from_slice(&99_u32.to_be_bytes()); // claims 99 bytes
        let mut iff = b"FORM".to_vec();
        iff.extend_from_slice(&(form.len() as u32).to_be_bytes());
        iff.extend_from_slice(&form);
        assert!(matches!(
            Iff::parse(&iff),
            Err(IffError::TruncatedChunk { .. })
        ));
    }
}
