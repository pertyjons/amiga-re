//! IFF ILBM image decoding: the standard Amiga image container.
//!
//! Both halves of this already existed and nothing joined them — the IFF
//! container here, planar deinterleaving and RGB4→RGB8 in `amiga-hw` — so a
//! caller holding an ILBM had to locate the `BODY` by hand, undo the compression
//! itself, and supply geometry the `BMHD` chunk already states. This is the join.
//!
//! # What is decoded and what is refused
//!
//! Compression 0 (none) and 1 (ByteRun1) are decoded. Any other value is refused
//! by number rather than guessed at.
//!
//! **HAM and Extra-Halfbrite are refused by name.** A HAM image's palette indices
//! do not mean what they say — each pixel either selects a register or modifies
//! the previous pixel's colour — and an EHB image's upper half of the register
//! range is the lower half at half brightness. Rendering either as flat indices
//! produces a picture that is wrong in a way the viewer cannot see, which is the
//! one failure this toolkit refuses to ship. When they are implemented it must be
//! as an explicit, typed step; until then [`IlbmError::UnsupportedViewportMode`]
//! names the mode.
//!
//! # Row alignment
//!
//! An ILBM row is **word**-aligned: `((width + 15) / 16) * 2` bytes per plane per
//! row, which is not the same as `width.div_ceil(8)` for any width that is not a
//! multiple of 16. `amiga_hw::planar::deinterleave` works in the latter, so the
//! rows are repacked before they reach it rather than handing it a stride it would
//! misread. Getting this wrong shifts every row of a 17-pixel-wide image by a
//! byte, which is exactly the kind of quiet corruption a caller cannot spot.

use amiga_hw::planar::{IndexedImage, PlaneOrder};

use crate::IffError;
use crate::container::Iff;

/// The largest image this decoder will allocate for.
///
/// A generous bound rather than a limit anyone should reach: it exists so a
/// `BMHD` claiming 65535×65535×8 fails immediately instead of asking for 34
/// gigabytes.
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;

/// How the form says transparency is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Masking {
    None,
    /// An extra bitplane per row, interleaved with the data planes.
    HasMask,
    /// One palette index is transparent; see [`Ilbm::transparent_color`].
    HasTransparentColor,
    /// A lasso outline. Carried as a mask plane in practice.
    Lasso,
}

/// A failure while decoding an ILBM form.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IlbmError {
    #[error(transparent)]
    Iff(#[from] IffError),
    #[error("BMHD is {0} bytes, too short for a bitmap header")]
    ShortHeader(usize),
    #[error("image dimensions {width}x{height} are invalid")]
    InvalidDimensions { width: u16, height: u16 },
    #[error("{planes} bitplanes is outside the 1..=8 this decoder indexes")]
    UnsupportedPlanes { planes: u8 },
    #[error("unsupported BMHD masking value {0}")]
    UnsupportedMasking(u8),
    #[error("unsupported BMHD compression method {0}")]
    UnsupportedCompression(u8),
    #[error(
        "the CAMG viewport declares {mode}, which this decoder refuses rather \
         than rendering as flat palette indices"
    )]
    UnsupportedViewportMode { mode: String },
    #[error("the image needs {needed} bytes, above the {MAX_IMAGE_BYTES}-byte limit")]
    ImageTooLarge { needed: u64 },
    #[error("BODY holds {actual} bytes but the geometry needs {needed}")]
    BodyTruncated { needed: usize, actual: usize },
    #[error("decompressing BODY: {0}")]
    Compression(#[from] amiga_compress::RleError),
    #[error("deinterleaving the bitplanes: {0}")]
    Planar(#[from] amiga_hw::planar::PlanarError),
}

/// A tolerated inconsistency in an ILBM form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IlbmWarningKind {
    /// `CMAP` holds fewer entries than the plane count can index. No entry is
    /// invented for the rest; a consumer decides what to do about them.
    PaletteShorterThanPlanes,
    /// The form carries no `CMAP` at all.
    PaletteMissing,
    /// `BODY` held more bytes than the geometry needs. The extra is ignored.
    BodyLongerThanGeometry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IlbmWarning {
    pub kind: IlbmWarningKind,
    pub message: String,
}

/// A decoded ILBM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ilbm {
    /// One palette index per pixel.
    pub image: IndexedImage,
    /// `CMAP` entries as RGB8, in order. Empty when the form carries none —
    /// never filled with invented colours.
    pub palette: Vec<[u8; 3]>,
    pub masking: Masking,
    /// The transparent index, meaningful only for [`Masking::HasTransparentColor`].
    pub transparent_color: u16,
    /// One byte per pixel, 1 where the mask plane is set. Present only when the
    /// form interleaves a mask plane, which is consumed either way rather than
    /// being left to shift the data planes.
    pub mask: Option<Vec<u8>>,
    /// The raw `CAMG` viewport mode word, when the form carries one.
    pub viewport_mode: Option<u32>,
    /// Pixel aspect, as `BMHD` states it.
    pub aspect: (u8, u8),
    pub warnings: Vec<IlbmWarning>,
}

/// The CAMG bits this decoder refuses.
const CAMG_HAM: u32 = 0x0800;
const CAMG_EXTRA_HALFBRITE: u32 = 0x0080;

/// Decode an ILBM `FORM`.
///
/// # Errors
/// Returns [`IlbmError`] if the input is not an ILBM form, `BMHD` or `BODY` is
/// missing or malformed, the geometry is unusable or above [`MAX_IMAGE_BYTES`],
/// the compression method is not 0 or 1, or the viewport declares HAM or
/// Extra-Halfbrite.
pub fn decode(bytes: &[u8]) -> Result<Ilbm, IlbmError> {
    let iff = Iff::parse(bytes)?;
    if &iff.form_type != b"ILBM" {
        return Err(IffError::UnexpectedFormType {
            expected: "ILBM".to_owned(),
            found: crate::container::id_string(&iff.form_type),
        }
        .into());
    }

    let header = iff
        .chunk(b"BMHD")
        .ok_or_else(|| IffError::MissingChunk { id: "BMHD".into() })?;
    if header.data.len() < 20 {
        return Err(IlbmError::ShortHeader(header.data.len()));
    }
    let width = u16::from_be_bytes([header.data[0], header.data[1]]);
    let height = u16::from_be_bytes([header.data[2], header.data[3]]);
    let planes = header.data[8];
    let masking = match header.data[9] {
        0 => Masking::None,
        1 => Masking::HasMask,
        2 => Masking::HasTransparentColor,
        3 => Masking::Lasso,
        other => return Err(IlbmError::UnsupportedMasking(other)),
    };
    let compression = header.data[10];
    let transparent_color = u16::from_be_bytes([header.data[12], header.data[13]]);
    let aspect = (header.data[14], header.data[15]);

    if width == 0 || height == 0 {
        return Err(IlbmError::InvalidDimensions { width, height });
    }
    if planes == 0 || planes > 8 {
        return Err(IlbmError::UnsupportedPlanes { planes });
    }

    // Refused before any decoding, so a HAM image never reaches the point where
    // it could be rendered as something it is not.
    let viewport_mode = iff.chunk(b"CAMG").and_then(|chunk| {
        (chunk.data.len() >= 4).then(|| {
            u32::from_be_bytes([chunk.data[0], chunk.data[1], chunk.data[2], chunk.data[3]])
        })
    });
    if let Some(mode) = viewport_mode {
        let mut refused = Vec::new();
        if mode & CAMG_HAM != 0 {
            refused.push(if planes >= 7 { "HAM8" } else { "HAM6" });
        }
        if mode & CAMG_EXTRA_HALFBRITE != 0 {
            refused.push("Extra-Halfbrite");
        }
        if !refused.is_empty() {
            return Err(IlbmError::UnsupportedViewportMode {
                mode: refused.join(" + "),
            });
        }
    }

    // An ILBM row is word-aligned, per plane. The mask, when present, is one more
    // plane in every row and must be counted here or every row after the first
    // is read from the wrong place.
    let row_bytes = (usize::from(width).div_ceil(16)) * 2;
    let data_planes = usize::from(planes);
    let has_mask_plane = matches!(masking, Masking::HasMask | Masking::Lasso);
    let row_planes = data_planes + usize::from(has_mask_plane);
    let needed = (row_bytes as u64)
        .checked_mul(row_planes as u64)
        .and_then(|per_row| per_row.checked_mul(u64::from(height)))
        .ok_or(IlbmError::ImageTooLarge { needed: u64::MAX })?;
    if needed > MAX_IMAGE_BYTES as u64 {
        return Err(IlbmError::ImageTooLarge { needed });
    }
    // Checked before decompressing, so a malformed run-length has a ceiling to
    // hit rather than a machine to exhaust.
    let needed = needed as usize;

    let body = iff
        .chunk(b"BODY")
        .ok_or_else(|| IffError::MissingChunk { id: "BODY".into() })?;
    let planar = match compression {
        0 => body.data.to_vec(),
        1 => amiga_compress::decode_byte_run1_bounded(body.data, needed)?,
        other => return Err(IlbmError::UnsupportedCompression(other)),
    };
    let mut warnings = Vec::new();
    if planar.len() < needed {
        return Err(IlbmError::BodyTruncated {
            needed,
            actual: planar.len(),
        });
    }
    if planar.len() > needed {
        warnings.push(IlbmWarning {
            kind: IlbmWarningKind::BodyLongerThanGeometry,
            message: format!(
                "BODY holds {} bytes, {} more than the geometry needs; the extra is ignored",
                planar.len(),
                planar.len() - needed
            ),
        });
    }

    // Repack from ILBM's word-aligned rows into the byte-aligned stride
    // `deinterleave` expects, dropping the mask plane into its own buffer so it is
    // neither ignored nor left to shift the data.
    let packed_row = usize::from(width).div_ceil(8);
    let mut data = Vec::with_capacity(packed_row * data_planes * usize::from(height));
    let mut mask_rows =
        has_mask_plane.then(|| Vec::with_capacity(packed_row * usize::from(height)));
    for row in 0..usize::from(height) {
        for plane in 0..row_planes {
            let start = (row * row_planes + plane) * row_bytes;
            let source = &planar[start..start + packed_row];
            if plane < data_planes {
                data.extend_from_slice(source);
            } else if let Some(mask) = mask_rows.as_mut() {
                mask.extend_from_slice(source);
            }
        }
    }

    let image = amiga_hw::planar::deinterleave(
        &data,
        usize::from(width),
        usize::from(height),
        planes,
        PlaneOrder::Interleaved,
    )?;
    // The mask is one plane, so deinterleaving it as a single-plane image gives
    // one byte per pixel without a second bit-twiddling loop here.
    let mask = mask_rows
        .map(|rows| {
            amiga_hw::planar::deinterleave(
                &rows,
                usize::from(width),
                usize::from(height),
                1,
                PlaneOrder::Interleaved,
            )
            .map(|image| image.pixels)
        })
        .transpose()?;

    // `CMAP` is RGB8 already: applying the RGB4 conversion to it would darken
    // every colour by a factor of sixteen.
    let palette: Vec<[u8; 3]> = iff
        .chunk(b"CMAP")
        .map(|chunk| {
            chunk
                .data
                .as_chunks::<3>()
                .0
                .iter()
                .map(|entry| [entry[0], entry[1], entry[2]])
                .collect()
        })
        .unwrap_or_default();
    if palette.is_empty() {
        warnings.push(IlbmWarning {
            kind: IlbmWarningKind::PaletteMissing,
            message: "the form carries no CMAP; no palette was invented".to_owned(),
        });
    } else if palette.len() < 1_usize << planes {
        warnings.push(IlbmWarning {
            kind: IlbmWarningKind::PaletteShorterThanPlanes,
            message: format!(
                "CMAP holds {} entries but {planes} planes index {}; the rest are unnamed",
                palette.len(),
                1_usize << planes
            ),
        });
    }

    Ok(Ilbm {
        image,
        palette,
        masking,
        transparent_color,
        mask,
        viewport_mode,
        aspect,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(id);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        if !data.len().is_multiple_of(2) {
            out.push(0);
        }
        out
    }

    fn bmhd(width: u16, height: u16, planes: u8, masking: u8, compression: u8) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&0_u16.to_be_bytes()); // x
        header.extend_from_slice(&0_u16.to_be_bytes()); // y
        header.push(planes);
        header.push(masking);
        header.push(compression);
        header.push(0); // pad
        header.extend_from_slice(&0_u16.to_be_bytes()); // transparent colour
        header.push(1); // x aspect
        header.push(1); // y aspect
        header.extend_from_slice(&width.to_be_bytes()); // page width
        header.extend_from_slice(&height.to_be_bytes()); // page height
        header
    }

    fn form(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.iter().flatten().copied().collect();
        let mut out = Vec::new();
        out.extend_from_slice(b"FORM");
        out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        out.extend_from_slice(b"ILBM");
        out.extend_from_slice(&body);
        out
    }

    /// A 16x2, two-plane image whose pixels are `(x + y) % 4`.
    fn two_plane_body() -> (Vec<u8>, Vec<u8>) {
        let width = 16_usize;
        let height = 2_usize;
        let mut expected = Vec::new();
        let mut planar = Vec::new();
        for y in 0..height {
            let mut rows = [0_u16; 2];
            for x in 0..width {
                let index = ((x + y) % 4) as u16;
                expected.push(index as u8);
                for (plane, row) in rows.iter_mut().enumerate() {
                    if index >> plane & 1 == 1 {
                        *row |= 0x8000 >> x;
                    }
                }
            }
            for row in rows {
                planar.extend_from_slice(&row.to_be_bytes());
            }
        }
        (planar, expected)
    }

    #[test]
    fn decodes_an_uncompressed_two_plane_image() {
        let (planar, expected) = two_plane_body();
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 2, 0, 0)),
            chunk(b"CMAP", &[0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]),
            chunk(b"BODY", &planar),
        ]);
        let ilbm = decode(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ilbm.image.width, 16);
        assert_eq!(ilbm.image.height, 2);
        assert_eq!(ilbm.image.pixels, expected);
        assert_eq!(ilbm.palette.len(), 4);
        assert_eq!(ilbm.palette[1], [255, 0, 0]);
        assert!(ilbm.mask.is_none());
        assert!(ilbm.warnings.is_empty(), "{:?}", ilbm.warnings);
    }

    #[test]
    fn decodes_the_same_image_compressed_with_byte_run1() {
        let (planar, expected) = two_plane_body();
        // Literal runs only: a valid ByteRun1 encoding, and the one a compressor
        // falls back to.
        let mut packed = Vec::new();
        for row in planar.chunks(2) {
            packed.push((row.len() - 1) as u8);
            packed.extend_from_slice(row);
        }
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 2, 0, 1)),
            chunk(b"BODY", &packed),
        ]);
        let ilbm = decode(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ilbm.image.pixels, expected);
        // No CMAP: a warning, and no invented colours.
        assert!(ilbm.palette.is_empty());
        assert!(
            ilbm.warnings
                .iter()
                .any(|warning| warning.kind == IlbmWarningKind::PaletteMissing)
        );
    }

    #[test]
    fn a_word_aligned_row_is_not_a_byte_aligned_one() {
        // 17 pixels: 4 bytes per row in the file, 3 bytes' worth of pixels. A
        // decoder using `div_ceil(8)` as the stride reads row 1 a byte early and
        // every row after it drifts further.
        let width = 17_usize;
        let mut planar = Vec::new();
        let mut expected = Vec::new();
        for y in 0..3_usize {
            let mut row = [0_u8; 4];
            for x in 0..width {
                let set = (x + y) % 2 == 0;
                expected.push(u8::from(set));
                if set {
                    row[x / 8] |= 0x80 >> (x % 8);
                }
            }
            planar.extend_from_slice(&row);
        }
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(17, 3, 1, 0, 0)),
            chunk(b"BODY", &planar),
        ]);
        let ilbm = decode(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ilbm.image.pixels, expected, "row stride is wrong");
    }

    #[test]
    fn a_mask_plane_is_consumed_and_exposed_rather_than_shifting_the_data() {
        // One data plane and one mask plane, 16x2. If the mask were ignored, row 1
        // of the data would be read from the mask of row 0.
        let mut planar = Vec::new();
        for y in 0..2_u16 {
            let data: u16 = if y == 0 { 0xff00 } else { 0x00ff };
            let mask: u16 = 0xf0f0;
            planar.extend_from_slice(&data.to_be_bytes());
            planar.extend_from_slice(&mask.to_be_bytes());
        }
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 1, 1, 0)),
            chunk(b"BODY", &planar),
        ]);
        let ilbm = decode(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ilbm.masking, Masking::HasMask);
        let expected_data: Vec<u8> = (0..16)
            .map(|x| u8::from(x < 8))
            .chain((0..16).map(|x| u8::from(x >= 8)))
            .collect();
        assert_eq!(ilbm.image.pixels, expected_data);
        let mask = ilbm.mask.unwrap_or_else(|| panic!("the mask is exposed"));
        let expected_mask: Vec<u8> = (0..2)
            .flat_map(|_| (0..16).map(|x: usize| u8::from((x / 4).is_multiple_of(2))))
            .collect();
        assert_eq!(mask, expected_mask);
    }

    #[test]
    fn ham_and_extra_halfbrite_are_refused_by_name() {
        let (planar, _) = two_plane_body();
        for (mode, expected) in [
            (CAMG_HAM, "HAM6"),
            (CAMG_EXTRA_HALFBRITE, "Extra-Halfbrite"),
        ] {
            let bytes = form(&[
                chunk(b"BMHD", &bmhd(16, 2, 2, 0, 0)),
                chunk(b"CAMG", &mode.to_be_bytes()),
                chunk(b"BODY", &planar),
            ]);
            let Err(IlbmError::UnsupportedViewportMode { mode }) = decode(&bytes) else {
                panic!("{expected} was not refused");
            };
            assert!(mode.contains(expected), "{mode}");
        }
        // HAM8 is named differently, because eight planes mean a different
        // decoder, not a different palette.
        let deep: Vec<u8> = vec![0; 2 * 8 * 2];
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 8, 0, 0)),
            chunk(b"CAMG", &CAMG_HAM.to_be_bytes()),
            chunk(b"BODY", &deep),
        ]);
        let Err(IlbmError::UnsupportedViewportMode { mode }) = decode(&bytes) else {
            panic!("HAM8 was not refused");
        };
        assert_eq!(mode, "HAM8");
    }

    #[test]
    fn refuses_what_it_cannot_decode_rather_than_guessing() {
        let (planar, _) = two_plane_body();
        // An unknown compression method.
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 2, 0, 9)),
            chunk(b"BODY", &planar),
        ]);
        assert!(matches!(
            decode(&bytes),
            Err(IlbmError::UnsupportedCompression(9))
        ));

        // A truncated BODY.
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 2, 0, 0)),
            chunk(b"BODY", &planar[..4]),
        ]);
        assert!(matches!(
            decode(&bytes),
            Err(IlbmError::BodyTruncated { .. })
        ));

        // No BMHD at all.
        let bytes = form(&[chunk(b"BODY", &planar)]);
        assert!(matches!(
            decode(&bytes),
            Err(IlbmError::Iff(IffError::MissingChunk { .. }))
        ));

        // Zero planes, and more than eight.
        for planes in [0_u8, 9] {
            let bytes = form(&[
                chunk(b"BMHD", &bmhd(16, 2, planes, 0, 0)),
                chunk(b"BODY", &planar),
            ]);
            assert!(matches!(
                decode(&bytes),
                Err(IlbmError::UnsupportedPlanes { .. })
            ));
        }

        // A geometry above the ceiling, refused before anything is allocated.
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(u16::MAX, u16::MAX, 8, 0, 0)),
            chunk(b"BODY", &planar),
        ]);
        assert!(matches!(
            decode(&bytes),
            Err(IlbmError::ImageTooLarge { .. })
        ));

        // A sound form is not an image.
        let mut sound = Vec::new();
        sound.extend_from_slice(b"FORM");
        sound.extend_from_slice(&4_u32.to_be_bytes());
        sound.extend_from_slice(b"8SVX");
        assert!(matches!(
            decode(&sound),
            Err(IlbmError::Iff(IffError::UnexpectedFormType { .. }))
        ));
    }

    #[test]
    fn a_short_palette_is_reported_rather_than_padded() {
        let (planar, _) = two_plane_body();
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 2, 0, 0)),
            chunk(b"CMAP", &[0, 0, 0, 255, 0, 0]),
            chunk(b"BODY", &planar),
        ]);
        let ilbm = decode(&bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ilbm.palette.len(), 2, "no entry was invented");
        assert!(
            ilbm.warnings
                .iter()
                .any(|warning| warning.kind == IlbmWarningKind::PaletteShorterThanPlanes)
        );
    }

    #[test]
    fn a_run_length_that_would_overrun_the_geometry_is_refused() {
        // Two bytes that decode to 128, repeated past what the image can hold.
        // The bound is the geometry, checked before the memory is taken.
        let mut packed = Vec::new();
        for _ in 0..64 {
            packed.push(0x81); // replicate the next byte 128 times
            packed.push(0xaa);
        }
        let bytes = form(&[
            chunk(b"BMHD", &bmhd(16, 2, 2, 0, 1)),
            chunk(b"BODY", &packed),
        ]);
        assert!(matches!(
            decode(&bytes),
            Err(IlbmError::Compression(
                amiga_compress::RleError::OutputTooLarge { .. }
            ))
        ));
    }
}
