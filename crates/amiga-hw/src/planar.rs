//! Planar bitplane to chunky (palette-index) conversion.
//!
//! Amiga displays store images as separate 1-bit planes. This converts them
//! into one palette index per pixel, with bit `p` of each index taken from
//! plane `p`. Every plane is row-major and MSB-first with `ceil(width / 8)`
//! bytes per row; the two common ways the planes are ordered in memory are
//! selected with [`PlaneOrder`].

use thiserror::Error;

/// How wide one interleaving chunk is, as bytes of a single bitplane.
///
/// The three widths a 68000 can move in one instruction, which is why stored
/// images use them: the code that scatters such an image into real bitplanes
/// copies one of these per plane per step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chunk {
    /// One byte — 8 pixels.
    Byte,
    /// One 16-bit word — 16 pixels.
    Word,
    /// One 32-bit longword — 32 pixels.
    Longword,
}

impl Chunk {
    /// Bytes of one plane the chunk covers.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Longword => 4,
        }
    }

    /// Pixels the chunk covers.
    #[must_use]
    pub const fn pixels(self) -> usize {
        self.bytes() * 8
    }
}

/// How bitplanes are ordered in memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaneOrder {
    /// Each plane stored fully in turn: all rows of plane 0, then plane 1, …
    Contiguous,
    /// Planes interleaved per scanline: every plane's bytes for row 0, then
    /// every plane's bytes for row 1, … (the ILBM interleaved layout).
    Interleaved,
    /// Planes interleaved within each scanline, every plane's chunk before the
    /// next chunk of the same plane.
    ///
    /// Not a display layout — no Amiga chipset reads a bitmap this way. It is
    /// how some titles *store* an image, for code that scatters the chunks into
    /// ordinary bitplanes at load time, and it is worth decoding directly so
    /// such an image is a reproducible record rather than a byte-reordering
    /// step somebody has to run first.
    ///
    /// Chunk-granular by construction: a row holds whole chunks for every
    /// plane, so a width the chunk does not divide costs the padding a
    /// byte-granular layout does not.
    ///
    /// [`PlaneOrder::Interleaved`] is the same idea with the whole scanline as
    /// the chunk, and the decoder treats it as exactly that.
    ChunkInterleaved(Chunk),
}

impl PlaneOrder {
    /// Bytes of one plane between one interleaving boundary and the next, for a
    /// row of `bytes_per_row` bytes — or `None` when planes are not interleaved
    /// at all.
    const fn chunk_bytes(self, bytes_per_row: usize) -> Option<usize> {
        match self {
            Self::Contiguous => None,
            Self::Interleaved => Some(bytes_per_row),
            Self::ChunkInterleaved(chunk) => Some(chunk.bytes()),
        }
    }
}

/// A decoded chunky image: one palette index per pixel, row-major.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedImage {
    pub width: usize,
    pub height: usize,
    pub planes: u8,
    pub pixels: Vec<u8>,
}

/// A failure while converting planar data.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PlanarError {
    #[error("image dimensions {width}x{height} are invalid")]
    InvalidDimensions { width: usize, height: usize },
    #[error("a planar image must have at least one bitplane")]
    NoPlanes,
    #[error("{planes} planes exceeds the 8 that fit in a byte index")]
    TooManyPlanes { planes: u8 },
    #[error("an interleaved mask requires interleaved plane order")]
    InterleavedMaskOrder,
    #[error("planar data is truncated: need {needed} bytes, have {available}")]
    Truncated { needed: usize, available: usize },
    /// The caller's stop signal fired at a decode checkpoint.
    ///
    /// A variant rather than a second error type: a decode either produced a
    /// complete image or it did not, and one `Result` keeps a caller from
    /// mistaking a half-decoded frame for a finished one.
    #[error("cancelled before the decode completed")]
    Cancelled,
}

impl From<amiga_core::Cancelled> for PlanarError {
    fn from(amiga_core::Cancelled: amiga_core::Cancelled) -> Self {
        Self::Cancelled
    }
}

/// Convert `data` from planar form to a chunky [`IndexedImage`].
///
/// # Errors
/// Returns [`PlanarError`] if the dimensions are zero, more than 8 planes are
/// requested, or `data` is shorter than the layout requires.
pub fn deinterleave(
    data: &[u8],
    width: usize,
    height: usize,
    planes: u8,
    order: PlaneOrder,
) -> Result<IndexedImage, PlanarError> {
    deinterleave_cancellable(data, width, height, planes, order, &amiga_core::Never)
}

/// [`deinterleave`], stopping between scanlines when `cancel` fires.
///
/// # Errors
/// Returns [`PlanarError::Cancelled`] rather than a partly decoded image, plus
/// every error [`deinterleave`] returns.
pub fn deinterleave_cancellable(
    data: &[u8],
    width: usize,
    height: usize,
    planes: u8,
    order: PlaneOrder,
    cancel: &impl amiga_core::Cancel,
) -> Result<IndexedImage, PlanarError> {
    if width == 0 || height == 0 {
        return Err(PlanarError::InvalidDimensions { width, height });
    }
    if planes == 0 {
        return Err(PlanarError::NoPlanes);
    }
    if planes > 8 {
        return Err(PlanarError::TooManyPlanes { planes });
    }
    let plane_count = usize::from(planes);
    let needed = required_bytes(width, height, plane_count, order)
        .ok_or(PlanarError::InvalidDimensions { width, height })?;
    if data.len() < needed {
        return Err(PlanarError::Truncated {
            needed,
            available: data.len(),
        });
    }

    let pixels =
        decode_planes_cancellable(data, width, height, plane_count, plane_count, order, cancel)?;
    Ok(IndexedImage {
        width,
        height,
        planes,
        pixels,
    })
}

/// Bytes a layout needs to hold `planes` planes of a `width` x `height` image.
///
/// `planes` is the number of planes *per row group* — the data planes, plus an
/// interleaved mask where one is stored alongside them.
fn required_bytes(width: usize, height: usize, planes: usize, order: PlaneOrder) -> Option<usize> {
    let bytes_per_row = width.div_ceil(8);
    // A row is a whole number of chunks per plane, so a width the chunk does
    // not divide is padded up to one rather than sharing a chunk with the next
    // plane. Contiguous and scanline-interleaved rows are already whole.
    let per_plane_row = match order.chunk_bytes(bytes_per_row) {
        None => bytes_per_row,
        Some(chunk) => bytes_per_row.div_ceil(chunk).checked_mul(chunk)?,
    };
    per_plane_row.checked_mul(planes)?.checked_mul(height)
}

/// Decode `planes` MSB-first bitplanes into one palette index per pixel, bit `p`
/// of each index taken from plane `p`.
///
/// `row_planes` is the number of planes per interleaved scanline — at least
/// `planes`, and larger when an extra plane (such as a mask) is interleaved with
/// the data; it is unused for [`PlaneOrder::Contiguous`]. The caller must have
/// checked that `data` is long enough for the layout.
fn decode_planes(
    data: &[u8],
    width: usize,
    height: usize,
    planes: usize,
    row_planes: usize,
    order: PlaneOrder,
) -> Vec<u8> {
    // `Never` cannot fire, so the error arm is unreachable; an empty image is
    // still the honest fallback if that ever stops being true.
    decode_planes_cancellable(
        data,
        width,
        height,
        planes,
        row_planes,
        order,
        &amiga_core::Never,
    )
    .unwrap_or_default()
}

/// [`decode_planes`], checking `cancel` between scanlines.
///
/// One row is the right granularity: it is the unit the loop already works in,
/// and a row of even a very wide bitmap is thousands of times cheaper than the
/// whole decode.
fn decode_planes_cancellable(
    data: &[u8],
    width: usize,
    height: usize,
    planes: usize,
    row_planes: usize,
    order: PlaneOrder,
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<Vec<u8>> {
    let bytes_per_row = width.div_ceil(8);
    let plane_size = bytes_per_row * height;
    let chunk = order.chunk_bytes(bytes_per_row);
    // Bytes one row of the whole group occupies, once every plane's chunks are
    // counted. Zero for a contiguous layout, which does not group rows at all.
    let row_stride = chunk.map_or(0, |chunk| {
        bytes_per_row.div_ceil(chunk) * chunk * row_planes
    });
    let mut pixels = vec![0_u8; width * height];
    let rows_per_checkpoint = (amiga_core::BYTES_PER_CHECKPOINT / bytes_per_row.max(1)).max(1);
    for plane in 0..planes {
        for y in 0..height {
            if y.is_multiple_of(rows_per_checkpoint) {
                amiga_core::checkpoint!(cancel);
            }
            let row_base = match chunk {
                None => plane * plane_size + y * bytes_per_row,
                Some(chunk) => y * row_stride + plane * chunk,
            };
            for x in 0..width {
                // Under an interleaved layout a plane's row is not contiguous:
                // the bytes within one chunk are adjacent, and the other planes'
                // chunks sit between one chunk and the same plane's next.
                let byte = match chunk {
                    None => row_base + x / 8,
                    Some(chunk) => {
                        row_base + (x / 8 / chunk) * chunk * row_planes + (x / 8) % chunk
                    }
                };
                let bit = (data[byte] >> (7 - (x % 8))) & 1;
                pixels[y * width + x] |= bit << plane;
            }
        }
    }
    Ok(pixels)
}

/// Geometry for tiling a run of fixed-size glyphs into a contact sheet.
///
/// A software font stores its glyphs as a table of small equal-sized bitmaps
/// rather than one screen-sized image; this lays `count` of them out into a
/// single indexed image, `columns` glyphs per row, so a whole font can be seen
/// at once. Glyphs are decoded with [`deinterleave`], so `planes`/`order` mean
/// the same as there.
#[derive(Clone, Copy, Debug)]
pub struct GlyphSheet {
    pub glyph_width: usize,
    pub glyph_height: usize,
    pub planes: u8,
    pub order: PlaneOrder,
    /// Number of glyphs to decode from the start of the data.
    pub count: usize,
    /// Glyphs per row in the contact sheet.
    pub columns: usize,
    /// Pixels of separator between adjacent glyphs (0 for none).
    pub gap: usize,
    /// Palette index used to fill the gaps.
    pub separator: u8,
}

impl GlyphSheet {
    /// Decode `count` consecutive glyphs from the start of `data` and tile them
    /// row by row into one indexed contact sheet.
    ///
    /// # Errors
    /// Returns [`PlanarError`] if a glyph dimension, `count`, or `columns` is
    /// zero, more than 8 planes are requested, the geometry overflows, or `data`
    /// is shorter than all `count` glyphs require.
    pub fn render(&self, data: &[u8]) -> Result<IndexedImage, PlanarError> {
        self.render_cancellable(data, &amiga_core::Never)
    }

    /// [`Self::render`], stopping between glyphs when `cancel` fires.
    ///
    /// One glyph is the checkpoint because a contact sheet's cost scales with
    /// the glyph count, which is the parameter a user is most likely to have
    /// typed too large.
    ///
    /// # Errors
    /// Returns [`PlanarError::Cancelled`] rather than a half-filled sheet, plus
    /// every error [`Self::render`] returns.
    pub fn render_cancellable(
        &self,
        data: &[u8],
        cancel: &impl amiga_core::Cancel,
    ) -> Result<IndexedImage, PlanarError> {
        if self.glyph_width == 0 || self.glyph_height == 0 {
            return Err(PlanarError::InvalidDimensions {
                width: self.glyph_width,
                height: self.glyph_height,
            });
        }
        if self.count == 0 || self.columns == 0 {
            return Err(PlanarError::InvalidDimensions {
                width: self.columns,
                height: self.count,
            });
        }
        if self.planes == 0 {
            return Err(PlanarError::NoPlanes);
        }
        if self.planes > 8 {
            return Err(PlanarError::TooManyPlanes {
                planes: self.planes,
            });
        }

        let glyph_size = required_bytes(
            self.glyph_width,
            self.glyph_height,
            usize::from(self.planes),
            self.order,
        )
        .ok_or(PlanarError::InvalidDimensions {
            width: self.glyph_width,
            height: self.glyph_height,
        })?;

        // Verify the data holds every requested glyph before allocating the
        // sheet, so an oversized `count` fails cleanly instead of trying to
        // allocate a huge contact sheet first.
        let needed = glyph_size
            .checked_mul(self.count)
            .ok_or(PlanarError::InvalidDimensions {
                width: glyph_size,
                height: self.count,
            })?;
        if data.len() < needed {
            return Err(PlanarError::Truncated {
                needed,
                available: data.len(),
            });
        }

        let rows = self.count.div_ceil(self.columns);
        let sheet_width = sheet_extent(self.columns, self.glyph_width, self.gap)?;
        let sheet_height = sheet_extent(rows, self.glyph_height, self.gap)?;
        let sheet_pixels =
            sheet_width
                .checked_mul(sheet_height)
                .ok_or(PlanarError::InvalidDimensions {
                    width: sheet_width,
                    height: sheet_height,
                })?;
        let mut pixels = vec![self.separator; sheet_pixels];

        for index in 0..self.count {
            amiga_core::checkpoint!(cancel);
            let start = index
                .checked_mul(glyph_size)
                .ok_or(PlanarError::InvalidDimensions {
                    width: self.glyph_width,
                    height: self.glyph_height,
                })?;
            let end = start
                .checked_add(glyph_size)
                .ok_or(PlanarError::InvalidDimensions {
                    width: self.glyph_width,
                    height: self.glyph_height,
                })?;
            let glyph_data = data.get(start..end).ok_or(PlanarError::Truncated {
                needed: end,
                available: data.len(),
            })?;
            let glyph = deinterleave(
                glyph_data,
                self.glyph_width,
                self.glyph_height,
                self.planes,
                self.order,
            )?;

            let column = index % self.columns;
            let row = index / self.columns;
            let dest_x = column * (self.glyph_width + self.gap);
            let dest_y = row * (self.glyph_height + self.gap);
            for gy in 0..self.glyph_height {
                let src = gy * self.glyph_width;
                let dst = (dest_y + gy) * sheet_width + dest_x;
                pixels[dst..dst + self.glyph_width]
                    .copy_from_slice(&glyph.pixels[src..src + self.glyph_width]);
            }
        }

        Ok(IndexedImage {
            width: sheet_width,
            height: sheet_height,
            planes: self.planes,
            pixels,
        })
    }
}

/// The pixel extent of `cells` cells of `cell` pixels each, separated (not
/// surrounded) by `gap` pixels: `cells*cell + (cells-1)*gap`.
fn sheet_extent(cells: usize, cell: usize, gap: usize) -> Result<usize, PlanarError> {
    let cells_extent = cells
        .checked_mul(cell)
        .ok_or(PlanarError::InvalidDimensions {
            width: cells,
            height: cell,
        })?;
    let gaps_extent =
        cells
            .saturating_sub(1)
            .checked_mul(gap)
            .ok_or(PlanarError::InvalidDimensions {
                width: cells,
                height: gap,
            })?;
    cells_extent
        .checked_add(gaps_extent)
        .ok_or(PlanarError::InvalidDimensions {
            width: cells_extent,
            height: gaps_extent,
        })
}

/// How a blitter object's 1-bit transparency mask is stored alongside its
/// bitplane data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BobMask {
    /// No mask: every pixel is opaque.
    None,
    /// A mask plane interleaved after the data planes on each scanline, so the
    /// row layout holds `planes + 1` planes. Requires [`PlaneOrder::Interleaved`].
    Interleaved,
    /// A separate contiguous 1-bit mask plane starting `offset` bytes into the
    /// data (commonly right after the bitplane data).
    Separate { offset: usize },
    /// Cookie-cut: pixels whose decoded palette index equals `index` are treated
    /// as transparent, so no mask is stored.
    ColorKey { index: u8 },
}

/// A blitter object (BOB): bitplane image data plus an optional transparency
/// mask, decoded together so the object can be cut from its background.
///
/// Menu and sprite graphics are often stored as BOBs rather than full-screen
/// bitmaps; the mask marks which pixels belong to the object.
#[derive(Clone, Copy, Debug)]
pub struct Bob {
    pub width: usize,
    pub height: usize,
    pub planes: u8,
    pub order: PlaneOrder,
    pub mask: BobMask,
}

/// A decoded [`Bob`]: the chunky image plus a per-pixel opacity flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BobImage {
    pub image: IndexedImage,
    /// One flag per pixel, row-major: `true` where the mask keeps the pixel.
    pub opaque: Vec<bool>,
}

impl Bob {
    /// Decode the object (and its mask) from `data`.
    ///
    /// # Errors
    /// Returns [`PlanarError`] if a dimension is zero, the plane count is zero or
    /// exceeds 8, an interleaved mask is paired with contiguous planes, the
    /// layout overflows, or `data` is shorter than the layout requires.
    pub fn extract(&self, data: &[u8]) -> Result<BobImage, PlanarError> {
        if self.width == 0 || self.height == 0 {
            return Err(PlanarError::InvalidDimensions {
                width: self.width,
                height: self.height,
            });
        }
        if self.planes == 0 {
            return Err(PlanarError::NoPlanes);
        }
        if self.planes > 8 {
            return Err(PlanarError::TooManyPlanes {
                planes: self.planes,
            });
        }
        let mask_interleaved = matches!(self.mask, BobMask::Interleaved);
        if mask_interleaved && self.order != PlaneOrder::Interleaved {
            return Err(PlanarError::InterleavedMaskOrder);
        }

        let planes = usize::from(self.planes);
        let bytes_per_row = self.width.div_ceil(8);
        let invalid = || PlanarError::InvalidDimensions {
            width: self.width,
            height: self.height,
        };
        let plane_size = bytes_per_row.checked_mul(self.height).ok_or_else(invalid)?;
        // Planes per interleaved row: the data planes plus an interleaved mask.
        let row_planes = planes + usize::from(mask_interleaved);

        // Bytes the data (and any interleaved mask) occupies. `row_planes` is
        // the plane count for every layout: a contiguous one never carries an
        // interleaved mask, which is refused above.
        let data_end =
            required_bytes(self.width, self.height, row_planes, self.order).ok_or_else(invalid)?;
        // End of a separate mask plane, if any.
        let mask_end = match self.mask {
            BobMask::Separate { offset } => offset.checked_add(plane_size).ok_or_else(invalid)?,
            _ => 0,
        };
        let needed = data_end.max(mask_end);
        if data.len() < needed {
            return Err(PlanarError::Truncated {
                needed,
                available: data.len(),
            });
        }

        // Decode the data planes (skipping the interleaved mask plane, if any,
        // via `row_planes`).
        let pixels = decode_planes(
            data,
            self.width,
            self.height,
            planes,
            row_planes,
            self.order,
        );

        // Build the per-pixel opacity mask. Every mask-plane byte read here lies
        // within `needed`, which the length check above guarantees is mapped.
        let opaque = match self.mask {
            BobMask::None => vec![true; self.width * self.height],
            BobMask::ColorKey { index } => pixels.iter().map(|&pixel| pixel != index).collect(),
            BobMask::Interleaved => read_mask_plane(data, self.width, self.height, |y| {
                y * bytes_per_row * row_planes + planes * bytes_per_row
            }),
            BobMask::Separate { offset } => read_mask_plane(data, self.width, self.height, |y| {
                offset + y * bytes_per_row
            }),
        };

        Ok(BobImage {
            image: IndexedImage {
                width: self.width,
                height: self.height,
                planes: self.planes,
                pixels,
            },
            opaque,
        })
    }
}

/// Read a 1-bit mask plane, MSB-first, whose row `y` starts at `row_base(y)`.
fn read_mask_plane(
    data: &[u8],
    width: usize,
    height: usize,
    row_base: impl Fn(usize) -> usize,
) -> Vec<bool> {
    let mut opaque = vec![false; width * height];
    for y in 0..height {
        let base = row_base(y);
        for x in 0..width {
            let bit = (data[base + x / 8] >> (7 - (x % 8))) & 1;
            opaque[y * width + x] = bit != 0;
        }
    }
    opaque
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bob_without_a_mask_is_fully_opaque() {
        // 8x1, two contiguous planes: plane0 0b1010_1010, plane1 0b1100_1100.
        let bob = Bob {
            width: 8,
            height: 1,
            planes: 2,
            order: PlaneOrder::Contiguous,
            mask: BobMask::None,
        };
        let result = bob
            .extract(&[0b1010_1010, 0b1100_1100])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(result.image.pixels, [3, 2, 1, 0, 3, 2, 1, 0]);
        assert!(result.opaque.iter().all(|&opaque| opaque));
    }

    #[test]
    fn bob_decodes_and_masks_multiple_rows() {
        // 8x2, two contiguous planes, then a separate mask plane at offset 4.
        // plane0 rows [0xF0, 0x0F], plane1 rows [0xCC, 0x33]; mask rows [0xF0, 0x0F].
        let bob = Bob {
            width: 8,
            height: 2,
            planes: 2,
            order: PlaneOrder::Contiguous,
            mask: BobMask::Separate { offset: 4 },
        };
        let result = bob
            .extract(&[0xF0, 0x0F, 0xCC, 0x33, 0xF0, 0x0F])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            result.image.pixels,
            [3, 3, 1, 1, 2, 2, 0, 0, 0, 0, 2, 2, 1, 1, 3, 3]
        );
        assert_eq!(
            result.opaque,
            [
                true, true, true, true, false, false, false, false, // row 0
                false, false, false, false, true, true, true, true, // row 1
            ]
        );
    }

    #[test]
    fn bob_applies_a_separate_mask() {
        // 8x1, one contiguous plane 0b1111_0000, then a mask plane 0b1100_0000.
        let bob = Bob {
            width: 8,
            height: 1,
            planes: 1,
            order: PlaneOrder::Contiguous,
            mask: BobMask::Separate { offset: 1 },
        };
        let result = bob
            .extract(&[0b1111_0000, 0b1100_0000])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(result.image.pixels, [1, 1, 1, 1, 0, 0, 0, 0]);
        assert_eq!(
            result.opaque,
            [true, true, false, false, false, false, false, false]
        );
    }

    #[test]
    fn bob_applies_an_interleaved_mask() {
        // 8x1, interleaved: row 0 = data plane 0b1010_0000 then mask 0b1110_0000.
        let bob = Bob {
            width: 8,
            height: 1,
            planes: 1,
            order: PlaneOrder::Interleaved,
            mask: BobMask::Interleaved,
        };
        let result = bob
            .extract(&[0b1010_0000, 0b1110_0000])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(result.image.pixels, [1, 0, 1, 0, 0, 0, 0, 0]);
        assert_eq!(
            result.opaque,
            [true, true, true, false, false, false, false, false]
        );
    }

    #[test]
    fn bob_color_key_masks_a_transparent_index() {
        // Same two planes as the no-mask case; index 0 is the transparent color.
        let bob = Bob {
            width: 8,
            height: 1,
            planes: 2,
            order: PlaneOrder::Contiguous,
            mask: BobMask::ColorKey { index: 0 },
        };
        let result = bob
            .extract(&[0b1010_1010, 0b1100_1100])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            result.opaque,
            [true, true, true, false, true, true, true, false]
        );
    }

    #[test]
    fn bob_rejects_an_interleaved_mask_with_contiguous_order() {
        let bob = Bob {
            width: 8,
            height: 1,
            planes: 1,
            order: PlaneOrder::Contiguous,
            mask: BobMask::Interleaved,
        };
        assert_eq!(bob.extract(&[0; 4]), Err(PlanarError::InterleavedMaskOrder));
    }

    #[test]
    fn bob_rejects_truncated_data() {
        // 8x1 two-plane BOB needs two bytes; only one is present.
        let bob = Bob {
            width: 8,
            height: 1,
            planes: 2,
            order: PlaneOrder::Contiguous,
            mask: BobMask::None,
        };
        assert_eq!(
            bob.extract(&[0]),
            Err(PlanarError::Truncated {
                needed: 2,
                available: 1
            })
        );
    }

    #[test]
    fn combines_two_contiguous_planes_into_indices() {
        // 8x1 image, two planes. Plane 0: 0b1010_1010, plane 1: 0b1100_1100.
        let data = [0b1010_1010, 0b1100_1100];
        let image = deinterleave(&data, 8, 1, 2, PlaneOrder::Contiguous)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(image.pixels, [3, 2, 1, 0, 3, 2, 1, 0]);
    }

    #[test]
    fn interleaved_matches_contiguous_for_a_single_row() {
        // With one row, interleaved and contiguous layouts are identical.
        let data = [0b1010_1010, 0b1100_1100];
        let contiguous = deinterleave(&data, 8, 1, 2, PlaneOrder::Contiguous)
            .unwrap_or_else(|error| panic!("{error}"));
        let interleaved = deinterleave(&data, 8, 1, 2, PlaneOrder::Interleaved)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(contiguous.pixels, interleaved.pixels);
    }

    #[test]
    fn interleaves_two_planes_across_two_rows() {
        // 8x2, two planes, interleaved: row0 p0, row0 p1, row1 p0, row1 p1.
        // index = plane0 bit | (plane1 bit << 1), MSB first.
        let data = [
            0b1100_0000, // row 0, plane 0 -> x0,x1
            0b1010_0000, // row 0, plane 1 -> x0,x2
            0b0000_1100, // row 1, plane 0 -> x4,x5
            0b0000_1010, // row 1, plane 1 -> x4,x6
        ];
        let image = deinterleave(&data, 8, 2, 2, PlaneOrder::Interleaved)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            image.pixels,
            [3, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 0]
        );
    }

    #[test]
    fn word_interleaved_reads_every_planes_word_before_the_next_row() {
        // 16x2, two planes: [row0 p0][row0 p1][row1 p0][row1 p1], one 16-pixel
        // word each. With a single word per row this is the scanline-interleaved
        // layout too, which is the point of the next test.
        let data = [
            0xf0, 0x0f, // row 0, plane 0
            0xcc, 0x33, // row 0, plane 1
            0xaa, 0x55, // row 1, plane 0
            0x00, 0xff, // row 1, plane 1
        ];
        let image = deinterleave(&data, 16, 2, 2, PlaneOrder::ChunkInterleaved(Chunk::Word))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            image.pixels,
            [
                3, 3, 1, 1, 2, 2, 0, 0, 0, 0, 2, 2, 1, 1, 3, 3, //
                1, 0, 1, 0, 1, 0, 1, 0, 2, 3, 2, 3, 2, 3, 2, 3,
            ]
        );
    }

    #[test]
    fn word_interleaved_differs_from_scanline_interleaved_past_the_first_word() {
        // 32x1, two planes. Word-interleaved: p0 word 0, p1 word 0, p0 word 1,
        // p1 word 1. Scanline-interleaved reads the same bytes as p0's whole
        // row followed by p1's, so the two decodes must disagree.
        let data = [
            0xff, 0x00, // word 0, plane 0
            0x00, 0xff, // word 0, plane 1
            0x0f, 0xf0, // word 1, plane 0
            0xf0, 0x0f, // word 1, plane 1
        ];
        let word = deinterleave(&data, 32, 1, 2, PlaneOrder::ChunkInterleaved(Chunk::Word))
            .unwrap_or_else(|error| panic!("{error}"));
        let scanline = deinterleave(&data, 32, 1, 2, PlaneOrder::Interleaved)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            word.pixels,
            [
                1, 1, 1, 1, 1, 1, 1, 1, // word 0: p0 = 0xff, p1 = 0x00
                2, 2, 2, 2, 2, 2, 2, 2, //         p0 = 0x00, p1 = 0xff
                2, 2, 2, 2, 1, 1, 1, 1, // word 1: p0 = 0x0f, p1 = 0xf0
                1, 1, 1, 1, 2, 2, 2, 2, //         p0 = 0xf0, p1 = 0x0f
            ]
        );
        assert_ne!(word.pixels, scanline.pixels);
    }

    #[test]
    fn every_chunk_width_reads_the_same_row_differently() {
        // 32x1, two planes, the same eight bytes read four ways. Each layout
        // takes a different byte as plane 1's first: the whole row for a
        // scanline, four bytes for a longword, two for a word, one for a byte.
        let data = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
        // Where the single set bit of each byte lands, as (pixel, plane).
        let seen = |order| {
            let image = deinterleave(&data, 32, 1, 2, order)
                .unwrap_or_else(|error: PlanarError| panic!("{error}"));
            image
                .pixels
                .iter()
                .enumerate()
                .filter(|(_, index)| **index != 0)
                .map(|(pixel, index)| (pixel, *index))
                .collect::<Vec<_>>()
        };

        // Byte chunks: plane 0 takes bytes 0, 2, 4, 6 and plane 1 the others.
        assert_eq!(
            seen(PlaneOrder::ChunkInterleaved(Chunk::Byte)),
            [
                (0, 1),
                (1, 2),
                (10, 1),
                (11, 2),
                (20, 1),
                (21, 2),
                (30, 1),
                (31, 2)
            ]
        );
        // Word chunks: bytes 0-1 are plane 0's first word, 2-3 plane 1's.
        assert_eq!(
            seen(PlaneOrder::ChunkInterleaved(Chunk::Word)),
            [
                (0, 1),
                (2, 2),
                (9, 1),
                (11, 2),
                (20, 1),
                (22, 2),
                (29, 1),
                (31, 2)
            ]
        );
        // Longword chunks: bytes 0-3 are plane 0's row and 4-7 plane 1's, which
        // for a 32-pixel row is exactly what a whole scanline is. The two
        // layouts agree here and only here, which is the general rule stated
        // once: a chunk as wide as the row *is* the scanline layout.
        assert_eq!(
            seen(PlaneOrder::ChunkInterleaved(Chunk::Longword)),
            [
                (0, 1),
                (4, 2),
                (9, 1),
                (13, 2),
                (18, 1),
                (22, 2),
                (27, 1),
                (31, 2)
            ]
        );
        assert_eq!(
            seen(PlaneOrder::ChunkInterleaved(Chunk::Longword)),
            seen(PlaneOrder::Interleaved)
        );
    }

    #[test]
    fn interleaved_data_is_chunk_granular() {
        // 8 pixels is half a word, and the layout still spends a whole word on
        // each plane — so the eight bytes a byte-granular layout would call
        // enough for four rows are only enough for two.
        let data = [0xff_u8; 8];
        let word = PlaneOrder::ChunkInterleaved(Chunk::Word);
        assert!(deinterleave(&data, 8, 4, 2, word).is_err());
        let image = deinterleave(&data, 8, 2, 2, word).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(image.pixels, [3; 16]);
        // At byte granularity the same bytes hold all four rows.
        assert!(deinterleave(&data, 8, 4, 2, PlaneOrder::ChunkInterleaved(Chunk::Byte)).is_ok());
    }

    #[test]
    fn rejects_truncated_data() {
        assert!(matches!(
            deinterleave(&[0], 8, 1, 2, PlaneOrder::Contiguous),
            Err(PlanarError::Truncated {
                needed: 2,
                available: 1
            })
        ));
    }

    #[test]
    fn rejects_too_many_planes() {
        assert!(matches!(
            deinterleave(&[0; 64], 8, 1, 9, PlaneOrder::Contiguous),
            Err(PlanarError::TooManyPlanes { planes: 9 })
        ));
    }

    #[test]
    fn tiles_glyphs_into_a_contact_sheet() {
        // Two 8x1 single-plane glyphs, laid out 2 columns wide with no gap.
        // Glyph 0: 0b1000_0000 -> pixel row [1,0,0,0,0,0,0,0].
        // Glyph 1: 0b0100_0000 -> pixel row [0,1,0,0,0,0,0,0].
        let data = [0b1000_0000, 0b0100_0000];
        let sheet = GlyphSheet {
            glyph_width: 8,
            glyph_height: 1,
            planes: 1,
            order: PlaneOrder::Contiguous,
            count: 2,
            columns: 2,
            gap: 0,
            separator: 0,
        };
        let image = sheet
            .render(&data)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(image.width, 16);
        assert_eq!(image.height, 1);
        // Glyph 0 occupies columns 0..8, glyph 1 columns 8..16.
        assert_eq!(image.pixels[0], 1);
        assert_eq!(image.pixels[9], 1);
    }

    #[test]
    fn wraps_glyphs_and_fills_gaps_with_the_separator() {
        // Three 8x1 glyphs, 2 columns, 1px gap, separator index 2 -> a 2-row
        // sheet whose gap column and the empty fourth cell read the separator.
        let data = [0xff, 0xff, 0xff];
        let sheet = GlyphSheet {
            glyph_width: 8,
            glyph_height: 1,
            planes: 1,
            order: PlaneOrder::Contiguous,
            count: 3,
            columns: 2,
            gap: 1,
            separator: 2,
        };
        let image = sheet
            .render(&data)
            .unwrap_or_else(|error| panic!("{error}"));
        // width = 2*8 + 1 gap = 17; height = 2 rows * 1 + 1 gap = 3.
        assert_eq!((image.width, image.height), (17, 3));
        // The gap column between the two first-row glyphs holds the separator.
        assert_eq!(image.pixels[8], 2);
        // The gap row (row 1) is all separator.
        assert!(image.pixels[17..34].iter().all(|&pixel| pixel == 2));
    }

    #[test]
    fn rejects_a_truncated_glyph_run() {
        // Two 8x1 glyphs need 2 bytes; only 1 is present.
        let sheet = GlyphSheet {
            glyph_width: 8,
            glyph_height: 1,
            planes: 1,
            order: PlaneOrder::Contiguous,
            count: 2,
            columns: 2,
            gap: 0,
            separator: 0,
        };
        assert!(matches!(
            sheet.render(&[0xff]),
            Err(PlanarError::Truncated {
                needed: 2,
                available: 1
            })
        ));
    }
}
