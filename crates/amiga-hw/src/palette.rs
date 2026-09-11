//! Standalone RGB4 palette-table discovery and swatch rendering.
//!
//! The Copper scanner only catches palettes written through the Copper. Real
//! title and menu palettes are frequently raw 16-word `$0RGB` tables sitting in
//! data, loaded into the color registers by code. This finds those standalone
//! tables so a render can be coloured correctly, and lays the located colors out
//! as a swatch strip for a visual preview.

use serde::Serialize;

use crate::color::rgb4_to_rgb8;
use crate::planar::IndexedImage;

/// A run of consecutive 12-bit `$0RGB` color words found by [`scan`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaletteTable {
    /// Byte offset of the first color word within the scanned image.
    pub offset: u32,
    /// The 12-bit color words, in order.
    pub colors: Vec<u16>,
}

impl PaletteTable {
    /// The number of colors in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.colors.len()
    }

    /// Whether the table has no colors (never true for a table from [`scan`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.colors.is_empty()
    }

    /// The colors expanded to 8-bit-per-channel RGB.
    #[must_use]
    pub fn rgb8(&self) -> Vec<[u8; 3]> {
        self.colors.iter().copied().map(rgb4_to_rgb8).collect()
    }
}

/// Whether `word` is a valid 12-bit Amiga color (`$0RGB`): the top four bits,
/// which no OCS/ECS color register uses, must be zero.
#[must_use]
pub fn is_rgb4(word: u16) -> bool {
    word & 0xf000 == 0
}

/// Scan `image` for word-aligned runs of at least `min_len` valid `$0RGB` color
/// words. To reject zero padding and single-value fills, a reported run must
/// contain at least two distinct values and at least one non-zero word. Returns
/// maximal runs in ascending offset order.
///
/// A `min_len` below 2 is treated as 2. Words are read big-endian on the even
/// byte grid, the only alignment a 68000 color table can use.
#[must_use]
pub fn scan(image: &[u8], min_len: usize) -> Vec<PaletteTable> {
    scan_cancellable(image, min_len, &amiga_core::Never).unwrap_or_default()
}

/// [`scan`], stopping at a block boundary when `cancel` fires.
///
/// # Errors
/// Returns [`amiga_core::Cancelled`] rather than the tables found so far.
pub fn scan_cancellable(
    image: &[u8],
    min_len: usize,
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<Vec<PaletteTable>> {
    let min_len = min_len.max(2);
    let word_count = image.len() / 2;
    let word_at = |index: usize| u16::from_be_bytes([image[index * 2], image[index * 2 + 1]]);

    let mut tables = Vec::new();
    let mut index = 0;
    let mut checkpoint = 0;
    while index < word_count {
        // Counted in words consumed rather than loop iterations: a long
        // qualifying run advances `index` far in one pass, and the checkpoint
        // must track the input covered, not the number of times around.
        if index >= checkpoint {
            amiga_core::checkpoint!(cancel);
            checkpoint = index + amiga_core::BYTES_PER_CHECKPOINT / 2;
        }
        if !is_rgb4(word_at(index)) {
            index += 1;
            continue;
        }
        let start = index;
        while index < word_count && is_rgb4(word_at(index)) {
            index += 1;
        }
        let colors: Vec<u16> = (start..index).map(word_at).collect();
        if colors.len() >= min_len
            && qualifies(&colors)
            && let Ok(offset) = u32::try_from(start * 2)
        {
            tables.push(PaletteTable { offset, colors });
        }
    }
    Ok(tables)
}

/// A run is palette-like only if it varies: at least two distinct values, at
/// least one of them non-zero.
fn qualifies(colors: &[u16]) -> bool {
    let first = colors[0];
    colors.iter().any(|color| *color != first) && colors.iter().any(|color| *color != 0)
}

/// Build a swatch preview: one `block`×`block` filled square per color, laid out
/// left-to-right in rows of `columns`. Pixel values are palette indices
/// `0..colors`, so the caller pairs the image with a palette built from the same
/// colors in order.
///
/// Returns `None` when `colors` is zero or above 256 (the 8-bit index limit), or
/// when `block` or `columns` is zero.
#[must_use]
pub fn swatches(colors: usize, block: usize, columns: usize) -> Option<IndexedImage> {
    if colors == 0 || colors > 256 || block == 0 || columns == 0 {
        return None;
    }
    let columns = columns.min(colors);
    let rows = colors.div_ceil(columns);
    let width = columns.checked_mul(block)?;
    let height = rows.checked_mul(block)?;
    let mut pixels = vec![0_u8; width.checked_mul(height)?];
    for index in 0..colors {
        let value = u8::try_from(index).ok()?;
        let x0 = (index % columns) * block;
        let y0 = (index / columns) * block;
        for y in y0..y0 + block {
            for x in x0..x0 + block {
                pixels[y * width + x] = value;
            }
        }
    }
    Some(IndexedImage {
        width,
        height,
        // Synthetic: swatch indices are not real bitplanes, but the field must
        // carry the bit width that spans the palette.
        planes: u8::try_from(usize::BITS - (colors - 1).leading_zeros()).unwrap_or(8),
        pixels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode `words` as a big-endian byte buffer.
    fn be_words(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    #[test]
    fn finds_a_run_between_non_color_words() {
        let mut image = be_words(&[0x1234, 0x5678]); // top nibble set -> not RGB4
        let palette_offset = image.len();
        image.extend(be_words(&[0x000, 0x0f0, 0x00f, 0xfff]));
        image.extend(be_words(&[0xabcd])); // not RGB4
        let tables = scan(&image, 4);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].offset as usize, palette_offset);
        assert_eq!(tables[0].colors, [0x000, 0x0f0, 0x00f, 0xfff]);
        assert_eq!(tables[0].rgb8()[3], [255, 255, 255]);
    }

    #[test]
    fn respects_the_minimum_length() {
        let image = be_words(&[0x0f0, 0x00f]); // valid run, but only two words
        assert!(scan(&image, 4).is_empty());
        assert_eq!(scan(&image, 2).len(), 1);
    }

    #[test]
    fn rejects_all_zero_and_single_value_runs() {
        assert!(scan(&be_words(&[0; 16]), 2).is_empty());
        assert!(scan(&be_words(&[0x0f0; 16]), 2).is_empty());
    }

    #[test]
    fn swatch_geometry_tiles_every_color() {
        let image = swatches(4, 8, 2).unwrap_or_else(|| panic!("expected an image"));
        assert_eq!(image.width, 16); // 2 columns * 8
        assert_eq!(image.height, 16); // 2 rows * 8
        assert_eq!(image.pixels[0], 0); // top-left swatch is color 0
        assert_eq!(image.pixels[8], 1); // next column is color 1
        assert_eq!(image.pixels[8 * 16], 2); // second row starts at color 2
    }

    #[test]
    fn swatch_rejects_degenerate_and_oversized_input() {
        assert!(swatches(0, 8, 8).is_none());
        assert!(swatches(257, 8, 8).is_none());
        assert!(swatches(4, 0, 8).is_none());
    }
}
