//! Arguments for the `graphics.*` operations: planar bitmaps, ILBM images, and
//! the palettes both are shown through.
use super::*;

/// Arguments for `graphics.ilbm.decode`.
///
/// The pixels are not among them. An ILBM's indices are what
/// `graphics.bitmap.export` writes, and returning a megapixel index buffer
/// through a response envelope would make the cheap question — what *is* this
/// image — as expensive as the write.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IlbmDecodeArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl IlbmDecodeArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_input_bytes: None,
        }
    }
}

/// Arguments for `graphics.bitmap.detect`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BitmapDetectArguments {
    pub source: SourceLocator,
    /// Where the examined region starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// How much of it to examine. Without a length the entropy map still runs,
    /// but the stride search does not: autocorrelation over an unbounded tail
    /// measures whatever follows the bitmap as much as the bitmap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// Block size the entropy map scores in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<u32>,
    /// Largest row stride the search considers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_stride: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_blocks: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_strides: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl BitmapDetectArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset: None,
            length: None,
            block: None,
            maximum_stride: None,
            maximum_blocks: None,
            maximum_strides: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn over(mut self, offset: u32, length: Option<u32>) -> Self {
        self.offset = Some(offset);
        self.length = length;
        self
    }

    #[must_use]
    pub const fn with_block(mut self, block: u32) -> Self {
        self.block = Some(block);
        self
    }

    #[must_use]
    pub const fn with_maximum_stride(mut self, stride: usize) -> Self {
        self.maximum_stride = Some(stride);
        self
    }
}

/// Arguments for `graphics.palette.scan`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaletteScanArguments {
    pub source: SourceLocator,
    /// Shortest run of `$0RGB` words to report as a table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_colours: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_tables: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl PaletteScanArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            minimum_colours: None,
            maximum_tables: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_minimum_colours(mut self, colours: usize) -> Self {
        self.minimum_colours = Some(colours);
        self
    }
}

/// Arguments for `graphics.palette.decode`.
///
/// A palette is `count` big-endian `$0RGB` words at `offset`. Nothing marks
/// where one starts, so both are the caller's claim; a word whose high nibble is
/// not zero is reported rather than refused, because a table with one stray
/// entry is still the table.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaletteArguments {
    pub source: SourceLocator,
    /// Byte offset of the first colour word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// How many colour words to read.
    pub count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl PaletteArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, count: usize) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset: None,
            count,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn at_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }
}

/// Arguments for `graphics.palette.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaletteExportArguments {
    #[serde(flatten)]
    pub decode: PaletteArguments,
    /// Directory the swatch PNG goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// Side of one swatch square, in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<usize>,
    /// Swatches per row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub columns: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl PaletteExportArguments {
    #[must_use]
    pub fn new(decode: PaletteArguments, destination: impl Into<String>) -> Self {
        Self {
            decode,
            destination: destination.into(),
            file_name: None,
            block: None,
            columns: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_swatches(mut self, block: usize, columns: usize) -> Self {
        self.block = Some(block);
        self.columns = Some(columns);
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `graphics.bitmap.export`.
///
/// Everything `graphics.bitmap.decode` takes, plus where the PNG goes and what
/// colors to give the indices. Flattened rather than nested so a caller that
/// has a working decode request can turn it into an export by adding three
/// fields, not by restructuring it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BitmapExportArguments {
    #[serde(flatten)]
    pub decode: BitmapDecodeArguments,
    /// Directory the PNG goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// RGB4 (`$0RGB`) colors, at least `1 << planes` of them. Omitted, the
    /// export uses a documented grayscale ramp and records that in the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub palette: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl BitmapExportArguments {
    #[must_use]
    pub fn new(decode: BitmapDecodeArguments, destination: impl Into<String>) -> Self {
        Self {
            decode,
            destination: destination.into(),
            file_name: None,
            palette: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_palette(mut self, palette: Vec<u16>) -> Self {
        self.palette = Some(palette);
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// How a planar region is laid out and what shape it decodes to.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BitmapShape {
    /// One image of `width` x `height` pixels.
    #[default]
    Bitmap,
    /// `glyph_count` images of `width` x `height`, tiled into a contact sheet.
    GlyphSheet,
    /// One blitter object, whose mask says which pixels are opaque.
    Bob,
}

/// Whether bitplanes are stored one after another, or interleaved — per
/// scanline, or per fixed-width chunk within a scanline.
///
/// The three chunk widths are the three a 68000 moves in one instruction, which
/// is why stored images use them: the code that scatters such an image into real
/// bitplanes copies one per plane per step. They are storage layouts rather than
/// display ones — no chipset reads a bitmap this way.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaneOrder {
    /// Every row of plane 0, then every row of plane 1, and so on.
    #[default]
    Contiguous,
    /// All planes of row 0, then all planes of row 1.
    Interleaved,
    /// All planes of pixels 0–7, then all planes of pixels 8–15, and so on
    /// across each row.
    ByteInterleaved,
    /// All planes of pixels 0–15, then all planes of pixels 16–31, and so on
    /// across each row.
    WordInterleaved,
    /// All planes of pixels 0–31, then all planes of pixels 32–63, and so on
    /// across each row.
    LongwordInterleaved,
}

/// Where a blitter object's transparency comes from.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BobMask {
    /// Every pixel is opaque.
    #[default]
    None,
    /// An extra plane interleaved with the image planes.
    Interleaved,
    /// A separate one-bit plane at this source offset.
    Separate { offset: usize },
    /// Every pixel holding this palette index is transparent.
    ColorKey { index: u8 },
}

/// Arguments for `graphics.bitmap.decode`.
///
/// Deliberately stops at palette *indices*. Which colors those indices mean,
/// which planes a viewer has switched off, and what a transparent pixel should
/// look like are presentation choices that belong to whatever is displaying the
/// result, not to the decode.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BitmapDecodeArguments {
    pub source: SourceLocator,
    /// Byte offset of the planar data within the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<BitmapShape>,
    /// Pixel width of one image; for `glyph_sheet`, of one glyph.
    pub width: usize,
    /// Pixel height of one image; for `glyph_sheet`, of one glyph.
    pub height: usize,
    pub planes: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane_order: Option<PlaneOrder>,
    /// `glyph_sheet` only: how many glyphs to decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glyph_count: Option<usize>,
    /// `glyph_sheet` only: glyphs per row of the contact sheet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glyph_columns: Option<usize>,
    /// `glyph_sheet` only: separator pixels between tiled glyphs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glyph_gap: Option<usize>,
    /// `bob` only: where transparency comes from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bob_mask: Option<BobMask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    /// Refuse a decode whose output would exceed this many pixels, before
    /// anything is allocated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_output_pixels: Option<usize>,
}

impl BitmapDecodeArguments {
    /// A decode of one `width` x `height` image with `planes` bitplanes.
    #[must_use]
    pub fn new(source: impl Into<String>, width: usize, height: usize, planes: u8) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset: None,
            shape: None,
            width,
            height,
            planes,
            plane_order: None,
            glyph_count: None,
            glyph_columns: None,
            glyph_gap: None,
            bob_mask: None,
            maximum_input_bytes: None,
            maximum_output_pixels: None,
        }
    }

    #[must_use]
    pub const fn at_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_shape(mut self, shape: BitmapShape) -> Self {
        self.shape = Some(shape);
        self
    }

    #[must_use]
    pub const fn with_plane_order(mut self, order: PlaneOrder) -> Self {
        self.plane_order = Some(order);
        self
    }

    #[must_use]
    pub const fn with_glyphs(mut self, count: usize, columns: usize, gap: usize) -> Self {
        self.glyph_count = Some(count);
        self.glyph_columns = Some(columns);
        self.glyph_gap = Some(gap);
        self
    }

    #[must_use]
    pub const fn with_bob_mask(mut self, mask: BobMask) -> Self {
        self.bob_mask = Some(mask);
        self
    }

    #[must_use]
    pub const fn with_maximum_output_pixels(mut self, pixels: usize) -> Self {
        self.maximum_output_pixels = Some(pixels);
        self
    }
}

/// One side of a bitmap comparison.
///
/// `planes` is what decides how the source is read. Present, the bytes are
/// planar and are deinterleaved exactly as `graphics.bitmap.decode` does;
/// absent, the source is already **one palette index per byte** — which is what
/// a decoded frame's indices are, and what makes an original and a
/// reimplementation comparable without either being re-encoded into the other's
/// layout.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparedBitmap {
    pub source: SourceLocator,
    /// Optional raw pixel-source plane from `env.frame.capture.export`.
    /// Each byte is zero for playfield or 1–8 for sprite channels 0–7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pixel_sources: Option<SourceLocator>,
    /// Byte offset of the pixel data within the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    pub width: usize,
    pub height: usize,
    /// Bitplanes to deinterleave. Absent means the source is already one
    /// palette index per byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planes: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane_order: Option<PlaneOrder>,
    /// The palette this side's indices are read through, as RGB4 words.
    ///
    /// Optional, and its absence is why the comparison reports index space and
    /// colour space separately: two images can agree pixel for pixel and still
    /// look different, and a comparison that only had colours could not tell
    /// that apart from a change in the picture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub palette: Vec<u16>,
    /// Shift this side by `(x, y)` before comparing.
    ///
    /// An explicit alignment, because the alternative is searching for one — and
    /// a comparison that found its own alignment would report whichever offset
    /// made the two agree best rather than the one the caller meant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub align: Option<PixelOffset>,
}

impl ComparedBitmap {
    #[must_use]
    pub fn new(source: impl Into<String>, width: usize, height: usize) -> Self {
        Self {
            source: SourceLocator::file(source),
            pixel_sources: None,
            offset: None,
            width,
            height,
            planes: None,
            plane_order: None,
            palette: Vec::new(),
            align: None,
        }
    }

    /// Read this side as planar data with `planes` bitplanes.
    #[must_use]
    pub const fn planar(mut self, planes: u8) -> Self {
        self.planes = Some(planes);
        self
    }

    #[must_use]
    pub fn with_palette(mut self, palette: Vec<u16>) -> Self {
        self.palette = palette;
        self
    }

    /// Compare the raw pixel-source plane exported beside this image.
    #[must_use]
    pub fn with_pixel_sources(mut self, source: impl Into<String>) -> Self {
        self.pixel_sources = Some(SourceLocator::file(source));
        self
    }
}

/// A signed pixel offset.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PixelOffset {
    pub x: i32,
    pub y: i32,
}

/// A rectangle of pixels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PixelRect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

/// A reviewed mask saying which pixels are worth comparing.
///
/// Pinned by digest, unlike either image: a mask decides what a comparison
/// *ignores*, so an unpinned one could turn a failing comparison into a passing
/// one and leave nothing in the record to say it had.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityMask {
    pub source: SourceLocator,
    /// Lowercase hex SHA-256 of the whole file.
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// One byte per pixel of the compared rectangle: zero excludes the pixel,
    /// anything else includes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

/// Arguments for `graphics.bitmap.compare`.
///
/// Compare two decoded images in palette-index space as well as in colour
/// space. A digest over two framebuffers says they differ and nothing about
/// where or how; this says which pixels, which indices were substituted for
/// which, and whether the picture changed at all or only the palette did.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BitmapCompareArguments {
    pub a: ComparedBitmap,
    pub b: ComparedBitmap,
    /// The rectangle compared, in the first image's coordinates. Omitted, the
    /// whole of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crop: Option<PixelRect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<ValidityMask>,
    /// Cap on the listed substitutions and differing regions. The true totals
    /// are always reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_entries: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl BitmapCompareArguments {
    #[must_use]
    pub fn new(a: ComparedBitmap, b: ComparedBitmap) -> Self {
        Self {
            a,
            b,
            crop: None,
            mask: None,
            maximum_entries: None,
            maximum_input_bytes: None,
        }
    }
}

/// Arguments for `graphics.bitmap.compare.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BitmapCompareExportArguments {
    #[serde(flatten)]
    pub compare: BitmapCompareArguments,
    pub destination: String,
    /// What the heatmap is called. The overlay and the manifest are named from
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl BitmapCompareExportArguments {
    #[must_use]
    pub fn new(compare: BitmapCompareArguments, destination: impl Into<String>) -> Self {
        Self {
            compare,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}
