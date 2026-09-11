//! Results of the `graphics.*` operations.
use super::*;

/// How an ILBM says which pixels are transparent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IlbmMasking {
    None,
    /// An extra bitplane per row, interleaved with the data planes.
    MaskPlane,
    /// One palette index is transparent.
    TransparentColour,
    /// A lasso outline, carried as a mask plane in practice.
    Lasso,
}

/// The `graphics.ilbm.decode` result.
///
/// What the form *is*, not what it holds: the indices are
/// `graphics.bitmap.export`'s to write, and returning a megapixel buffer
/// through a response envelope would make the cheap question as expensive as
/// the write.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct IlbmDecodeResult {
    pub source: SourcePin,
    pub width: u32,
    pub height: u32,
    pub planes: u8,
    /// Palette indices the plane count can express, `1 << planes`.
    pub indexable_colours: u64,
    pub masking: IlbmMasking,
    /// The transparent index, meaningful only for `transparent_colour`.
    pub transparent_colour: u16,
    /// Whether the form interleaves a mask plane, which the decode consumes
    /// either way rather than letting it shift the data planes.
    pub has_mask: bool,
    /// The raw `CAMG` viewport mode word, when the form carries one. Absent
    /// rather than zero: no CAMG and a CAMG of zero are different claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport_mode: Option<u32>,
    /// Pixel aspect, as `BMHD` states it.
    pub aspect: [u8; 2],
    /// `CMAP` entries as RGB8, in order. Empty when the form carries none —
    /// never filled with invented colours.
    pub palette: Vec<[u8; 3]>,
}

/// What a block's entropy suggests it holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionClass {
    /// Very low entropy: zero fill, padding, or a highly repetitive structure.
    Sparse,
    /// Moderate entropy: machine code or an uncompressed bitmap. The two are
    /// indistinguishable by entropy alone, and saying so beats picking one.
    CodeOrBitmap,
    /// High entropy: packed, compressed, or encrypted.
    Packed,
}

/// One scored block of the examined region.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub struct EntropyBlock {
    /// Whole-file byte offset, so a block can be named without adding the
    /// region start back on — which is the arithmetic a frontend would
    /// otherwise redo.
    pub offset: u32,
    pub length: u64,
    /// Shannon entropy in bits per byte, 0.0..=8.0.
    pub entropy: f32,
    pub class: RegionClass,
}

/// One candidate row stride and how strongly the region repeats at it.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub struct StrideScore {
    /// The lag in bytes.
    pub stride: usize,
    /// Fraction of byte positions equal to the byte `stride` earlier.
    pub score: f32,
}

/// A width the best stride admits at a given plane count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GeometryCandidate {
    pub planes: u8,
    pub width: u64,
}

/// The `graphics.bitmap.detect` result.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct BitmapDetectResult {
    pub source: SourcePin,
    pub offset: u32,
    /// The region actually examined, which is the rest of the source when the
    /// request named no length.
    pub length: u64,
    pub block: u32,
    pub blocks: Vec<EntropyBlock>,
    pub block_total: u64,
    pub blocks_truncated: bool,
    /// Empty when the request named no length. Autocorrelation over an
    /// unbounded tail measures whatever follows the bitmap as much as the
    /// bitmap, so it is not run rather than run and disclaimed.
    pub strides: Vec<StrideScore>,
    pub stride_total: u64,
    pub strides_truncated: bool,
    /// Widths the best-scoring stride admits, one per plane count that divides
    /// it. Derived here because the division is the same in every frontend.
    pub geometry: Vec<GeometryCandidate>,
}

/// One run of `$0RGB` words that scores as a palette table.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PaletteTable {
    /// Byte offset of the first colour word.
    pub offset: u32,
    /// The 12-bit colour words, in order.
    pub rgb12: Vec<u16>,
    /// The same colours expanded to 8 bits per channel. Both encodings travel
    /// because deriving one from the other separately in each frontend is how
    /// two of them end up showing different colours.
    pub rgb8: Vec<[u8; 3]>,
}

/// The `graphics.palette.scan` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PaletteScanResult {
    pub source: SourcePin,
    /// The shortest run the scan accepted, echoed because a table is what this
    /// number accepted rather than something the file declares.
    pub minimum_colours: u64,
    pub tables: Vec<PaletteTable>,
    pub table_total: u64,
    pub tables_truncated: bool,
}

/// The `graphics.palette.decode` result.
///
/// Both encodings of every colour: the `$0RGB` word as stored and the 8-bit triple it
/// expands to. Consumers can compare against source words or use RGB values without
/// duplicating the conversion.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PaletteResult {
    pub source: SourcePin,
    /// Byte offset the words were read from.
    pub offset: u64,
    /// The `$0RGB` words as stored.
    pub colors_rgb4: Vec<u16>,
    /// The same colours as `[r, g, b]` triples.
    pub colors_rgb8: Vec<[u8; 3]>,
    /// Words whose high nibble is not zero, so are not `$0RGB` at all.
    ///
    /// Reported rather than refused: a table with one stray entry is still the
    /// table, and a caller guessing at an offset needs the count to judge the
    /// guess.
    pub invalid_words: u64,
}

/// The `graphics.palette.export` result: the same summary, plus the plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PaletteExportResult {
    pub palette: PaletteResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `graphics.bitmap.export` result.
///
/// Carries the palette it used, not only the plan: an export with no palette
/// argument still committed to specific colors, and a reviewer who cannot see
/// which ones has not really reviewed the PNG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitmapExportResult {
    pub source: SourcePin,
    pub width: usize,
    pub height: usize,
    pub palette: Vec<u16>,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `graphics.bitmap.decode` result: one palette index per pixel.
///
/// No colors and no RGBA. A palette is a separate piece of knowledge that may
/// come from a Copper list, a config, or a guess, and combining it with the
/// pixels here would make this operation answer two questions at once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitmapDecodeResult {
    pub source: SourcePin,
    pub width: usize,
    pub height: usize,
    pub planes: u8,
    /// One palette index per pixel, row-major.
    pub indices: Vec<u8>,
    /// `bob` only: whether each pixel is opaque, in the same order as
    /// `indices`. Absent for the shapes that have no transparency.
    pub opaque: Option<Vec<bool>>,
}

/// A rectangle of pixels, as a result reports one.
///
/// Every rectangle a comparison reports is in the first image's coordinates,
/// including the ones found inside a crop: a reader looks the rectangle up in
/// the image, and a rectangle counted from the crop's own corner would be
/// displaced by the crop origin with nothing in the response saying so.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PixelBounds {
    pub x: u64,
    pub y: u64,
    pub width: u64,
    pub height: u64,
}

/// One index consistently replaced by another.
///
/// The finding that separates a recoloured picture from a redrawn one: a port
/// whose palette entries came out in a different order produces a handful of
/// substitutions covering every differing pixel, while a geometry fault produces
/// scattered ones covering few.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct IndexSubstitution {
    pub from: u8,
    pub to: u8,
    pub pixels: u64,
}

/// One connected run of differing pixels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DifferingRegion {
    pub bounds: PixelBounds,
    pub pixels: u64,
}

/// Comparison of the separate per-pixel display-source planes.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PixelSourceComparison {
    pub a: SourcePin,
    pub b: SourcePin,
    pub identical: bool,
    pub differing_pixels: u64,
}

/// The `graphics.bitmap.compare` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BitmapCompareResult {
    pub a: SourcePin,
    pub b: SourcePin,
    /// The rectangle compared, in the first image's coordinates.
    pub compared: PixelBounds,
    /// Pixels the comparison looked at, after the crop and the mask.
    pub compared_pixels: u64,
    /// Pixels the mask excluded.
    pub masked_pixels: u64,
    /// Whether every compared pixel holds the same palette index.
    pub identical: bool,
    /// Whether every compared pixel resolves to the same colour.
    ///
    /// Separate from `identical`, and the pair is the point: two images can
    /// agree pixel for pixel and still look different, and a comparison that
    /// only had colours could not tell that apart from a change in the picture.
    pub colours_identical: bool,
    /// The indices agree everywhere and the colours do not — a palette
    /// disagreement rather than a geometry one.
    pub palette_only: bool,
    pub differing_pixels: u64,
    pub differing_colour_pixels: u64,
    /// Present when both sides supplied a raw pixel-source plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pixel_sources: Option<PixelSourceComparison>,
    /// The rectangle every differing pixel falls inside, in the first image's
    /// coordinates. Absent when none does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub differing_bounds: Option<PixelBounds>,
    pub substitutions: Vec<IndexSubstitution>,
    pub substitutions_total: u64,
    pub substitutions_truncated: bool,
    pub regions: Vec<DifferingRegion>,
    pub regions_total: u64,
    pub regions_truncated: bool,
}

/// The `graphics.bitmap.compare.export` result: the comparison, plus the plan
/// for the heatmap and the overlay.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BitmapCompareExportResult {
    pub comparison: BitmapCompareResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}
