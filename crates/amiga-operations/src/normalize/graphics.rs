//! The normalized `graphics.*` requests, and what filling their defaults decides.
use super::*;

/// Widest or tallest a decoded image may be asked to be.
///
/// Far above any Amiga display mode, and small enough that `width * height`
/// cannot overflow before the pixel bound is checked.
const MAX_BITMAP_EXTENT: usize = 1 << 16;

/// The MC68000-era blitter addresses at most eight bitplanes, and the planar
/// primitives encode a palette index in one byte.
const MAX_BITPLANES: u8 = 8;

/// Glyphs, or glyphs per row, one contact sheet may be asked for.
const MAX_GLYPHS: usize = 1 << 16;

/// Block size the entropy map scores in, and the largest row stride the
/// autocorrelation considers. Both match the command line's own defaults.
const DEFAULT_ENTROPY_BLOCK: u32 = 4096;
const DEFAULT_MAXIMUM_STRIDE: usize = 512;

/// Shortest run of `$0RGB` words the palette scan reports as a table. Matches
/// the command line's own default, which is `amiga_hw::palette`'s convention.
const DEFAULT_MINIMUM_PALETTE_COLOURS: usize = 8;

/// The file name a palette swatch sheet uses when the request names none.
const DEFAULT_PALETTE_FILE_NAME: &str = "palette.png";

/// The swatch geometry an export uses when the request names none.
const DEFAULT_SWATCH_BLOCK: usize = 16;
const DEFAULT_SWATCH_COLUMNS: usize = 8;

/// The file name an export uses when the request names none.
const DEFAULT_EXPORT_FILE_NAME: &str = "bitmap.png";

/// Fully resolved `graphics.ilbm.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedIlbmDecode {
    pub source: NormalizedSource,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `graphics.bitmap.detect` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBitmapDetect {
    pub source: NormalizedSource,
    pub offset: u32,
    /// `None` means "to the end of the source", which also turns the stride
    /// search off: autocorrelation over an unbounded tail measures whatever
    /// follows the bitmap as much as the bitmap.
    pub length: Option<u32>,
    pub block: u32,
    pub maximum_stride: usize,
    pub maximum_blocks: usize,
    pub maximum_strides: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `graphics.palette.scan` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPaletteScan {
    pub source: NormalizedSource,
    pub minimum_colours: usize,
    pub maximum_tables: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `graphics.palette.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPalette {
    pub source: NormalizedSource,
    pub offset: usize,
    pub count: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `graphics.palette.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPaletteExport {
    pub decode: NormalizedPalette,
    pub destination: DestinationName,
    pub file_name: String,
    pub block: usize,
    pub columns: usize,
    pub policy: OutputPolicy,
}

/// Fully resolved `graphics.bitmap.export` arguments.
///
/// Holds the decode's own normalized form rather than a copy of its fields, so
/// the two operations cannot drift apart about what a decode means.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBitmapExport {
    pub decode: NormalizedBitmapDecode,
    pub destination: DestinationName,
    pub file_name: String,
    pub palette: Option<Vec<u16>>,
    pub policy: OutputPolicy,
}

/// Fully resolved `graphics.bitmap.decode` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBitmapDecode {
    pub source: NormalizedSource,
    pub offset: usize,
    pub shape: BitmapShape,
    pub width: usize,
    pub height: usize,
    pub planes: u8,
    pub plane_order: PlaneOrder,
    pub glyph_count: usize,
    pub glyph_columns: usize,
    pub glyph_gap: usize,
    pub bob_mask: BobMask,
    pub maximum_input_bytes: u64,
    pub maximum_output_pixels: usize,
}

/// The canonical form of one palette read, shared by the decode and the export.
pub(super) fn palette_document(decode: &NormalizedPalette) -> Value {
    json!({
        "source": decode.source.canonical(),
        "offset": decode.offset,
        "count": decode.count,
        "maximum_input_bytes": decode.maximum_input_bytes,
    })
}

/// The canonical form of one palette export.
pub(super) fn palette_export_document(export: &NormalizedPaletteExport) -> Value {
    json!({
        "decode": palette_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "block": export.block,
        "columns": export.columns,
        "policy": export.policy,
    })
}

/// The canonical form of one bitmap read, shared by the decode and the export.
///
/// Every geometry field is here because every one of them changes which pixels
/// come out: two requests differing only in `plane_order` decode the same bytes
/// to two different images without either failing.
pub(super) fn bitmap_decode_document(decode: &NormalizedBitmapDecode) -> Value {
    json!({
        "source": decode.source.canonical(),
        "offset": decode.offset,
        "shape": decode.shape,
        "width": decode.width,
        "height": decode.height,
        "planes": decode.planes,
        "plane_order": decode.plane_order,
        "glyph_count": decode.glyph_count,
        "glyph_columns": decode.glyph_columns,
        "glyph_gap": decode.glyph_gap,
        "bob_mask": decode.bob_mask,
        "maximum_input_bytes": decode.maximum_input_bytes,
        "maximum_output_pixels": decode.maximum_output_pixels,
    })
}

/// The canonical form of one bitmap export.
pub(super) fn bitmap_export_document(export: &NormalizedBitmapExport) -> Value {
    json!({
        "decode": bitmap_decode_document(&export.decode),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "palette": export.palette,
        "policy": export.policy,
    })
}

/// The canonical form of one `graphics.palette.scan`.
pub(super) fn palette_scan_document(scan: &NormalizedPaletteScan) -> Value {
    json!({
        "source": scan.source.canonical(),
        "minimum_colours": scan.minimum_colours,
        "maximum_tables": scan.maximum_tables,
        "maximum_input_bytes": scan.maximum_input_bytes,
    })
}

/// The canonical form of one `graphics.ilbm.decode`.
///
/// An ILBM carries its own geometry, so the request has nothing to configure
/// beyond which bytes to read and how many of them.
pub(super) fn ilbm_decode_document(decode: &NormalizedIlbmDecode) -> Value {
    json!({
        "source": decode.source.canonical(),
        "maximum_input_bytes": decode.maximum_input_bytes,
    })
}

/// The canonical form of one `graphics.bitmap.detect`.
pub(super) fn bitmap_detect_document(detect: &NormalizedBitmapDetect) -> Value {
    json!({
        "source": detect.source.canonical(),
        "offset": detect.offset,
        "length": detect.length,
        "block": detect.block,
        "maximum_stride": detect.maximum_stride,
        "maximum_blocks": detect.maximum_blocks,
        "maximum_strides": detect.maximum_strides,
        "maximum_input_bytes": detect.maximum_input_bytes,
    })
}

/// Resolve palette arguments, shared by the decode and the export.
///
/// The 256-colour ceiling is the indexed-PNG format's, and it is checked here so
/// a request that could never be drawn is refused before a source is opened.
pub(super) fn normalize_palette(
    arguments: &crate::request::PaletteArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedPalette, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    if !(1..=256).contains(&arguments.count) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("count must be between 1 and 256; got {}", arguments.count),
            )
            .at("$.request.arguments.count"),
        ]);
    }
    let maximum_input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    Ok(NormalizedPalette {
        source,
        offset: arguments.offset.unwrap_or(0),
        count: arguments.count,
        maximum_input_bytes,
    })
}

/// Resolve `graphics.bitmap.decode` arguments.
///
/// Shared with `graphics.bitmap.export`, which decodes the same way and then
/// encodes: two normalizations of the same geometry would eventually disagree
/// about which requests are refused.
pub(super) fn normalize_bitmap_decode(
    arguments: &crate::request::BitmapDecodeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedBitmapDecode, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    let input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let output_pixels = normalize_count(
        arguments.maximum_output_pixels,
        limits.maximum_output_pixels(),
        "maximum_output_pixels",
        "pixels",
        diagnostics,
    )?;

    let shape = arguments.shape.unwrap_or_default();
    // Geometry is refused here, before a source is opened, so an
    // impossible request never costs a read. The upper bounds are the
    // widest an Amiga display or a bitplane count can be; beyond them
    // the arguments cannot describe real planar data.
    let refuse = |field: &str, message: String| {
        Err(vec![
            Diagnostic::error(DiagnosticCode::RequestArgumentOutOfRange, message)
                .at(format!("$.request.arguments.{field}")),
        ])
    };
    if arguments.width == 0 || arguments.width > MAX_BITMAP_EXTENT {
        return refuse(
            "width",
            format!("width must be between 1 and {MAX_BITMAP_EXTENT}"),
        );
    }
    if arguments.height == 0 || arguments.height > MAX_BITMAP_EXTENT {
        return refuse(
            "height",
            format!("height must be between 1 and {MAX_BITMAP_EXTENT}"),
        );
    }
    if arguments.planes == 0 || arguments.planes > MAX_BITPLANES {
        return refuse(
            "planes",
            format!("planes must be between 1 and {MAX_BITPLANES}"),
        );
    }

    let glyph_count = arguments.glyph_count.unwrap_or(1);
    let glyph_columns = arguments.glyph_columns.unwrap_or(1);
    if shape == BitmapShape::GlyphSheet {
        if glyph_count == 0 || glyph_count > MAX_GLYPHS {
            return refuse(
                "glyph_count",
                format!("glyph_count must be between 1 and {MAX_GLYPHS}"),
            );
        }
        if glyph_columns == 0 || glyph_columns > MAX_GLYPHS {
            return refuse(
                "glyph_columns",
                format!("glyph_columns must be between 1 and {MAX_GLYPHS}"),
            );
        }
    }

    Ok(NormalizedBitmapDecode {
        source,
        offset: arguments.offset.unwrap_or(0),
        shape,
        width: arguments.width,
        height: arguments.height,
        planes: arguments.planes,
        plane_order: arguments.plane_order.unwrap_or_default(),
        glyph_count,
        glyph_columns,
        glyph_gap: arguments.glyph_gap.unwrap_or(0),
        bob_mask: arguments.bob_mask.unwrap_or_default(),
        maximum_input_bytes: input_bytes,
        maximum_output_pixels: output_pixels,
    })
}

/// Fill in what an `graphics.bitmap.decode` request left unsaid.
pub(super) fn bitmap_decode(
    arguments: &crate::request::BitmapDecodeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::GraphicsBitmapDecode(
        normalize_bitmap_decode(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what an `graphics.bitmap.export` request left unsaid.
pub(super) fn bitmap_export(
    arguments: &crate::request::BitmapExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_bitmap_decode(&arguments.decode, limits, diagnostics)?;
    let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    // The file name is a single component under the destination, so it
    // goes through the same path rules: an export must not be able to
    // write beside its destination, let alone outside it.
    let file_name = arguments
        .file_name
        .clone()
        .unwrap_or_else(|| DEFAULT_EXPORT_FILE_NAME.to_owned());
    if DestinationName::parse(&file_name).is_err() || file_name.contains('/') {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestSourceNameInvalid,
                "file_name must be one relative path component",
            )
            .at("$.request.arguments.file_name"),
        ]);
    }

    Ok(NormalizedOperation::GraphicsBitmapExport(
        NormalizedBitmapExport {
            decode,
            destination,
            file_name,
            palette: arguments.palette.clone(),
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `graphics.palette.scan` request left unsaid.
pub(super) fn palette_scan(
    arguments: &crate::request::PaletteScanArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let minimum_colours = arguments
        .minimum_colours
        .unwrap_or(DEFAULT_MINIMUM_PALETTE_COLOURS);
    // A run of zero words is every position in the file, and a run of
    // one is any word whose high nibble happens to be zero — which is
    // one in sixteen of all bytes. Neither is a table.
    if minimum_colours < 2 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "minimum_colours must be at least 2; a single $0RGB word is one byte \
                 pair in sixteen and not a table",
            )
            .at("$.request.arguments.minimum_colours"),
        ]);
    }
    Ok(NormalizedOperation::GraphicsPaletteScan(
        NormalizedPaletteScan {
            source: normalize_source(&arguments.source)?,
            minimum_colours,
            maximum_tables: normalize_count(
                arguments.maximum_tables,
                limits.maximum_entries(),
                "maximum_tables",
                "tables",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `graphics.ilbm.decode` request left unsaid.
pub(super) fn ilbm_decode(
    arguments: &crate::request::IlbmDecodeArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::GraphicsIlbmDecode(
        NormalizedIlbmDecode {
            source: normalize_source(&arguments.source)?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `graphics.bitmap.detect` request left unsaid.
pub(super) fn bitmap_detect(
    arguments: &crate::request::BitmapDetectArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let block = arguments.block.unwrap_or(DEFAULT_ENTROPY_BLOCK);
    // Entropy over a zero-length block is undefined, and every block
    // would score the same — which is the one thing the map exists to
    // stop happening.
    if block == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "block must be at least 1; entropy over no bytes is undefined",
            )
            .at("$.request.arguments.block"),
        ]);
    }
    Ok(NormalizedOperation::GraphicsBitmapDetect(
        NormalizedBitmapDetect {
            source: normalize_source(&arguments.source)?,
            offset: arguments.offset.unwrap_or(0),
            length: arguments.length,
            block,
            maximum_stride: arguments.maximum_stride.unwrap_or(DEFAULT_MAXIMUM_STRIDE),
            maximum_blocks: normalize_count(
                arguments.maximum_blocks,
                limits.maximum_regions(),
                "maximum_blocks",
                "blocks",
                diagnostics,
            )?,
            maximum_strides: normalize_count(
                arguments.maximum_strides,
                limits.maximum_entries(),
                "maximum_strides",
                "strides",
                diagnostics,
            )?,
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// Fill in what an `graphics.palette.decode` request left unsaid.
pub(super) fn palette_decode(
    arguments: &crate::request::PaletteArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::GraphicsPaletteDecode(
        normalize_palette(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what an `graphics.palette.export` request left unsaid.
pub(super) fn palette_export(
    arguments: &crate::request::PaletteExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let decode = normalize_palette(&arguments.decode, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_PALETTE_FILE_NAME,
    )?;
    let block = arguments.block.unwrap_or(DEFAULT_SWATCH_BLOCK);
    let columns = arguments.columns.unwrap_or(DEFAULT_SWATCH_COLUMNS);
    if block == 0 || columns == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "block and columns must both be at least 1",
            )
            .at("$.request.arguments.block"),
        ]);
    }
    Ok(NormalizedOperation::GraphicsPaletteExport(
        NormalizedPaletteExport {
            decode,
            destination,
            file_name,
            block,
            columns,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// One resolved side of a comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedComparedBitmap {
    pub source: NormalizedSource,
    pub pixel_sources: Option<NormalizedSource>,
    pub offset: usize,
    pub width: usize,
    pub height: usize,
    pub planes: Option<u8>,
    pub plane_order: crate::request::PlaneOrder,
    pub palette: Vec<u16>,
    pub align: (i32, i32),
}

/// Fully resolved `graphics.bitmap.compare` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBitmapCompare {
    pub a: NormalizedComparedBitmap,
    pub b: NormalizedComparedBitmap,
    pub crop: crate::request::PixelRect,
    pub mask: Option<NormalizedValidityMask>,
    pub maximum_entries: usize,
    pub maximum_input_bytes: u64,
}

/// A resolved validity mask.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedValidityMask {
    pub source: NormalizedSource,
    pub sha256: String,
    pub offset: usize,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `graphics.bitmap.compare.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBitmapCompareExport {
    pub compare: NormalizedBitmapCompare,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

fn compared_bitmap_document(bitmap: &NormalizedComparedBitmap) -> Value {
    json!({
        "source": bitmap.source.canonical(),
        "pixel_sources": bitmap.pixel_sources.as_ref().map(NormalizedSource::canonical),
        "offset": bitmap.offset,
        "width": bitmap.width,
        "height": bitmap.height,
        "planes": bitmap.planes,
        "plane_order": bitmap.plane_order,
        "palette": bitmap.palette,
        "align": { "x": bitmap.align.0, "y": bitmap.align.1 },
    })
}

/// The canonical form of one `graphics.bitmap.compare`.
pub(super) fn bitmap_compare_document(compare: &NormalizedBitmapCompare) -> Value {
    json!({
        "a": compared_bitmap_document(&compare.a),
        "b": compared_bitmap_document(&compare.b),
        "crop": {
            "x": compare.crop.x,
            "y": compare.crop.y,
            "width": compare.crop.width,
            "height": compare.crop.height,
        },
        // The mask decides what the comparison ignores, so it is part of the
        // question rather than a detail of how it was asked.
        "mask": compare.mask.as_ref().map(|mask| json!({
            "source": mask.source.canonical(),
            "sha256": mask.sha256,
            "offset": mask.offset,
        })),
        "maximum_entries": compare.maximum_entries,
        "maximum_input_bytes": compare.maximum_input_bytes,
    })
}

/// The canonical form of one `graphics.bitmap.compare.export`.
pub(super) fn bitmap_compare_export_document(export: &NormalizedBitmapCompareExport) -> Value {
    json!({
        "compare": bitmap_compare_document(&export.compare),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// Entries reported when the request names no cap.
const DEFAULT_REPORTED_COMPARE_ENTRIES: usize = 256;

/// The file name a heatmap uses when the request names none.
const DEFAULT_HEATMAP_FILE_NAME: &str = "heatmap.png";

/// One side of a comparison, resolved.
///
/// `source_path` is passed rather than built from `side` because the source
/// refusals carry a `&'static str`; spelling it once at each call site is what
/// stops the two sides sharing one path and reporting `b`'s bad source against
/// `a`.
fn normalize_compared_bitmap(
    bitmap: &crate::request::ComparedBitmap,
    side: &'static str,
    source_path: &'static str,
) -> Result<NormalizedComparedBitmap, Vec<Diagnostic>> {
    let at = |field: &str| format!("$.request.arguments.{side}.{field}");
    if bitmap.width == 0 || bitmap.height == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "an image compared must be at least one pixel each way",
            )
            .at(at("width")),
        ]);
    }
    if bitmap.planes == Some(0) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "planes must be at least 1; omit it for a source that is already one \
                 palette index per byte",
            )
            .at(at("planes")),
        ]);
    }
    Ok(NormalizedComparedBitmap {
        source: normalize_named_source(&bitmap.source, source_path)?,
        pixel_sources: bitmap
            .pixel_sources
            .as_ref()
            .map(|source| {
                normalize_named_source(
                    source,
                    if side == "a" {
                        "$.request.arguments.a.pixel_sources"
                    } else {
                        "$.request.arguments.b.pixel_sources"
                    },
                )
            })
            .transpose()?,
        offset: bitmap.offset.unwrap_or(0),
        width: bitmap.width,
        height: bitmap.height,
        planes: bitmap.planes,
        plane_order: bitmap.plane_order.unwrap_or_default(),
        palette: bitmap.palette.clone(),
        align: bitmap.align.map_or((0, 0), |align| (align.x, align.y)),
    })
}

/// Fill in what a `graphics.bitmap.compare` request left unsaid.
pub(super) fn normalize_bitmap_compare(
    arguments: &crate::request::BitmapCompareArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedBitmapCompare, Vec<Diagnostic>> {
    let a = normalize_compared_bitmap(&arguments.a, "a", "$.request.arguments.a.source")?;
    let b = normalize_compared_bitmap(&arguments.b, "b", "$.request.arguments.b.source")?;
    if a.pixel_sources.is_some() != b.pixel_sources.is_some() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "pixel-source comparison requires a source plane on both sides; comparing one \
             plane with an unstated origin would invent facts about the other image",
            )
            .at("$.request.arguments.b.pixel_sources"),
        ]);
    }
    // Two images of different sizes are refused rather than resampled. A
    // comparison that scaled one to the other would report the resampler's
    // rounding as a difference in the picture, which is worse than no answer.
    if a.width != b.width || a.height != b.height {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "the images are {}x{} and {}x{}; a comparison does not resample, \
                     because a resampler's rounding would be reported as a difference in \
                     the picture. Crop them to a common rectangle instead.",
                    a.width, a.height, b.width, b.height
                ),
            )
            .at("$.request.arguments.b.width"),
        ]);
    }
    let crop = arguments.crop.unwrap_or(crate::request::PixelRect {
        x: 0,
        y: 0,
        width: a.width,
        height: a.height,
    });
    if crop.width == 0
        || crop.height == 0
        || crop.x.saturating_add(crop.width) > a.width
        || crop.y.saturating_add(crop.height) > a.height
    {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "the crop [{},{} {}x{}] is empty or reaches outside the {}x{} images",
                    crop.x, crop.y, crop.width, crop.height, a.width, a.height
                ),
            )
            .at("$.request.arguments.crop"),
        ]);
    }
    let mask = arguments
        .mask
        .as_ref()
        .map(|mask| {
            if mask.sha256.len() != 64
                || !mask
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        "a validity mask is pinned with a 64-character lowercase hex \
                         SHA-256: a mask decides what the comparison ignores, so an \
                         unpinned one could turn a failing comparison into a passing one \
                         and leave nothing in the record to say it had",
                    )
                    .at("$.request.arguments.mask.sha256"),
                ]);
            }
            Ok(NormalizedValidityMask {
                source: normalize_named_source(&mask.source, "$.request.arguments.mask.source")?,
                sha256: mask.sha256.clone(),
                offset: mask.offset.unwrap_or(0),
                maximum_input_bytes: mask
                    .maximum_input_bytes
                    .unwrap_or(limits.maximum_input_bytes()),
            })
        })
        .transpose()?;
    Ok(NormalizedBitmapCompare {
        a,
        b,
        crop,
        mask,
        maximum_entries: normalize_count(
            arguments
                .maximum_entries
                .or(Some(DEFAULT_REPORTED_COMPARE_ENTRIES)),
            limits.maximum_entries(),
            "maximum_entries",
            "entries",
            diagnostics,
        )?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    })
}

/// Fill in what a `graphics.bitmap.compare` request left unsaid.
pub(super) fn bitmap_compare(
    arguments: &crate::request::BitmapCompareArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::GraphicsBitmapCompare(
        normalize_bitmap_compare(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what a `graphics.bitmap.compare.export` request left unsaid.
pub(super) fn bitmap_compare_export(
    arguments: &crate::request::BitmapCompareExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let compare = normalize_bitmap_compare(&arguments.compare, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_HEATMAP_FILE_NAME,
    )?;
    Ok(NormalizedOperation::GraphicsBitmapCompareExport(
        NormalizedBitmapCompareExport {
            compare,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}
