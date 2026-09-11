use thiserror::Error;

use crate::IndexedImage;

/// A failure while encoding a decoded indexed image as PNG.
#[derive(Debug, Error)]
pub enum PngError {
    #[error("image dimensions do not fit the PNG format")]
    Dimensions,
    #[error("failed to encode PNG: {0}")]
    Encoding(#[from] png::EncodingError),
}

/// Encode an indexed image as PNG.
///
/// `palette` is a flat RGB byte table. When `alpha` is given, it contains the
/// per-index alpha values written to the PNG `tRNS` chunk.
///
/// # Errors
/// Returns [`PngError`] when dimensions do not fit PNG or the encoder rejects
/// the image, palette, transparency, or pixel data.
pub fn encode_indexed_png(
    image: &IndexedImage,
    palette: &[u8],
    alpha: Option<&[u8]>,
) -> Result<Vec<u8>, PngError> {
    let width = u32::try_from(image.width).map_err(|_| PngError::Dimensions)?;
    let height = u32::try_from(image.height).map_err(|_| PngError::Dimensions)?;
    let mut buffer = Vec::new();
    let mut encoder = png::Encoder::new(&mut buffer, width, height);
    encoder.set_color(png::ColorType::Indexed);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_palette(palette.to_vec());
    if let Some(alpha) = alpha {
        encoder.set_trns(alpha.to_vec());
    }
    let mut writer = encoder.write_header()?;
    writer.write_image_data(&image.pixels)?;
    writer.finish()?;
    Ok(buffer)
}

/// Encode an RGBA8 pixel buffer as PNG.
///
/// # Errors
/// Returns [`PngError`] when dimensions do not fit PNG or the pixel buffer is
/// not valid for the declared dimensions.
pub fn encode_rgba_png(width: usize, height: usize, rgba: &[u8]) -> Result<Vec<u8>, PngError> {
    let width = u32::try_from(width).map_err(|_| PngError::Dimensions)?;
    let height = u32::try_from(height).map_err(|_| PngError::Dimensions)?;
    let mut buffer = Vec::new();
    let mut encoder = png::Encoder::new(&mut buffer, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(rgba)?;
    writer.finish()?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_pixels_palette_and_transparency() {
        let image = IndexedImage {
            width: 2,
            height: 1,
            planes: 1,
            pixels: vec![0, 1],
        };
        let png = encode_indexed_png(&image, &[0, 0, 0, 255, 255, 255], Some(&[0, 255]))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert!(png.windows(4).any(|chunk| chunk == b"PLTE"));
        assert!(png.windows(4).any(|chunk| chunk == b"tRNS"));
    }

    #[test]
    fn encodes_the_same_rgba_pixels_used_by_a_preview() {
        let png = encode_rgba_png(1, 1, &[1, 2, 3, 4]).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    }
}
