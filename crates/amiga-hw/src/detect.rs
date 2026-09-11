//! Region classification and bitmap-geometry guessing.
//!
//! Two heuristics that remove blind guessing when facing an unknown binary:
//!
//! - An **entropy map** splits the image into fixed blocks and classifies each
//!   by Shannon entropy — near-empty padding, moderate-entropy code or
//!   uncompressed bitmap, or high-entropy packed/compressed data.
//! - **Row-stride autocorrelation** scores how strongly a region repeats at each
//!   candidate byte stride. An uncompressed bitmap repeats at its scanline
//!   stride, so the strongest stride, combined with [`geometry_candidates`],
//!   suggests the region's width and plane count.
//!
//! Both are statistical hints, not proofs: entropy cannot separate code from an
//! uncompressed bitmap, so that band is labelled as either.

use std::cmp::Ordering;

use serde::Serialize;

/// Entropy at or above this (bits/byte) reads as packed/compressed data.
pub const PACKED_ENTROPY: f32 = 7.5;
/// Entropy at or below this (bits/byte) reads as sparse padding/zero fill.
pub const SPARSE_ENTROPY: f32 = 2.0;

/// The coarse class an entropy band maps to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RegionClass {
    /// Very low entropy: zero fill, padding, or a highly repetitive structure.
    Sparse,
    /// Moderate entropy: machine code or an uncompressed bitmap (indistinguishable
    /// by entropy alone).
    CodeOrBitmap,
    /// High entropy: packed, compressed, or encrypted data.
    Packed,
}

impl RegionClass {
    /// Classify a block by its Shannon entropy in bits/byte.
    #[must_use]
    pub fn classify(entropy: f32) -> Self {
        if entropy >= PACKED_ENTROPY {
            Self::Packed
        } else if entropy <= SPARSE_ENTROPY {
            Self::Sparse
        } else {
            Self::CodeOrBitmap
        }
    }

    /// A short label for display.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sparse => "sparse",
            Self::CodeOrBitmap => "code-or-bitmap",
            Self::Packed => "packed",
        }
    }
}

/// One fixed-size block of the entropy map.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct EntropyBlock {
    /// Byte offset of the block within the scanned image.
    pub offset: u32,
    /// Length of the block (the final block may be short).
    pub len: usize,
    /// Shannon entropy of the block in bits per byte (0.0..=8.0).
    pub entropy: f32,
    pub class: RegionClass,
}

/// The Shannon entropy of `block` in bits per byte (0.0 for empty or single-value
/// input, up to 8.0 for a uniform distribution over all 256 byte values).
#[must_use]
pub fn shannon_entropy(block: &[u8]) -> f32 {
    if block.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u32; 256];
    for &byte in block {
        counts[usize::from(byte)] += 1;
    }
    let len = block.len() as f32;
    let mut entropy = 0.0_f32;
    for &count in &counts {
        if count > 0 {
            let probability = count as f32 / len;
            entropy -= probability * probability.log2();
        }
    }
    entropy
}

/// Split `image` into `block_size`-byte blocks and classify each by entropy.
///
/// A `block_size` of zero is treated as one.
#[must_use]
pub fn entropy_map(image: &[u8], block_size: usize) -> Vec<EntropyBlock> {
    let block_size = block_size.max(1);
    let mut blocks = Vec::new();
    let mut offset = 0;
    while offset < image.len() {
        let end = (offset + block_size).min(image.len());
        let entropy = shannon_entropy(&image[offset..end]);
        blocks.push(EntropyBlock {
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
            len: end - offset,
            entropy,
            class: RegionClass::classify(entropy),
        });
        offset = end;
    }
    blocks
}

/// A candidate row stride and how strongly the region repeats at it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct StrideScore {
    /// The lag in bytes.
    pub stride: usize,
    /// Fraction of byte positions that equal the byte `stride` earlier (0.0..=1.0).
    pub score: f32,
}

/// Score every stride in `min_stride..=max_stride` by the fraction of byte
/// positions in `region` that match the byte `stride` bytes earlier — the
/// signature of a bitmap's scanline repeat. Returned sorted by score descending,
/// then by stride ascending.
///
/// A `min_stride` below 1 is treated as 1. Strides at or beyond the region
/// length are skipped.
#[must_use]
pub fn autocorrelate(region: &[u8], min_stride: usize, max_stride: usize) -> Vec<StrideScore> {
    let min_stride = min_stride.max(1);
    let mut scores = Vec::new();
    for stride in min_stride..=max_stride {
        if stride >= region.len() {
            break;
        }
        let comparisons = region.len() - stride;
        let matches = (0..comparisons)
            .filter(|&index| region[index] == region[index + stride])
            .count();
        scores.push(StrideScore {
            stride,
            score: matches as f32 / comparisons as f32,
        });
    }
    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then(a.stride.cmp(&b.stride))
    });
    scores
}

/// The plausible `(planes, width)` geometries for a detected byte `stride`: for
/// each plane count 1..=8 that divides `stride`, the pixel width if that byte row
/// holds that many interleaved bitplanes (`width = stride / planes * 8`).
///
/// For example, a stride of 160 yields `(4, 320)` among its candidates: four
/// interleaved bitplanes with 320 pixels per row.
#[must_use]
pub fn geometry_candidates(stride: usize) -> Vec<(u8, usize)> {
    (1_u8..=8)
        .filter(|planes| stride.is_multiple_of(usize::from(*planes)))
        .map(|planes| (planes, stride / usize::from(planes) * 8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-4
    }

    #[test]
    fn entropy_spans_zero_to_eight() {
        assert!(close(shannon_entropy(&[7; 100]), 0.0));
        assert!(close(shannon_entropy(&[0, 1]), 1.0));
        let all_bytes: Vec<u8> = (0..=255).collect();
        assert!(close(shannon_entropy(&all_bytes), 8.0));
        assert!(close(shannon_entropy(&[]), 0.0));
    }

    #[test]
    fn classification_bands_match_thresholds() {
        assert_eq!(RegionClass::classify(0.5), RegionClass::Sparse);
        assert_eq!(RegionClass::classify(5.5), RegionClass::CodeOrBitmap);
        assert_eq!(RegionClass::classify(7.9), RegionClass::Packed);
    }

    #[test]
    fn entropy_map_covers_every_byte() {
        let image = [0_u8; 10];
        let blocks = entropy_map(&image, 4);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].len, 4);
        assert_eq!(blocks[2].len, 2);
        assert_eq!(blocks[2].offset, 8);
        assert!(
            blocks
                .iter()
                .all(|block| block.class == RegionClass::Sparse)
        );
    }

    #[test]
    fn autocorrelation_peaks_at_the_true_period() {
        // A four-byte period: every byte equals the one four positions earlier.
        let region: Vec<u8> = (0..64).map(|i| [1, 2, 3, 4][i % 4]).collect();
        let scores = autocorrelate(&region, 1, 16);
        assert_eq!(scores[0].stride, 4);
        assert!(close(scores[0].score, 1.0));
    }

    #[test]
    fn geometry_candidates_include_the_expected_layout() {
        let candidates = geometry_candidates(160);
        assert!(candidates.contains(&(4, 320)));
        assert!(candidates.contains(&(1, 1280)));
        assert!(candidates.contains(&(8, 160)));
    }
}
