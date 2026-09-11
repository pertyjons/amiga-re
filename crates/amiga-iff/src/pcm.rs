//! Heuristic detection of raw 8-bit signed PCM (Paula) sample data.
//!
//! Some Amiga programs play samples straight to Paula without wrapping them in
//! an 8SVX form, so there is no header to key on. [`scan`] flags regions whose
//! byte statistics look like a sampled waveform rather than code, text, or
//! packed data. It is deliberately a **hint**: it reports candidates for a human
//! to audition (via `sample to-wav`), never a decode, and errs toward rejecting
//! ambiguous data.
//!
//! A block of signed samples reads as sample-like when it is:
//!
//! - **loud enough** — mean absolute amplitude above a floor, so silence and
//!   sparse tables are skipped;
//! - **smooth** — the mean absolute step between consecutive samples is small
//!   relative to the amplitude, as a sampled waveform is oversampled (code and
//!   packed data step almost randomly);
//! - **roughly zero-mean** — little DC bias, which rejects ASCII text and other
//!   all-positive byte runs; and
//! - **not a constant** — no single byte value dominates the block.

/// A region that scores as raw 8-bit signed PCM.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcmRegion {
    /// Byte offset of the region within the scanned image.
    pub offset: usize,
    /// Length of the region in bytes (one byte per sample).
    pub len: usize,
    /// Mean absolute sample amplitude over the region (0..=128).
    pub mean_amplitude: f32,
    /// Mean absolute step between consecutive samples, relative to amplitude;
    /// lower is smoother and more waveform-like.
    pub smoothness: f32,
}

/// Thresholds controlling [`scan`]. [`ScanParams::default`] is a conservative
/// starting point; loosen `max_smoothness` or lower `min_amplitude` to catch
/// noisier or quieter samples at the cost of more false positives.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScanParams {
    /// Block size in bytes used to score the image.
    pub block: usize,
    /// Minimum total length of a merged region to report, in bytes.
    pub min_len: usize,
    /// A block must have at least this mean absolute amplitude.
    pub min_amplitude: f32,
    /// A block's smoothness must be at most this to be accepted.
    pub max_smoothness: f32,
    /// A block's DC bias (|mean| relative to amplitude) must be at most this.
    pub max_dc_bias: f32,
    /// The most common byte in a block must be at most this fraction of it.
    pub max_dominant_fraction: f32,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            block: 1024,
            min_len: 2048,
            min_amplitude: 6.0,
            max_smoothness: 0.85,
            max_dc_bias: 0.5,
            max_dominant_fraction: 0.5,
        }
    }
}

/// Statistics of one block of signed samples.
struct BlockStats {
    mean_amplitude: f32,
    smoothness: f32,
    dc_bias: f32,
    dominant_fraction: f32,
}

fn block_stats(samples: &[i8]) -> Option<BlockStats> {
    if samples.len() < 2 {
        return None;
    }
    let count = samples.len() as f32;
    let mut sum: i64 = 0;
    let mut sum_abs: i64 = 0;
    let mut sum_diff: i64 = 0;
    let mut histogram = [0_u32; 256];
    let mut previous = i32::from(samples[0]);
    for &sample in samples {
        let value = i32::from(sample);
        sum += i64::from(value);
        sum_abs += i64::from(value.unsigned_abs());
        sum_diff += i64::from((value - previous).unsigned_abs());
        previous = value;
        histogram[usize::from(sample.to_ne_bytes()[0])] += 1;
    }
    let mean_amplitude = sum_abs as f32 / count;
    let mean_signed = sum as f32 / count;
    // (n-1) steps contribute to sum_diff.
    let mean_diff = sum_diff as f32 / (count - 1.0);
    // Bias the denominator by 1 so a near-silent block cannot divide by ~0.
    let denominator = mean_amplitude + 1.0;
    let dominant = histogram.iter().copied().max().unwrap_or(0);
    Some(BlockStats {
        mean_amplitude,
        smoothness: mean_diff / denominator,
        dc_bias: mean_signed.abs() / denominator,
        dominant_fraction: dominant as f32 / count,
    })
}

fn is_sample_like(stats: &BlockStats, params: &ScanParams) -> bool {
    stats.mean_amplitude >= params.min_amplitude
        && stats.smoothness <= params.max_smoothness
        && stats.dc_bias <= params.max_dc_bias
        && stats.dominant_fraction <= params.max_dominant_fraction
}

/// Scan `bytes` (interpreted as signed 8-bit samples) for regions that look
/// like raw PCM, merging adjacent sample-like blocks and reporting each merged
/// run at least [`ScanParams::min_len`] bytes long. Returns an empty list when
/// `block` is less than 2.
#[must_use]
pub fn scan(bytes: &[u8], params: ScanParams) -> Vec<PcmRegion> {
    if params.block < 2 {
        return Vec::new();
    }
    let mut regions = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut offset = 0;
    while offset < bytes.len() {
        let end = offset.saturating_add(params.block).min(bytes.len());
        let samples = to_samples(&bytes[offset..end]);
        let accepted = block_stats(&samples)
            .as_ref()
            .is_some_and(|stats| is_sample_like(stats, &params));
        if accepted {
            run_start.get_or_insert(offset);
        } else if let Some(start) = run_start.take() {
            push_region(bytes, start, offset, &params, &mut regions);
        }
        offset = end;
    }
    if let Some(start) = run_start.take() {
        push_region(bytes, start, bytes.len(), &params, &mut regions);
    }
    regions
}

fn push_region(
    bytes: &[u8],
    start: usize,
    end: usize,
    params: &ScanParams,
    regions: &mut Vec<PcmRegion>,
) {
    if end - start < params.min_len {
        return;
    }
    // Recompute over the whole merged run for the reported figures.
    if let Some(stats) = block_stats(&to_samples(&bytes[start..end])) {
        regions.push(PcmRegion {
            offset: start,
            len: end - start,
            mean_amplitude: stats.mean_amplitude,
            smoothness: stats.smoothness,
        });
    }
}

fn to_samples(bytes: &[u8]) -> Vec<i8> {
    bytes
        .iter()
        .map(|byte| i8::from_ne_bytes([*byte]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `period`-sample sine of the given amplitude, `count` samples long.
    fn sine(count: usize, amplitude: f32, period: f32) -> Vec<u8> {
        (0..count)
            .map(|index| {
                let value =
                    (amplitude * (index as f32 * std::f32::consts::TAU / period).sin()).round();
                (value as i32).clamp(-128, 127) as i8 as u8
            })
            .collect()
    }

    /// A deterministic pseudo-random byte run (a small LCG), standing in for
    /// code or packed data.
    fn noise(count: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_u32;
        (0..count)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn flags_a_smooth_sine_between_padding() {
        let mut bytes = vec![0_u8; 1024]; // silence: rejected on amplitude
        bytes.extend(sine(2048, 100.0, 32.0)); // a loud, smooth tone
        bytes.extend(vec![0_u8; 512]);
        let params = ScanParams {
            block: 256,
            min_len: 512,
            ..ScanParams::default()
        };
        let regions = scan(&bytes, params);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 1024);
        assert_eq!(regions[0].len, 2048);
        assert!(regions[0].smoothness < 0.5);
    }

    #[test]
    fn rejects_ascii_text_and_noise() {
        let params = ScanParams {
            block: 256,
            min_len: 256,
            ..ScanParams::default()
        };
        // ASCII text is all-positive: strong DC bias.
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
        assert!(scan(&text, params).is_empty());
        // Random bytes step almost as much as their amplitude: high smoothness.
        assert!(scan(&noise(4096), params).is_empty());
    }

    #[test]
    fn rejects_a_constant_run() {
        let params = ScanParams {
            block: 256,
            min_len: 256,
            ..ScanParams::default()
        };
        // A single repeated non-zero value: one byte dominates the block.
        assert!(scan(&vec![0x40_u8; 4096], params).is_empty());
    }

    #[test]
    fn zero_block_size_finds_nothing() {
        let params = ScanParams {
            block: 0,
            ..ScanParams::default()
        };
        assert!(scan(&sine(4096, 100.0, 32.0), params).is_empty());
    }
}
