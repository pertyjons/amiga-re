//! ProTracker / SoundTracker module detection and carving.
//!
//! A tracker module is not an IFF FORM: it is a fixed 1084-byte header (title,
//! 31 sample descriptors, a 128-entry order table, and a 4-byte format
//! signature at offset 1080) followed by pattern data and then raw 8-bit sample
//! PCM. This locates modules embedded in a binary by their signature, validates
//! the header, and computes the exact carved length so the module can be ripped
//! to a standalone `.mod`.
//!
//! Signatures are read on the even byte grid (68000 word alignment), the only
//! placement a DMA-played module can use.

use amiga_core::strings::{latin1, latin1_cstr};

/// Bytes from a module's start to its 4-byte format signature.
const SIGNATURE_OFFSET: usize = 1080;
/// Bytes of fixed header before the pattern data (signature included).
const HEADER_LEN: usize = 1084;
/// Number of sample descriptors in the header.
const SAMPLE_COUNT: usize = 31;
/// Bytes per sample descriptor.
const SAMPLE_ENTRY_LEN: usize = 30;
/// Offset of the first sample descriptor.
const SAMPLE_TABLE_OFFSET: usize = 20;
/// Offset of the song-length byte.
const SONG_LENGTH_OFFSET: usize = 950;
/// Offset of the 128-entry pattern order table.
const ORDER_TABLE_OFFSET: usize = 952;
const ORDER_TABLE_LEN: usize = 128;
const ROWS_PER_PATTERN: usize = 64;
const BYTES_PER_NOTE: usize = 4;
/// Maximum hardware playback volume.
const MAX_VOLUME: u8 = 64;

/// One of the 31 sample descriptors in a module header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sample {
    pub name: String,
    /// Sample length in bytes (the header stores it in 16-bit words).
    pub length: u32,
    /// Finetune, 0..=15 (a signed 4-bit value in the low nibble).
    pub finetune: u8,
    /// Playback volume, 0..=64.
    pub volume: u8,
    /// Repeat start in bytes.
    pub repeat_start: u32,
    /// Repeat length in bytes.
    pub repeat_length: u32,
}

impl Sample {
    /// Whether this descriptor carries no sample data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// A tracker module located in a binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Module {
    /// Byte offset of the module's start within the scanned image.
    pub offset: u32,
    pub title: String,
    /// The 4-byte format signature (e.g. `M.K.`).
    pub signature: String,
    pub channels: u8,
    /// Number of entries used in the pattern order table (1..=128).
    pub song_length: u8,
    /// Number of distinct patterns stored.
    pub pattern_count: usize,
    /// The 31 sample descriptors (some may be empty).
    pub samples: Vec<Sample>,
    /// Total module length in bytes (header + patterns + sample PCM).
    pub total_len: usize,
}

impl Module {
    /// The number of sample descriptors that carry data.
    #[must_use]
    pub fn used_samples(&self) -> usize {
        self.samples
            .iter()
            .filter(|sample| !sample.is_empty())
            .count()
    }
}

/// The channel count implied by a 4-byte format signature, or `None` if it is
/// not a recognised tracker tag.
#[must_use]
pub fn channels_for(signature: &[u8; 4]) -> Option<u8> {
    let channels = match signature {
        b"M.K." | b"M!K!" | b"M&K!" | b"FLT4" | b"4CHN" => 4,
        b"6CHN" => 6,
        b"8CHN" | b"FLT8" | b"CD81" | b"OKTA" => 8,
        // `xCHN` (single digit) or `xxCH` (two digits) name the channel count.
        [digit, b'C', b'H', b'N'] if digit.is_ascii_digit() => digit - b'0',
        [tens, ones, b'C', b'H'] if tens.is_ascii_digit() && ones.is_ascii_digit() => {
            (tens - b'0') * 10 + (ones - b'0')
        }
        _ => return None,
    };
    (1..=32).contains(&channels).then_some(channels)
}

/// Parse a module whose signature would sit at `image[start + 1080..]`,
/// validating the header and computing the carved length. Returns `None` when
/// the signature is unknown, a field is implausible (volume above 64, song
/// length out of 1..=128), or the module would run past the end of `image`.
#[must_use]
pub fn parse_at(image: &[u8], start: usize) -> Option<Module> {
    let signature_start = start.checked_add(SIGNATURE_OFFSET)?;
    let signature: [u8; 4] = image
        .get(signature_start..signature_start.checked_add(4)?)?
        .try_into()
        .ok()?;
    let channels = channels_for(&signature)?;
    let header = image.get(start..start.checked_add(HEADER_LEN)?)?;

    let title = latin1_cstr(&header[0..SAMPLE_TABLE_OFFSET]);
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    let mut sample_bytes = 0_usize;
    for index in 0..SAMPLE_COUNT {
        let base = SAMPLE_TABLE_OFFSET + index * SAMPLE_ENTRY_LEN;
        let entry = &header[base..base + SAMPLE_ENTRY_LEN];
        let volume = entry[25];
        if volume > MAX_VOLUME {
            return None;
        }
        let length = u32::from(be16(entry, 22)) * 2;
        sample_bytes = sample_bytes.checked_add(length as usize)?;
        samples.push(Sample {
            name: latin1_cstr(&entry[0..22]),
            length,
            finetune: entry[24] & 0x0f,
            volume,
            repeat_start: u32::from(be16(entry, 26)) * 2,
            repeat_length: u32::from(be16(entry, 28)) * 2,
        });
    }

    let song_length = header[SONG_LENGTH_OFFSET];
    if !(1..=128).contains(&song_length) {
        return None;
    }
    let order = &header[ORDER_TABLE_OFFSET..ORDER_TABLE_OFFSET + ORDER_TABLE_LEN];
    let pattern_count = usize::from(order.iter().copied().max().unwrap_or(0)) + 1;

    let pattern_bytes = pattern_count
        .checked_mul(ROWS_PER_PATTERN)?
        .checked_mul(usize::from(channels))?
        .checked_mul(BYTES_PER_NOTE)?;
    let total_len = HEADER_LEN
        .checked_add(pattern_bytes)?
        .checked_add(sample_bytes)?;
    if start.checked_add(total_len)? > image.len() {
        return None;
    }

    Some(Module {
        offset: u32::try_from(start).ok()?,
        title,
        signature: latin1(&signature),
        channels,
        song_length,
        pattern_count,
        samples,
        total_len,
    })
}

/// Scan `image` for tracker modules, validating each candidate and skipping past
/// a located module's body. Returns modules in ascending offset order.
#[must_use]
pub fn scan(image: &[u8]) -> Vec<Module> {
    let mut modules = Vec::new();
    let mut offset = 0;
    while offset + HEADER_LEN <= image.len() {
        if let Some(module) = parse_at(image, offset) {
            offset += module.total_len;
            modules.push(module);
        } else {
            offset += 2;
        }
    }
    modules
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid module: `M.K.`-style with `signature`, one pattern (order
    /// table all zero), and the given per-sample lengths in words.
    fn build_module(signature: &[u8; 4], sample_words: &[u16]) -> Vec<u8> {
        let channels = channels_for(signature).unwrap_or_else(|| panic!("bad signature"));
        let mut buf = vec![0_u8; HEADER_LEN];
        buf[0..4].copy_from_slice(b"SONG");
        for (index, &words) in sample_words.iter().enumerate() {
            let base = SAMPLE_TABLE_OFFSET + index * SAMPLE_ENTRY_LEN;
            buf[base + 22..base + 24].copy_from_slice(&words.to_be_bytes());
            buf[base + 25] = MAX_VOLUME; // volume
        }
        buf[SONG_LENGTH_OFFSET] = 1;
        buf[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 4].copy_from_slice(signature);
        let pattern_bytes = ROWS_PER_PATTERN * usize::from(channels) * BYTES_PER_NOTE;
        buf.extend(std::iter::repeat_n(0, pattern_bytes));
        let sample_bytes: usize = sample_words.iter().map(|w| usize::from(*w) * 2).sum();
        buf.extend(std::iter::repeat_n(0, sample_bytes));
        buf
    }

    #[test]
    fn signatures_map_to_channel_counts() {
        assert_eq!(channels_for(b"M.K."), Some(4));
        assert_eq!(channels_for(b"6CHN"), Some(6));
        assert_eq!(channels_for(b"8CHN"), Some(8));
        assert_eq!(channels_for(b"2CHN"), Some(2));
        assert_eq!(channels_for(b"16CH"), Some(16));
        assert_eq!(channels_for(b"ZZZZ"), None);
        assert_eq!(channels_for(b"0CHN"), None); // zero channels rejected
    }

    #[test]
    fn parses_a_minimal_module_and_computes_its_length() {
        let image = build_module(b"M.K.", &[3, 0, 0]); // first sample: 3 words = 6 bytes
        let module = parse_at(&image, 0).unwrap_or_else(|| panic!("expected a module"));
        assert_eq!(module.signature, "M.K.");
        assert_eq!(module.channels, 4);
        assert_eq!(module.pattern_count, 1);
        assert_eq!(module.total_len, image.len());
        assert_eq!(module.total_len, HEADER_LEN + 1024 + 6);
        assert_eq!(module.samples[0].length, 6);
        assert_eq!(module.used_samples(), 1);
        assert_eq!(module.title, "SONG");
    }

    #[test]
    fn rejects_an_out_of_range_volume() {
        let mut image = build_module(b"M.K.", &[0]);
        let base = SAMPLE_TABLE_OFFSET; // first sample
        image[base + 25] = 65;
        assert!(parse_at(&image, 0).is_none());
    }

    #[test]
    fn rejects_a_module_that_runs_past_the_end() {
        let mut image = build_module(b"M.K.", &[10]);
        image.truncate(image.len() - 4); // lose the tail of the sample data
        assert!(parse_at(&image, 0).is_none());
    }

    #[test]
    fn finds_a_module_embedded_after_a_prefix() {
        let mut image = vec![0xaa; 8];
        let module = build_module(b"M.K.", &[1]);
        image.extend_from_slice(&module);
        let found = scan(&image);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, 8);
    }
}
