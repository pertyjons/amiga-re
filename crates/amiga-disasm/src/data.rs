//! Classifying the regions of a hunk that code references but control flow
//! never decoded.
//!
//! A recursive traversal tells you which bytes are instructions. What is left
//! over is not automatically meaningless: it is the strings, pointer tables,
//! and constant tables the code addresses. This module reads a bounded window
//! at each referenced offset and reports what the bytes look like, so a report
//! can show a reader *what* an operand points at instead of only *where*.
//!
//! Everything here is a guess about intent, so every region is reported with
//! its evidence and stays at `Probable` confidence in the fact model. The
//! previews are deliberately small and escaped: a preview is a legible excerpt
//! for a human, never a channel for the file's bytes to reach a renderer
//! unfiltered.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::control_flow::ControlFlowAnalysis;

/// The most bytes examined when classifying one region. A referenced table can
/// be arbitrarily long; the classification only needs its beginning, and the
/// bound keeps a hostile input from turning one reference into a large scan.
pub const MAX_DATA_REGION: usize = 256;

/// The most source bytes rendered into a text preview.
pub const MAX_PREVIEW_TEXT: usize = 48;

/// The most values listed in a pointer or constant preview.
pub const MAX_PREVIEW_VALUES: usize = 8;

/// The shortest printable run accepted as text, so two stray letters in a
/// constant table do not read as a string.
const MIN_TEXT_LENGTH: usize = 3;

/// The shortest printable run inside decoded code that is worth reporting as a
/// code/data disagreement. Real instruction encodings produce short printable
/// runs often and long ones almost never.
const MIN_SUSPECT_TEXT_LENGTH: usize = 8;

/// A bounded, escaped excerpt of a referenced region, and what it looks like.
///
/// The variant is the classification: text, a table of pointers into this
/// image, or bytes that are neither. `truncated` says the region continues
/// past the excerpt, so a short preview is never mistaken for a short region.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum DataPreview {
    /// A NUL-terminated run of printable bytes, escaped by [`escape`].
    Text { text: String, truncated: bool },
    /// Longwords that all address a byte of this image.
    Pointers { offsets: Vec<u32>, truncated: bool },
    /// Anything else, as raw bytes.
    Bytes { bytes: Vec<u8>, truncated: bool },
}

impl DataPreview {
    /// The snake_case class tag shared by text renderers and the JSON
    /// serialization.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Text { .. } => "text",
            Self::Pointers { .. } => "pointers",
            Self::Bytes { .. } => "bytes",
        }
    }
}

/// One referenced region of a hunk that control flow did not decode.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DataRegion {
    /// Hunk offset of the region's first byte, which is the referenced offset.
    pub start: u32,
    /// Hunk offset one past the last byte the classification accounts for: the
    /// string and its terminator, the whole longwords of the table, or the
    /// examined window when nothing was recognized.
    pub end: u32,
    pub preview: DataPreview,
}

/// Why a referenced offset's classification as code or data is disputed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetConflict {
    /// A reference lands inside a decoded instruction instead of at its start,
    /// so either the decode or the reference is reading these bytes wrongly.
    IntoInstruction,
    /// Bytes control flow decoded as instructions also read as a printable,
    /// NUL-terminated string, and something addresses them.
    CodeReadsAsText,
}

impl TargetConflict {
    /// The snake_case tag shared by text renderers and the JSON serialization.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::IntoInstruction => "into_instruction",
            Self::CodeReadsAsText => "code_reads_as_text",
        }
    }
}

/// A referenced offset whose classification as code or data is disputed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DisputedTarget {
    /// The disputed hunk offset.
    pub offset: u32,
    pub conflict: TargetConflict,
    /// The decoded instruction covering `offset`, for
    /// [`TargetConflict::IntoInstruction`].
    pub instruction: Option<u32>,
}

/// What a scan of the referenced offsets of one hunk found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DataScan {
    /// Referenced regions control flow never decoded, in offset order.
    pub regions: Vec<DataRegion>,
    /// Referenced offsets whose code/data classification is disputed, in
    /// offset order.
    pub disputed: Vec<DisputedTarget>,
}

/// Classify every referenced offset of `code` as decoded code or as data, and
/// preview the data.
///
/// `targets` are the offsets of `code` that something references. A target
/// that starts a decoded instruction is code and gets no region; one that does
/// not is examined as data. A region stops at the next decoded instruction,
/// the next referenced target, the end of the code, or [`MAX_DATA_REGION`]
/// bytes — whichever comes first — so neighbouring regions never swallow each
/// other and no single region is unbounded.
#[must_use]
pub fn scan(code: &[u8], analysis: &ControlFlowAnalysis, targets: &BTreeSet<u32>) -> DataScan {
    let mut found = DataScan::default();
    for &target in targets {
        let Ok(start) = usize::try_from(target) else {
            continue;
        };
        if start >= code.len() {
            continue;
        }
        if analysis.instructions.contains_key(&target) {
            // Decoded as code. Only report it as disputed when the same bytes
            // also read as a string long enough not to be a coincidence.
            if printable_run(&code[start..], MIN_SUSPECT_TEXT_LENGTH).is_some() {
                found.disputed.push(DisputedTarget {
                    offset: target,
                    conflict: TargetConflict::CodeReadsAsText,
                    instruction: Some(target),
                });
            }
            continue;
        }
        if let Some(instruction) = covering_instruction(analysis, target) {
            // Inside a decoded instruction but not at its start.
            found.disputed.push(DisputedTarget {
                offset: target,
                conflict: TargetConflict::IntoInstruction,
                instruction: Some(instruction),
            });
            continue;
        }
        let window = region_end(code, analysis, targets, target, start);
        let (preview, length) = classify(&code[start..window], code.len());
        found.regions.push(DataRegion {
            start: target,
            // `length` never exceeds the window, which is derived from
            // `code.len()`, so the cast cannot lose a meaningful value.
            end: u32::try_from(start + length).unwrap_or(u32::MAX),
            preview,
        });
    }
    found
}

/// Where the region starting at `start` stops.
fn region_end(
    code: &[u8],
    analysis: &ControlFlowAnalysis,
    targets: &BTreeSet<u32>,
    target: u32,
    start: usize,
) -> usize {
    let after = target.saturating_add(1);
    let next_instruction = analysis
        .instructions
        .range(after..)
        .next()
        .map(|(&offset, _)| offset as usize);
    let next_target = targets.range(after..).next().map(|&offset| offset as usize);
    let limit = start.saturating_add(MAX_DATA_REGION);
    [next_instruction, next_target, Some(limit), Some(code.len())]
        .into_iter()
        .flatten()
        .filter(|end| *end > start)
        .min()
        .unwrap_or(code.len())
        .min(code.len())
}

/// The decoded instruction whose bytes cover `offset` without starting there.
fn covering_instruction(analysis: &ControlFlowAnalysis, offset: u32) -> Option<u32> {
    let (&start, decoded) = analysis.instructions.range(..offset).next_back()?;
    (offset < decoded.end).then_some(start)
}

/// Read `region` as text, a pointer table, or plain bytes.
///
/// Returns the preview and how many bytes the classification actually accounts
/// for: the string and its terminator, the whole longwords of the table, or —
/// when nothing was recognized — the examined window. The caller reports that
/// length as the region's extent, so a region never claims bytes it did not
/// classify.
fn classify(region: &[u8], code_len: usize) -> (DataPreview, usize) {
    if let Some(run) = printable_run(region, MIN_TEXT_LENGTH) {
        let (text, truncated) = escape(run, MAX_PREVIEW_TEXT);
        // The run plus its NUL terminator, which `printable_run` proved is
        // inside the window.
        return (DataPreview::Text { text, truncated }, run.len() + 1);
    }
    if let Some(offsets) = pointer_table(region, code_len) {
        let length = offsets.len() * 4;
        let truncated = offsets.len() > MAX_PREVIEW_VALUES;
        return (
            DataPreview::Pointers {
                offsets: offsets.into_iter().take(MAX_PREVIEW_VALUES).collect(),
                truncated,
            },
            length,
        );
    }
    (
        DataPreview::Bytes {
            bytes: region.iter().copied().take(MAX_PREVIEW_VALUES).collect(),
            truncated: region.len() > MAX_PREVIEW_VALUES,
        },
        region.len(),
    )
}

/// The printable bytes before the first NUL, when there is a NUL inside the
/// region and the run is at least `minimum` bytes long.
fn printable_run(region: &[u8], minimum: usize) -> Option<&[u8]> {
    let nul = region.iter().position(|byte| *byte == 0)?;
    let run = &region[..nul];
    (run.len() >= minimum && run.iter().all(|byte| is_printable(*byte))).then_some(run)
}

/// Printable ASCII plus the whitespace an Amiga message string realistically
/// holds. Line breaks are accepted here and escaped by [`escape`], so a
/// multi-line message is still recognized as text without any renderer having
/// to cope with a fact that spans lines.
const fn is_printable(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r') || (byte >= 0x20 && byte <= 0x7e)
}

/// The region read as a table of longword offsets into this image: at least
/// two whole longwords, every one addressing a byte of the image, and at least
/// two distinct non-zero values so a run of padding does not read as a table.
fn pointer_table(region: &[u8], code_len: usize) -> Option<Vec<u32>> {
    let count = region.len() / 4;
    if count < 2 {
        return None;
    }
    let mut offsets = Vec::with_capacity(count);
    for chunk in region.as_chunks::<4>().0.iter().take(count) {
        let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if value as usize >= code_len {
            return None;
        }
        offsets.push(value);
    }
    let distinct: BTreeSet<u32> = offsets
        .iter()
        .copied()
        .filter(|value| *value != 0)
        .collect();
    (distinct.len() >= 2).then_some(offsets)
}

/// Escape `bytes` into a bounded, single-line, printable-ASCII preview.
///
/// Every byte that is not printable ASCII becomes `\xNN`, and backslash and
/// double quote are escaped, so the result can never carry a control
/// character, a line break, or an unbalanced quote into a renderer. Returns
/// the escaped text and whether the source was longer than `limit` bytes.
///
/// This is not markup escaping: a preview may legitimately contain `<` or `&`,
/// and a renderer that emits markup must still escape for its own medium.
#[must_use]
pub fn escape(bytes: &[u8], limit: usize) -> (String, bool) {
    let shown = bytes.len().min(limit);
    let mut text = String::with_capacity(shown);
    for &byte in &bytes[..shown] {
        match byte {
            b'\\' => text.push_str("\\\\"),
            b'"' => text.push_str("\\\""),
            byte if (0x20..=0x7e).contains(&byte) => text.push(byte as char),
            byte => {
                use std::fmt::Write;
                let _ = write!(text, "\\x{byte:02x}");
            }
        }
    }
    (text, bytes.len() > limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::analyze;

    fn targets(offsets: &[u32]) -> BTreeSet<u32> {
        offsets.iter().copied().collect()
    }

    /// `LEA (2,PC),A0 ; RTS` then data at 0x06.
    fn code_with_data(data: &[u8]) -> Vec<u8> {
        let mut code = vec![0x41, 0xfa, 0x00, 0x02, 0x4e, 0x75];
        code.extend_from_slice(data);
        code
    }

    #[test]
    fn reads_a_nul_terminated_string_as_text() {
        let code = code_with_data(b"graphics.library\0");
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        assert_eq!(found.regions.len(), 1);
        assert_eq!(found.regions[0].start, 6);
        assert_eq!(
            found.regions[0].preview,
            DataPreview::Text {
                text: "graphics.library".to_owned(),
                truncated: false,
            }
        );
        assert!(found.disputed.is_empty());
    }

    #[test]
    fn reads_in_range_longwords_as_a_pointer_table() {
        let mut data = Vec::new();
        for value in [0x00u32, 0x04, 0x08] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        let code = code_with_data(&data);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        assert_eq!(
            found.regions[0].preview,
            DataPreview::Pointers {
                offsets: vec![0, 4, 8],
                truncated: false,
            }
        );
    }

    #[test]
    fn refuses_to_read_padding_or_out_of_range_words_as_pointers() {
        // All zero: one distinct value, so it is padding, not a table.
        let code = code_with_data(&[0; 12]);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        assert!(matches!(
            found.regions[0].preview,
            DataPreview::Bytes { .. }
        ));
        // A longword beyond the image is not an offset into it.
        let mut data = 0x1234_5678u32.to_be_bytes().to_vec();
        data.extend_from_slice(&4u32.to_be_bytes());
        let code = code_with_data(&data);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        assert!(matches!(
            found.regions[0].preview,
            DataPreview::Bytes { .. }
        ));
    }

    #[test]
    fn a_region_stops_at_the_next_referenced_target() {
        let code = code_with_data(b"one\0two\0");
        let found = scan(&code, &analyze(&code, 0), &targets(&[6, 10]));
        assert_eq!(found.regions.len(), 2);
        // "one" plus its terminator: the extent classified, not the window.
        assert_eq!((found.regions[0].start, found.regions[0].end), (6, 10));
        assert_eq!(
            found.regions[1].preview,
            DataPreview::Text {
                text: "two".to_owned(),
                truncated: false,
            }
        );
    }

    #[test]
    fn a_region_claims_only_the_bytes_it_classified() {
        // The string, its terminator, then unrelated bytes in the same window.
        let mut data = b"name\0".to_vec();
        data.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let code = code_with_data(&data);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        assert_eq!((found.regions[0].start, found.regions[0].end), (6, 11));
        // A pointer table claims its whole longwords and nothing after them.
        let mut data = Vec::new();
        for value in [0x04u32, 0x08] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        data.push(0xff);
        let code = code_with_data(&data);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        assert_eq!((found.regions[0].start, found.regions[0].end), (6, 14));
    }

    #[test]
    fn a_long_region_is_bounded_and_says_so() {
        let mut data = vec![b'a'; MAX_DATA_REGION * 2];
        data.push(0);
        let code = code_with_data(&data);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        // The examined window is capped, and nothing was recognized inside it,
        // so the region reports exactly that window.
        assert_eq!(
            found.regions[0].end - found.regions[0].start,
            MAX_DATA_REGION as u32
        );
        // ...and the window holds no NUL, so it is not text.
        assert!(matches!(
            found.regions[0].preview,
            DataPreview::Bytes { .. }
        ));
    }

    #[test]
    fn a_preview_is_length_bounded_and_marked_when_cut() {
        let mut data = vec![b'x'; MAX_PREVIEW_TEXT + 10];
        data.push(0);
        let code = code_with_data(&data);
        let found = scan(&code, &analyze(&code, 0), &targets(&[6]));
        let DataPreview::Text { text, truncated } = &found.regions[0].preview else {
            panic!("not text: {:?}", found.regions[0].preview);
        };
        assert_eq!(text.len(), MAX_PREVIEW_TEXT);
        assert!(truncated);
    }

    #[test]
    fn escaping_neutralizes_control_characters_and_quotes() {
        let (text, truncated) = escape(b"a\nb\"c\\d\x1b[0m", 64);
        assert_eq!(text, "a\\x0ab\\\"c\\\\d\\x1b[0m");
        assert!(!truncated);
        assert!(!text.contains('\n'));
        assert!(!text.chars().any(char::is_control));
        // Non-ASCII bytes never reach the output as raw bytes.
        let (high, _) = escape(&[0x80, 0xff], 64);
        assert_eq!(high, "\\x80\\xff");
    }

    #[test]
    fn a_reference_into_the_middle_of_an_instruction_is_disputed() {
        let code = code_with_data(b"data\0");
        // 0x02 is inside the LEA at 0x00.
        let found = scan(&code, &analyze(&code, 0), &targets(&[2]));
        assert!(found.regions.is_empty());
        assert_eq!(
            found.disputed,
            [DisputedTarget {
                offset: 2,
                conflict: TargetConflict::IntoInstruction,
                instruction: Some(0),
            }]
        );
    }

    #[test]
    fn decoded_code_that_also_reads_as_a_long_string_is_disputed() {
        // "NqNqNqNq..." decodes as a run of RTS and reads as printable text.
        let mut code = vec![0x4e, 0x75];
        code.extend_from_slice(&b"Nq".repeat(6));
        code.push(0);
        let analysis = analyze(&code, 2);
        let found = scan(&code, &analysis, &targets(&[2]));
        assert_eq!(
            found.disputed,
            [DisputedTarget {
                offset: 2,
                conflict: TargetConflict::CodeReadsAsText,
                instruction: Some(2),
            }]
        );
    }

    #[test]
    fn a_target_outside_the_code_is_ignored() {
        let code = code_with_data(b"data\0");
        let found = scan(&code, &analyze(&code, 0), &targets(&[0xffff]));
        assert!(found.regions.is_empty());
        assert!(found.disputed.is_empty());
    }
}
