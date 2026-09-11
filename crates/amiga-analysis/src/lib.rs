//! Typed analysis operations composed by `amiga-operations` and downstream tools.
//!
//! This crate composes parser and locator results without formatting them for a
//! particular frontend. It has no dependency on the CLI.

mod extraction;
mod hunk_sources;

pub use extraction::{
    AdfExtractionLimits, ExtractionPreparationError, PreparedExtraction, prepare_adf_extraction,
    prepare_lha_extraction,
};
pub use hunk_sources::{
    HunkCarrier, HunkDiscovery, HunkDiscoveryError, HunkDiscoveryKind, HunkDiscoveryWarning,
    HunkSource, discover_hunk_sources, discover_hunk_sources_with_cancel,
};

/// Adjacent printable strings within this many bytes are merged into one run.
const STRING_MERGE_GAP: usize = 8;

/// Minimum printable-run length [`survey`] uses when a caller states none.
///
/// Deliberately higher than [`amiga_core::strings::DEFAULT_MIN_LENGTH`], which
/// serves a plain string dump and wants recall. A survey instead uses string
/// location as one of several competing locators, and overlap resolution is a
/// cursor sweep in start order: an earlier finding claims the overlapping span
/// outright, so a short spurious run beginning a few bytes before a real Copper
/// list eats that list's head, and the gap the sweep tolerates when merging
/// adjacent runs can chain several such
/// false positives into one long spurious `strings` region. A higher threshold
/// suppresses exactly that class.
pub const DEFAULT_SURVEY_MIN_STRING_LENGTH: usize = 6;

/// The semantic class of a region in a source survey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurveyKind {
    Strings,
    Copper,
    Palette,
    Module,
    Sparse,
    CodeOrBitmap,
    Packed,
}

impl SurveyKind {
    /// A stable short name suitable for labels and text output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strings => "strings",
            Self::Copper => "copper",
            Self::Palette => "palette",
            Self::Module => "module",
            Self::Sparse => "sparse",
            Self::CodeOrBitmap => "code-or-bitmap",
            Self::Packed => "packed",
        }
    }

    fn from_region_class(class: amiga_hw::RegionClass) -> Self {
        match class {
            amiga_hw::RegionClass::Sparse => Self::Sparse,
            amiga_hw::RegionClass::CodeOrBitmap => Self::CodeOrBitmap,
            amiga_hw::RegionClass::Packed => Self::Packed,
        }
    }
}

/// One non-overlapping, typed region in source-offset order.
#[derive(Clone, Debug, PartialEq)]
pub struct SurveyRegion {
    pub start: usize,
    pub end: usize,
    pub kind: SurveyKind,
    pub detail: String,
    /// Entropy in bits per byte for unclassified gaps.
    pub entropy: Option<f32>,
    /// RGB4 words when this is a standalone palette-table region.
    pub palette: Option<Vec<u16>>,
}

/// Detailed survey output with typed regions and diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct SurveyResult {
    pub regions: Vec<SurveyRegion>,
    pub copper_lists: Vec<amiga_hw::CopperList>,
}

impl SurveyRegion {
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

struct Finding {
    start: usize,
    end: usize,
    kind: SurveyKind,
    detail: String,
    palette: Option<Vec<u16>>,
    /// Higher wins when findings overlap.
    priority: u8,
}

/// Survey `bytes` with the shared typed locators.
///
/// The result covers the complete input without overlap. Located strings,
/// Copper lists, palettes, and tracker modules take precedence over entropy
/// classification, using deterministic priority and width rules.
#[must_use]
pub fn survey(bytes: &[u8], minimum_string_length: usize) -> Vec<SurveyRegion> {
    survey_detailed(bytes, minimum_string_length).regions
}

/// Survey a source while retaining typed locator results needed by rich views.
#[must_use]
pub fn survey_detailed(bytes: &[u8], minimum_string_length: usize) -> SurveyResult {
    // One implementation, run with a signal that never fires.
    survey_detailed_cancellable(bytes, minimum_string_length, &amiga_core::Never).unwrap_or_else(
        |amiga_core::Cancelled| SurveyResult {
            regions: Vec::new(),
            copper_lists: Vec::new(),
        },
    )
}

/// [`survey_detailed`], stopping between and inside locators when `cancel`
/// fires.
///
/// A survey is the most expensive read-only thing this toolkit does — four
/// locators over the whole input, then an overlap sweep — so it checks at every
/// boundary that separates two locators as well as inside each of them.
///
/// # Errors
/// Returns [`amiga_core::Cancelled`] rather than a survey missing whichever
/// locators had not run yet. A partial survey is indistinguishable from a
/// complete one that found nothing, which is exactly the confusion the
/// repository's recovery rule exists to prevent.
pub fn survey_detailed_cancellable(
    bytes: &[u8],
    minimum_string_length: usize,
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<SurveyResult> {
    let mut findings = Vec::new();

    let strings = amiga_core::strings::scan_cancellable(bytes, minimum_string_length, cancel)?;
    let mut iter = strings.iter().peekable();
    while let Some(first) = iter.next() {
        let mut end = first.offset + first.text.len();
        let mut count = 1;
        while let Some(next) = iter.peek() {
            if next.offset <= end + STRING_MERGE_GAP {
                end = next.offset + next.text.len();
                count += 1;
                iter.next();
            } else {
                break;
            }
        }
        let sample: String = first.text.chars().take(20).collect();
        findings.push(Finding {
            start: first.offset,
            end,
            kind: SurveyKind::Strings,
            detail: format!("{count} string(s), {sample:?}"),
            palette: None,
            priority: 1,
        });
    }

    amiga_core::checkpoint!(cancel);
    let copper_lists = amiga_hw::copper::scan_cancellable(bytes, cancel)?;
    for list in &copper_lists {
        findings.push(Finding {
            start: list.start as usize,
            end: list.end as usize,
            kind: SurveyKind::Copper,
            detail: format!(
                "{} instr, {} palette(s)",
                list.instruction_count,
                list.palettes.len()
            ),
            palette: None,
            priority: 3,
        });
    }

    amiga_core::checkpoint!(cancel);
    for table in amiga_hw::palette::scan_cancellable(bytes, 8, cancel)? {
        let color_count = table.len();
        findings.push(Finding {
            start: table.offset as usize,
            end: table.offset as usize + color_count * 2,
            kind: SurveyKind::Palette,
            detail: format!("{color_count} colors"),
            palette: Some(table.colors),
            priority: 2,
        });
    }

    amiga_core::checkpoint!(cancel);
    for module in amiga_iff::tracker::scan(bytes) {
        findings.push(Finding {
            start: module.offset as usize,
            end: module.offset as usize + module.total_len,
            kind: SurveyKind::Module,
            detail: format!("{} {}ch", module.signature, module.channels),
            palette: None,
            priority: 4,
        });
    }

    findings.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then(right.priority.cmp(&left.priority))
            .then(right.end.cmp(&left.end))
    });

    let mut regions = Vec::new();
    let mut cursor = 0;
    for finding in findings {
        if finding.end <= cursor {
            continue;
        }
        let start = finding.start.max(cursor);
        if start > cursor {
            regions.push(entropy_region(bytes, cursor, start));
        }
        regions.push(SurveyRegion {
            start,
            end: finding.end,
            kind: finding.kind,
            detail: finding.detail,
            entropy: None,
            palette: finding.palette,
        });
        cursor = finding.end;
    }
    if cursor < bytes.len() {
        regions.push(entropy_region(bytes, cursor, bytes.len()));
    }
    Ok(SurveyResult {
        regions,
        copper_lists,
    })
}

fn entropy_region(bytes: &[u8], start: usize, end: usize) -> SurveyRegion {
    let entropy = amiga_hw::detect::shannon_entropy(&bytes[start..end]);
    let class = amiga_hw::RegionClass::classify(entropy);
    SurveyRegion {
        start,
        end,
        kind: SurveyKind::from_region_class(class),
        detail: format!("(entropy {entropy:.2})"),
        entropy: Some(entropy),
        palette: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_source_in_order_and_merges_nearby_strings() {
        let bytes = b"\0HELLO\0\0WORLD\0\xff\xfe";
        let regions = survey(bytes, 4);
        assert_eq!(regions.first().map(|region| region.start), Some(0));
        assert_eq!(regions.last().map(|region| region.end), Some(bytes.len()));
        assert!(regions.windows(2).all(|pair| pair[0].end == pair[1].start));
        let strings = regions
            .iter()
            .find(|region| region.kind == SurveyKind::Strings)
            .expect("strings region");
        assert_eq!(strings.start, 1);
        assert_eq!(strings.end, 13);
        assert!(strings.detail.starts_with("2 string(s)"));
    }

    #[test]
    fn empty_input_has_no_regions() {
        assert!(survey(&[], 4).is_empty());
    }

    #[test]
    fn detailed_survey_retains_typed_copper_lists() {
        let bytes = [
            0x01, 0x00, 0x12, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x82, 0x01, 0x11, 0x01, 0x84,
            0x02, 0x22, 0xff, 0xff, 0xff, 0xfe,
        ];
        let result = survey_detailed(&bytes, 4);
        assert_eq!(result.copper_lists.len(), 1);
        assert_eq!(result.copper_lists[0].start, 0);
    }

    #[test]
    fn palette_locator_wins_over_its_string_overlap() {
        let words = [0x000_u16, 0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777];
        let bytes: Vec<_> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let regions = survey(&bytes, 1);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].kind, SurveyKind::Palette);
    }
}
