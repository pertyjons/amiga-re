//! Results of the `source.*` operations.
use super::*;

/// The `source.read` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SourceReadResult {
    pub source: SourcePin,
    /// The hunk the window was taken from, when the request named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the window starts, in the frame the request used.
    pub offset: u32,
    /// Bytes actually returned, which is the shorter of the request's length
    /// and what the source holds from `offset`. A window running past the end
    /// is reported short rather than refused: a reader looking at the tail of a
    /// file is asking an ordinary question.
    pub length: u64,
    /// The bytes, as lowercase hex.
    pub bytes: String,
    /// Offsets within the window at which a relocation sits, when the window
    /// came from a hunk. The one thing a raw file read cannot say, and what
    /// makes a hex view of code readable.
    pub relocation_sites: Vec<u32>,
}

/// The `source.carve` result: which bytes would be written, and whether they
/// were.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarveResult {
    pub source: SourcePin,
    pub offset: u64,
    pub length: u64,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `source.survey` result.
///
/// `regions` may be capped; `region_total` is always the true count, so a
/// truncated result can never be mistaken for a complete one.
#[derive(Clone, Debug)]
pub struct SourceSurveyResult {
    pub source: SourcePin,
    pub regions: Vec<amiga_analysis::SurveyRegion>,
    pub region_total: usize,
    pub regions_truncated: bool,
    pub copper_lists: Vec<amiga_hw::CopperList>,
}
