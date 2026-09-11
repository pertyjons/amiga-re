//! Results of the `compress.*` operations.
use super::*;

/// The `compress.*.decode` result.
///
/// Carries what the stream *is*, not what it holds: the decoded length, the
/// ratio, and — when the layout has a size field — what that field claimed.
/// The bytes themselves are the export's business, for the same reason a
/// sample's PCM is: a frontend deciding whether a recipe is right needs the
/// shape, and a decode that returned megabytes through a response envelope
/// would make the cheap question expensive.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CompressDecodeResult {
    pub source: SourcePin,
    /// Byte offset the packed stream was read from.
    pub offset: u64,
    /// Bytes of packed input consumed from that offset.
    pub packed_bytes: u64,
    /// Bytes the stream decoded to.
    pub decoded_bytes: u64,
    /// SHA-256 of the decoded bytes, so a caller can compare two recipes'
    /// output without holding either.
    pub decoded_sha256: String,
    /// What a leading size field claimed, when the layout has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_size: Option<u64>,
}

/// The `compress.*.export` result: the same summary, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CompressExportResult {
    pub decoded: CompressDecodeResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}
