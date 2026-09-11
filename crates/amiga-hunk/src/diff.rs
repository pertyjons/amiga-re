//! Structural comparison of two HUNK executables.
//!
//! [`diff`] aligns two [`Executable`]s hunk-by-hunk and reports, for each hunk,
//! the byte ranges whose contents changed and the relocations that were added or
//! removed, identifying structural differences between builds. It is purely structural: the disassembly of a
//! changed code range is left to the caller, so this crate keeps its single
//! dependency direction (`amiga-hunk` never depends on the disassembler).

use std::collections::BTreeSet;

use crate::{Executable, Relocation, SegmentKind};

/// Which of the two images a hunk index appears in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HunkPresence {
    /// Present in both images.
    Both,
    /// Present only in the first image (removed).
    OnlyA,
    /// Present only in the second image (added).
    OnlyB,
}

/// A half-open run of differing bytes, hunk-relative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: u32,
    pub len: u32,
}

impl ByteRange {
    /// The exclusive end of the range (`start + len`), saturating.
    #[must_use]
    pub fn end(&self) -> u32 {
        self.start.saturating_add(self.len)
    }
}

/// The per-hunk result of a [`diff`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HunkDiff {
    pub index: u32,
    pub presence: HunkPresence,
    /// The hunk kind in each image (`None` on the side where it is absent).
    pub kind_a: Option<SegmentKind>,
    pub kind_b: Option<SegmentKind>,
    /// The allocation size in each image (`None` where the hunk is absent).
    pub allocation_a: Option<usize>,
    pub allocation_b: Option<usize>,
    /// Byte ranges whose contents differ (empty unless the hunk is in both).
    pub changed_ranges: Vec<ByteRange>,
    /// Relocations present in the second image but not the first.
    pub added_relocations: Vec<Relocation>,
    /// Relocations present in the first image but not the second.
    pub removed_relocations: Vec<Relocation>,
}

impl HunkDiff {
    /// Whether this hunk is byte-for-byte identical in both images, including
    /// kind, allocation, and relocations.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.presence == HunkPresence::Both
            && self.kind_a == self.kind_b
            && self.allocation_a == self.allocation_b
            && self.changed_ranges.is_empty()
            && self.added_relocations.is_empty()
            && self.removed_relocations.is_empty()
    }
}

/// The result of comparing two executables.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutableDiff {
    /// One entry per hunk index present in either image, in ascending order.
    pub hunks: Vec<HunkDiff>,
}

impl ExecutableDiff {
    /// Whether the two images are structurally identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hunks.iter().all(HunkDiff::is_unchanged)
    }
}

/// Compare two HUNK executables, aligning hunks by index.
#[must_use]
pub fn diff(a: &Executable, b: &Executable) -> ExecutableDiff {
    let mut indices: BTreeSet<u32> = BTreeSet::new();
    indices.extend(a.segments.iter().map(|segment| segment.index));
    indices.extend(b.segments.iter().map(|segment| segment.index));

    let hunks = indices
        .into_iter()
        .map(|index| {
            let segment_a = a.segment(index);
            let segment_b = b.segment(index);
            let presence = match (segment_a.is_some(), segment_b.is_some()) {
                (true, true) => HunkPresence::Both,
                (true, false) => HunkPresence::OnlyA,
                _ => HunkPresence::OnlyB,
            };
            let (changed_ranges, added, removed) = match (segment_a, segment_b) {
                (Some(segment_a), Some(segment_b)) => {
                    let (added, removed) = relocation_diff(a, b, index);
                    (
                        changed_ranges(segment_a.bytes, segment_b.bytes),
                        added,
                        removed,
                    )
                }
                _ => (Vec::new(), Vec::new(), Vec::new()),
            };
            HunkDiff {
                index,
                presence,
                kind_a: segment_a.map(|segment| segment.kind),
                kind_b: segment_b.map(|segment| segment.kind),
                allocation_a: segment_a.map(|segment| segment.allocation_size),
                allocation_b: segment_b.map(|segment| segment.allocation_size),
                changed_ranges,
                added_relocations: added,
                removed_relocations: removed,
            }
        })
        .collect();

    ExecutableDiff { hunks }
}

/// Contiguous runs of positions where `a` and `b` differ. A position past the
/// end of the shorter slice counts as a difference, so a length change becomes a
/// trailing range.
fn changed_ranges(a: &[u8], b: &[u8]) -> Vec<ByteRange> {
    let max = a.len().max(b.len());
    let mut ranges = Vec::new();
    let mut run_start: Option<usize> = None;
    for index in 0..max {
        if a.get(index) != b.get(index) {
            run_start.get_or_insert(index);
        } else if let Some(start) = run_start.take() {
            ranges.push(byte_range(start, index));
        }
    }
    if let Some(start) = run_start.take() {
        ranges.push(byte_range(start, max));
    }
    ranges
}

fn byte_range(start: usize, end: usize) -> ByteRange {
    ByteRange {
        start: u32::try_from(start).unwrap_or(u32::MAX),
        len: u32::try_from(end.saturating_sub(start)).unwrap_or(u32::MAX),
    }
}

/// Relocations added in `b` and removed from `a`, for one hunk, keyed by
/// `(source_offset, target_hunk)` and sorted for a stable report.
fn relocation_diff(
    a: &Executable,
    b: &Executable,
    index: u32,
) -> (Vec<Relocation>, Vec<Relocation>) {
    let key = |relocation: &Relocation| (relocation.source_offset, relocation.target_hunk);
    let in_a: BTreeSet<(u32, u32)> = a
        .relocations
        .iter()
        .filter(|relocation| relocation.source_hunk == index)
        .map(key)
        .collect();
    let in_b: BTreeSet<(u32, u32)> = b
        .relocations
        .iter()
        .filter(|relocation| relocation.source_hunk == index)
        .map(key)
        .collect();

    let mut added: Vec<Relocation> = b
        .relocations
        .iter()
        .filter(|relocation| relocation.source_hunk == index && !in_a.contains(&key(relocation)))
        .copied()
        .collect();
    let mut removed: Vec<Relocation> = a
        .relocations
        .iter()
        .filter(|relocation| relocation.source_hunk == index && !in_b.contains(&key(relocation)))
        .copied()
        .collect();
    added.sort_by_key(key);
    removed.sort_by_key(key);
    (added, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_word(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// A single-CODE-hunk executable holding `code` (padded to a longword),
    /// with an optional RELOC32 at `reloc_offset` targeting the same hunk.
    fn code_executable(code: &[u8], reloc_offset: Option<u32>) -> Vec<u8> {
        let mut padded = code.to_vec();
        while !padded.len().is_multiple_of(4) {
            padded.push(0);
        }
        let longs = (padded.len() / 4) as u32;
        let mut bytes = Vec::new();
        for word in [0x03f3, 0, 1, 0, 0, longs, 0x03e9, longs] {
            push_word(&mut bytes, word);
        }
        bytes.extend_from_slice(&padded);
        if let Some(offset) = reloc_offset {
            for word in [0x03ec, 1, 0, offset, 0] {
                push_word(&mut bytes, word);
            }
        }
        push_word(&mut bytes, 0x03f2); // HUNK_END
        bytes
    }

    #[test]
    fn reports_a_single_changed_byte() {
        let a = code_executable(&[0x4e, 0x71, 0x4e, 0x75], None);
        let b = code_executable(&[0x4e, 0x75, 0x4e, 0x75], None);
        let exe_a = Executable::parse(&a).unwrap_or_else(|error| panic!("{error}"));
        let exe_b = Executable::parse(&b).unwrap_or_else(|error| panic!("{error}"));
        let result = diff(&exe_a, &exe_b);
        assert!(!result.is_empty());
        assert_eq!(result.hunks.len(), 1);
        assert_eq!(
            result.hunks[0].changed_ranges,
            [ByteRange { start: 1, len: 1 }]
        );
    }

    #[test]
    fn detects_a_removed_relocation() {
        let a = code_executable(&[0, 0, 0, 0], Some(0));
        let b = code_executable(&[0, 0, 0, 0], None);
        let exe_a = Executable::parse(&a).unwrap_or_else(|error| panic!("{error}"));
        let exe_b = Executable::parse(&b).unwrap_or_else(|error| panic!("{error}"));
        let result = diff(&exe_a, &exe_b);
        assert_eq!(result.hunks[0].removed_relocations.len(), 1);
        assert!(result.hunks[0].added_relocations.is_empty());
        assert_eq!(result.hunks[0].removed_relocations[0].source_offset, 0);
    }

    #[test]
    fn identical_images_diff_empty() {
        let bytes = code_executable(&[0x4e, 0x75, 0x4e, 0x75], Some(0));
        let exe = Executable::parse(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let result = diff(&exe, &exe);
        assert!(result.is_empty());
        assert!(result.hunks[0].is_unchanged());
    }

    #[test]
    fn a_length_change_becomes_a_trailing_range() {
        assert_eq!(
            changed_ranges(&[1, 2, 3, 4], &[1, 2]),
            [ByteRange { start: 2, len: 2 }]
        );
    }
}
