//! Results of the `container.*` operations.
use super::*;

/// One archive member, as its header declares it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LhaMember {
    pub name: String,
    /// The five-byte method id, e.g. `-lh5-`. Reported verbatim rather than
    /// mapped to "supported"/"unsupported": a caller deciding whether an
    /// extraction will work needs to know *which* method, and `-lh2-` staying
    /// an honest name is what keeps its refusal precise.
    pub method: String,
    pub compressed_size: u64,
    pub original_size: u64,
    /// CRC-16 of the uncompressed file, as stored in the header.
    pub crc16: u16,
    pub header_level: u8,
    /// A directory marker (`-lhd-`) rather than a file.
    pub directory: bool,
}

/// The `container.lha.list` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LhaListResult {
    pub source: SourcePin,
    pub members: Vec<LhaMember>,
    pub member_total: u64,
    pub members_truncated: bool,
}

/// A container extraction's result: what would be written, and whether it was.
///
/// `prepare` and a refused `commit_reviewed` both carry the plan with
/// `committed: false`; the status says which happened. A successful commit
/// carries the same plan with `committed: true`, so the response documents
/// exactly what is now on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerExtractResult {
    pub source: SourcePin,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
    /// Members the container names and this build could not recover.
    ///
    /// Empty for a sound container, and the plan is unaffected either way: a
    /// damaged member is absent from it rather than written short or
    /// zero-filled. It is here rather than only in the diagnostics because a
    /// caller deciding whether the extraction is usable needs the list as data,
    /// and a directory silently missing a file is what makes one untrustworthy.
    pub unreadable: Vec<UnreadableMember>,
}

/// One member a container names and this build could not recover.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct UnreadableMember {
    /// The path it would have been written to, `/`-separated.
    pub path: String,
    /// Why it could not be read, as the reader that refused it said.
    pub reason: String,
}

/// The `container.adf.list` result.
///
/// `entries` may be capped; `entry_total` is always the true count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdfListResult {
    pub source: SourcePin,
    pub volume: AdfVolume,
    pub entries: Vec<AdfEntry>,
    pub entry_total: usize,
    pub entries_truncated: bool,
}

/// What the volume itself declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdfVolume {
    pub name: String,
    /// Which AmigaDOS filesystem the volume declares: `ofs` or `ffs`. Read from
    /// the boot block, and the same thing that decides how a file's contents are
    /// recovered — so a listing says which reader would be used, rather than
    /// leaving that to be discovered by an extraction that fails.
    pub filesystem: &'static str,
    pub block_size: u32,
    pub root_block: u32,
}

/// One file or directory located during the directory walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdfEntry {
    /// Volume-relative, `/`-separated, never absolute.
    pub path: String,
    pub kind: AdfEntryKind,
    pub size: u32,
    pub header_block: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdfEntryKind {
    File,
    Directory,
}

impl AdfEntryKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
}
