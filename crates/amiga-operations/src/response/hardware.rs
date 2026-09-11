//! Results of the `hardware.*` operations.
use super::*;

/// Which half of a Copper instruction a write lands in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopperWord {
    /// The first word: a `MOVE`'s register selector, or a `WAIT`/`SKIP`
    /// position.
    Control,
    /// The second word: a `MOVE`'s value, or a `WAIT`/`SKIP` mask.
    Data,
}

/// The Copper instruction word a CPU write patches.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperPatchSite {
    /// List-relative offset of the instruction the write lands in.
    pub instruction_offset: u32,
    pub word: CopperWord,
    /// The field in Copper terms, e.g. `COLOR02 value` or `WAIT position`.
    pub description: String,
}

/// One store the patch routine makes through the pointer register.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperPatchWrite {
    /// Hunk offset of the storing instruction.
    pub site: u32,
    /// Its runtime address, when an origin is in effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u32>,
    /// Byte offset of the store from the pointer register's value at the entry.
    pub offset: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u8>,
    /// The immediate stored, when the encoding gives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
    /// Where the write lands in the list. Absent when it lands outside — a
    /// write through the pointer that misses the copied list is still a fact
    /// about the routine, so it is reported rather than dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patches: Option<CopperPatchSite>,
    /// Hunk offset of the instruction that loaded the list's address, when the
    /// base was established inside the routine rather than at the entry.
    ///
    /// Absent means the offset is measured from the value the caller asserted
    /// the pointer register held. The distinction is worth reporting because
    /// one is a fact about the code and the other is an assumption, and a
    /// reader deciding whether to trust an offset needs to know which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_site: Option<u32>,
}

/// One instruction the applied writes changed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperChange {
    pub offset: u32,
    pub before: CopperOp,
    pub after: CopperOp,
}

/// What the list becomes once every immediate write is applied.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperEffectiveList {
    /// Writes that were applied — those with an immediate value that lands
    /// inside the list.
    pub applied: u64,
    pub instructions: Vec<CopperInstruction>,
    pub instruction_total: u64,
    pub instructions_truncated: bool,
    /// Every instruction whose decode differs from the template's. Applying
    /// immediates only rewrites words, so the structure is unchanged and the
    /// two lists zip.
    pub changes: Vec<CopperChange>,
    /// The palette the effective list installs, in both encodings — the same
    /// rule every colour in this catalog follows.
    pub palette_rgb12: Vec<u16>,
    pub palette_rgb8: Vec<[u8; 3]>,
}

/// The `hardware.copper.references` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperReferencesResult {
    pub source: SourcePin,
    pub hunk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    pub pointer_register: u8,
    /// The template's source, which may be the same file as the code's.
    pub template_source: SourcePin,
    pub template_offset: u32,
    /// Where the list runs, when the request said — the address a constant load
    /// inside the routine is matched against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_address: Option<u32>,
    /// The template as it sits in the file, decoded from its own bytes so the
    /// offsets are list-relative and comparable with the write offsets.
    pub template: Vec<CopperInstruction>,
    pub template_total: u64,
    pub template_truncated: bool,
    /// Bytes the decoded list occupies.
    pub list_bytes: u64,
    pub writes: Vec<CopperPatchWrite>,
    pub write_total: u64,
    pub writes_truncated: bool,
    /// Writes that land inside the list. The others are still reported.
    pub writes_in_list: u64,
    /// Present only when the request asked for the writes to be applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective: Option<CopperEffectiveList>,
}

/// How an instruction reaches a custom-chip register.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterAccessForm {
    /// An absolute-long operand naming the register outright.
    Absolute,
    /// A displacement from an address register holding the custom base.
    BaseRelative,
}

/// One access an instruction makes to a custom-chip register.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RegisterReference {
    /// Hunk offset of the accessing instruction.
    pub site: u32,
    /// Register offset from the custom base.
    pub offset: u16,
    /// The register's name, when this build's map knows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Which part of the machine the register belongs to — `dma`, `blitter`,
    /// `audio`, and so on. Hardware knowledge, so it travels with the access
    /// rather than being looked up again by whoever renders it.
    pub subsystem: &'static str,
    pub form: RegisterAccessForm,
    pub kind: GlobalAccessKind,
}

/// The `hardware.register.references` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RegisterReferencesResult {
    pub source: SourcePin,
    pub hunk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    /// The base the offsets are relative to, normally `$DFF000`.
    pub custom_base: u32,
    /// Ordered by register then site, so every access to one register groups
    /// together — which is the order the question is asked in.
    pub accesses: Vec<RegisterReference>,
    pub access_total: u64,
    pub accesses_truncated: bool,
}

/// A run of consecutive colour registers inside a Copper list.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperPalette {
    pub start_offset: u32,
    /// The `COLORnn` index the run starts at.
    pub first_colour: u8,
    pub rgb12: Vec<u16>,
    pub rgb8: Vec<[u8; 3]>,
}

/// A resolved `BPLxPT` high/low pointer pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperBitplanePointer {
    pub plane: u8,
    pub high_offset: u32,
    pub low_offset: u32,
    /// The address the pair writes.
    pub address: u32,
    /// Whether that address lands inside the scanned image, which is what says
    /// a pointer was found rather than two unrelated writes.
    pub points_inside_image: bool,
}

/// One plausible Copper list.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperListSummary {
    pub start: u32,
    pub end: u32,
    pub instruction_count: u64,
    pub palettes: Vec<CopperPalette>,
    pub bitplane_pointers: Vec<CopperBitplanePointer>,
}

/// The `hardware.copper.scan` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperScanResult {
    pub source: SourcePin,
    pub lists: Vec<CopperListSummary>,
    pub list_total: u64,
    pub lists_truncated: bool,
}

/// What one decoded Copper instruction does.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum CopperOp {
    /// `MOVE #value, register`, where the register is a custom-chip offset.
    Move {
        register: u16,
        value: u16,
        /// The register's name, when this build's map knows it. Hardware
        /// knowledge rather than configuration, so it belongs in the answer —
        /// the same call `env.boot.trace` made.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// The value read as an `$0RGB` colour, for a `COLORnn` write.
        #[serde(skip_serializing_if = "Option::is_none")]
        rgb8: Option<[u8; 3]>,
    },
    /// `WAIT` for a beam position.
    Wait {
        vpos: u8,
        hpos: u8,
        vmask: u8,
        hmask: u8,
        blitter_finish_disable: bool,
        /// The `$fffe` wait every Copper list ends with. A hardware fact rather
        /// than a rendering, so a consumer need not know the magic position to
        /// tell "wait for a beam that never comes" from an ordinary wait.
        terminator: bool,
    },
    /// `SKIP` the next instruction if the beam is at or past a position.
    Skip {
        vpos: u8,
        hpos: u8,
        vmask: u8,
        hmask: u8,
        blitter_finish_disable: bool,
    },
}

/// One decoded Copper instruction with its offset.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperInstruction {
    pub offset: u32,
    #[serde(flatten)]
    pub op: CopperOp,
}

/// The `hardware.copper.decode` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CopperDecodeResult {
    pub source: SourcePin,
    /// The offset the decode started from, echoed because nothing in an image
    /// marks a Copper stream: the offset is a claim about the bytes.
    pub offset: u32,
    pub instructions: Vec<CopperInstruction>,
    pub instruction_total: u64,
    pub instructions_truncated: bool,
}

/// One custom-chip register in the map this build carries.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HardwareRegister {
    /// Offset from the custom-chip base.
    pub offset: u16,
    /// The absolute address on a real machine, so a caller matching a listing
    /// against this map does not have to know where the chips sit.
    pub address: u32,
    pub name: String,
}

/// The `hardware.register.list` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HardwareRegisterListResult {
    /// The base the offsets are relative to, normally `$DFF000`.
    pub custom_base: u32,
    pub registers: Vec<HardwareRegister>,
}
