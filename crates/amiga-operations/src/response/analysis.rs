//! Results of the `analysis.*` operations.
use super::*;

/// The `analysis.code.facts` result.
///
/// The fact list is `amiga_disasm`'s own model, serialized as that crate
/// defines it and versioned by its `schema_version`. Re-typing it here would
/// create a second definition of a wire shape `disasm report --format json` has
/// published since it landed — which is the duplication this plan exists to
/// end, one level down.
///
/// The instructions travel beside the facts because every renderer of the facts
/// needs both: an annotated listing walks instructions and hangs facts off
/// them. One request rather than two that could disagree about which
/// traversal produced either.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CodeFactsResult {
    pub source: SourcePin,
    /// Which bytes the facts are about.
    pub region: crate::request::CodeRegion,
    /// The hunk, for the `hunk` region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the analyzed code starts in the file, so a fact's offset can be
    /// named in the frame a reader has open.
    pub code_offset: u64,
    pub code_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    /// The fact model's own version, which is what a consumer pins against.
    pub schema_version: u32,
    pub facts: Vec<amiga_disasm::Fact>,
    pub fact_total: u64,
    pub facts_truncated: bool,
    pub instructions: Vec<DisassembledInstruction>,
    pub instruction_total: u64,
    pub instructions_truncated: bool,
}

/// What an instruction does to the memory it touches.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalAccessKind {
    Read,
    Write,
    Modify,
    /// The address itself is taken, not the contents.
    Address,
    Other,
}

/// One access to a slot addressed as a displacement from the base register.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BaseRelativeAccess {
    /// Hunk offset of the accessing instruction.
    pub site: u32,
    /// Signed displacement from the base register.
    pub displacement: i32,
    /// Operand size in bytes, where the encoding specifies one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u8>,
    pub kind: GlobalAccessKind,
    /// Constant stored by a direct `MOVE #value,slot`, or zero by `CLR`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
    /// The slot is loaded into an address register used for a library call.
    pub library_base: bool,
    /// The stored constant lands inside the loaded image, so the slot plausibly
    /// holds a pointer. Judged here because it needs the image's bounds, which
    /// the operation has and a frontend would have to re-derive.
    pub value_points_into_image: bool,
}

/// One absolute-addressed access whose target lies inside the loaded image.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AbsoluteGlobalAccess {
    pub site: u32,
    /// The absolute target address.
    pub address: u32,
    /// That address as a hunk offset, when the origin can express it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u8>,
    pub kind: GlobalAccessKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
    pub library_base: bool,
    pub value_points_into_image: bool,
}

/// Where a derived access lands, as far as propagation could tell.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DerivedTarget {
    /// One exact effective address.
    Exact { address: u32 },
    /// An inclusive range produced by a word-sized index register.
    Range { start: u32, end: u32 },
    /// The base or index value is not known at this control-flow point.
    /// Reported rather than dropped: an access whose target is unknown is still
    /// an access, and a list that omitted it would understate what the code
    /// touches.
    Unknown,
}

/// One memory access resolved through a propagated address register.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DerivedGlobalAccess {
    pub site: u32,
    /// Address register the memory operand used.
    pub register: u8,
    pub target: DerivedTarget,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u8>,
    pub kind: GlobalAccessKind,
}

/// The `analysis.code.globals` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeGlobalsResult {
    pub source: SourcePin,
    pub hunk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    /// The address register the base-relative accesses were read through.
    pub base_register: u8,
    /// Bytes of the analyzed hunk, which is what "inside the image" means.
    pub hunk_bytes: u64,
    pub base_relative: Vec<BaseRelativeAccess>,
    pub base_relative_total: u64,
    /// Absolute accesses landing inside the image. Empty without an origin:
    /// "inside the image" has no meaning until the image has a place.
    pub absolute: Vec<AbsoluteGlobalAccess>,
    pub absolute_total: u64,
    /// Present only when the request asked for the propagation pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<Vec<DerivedGlobalAccess>>,
    pub derived_total: u64,
    /// True when any of the three lists was capped.
    pub truncated: bool,
}

/// Which fixed-point idiom a hint recognizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedPointKind {
    /// `MULS`/`MULU` followed by a right shift that renormalizes the product.
    ScaledMultiply,
    /// A left shift that pre-scales the dividend, followed by `DIVS`/`DIVU`.
    ScaledDivide,
}

/// A recognized fixed-point multiply or divide idiom.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FixedPointHint {
    /// Offset of the multiply or divide.
    pub site: u32,
    /// Offset of the normalizing shift.
    pub shift_site: u32,
    pub kind: FixedPointKind,
    /// The data register carrying the fixed-point value.
    pub register: u8,
    /// The Q fractional bit count, when the shift is by an immediate. Absent
    /// for a register-count shift, where the scale is not statically known —
    /// and a guessed Q is worse than none, because every value derived from it
    /// would be wrong by a power of two.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fractional_bits: Option<u8>,
}

/// Which side of a value a clamp bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClampKind {
    Lower,
    Upper,
}

/// A compare/branch/constant-write sequence that clamps a data register.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ClampHint {
    /// Offset of the comparison or overflow-producing operation.
    pub site: u32,
    /// Offset of the write that applies the bound.
    pub assign_site: u32,
    pub register: u8,
    pub size: u8,
    pub bound: u32,
    pub kind: ClampKind,
}

/// A point where a data register acquires a known Q fractional-bit scale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FixedPointScale {
    pub site: u32,
    pub register: u8,
    pub fractional_bits: u8,
}

/// The `analysis.code.fixed-point` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeFixedPointResult {
    pub source: SourcePin,
    pub hunk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    pub hints: Vec<FixedPointHint>,
    pub hint_total: u64,
    pub clamps: Vec<ClampHint>,
    pub clamp_total: u64,
    pub scales: Vec<FixedPointScale>,
    pub scale_total: u64,
    pub truncated: bool,
}

/// One function in the call graph, with its degree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CallgraphNode {
    /// Hunk offset of the function entry.
    pub function: u32,
    /// The runtime address of that entry, when an origin is in effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u32>,
    /// Distinct functions that call this one.
    pub in_degree: u64,
    /// Distinct functions this one calls.
    pub out_degree: u64,
}

/// A call relationship between two functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CallgraphEdge {
    pub caller: u32,
    pub callee: u32,
    /// Distinct call sites in `caller` that reach `callee`. The sites are
    /// collapsed onto the pair, so an edge is a relationship rather than a
    /// count of instructions.
    pub calls: u64,
}

/// The `analysis.code.callgraph` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeCallgraphResult {
    pub source: SourcePin,
    pub hunk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    pub nodes: Vec<CallgraphNode>,
    pub node_total: u64,
    pub nodes_truncated: bool,
    pub edges: Vec<CallgraphEdge>,
    pub edge_total: u64,
    pub edges_truncated: bool,
}

/// How an instruction names its target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    /// An absolute-long operand; the target is the encoded absolute address.
    Absolute,
    /// An absolute-short operand; the target is the encoded address, sign-extended
    /// as the 68000 extends it. Never a hunk offset — sixteen bits carry no
    /// relocation record — so a consumer must read it in the absolute frame.
    AbsoluteShort,
    /// A PC-relative operand; the target is a hunk offset, resolved against the
    /// instruction's own program counter.
    PcRelative,
}

/// One address an instruction names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeReference {
    /// Hunk offset of the referencing instruction.
    pub site: u32,
    pub kind: ReferenceKind,
    /// The referenced address, in the frame its addressing mode uses: an
    /// encoded absolute address, or a hunk offset for a PC-relative operand.
    /// The two are *not* interchangeable, which is why the kind travels with it.
    pub target: u32,
    /// The runtime address the target names, where that can be said: an
    /// absolute operand already is one, and a PC-relative offset becomes one
    /// through the mapped origin. Absent without an origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_address: Option<u32>,
}

/// The `analysis.address.references` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AddressReferencesResult {
    pub source: SourcePin,
    pub hunk: u32,
    /// The address the request asked about, when it named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    pub entries: Vec<u32>,
    pub references: Vec<CodeReference>,
    pub reference_total: u64,
    pub references_truncated: bool,
    /// Relocation sites whose stored pointer names the requested target,
    /// searched across the whole image rather than the analyzed hunk: a pointer
    /// to this address is a reference to it wherever it sits. Empty when the
    /// request named no target.
    pub relocations: Vec<HunkRelocation>,
    pub relocation_total: u64,
    pub relocations_truncated: bool,
}

/// One decoded instruction, with everything a listing is rendered *from* and
/// nothing about how.
///
/// The mnemonic is text because the decoder produces text; the label, the
/// column widths, and the comment marker are not here, because they are one
/// frontend's choice and would become every consumer's contract.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DisassembledInstruction {
    /// Offset within the analyzed hunk.
    pub offset: u32,
    /// The runtime address, when the request named an origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u32>,
    /// The encoded instruction, as lowercase hex.
    pub bytes: String,
    /// The mnemonic and its operands.
    pub text: String,
    /// Flow mode: the entries whose traversal reached this instruction, capped
    /// by the analysis itself.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<u32>,
    /// Distinct owners that arrived, counting those the analysis's own cap
    /// refused. Carried separately so a capped owner set never reads as a
    /// complete one.
    pub owner_total: u64,
}

/// A run of bytes no traversal reached.
///
/// Unreached does not prove data — only that recursive direct control flow did
/// not arrive. The bytes travel so a caller can render or re-examine them
/// without opening the source again.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct UnreachedRun {
    pub offset: u32,
    /// The unreached bytes, as lowercase hex.
    pub bytes: String,
}

/// How much of a hunk the traversal reached.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct CodeCoverage {
    pub total_bytes: u64,
    pub decoded_bytes: u64,
    pub instructions: u64,
    pub functions: u64,
    /// Statically resolved direct calls, as distinct (site, callee) pairs.
    pub calls: u64,
    pub library_calls: u64,
    pub unresolved: u64,
    pub external: u64,
}

/// One resolved call edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeCallEdge {
    pub caller: u32,
    pub call_site: u32,
    pub callee: u32,
}

/// The semantic kind of a statically resolved control-flow edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFlowKind {
    Fallthrough,
    Branch,
    Call,
}

/// One instruction-level control-flow edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeFlowEdge {
    /// Function entry whose traversal discovered the edge.
    pub owner: u32,
    pub site: u32,
    pub target: u32,
    pub kind: CodeFlowKind,
}

/// A transfer with no static target and no explaining convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeUnresolvedFlow {
    pub owner: u32,
    pub site: u32,
}

/// How a relocation-proved transfer leaves the analyzed hunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeExternalKind {
    Call,
    Jump,
}

/// A transfer a relocation proves leaves the analyzed hunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeExternalFlow {
    pub site: u32,
    pub kind: CodeExternalKind,
    /// Offset of the patched longword whose relocation proves the target.
    pub relocation: u32,
    pub target_hunk: u32,
    pub target_offset: u32,
}

/// What the traversal found, beside the instructions it decoded.
///
/// Present only in flow mode: a linear sweep follows nothing and so knows
/// nothing about functions, calls, or what it failed to reach.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct CodeFlowFacts {
    /// The entry offsets the traversal started from, echoed because the answer
    /// means nothing without them.
    pub entries: Vec<u32>,
    pub unreached: Vec<UnreachedRun>,
    pub unreached_total: u64,
    pub unreached_truncated: bool,
    pub functions: Vec<u32>,
    pub function_total: u64,
    pub calls: Vec<CodeCallEdge>,
    pub call_total: u64,
    pub flows: Vec<CodeFlowEdge>,
    pub flow_total: u64,
    pub unresolved: Vec<CodeUnresolvedFlow>,
    pub unresolved_total: u64,
    pub library_calls: Vec<u32>,
    pub library_call_total: u64,
    pub external: Vec<CodeExternalFlow>,
    pub external_total: u64,
    /// True when any of the lists above was capped.
    pub truncated: bool,
    pub coverage: CodeCoverage,
}

/// The `analysis.code.disassemble` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CodeDisassembleResult {
    pub source: SourcePin,
    /// Whether the source was a HUNK container or pinned raw code.
    pub region: crate::request::CodeRegion,
    /// Selected CODE hunk. Absent for raw code, which has no hunk frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    pub mode: crate::request::CodeDisassembleMode,
    /// Bytes the selected code region holds.
    pub hunk_bytes: u64,
    /// The mapped origin, when the request named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    /// The range actually covered, as code-region offsets. Linear mode's request may
    /// leave `end` open; this is what it resolved to.
    pub start: u32,
    pub end: u32,
    pub instructions: Vec<DisassembledInstruction>,
    pub instruction_total: u64,
    pub instructions_truncated: bool,
    /// Flow mode only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<CodeFlowFacts>,
}

/// One number expressed in every frame that reading reaches.
///
/// A frame is absent when the reading has none: a value below the mapped origin
/// is not a hunk offset, and no reading has a whole-file position without an
/// anchor. Absent and zero must not read the same.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct AddressFrames {
    /// The runtime address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute: Option<u32>,
    /// The offset within the mapped hunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk_relative: Option<u32>,
    /// The offset within the whole file, when a hunk anchors it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whole_file: Option<u64>,
}

/// The `analysis.address.resolve` result.
///
/// Every reading the value admits, rather than the one the caller meant: which
/// frame a number came from is exactly what a reader is trying to work out, so
/// answering only one of them would assume the answer.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AddressResolveResult {
    /// The anchoring image, when one was named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourcePin>,
    pub value: u32,
    pub origin: u32,
    /// The anchoring hunk, when one was named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where that hunk's bytes start in the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk_file_offset: Option<u64>,
    /// How many bytes that hunk holds, so a caller can tell a reading that
    /// lands inside it from one that lands just past the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk_bytes: Option<u64>,
    /// Reading the value as a runtime address.
    pub as_absolute: AddressFrames,
    /// Reading the value as an offset within the mapped hunk.
    pub as_hunk_relative: AddressFrames,
    /// Reading the value as an offset within the whole file. Present only when
    /// a hunk anchors the frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_whole_file: Option<AddressFrames>,
}

/// How a pointer table's entries encode their targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerEncoding {
    /// A big-endian absolute longword.
    Long,
    /// A big-endian unsigned word, scaled and added to the origin.
    ScaledWord,
}

/// One run of plausible pointer entries.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PointerTable {
    /// Byte offset of the first entry within the scanned hunk.
    pub offset: u32,
    pub encoding: PointerEncoding,
    /// The decoded targets, in table order.
    pub targets: Vec<u32>,
    /// Entries the run holds before the cap. Always the true total.
    pub target_total: u64,
    pub targets_truncated: bool,
    /// Lowest and highest target the *whole* run reaches, capped or not — the
    /// span is what says which part of the hunk a table addresses, and reading
    /// it off a truncated list would understate it.
    pub target_lowest: u32,
    pub target_highest: u32,
}

/// The `analysis.pointers.scan` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PointerScanResult {
    pub source: SourcePin,
    pub hunk: u32,
    /// The mapped origin the targets were judged against.
    pub origin: u32,
    /// Bytes of the hunk that were scanned.
    pub scanned_bytes: u64,
    pub tables: Vec<PointerTable>,
    /// Tables found before the cap. Always the true total.
    pub table_total: u64,
    pub tables_truncated: bool,
    /// Every distinct target that lands on an even offset inside the scanned
    /// hunk, ascending — the entry points a control-flow analysis would be
    /// seeded from. Derived from every target found, not from the capped lists,
    /// so a capped response still names the same seeds.
    pub entry_offsets: Vec<u32>,
    pub entry_offset_total: u64,
    pub entry_offsets_truncated: bool,
}

/// One printable run the scan found.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FoundString {
    /// Byte offset within what was scanned — the file, or the hunk when the
    /// request named one.
    pub offset: u64,
    pub text: String,
}

/// The `analysis.strings.scan` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StringsScanResult {
    pub source: SourcePin,
    /// The hunk the offsets are relative to, when the request named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Bytes actually scanned.
    pub scanned_bytes: u64,
    pub strings: Vec<FoundString>,
    /// Strings matching the request before the cap. Always the true total.
    pub string_total: u64,
    pub strings_truncated: bool,
}

/// One relocation site: where a pointer sits, and what it points into.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkRelocation {
    pub source_hunk: u32,
    pub source_offset: u32,
    pub target_hunk: u32,
    /// The offset stored at the site, which is what the pointer becomes once
    /// the target hunk's load address is added to it. Absent when the site
    /// itself is unreadable — reported rather than skipped, because a
    /// relocation nobody can read is a fact about the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_offset: Option<u32>,
}

/// One hunk of a LoadSeg image.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkSegment {
    pub index: u32,
    /// `code`, `data`, or `bss`.
    pub kind: String,
    /// Bytes the loader allocates, which for BSS exceeds what the file holds.
    pub allocation_bytes: u64,
    /// Byte offset of the hunk's data within the file.
    pub file_offset: u64,
    /// Bytes the file actually carries for it.
    pub file_bytes: u64,
    /// Relocations whose *source* is this hunk, capped.
    pub relocations: Vec<HunkRelocation>,
    /// Relocations this hunk has before the cap. Always the true total.
    pub relocation_total: u64,
    pub relocations_truncated: bool,
}

/// The `analysis.hunk.list` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkListResult {
    pub source: SourcePin,
    pub first_hunk: u32,
    pub last_hunk: u32,
    pub segments: Vec<HunkSegment>,
}

/// The `analysis.hunk.normalize` result.
///
/// Reports what the rewrite *would* produce without producing it anywhere: the
/// digest of the rewritten image, and the hunk and relocation counts the
/// rewrite's own re-parse found. The re-parse is the rewrite's proof — reading
/// an ordinary image as compact shifts every record after the first count — so
/// these counts exist only because the output parsed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkNormalizeResult {
    pub source: SourcePin,
    /// Bytes of the rewritten image.
    pub normalized_bytes: u64,
    /// SHA-256 of the rewritten image.
    pub normalized_sha256: String,
    /// Hunks the rewritten image declares.
    pub segments: u64,
    /// Relocations the rewritten image declares.
    pub relocations: u64,
}

/// The `analysis.hunk.normalize.export` result: the same summary, plus the plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkNormalizeExportResult {
    pub normalized: HunkNormalizeResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `analysis.table.decode` result.
///
/// `row_total` is how many whole rows the region actually holds, which is the
/// number that makes a guessed layout falsifiable: a request for 40 rows that
/// comes back with 37 has learned something about the table.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableDecodeResult {
    pub source: SourcePin,
    pub offset: u64,
    pub record_size: u64,
    pub rows: Vec<TableRow>,
    pub row_total: usize,
}

/// One decoded record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableRow {
    /// Where this row starts in the source.
    pub offset: u64,
    pub fields: Vec<TableField>,
}

/// One decoded field.
///
/// A pointer stays distinct from an unsigned integer even though both are 32
/// bits wide: which fields are pointers is most of what identifying a table is
/// for.
/// Ordered as well as compared, so a frequency list can be sorted into one
/// order two runs over the same bytes agree on. The order between *kinds* is
/// the declaration order and means nothing; one column holds one kind.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TableField {
    Unsigned(u32),
    Signed(i32),
    Pointer(u32),
    Text(String),
    Bytes(Vec<u8>),
}

/// The `analysis.table.summarize` result: what each table's columns hold, and
/// where the tables disagree.
///
/// Every count is exact and every list is capped, which is the property that
/// makes this usable as evidence: "this column holds three distinct values" is
/// a fact about the table, and a capped list of them beside a count that was
/// also capped would be a fact about the request.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableSummarizeResult {
    /// The layout every table was read with, as a record size. One layout, so
    /// one size: a comparison between tables read differently would compare
    /// columns that are not the same column.
    pub record_size: u64,
    pub offset: u64,
    pub tables: Vec<TableSummary>,
    /// Per column, where the tables disagree. Empty when one source was named:
    /// there is nothing to compare a table with.
    pub comparisons: Vec<TableColumnComparison>,
    /// Rows compared across every table — the shortest table's count, since a
    /// row one table does not have is not a disagreement about a value.
    pub compared_rows: u64,
}

/// One table's columns, summarized.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableSummary {
    pub source: SourcePin,
    /// Rows actually read, which the caps and the region's length both bound.
    pub rows_read: u64,
    /// Whole rows the region holds from `offset`. Always the true total.
    pub row_total: u64,
    pub columns: Vec<TableColumnSummary>,
}

/// What one column of one table holds.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableColumnSummary {
    /// Which field of the record this is, counting the fields that produce
    /// values — a `pad` consumes bytes and is not a column.
    pub column: u32,
    /// Byte offset of the field inside one record, so a column can be found in
    /// a hex dump without recounting the layout.
    pub field_offset: u64,
    /// Distinct values in this column. Always exact.
    pub distinct_total: u64,
    /// The most frequent values, most frequent first and then by value so the
    /// order is total. Capped; `values_truncated` says when.
    pub values: Vec<TableValueCount>,
    pub values_truncated: bool,
    /// The extremes, for a column whose values are numeric. Absent for text and
    /// byte columns, where a minimum is a fact about an encoding rather than
    /// about the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
}

/// One value and how often the column holds it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableValueCount {
    pub value: TableField,
    pub count: u64,
}

/// Where the tables disagree in one column.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableColumnComparison {
    pub column: u32,
    /// Whether every compared row holds the same value in every table. The one
    /// answer a reader wants first, and the one a list of differences cannot
    /// give when it is capped.
    pub identical: bool,
    /// Rows where at least two tables differ. Always exact.
    pub differing_total: u64,
    /// The first of them, capped.
    pub differences: Vec<TableRowDifference>,
}

/// One row where the tables hold different values in one column.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TableRowDifference {
    pub row: u64,
    /// One value per table, in the order the request named them.
    pub values: Vec<TableField>,
}

/// The `analysis.hunk.diff` result.
///
/// Lists every hunk present in either image, identical ones included: a report
/// that omitted them would make "this hunk is not listed" mean both "unchanged"
/// and "absent from both".
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkDiffResult {
    pub a: SourcePin,
    pub b: SourcePin,
    /// Whether the two images are structurally identical.
    pub identical: bool,
    pub changed_hunks: usize,
    pub hunks: Vec<HunkDiffEntry>,
}

/// One hunk's comparison.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HunkDiffEntry {
    pub index: u32,
    pub presence: HunkPresence,
    pub unchanged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_a: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_b: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation_a: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation_b: Option<u64>,
    pub changed_ranges: Vec<ByteRangeReport>,
    /// The true number of changed ranges, whether or not they all fit.
    pub changed_range_total: usize,
    pub changed_ranges_truncated: bool,
    pub added_relocations: Vec<RelocationReport>,
    pub removed_relocations: Vec<RelocationReport>,
}

/// Which of the two images a hunk index appears in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HunkPresence {
    Both,
    OnlyA,
    OnlyB,
}

impl HunkPresence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::OnlyA => "only_a",
            Self::OnlyB => "only_b",
        }
    }
}

/// A half-open run of differing bytes, hunk-relative.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ByteRangeReport {
    pub start: u32,
    pub length: u32,
}

/// One relocation, as a comparison reports it.
///
/// The source hunk is not repeated: it is the hunk this relocation is listed
/// under, and a second spelling could only ever disagree with the first.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RelocationReport {
    pub source_offset: u32,
    pub target_hunk: u32,
}

/// The `analysis.hunk.diff.export` result.
///
/// Carries the comparison's summary beside the plan, so a reviewer sees what
/// the report says before authorizing the file that would say it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HunkDiffExportResult {
    pub a: SourcePin,
    pub b: SourcePin,
    pub identical: bool,
    pub changed_hunks: usize,
    pub format: crate::request::HunkDiffFormat,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `analysis.state.snapshot` result: one machine's reviewed state, named.
///
/// Deserializable as well as serializable, and `deny_unknown_fields` in both
/// directions, because `analysis.state.compare` reads these back — including
/// ones this toolkit did not write. A clean-room port stating its state in this
/// shape is exactly the case the operation exists for, and a document neither
/// side fully understood would still produce a plausible-looking comparison.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshotResult {
    /// The image whose variables were decoded.
    pub image_id: String,
    /// The ranges of memory the snapshot read, each with the digest of the
    /// bytes it actually got.
    pub regions: Vec<StateRegionPin>,
    /// The register file the snapshot was taken with, when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registers: Option<SandboxRegisters>,
    /// Every leaf value, in path order. Aggregates contribute their leaves and
    /// no row of their own: a struct has no value, only fields that do.
    pub fields: Vec<StateField>,
    /// Leaves the snapshot decoded before the report cap.
    pub fields_total: u64,
    pub fields_truncated: bool,
}

/// One range of memory a snapshot read.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateRegionPin {
    pub address: u32,
    pub length: u32,
    /// The identity the range was read from, so a snapshot says which file it
    /// described rather than only which addresses.
    pub source: String,
    /// The digest of the bytes actually read.
    pub sha256: String,
}

/// One named leaf of the decoded state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateField {
    /// `name`, `name.field`, `name[3].field` — stable, and what a comparison
    /// aligns on. Never an address: two runs under different load maps hold the
    /// same state at different addresses, and aligning on the number would
    /// report a relocation as a difference in the data.
    pub path: String,
    /// Where this leaf was read from in the snapshot's address space.
    pub address: u32,
    pub size: u64,
    /// The type the project gives it, so a consumer can tell a byte from a
    /// signed byte without re-deriving it.
    pub type_id: String,
    /// The object digest the annotation naming this was established against.
    pub object_sha256: String,
    pub value: StateValue,
}

/// What one leaf holds.
///
/// Tagged, and deliberately not collapsed into "a number": a pointer that
/// compared equal to an integer of the same bit pattern would let a relocated
/// address read as an unchanged value.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateValue {
    /// An integer, read at the width, signedness and byte order its type gives.
    Integer {
        value: i64,
        signed: bool,
        byte_order: String,
    },
    /// A pointer, with the space its value is read in.
    Pointer { address: u32, address_space: String },
    /// An enumerated value. `member` is absent when the stored number is not
    /// one the project names — which is a finding rather than an error, and one
    /// a comparison shows plainly.
    Enum {
        value: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member: Option<String>,
    },
    /// Bytes, for a leaf whose type states a width this build cannot read as a
    /// scalar. Reported rather than skipped, so the field still appears in a
    /// comparison and still says it changed.
    Bytes { hex: String },
}

/// The `analysis.state.compare` result: which fields disagree, and how.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StateCompareResult {
    pub snapshots: Vec<ComparedSnapshot>,
    /// Whether every path present in any snapshot holds the same value in all
    /// of them.
    pub identical: bool,
    /// Paths compared across all snapshots, whether or not they differ.
    pub paths_total: u64,
    pub differences: Vec<StateDifference>,
    pub differences_total: u64,
    pub differences_truncated: bool,
}

/// One snapshot the comparison read.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ComparedSnapshot {
    /// The locator the request named it by, so a difference's positional values
    /// can be read back to a file.
    pub name: String,
    /// The digest of the snapshot *document*, which is what pins the
    /// comparison.
    pub sha256: String,
    pub image_id: String,
    pub fields_total: u64,
    /// Whether this snapshot's field list was capped when it was written. A
    /// comparison against a capped snapshot cannot tell an absent field from
    /// one that was truncated away, and says so rather than reporting it as a
    /// difference.
    pub fields_truncated: bool,
}

/// One path the snapshots disagree about.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StateDifference {
    pub path: String,
    /// Each snapshot's value, in the order the request named them. `None` is
    /// the field being absent from that snapshot, which is a difference of its
    /// own kind and is named rather than rendered as a value.
    pub values: Vec<Option<StateValue>>,
}
