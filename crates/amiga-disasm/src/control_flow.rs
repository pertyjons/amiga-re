//! Recursive control-flow analysis of MC68000 code.
//!
//! Instruction decoding comes from the external `m68000` crate; this module adds
//! the reverse-engineering layer on top: recursive-descent traversal that follows
//! branches, `BSR`/`JSR` calls, `DBcc`, direct `JMP`/`JSR` targets, and
//! PC-indexed branch/call tables of `BRA.W` stubs and range-checked data jump
//! tables, recording a call graph and any control flow it could not resolve.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Instruction, Operands, Size};
use m68000::isa::Isa;
use m68000::memory_access::MemoryAccess;
use serde::Serialize;

mod jump_tables;

/// How many owners one instruction records before propagation stops.
///
/// Ownership costs one traversal per `(instruction, owner)` pair, so code that
/// every entry in a large executable falls into would otherwise be walked once
/// per entry. The cap is [`crate::report::MAX_XREF_SITES`] by definition rather
/// than by coincidence: recording an owner a fact can never list buys nothing.
pub const MAX_INSTRUCTION_OWNERS: usize = crate::report::MAX_XREF_SITES;

/// A decoded instruction and the set of function entries that reach it.
#[derive(Clone, Debug)]
pub struct DecodedInstruction {
    pub address: u32,
    pub end: u32,
    pub instruction: Instruction,
    pub encoded: Vec<u8>,
    /// Entries whose traversal reached this instruction, capped at
    /// [`MAX_INSTRUCTION_OWNERS`].
    pub owners: BTreeSet<u32>,
    /// Distinct owners that arrived here, counting those the cap refused, so a
    /// capped set never reads as a complete one.
    ///
    /// Beyond the cap this is a lower bound: a refused owner stops walking, so
    /// instructions further along the block never see it. `owner_total >
    /// owners.len()` is the signal that ownership was truncated.
    pub owner_total: usize,
}

/// Which encoded operand a consumer is resolving. MC68000 `MOVE` is the only
/// ordinary form with two arbitrary effective addresses; naming the role keeps
/// equal source and destination addends distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperandRole {
    Source,
    Destination,
    /// The instruction has one effective-address operand.
    Only,
}

impl OperandRole {
    /// Identify the encoded operand responsible for one classified access.
    pub(crate) fn for_access(operands: Operands, access: crate::globals::AccessKind) -> Self {
        match operands {
            Operands::SizeEffectiveAddressEffectiveAddress(..) => match access {
                crate::globals::AccessKind::Read => Self::Source,
                crate::globals::AccessKind::Write => Self::Destination,
                crate::globals::AccessKind::Modify
                | crate::globals::AccessKind::Address
                | crate::globals::AccessKind::Other => Self::Only,
            },
            Operands::SizeEffectiveAddressImmediate(..) => Self::Destination,
            _ => Self::Only,
        }
    }
}

impl DecodedInstruction {
    /// Render this instruction, including the small set of later-family
    /// instructions the pinned MC68000 decoder deliberately does not name.
    #[must_use]
    pub fn text(&self) -> String {
        opaque_fallthrough_text(self.instruction.opcode, &self.encoded)
            .unwrap_or_else(|| self.instruction.to_string())
    }

    /// Whether this is a fully sized, straight-line instruction outside the
    /// pinned decoder's MC68000 instruction set.
    pub(crate) fn is_opaque_fallthrough(&self) -> bool {
        movec_fields(self.instruction.opcode, &self.encoded).is_some()
    }

    /// The general register MOVEC overwrites, if it moves a control register
    /// into one. `true` identifies an address register and `false` a data
    /// register.
    pub(crate) fn movec_destination(&self) -> Option<(bool, u8)> {
        if self.instruction.opcode != 0x4e7a {
            return None;
        }
        let (address, register, _) = movec_fields(self.instruction.opcode, &self.encoded)?;
        Some((address, register))
    }

    /// Record `owner`, and report whether the traversal may keep walking.
    ///
    /// Returns `false` once the cap refuses a new owner: continuing would walk
    /// the rest of the block for an owner no consumer can be told about.
    fn add_owner(&mut self, owner: u32) -> bool {
        if self.owners.contains(&owner) {
            return true;
        }
        self.owner_total = self.owner_total.saturating_add(1);
        if self.owners.len() >= MAX_INSTRUCTION_OWNERS {
            return false;
        }
        self.owners.insert(owner);
        true
    }
}

/// A resolved call edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CallEdge {
    pub caller: u32,
    pub call_site: u32,
    pub callee: u32,
}

/// The semantic kind of a statically resolved control-flow edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FlowKind {
    Fallthrough,
    Branch,
    Call,
}

/// One instruction-level edge in the control-flow graph.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FlowEdge {
    /// Function entry whose traversal discovered the edge.
    pub owner: u32,
    pub site: u32,
    pub target: u32,
    pub kind: FlowKind,
}

/// A control-flow transfer whose target could not be resolved statically.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnresolvedFlow {
    pub owner: u32,
    pub address: u32,
}

/// How a relocation-proved transfer leaves the analyzed hunk.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalKind {
    /// `JSR`: control is expected back at the following instruction.
    Call,
    /// `JMP`: a tail transfer that does not come back to this hunk.
    Jump,
}

impl ExternalKind {
    /// The snake_case name shared by text renderers and the JSON
    /// serialization (kept in lockstep by a unit test).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
        }
    }
}

/// A control-flow transfer a relocation proves leaves the analyzed hunk.
///
/// Its target is resolved — the record names the destination hunk and offset —
/// but it is not reachable from here, so it is neither an in-hunk edge nor an
/// [`UnresolvedFlow`] warning.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExternalFlow {
    /// Hunk offset of the transferring instruction.
    ///
    /// The transfer carries no owner of its own: which functions reach it is a
    /// property of the instruction, and
    /// [`DecodedInstruction::owners`] is the one place that records it. A field
    /// here would name only whichever traversal happened to arrive first.
    pub site: u32,
    pub kind: ExternalKind,
    /// Hunk offset of the patched longword whose relocation proves the target.
    pub relocation: u32,
    pub target_hunk: u32,
    pub target_offset: u32,
}

/// The result of analyzing a code image from one or more entry points.
#[derive(Clone, Debug)]
pub struct ControlFlowAnalysis {
    pub instructions: BTreeMap<u32, DecodedInstruction>,
    pub functions: BTreeSet<u32>,
    pub calls: BTreeSet<CallEdge>,
    pub flows: BTreeSet<FlowEdge>,
    /// Control flow with no static target and no explaining convention.
    pub unresolved: BTreeSet<UnresolvedFlow>,
    /// Sites of `JSR`/`JMP (d16,A6)` with a negative displacement — the
    /// AmigaOS library-call convention ([`crate::lvo::is_library_call_mode`]).
    /// Statically unresolved too, but the convention explains the target, so
    /// they are not warned about as [`Self::unresolved`].
    pub library_calls: BTreeSet<u32>,
    /// Calls and jumps whose relocation proves they leave the analyzed hunk.
    /// Empty unless the caller supplied [`FlowOptions::relocations`].
    pub external: BTreeSet<ExternalFlow>,
    /// The relocation index used by this traversal. Keeping it with the graph
    /// makes every later interpretation of an operand use the same record.
    relocations: Option<Relocations>,
    /// The runtime-to-image mapping used by this traversal.
    rebase: Option<Rebase>,
}

impl ControlFlowAnalysis {
    /// The relocation index used to traverse this image, when one was
    /// supplied.
    #[must_use]
    pub fn relocations(&self) -> Option<&Relocations> {
        self.relocations.as_ref()
    }

    /// Read an unrelocated absolute address in the same coordinate system the
    /// traversal used. The caller still decides whether the resulting offset
    /// names an instruction it owns.
    pub(crate) fn image_offset(&self, address: u32) -> Option<u32> {
        self.rebase
            .map_or(Some(address), |rebase| address.checked_sub(rebase.origin))
    }

    /// What an address-bearing longword operand names after consulting the
    /// relocation index used by this traversal.
    pub(crate) fn operand_address(
        &self,
        decoded: &DecodedInstruction,
        role: OperandRole,
        addend: u32,
    ) -> OperandAddress {
        let Some(relocations) = self.relocations() else {
            return OperandAddress::Encoded(addend);
        };
        let relocation = relocations.resolve_operand(
            decoded.address,
            decoded.end,
            operand_longword_position(decoded, role),
            addend,
        );
        let Some(relocation) = relocation else {
            return OperandAddress::Encoded(addend);
        };
        let hunk = relocations.hunk();
        if relocation.target_hunk == hunk {
            OperandAddress::ThisHunk(relocation.target_offset)
        } else {
            OperandAddress::OtherHunk {
                hunk: relocation.target_hunk,
                offset: relocation.target_offset,
            }
        }
    }
}

/// Exact hunk offset of the longword extension belonging to `role`.
///
/// The decoder exposes values but not their byte spans. This bounded layout
/// mirrors the MC68000 extension order: immediate fields precede their EA,
/// `MOVEM` has a mask word first, and `MOVE` encodes source extensions before
/// destination extensions even though its decoded tuple names destination
/// first. Returning `None` preserves the conservative range/addend fallback
/// for an operand form added by a future decoder version.
pub(crate) fn operand_longword_position(
    decoded: &DecodedInstruction,
    role: OperandRole,
) -> Option<u32> {
    let (relative, mode, size) = operand_layout(decoded, role)?;
    if !is_longword_extension(mode, size) {
        return None;
    }
    let patched = decoded.address.checked_add(2)?.checked_add(relative)?;
    let after = patched.checked_add(4)?;
    (after <= decoded.end).then_some(patched)
}

/// Byte displacement, addressing mode, and encoded size of one operand.
///
/// This is exhaustive over the decoder's operand vocabulary. A decoder update
/// that adds a form therefore fails to compile until its extension layout is
/// classified, instead of silently losing exact relocation attribution.
fn operand_layout(
    decoded: &DecodedInstruction,
    role: OperandRole,
) -> Option<(u32, AddressingMode, Size)> {
    match decoded.instruction.operands {
        Operands::SizeEffectiveAddressEffectiveAddress(size, destination, source) => match role {
            OperandRole::Source => Some((0, source, size)),
            OperandRole::Destination => Some((ea_extension_bytes(source, size), destination, size)),
            OperandRole::Only => None,
        },
        Operands::SizeEffectiveAddressImmediate(size, destination, value) => match role {
            OperandRole::Source => Some((0, AddressingMode::Immediate(value), size)),
            OperandRole::Destination => Some((immediate_extension_bytes(size), destination, size)),
            OperandRole::Only => None,
        },
        Operands::DirectionSizeEffectiveAddressList(_, size, mode, _) => Some((2, mode, size)),
        Operands::EffectiveAddressCount(mode, _) => {
            let relative = u32::from(decoded.instruction.opcode & 0xff00 == 0x0800) * 2;
            Some((relative, mode, Size::Long))
        }
        Operands::SizeEffectiveAddress(size, mode)
        | Operands::SizeRegisterEffectiveAddress(size, _, mode)
        | Operands::DataSizeEffectiveAddress(_, size, mode)
        | Operands::RegisterDirectionSizeEffectiveAddress(_, _, size, mode)
        | Operands::RegisterSizeEffectiveAddress(_, size, mode) => Some((0, mode, size)),
        Operands::EffectiveAddress(mode)
        | Operands::RegisterEffectiveAddress(_, mode)
        | Operands::ConditionEffectiveAddress(_, mode)
        | Operands::DirectionEffectiveAddress(_, mode) => Some((0, mode, Size::Long)),
        Operands::NoOperands
        | Operands::Immediate(..)
        | Operands::Vector(..)
        | Operands::RegisterDirectionSizeRegisterDisplacement(..)
        | Operands::RegisterOpmodeRegister(..)
        | Operands::OpmodeRegister(..)
        | Operands::RegisterDisplacement(..)
        | Operands::Register(..)
        | Operands::DirectionRegister(..)
        | Operands::ConditionRegisterDisplacement(..)
        | Operands::Displacement(..)
        | Operands::ConditionDisplacement(..)
        | Operands::RegisterData(..)
        | Operands::RegisterSizeModeRegister(..)
        | Operands::RegisterSizeRegister(..)
        | Operands::RotationDirectionSizeModeRegister(..) => None,
    }
}

const fn is_longword_extension(mode: AddressingMode, size: Size) -> bool {
    matches!(mode, AddressingMode::AbsLong(_))
        || matches!(mode, AddressingMode::Immediate(_)) && matches!(size, Size::Long)
}

const fn ea_extension_bytes(mode: AddressingMode, size: Size) -> u32 {
    match mode {
        AddressingMode::Drd(_)
        | AddressingMode::Ard(_)
        | AddressingMode::Ari(_)
        | AddressingMode::Ariwpo(_)
        | AddressingMode::Ariwpr(_) => 0,
        AddressingMode::Ariwd(..)
        | AddressingMode::Ariwi8(..)
        | AddressingMode::AbsShort(_)
        | AddressingMode::Pciwd(..)
        | AddressingMode::Pciwi8(..) => 2,
        AddressingMode::AbsLong(_) => 4,
        AddressingMode::Immediate(_) => immediate_extension_bytes(size),
    }
}

const fn immediate_extension_bytes(size: Size) -> u32 {
    match size {
        Size::Byte | Size::Word => 2,
        Size::Long => 4,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperandAddress {
    /// No relocation patches the operand, so the stored longword is its
    /// address.
    Encoded(u32),
    /// The relocation names an offset in the analyzed hunk.
    ThisHunk(u32),
    /// The relocation names a hunk whose runtime mapping is unknown here.
    OtherHunk { hunk: u32, offset: u32 },
}

/// Rebases absolute addresses to file offsets for an image copied to a fixed
/// load address and executed there: `offset = absolute - origin`, where `origin`
/// is the absolute address that file offset 0 occupies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rebase {
    origin: u32,
}

impl Rebase {
    /// Create a rebase whose file offset 0 sits at absolute address `origin`.
    #[must_use]
    pub const fn new(origin: u32) -> Self {
        Self { origin }
    }

    /// Convert an absolute `address` to a file offset, if it lies within the
    /// `len`-byte loaded image.
    fn to_offset(self, address: u32, len: usize) -> Option<u32> {
        let offset = address.checked_sub(self.origin)?;
        (usize::try_from(offset).ok()? < len).then_some(offset)
    }
}

/// One HUNK relocation patching the analyzed hunk, as the caller that parsed
/// the executable read it. Supplying them here keeps this crate free of HUNK
/// parsing while letting the traversal read a patched operand correctly.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Relocation {
    /// Hunk offset of the patched longword.
    pub patched: u32,
    /// The hunk the stored pointer names.
    pub target_hunk: u32,
    /// The offset into `target_hunk` the stored pointer names — the addend an
    /// unloaded file stores in the patched longword.
    pub target_offset: u32,
}

/// The relocations patching one hunk, indexed for the question the traversal
/// asks of them: where does this absolute-long operand really point?
///
/// An unloaded HUNK file stores the addend, not the loaded address, so a
/// `JSR $0.L` patched into another hunk reads as "offset zero of this hunk"
/// unless the relocation record is consulted.
#[derive(Clone, Debug)]
pub struct Relocations {
    hunk: u32,
    patched: BTreeMap<u32, Relocation>,
}

impl Relocations {
    /// Index the relocations that patch `hunk`, which is the hunk being
    /// analyzed. Records patching any other hunk are the caller's to filter
    /// out; their offsets mean nothing in this code.
    #[must_use]
    pub fn new(hunk: u32, relocations: impl IntoIterator<Item = Relocation>) -> Self {
        Self {
            hunk,
            patched: relocations
                .into_iter()
                .map(|relocation| (relocation.patched, relocation))
                .collect(),
        }
    }

    /// The hunk these relocations patch.
    #[must_use]
    pub const fn hunk(&self) -> u32 {
        self.hunk
    }

    /// The relocation patching an absolute-long operand of the instruction
    /// spanning `site..end` whose stored longword is `addend`.
    ///
    /// The patched longword must lie wholly inside the instruction and after
    /// its opcode word. Matching the stored value as well as the byte range
    /// keeps an instruction whose two absolute operands store different
    /// addends attributed to the one the record actually patches; two operands
    /// storing the *same* addend are indistinguishable here, and both read as
    /// relocated.
    pub fn covering(&self, site: u32, end: u32, addend: u32) -> Option<Relocation> {
        let (first, last) = operand_range(site, end)?;
        self.patched
            .range(first..=last)
            .map(|(_, relocation)| *relocation)
            .find(|relocation| relocation.target_offset == addend)
    }

    /// The relocation at one exact longword position, provided its stored
    /// addend agrees with the record.
    #[must_use]
    pub fn at(&self, patched: u32, addend: u32) -> Option<Relocation> {
        self.patched
            .get(&patched)
            .copied()
            .filter(|relocation| relocation.target_offset == addend)
    }

    /// Resolve the relocation for one decoded operand.
    ///
    /// An exact operand position takes precedence. When the decoder exposes no
    /// position, fall back to the instruction range and stored addend.
    #[must_use]
    pub fn resolve_operand(
        &self,
        site: u32,
        end: u32,
        operand: Option<u32>,
        addend: u32,
    ) -> Option<Relocation> {
        match operand {
            Some(patched) => self.at(patched, addend),
            None => self.covering(site, end, addend),
        }
    }

    /// The inverse question: which decoded instruction's operand does the
    /// patched longword at `patched` belong to?
    ///
    /// Answered by the same operand-range rule [`Self::covering`] uses, so
    /// a caller cannot reach a state where one says an instruction owns a
    /// patched offset and the other denies it. Deciding this in two places is
    /// how the two rules drifted apart before.
    ///
    /// `None` for a relocation in data, or in an instruction's opcode word.
    ///
    /// Takes no `self`: the answer is a property of the decoded code, so the
    /// question is askable about a relocation record this index does not hold —
    /// one whose stored pointer could not be read, and which therefore proves
    /// nothing about where an operand points but still patches an instruction.
    ///
    /// Instructions that overlap — a jump into the middle of another — can both
    /// contain the longword. The innermost, i.e. the one starting latest, wins,
    /// and the choice is arbitrary but deterministic: nothing in the encoding
    /// says which reading executes.
    #[must_use]
    pub fn covering_instruction(analysis: &ControlFlowAnalysis, patched: u32) -> Option<u32> {
        analysis
            .instructions
            .range(..=patched)
            .rev()
            .find(|(start, decoded)| {
                operand_range(**start, decoded.end)
                    .is_some_and(|(first, last)| (first..=last).contains(&patched))
            })
            .map(|(&start, _)| start)
    }
}

/// The inclusive range of offsets at which a patched longword may start inside
/// the instruction spanning `site..end`: after the opcode word, and far enough
/// from the end that all four bytes lie inside the instruction.
///
/// `None` when the instruction is too short to hold an absolute-long operand.
const fn operand_range(site: u32, end: u32) -> Option<(u32, u32)> {
    let (Some(first), Some(last)) = (site.checked_add(2), end.checked_sub(4)) else {
        return None;
    };
    if first > last {
        None
    } else {
        Some((first, last))
    }
}

/// What the caller knows about how the analyzed code is addressed.
#[derive(Clone, Debug, Default)]
pub struct FlowOptions {
    /// Rebase for an image copied to a fixed load address and executed there
    /// (see [`Rebase`]). `None` reads an absolute operand as a file offset,
    /// which is correct for a plain, in-place hunk.
    pub rebase: Option<Rebase>,
    /// The analyzed hunk's HUNK relocations, when the caller parsed them.
    /// Without them the stored addend is all the traversal has, and a
    /// cross-hunk call reads as an in-hunk one.
    pub relocations: Option<Relocations>,
}

/// Analyze `code` starting from a single `entry` offset.
#[must_use]
pub fn analyze(code: &[u8], entry: u32) -> ControlFlowAnalysis {
    analyze_entries(code, &[entry])
}

/// Analyze `code` starting from several `entries` (in file-offset space).
#[must_use]
pub fn analyze_entries(code: &[u8], entries: &[u32]) -> ControlFlowAnalysis {
    analyze_entries_with(code, entries, &FlowOptions::default())
}

/// Analyze `code` from `entries` with what the caller knows about addressing.
///
/// With [`FlowOptions::rebase`] set, an absolute-long `JMP`/`JSR` target inside
/// the loaded range is converted to a file offset and traversal continues into
/// it; targets outside the range become unresolved. This lets an image copied
/// to a fixed absolute address and executed there be traced. Without it,
/// absolute targets are taken as file offsets (correct for a plain, in-place
/// hunk).
///
/// With [`FlowOptions::relocations`] set, an absolute-long target whose operand
/// a relocation patches is read through that record rather than through its
/// stored addend: into another hunk it becomes an [`ExternalFlow`] instead of a
/// call edge inside this one.
#[must_use]
pub fn analyze_entries_with(
    code: &[u8],
    entries: &[u32],
    options: &FlowOptions,
) -> ControlFlowAnalysis {
    // One implementation, run with a signal that never fires.
    analyze_entries_cancellable(code, entries, options, &amiga_core::Never).unwrap_or_else(
        |amiga_core::Cancelled| ControlFlowAnalysis {
            instructions: BTreeMap::new(),
            functions: entries.iter().copied().collect(),
            calls: BTreeSet::new(),
            flows: BTreeSet::new(),
            unresolved: BTreeSet::new(),
            library_calls: BTreeSet::new(),
            external: BTreeSet::new(),
            relocations: options.relocations.clone(),
            rebase: options.rebase,
        },
    )
}

/// [`analyze_entries_with`], stopping between queue items when `cancel` fires.
///
/// The traversal's natural checkpoint is the worklist: an item is one address
/// to walk from, and the walk between two items is bounded by the code size.
/// Checking here rather than per instruction keeps the cost invisible while
/// still stopping promptly, because a large executable has many queue items.
///
/// # Errors
/// Returns [`amiga_core::Cancelled`] rather than the partial analysis. A
/// half-traversed control-flow graph would report missing calls and spurious
/// unresolved exits as if they were findings.
pub fn analyze_entries_cancellable(
    code: &[u8],
    entries: &[u32],
    options: &FlowOptions,
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<ControlFlowAnalysis> {
    let analysis = analyze_with_data_tables(code, entries, options, cancel)?;
    let promoted = promotable_tail_targets(&analysis);
    if promoted.is_empty() {
        return Ok(analysis);
    }
    let mut augmented = entries.to_vec();
    augmented.extend(promoted);
    augmented.sort_unstable();
    augmented.dedup();
    analyze_with_data_tables(code, &augmented, options, cancel)
}

/// Rebuild ownership after discovering data tables, then check their guards
/// against the expanded graph. A newly reached branch can bypass a guard that
/// looked exclusive in the first traversal. Refused sites stay refused for
/// this analysis; the bounded loop falls back to explicit unresolved jumps if
/// nested discovery and validation do not settle.
fn analyze_with_data_tables(
    code: &[u8],
    entries: &[u32],
    options: &FlowOptions,
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<ControlFlowAnalysis> {
    let mut tables = BTreeMap::new();
    let mut rejected = BTreeSet::new();
    let mut analysis = analyze_entries_once(code, entries, options, &tables, cancel)?;
    for _ in 0..8 {
        amiga_core::checkpoint!(cancel);
        let candidates: BTreeSet<u32> = analysis
            .unresolved
            .iter()
            .map(|flow| flow.address)
            .filter(|site| !rejected.contains(site))
            .filter(|site| {
                analysis
                    .instructions
                    .get(site)
                    .is_some_and(|decoded| Isa::from(decoded.instruction.opcode) == Isa::Jmp)
            })
            .collect();
        if tables.is_empty() && candidates.is_empty() {
            return Ok(analysis);
        }
        let index = FlowIndex::new(&analysis.flows);
        let mut next = tables.clone();
        for (&site, targets) in &tables {
            amiga_core::checkpoint!(cancel);
            if jump_tables::targets(code, &analysis, &index, site).as_ref() != Some(targets) {
                next.remove(&site);
                rejected.insert(site);
            }
        }
        for site in candidates {
            amiga_core::checkpoint!(cancel);
            if !next.contains_key(&site)
                && let Some(targets) = jump_tables::targets(code, &analysis, &index, site)
            {
                next.insert(site, targets);
            }
        }
        if next == tables {
            return Ok(analysis);
        }
        tables = next;
        analysis = analyze_entries_once(code, entries, options, &tables, cancel)?;
    }
    analyze_entries_once(code, entries, options, &BTreeMap::new(), cancel)
}

fn analyze_entries_once(
    code: &[u8],
    entries: &[u32],
    options: &FlowOptions,
    tables: &BTreeMap<u32, Vec<u32>>,
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<ControlFlowAnalysis> {
    let mut analysis = ControlFlowAnalysis {
        instructions: BTreeMap::new(),
        functions: entries.iter().copied().collect(),
        calls: BTreeSet::new(),
        flows: BTreeSet::new(),
        unresolved: BTreeSet::new(),
        library_calls: BTreeSet::new(),
        external: BTreeSet::new(),
        relocations: options.relocations.clone(),
        rebase: options.rebase,
    };
    let mut queue = entries
        .iter()
        .map(|entry| (*entry, *entry))
        .collect::<VecDeque<_>>();
    let mut visited = BTreeSet::new();
    let mut items = 0_usize;
    while let Some((mut address, owner)) = queue.pop_front() {
        items += 1;
        if items.is_multiple_of(amiga_core::ITEMS_PER_CHECKPOINT) {
            amiga_core::checkpoint!(cancel);
        }
        while valid_address(code, address) {
            if !visited.insert((address, owner)) {
                break;
            }
            // Arriving at an instruction another traversal already decoded adds
            // this owner and keeps walking rather than stopping: an entry owns
            // every instruction it reaches, not just the first one it shares.
            // Stopping here would leave the rest of a shared block — and the
            // calls, edges, and unresolved exits in it — attributed to the
            // traversal that happened to decode it first. `visited` bounds the
            // re-walk to one pass per (instruction, owner), and
            // `MAX_INSTRUCTION_OWNERS` bounds it again for code every entry
            // falls into — visibly, through `owner_total`.
            let known = analysis.instructions.get_mut(&address).map(|existing| {
                let may_continue = existing.add_owner(owner);
                (
                    existing.end,
                    existing.instruction.opcode,
                    existing.instruction.operands,
                    may_continue,
                )
            });
            let (end, opcode, operands) = match known {
                Some((_, _, _, false)) => break,
                Some((end, opcode, operands, true)) => (end, opcode, operands),
                None => {
                    let Some(decoded) = decode(code, address, owner) else {
                        analysis
                            .unresolved
                            .insert(UnresolvedFlow { owner, address });
                        break;
                    };
                    let known = (
                        decoded.end,
                        decoded.instruction.opcode,
                        decoded.instruction.operands,
                    );
                    analysis.instructions.insert(address, decoded);
                    known
                }
            };

            let isa = Isa::from(opcode);
            // A word the decoder cannot name is almost always data walked into,
            // and nothing downstream can say what it does to memory or to a
            // register. Following it would report the bytes after it as code on
            // the strength of an instruction length nobody decoded. Stop, and
            // say so — the walk's tolerated gaps are visible in `unresolved`.
            let opaque_fallthrough = analysis
                .instructions
                .get(&address)
                .is_some_and(DecodedInstruction::is_opaque_fallthrough);
            if isa == Isa::Unknown && !opaque_fallthrough {
                analysis
                    .unresolved
                    .insert(UnresolvedFlow { owner, address });
                break;
            }
            if is_return(isa) {
                break;
            }
            if matches!(isa, Isa::Bra | Isa::Bsr | Isa::Bcc) {
                let (Operands::Displacement(displacement)
                | Operands::ConditionDisplacement(_, displacement)) = operands
                else {
                    analysis
                        .unresolved
                        .insert(UnresolvedFlow { owner, address });
                    break;
                };
                let target = relative_target(address, displacement);
                if isa == Isa::Bsr {
                    add_call(&mut analysis, &mut queue, owner, address, target);
                    add_flow(&mut analysis, owner, address, end, FlowKind::Fallthrough);
                    address = end;
                    continue;
                }
                add_flow(&mut analysis, owner, address, target, FlowKind::Branch);
                enqueue_valid(code, &mut queue, target, owner);
                if isa == Isa::Bra {
                    break;
                }
                add_flow(&mut analysis, owner, address, end, FlowKind::Fallthrough);
                address = end;
                continue;
            }
            if isa == Isa::Dbcc {
                if let Operands::ConditionRegisterDisplacement(_, _, displacement) = operands {
                    let target = relative_target(address, displacement);
                    add_flow(&mut analysis, owner, address, target, FlowKind::Branch);
                    enqueue_valid(code, &mut queue, target, owner);
                } else {
                    analysis
                        .unresolved
                        .insert(UnresolvedFlow { owner, address });
                }
                add_flow(&mut analysis, owner, address, end, FlowKind::Fallthrough);
                address = end;
                continue;
            }
            if isa == Isa::Jsr {
                if let Operands::EffectiveAddress(mode) = operands {
                    match resolve_direct(code, options, mode, address, end) {
                        DirectTarget::Offset(target) => {
                            add_call(&mut analysis, &mut queue, owner, address, target);
                        }
                        DirectTarget::Table(targets) => {
                            for target in targets {
                                add_call(&mut analysis, &mut queue, owner, address, target);
                            }
                        }
                        DirectTarget::External(relocation) => {
                            analysis.external.insert(external_flow(
                                address,
                                ExternalKind::Call,
                                relocation,
                            ));
                        }
                        DirectTarget::LibraryCall => {
                            analysis.library_calls.insert(address);
                        }
                        DirectTarget::Unresolved => {
                            analysis
                                .unresolved
                                .insert(UnresolvedFlow { owner, address });
                        }
                    }
                }
                add_flow(&mut analysis, owner, address, end, FlowKind::Fallthrough);
                address = end;
                continue;
            }
            if isa == Isa::Jmp {
                if let Operands::EffectiveAddress(mode) = operands {
                    match tables.get(&address).map_or_else(
                        || {
                            if jump_tables::loads_target(&analysis, address) {
                                DirectTarget::Unresolved
                            } else {
                                resolve_direct(code, options, mode, address, end)
                            }
                        },
                        |targets| DirectTarget::Table(targets.clone()),
                    ) {
                        DirectTarget::Offset(target) => {
                            add_flow(&mut analysis, owner, address, target, FlowKind::Branch);
                            enqueue_valid(code, &mut queue, target, owner);
                        }
                        DirectTarget::Table(targets) => {
                            for target in targets {
                                add_flow(&mut analysis, owner, address, target, FlowKind::Branch);
                                enqueue_valid(code, &mut queue, target, owner);
                            }
                        }
                        DirectTarget::External(relocation) => {
                            analysis.external.insert(external_flow(
                                address,
                                ExternalKind::Jump,
                                relocation,
                            ));
                        }
                        DirectTarget::LibraryCall => {
                            analysis.library_calls.insert(address);
                        }
                        DirectTarget::Unresolved => {
                            analysis
                                .unresolved
                                .insert(UnresolvedFlow { owner, address });
                        }
                    }
                }
                break;
            }
            add_flow(&mut analysis, owner, address, end, FlowKind::Fallthrough);
            address = end;
        }
    }
    Ok(analysis)
}

/// Promote only a direct forward `JMP` whose target has independent routine
/// boundary evidence. The first traversal deliberately treats every jump as a
/// branch; promoted entries cause one clean second traversal so ownership is
/// recomputed rather than patched after the fact.
fn promotable_tail_targets(analysis: &ControlFlowAnalysis) -> BTreeSet<u32> {
    let candidates: Vec<FlowEdge> = analysis
        .flows
        .iter()
        .filter(|flow| {
            flow.kind == FlowKind::Branch
                && flow.target > flow.site
                && !analysis.functions.contains(&flow.target)
                && direct_jump_at(analysis, flow.site)
                && routine_entry_evidence(analysis, flow.target)
        })
        .copied()
        .collect();
    if candidates.is_empty() {
        return BTreeSet::new();
    }
    let flow_index = FlowIndex::new(&analysis.flows);
    candidates
        .into_iter()
        .filter(|flow| {
            unique_unshared_incoming_jump(analysis, &flow_index, flow.site, flow.target)
                && reaches_ordinary_return(analysis, &flow_index, flow.owner, flow.target)
        })
        .map(|flow| flow.target)
        .collect()
}

struct FlowIndex {
    by_site: BTreeMap<u32, Vec<FlowEdge>>,
    by_target: BTreeMap<u32, Vec<FlowEdge>>,
}

impl FlowIndex {
    fn new(flows: &BTreeSet<FlowEdge>) -> Self {
        let mut index = Self {
            by_site: BTreeMap::new(),
            by_target: BTreeMap::new(),
        };
        for flow in flows {
            index.by_site.entry(flow.site).or_default().push(*flow);
            index.by_target.entry(flow.target).or_default().push(*flow);
        }
        index
    }
}

fn reaches_ordinary_return(
    analysis: &ControlFlowAnalysis,
    flow_index: &FlowIndex,
    owner: u32,
    target: u32,
) -> bool {
    let mut queue = VecDeque::from([target]);
    let mut visited = BTreeSet::new();
    while let Some(address) = queue.pop_front() {
        if !visited.insert(address) {
            continue;
        }
        let Some(instruction) = analysis.instructions.get(&address) else {
            continue;
        };
        if is_return(Isa::from(instruction.instruction.opcode)) {
            return true;
        }
        for flow in flow_index
            .by_site
            .get(&address)
            .into_iter()
            .flatten()
            .filter(|flow| flow.owner == owner)
            .filter(|flow| flow.kind != FlowKind::Call)
        {
            if flow.target == target || !analysis.functions.contains(&flow.target) {
                queue.push_back(flow.target);
            }
        }
    }
    false
}

fn direct_jump_at(analysis: &ControlFlowAnalysis, site: u32) -> bool {
    analysis.instructions.get(&site).is_some_and(|decoded| {
        Isa::from(decoded.instruction.opcode) == Isa::Jmp
            && matches!(
                decoded.instruction.operands,
                Operands::EffectiveAddress(AddressingMode::AbsLong(_) | AddressingMode::Pciwd(..))
            )
    })
}

fn unique_unshared_incoming_jump(
    analysis: &ControlFlowAnalysis,
    flow_index: &FlowIndex,
    site: u32,
    target: u32,
) -> bool {
    let Some(source) = analysis.instructions.get(&site) else {
        return false;
    };
    if source.owner_total != 1 || source.owners.len() != 1 {
        return false;
    }
    flow_index
        .by_target
        .get(&target)
        .is_some_and(|flows| flows.iter().all(|flow| flow.site == site))
}

fn routine_entry_evidence(analysis: &ControlFlowAnalysis, target: u32) -> bool {
    let Some(first) = analysis.instructions.get(&target) else {
        return false;
    };
    let isa = Isa::from(first.instruction.opcode);
    let prologue = match first.instruction.operands {
        Operands::RegisterDisplacement(_, _) => isa == Isa::Link,
        Operands::DirectionSizeEffectiveAddressList(
            Direction::RegisterToMemory,
            _,
            AddressingMode::Ariwpr(7),
            _,
        ) => true,
        Operands::SizeEffectiveAddressEffectiveAddress(
            Size::Long,
            AddressingMode::Ariwpr(7),
            AddressingMode::Drd(_) | AddressingMode::Ard(_),
        ) => true,
        Operands::RegisterSizeEffectiveAddress(7, _, AddressingMode::Immediate(_)) => {
            isa == Isa::Suba
        }
        Operands::DataSizeEffectiveAddress(_, _, AddressingMode::Ard(7)) => isa == Isa::Subq,
        Operands::RegisterEffectiveAddress(7, AddressingMode::Ariwd(7, displacement)) => {
            isa == Isa::Lea && displacement < 0
        }
        _ => false,
    };
    prologue
        || analysis
            .instructions
            .range(..target)
            .next_back()
            .is_some_and(|(_, previous)| {
                previous.end == target && is_return(Isa::from(previous.instruction.opcode))
            })
}

fn decode(code: &[u8], address: u32, owner: u32) -> Option<DecodedInstruction> {
    let start = usize::try_from(address).ok()?;
    let padded;
    let mut memory = if code.len().saturating_sub(start) < 10 {
        padded = {
            let mut bytes = code.to_vec();
            bytes.resize(code.len().checked_add(10)?, 0);
            bytes
        };
        padded.as_slice()
    } else {
        code
    };
    let mut words = memory.iter_u16(address);
    let instruction = Instruction::from_memory(&mut words).ok()?;
    let decoded_end = if is_movec(instruction.opcode) {
        address.checked_add(4)?
    } else {
        words.next_addr
    };
    let end = usize::try_from(decoded_end).ok()?;
    let encoded = code.get(start..end)?.to_vec();
    Some(DecodedInstruction {
        address,
        end: decoded_end,
        instruction,
        encoded,
        owners: BTreeSet::from([owner]),
        owner_total: 1,
    })
}

const fn is_movec(opcode: u16) -> bool {
    matches!(opcode, 0x4e7a | 0x4e7b)
}

pub(crate) fn opaque_fallthrough_text(opcode: u16, encoded: &[u8]) -> Option<String> {
    let (address, register, control) = movec_fields(opcode, encoded)?;
    let general = if address { 'A' } else { 'D' };
    Some(if opcode == 0x4e7a {
        format!("MOVEC {control},{general}{register}")
    } else {
        format!("MOVEC {general}{register},{control}")
    })
}

fn movec_fields(opcode: u16, encoded: &[u8]) -> Option<(bool, u8, &'static str)> {
    if !is_movec(opcode) || encoded.len() != 4 {
        return None;
    }
    let extension = u16::from_be_bytes([encoded[2], encoded[3]]);
    let control = match extension & 0x0fff {
        0x000 => "SFC",
        0x001 => "DFC",
        0x002 => "CACR",
        0x800 => "USP",
        0x801 => "VBR",
        0x802 => "CAAR",
        0x803 => "MSP",
        0x804 => "ISP",
        _ => return None,
    };
    Some((
        extension & 0x8000 != 0,
        ((extension >> 12) & 7) as u8,
        control,
    ))
}

fn add_call(
    analysis: &mut ControlFlowAnalysis,
    queue: &mut VecDeque<(u32, u32)>,
    caller: u32,
    call_site: u32,
    callee: u32,
) {
    analysis.functions.insert(callee);
    analysis.calls.insert(CallEdge {
        caller,
        call_site,
        callee,
    });
    add_flow(analysis, caller, call_site, callee, FlowKind::Call);
    queue.push_back((callee, callee));
}

const fn external_flow(site: u32, kind: ExternalKind, relocation: Relocation) -> ExternalFlow {
    ExternalFlow {
        site,
        kind,
        relocation: relocation.patched,
        target_hunk: relocation.target_hunk,
        target_offset: relocation.target_offset,
    }
}

fn add_flow(
    analysis: &mut ControlFlowAnalysis,
    owner: u32,
    site: u32,
    target: u32,
    kind: FlowKind,
) {
    analysis.flows.insert(FlowEdge {
        owner,
        site,
        target,
        kind,
    });
}

fn enqueue_valid(code: &[u8], queue: &mut VecDeque<(u32, u32)>, address: u32, owner: u32) {
    if valid_address(code, address) {
        queue.push_back((address, owner));
    }
}

fn valid_address(code: &[u8], address: u32) -> bool {
    address.is_multiple_of(2) && usize::try_from(address).is_ok_and(|value| value < code.len())
}

fn relative_target(address: u32, displacement: i16) -> u32 {
    address
        .wrapping_add(2)
        .wrapping_add_signed(i32::from(displacement))
}

/// What a direct `JSR`/`JMP` operand resolves to.
enum DirectTarget {
    /// A hunk offset this traversal can continue into.
    Offset(u32),
    /// Several offsets, from an instruction or data dispatch table.
    Table(Vec<u32>),
    /// Another hunk, proved by the relocation patching the operand.
    External(Relocation),
    /// The AmigaOS library-call convention explains the target.
    LibraryCall,
    /// Nothing static explains the target.
    Unresolved,
}

/// Resolve the operand of a direct `JSR`/`JMP` spanning `site..end`.
///
/// A relocation patching the operand outranks every other reading: it is the
/// only evidence that says which hunk the stored longword belongs to. Into the
/// analyzed hunk the record's offset *is* the target, so no address arithmetic
/// applies; into another hunk the target is external.
///
/// A record naming an offset that is not a traversable address of this hunk —
/// past its end or odd — describes no reachable code, so it becomes an
/// unresolved-flow warning rather than an invented entry point.
fn resolve_direct(
    code: &[u8],
    options: &FlowOptions,
    mode: AddressingMode,
    site: u32,
    end: u32,
) -> DirectTarget {
    if let (AddressingMode::AbsLong(addend), Some(relocations)) = (mode, &options.relocations)
        && let Some(relocation) = site
            .checked_add(2)
            .filter(|patched| patched.checked_add(4).is_some_and(|after| after <= end))
            .and_then(|patched| relocations.at(patched, addend))
    {
        return if relocation.target_hunk != relocations.hunk() {
            DirectTarget::External(relocation)
        } else if valid_address(code, relocation.target_offset) {
            DirectTarget::Offset(relocation.target_offset)
        } else {
            DirectTarget::Unresolved
        };
    }
    if let Some(target) = direct_address(mode, options.rebase, code.len()) {
        DirectTarget::Offset(target)
    } else if let Some(targets) = branch_jump_table_targets(code, mode) {
        DirectTarget::Table(targets)
    } else if crate::lvo::is_library_call_mode(mode) {
        DirectTarget::LibraryCall
    } else {
        DirectTarget::Unresolved
    }
}

fn direct_address(mode: AddressingMode, rebase: Option<Rebase>, len: usize) -> Option<u32> {
    match mode {
        AddressingMode::AbsLong(address) => match rebase {
            Some(rebase) => rebase.to_offset(address, len),
            None => Some(address),
        },
        AddressingMode::Pciwd(pc, displacement) => {
            Some(pc.wrapping_add_signed(i32::from(displacement)))
        }
        _ => None,
    }
}

fn branch_jump_table_targets(code: &[u8], mode: AddressingMode) -> Option<Vec<u32>> {
    let AddressingMode::Pciwi8(pc, extension) = mode else {
        return None;
    };
    let table = pc.wrapping_add_signed(i32::from(extension.disp()));
    let base = usize::try_from(table).ok()?;
    // The `0x6000` here is a whole-word `BRA.W` compare over *undecoded* bytes,
    // not a classification mask: `Isa::from` would also accept `BRA.S`, whose
    // entries are two bytes wide and would misread the table's stride.
    let mut cursor = (0..=32)
        .step_by(2)
        .filter_map(|offset| base.checked_add(offset))
        .find(|cursor| {
            code.get(*cursor..cursor.saturating_add(2))
                .is_some_and(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) == 0x6000)
        })?;
    let mut targets = Vec::new();
    while targets.len() < 256 {
        let entry = code.get(cursor..cursor.checked_add(4)?)?;
        if u16::from_be_bytes([entry[0], entry[1]]) != 0x6000 {
            break;
        }
        let displacement = i16::from_be_bytes([entry[2], entry[3]]);
        let address = u32::try_from(cursor).ok()?;
        targets.push(relative_target(address, displacement));
        cursor += 4;
    }
    (!targets.is_empty()).then_some(targets)
}

pub(crate) fn is_return(isa: Isa) -> bool {
    matches!(isa, Isa::Rte | Isa::Rts | Isa::Rtr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_calls_branches_and_fallthrough() {
        let code = [
            0x61, 0x00, 0x00, 0x04, 0x4e, 0x75, 0x60, 0x02, 0x4e, 0x71, 0x4e, 0x75, 0, 0, 0, 0,
        ];
        let analysis = analyze(&code, 0);
        assert!(analysis.functions.contains(&0));
        assert!(analysis.functions.contains(&6));
        assert!(analysis.instructions.contains_key(&4));
        assert!(analysis.instructions.contains_key(&6));
        assert!(analysis.instructions.contains_key(&10));
        assert_eq!(analysis.calls.len(), 1);
        assert!(analysis.flows.contains(&FlowEdge {
            owner: 0,
            site: 0,
            target: 6,
            kind: FlowKind::Call,
        }));
        assert!(analysis.flows.contains(&FlowEdge {
            owner: 0,
            site: 0,
            target: 4,
            kind: FlowKind::Fallthrough,
        }));
    }

    #[test]
    fn an_undecodable_word_stops_the_walk_and_is_reported() {
        // NOP ; $4EC0 (a JMP encoding with an invalid mode — no such
        // instruction) ; RTS. The walk must stop at the bad word rather than
        // decode the bytes after it as code on an unknown instruction length.
        let code = [0x4e, 0x71, 0x4e, 0xc0, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        assert_eq!(Isa::from(0x4ec0_u16), Isa::Unknown);
        assert!(analysis.instructions.contains_key(&0));
        assert!(
            analysis.unresolved.contains(&UnresolvedFlow {
                owner: 0,
                address: 2
            }),
            "the undecodable word must be reported, not silently skipped"
        );
        assert!(
            !analysis.instructions.contains_key(&4),
            "nothing after an undecodable word is code this walk established"
        );
    }

    #[test]
    fn movec_has_its_extension_word_and_falls_through() {
        // MOVEC VBR,D0 ; RTS. MOVEC starts with an opcode the pinned MC68000
        // decoder cannot name, but Motorola defines it as a four-byte,
        // straight-line MC68010+ instruction.
        let code = [0x4e, 0x7a, 0x08, 0x01, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let movec = analysis.instructions.get(&0).expect("MOVEC decoded");
        assert_eq!(movec.end, 4);
        assert_eq!(movec.encoded, code[..4]);
        assert_eq!(movec.text(), "MOVEC VBR,D0");
        assert!(analysis.instructions.contains_key(&4));
        assert!(analysis.unresolved.is_empty());
    }

    #[test]
    fn movec_with_an_undefined_control_register_still_stops() {
        let code = [0x4e, 0x7a, 0x00, 0x03, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.contains(&UnresolvedFlow {
            owner: 0,
            address: 0,
        }));
        assert!(!analysis.instructions.contains_key(&4));
    }

    #[test]
    fn analyzes_multiple_external_entry_points() {
        let code = [0x4e, 0x75, 0x4e, 0x71, 0x4e, 0x75, 0x4e, 0x71];
        let analysis = analyze_entries(&code, &[0, 4]);
        assert_eq!(analysis.functions, BTreeSet::from([0, 4]));
        assert!(analysis.instructions.contains_key(&0));
        assert!(analysis.instructions.contains_key(&4));
        assert!(!analysis.instructions.contains_key(&2));
    }

    /// Two entries joining at 0x08: entry 0 branches there, entry 4 falls into
    /// it. The shared block runs NOP, BSR, JMP (A0).
    fn joined_entries() -> [u8; 16] {
        [
            0x60, 0x00, 0x00, 0x06, // 0x00 entry A: BRA.W 0x08
            0x4e, 0x71, // 0x04 entry B: NOP
            0x4e, 0x71, // 0x06 NOP
            0x4e, 0x71, // 0x08 shared: NOP
            0x61, 0x02, // 0x0a BSR.S 0x0e
            0x4e, 0xd0, // 0x0c JMP (A0) (unresolved)
            0x4e, 0x75, // 0x0e sub: RTS
        ]
    }

    #[test]
    fn ownership_reaches_the_whole_shared_block_not_just_its_first_instruction() {
        // Entry 4's traversal decodes the shared block first. Entry 0 arrives
        // at 0x08 afterwards and must own the rest of the block too, or every
        // consumer of ownership — callees, per-function summaries, join
        // checks — attributes shared code to whichever entry happened to run
        // first.
        let analysis = analyze_entries(&joined_entries(), &[0, 4]);
        let both = BTreeSet::from([0, 4]);
        for address in [0x08, 0x0a, 0x0c] {
            assert_eq!(
                analysis.instructions[&address].owners, both,
                "instruction {address:#x} of the shared block"
            );
        }
        // Instructions before the join stay owned by the entry that reaches
        // them: propagation must not make ownership universal.
        assert_eq!(
            analysis.instructions[&0x00].owners,
            BTreeSet::from([0]),
            "entry A's own instruction"
        );
        assert_eq!(
            analysis.instructions[&0x06].owners,
            BTreeSet::from([4]),
            "entry B's own instruction"
        );
        // Nothing was refused, so the count matches the set exactly.
        for address in [0x00, 0x06, 0x08, 0x0a, 0x0c] {
            let decoded = &analysis.instructions[&address];
            assert_eq!(decoded.owner_total, decoded.owners.len());
        }
    }

    #[test]
    fn ownership_propagation_stops_at_the_cap_and_says_so() {
        // Every entry is a `BRA.W` into one shared tail, so the tail would
        // otherwise be walked once per entry. The cap bounds that, and
        // `owner_total` keeps the truncation visible instead of silent.
        let count = MAX_INSTRUCTION_OWNERS + 5;
        let tail = u32::try_from(4 * count).unwrap_or_else(|error| panic!("{error}"));
        let mut code = Vec::new();
        for index in 0..count {
            let site = u32::try_from(4 * index).unwrap_or_else(|error| panic!("{error}"));
            let displacement = i16::try_from(i64::from(tail) - i64::from(site) - 2)
                .unwrap_or_else(|error| panic!("{error}"));
            code.extend_from_slice(&[0x60, 0x00]);
            code.extend_from_slice(&displacement.to_be_bytes());
        }
        code.extend_from_slice(&[0x4e, 0x71, 0x4e, 0x75]); // NOP ; RTS
        let entries: Vec<u32> = (0..count)
            .map(|index| u32::try_from(4 * index).unwrap_or_else(|error| panic!("{error}")))
            .collect();

        let analysis = analyze_entries(&code, &entries);

        let head = &analysis.instructions[&tail];
        assert_eq!(head.owners.len(), MAX_INSTRUCTION_OWNERS);
        assert_eq!(head.owner_total, count, "refused owners are still counted");
        // The listed owners are the lowest entries, in offset order.
        assert_eq!(
            head.owners.iter().copied().collect::<Vec<u32>>(),
            entries[..MAX_INSTRUCTION_OWNERS]
        );
        // A refused owner stops walking, so it never reaches the RTS either.
        let rts = &analysis.instructions[&(tail + 2)];
        assert_eq!(rts.owners.len(), MAX_INSTRUCTION_OWNERS);
        assert!(
            rts.owner_total <= count,
            "beyond the cap the count is a lower bound, never an overcount"
        );
    }

    #[test]
    fn every_owner_of_a_shared_block_records_its_calls_and_unresolved_exits() {
        let analysis = analyze_entries(&joined_entries(), &[0, 4]);
        // The call in the shared block belongs to both entries.
        assert_eq!(
            analysis
                .calls
                .iter()
                .filter(|call| call.call_site == 0x0a)
                .map(|call| call.caller)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 4])
        );
        // So does the unresolved exit that ends it.
        assert_eq!(
            analysis
                .unresolved
                .iter()
                .filter(|flow| flow.address == 0x0c)
                .map(|flow| flow.owner)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 4])
        );
        // One call and one unresolved site all the same: the statistics count
        // distinct sites, not one per owner.
        let coverage = crate::listing::coverage(&analysis, joined_entries().len());
        assert_eq!(coverage.calls, 1);
        assert_eq!(coverage.unresolved, 1);
    }

    #[test]
    fn recovers_pc_indexed_branch_tables() {
        let code = [
            0x4e, 0xfb, 0x00, 0x02, 0x60, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x06, 0x4e, 0x71,
            0x4e, 0x75, 0x4e, 0x75, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let analysis = analyze(&code, 0);
        assert!(analysis.instructions.contains_key(&12));
        assert!(analysis.instructions.contains_key(&16));
        assert!(analysis.unresolved.is_empty());
        assert_eq!(analysis.functions, BTreeSet::from([0]));
    }

    #[test]
    fn promotes_a_forward_direct_jump_to_an_unseeded_prologue() {
        // JMP $8.L ; NOP ; target: MOVEM.L D0,-(A7) ;
        // MOVEM.L (A7)+,D0 ; RTS
        let code = [
            0x4e, 0xf9, 0, 0, 0, 8, 0x4e, 0x71, 0x48, 0xe7, 0x80, 0x00, 0x4c, 0xdf, 0x00, 0x01,
            0x4e, 0x75,
        ];
        let analysis = analyze(&code, 0);
        assert_eq!(analysis.functions, BTreeSet::from([0, 8]));
        assert_eq!(analysis.instructions[&8].owners, BTreeSet::from([0, 8]));
        assert!(analysis.flows.contains(&FlowEdge {
            owner: 0,
            site: 0,
            target: 8,
            kind: FlowKind::Branch,
        }));
    }

    #[test]
    fn a_shared_epilogue_is_not_promoted_to_a_function() {
        // BEQ target ; JMP target ; NOP ; NOP ; target: RTS. Two distinct
        // incoming transfers make this a shared block, not an inferred entry.
        let code = [
            0x67, 0x0a, 0x4e, 0xf9, 0, 0, 0, 12, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x75,
        ];
        let analysis = analyze(&code, 0);
        assert_eq!(analysis.functions, BTreeSet::from([0]));
        assert_eq!(analysis.instructions[&12].owners, BTreeSet::from([0]));
    }

    #[test]
    fn a_backward_direct_jump_stays_an_intrafunction_branch() {
        // target: MOVEM.L D0,-(A7) ; MOVEM.L (A7)+,D0 ; RTS ; JMP target.
        let code = [
            0x48, 0xe7, 0x80, 0x00, 0x4c, 0xdf, 0x00, 0x01, 0x4e, 0x75, 0x4e, 0xf9, 0, 0, 0, 0,
        ];
        let analysis = analyze(&code, 10);
        assert_eq!(analysis.functions, BTreeSet::from([10]));
    }

    #[test]
    fn a_frameless_forward_jump_without_boundary_evidence_stays_ambiguous() {
        // JMP $8.L ; NOP ; target: MOVEQ #1,D0 ; RTS. The target may be an
        // ordinary block, so a return reachable from it is not enough.
        let code = [0x4e, 0xf9, 0, 0, 0, 8, 0x4e, 0x71, 0x70, 0x01, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        assert_eq!(analysis.functions, BTreeSet::from([0]));
    }

    #[test]
    fn recovers_pc_indexed_call_tables() {
        let code = [
            0x4e, 0xbb, 0x00, 0x02, 0x4e, 0x75, 0x60, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x06,
            0x4e, 0x71, 0x4e, 0x75, 0x4e, 0x75, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let analysis = analyze(&code, 0);
        assert!(analysis.functions.contains(&14));
        assert!(analysis.functions.contains(&18));
        assert_eq!(analysis.calls.len(), 2);
    }

    #[test]
    fn classifies_lvo_form_jumps_as_library_calls_not_unresolved() {
        // JSR (-552,A6) ; JMP (A0) — the LVO call is convention-explained,
        // the register-indirect jump stays a real unresolved warning.
        let code = [0x4e, 0xae, 0xfd, 0xd8, 0x4e, 0xd0];
        let analysis = analyze(&code, 0);
        assert_eq!(analysis.library_calls, BTreeSet::from([0]));
        assert_eq!(analysis.unresolved.len(), 1);
        assert!(
            analysis
                .unresolved
                .iter()
                .all(|unresolved| unresolved.address == 4)
        );
        // A library-form tail jump is classified the same way.
        let tail = [0x4e, 0xee, 0xff, 0xe2]; // JMP (-30,A6)
        let analysis = analyze(&tail, 0);
        assert_eq!(analysis.library_calls, BTreeSet::from([0]));
        assert!(analysis.unresolved.is_empty());
    }

    #[test]
    fn negative_displacement_off_non_a6_registers_stays_unresolved() {
        // The ABI puts the library base in A6; a negative displacement off the
        // stack pointer or a small-data base is a computed jump, not a
        // convention-explained call.
        for code in [
            [0x4e, 0xaf, 0xff, 0xf8], // JSR (-8,A7)
            [0x4e, 0xad, 0xff, 0xfc], // JSR (-4,A5)
        ] {
            let analysis = analyze(&code, 0);
            assert!(analysis.library_calls.is_empty());
            assert_eq!(analysis.unresolved.len(), 1);
        }
    }

    #[test]
    fn rebase_follows_an_absolute_target_into_the_hunk() {
        // JSR $00001008 ; RTS ; RTS, with the hunk loaded at absolute $1000.
        let code = [0x4e, 0xb9, 0x00, 0x00, 0x10, 0x08, 0x4e, 0x75, 0x4e, 0x75];
        // Without a rebase the absolute target is an out-of-range "offset".
        assert!(!analyze(&code, 0).instructions.contains_key(&8));
        // With a rebase, $1008 maps to offset 8 and traversal reaches it.
        let options = FlowOptions {
            rebase: Some(Rebase::new(0x1000)),
            ..Default::default()
        };
        let rebased = analyze_entries_with(&code, &[0], &options);
        assert!(rebased.instructions.contains_key(&8));
        assert!(rebased.functions.contains(&8));
    }

    /// `JSR $0.L ; RTS ; RTS`, whose absolute operand sits at offset 2.
    fn cross_hunk_call() -> [u8; 10] {
        [0x4e, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x75, 0x4e, 0x75]
    }

    #[test]
    fn a_relocated_call_into_another_hunk_is_external_not_an_in_hunk_edge() {
        let code = cross_hunk_call();
        // Without the relocations the stored addend reads as "offset zero of
        // this hunk", which is exactly the misreading this option fixes.
        let blind = analyze(&code, 0);
        assert!(blind.calls.iter().any(|call| call.callee == 0));
        assert!(blind.external.is_empty());

        let options = FlowOptions {
            relocations: Some(Relocations::new(
                0,
                [Relocation {
                    patched: 2,
                    target_hunk: 1,
                    target_offset: 0,
                }],
            )),
            ..Default::default()
        };
        let analysis = analyze_entries_with(&code, &[0], &options);
        // No invented call edge, no invented function, no bogus caller list.
        assert!(analysis.calls.is_empty());
        assert_eq!(analysis.functions, BTreeSet::from([0]));
        assert!(
            !analysis
                .flows
                .iter()
                .any(|flow| flow.kind == FlowKind::Call)
        );
        // The transfer is resolved, just not here.
        assert_eq!(
            analysis.external,
            BTreeSet::from([ExternalFlow {
                site: 0,
                kind: ExternalKind::Call,
                relocation: 2,
                target_hunk: 1,
                target_offset: 0,
            }])
        );
        // It is not a warning either: the record says where it goes.
        assert!(analysis.unresolved.is_empty());
        // Execution still continues after the call.
        assert!(analysis.instructions.contains_key(&6));
    }

    #[test]
    fn a_relocated_jump_into_another_hunk_is_an_external_tail_transfer() {
        // JMP $0.L, relocated into hunk 1.
        let code = [0x4e, 0xf9, 0x00, 0x00, 0x00, 0x00];
        let options = FlowOptions {
            relocations: Some(Relocations::new(
                0,
                [Relocation {
                    patched: 2,
                    target_hunk: 1,
                    target_offset: 0,
                }],
            )),
            ..Default::default()
        };
        let analysis = analyze_entries_with(&code, &[0], &options);
        assert!(analysis.unresolved.is_empty());
        assert_eq!(
            analysis
                .external
                .iter()
                .map(|external| external.kind)
                .collect::<Vec<_>>(),
            vec![ExternalKind::Jump]
        );
    }

    #[test]
    fn a_relocation_inside_the_analyzed_hunk_is_still_followed() {
        // JSR $8.L relocated within hunk 0: the addend is the target offset,
        // so traversal continues into it exactly as before.
        let code = [
            0x4e, 0xb9, 0x00, 0x00, 0x00, 0x08, 0x4e, 0x75, 0x4e, 0x71, 0x4e, 0x75,
        ];
        let options = FlowOptions {
            relocations: Some(Relocations::new(
                0,
                [Relocation {
                    patched: 2,
                    target_hunk: 0,
                    target_offset: 8,
                }],
            )),
            ..Default::default()
        };
        let analysis = analyze_entries_with(&code, &[0], &options);
        assert!(analysis.external.is_empty());
        assert!(analysis.functions.contains(&8));
        assert!(analysis.instructions.contains_key(&8));
    }

    #[test]
    fn a_relocation_naming_an_offset_outside_the_hunk_warns_instead_of_inventing_an_entry() {
        // JSR $FFFF0000.L relocated within hunk 0: the record names an offset
        // this hunk does not contain, so there is no code to call there.
        let code = [0x4e, 0xb9, 0xff, 0xff, 0x00, 0x00, 0x4e, 0x75];
        let options = FlowOptions {
            relocations: Some(Relocations::new(
                0,
                [Relocation {
                    patched: 2,
                    target_hunk: 0,
                    target_offset: 0xffff_0000,
                }],
            )),
            ..Default::default()
        };
        let analysis = analyze_entries_with(&code, &[0], &options);
        // No invented function entry and no call edge outside the hunk.
        assert_eq!(analysis.functions, BTreeSet::from([0]));
        assert!(analysis.calls.is_empty());
        assert!(analysis.external.is_empty());
        // Tolerated corruption is reported, not silently dropped.
        assert_eq!(
            analysis.unresolved,
            BTreeSet::from([UnresolvedFlow {
                owner: 0,
                address: 0
            }])
        );
    }

    #[test]
    fn an_unrelocated_operand_keeps_its_plain_reading() {
        // The same encoding with the relocation naming a different addend must
        // not be attributed to this operand.
        let code = cross_hunk_call();
        let options = FlowOptions {
            relocations: Some(Relocations::new(
                0,
                [Relocation {
                    patched: 2,
                    target_hunk: 1,
                    target_offset: 0x20,
                }],
            )),
            ..Default::default()
        };
        let analysis = analyze_entries_with(&code, &[0], &options);
        assert!(analysis.external.is_empty());
        assert!(analysis.calls.iter().any(|call| call.callee == 0));
    }

    #[test]
    fn a_relocation_outside_the_operand_bytes_is_not_attributed_to_it() {
        // A record patching the longword that *starts* at the last two bytes
        // of the instruction does not fit inside it and must be ignored.
        let code = cross_hunk_call();
        let options = FlowOptions {
            relocations: Some(Relocations::new(
                0,
                [Relocation {
                    patched: 4,
                    target_hunk: 1,
                    target_offset: 0,
                }],
            )),
            ..Default::default()
        };
        let analysis = analyze_entries_with(&code, &[0], &options);
        assert!(analysis.external.is_empty());
    }

    #[test]
    fn external_kind_labels_match_the_serde_names() {
        for kind in [ExternalKind::Call, ExternalKind::Jump] {
            let json = serde_json::to_value(kind).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json.as_str(), Some(kind.label()));
        }
    }
}
