//! Exact register values at each instruction, propagated through control flow.
//!
//! This exists to fill in library-call arguments. An fd table says
//! `AllocMem(byteSize=D0, requirements=D1)`; that names the registers but not
//! what a given call passes in them, which is the part a reader actually wants.
//! The analysis is the first deliberately small Stage 5A abstract domain: it
//! knows *unknown*, an exact 32-bit value, and a symbolic 32-bit memory read.
//! It follows whole-register immediates, `MOVE.L` register copies and bounded
//! additive transformations, PC-relative address formation, and a small set of
//! exact 32-bit arithmetic through a bounded forward worklist.
//!
//! ## Conservative control-flow joins
//!
//! Each function owner is analyzed separately over a shared internal
//! basic-block engine. Two incoming paths retain a value only when both hold
//! the same exact number or the same symbolic expression. A path with no value,
//! two different values, a call, an unknown write, a function boundary, or
//! unresolved control flow produces an explicit [`Unresolved`] reason rather
//! than a guess.
//!
//! The worklist is deterministic and bounded. A pathological graph that cannot
//! converge within its budget loses every result for that owner with
//! [`Unresolved::StepLimit`]; it never exposes a partial fixpoint.
//!
//! Every retained value has a bounded chain of the instructions that
//! established, copied, or transformed it. The chain is evidence for the
//! report, not merely an implementation detail.
//!
//! ## Relocated operands are not the numbers they encode
//!
//! An unloaded HUNK file stores an *addend* in every longword a relocation
//! patches, so `LEA $1c.L,A0` patched into hunk 1 encodes `$1c` while naming an
//! address this hunk's coordinate space has no number for. Reading the encoded
//! bytes alone therefore states an address in the wrong frame. The relocation
//! index retained by [`ControlFlowAnalysis`] makes an address-bearing longword
//! operand read through the same record the traversal used: into the analyzed
//! hunk it is an offset (converted to a runtime address only where a mapped
//! origin proves one), and into any other hunk it is retained as an explicit
//! hunk and offset rather than flattened into a `u32`.
//!
//! ## Exact values and sized memory reads
//!
//! Only writes covering the whole register establish an exact value. A narrow
//! immediate write remains unknown. Byte/word memory writes to Dn instead keep
//! an explicit replacement of its low bits, with its old high bits named by a
//! register snapshot. MOVEA.W and MOVEM.W memory reads sign-extend to 32 bits.
//! Indexed reads retain the base, signed brief displacement and word/long index
//! snapshot. MOVEM loads retain each transfer's byte offset and final base update.
//! Source trees have at most three nodes (address, index, MOVEM slot); copies
//! and arithmetic extend bounded evidence without nesting the source further.

use std::collections::{BTreeMap, BTreeSet};

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Operands};
use m68000::isa::Isa;
use serde::Serialize;

use crate::control_flow::{
    ControlFlowAnalysis, DecodedInstruction, OperandAddress, OperandRole, UnresolvedFlow,
};
use crate::dataflow::{self, Domain};

/// Maximum instructions retained in one tracked value's evidence chain.
const MAX_VALUE_EVIDENCE: usize = 24;

/// What the caller knows about the analyzed hunk's runtime mapping.
///
/// Relocations are intentionally absent: [`ControlFlowAnalysis`] retains the
/// record used by traversal so value analysis cannot be given a different one.
/// The default is the plain, in-place reading, where a PC-relative address is
/// an offset in the analysis' own coordinate space.
#[derive(Clone, Copy, Debug, Default)]
pub struct ValueOptions {
    /// Absolute address of hunk offset zero, for an image mapped to a fixed
    /// load address. Turns image-relative results into runtime addresses.
    pub image_origin: Option<u32>,
}

#[derive(Clone, Copy)]
struct OperandOptions<'a> {
    image_origin: Option<u32>,
    analysis: &'a ControlFlowAnalysis,
}

/// One register's value at a site, with the instruction that put it there.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConstantValue {
    /// The whole register's value. Only writes that cover all 32 bits are
    /// reported, so this is never a partial answer dressed as a complete one.
    pub value: u32,
    /// Hunk offset of the instruction that wrote it — the evidence for this
    /// claim, so a reader can check it rather than trust it.
    pub site: u32,
    /// Instructions that established and copied the value, in flow order.
    ///
    /// At a join where several chains prove the same value, the shortest then
    /// lexicographically smallest chain is retained. That total rule keeps the
    /// fixpoint independent of block visitation order.
    pub evidence: Vec<u32>,
}

/// A non-numeric register value retained for semantic report collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TrackedValue {
    Exact(ConstantValue),
    Symbolic(SymbolicValue),
}

/// A 32-bit value named by a location rather than by a number, optionally
/// adjusted by wrapping arithmetic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SymbolicValue {
    pub(crate) subject: SymbolicSubject,
    pub(crate) location: SymbolicLocation,
    pub(crate) offset: u32,
    pub(crate) site: u32,
    pub(crate) evidence: Vec<u32>,
}

/// How a location contributes to the resulting 32-bit [`SymbolicValue`].
///
/// Keeping them apart is what stops `memory32[hunk1+$1c]` and `hunk1+$1c` from
/// being reported as the same finding: one is the pointer, the other is what it
/// points at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolicSubject {
    /// The longword stored at the location.
    Contents,
    /// A word read and sign-extended to the entire destination register.
    SignExtendedWord,
    /// A byte/word read replacing only the low bits of the named register.
    /// The remaining bits refer to its value immediately before this site.
    PreserveHigh {
        register: u8,
        read_site: u32,
        low_bytes: u8,
    },
    /// The location's own address. Produced only where no number in this hunk's
    /// address space names it, which currently means a relocation into another
    /// hunk.
    Address,
}

/// The effective address behind a symbolic value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SymbolicLocation {
    Absolute {
        address: u32,
    },
    ImageRelative {
        offset: u32,
        runtime_address: Option<u32>,
    },
    /// An offset into another hunk, proved by the relocation patching the
    /// operand. Nothing here maps that hunk to an address, so the frame is
    /// retained instead of being flattened into a number.
    HunkRelative {
        hunk: u32,
        offset: u32,
    },
    RegisterRelative {
        register: u8,
        displacement: i32,
    },
    /// A longword read through `(An)+`, identified by the instruction that
    /// consumed the pre-increment address. The site keeps distinct reads from
    /// joining merely because they used the same address register.
    RegisterPostincrement {
        register: u8,
        site: u32,
    },
    /// A longword read through `-(An)`, identified by the instruction that
    /// consumed the decremented address. The site keeps distinct mutations
    /// of the same address register from joining.
    RegisterPredecrement {
        register: u8,
        site: u32,
    },
    /// A brief-extension indexed address. Only MC68000 encodings (scale 1)
    /// are accepted. Register values are snapshots at the read site.
    Indexed {
        base: Box<Self>,
        index_address: bool,
        index_register: u8,
        index_bytes: u8,
        displacement: i8,
        read_site: u32,
    },
    /// One ascending transfer slot in a memory-to-register MOVEM.
    MovemSlot {
        base: Box<Self>,
        byte_offset: u32,
        read_site: u32,
    },
}

/// Why bounded dataflow could not establish a register's value.
///
/// Each variant is a *stop*, never a guess, so the set doubles as a diagnosis:
/// counted across a whole program it says which limitation is actually costing
/// argument values, and the answers point at different work. `Join`,
/// `WriteNotValued` and `UnresolvedFlow` are the current domain's own limits;
/// `UnknownRegister` is a table problem. [`crate::resolution`] folds these into
/// per-program totals, which is where that distinction is meant to be read.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unresolved {
    /// The site is not an instruction this analysis decoded. Nothing can be
    /// read about code that was never read.
    NotDecoded,
    /// A function reaching the site also contains a non-call transfer the
    /// analysis could not resolve. That transfer may land between a write and
    /// this site, so no run inside the function can be walked at all. An
    /// unresolved `JSR` instead has a known fallthrough and uses [`Self::Call`]
    /// clobbering there.
    UnresolvedFlow,
    /// Control arrives with incompatible exact or symbolic values, so the value
    /// depends on which path was taken. Equal values survive the join.
    Join,
    /// No predecessor established a value before the site.
    NoPredecessor,
    /// The value reaches a nested function entry from an unknown caller state.
    FunctionEntry,
    /// A call sits between the site and any write, and a callee may clobber
    /// anything.
    Call,
    /// An instruction wrote the register with something this tracker cannot
    /// value: an unsupported memory load or computed result, or a write
    /// narrower than the whole register.
    WriteNotValued,
    /// The forward worklist or a value's evidence chain reached its bound.
    StepLimit,
    /// The table describing this argument named a register that is not a 68000
    /// register. Produced by the caller rather than by dataflow, because the
    /// analysis is never queried for a register it cannot name.
    UnknownRegister,
}

impl Unresolved {
    /// The snake_case tag shared by text renderers and the JSON serialization
    /// (kept in lockstep by a unit test).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NotDecoded => "not_decoded",
            Self::UnresolvedFlow => "unresolved_flow",
            Self::Join => "join",
            Self::NoPredecessor => "no_predecessor",
            Self::FunctionEntry => "function_entry",
            Self::Call => "call",
            Self::WriteNotValued => "write_not_valued",
            Self::StepLimit => "step_limit",
            Self::UnknownRegister => "unknown_register",
        }
    }

    /// Every variant, in declaration order, so a renderer can present a
    /// complete, stably ordered histogram without hard-coding the list.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::NotDecoded,
            Self::UnresolvedFlow,
            Self::Join,
            Self::NoPredecessor,
            Self::FunctionEntry,
            Self::Call,
            Self::WriteNotValued,
            Self::StepLimit,
            Self::UnknownRegister,
        ]
    }
}

impl std::fmt::Display for Unresolved {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Which registers a lookup asks about.
///
/// Data and address registers are separate spaces on this architecture, so a
/// name alone is ambiguous; this keeps the caller's `d1`/`a0` distinction.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterKind {
    Data,
    Address,
}

/// Parse an fd-style register name such as `d0` or `A1`.
#[must_use]
pub fn parse_register(name: &str) -> Option<(RegisterKind, u8)> {
    let name = name.trim().to_ascii_lowercase();
    let mut characters = name.chars();
    let kind = match characters.next()? {
        'd' => RegisterKind::Data,
        'a' => RegisterKind::Address,
        _ => return None,
    };
    let index: u8 = characters.as_str().parse().ok()?;
    (index < 8 && characters.as_str().len() == 1).then_some((kind, index))
}

/// The constant in `(kind, register)` on entry to the instruction at `site`, or
/// the reason it cannot be established under the rules above.
///
/// `options` says how the analyzed hunk is addressed. Without an image origin,
/// image-relative addresses use the analysis' offset coordinate; without
/// relocations, a patched operand's stored addend is read as an address of this
/// hunk. An address a relocation proves lies in another hunk is never returned
/// as a number — it refuses with [`Unresolved::WriteNotValued`], because this
/// entry point answers only in exact values.
///
/// # Errors
///
/// Returns the conservative [`Unresolved`] reason that prevented an answer.
pub fn constant_before(
    analysis: &ControlFlowAnalysis,
    options: ValueOptions,
    site: u32,
    kind: RegisterKind,
    register: u8,
) -> Result<ConstantValue, Unresolved> {
    ConstantAnalysis::new(analysis, options).before(site, kind, register)
}

/// Register states computed once for all lookups in one report.
pub(crate) struct ConstantAnalysis {
    instructions: BTreeSet<u32>,
    site_owners: BTreeMap<u32, BTreeSet<u32>>,
    owners: BTreeMap<u32, Result<BTreeMap<u32, RegisterState>, Unresolved>>,
}

impl ConstantAnalysis {
    pub(crate) fn new(analysis: &ControlFlowAnalysis, options: ValueOptions) -> Self {
        let options = OperandOptions {
            image_origin: options.image_origin,
            analysis,
        };
        let owner_ids: BTreeSet<u32> = analysis
            .instructions
            .values()
            .flat_map(|decoded| decoded.owners.iter().copied())
            .collect();
        let mut owners = BTreeMap::new();
        for owner in owner_ids {
            if owner_has_invalidating_unresolved_flow(analysis, owner) {
                owners.insert(owner, Err(Unresolved::UnresolvedFlow));
                continue;
            }
            let walked = dataflow::forward(
                analysis,
                owner,
                RegisterState::unknown(Unresolved::NoPredecessor),
                |owner, decoded, state| {
                    if decoded.address != owner && analysis.functions.contains(&decoded.address) {
                        *state = RegisterState::unknown(Unresolved::FunctionEntry);
                    }
                },
                |decoded, state| transfer(decoded, state, options),
            );
            owners.insert(
                owner,
                if walked.exhausted {
                    Err(Unresolved::StepLimit)
                } else {
                    Ok(walked.before)
                },
            );
        }
        Self {
            instructions: analysis.instructions.keys().copied().collect(),
            site_owners: analysis
                .instructions
                .iter()
                .map(|(site, decoded)| (*site, decoded.owners.clone()))
                .collect(),
            owners,
        }
    }

    pub(crate) fn before(
        &self,
        site: u32,
        kind: RegisterKind,
        register: u8,
    ) -> Result<ConstantValue, Unresolved> {
        match self.before_value(site, kind, register)? {
            TrackedValue::Exact(value) => Ok(value),
            TrackedValue::Symbolic(_) => Err(Unresolved::WriteNotValued),
        }
    }

    fn before_value(
        &self,
        site: u32,
        kind: RegisterKind,
        register: u8,
    ) -> Result<TrackedValue, Unresolved> {
        if !self.instructions.contains(&site) {
            return Err(Unresolved::NotDecoded);
        }
        if register >= 8 {
            return Err(Unresolved::UnknownRegister);
        }
        let mut value: Option<AbstractValue> = None;
        let mut reached = false;
        let site_owners = self.site_owners.get(&site).ok_or(Unresolved::NotDecoded)?;
        for owner in site_owners {
            let Some(result) = self.owners.get(owner) else {
                continue;
            };
            let states = match result {
                Ok(states) => states,
                Err(reason) => return Err(*reason),
            };
            let Some(state) = states.get(&site) else {
                continue;
            };
            reached = true;
            let incoming = state.get(kind, register).clone();
            match value.as_mut() {
                Some(current) => {
                    current.join(&incoming);
                }
                None => value = Some(incoming),
            }
        }
        if !reached {
            return Err(Unresolved::NoPredecessor);
        }
        match value.ok_or(Unresolved::NoPredecessor)? {
            AbstractValue::Unknown(reason) => Err(reason),
            AbstractValue::Exact(exact) => Ok(TrackedValue::Exact(ConstantValue {
                value: exact.value,
                site: exact.site,
                evidence: exact.evidence,
            })),
            AbstractValue::Symbolic(symbolic) => Ok(TrackedValue::Symbolic(symbolic)),
        }
    }
}

/// Whether an owner's unresolved control flow could introduce an unknown
/// intraprocedural predecessor.
///
/// An indirect `JSR` has no known callee target, but its return address is the
/// decoded fallthrough already present in the graph. [`transfer`] clobbers the
/// complete register state at every call, so an unknown callee *outside* this
/// owner adds no state the owner-local walk lacks. Jumps and opaque/missing
/// instructions have no such return edge and still invalidate the entire owner.
///
fn owner_has_invalidating_unresolved_flow(analysis: &ControlFlowAnalysis, owner: u32) -> bool {
    // `UnresolvedFlow` orders by `(owner, address)`, so one owner's entries are
    // a contiguous range. Scanning the whole set once per owner would be
    // quadratic in a program with many entry points and many unresolved exits.
    let first = UnresolvedFlow { owner, address: 0 };
    let last = UnresolvedFlow {
        owner,
        address: u32::MAX,
    };
    let mut call_registers = BTreeSet::new();
    for flow in analysis.unresolved.range(first..=last) {
        let Some(decoded) = analysis.instructions.get(&flow.address) else {
            return true;
        };
        if Isa::from(decoded.instruction.opcode) != Isa::Jsr {
            return true;
        }
        let Operands::EffectiveAddress(mode) = decoded.instruction.operands else {
            return true;
        };
        let Some(register) = indirect_base_register(mode) else {
            // A non-register indirect form can still enter owned code, but the
            // bounded candidate rule below has no register whose sources it
            // can inspect.
            return true;
        };
        call_registers.insert(register);
    }
    if call_registers.is_empty() {
        return false;
    }

    analysis
        .instructions
        .values()
        .filter(|decoded| decoded.owners.contains(&owner))
        .filter_map(address_register_candidate)
        .filter(|(register, _, _)| call_registers.contains(register))
        .filter_map(|(_, decoded, source)| candidate_offset(analysis, decoded, source))
        .any(|target| {
            analysis
                .instructions
                .get(&target)
                .is_some_and(|decoded| decoded.owners.contains(&owner))
        })
}

fn indirect_base_register(mode: AddressingMode) -> Option<u8> {
    match mode {
        AddressingMode::Ari(register)
        | AddressingMode::Ariwd(register, _)
        | AddressingMode::Ariwi8(register, _) => Some(register),
        _ => None,
    }
}

/// One instruction that places a statically named address in an address
/// register. Memory loads are deliberately absent: their runtime contents
/// cannot prove that an unresolved call stays outside this owner.
fn address_register_candidate(
    decoded: &DecodedInstruction,
) -> Option<(u8, &DecodedInstruction, CandidateSource)> {
    match decoded.instruction.operands {
        Operands::RegisterEffectiveAddress(register, mode)
            if Isa::from(decoded.instruction.opcode) == Isa::Lea =>
        {
            Some((register, decoded, CandidateSource::Address(mode)))
        }
        Operands::SizeEffectiveAddressEffectiveAddress(
            size,
            AddressingMode::Ard(register),
            AddressingMode::Immediate(value),
        )
        | Operands::SizeRegisterEffectiveAddress(
            size,
            register,
            AddressingMode::Immediate(value),
        ) => Some((register, decoded, CandidateSource::Immediate(size, value))),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum CandidateSource {
    Address(AddressingMode),
    Immediate(m68000::instruction::Size, u32),
}

fn candidate_offset(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    source: CandidateSource,
) -> Option<u32> {
    let address = match source {
        CandidateSource::Address(AddressingMode::Pciwd(pc, displacement)) => {
            return pc.checked_add_signed(i32::from(displacement));
        }
        CandidateSource::Address(AddressingMode::AbsShort(address)) => {
            OperandAddress::Encoded(crate::globals::sign_extend_word(address))
        }
        CandidateSource::Address(AddressingMode::AbsLong(addend))
        | CandidateSource::Immediate(m68000::instruction::Size::Long, addend) => {
            analysis.operand_address(decoded, OperandRole::Source, addend)
        }
        CandidateSource::Immediate(_, value) => {
            OperandAddress::Encoded(address_immediate(m68000::instruction::Size::Word, value))
        }
        CandidateSource::Address(_) => return None,
    };
    match address {
        OperandAddress::Encoded(address) => analysis.image_offset(address),
        OperandAddress::ThisHunk(offset) => Some(offset),
        OperandAddress::OtherHunk { .. } => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegisterState {
    registers: [AbstractValue; 16],
}

impl RegisterState {
    fn unknown(reason: Unresolved) -> Self {
        Self {
            registers: std::array::from_fn(|_| AbstractValue::Unknown(reason)),
        }
    }

    fn get(&self, kind: RegisterKind, register: u8) -> &AbstractValue {
        &self.registers[register_index(kind, register)]
    }
}

impl Domain for RegisterState {
    fn join(&mut self, incoming: &Self) -> bool {
        let mut changed = false;
        for (current, incoming) in self.registers.iter_mut().zip(&incoming.registers) {
            changed |= current.join(incoming);
        }
        changed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AbstractValue {
    Unknown(Unresolved),
    Exact(ExactValue),
    Symbolic(SymbolicValue),
}

impl AbstractValue {
    fn join(&mut self, incoming: &Self) -> bool {
        match (&mut *self, incoming) {
            (Self::Unknown(current), Self::Unknown(other)) => {
                let merged = merge_reason(*current, *other);
                if *current == merged {
                    false
                } else {
                    *current = merged;
                    true
                }
            }
            (Self::Unknown(_), Self::Exact(_) | Self::Symbolic(_)) => false,
            (Self::Exact(_) | Self::Symbolic(_), Self::Unknown(reason)) => {
                *self = Self::Unknown(*reason);
                true
            }
            (Self::Exact(_), Self::Symbolic(_)) | (Self::Symbolic(_), Self::Exact(_)) => {
                *self = Self::Unknown(Unresolved::Join);
                true
            }
            (Self::Exact(current), Self::Exact(other)) if current.value != other.value => {
                *self = Self::Unknown(Unresolved::Join);
                true
            }
            (Self::Exact(current), Self::Exact(other)) => {
                let take_other = (other.evidence.len(), &other.evidence, other.site)
                    < (current.evidence.len(), &current.evidence, current.site);
                if take_other {
                    *current = other.clone();
                }
                take_other
            }
            (Self::Symbolic(current), Self::Symbolic(other))
                if current.subject != other.subject
                    || current.location != other.location
                    || current.offset != other.offset =>
            {
                *self = Self::Unknown(Unresolved::Join);
                true
            }
            (Self::Symbolic(current), Self::Symbolic(other)) => {
                let take_other = (other.evidence.len(), &other.evidence, other.site)
                    < (current.evidence.len(), &current.evidence, current.site);
                if take_other {
                    *current = other.clone();
                }
                take_other
            }
        }
    }
}

const fn merge_reason(left: Unresolved, right: Unresolved) -> Unresolved {
    if reason_rank(left) >= reason_rank(right) {
        left
    } else {
        right
    }
}

const fn reason_rank(reason: Unresolved) -> u8 {
    match reason {
        Unresolved::UnknownRegister => 0,
        Unresolved::NoPredecessor => 1,
        Unresolved::Join => 2,
        Unresolved::WriteNotValued => 3,
        Unresolved::Call => 4,
        Unresolved::FunctionEntry => 5,
        Unresolved::NotDecoded => 6,
        Unresolved::UnresolvedFlow => 7,
        Unresolved::StepLimit => 8,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactValue {
    value: u32,
    site: u32,
    evidence: Vec<u32>,
}

impl ExactValue {
    fn established(value: u32, site: u32) -> Self {
        Self {
            value,
            site,
            evidence: vec![site],
        }
    }

    fn copied(&self, site: u32) -> Option<Self> {
        if self.evidence.len() >= MAX_VALUE_EVIDENCE {
            return None;
        }
        let mut evidence = self.evidence.clone();
        evidence.push(site);
        Some(Self {
            value: self.value,
            site,
            evidence,
        })
    }

    fn transformed(&self, site: u32, operation: ExactOperation) -> Option<Self> {
        let mut transformed = self.copied(site)?;
        transformed.value = operation.apply(self.value);
        Some(transformed)
    }
}

impl SymbolicValue {
    fn established(subject: SymbolicSubject, location: SymbolicLocation, site: u32) -> Self {
        Self {
            subject,
            location,
            offset: 0,
            site,
            evidence: vec![site],
        }
    }

    fn copied(&self, site: u32) -> Option<Self> {
        if self.evidence.len() >= MAX_VALUE_EVIDENCE {
            return None;
        }
        let mut evidence = self.evidence.clone();
        evidence.push(site);
        Some(Self {
            subject: self.subject,
            location: self.location.clone(),
            offset: self.offset,
            site,
            evidence,
        })
    }

    fn transformed(&self, site: u32, operation: ExactOperation) -> Result<Self, Unresolved> {
        let offset = operation
            .apply_symbolic(self.offset)
            .ok_or(Unresolved::WriteNotValued)?;
        let mut transformed = self.copied(site).ok_or(Unresolved::StepLimit)?;
        transformed.offset = offset;
        Ok(transformed)
    }
}

const fn register_index(kind: RegisterKind, register: u8) -> usize {
    match kind {
        RegisterKind::Data => register as usize,
        RegisterKind::Address => 8 + register as usize,
    }
}

fn transfer(decoded: &DecodedInstruction, state: &mut RegisterState, options: OperandOptions<'_>) {
    if is_call(decoded) {
        *state = RegisterState::unknown(Unresolved::Call);
        return;
    }
    let before = state.clone();
    for kind in [RegisterKind::Data, RegisterKind::Address] {
        for register in 0..8 {
            let Some(write) = register_write(decoded, kind, register, options) else {
                continue;
            };
            state.registers[register_index(kind, register)] = match write {
                RegisterWrite::Exact(value) => {
                    AbstractValue::Exact(ExactValue::established(value, decoded.address))
                }
                RegisterWrite::Symbolic(subject, location) => AbstractValue::Symbolic(
                    SymbolicValue::established(subject, location, decoded.address),
                ),
                RegisterWrite::Copy(source_kind, source_register) => {
                    match before.get(source_kind, source_register) {
                        AbstractValue::Exact(value) => value
                            .copied(decoded.address)
                            .map(AbstractValue::Exact)
                            .unwrap_or(AbstractValue::Unknown(Unresolved::StepLimit)),
                        AbstractValue::Symbolic(value) => value
                            .copied(decoded.address)
                            .map(AbstractValue::Symbolic)
                            .unwrap_or(AbstractValue::Unknown(Unresolved::StepLimit)),
                        AbstractValue::Unknown(reason) => AbstractValue::Unknown(*reason),
                    }
                }
                RegisterWrite::Transform(operation) => match before.get(kind, register) {
                    AbstractValue::Exact(value) => value
                        .transformed(decoded.address, operation)
                        .map(AbstractValue::Exact)
                        .unwrap_or(AbstractValue::Unknown(Unresolved::StepLimit)),
                    AbstractValue::Symbolic(value) => value
                        .transformed(decoded.address, operation)
                        .map(AbstractValue::Symbolic)
                        .unwrap_or_else(AbstractValue::Unknown),
                    AbstractValue::Unknown(reason) => AbstractValue::Unknown(*reason),
                },
                RegisterWrite::Unknown => AbstractValue::Unknown(Unresolved::WriteNotValued),
            };
        }
    }
}

#[derive(Clone)]
enum RegisterWrite {
    Exact(u32),
    Symbolic(SymbolicSubject, SymbolicLocation),
    Copy(RegisterKind, u8),
    Transform(ExactOperation),
    Unknown,
}

#[derive(Clone, Copy)]
enum ExactOperation {
    Add(u32),
    Subtract(u32),
    And(u32),
    Or(u32),
    ExclusiveOr(u32),
    Negate,
    Not,
}

impl ExactOperation {
    const fn apply(self, value: u32) -> u32 {
        match self {
            Self::Add(amount) => value.wrapping_add(amount),
            Self::Subtract(amount) => value.wrapping_sub(amount),
            Self::And(mask) => value & mask,
            Self::Or(mask) => value | mask,
            Self::ExclusiveOr(mask) => value ^ mask,
            Self::Negate => 0_u32.wrapping_sub(value),
            Self::Not => !value,
        }
    }

    const fn apply_symbolic(self, offset: u32) -> Option<u32> {
        match self {
            Self::Add(amount) => Some(offset.wrapping_add(amount)),
            Self::Subtract(amount) => Some(offset.wrapping_sub(amount)),
            Self::And(_) | Self::Or(_) | Self::ExclusiveOr(_) | Self::Negate | Self::Not => None,
        }
    }
}

pub(crate) fn constant_before_with(
    constants: &ConstantAnalysis,
    site: u32,
    kind: RegisterKind,
    register: u8,
) -> Result<TrackedValue, Unresolved> {
    constants.before_value(site, kind, register)
}

/// Whether this instruction transfers control to a subroutine, or is a word
/// the decoder cannot name — both clobber the propagated state because nothing
/// here can say what they left in the registers.
fn is_call(decoded: &DecodedInstruction) -> bool {
    matches!(
        Isa::from(decoded.instruction.opcode),
        Isa::Jsr | Isa::Bsr | Isa::Unknown
    )
}

/// What `decoded` writes to `(kind, register)`.
///
/// The match is **exhaustive on purpose**: no wildcard arm. A wildcard here
/// reads as "leaves the register alone", which is the dangerous default — an
/// unclassified form that actually writes would preserve a stale value as
/// current. With no wildcard, a decoder that
/// grows a variant fails to compile until someone decides what it does, which
/// is the only way this stays honest as the dependency moves.
fn register_write(
    decoded: &DecodedInstruction,
    kind: RegisterKind,
    register: u8,
    options: OperandOptions<'_>,
) -> Option<RegisterWrite> {
    let isa = Isa::from(decoded.instruction.opcode);
    let target = match kind {
        RegisterKind::Data => AddressingMode::Drd(register),
        RegisterKind::Address => AddressingMode::Ard(register),
    };
    let value = |value: u32| Some(RegisterWrite::Exact(value));
    let data = |written: u8| {
        (kind == RegisterKind::Data && written == register).then_some(RegisterWrite::Unknown)
    };
    let address = |written: u8| {
        (kind == RegisterKind::Address && written == register).then_some(RegisterWrite::Unknown)
    };
    let either = |written: u8| (written == register).then_some(RegisterWrite::Unknown);

    // MOVEM (An)+ writes the final address even when An is in the load mask.
    // Compute it from the pre-instruction state, never from the loaded slot.
    if let Operands::DirectionSizeEffectiveAddressList(
        Direction::MemoryToRegister,
        size,
        AddressingMode::Ariwpo(base),
        list,
    ) = decoded.instruction.operands
        && kind == RegisterKind::Address
        && register == base
    {
        return Some(RegisterWrite::Transform(ExactOperation::Add(
            list.count_ones() * if is_long(size) { 4 } else { 2 },
        )));
    }

    // An addressing mode that increments or decrements its base changes that
    // register as a side effect, wherever in the instruction it appears — the
    // destination checks below would sail straight past it.
    if kind == RegisterKind::Address && adjusts_base(decoded, register) {
        return Some(RegisterWrite::Unknown);
    }
    // EXG swaps two registers, so both hold something this tracker cannot
    // value. Its operand form names registers without marking either written.
    if let Some((left, right)) = exchanged_registers(decoded)
        && (left == (kind, register) || right == (kind, register))
    {
        return Some(RegisterWrite::Unknown);
    }

    match decoded.instruction.operands {
        // MOVEQ #n,Dn — sign-extended into the whole register.
        Operands::RegisterData(destination, immediate) => (kind == RegisterKind::Data
            && destination == register)
            .then_some(RegisterWrite::Exact(i32::from(immediate) as u32)),
        // MOVE <ea>,<ea>: a longword immediate establishes the register, a
        // direct memory source establishes a symbolic read, and a narrower
        // data-register write leaves part of its previous value in place.
        Operands::SizeEffectiveAddressEffectiveAddress(size, destination, source) => {
            if !writes(destination, target) {
                return None;
            }
            match source {
                AddressingMode::Immediate(immediate) if is_long(size) => {
                    Some(address_operand(decoded, immediate, options))
                }
                source if is_long(size) => direct_register(source)
                    .map(|(kind, register)| RegisterWrite::Copy(kind, register))
                    .or_else(|| {
                        symbolic_memory(decoded, source, options).map(|location| {
                            RegisterWrite::Symbolic(SymbolicSubject::Contents, location)
                        })
                    })
                    .or(Some(RegisterWrite::Unknown)),
                source => Some(symbolic_memory(decoded, source, options).map_or(
                    RegisterWrite::Unknown,
                    |location| {
                        RegisterWrite::Symbolic(
                            SymbolicSubject::PreserveHigh {
                                register,
                                read_site: decoded.address,
                                low_bytes: if matches!(size, m68000::instruction::Size::Byte) {
                                    1
                                } else {
                                    2
                                },
                            },
                            location,
                        )
                    },
                )),
            }
        }
        // MOVEA <ea>,An. The word form sign-extends into the whole register.
        Operands::SizeRegisterEffectiveAddress(size, destination, source) => {
            if kind != RegisterKind::Address || destination != register {
                return None;
            }
            match source {
                AddressingMode::Immediate(immediate) if is_long(size) => {
                    Some(address_operand(decoded, immediate, options))
                }
                AddressingMode::Immediate(immediate) => {
                    value(i32::from(immediate as u16 as i16) as u32)
                }
                source if is_long(size) => direct_register(source)
                    .map(|(kind, register)| RegisterWrite::Copy(kind, register))
                    .or_else(|| {
                        symbolic_memory(decoded, source, options).map(|location| {
                            RegisterWrite::Symbolic(SymbolicSubject::Contents, location)
                        })
                    })
                    .or(Some(RegisterWrite::Unknown)),
                source => {
                    Some(symbolic_memory(decoded, source, options).map_or(
                        RegisterWrite::Unknown,
                        |location| {
                            RegisterWrite::Symbolic(SymbolicSubject::SignExtendedWord, location)
                        },
                    ))
                }
            }
        }
        // LEA <ea>,An: an absolute address is a constant; anything computed is
        // not. The short form sign-extends.
        Operands::RegisterEffectiveAddress(destination, source) if isa == Isa::Lea => {
            if kind != RegisterKind::Address || destination != register {
                return None;
            }
            match source {
                AddressingMode::AbsShort(address) => {
                    value(crate::globals::sign_extend_word(address))
                }
                AddressingMode::AbsLong(address) => {
                    Some(address_operand(decoded, address, options))
                }
                AddressingMode::Pciwd(pc, displacement) => {
                    let Some(offset) = pc.checked_add_signed(i32::from(displacement)) else {
                        return Some(RegisterWrite::Unknown);
                    };
                    Some(
                        runtime_address(offset, options)
                            .map_or(RegisterWrite::Unknown, RegisterWrite::Exact),
                    )
                }
                _ => Some(RegisterWrite::Unknown),
            }
        }
        // The remaining `RegisterEffectiveAddress` forms — MULS/MULU/DIVS/DIVU
        // and CHK — write the named data register.
        Operands::RegisterEffectiveAddress(destination, _) => data(destination),

        // --- forms that write a register with a value this tracker cannot give
        // EXT/EXTB and SWAP: `OpmodeRegister`/`Register` over a data register.
        Operands::OpmodeRegister(_, destination) => data(destination),
        // SWAP, UNLK, and the other single-register forms. UNLK writes an
        // address register; SWAP a data one; the mnemonic decides which.
        Operands::Register(destination) => {
            if isa == Isa::Swap {
                data(destination) // SWAP Dn
            } else {
                either(destination) // UNLK An, and anything else naming a register
            }
        }
        // MOVE USP,An / MOVE An,USP.
        Operands::DirectionRegister(_, destination) => address(destination),
        // BTST/BCHG/BCLR/BSET with an immediate bit number: the register form
        // writes the register (BTST only reads, and is excluded by mnemonic).
        Operands::EffectiveAddressCount(destination, _) => {
            if isa == Isa::Btst {
                None // BTST reads only
            } else {
                writes(destination, target).then_some(RegisterWrite::Unknown)
            }
        }
        // Scc <ea> sets its destination to 0 or -1.
        Operands::ConditionEffectiveAddress(_, destination) => {
            writes(destination, target).then_some(RegisterWrite::Unknown)
        }
        // DBcc Dn,label decrements its counter.
        Operands::ConditionRegisterDisplacement(_, counter, _) => data(counter),
        // ABCD/SBCD/ADDX/SUBX: the register form writes a data register, the
        // memory form writes through predecremented address registers (which
        // `adjusts_base` has already accounted for).
        Operands::RegisterSizeModeRegister(destination, _, Direction::RegisterToRegister, _) => {
            data(destination)
        }
        Operands::RegisterSizeModeRegister(..) => None,
        // CMPM only compares, but its postincrements are handled above.
        Operands::RegisterSizeRegister(_, _, _) => None,
        // MOVEP moves between memory and a data register.
        Operands::RegisterDirectionSizeRegisterDisplacement(data_register, direction, _, _, _) => {
            match direction {
                Direction::MemoryToRegister => data(data_register),
                _ => None,
            }
        }
        // CLR/NEG/NOT/TAS/NBCD/MOVE-from-SR write their operand; TST reads it.
        Operands::SizeEffectiveAddress(..) if isa == Isa::Tst => None,
        Operands::SizeEffectiveAddress(size, destination) => {
            if !writes(destination, target) {
                return None;
            }
            match (isa, size, kind) {
                (Isa::Clr, m68000::instruction::Size::Long, RegisterKind::Data) => {
                    Some(RegisterWrite::Exact(0))
                }
                (Isa::Neg, m68000::instruction::Size::Long, RegisterKind::Data) => {
                    Some(RegisterWrite::Transform(ExactOperation::Negate))
                }
                (Isa::Not, m68000::instruction::Size::Long, RegisterKind::Data) => {
                    Some(RegisterWrite::Transform(ExactOperation::Not))
                }
                _ => Some(RegisterWrite::Unknown),
            }
        }
        Operands::EffectiveAddress(destination) => {
            writes(destination, target).then_some(RegisterWrite::Unknown)
        }
        // Immediate arithmetic (ADDI/SUBI/ANDI/ORI/EORI); CMPI only reads.
        Operands::SizeEffectiveAddressImmediate(..) if isa == Isa::Cmpi => None,
        Operands::SizeEffectiveAddressImmediate(size, destination, immediate) => {
            if !writes(destination, target) {
                return None;
            }
            if kind != RegisterKind::Data || !is_long(size) {
                return Some(RegisterWrite::Unknown);
            }
            // A relocation patching the immediate makes the amount an address
            // in a frame this arithmetic cannot add: refuse rather than fold an
            // addend into the running value.
            if patched(decoded, immediate, options) {
                return Some(RegisterWrite::Unknown);
            }
            match isa {
                Isa::Addi => Some(RegisterWrite::Transform(ExactOperation::Add(immediate))),
                Isa::Subi => Some(RegisterWrite::Transform(ExactOperation::Subtract(
                    immediate,
                ))),
                Isa::Andi => Some(RegisterWrite::Transform(ExactOperation::And(immediate))),
                Isa::Ori => Some(RegisterWrite::Transform(ExactOperation::Or(immediate))),
                Isa::Eori => Some(RegisterWrite::Transform(ExactOperation::ExclusiveOr(
                    immediate,
                ))),
                _ => Some(RegisterWrite::Unknown),
            }
        }
        // ADDQ/SUBQ.
        Operands::DataSizeEffectiveAddress(amount, size, destination) => {
            if !writes(destination, target) {
                return None;
            }
            if kind == RegisterKind::Data && !is_long(size) {
                return Some(RegisterWrite::Unknown);
            }
            let amount = if amount == 0 { 8 } else { u32::from(amount) };
            match isa {
                Isa::Addq => Some(RegisterWrite::Transform(ExactOperation::Add(amount))),
                Isa::Subq => Some(RegisterWrite::Transform(ExactOperation::Subtract(amount))),
                _ => Some(RegisterWrite::Unknown),
            }
        }
        // Register arithmetic: one side or the other.
        Operands::RegisterDirectionSizeEffectiveAddress(source, direction, _, destination) => {
            match direction {
                Direction::DstEa => writes(destination, target).then_some(RegisterWrite::Unknown),
                _ => data(source),
            }
        }
        // ADDA/SUBA/CMPA and LINK write an address register (CMPA does not,
        // but over-approximating a compare only loses precision).
        Operands::RegisterSizeEffectiveAddress(destination, size, source) => {
            if kind != RegisterKind::Address || destination != register {
                return None;
            }
            let AddressingMode::Immediate(immediate) = source else {
                return Some(RegisterWrite::Unknown);
            };
            // As above: a patched immediate is an address, not an amount.
            if is_long(size) && patched(decoded, immediate, options) {
                return Some(RegisterWrite::Unknown);
            }
            let immediate = address_immediate(size, immediate);
            match isa {
                Isa::Adda => Some(RegisterWrite::Transform(ExactOperation::Add(immediate))),
                Isa::Suba => Some(RegisterWrite::Transform(ExactOperation::Subtract(
                    immediate,
                ))),
                _ => Some(RegisterWrite::Unknown),
            }
        }
        Operands::RegisterDisplacement(destination, _) => address(destination),
        // Shifts and rotates in their register form.
        Operands::RotationDirectionSizeModeRegister(_, _, _, _, destination) => data(destination),
        // MOVEM memory-to-register: bit 0 = D0 … bit 15 = A7.
        Operands::DirectionSizeEffectiveAddressList(
            Direction::MemoryToRegister,
            size,
            source,
            list,
        ) => {
            let bit = match kind {
                RegisterKind::Data => u16::from(register),
                RegisterKind::Address => 8 + u16::from(register),
            };
            if list & (1 << bit) == 0 {
                return None;
            }
            // Predecrement and register-direct loads are not valid MOVEM sources.
            if matches!(
                source,
                AddressingMode::Ariwpr(_)
                    | AddressingMode::Drd(_)
                    | AddressingMode::Ard(_)
                    | AddressingMode::Immediate(_)
            ) {
                return Some(RegisterWrite::Unknown);
            }
            let slot = (list & ((1_u16 << bit) - 1)).count_ones();
            Some(
                symbolic_memory(decoded, source, options).map_or(RegisterWrite::Unknown, |base| {
                    RegisterWrite::Symbolic(
                        if is_long(size) {
                            SymbolicSubject::Contents
                        } else {
                            SymbolicSubject::SignExtendedWord
                        },
                        SymbolicLocation::MovemSlot {
                            base: Box::new(base),
                            byte_offset: slot * if is_long(size) { 4 } else { 2 },
                            read_site: decoded.address,
                        },
                    )
                }),
            )
        }
        Operands::DirectionSizeEffectiveAddressList(..) => None,
        // Bcc/BSR, JMP/JSR (the caller stops at those anyway), TRAP, and the
        // operandless forms touch no register this tracker follows.
        Operands::DirectionEffectiveAddress(_, destination) => {
            writes(destination, target).then_some(RegisterWrite::Unknown)
        }
        Operands::RegisterOpmodeRegister(destination, direction, _) => match direction {
            // ABCD/SBCD/ADDX/SUBX register form, and AND/OR/EOR to a register.
            Direction::RegisterToMemory => None,
            _ => data(destination),
        },
        Operands::NoOperands
        | Operands::Immediate(_)
        | Operands::Vector(_)
        | Operands::Displacement(_)
        | Operands::ConditionDisplacement(..) => None,
    }
}

/// Whether writing `destination` overwrites `target`.
///
/// Only the register-direct forms are decidable here: an indirect write
/// through an address register changes memory, not the register.
fn writes(destination: AddressingMode, target: AddressingMode) -> bool {
    destination == target
}

fn direct_register(mode: AddressingMode) -> Option<(RegisterKind, u8)> {
    match mode {
        AddressingMode::Drd(register) => Some((RegisterKind::Data, register)),
        AddressingMode::Ard(register) => Some((RegisterKind::Address, register)),
        _ => None,
    }
}

/// Whether a relocation patches the longword operand storing `addend`.
fn patched(decoded: &DecodedInstruction, addend: u32, options: OperandOptions<'_>) -> bool {
    !matches!(
        options
            .analysis
            .operand_address(decoded, OperandRole::Source, addend),
        OperandAddress::Encoded(_)
    )
}

/// The write establishing an address-bearing longword operand as a value.
fn address_operand(
    decoded: &DecodedInstruction,
    addend: u32,
    options: OperandOptions<'_>,
) -> RegisterWrite {
    match options
        .analysis
        .operand_address(decoded, OperandRole::Source, addend)
    {
        OperandAddress::Encoded(address) => RegisterWrite::Exact(address),
        OperandAddress::ThisHunk(offset) => {
            runtime_address(offset, options).map_or(RegisterWrite::Unknown, RegisterWrite::Exact)
        }
        OperandAddress::OtherHunk { hunk, offset } => RegisterWrite::Symbolic(
            SymbolicSubject::Address,
            SymbolicLocation::HunkRelative { hunk, offset },
        ),
    }
}

/// An offset into the analyzed hunk as an absolute address where a mapped
/// origin proves one, and as the analysis' own coordinate otherwise.
fn runtime_address(offset: u32, options: OperandOptions<'_>) -> Option<u32> {
    options
        .image_origin
        .map_or(Some(offset), |origin| origin.checked_add(offset))
}

/// A stable, non-mutating memory source whose contents can be named without
/// pretending to know the bytes stored there.
fn symbolic_memory(
    decoded: &DecodedInstruction,
    mode: AddressingMode,
    options: OperandOptions<'_>,
) -> Option<SymbolicLocation> {
    match mode {
        AddressingMode::Ari(register) => Some(SymbolicLocation::RegisterRelative {
            register,
            displacement: 0,
        }),
        AddressingMode::Ariwd(register, displacement) => Some(SymbolicLocation::RegisterRelative {
            register,
            displacement: i32::from(displacement),
        }),
        AddressingMode::Ariwpo(register) => Some(SymbolicLocation::RegisterPostincrement {
            register,
            site: decoded.address,
        }),
        AddressingMode::Ariwpr(register) => Some(SymbolicLocation::RegisterPredecrement {
            register,
            site: decoded.address,
        }),
        AddressingMode::AbsShort(address) => Some(SymbolicLocation::Absolute {
            address: crate::globals::sign_extend_word(address),
        }),
        AddressingMode::AbsLong(address) => Some(
            match options
                .analysis
                .operand_address(decoded, OperandRole::Source, address)
            {
                OperandAddress::Encoded(address) => SymbolicLocation::Absolute { address },
                OperandAddress::ThisHunk(offset) => SymbolicLocation::ImageRelative {
                    offset,
                    runtime_address: options
                        .image_origin
                        .and_then(|origin| origin.checked_add(offset)),
                },
                OperandAddress::OtherHunk { hunk, offset } => {
                    SymbolicLocation::HunkRelative { hunk, offset }
                }
            },
        ),
        AddressingMode::Pciwd(pc, displacement) => {
            let offset = pc.checked_add_signed(i32::from(displacement))?;
            Some(SymbolicLocation::ImageRelative {
                offset,
                runtime_address: options
                    .image_origin
                    .and_then(|origin| origin.checked_add(offset)),
            })
        }
        AddressingMode::Ariwi8(register, extension) => indexed_memory(
            decoded,
            extension,
            SymbolicLocation::RegisterRelative {
                register,
                displacement: 0,
            },
        ),
        AddressingMode::Pciwi8(pc, extension) => indexed_memory(
            decoded,
            extension,
            SymbolicLocation::ImageRelative {
                offset: pc,
                runtime_address: options
                    .image_origin
                    .and_then(|origin| origin.checked_add(pc)),
            },
        ),
        AddressingMode::Drd(_) | AddressingMode::Ard(_) | AddressingMode::Immediate(_) => None,
    }
}

/// Constant-depth source trees: plain address, optionally indexed, optionally
/// a MOVEM slot. Propagation never nests expressions further.
fn indexed_memory(
    decoded: &DecodedInstruction,
    extension: m68000::addressing_modes::BriefExtensionWord,
    base: SymbolicLocation,
) -> Option<SymbolicLocation> {
    // Scale/full-extension bits belong to later CPUs, outside this MC68000 API.
    if extension.0 & 0x0700 != 0 {
        return None;
    }
    Some(SymbolicLocation::Indexed {
        base: Box::new(base),
        index_address: extension.0 & 0x8000 != 0,
        index_register: ((extension.0 >> 12) & 7) as u8,
        index_bytes: if extension.0 & 0x0800 != 0 { 4 } else { 2 },
        displacement: extension.disp(),
        read_site: decoded.address,
    })
}

const fn is_long(size: m68000::instruction::Size) -> bool {
    matches!(size, m68000::instruction::Size::Long)
}

fn address_immediate(size: m68000::instruction::Size, value: u32) -> u32 {
    match size {
        m68000::instruction::Size::Word => i32::from(value as u16 as i16) as u32,
        _ => value,
    }
}

/// Whether any operand of `decoded` post-increments or pre-decrements `An`.
///
/// The side effect belongs to the addressing mode, not to the instruction's
/// destination, so `MOVE.B (A1)+,D0` changes A1 while writing D0.
fn adjusts_base(decoded: &DecodedInstruction, register: u8) -> bool {
    let adjusts = |mode: AddressingMode| matches!(mode, AddressingMode::Ariwpo(base) | AddressingMode::Ariwpr(base) if base == register);
    match decoded.instruction.operands {
        Operands::SizeEffectiveAddressEffectiveAddress(_, left, right) => {
            adjusts(left) || adjusts(right)
        }
        Operands::SizeRegisterEffectiveAddress(_, _, mode)
        | Operands::RegisterEffectiveAddress(_, mode)
        | Operands::SizeEffectiveAddress(_, mode)
        | Operands::DirectionEffectiveAddress(_, mode)
        | Operands::RegisterDirectionSizeEffectiveAddress(_, _, _, mode)
        | Operands::DataSizeEffectiveAddress(_, _, mode)
        | Operands::SizeEffectiveAddressImmediate(_, mode, _)
        | Operands::DirectionSizeEffectiveAddressList(_, _, mode, _)
        | Operands::EffectiveAddressCount(mode, _) => adjusts(mode),
        // CMPM (Ay)+,(Ax)+ and the `-(Ay),-(Ax)` forms of ABCD/SBCD/ADDX/SUBX
        // encode their increments as bare register numbers, with no
        // addressing mode to inspect.
        Operands::RegisterSizeRegister(left, _, right) => left == register || right == register,
        // `MemoryToMemory` is the `-(Ay),-(Ax)` form; the register form
        // touches data registers only.
        Operands::RegisterSizeModeRegister(left, _, Direction::MemoryToMemory, right) => {
            left == register || right == register
        }
        _ => false,
    }
}

/// The two registers an `EXG` swaps, if this is one.
///
/// Read from the encoding rather than the decoded operands, because the
/// operand form `EXG` shares with `AND`/`ABCD` names registers without marking
/// either as written.
fn exchanged_registers(
    decoded: &DecodedInstruction,
) -> Option<((RegisterKind, u8), (RegisterKind, u8))> {
    let opcode = decoded.instruction.opcode;
    if Isa::from(opcode) != Isa::Exg {
        return None;
    }
    // `Isa` stops at the mnemonic: one `Exg` covers all three register-pair
    // modes, and the register numbers are not in it at all. Both still come
    // from the encoding.
    let left = ((opcode >> 9) & 7) as u8;
    let right = (opcode & 7) as u8;
    match opcode & 0x00f8 {
        0x0040 => Some(((RegisterKind::Data, left), (RegisterKind::Data, right))),
        0x0048 => Some((
            (RegisterKind::Address, left),
            (RegisterKind::Address, right),
        )),
        0x0088 => Some(((RegisterKind::Data, left), (RegisterKind::Address, right))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Relocations;

    /// Analyze `code` from offset 0 and ask for `(kind, register)` at `site`.
    fn lookup(
        code: &[u8],
        site: u32,
        kind: RegisterKind,
        register: u8,
    ) -> Result<ConstantValue, Unresolved> {
        let analysis = crate::analyze_entries(code, &[0]);
        constant_before(&analysis, ValueOptions::default(), site, kind, register)
    }

    fn tracked(
        code: &[u8],
        site: u32,
        kind: RegisterKind,
        register: u8,
        image_origin: Option<u32>,
    ) -> Result<TrackedValue, Unresolved> {
        tracked_with(code, site, kind, register, ValueOptions { image_origin })
    }

    fn tracked_with(
        code: &[u8],
        site: u32,
        kind: RegisterKind,
        register: u8,
        options: ValueOptions,
    ) -> Result<TrackedValue, Unresolved> {
        let analysis = crate::analyze_entries(code, &[0]);
        ConstantAnalysis::new(&analysis, options).before_value(site, kind, register)
    }

    fn tracked_with_relocations(
        code: &[u8],
        site: u32,
        kind: RegisterKind,
        register: u8,
        options: ValueOptions,
        relocations: Relocations,
    ) -> Result<TrackedValue, Unresolved> {
        let analysis = crate::analyze_entries_with(
            code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(relocations),
                ..crate::FlowOptions::default()
            },
        );
        ConstantAnalysis::new(&analysis, options).before_value(site, kind, register)
    }

    #[test]
    fn an_immediate_load_is_resolved_with_the_site_that_set_it() {
        // MOVE.L #32000,D0 ; MOVEQ #2,D1 ; RTS
        let code = [
            0x20, 0x3c, 0x00, 0x00, 0x7d, 0x00, // 0x00 MOVE.L #32000,D0
            0x72, 0x02, // 0x06 MOVEQ #2,D1
            0x4e, 0x75, // 0x08 RTS
        ];
        let d0 = lookup(&code, 8, RegisterKind::Data, 0).expect("D0 is known at the RTS");
        assert_eq!(d0.value, 32_000);
        assert_eq!(d0.site, 0, "the evidence is the instruction that set it");
        let d1 = lookup(&code, 8, RegisterKind::Data, 1).expect("D1 is known at the RTS");
        assert_eq!(d1.value, 2);
        assert_eq!(d1.site, 6);
    }

    #[test]
    fn indexed_sources_preserve_base_signed_index_width_and_displacement() {
        for (code, expected_base, index_address, index_register, index_bytes, displacement) in [
            (
                [0x20, 0x30, 0x10, 0xfe, 0x4e, 0x75],
                SymbolicLocation::RegisterRelative {
                    register: 0,
                    displacement: 0,
                },
                false,
                1,
                2,
                -2,
            ),
            (
                [0x20, 0x3b, 0xa8, 0x06, 0x4e, 0x75],
                SymbolicLocation::ImageRelative {
                    offset: 2,
                    runtime_address: Some(0x1002),
                },
                true,
                2,
                4,
                6,
            ),
        ] {
            let TrackedValue::Symbolic(value) =
                tracked(&code, 4, RegisterKind::Data, 0, Some(0x1000)).unwrap()
            else {
                panic!("indexed memory is not an exact number");
            };
            assert_eq!(
                value.location,
                SymbolicLocation::Indexed {
                    base: Box::new(expected_base),
                    index_address,
                    index_register,
                    index_bytes,
                    displacement,
                    read_site: 0,
                }
            );
        }
    }

    #[test]
    fn indexed_sources_survive_copy_and_wrapping_arithmetic() {
        // MOVE.L (-2,A0,D1.W),D0 ; MOVE.L D0,D2 ; SUBQ.L #1,D2 ; RTS.
        let code = [0x20, 0x30, 0x10, 0xfe, 0x24, 0x00, 0x53, 0x82, 0x4e, 0x75];
        let TrackedValue::Symbolic(value) = tracked(&code, 8, RegisterKind::Data, 2, None).unwrap()
        else {
            panic!("the copied read is symbolic");
        };
        assert_eq!(value.offset, u32::MAX);
        assert_eq!(value.evidence, vec![0, 4, 6]);
        assert!(matches!(
            value.location,
            SymbolicLocation::Indexed { read_site: 0, .. }
        ));
    }

    #[test]
    fn different_indexed_read_sites_do_not_join_unknown_register_snapshots() {
        let code = [
            0x4a, 0x41, 0x67, 0x06, 0x20, 0x30, 0x10, 0xfe, 0x60, 0x04, 0x20, 0x30, 0x10, 0xfe,
            0x4e, 0x75,
        ];
        assert_eq!(
            tracked(&code, 14, RegisterKind::Data, 0, None),
            Err(Unresolved::Join)
        );
    }

    #[test]
    fn scaled_full_and_truncated_index_extensions_do_not_establish_sources() {
        for extension in [0x1200_u16, 0x1100, 0x1400] {
            let [hi, lo] = extension.to_be_bytes();
            assert_eq!(
                tracked(
                    &[0x20, 0x30, hi, lo, 0x4e, 0x75],
                    4,
                    RegisterKind::Data,
                    0,
                    None
                ),
                Err(Unresolved::WriteNotValued)
            );
        }
        for code in [
            &[0x20, 0x30][..],
            &[0x20, 0x30, 0x10][..],
            &[0x4c, 0xd8, 0x03][..],
        ] {
            assert!(tracked(code, 0, RegisterKind::Data, 0, None).is_err());
        }
    }

    #[test]
    fn movem_long_uses_transfer_order_and_final_base_even_when_base_is_loaded() {
        // LEA $1000,A0 ; MOVEM.L (A0)+,D0/D2/A0/A1 ; RTS.
        let code = [
            0x41, 0xf9, 0x00, 0x00, 0x10, 0x00, 0x4c, 0xd8, 0x03, 0x05, 0x4e, 0x75,
        ];
        assert_eq!(
            lookup(&code, 10, RegisterKind::Address, 0).unwrap().value,
            0x1010
        );
        for (kind, register, byte_offset) in [
            (RegisterKind::Data, 0, 0),
            (RegisterKind::Data, 2, 4),
            (RegisterKind::Address, 1, 12),
        ] {
            let TrackedValue::Symbolic(value) = tracked(&code, 10, kind, register, None).unwrap()
            else {
                panic!("MOVEM slots are symbolic");
            };
            assert_eq!(value.subject, SymbolicSubject::Contents);
            assert_eq!(
                value.location,
                SymbolicLocation::MovemSlot {
                    base: Box::new(SymbolicLocation::RegisterPostincrement {
                        register: 0,
                        site: 6
                    }),
                    byte_offset,
                    read_site: 6,
                }
            );
        }
        assert_eq!(
            tracked(&code, 10, RegisterKind::Data, 1, None),
            Err(Unresolved::NoPredecessor)
        );
    }

    #[test]
    fn movem_words_sign_extend_data_and_address_registers() {
        // MOVEM.W (A0),D0/A1 ; RTS.
        let code = [0x4c, 0x90, 0x02, 0x01, 0x4e, 0x75];
        for (kind, register, byte_offset) in
            [(RegisterKind::Data, 0, 0), (RegisterKind::Address, 1, 2)]
        {
            let TrackedValue::Symbolic(value) = tracked(&code, 4, kind, register, None).unwrap()
            else {
                panic!("MOVEM word reads are symbolic");
            };
            assert_eq!(value.subject, SymbolicSubject::SignExtendedWord);
            assert!(
                matches!(value.location, SymbolicLocation::MovemSlot { byte_offset: offset, .. } if offset == byte_offset)
            );
        }
    }

    #[test]
    fn narrow_reads_preserve_old_high_bits_while_movea_sign_extends() {
        for (opcode, low_bytes) in [(0x10, 1), (0x30, 2)] {
            // MOVE.B/W (A0),D0 ; MOVE.L D0,D1 ; RTS.
            let code = [opcode, 0x10, 0x22, 0x00, 0x4e, 0x75];
            let TrackedValue::Symbolic(value) =
                tracked(&code, 4, RegisterKind::Data, 1, None).unwrap()
            else {
                panic!("narrow read is symbolic");
            };
            assert_eq!(
                value.subject,
                SymbolicSubject::PreserveHigh {
                    register: 0,
                    read_site: 0,
                    low_bytes
                }
            );
            assert_eq!(value.evidence, vec![0, 2]);
        }
        let TrackedValue::Symbolic(value) =
            tracked(&[0x32, 0x50, 0x4e, 0x75], 2, RegisterKind::Address, 1, None).unwrap()
        else {
            panic!("MOVEA.W is symbolic");
        };
        assert_eq!(value.subject, SymbolicSubject::SignExtendedWord);
    }

    #[test]
    fn copies_of_one_indexed_snapshot_survive_a_branch_join() {
        // Read ; TST.W D1 ; BEQ right ; MOVE.L D0,D2 ; BRA join ;
        // right: MOVE.L D0,D2 ; join: RTS.
        let code = [
            0x20, 0x30, 0x10, 0xfe, 0x4a, 0x41, 0x67, 0x04, 0x24, 0x00, 0x60, 0x02, 0x24, 0x00,
            0x4e, 0x75,
        ];
        let TrackedValue::Symbolic(value) =
            tracked(&code, 14, RegisterKind::Data, 2, None).unwrap()
        else {
            panic!("both copies describe the same read");
        };
        assert_eq!(value.evidence, vec![0, 8]);
    }

    #[test]
    fn different_movem_or_narrow_read_sites_refuse_a_join() {
        for read in [
            vec![0x4c, 0x90, 0x00, 0x01],
            vec![0x30, 0x10],
            vec![0x10, 0x10],
        ] {
            let mut code = vec![0x4a, 0x41, 0x67, (read.len() + 2) as u8];
            code.extend_from_slice(&read);
            code.extend([0x60, read.len() as u8]);
            code.extend_from_slice(&read);
            let site = code.len() as u32;
            code.extend([0x4e, 0x75]);
            assert_eq!(
                tracked(&code, site, RegisterKind::Data, 0, None),
                Err(Unresolved::Join)
            );
        }
    }

    #[test]
    fn new_symbolic_forms_keep_the_evidence_limit_and_call_clobber() {
        for read in [
            vec![0x20, 0x30, 0x10, 0xfe],
            vec![0x4c, 0x90, 0x00, 0x01],
            vec![0x30, 0x10],
        ] {
            let mut code = read.clone();
            for _ in 0..MAX_VALUE_EVIDENCE {
                code.extend([0x20, 0x00]);
            }
            let site = code.len() as u32;
            code.extend([0x4e, 0x75]);
            assert_eq!(
                tracked(&code, site, RegisterKind::Data, 0, None),
                Err(Unresolved::StepLimit)
            );
            let mut code = read;
            code.extend([0x4e, 0xae, 0xff, 0x3a]);
            let site = code.len() as u32;
            code.extend([0x4e, 0x75]);
            assert_eq!(
                tracked(&code, site, RegisterKind::Data, 0, None),
                Err(Unresolved::Call)
            );
        }
    }

    #[test]
    fn a_long_register_copy_carries_the_exact_value_and_both_evidence_sites() {
        // MOVEQ #7,D3 ; MOVE.L D3,D0 ; RTS
        let code = [0x76, 0x07, 0x20, 0x03, 0x4e, 0x75];
        let value = lookup(&code, 4, RegisterKind::Data, 0).expect("D0 is known");
        assert_eq!(value.value, 7);
        assert_eq!(value.site, 2, "the copy is the immediate producer");
        assert_eq!(value.evidence, vec![0, 2]);
    }

    #[test]
    fn a_long_address_register_copy_carries_an_exact_address() {
        // LEA $123456,A2 ; MOVEA.L A2,A1 ; RTS
        let code = [0x45, 0xf9, 0x00, 0x12, 0x34, 0x56, 0x22, 0x4a, 0x4e, 0x75];
        let value = lookup(&code, 8, RegisterKind::Address, 1).expect("A1 is known");
        assert_eq!(value.value, 0x12_3456);
        assert_eq!(value.site, 6);
        assert_eq!(value.evidence, vec![0, 6]);
    }

    #[test]
    fn a_memory_read_survives_additive_transformation_and_register_copy() {
        // MOVE.L (8,A5),D1 ; ADDQ.L #1,D1 ; MOVE.L D1,D2 ; RTS
        let code = [0x22, 0x2d, 0x00, 0x08, 0x52, 0x81, 0x24, 0x01, 0x4e, 0x75];
        let TrackedValue::Symbolic(value) = tracked(&code, 8, RegisterKind::Data, 2, None)
            .expect("D2 should retain the expression")
        else {
            panic!("D2 should not become exact");
        };
        assert_eq!(
            value.location,
            SymbolicLocation::RegisterRelative {
                register: 5,
                displacement: 8,
            }
        );
        assert_eq!(value.offset, 1);
        assert_eq!(value.site, 6);
        assert_eq!(value.evidence, vec![0, 4, 6]);
    }

    #[test]
    fn pc_relative_memory_keeps_image_and_runtime_coordinates() {
        // MOVE.L (6,PC),D0 ; RTS. The effective source offset is 8.
        let code = [0x20, 0x3a, 0x00, 0x06, 0x4e, 0x75];
        let TrackedValue::Symbolic(value) = tracked(&code, 4, RegisterKind::Data, 0, Some(0x1000))
            .expect("D0 should retain the PC-relative source")
        else {
            panic!("D0 should not become exact");
        };
        assert_eq!(
            value.location,
            SymbolicLocation::ImageRelative {
                offset: 8,
                runtime_address: Some(0x1008),
            }
        );
    }

    #[test]
    fn non_additive_arithmetic_refuses_a_symbolic_memory_value() {
        // MOVE.L (8,A5),D1 ; ANDI.L #$ff,D1 ; RTS
        let code = [
            0x22, 0x2d, 0x00, 0x08, 0x02, 0x81, 0x00, 0x00, 0x00, 0xff, 0x4e, 0x75,
        ];
        assert_eq!(
            tracked(&code, 10, RegisterKind::Data, 1, None),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn pc_relative_lea_and_address_arithmetic_keep_an_exact_address() {
        // LEA (6,PC),A1 -> 8 ; ADDQ.W #8,A1 ; SUBQ.W #1,A1 ;
        // ADDA.W #-3,A1 ; SUBA.W #4,A1 ; RTS
        // Address-register quick arithmetic always updates the whole register,
        // even when its encoded size is word. ADDA/SUBA sign-extend word
        // immediates before applying them to the whole address register.
        let code = [
            0x43, 0xfa, 0x00, 0x06, // 0x00 LEA (6,PC),A1 = 8
            0x50, 0x49, // 0x04 ADDQ.W #8,A1
            0x53, 0x49, // 0x06 SUBQ.W #1,A1
            0xd2, 0xfc, 0xff, 0xfd, // 0x08 ADDA.W #-3,A1
            0x92, 0xfc, 0x00, 0x04, // 0x0c SUBA.W #4,A1
            0x4e, 0x75, // 0x10 RTS
        ];
        let value = lookup(&code, 16, RegisterKind::Address, 1).expect("A1 is known");
        assert_eq!(value.value, 8);
        assert_eq!(value.site, 12);
        assert_eq!(value.evidence, vec![0, 4, 6, 8, 12]);
    }

    #[test]
    fn selected_long_data_arithmetic_is_exact_and_wraps_like_the_cpu() {
        let code = [
            0x20, 0x3c, 0xff, 0xff, 0xff, 0xf0, // 0x00 MOVE.L #$fffffff0,D0
            0x06, 0x80, 0x00, 0x00, 0x00, 0x20, // 0x06 ADDI.L #$20,D0 = $10
            0x04, 0x80, 0x00, 0x00, 0x00, 0x01, // 0x0c SUBI.L #1,D0 = $0f
            0x52, 0x80, // 0x12 ADDQ.L #1,D0 = $10
            0x53, 0x80, // 0x14 SUBQ.L #1,D0 = $0f
            0x00, 0x80, 0x00, 0x00, 0x01, 0x00, // 0x16 ORI.L #$100,D0 = $10f
            0x02, 0x80, 0x00, 0x00, 0x00, 0xff, // 0x1c ANDI.L #$ff,D0 = $0f
            0x0a, 0x80, 0x00, 0x00, 0x00, 0xff, // 0x22 EORI.L #$ff,D0 = $f0
            0x46, 0x80, // 0x28 NOT.L D0 = $ffffff0f
            0x44, 0x80, // 0x2a NEG.L D0 = $f1
            0x4e, 0x75, // 0x2c RTS
        ];
        let value = lookup(&code, 44, RegisterKind::Data, 0).expect("D0 is known");
        assert_eq!(value.value, 0xf1);
        assert_eq!(value.site, 42);
        assert_eq!(value.evidence, vec![0, 6, 12, 18, 20, 22, 28, 34, 40, 42]);
    }

    #[test]
    fn clr_long_establishes_zero_without_an_input_value() {
        let code = [0x42, 0x80, 0x4e, 0x75]; // CLR.L D0 ; RTS
        let value = lookup(&code, 2, RegisterKind::Data, 0).expect("D0 is known");
        assert_eq!(value.value, 0);
        assert_eq!(value.evidence, vec![0]);
    }

    #[test]
    fn arithmetic_on_an_unknown_input_stays_unknown() {
        // ADDI.L #1,D0 cannot invent the D0 value it adds to.
        let code = [0x06, 0x80, 0x00, 0x00, 0x00, 0x01, 0x4e, 0x75];
        assert_eq!(
            lookup(&code, 6, RegisterKind::Data, 0),
            Err(Unresolved::NoPredecessor)
        );
    }

    #[test]
    fn arithmetic_preserves_the_reason_its_input_is_unknown() {
        // MOVEQ #7,D0 ; BSR.S sub ; ADDI.L #1,D0 ; RTS ; sub: RTS
        // The addition cannot recover what the callee left in D0, and should
        // retain that useful diagnosis instead of calling itself an unknown
        // write.
        let code = [
            0x70, 0x07, 0x61, 0x08, 0x06, 0x80, 0x00, 0x00, 0x00, 0x01, 0x4e, 0x75, 0x4e, 0x75,
        ];
        assert_eq!(
            lookup(&code, 10, RegisterKind::Data, 0),
            Err(Unresolved::Call)
        );
    }

    #[test]
    fn equal_values_from_two_paths_survive_the_join_deterministically() {
        // TST.W D1 ; BEQ.S right ; MOVEQ #7,D0 ; BRA.S join ;
        // right: MOVEQ #7,D0 ; join: RTS
        let code = [
            0x4a, 0x41, 0x67, 0x04, 0x70, 0x07, 0x60, 0x02, 0x70, 0x07, 0x4e, 0x75,
        ];
        let value = lookup(&code, 10, RegisterKind::Data, 0).expect("both paths agree");
        assert_eq!(value.value, 7);
        assert_eq!(value.evidence, vec![4]);
    }

    #[test]
    fn equal_symbolic_values_from_two_paths_survive_the_join() {
        // TST.W D1 ; BEQ.S right ; MOVE.L (8,A5),D0 ; BRA.S join ;
        // right: MOVE.L (8,A5),D0 ; join: RTS
        let code = [
            0x4a, 0x41, 0x67, 0x06, 0x20, 0x2d, 0x00, 0x08, 0x60, 0x04, 0x20, 0x2d, 0x00, 0x08,
            0x4e, 0x75,
        ];
        let TrackedValue::Symbolic(value) = tracked(&code, 14, RegisterKind::Data, 0, None)
            .expect("both paths retain the same expression")
        else {
            panic!("the expression should not become exact");
        };
        assert_eq!(
            value.location,
            SymbolicLocation::RegisterRelative {
                register: 5,
                displacement: 8,
            }
        );
        assert_eq!(value.evidence, vec![4]);
    }

    #[test]
    fn an_unchanged_exact_value_converges_through_a_loop() {
        // MOVEQ #7,D0 ; loop: TST.W D1 ; BNE.S loop ; RTS
        let code = [0x70, 0x07, 0x4a, 0x41, 0x66, 0xfc, 0x4e, 0x75];
        let value = lookup(&code, 6, RegisterKind::Data, 0).expect("the loop preserves D0");
        assert_eq!(value.value, 7);
        assert_eq!(value.evidence, vec![0]);
    }

    #[test]
    fn a_bit_set_is_a_write_the_walk_stops_at() {
        // MOVEQ #2,D1 ; BSET #16,D1 — the review's real-report case: reporting
        // `2` here renders MEMF_CHIP for a register holding
        // MEMF_CHIP|MEMF_CLEAR. Adding a flag bit this way is idiomatic 68k.
        let code = [
            0x72, 0x02, // MOVEQ #2,D1
            0x08, 0xc1, 0x00, 0x10, // BSET #16,D1
            0x4e, 0x75, // RTS
        ];
        assert_eq!(
            lookup(&code, 6, RegisterKind::Data, 1),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn every_register_writing_form_stops_the_walk() {
        // One case per operand form the classification had to decide about.
        // Each fixture sets the register, then mangles it; a value surviving
        // to the end would be the stale one.
        for (name, code, kind, register, site) in [
            (
                "EXT.L D0",
                vec![0x70, 0x7f, 0x48, 0xc0, 0x4e, 0x75],
                RegisterKind::Data,
                0,
                4,
            ),
            (
                "SWAP D1",
                vec![0x72, 0x02, 0x48, 0x41, 0x4e, 0x75],
                RegisterKind::Data,
                1,
                4,
            ),
            (
                "SEQ D0",
                vec![0x70, 0x01, 0x57, 0xc0, 0x4e, 0x75],
                RegisterKind::Data,
                0,
                4,
            ),
            (
                "ADDX.L D2,D1",
                vec![0x72, 0x02, 0xd3, 0x82, 0x4e, 0x75],
                RegisterKind::Data,
                1,
                4,
            ),
            (
                "TAS D0",
                vec![0x70, 0x01, 0x4a, 0xc0, 0x4e, 0x75],
                RegisterKind::Data,
                0,
                4,
            ),
            (
                "NBCD D0",
                vec![0x70, 0x01, 0x48, 0x00, 0x4e, 0x75],
                RegisterKind::Data,
                0,
                4,
            ),
            (
                "MOVE SR,D0",
                vec![0x70, 0x01, 0x40, 0xc0, 0x4e, 0x75],
                RegisterKind::Data,
                0,
                4,
            ),
            (
                "UNLK A1",
                vec![0x22, 0x7c, 0x00, 0x00, 0x10, 0x00, 0x4e, 0x59, 0x4e, 0x75],
                RegisterKind::Address,
                1,
                8,
            ),
        ] {
            assert_eq!(
                lookup(&code, site, kind, register),
                Err(Unresolved::WriteNotValued),
                "{name}: a value survived a write to its own register"
            );
        }
    }

    #[test]
    fn a_function_entry_is_not_walked_through() {
        // Falling into an address that is also a seeded entry means control
        // can arrive from anywhere; what precedes it in address order is not
        // what precedes it in execution.
        let code = [
            0x72, 0x02, // 0x00 MOVEQ #2,D1
            0x4e, 0x71, // 0x02 NOP        <- also an entry
            0x4e, 0x75, // 0x04 RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0, 2]);
        assert_eq!(
            constant_before(&analysis, ValueOptions::default(), 4, RegisterKind::Data, 1),
            Err(Unresolved::FunctionEntry),
            "the walk crossed a function entry"
        );
    }

    #[test]
    fn an_unresolved_jump_in_the_function_refuses_every_value_in_it() {
        // JMP (A0) could land anywhere in this function, including between a
        // write and the site that reads it, and the flow graph cannot say
        // where. Refusing the whole function is the only answer it supports.
        let code = [
            0x72, 0x02, // 0x00 MOVEQ #2,D1
            0x4a, 0x40, // 0x02 TST.W D0
            0x67, 0x02, // 0x04 BEQ.S 0x08
            0x4e, 0xd0, // 0x06 JMP (A0)   <- unresolved
            0x4e, 0x71, // 0x08 NOP
            0x4e, 0x75, // 0x0a RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        assert!(!analysis.unresolved.is_empty(), "the fixture resolved");
        assert_eq!(
            constant_before(
                &analysis,
                ValueOptions::default(),
                0x0a,
                RegisterKind::Data,
                1
            ),
            Err(Unresolved::UnresolvedFlow),
            "a value was reported inside a function with unresolved flow"
        );
    }

    #[test]
    fn an_unresolved_indirect_call_uses_its_fallthrough_and_call_clobber() {
        // MOVEQ #7,D0 ; JSR (A0) ; MOVEQ #2,D1 ; RTS. The callee target is
        // unknown, but JSR still returns to the following instruction.
        let code = [0x70, 0x07, 0x4e, 0x90, 0x72, 0x02, 0x4e, 0x75];
        let analysis = crate::analyze_entries(&code, &[0]);
        assert!(!analysis.unresolved.is_empty(), "the fixture resolved");

        let before_call =
            constant_before(&analysis, ValueOptions::default(), 2, RegisterKind::Data, 0)
                .expect("the unresolved call should not poison earlier state");
        assert_eq!(before_call.value, 7);
        assert_eq!(
            constant_before(&analysis, ValueOptions::default(), 4, RegisterKind::Data, 0),
            Err(Unresolved::Call),
            "the unknown callee did not clobber its fallthrough state"
        );
        let after_call =
            constant_before(&analysis, ValueOptions::default(), 6, RegisterKind::Data, 1)
                .expect("a value established after the call should be visible");
        assert_eq!(after_call.value, 2);
    }

    #[test]
    fn an_indirect_call_that_can_enter_its_owner_refuses_the_owner_walk() {
        // MOVEQ #1,D0 ; LEA handler(PC),A0 ; JSR (A0) ; MOVEQ #2,D0 ;
        // handler: NOP ; RTS. The graph reaches handler only through the
        // fallthrough carrying 2, but the unresolved call can enter it with 1.
        let code = [
            0x70, 0x01, // 0x00 MOVEQ #1,D0
            0x41, 0xfa, 0x00, 0x06, // 0x02 LEA (6,PC),A0 -> 0x0a
            0x4e, 0x90, // 0x06 JSR (A0)
            0x70, 0x02, // 0x08 MOVEQ #2,D0
            0x4e, 0x71, // 0x0a NOP (handler)
            0x4e, 0x75, // 0x0c RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        assert!(analysis.unresolved.contains(&UnresolvedFlow {
            owner: 0,
            address: 6
        }));
        assert_eq!(
            constant_before(
                &analysis,
                ValueOptions::default(),
                0x0c,
                RegisterKind::Data,
                0,
            ),
            Err(Unresolved::UnresolvedFlow),
            "the missing call edge let the fallthrough value look exact"
        );
    }

    #[test]
    fn an_unresolved_call_in_one_owner_does_not_poison_its_shared_tail() {
        // Entry 0: MOVEQ #7,D0 ; shared: NOP ; RTS.
        // Entry 6: MOVEQ #7,D0 ; BEQ.S shared ; JSR (A0) ; RTS.
        // The second owner contains an unresolved call on its fallthrough path,
        // but both owners agree on D0 along the branch into the shared tail.
        let code = [
            0x70, 0x07, 0x4e, 0x71, 0x4e, 0x75, 0x70, 0x07, 0x67, 0xf8, 0x4e, 0x90, 0x4e, 0x75,
        ];
        let analysis = crate::analyze_entries(&code, &[0, 6]);
        assert!(
            analysis
                .unresolved
                .iter()
                .any(|flow| flow.owner == 6 && flow.address == 10),
            "the second owner did not retain its unresolved call"
        );
        let shared = constant_before(&analysis, ValueOptions::default(), 4, RegisterKind::Data, 0)
            .expect("the shared owners establish the same value");
        assert_eq!(shared.value, 7);
        assert_eq!(shared.evidence, vec![0]);
    }

    #[test]
    fn a_partial_write_does_not_establish_the_register() {
        // MOVE.W #1,D0 sets the low word only. Reporting `1` would answer for
        // 32 bits a write that touched 16.
        let code = [0x30, 0x3c, 0x00, 0x01, 0x4e, 0x75];
        assert_eq!(
            lookup(&code, 4, RegisterKind::Data, 0),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn an_exchange_invalidates_both_of_its_registers() {
        // MOVEQ #7,D0 ; EXG D0,D1 — after the swap D0 holds what D1 held, and
        // reporting 7 would be reporting the value the swap moved away.
        let code = [0x70, 0x07, 0xc1, 0x41, 0x4e, 0x75];
        assert_eq!(
            lookup(&code, 4, RegisterKind::Data, 0),
            Err(Unresolved::WriteNotValued)
        );
        assert_eq!(
            lookup(&code, 4, RegisterKind::Data, 1),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn a_postincrement_invalidates_the_register_it_walks() {
        // MOVEA.L #$1000,A1 ; MOVE.B (A1)+,D0 — A1 is $1001 at the RTS, and
        // the increment belongs to the addressing mode rather than to the
        // instruction's destination.
        let code = [
            0x22, 0x7c, 0x00, 0x00, 0x10, 0x00, // MOVEA.L #$1000,A1
            0x10, 0x19, // MOVE.B (A1)+,D0
            0x4e, 0x75, // RTS
        ];
        assert_eq!(
            lookup(&code, 8, RegisterKind::Address, 1),
            Err(Unresolved::WriteNotValued)
        );
        // The value it loaded is not knowable either, but D0 is not the point:
        // the point is that A1 stopped being $1000.
    }

    #[test]
    fn a_long_postincrement_read_keeps_its_source_and_invalidates_its_base() {
        // MOVE.L (A0)+,D0 ; RTS. D0 names the longword consumed at this site,
        // while A0 itself has changed and cannot retain a stale exact value.
        let code = [0x20, 0x18, 0x4e, 0x75];
        assert_eq!(
            tracked(&code, 2, RegisterKind::Data, 0, None),
            Ok(TrackedValue::Symbolic(SymbolicValue {
                subject: SymbolicSubject::Contents,
                location: SymbolicLocation::RegisterPostincrement {
                    register: 0,
                    site: 0,
                },
                offset: 0,
                site: 0,
                evidence: vec![0],
            }))
        );
        assert_eq!(
            tracked(&code, 2, RegisterKind::Address, 0, None),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn a_long_predecrement_read_keeps_its_source_and_invalidates_its_base() {
        // MOVE.L -(A0),D0 ; RTS. The source is the longword at A0-4, while A0
        // itself changes and cannot retain a stale value.
        let code = [0x20, 0x20, 0x4e, 0x75];
        assert_eq!(
            tracked(&code, 2, RegisterKind::Data, 0, None),
            Ok(TrackedValue::Symbolic(SymbolicValue {
                subject: SymbolicSubject::Contents,
                location: SymbolicLocation::RegisterPredecrement {
                    register: 0,
                    site: 0,
                },
                offset: 0,
                site: 0,
                evidence: vec![0],
            }))
        );
        assert_eq!(
            tracked(&code, 2, RegisterKind::Address, 0, None),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn a_predecrement_symbolic_read_survives_a_register_copy() {
        // MOVE.L -(A0),D0 ; MOVE.L D0,D1 ; RTS
        let code = [0x20, 0x20, 0x22, 0x00, 0x4e, 0x75];
        let TrackedValue::Symbolic(value) =
            tracked(&code, 4, RegisterKind::Data, 1, None).expect("D1 keeps the source")
        else {
            panic!("the copied source should remain symbolic");
        };
        assert_eq!(
            value.location,
            SymbolicLocation::RegisterPredecrement {
                register: 0,
                site: 0,
            }
        );
        assert_eq!(value.site, 2);
        assert_eq!(value.evidence, vec![0, 2]);
    }

    #[test]
    fn predecrement_reads_at_different_sites_do_not_join() {
        // TST.W D1 ; BEQ read2 ; read1: MOVE.L -(A0),D0 ; BRA join ;
        // read2: MOVE.L -(A0),D0 ; join: RTS.
        let code = [
            0x4a, 0x41, 0x67, 0x04, 0x20, 0x20, 0x60, 0x02, 0x20, 0x20, 0x4e, 0x75,
        ];
        assert_eq!(
            tracked(&code, 10, RegisterKind::Data, 0, None),
            Err(Unresolved::Join)
        );
    }

    #[test]
    fn a_narrow_predecrement_load_names_the_preserved_high_bits() {
        // MOVE.W -(A0),D0 ; RTS leaves half of D0 caller-owned.
        let TrackedValue::Symbolic(value) =
            tracked(&[0x30, 0x20, 0x4e, 0x75], 2, RegisterKind::Data, 0, None).unwrap()
        else {
            panic!("the narrow read is symbolic");
        };
        assert_eq!(
            value.subject,
            SymbolicSubject::PreserveHigh {
                register: 0,
                read_site: 0,
                low_bytes: 2,
            }
        );
        // A truncated MOVE opcode establishes no source at all.
        assert_eq!(
            tracked(&[0x20], 0, RegisterKind::Data, 0, None),
            Err(Unresolved::NotDecoded)
        );
    }

    #[test]
    fn postincrement_reads_at_different_sites_do_not_join() {
        // TST.W D1 ; BEQ read2 ; read1: MOVE.L (A0)+,D0 ; BRA join ;
        // read2: MOVE.L (A0)+,D0 ; join: RTS.
        let code = [
            0x4a, 0x41, 0x67, 0x04, 0x20, 0x18, 0x60, 0x02, 0x20, 0x18, 0x4e, 0x75,
        ];
        assert_eq!(
            tracked(&code, 10, RegisterKind::Data, 0, None),
            Err(Unresolved::Join)
        );
    }

    #[test]
    fn a_predecrement_invalidates_its_register_too() {
        // MOVEA.L #$1000,A1 ; MOVE.B D0,-(A1)
        let code = [
            0x22, 0x7c, 0x00, 0x00, 0x10, 0x00, // MOVEA.L #$1000,A1
            0x13, 0x00, // MOVE.B D0,-(A1)
            0x4e, 0x75, // RTS
        ];
        assert_eq!(
            lookup(&code, 8, RegisterKind::Address, 1),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn a_negative_moveq_keeps_its_sign_extension() {
        // MOVEQ #-1,D0 leaves 0xffffffff, and reporting 0xff would be a
        // different claim about the register.
        let code = [0x70, 0xff, 0x4e, 0x75];
        let value = lookup(&code, 2, RegisterKind::Data, 0).expect("D0 is known");
        assert_eq!(value.value, 0xffff_ffff);
    }

    #[test]
    fn a_later_unknowable_write_hides_an_earlier_constant() {
        // MOVE.L #1,D0 ; MOVE.L (A0),D0 ; RTS — the second write is what
        // reaches the end, and its value is not knowable here.
        let code = [
            0x20, 0x3c, 0x00, 0x00, 0x00, 0x01, // 0x00 MOVE.L #1,D0
            0x20, 0x10, // 0x06 MOVE.L (A0),D0
            0x4e, 0x75, // 0x08 RTS
        ];
        assert_eq!(
            lookup(&code, 8, RegisterKind::Data, 0),
            Err(Unresolved::WriteNotValued),
            "a register copy is a write this tracker cannot value, not a skip"
        );
    }

    #[test]
    fn a_call_stops_the_walk_because_a_callee_may_clobber_anything() {
        // MOVEQ #7,D0 ; BSR.S sub ; RTS ; sub: RTS
        let code = [
            0x70, 0x07, // 0x00 MOVEQ #7,D0
            0x61, 0x02, // 0x02 BSR.S 0x06
            0x4e, 0x75, // 0x04 RTS
            0x4e, 0x75, // 0x06 RTS
        ];
        assert_eq!(
            lookup(&code, 4, RegisterKind::Data, 0),
            Err(Unresolved::Call),
            "a value from before a call was reported as still live"
        );
    }

    #[test]
    fn a_join_stops_the_walk_because_the_value_depends_on_the_path() {
        // The two paths establish different values, so the join must retain
        // neither rather than picking whichever block the worklist saw first.
        let code = [
            0x4a, 0x40, // 0x00 TST.W D0
            0x67, 0x04, // 0x02 BEQ.S 0x08
            0x70, 0x01, // 0x04 MOVEQ #1,D0
            0x60, 0x02, // 0x06 BRA.S 0x0a
            0x70, 0x02, // 0x08 MOVEQ #2,D0
            0x4e, 0x75, // 0x0a RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        assert_eq!(
            constant_before(
                &analysis,
                ValueOptions::default(),
                10,
                RegisterKind::Data,
                0
            ),
            Err(Unresolved::Join),
            "one path's value survived an incompatible join"
        );
    }

    #[test]
    fn a_symbolic_path_cannot_become_exact_at_a_join() {
        // TST.W D1 ; BEQ.S symbolic ; MOVEQ #7,D0 ; BRA.S join ;
        // symbolic: MOVE.L (A0),D0 ; join: RTS
        let code = [
            0x4a, 0x41, 0x67, 0x04, 0x70, 0x07, 0x60, 0x02, 0x20, 0x10, 0x4e, 0x75,
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        assert_eq!(
            constant_before(
                &analysis,
                ValueOptions::default(),
                10,
                RegisterKind::Data,
                0
            ),
            Err(Unresolved::Join)
        );
    }

    #[test]
    fn a_site_with_nothing_before_it_says_so() {
        // The first instruction of an entry has no recorded predecessor, which
        // is a different answer from "something before it was unreadable".
        let code = [0x70, 0x07, 0x4e, 0x75];
        assert_eq!(
            lookup(&code, 0, RegisterKind::Data, 0),
            Err(Unresolved::NoPredecessor)
        );
    }

    #[test]
    fn an_offset_that_is_not_an_instruction_says_so() {
        // Offset 1 is the second byte of MOVEQ, not a site at all. Answering
        // anything about it would be answering about code nobody decoded.
        let code = [0x70, 0x07, 0x4e, 0x75];
        assert_eq!(
            lookup(&code, 1, RegisterKind::Data, 0),
            Err(Unresolved::NotDecoded)
        );
    }

    #[test]
    fn a_long_copy_chain_stops_at_the_evidence_cap() {
        // Each copy is evidence for the resulting value. The chain is bounded
        // independently of the worklist so a hostile copy train cannot make
        // one report fact grow without limit.
        let mut code = vec![0x70, 0x07]; // MOVEQ #7,D0
        for index in 0..MAX_VALUE_EVIDENCE {
            code.extend_from_slice(if index % 2 == 0 {
                &[0x22, 0x00] // MOVE.L D0,D1
            } else {
                &[0x20, 0x01] // MOVE.L D1,D0
            });
        }
        let site = u32::try_from(code.len()).expect("fixture fits in u32");
        code.extend_from_slice(&[0x4e, 0x75]); // RTS
        let register = if MAX_VALUE_EVIDENCE.is_multiple_of(2) {
            0
        } else {
            1
        };
        assert_eq!(
            lookup(&code, site, RegisterKind::Data, register),
            Err(Unresolved::StepLimit)
        );
    }

    #[test]
    fn every_reason_has_a_distinct_label() {
        let mut labels: Vec<&str> = Unresolved::all().iter().map(|kind| kind.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count, "two reasons share a label");
    }

    #[test]
    fn the_label_matches_the_serialized_tag() {
        // The text renderers print `label()` and consumers read the JSON tag;
        // if they drift, two names exist for the same reason.
        for reason in Unresolved::all() {
            let json = serde_json::to_string(reason).expect("a unit variant serializes");
            assert_eq!(json, format!("\"{}\"", reason.label()));
        }
    }

    /// `LEA $1c.L,A0 ; RTS` — one address-bearing longword operand at offset 2.
    const LEA_ABSOLUTE: [u8; 8] = [0x41, 0xf9, 0x00, 0x00, 0x00, 0x1c, 0x4e, 0x75];

    /// `MOVE.L $1c.L,D0 ; RTS` — the same operand as a memory source.
    const LOAD_ABSOLUTE: [u8; 8] = [0x20, 0x39, 0x00, 0x00, 0x00, 0x1c, 0x4e, 0x75];

    fn relocations(hunk: u32, records: &[(u32, u32, u32)]) -> Relocations {
        Relocations::new(
            hunk,
            records
                .iter()
                .map(
                    |&(patched, target_hunk, target_offset)| crate::control_flow::Relocation {
                        patched,
                        target_hunk,
                        target_offset,
                    },
                )
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn an_address_relocated_into_another_hunk_is_never_a_number() {
        let relocations = relocations(0, &[(2, 1, 0x1c)]);
        let value = tracked_with_relocations(
            &LEA_ABSOLUTE,
            6,
            RegisterKind::Address,
            0,
            ValueOptions {
                image_origin: Some(0x2_1000),
            },
            relocations,
        )
        .expect("the relocation names the address");
        let TrackedValue::Symbolic(symbolic) = value else {
            panic!("a cross-hunk address was flattened into a number");
        };
        assert_eq!(symbolic.subject, SymbolicSubject::Address);
        assert_eq!(
            symbolic.location,
            SymbolicLocation::HunkRelative {
                hunk: 1,
                offset: 0x1c
            }
        );
        assert_eq!(symbolic.offset, 0);
        assert_eq!(symbolic.evidence, vec![0]);
    }

    #[test]
    fn an_address_relocated_into_this_hunk_is_the_mapped_runtime_address() {
        // The stored longword is an offset, so a mapped image turns it into an
        // address; without the record the same bytes read as the address
        // itself, which is the misreading this exists to prevent.
        let relocations = relocations(0, &[(2, 0, 0x1c)]);
        let options = ValueOptions {
            image_origin: Some(0x2_1000),
        };
        let relocated = tracked_with_relocations(
            &LEA_ABSOLUTE,
            6,
            RegisterKind::Address,
            0,
            options,
            relocations,
        )
        .expect("a same-hunk relocation still yields a number");
        assert_eq!(
            relocated,
            TrackedValue::Exact(ConstantValue {
                value: 0x2_101c,
                site: 0,
                evidence: vec![0],
            })
        );
        let unrelocated = tracked_with(
            &LEA_ABSOLUTE,
            6,
            RegisterKind::Address,
            0,
            ValueOptions {
                image_origin: Some(0x2_1000),
            },
        )
        .expect("an encoded absolute address is a number");
        assert_eq!(
            unrelocated,
            TrackedValue::Exact(ConstantValue {
                value: 0x1c,
                site: 0,
                evidence: vec![0],
            })
        );
    }

    #[test]
    fn a_hunk_offset_without_a_mapped_origin_stays_in_the_analysis_coordinate() {
        let relocations = relocations(0, &[(2, 0, 0x1c)]);
        let value = tracked_with_relocations(
            &LEA_ABSOLUTE,
            6,
            RegisterKind::Address,
            0,
            ValueOptions { image_origin: None },
            relocations,
        )
        .expect("the offset is the coordinate this analysis speaks");
        assert_eq!(
            value,
            TrackedValue::Exact(ConstantValue {
                value: 0x1c,
                site: 0,
                evidence: vec![0],
            })
        );
    }

    #[test]
    fn an_overflowing_same_hunk_runtime_mapping_is_refused() {
        let relocations = relocations(0, &[(2, 0, 0x1c)]);
        assert_eq!(
            tracked_with_relocations(
                &LEA_ABSOLUTE,
                6,
                RegisterKind::Address,
                0,
                ValueOptions {
                    image_origin: Some(0xffff_fff0),
                },
                relocations,
            ),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn an_overflowing_symbolic_runtime_mapping_keeps_only_the_image_offset() {
        let relocations = relocations(0, &[(2, 0, 0x1c)]);
        let value = tracked_with_relocations(
            &LOAD_ABSOLUTE,
            6,
            RegisterKind::Data,
            0,
            ValueOptions {
                image_origin: Some(0xffff_fff0),
            },
            relocations,
        )
        .expect("the hunk-relative source remains describable");
        let TrackedValue::Symbolic(symbolic) = value else {
            panic!("a memory read was given a numeric value");
        };
        assert_eq!(
            symbolic.location,
            SymbolicLocation::ImageRelative {
                offset: 0x1c,
                runtime_address: None,
            }
        );
    }

    #[test]
    fn an_underflowing_pc_relative_address_is_refused() {
        // LEA (-4,PC),A0 has a PC base of 2 and therefore cannot be expressed
        // in the analysis' unsigned image coordinate.
        let code = [0x41, 0xfa, 0xff, 0xfc, 0x4e, 0x75];
        assert_eq!(
            tracked(&code, 4, RegisterKind::Address, 0, Some(0x1000)),
            Err(Unresolved::WriteNotValued)
        );
    }

    #[test]
    fn movem_and_narrow_absolute_reads_use_the_operand_relocation() {
        for (code, patch, movem) in [
            (
                vec![0x4c, 0xf9, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x4e, 0x75],
                4,
                true,
            ),
            (
                vec![0x30, 0x39, 0x00, 0x00, 0x00, 0x1c, 0x4e, 0x75],
                2,
                false,
            ),
        ] {
            let site = code.len() as u32 - 2;
            let value = tracked_with_relocations(
                &code,
                site,
                RegisterKind::Data,
                0,
                ValueOptions::default(),
                relocations(0, &[(patch, 1, 0x1c)]),
            )
            .unwrap();
            let TrackedValue::Symbolic(value) = value else {
                panic!("relocated read is symbolic");
            };
            let expected = SymbolicLocation::HunkRelative {
                hunk: 1,
                offset: 0x1c,
            };
            if movem {
                assert_eq!(
                    value.location,
                    SymbolicLocation::MovemSlot {
                        base: Box::new(expected),
                        byte_offset: 0,
                        read_site: 0,
                    }
                );
            } else {
                assert_eq!(value.location, expected);
                assert!(matches!(
                    value.subject,
                    SymbolicSubject::PreserveHigh { low_bytes: 2, .. }
                ));
            }
        }
    }

    #[test]
    fn a_relocated_memory_source_names_its_hunk_rather_than_an_absolute_address() {
        for (record, expected) in [
            (
                (2, 1, 0x1c),
                SymbolicLocation::HunkRelative {
                    hunk: 1,
                    offset: 0x1c,
                },
            ),
            (
                (2, 0, 0x1c),
                SymbolicLocation::ImageRelative {
                    offset: 0x1c,
                    runtime_address: Some(0x2_101c),
                },
            ),
        ] {
            let relocations = relocations(0, &[record]);
            let value = tracked_with_relocations(
                &LOAD_ABSOLUTE,
                6,
                RegisterKind::Data,
                0,
                ValueOptions {
                    image_origin: Some(0x2_1000),
                },
                relocations,
            )
            .expect("the source is describable");
            let TrackedValue::Symbolic(symbolic) = value else {
                panic!("a memory read was given a numeric value");
            };
            assert_eq!(symbolic.subject, SymbolicSubject::Contents);
            assert_eq!(symbolic.location, expected);
        }
    }

    #[test]
    fn an_unpatched_absolute_source_is_still_absolute() {
        let relocations = relocations(0, &[]);
        let value = tracked_with_relocations(
            &LOAD_ABSOLUTE,
            6,
            RegisterKind::Data,
            0,
            ValueOptions {
                image_origin: Some(0x2_1000),
            },
            relocations,
        )
        .expect("the source is describable");
        let TrackedValue::Symbolic(symbolic) = value else {
            panic!("a memory read was given a numeric value");
        };
        assert_eq!(
            symbolic.location,
            SymbolicLocation::Absolute { address: 0x1c }
        );
    }

    #[test]
    fn a_relocated_immediate_is_an_address_rather_than_an_amount() {
        // MOVEQ #1,D0 ; ADDI.L #$1c,D0 ; RTS — with the addend patched, `$1c`
        // names a hunk, so adding it would produce a number meaning nothing.
        let code = [
            0x70, 0x01, // 0x00 MOVEQ #1,D0
            0x06, 0x80, 0x00, 0x00, 0x00, 0x1c, // 0x02 ADDI.L #$1c,D0
            0x4e, 0x75, // 0x08 RTS
        ];
        let relocations = relocations(0, &[(4, 1, 0x1c)]);
        assert_eq!(
            tracked_with_relocations(
                &code,
                8,
                RegisterKind::Data,
                0,
                ValueOptions { image_origin: None },
                relocations,
            ),
            Err(Unresolved::WriteNotValued)
        );
        assert_eq!(
            tracked_with(&code, 8, RegisterKind::Data, 0, ValueOptions::default()),
            Ok(TrackedValue::Exact(ConstantValue {
                value: 0x1d,
                site: 2,
                evidence: vec![0, 2],
            })),
            "without the record the same bytes are an ordinary addition"
        );
    }

    #[test]
    fn a_record_that_does_not_describe_the_operand_leaves_it_encoded() {
        // Two malformed shapes, both of which must fall back to the encoded
        // reading rather than assert an address the image does not support:
        // a record patching the opcode word, and one whose target offset
        // contradicts the longword actually stored there.
        for record in [(0, 1, 0x1c), (2, 1, 0x99)] {
            let relocations = relocations(0, &[record]);
            assert_eq!(
                tracked_with_relocations(
                    &LEA_ABSOLUTE,
                    6,
                    RegisterKind::Address,
                    0,
                    ValueOptions { image_origin: None },
                    relocations,
                ),
                Ok(TrackedValue::Exact(ConstantValue {
                    value: 0x1c,
                    site: 0,
                    evidence: vec![0],
                })),
                "{record:?} was allowed to rename an operand it does not cover"
            );
        }
    }

    #[test]
    fn an_address_and_the_contents_at_it_do_not_join() {
        // Both paths reach A0 with the same location, but one carries the
        // pointer and the other the longword stored there.
        let code = [
            0x67, 0x08, // 0x00 BEQ.B 0x0a
            0x20, 0x79, 0x00, 0x00, 0x00, 0x1c, // 0x02 MOVEA.L $1c.L,A0
            0x60, 0x06, // 0x08 BRA.B 0x10
            0x41, 0xf9, 0x00, 0x00, 0x00, 0x1c, // 0x0a LEA $1c.L,A0
            0x4e, 0x75, // 0x10 RTS
        ];
        let relocations = relocations(0, &[(4, 1, 0x1c), (0x0c, 1, 0x1c)]);
        assert_eq!(
            tracked_with_relocations(
                &code,
                0x10,
                RegisterKind::Address,
                0,
                ValueOptions { image_origin: None },
                relocations,
            ),
            Err(Unresolved::Join)
        );
    }

    #[test]
    fn a_register_name_parses_only_in_its_own_space() {
        assert_eq!(parse_register("d0"), Some((RegisterKind::Data, 0)));
        assert_eq!(parse_register("A6"), Some((RegisterKind::Address, 6)));
        assert_eq!(parse_register(" d1 "), Some((RegisterKind::Data, 1)));
        for bad in ["d8", "a9", "x0", "d", "d10", "sp"] {
            assert_eq!(parse_register(bad), None, "{bad:?} parsed");
        }
    }
}
