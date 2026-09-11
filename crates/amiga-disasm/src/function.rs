//! Bounded inference of MC68000 function interfaces and stack frames.
//!
//! The analysis reports only properties supported by every owned path it can
//! inspect. Register inputs are reads reached before a definition, outputs are
//! registers defined on every ordinary return path, and joins intersect the
//! set of definitions. Unsupported code or exhausted ownership clears the
//! register claims instead of turning a partial walk into a prototype.

use std::collections::{BTreeMap, BTreeSet};

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Operands, Size};
use m68000::isa::Isa;
use serde::Serialize;

use crate::constants::RegisterKind;
use crate::control_flow::{ControlFlowAnalysis, DecodedInstruction, ExternalKind, FlowKind};
use crate::dataflow::{self, Domain};
use crate::globals::{AccessKind, OperandCoverage, for_each_operand_access};

const GENERAL_REGISTERS: u16 = 0x7fff;
const GENERAL_REGISTER_LANES: u64 = (1_u64 << 60) - 1;
const MAX_SIGNATURE_EVIDENCE: usize = 32;

/// One MC68000 general register.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FunctionRegister {
    pub kind: RegisterKind,
    pub index: u8,
}

impl FunctionRegister {
    fn from_bit(bit: u8) -> Self {
        if bit < 8 {
            Self {
                kind: RegisterKind::Data,
                index: bit,
            }
        } else {
            Self {
                kind: RegisterKind::Address,
                index: bit - 8,
            }
        }
    }

    /// Conventional assembly spelling (`D0` or `A2`).
    #[must_use]
    pub fn label(self) -> String {
        let prefix = match self.kind {
            RegisterKind::Data => 'D',
            RegisterKind::Address => 'A',
        };
        format!("{prefix}{}", self.index)
    }
}

/// One register probably supplied by the caller.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FunctionInput {
    pub register: FunctionRegister,
    /// Byte lanes supplied by the caller. Bit zero is the least-significant
    /// byte; address-register inputs always carry all four lanes.
    pub lanes: RegisterLanes,
    /// The register formed a memory effective address before being defined.
    pub pointer: bool,
}

/// Byte lanes of one 32-bit MC68000 register value.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RegisterLanes(u8);

impl RegisterLanes {
    pub const BYTE: Self = Self(0b0001);
    pub const WORD: Self = Self(0b0011);
    pub const LONG: Self = Self(0b1111);

    /// Four-bit mask from least- to most-significant byte.
    pub const fn bits(self) -> u8 {
        self.0
    }

    const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::LONG.0)
    }
}

/// One register value consistently established on every ordinary return.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FunctionOutput {
    pub register: FunctionRegister,
    /// Lanes established by the function on every return path.
    pub lanes: RegisterLanes,
}

/// How a function establishes its stack frame.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FrameStyle {
    /// `LINK An,#-n`, normally with `UNLK An` on return.
    Link { register: u8, local_bytes: u32 },
    /// An explicit decrement of A7 without `LINK`.
    StackPointer { local_bytes: u32 },
    /// Different bounded paths establish different A7 depths. The maximum
    /// local allocation is known, but a slot after a divergent join is not.
    PathDependent { maximum_local_bytes: u32 },
    /// A dynamic A7 write, an unbalanced return, or an exhausted walk prevents
    /// a bounded frame description.
    Unknown,
    /// No local stack allocation was recognized.
    Frameless,
}

/// Return instruction shape shared by every return, or `mixed` when paths
/// disagree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionReturn {
    None,
    Rts,
    Rte,
    Rtr,
    Mixed,
}

/// Whether one stack slot is a caller argument or a local allocation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StackSlotKind {
    Argument,
    Local,
}

/// One stack or frame-pointer-relative slot used by a function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StackSlot {
    pub kind: StackSlotKind,
    /// Offset in the entry frame: arguments are measured from the caller's
    /// stack pointer, locals from the established frame base.
    pub offset: i32,
    pub size: Option<u8>,
    pub access: AccessKind,
}

/// One conservative, register-oriented function interface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FunctionSignature {
    pub entry: u32,
    /// False when ownership, decoding, or the bounded worklist was incomplete.
    /// In that state register claims are empty, while independently recognized
    /// frame and return shapes remain available.
    pub complete: bool,
    pub inputs: Vec<FunctionInput>,
    pub outputs: Vec<FunctionOutput>,
    pub clobbered: Vec<FunctionRegister>,
    pub preserved: Vec<FunctionRegister>,
    pub frame: FrameStyle,
    pub stack_slots: Vec<StackSlot>,
    pub returns: FunctionReturn,
    pub leaf: bool,
    pub tail_call: bool,
    /// Bounded instruction evidence in address order.
    pub evidence: Vec<u32>,
    pub evidence_total: usize,
}

impl FunctionSignature {
    /// Compact register-oriented prototype. The supplied name is presentation
    /// text; callers remain responsible for escaping user-supplied names.
    #[must_use]
    pub fn prototype(&self, name: &str) -> String {
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                let register = input.register.label();
                if input.pointer {
                    format!("{register}: ptr")
                } else {
                    render_register_lanes(&register, input.lanes)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let outputs = self
            .outputs
            .iter()
            .map(|output| render_register_lanes(&output.register.label(), output.lanes))
            .collect::<Vec<_>>()
            .join(", ");
        if outputs.is_empty() {
            format!("{name}({inputs})")
        } else {
            format!("{name}({inputs}) -> {outputs}")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Defined(u64);

impl Domain for Defined {
    fn join(&mut self, incoming: &Self) -> bool {
        let joined = self.0 & incoming.0;
        let changed = joined != self.0;
        self.0 = joined;
        changed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StackPosition {
    /// Bytes below A7 at function entry. Positive values grow downward.
    depth: i32,
    /// Bytes reserved explicitly for locals, excluding saved registers and
    /// transient pushes.
    locals: i32,
    /// Greatest local allocation seen on this path.
    peak_locals: i32,
    /// Paths with equal current coordinates reached them through different
    /// maximum allocations.
    path_dependent_frame: bool,
    /// A `LINK` restores these coordinates at its matching `UNLK`.
    link: Option<LinkState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkState {
    register: u8,
    depth: i32,
    locals: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StackDepth {
    Exact(StackPosition),
    /// Two bounded incoming paths disagree.
    PathDependent,
    /// A dynamic write or arithmetic overflow destroyed the coordinate.
    Unknown,
}

impl Domain for StackDepth {
    fn join(&mut self, incoming: &Self) -> bool {
        let joined = match (*self, *incoming) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::PathDependent, _) | (_, Self::PathDependent) => Self::PathDependent,
            (Self::Exact(left), Self::Exact(right))
                if left.depth == right.depth
                    && left.locals == right.locals
                    && left.link == right.link =>
            {
                Self::Exact(StackPosition {
                    depth: left.depth,
                    locals: left.locals,
                    peak_locals: left.peak_locals.max(right.peak_locals),
                    path_dependent_frame: left.path_dependent_frame
                        || right.path_dependent_frame
                        || left.peak_locals != right.peak_locals,
                    link: left.link,
                })
            }
            (Self::Exact(_), Self::Exact(_)) => Self::PathDependent,
        };
        let changed = joined != *self;
        *self = joined;
        changed
    }
}

struct StackAnalysis {
    before: BTreeMap<u32, StackDepth>,
    frame: FrameStyle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Preservation {
    original: u16,
    saved: u16,
}

impl Domain for Preservation {
    fn join(&mut self, incoming: &Self) -> bool {
        let joined = Self {
            original: self.original & incoming.original,
            saved: self.saved & incoming.saved,
        };
        let changed = joined != *self;
        *self = joined;
        changed
    }
}

#[derive(Clone, Copy, Debug)]
struct Effects {
    reads: u64,
    writes: u64,
    meaningful_writes: u64,
    pointers: u16,
    complete: bool,
}

#[derive(Clone, Copy, Debug)]
struct InstructionEffects {
    registers: Effects,
    saved: u16,
    restored: u16,
    stack: StackAdjustment,
}

impl InstructionEffects {
    const CONSERVATIVE: Self = Self {
        registers: Effects {
            reads: u64::MAX,
            writes: u64::MAX,
            meaningful_writes: 0,
            pointers: u16::MAX,
            complete: false,
        },
        saved: 0,
        restored: 0,
        stack: StackAdjustment::Unknown,
    };
}

impl Default for Effects {
    fn default() -> Self {
        Self {
            reads: 0,
            writes: 0,
            meaningful_writes: 0,
            pointers: 0,
            complete: true,
        }
    }
}

impl Effects {
    fn read(&mut self, bit: u8, size: Option<Size>, pointer: bool) {
        self.reads |= register_lanes(bit, size);
        self.pointers |= u16::from(pointer) << bit;
    }

    fn write(&mut self, bit: u8) {
        self.write_lanes(bit, None);
    }

    fn write_lanes(&mut self, bit: u8, size: Option<Size>) {
        let lanes = register_lanes(bit, size);
        self.writes |= lanes;
        self.meaningful_writes |= lanes;
    }

    fn clobber(&mut self, mask: u16) {
        self.writes |= lanes_for_registers(mask);
    }
}

fn render_register_lanes(register: &str, lanes: RegisterLanes) -> String {
    match lanes {
        RegisterLanes::BYTE => format!("{register}.b"),
        RegisterLanes::WORD => format!("{register}.w"),
        RegisterLanes::LONG => register.to_owned(),
        _ => format!("{register}[lanes=0x{:x}]", lanes.bits()),
    }
}

/// Infer one signature for every function entry, ordered by entry.
#[must_use]
pub fn function_signatures(analysis: &ControlFlowAnalysis) -> Vec<FunctionSignature> {
    let effects: BTreeMap<u32, InstructionEffects> = analysis
        .instructions
        .values()
        .map(|instruction| (instruction.address, instruction_effects(instruction)))
        .collect();
    analysis
        .functions
        .iter()
        .map(|entry| function_signature(analysis, &effects, *entry))
        .collect()
}

fn function_signature(
    analysis: &ControlFlowAnalysis,
    effects: &BTreeMap<u32, InstructionEffects>,
    entry: u32,
) -> FunctionSignature {
    let tail_targets: BTreeSet<u32> = analysis
        .flows
        .iter()
        .filter(|flow| {
            flow.owner == entry
                && flow.kind == FlowKind::Branch
                && flow.target != entry
                && analysis.functions.contains(&flow.target)
                && analysis
                    .instructions
                    .get(&flow.site)
                    .is_some_and(|instruction| {
                        Isa::from(instruction.instruction.opcode) == Isa::Jmp
                    })
        })
        .map(|flow| flow.target)
        .collect();
    let owned: Vec<&DecodedInstruction> = analysis
        .instructions
        .values()
        .filter(|instruction| {
            instruction.owners.contains(&entry)
                && !belongs_to_tail_target(instruction, &tail_targets)
        })
        .collect();
    let ownership_complete = owned
        .iter()
        .all(|instruction| instruction.owner_total == instruction.owners.len());
    let mut effects_complete = true;
    let mut all_writes = 0_u16;
    for instruction in &owned {
        let effect = effects_for(effects, instruction).registers;
        effects_complete &= effect.complete;
        all_writes |= registers_for_lanes(effect.writes);
    }

    let tail_call = has_tail_call(analysis, entry, &owned);
    let return_sites: Vec<(u32, FunctionReturn)> = owned
        .iter()
        .filter_map(|instruction| {
            return_kind(Isa::from(instruction.instruction.opcode))
                .map(|kind| (instruction.address, kind))
        })
        .collect();
    let preservation_walk = dataflow::forward_filtered(
        analysis,
        entry,
        Preservation {
            original: GENERAL_REGISTERS,
            saved: 0,
        },
        |instruction| !belongs_to_tail_target(instruction, &tail_targets),
        |_, _, _| {},
        |instruction, state| preservation_transfer(effects_for(effects, instruction), state),
    );
    let preserved_on_returns = return_sites
        .iter()
        .filter_map(|(site, _)| {
            preservation_walk
                .before
                .get(site)
                .map(|state| state.original)
        })
        .reduce(|left, right| left & right)
        .unwrap_or(0);

    let mut input_lanes = 0_u64;
    let mut input_pointers = 0_u16;
    let input_walk = dataflow::forward_filtered(
        analysis,
        entry,
        Defined(0),
        |instruction| !belongs_to_tail_target(instruction, &tail_targets),
        |_, instruction, state| {
            let effect = effects_for(effects, instruction);
            let preservation_only = lanes_for_registers(effect.saved & preserved_on_returns);
            let inputs = effect.registers.reads & !state.0 & !preservation_only;
            input_lanes |= inputs;
            input_pointers |= effect.registers.pointers & registers_for_lanes(inputs);
        },
        |instruction, state| state.0 |= effects_for(effects, instruction).registers.writes,
    );

    let output_walk = dataflow::forward_filtered(
        analysis,
        entry,
        Defined(0),
        |instruction| !belongs_to_tail_target(instruction, &tail_targets),
        |_, _, _| {},
        |instruction, state| {
            let effect = effects_for(effects, instruction).registers;
            state.0 &= !effect.writes;
            state.0 |= effect.meaningful_writes;
        },
    );
    let return_defined_lanes = return_sites
        .iter()
        .filter_map(|(site, _)| output_walk.before.get(site).map(|state| state.0))
        .reduce(|left, right| left & right)
        .unwrap_or(0);
    let flow_complete = analysis.unresolved.iter().all(|flow| {
        flow.owner != entry
            || analysis
                .instructions
                .get(&flow.address)
                .is_some_and(|instruction| Isa::from(instruction.instruction.opcode) == Isa::Jsr)
    });
    let complete = ownership_complete
        && effects_complete
        && flow_complete
        && !tail_call
        && !preservation_walk.exhausted
        && !input_walk.exhausted
        && !output_walk.exhausted;
    let usable_input_lanes = if complete {
        input_lanes & GENERAL_REGISTER_LANES
    } else {
        0
    };
    let output_lanes = if complete {
        return_defined_lanes & !lanes_for_registers(preserved_on_returns) & GENERAL_REGISTER_LANES
    } else {
        0
    };
    let clobbered_mask = if complete {
        all_writes & !preserved_on_returns & GENERAL_REGISTERS
    } else {
        0
    };
    let preserved_mask = if complete {
        preserved_on_returns & GENERAL_REGISTERS
    } else {
        0
    };
    let stack = analyze_stack(analysis, effects, entry, &owned, &tail_targets);
    let frame = stack.frame;
    let stack_slots = stack_slots(&owned, frame, &stack.before);
    let leaf = !tail_call
        && !owned.iter().any(|instruction| {
            matches!(
                Isa::from(instruction.instruction.opcode),
                Isa::Jsr | Isa::Bsr | Isa::Trap | Isa::Trapv | Isa::Unknown
            )
        });
    let evidence_total = owned.len();
    let evidence = owned
        .iter()
        .map(|instruction| instruction.address)
        .take(MAX_SIGNATURE_EVIDENCE)
        .collect();

    FunctionSignature {
        entry,
        complete,
        inputs: registers(registers_for_lanes(usable_input_lanes))
            .into_iter()
            .map(|register| {
                let bit = register_bit(register);
                FunctionInput {
                    register,
                    lanes: RegisterLanes::from_bits(lanes_of(usable_input_lanes, bit)),
                    pointer: input_pointers & (1 << bit) != 0,
                }
            })
            .collect(),
        outputs: registers(registers_for_lanes(output_lanes))
            .into_iter()
            .map(|register| {
                let bit = register_bit(register);
                FunctionOutput {
                    register,
                    lanes: RegisterLanes::from_bits(lanes_of(output_lanes, bit)),
                }
            })
            .collect(),
        clobbered: registers(clobbered_mask),
        preserved: registers(preserved_mask),
        frame,
        stack_slots,
        returns: combined_return(&return_sites),
        leaf,
        tail_call,
        evidence,
        evidence_total,
    }
}

fn belongs_to_tail_target(instruction: &DecodedInstruction, tail_targets: &BTreeSet<u32>) -> bool {
    tail_targets
        .iter()
        .any(|target| instruction.owners.contains(target))
}

fn registers(mask: u16) -> Vec<FunctionRegister> {
    (0..15_u8)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(FunctionRegister::from_bit)
        .collect()
}

const fn register_lanes(bit: u8, size: Option<Size>) -> u64 {
    let width = if bit >= 8 {
        4
    } else {
        match size {
            Some(Size::Byte) => 1,
            Some(Size::Word) => 2,
            Some(Size::Long) | None => 4,
        }
    };
    ((1_u64 << width) - 1) << ((bit as u32) * 4)
}

fn lanes_for_registers(registers: u16) -> u64 {
    let mut lanes = 0_u64;
    for bit in 0..16_u8 {
        if registers & (1 << bit) != 0 {
            lanes |= register_lanes(bit, None);
        }
    }
    lanes
}

fn registers_for_lanes(lanes: u64) -> u16 {
    let mut registers = 0_u16;
    for bit in 0..16_u8 {
        if lanes_of(lanes, bit) != 0 {
            registers |= 1 << bit;
        }
    }
    registers
}

const fn lanes_of(lanes: u64, bit: u8) -> u8 {
    ((lanes >> ((bit as u32) * 4)) & 0xf) as u8
}

const fn register_bit(register: FunctionRegister) -> u8 {
    match register.kind {
        RegisterKind::Data => register.index,
        RegisterKind::Address => 8 + register.index,
    }
}

fn combined_return(sites: &[(u32, FunctionReturn)]) -> FunctionReturn {
    let Some((_, first)) = sites.first() else {
        return FunctionReturn::None;
    };
    if sites.iter().all(|(_, kind)| kind == first) {
        *first
    } else {
        FunctionReturn::Mixed
    }
}

const fn return_kind(isa: Isa) -> Option<FunctionReturn> {
    match isa {
        Isa::Rts => Some(FunctionReturn::Rts),
        Isa::Rte => Some(FunctionReturn::Rte),
        Isa::Rtr => Some(FunctionReturn::Rtr),
        _ => None,
    }
}

fn has_tail_call(
    analysis: &ControlFlowAnalysis,
    owner: u32,
    owned: &[&DecodedInstruction],
) -> bool {
    analysis.external.iter().any(|flow| {
        flow.kind == ExternalKind::Jump
            && analysis
                .instructions
                .get(&flow.site)
                .is_some_and(|instruction| instruction.owners.contains(&owner))
    }) || analysis.flows.iter().any(|flow| {
        flow.owner == owner
            && flow.kind == FlowKind::Branch
            && analysis.functions.contains(&flow.target)
            && flow.target != owner
            && analysis
                .instructions
                .get(&flow.site)
                .is_some_and(|instruction| Isa::from(instruction.instruction.opcode) == Isa::Jmp)
    }) || owned.iter().any(|instruction| {
        Isa::from(instruction.instruction.opcode) == Isa::Jmp
            && crate::lvo::library_call(instruction).is_some()
    })
}

fn signed_immediate(size: Size, value: u32) -> Option<i32> {
    match size {
        Size::Word => Some(i32::from(value as u16 as i16)),
        Size::Long => Some(value as i32),
        Size::Byte => None,
    }
}

fn analyze_stack(
    analysis: &ControlFlowAnalysis,
    effects: &BTreeMap<u32, InstructionEffects>,
    entry: u32,
    owned: &[&DecodedInstruction],
    tail_targets: &BTreeSet<u32>,
) -> StackAnalysis {
    let mut observations = StackObservations {
        unknown: analysis
            .unresolved
            .iter()
            .any(|flow| flow.owner == entry && !analysis.instructions.contains_key(&flow.address)),
        ..StackObservations::default()
    };
    let walk = dataflow::forward_filtered(
        analysis,
        entry,
        StackDepth::Exact(StackPosition {
            depth: 0,
            locals: 0,
            peak_locals: 0,
            path_dependent_frame: false,
            link: None,
        }),
        |instruction| !belongs_to_tail_target(instruction, tail_targets),
        |_, _, _| {},
        |instruction, state| {
            let before = *state;
            observe_stack_state(before, &mut observations);
            if return_kind(Isa::from(instruction.instruction.opcode)).is_some()
                && !matches!(
                    before,
                    StackDepth::Exact(position)
                        if position.depth == 0 && position.locals == 0
                )
            {
                observations.unknown = true;
            }
            stack_transfer(effects_for(effects, instruction).stack, state);
            observe_stack_state(*state, &mut observations);
        },
    );
    finish_stack_analysis(owned, walk, observations)
}

#[derive(Default)]
struct StackObservations {
    maximum_local_bytes: i32,
    path_dependent: bool,
    unknown: bool,
}

fn finish_stack_analysis(
    owned: &[&DecodedInstruction],
    walk: dataflow::ForwardResult<StackDepth>,
    mut observations: StackObservations,
) -> StackAnalysis {
    if walk.exhausted {
        return StackAnalysis {
            before: BTreeMap::new(),
            frame: FrameStyle::Unknown,
        };
    }
    let maximum_local_bytes =
        u32::try_from(observations.maximum_local_bytes).unwrap_or_else(|_| {
            observations.unknown = true;
            0
        });
    let frame = if observations.unknown {
        FrameStyle::Unknown
    } else if observations.path_dependent {
        FrameStyle::PathDependent {
            maximum_local_bytes,
        }
    } else if let Some(register) = link_register(owned) {
        FrameStyle::Link {
            register,
            local_bytes: maximum_local_bytes,
        }
    } else if maximum_local_bytes > 0 {
        FrameStyle::StackPointer {
            local_bytes: maximum_local_bytes,
        }
    } else {
        FrameStyle::Frameless
    };
    StackAnalysis {
        before: walk.before,
        frame,
    }
}

fn observe_stack_state(state: StackDepth, observations: &mut StackObservations) {
    match state {
        StackDepth::Exact(position) => {
            debug_assert!(position.peak_locals >= position.locals);
            observations.maximum_local_bytes =
                observations.maximum_local_bytes.max(position.peak_locals);
            observations.path_dependent |= position.path_dependent_frame;
        }
        StackDepth::PathDependent => observations.path_dependent = true,
        StackDepth::Unknown => observations.unknown = true,
    }
}

fn link_register(owned: &[&DecodedInstruction]) -> Option<u8> {
    let mut registers = owned.iter().filter_map(|instruction| {
        let Operands::RegisterDisplacement(register, _) = instruction.instruction.operands else {
            return None;
        };
        (Isa::from(instruction.instruction.opcode) == Isa::Link).then_some(register)
    });
    let register = registers.next()?;
    registers.all(|other| other == register).then_some(register)
}

fn stack_transfer(adjustment: StackAdjustment, state: &mut StackDepth) {
    let StackDepth::Exact(position) = state else {
        if adjustment == StackAdjustment::Unknown {
            *state = StackDepth::Unknown;
        }
        return;
    };
    match adjustment {
        StackAdjustment::None => {}
        StackAdjustment::Adjust { depth, locals } => {
            let Some(next_depth) = position.depth.checked_add(depth) else {
                *state = StackDepth::Unknown;
                return;
            };
            let Some(next_locals) = position
                .locals
                .checked_add(locals)
                .map(|value| value.max(0))
            else {
                *state = StackDepth::Unknown;
                return;
            };
            position.depth = next_depth;
            position.locals = next_locals;
            position.peak_locals = position.peak_locals.max(next_locals);
        }
        StackAdjustment::Link {
            register,
            displacement,
        } => {
            if register == 7 || position.link.is_some() {
                *state = StackDepth::Unknown;
                return;
            }
            let saved = LinkState {
                register,
                depth: position.depth,
                locals: position.locals,
            };
            let local_bytes = i32::from(displacement).saturating_neg().max(0);
            let Some(depth) = position
                .depth
                .checked_add(4)
                .and_then(|value| value.checked_sub(i32::from(displacement)))
            else {
                *state = StackDepth::Unknown;
                return;
            };
            let Some(locals) = position.locals.checked_add(local_bytes) else {
                *state = StackDepth::Unknown;
                return;
            };
            position.depth = depth;
            position.locals = locals;
            position.peak_locals = position.peak_locals.max(locals);
            position.link = Some(saved);
        }
        StackAdjustment::Unlink { register } => {
            let Some(link) = position.link.filter(|link| link.register == register) else {
                *state = StackDepth::Unknown;
                return;
            };
            position.depth = link.depth;
            position.locals = link.locals;
            position.link = None;
        }
        StackAdjustment::Unknown => *state = StackDepth::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StackAdjustment {
    None,
    Adjust { depth: i32, locals: i32 },
    Link { register: u8, displacement: i16 },
    Unlink { register: u8 },
    Unknown,
}

fn stack_adjustment(instruction: &DecodedInstruction, register_writes: u64) -> StackAdjustment {
    if instruction
        .movec_destination()
        .is_some_and(|(address, register)| address && register == 7)
    {
        return StackAdjustment::Unknown;
    }
    let isa = Isa::from(instruction.instruction.opcode);
    match instruction.instruction.operands {
        Operands::RegisterDisplacement(register, displacement) if isa == Isa::Link => {
            return StackAdjustment::Link {
                register,
                displacement,
            };
        }
        Operands::Register(register) if isa == Isa::Unlk => {
            return StackAdjustment::Unlink { register };
        }
        Operands::RegisterSizeEffectiveAddress(7, size, AddressingMode::Immediate(value))
            if matches!(isa, Isa::Adda | Isa::Suba) =>
        {
            let Some(value) = signed_immediate(size, value) else {
                return StackAdjustment::Unknown;
            };
            let Some(delta) = (if isa == Isa::Suba {
                Some(value)
            } else {
                value.checked_neg()
            }) else {
                return StackAdjustment::Unknown;
            };
            return StackAdjustment::Adjust {
                depth: delta,
                locals: delta,
            };
        }
        Operands::DataSizeEffectiveAddress(value, _, AddressingMode::Ard(7))
            if matches!(isa, Isa::Addq | Isa::Subq) =>
        {
            let value = i32::from(if value == 0 { 8 } else { value });
            let delta = if isa == Isa::Subq { value } else { -value };
            return StackAdjustment::Adjust {
                depth: delta,
                locals: delta,
            };
        }
        Operands::RegisterEffectiveAddress(7, AddressingMode::Ariwd(7, displacement))
            if isa == Isa::Lea =>
        {
            let delta = -i32::from(displacement);
            return StackAdjustment::Adjust {
                depth: delta,
                locals: delta,
            };
        }
        Operands::DirectionSizeEffectiveAddressList(
            direction,
            size,
            AddressingMode::Ariwpr(7) | AddressingMode::Ariwpo(7),
            mask,
        ) => {
            if direction == Direction::MemoryToRegister && mask & (1 << 15) != 0 {
                return StackAdjustment::Unknown;
            }
            let count = i32::try_from(mask.count_ones()).unwrap_or(i32::MAX);
            let bytes = count.saturating_mul(i32::from(size as u8));
            let depth = if direction == Direction::RegisterToMemory {
                bytes
            } else {
                -bytes
            };
            return StackAdjustment::Adjust { depth, locals: 0 };
        }
        _ => {}
    }
    if isa == Isa::Pea {
        return StackAdjustment::Adjust {
            depth: 4,
            locals: 0,
        };
    }
    if unmodeled_stack_pointer_write(isa, instruction.instruction.operands) {
        return StackAdjustment::Unknown;
    }
    let mut depth = 0_i32;
    let mut stack_side_effect = false;
    let coverage = for_each_operand_access(
        isa,
        instruction.instruction.operands,
        |mode, size, _| match mode {
            AddressingMode::Ariwpr(7) | AddressingMode::Ariwpo(7) => {
                stack_side_effect = true;
                let Some(bytes) = stack_increment(size) else {
                    depth = i32::MAX;
                    return;
                };
                let delta = if matches!(mode, AddressingMode::Ariwpr(7)) {
                    bytes
                } else {
                    -bytes
                };
                depth = depth.checked_add(delta).unwrap_or(i32::MAX);
            }
            _ => {}
        },
    );
    debug_assert_eq!(coverage, OperandCoverage::Complete);
    if stack_side_effect {
        return if depth == i32::MAX {
            StackAdjustment::Unknown
        } else {
            StackAdjustment::Adjust { depth, locals: 0 }
        };
    }
    let writes_a7 = registers_for_lanes(register_writes) & (1 << 15) != 0;
    if writes_a7 {
        StackAdjustment::Unknown
    } else {
        StackAdjustment::None
    }
}

fn unmodeled_stack_pointer_write(isa: Isa, operands: Operands) -> bool {
    match operands {
        Operands::SizeRegisterEffectiveAddress(_, 7, _) => true,
        Operands::RegisterEffectiveAddress(7, _) => isa == Isa::Lea,
        Operands::RegisterSizeEffectiveAddress(7, _, _) => isa != Isa::Cmpa,
        Operands::DirectionRegister(Direction::UspToRegister, 7) => true,
        Operands::RegisterOpmodeRegister(left, direction, right) => match direction {
            Direction::ExchangeAddress => left == 7 || right == 7,
            Direction::ExchangeDataAddress => right == 7,
            _ => false,
        },
        _ => false,
    }
}

fn stack_increment(size: Option<u8>) -> Option<i32> {
    match size {
        Some(1) => Some(2),
        Some(2) => Some(2),
        Some(4) => Some(4),
        _ => None,
    }
}

fn stack_slots(
    owned: &[&DecodedInstruction],
    frame: FrameStyle,
    depths: &BTreeMap<u32, StackDepth>,
) -> Vec<StackSlot> {
    let mut slots = BTreeSet::new();
    for instruction in owned {
        let isa = Isa::from(instruction.instruction.opcode);
        let coverage = for_each_operand_access(
            isa,
            instruction.instruction.operands,
            |mode, size, access| {
                let depth = depths.get(&instruction.address).copied();
                let slot = match mode {
                    AddressingMode::Ariwd(7, offset) => {
                        depth.and_then(|depth| stack_pointer_slot(frame, depth, offset))
                    }
                    AddressingMode::Ariwd(base, offset) => {
                        depth.and_then(|depth| frame_pointer_slot(frame, depth, base, offset))
                    }
                    _ => None,
                };
                if let Some((kind, offset)) = slot {
                    slots.insert(StackSlot {
                        kind,
                        offset,
                        size,
                        access,
                    });
                }
            },
        );
        debug_assert_eq!(coverage, OperandCoverage::Complete);
    }
    slots.into_iter().collect()
}

fn stack_pointer_slot(
    frame: FrameStyle,
    depth: StackDepth,
    displacement: i16,
) -> Option<(StackSlotKind, i32)> {
    let StackDepth::Exact(position) = depth else {
        return None;
    };
    if displacement < 0 {
        return None;
    }
    let entry_offset = i32::from(displacement).checked_sub(position.depth)?;
    classify_stack_slot(frame, entry_offset)
}

fn frame_pointer_slot(
    frame: FrameStyle,
    depth: StackDepth,
    base: u8,
    displacement: i16,
) -> Option<(StackSlotKind, i32)> {
    let FrameStyle::Link { register, .. } = frame else {
        return None;
    };
    let StackDepth::Exact(position) = depth else {
        return None;
    };
    let link = position
        .link
        .filter(|link| link.register == register && base == register)?;
    let frame_depth = link.depth.checked_add(4)?;
    let entry_offset = i32::from(displacement).checked_sub(frame_depth)?;
    classify_stack_slot(frame, entry_offset)
}

fn classify_stack_slot(frame: FrameStyle, entry_offset: i32) -> Option<(StackSlotKind, i32)> {
    if entry_offset >= 4 {
        return Some((StackSlotKind::Argument, entry_offset));
    }
    let local_bytes = match frame {
        FrameStyle::Link { local_bytes, .. }
        | FrameStyle::StackPointer { local_bytes }
        | FrameStyle::PathDependent {
            maximum_local_bytes: local_bytes,
        } => i32::try_from(local_bytes).ok()?,
        FrameStyle::Unknown | FrameStyle::Frameless => return None,
    };
    match frame {
        FrameStyle::Link { .. } => {
            let lower = local_bytes.checked_add(4)?.checked_neg()?;
            if entry_offset >= lower && entry_offset < -4 {
                Some((StackSlotKind::Local, entry_offset.checked_add(4)?))
            } else {
                None
            }
        }
        FrameStyle::StackPointer { .. } | FrameStyle::PathDependent { .. } => {
            if entry_offset >= -local_bytes && entry_offset < 0 {
                Some((StackSlotKind::Local, entry_offset.checked_add(local_bytes)?))
            } else {
                None
            }
        }
        FrameStyle::Unknown | FrameStyle::Frameless => None,
    }
}

fn instruction_effects(instruction: &DecodedInstruction) -> InstructionEffects {
    let registers = register_effects(instruction);
    InstructionEffects {
        registers,
        saved: saved_register_mask(instruction),
        restored: restored_register_mask(instruction),
        stack: stack_adjustment(instruction, registers.writes),
    }
}

fn effects_for(
    effects: &BTreeMap<u32, InstructionEffects>,
    instruction: &DecodedInstruction,
) -> InstructionEffects {
    let effect = effects.get(&instruction.address).copied();
    debug_assert!(effect.is_some(), "every analyzed instruction is cached");
    effect.unwrap_or(InstructionEffects::CONSERVATIVE)
}

fn preservation_transfer(effect: InstructionEffects, state: &mut Preservation) {
    state.saved = (state.saved & !effect.saved) | (state.original & effect.saved);
    state.original &= !(registers_for_lanes(effect.registers.writes) & !effect.restored);
    state.original = (state.original & !effect.restored) | (state.saved & effect.restored);
    state.saved &= !effect.restored;
}

fn saved_register_mask(instruction: &DecodedInstruction) -> u16 {
    match instruction.instruction.operands {
        Operands::DirectionSizeEffectiveAddressList(
            Direction::RegisterToMemory,
            _,
            AddressingMode::Ariwpr(7),
            mask,
        ) => mask.reverse_bits(),
        Operands::SizeEffectiveAddressEffectiveAddress(
            Size::Long,
            AddressingMode::Ariwpr(7),
            source,
        ) => direct_register_mask(source),
        Operands::RegisterDisplacement(register, _)
            if Isa::from(instruction.instruction.opcode) == Isa::Link =>
        {
            1 << (8 + register)
        }
        _ => 0,
    }
}

fn restored_register_mask(instruction: &DecodedInstruction) -> u16 {
    match instruction.instruction.operands {
        Operands::DirectionSizeEffectiveAddressList(
            Direction::MemoryToRegister,
            _,
            AddressingMode::Ariwpo(7),
            mask,
        ) => mask,
        Operands::SizeEffectiveAddressEffectiveAddress(
            Size::Long,
            destination,
            AddressingMode::Ariwpo(7),
        ) => direct_register_mask(destination),
        Operands::Register(register) if Isa::from(instruction.instruction.opcode) == Isa::Unlk => {
            1 << (8 + register)
        }
        _ => 0,
    }
}

fn direct_register_mask(mode: AddressingMode) -> u16 {
    match mode {
        AddressingMode::Drd(register) => 1 << register,
        AddressingMode::Ard(register) => 1 << (8 + register),
        _ => 0,
    }
}

fn register_effects(instruction: &DecodedInstruction) -> Effects {
    let isa = Isa::from(instruction.instruction.opcode);
    let mut effect = Effects::default();
    match instruction.instruction.operands {
        Operands::NoOperands | Operands::Immediate(_) | Operands::Vector(_) => {}
        Operands::SizeEffectiveAddressImmediate(size, destination, _) => {
            if isa == Isa::Cmpi {
                read_ea(&mut effect, destination, Some(size));
            } else {
                modify_ea(&mut effect, destination, Some(size));
            }
        }
        Operands::EffectiveAddressCount(destination, count) => {
            let dynamic = instruction.instruction.opcode & 0x0100 != 0;
            if dynamic {
                effect.read(count, Some(Size::Long), false);
            }
            if let AddressingMode::Drd(register) = destination
                && !dynamic
            {
                let lane = 1_u64 << (u32::from(register) * 4 + u32::from((count & 31) / 8));
                effect.reads |= lane;
                if isa != Isa::Btst {
                    effect.writes |= lane;
                    effect.meaningful_writes |= lane;
                }
            } else {
                let size = if matches!(destination, AddressingMode::Drd(_)) {
                    Size::Long
                } else {
                    Size::Byte
                };
                if isa == Isa::Btst {
                    read_ea(&mut effect, destination, Some(size));
                } else {
                    modify_ea(&mut effect, destination, Some(size));
                }
            }
        }
        Operands::EffectiveAddress(mode) => match isa {
            Isa::Jmp | Isa::Jsr | Isa::Pea => address_ea(&mut effect, mode),
            Isa::Moveccr | Isa::Movesr => read_ea(&mut effect, mode, Some(Size::Word)),
            Isa::Movefsr => write_ea(&mut effect, mode, Some(Size::Word), false),
            Isa::Nbcd | Isa::Tas => modify_ea(&mut effect, mode, Some(Size::Byte)),
            _ => modify_ea(&mut effect, mode, None),
        },
        Operands::SizeEffectiveAddress(size, mode) => {
            if isa == Isa::Tst {
                read_ea(&mut effect, mode, Some(size));
            } else if isa == Isa::Clr {
                write_ea(&mut effect, mode, Some(size), false);
            } else {
                modify_ea(&mut effect, mode, Some(size));
            }
        }
        Operands::RegisterEffectiveAddress(register, source) => match isa {
            Isa::Lea => {
                address_ea(&mut effect, source);
                effect.write(8 + register);
            }
            Isa::Chk => {
                read_ea(&mut effect, source, Some(Size::Word));
                effect.read(register, Some(Size::Word), false);
            }
            Isa::Muls | Isa::Mulu => {
                read_ea(&mut effect, source, Some(Size::Word));
                effect.read(register, Some(Size::Word), false);
                effect.write(register);
            }
            Isa::Divs | Isa::Divu => {
                read_ea(&mut effect, source, Some(Size::Word));
                effect.read(register, Some(Size::Long), false);
                effect.write(register);
            }
            _ => effect.complete = false,
        },
        Operands::RegisterDirectionSizeRegisterDisplacement(data, direction, size, address, _) => {
            effect.read(8 + address, Some(Size::Long), true);
            match direction {
                Direction::MemoryToRegister => effect.write_lanes(data, Some(size)),
                Direction::RegisterToMemory => effect.read(data, Some(size), false),
                _ => effect.complete = false,
            }
        }
        Operands::SizeRegisterEffectiveAddress(size, destination, source) => {
            read_ea(&mut effect, source, Some(size));
            effect.write(8 + destination);
        }
        Operands::SizeEffectiveAddressEffectiveAddress(size, destination, source) => {
            read_ea(&mut effect, source, Some(size));
            write_ea(&mut effect, destination, Some(size), false);
        }
        Operands::RegisterOpmodeRegister(left, direction, right) => match direction {
            Direction::ExchangeData => exchange(&mut effect, left, right),
            Direction::ExchangeAddress => exchange(&mut effect, 8 + left, 8 + right),
            Direction::ExchangeDataAddress => exchange(&mut effect, left, 8 + right),
            _ => effect.complete = false,
        },
        Operands::OpmodeRegister(opmode, register) => {
            let (read_size, write_size) = if opmode == 0b010 {
                (Size::Byte, Size::Word)
            } else {
                (Size::Word, Size::Long)
            };
            effect.read(register, Some(read_size), false);
            effect.write_lanes(register, Some(write_size));
        }
        Operands::RegisterDisplacement(register, _) => {
            effect.read(8 + register, Some(Size::Long), true);
            effect.write(8 + register);
            effect.read(15, Some(Size::Long), true);
            effect.write(15);
        }
        Operands::Register(register) => {
            let bit = if isa == Isa::Swap {
                register
            } else {
                8 + register
            };
            effect.read(bit, None, false);
            effect.write(bit);
            if isa == Isa::Unlk {
                effect.write(15);
            }
        }
        Operands::DirectionRegister(direction, register) => match direction {
            Direction::RegisterToUsp => effect.read(8 + register, Some(Size::Long), true),
            Direction::UspToRegister => effect.write(8 + register),
            _ => effect.complete = false,
        },
        Operands::DirectionSizeEffectiveAddressList(direction, size, mode, mask) => match direction
        {
            Direction::RegisterToMemory => {
                let mask = if matches!(mode, AddressingMode::Ariwpr(_)) {
                    mask.reverse_bits()
                } else {
                    mask
                };
                for bit in 0..16_u8 {
                    if mask & (1 << bit) != 0 {
                        effect.read(bit, Some(size), bit >= 8);
                    }
                }
                write_ea(&mut effect, mode, Some(size), false);
            }
            Direction::MemoryToRegister => {
                read_ea(&mut effect, mode, Some(size));
                let lanes = lanes_for_registers(mask);
                effect.writes |= lanes;
                effect.meaningful_writes |= lanes;
            }
            _ => effect.complete = false,
        },
        Operands::DataSizeEffectiveAddress(_, size, mode) => {
            modify_ea(&mut effect, mode, Some(size));
        }
        Operands::ConditionEffectiveAddress(_, mode) => {
            write_ea(&mut effect, mode, Some(Size::Byte), false);
        }
        Operands::ConditionRegisterDisplacement(_, register, _) => {
            effect.read(register, Some(Size::Word), false);
            effect.write_lanes(register, Some(Size::Word));
        }
        Operands::Displacement(_) | Operands::ConditionDisplacement(_, _) => {}
        Operands::RegisterData(register, _) => effect.write(register),
        Operands::RegisterDirectionSizeEffectiveAddress(register, direction, size, mode) => {
            match direction {
                Direction::DstReg => {
                    read_ea(&mut effect, mode, Some(size));
                    effect.read(register, Some(size), false);
                    if !matches!(isa, Isa::Cmp) {
                        effect.write_lanes(register, Some(size));
                    }
                }
                Direction::DstEa => {
                    effect.read(register, Some(size), false);
                    modify_ea(&mut effect, mode, Some(size));
                }
                _ => effect.complete = false,
            }
        }
        Operands::RegisterSizeEffectiveAddress(register, size, source) => {
            read_ea(&mut effect, source, Some(size));
            effect.read(8 + register, Some(Size::Long), true);
            if isa != Isa::Cmpa {
                effect.write(8 + register);
            }
        }
        Operands::RegisterSizeModeRegister(left, size, direction, right) => match direction {
            Direction::RegisterToRegister => {
                effect.read(left, Some(size), false);
                effect.read(right, Some(size), false);
                effect.write_lanes(left, Some(size));
            }
            Direction::MemoryToMemory => {
                for register in [left, right] {
                    effect.read(8 + register, Some(Size::Long), true);
                    effect.write(8 + register);
                }
            }
            _ => effect.complete = false,
        },
        Operands::RegisterSizeRegister(left, _, right) => {
            for register in [left, right] {
                effect.read(8 + register, Some(Size::Long), true);
                effect.write(8 + register);
            }
        }
        Operands::DirectionEffectiveAddress(_, mode) => modify_ea(&mut effect, mode, None),
        Operands::RotationDirectionSizeModeRegister(
            count,
            _,
            size,
            register_count,
            destination,
        ) => {
            if register_count {
                effect.read(count, Some(Size::Long), false);
            }
            effect.read(destination, Some(size), false);
            effect.write_lanes(destination, Some(size));
        }
    }
    if matches!(
        isa,
        Isa::Jsr | Isa::Bsr | Isa::Trap | Isa::Trapv | Isa::Unknown
    ) {
        effect.clobber(GENERAL_REGISTERS);
    }
    if isa == Isa::Unknown {
        effect.complete = false;
    }
    effect
}

fn exchange(effect: &mut Effects, left: u8, right: u8) {
    effect.read(left, Some(Size::Long), left >= 8);
    effect.read(right, Some(Size::Long), right >= 8);
    effect.write(left);
    effect.write(right);
}

fn read_ea(effect: &mut Effects, mode: AddressingMode, size: Option<Size>) {
    match mode {
        AddressingMode::Drd(register) => effect.read(register, size, false),
        AddressingMode::Ard(register) => effect.read(8 + register, size, true),
        _ => address_ea(effect, mode),
    }
}

fn write_ea(effect: &mut Effects, mode: AddressingMode, size: Option<Size>, modify: bool) {
    match mode {
        AddressingMode::Drd(register) => {
            if modify {
                effect.read(register, size, false);
            }
            effect.write_lanes(register, size);
        }
        AddressingMode::Ard(register) => {
            if modify {
                effect.read(8 + register, size, true);
            }
            effect.write(8 + register);
        }
        _ => address_ea(effect, mode),
    }
}

fn modify_ea(effect: &mut Effects, mode: AddressingMode, size: Option<Size>) {
    match mode {
        AddressingMode::Drd(_) | AddressingMode::Ard(_) => write_ea(effect, mode, size, true),
        _ => address_ea(effect, mode),
    }
}

fn address_ea(effect: &mut Effects, mode: AddressingMode) {
    match mode {
        AddressingMode::Ari(register) | AddressingMode::Ariwd(register, _) => {
            effect.read(8 + register, Some(Size::Long), true);
        }
        AddressingMode::Ariwpo(register) | AddressingMode::Ariwpr(register) => {
            effect.read(8 + register, Some(Size::Long), true);
            effect.write(8 + register);
        }
        AddressingMode::Ariwi8(register, extension) => {
            effect.read(8 + register, Some(Size::Long), true);
            read_index(effect, extension.0);
        }
        AddressingMode::Pciwi8(_, extension) => read_index(effect, extension.0),
        AddressingMode::Drd(register) => effect.read(register, None, false),
        AddressingMode::Ard(register) => effect.read(8 + register, None, true),
        AddressingMode::AbsShort(_)
        | AddressingMode::AbsLong(_)
        | AddressingMode::Pciwd(..)
        | AddressingMode::Immediate(_) => {}
    }
}

fn read_index(effect: &mut Effects, extension: u16) {
    let register = ((extension >> 12) & 7) as u8;
    let address = extension & 0x8000 != 0;
    effect.read(register + if address { 8 } else { 0 }, None, address);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;

    fn signature(code: &[u8]) -> FunctionSignature {
        function_signatures(&analyze(code, 0))
            .into_iter()
            .next()
            .expect("the entry has a signature")
    }

    #[test]
    fn link_frame_finds_register_inputs_outputs_and_stack_slots() {
        // LINK A6,#-16 ; MOVE.L (8,A6),D0 ; MOVE.L D1,(-4,A6) ; UNLK A6 ; RTS
        let code = [
            0x4e, 0x56, 0xff, 0xf0, 0x20, 0x2e, 0x00, 0x08, 0x2d, 0x41, 0xff, 0xfc, 0x4e, 0x5e,
            0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(
            signature.frame,
            FrameStyle::Link {
                register: 6,
                local_bytes: 16,
            }
        );
        assert!(signature.inputs.iter().any(|input| {
            input.register
                == FunctionRegister {
                    kind: RegisterKind::Data,
                    index: 1,
                }
        }));
        assert_eq!(
            signature.outputs,
            [FunctionOutput {
                register: FunctionRegister {
                    kind: RegisterKind::Data,
                    index: 0,
                },
                lanes: RegisterLanes::LONG,
            }]
        );
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Argument,
            offset: 4,
            size: Some(4),
            access: AccessKind::Read,
        }));
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Local,
            offset: -4,
            size: Some(4),
            access: AccessKind::Write,
        }));
        assert!(signature.preserved.contains(&FunctionRegister {
            kind: RegisterKind::Address,
            index: 6,
        }));
        assert_eq!(signature.returns, FunctionReturn::Rts);
    }

    #[test]
    fn link_frame_excludes_the_saved_frame_pointer_and_keeps_the_deepest_local() {
        // LINK A6,#-8 ; MOVE.L D0,(0,A7) ; MOVE.L D1,(8,A7) ; UNLK A6 ; RTS
        let code = [
            0x4e, 0x56, 0xff, 0xf8, 0x2f, 0x40, 0x00, 0x00, 0x2f, 0x41, 0x00, 0x08, 0x4e, 0x5e,
            0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(
            signature.frame,
            FrameStyle::Link {
                register: 6,
                local_bytes: 8,
            }
        );
        assert_eq!(
            signature.stack_slots,
            [StackSlot {
                kind: StackSlotKind::Local,
                offset: -8,
                size: Some(4),
                access: AccessKind::Write,
            }]
        );
    }

    #[test]
    fn link_frame_deduplicates_an_argument_reached_through_a6_and_a7() {
        // LINK A6,#0 ; MOVE.L (8,A6),D0 ; MOVE.L (8,A7),D1 ; UNLK A6 ; RTS
        let code = [
            0x4e, 0x56, 0x00, 0x00, 0x20, 0x2e, 0x00, 0x08, 0x22, 0x2f, 0x00, 0x08, 0x4e, 0x5e,
            0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(
            signature.stack_slots,
            [StackSlot {
                kind: StackSlotKind::Argument,
                offset: 4,
                size: Some(4),
                access: AccessKind::Read,
            }]
        );
    }

    #[test]
    fn explicit_stack_pointer_frame_maps_locals_and_arguments() {
        // SUBA.W #16,A7 ; MOVE.L (20,A7),D0 ; MOVE.L D1,(4,A7) ;
        // ADDA.W #16,A7 ; RTS
        let code = [
            0x9e, 0xfc, 0x00, 0x10, 0x20, 0x2f, 0x00, 0x14, 0x2f, 0x41, 0x00, 0x04, 0xde, 0xfc,
            0x00, 0x10, 0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(
            signature.frame,
            FrameStyle::StackPointer { local_bytes: 16 }
        );
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Argument,
            offset: 4,
            size: Some(4),
            access: AccessKind::Read,
        }));
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Local,
            offset: 4,
            size: Some(4),
            access: AccessKind::Write,
        }));
    }

    #[test]
    fn compound_stack_pointer_frame_tracks_each_adjustment() {
        // SUBA.W #8,A7 ; SUBA.W #8,A7 ; MOVE.L (20,A7),D0 ;
        // MOVE.L D1,(4,A7) ; ADDA.W #8,A7 ; ADDA.W #8,A7 ; RTS
        let code = [
            0x9e, 0xfc, 0x00, 0x08, 0x9e, 0xfc, 0x00, 0x08, 0x20, 0x2f, 0x00, 0x14, 0x2f, 0x41,
            0x00, 0x04, 0xde, 0xfc, 0x00, 0x08, 0xde, 0xfc, 0x00, 0x08, 0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(
            signature.frame,
            FrameStyle::StackPointer { local_bytes: 16 }
        );
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Argument,
            offset: 4,
            size: Some(4),
            access: AccessKind::Read,
        }));
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Local,
            offset: 4,
            size: Some(4),
            access: AccessKind::Write,
        }));
    }

    #[test]
    fn negative_adda_word_immediate_allocates_a_stack_pointer_frame() {
        // ADDA.W #-8,A7 ; MOVE.L (12,A7),D0 ; ADDA.W #8,A7 ; RTS
        let code = [
            0xde, 0xfc, 0xff, 0xf8, 0x20, 0x2f, 0x00, 0x0c, 0xde, 0xfc, 0x00, 0x08, 0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(signature.frame, FrameStyle::StackPointer { local_bytes: 8 });
        assert_eq!(
            signature.stack_slots,
            [StackSlot {
                kind: StackSlotKind::Argument,
                offset: 4,
                size: Some(4),
                access: AccessKind::Read,
            }]
        );
    }

    #[test]
    fn negative_long_immediates_can_allocate_and_deallocate_a7() {
        // ADDA.L #-8,A7 ; MOVE.L (12,A7),D0 ; SUBA.L #-8,A7 ; RTS
        let code = [
            0xdf, 0xfc, 0xff, 0xff, 0xff, 0xf8, 0x20, 0x2f, 0x00, 0x0c, 0x9f, 0xfc, 0xff, 0xff,
            0xff, 0xf8, 0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(signature.frame, FrameStyle::StackPointer { local_bytes: 8 });
        assert_eq!(
            signature.stack_slots,
            [StackSlot {
                kind: StackSlotKind::Argument,
                offset: 4,
                size: Some(4),
                access: AccessKind::Read,
            }]
        );
        assert_eq!(signed_immediate(Size::Long, 0x8000_0000), Some(i32::MIN));
    }

    #[test]
    fn lea_stack_allocation_does_not_register_its_own_operand_as_a_local() {
        // LEA (-8,A7),A7 ; MOVE.L (12,A7),D0 ; LEA (8,A7),A7 ; RTS
        let code = [
            0x4f, 0xef, 0xff, 0xf8, 0x20, 0x2f, 0x00, 0x0c, 0x4f, 0xef, 0x00, 0x08, 0x4e, 0x75,
        ];
        let signature = signature(&code);
        assert_eq!(signature.frame, FrameStyle::StackPointer { local_bytes: 8 });
        assert_eq!(
            signature.stack_slots,
            [StackSlot {
                kind: StackSlotKind::Argument,
                offset: 4,
                size: Some(4),
                access: AccessKind::Read,
            }]
        );
    }

    #[test]
    fn overflowing_signed_stack_delta_is_conservatively_unknown() {
        // ADDA.L #$80000000,A7 ; RTS
        assert_eq!(
            signature(&[0xdf, 0xfc, 0x80, 0x00, 0x00, 0x00, 0x4e, 0x75]).frame,
            FrameStyle::Unknown
        );
    }

    #[test]
    fn statically_sized_single_operand_predecrements_preserve_the_frame() {
        for (name, instruction) in [
            ("MOVE SR,-(A7)", [0x40, 0xe7]),
            ("MOVE -(A7),CCR", [0x44, 0xe7]),
            ("TAS -(A7)", [0x4a, 0xe7]),
            ("NBCD -(A7)", [0x48, 0x27]),
        ] {
            let code = [instruction[0], instruction[1], 0x54, 0x4f, 0x4e, 0x75];
            assert_eq!(signature(&code).frame, FrameStyle::Frameless, "{name}");
        }
    }

    #[test]
    fn balanced_paths_with_different_allocations_are_path_dependent() {
        // TST.W D0 ; BEQ.S larger ; SUBA.W #8,A7 ; ADDA.W #8,A7 ;
        // BRA.W done ; larger: SUBA.W #16,A7 ; ADDA.W #16,A7 ;
        // BRA.S done ; NOP ; done: RTS
        let code = [
            0x4a, 0x40, 0x67, 0x0c, 0x9e, 0xfc, 0x00, 0x08, 0xde, 0xfc, 0x00, 0x08, 0x60, 0x00,
            0x00, 0x0e, 0x9e, 0xfc, 0x00, 0x10, 0xde, 0xfc, 0x00, 0x10, 0x60, 0x02, 0x4e, 0x71,
            0x4e, 0x75,
        ];
        assert_eq!(
            signature(&code).frame,
            FrameStyle::PathDependent {
                maximum_local_bytes: 16,
            }
        );
    }

    #[test]
    fn dynamic_stack_pointer_write_makes_the_frame_unknown() {
        // MOVEA.L A0,A7 ; RTS
        assert_eq!(
            signature(&[0x2e, 0x48, 0x4e, 0x75]).frame,
            FrameStyle::Unknown
        );
    }

    #[test]
    fn movec_to_a7_makes_the_frame_unknown_but_movec_from_a7_does_not() {
        // MOVEC VBR,A7 ; MOVE.L (4,A7),D0 ; RTS
        let destination = signature(&[0x4e, 0x7a, 0xf8, 0x01, 0x20, 0x2f, 0x00, 0x04, 0x4e, 0x75]);
        assert_eq!(destination.frame, FrameStyle::Unknown);
        assert!(destination.stack_slots.is_empty());

        // MOVEC A7,VBR ; MOVE.L (4,A7),D0 ; RTS
        let source = signature(&[0x4e, 0x7b, 0xf8, 0x01, 0x20, 0x2f, 0x00, 0x04, 0x4e, 0x75]);
        assert_eq!(source.frame, FrameStyle::Frameless);
        assert_eq!(
            source.stack_slots,
            [StackSlot {
                kind: StackSlotKind::Argument,
                offset: 4,
                size: Some(4),
                access: AccessKind::Read,
            }]
        );
    }

    #[test]
    fn a_pop_that_loads_a7_is_not_mistaken_for_a_static_adjustment() {
        // MOVEA.L (A7)+,A7 ; RTS
        assert_eq!(
            signature(&[0x2e, 0x5f, 0x4e, 0x75]).frame,
            FrameStyle::Unknown
        );
    }

    #[test]
    fn transient_push_and_pop_preserve_entry_relative_arguments() {
        // MOVE.L D0,-(A7) ; MOVE.L (8,A7),D1 ; MOVE.L (A7)+,D0 ; RTS
        let signature = signature(&[0x2f, 0x00, 0x22, 0x2f, 0x00, 0x08, 0x20, 0x1f, 0x4e, 0x75]);
        assert_eq!(signature.frame, FrameStyle::Frameless);
        assert!(signature.stack_slots.contains(&StackSlot {
            kind: StackSlotKind::Argument,
            offset: 4,
            size: Some(4),
            access: AccessKind::Read,
        }));
    }

    #[test]
    fn a_call_is_stack_neutral_and_an_argument_cleanup_balances_its_push() {
        // MOVE.L D0,-(A7) ; BSR.S helper ; ADDQ.L #4,A7 ; RTS ; helper: RTS
        let code = [0x2f, 0x00, 0x61, 0x04, 0x58, 0x8f, 0x4e, 0x75, 0x4e, 0x75];
        assert_eq!(signature(&code).frame, FrameStyle::Frameless);
    }

    #[test]
    fn balanced_stack_loop_converges_without_inventing_a_frame() {
        // MOVE.L D0,-(A7) ; MOVE.L (A7)+,D0 ; DBF D1,loop ; RTS
        let code = [0x2f, 0x00, 0x20, 0x1f, 0x51, 0xc9, 0xff, 0xf8, 0x4e, 0x75];
        assert_eq!(signature(&code).frame, FrameStyle::Frameless);
    }

    #[test]
    fn unbalanced_stack_loop_is_unknown_at_return() {
        // SUBQ.L #4,A7 ; DBF D0,loop ; RTS
        let code = [0x59, 0x8f, 0x51, 0xc8, 0xff, 0xfa, 0x4e, 0x75];
        assert_eq!(signature(&code).frame, FrameStyle::Unknown);
    }

    #[test]
    fn truncated_stack_adjustment_is_conservatively_unknown() {
        // Truncated SUBA.W #imm,A7.
        let signature = signature(&[0x9e, 0xfc]);
        assert_eq!(signature.frame, FrameStyle::Unknown);
        assert!(signature.stack_slots.is_empty());
    }

    #[test]
    fn an_exhausted_stack_walk_discards_every_partial_slot_state() {
        // Model a bounded walk that stopped after learning a plausible argument
        // depth. No fact derived from that non-fixpoint state may escape.
        let code = [0x20, 0x2f, 0x00, 0x04, 0x4e, 0x75];
        let analysis = crate::analyze(&code, 0);
        let owned: Vec<_> = analysis.instructions.values().collect();
        let partial = dataflow::ForwardResult {
            before: BTreeMap::from([(
                0,
                StackDepth::Exact(StackPosition {
                    depth: 0,
                    locals: 0,
                    peak_locals: 0,
                    path_dependent_frame: false,
                    link: None,
                }),
            )]),
            exhausted: true,
        };
        let stack = finish_stack_analysis(&owned, partial, StackObservations::default());
        assert_eq!(stack.frame, FrameStyle::Unknown);
        assert!(stack.before.is_empty());
        assert!(stack_slots(&owned, stack.frame, &stack.before).is_empty());
    }

    #[test]
    fn frameless_leaf_renders_a_register_oriented_prototype() {
        // MOVE.L (A0),D0 ; ADD.L D1,D0 ; RTS
        let code = [0x20, 0x10, 0xd0, 0x81, 0x4e, 0x75];
        let signature = signature(&code);
        assert_eq!(signature.frame, FrameStyle::Frameless);
        assert!(signature.leaf);
        assert_eq!(
            signature.prototype("copy_word"),
            "copy_word(D1, A0: ptr) -> D0"
        );
    }

    #[test]
    fn immediate_word_write_is_not_a_false_low_word_input() {
        // MOVE.W #1079,D0 ; DBF D0,DBF ; RTS
        let code = [0x30, 0x3c, 0x04, 0x37, 0x51, 0xc8, 0xff, 0xfc, 0x4e, 0x75];
        let signature = signature(&code);
        assert!(signature.inputs.is_empty());
        assert_eq!(
            signature.outputs,
            [FunctionOutput {
                register: FunctionRegister {
                    kind: RegisterKind::Data,
                    index: 0,
                },
                lanes: RegisterLanes::WORD,
            }]
        );
        assert_eq!(signature.prototype("fill"), "fill() -> D0.w");
    }

    #[test]
    fn long_read_after_word_write_needs_only_the_untouched_upper_lanes() {
        // MOVE.W #1,D0 ; MOVE.L D0,D1 ; RTS
        let code = [0x30, 0x3c, 0x00, 0x01, 0x22, 0x00, 0x4e, 0x75];
        let signature = signature(&code);
        assert_eq!(
            signature.inputs,
            [FunctionInput {
                register: FunctionRegister {
                    kind: RegisterKind::Data,
                    index: 0,
                },
                lanes: RegisterLanes::from_bits(0b1100),
                pointer: false,
            }]
        );
        assert_eq!(
            signature.prototype("extend"),
            "extend(D0[lanes=0xc]) -> D0.w, D1"
        );
    }

    #[test]
    fn immediate_byte_write_leaves_only_the_upper_three_lanes_caller_owned() {
        // MOVE.B #1,D0 ; MOVE.L D0,D1 ; RTS
        let code = [0x10, 0x3c, 0x00, 0x01, 0x22, 0x00, 0x4e, 0x75];
        let signature = signature(&code);
        assert_eq!(signature.inputs[0].lanes.bits(), 0b1110);
        assert_eq!(signature.outputs[0].lanes, RegisterLanes::BYTE);
    }

    #[test]
    fn static_bit_operations_touch_only_the_selected_data_register_lane() {
        for (name, opcode, prototype) in [
            ("BTST", [0x08, 0x00], "f(D0.b)"),
            ("BCHG", [0x08, 0x40], "f(D0.b) -> D0.b"),
            ("BCLR", [0x08, 0x80], "f(D0.b) -> D0.b"),
            ("BSET", [0x08, 0xc0], "f(D0.b) -> D0.b"),
        ] {
            let code = [opcode[0], opcode[1], 0x00, 0x01, 0x4e, 0x75];
            assert_eq!(signature(&code).prototype("f"), prototype, "{name}");
        }
    }

    #[test]
    fn dynamic_bit_operations_read_the_count_and_the_whole_data_register() {
        for (name, opcode, prototype) in [
            ("BTST", [0x03, 0x00], "f(D0, D1)"),
            ("BCHG", [0x03, 0x40], "f(D0, D1) -> D0"),
            ("BCLR", [0x03, 0x80], "f(D0, D1) -> D0"),
            ("BSET", [0x03, 0xc0], "f(D0, D1) -> D0"),
        ] {
            let code = [opcode[0], opcode[1], 0x4e, 0x75];
            assert_eq!(signature(&code).prototype("f"), prototype, "{name}");
        }
    }

    #[test]
    fn bit_operations_read_the_count_register_only_in_the_dynamic_memory_form() {
        // BSET #1,(A0) ; RTS
        assert_eq!(
            signature(&[0x08, 0xd0, 0x00, 0x01, 0x4e, 0x75]).prototype("f"),
            "f(A0: ptr)"
        );
        // BSET D1,(A0) ; RTS
        assert_eq!(
            signature(&[0x03, 0xd0, 0x4e, 0x75]).prototype("f"),
            "f(D1, A0: ptr)"
        );
    }

    #[test]
    fn extend_arithmetic_writes_only_its_data_register_destination() {
        for (name, opcode, prototype) in [
            ("ABCD", [0xc1, 0x01], "f(D0.b, D1.b) -> D0.b"),
            ("SBCD", [0x81, 0x01], "f(D0.b, D1.b) -> D0.b"),
            ("ADDX.L", [0xd1, 0x81], "f(D0, D1) -> D0"),
            ("SUBX.L", [0x91, 0x81], "f(D0, D1) -> D0"),
        ] {
            let code = [opcode[0], opcode[1], 0x4e, 0x75];
            assert_eq!(signature(&code).prototype("f"), prototype, "{name}");
        }
    }

    #[test]
    fn predecrement_extend_arithmetic_updates_both_address_registers() {
        for (name, opcode) in [
            ("ABCD", [0xc1, 0x09]),
            ("SBCD", [0x81, 0x09]),
            ("ADDX.L", [0xd1, 0x89]),
            ("SUBX.L", [0x91, 0x89]),
        ] {
            let code = [opcode[0], opcode[1], 0x4e, 0x75];
            assert_eq!(
                signature(&code).prototype("f"),
                "f(A0: ptr, A1: ptr) -> A0, A1",
                "{name}"
            );
        }
    }

    #[test]
    fn rte_marks_an_interrupt_handler_and_saved_registers_survive() {
        // MOVEM.L D0-D1/A0,-(A7) ; MOVEQ #1,D0 ;
        // MOVEM.L (A7)+,D0-D1/A0 ; RTE
        let code = [
            0x48, 0xe7, 0xc0, 0x80, 0x70, 0x01, 0x4c, 0xdf, 0x01, 0x03, 0x4e, 0x73,
        ];
        let signature = signature(&code);
        assert_eq!(signature.returns, FunctionReturn::Rte);
        assert!(signature.leaf);
        assert!(signature.inputs.is_empty());
        for register in [
            FunctionRegister {
                kind: RegisterKind::Data,
                index: 0,
            },
            FunctionRegister {
                kind: RegisterKind::Data,
                index: 1,
            },
            FunctionRegister {
                kind: RegisterKind::Address,
                index: 0,
            },
        ] {
            assert!(signature.preserved.contains(&register), "{signature:?}");
            assert!(!signature.clobbered.contains(&register));
            assert!(
                !signature
                    .inputs
                    .iter()
                    .any(|input| input.register == register)
            );
        }
    }

    #[test]
    fn a_jump_to_another_entry_is_a_tail_call_not_a_leaf() {
        // JMP $8.L ; padding ; target: MOVE.L (A0),D0 ; RTS
        let code = [
            0x4e, 0xf9, 0x00, 0x00, 0x00, 0x08, 0x4e, 0x71, 0x20, 0x10, 0x4e, 0x75,
        ];
        let analysis = crate::analyze_entries(&code, &[0, 8]);
        let signatures = function_signatures(&analysis);
        let signature = signatures
            .iter()
            .find(|signature| signature.entry == 0)
            .expect("the jumping function is present");
        assert!(signature.tail_call);
        assert!(!signature.leaf);
        assert!(!signature.complete);
        assert!(signature.inputs.is_empty());
        assert!(signature.outputs.is_empty());
        assert_eq!(signature.returns, FunctionReturn::None);
        let target = signatures
            .iter()
            .find(|signature| signature.entry == 8)
            .expect("the target function is present");
        assert_eq!(target.prototype("target"), "target(A0: ptr) -> D0");
    }

    #[test]
    fn an_evidence_backed_unseeded_jump_target_becomes_a_tail_callee() {
        // JMP $8.L ; NOP ; target: MOVEM.L D0,-(A7) ;
        // MOVEM.L (A7)+,D0 ; RTS
        let code = [
            0x4e, 0xf9, 0, 0, 0, 8, 0x4e, 0x71, 0x48, 0xe7, 0x80, 0x00, 0x4c, 0xdf, 0x00, 0x01,
            0x4e, 0x75,
        ];
        let analysis = crate::analyze(&code, 0);
        let signatures = function_signatures(&analysis);
        let wrapper = signatures
            .iter()
            .find(|signature| signature.entry == 0)
            .expect("the wrapper is present");
        assert!(wrapper.tail_call);
        assert!(!wrapper.leaf);
        assert!(signatures.iter().any(|signature| signature.entry == 8));
    }

    #[test]
    fn a_definition_on_only_one_return_path_is_not_an_output() {
        // TST.W D2 ; BEQ return ; MOVEQ #1,D0 ; return: RTS
        let code = [0x4a, 0x42, 0x67, 0x02, 0x70, 0x01, 0x4e, 0x75];
        let signature = signature(&code);
        assert!(signature.outputs.is_empty());
        assert!(signature.inputs.iter().any(|input| {
            input.register
                == FunctionRegister {
                    kind: RegisterKind::Data,
                    index: 2,
                }
        }));
    }

    #[test]
    fn an_unknown_call_result_on_one_path_is_not_an_output() {
        // TST.W D2 ; BEQ call ; MOVEQ #1,D0 ; BRA return ;
        // call: BSR helper ; return: RTS ; helper: RTS
        let code = [
            0x4a, 0x42, 0x67, 0x04, 0x70, 0x01, 0x60, 0x02, 0x61, 0x02, 0x4e, 0x75, 0x4e, 0x75,
        ];
        let signature = function_signatures(&crate::analyze_entries(&code, &[0, 12]))
            .into_iter()
            .find(|signature| signature.entry == 0)
            .expect("the caller is present");
        assert!(signature.complete);
        assert!(signature.outputs.is_empty());
    }

    #[test]
    fn a_save_restored_on_only_one_path_does_not_prove_preservation() {
        // MOVEM.L D2,-(A7) ; MOVEQ #1,D2 ; TST.W D0 ; BEQ return ;
        // MOVEM.L (A7)+,D2 ; return: RTS
        let code = [
            0x48, 0xe7, 0x20, 0x00, 0x74, 0x01, 0x4a, 0x40, 0x67, 0x04, 0x4c, 0xdf, 0x00, 0x04,
            0x4e, 0x75,
        ];
        let signature = signature(&code);
        let d2 = FunctionRegister {
            kind: RegisterKind::Data,
            index: 2,
        };
        assert!(!signature.preserved.contains(&d2));
        assert!(signature.clobbered.contains(&d2));
        assert!(signature.inputs.iter().any(|input| input.register == d2));
    }

    #[test]
    fn a_preserved_register_used_after_its_save_remains_an_input() {
        // MOVEM.L D2,-(A7) ; ADD.L D2,D0 ; MOVEM.L (A7)+,D2 ; RTS
        let code = [
            0x48, 0xe7, 0x20, 0x00, 0xd0, 0x82, 0x4c, 0xdf, 0x00, 0x04, 0x4e, 0x75,
        ];
        let signature = signature(&code);
        let d2 = FunctionRegister {
            kind: RegisterKind::Data,
            index: 2,
        };
        assert!(signature.preserved.contains(&d2));
        assert!(signature.inputs.iter().any(|input| input.register == d2));
    }

    #[test]
    fn a_trap_is_not_a_leaf_and_conservatively_clobbers_registers() {
        // TRAP #0 ; RTS
        let signature = signature(&[0x4e, 0x40, 0x4e, 0x75]);
        assert!(signature.complete);
        assert!(!signature.leaf);
        assert!(signature.preserved.is_empty());
        assert_eq!(signature.clobbered.len(), 15);
    }

    #[test]
    fn unresolved_non_call_flow_clears_register_claims() {
        // MOVE.L (A0),D0 ; JMP (A1)
        let code = [0x20, 0x10, 0x4e, 0xd1];
        let signature = signature(&code);
        assert!(!signature.complete);
        assert!(signature.inputs.is_empty());
        assert!(signature.outputs.is_empty());
        assert!(signature.clobbered.is_empty());
        assert!(signature.preserved.is_empty());
    }
}
