//! Recognising fixed-point (Q-format) arithmetic idioms.
//!
//! Integer fixed-point math is invisible in a raw listing: a `MULS` followed by
//! an `ASR #k` is a Q-format multiply renormalised by `k` fractional bits, and an
//! `ASL #k` feeding a `DIVS` pre-scales the dividend for a Q-format quotient.
//! Reading a routine's Q split otherwise means inferring it by hand. The
//! analysis flags those arithmetic idioms, recognises common compare/branch
//! saturation clamps, and conservatively propagates known Q scales through
//! register copies and explicit scaling shifts along the control-flow graph.

use std::collections::{BTreeMap, BTreeSet};

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Operands, Size};
use m68000::isa::Isa;

use crate::constants::{RegisterKind, owner_has_invalidating_unresolved_flow, writes_register};
use crate::control_flow::{ControlFlowAnalysis, DecodedInstruction, FlowKind};
use crate::dataflow::{self, Domain};

/// How many instructions apart a multiply/divide and its normalising shift may
/// sit and still be paired.
const WINDOW: usize = 4;

/// The fixed-point idiom a [`FixedPointHint`] flags.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedPointKind {
    /// `MULS`/`MULU` followed by a right shift that renormalises the product.
    ScaledMultiply,
    /// A left shift that pre-scales the dividend, followed by `DIVS`/`DIVU`.
    ScaledDivide,
}

impl FixedPointKind {
    /// A short label for display.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScaledMultiply => "scaled multiply",
            Self::ScaledDivide => "scaled divide",
        }
    }
}

/// A detected fixed-point idiom: a multiply or divide paired with its
/// normalising shift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedPointHint {
    /// Address of the multiply (for a multiply idiom) or divide (for a divide).
    pub site: u32,
    /// Address of the normalising shift.
    pub shift_site: u32,
    pub kind: FixedPointKind,
    /// The data register carrying the fixed-point value.
    pub register: u8,
    /// The Q fractional bit count, when the shift is by an immediate.
    pub fractional_bits: Option<u8>,
}

/// Which side of a fixed-point value a clamp bounds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClampKind {
    Lower,
    Upper,
}

/// A compare/branch/constant-write sequence that clamps a data register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClampHint {
    /// Address of the comparison or overflow-producing arithmetic operation.
    pub site: u32,
    pub assign_site: u32,
    pub register: u8,
    pub size: u8,
    pub bound: u32,
    pub kind: ClampKind,
}

/// A point where a data register acquires a known Q fractional-bit scale.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FixedPointScale {
    pub site: u32,
    pub register: u8,
    pub fractional_bits: u8,
}

/// A register-form arithmetic/logical shift, decomposed.
struct ShiftInfo {
    register: u8,
    right: bool,
    /// The shift amount when it is an immediate (register-count shifts give `None`).
    amount: Option<u8>,
}

/// Scan `analysis` for fixed-point multiply/divide idioms, in address order.
#[must_use]
pub fn fixed_point_hints(analysis: &ControlFlowAnalysis) -> Vec<FixedPointHint> {
    let instructions: Vec<_> = analysis.instructions.values().collect();
    // A pair must stay inside one basic block. Count incoming edges globally:
    // a second function or a call into the middle also breaks the pairing.
    let mut incoming = BTreeMap::<u32, BTreeSet<(u32, FlowKind)>>::new();
    let mut outgoing = BTreeMap::<u32, BTreeSet<(u32, FlowKind)>>::new();
    for flow in &analysis.flows {
        incoming
            .entry(flow.target)
            .or_default()
            .insert((flow.site, flow.kind));
        outgoing
            .entry(flow.site)
            .or_default()
            .insert((flow.target, flow.kind));
    }
    let follows = |previous: &DecodedInstruction, next: &DecodedInstruction| {
        previous.end == next.address
            && previous.owners == next.owners
            && previous.owner_total == previous.owners.len()
            && next.owner_total == next.owners.len()
            && !analysis.functions.contains(&next.address)
            && incoming.get(&next.address).is_some_and(|edges| {
                edges.len() == 1 && edges.contains(&(previous.address, FlowKind::Fallthrough))
            })
            && outgoing.get(&previous.address).is_some_and(|edges| {
                edges.len() == 1 && edges.contains(&(next.address, FlowKind::Fallthrough))
            })
    };
    let mut hints = Vec::new();
    for (index, decoded) in instructions.iter().enumerate() {
        let isa = Isa::from(decoded.instruction.opcode);
        let operands = decoded.instruction.operands;
        let (register, kind, backwards) = if let Some(register) = mul_register(isa, operands) {
            (register, FixedPointKind::ScaledMultiply, false)
        } else if let Some(register) = div_register(isa, operands) {
            (register, FixedPointKind::ScaledDivide, true)
        } else {
            continue;
        };
        let mut previous = *decoded;
        for distance in 1..=WINDOW {
            let candidate = if backwards {
                index.checked_sub(distance)
            } else {
                index.checked_add(distance)
            }
            .and_then(|index| instructions.get(index))
            .copied();
            let Some(candidate) = candidate else { break };
            if !(if backwards {
                follows(candidate, previous)
            } else {
                follows(previous, candidate)
            }) {
                break;
            }
            if let Some(shift) = scaling_shift(
                Isa::from(candidate.instruction.opcode),
                candidate.instruction.operands,
            ) && shift.register == register
                && shift.right != backwards
            {
                hints.push(FixedPointHint {
                    site: decoded.address,
                    shift_site: candidate.address,
                    kind,
                    register,
                    fractional_bits: shift.amount,
                });
                break;
            }
            if writes_register(candidate, RegisterKind::Data, register, analysis) {
                break;
            }
            previous = candidate;
        }
    }
    hints
}

/// Find compare/conditional-skip/constant-write clamp idioms.
#[must_use]
pub fn clamp_hints(analysis: &ControlFlowAnalysis) -> Vec<ClampHint> {
    let instructions: Vec<_> = analysis.instructions.values().collect();
    let mut hints = Vec::new();
    for window in instructions.windows(3) {
        let compare = window[0];
        let branch = window[1];
        let assignment = window[2];
        if compare.end != branch.address
            || branch.end != assignment.address
            || compare.owners.is_disjoint(&branch.owners)
            || compare.owners.is_disjoint(&assignment.owners)
        {
            continue;
        }
        let Some((assigned_size, assigned_register, assigned_bound)) =
            immediate_register_move(assignment.instruction.operands)
        else {
            continue;
        };
        if let Some((size, register, bound)) = immediate_compare(
            Isa::from(compare.instruction.opcode),
            compare.instruction.operands,
        ) && let Some((kind, target)) = clamp_branch(branch.address, branch.instruction.operands)
            && assigned_size == size
            && assigned_register == register
            && assigned_bound == bound
            && target >= assignment.end
        {
            hints.push(ClampHint {
                site: compare.address,
                assign_site: assignment.address,
                register,
                size: size as u8,
                bound,
                kind,
            });
            continue;
        }
        if let Some((size, register)) = arithmetic_destination(
            Isa::from(compare.instruction.opcode),
            compare.instruction.operands,
        ) && assigned_size == size
            && assigned_register == register
            && overflow_skip(branch.address, branch.instruction.operands)
                .is_some_and(|target| target >= assignment.end)
            && let Some(kind) = signed_bound_kind(size, assigned_bound)
        {
            hints.push(ClampHint {
                site: compare.address,
                assign_site: assignment.address,
                register,
                size: size as u8,
                bound: assigned_bound,
                kind,
            });
        }
    }
    hints
}

/// Propagate Q scales seeded by recognised multiply/divide idioms through data
/// register copies and immediate arithmetic/logical shifts within each function.
#[must_use]
pub fn fixed_point_scales(analysis: &ControlFlowAnalysis) -> Vec<FixedPointScale> {
    let seeds = fixed_point_hints(analysis)
        .into_iter()
        .filter_map(|hint| {
            hint.fractional_bits.map(|bits| {
                let site = match hint.kind {
                    FixedPointKind::ScaledMultiply => hint.shift_site,
                    FixedPointKind::ScaledDivide => hint.site,
                };
                ((site, hint.register), bits)
            })
        })
        .collect::<BTreeMap<_, _>>();
    let mut found = BTreeMap::<(u32, u8), Option<u8>>::new();
    let transfer = |decoded: &DecodedInstruction, state: &mut Scales| {
        update_scales(&mut state.0, decoded);
        for register in 0_u8..8 {
            if let Some(&bits) = seeds.get(&(decoded.address, register)) {
                state.0[usize::from(register)] = Some(bits);
            }
        }
    };
    for &owner in &analysis.functions {
        let walked = (!owner_has_invalidating_unresolved_flow(analysis, owner)).then(|| {
            dataflow::forward(
                analysis,
                owner,
                Scales::default(),
                |owner, decoded, state| {
                    if decoded.address != owner && analysis.functions.contains(&decoded.address) {
                        *state = Scales::default();
                    }
                },
                transfer,
            )
        });
        // Collect only after convergence. Intermediate worklist states must
        // never leave records behind when a later predecessor erases a scale.
        for decoded in analysis
            .instructions
            .values()
            .filter(|decoded| decoded.owners.contains(&owner))
        {
            let before = walked
                .as_ref()
                .filter(|walked| !walked.exhausted)
                .and_then(|walked| walked.before.get(&decoded.address));
            let mut after = before.cloned().unwrap_or_default();
            if before.is_some() && decoded.owner_total == decoded.owners.len() {
                transfer(decoded, &mut after);
            } else {
                after = Scales::default();
            }
            for register in 0_u8..8 {
                let index = usize::from(register);
                let bits = after.0[index]
                    .filter(|_| before.is_some_and(|before| before.0[index] != after.0[index]));
                found
                    .entry((decoded.address, register))
                    .and_modify(|existing| {
                        if *existing != bits {
                            *existing = None;
                        }
                    })
                    .or_insert(bits);
            }
        }
    }
    found
        .into_iter()
        .filter_map(|((site, register), bits)| {
            bits.map(|fractional_bits| FixedPointScale {
                site,
                register,
                fractional_bits,
            })
        })
        .collect()
}

#[derive(Clone, Default, Eq, PartialEq)]
struct Scales([Option<u8>; 8]);

impl Domain for Scales {
    fn join(&mut self, incoming: &Self) -> bool {
        let mut changed = false;
        for (held, next) in self.0.iter_mut().zip(incoming.0) {
            if held.is_some() && *held != next {
                *held = None;
                changed = true;
            }
        }
        changed
    }
}

fn immediate_compare(isa: Isa, operands: Operands) -> Option<(Size, u8, u32)> {
    if isa != Isa::Cmpi {
        return None;
    }
    match operands {
        Operands::SizeEffectiveAddressImmediate(size, AddressingMode::Drd(register), bound) => {
            Some((size, register, bound))
        }
        _ => None,
    }
}

fn clamp_branch(address: u32, operands: Operands) -> Option<(ClampKind, u32)> {
    let Operands::ConditionDisplacement(condition, displacement) = operands else {
        return None;
    };
    let kind = match condition {
        12 | 14 => ClampKind::Lower, // BGE/BGT skips a lower-bound assignment.
        13 | 15 => ClampKind::Upper, // BLT/BLE skips an upper-bound assignment.
        _ => return None,
    };
    Some((
        kind,
        address
            .wrapping_add(2)
            .wrapping_add_signed(i32::from(displacement)),
    ))
}

/// A `MOVE #imm,Dn` or `MOVEQ #imm,Dn` — the constant assignment half of a
/// clamp.
///
/// `MOVEQ` is here because it is what a compiler emits for the common
/// `MOVEQ #0,Dn` lower clamp: it is a longword assignment of a sign-extended
/// byte, so an upper clamp at a word or longword bound cannot be spelled with
/// it, but a zero or small bound can — and reading only the `MOVE` form missed
/// every one of them.
fn immediate_register_move(operands: Operands) -> Option<(Size, u8, u32)> {
    match operands {
        Operands::SizeEffectiveAddressEffectiveAddress(
            size,
            AddressingMode::Drd(register),
            AddressingMode::Immediate(value),
        ) => Some((size, register, value)),
        Operands::RegisterData(register, value) => {
            Some((Size::Long, register, i32::from(value) as u32))
        }
        _ => None,
    }
}

fn arithmetic_destination(isa: Isa, operands: Operands) -> Option<(Size, u8)> {
    match operands {
        Operands::RegisterDirectionSizeEffectiveAddress(register, direction, size, effective)
            if matches!(isa, Isa::Add | Isa::Sub) =>
        {
            match (direction, effective) {
                (Direction::DstReg, _) => Some((size, register)),
                (Direction::DstEa, AddressingMode::Drd(destination)) => Some((size, destination)),
                _ => None,
            }
        }
        Operands::SizeEffectiveAddressImmediate(size, AddressingMode::Drd(register), _)
            if matches!(isa, Isa::Addi | Isa::Subi) =>
        {
            Some((size, register))
        }
        Operands::DataSizeEffectiveAddress(_, size, AddressingMode::Drd(register)) => {
            Some((size, register))
        }
        _ => None,
    }
}

fn overflow_skip(address: u32, operands: Operands) -> Option<u32> {
    let Operands::ConditionDisplacement(8, displacement) = operands else {
        return None;
    };
    Some(
        address
            .wrapping_add(2)
            .wrapping_add_signed(i32::from(displacement)),
    )
}

fn signed_bound_kind(size: Size, bound: u32) -> Option<ClampKind> {
    let sign_bit = match size {
        Size::Byte => 0x80,
        Size::Word => 0x8000,
        Size::Long => 0x8000_0000,
    };
    match bound {
        value if value == sign_bit => Some(ClampKind::Lower),
        value if value == sign_bit - 1 => Some(ClampKind::Upper),
        _ => None,
    }
}

/// Clear the tracked scale of `mode`, if it names a data register.
fn clear_data_register(scales: &mut [Option<u8>; 8], mode: AddressingMode) {
    if let AddressingMode::Drd(register) = mode {
        scales[usize::from(register)] = None;
    }
}

/// Advance the per-register Q scales past one instruction.
///
/// **An unnamed form loses a scale; it never keeps one.** This walk exists to
/// report a fractional-bit count, and the two ways it can be wrong are not
/// symmetric: forgetting a scale reports nothing, while keeping a stale one
/// *emits a `FixedPointScale` record with a number that is no longer true*. So
/// every arm below either states what the instruction does to a register's
/// binary point or clears it, and the fallthrough — reachable only from an
/// operand form added upstream — clears every register rather than asserting
/// that an instruction nobody classified preserved them all.
///
/// The one form that genuinely preserves a scale is `EXT`: sign extension keeps
/// the fractional-bit count, because it changes the integer width and not the
/// position of the binary point.
fn update_scales(scales: &mut [Option<u8>; 8], decoded: &DecodedInstruction) {
    if decoded.is_opaque_fallthrough() {
        if let Some((false, register)) = decoded.movec_destination() {
            scales[usize::from(register)] = None;
        }
        return;
    }
    let isa = Isa::from(decoded.instruction.opcode);
    let operands = decoded.instruction.operands;
    // No calling convention is proved here: a callee or trap handler may
    // replace any register, including those outside the usual scratch set.
    if matches!(isa, Isa::Jsr | Isa::Bsr | Isa::Trap | Isa::Unknown) {
        scales.fill(None);
        return;
    }
    match operands {
        // A register-to-register move carries the scale with the value.
        Operands::SizeEffectiveAddressEffectiveAddress(
            _,
            AddressingMode::Drd(destination),
            AddressingMode::Drd(source),
        ) => scales[usize::from(destination)] = scales[usize::from(source)],
        // Any other MOVE into a data register replaces what it held.
        Operands::SizeEffectiveAddressEffectiveAddress(_, AddressingMode::Drd(destination), _) => {
            scales[usize::from(destination)] = None
        }
        // MOVE with a memory destination writes no register.
        Operands::SizeEffectiveAddressEffectiveAddress(..) => {}
        // MOVEQ.
        Operands::RegisterData(register, _) => scales[usize::from(register)] = None,
        // CLR/NEG/NEGX/NOT replace the operand; TST only reads it.
        Operands::SizeEffectiveAddress(_, effective) => {
            if isa != Isa::Tst {
                clear_data_register(scales, effective);
            }
        }
        // ADDI/ANDI/EORI/ORI/SUBI replace the operand; CMPI only reads it.
        Operands::SizeEffectiveAddressImmediate(_, effective, _) => {
            if isa != Isa::Cmpi {
                clear_data_register(scales, effective);
            }
        }
        // BCHG/BCLR/BSET change a bit of the operand; BTST only tests it.
        Operands::EffectiveAddressCount(effective, _) => {
            if isa != Isa::Btst {
                clear_data_register(scales, effective);
            }
        }
        // ADDQ/SUBQ and Scc write their operand.
        Operands::DataSizeEffectiveAddress(_, _, effective)
        | Operands::ConditionEffectiveAddress(_, effective) => {
            clear_data_register(scales, effective);
        }
        // TAS/NBCD and MOVE SR,<ea> write theirs. JMP/JSR/PEA cannot name a
        // data register, and MOVE <ea>,SR/CCR only reads one — clearing it
        // loses a scale, which is the safe direction.
        Operands::EffectiveAddress(effective) => clear_data_register(scales, effective),
        // MULx/DIVx replace their destination register. LEA writes an address
        // register and CHK only reads its register.
        Operands::RegisterEffectiveAddress(register, _) => {
            if mul_register(isa, operands).is_some() || div_register(isa, operands).is_some() {
                scales[usize::from(register)] = None;
            }
        }
        Operands::RegisterDirectionSizeEffectiveAddress(register, direction, _, effective) => {
            // CMP reads both operands and does not replace either register.
            if isa == Isa::Cmp {
                return;
            }
            let (destination, source) = match (direction, effective) {
                (Direction::DstEa, AddressingMode::Drd(destination)) => (destination, register),
                (Direction::DstReg, AddressingMode::Drd(source)) => (register, source),
                (Direction::DstReg, _) => {
                    scales[usize::from(register)] = None;
                    return;
                }
                _ => return,
            };
            if scales[usize::from(destination)] != scales[usize::from(source)] {
                scales[usize::from(destination)] = None;
            }
        }
        // A shift by a literal amount moves the binary point by exactly that
        // many bits. A rotate does not scale at all, and a shift whose count is
        // in a register moves it by an amount this walk cannot read — which is
        // not the same as not moving it, and is why both clear.
        Operands::RotationDirectionSizeModeRegister(_, _, _, _, register) => {
            let index = usize::from(register);
            let held = scales[index];
            scales[index] = match scaling_shift(isa, operands) {
                Some(ShiftInfo {
                    right,
                    amount: Some(amount),
                    ..
                }) => held.and_then(|bits| {
                    if right {
                        bits.checked_sub(amount)
                    } else {
                        bits.checked_add(amount)
                    }
                }),
                _ => None,
            };
        }
        // EXG exchanges two registers, so it exchanges their scales. The
        // data/address form puts an address in the data register.
        Operands::RegisterOpmodeRegister(first, mode, second) => match mode {
            Direction::ExchangeData => scales.swap(usize::from(first), usize::from(second)),
            Direction::ExchangeDataAddress => scales[usize::from(first)] = None,
            // Two address registers hold no scale.
            _ => {}
        },
        // SWAP exchanges the halves of a data register, which moves the binary
        // point by an amount that depends on where it was. UNLK writes A7.
        Operands::Register(register) => {
            if isa == Isa::Swap {
                scales[usize::from(register)] = None;
            }
        }
        // MOVEM into registers replaces every one in its list; the low eight
        // bits are D0..D7 for a memory-to-register transfer.
        Operands::DirectionSizeEffectiveAddressList(Direction::MemoryToRegister, _, _, list) => {
            for (register, scale) in scales.iter_mut().enumerate() {
                if list & (1 << register) != 0 {
                    *scale = None;
                }
            }
        }
        // MOVEP moves a sparse byte sequence into or out of a data register.
        Operands::RegisterDirectionSizeRegisterDisplacement(
            register,
            Direction::MemoryToRegister,
            ..,
        ) => scales[usize::from(register)] = None,
        // DBcc decrements its loop counter.
        Operands::ConditionRegisterDisplacement(_, register, _) => {
            scales[usize::from(register)] = None;
        }
        // ABCD/ADDX/SBCD/SUBX write their destination register in the
        // register-to-register form; the predecrement form writes memory.
        Operands::RegisterSizeModeRegister(destination, _, Direction::RegisterToRegister, _) => {
            scales[usize::from(destination)] = None;
        }
        // Forms that write no data register at all: no operands; an immediate
        // to CCR/SR; TRAP's vector; LINK and MOVE USP (address registers);
        // MOVEA, ADDA/CMPA/SUBA (address-register destinations); CMPM (reads
        // both); the memory shift and MOVEM out of registers; the branches; and
        // the predecrement ABCD/ADDX form.
        Operands::NoOperands
        | Operands::Immediate(_)
        | Operands::Vector(_)
        | Operands::RegisterDisplacement(..)
        | Operands::DirectionRegister(..)
        | Operands::SizeRegisterEffectiveAddress(..)
        | Operands::RegisterSizeEffectiveAddress(..)
        | Operands::RegisterSizeRegister(..)
        | Operands::DirectionEffectiveAddress(..)
        | Operands::DirectionSizeEffectiveAddressList(..)
        | Operands::RegisterDirectionSizeRegisterDisplacement(..)
        | Operands::RegisterSizeModeRegister(..)
        | Operands::Displacement(_)
        | Operands::ConditionDisplacement(..) => {}
        // EXT is the one form that preserves a scale: sign extension changes the
        // integer width, not the position of the binary point.
        Operands::OpmodeRegister(..) => {}
        // Only an operand form added upstream reaches here. It named a register
        // this walk did not read, so no scale it has is trustworthy.
        #[allow(unreachable_patterns)]
        _ => scales.fill(None),
    }
}

/// The destination data register of a `MULS`/`MULU`, or `None`.
fn mul_register(isa: Isa, operands: Operands) -> Option<u8> {
    match isa {
        Isa::Mulu | Isa::Muls => register_operand(operands),
        _ => None,
    }
}

/// The destination data register of a `DIVS`/`DIVU`, or `None`.
fn div_register(isa: Isa, operands: Operands) -> Option<u8> {
    match isa {
        Isa::Divu | Isa::Divs => register_operand(operands),
        _ => None,
    }
}

fn register_operand(operands: Operands) -> Option<u8> {
    match operands {
        Operands::RegisterEffectiveAddress(register, _) => Some(register),
        _ => None,
    }
}

/// Decompose a register-form arithmetic or logical shift (the only shifts that
/// scale; rotates do not). Returns `None` for a memory shift, a rotate, or a
/// non-shift.
fn scaling_shift(isa: Isa, operands: Operands) -> Option<ShiftInfo> {
    // Only arithmetic and logical shifts scale a value; rotates do not. The
    // `…r` variants are the register forms, which is what the operand shape
    // below requires anyway.
    if !matches!(isa, Isa::Asr | Isa::Lsr) {
        return None;
    }
    match operands {
        Operands::RotationDirectionSizeModeRegister(
            count,
            direction,
            _,
            register_count,
            register,
        ) => {
            // `register_count` true means the amount is in a register, not an immediate.
            // The immediate 0 encodes a shift of 8.
            let immediate = if count == 0 { 8 } else { count };
            let amount = (!register_count).then_some(immediate);
            Some(ShiftInfo {
                register,
                right: matches!(direction, Direction::Right),
                amount,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::analyze;

    #[test]
    fn flags_a_multiply_normalised_by_a_right_shift() {
        // MULS.W D1,D3 ; ASR.L #8,D3 ; RTS
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x4e, 0x75];
        let hints = fixed_point_hints(&analyze(&code, 0));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].kind, FixedPointKind::ScaledMultiply);
        assert_eq!(hints[0].register, 3);
        assert_eq!(hints[0].site, 0);
        assert_eq!(hints[0].shift_site, 2);
        assert_eq!(hints[0].fractional_bits, Some(8));
    }

    #[test]
    fn flags_a_divide_prescaled_by_a_left_shift() {
        // ASL.L #4,D2 ; DIVS.W D1,D2 ; RTS
        let code = [0xe9, 0x82, 0x85, 0xc1, 0x4e, 0x75];
        let hints = fixed_point_hints(&analyze(&code, 0));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].kind, FixedPointKind::ScaledDivide);
        assert_eq!(hints[0].register, 2);
        assert_eq!(hints[0].site, 2);
        assert_eq!(hints[0].shift_site, 0);
        assert_eq!(hints[0].fractional_bits, Some(4));
    }

    #[test]
    fn ignores_a_multiply_with_no_normalising_shift() {
        // MULS.W D1,D3 ; RTS
        let code = [0xc7, 0xc1, 0x4e, 0x75];
        assert!(fixed_point_hints(&analyze(&code, 0)).is_empty());
    }

    #[test]
    fn ignores_a_right_shift_on_a_different_register() {
        // MULS.W D1,D3 ; ASR.L #8,D2 ; RTS  (shift renormalises D2, not the product D3)
        let code = [0xc7, 0xc1, 0xe0, 0x82, 0x4e, 0x75];
        assert!(fixed_point_hints(&analyze(&code, 0)).is_empty());
    }

    #[test]
    fn idioms_refuse_intervening_register_writes_in_both_directions() {
        for clobber in [
            &[0x76, 0x00][..],         // MOVEQ #0,D3
            &[0x48, 0xc3],             // EXT.L D3 (scale-preserving, but changes the value)
            &[0xd6, 0x43],             // ADD.W D3,D3
            &[0x4c, 0xd8, 0x00, 0x08], // MOVEM.L (A0)+,D3
            &[0x4e, 0x7a, 0x38, 0x01], // MOVEC VBR,D3
            &[0x4e, 0x40],             // TRAP #0
        ] {
            for (first, last) in [
                ([0xc7, 0xc1], [0xe0, 0x83]), // MULS ; ASR
                ([0xe9, 0x83], [0x87, 0xc1]), // ASL ; DIVS
            ] {
                let mut code = first.to_vec();
                code.extend_from_slice(clobber);
                code.extend_from_slice(&last);
                code.extend_from_slice(&[0x4e, 0x75]);
                assert!(
                    fixed_point_hints(&analyze(&code, 0)).is_empty(),
                    "{code:02x?}"
                );
            }
        }
    }

    #[test]
    fn idioms_allow_unrelated_writes_and_read_only_intermediates() {
        // MULS D1,D3 ; MOVEQ #0,D2 ; TST.L D3 ; ASR.L #8,D3 ; RTS
        let code = [0xc7, 0xc1, 0x74, 0x00, 0x4a, 0x83, 0xe0, 0x83, 0x4e, 0x75];
        assert_eq!(fixed_point_hints(&analyze(&code, 0)).len(), 1);
    }

    #[test]
    fn idioms_do_not_cross_branches_gaps_joins_or_function_entries() {
        for code in [
            // MULS ; BEQ shift ; NOP ; shift: ASR ; RTS
            &[0xc7, 0xc1, 0x67, 0x02, 0x4e, 0x71, 0xe0, 0x83, 0x4e, 0x75][..],
            // MULS ; BRA shift ; data ; shift: ASR ; RTS
            &[0xc7, 0xc1, 0x60, 0x02, 0xff, 0xff, 0xe0, 0x83, 0x4e, 0x75],
            // BEQ shift ; MULS ; shift: ASR ; RTS
            &[0x67, 0x02, 0xc7, 0xc1, 0xe0, 0x83, 0x4e, 0x75],
            // ASL ; BEQ divide ; NOP ; divide: DIVS ; RTS
            &[0xe9, 0x83, 0x67, 0x02, 0x4e, 0x71, 0x87, 0xc1, 0x4e, 0x75],
        ] {
            assert!(
                fixed_point_hints(&analyze(code, 0)).is_empty(),
                "{code:02x?}"
            );
        }
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x4e, 0x75];
        assert!(fixed_point_hints(&crate::analyze_entries(&code, &[0, 2])).is_empty());
    }

    #[test]
    fn scales_follow_non_linear_blocks_including_backward_edges() {
        // BRA seed ; copy: MOVE.L D3,D2 ; RTS ; seed: MULS ; ASR ; BRA copy
        let code = [
            0x60, 0x04, 0x24, 0x03, 0x4e, 0x75, 0xc7, 0xc1, 0xe0, 0x83, 0x60, 0xf6,
        ];
        assert!(
            fixed_point_scales(&analyze(&code, 0)).contains(&FixedPointScale {
                site: 2,
                register: 2,
                fractional_bits: 8,
            })
        );
    }

    #[test]
    fn scale_joins_require_agreement_from_every_predecessor() {
        for (right_shift, expected) in [(0xe0, Some(8)), (0xe2, None)] {
            // BEQ right ; MULS ; ASR #8 ; BRA join ;
            // right: MULS ; ASR #8/#1 ; join: MOVE.L D3,D2 ; RTS
            let code = [
                0x67,
                0x06,
                0xc7,
                0xc1,
                0xe0,
                0x83,
                0x60,
                0x04,
                0xc7,
                0xc1,
                right_shift,
                0x83,
                0x24,
                0x03,
                0x4e,
                0x75,
            ];
            let scales = fixed_point_scales(&analyze(&code, 0));
            assert_eq!(
                scales
                    .iter()
                    .find(|scale| scale.site == 12)
                    .map(|scale| scale.fractional_bits),
                expected
            );
        }
        // BEQ join ; MULS ; ASR ; join: MOVE.L D3,D2 ; RTS
        let code = [0x67, 0x04, 0xc7, 0xc1, 0xe0, 0x83, 0x24, 0x03, 0x4e, 0x75];
        assert!(
            !fixed_point_scales(&analyze(&code, 0))
                .iter()
                .any(|scale| scale.site == 6)
        );
    }

    #[test]
    fn loop_backedges_erase_stale_worklist_results() {
        // MULS ; ASR ; loop: MOVE.L D3,D2 ; ASL.L #1,D3 ; BNE loop ; RTS
        let code = [
            0xc7, 0xc1, 0xe0, 0x83, 0x24, 0x03, 0xe3, 0x83, 0x66, 0xfa, 0x4e, 0x75,
        ];
        let scales = fixed_point_scales(&analyze(&code, 0));
        assert!(scales.iter().any(|scale| scale.site == 2));
        assert!(!scales.iter().any(|scale| matches!(scale.site, 4 | 6)));
    }

    #[test]
    fn calls_clear_scales_even_in_non_scratch_registers() {
        // MULS ; ASR ; JSR (A0) ; MOVE.L D3,D2 ; RTS
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x4e, 0x90, 0x24, 0x03, 0x4e, 0x75];
        let scales = fixed_point_scales(&analyze(&code, 0));
        assert!(scales.iter().any(|scale| scale.site == 2));
        assert!(!scales.iter().any(|scale| scale.site == 6));
    }

    #[test]
    fn unresolved_jumps_and_shared_entries_cannot_invent_scales() {
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x24, 0x03, 0x4e, 0xd0];
        assert!(fixed_point_scales(&analyze(&code, 0)).is_empty());
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x24, 0x03, 0x4e, 0x75];
        assert!(
            !fixed_point_scales(&crate::analyze_entries(&code, &[0, 4]))
                .iter()
                .any(|scale| scale.site == 4)
        );
    }

    #[test]
    fn detects_an_upper_saturating_clamp() {
        // CMPI.W #$7fff,D0 ; BLE.S done ; MOVE.W #$7fff,D0 ; done: RTS
        let code = [
            0x0c, 0x40, 0x7f, 0xff, 0x6f, 0x04, 0x30, 0x3c, 0x7f, 0xff, 0x4e, 0x75,
        ];
        let hints = clamp_hints(&analyze(&code, 0));
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0],
            ClampHint {
                site: 0,
                assign_site: 6,
                register: 0,
                size: 2,
                bound: 0x7fff,
                kind: ClampKind::Upper,
            }
        );
    }

    #[test]
    fn detects_add_overflow_saturation() {
        // ADD.W D1,D0 ; BVC.S done ; MOVE.W #$7fff,D0 ; done: RTS
        let code = [0xd0, 0x41, 0x68, 0x04, 0x30, 0x3c, 0x7f, 0xff, 0x4e, 0x75];
        let hints = clamp_hints(&analyze(&code, 0));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].site, 0);
        assert_eq!(hints[0].assign_site, 4);
        assert_eq!(hints[0].register, 0);
        assert_eq!(hints[0].bound, 0x7fff);
        assert_eq!(hints[0].kind, ClampKind::Upper);
    }

    #[test]
    fn propagates_q_scale_through_copies_and_shifts() {
        // MULS.W D1,D3 ; ASR.L #8,D3 ; MOVE.L D3,D2 ; ASL.L #2,D2 ; RTS
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x24, 0x03, 0xe5, 0x82, 0x4e, 0x75];
        let scales = fixed_point_scales(&analyze(&code, 0));
        assert!(scales.contains(&FixedPointScale {
            site: 2,
            register: 3,
            fractional_bits: 8,
        }));
        assert!(scales.contains(&FixedPointScale {
            site: 4,
            register: 2,
            fractional_bits: 8,
        }));
        assert!(scales.contains(&FixedPointScale {
            site: 6,
            register: 2,
            fractional_bits: 10,
        }));
    }

    /// Every instruction here replaces or reorders `D3` after it acquired a Q8
    /// scale, so the copy that follows must carry *no* scale into `D2`.
    ///
    /// These are not hypothetical forms. `MULU`+`SWAP` is the classic 68000 Q16
    /// renormalisation idiom, so a walk that reads `SWAP` as scale-preserving
    /// fires on exactly the code this module exists to read — and reports a
    /// number rather than nothing, which is the worse of the two ways to be
    /// wrong.
    #[test]
    fn a_clobbered_register_carries_no_scale_into_a_copy() {
        // MULS.W D1,D3 ; ASR.L #8,D3 ; <clobber> ; MOVE.L D3,D2 ; RTS
        let clobbers: [(&str, &[u8]); 7] = [
            ("SWAP D3", &[0x48, 0x43]),
            ("MOVEM.L (A0)+,D3", &[0x4c, 0xd8, 0x00, 0x08]),
            ("ADDQ.W #1,D3", &[0x52, 0x43]),
            ("ROR.L #4,D3", &[0xe8, 0x9b]),
            ("ANDI.W #$00ff,D3", &[0x02, 0x43, 0x00, 0xff]),
            ("EXG D3,D2", &[0xc7, 0x42]),
            ("NEG.L D3", &[0x44, 0x83]),
        ];
        for (name, clobber) in clobbers {
            let mut code = vec![0xc7, 0xc1, 0xe0, 0x83];
            code.extend_from_slice(clobber);
            code.extend_from_slice(&[0x24, 0x03, 0x4e, 0x75]);
            let copy_site = u32::try_from(4 + clobber.len()).expect("fixture fits");
            let scales = fixed_point_scales(&analyze(&code, 0));
            assert!(
                !scales
                    .iter()
                    .any(|scale| scale.site == copy_site && scale.register == 2),
                "{name} left a stale Q scale to be copied into D2: {scales:?}"
            );
        }
    }

    /// A shift whose count is in a register moves the binary point by an amount
    /// this walk cannot read. That is not the same as not moving it.
    #[test]
    fn a_register_count_shift_clears_the_scale_it_cannot_compute() {
        // MULS.W D1,D3 ; ASR.L #8,D3 ; ASR.L D0,D3 ; MOVE.L D3,D2 ; RTS
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0xe0, 0xa3, 0x24, 0x03, 0x4e, 0x75];
        let scales = fixed_point_scales(&analyze(&code, 0));
        assert!(
            !scales
                .iter()
                .any(|scale| scale.site == 6 && scale.register == 2),
            "a register-count shift left the scale it could not compute: {scales:?}"
        );
    }

    /// `EXG` swaps two registers, so it swaps their scales rather than
    /// destroying one and inventing the other.
    #[test]
    fn exg_moves_a_scale_to_the_other_register() {
        // MULS.W D1,D3 ; ASR.L #8,D3 ; EXG D3,D2 ; MOVE.L D2,D1 ; RTS
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0xc7, 0x42, 0x22, 0x02, 0x4e, 0x75];
        let scales = fixed_point_scales(&analyze(&code, 0));
        assert!(
            scales.contains(&FixedPointScale {
                site: 6,
                register: 1,
                fractional_bits: 8,
            }),
            "EXG did not carry the scale to the register it exchanged with: {scales:?}"
        );
    }

    /// Sign extension changes the integer width, not the position of the binary
    /// point — the one form that genuinely preserves a scale.
    #[test]
    fn sign_extension_preserves_a_scale() {
        // MULS.W D1,D3 ; ASR.L #8,D3 ; EXT.L D3 ; MOVE.L D3,D2 ; RTS
        let code = [0xc7, 0xc1, 0xe0, 0x83, 0x48, 0xc3, 0x24, 0x03, 0x4e, 0x75];
        let scales = fixed_point_scales(&analyze(&code, 0));
        assert!(
            scales.contains(&FixedPointScale {
                site: 6,
                register: 2,
                fractional_bits: 8,
            }),
            "sign extension lost a scale it preserves: {scales:?}"
        );
    }
}
