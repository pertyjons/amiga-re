//! Conservative address-register propagation for indirect memory accesses.
//!
//! The pass deliberately limits itself to straight-line facts. Branch targets,
//! function entries, calls, and discontinuities clear the register state, so a
//! value is never guessed across an unresolved control-flow join.

use std::collections::BTreeSet;

use m68000::addressing_modes::{AddressingMode, BriefExtensionWord};
use m68000::instruction::{Direction, Operands};
use m68000::isa::Isa;

use crate::constants::ValueOptions;
use crate::control_flow::{ControlFlowAnalysis, DecodedInstruction, OperandAddress, OperandRole};
use crate::globals::{AccessKind, OperandCoverage, for_each_operand_access, sign_extend_word};

/// The effective address inferred for an indirect memory access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivedTarget {
    /// One exact effective address.
    Exact(u32),
    /// An inclusive range produced by a word-sized index register.
    Range { start: u32, end: u32 },
    /// The base or index value is not known at this control-flow point.
    Unknown,
}

/// One memory access resolved through a propagated address register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedAccess {
    /// Hunk-relative instruction address.
    pub site: u32,
    /// Address register used by the memory operand.
    pub register: u8,
    pub target: DerivedTarget,
    pub size: Option<u8>,
    pub kind: AccessKind,
}

/// Propagate exact address-register values through straight-line code and
/// resolve indirect memory operands. Only facts built by `LEA`, immediate
/// `MOVEA`, address-register copies, and constant `ADDA`/`SUBA`/`ADDQ`/`SUBQ`
/// are retained.
#[must_use]
pub fn derived_accesses(
    analysis: &ControlFlowAnalysis,
    options: ValueOptions,
) -> Vec<DerivedAccess> {
    let reset_sites = reset_sites(analysis);
    let mut registers = [None; 8];
    let mut previous_end = None;
    let mut found = Vec::new();

    for (site, decoded) in &analysis.instructions {
        if previous_end != Some(*site) || reset_sites.contains(site) {
            registers = [None; 8];
        }

        let isa = Isa::from(decoded.instruction.opcode);
        let coverage =
            for_each_operand_access(isa, decoded.instruction.operands, |mode, size, kind| {
                let Some((register, target)) = resolve(mode, size, &mut registers) else {
                    return;
                };
                found.push(DerivedAccess {
                    site: *site,
                    register,
                    target,
                    size,
                    kind,
                });
            });
        debug_assert_eq!(
            coverage,
            OperandCoverage::Complete,
            "an operand form this classifier does not name contributes no access at all"
        );

        transfer(analysis, decoded, &mut registers, options);
        if clobbers_tracked_registers(isa) {
            registers = [None; 8];
        }
        previous_end = Some(decoded.end);
    }
    found
}

fn resolve(
    mode: AddressingMode,
    size: Option<u8>,
    registers: &mut [Option<u32>; 8],
) -> Option<(u8, DerivedTarget)> {
    match mode {
        AddressingMode::Ari(register) => Some((
            register,
            registers[usize::from(register)]
                .map(DerivedTarget::Exact)
                .unwrap_or(DerivedTarget::Unknown),
        )),
        AddressingMode::Ariwd(register, displacement) => Some((
            register,
            registers[usize::from(register)]
                .and_then(|base| add_signed(base, i32::from(displacement)))
                .map(DerivedTarget::Exact)
                .unwrap_or(DerivedTarget::Unknown),
        )),
        AddressingMode::Ariwpo(register) => {
            let bytes = increment_bytes(register, size);
            let slot = &mut registers[usize::from(register)];
            let target = (*slot)
                .map(DerivedTarget::Exact)
                .unwrap_or(DerivedTarget::Unknown);
            *slot = slot.and_then(|address| address.checked_add(bytes));
            Some((register, target))
        }
        AddressingMode::Ariwpr(register) => {
            let bytes = increment_bytes(register, size);
            let slot = &mut registers[usize::from(register)];
            *slot = slot.and_then(|address| address.checked_sub(bytes));
            Some((
                register,
                (*slot)
                    .map(DerivedTarget::Exact)
                    .unwrap_or(DerivedTarget::Unknown),
            ))
        }
        AddressingMode::Ariwi8(register, extension) => {
            let target = registers[usize::from(register)]
                .and_then(|base| indexed_target(base, extension))
                .unwrap_or(DerivedTarget::Unknown);
            Some((register, target))
        }
        _ => None,
    }
}

fn increment_bytes(register: u8, size: Option<u8>) -> u32 {
    // Byte accesses through A7 keep the stack word-aligned on MC68000.
    if register == 7 && size == Some(1) {
        2
    } else {
        u32::from(size.unwrap_or(1))
    }
}

fn indexed_target(base: u32, extension: BriefExtensionWord) -> Option<DerivedTarget> {
    let displacement = i32::from(extension.disp());
    // Bit 11 selects a long index. With no value-range analysis a long index
    // spans the whole address space and carries no useful conservative bound.
    if extension.0 & 0x0800 != 0 {
        return None;
    }
    let start = add_signed(base, displacement.checked_add(i32::from(i16::MIN))?)?;
    let end = add_signed(base, displacement.checked_add(i32::from(i16::MAX))?)?;
    Some(DerivedTarget::Range { start, end })
}

fn add_signed(value: u32, delta: i32) -> Option<u32> {
    if delta < 0 {
        value.checked_sub(delta.unsigned_abs())
    } else {
        value.checked_add(delta as u32)
    }
}

fn transfer(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    registers: &mut [Option<u32>; 8],
    options: ValueOptions,
) {
    let isa = Isa::from(decoded.instruction.opcode);
    match decoded.instruction.operands {
        Operands::RegisterEffectiveAddress(destination, source) if isa == Isa::Lea => {
            registers[usize::from(destination)] =
                effective_address(analysis, decoded, source, registers, options);
        }
        Operands::SizeRegisterEffectiveAddress(size, destination, source) => {
            registers[usize::from(destination)] =
                address_value(analysis, decoded, size, source, registers, options);
        }
        Operands::RegisterSizeEffectiveAddress(
            destination,
            size,
            AddressingMode::Immediate(value),
        ) if isa == Isa::Adda => {
            registers[usize::from(destination)] = address_immediate(analysis, decoded, size, value)
                .and_then(|delta| {
                    registers[usize::from(destination)]
                        .and_then(|current| add_signed(current, delta))
                });
        }
        Operands::RegisterSizeEffectiveAddress(
            destination,
            size,
            AddressingMode::Immediate(value),
        ) if isa == Isa::Suba => {
            registers[usize::from(destination)] = address_immediate(analysis, decoded, size, value)
                .and_then(i32::checked_neg)
                .and_then(|delta| {
                    registers[usize::from(destination)]
                        .and_then(|current| add_signed(current, delta))
                });
        }
        Operands::RegisterSizeEffectiveAddress(destination, _, _)
            if matches!(isa, Isa::Adda | Isa::Suba) =>
        {
            registers[usize::from(destination)] = None;
        }
        Operands::DataSizeEffectiveAddress(value, _, AddressingMode::Ard(destination)) => {
            // The 3-bit ADDQ/SUBQ quick field encodes 8 as 0.
            let amount = if value == 0 { 8 } else { u32::from(value) };
            let slot = &mut registers[usize::from(destination)];
            *slot = if isa == Isa::Addq {
                (*slot).and_then(|current| current.checked_add(amount))
            } else {
                (*slot).and_then(|current| current.checked_sub(amount))
            };
        }
        Operands::RegisterOpmodeRegister(left, Direction::ExchangeAddress, right) => {
            registers.swap(usize::from(left), usize::from(right));
        }
        Operands::RegisterOpmodeRegister(_, Direction::ExchangeDataAddress, address) => {
            registers[usize::from(address)] = None;
        }
        Operands::RegisterDisplacement(register, _) => {
            registers[usize::from(register)] = None;
        }
        Operands::Register(register) if isa == Isa::Unlk => {
            registers[usize::from(register)] = None;
        }
        Operands::DirectionRegister(Direction::UspToRegister, register) => {
            registers[usize::from(register)] = None;
        }
        Operands::DirectionSizeEffectiveAddressList(Direction::MemoryToRegister, _, _, list) => {
            for (register, value) in registers.iter_mut().enumerate() {
                if list & (1 << (register + 8)) != 0 {
                    *value = None;
                }
            }
        }
        _ => {}
    }
}

fn address_immediate(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    size: m68000::instruction::Size,
    value: u32,
) -> Option<i32> {
    match size {
        m68000::instruction::Size::Word => Some(i32::from(value as i16)),
        _ if matches!(
            analysis.operand_address(decoded, OperandRole::Source, value),
            OperandAddress::Encoded(_)
        ) =>
        {
            Some(value as i32)
        }
        _ => None,
    }
}

fn address_value(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    size: m68000::instruction::Size,
    mode: AddressingMode,
    registers: &[Option<u32>; 8],
    options: ValueOptions,
) -> Option<u32> {
    match mode {
        AddressingMode::Immediate(value) if size == m68000::instruction::Size::Long => {
            resolved_address(analysis, decoded, value, options.image_origin)
        }
        AddressingMode::Immediate(value) => Some(value),
        AddressingMode::Ard(register) => registers[usize::from(register)],
        _ => None,
    }
}

fn effective_address(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    mode: AddressingMode,
    registers: &[Option<u32>; 8],
    options: ValueOptions,
) -> Option<u32> {
    match mode {
        AddressingMode::AbsLong(address) => {
            resolved_address(analysis, decoded, address, options.image_origin)
        }
        AddressingMode::AbsShort(address) => Some(sign_extend_word(address)),
        AddressingMode::Pciwd(pc, displacement) => add_signed(pc, i32::from(displacement)),
        AddressingMode::Ari(register) => registers[usize::from(register)],
        AddressingMode::Ariwd(register, displacement) => {
            add_signed(registers[usize::from(register)]?, i32::from(displacement))
        }
        _ => None,
    }
}

fn resolved_address(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    encoded: u32,
    image_origin: Option<u32>,
) -> Option<u32> {
    match analysis.operand_address(decoded, OperandRole::Source, encoded) {
        OperandAddress::Encoded(address) => Some(address),
        OperandAddress::ThisHunk(offset) => {
            image_origin.map_or(Some(offset), |origin| origin.checked_add(offset))
        }
        OperandAddress::OtherHunk { .. } => None,
    }
}

pub(crate) fn reset_sites(analysis: &ControlFlowAnalysis) -> BTreeSet<u32> {
    let mut sites = analysis.functions.clone();
    for decoded in analysis.instructions.values() {
        let target = match decoded.instruction.operands {
            Operands::Displacement(displacement)
            | Operands::ConditionDisplacement(_, displacement)
            | Operands::ConditionRegisterDisplacement(_, _, displacement) => {
                add_signed(decoded.address, i32::from(displacement))
            }
            _ => None,
        };
        if let Some(target) = target {
            sites.insert(target);
        }
    }
    sites
}

/// Whether this instruction leaves every tracked register value unusable.
///
/// A call may clobber anything by ABI. A word the decoder cannot name is the
/// same answer for the opposite reason — not that it certainly writes, but that
/// nothing here can say it does not, and a tracker that kept its values across
/// one would report a stale address as current.
pub(crate) fn clobbers_tracked_registers(isa: Isa) -> bool {
    matches!(isa, Isa::Jsr | Isa::Bsr | Isa::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;

    #[test]
    fn resolves_lea_copy_displacement_and_postincrement() {
        // LEA $1000,A0 ; MOVEA.L A0,A1 ; MOVE.W D0,(4,A1) ;
        // MOVE.B (A1)+,D1 ; MOVE.B (A1),D2 ; RTS
        let code = [
            0x41, 0xf9, 0, 0, 0x10, 0, 0x22, 0x48, 0x33, 0x40, 0, 4, 0x12, 0x19, 0x14, 0x11, 0x4e,
            0x75,
        ];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        assert!(
            accesses.iter().any(|access| {
                access.site == 8 && access.target == DerivedTarget::Exact(0x1004)
            })
        );
        assert!(
            accesses.iter().any(|access| {
                access.site == 12 && access.target == DerivedTarget::Exact(0x1000)
            })
        );
        assert!(
            accesses.iter().any(|access| {
                access.site == 14 && access.target == DerivedTarget::Exact(0x1001)
            })
        );
    }

    #[test]
    fn clears_facts_at_branch_targets() {
        // LEA $1000,A0 ; BRA +2 ; NOP ; MOVE.B (A0),D0 ; RTS
        let code = [
            0x41, 0xf9, 0, 0, 0x10, 0, 0x60, 0x02, 0x4e, 0x71, 0x10, 0x10, 0x4e, 0x75,
        ];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].target, DerivedTarget::Unknown);
    }

    #[test]
    fn byte_postincrement_keeps_a7_word_aligned() {
        // LEA $1000,A7 ; MOVE.B (A7)+,D0 ; MOVE.B (A7),D1 ; RTS
        let code = [
            0x4f, 0xf9, 0, 0, 0x10, 0, 0x10, 0x1f, 0x12, 0x17, 0x4e, 0x75,
        ];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        assert_eq!(accesses[0].target, DerivedTarget::Exact(0x1000));
        assert_eq!(accesses[1].target, DerivedTarget::Exact(0x1002));
    }

    #[test]
    fn addq_of_eight_advances_an_address_register_by_eight() {
        // LEA $1000,A0 ; ADDQ.L #8,A0 ; MOVE.B (A0),D0 ; RTS
        let code = [
            0x41, 0xf9, 0, 0, 0x10, 0, // LEA $1000,A0
            0x50, 0x88, // ADDQ.L #8,A0 (quick field 0 == 8)
            0x10, 0x10, // MOVE.B (A0),D0
            0x4e, 0x75,
        ];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        assert!(
            accesses
                .iter()
                .any(|access| access.target == DerivedTarget::Exact(0x1008))
        );
    }

    #[test]
    fn an_unrepresentable_signed_suba_delta_loses_the_address_without_panicking() {
        // LEA $1000,A0 ; SUBA.L #$80000000,A0 ; MOVE.B (A0),D0 ; RTS.
        // Negating i32::MIN is not representable in the tracker's signed
        // helper, so the conservative result is unknown.
        let code = [
            0x41, 0xf9, 0, 0, 0x10, 0, // LEA $1000,A0
            0x91, 0xfc, 0x80, 0, 0, 0, // SUBA.L #$80000000,A0
            0x10, 0x10, // MOVE.B (A0),D0
            0x4e, 0x75,
        ];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        assert_eq!(accesses[0].target, DerivedTarget::Unknown);
    }

    #[test]
    fn lea_sign_extends_an_absolute_short_address() {
        // LEA $FFF0.W,A0 ; MOVE.B (A0),D0 ; RTS
        let code = [0x41, 0xf8, 0xff, 0xf0, 0x10, 0x10, 0x4e, 0x75];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        assert_eq!(accesses[0].target, DerivedTarget::Exact(0xffff_fff0));
    }

    #[test]
    fn a_cross_hunk_lea_does_not_seed_a_derived_address() {
        // LEA $1000.L,A0 ; MOVE.B (A0),D0 ; RTS. The addend is in hunk 1,
        // whose runtime mapping this analysis does not know.
        let code = [0x41, 0xf9, 0, 0, 0x10, 0, 0x10, 0x10, 0x4e, 0x75];
        let analysis = crate::analyze_entries_with(
            &code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(crate::Relocations::new(
                    0,
                    [crate::Relocation {
                        patched: 2,
                        target_hunk: 1,
                        target_offset: 0x1000,
                    }],
                )),
                ..crate::FlowOptions::default()
            },
        );
        let accesses = derived_accesses(&analysis, ValueOptions::default());
        assert_eq!(accesses[0].target, DerivedTarget::Unknown);
    }

    #[test]
    fn a_same_hunk_lea_uses_the_mapped_image_offset() {
        // LEA $4.L,A0 ; MOVE.B (A0),D0 ; RTS. Relocation turns the stored
        // addend into hunk offset 4, then the mapping places it at $10004.
        let code = [0x41, 0xf9, 0, 0, 0, 4, 0x10, 0x10, 0x4e, 0x75];
        let analysis = crate::analyze_entries_with(
            &code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(crate::Relocations::new(
                    0,
                    [crate::Relocation {
                        patched: 2,
                        target_hunk: 0,
                        target_offset: 4,
                    }],
                )),
                ..crate::FlowOptions::default()
            },
        );
        let accesses = derived_accesses(
            &analysis,
            ValueOptions {
                image_origin: Some(0x0001_0000),
            },
        );
        assert_eq!(accesses[0].target, DerivedTarget::Exact(0x0001_0004));
    }

    #[test]
    fn an_addx_through_tracked_registers_resolves_both_of_its_operands() {
        // LEA $00DFF004,A1 ; LEA $00DFF09A,A2 ; ADDX.L -(A1),-(A2) ; RTS.
        //
        // The predecrement operands of `ADDX` used to reach this pass as no
        // access at all, so a routine accumulating into a custom-chip register
        // through them read as code that touches no memory. Both now resolve.
        let code = [
            0x43, 0xf9, 0x00, 0xdf, 0xf0, 0x04, // LEA $00DFF004,A1
            0x45, 0xf9, 0x00, 0xdf, 0xf0, 0x9a, // LEA $00DFF09A,A2
            0xd5, 0x89, // ADDX.L -(A1),-(A2)
            0x4e, 0x75,
        ];
        let accesses = derived_accesses(&analyze(&code, 0), ValueOptions::default());
        let addx: Vec<_> = accesses.iter().filter(|a| a.site == 12).collect();
        assert_eq!(addx.len(), 2, "both operands must be reported");
        assert_eq!(addx[0].register, 1);
        assert_eq!(addx[0].target, DerivedTarget::Exact(0x00df_f000));
        assert_eq!(addx[0].kind, AccessKind::Read);
        assert_eq!(addx[1].register, 2);
        assert_eq!(addx[1].target, DerivedTarget::Exact(0x00df_f096));
        assert_eq!(addx[1].kind, AccessKind::Modify);
    }
}
