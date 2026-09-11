//! Finding base-register-relative (small-data) global accesses.
//!
//! Amiga programs built for the small-data model reach their globals through a
//! base address register (conventionally `A5`, sometimes `A4`) with a 16-bit
//! displacement, e.g. `MOVE.W D0,(850,A5)`. This enumerates every such access
//! reached by the control-flow analysis, classifying it as read, write, modify,
//! or address-of, and recording the operand size where the encoding gives one.
//!
//! Read/write direction is derived from the operand form (and, for the shared
//! forms, the mnemonic the decoder recovered); instructions whose direction is
//! genuinely ambiguous are reported as `Other` rather than guessed. `MOVEM`
//! reports only its base slot, not each register it transfers.

use std::collections::BTreeSet;

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Operands, Size};
use m68000::isa::Isa;

use crate::control_flow::{ControlFlowAnalysis, DecodedInstruction, OperandAddress, OperandRole};
use crate::lvo::library_call;

/// How a base-relative slot is touched.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Read,
    Write,
    /// Read-modify-write (e.g. `NEG`, `ADDQ`, `BCHG`).
    Modify,
    /// The slot's address is taken (`LEA`/`PEA`); a hint it is a buffer/pointer.
    Address,
    /// The direction could not be determined.
    Other,
}

/// One base-register-relative access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalAccess {
    /// Address (hunk offset) of the accessing instruction.
    pub site: u32,
    /// Signed displacement from the base register.
    pub offset: i16,
    /// Operand size in bytes (1/2/4), where the encoding specifies one.
    pub size: Option<u8>,
    pub kind: AccessKind,
    /// Constant stored by a direct `MOVE #value,slot` (or zero by `CLR`).
    pub value: Option<u32>,
    /// The slot is loaded into an address register used for an LVO call.
    pub library_base: bool,
}

/// One absolute-addressed access whose target lies inside the loaded image: a
/// global of a copied-to-fixed-address program, which reaches its variables as
/// absolute longs instead of through a base register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteAccess {
    /// Address (hunk offset) of the accessing instruction.
    pub site: u32,
    /// The absolute target address of the access.
    pub address: u32,
    /// Operand size in bytes (1/2/4), where the encoding specifies one.
    pub size: Option<u8>,
    pub kind: AccessKind,
    /// Constant stored by a direct `MOVE #value,slot` (or zero by `CLR`).
    pub value: Option<u32>,
    /// The slot is loaded into an address register used for an LVO call.
    pub library_base: bool,
}

/// Collect every access made through `base_register` (e.g. 5 for `A5`) in
/// `analysis`, ordered by referencing site. `image_origin` maps same-hunk
/// relocated constants stored into a slot; without it those values are omitted
/// rather than reported as raw addends.
#[must_use]
pub fn global_accesses(
    analysis: &ControlFlowAnalysis,
    base_register: u8,
    image_origin: Option<u32>,
) -> Vec<GlobalAccess> {
    let library_registers = library_registers(analysis);
    let mut found = Vec::new();
    for (site, decoded) in &analysis.instructions {
        let isa = Isa::from(decoded.instruction.opcode);
        let constant = constant_write(analysis, decoded, image_origin);
        let library_source = library_base_source(
            decoded.instruction.operands,
            &decoded.owners,
            &library_registers,
        );
        let coverage =
            for_each_operand_access(isa, decoded.instruction.operands, |mode, size, kind| {
                if let Some(offset) = displacement(mode, base_register) {
                    found.push(GlobalAccess {
                        site: *site,
                        offset,
                        size,
                        kind,
                        value: constant
                            .filter(|(destination, _)| *destination == mode)
                            .map(|(_, value)| value),
                        library_base: library_source == Some(mode),
                    });
                }
            });
        debug_assert_eq!(
            coverage,
            OperandCoverage::Complete,
            "an operand form this classifier does not name contributes no access at all"
        );
    }
    found
}

/// Collect every absolute-long memory access whose resolved target falls
/// within the loaded image. A relocation into this hunk resolves its stored
/// addend as an image offset; one into another hunk contributes no access here.
/// Ordered by referencing site.
#[must_use]
pub fn absolute_accesses(
    analysis: &ControlFlowAnalysis,
    load: u32,
    size: u32,
) -> Vec<AbsoluteAccess> {
    let library_registers = library_registers(analysis);
    let mut found = Vec::new();
    for (site, decoded) in &analysis.instructions {
        let isa = Isa::from(decoded.instruction.opcode);
        let constant = constant_write(analysis, decoded, Some(load));
        let library_source = library_base_source(
            decoded.instruction.operands,
            &decoded.owners,
            &library_registers,
        );
        let coverage =
            for_each_operand_access(isa, decoded.instruction.operands, |mode, opsize, kind| {
                if let AddressingMode::AbsLong(encoded) = mode
                    && let Some(address) = absolute_address(
                        analysis,
                        decoded,
                        encoded,
                        OperandRole::for_access(decoded.instruction.operands, kind),
                        load,
                        size,
                    )
                {
                    found.push(AbsoluteAccess {
                        site: *site,
                        address,
                        size: opsize,
                        kind,
                        value: constant
                            .filter(|(destination, _)| *destination == mode)
                            .map(|(_, value)| value),
                        library_base: library_source == Some(mode),
                    });
                }
            });
        debug_assert_eq!(
            coverage,
            OperandCoverage::Complete,
            "an operand form this classifier does not name contributes no access at all"
        );
    }
    found
}

fn absolute_address(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    encoded: u32,
    role: OperandRole,
    load: u32,
    size: u32,
) -> Option<u32> {
    let resolved = analysis.operand_address(decoded, role, encoded);
    match resolved {
        OperandAddress::Encoded(address) => address
            .checked_sub(load)
            .filter(|offset| *offset < size)
            .map(|_| address),
        OperandAddress::ThisHunk(offset) if offset < size => load.checked_add(offset),
        OperandAddress::ThisHunk(_) | OperandAddress::OtherHunk { .. } => None,
    }
}

/// Function owners in which each address register is used for an LVO call.
fn library_registers(analysis: &ControlFlowAnalysis) -> [BTreeSet<u32>; 8] {
    let mut registers = std::array::from_fn(|_| BTreeSet::new());
    for decoded in analysis.instructions.values() {
        if let Some(call) = library_call(decoded)
            && let Some(used) = registers.get_mut(usize::from(call.register))
        {
            used.extend(&decoded.owners);
        }
    }
    registers
}

/// A memory operand loaded into a register that is used for an LVO call.
fn library_base_source(
    operands: Operands,
    owners: &BTreeSet<u32>,
    registers: &[BTreeSet<u32>; 8],
) -> Option<AddressingMode> {
    match operands {
        Operands::SizeRegisterEffectiveAddress(_, register, source)
            if registers
                .get(usize::from(register))
                .is_some_and(|callers| !owners.is_disjoint(callers)) =>
        {
            Some(source)
        }
        _ => None,
    }
}

/// A destination and the constant value an instruction stores there.
pub(crate) fn constant_write(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    image_origin: Option<u32>,
) -> Option<(AddressingMode, u32)> {
    let isa = Isa::from(decoded.instruction.opcode);
    match decoded.instruction.operands {
        Operands::SizeEffectiveAddressEffectiveAddress(
            size,
            destination,
            AddressingMode::Immediate(value),
        ) => {
            let value = if size == Size::Long {
                match analysis.operand_address(decoded, OperandRole::Source, value) {
                    OperandAddress::Encoded(value) => Some(value),
                    OperandAddress::ThisHunk(offset) => {
                        image_origin.and_then(|origin| origin.checked_add(offset))
                    }
                    OperandAddress::OtherHunk { .. } => None,
                }
            } else {
                Some(value)
            }?;
            Some((destination, value))
        }
        Operands::SizeEffectiveAddress(_, destination) if isa == Isa::Clr => Some((destination, 0)),
        _ => None,
    }
}

fn displacement(mode: AddressingMode, base_register: u8) -> Option<i16> {
    match mode {
        AddressingMode::Ariwd(register, displacement) if register == base_register => {
            Some(displacement)
        }
        _ => None,
    }
}

fn size_bytes(size: Size) -> u8 {
    size as u8
}

/// Whether an operand walk accounted for the instruction it was given.
///
/// The classifier below names every `Operands` variant explicitly, including
/// the ones that address no memory, so an unaccounted-for form is reported
/// rather than absorbed by a wildcard. A pass that ignored this would report a
/// clean result over incomplete data — the failure the project's recovery rule
/// exists to prevent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum OperandCoverage {
    /// Every operand this instruction carries was classified.
    Complete,
    /// The operand form is not one this classifier names, so any memory the
    /// instruction touches is missing from the walk.
    Unclassified,
}

/// An absolute-short address as the 68000 forms it: the word is sign-extended,
/// so `($FFFF).W` is `$FFFFFFFF` and not `$0000FFFF`.
///
/// Shared because four modules decoded it by hand and one of them dropped the
/// extension, which is how `($FFF8).W` came to name a plausible position inside
/// a hunk instead of the high end of the address space.
pub(crate) const fn sign_extend_word(address: u16) -> u32 {
    address as i16 as i32 as u32
}

/// Invoke `push` for every memory effective-address operand an instruction
/// touches, with the operand size (where the encoding gives one) and how it is
/// accessed. The caller filters by addressing mode (base-relative, absolute, or
/// a custom-chip register). An instruction touches at most two operands, so this
/// allocates nothing.
pub(crate) fn for_each_operand_access(
    isa: Isa,
    operands: Operands,
    mut push: impl FnMut(AddressingMode, Option<u8>, AccessKind),
) -> OperandCoverage {
    match operands {
        // MOVE: the m68000 decoder yields (size, destination, source).
        Operands::SizeEffectiveAddressEffectiveAddress(size, destination, source) => {
            push(destination, Some(size_bytes(size)), AccessKind::Write);
            push(source, Some(size_bytes(size)), AccessKind::Read);
        }
        // MOVEA <ea>, An (source is read).
        Operands::SizeRegisterEffectiveAddress(size, _, ea) => {
            push(ea, Some(size_bytes(size)), AccessKind::Read);
        }
        // LEA (address-of) shares this form with CHK/DIVx/MULx (which read).
        Operands::RegisterEffectiveAddress(_, ea) => {
            let kind = if isa == Isa::Lea {
                AccessKind::Address
            } else {
                AccessKind::Read
            };
            push(ea, None, kind);
        }
        // PEA (address-of), TAS/NBCD (modify), MOVE from/to SR/CCR, else other.
        Operands::EffectiveAddress(ea) => {
            let (size, kind) = match isa {
                Isa::Pea => (None, AccessKind::Address),
                Isa::Tas | Isa::Nbcd => (Some(1), AccessKind::Modify),
                // `Movefsr` is MOVE SR,<ea> — the operand is the destination.
                Isa::Movefsr => (Some(2), AccessKind::Write),
                // MOVE <ea>,CCR and MOVE <ea>,SR read the operand.
                Isa::Moveccr | Isa::Movesr => (Some(2), AccessKind::Read),
                _ => (None, AccessKind::Other),
            };
            push(ea, size, kind);
        }
        // CLR (write) / TST (read) / NEG/NEGX/NOT (modify).
        Operands::SizeEffectiveAddress(size, ea) => {
            let kind = match isa {
                Isa::Tst => AccessKind::Read,
                Isa::Clr => AccessKind::Write,
                _ => AccessKind::Modify,
            };
            push(ea, Some(size_bytes(size)), kind);
        }
        // ADDI/ANDI/EORI/ORI/SUBI (modify) vs CMPI (read).
        Operands::SizeEffectiveAddressImmediate(size, ea, _) => {
            let kind = if isa == Isa::Cmpi {
                AccessKind::Read
            } else {
                AccessKind::Modify
            };
            push(ea, Some(size_bytes(size)), kind);
        }
        // BTST (read) vs BCHG/BCLR/BSET (modify); memory bit ops are byte-sized.
        // The static and dynamic BTST encodings both decode to `Isa::Btst`.
        Operands::EffectiveAddressCount(ea, _) => {
            let kind = if isa == Isa::Btst {
                AccessKind::Read
            } else {
                AccessKind::Modify
            };
            push(ea, Some(1), kind);
        }
        // ADDQ/SUBQ (modify).
        Operands::DataSizeEffectiveAddress(_, size, ea) => {
            push(ea, Some(size_bytes(size)), AccessKind::Modify);
        }
        // Scc writes a byte.
        Operands::ConditionEffectiveAddress(_, ea) => {
            push(ea, Some(1), AccessKind::Write);
        }
        // MOVEM: direction says whether memory is read or written.
        Operands::DirectionSizeEffectiveAddressList(direction, size, ea, _) => {
            let kind = match direction {
                Direction::MemoryToRegister => AccessKind::Read,
                _ => AccessKind::Write,
            };
            push(ea, Some(size_bytes(size)), kind);
        }
        // ADD/AND/OR/SUB read the EA when the destination is a register and
        // modify it when the destination is the EA. CMP always reads; EOR uses
        // the destination-EA encoding and modifies it.
        Operands::RegisterDirectionSizeEffectiveAddress(_, direction, size, ea) => {
            let kind = match direction {
                Direction::DstEa => AccessKind::Modify,
                _ => AccessKind::Read,
            };
            push(ea, Some(size_bytes(size)), kind);
        }
        // ADDA/CMPA/SUBA all read their effective-address source.
        Operands::RegisterSizeEffectiveAddress(_, size, ea) => {
            push(ea, Some(size_bytes(size)), AccessKind::Read);
        }
        // Memory shift/rotate forms read-modify-write one word.
        Operands::DirectionEffectiveAddress(_, ea) => {
            push(ea, Some(2), AccessKind::Modify);
        }
        // MOVEP addresses memory as (d16,An); direction determines whether that
        // sparse byte sequence is read or written.
        Operands::RegisterDirectionSizeRegisterDisplacement(
            _,
            direction,
            size,
            register,
            offset,
        ) => {
            let kind = match direction {
                Direction::MemoryToRegister => AccessKind::Read,
                _ => AccessKind::Write,
            };
            push(
                AddressingMode::Ariwd(register, offset),
                Some(size_bytes(size)),
                kind,
            );
        }
        // ABCD/ADDX/SBCD/SUBX -(Ay),-(Ax). The variant carries raw register
        // numbers rather than addressing modes, so the mode is synthesised —
        // exactly as the MOVEP arm above synthesises `Ariwd`. The destination
        // is read, combined and written back, which is what `Modify` names.
        Operands::RegisterSizeModeRegister(
            destination,
            size,
            Direction::MemoryToMemory,
            source,
        ) => {
            push(
                AddressingMode::Ariwpr(source),
                Some(size_bytes(size)),
                AccessKind::Read,
            );
            push(
                AddressingMode::Ariwpr(destination),
                Some(size_bytes(size)),
                AccessKind::Modify,
            );
        }
        // The `Dy,Dx` form of the same four instructions touches no memory.
        Operands::RegisterSizeModeRegister(..) => {}
        // CMPM (Ay)+,(Ax)+ compares two memory operands and writes neither.
        Operands::RegisterSizeRegister(destination, size, source) => {
            push(
                AddressingMode::Ariwpo(source),
                Some(size_bytes(size)),
                AccessKind::Read,
            );
            push(
                AddressingMode::Ariwpo(destination),
                Some(size_bytes(size)),
                AccessKind::Read,
            );
        }

        // The forms that address no memory through an operand. Named
        // explicitly, rather than left to a wildcard, so that a variant this
        // classifier does not know about reaches the arm below instead of being
        // absorbed here as "touches nothing".
        //
        // Some of these do reach memory *implicitly* — LINK and TRAP push
        // through A7, and so do BSR/JSR — but that traffic is not an operand
        // and no caller filters for it. Modelling the stack is a separate
        // question from classifying operands.
        Operands::NoOperands
        | Operands::Immediate(..)
        | Operands::Vector(..)
        | Operands::Register(..)
        | Operands::RegisterData(..)
        | Operands::RegisterDisplacement(..)
        | Operands::RegisterOpmodeRegister(..)
        | Operands::OpmodeRegister(..)
        | Operands::DirectionRegister(..)
        | Operands::Displacement(..)
        | Operands::ConditionDisplacement(..)
        | Operands::ConditionRegisterDisplacement(..)
        | Operands::RotationDirectionSizeModeRegister(..) => {}

        // Unreachable against today's `m68000`: the arms above name every
        // variant it has, which is why the compiler calls this one redundant.
        // It exists for the upgrade that adds one — that variant arrives here
        // and says so, instead of contributing no access at all while the walk
        // above it reports a clean result. Dropping the arm would make the
        // match exhaustive-by-luck and turn such an upgrade into a build
        // failure, which is what this is chosen over.
        #[allow(
            unreachable_patterns,
            reason = "reachable only from an m68000 upgrade that adds an operand form"
        )]
        _ => return OperandCoverage::Unclassified,
    }
    OperandCoverage::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::analyze;

    fn with_relocation(
        code: &[u8],
        patched: u32,
        target_hunk: u32,
        target_offset: u32,
    ) -> ControlFlowAnalysis {
        crate::analyze_entries_with(
            code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(crate::Relocations::new(
                    0,
                    [crate::Relocation {
                        patched,
                        target_hunk,
                        target_offset,
                    }],
                )),
                ..crate::FlowOptions::default()
            },
        )
    }

    #[test]
    fn classifies_write_read_and_address_of_a5_slots() {
        // MOVE.W D0,(4,A5) ; MOVE.L (8,A5),D1 ; LEA (12,A5),A0 ; RTS
        let code = [
            0x3b, 0x40, 0x00, 0x04, // MOVE.W D0,(4,A5)
            0x22, 0x2d, 0x00, 0x08, // MOVE.L (8,A5),D1
            0x41, 0xed, 0x00, 0x0c, // LEA (12,A5),A0
            0x4e, 0x75, // RTS
        ];
        let accesses = global_accesses(&analyze(&code, 0), 5, None);
        assert!(accesses.contains(&GlobalAccess {
            site: 0,
            offset: 4,
            size: Some(2),
            kind: AccessKind::Write,
            value: None,
            library_base: false,
        }));
        assert!(accesses.contains(&GlobalAccess {
            site: 4,
            offset: 8,
            size: Some(4),
            kind: AccessKind::Read,
            value: None,
            library_base: false,
        }));
        assert!(accesses.contains(&GlobalAccess {
            site: 8,
            offset: 12,
            size: None,
            kind: AccessKind::Address,
            value: None,
            library_base: false,
        }));
    }

    #[test]
    fn clr_is_a_write_not_a_modify() {
        // CLR.W (4,A5) ; RTS
        let code = [0x42, 0x6d, 0x00, 0x04, 0x4e, 0x75];
        let accesses = global_accesses(&analyze(&code, 0), 5, None);
        assert_eq!(accesses[0].kind, AccessKind::Write);
    }

    #[test]
    fn classifies_register_ea_arithmetic_in_both_directions() {
        // ADD.W (4,A5),D0 ; ADD.W D0,(8,A5) ; RTS
        let code = [
            0xd0, 0x6d, 0x00, 0x04, // source EA is read
            0xd1, 0x6d, 0x00, 0x08, // destination EA is modified
            0x4e, 0x75,
        ];
        let accesses = global_accesses(&analyze(&code, 0), 5, None);
        assert!(accesses.contains(&GlobalAccess {
            site: 0,
            offset: 4,
            size: Some(2),
            kind: AccessKind::Read,
            value: None,
            library_base: false,
        }));
        assert!(accesses.contains(&GlobalAccess {
            site: 4,
            offset: 8,
            size: Some(2),
            kind: AccessKind::Modify,
            value: None,
            library_base: false,
        }));
    }

    #[test]
    fn selects_only_the_requested_base_register() {
        // MOVE.W D0,(4,A5) ; RTS
        let code = [0x3b, 0x40, 0x00, 0x04, 0x4e, 0x75];
        assert!(!global_accesses(&analyze(&code, 0), 5, None).is_empty()); // A5: found
        assert!(global_accesses(&analyze(&code, 0), 4, None).is_empty()); // A4: nothing
    }

    #[test]
    fn finds_absolute_accesses_within_the_loaded_range() {
        // MOVE.W D0,$00010004 ; MOVE.L $00010008,D1 ; RTS
        let code = [
            0x33, 0xc0, 0x00, 0x01, 0x00, 0x04, // MOVE.W D0,$00010004
            0x22, 0x39, 0x00, 0x01, 0x00, 0x08, // MOVE.L $00010008,D1
            0x4e, 0x75, // RTS
        ];
        let accesses = absolute_accesses(&analyze(&code, 0), 0x0001_0000, 0x100);
        assert!(accesses.contains(&AbsoluteAccess {
            site: 0,
            address: 0x0001_0004,
            size: Some(2),
            kind: AccessKind::Write,
            value: None,
            library_base: false,
        }));
        assert!(accesses.contains(&AbsoluteAccess {
            site: 6,
            address: 0x0001_0008,
            size: Some(4),
            kind: AccessKind::Read,
            value: None,
            library_base: false,
        }));
    }

    #[test]
    fn ignores_absolute_accesses_outside_the_loaded_range() {
        // MOVE.W D0,$00DFF096 (a custom-chip write, outside the image) ; RTS
        let code = [0x33, 0xc0, 0x00, 0xdf, 0xf0, 0x96, 0x4e, 0x75];
        assert!(absolute_accesses(&analyze(&code, 0), 0x0001_0000, 0x100).is_empty());
    }

    #[test]
    fn a_cross_hunk_addend_inside_the_load_range_is_not_an_absolute_global() {
        // MOVE.L $10004.L,D0 ; RTS. The stored addend looks like a global in
        // this image, but the relocation proves that it belongs to hunk 1.
        let code = [0x20, 0x39, 0x00, 0x01, 0x00, 0x04, 0x4e, 0x75];
        let analysis = crate::analyze_entries_with(
            &code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(crate::Relocations::new(
                    0,
                    [crate::Relocation {
                        patched: 2,
                        target_hunk: 1,
                        target_offset: 0x0001_0004,
                    }],
                )),
                ..crate::FlowOptions::default()
            },
        );
        assert!(absolute_accesses(&analysis, 0x0001_0000, 0x100).is_empty());
    }

    #[test]
    fn a_same_hunk_addend_is_mapped_from_its_image_offset() {
        // MOVE.L $4.L,D0 ; RTS. The loaded instruction reads $10004 because
        // the relocation patches offset 4 into this hunk's runtime mapping.
        let code = [0x20, 0x39, 0x00, 0x00, 0x00, 0x04, 0x4e, 0x75];
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
        assert_eq!(
            absolute_accesses(&analysis, 0x0001_0000, 0x100),
            [AbsoluteAccess {
                site: 0,
                address: 0x0001_0004,
                size: Some(4),
                kind: AccessKind::Read,
                value: None,
                library_base: false,
            }]
        );
    }

    #[test]
    fn reports_immediate_values_written_to_relative_and_absolute_slots() {
        // MOVE.L #$10020,(4,A5) ; MOVE.L #$10030,$10008 ; RTS
        let code = [
            0x2b, 0x7c, 0x00, 0x01, 0x00, 0x20, 0x00, 0x04, 0x23, 0xfc, 0x00, 0x01, 0x00, 0x30,
            0x00, 0x01, 0x00, 0x08, 0x4e, 0x75,
        ];
        let analysis = analyze(&code, 0);
        let relative = global_accesses(&analysis, 5, Some(0x0001_0000));
        assert_eq!(relative[0].value, Some(0x0001_0020));
        let absolute = absolute_accesses(&analysis, 0x0001_0000, 0x100);
        assert_eq!(absolute[0].value, Some(0x0001_0030));
    }

    #[test]
    fn a_relocated_global_value_needs_a_same_hunk_runtime_mapping() {
        // MOVE.L #$20,(4,A5) ; RTS. The immediate longword starts at 2.
        let code = [0x2b, 0x7c, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x4e, 0x75];
        let same_hunk = with_relocation(&code, 2, 0, 0x20);
        assert_eq!(
            global_accesses(&same_hunk, 5, Some(0x1000))[0].value,
            Some(0x1020)
        );
        assert_eq!(global_accesses(&same_hunk, 5, None)[0].value, None);

        let other_hunk = with_relocation(&code, 2, 1, 0x20);
        assert_eq!(global_accesses(&other_hunk, 5, Some(0x1000))[0].value, None);
    }

    #[test]
    fn a_word_immediate_is_not_treated_as_a_relocated_pointer() {
        // MOVE.W #$20,(4,A5) ; RTS. A malformed longword relocation at the
        // immediate position must not rename a two-byte scalar.
        let code = [0x3b, 0x7c, 0x00, 0x20, 0x00, 0x04, 0x4e, 0x75];
        let analysis = with_relocation(&code, 2, 1, 0x20);
        assert_eq!(
            global_accesses(&analysis, 5, Some(0x1000))[0].value,
            Some(0x20)
        );
    }

    #[test]
    fn two_identical_longwords_use_their_exact_relocation_positions() {
        // MOVE.L #$20,$20.L ; RTS. Relocating the immediate into another hunk
        // removes only the stored numeric value; the unrelocated destination
        // remains an absolute global at $20.
        let code = [
            0x23, 0xfc, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x4e, 0x75,
        ];
        let immediate = with_relocation(&code, 2, 1, 0x20);
        assert_eq!(
            absolute_accesses(&immediate, 0, 0x100),
            [AbsoluteAccess {
                site: 0,
                address: 0x20,
                size: Some(4),
                kind: AccessKind::Write,
                value: None,
                library_base: false,
            }]
        );

        let destination = with_relocation(&code, 6, 1, 0x20);
        assert!(absolute_accesses(&destination, 0, 0x100).is_empty());
    }

    #[test]
    fn equal_absolute_source_and_destination_resolve_independently() {
        // MOVE.L $20.L,$20.L ; RTS. Unlike the immediate-write case above,
        // both operands are arbitrary effective addresses.
        let code = [
            0x23, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x4e, 0x75,
        ];
        let source = with_relocation(&code, 2, 1, 0x20);
        assert_eq!(
            absolute_accesses(&source, 0, 0x100),
            [AbsoluteAccess {
                site: 0,
                address: 0x20,
                size: Some(4),
                kind: AccessKind::Write,
                value: None,
                library_base: false,
            }]
        );

        let destination = with_relocation(&code, 6, 1, 0x20);
        assert_eq!(
            absolute_accesses(&destination, 0, 0x100),
            [AbsoluteAccess {
                site: 0,
                address: 0x20,
                size: Some(4),
                kind: AccessKind::Read,
                value: None,
                library_base: false,
            }]
        );
    }

    #[test]
    fn flags_a_slot_loaded_as_a_library_base() {
        // MOVEA.L (8,A5),A6 ; JSR (-30,A6) ; RTS
        let code = [0x2c, 0x6d, 0x00, 0x08, 0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75];
        let accesses = global_accesses(&analyze(&code, 0), 5, None);
        assert_eq!(accesses.len(), 1);
        assert!(accesses[0].library_base);
        assert_eq!(accesses[0].kind, AccessKind::Read);
    }

    /// Every operand the classifier reports for the instruction at offset 0.
    fn operand_accesses(code: &[u8]) -> Vec<(AddressingMode, Option<u8>, AccessKind)> {
        let analysis = analyze(code, 0);
        let decoded = &analysis.instructions[&0];
        let mut found = Vec::new();
        let coverage = for_each_operand_access(
            Isa::from(decoded.instruction.opcode),
            decoded.instruction.operands,
            |mode, size, kind| found.push((mode, size, kind)),
        );
        assert_eq!(coverage, OperandCoverage::Complete);
        found
    }

    #[test]
    fn addx_memory_form_reads_its_source_and_modifies_its_destination() {
        // ADDX.L -(A1),-(A2) ; RTS. Multi-precision arithmetic: real memory
        // traffic that used to reach every caller as an instruction touching
        // nothing at all.
        assert_eq!(
            operand_accesses(&[0xd5, 0x89, 0x4e, 0x75]),
            vec![
                (AddressingMode::Ariwpr(1), Some(4), AccessKind::Read),
                (AddressingMode::Ariwpr(2), Some(4), AccessKind::Modify),
            ]
        );
    }

    #[test]
    fn cmpm_reads_both_of_its_memory_operands() {
        // CMPM.W (A3)+,(A4)+ ; RTS — the buffer-compare idiom.
        assert_eq!(
            operand_accesses(&[0xb9, 0x4b, 0x4e, 0x75]),
            vec![
                (AddressingMode::Ariwpo(3), Some(2), AccessKind::Read),
                (AddressingMode::Ariwpo(4), Some(2), AccessKind::Read),
            ]
        );
    }

    #[test]
    fn the_register_form_of_addx_touches_no_memory() {
        // ADDX.L D1,D2 ; RTS — same mnemonic, no operand addresses memory.
        assert!(operand_accesses(&[0xd5, 0x81, 0x4e, 0x75]).is_empty());
    }

    /// The guard behind [`OperandCoverage`]: no instruction the pinned decoder
    /// produces reaches the classifier's fallthrough arm. An `m68000` upgrade
    /// that adds an operand form fails here rather than silently contributing
    /// no access to every walk built on this classifier.
    #[test]
    fn every_decodable_instruction_is_classified() {
        use m68000::instruction::Instruction;
        use m68000::memory_access::MemoryAccess;

        let mut unclassified = Vec::new();
        for opcode in 0..=u16::MAX {
            let isa = Isa::from(opcode);
            if isa == Isa::Unknown {
                continue;
            }
            // Extension words read as zero; only the operand *form* matters.
            let bytes = [(opcode >> 8) as u8, opcode as u8, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut memory = bytes.as_slice();
            let mut words = memory.iter_u16(0);
            let Ok(instruction) = Instruction::from_memory(&mut words) else {
                continue;
            };
            if for_each_operand_access(isa, instruction.operands, |_, _, _| {})
                != OperandCoverage::Complete
            {
                unclassified.push((opcode, isa));
            }
        }
        assert!(
            unclassified.is_empty(),
            "operand forms no walk would report: {unclassified:x?}"
        );
    }
}
