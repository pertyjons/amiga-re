//! Immediate/register stores through a designated pointer register, resolved to
//! their **offset from that register's value at a chosen entry**.
//!
//! This is the analysis behind tracing CPU writes into a block of memory whose
//! runtime address is not statically known — for example a Copper list copied to
//! a fresh allocation before being patched. The absolute destination cannot be
//! computed, but the *offset into the block* can: seed the base register with a
//! symbolic origin of 0 at the entry where it already points at the block, then
//! follow straight-line constant address arithmetic (`LEA`, register-copy
//! `MOVEA`, `ADDA`/`SUBA`/`ADDQ`/`SUBQ`, pre/postincrement) and report each store
//! through the tracked pointer as `(offset, value)`.
//!
//! Like [`crate::derived`], the pass is conservative: branch targets, calls,
//! joins, and any non-constant redefinition of a tracked register clear its
//! offset, so a write is only reported when its offset is provably known.
//!
//! A routine need not *receive* the block's address. A helper that loads it as
//! a constant — `MOVEA.L #list,A0`, `LEA list.L,A0` — establishes the same base
//! at that instruction, and until this pass could say so, every store after such
//! a load was dropped: the load overwrites the register the caller named, and an
//! absolute address is not related to the entry value. Give the pass a
//! [`BlockAddress`] and a constant landing inside the block seeds the register it
//! is loaded into. The block bound is what makes that safe — without it, any
//! constant would be read as a base and stores into unrelated memory would be
//! reported as edits to this block. Each write records which of the two
//! established its base ([`PointerWrite::base`]), because one is the caller's
//! assertion and the other is a fact about the code.

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Operands, Size};
use m68000::isa::Isa;

use crate::control_flow::ControlFlowAnalysis;
use crate::derived::{clobbers_tracked_registers, reset_sites};
use crate::globals::{
    AccessKind, OperandCoverage, constant_write, for_each_operand_access, sign_extend_word,
};

/// Where the block being written into lives in the address space, for a routine
/// that loads its address as a constant rather than receiving it.
///
/// `length` is what keeps the match honest: a constant is read as this block's
/// base only when it lands inside the block. A pointer to `address + length`
/// counts too, because loading the end and storing backwards with predecrement
/// is an ordinary shape and every such store still lands inside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockAddress {
    /// Absolute address the block's offset 0 sits at.
    pub address: u32,
    /// The block's length in bytes.
    pub length: u32,
}

impl BlockAddress {
    /// The block-relative offset `address` names, when it is in the block.
    fn offset_of(self, address: u32) -> Option<i64> {
        let difference = address.checked_sub(self.address)?;
        (difference <= self.length).then_some(i64::from(difference))
    }
}

/// How a write's base was established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerBase {
    /// The base register's value at the chosen entry: what the caller asserted.
    Entry,
    /// A constant address the instruction at this hunk offset loaded, matched
    /// against the block: a fact about the code rather than an assertion.
    Loaded(u32),
}

/// One store through the tracked pointer register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerWrite {
    /// Hunk-relative address of the storing instruction.
    pub site: u32,
    /// The address register the store went through.
    pub register: u8,
    /// Byte offset of the store from the base register's origin.
    pub offset: u32,
    /// Operand size in bytes (1/2/4), where the encoding gives one.
    pub size: Option<u8>,
    /// The immediate value stored (`MOVE #imm` / `CLR`), if any.
    pub value: Option<u32>,
    /// Which base the offset is measured from.
    pub base: PointerBase,
}

/// One address register's tracked distance from a base, and which base.
#[derive(Clone, Copy, Debug)]
struct Tracked {
    offset: i64,
    base: PointerBase,
}

type Offsets = [Option<Tracked>; 8];

/// Find every store through `base_register` (0..=7 for A0..A7), treating its
/// value at `entry` as offset 0 and following straight-line constant address
/// arithmetic. Stores whose offset is unknown or negative are not reported.
///
/// `block` additionally establishes the base wherever the routine loads the
/// block's address as a constant. Pass `None` when the block's runtime address
/// is unknown, which is the case the entry value exists for. `image_origin`
/// maps same-hunk relocated constants stored through the pointer; without it
/// those values are omitted rather than reported as raw addends.
#[must_use]
pub fn pointer_relative_writes(
    analysis: &ControlFlowAnalysis,
    entry: u32,
    base_register: u8,
    block: Option<BlockAddress>,
    image_origin: Option<u32>,
) -> Vec<PointerWrite> {
    if usize::from(base_register) >= 8 {
        return Vec::new();
    }
    let reset = reset_sites(analysis);
    let mut offsets: Offsets = [None; 8];
    let mut previous_end = None;
    let mut writes = Vec::new();

    for (site, decoded) in &analysis.instructions {
        // Seed at the chosen entry; otherwise clear on any discontinuity or join.
        if *site == entry {
            offsets = [None; 8];
            offsets[usize::from(base_register)] = Some(Tracked {
                offset: 0,
                base: PointerBase::Entry,
            });
        } else if previous_end != Some(*site) || reset.contains(site) {
            offsets = [None; 8];
        }

        let isa = Isa::from(decoded.instruction.opcode);
        let constant = constant_write(analysis, decoded, image_origin);
        let coverage =
            for_each_operand_access(isa, decoded.instruction.operands, |mode, size, kind| {
                let Some((register, tracked)) = resolve_operand(mode, size, &mut offsets) else {
                    return;
                };
                if !matches!(kind, AccessKind::Write | AccessKind::Modify) {
                    return;
                }
                let Ok(offset) = u32::try_from(tracked.offset) else {
                    return;
                };
                let value = constant
                    .filter(|(destination, _)| *destination == mode)
                    .map(|(_, value)| value);
                writes.push(PointerWrite {
                    site: *site,
                    register,
                    offset,
                    size,
                    value,
                    base: tracked.base,
                });
            });
        debug_assert_eq!(
            coverage,
            OperandCoverage::Complete,
            "an operand form this classifier does not name contributes no access at all"
        );

        transfer(
            *site,
            isa,
            decoded.instruction.operands,
            &mut offsets,
            block,
        );
        if clobbers_tracked_registers(isa) {
            offsets = [None; 8];
        }
        previous_end = Some(decoded.end);
    }
    writes
}

/// The `(register, tracked offset)` an indirect operand resolves to, applying
/// any pre/postincrement side effect. Returns `None` for non-address-register
/// modes or when the register's offset is unknown.
fn resolve_operand(
    mode: AddressingMode,
    size: Option<u8>,
    offsets: &mut Offsets,
) -> Option<(u8, Tracked)> {
    let shift = |tracked: Tracked, by: i64| Tracked {
        offset: tracked.offset + by,
        base: tracked.base,
    };
    match mode {
        AddressingMode::Ari(register) => Some((register, offsets[usize::from(register)]?)),
        AddressingMode::Ariwd(register, displacement) => Some((
            register,
            shift(offsets[usize::from(register)]?, i64::from(displacement)),
        )),
        AddressingMode::Ariwpo(register) => {
            let base = offsets[usize::from(register)]?;
            offsets[usize::from(register)] =
                Some(shift(base, i64::from(increment_bytes(register, size))));
            Some((register, base))
        }
        AddressingMode::Ariwpr(register) => {
            let base = shift(
                offsets[usize::from(register)]?,
                -i64::from(increment_bytes(register, size)),
            );
            offsets[usize::from(register)] = Some(base);
            Some((register, base))
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

/// Propagate symbolic offsets across an instruction's register-defining effect.
fn transfer(
    site: u32,
    isa: Isa,
    operands: Operands,
    offsets: &mut Offsets,
    block: Option<BlockAddress>,
) {
    // A constant address, read as this block's base when it lands inside it.
    let loaded = |address: u32| {
        block?.offset_of(address).map(|offset| Tracked {
            offset,
            base: PointerBase::Loaded(site),
        })
    };
    let adjust = |slot: &mut Option<Tracked>, by: i64| {
        *slot = slot.map(|tracked| Tracked {
            offset: tracked.offset + by,
            base: tracked.base,
        });
    };
    match operands {
        // LEA <ea>,An: an address-register-relative source stays related to the
        // origin, and an absolute one establishes the base when it names this
        // block. Every other source is a fresh, unrelated value.
        Operands::RegisterEffectiveAddress(destination, source) if isa == Isa::Lea => {
            offsets[usize::from(destination)] = match source {
                AddressingMode::AbsLong(address) => loaded(address),
                AddressingMode::AbsShort(address) => loaded(sign_extend_word(address)),
                other => symbolic_lea(other, offsets),
            };
        }
        // MOVEA <ea>,An: a register copy preserves the offset, and an immediate
        // establishes the base on the same terms as an absolute `LEA`.
        Operands::SizeRegisterEffectiveAddress(size, destination, source) => {
            offsets[usize::from(destination)] = match source {
                AddressingMode::Ard(register) => offsets[usize::from(register)],
                AddressingMode::Immediate(value) => loaded(address_immediate(size, value) as u32),
                _ => None,
            };
        }
        // ADDA #imm,An.
        Operands::RegisterSizeEffectiveAddress(
            destination,
            size,
            AddressingMode::Immediate(value),
        ) if isa == Isa::Adda => {
            adjust(
                &mut offsets[usize::from(destination)],
                i64::from(address_immediate(size, value)),
            );
        }
        // SUBA #imm,An.
        Operands::RegisterSizeEffectiveAddress(
            destination,
            size,
            AddressingMode::Immediate(value),
        ) if isa == Isa::Suba => {
            adjust(
                &mut offsets[usize::from(destination)],
                -i64::from(address_immediate(size, value)),
            );
        }
        // ADDA/SUBA <ea>,An with a non-immediate source: unknown.
        Operands::RegisterSizeEffectiveAddress(destination, _, _)
            if matches!(isa, Isa::Adda | Isa::Suba) =>
        {
            offsets[usize::from(destination)] = None;
        }
        // ADDQ/SUBQ #k,An. The 3-bit quick field encodes 8 as 0.
        Operands::DataSizeEffectiveAddress(value, _, AddressingMode::Ard(destination)) => {
            let amount = quick_immediate(value);
            let signed = if isa == Isa::Addq { amount } else { -amount };
            adjust(&mut offsets[usize::from(destination)], signed);
        }
        Operands::RegisterOpmodeRegister(left, Direction::ExchangeAddress, right) => {
            offsets.swap(usize::from(left), usize::from(right));
        }
        Operands::RegisterOpmodeRegister(_, Direction::ExchangeDataAddress, address) => {
            offsets[usize::from(address)] = None;
        }
        Operands::RegisterDisplacement(register, _) => {
            offsets[usize::from(register)] = None;
        }
        Operands::Register(register) if isa == Isa::Unlk => {
            offsets[usize::from(register)] = None;
        }
        Operands::DirectionRegister(Direction::UspToRegister, register) => {
            offsets[usize::from(register)] = None;
        }
        Operands::DirectionSizeEffectiveAddressList(Direction::MemoryToRegister, _, _, list) => {
            for (register, value) in offsets.iter_mut().enumerate() {
                if list & (1 << (register + 8)) != 0 {
                    *value = None;
                }
            }
        }
        _ => {}
    }
}

fn symbolic_lea(mode: AddressingMode, offsets: &Offsets) -> Option<Tracked> {
    match mode {
        AddressingMode::Ari(register) => offsets[usize::from(register)],
        AddressingMode::Ariwd(register, displacement) => {
            offsets[usize::from(register)].map(|tracked| Tracked {
                offset: tracked.offset + i64::from(displacement),
                base: tracked.base,
            })
        }
        _ => None,
    }
}

fn address_immediate(size: Size, value: u32) -> i32 {
    match size {
        Size::Word => i32::from(value as i16),
        _ => value as i32,
    }
}

/// The value of an `ADDQ`/`SUBQ` 3-bit "quick" field: 1..=7 literally, but 0
/// encodes 8 on the MC68000.
fn quick_immediate(value: u8) -> i64 {
    if value == 0 { 8 } else { i64::from(value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;

    fn with_relocation(code: &[u8], target_hunk: u32) -> ControlFlowAnalysis {
        crate::analyze_entries_with(
            code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(crate::Relocations::new(
                    0,
                    [crate::Relocation {
                        patched: 2,
                        target_hunk,
                        target_offset: 0x20,
                    }],
                )),
                ..crate::FlowOptions::default()
            },
        )
    }

    #[test]
    fn resolves_displacement_and_direct_stores() {
        // MOVE.L #$F00,(4,A0) ; MOVE.L #$FFF,(A0) ; RTS
        let code = [
            0x21, 0x7c, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x04, // MOVE.L #$F00,(4,A0)
            0x20, 0xbc, 0x00, 0x00, 0x0f, 0xff, // MOVE.L #$FFF,(A0)
            0x4e, 0x75, // RTS
        ];
        let writes = pointer_relative_writes(&analyze(&code, 0), 0, 0, None, None);
        assert_eq!(
            writes,
            [
                PointerWrite {
                    site: 0,
                    register: 0,
                    offset: 4,
                    size: Some(4),
                    value: Some(0xf00),
                    base: PointerBase::Entry,
                },
                PointerWrite {
                    site: 8,
                    register: 0,
                    offset: 0,
                    size: Some(4),
                    value: Some(0xfff),
                    base: PointerBase::Entry,
                },
            ]
        );
    }

    #[test]
    fn a_relocated_pointer_write_value_needs_a_local_runtime_mapping() {
        // MOVE.L #$20,(A0) ; RTS. The store location comes from the entry seed;
        // only the immediate value is relocation-sensitive.
        let code = [0x20, 0xbc, 0x00, 0x00, 0x00, 0x20, 0x4e, 0x75];
        let same_hunk = with_relocation(&code, 0);
        assert_eq!(
            pointer_relative_writes(&same_hunk, 0, 0, None, Some(0x1000))[0].value,
            Some(0x1020)
        );
        assert_eq!(
            pointer_relative_writes(&same_hunk, 0, 0, None, None)[0].value,
            None
        );

        let other_hunk = with_relocation(&code, 1);
        assert_eq!(
            pointer_relative_writes(&other_hunk, 0, 0, None, Some(0x1000))[0].value,
            None
        );
    }

    #[test]
    fn a_pointer_write_keeps_a_word_immediate_scalar() {
        let code = [0x30, 0xbc, 0x00, 0x20, 0x4e, 0x75];
        let analysis = with_relocation(&code, 1);
        assert_eq!(
            pointer_relative_writes(&analysis, 0, 0, None, Some(0x1000))[0].value,
            Some(0x20)
        );
    }

    #[test]
    fn tracks_a_constant_pointer_adjustment() {
        // ADDQ.L #4,A0 ; MOVE.L #$AAA,(A0) ; RTS — offset shifts to 4.
        let code = [
            0x58, 0x88, // ADDQ.L #4,A0
            0x20, 0xbc, 0x00, 0x00, 0x0a, 0xaa, // MOVE.L #$AAA,(A0)
            0x4e, 0x75,
        ];
        let writes = pointer_relative_writes(&analyze(&code, 0), 0, 0, None, None);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].offset, 4);
        assert_eq!(writes[0].value, Some(0xaaa));
    }

    #[test]
    fn addq_of_eight_advances_by_eight_not_zero() {
        // ADDQ.L #8,A0 ; MOVE.L #$AAA,(A0) ; RTS — the quick field 0 means 8.
        let code = [
            0x50, 0x88, // ADDQ.L #8,A0
            0x20, 0xbc, 0x00, 0x00, 0x0a, 0xaa, // MOVE.L #$AAA,(A0)
            0x4e, 0x75,
        ];
        let writes = pointer_relative_writes(&analyze(&code, 0), 0, 0, None, None);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].offset, 8);
    }

    #[test]
    fn postincrement_advances_the_offset() {
        // MOVE.L #$1,(A0)+ ; MOVE.L #$2,(A0)+ ; RTS — offsets 0 then 4.
        let code = [
            0x20, 0xfc, 0x00, 0x00, 0x00, 0x01, // MOVE.L #$1,(A0)+
            0x20, 0xfc, 0x00, 0x00, 0x00, 0x02, // MOVE.L #$2,(A0)+
            0x4e, 0x75,
        ];
        let writes = pointer_relative_writes(&analyze(&code, 0), 0, 0, None, None);
        assert_eq!(
            writes.iter().map(|write| write.offset).collect::<Vec<_>>(),
            [0, 4]
        );
    }

    #[test]
    fn copies_the_offset_through_a_register_alias() {
        // MOVEA.L A0,A1 ; MOVE.L #$5,(8,A1) ; RTS — the write is at A0-relative 8.
        let code = [
            0x22, 0x48, // MOVEA.L A0,A1
            0x23, 0x7c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x08, // MOVE.L #$5,(8,A1)
            0x4e, 0x75,
        ];
        let writes = pointer_relative_writes(&analyze(&code, 0), 0, 0, None, None);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].register, 1);
        assert_eq!(writes[0].offset, 8);
    }

    #[test]
    fn a_constant_load_of_the_block_address_establishes_the_base() {
        // MOVEA.L #$40000,A0 ; MOVE.W #$0F00,(2,A0) ; LEA $40010.L,A1 ;
        // MOVE.W #$0FFF,(A1) ; RTS
        //
        // Without the block the load kills the entry seed and neither store is
        // reported, which is the whole defect: a helper that loads the list
        // itself looked like a routine that never touches it.
        let code = [
            0x20, 0x7c, 0x00, 0x04, 0x00, 0x00, // MOVEA.L #$40000,A0
            0x31, 0x7c, 0x0f, 0x00, 0x00, 0x02, // MOVE.W #$0F00,(2,A0)
            0x43, 0xf9, 0x00, 0x04, 0x00, 0x10, // LEA $40010.L,A1
            0x32, 0xbc, 0x0f, 0xff, // MOVE.W #$0FFF,(A1)
            0x4e, 0x75, // RTS
        ];
        let analysis = analyze(&code, 0);
        assert!(
            pointer_relative_writes(&analysis, 0, 0, None, None).is_empty(),
            "the entry value cannot explain a store after an absolute load"
        );

        let block = BlockAddress {
            address: 0x0004_0000,
            length: 0x40,
        };
        let writes = pointer_relative_writes(&analysis, 0, 0, Some(block), None);
        assert_eq!(
            writes
                .iter()
                .map(|write| (write.register, write.offset, write.value, write.base))
                .collect::<Vec<_>>(),
            [
                (0, 2, Some(0x0f00), PointerBase::Loaded(0)),
                (1, 0x10, Some(0x0fff), PointerBase::Loaded(12)),
            ]
        );
    }

    #[test]
    fn a_constant_outside_the_block_is_not_a_base() {
        // The same routine pointed at a block it does not name: an unrelated
        // constant must stay unrelated, or every absolute store in a program
        // would be reported as an edit to this list.
        let code = [
            0x20, 0x7c, 0x00, 0x04, 0x00, 0x00, // MOVEA.L #$40000,A0
            0x31, 0x7c, 0x0f, 0x00, 0x00, 0x02, // MOVE.W #$0F00,(2,A0)
            0x4e, 0x75, // RTS
        ];
        let writes = pointer_relative_writes(
            &analyze(&code, 0),
            0,
            0,
            Some(BlockAddress {
                address: 0x0005_0000,
                length: 0x40,
            }),
            None,
        );
        assert!(writes.is_empty(), "{writes:?}");
    }

    #[test]
    fn a_pointer_to_the_end_of_the_block_serves_predecrement_stores() {
        // LEA $40004.L,A0 ; MOVE.W #$1,-(A0) ; MOVE.W #$2,-(A0) ; RTS.
        // Loading the end and walking backwards is an ordinary shape, and both
        // stores land inside a four-byte block.
        let code = [
            0x41, 0xf9, 0x00, 0x04, 0x00, 0x04, // LEA $40004.L,A0
            0x31, 0x3c, 0x00, 0x01, // MOVE.W #$1,-(A0)
            0x31, 0x3c, 0x00, 0x02, // MOVE.W #$2,-(A0)
            0x4e, 0x75,
        ];
        let writes = pointer_relative_writes(
            &analyze(&code, 0),
            0,
            0,
            Some(BlockAddress {
                address: 0x0004_0000,
                length: 4,
            }),
            None,
        );
        assert_eq!(
            writes.iter().map(|write| write.offset).collect::<Vec<_>>(),
            [2, 0]
        );
    }

    #[test]
    fn clears_the_offset_at_a_branch_target() {
        // BRA +2 ; NOP ; MOVE.L #$5,(A0) ; RTS — the store is not resolvable.
        let code = [
            0x60, 0x02, // BRA +2 -> 4
            0x4e, 0x71, // NOP (branch target region)
            0x20, 0xbc, 0x00, 0x00, 0x00, 0x05, // MOVE.L #$5,(A0)
            0x4e, 0x75,
        ];
        let writes = pointer_relative_writes(&analyze(&code, 0), 0, 0, None, None);
        assert!(writes.is_empty());
    }
}
