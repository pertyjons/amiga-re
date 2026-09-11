//! Extracting the addresses that instructions reference.
//!
//! Walks the decoded instructions of a [`ControlFlowAnalysis`] and reports every
//! absolute and PC-relative effective address they name — the immediates a
//! reader would otherwise resolve by hand (`JSR $1BA08`, `LEA (d16,PC),An`). The
//! resolved target is a hunk offset for PC-relative references and the encoded
//! absolute address for the two absolute forms.
//!
//! **The two absolute forms are distinct kinds because their encodings are.**
//! An absolute-long operand may be patched by a `HUNK_RELOC32` record and so can
//! name a hunk offset; there is no 16-bit relocation record, so an absolute-short
//! operand never can. Collapsing them would make `MOVEA.L (4).W,A6` — the
//! AbsExecBase idiom every Amiga program begins with — resolve to hunk offset 4
//! for a consumer with no load base, and turn into a `certain` "addressed from"
//! fact on whatever instruction happens to sit there.
//!
//! **Which operands it looks at is not this module's own list.** It walks
//! `globals::for_each_operand_access`, the one classifier every operand walk
//! goes through, and asserts its `OperandCoverage`. A second parallel list is how this module
//! came to miss `RegisterDirectionSizeEffectiveAddress` (ADD/AND/CMP/EOR/OR/SUB),
//! `RegisterSizeEffectiveAddress` (ADDA/CMPA/SUBA) and `DirectionEffectiveAddress`
//! (the memory shifts) for as long as it did: `CMP.L $00001000,D0` produced *no*
//! reference at all while `MOVE.W $00001000,D0` produced one, and nothing said so.
//! An operand form added upstream now reports itself here instead of contributing
//! silence.

use m68000::addressing_modes::AddressingMode;
use m68000::isa::Isa;

use crate::control_flow::{ControlFlowAnalysis, OperandRole, operand_longword_position};
use crate::globals::{OperandCoverage, for_each_operand_access, sign_extend_word};

/// How an instruction names its target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefKind {
    /// An absolute-long operand; `target` is the encoded absolute address.
    ///
    /// This is the only form a `HUNK_RELOC32` record can patch, so it is the
    /// only absolute form that may name a hunk offset.
    Absolute,
    /// An absolute-short operand; `target` is the encoded address, sign-extended
    /// to 32 bits as the 68000 extends it.
    ///
    /// Never a hunk offset: the encoding holds sixteen bits and no relocation
    /// record patches sixteen bits, so a consumer must read it in the absolute
    /// frame or not at all.
    AbsoluteShort,
    /// A PC-relative operand; `target` is resolved against the instruction's PC.
    PcRelative,
}

/// One address referenced by an instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reference {
    /// Address (hunk offset) of the referencing instruction.
    pub site: u32,
    /// The referenced address.
    pub target: u32,
    pub kind: RefKind,
    /// Exact hunk offset of a longword operand extension, when this reference
    /// uses one. Consumers use it to distinguish equal dual-EA addends.
    pub operand: Option<u32>,
}

/// Collect every absolute-long and PC-relative reference in `analysis`, ordered
/// by referencing site.
#[must_use]
pub fn references(analysis: &ControlFlowAnalysis) -> Vec<Reference> {
    let mut found = Vec::new();
    for (site, decoded) in &analysis.instructions {
        let coverage = for_each_operand_access(
            Isa::from(decoded.instruction.opcode),
            decoded.instruction.operands,
            |mode, _size, access| {
                if let Some((target, kind)) = resolve(mode) {
                    let role = OperandRole::for_access(decoded.instruction.operands, access);
                    found.push(Reference {
                        site: *site,
                        target,
                        kind,
                        operand: operand_longword_position(decoded, role),
                    });
                }
            },
        );
        debug_assert_eq!(
            coverage,
            OperandCoverage::Complete,
            "an operand form this classifier does not name references nothing at all"
        );
    }
    found
}

/// Resolve one addressing mode to the address it names, if it names one at
/// analysis time.
///
/// **The PC-relative index form resolves to its base displacement.** `(d8,PC,Xn)`
/// is how a position-independent jump table is reached: the base is the table
/// and the index is the entry, so the base is a real reference even though the
/// final address depends on a register. `(d8,An,Xn)` is deliberately *not*
/// resolved — its base is a register value, which is not known here.
///
/// **Absolute short resolves under its own kind**, sign-extended as the 68000
/// extends it, so that `(0xFFF8).W` names `0xFFFFFFF8` rather than `0xFFF8`.
/// Reporting it as [`RefKind::Absolute`] would let a consumer with no load base
/// read low memory as a hunk offset; [`RefKind::AbsoluteShort`] states the
/// encoding instead, and the encoding is what forbids that reading.
fn resolve(mode: AddressingMode) -> Option<(u32, RefKind)> {
    match mode {
        AddressingMode::AbsLong(address) => Some((address, RefKind::Absolute)),
        AddressingMode::AbsShort(address) => {
            Some((sign_extend_word(address), RefKind::AbsoluteShort))
        }
        AddressingMode::Pciwd(pc, displacement) => Some((
            pc.wrapping_add_signed(i32::from(displacement)),
            RefKind::PcRelative,
        )),
        AddressingMode::Pciwi8(pc, extension) => Some((
            pc.wrapping_add_signed(i32::from(extension.disp())),
            RefKind::PcRelative,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::analyze;

    #[test]
    fn resolves_an_absolute_long_reference() {
        // JSR $00001000 ; then RTS
        let code = [0x4e, 0xb9, 0x00, 0x00, 0x10, 0x00, 0x4e, 0x75];
        let refs = references(&analyze(&code, 0));
        assert!(refs.contains(&Reference {
            site: 0,
            target: 0x1000,
            kind: RefKind::Absolute,
            operand: Some(2),
        }));
    }

    #[test]
    fn equal_dual_ea_references_retain_distinct_longword_positions() {
        // MOVE.L $00000020.L,$00000020.L ; RTS
        let code = [
            0x23, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x4e, 0x75,
        ];
        let refs = references(&analyze(&code, 0));
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].operand, Some(6));
        assert_eq!(refs[1].operand, Some(2));
        assert!(
            refs.iter().all(|reference| {
                reference.target == 0x20 && reference.kind == RefKind::Absolute
            })
        );
    }

    #[test]
    fn resolves_a_pc_relative_reference() {
        // LEA (d16,PC),A0 ; then RTS
        let code = [0x41, 0xfa, 0x00, 0x04, 0x4e, 0x75];
        let refs = references(&analyze(&code, 0));
        assert!(
            refs.iter()
                .any(|reference| reference.site == 0 && reference.kind == RefKind::PcRelative)
        );
    }

    #[test]
    fn ignores_instructions_without_address_operands() {
        // NOP ; RTS
        let code = [0x4e, 0x71, 0x4e, 0x75];
        assert!(references(&analyze(&code, 0)).is_empty());
    }

    /// The three effective-address forms this module used to enumerate by hand
    /// and miss. Each is an ordinary instruction shape, and each reported *no*
    /// reference at all before the walk went through the shared classifier.
    #[test]
    fn resolves_the_arithmetic_effective_address_forms() {
        // CMP.L $00001000,D0 ; RTS — RegisterDirectionSizeEffectiveAddress.
        let compare = [0xb0, 0xb9, 0x00, 0x00, 0x10, 0x00, 0x4e, 0x75];
        assert!(
            references(&analyze(&compare, 0)).contains(&Reference {
                site: 0,
                target: 0x1000,
                kind: RefKind::Absolute,
                operand: Some(2),
            }),
            "a comparison against an absolute address named nothing"
        );

        // ADDA.L $00001000,A0 ; RTS — RegisterSizeEffectiveAddress.
        let add_address = [0xd1, 0xf9, 0x00, 0x00, 0x10, 0x00, 0x4e, 0x75];
        assert!(
            references(&analyze(&add_address, 0)).contains(&Reference {
                site: 0,
                target: 0x1000,
                kind: RefKind::Absolute,
                operand: Some(2),
            }),
            "an address-register add against an absolute address named nothing"
        );

        // ASL.W $00001000 ; RTS — DirectionEffectiveAddress (memory shift).
        let shift = [0xe1, 0xf9, 0x00, 0x00, 0x10, 0x00, 0x4e, 0x75];
        assert!(
            references(&analyze(&shift, 0)).contains(&Reference {
                site: 0,
                target: 0x1000,
                kind: RefKind::Absolute,
                operand: Some(2),
            }),
            "a memory shift of an absolute address named nothing"
        );
    }

    /// PC-relative comparisons against a limit are everywhere in
    /// position-independent Amiga code, and are the same missing form.
    #[test]
    fn resolves_a_pc_relative_arithmetic_operand() {
        // ADD.W (d16,PC),D0 ; RTS
        let code = [0xd0, 0x7a, 0x00, 0x04, 0x4e, 0x75];
        assert!(
            references(&analyze(&code, 0))
                .iter()
                .any(|reference| reference.site == 0 && reference.kind == RefKind::PcRelative),
            "a PC-relative add named nothing"
        );
    }

    /// Absolute short names an address, and says so under its own kind — never
    /// [`RefKind::Absolute`], which a consumer with no load base reads as a hunk
    /// offset. Low memory is exactly where the short form points, so that
    /// reading would fabricate a cross-reference on `MOVEA.L (4).W,A6`.
    #[test]
    fn an_absolute_short_operand_names_an_absolute_address() {
        // MOVEA.L (0x4).W,A6 ; RTS — AbsExecBase, not hunk offset 4.
        let exec_base = [0x2c, 0x78, 0x00, 0x04, 0x4e, 0x75];
        assert!(
            references(&analyze(&exec_base, 0)).contains(&Reference {
                site: 0,
                target: 0x4,
                kind: RefKind::AbsoluteShort,
                operand: None,
            }),
            "the AbsExecBase idiom named no address at all"
        );
        assert!(
            !references(&analyze(&exec_base, 0))
                .iter()
                .any(|reference| reference.kind == RefKind::Absolute),
            "the AbsExecBase idiom was reported in the frame a consumer reads as a hunk offset"
        );
    }

    /// The 68000 sign-extends the short form to 32 bits, so the high half of the
    /// address space is what `(0xFFF8).W` names — not offset `0xFFF8`, which is
    /// a plausible position inside a real hunk and would land in the code.
    #[test]
    fn an_absolute_short_operand_is_sign_extended() {
        // MOVEA.L (0xFFF8).W,A6 ; RTS
        let high = [0x2c, 0x78, 0xff, 0xf8, 0x4e, 0x75];
        assert!(
            references(&analyze(&high, 0)).contains(&Reference {
                site: 0,
                target: 0xffff_fff8,
                kind: RefKind::AbsoluteShort,
                operand: None,
            }),
            "a negative absolute-short displacement was not sign-extended"
        );
    }

    /// `(d8,PC,Xn)` reaches a jump table: the base displacement is the table and
    /// is a real reference, even though the entry depends on a register.
    #[test]
    fn a_pc_relative_index_operand_resolves_its_base() {
        // JMP (6,PC,D0.W)
        let code = [0x4e, 0xfb, 0x00, 0x06];
        assert!(
            references(&analyze(&code, 0))
                .iter()
                .any(|reference| reference.site == 0 && reference.kind == RefKind::PcRelative),
            "a PC-relative indexed jump named nothing"
        );
    }
}
