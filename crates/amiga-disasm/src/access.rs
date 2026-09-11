//! Finding custom-chip register accesses in code.
//!
//! Amiga code touches the custom chips two ways: through an absolute-long
//! operand (`$DFFxxx`), or — the dominant idiom — through an address register
//! holding the `$DFF000` base with a displacement, e.g. `MOVE.W #x,(0x96,A6)`.
//!
//! This resolves both. Base registers are found by scanning for an address
//! register loaded with the custom base (`LEA $DFF000,An` or
//! `MOVEA.L #$DFF000,An`); the scan is deliberately conservative and sticky:
//! once a register is seen holding the base it is treated as the base for all
//! its displacement accesses, which is accurate for the common set-once idiom
//! but does not model a register later reused for a different base. The negative
//! displacements of AmigaOS library calls (`JSR (-30,A6)`) are excluded by
//! range, so they are never mistaken for register accesses.

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::Operands;
use m68000::isa::Isa;

use crate::control_flow::ControlFlowAnalysis;
use crate::globals::{AccessKind, OperandCoverage, for_each_operand_access};

/// The size of the custom-chip register block, in bytes.
const CUSTOM_RANGE: u32 = 0x200;

/// How an access names its register.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessForm {
    /// An absolute-long `$DFFxxx` operand.
    Absolute,
    /// An `(displacement, An)` operand where `An` holds the custom base.
    BaseRelative,
}

/// One custom-chip register access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterAccess {
    /// Address (hunk offset) of the accessing instruction.
    pub site: u32,
    /// Register offset from the custom base (e.g. `0x096` for `DMACON`).
    pub offset: u16,
    pub form: AccessForm,
    /// Whether the register is read, written, or read-modified.
    pub kind: AccessKind,
}

/// Find every custom-chip register access reached by `analysis`, treating
/// `custom_base` (normally `$DFF000`) as the chip register base.
///
/// The access direction (`kind`) comes from the same shared operand-access
/// classifier every other operand walk uses, so a `MOVE.W #x,DMACON` reports [`AccessKind::Write`]
/// and a `MOVE.W INTENAR,D0` reports [`AccessKind::Read`].
#[must_use]
pub fn register_accesses(analysis: &ControlFlowAnalysis, custom_base: u32) -> Vec<RegisterAccess> {
    let custom_end = custom_base.saturating_add(CUSTOM_RANGE);
    let base_registers = base_registers(analysis, custom_base);

    let mut accesses = Vec::new();
    for (site, decoded) in &analysis.instructions {
        let coverage = for_each_operand_access(
            Isa::from(decoded.instruction.opcode),
            decoded.instruction.operands,
            |mode, _size, kind| {
                let register = match mode {
                    // Absolute $DFFxxx, excluding the base itself (offset 0). The
                    // guard bounds `address - custom_base` to 1..0x200.
                    AddressingMode::AbsLong(address)
                        if address > custom_base && address < custom_end =>
                    {
                        Some(((address - custom_base) as u16, AccessForm::Absolute))
                    }
                    // (d16, An) where An holds the custom base and d16 is a register
                    // offset (non-negative, within the block).
                    AddressingMode::Ariwd(register, displacement)
                        if base_registers.get(usize::from(register)) == Some(&true)
                            && (0..CUSTOM_RANGE as i16).contains(&displacement) =>
                    {
                        Some((displacement as u16, AccessForm::BaseRelative))
                    }
                    _ => None,
                };
                if let Some((offset, form)) = register {
                    accesses.push(RegisterAccess {
                        site: *site,
                        offset,
                        form,
                        kind,
                    });
                }
            },
        );
        debug_assert_eq!(
            coverage,
            OperandCoverage::Complete,
            "an operand form this classifier does not name contributes no access at all"
        );
    }
    accesses
}

/// Which of the eight address registers are seen loaded with `custom_base`.
fn base_registers(analysis: &ControlFlowAnalysis, custom_base: u32) -> [bool; 8] {
    let mut loaded = [false; 8];
    for decoded in analysis.instructions.values() {
        let register = match decoded.instruction.operands {
            // LEA $DFF000, An
            Operands::RegisterEffectiveAddress(register, AddressingMode::AbsLong(address))
                if address == custom_base =>
            {
                register
            }
            // MOVEA.L #$DFF000, An
            Operands::SizeRegisterEffectiveAddress(
                _,
                register,
                AddressingMode::Immediate(value),
            ) if value == custom_base => register,
            _ => continue,
        };
        if let Some(slot) = loaded.get_mut(usize::from(register)) {
            *slot = true;
        }
    }
    loaded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::analyze;

    const DFF000: u32 = 0x00df_f000;

    #[test]
    fn finds_an_absolute_register_write() {
        // MOVE.W #$8020, $00DFF096 ; RTS
        let code = [0x33, 0xfc, 0x80, 0x20, 0x00, 0xdf, 0xf0, 0x96, 0x4e, 0x75];
        let accesses = register_accesses(&analyze(&code, 0), DFF000);
        assert!(accesses.contains(&RegisterAccess {
            site: 0,
            offset: 0x096,
            form: AccessForm::Absolute,
            kind: AccessKind::Write,
        }));
    }

    #[test]
    fn classifies_an_absolute_register_read() {
        // MOVE.W $00DFF01C,D0 ; RTS — read INTENAR into D0.
        let code = [0x30, 0x39, 0x00, 0xdf, 0xf0, 0x1c, 0x4e, 0x75];
        let accesses = register_accesses(&analyze(&code, 0), DFF000);
        assert!(accesses.contains(&RegisterAccess {
            site: 0,
            offset: 0x01c,
            form: AccessForm::Absolute,
            kind: AccessKind::Read,
        }));
    }

    #[test]
    fn finds_a_base_relative_access_after_loading_the_base() {
        // LEA $00DFF000,A6 ; MOVE.W #$8020,(0x96,A6) ; RTS
        let code = [
            0x4d, 0xf9, 0x00, 0xdf, 0xf0, 0x00, // LEA $DFF000,A6
            0x3d, 0x7c, 0x80, 0x20, 0x00, 0x96, // MOVE.W #$8020,(0x96,A6)
            0x4e, 0x75, // RTS
        ];
        let accesses = register_accesses(&analyze(&code, 0), DFF000);
        assert!(accesses.contains(&RegisterAccess {
            site: 6,
            offset: 0x096,
            form: AccessForm::BaseRelative,
            kind: AccessKind::Write,
        }));
        // The base-loading LEA itself (offset 0) is not reported as an access.
        assert!(accesses.iter().all(|access| access.offset != 0));
    }

    #[test]
    fn does_not_treat_a_plain_address_register_offset_as_a_register() {
        // Without a base load, (0x96,A6) is not a custom-chip access.
        // MOVE.W #$8020,(0x96,A6) ; RTS
        let code = [0x3d, 0x7c, 0x80, 0x20, 0x00, 0x96, 0x4e, 0x75];
        assert!(register_accesses(&analyze(&code, 0), DFF000).is_empty());
    }
}
