//! Conservative data-table dispatch recognition over a completed traversal.
//!
//! The accepted suffix is CMP[I] / BHI, explicit index scaling, a table load,
//! and JMP. Optional LEA instructions establish table bases. The entire suffix
//! must have no other incoming edges. Table size comes from the unsigned guard,
//! never from scanning plausible-looking data until the first bad pointer.

use super::{
    AddressingMode, ControlFlowAnalysis, DecodedInstruction, Direction, FlowIndex, FlowKind, Isa,
    OperandAddress, OperandRole, Operands, Size, decode, valid_address,
};
use m68000::addressing_modes::BriefExtensionWord;

const MAX_PREFIX_INSTRUCTIONS: usize = 12;
const MAX_TABLE_ENTRIES: u32 = 256;
// An MC68000 MOVE with two absolute-long operands is the longest encoding.
const MAX_INSTRUCTION_BYTES: u32 = 10;

/// A loaded target must not fall back to the legacy BRA-stub scan if its
/// guard or data table is malformed: nearby executable bytes are not entries.
pub(super) fn loads_target(analysis: &ControlFlowAnalysis, site: u32) -> bool {
    let Some(jump) = analysis.instructions.get(&site) else {
        return false;
    };
    let Some((_, load)) = analysis.instructions.range(..site).next_back() else {
        return false;
    };
    if load.end != site {
        return false;
    }
    let Some((width, destination, AddressingMode::Pciwi8(..) | AddressingMode::Ariwi8(..))) =
        table_load(load)
    else {
        return false;
    };
    match jump.instruction.operands {
        Operands::EffectiveAddress(
            AddressingMode::Pciwi8(_, extension) | AddressingMode::Ariwi8(_, extension),
        ) => {
            width == 2
                && extension.0 & 0x8000 == 0
                && ((extension.0 >> 12) & 7) as u8 == destination
        }
        Operands::EffectiveAddress(AddressingMode::Ari(register)) => {
            width == 4 && register == destination
        }
        _ => false,
    }
}

/// Recover a complete table or retain the dispatch's unresolved-flow warning.
pub(super) fn targets(
    code: &[u8],
    analysis: &ControlFlowAnalysis,
    index: &FlowIndex,
    site: u32,
) -> Option<Vec<u32>> {
    let jump = analysis.instructions.get(&site)?;
    if Isa::from(jump.instruction.opcode) != Isa::Jmp {
        return None;
    }
    let mut prefix = vec![jump];
    let mut cursor = site;
    for (_, previous) in analysis.instructions.range(..site).rev() {
        if previous.end != cursor || prefix.len() >= MAX_PREFIX_INSTRUCTIONS {
            break;
        }
        prefix.push(previous);
        cursor = previous.address;
    }
    prefix.reverse();
    let compare_index = prefix
        .iter()
        .rposition(|decoded| comparison(decoded).is_some())?;
    let compare = prefix[compare_index];
    let (size, register, maximum) = comparison(compare)?;
    let count = maximum
        .checked_add(1)
        .filter(|count| *count <= MAX_TABLE_ENTRIES)?;
    let guard = *prefix.get(compare_index.checked_add(1)?)?;
    if !matches!(
        guard.instruction.operands,
        Operands::ConditionDisplacement(2, _)
    ) || Isa::from(guard.instruction.opcode) != Isa::Bcc
    {
        return None;
    }
    // A LEA directly before the comparison is a common compiler spelling.
    // Include it in the proof so a path entering at CMP cannot skip the base.
    let start = compare_index
        .checked_sub(1)
        .filter(|index| Isa::from(prefix[*index].instruction.opcode) == Isa::Lea)
        .unwrap_or(compare_index);
    let prefix = &prefix[start..];
    if !exclusive_prefix(analysis, index, prefix, guard.address) {
        return None;
    }
    let load_index = prefix.len().checked_sub(2)?;
    let load = prefix[load_index];
    if load.address <= guard.address {
        return None;
    }
    let (width, destination, lookup) = table_load(load)?;
    let mut bases = [None; 8];
    let mut stride = 1_u32;
    for decoded in &prefix[..load_index] {
        if decoded.address == compare.address || decoded.address == guard.address {
            continue;
        }
        if let Some((base, offset)) = lea_offset(code, analysis, decoded) {
            bases[usize::from(base)] = Some(offset);
        } else if decoded.address > guard.address {
            stride = stride.checked_mul(scale_factor(decoded, size, register)?)?;
        } else {
            return None;
        }
    }
    if stride != width {
        return None;
    }
    let (table, lookup_index, long) = indexed_base(lookup, &bases)?;
    if lookup_index != register || long != matches!(size, Size::Long) {
        return None;
    }
    // Brief word indices sign-extend. Refuse a guard/scale combination whose
    // final byte offset could wrap or become negative.
    maximum
        .checked_mul(stride)
        .filter(|offset| *offset <= i16::MAX as u32)?;
    let Operands::EffectiveAddress(jump_mode) = jump.instruction.operands else {
        return None;
    };
    let relative_base = if width == 2 {
        let (base, jump_index, long) = indexed_base(jump_mode, &bases)?;
        if jump_index != destination || long {
            return None;
        }
        Some(base)
    } else {
        if jump_mode != AddressingMode::Ari(destination) {
            return None;
        }
        None
    };
    let table_end = table.checked_add(count.checked_mul(width)?)?;
    if !table.is_multiple_of(2) || instruction_overlaps(analysis, table, table_end) {
        return None;
    }
    let bytes = code.get(usize::try_from(table).ok()?..usize::try_from(table_end).ok()?)?;
    let mut targets = std::collections::BTreeSet::new();
    for (index, entry) in bytes.chunks_exact(usize::try_from(width).ok()?).enumerate() {
        let target = if let Some(base) = relative_base {
            base.checked_add_signed(i32::from(i16::from_be_bytes([entry[0], entry[1]])))?
        } else {
            let value = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let patched = table.checked_add(u32::try_from(index).ok()?.checked_mul(width)?)?;
            pointer_offset(code, analysis, patched, value)?
        };
        if !valid_address(code, target)
            || (table..table_end).contains(&target)
            || (prefix[0].address..jump.end).contains(&target)
            || analysis
                .instructions
                .range(target.saturating_sub(MAX_INSTRUCTION_BYTES)..target)
                .any(|(_, previous)| previous.end > target)
        {
            return None;
        }
        // A complete first instruction must fit. Do not accept a truncated
        // opcode or a decoder-unknown word just because its address is even.
        if targets.insert(target) {
            let decoded = decode(code, target, target)?;
            if Isa::from(decoded.instruction.opcode) == Isa::Unknown
                && !decoded.is_opaque_fallthrough()
            {
                return None;
            }
        }
    }
    Some(targets.into_iter().collect())
}

fn comparison(decoded: &DecodedInstruction) -> Option<(Size, u8, u32)> {
    match (
        Isa::from(decoded.instruction.opcode),
        decoded.instruction.operands,
    ) {
        (
            Isa::Cmpi,
            Operands::SizeEffectiveAddressImmediate(size, AddressingMode::Drd(register), maximum),
        )
        | (
            Isa::Cmp,
            Operands::RegisterDirectionSizeEffectiveAddress(
                register,
                Direction::DstReg,
                size,
                AddressingMode::Immediate(maximum),
            ),
        ) if matches!(size, Size::Word | Size::Long) => Some((size, register, maximum)),
        _ => None,
    }
}

fn exclusive_prefix(
    analysis: &ControlFlowAnalysis,
    index: &FlowIndex,
    prefix: &[&DecodedInstruction],
    guard: u32,
) -> bool {
    if prefix.iter().any(|decoded| {
        decoded.owners != prefix[0].owners || decoded.owner_total != decoded.owners.len()
    }) {
        return false;
    }
    prefix.windows(2).all(|pair| {
        let (previous, next) = (pair[0], pair[1]);
        !analysis.functions.contains(&next.address)
            && index.by_target.get(&next.address).is_some_and(|flows| {
                !flows.is_empty()
                    && flows.iter().all(|flow| {
                        flow.site == previous.address && flow.kind == FlowKind::Fallthrough
                    })
            })
            && index.by_site.get(&previous.address).is_some_and(|flows| {
                flows
                    .iter()
                    .any(|flow| flow.target == next.address && flow.kind == FlowKind::Fallthrough)
                    && flows.iter().all(|flow| {
                        (flow.target == next.address && flow.kind == FlowKind::Fallthrough)
                            || (previous.address == guard && flow.kind == FlowKind::Branch)
                    })
            })
    })
}

/// (entry width, register receiving the entry, table addressing mode).
fn table_load(decoded: &DecodedInstruction) -> Option<(u32, u8, AddressingMode)> {
    match (
        Isa::from(decoded.instruction.opcode),
        decoded.instruction.operands,
    ) {
        (
            Isa::Move,
            Operands::SizeEffectiveAddressEffectiveAddress(
                Size::Word,
                AddressingMode::Drd(register),
                mode,
            ),
        ) => Some((2, register, mode)),
        (Isa::Movea, Operands::SizeRegisterEffectiveAddress(Size::Long, register, mode)) => {
            Some((4, register, mode))
        }
        _ => None,
    }
}

fn scale_factor(decoded: &DecodedInstruction, size: Size, register: u8) -> Option<u32> {
    match (
        Isa::from(decoded.instruction.opcode),
        decoded.instruction.operands,
    ) {
        (
            Isa::Add,
            Operands::RegisterDirectionSizeEffectiveAddress(
                destination,
                Direction::DstReg,
                actual_size,
                AddressingMode::Drd(source),
            ),
        ) if source == register && destination == register && actual_size == size => Some(2),
        (
            Isa::Asr | Isa::Lsr,
            Operands::RotationDirectionSizeModeRegister(
                count,
                Direction::Left,
                actual_size,
                false,
                destination,
            ),
        ) if destination == register && actual_size == size && matches!(count, 1 | 2) => {
            Some(1_u32 << count)
        }
        _ => None,
    }
}

fn indexed_base(mode: AddressingMode, bases: &[Option<u32>; 8]) -> Option<(u32, u8, bool)> {
    let (base, extension) = match mode {
        AddressingMode::Pciwi8(pc, extension) => (pc, extension),
        AddressingMode::Ariwi8(register, extension) => (bases[usize::from(register)]?, extension),
        _ => return None,
    };
    let BriefExtensionWord(bits) = extension;
    // MC68000 brief format, data-register index only; reserved bits are not
    // silently read as 68020 scale/full-extension fields.
    if bits & 0x8700 != 0 {
        return None;
    }
    Some((
        base.checked_add_signed(i32::from(extension.disp()))?,
        ((bits >> 12) & 7) as u8,
        bits & 0x0800 != 0,
    ))
}

fn lea_offset(
    code: &[u8],
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
) -> Option<(u8, u32)> {
    if Isa::from(decoded.instruction.opcode) != Isa::Lea {
        return None;
    }
    let Operands::RegisterEffectiveAddress(register, mode) = decoded.instruction.operands else {
        return None;
    };
    let offset = match mode {
        AddressingMode::Pciwd(pc, displacement) => {
            pc.checked_add_signed(i32::from(displacement))?
        }
        AddressingMode::AbsLong(value) => {
            match analysis.operand_address(decoded, OperandRole::Only, value) {
                OperandAddress::ThisHunk(offset) => offset,
                OperandAddress::Encoded(value) => absolute_offset(code, analysis, value)?,
                OperandAddress::OtherHunk { .. } => return None,
            }
        }
        _ => return None,
    };
    Some((register, offset))
}

fn absolute_offset(code: &[u8], analysis: &ControlFlowAnalysis, value: u32) -> Option<u32> {
    match analysis.rebase {
        Some(rebase) => rebase.to_offset(value, code.len()),
        None => Some(value),
    }
}

fn pointer_offset(
    code: &[u8],
    analysis: &ControlFlowAnalysis,
    patched: u32,
    value: u32,
) -> Option<u32> {
    if let Some(relocations) = analysis.relocations()
        && let Some(relocation) = relocations.at(patched, value)
    {
        return (relocation.target_hunk == relocations.hunk()).then_some(relocation.target_offset);
    }
    absolute_offset(code, analysis, value)
}

fn instruction_overlaps(analysis: &ControlFlowAnalysis, start: u32, end: u32) -> bool {
    analysis
        .instructions
        .range(start.saturating_sub(MAX_INSTRUCTION_BYTES)..end)
        .any(|(_, decoded)| decoded.end > start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::{
        FlowOptions, Rebase, Relocation, Relocations, UnresolvedFlow, analyze, analyze_entries,
        analyze_entries_with,
    };
    use std::collections::BTreeSet;

    fn put(code: &mut [u8], offset: usize, bytes: &[u8]) {
        code[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn word_table(table: usize) -> Vec<u8> {
        let mut code = vec![0; (table + 4).max(32)];
        put(
            &mut code,
            0,
            &[
                0x0c,
                0x40,
                0x00,
                0x01, // CMPI.W #1,D0
                0x62,
                0x0a, // BHI default (16)
                0xd0,
                0x40, // ADD.W D0,D0
                0x32,
                0x3b,
                0x00,
                u8::try_from(table - 10).unwrap(), // MOVE.W table(PC,D0.W),D1
                0x4e,
                0xfb,
                0x10,
                u8::try_from(table - 14).unwrap(), // JMP table(PC,D1.W)
                0x4e,
                0x75, // default: RTS
            ],
        );
        for (index, target) in [24, 28].into_iter().enumerate() {
            let displacement = i16::try_from(target - i32::try_from(table).unwrap()).unwrap();
            put(&mut code, table + index * 2, &displacement.to_be_bytes());
        }
        put(&mut code, 24, &[0x74, 0x01, 0x4e, 0x75]); // case 0: MOVEQ #1,D2 ; RTS
        put(&mut code, 28, &[0x74, 0x02, 0x4e, 0x75]); // case 1: MOVEQ #2,D2 ; RTS
        code
    }

    fn pointer_table(origin: u32) -> Vec<u8> {
        let mut code = vec![0; 36];
        put(
            &mut code,
            0,
            &[
                0x0c, 0x40, 0x00, 0x01, // CMPI.W #1,D0
                0x62, 0x0a, // BHI default (16)
                0xe5, 0x48, // LSL.W #2,D0
                0x20, 0x7b, 0x00, 0x0a, // MOVEA.L table(PC,D0.W),A0
                0x4e, 0xd0, // JMP (A0)
                0x4e, 0x71, // unreached padding
                0x4e, 0x75, // default: RTS
            ],
        );
        put(&mut code, 20, &(origin + 28).to_be_bytes());
        put(&mut code, 24, &(origin + 32).to_be_bytes());
        put(&mut code, 28, &[0x74, 0x01, 0x4e, 0x75]);
        put(&mut code, 32, &[0x74, 0x02, 0x4e, 0x75]);
        code
    }

    fn branch_targets(analysis: &ControlFlowAnalysis, site: u32) -> BTreeSet<u32> {
        analysis
            .flows
            .iter()
            .filter(|flow| flow.site == site && flow.kind == FlowKind::Branch)
            .map(|flow| flow.target)
            .collect()
    }

    fn assert_unresolved(code: &[u8]) {
        let analysis = analyze(code, 0);
        assert!(
            analysis.unresolved.contains(&UnresolvedFlow {
                owner: 0,
                address: 12
            }),
            "{analysis:?}"
        );
        assert!(branch_targets(&analysis, 12).is_empty());
    }

    #[test]
    fn recovers_relative_words_with_positive_and_negative_offsets() {
        for table in [20, 32] {
            let analysis = analyze(&word_table(table), 0);
            assert!(analysis.unresolved.is_empty(), "{analysis:?}");
            assert_eq!(branch_targets(&analysis, 12), BTreeSet::from([24, 28]));
            assert_eq!(analysis.instructions[&24].encoded, [0x74, 0x01]);
            assert_eq!(analysis.instructions[&28].encoded, [0x74, 0x02]);
            assert_eq!(analysis.instructions[&28].owners, BTreeSet::from([0]));
            assert!(
                !analysis
                    .instructions
                    .contains_key(&u32::try_from(table).unwrap())
            );
        }
    }

    #[test]
    fn recovers_word_tables_using_an_address_register_base() {
        // LEA table(PC),A0 before the guard, then (A0,D0.W)/(A0,D1.W).
        let code = [
            0x41, 0xfa, 0x00, 0x16, 0x0c, 0x40, 0x00, 0x01, 0x62, 0x0a, 0xd0, 0x40, 0x32, 0x30,
            0x00, 0x00, 0x4e, 0xf0, 0x10, 0x00, 0x4e, 0x75, 0, 0, 0x00, 0x04, 0x00, 0x08, 0x74,
            0x01, 0x4e, 0x75, 0x74, 0x02, 0x4e, 0x75,
        ];
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.is_empty(), "{analysis:?}");
        assert_eq!(branch_targets(&analysis, 16), BTreeSet::from([28, 32]));
        // An independent entry after LEA cannot inherit its table base.
        let analysis = analyze_entries(&code, &[0, 4]);
        assert!(branch_targets(&analysis, 16).is_empty());
        assert!(!analysis.unresolved.is_empty());
    }

    #[test]
    fn recovers_absolute_pointer_tables_in_plain_and_rebased_images() {
        for origin in [0, 0x10000] {
            let analysis = analyze_entries_with(
                &pointer_table(origin),
                &[0],
                &FlowOptions {
                    rebase: (origin != 0).then_some(Rebase::new(origin)),
                    relocations: None,
                },
            );
            assert!(analysis.unresolved.is_empty(), "{analysis:?}");
            assert_eq!(branch_targets(&analysis, 12), BTreeSet::from([28, 32]));
            assert_eq!(analysis.instructions[&32].encoded, [0x74, 0x02]);
            assert_eq!(analysis.functions, BTreeSet::from([0]));
        }
    }

    #[test]
    fn pointer_relocations_override_rebase_and_cross_hunk_entries_are_refused() {
        for other_hunk in [false, true] {
            let analysis = analyze_entries_with(
                &pointer_table(0),
                &[0],
                &FlowOptions {
                    rebase: Some(Rebase::new(0x10000)),
                    relocations: Some(Relocations::new(
                        0,
                        [
                            Relocation {
                                patched: 20,
                                target_hunk: 0,
                                target_offset: 28,
                            },
                            Relocation {
                                patched: 24,
                                target_hunk: u32::from(other_hunk),
                                target_offset: 32,
                            },
                        ],
                    )),
                },
            );
            if other_hunk {
                assert!(branch_targets(&analysis, 12).is_empty());
                assert!(!analysis.unresolved.is_empty());
            } else {
                assert!(analysis.unresolved.is_empty(), "{analysis:?}");
                assert_eq!(branch_targets(&analysis, 12), BTreeSet::from([28, 32]));
            }
        }
    }

    #[test]
    fn accepts_double_add_scaling_and_long_indices() {
        let mut code = pointer_table(0);
        // Replace LSL.W with two ADD.W instructions; move table/body offsets.
        code.splice(6..8, [0xd0, 0x40, 0xd0, 0x40]);
        code[5] += 2;
        put(&mut code, 22, &30_u32.to_be_bytes());
        put(&mut code, 26, &34_u32.to_be_bytes());
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.is_empty(), "{analysis:?}");
        assert_eq!(branch_targets(&analysis, 14), BTreeSet::from([30, 34]));

        let mut code = pointer_table(0);
        // Widen CMPI, LSL and the lookup index together.
        code.splice(0..4, [0x0c, 0x80, 0, 0, 0, 1]);
        code[9] = 0x88;
        code[12] = 0x08;
        put(&mut code, 22, &30_u32.to_be_bytes());
        put(&mut code, 26, &34_u32.to_be_bytes());
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.is_empty(), "{analysis:?}");
        assert_eq!(branch_targets(&analysis, 14), BTreeSet::from([30, 34]));
    }

    #[test]
    fn rejects_missing_or_signed_guards_wrong_registers_and_wrong_scaling() {
        for (offset, replacement) in [
            (0, &[0x4e, 0x71, 0x4e, 0x71][..]), // no comparison
            (4, &[0x6e]),                       // BGT is signed; negative indices remain possible
            (1, &[0x41]),                       // compares D1 rather than D0
            (6, &[0x52, 0x40]),                 // ADDQ is not index scaling
            (7, &[0x80]),                       // long scaling after a word comparison
            (10, &[0x08]),                      // long index after a word comparison
            (10, &[0x02]),                      // 68020 scale bits
            (14, &[0x18]),                      // long jump index after a word table load
        ] {
            let mut code = word_table(20);
            put(&mut code, offset, replacement);
            assert_unresolved(&code);
        }
    }

    #[test]
    fn rejects_bad_entries_and_does_not_accept_a_valid_prefix() {
        for bad in [1_i16, 0, -14, 0x7fff, i16::MIN] {
            let mut code = word_table(20);
            // First entry is valid. Second is odd, inside table/dispatch, or outside image.
            put(&mut code, 22, &bad.to_be_bytes());
            assert_unresolved(&code);
        }
        for bad in [0xffff_ffff_u32, 29, 20, 6, 0x10000] {
            let mut code = pointer_table(0);
            put(&mut code, 24, &bad.to_be_bytes());
            assert_unresolved(&code);
        }
        let mut code = word_table(32);
        code.truncate(35); // partial final table entry
        assert_unresolved(&code);
        let mut code = pointer_table(0);
        code.truncate(33); // final target has only one byte of its opcode
        assert_unresolved(&code);
        let mut code = word_table(20);
        put(&mut code, 28, &[0xff, 0xff]); // unknown target instruction
        assert_unresolved(&code);
    }

    #[test]
    fn guard_count_is_complete_and_bounded() {
        let mut code = word_table(20);
        code[3] = 0; // exactly one possible index
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.is_empty());
        assert_eq!(branch_targets(&analysis, 12), BTreeSet::from([24]));
        code[2] = 1; // 257 entries exceed the explicit budget
        assert_unresolved(&code);
        code[2] = 0xff;
        code[3] = 0xff;
        assert_unresolved(&code);
    }

    #[test]
    fn rejects_a_guard_bypass_discovered_through_a_table_target() {
        let mut code = word_table(20);
        // A case jumps into the scaling step, bypassing CMP/BHI. This edge is
        // discovered only after table recovery, and must revoke that recovery.
        put(&mut code, 24, &[0x60, 0xec]); // BRA 6
        assert_unresolved(&code);
        let analysis = analyze(&code, 0);
        assert!(!analysis.instructions.contains_key(&24));
    }

    #[test]
    fn rejects_known_alternate_entries_and_overlapping_code() {
        let code = word_table(20);
        for extra in [6, 8, 12, 20] {
            let analysis = analyze_entries(&code, &[0, extra]);
            assert!(
                branch_targets(&analysis, 12).is_empty(),
                "entry {extra}: {analysis:?}"
            );
            assert!(!analysis.unresolved.is_empty());
        }
    }

    #[test]
    fn malformed_data_dispatch_cannot_fall_back_to_nearby_bra_stubs() {
        let mut code = word_table(20);
        code.resize(40, 0);
        put(&mut code, 0, &[0x4e, 0x71, 0x4e, 0x71]); // no guard comparison
        put(&mut code, 24, &[0x60, 0x00, 0x00, 0x08]); // plausible unrelated BRA.W
        assert_unresolved(&code);
    }
    #[test]
    fn recovered_edges_agree_with_bounded_execution() {
        use crate::execute::{Memory, RunOptions, StopReason, run};
        let origin = 0x1000;
        for code in [word_table(20), word_table(32), pointer_table(origin)] {
            let analysis = analyze_entries_with(
                &code,
                &[0],
                &FlowOptions {
                    rebase: Some(Rebase::new(origin)),
                    relocations: None,
                },
            );
            let targets = branch_targets(&analysis, 12);
            assert_eq!(targets.len(), 2);
            // Word comparison/indexing must ignore arbitrary upper D0 bits,
            // and BHI must exclude negative words as well as index 2.
            for (input, expected) in [(0, 1), (1, 2), (0xabcd_0001, 2), (2, 0), (0xffff, 0)] {
                let mut memory = Memory::new();
                memory.map(origin, 0x1000).unwrap();
                memory.load(origin, &code).unwrap();
                let mut options = RunOptions::new(origin + 0x1000, 0xffff_fffc);
                options.max_steps = 32;
                options.data[0] = input;
                let result = run(&mut memory, origin, &options);
                assert_eq!(result.stop, StopReason::Returned, "{input:x}: {result:?}");
                assert_eq!(result.registers.d[2], expected);
                if expected != 0 {
                    assert!(
                        result
                            .steps
                            .iter()
                            .any(|step| targets.contains(&(step.address - origin)))
                    );
                }
            }
        }
    }

    #[test]
    fn table_recovery_restores_constant_and_scale_propagation() {
        use crate::{RegisterKind, ValueOptions, constant_before, fixed_point_scales};
        let mut code = word_table(20);
        // Establish a constant before the guarded dispatch. PC-relative table
        // bytes remain unchanged when the entire routine shifts together.
        code.splice(0..0, [0x78, 0x07]); // MOVEQ #7,D4
        let analysis = analyze(&code, 0);
        for target in [26, 30] {
            assert_eq!(
                constant_before(
                    &analysis,
                    ValueOptions::default(),
                    target,
                    RegisterKind::Data,
                    4
                )
                .unwrap()
                .value,
                7
            );
        }
        let mut code = word_table(20);
        put(&mut code, 24, &[0x24, 0x03]); // MOVE.L D3,D2
        put(&mut code, 28, &[0x24, 0x03]);
        code.splice(0..0, [0xc7, 0xc1, 0xe0, 0x83]); // MULS ; ASR #8
        let analysis = analyze(&code, 0);
        let scales = fixed_point_scales(&analysis);
        for target in [28, 32] {
            assert!(
                scales.iter().any(|scale| scale.site == target
                    && scale.register == 2
                    && scale.fractional_bits == 8),
                "{scales:?}"
            );
        }
    }

    #[test]
    fn accepts_the_full_entry_budget_and_deduplicates_edges_without_truncation() {
        let mut code = word_table(20);
        code.resize(548, 0);
        code[3] = 255;
        for index in 0..256 {
            put(&mut code, 20 + index * 2, &520_i16.to_be_bytes());
        }
        put(&mut code, 540, &[0x74, 0x01, 0x4e, 0x75]);
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.is_empty(), "{analysis:?}");
        assert_eq!(branch_targets(&analysis, 12), BTreeSet::from([540]));
        // The last entry still matters even though every earlier target is identical.
        put(&mut code, 530, &i16::MAX.to_be_bytes());
        assert_unresolved(&code);
    }

    #[test]
    fn rejects_a_branch_into_an_instruction_extension_word() {
        let mut code = word_table(20);
        // First case begins with MOVE.L #imm,D2, so the second target (28)
        // would enter its immediate. Only the expanded traversal reveals this.
        code.resize(34, 0);
        put(&mut code, 24, &[0x24, 0x3c, 0, 0, 0x4e, 0x75, 0x4e, 0x75]);
        assert_unresolved(&code);
    }
    fn nested_tables(count: usize) -> Vec<u8> {
        let mut code = Vec::new();
        for index in 0..count {
            let mut part = word_table(20);
            if index + 1 < count {
                put(&mut part, 24, &[0x60, 0x00, 0x00, 0x06]); // BRA.W next dispatch
            }
            code.extend_from_slice(&part);
        }
        code
    }

    #[test]
    fn nested_tables_are_discovered_and_excessive_depth_stays_unresolved() {
        let analysis = analyze(&nested_tables(2), 0);
        assert!(analysis.unresolved.is_empty());
        assert_eq!(branch_targets(&analysis, 12), BTreeSet::from([24, 28]));
        assert_eq!(branch_targets(&analysis, 44), BTreeSet::from([56, 60]));
        let analysis = analyze(&nested_tables(9), 0);
        assert!(analysis.unresolved.contains(&UnresolvedFlow {
            owner: 0,
            address: 12
        }));
        assert!(branch_targets(&analysis, 12).is_empty());
        assert!(!analysis.instructions.contains_key(&32));
    }

    #[test]
    fn a_nested_case_cannot_bypass_an_earlier_tables_guard() {
        let mut code = nested_tables(2);
        put(&mut code, 56, &[0x60, 0x00, 0xff, 0xcc]); // BRA.W 6
        let analysis = analyze(&code, 0);
        assert!(analysis.unresolved.contains(&UnresolvedFlow {
            owner: 0,
            address: 12
        }));
        assert!(branch_targets(&analysis, 12).is_empty());
        assert!(!analysis.instructions.contains_key(&32));
    }

    #[test]
    fn discovery_observes_cancellation_without_returning_partial_edges() {
        use std::cell::Cell;
        struct CancelDiscovery(Cell<usize>);
        impl amiga_core::Cancel for CancelDiscovery {
            fn is_cancelled(&self) -> bool {
                let calls = self.0.get();
                self.0.set(calls + 1);
                calls >= 1
            }
        }
        let result = crate::analyze_entries_cancellable(
            &word_table(20),
            &[0],
            &FlowOptions::default(),
            &CancelDiscovery(Cell::new(0)),
        );
        assert!(matches!(result, Err(amiga_core::Cancelled)));
    }

    #[test]
    fn resolves_absolute_lea_bases_through_rebase_and_relocations() {
        for relocated in [false, true] {
            let mut code = vec![
                0x41, 0xf9, 0, 0, 0, 26, // LEA table.L,A0
                0x0c, 0x40, 0, 1, 0x62, 0x0a, 0xd0, 0x40, 0x32, 0x30, 0, 0, 0x4e, 0xf0, 0x10, 0,
                0x4e, 0x75, 0, 0, // default/pad
                0, 4, 0, 8, 0x74, 1, 0x4e, 0x75, 0x74, 2, 0x4e, 0x75,
            ];
            if !relocated {
                put(&mut code, 2, &0x1001a_u32.to_be_bytes());
            }
            let analysis = analyze_entries_with(
                &code,
                &[0],
                &FlowOptions {
                    rebase: Some(Rebase::new(0x10000)),
                    relocations: relocated.then(|| {
                        Relocations::new(
                            0,
                            [Relocation {
                                patched: 2,
                                target_hunk: 0,
                                target_offset: 26,
                            }],
                        )
                    }),
                },
            );
            assert!(analysis.unresolved.is_empty(), "{analysis:?}");
            assert_eq!(branch_targets(&analysis, 18), BTreeSet::from([30, 34]));
        }
    }
}
