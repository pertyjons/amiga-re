//! The `analysis.*` operations: questions asked of an image's bytes.
//!
//! These tests cover shared analysis responses: true totals beside capped lists,
//! filters applied before caps, and analysis seeds derived from the complete target
//! set rather than only the targets that fit in the response.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, InMemorySourceResolver, OperationRequestDocument, RequestEnvelope,
    ResolvedSource, Router, SourceName, Status,
};

/// A one-hunk LoadSeg image whose CODE hunk holds `code`.
fn image(code: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let longwords = code.len().div_ceil(4) as u32;
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, longwords] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(code);
    bytes.resize(bytes.len() + (longwords as usize * 4 - code.len()), 0);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

fn resolver(bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse("game").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

#[test]
fn a_hunk_listing_reports_relocation_sites_rather_than_only_counting_them() {
    // A count says a hunk has pointers; what a reader is usually after is which
    // hunk they point into, which is why the sites travel with the count.
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 4] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&4_u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&0x0000_03ec_u32.to_be_bytes()); // HUNK_RELOC32
    for value in [2_u32, 0, 0, 8, 0] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END

    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisHunkList(
            amiga_operations::HunkListArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let list = outcome.analysis_hunk_list().expect("a listing");
    assert_eq!(list.first_hunk, 0);
    assert_eq!(list.segments.len(), 1);
    let segment = &list.segments[0];
    assert_eq!(segment.kind, "CODE");
    assert_eq!(segment.relocation_total, 2);
    assert_eq!(segment.relocations.len(), 2);
    assert_eq!(segment.relocations[0].source_offset, 0);
    assert_eq!(segment.relocations[1].source_offset, 8);
    assert!(!segment.relocations_truncated);
}

#[test]
fn a_capped_relocation_list_still_reports_its_hunks_true_total() {
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 4] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes());
    bytes.extend_from_slice(&4_u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&0x0000_03ec_u32.to_be_bytes());
    for value in [3_u32, 0, 0, 4, 8, 0] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes());

    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisHunkList(
            amiga_operations::HunkListArguments::new("game").with_maximum_relocations(1),
        )),
        &context,
    );

    let segment = &outcome.analysis_hunk_list().expect("a listing").segments[0];
    assert_eq!(segment.relocations.len(), 1);
    // A capped list that read as a complete one would make a heavily relocated
    // hunk look simple.
    assert_eq!(segment.relocation_total, 3);
    assert!(segment.relocations_truncated);
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::ResultEntriesTruncated),
        "the truncation was silent"
    );
}

#[test]
fn a_string_filter_is_applied_before_the_cap_not_after() {
    // Filtering a capped list would drop matches the scan found and the cap
    // discarded, so a caller asking for "strings containing disk" would get
    // fewer than exist for a reason nothing in the response explains.
    let mut bytes = Vec::new();
    for index in 0..40 {
        bytes.extend_from_slice(format!("noise{index:03}\0").as_bytes());
    }
    bytes.extend_from_slice(b"diskloader\0");
    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisStringsScan(
            amiga_operations::StringsScanArguments::new("game")
                .containing("disk")
                .with_maximum_strings(4),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let scan = outcome.analysis_strings_scan().expect("a scan");
    // The one match survives, even though it sits well past the fourth string
    // in the file: filter first, cap second.
    assert_eq!(scan.string_total, 1);
    assert_eq!(scan.strings.len(), 1);
    assert_eq!(scan.strings[0].text, "diskloader");
    assert!(!scan.strings_truncated);
}

#[test]
fn a_source_that_is_not_a_hunk_image_still_scans() {
    // A data file is an ordinary thing to scan. Parsing it because the code
    // *could* would answer a question nobody asked.
    let resolver = resolver(b"not a hunk image, but readable\0".to_vec());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisStringsScan(
            amiga_operations::StringsScanArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let scan = outcome.analysis_strings_scan().expect("a scan");
    assert_eq!(scan.strings.len(), 1);
    assert_eq!(scan.hunk, None);
}

#[test]
fn one_number_is_reported_in_every_frame_it_could_have_come_from() {
    // The whole point: a number copied out of a listing carries no record of
    // which coordinate system it came from, so answering only one reading would
    // assume what the caller is trying to work out.
    let bytes = image(&[0x4e, 0x75, 0x4e, 0x75]);
    // Six header longwords, then HUNK_CODE and its length: eight in all.
    let hunk_start = 32;
    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisAddressResolve(
            amiga_operations::AddressResolveArguments::new(0x1002, 0x1000)
                .anchored_on(amiga_operations::HunkAnchor::new("game")),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let resolved = outcome.analysis_address_resolve().expect("a resolution");
    assert_eq!(resolved.hunk_file_offset, Some(hunk_start));
    assert_eq!(resolved.hunk_bytes, Some(4));

    // As a runtime address it is two bytes into the mapped hunk.
    assert_eq!(resolved.as_absolute.absolute, Some(0x1002));
    assert_eq!(resolved.as_absolute.hunk_relative, Some(2));
    assert_eq!(resolved.as_absolute.whole_file, Some(hunk_start + 2));

    // Read as a hunk offset instead, the same number is a different byte.
    assert_eq!(resolved.as_hunk_relative.absolute, Some(0x2002));
    assert_eq!(
        resolved.as_hunk_relative.whole_file,
        Some(hunk_start + 0x1002)
    );

    // And read as a file position it is past the end of this small image, which
    // the arithmetic still answers — `hunk_bytes` is what says it is a miss.
    let whole = resolved.as_whole_file.expect("an anchored reading");
    assert_eq!(whole.whole_file, Some(0x1002));
    assert_eq!(whole.hunk_relative, Some(0x1002 - hunk_start as u32));
}

#[test]
fn a_value_below_the_mapped_origin_has_no_hunk_offset_rather_than_a_wrapped_one() {
    let resolver = resolver(b"not an image".to_vec());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisAddressResolve(
            amiga_operations::AddressResolveArguments::new(0x800, 0x1000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let resolved = outcome.analysis_address_resolve().expect("a resolution");
    // Absent, not zero and not 0xfffff800: the value is simply not an offset
    // into this hunk, and a computed difference would read as one.
    assert_eq!(resolved.as_absolute.hunk_relative, None);
    // With no anchor there is no file frame at all, for either reading.
    assert_eq!(resolved.as_absolute.whole_file, None);
    assert_eq!(resolved.as_whole_file, None);
    // The image was never opened, because nothing asked it anything.
    assert_eq!(resolved.source, None);
}

#[test]
fn pointer_entry_offsets_are_derived_before_the_target_cap_not_after() {
    // Seeding a flow analysis from a capped target list would analyze less of
    // the hunk the larger the answer got — a silent loss that scales the wrong
    // way. The seeds come from every target found.
    let origin = 0x1000_u32;
    let mut code = Vec::new();
    for offset in [0x40_u32, 0x44, 0x48, 0x4c, 0x50] {
        code.extend_from_slice(&(origin + offset).to_be_bytes());
    }
    code.resize(0x60, 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisPointersScan(
            amiga_operations::PointerScanArguments::new("game")
                .mapped_at(origin)
                .with_maximum_targets(2),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let scan = outcome.analysis_pointers_scan().expect("a scan");
    assert_eq!(scan.tables.len(), 1);
    let table = &scan.tables[0];
    assert_eq!(table.offset, 0);
    assert_eq!(table.encoding, amiga_operations::PointerEncoding::Long);
    // The list is capped, and says so — while the total and the span still
    // describe the whole run.
    assert_eq!(table.targets, [origin + 0x40, origin + 0x44]);
    assert_eq!(table.target_total, 5);
    assert!(table.targets_truncated);
    assert_eq!(table.target_lowest, origin + 0x40);
    assert_eq!(table.target_highest, origin + 0x50);
    // Every seed, not the two that fit.
    assert_eq!(scan.entry_offsets, [0x40, 0x44, 0x48, 0x4c, 0x50]);
    assert_eq!(scan.entry_offset_total, 5);
    assert!(!scan.entry_offsets_truncated);
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::ResultEntriesTruncated),
        "the truncation was silent"
    );
}

#[test]
fn a_pointer_scan_judges_targets_against_the_origin_the_request_names() {
    // The same bytes are a table or noise depending on where the hunk is mapped,
    // which is why the origin is a request argument and travels back in the
    // result: a candidate whose criteria are invisible cannot be judged.
    let mut code = Vec::new();
    for offset in [0x40_u32, 0x44, 0x48] {
        code.extend_from_slice(&(0x1000 + offset).to_be_bytes());
    }
    code.resize(0x60, 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisPointersScan(
            amiga_operations::PointerScanArguments::new("game").mapped_at(0x2000),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let scan = outcome.analysis_pointers_scan().expect("a scan");
    assert_eq!(scan.origin, 0x2000);
    assert!(scan.tables.is_empty(), "{:?}", scan.tables);
    assert!(scan.entry_offsets.is_empty());
}

#[test]
fn a_word_scale_of_zero_is_refused_before_the_source_is_opened() {
    // Every word would decode to the origin, so every run of words would read
    // as a table addressing one byte: noise wearing the shape of a result.
    let resolver = resolver(image(&[0; 64]));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisPointersScan(
            amiga_operations::PointerScanArguments::new("game").with_word_scale(0),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
    assert!(outcome.result.is_none());
}

/// The fixture the disassembly tests read: a BSR into a subroutine, a BRA past
/// it, a NOP nothing reaches, and two bytes of data at the end.
fn control_flow_image() -> Vec<u8> {
    image(&[
        0x61, 0x00, 0x00, 0x08, // 0000 BSR.W -> 0x000a
        0x60, 0x00, 0x00, 0x0a, // 0004 BRA.W -> 0x0010
        0x4e, 0x71, // 0008 NOP, reached by nothing
        0x70, 0x07, // 000a MOVEQ #7,D0
        0x4e, 0x75, // 000c RTS
        0x4e, 0x71, // 000e NOP, reached by nothing
        0x4e, 0x75, // 0010 RTS
        0xab, 0xcd, // 0012 data
    ])
}

#[test]
fn a_disassembly_carries_instructions_and_edges_never_a_listing() {
    // A listing is a display format. Freezing one into the machine contract
    // would make every consumer inherit one frontend's labels and columns.
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game").following_flow(vec![0]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.analysis_code_disassemble().expect("a disassembly");
    let flow = result.flow.as_ref().expect("flow facts");

    // The mnemonic, and nothing about how to print it.
    let first = &result.instructions[0];
    assert_eq!(first.offset, 0);
    assert_eq!(first.bytes, "61000008");
    assert!(first.text.starts_with("BSR"), "{}", first.text);
    assert!(
        !first.text.contains('L') || !first.text.contains(':'),
        "a label leaked into the fact: {}",
        first.text
    );
    // No origin was named, so no instruction claims a runtime address.
    assert_eq!(first.address, None);

    // The subroutine the BSR reaches is a function; the BRA target is not.
    assert_eq!(flow.functions, [0x00, 0x0a]);
    assert_eq!(flow.calls.len(), 1);
    assert_eq!(flow.calls[0].call_site, 0x00);
    assert_eq!(flow.calls[0].callee, 0x0a);

    // What nothing reached is reported as runs of bytes, so a caller can
    // render or re-examine them without opening the source again.
    let unreached: Vec<(u32, &str)> = flow
        .unreached
        .iter()
        .map(|run| (run.offset, run.bytes.as_str()))
        .collect();
    assert_eq!(unreached, [(0x08, "4e71"), (0x0e, "4e71"), (0x12, "abcd")]);
    assert_eq!(flow.coverage.total_bytes, 20);
    assert_eq!(flow.coverage.decoded_bytes, 14);
}

#[test]
fn a_pinned_raw_image_is_followed_from_every_supplied_entry() {
    // Multi-entry modules are plain bytes with several public entry points,
    // not LoadSeg files. Each entry must seed the same traversal; choosing only
    // the first would silently omit two thirds of a three-routine module.
    let bytes = vec![0x4e, 0x75, 0x4e, 0x75, 0x4e, 0x75];
    let digest = amiga_core::sha256(&bytes);
    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game")
                .in_raw(digest)
                .following_flow(vec![0, 2, 4])
                .mapped_at(0x20_000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.analysis_code_disassemble().expect("a disassembly");
    assert_eq!(result.region, amiga_operations::CodeRegion::Raw);
    assert_eq!(result.hunk, None);
    assert_eq!(result.hunk_bytes, 6);
    let flow = result.flow.as_ref().expect("flow facts");
    assert_eq!(flow.entries, [0, 2, 4]);
    assert_eq!(flow.functions, [0, 2, 4]);
    assert_eq!(result.instructions[2].address, Some(0x20_004));
}

#[test]
fn a_raw_image_whose_pin_does_not_match_is_not_analyzed() {
    let resolver = resolver(vec![0x4e, 0x75]);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game")
                .in_raw("0".repeat(64))
                .following_flow(vec![0]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::SourceDigestMismatch
    );
    assert!(outcome.result.is_none());
}

#[test]
fn an_origin_gives_every_instruction_the_address_the_cpu_would_fetch_it_from() {
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game")
                .following_flow(vec![0])
                .mapped_at(0x1000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.analysis_code_disassemble().expect("a disassembly");
    assert_eq!(result.origin, Some(0x1000));
    assert_eq!(result.instructions[0].offset, 0);
    assert_eq!(result.instructions[0].address, Some(0x1000));
    // The offset is still the offset: an address is an addition, not a
    // replacement, and a caller indexing the hunk needs both.
    let last = result.instructions.last().expect("instructions");
    assert_eq!(last.address, Some(0x1000 + last.offset));
}

#[test]
fn a_linear_sweep_decodes_what_control_flow_never_reaches() {
    // The two modes answer one question two ways, and this is the difference:
    // the sweep decodes the NOP at 0x08 that no traversal arrives at.
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game").over_range(0x08, Some(0x0c)),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.analysis_code_disassemble().expect("a disassembly");
    assert_eq!(result.start, 0x08);
    assert_eq!(result.end, 0x0c);
    assert_eq!(result.instructions.len(), 2);
    assert_eq!(result.instructions[0].offset, 0x08);
    assert_eq!(result.instructions[0].bytes, "4e71");
    // A sweep follows nothing, so it knows nothing about functions or reach.
    assert!(result.flow.is_none());
    assert_eq!(result.instructions[0].owners, Vec::<u32>::new());
}

#[test]
fn an_odd_sweep_start_is_refused_before_the_source_is_opened() {
    // An MC68000 fetches instructions on word boundaries; decoding from an odd
    // offset would produce a listing of instructions the machine never sees.
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game").over_range(1, None),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
    assert!(outcome.result.is_none());
}

#[test]
fn a_hunk_that_is_not_code_is_refused_by_name_rather_than_decoded() {
    // Decoding a DATA hunk would produce a plausible listing of something that
    // is not code, which is worse than saying no.
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 2] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03ea_u32.to_be_bytes()); // HUNK_DATA
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(&[0x4e, 0x75, 0x4e, 0x71, 0, 0, 0, 0]);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes());

    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::AnalysisHunkUnreadable
    );
}

#[test]
fn a_capped_owner_set_still_reports_how_many_entries_arrived() {
    // `DecodedInstruction` caps its owner set and counts what it refused,
    // precisely so a capped set never reads as a complete one. A response
    // carrying only `owners` would undo that.
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeDisassemble(
            amiga_operations::CodeDisassembleArguments::new("game")
                .following_flow(vec![0x00, 0x0a]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.analysis_code_disassemble().expect("a disassembly");
    // Every instruction names the entry whose traversal reached it, and the
    // total is never below the set: a response where it could be would be
    // reporting a capped set as a complete one.
    for instruction in &result.instructions {
        assert!(
            !instruction.owners.is_empty(),
            "{:#x} names no owning entry",
            instruction.offset
        );
        assert!(
            instruction.owner_total >= instruction.owners.len() as u64,
            "{:#x} counts fewer owners than it lists",
            instruction.offset
        );
    }
    // The BSR belongs to the entry it was reached from; the subroutine it calls
    // is a function scope of its own, so its body does not inherit that owner.
    let entry = result
        .instructions
        .iter()
        .find(|instruction| instruction.offset == 0x00)
        .expect("the entry");
    assert_eq!(entry.owners, [0x00]);
    let subroutine = result
        .instructions
        .iter()
        .find(|instruction| instruction.offset == 0x0a)
        .expect("the subroutine");
    assert_eq!(subroutine.owners, [0x0a]);
    assert_eq!(subroutine.owner_total, 1);
}

/// A two-hunk image whose first hunk jumps into the second through a
/// relocation. Without the relocation record the jump reads as "offset 6 of
/// this hunk", and the bytes there are decoded as code that never runs.
fn cross_hunk_jump_image() -> Vec<u8> {
    let first: [u8; 14] = [
        0x4e, 0xf9, 0x00, 0x00, 0x00, 0x06, // 0000 JMP $6.L, patched at 0x2
        0x41, 0xf9, 0x12, 0x34, 0x56, 0x78, // 0006 LEA $12345678.L,A0
        0x4e, 0x75, // 000c RTS
    ];
    let second: [u8; 4] = [0x4e, 0x71, 0x4e, 0x75]; // NOP ; RTS
    let (first_longwords, second_longwords) = (
        first.len().div_ceil(4) as u32,
        second.len().div_ceil(4) as u32,
    );

    let mut bytes = Vec::new();
    for value in [
        0x0000_03f3_u32,
        0,
        2,
        0,
        1,
        first_longwords,
        second_longwords,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&first_longwords.to_be_bytes());
    bytes.extend_from_slice(&first);
    bytes.resize(
        bytes.len() + (first_longwords as usize * 4 - first.len()),
        0,
    );
    bytes.extend_from_slice(&0x0000_03ec_u32.to_be_bytes()); // HUNK_RELOC32
    for value in [1_u32, 1, 2, 0] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&second_longwords.to_be_bytes());
    bytes.extend_from_slice(&second);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

#[test]
fn a_transfer_a_relocation_proves_external_is_not_followed_into_this_hunk() {
    // `xref to` used to analyze without the image's relocations, so this JMP
    // was followed to offset 6 of its own hunk and the `LEA` sitting there was
    // decoded — reporting a reference made by code that never runs here. One
    // operation for both questions is what ends that.
    let resolver = resolver(cross_hunk_jump_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisAddressReferences(
            amiga_operations::AddressReferencesArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome
        .analysis_address_references()
        .expect("a cross-reference");
    // The JMP's own operand is still a reference: the instruction is decoded.
    assert_eq!(result.references.len(), 1);
    assert_eq!(result.references[0].site, 0);
    assert_eq!(result.references[0].target, 6);
    assert_eq!(
        result.references[0].kind,
        amiga_operations::ReferenceKind::Absolute
    );
    // What is *not* here is the LEA at 0x6 and its 0x12345678 operand.
    assert!(
        !result
            .references
            .iter()
            .any(|reference| reference.target == 0x1234_5678),
        "a reference from unreached bytes was reported: {:?}",
        result.references
    );
}

#[test]
fn naming_a_target_finds_the_relocations_that_point_at_it_across_the_image() {
    // A pointer to an address is a reference to it wherever it sits, so the
    // relocations are searched image-wide rather than in the analyzed hunk.
    let resolver = resolver(cross_hunk_jump_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisAddressReferences(
            amiga_operations::AddressReferencesArguments::new("game").naming(6),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome
        .analysis_address_references()
        .expect("a cross-reference");
    assert_eq!(result.target, Some(6));
    assert_eq!(result.references.len(), 1);
    assert_eq!(result.references[0].site, 0);
    assert_eq!(result.relocations.len(), 1);
    assert_eq!(result.relocations[0].source_hunk, 0);
    assert_eq!(result.relocations[0].source_offset, 2);
    assert_eq!(result.relocations[0].target_hunk, 1);
    assert_eq!(result.relocations[0].stored_offset, Some(6));

    // Without a target there is nothing to match a relocation against, and the
    // full list is `analysis.hunk.list`'s answer already.
    let untargeted = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisAddressReferences(
            amiga_operations::AddressReferencesArguments::new("game"),
        )),
        &context,
    );
    let untargeted = untargeted
        .analysis_address_references()
        .expect("a cross-reference");
    assert!(untargeted.relocations.is_empty());
    assert_eq!(untargeted.relocation_total, 0);
}

#[test]
fn a_reference_filter_is_applied_before_the_cap_not_after() {
    // The same rule the string scan follows: a total counting references the
    // filter would have excluded would say more exist than the question has
    // answers.
    let resolver = resolver(cross_hunk_jump_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisAddressReferences(
            amiga_operations::AddressReferencesArguments::new("game")
                .naming(0x1234_5678)
                .with_maximum_references(1),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome
        .analysis_address_references()
        .expect("a cross-reference");
    assert_eq!(result.reference_total, 0);
    assert!(!result.references_truncated);
}

#[test]
fn a_call_graph_collapses_sites_onto_pairs_and_counts_the_degrees() {
    // The traversal records one edge per (caller, site, callee) triple; a graph
    // wants one edge per pair with the sites counted, and the degrees that fall
    // out of the collapsed edges. Doing that reduction in each frontend is how
    // two of them end up disagreeing about how connected a routine is.
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeCallgraph(
            amiga_operations::CodeCallgraphArguments::new("game").mapped_at(0x1000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let graph = outcome.analysis_code_callgraph().expect("a call graph");
    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph.nodes[0].function, 0x00);
    // The origin travels down to the node, so a caller need not re-derive it.
    assert_eq!(graph.nodes[0].address, Some(0x1000));
    assert_eq!(graph.nodes[0].out_degree, 1);
    assert_eq!(graph.nodes[0].in_degree, 0);
    assert_eq!(graph.nodes[1].function, 0x0a);
    assert_eq!(graph.nodes[1].address, Some(0x100a));
    assert_eq!(graph.nodes[1].in_degree, 1);

    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.edges[0].caller, 0x00);
    assert_eq!(graph.edges[0].callee, 0x0a);
    assert_eq!(graph.edges[0].calls, 1);
}

#[test]
fn globals_report_every_convention_a_program_might_use() {
    // A caller guessing which convention a binary follows wants to see which
    // one actually appears. Answering only the one they asked about would
    // confirm the guess instead of testing it.
    let mut code = vec![
        0x42, 0x6d, 0x00, 0x08, // 0000 CLR.W (8,A5)
        0x42, 0x79, 0x00, 0x00, 0x10, 0x10, // 0004 CLR.W $1010.L
        0x4e, 0x75, // 000a RTS
    ];
    code.resize(0x20, 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeGlobals(
            amiga_operations::CodeGlobalsArguments::new("game").mapped_at(0x1000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let globals = outcome.analysis_code_globals().expect("a globals map");
    assert_eq!(globals.base_register, 5);
    assert_eq!(globals.hunk_bytes, 0x20);

    assert_eq!(globals.base_relative.len(), 1);
    assert_eq!(globals.base_relative[0].site, 0);
    assert_eq!(globals.base_relative[0].displacement, 8);
    assert_eq!(globals.base_relative[0].value, Some(0));
    // Zero never counts as a pointer: it is the commonest constant in any
    // program, and calling it one would make almost every slot look like one.
    assert!(!globals.base_relative[0].value_points_into_image);

    assert_eq!(globals.absolute.len(), 1);
    assert_eq!(globals.absolute[0].site, 4);
    assert_eq!(globals.absolute[0].address, 0x1010);
    // The offset travels beside the address, so a caller need not re-derive it.
    assert_eq!(globals.absolute[0].offset, Some(0x10));

    // The propagation pass costs work, so it runs only when asked.
    assert_eq!(globals.derived, None);
}

#[test]
fn absolute_globals_are_empty_without_an_origin_rather_than_guessed_at() {
    // "Inside the image" has no meaning until the image has a place, so the
    // absolute list is empty rather than measured from offset zero.
    let mut code = vec![
        0x42, 0x79, 0x00, 0x00, 0x10, 0x10, // CLR.W $1010.L
        0x4e, 0x75, // RTS
    ];
    code.resize(0x20, 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeGlobals(
            amiga_operations::CodeGlobalsArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let globals = outcome.analysis_code_globals().expect("a globals map");
    assert_eq!(globals.origin, None);
    assert!(globals.absolute.is_empty());
    assert_eq!(globals.absolute_total, 0);
}

#[test]
fn a_base_register_outside_a0_a7_is_refused_before_the_source_is_opened() {
    let resolver = resolver(control_flow_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeGlobals(
            amiga_operations::CodeGlobalsArguments::new("game").through_register(9),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
}

#[test]
fn a_fixed_point_scan_reports_three_kinds_of_observation() {
    // MULS D1,D0 then ASR.L #8,D0: an 8.8 multiply, normalised.
    let mut code = vec![
        0xc1, 0xc1, // 0000 MULS.W D1,D0
        0xe1, 0x80, // 0002 ASL.L #8,D0 — placeholder, replaced below
        0x4e, 0x75, // 0004 RTS
    ];
    // ASR.L #8,D0 = 1110 000 0 10 1 00 000 -> 0xe080.
    code[2] = 0xe0;
    code[3] = 0x80;
    code.resize(0x10, 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeFixedPoint(
            amiga_operations::CodeFixedPointArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let fixed = outcome.analysis_code_fixed_point().expect("a scan");
    assert_eq!(fixed.hints.len(), 1);
    assert_eq!(fixed.hints[0].site, 0);
    assert_eq!(fixed.hints[0].shift_site, 2);
    assert_eq!(
        fixed.hints[0].kind,
        amiga_operations::FixedPointKind::ScaledMultiply
    );
    assert_eq!(fixed.hints[0].register, 0);
    // The shift is by an immediate, so the Q scale is known. A register-count
    // shift would report None rather than a guess.
    assert_eq!(fixed.hints[0].fractional_bits, Some(8));
    assert_eq!(fixed.hint_total, 1);
    assert!(!fixed.truncated);
}

#[test]
fn the_register_map_reports_both_frames_of_every_register() {
    // The one operation that reads nothing: its subject is knowledge, not a
    // file. Both frames travel because deriving one from the other separately
    // in every consumer is the arithmetic this layer exists to do once.
    let resolver = resolver(Vec::new());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::HardwareRegisterList(
            amiga_operations::HardwareRegisterListArguments::new(),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let list = outcome.hardware_register_list().expect("a register map");
    assert!(!list.registers.is_empty());
    for register in &list.registers {
        assert_eq!(
            register.address,
            list.custom_base + u32::from(register.offset),
            "{} disagrees with the base it is relative to",
            register.name
        );
    }
    let dmacon = list
        .registers
        .iter()
        .find(|register| register.name == "DMACON")
        .expect("DMACON is in the map");
    assert_eq!(dmacon.offset, 0x096);
}

/// A Copper stream: four colour writes and the `$fffe` wait that ends a list.
fn copper_list() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (register, value) in [
        (0x0180_u16, 0x0123_u16),
        (0x0182, 0x0456),
        (0x0184, 0x0789),
        (0x0186, 0x0abc),
    ] {
        bytes.extend_from_slice(&register.to_be_bytes());
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    // `FFFF FFFE`: the wait for a beam position that never comes.
    bytes.extend_from_slice(&0xffff_u16.to_be_bytes());
    bytes.extend_from_slice(&0xfffe_u16.to_be_bytes());
    bytes
}

#[test]
fn a_copper_decode_names_its_registers_and_expands_only_colour_writes() {
    // A register name is hardware knowledge, so it belongs in the answer rather
    // than in whichever frontend renders it — the call `env.boot.trace` made.
    let resolver = resolver(copper_list());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::HardwareCopperDecode(
            amiga_operations::CopperDecodeArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let decode = outcome.hardware_copper_decode().expect("a decode");
    assert_eq!(decode.offset, 0);
    assert_eq!(decode.instructions.len(), 5);
    match &decode.instructions[0].op {
        amiga_operations::CopperOp::Move {
            register,
            value,
            name,
            rgb8,
        } => {
            assert_eq!(*register, 0x180);
            assert_eq!(*value, 0x0123);
            assert_eq!(name.as_deref(), Some("COLOR00"));
            // $0123 expands to 8 bits per channel by nibble replication.
            assert_eq!(*rgb8, Some([0x11, 0x22, 0x33]));
        }
        other => panic!("expected a MOVE, got {other:?}"),
    }
    // The terminator is reported as one, so a consumer need not know that
    // `$fffe` is the magic position.
    match &decode.instructions[4].op {
        amiga_operations::CopperOp::Wait { terminator, .. } => assert!(terminator),
        other => panic!("expected a WAIT, got {other:?}"),
    }
}

#[test]
fn an_odd_copper_offset_is_refused_rather_than_decoded() {
    // A Copper instruction is read on a word boundary. Decoding from an odd
    // byte produced a plausible listing of a stream the hardware never sees,
    // which is the failure mode this toolkit refuses by name.
    let resolver = resolver(copper_list());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::HardwareCopperDecode(
            amiga_operations::CopperDecodeArguments::new("game").at_offset(3),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
}

#[test]
fn a_palette_scan_reports_both_colour_encodings() {
    // Deriving one from the other separately in each frontend is how two of
    // them end up showing different colours.
    let resolver = resolver(copper_list());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsPaletteScan(
            amiga_operations::PaletteScanArguments::new("game").with_minimum_colours(2),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let scan = outcome.graphics_palette_scan().expect("a palette scan");
    assert_eq!(scan.minimum_colours, 2);
    for table in &scan.tables {
        assert_eq!(
            table.rgb12.len(),
            table.rgb8.len(),
            "the two encodings describe different numbers of colours"
        );
    }
}

#[test]
fn an_ilbm_decode_describes_the_form_without_returning_its_pixels() {
    // The indices are `graphics.bitmap.export`'s to write. Sending a megapixel
    // buffer back through a response envelope would make the cheap question —
    // is this the image I am looking for — as expensive as the export.
    let mut bmhd = Vec::new();
    bmhd.extend_from_slice(&16_u16.to_be_bytes()); // width
    bmhd.extend_from_slice(&2_u16.to_be_bytes()); // height
    bmhd.extend_from_slice(&0_u16.to_be_bytes()); // x
    bmhd.extend_from_slice(&0_u16.to_be_bytes()); // y
    bmhd.extend_from_slice(&[2, 0, 0, 0]); // planes, masking, compression, pad
    bmhd.extend_from_slice(&0_u16.to_be_bytes()); // transparent colour
    bmhd.extend_from_slice(&[1, 1]); // aspect
    bmhd.extend_from_slice(&16_u16.to_be_bytes()); // page width
    bmhd.extend_from_slice(&2_u16.to_be_bytes()); // page height

    let mut chunks = Vec::new();
    for (id, data) in [
        (b"BMHD", bmhd),
        (b"CMAP", vec![0, 0, 0, 0xff, 0xff, 0xff]),
        // Two planes, sixteen pixels a row, two rows: two bytes each.
        (
            b"BODY",
            vec![0xff, 0x00, 0x0f, 0xf0, 0xaa, 0x55, 0x12, 0x34],
        ),
    ] {
        chunks.extend_from_slice(id);
        chunks.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunks.extend_from_slice(&data);
    }
    let mut form = Vec::new();
    form.extend_from_slice(b"FORM");
    form.extend_from_slice(&((chunks.len() + 4) as u32).to_be_bytes());
    form.extend_from_slice(b"ILBM");
    form.extend_from_slice(&chunks);

    let resolver = resolver(form);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsIlbmDecode(
            amiga_operations::IlbmDecodeArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let ilbm = outcome.graphics_ilbm_decode().expect("a decode");
    assert_eq!(ilbm.width, 16);
    assert_eq!(ilbm.height, 2);
    assert_eq!(ilbm.planes, 2);
    assert_eq!(ilbm.indexable_colours, 4);
    assert_eq!(ilbm.masking, amiga_operations::IlbmMasking::None);
    assert!(!ilbm.has_mask);
    // No CAMG and a CAMG of zero are different claims, so the absent one is
    // absent rather than zero.
    assert_eq!(ilbm.viewport_mode, None);
    // Two entries, never padded out to the four the planes could index: the
    // decode reports the colours the form carries and invents none.
    assert_eq!(ilbm.palette.len(), 2);
    assert_eq!(ilbm.palette[1], [0xff, 0xff, 0xff]);
}

#[test]
fn bitmap_detection_derives_width_candidates_and_only_correlates_a_bounded_region() {
    // Guessing geometry is the interactive question this operation exists for,
    // so the widths are derived here rather than in each frontend. And the
    // stride search runs only over a named region: autocorrelation over an
    // unbounded tail measures whatever follows the bitmap as much as it does.
    let mut bytes = Vec::new();
    for row in 0..16_u8 {
        // Forty bytes a row — a 320-pixel one-plane scanline — with a repeating
        // body so the stride is discoverable.
        for column in 0..40_u8 {
            bytes.push(column.wrapping_mul(3).wrapping_add(row / 8));
        }
    }
    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);

    let bounded = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapDetect(
            amiga_operations::BitmapDetectArguments::new("game")
                .over(0, Some(640))
                .with_block(64),
        )),
        &context,
    );
    assert_eq!(bounded.status, Status::Success, "{:?}", bounded.diagnostics);
    let detect = bounded.graphics_bitmap_detect().expect("a detection");
    assert_eq!(detect.length, 640);
    assert!(!detect.blocks.is_empty());
    assert!(!detect.strides.is_empty());
    let best = detect.strides[0].stride;
    // One candidate per plane count that divides the stride, and each width is
    // the stride's bytes-per-plane in pixels.
    for candidate in &detect.geometry {
        assert_eq!(best % usize::from(candidate.planes), 0);
        assert_eq!(
            candidate.width,
            (best as u64 / u64::from(candidate.planes)) * 8
        );
    }

    let unbounded = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapDetect(
            amiga_operations::BitmapDetectArguments::new("game").with_block(64),
        )),
        &context,
    );
    let detect = unbounded.graphics_bitmap_detect().expect("a detection");
    assert!(!detect.blocks.is_empty(), "the entropy map still runs");
    assert!(
        detect.strides.is_empty() && detect.geometry.is_empty(),
        "the stride search ran over an unbounded tail"
    );
}

#[test]
fn register_references_carry_what_the_register_is_as_well_as_where_it_is_touched() {
    // Which instruction touches which register is analysis; the name and the
    // subsystem are hardware fact. Leaving the second to whichever frontend
    // renders the first is how two of them end up disagreeing about $09a.
    let mut code = vec![
        0x33, 0xfc, 0x00, 0x20, 0x00, 0xdf, 0xf0, 0x96, // MOVE.W #$20,DMACON
        0x33, 0xfc, 0x00, 0x0f, 0x00, 0xdf, 0xf1, 0x80, // MOVE.W #$0f,COLOR00
        0x30, 0x39, 0x00, 0xdf, 0xf0, 0x04, // MOVE.W VPOSR,D0
        0x4e, 0x75, // RTS
    ];
    code.resize(code.len().next_multiple_of(4), 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::HardwareRegisterReferences(
            amiga_operations::RegisterReferencesArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let references = outcome
        .hardware_register_references()
        .expect("a cross-reference");
    assert_eq!(references.custom_base, 0x00df_f000);
    // Ordered by register then site, so every access to one register groups
    // together — which is the order the question is asked in.
    let offsets: Vec<u16> = references
        .accesses
        .iter()
        .map(|access| access.offset)
        .collect();
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    assert_eq!(offsets, sorted);

    let dmacon = references
        .accesses
        .iter()
        .find(|access| access.offset == 0x096)
        .expect("the DMACON write");
    assert_eq!(dmacon.name.as_deref(), Some("DMACON"));
    assert_eq!(dmacon.subsystem, "dma");
    assert_eq!(dmacon.kind, amiga_operations::GlobalAccessKind::Write);
    assert_eq!(dmacon.form, amiga_operations::RegisterAccessForm::Absolute);

    let vposr = references
        .accesses
        .iter()
        .find(|access| access.offset == 0x004)
        .expect("the VPOSR read");
    assert_eq!(vposr.kind, amiga_operations::GlobalAccessKind::Read);
}

#[test]
fn copper_patch_writes_are_matched_to_the_field_they_edit() {
    // A loader copies a template into chip RAM and patches the copy, so the
    // template in the file is not what the Copper executes. Matching a write to
    // the field it lands in is the whole question.
    let mut code = vec![
        0x30, 0xbc, 0x01, 0x23, // MOVE.W #$0123,(A0)
        0x31, 0x7c, 0x0f, 0xff, 0x00, 0x06, // MOVE.W #$0fff,(6,A0)
        0x4e, 0x75, // RTS
    ];
    code.resize(code.len().next_multiple_of(4), 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::HardwareCopperReferences(
            // The template lives in the same file here; a request may name
            // another, because the code and the list it edits need not be the
            // same bytes.
            amiga_operations::CopperReferencesArguments::new("game", vec![0], 0).applying(),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let references = outcome
        .hardware_copper_references()
        .expect("a cross-reference");
    assert_eq!(references.pointer_register, 0);
    assert_eq!(references.write_total, 2);
    // Both writes are through the pointer; whether each lands in the list is
    // what `patches` says, and a miss is reported rather than dropped.
    assert_eq!(
        references.writes_in_list,
        references
            .writes
            .iter()
            .filter(|write| write.patches.is_some())
            .count() as u64
    );
    assert_eq!(references.writes[0].offset, 0);
    assert_eq!(references.writes[0].value, Some(0x0123));
    assert_eq!(references.writes[1].offset, 6);
    assert_eq!(references.writes[1].value, Some(0x0fff));

    let effective = references.effective.as_ref().expect("an effective list");
    assert_eq!(effective.applied, references.writes_in_list);
    // Applying immediates only rewrites words, so the effective list has the
    // template's structure and the two zip instruction for instruction.
    assert_eq!(effective.instruction_total, references.template_total);
    assert_eq!(
        effective.palette_rgb12.len(),
        effective.palette_rgb8.len(),
        "the two encodings describe different numbers of colours"
    );
}

#[test]
fn a_routine_that_loads_the_list_address_itself_still_reports_its_patches() {
    // The shape the entry value cannot describe: the helper is not handed the
    // list, it loads it. The load overwrites the register the caller named with
    // an address unrelated to the entry value, so every store after it used to
    // be dropped and the routine read as one that never touches the list.
    const LIST: u32 = 0x0006_0000;
    let mut code = vec![
        0x20, 0x7c, 0x00, 0x06, 0x00, 0x00, // MOVEA.L #$60000,A0
        0x31, 0x7c, 0x0f, 0xff, 0x00, 0x06, // MOVE.W #$0fff,(6,A0)
        0x4e, 0x75, // RTS
    ];
    code.resize(code.len().next_multiple_of(4), 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let run = |arguments| {
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::HardwareCopperReferences(
                arguments,
            )),
            &context,
        );
        assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
        outcome
    };
    let arguments = || amiga_operations::CopperReferencesArguments::new("game", vec![0], 0);

    let silent = run(arguments());
    assert_eq!(
        silent
            .hardware_copper_references()
            .expect("a cross-reference")
            .write_total,
        0,
        "an absolute load is not related to the entry value, and saying otherwise \
         would be inventing a base"
    );

    let told = run(arguments().with_template_address(LIST));
    let references = told
        .hardware_copper_references()
        .expect("a cross-reference");
    assert_eq!(references.template_address, Some(LIST));
    assert_eq!(references.write_total, 1);
    assert_eq!(references.writes[0].offset, 6);
    assert_eq!(references.writes[0].value, Some(0x0fff));
    // Which base the offset rests on, reported rather than left to infer: this
    // one is a fact about the code, not the caller's assertion about A0.
    assert_eq!(references.writes[0].base_site, Some(0));

    // A list somewhere else does not claim this routine's stores. Without the
    // bound, every absolute address in a program would read as this list's base.
    let elsewhere = run(arguments().with_template_address(LIST + 0x1_0000));
    assert_eq!(
        elsewhere
            .hardware_copper_references()
            .expect("a cross-reference")
            .write_total,
        0
    );
}

#[test]
fn the_fact_model_is_one_model_whichever_bytes_it_is_about() {
    // A boot block's code is not a hunk's, and the same question is asked of
    // it. One selector on one operation rather than two fact models, which is
    // the duplication this whole plan removes.
    let mut image = vec![0_u8; 1024];
    image[0..4].copy_from_slice(b"DOS\0");
    // MOVEQ #0,D0 ; RTS, at the boot block's code offset.
    image[12..16].copy_from_slice(&[0x70, 0x00, 0x4e, 0x75]);

    let resolver = resolver(image);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeFacts(
            amiga_operations::CodeFactsArguments::new("game").in_boot_block(),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let facts = outcome.analysis_code_facts().expect("a fact set");
    assert_eq!(facts.region, amiga_operations::CodeRegion::BootBlock);
    assert_eq!(facts.hunk, None);
    // Where the code sits in the file, so a fact's offset can be named in the
    // frame a reader has open.
    assert_eq!(facts.code_offset, 12);
    // The instructions travel beside the facts because every renderer needs
    // both: an annotated listing walks instructions and hangs facts off them.
    assert_eq!(facts.instructions.len(), 2);
    assert_eq!(facts.instructions[0].offset, 0);
    assert!(facts.instructions[0].text.starts_with("MOVEQ"));
    // A function entry is a fact, which is what lets a renderer label a line
    // without a second traversal.
    assert!(
        facts
            .facts
            .iter()
            .any(|fact| matches!(fact.kind, amiga_disasm::FactKind::Function { entry: 0 })),
        "no function fact at the entry"
    );
    assert_eq!(facts.schema_version, amiga_disasm::SCHEMA_VERSION);
}

#[test]
fn raw_image_facts_keep_the_same_offsets_and_all_entry_points() {
    let bytes = vec![0x70, 0x01, 0x4e, 0x75, 0x70, 0x02, 0x4e, 0x75];
    let digest = amiga_core::sha256(&bytes);
    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeFacts(
            amiga_operations::CodeFactsArguments::new("game")
                .in_raw(digest)
                .from_entries(vec![0, 4]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let facts = outcome.analysis_code_facts().expect("a fact set");
    assert_eq!(facts.region, amiga_operations::CodeRegion::Raw);
    assert_eq!(facts.hunk, None);
    assert_eq!(facts.code_offset, 0);
    assert_eq!(facts.code_bytes, 8);
    assert_eq!(facts.entries, [0, 4]);
    assert!(
        facts
            .facts
            .iter()
            .any(|fact| { matches!(fact.kind, amiga_disasm::FactKind::Function { entry: 4 }) })
    );
}

#[test]
fn a_supplied_library_vector_names_the_call_it_describes() {
    // `collect` bakes library and function names into every LibraryCall fact,
    // from tables a frontend reads out of its own fd files. The tables travel
    // as data so no request names a host path — and a fact that lost the name
    // would be a worse fact.
    let mut code = vec![
        0x2c, 0x78, 0x00, 0x04, // MOVEA.L (4).W,A6   — ExecBase
        0x4e, 0xae, 0xff, 0x3a, // JSR (-198,A6)      — OpenLibrary
        0x4e, 0x75, // RTS
    ];
    code.resize(code.len().next_multiple_of(4), 0);
    let resolver = resolver(image(&code));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisCodeFacts(
            amiga_operations::CodeFactsArguments::new("game")
                .with_default_library("exec")
                .with_library_vectors(vec![amiga_operations::LibraryVector {
                    library: "exec".to_owned(),
                    lvo: -198,
                    name: "TotallyMadeUpVector".to_owned(),
                    arguments: vec![amiga_operations::VectorArgument {
                        register: "a1".to_owned(),
                        name: Some("libName".to_owned()),
                    }],
                    public: true,
                }]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let facts = outcome.analysis_code_facts().expect("a fact set");
    let named = facts.facts.iter().any(|fact| {
        matches!(
            &fact.kind,
            amiga_disasm::FactKind::LibraryCall { function, .. }
                if function.as_deref() == Some("TotallyMadeUpVector")
        )
    });
    assert!(
        named,
        "the supplied vector did not name its call: {:?}",
        facts.facts
    );
    // The parameter's name survives too. A table that named `libName` in A1 and
    // one that said only `a1` describe different amounts of knowledge, and a
    // fact keeping only the register would be the weaker wearing the
    // stronger's shape.
    let named_argument = facts.facts.iter().any(|fact| match &fact.kind {
        amiga_disasm::FactKind::LibraryCall { arguments, .. } => arguments
            .iter()
            .any(|argument| argument.name.as_deref() == Some("libName")),
        _ => false,
    });
    assert!(named_argument, "the argument's name was lost");
}
