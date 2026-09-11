//! `env.sandbox.run`: bounded execution through the shared operation API.
//!
//! These tests verify the memory layout, step ceiling, and structured stop reasons
//! returned by the sandbox operation.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, InMemorySourceResolver, OperationRequestDocument, RequestEnvelope,
    ResolvedSource, Router, SandboxRunArguments, SourceName, Status, WatchAccess, WatchRange,
};

/// A one-hunk LoadSeg image whose CODE hunk holds `code`, padded to
/// `allocation` bytes so the sandbox has room above it.
fn image(code: &[u8], allocation_longwords: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, allocation_longwords] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    let longwords = code.len().div_ceil(4) as u32;
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(code);
    bytes.resize(bytes.len() + (longwords as usize * 4 - code.len()), 0);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// A two-hunk LoadSeg image: a CODE hunk holding `code` allocated
/// `code_allocation` bytes, and a BSS hunk of `bss_allocation` bytes after it.
fn code_and_bss(code: &[u8], code_allocation: u32, bss_allocation: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        0x0000_03f3_u32,
        0,
        2,
        0,
        1,
        code_allocation / 4,
        bss_allocation / 4,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    let longwords = code.len().div_ceil(4) as u32;
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(code);
    bytes.resize(bytes.len() + (longwords as usize * 4 - code.len()), 0);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes.extend_from_slice(&0x0000_03eb_u32.to_be_bytes()); // HUNK_BSS
    bytes.extend_from_slice(&(bss_allocation / 4).to_be_bytes());
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

fn resolver(bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse("game").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

#[test]
fn a_routine_that_returns_says_so_and_reports_its_map() {
    // MOVEQ #7,D0 ; RTS
    let resolver = resolver(image(&[0x70, 0x07, 0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game")
                .at_origin(0x2_0000)
                .tracing(),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let run = outcome.env_sandbox_run().expect("a run");
    assert_eq!(run.stop, amiga_operations::SandboxStop::Returned);
    assert_eq!(run.registers.d[0], 7);
    assert_eq!(run.steps_executed, 2);
    // The map is reported because it is what the trace's addresses mean.
    assert_eq!(run.load_origin, 0x2_0000);
    assert_eq!(run.entry, 0x2_0000);
    assert!(
        run.stack_base > run.load_origin + run.allocation_bytes as u32,
        "the derived stack does not sit above the hunk"
    );
    assert_eq!(run.trace.len(), 2);
    assert_eq!(run.trace[0].address, 0x2_0000);
}

#[test]
fn a_routine_that_never_returns_stops_on_the_budget_it_was_given() {
    // BRA.S *  — an endless loop, which is the normal case while identifying
    // unknown code, and the reason the budget is not optional.
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").with_maximum_steps(32),
        )),
        &context,
    );

    let run = outcome.env_sandbox_run().expect("a run");
    assert_eq!(run.stop, amiga_operations::SandboxStop::StepLimit);
    assert_eq!(run.steps_executed, 32);
}

#[test]
fn a_step_budget_above_the_ceiling_is_reduced_and_says_so() {
    // The ceiling is the context's, not the caller's: a request that could
    // ask for an unbounded run would be asking the process to hang.
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").with_maximum_steps(10_000_000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::LimitReduced),
        "the reduction was silent: {:?}",
        outcome.diagnostics
    );
    assert_eq!(
        outcome.env_sandbox_run().expect("a run").steps_executed,
        200_000
    );
}

#[test]
fn a_reviewed_context_may_raise_the_budget_but_not_remove_it() {
    // An initialization routine that decodes graphics, builds geometry tables,
    // and runs a palette-transition loop can legitimately exceed the default
    // budget, and splitting the run loses the excluded call stack — so it
    // cannot reproduce the same state. A host running local media it has
    // reviewed may therefore raise the ceiling. To a number, never to none.
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver).with_limits(
        amiga_operations::OperationLimits::default().with_maximum_sandbox_steps(1_000_000),
    );
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").with_maximum_steps(400_000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success);
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != amiga_operations::DiagnosticCode::LimitReduced),
        "a budget the context allows was still reduced: {:?}",
        outcome.diagnostics
    );
    assert_eq!(
        outcome.env_sandbox_run().expect("a run").steps_executed,
        400_000
    );

    // And the raise itself is bounded: a context asking for more than the
    // crate's absolute maximum gets the maximum, not what it asked for.
    let unbounded = amiga_operations::OperationLimits::default()
        .with_maximum_sandbox_steps(usize::MAX)
        .maximum_sandbox_steps();
    assert_eq!(unbounded, amiga_operations::MAXIMUM_SANDBOX_STEPS_CEILING);
}

#[test]
fn a_long_run_keeps_only_the_trace_rows_it_could_report() {
    // A step row holds the instruction's text, its register deltas, and its
    // writes, so a budget a context can raise is finite in instructions only if
    // the trace is finite in memory too. The rows beyond the cap are not built
    // at all — and the count of them is still true, so a capped trace cannot
    // read as a short run.
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver).with_limits(
        amiga_operations::OperationLimits::default().with_maximum_sandbox_steps(1_000_000),
    );
    let mut arguments = SandboxRunArguments::new("game")
        .with_maximum_steps(300_000)
        .tracing();
    arguments.maximum_trace_rows = Some(64);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(arguments)),
        &context,
    );

    let run = outcome.env_sandbox_run().expect("a run");
    assert_eq!(run.trace.len(), 64);
    assert_eq!(run.trace_total, 300_000);
    assert!(run.trace_truncated);
}

#[test]
fn a_runaway_stack_faults_instead_of_overwriting_the_code() {
    // The unmapped gap between the hunk and the derived stack is what makes
    // this a fault. Without it the stack would grow into the code being run and
    // the trace would show a program that rewrote itself for no visible reason.
    // MOVE.L #0,-(SP) repeated forever: LEA is simpler — just push in a loop.
    let code = [
        0x2f, 0x3c, 0x00, 0x00, 0x00, 0x00, // MOVE.L #0,-(SP)
        0x60, 0xf8, // BRA.S back
    ];
    let resolver = resolver(image(&code, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").with_maximum_steps(100_000),
        )),
        &context,
    );

    let run = outcome.env_sandbox_run().expect("a run");
    assert!(
        matches!(run.stop, amiga_operations::SandboxStop::Fault { .. }),
        "a stack that ran past its region did not fault: {:?}",
        run.stop
    );
}

#[test]
fn a_watched_write_stops_the_run_and_the_trace_points_at_it() {
    // A watch hit with no trace to point at would be a stop nobody could
    // explain, so watching records even when no trace was asked for.
    let code = [
        0x21, 0xfc, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, // MOVE.L #42,($0000).W
        0x4e, 0x75, // RTS
    ];
    let resolver = resolver(image(&code, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").watching(
                vec![WatchRange {
                    start: 0,
                    length: 4,
                    access: WatchAccess::Write,
                }],
                true,
            ),
        )),
        &context,
    );

    let run = outcome.env_sandbox_run().expect("a run");
    // Address zero is unmapped in this layout, so the access faults before the
    // watch can match — which is itself the point: a watch on unmapped memory
    // reports the fault rather than pretending the write happened.
    assert!(
        matches!(
            run.stop,
            amiga_operations::SandboxStop::Watch { .. }
                | amiga_operations::SandboxStop::Fault { .. }
        ),
        "{:?}",
        run.stop
    );
}

#[test]
fn more_watched_ranges_than_the_bound_are_refused_rather_than_dropped() {
    // Every watchpoint is compared against every access, so the list is a
    // per-access cost. Truncating it would be the worst answer available: a run
    // that observed nothing would be indistinguishable from one that had
    // nothing to observe.
    let resolver = resolver(image(&[0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let watch: Vec<WatchRange> = (0..65)
        .map(|index| WatchRange {
            start: 0x1000 + index * 4,
            length: 4,
            access: WatchAccess::Both,
        })
        .collect();
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").watching(watch, false),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
    assert_eq!(
        outcome.diagnostics[0].json_path.as_deref(),
        Some("$.request.arguments.watch")
    );
}

#[test]
fn exactly_the_bound_of_watched_ranges_is_accepted() {
    let resolver = resolver(image(&[0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let watch: Vec<WatchRange> = (0..64)
        .map(|index| WatchRange {
            start: 0x1000 + index * 4,
            length: 4,
            access: WatchAccess::Both,
        })
        .collect();
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").watching(watch, false),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success);
    let run = outcome.env_sandbox_run().expect("a run");
    // Nothing the routine did lands in a watched range, so nothing matched.
    assert_eq!(run.watch_events_total, 0);
    assert!(!run.watch_events_truncated);
}

#[test]
fn a_zero_length_watch_is_refused_rather_than_never_matching() {
    let resolver = resolver(image(&[0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").watching(
                vec![WatchRange {
                    start: 0x1000,
                    length: 0,
                    access: WatchAccess::Both,
                }],
                false,
            ),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.exit_code(),
        2,
        "a bad request has its own exit code"
    );
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
}

#[test]
fn an_entry_outside_the_hunk_is_refused_before_anything_runs() {
    let resolver = resolver(image(&[0x4e, 0x75], 4));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("game").with_entry_offset(0x1000),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.diagnostics[0].json_path.as_deref(),
        Some("$.request.arguments.entry_offset")
    );
}

#[test]
fn a_capped_trace_still_reports_the_true_total() {
    // A capped trace that read as a complete one would make a step limit look
    // like a short routine.
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver);
    let mut arguments = SandboxRunArguments::new("game")
        .with_maximum_steps(500)
        .tracing();
    arguments.maximum_trace_rows = Some(10);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(arguments)),
        &context,
    );

    let run = outcome.env_sandbox_run().expect("a run");
    assert_eq!(run.trace.len(), 10);
    assert_eq!(run.trace_total, 500);
    assert!(run.trace_truncated);
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::ResultEntriesTruncated),
        "the truncation was silent"
    );
}

#[test]
fn the_same_run_asked_for_twice_digests_the_same() {
    // The digest is what a cache would key on, so two identical requests must
    // agree and a request differing in any bound must not.
    let resolver = resolver(image(&[0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let digest = |steps| {
        Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxRun(
                SandboxRunArguments::new("game").with_maximum_steps(steps),
            )),
            &context,
        )
        .normalized_request_sha256
    };
    assert_eq!(digest(100), digest(100));
    assert_ne!(digest(100), digest(200));
}

/// A two-block boot area with `tag`, a stored checksum, and `code` after the
/// twelve-byte header.
fn bootblock(tag: &[u8; 4], checksum: u32, code: &[u8]) -> Vec<u8> {
    let mut block = vec![0_u8; 1024];
    block[0..4].copy_from_slice(tag);
    block[4..8].copy_from_slice(&checksum.to_be_bytes());
    block[8..12].copy_from_slice(&880_u32.to_be_bytes()); // root block
    block[12..12 + code.len()].copy_from_slice(code);
    block
}

#[test]
fn a_boot_block_reports_its_checksum_as_stored_beside_whether_it_verifies() {
    // A trackloader disk with a deliberately wrong checksum is a normal thing to
    // find. A result that only said "invalid" would lose the number that
    // recognizes which one, so both travel together.
    let resolver = resolver(bootblock(b"DOS\0", 0xdead_beef, &[0x4e, 0x75]));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvBootInfo(
            amiga_operations::BootInfoArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let info = outcome.env_boot_info().expect("a boot block");
    assert_eq!(info.tag, "DOS");
    assert!(info.is_dos);
    assert_eq!(info.stored_checksum, 0xdead_beef);
    assert!(!info.checksum_valid);
    assert_eq!(info.root_block, 880);
    assert!(info.has_boot_code);
    // A checksum that does not verify is a warning, not a refusal: the
    // filesystem does not depend on it.
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::ContainerAdfBootChecksumInvalid),
        "the broken checksum was silent: {:?}",
        outcome.diagnostics
    );
}

#[test]
fn a_non_dos_tag_is_reported_rather_than_refused() {
    // The disks this toolkit exists for often have no DOS tag at all.
    let resolver = resolver(bootblock(b"HORS", 0, &[]));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvBootInfo(
            amiga_operations::BootInfoArguments::new("game"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let info = outcome.env_boot_info().expect("a boot block");
    assert!(!info.is_dos);
    assert_eq!(info.tag, "HOR");
    assert!(!info.has_boot_code, "an all-zero code area is not code");
}

#[test]
fn a_call_records_its_inputs_its_outputs_and_what_it_changed() {
    // MOVE.L (4,SP),D0 ; MOVE.L D0,(0x30000).L ; RTS — read the stack argument,
    // store it into a mapped region, return.
    let code = [
        0x20, 0x2f, 0x00, 0x04, // MOVE.L (4,SP),D0
        0x23, 0xc0, 0x00, 0x04, 0x00, 0x00, // MOVE.L D0,($00040000).L
        0x4e, 0x75, // RTS
    ];
    let resolver = resolver(image(&code, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(
                SandboxRunArguments::new("game").at_origin(0x2_0000),
            )
            .with_stack_arguments(vec![0xcafe_babe])
            .with_mapped_regions(vec![amiga_operations::MappedRegion {
                address: 0x4_0000,
                size: 16,
            }]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned);
    assert_eq!(record.stop, amiga_operations::SandboxStop::Returned);
    assert_eq!(record.outputs.d[0], 0xcafe_babe);
    assert_eq!(record.stack_arguments, vec![0xcafe_babe]);
    // The mapped region shows the change; the stack does not appear at all,
    // because it is scratch and would make every record differ from every other.
    assert!(
        record
            .changed_memory
            .iter()
            .any(|region| region.address == 0x4_0000 && region.hex.starts_with("cafebabe")),
        "the write into the mapped region is missing: {:?}",
        record.changed_memory
    );
}

#[test]
fn a_records_stop_reason_is_structured_rather_than_prose() {
    // The record this replaces carried an `outcome` string rendered through the
    // frontend's fd tables, so the same routine on the same bytes produced a
    // different record depending on what `amiga-re.toml` said — unstable in
    // exactly the dimension a diffable record exists to be stable in.
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(
                SandboxRunArguments::new("game").with_maximum_steps(16),
            ),
        )),
        &context,
    );

    let record = outcome.env_sandbox_call().expect("a record");
    assert!(!record.returned);
    assert_eq!(record.stop, amiga_operations::SandboxStop::StepLimit);
    let document = serde_json::to_value(record).expect("the record serializes");
    assert_eq!(document["stop"]["reason"], "step_limit");
    assert!(
        document.get("outcome").is_none(),
        "the record still carries rendered prose: {document}"
    );
}

/// Two stores into a mapped region, then `RTS`.
///
/// `MOVE.L #42,($00040000).L` · `MOVE.L #43,($00040004).L` · `RTS`, so a watch
/// on the second word has a first word to run past before it matches.
const TWO_STORES: [u8; 22] = [
    0x23, 0xfc, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, // MOVE.L #42,($40000).L
    0x23, 0xfc, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x04, // MOVE.L #43,($40004).L
    0x4e, 0x75, // RTS
];

/// A call over `TWO_STORES` with the region it writes into mapped.
fn two_store_call(run: SandboxRunArguments) -> amiga_operations::SandboxCallArguments {
    amiga_operations::SandboxCallArguments::new(run).with_mapped_regions(vec![
        amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 16,
        },
    ])
}

#[test]
fn a_call_that_asked_for_no_trace_keeps_none() {
    // A golden record is about inputs and outputs. Recording megabytes to
    // discard them is work nobody wanted, and a record that carried a trace by
    // default would make two runs with identical outputs produce records that
    // differ.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(two_store_call(
            SandboxRunArguments::new("game").at_origin(0x2_0000),
        ))),
        &context,
    );

    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned);
    assert!(record.trace.is_empty());
    assert_eq!(record.trace_total, 0);
    assert!(!record.trace_truncated);
}

#[test]
fn a_seeded_call_returns_the_trace_it_was_asked_for() {
    // The trace was accepted and discarded: `call` set `record_steps = false`
    // whatever the request said, so a fault after a long initialization could
    // not be traced back to the instruction that caused it. A call that maps
    // regions and seeds memory — the shape `run` cannot express — now answers
    // with the trace as well as the diff.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            two_store_call(
                SandboxRunArguments::new("game")
                    .at_origin(0x2_0000)
                    .tracing(),
            )
            .with_memory_seeds(vec![amiga_operations::MemorySeed::hex(
                0x4_0008, "deadbeef",
            )]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned);
    assert_eq!(record.trace_total, 3, "two stores and an RTS");
    assert_eq!(record.trace.len(), 3);
    assert_eq!(record.trace[0].address, 0x2_0000);
    // The trace says what the diff only shows the end of: which instruction
    // wrote which word.
    assert!(
        record.trace[0]
            .writes
            .iter()
            .any(|write| write.address == 0x4_0000 && write.value == 42),
        "the first store is not in its trace row: {:?}",
        record.trace[0].writes
    );
}

#[test]
fn a_watched_call_stops_at_the_access_and_says_which_instruction_reached_it() {
    // `stop_on_watch` was advertised by the request schema and never passed
    // into the run, so it could not fire. A watch that stops is only useful
    // with a trace to point at, so watching records even when no trace was
    // asked for — the same rule `run` follows.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(two_store_call(
            SandboxRunArguments::new("game")
                .at_origin(0x2_0000)
                .watching(
                    vec![WatchRange {
                        start: 0x4_0004,
                        length: 4,
                        access: WatchAccess::Write,
                    }],
                    true,
                ),
        ))),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(!record.returned, "the watch should have stopped the call");
    match record.stop {
        amiga_operations::SandboxStop::Watch { address, site, .. } => {
            assert_eq!(address, 0x4_0004);
            assert_eq!(site, 0x2_000a, "the second store is what reached it");
        }
        ref other => panic!("the watch did not stop the call: {other:?}"),
    }
    // Recorded, but not reported: the request asked for a watch, not a trace.
    assert!(record.trace.is_empty());
    assert_eq!(record.trace_total, 2);
}

#[test]
fn a_capped_call_trace_still_reports_the_true_total() {
    let resolver = resolver(image(&[0x60, 0xfe], 64));
    let context = ExecutionContext::new(&resolver);
    let mut run = SandboxRunArguments::new("game")
        .with_maximum_steps(500)
        .tracing();
    run.maximum_trace_rows = Some(10);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(run),
        )),
        &context,
    );

    let record = outcome.env_sandbox_call().expect("a record");
    assert_eq!(record.trace.len(), 10);
    assert_eq!(record.trace_total, 500);
    assert!(record.trace_truncated);
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::ResultEntriesTruncated),
        "the truncation was silent"
    );
}

#[test]
fn a_longword_across_the_hunk_and_its_bss_is_one_legal_access() {
    // A selected hunk and the BSS mapped immediately after it were two bus
    // regions, so a legal MOVE.L crossing their shared boundary faulted even
    // though every byte was mapped — which forced instruction-width patches
    // into code that copies or clears a buffer spanning the seam.
    //
    // MOVE.L #$11223344,($0002003e).L ; RTS — two bytes either side of the
    // 0x20040 boundary between a 0x40-byte CODE hunk at 0x20000 and the BSS
    // hunk mapped straight after it.
    let code = [
        0x23, 0xfc, 0x11, 0x22, 0x33, 0x44, 0x00, 0x02, 0x00, 0x3e, //
        0x4e, 0x75,
    ];
    let resolver = resolver(code_and_bss(&code, 0x40, 0x40));
    let context = ExecutionContext::new(&resolver);
    let mut run = SandboxRunArguments::new("game").at_origin(0x2_0000);
    run.hunk_bases.push(amiga_operations::HunkBase {
        hunk: 1,
        address: 0x2_0040,
    });
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(run),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(
        record.returned,
        "the access across the seam did not complete: {:?}",
        record.stop
    );
    assert!(
        record
            .changed_memory
            .iter()
            .any(|region| region.address == 0x2_003e && region.hex == "11223344"),
        "the straddling write is missing: {:?}",
        record.changed_memory
    );
}

#[test]
fn a_seed_copies_a_range_of_the_image_and_the_record_says_where_from() {
    // A self-relocating loader installs a small resident helper by copying part
    // of its own image to low memory. Reproducing that state used to mean
    // converting those bytes to hex by hand — a string nothing could check
    // against the image it came from.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000)).with_memory_seeds(
                vec![amiga_operations::MemorySeed::from(
                    0x4_0008,
                    amiga_operations::SeedRange {
                        source: None,
                        // The routine's own first four bytes, at their hunk
                        // offset — the number a disassembly shows.
                        hunk: Some(0),
                        offset: 0,
                        length: 4,
                    },
                )],
            ),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    let [seed] = record.memory_seeds.as_slice() else {
        panic!("expected one seed: {:?}", record.memory_seeds);
    };
    assert_eq!(seed.address, 0x4_0008);
    // The bytes the hunk actually holds, not a string somebody typed.
    assert_eq!(seed.hex, "23fc0000");
    let from = seed.from.as_ref().expect("the range it came from");
    assert_eq!(from.hunk, Some(0));
    assert_eq!(from.offset, 0);
    assert_eq!(from.length, 4);
    assert!(from.source.is_none(), "no source means the image being run");
}

/// The other end of `memory_exports`, and the whole of what made replaying one
/// an external conversion: `call --save` preserves a decoded runtime table so a
/// later stage can be run against it, and turning that file back into a seed
/// meant hexadecimal produced outside the toolkit — which loses the one thing
/// that made it evidence, which file it was.
#[test]
fn a_seed_replays_a_pinned_artifact_and_the_record_carries_its_digest() {
    let artifact = b"a decoded table an earlier run wrote".to_vec();
    let sha256 = amiga_core::sha256(&artifact);
    let resolver = InMemorySourceResolver::holding(vec![
        ResolvedSource::new(
            SourceName::parse("game").expect("a valid name"),
            Arc::from(image(&TWO_STORES, 64)),
        ),
        ResolvedSource::new(
            SourceName::parse("table.bin").expect("a valid name"),
            Arc::from(artifact.clone()),
        ),
    ]);
    let context = ExecutionContext::new(&resolver);
    let call = |artifact: amiga_operations::SeedArtifact| {
        RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(
                SandboxRunArguments::new("game").at_origin(0x2_0000),
            )
            .with_mapped_regions(vec![amiga_operations::MappedRegion {
                address: 0x4_0000,
                size: 64,
            }])
            .with_memory_seeds(vec![amiga_operations::MemorySeed::artifact(
                0x4_0010, artifact,
            )]),
        ))
    };

    let outcome = Router::execute(
        &call(amiga_operations::SeedArtifact::new("table.bin", &sha256)),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    let [seed] = record.memory_seeds.as_slice() else {
        panic!("expected one seed: {:?}", record.memory_seeds);
    };
    let from = seed.from.as_ref().expect("the artifact it came from");
    assert_eq!(from.source.as_deref(), Some("table.bin"));
    assert_eq!(from.offset, 0);
    // Omitting the length replays the whole file, and the record states the
    // resolved number rather than the absence the request spelled.
    assert_eq!(from.length, artifact.len() as u32);
    // The digest is what tells this apart from a range of the image the record
    // already pins.
    assert_eq!(from.sha256.as_deref(), Some(sha256.as_str()));
    assert!(from.hunk.is_none());

    // A stale artifact is a refused request, not a completed run whose outputs
    // describe a file it never read.
    let stale = Router::execute(
        &call(amiga_operations::SeedArtifact::new(
            "table.bin",
            "b".repeat(64),
        )),
        &context,
    );
    assert_eq!(stale.status, Status::Error);
    assert!(
        stale
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == amiga_operations::DiagnosticCode::SourceDigestMismatch),
        "{:?}",
        stale.diagnostics
    );

    // And a range outside the file is refused before anything runs, like every
    // other seed range.
    let outside = Router::execute(
        &call(amiga_operations::SeedArtifact::new("table.bin", &sha256).with_range(4, 1024)),
        &context,
    );
    assert_eq!(outside.status, Status::Error);
    assert!(
        outside
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("which holds")),
        "{:?}",
        outside.diagnostics
    );
}

#[test]
fn a_seed_naming_a_range_the_image_does_not_hold_is_refused() {
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000)).with_memory_seeds(
                vec![amiga_operations::MemorySeed::from(
                    0x4_0000,
                    amiga_operations::SeedRange {
                        source: None,
                        hunk: Some(0),
                        offset: 0,
                        length: 0x1000,
                    },
                )],
            ),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::SourceRangeOutsideSource
    );
}

#[test]
fn a_seed_states_its_bytes_exactly_one_way() {
    // Serde cannot say "one or the other". A seed with both would have two
    // answers to what it seeds; one with neither would seed nothing while
    // looking like it seeded something.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let range = amiga_operations::SeedRange {
        source: None,
        hunk: None,
        offset: 0,
        length: 4,
    };
    for seed in [
        amiga_operations::MemorySeed {
            address: 0x4_0000,
            hex: Some("deadbeef".to_owned()),
            from: Some(range.clone()),
            artifact: None,
        },
        amiga_operations::MemorySeed {
            address: 0x4_0000,
            hex: None,
            from: None,
            artifact: None,
        },
    ] {
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
                two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000))
                    .with_memory_seeds(vec![seed]),
            )),
            &context,
        );
        assert_eq!(outcome.status, Status::Error);
        assert_eq!(
            outcome.diagnostics[0].code,
            amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
        );
    }
}

#[test]
fn a_seed_from_a_bss_hunk_is_refused_rather_than_copying_zeros() {
    // A BSS hunk holds no bytes in the file. Reading it as zeros would seed
    // something that is not in the image and say it was.
    let code = [0x4e, 0x75];
    let resolver = resolver(code_and_bss(&code, 0x40, 0x40));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(
                SandboxRunArguments::new("game").at_origin(0x2_0000),
            )
            .with_mapped_regions(vec![amiga_operations::MappedRegion {
                address: 0x5_0000,
                size: 16,
            }])
            .with_memory_seeds(vec![amiga_operations::MemorySeed::from(
                0x5_0000,
                amiga_operations::SeedRange {
                    source: None,
                    hunk: Some(1),
                    offset: 0,
                    length: 4,
                },
            )]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
    assert!(
        outcome.diagnostics[0].message.contains("BSS"),
        "the refusal did not say which kind of hunk: {}",
        outcome.diagnostics[0].message
    );
}

#[test]
fn a_scheduled_interrupt_releases_a_routine_spinning_on_a_flag() {
    // The shape that made otherwise valid initialization never return: set a
    // synchronization flag, then spin until an interrupt handler clears it. The
    // beam counter advances on its own and nothing runs the handler, so the
    // only way through was to patch the wait branch — which changes the code
    // being studied.
    //
    //   entry:   MOVE.W #1,($40000).L     ; the flag
    //   wait:    TST.W ($40000).L
    //            BNE.S wait
    //            RTS
    //   handler: CLR.W ($40000).L
    //            RTE
    let code = [
        0x33, 0xfc, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, // 0x00 MOVE.W #1,($40000).L
        0x4a, 0x79, 0x00, 0x04, 0x00, 0x00, // 0x08 TST.W ($40000).L
        0x66, 0xf8, // 0x0e BNE.S wait
        0x4e, 0x75, // 0x10 RTS
        0x42, 0x79, 0x00, 0x04, 0x00, 0x00, // 0x12 CLR.W ($40000).L
        0x4e, 0x73, // 0x18 RTE
    ];
    let resolver = resolver(image(&code, 64));
    let context = ExecutionContext::new(&resolver);
    let call = |interrupts: Vec<amiga_operations::ScheduledInterrupt>| {
        Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
                amiga_operations::SandboxCallArguments::new(
                    SandboxRunArguments::new("game")
                        .at_origin(0x2_0000)
                        .with_maximum_steps(500),
                )
                .with_mapped_regions(vec![amiga_operations::MappedRegion {
                    address: 0x4_0000,
                    size: 16,
                }])
                .with_interrupts(interrupts),
            )),
            &context,
        )
    };

    // Without a schedule, the routine spins until the budget runs out. This is
    // the behaviour the entry reported, asserted so the fix is visible as a
    // change rather than only as a passing test.
    let spinning = call(Vec::new());
    let record = spinning.env_sandbox_call().expect("a record");
    assert!(!record.returned);
    assert_eq!(record.stop, amiga_operations::SandboxStop::StepLimit);

    let released = call(vec![amiga_operations::ScheduledInterrupt {
        vector: None,
        address: Some(0x2_0012),
        after_steps: Some(8),
        every_steps: None,
        deliveries: None,
        frame: None,
    }]);
    assert_eq!(
        released.status,
        Status::Success,
        "{:?}",
        released.diagnostics
    );
    let record = released.env_sandbox_call().expect("a record");
    assert!(
        record.returned,
        "the handler did not release the wait: {:?}",
        record.stop
    );
    // The record says the handler ran, and where. A run whose outcome depended
    // on it is not reproducible from a record that does not mention it.
    assert_eq!(record.interrupts_total, 1);
    let [delivery] = record.interrupts_delivered.as_slice() else {
        panic!("expected one delivery: {:?}", record.interrupts_delivered);
    };
    assert_eq!(delivery.handler, 0x2_0012);
    assert_eq!(delivery.index, 0);
}

#[test]
fn a_scheduled_interrupt_runs_the_handler_the_program_installed() {
    // Naming a vector rather than an address is the point: the recipe says
    // *when*, and the program's own initialization says *what*.
    //
    //   entry:   MOVE.L #handler,(0x6c).L   ; install the level-3 vector
    //            MOVE.W #1,($40000).L
    //   wait:    TST.W ($40000).L ; BNE.S wait ; RTS
    //   handler: CLR.W ($40000).L ; RTE
    let code = [
        0x23, 0xfc, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x6c, // 0x00 MOVE.L #0x20020,(0x6c).L
        0x33, 0xfc, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, // 0x0a MOVE.W #1,($40000).L
        0x4a, 0x79, 0x00, 0x04, 0x00, 0x00, // 0x12 TST.W ($40000).L
        0x66, 0xf8, // 0x18 BNE.S wait
        0x4e, 0x75, // 0x1a RTS
        0x4e, 0x71, 0x4e, 0x71, // 0x1c padding, so the handler is at 0x20
        0x42, 0x79, 0x00, 0x04, 0x00, 0x00, // 0x20 CLR.W ($40000).L
        0x4e, 0x73, // 0x26 RTE
    ];
    let resolver = resolver(image(&code, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(
                SandboxRunArguments::new("game")
                    .at_origin(0x2_0000)
                    .with_maximum_steps(500),
            )
            .with_mapped_regions(vec![
                amiga_operations::MappedRegion {
                    address: 0x4_0000,
                    size: 16,
                },
                // Low memory, so the program can install its own vector.
                amiga_operations::MappedRegion {
                    address: 0,
                    size: 0x400,
                },
            ])
            .with_interrupts(vec![amiga_operations::ScheduledInterrupt {
                vector: Some(27),
                address: None,
                // After the install and after the flag is set: a schedule is a
                // statement about when, and delivering before the code being
                // waited on has run would be a different experiment.
                after_steps: Some(3),
                every_steps: None,
                deliveries: None,
                frame: None,
            }]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(
        record.returned,
        "the installed handler did not run: {:?}",
        record.stop
    );
    let [delivery] = record.interrupts_delivered.as_slice() else {
        panic!("expected one delivery: {:?}", record.interrupts_delivered);
    };
    assert_eq!(
        delivery.handler, 0x2_0020,
        "the vector table was not read at delivery"
    );
}

#[test]
fn a_vector_nothing_has_installed_delays_the_delivery_rather_than_faulting() {
    // Installing the vector is exactly what the initialization being run is
    // doing, so a vector still holding zero is a "not yet", not an error. The
    // routine here never installs one, and the run completes with no delivery
    // rather than jumping to address zero.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000)).with_interrupts(
                vec![amiga_operations::ScheduledInterrupt {
                    vector: Some(27),
                    address: None,
                    after_steps: Some(0),
                    every_steps: Some(1),
                    deliveries: None,
                    frame: None,
                }],
            ),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned, "{:?}", record.stop);
    assert_eq!(record.interrupts_total, 0);
}

#[test]
fn an_interrupt_names_its_handler_exactly_one_way() {
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    for interrupt in [
        amiga_operations::ScheduledInterrupt {
            vector: Some(27),
            address: Some(0x2_0000),
            after_steps: None,
            every_steps: None,
            deliveries: None,
            frame: None,
        },
        amiga_operations::ScheduledInterrupt {
            vector: None,
            address: None,
            after_steps: None,
            every_steps: None,
            deliveries: None,
            frame: None,
        },
        amiga_operations::ScheduledInterrupt {
            vector: Some(27),
            address: None,
            after_steps: None,
            every_steps: Some(0),
            deliveries: None,
            frame: None,
        },
    ] {
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
                two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000))
                    .with_interrupts(vec![interrupt]),
            )),
            &context,
        );
        assert_eq!(outcome.status, Status::Error, "accepted {interrupt:?}");
        assert_eq!(
            outcome.diagnostics[0].code,
            amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
        );
    }
}

#[test]
fn a_named_range_is_digested_in_the_record_rather_than_carried() {
    // Reconstructing a runtime framebuffer used to mean reapplying thousands of
    // recorded changes to the original image and then carving the range out. A
    // named range is an output of the recipe instead — digested here, written
    // by the export.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000))
                .with_memory_exports(vec![amiga_operations::MemoryExport {
                    address: 0x4_0000,
                    length: 8,
                    name: "table.bin".to_owned(),
                }]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    let [region] = record.exported_regions.as_slice() else {
        panic!(
            "expected one exported region: {:?}",
            record.exported_regions
        );
    };
    assert_eq!(region.name, "table.bin");
    assert_eq!(region.address, 0x4_0000);
    assert_eq!(region.length, 8);
    // The bytes the two stores left there, digested rather than spelled out.
    assert_eq!(
        region.sha256,
        amiga_core::sha256(&[0, 0, 0, 42, 0, 0, 0, 43])
    );
}

#[test]
fn a_named_range_outside_the_map_is_refused_rather_than_exported_short() {
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000))
                .with_memory_exports(vec![amiga_operations::MemoryExport {
                    // The mapped region is sixteen bytes; this asks for thirty-two.
                    address: 0x4_0000,
                    length: 32,
                    name: "table.bin".to_owned(),
                }]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::SandboxMemoryUnmappable
    );
}

#[test]
fn two_ranges_under_one_name_are_a_bad_request() {
    // One file would be written and the other silently lost.
    let resolver = resolver(image(&TWO_STORES, 64));
    let context = ExecutionContext::new(&resolver);
    for exports in [
        vec![
            amiga_operations::MemoryExport {
                address: 0x4_0000,
                length: 4,
                name: "same".to_owned(),
            },
            amiga_operations::MemoryExport {
                address: 0x4_0004,
                length: 4,
                name: "same".to_owned(),
            },
        ],
        vec![amiga_operations::MemoryExport {
            address: 0x4_0000,
            length: 4,
            name: "sub/dir".to_owned(),
        }],
        vec![amiga_operations::MemoryExport {
            address: 0x4_0000,
            length: 0,
            name: "empty".to_owned(),
        }],
    ] {
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
                two_store_call(SandboxRunArguments::new("game").at_origin(0x2_0000))
                    .with_memory_exports(exports.clone()),
            )),
            &context,
        );
        assert_eq!(outcome.status, Status::Error, "accepted {exports:?}");
        assert_eq!(
            outcome.diagnostics[0].code,
            amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
        );
    }
}

#[test]
fn a_malformed_memory_seed_is_a_bad_request_not_a_failed_run() {
    let resolver = resolver(image(&[0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(SandboxRunArguments::new("game"))
                .with_memory_seeds(vec![amiga_operations::MemorySeed::hex(0x4_0000, "nothex")]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.exit_code(),
        2,
        "a bad request has its own exit code"
    );
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
}

/// `MOVE.W #value,($DFFxxx).L` — the way a program pokes a chip register.
fn poke_register(code: &mut Vec<u8>, offset: u16, value: u16) {
    code.extend_from_slice(&[0x33, 0xfc]);
    code.extend_from_slice(&value.to_be_bytes());
    code.extend_from_slice(&(0x00df_f000_u32 + u32::from(offset)).to_be_bytes());
}

/// A routine that copies `words` words from `source` to `destination` with the
/// blitter's A channel, and returns.
fn blit_routine(source: u32, destination: u32, words: u16) -> Vec<u8> {
    let mut code = Vec::new();
    poke_register(&mut code, 0x040, 0x09f0); // BLTCON0: USEA | USED | copy A
    poke_register(&mut code, 0x042, 0x0000); // BLTCON1: ascending, no fill
    poke_register(&mut code, 0x044, 0xffff); // BLTAFWM
    poke_register(&mut code, 0x046, 0xffff); // BLTALWM
    poke_register(&mut code, 0x050, (source >> 16) as u16); // BLTAPTH
    poke_register(&mut code, 0x052, source as u16); // BLTAPTL
    poke_register(&mut code, 0x054, (destination >> 16) as u16); // BLTDPTH
    poke_register(&mut code, 0x056, destination as u16); // BLTDPTL
    poke_register(&mut code, 0x058, words); // BLTSIZE: `words` wide, one line
    code.extend_from_slice(&[0x4e, 0x75]); // RTS
    code
}

/// A `custom_chips` object naming a blitter configuration.
fn chips_with(blitter: amiga_operations::BlitterOptions) -> amiga_operations::CustomChips {
    amiga_operations::CustomChips {
        chipset: None,
        blitter: Some(blitter),
    }
}

fn call_with_chips(
    code: &[u8],
    chips: Option<amiga_operations::CustomChips>,
    regions: Vec<amiga_operations::MappedRegion>,
    seeds: Vec<amiga_operations::MemorySeed>,
) -> amiga_operations::OperationOutcome {
    let resolver = resolver(image(code, 256));
    let context = ExecutionContext::new(&resolver);
    let mut arguments = amiga_operations::SandboxCallArguments::new(
        SandboxRunArguments::new("game").at_origin(0x2_0000),
    )
    .with_mapped_regions(regions)
    .with_memory_seeds(seeds);
    arguments.custom_chips = chips;
    Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(arguments)),
        &context,
    )
}

#[test]
fn a_routine_that_drives_the_blitter_changes_memory() {
    let outcome = call_with_chips(
        &blit_routine(0x4_0000, 0x4_0010, 0x0042),
        Some(amiga_operations::CustomChips::default()),
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x100,
        }],
        vec![amiga_operations::MemorySeed {
            address: 0x4_0000,
            hex: Some("12345678".to_owned()),
            from: None,
            artifact: None,
        }],
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned);
    // The blit's words are in changed memory exactly as CPU writes would be,
    // which is the whole point: DMA marks memory dirty even though it never
    // enters the write log.
    assert!(
        record
            .changed_memory
            .iter()
            .any(|region| region.address == 0x4_0010 && region.hex.starts_with("12345678")),
        "the blitted words are missing: {:?}",
        record.changed_memory
    );
    assert_eq!(record.blits_total, 1);
    assert_eq!(record.attempted_blit_words_total, 2);
    assert_eq!(record.executed_blit_words_total, 2);
    let blit = &record.blits[0];
    assert_eq!((blit.width, blit.height), (2, 1));
    assert_eq!(blit.words_written, 2);
    assert_eq!(blit.refused, None);
    assert_eq!(blit.initial_pointers[0], 0x4_0000);
    assert_eq!(blit.final_pointers[0], 0x4_0004);
    // The record says what drew the pixels.
    let chips = record.custom_chips.as_ref().expect("the configuration");
    assert_eq!(chips.chipset, "ocs");
    assert_eq!(chips.blitter.mode, "emulate");
    assert_eq!(chips.blitter.dma.as_deref(), Some("assume_enabled"));
}

#[test]
fn without_custom_chips_the_same_routine_changes_nothing() {
    // The chip page is not modelled, so $DFF000 is unmapped and the first poke
    // faults. That is the behaviour this feature exists to replace, and pinning
    // it here is what makes the difference visible.
    let outcome = call_with_chips(
        &blit_routine(0x4_0000, 0x4_0010, 0x0042),
        None,
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x100,
        }],
        Vec::new(),
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.blits.is_empty());
    assert_eq!(record.blits_total, 0);
    assert!(record.custom_chips.is_none());
    assert!(
        !record
            .changed_memory
            .iter()
            .any(|region| region.address == 0x4_0010),
        "nothing should have reached the destination"
    );
}

#[test]
fn a_mapping_that_covers_the_chip_page_is_refused_when_the_chips_are_modelled() {
    let outcome = call_with_chips(
        &[0x4e, 0x75],
        Some(amiga_operations::CustomChips::default()),
        vec![amiga_operations::MappedRegion {
            address: 0x00df_f000,
            size: 0x200,
        }],
        Vec::new(),
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
}

#[test]
fn the_same_mapping_is_accepted_when_they_are_not() {
    // A recipe deliberately using that range as RAM has to keep working: the
    // check belongs to the request that asked for chips, not to the address.
    let outcome = call_with_chips(
        &[0x4e, 0x75],
        None,
        vec![amiga_operations::MappedRegion {
            address: 0x00df_f000,
            size: 0x200,
        }],
        Vec::new(),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
}

#[test]
fn a_run_that_exceeds_its_blit_budget_is_refused_and_says_so() {
    let chips = chips_with(amiga_operations::BlitterOptions {
        mode: None,
        dma: None,
        maximum_words: Some(1),
    });
    let outcome = call_with_chips(
        &blit_routine(0x4_0000, 0x4_0010, 0x0042),
        Some(chips),
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x100,
        }],
        Vec::new(),
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    let refusal = record.blits[0].refused.as_ref().expect("a refusal");
    assert_eq!(refusal.kind, "budget_exceeded");
    assert_eq!(record.executed_blit_words_total, 0);
    assert_eq!(
        record.attempted_blit_words_total, 2,
        "charged before the preflight, and not refunded"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == amiga_operations::DiagnosticCode::SandboxBlitterRefused),
        "a refused blit is a diagnostic, not just a row"
    );
}

#[test]
fn line_mode_is_reported_as_unsupported_rather_than_merely_refused() {
    let mut code = blit_routine(0x4_0000, 0x4_0010, 0x0042);
    // Patch BLTCON1 to set LINE. It is the second poke, and its immediate is at
    // offset 10: two opcode bytes, then the first poke's eight.
    code[10] = 0x00;
    code[11] = 0x01;
    let outcome = call_with_chips(
        &code,
        Some(amiga_operations::CustomChips::default()),
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x100,
        }],
        Vec::new(),
    );

    let record = outcome.env_sandbox_call().expect("a record");
    assert_eq!(
        record.blits[0].refused.as_ref().map(|r| r.kind.as_str()),
        Some("line_mode")
    );
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::SandboxBlitterUnsupported)
    );
}

#[test]
fn a_bltsizh_write_is_unsupported_while_bltsizv_stays_a_quiet_observation() {
    // On ECS BLTSIZH starts a blit; on the OCS blitter this build models it
    // changes nothing, so the blits it would have started are simply missing.
    // BLTSIZV starts nothing on either chipset, so it is observed and no more.
    for (register, expect_diagnostic) in [(0x05c_u16, false), (0x05e, true)] {
        let mut code = Vec::new();
        poke_register(&mut code, 0x040, 0x09f0);
        poke_register(&mut code, register, 0x0020);
        poke_register(&mut code, register, 0x0020);
        code.extend_from_slice(&[0x4e, 0x75]);

        let outcome = call_with_chips(
            &code,
            Some(amiga_operations::CustomChips::default()),
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
        let record = outcome.env_sandbox_call().expect("a record");
        assert_eq!(record.blits_total, 0, "neither register starts a blit here");
        let observation = record
            .chip_observations
            .iter()
            .find(|observation| observation.register == Some(register))
            .unwrap_or_else(|| panic!("{register:#05x} observed"));
        assert_eq!(observation.kind, "ecs_register_written");
        assert_eq!(observation.occurrences, 2, "aggregated, not accumulated");

        let unsupported: Vec<_> = outcome
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == amiga_operations::DiagnosticCode::SandboxBlitterUnsupported
            })
            .collect();
        assert_eq!(
            unsupported.len(),
            usize::from(expect_diagnostic),
            "{register:#05x}: {:?}",
            outcome.diagnostics
        );
        if let Some(diagnostic) = unsupported.first() {
            assert!(
                diagnostic.message.contains("BLTSIZH"),
                "{}",
                diagnostic.message
            );
            assert_eq!(
                diagnostic.json_path.as_deref(),
                Some("$.result.chip_observations")
            );
        }
    }
}

#[test]
fn an_assumed_dma_policy_is_reported_from_a_blit_past_the_row_cap() {
    // The row cap bounds what a record shows, not what the run did. A program
    // that blits with DMA on and then disables it changed memory under the
    // assumption, and deriving the diagnostic from the retained rows would drop
    // exactly that case.
    let mut code = Vec::new();
    poke_register(&mut code, 0x096, 0x8240); // DMACON: set DMAEN | BLTEN
    poke_register(&mut code, 0x040, 0x0100); // BLTCON0: USED, clear
    poke_register(&mut code, 0x042, 0x0000);
    poke_register(&mut code, 0x054, 0x0004); // BLTDPTH
    poke_register(&mut code, 0x056, 0x0000); // BLTDPTL: $40000
    code.extend_from_slice(&[0x30, 0x3c, 0x01, 0x2b]); // MOVE.W #299,D0
    let loop_start = code.len();
    poke_register(&mut code, 0x058, 0x0041); // BLTSIZE: one word, one line
    code.extend_from_slice(&[0x51, 0xc8]); // DBF D0,loop_start
    // The displacement is relative to the extension word, which is what the
    // next two bytes are: the whole distance back from here to the loop head.
    let displacement = -((code.len() - loop_start) as i16);
    code.extend_from_slice(&displacement.to_be_bytes());
    poke_register(&mut code, 0x096, 0x0040); // DMACON: clear BLTEN
    poke_register(&mut code, 0x058, 0x0041); // one more, now assumed
    code.extend_from_slice(&[0x4e, 0x75]);

    let outcome = call_with_chips(
        &code,
        Some(amiga_operations::CustomChips::default()),
        // The D pointer advances a word per blit and is never re-pointed, so the
        // region has to hold all 301 of them.
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x1000,
        }],
        Vec::new(),
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert_eq!(record.blits_total, 301);
    assert!(
        record.blits.iter().all(|blit| blit.refused.is_none()),
        "every blit here runs; the cap is what this test is about"
    );
    assert_eq!(record.blits.len(), 256, "rows are capped");
    assert!(
        !record.blits.iter().any(|blit| blit.dma_assumed),
        "every retained row ran with DMA enabled"
    );
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::SandboxBlitterDmaAssumed),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn a_blit_budget_of_zero_is_a_request_error_rather_than_a_run_of_refusals() {
    // Both call request schemas declare `minimum: 1`. Accepting zero would let a
    // typed caller run a request a JSON caller cannot write, and the run it
    // produces reports every blit as budget-exceeded — which reads as a program
    // whose blits were too large rather than as a request that asked for none.
    let outcome = call_with_chips(
        &blit_routine(0x4_0000, 0x4_0010, 0x0042),
        Some(chips_with(amiga_operations::BlitterOptions {
            mode: None,
            dma: None,
            maximum_words: Some(0),
        })),
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x100,
        }],
        Vec::new(),
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.exit_code(),
        2,
        "a bad request has its own exit code"
    );
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
    assert_eq!(
        outcome.diagnostics[0].json_path.as_deref(),
        Some("$.request.arguments.custom_chips.blitter.maximum_words")
    );
}

#[test]
fn two_requests_differing_only_in_the_dma_policy_digest_differently() {
    let digest = |dma| {
        let chips = chips_with(amiga_operations::BlitterOptions {
            mode: None,
            dma: Some(dma),
            maximum_words: None,
        });
        call_with_chips(&[0x4e, 0x75], Some(chips), Vec::new(), Vec::new())
            .normalized_request_sha256
            .expect("a digest")
    };
    assert_ne!(
        digest(amiga_operations::BlitterDma::AssumeEnabled),
        digest(amiga_operations::BlitterDma::RequireEnabled),
        "the policy changes what runs, so it must change the digest"
    );
}

#[test]
fn two_shadow_requests_differing_only_in_the_dma_policy_digest_the_same() {
    // Under shadow mode the policy does nothing, and redundancy is not
    // contradiction: two recipes that describe the same run must not be told
    // they are different runs.
    let digest = |dma| {
        let chips = chips_with(amiga_operations::BlitterOptions {
            mode: Some(amiga_operations::BlitterMode::Shadow),
            dma: Some(dma),
            maximum_words: Some(1234),
        });
        call_with_chips(&[0x4e, 0x75], Some(chips), Vec::new(), Vec::new())
            .normalized_request_sha256
            .expect("a digest")
    };
    assert_eq!(
        digest(amiga_operations::BlitterDma::AssumeEnabled),
        digest(amiga_operations::BlitterDma::RequireEnabled)
    );
}

#[test]
fn an_empty_custom_chips_object_means_the_emulating_defaults() {
    // One request spelled two ways must not mean two things.
    let spelled_out = amiga_operations::CustomChips {
        chipset: Some(amiga_operations::Chipset::Ocs),
        blitter: Some(amiga_operations::BlitterOptions {
            mode: Some(amiga_operations::BlitterMode::Emulate),
            dma: Some(amiga_operations::BlitterDma::AssumeEnabled),
            maximum_words: None,
        }),
    };
    let empty = amiga_operations::CustomChips::default();
    assert_eq!(
        call_with_chips(&[0x4e, 0x75], Some(empty), Vec::new(), Vec::new())
            .normalized_request_sha256,
        call_with_chips(&[0x4e, 0x75], Some(spelled_out), Vec::new(), Vec::new())
            .normalized_request_sha256
    );
}

#[test]
fn shadow_mode_reports_no_policy_it_did_not_apply() {
    let chips = chips_with(amiga_operations::BlitterOptions {
        mode: Some(amiga_operations::BlitterMode::Shadow),
        dma: Some(amiga_operations::BlitterDma::RequireEnabled),
        maximum_words: Some(99),
    });
    let outcome = call_with_chips(
        &blit_routine(0x4_0000, 0x4_0010, 0x0042),
        Some(chips),
        vec![amiga_operations::MappedRegion {
            address: 0x4_0000,
            size: 0x100,
        }],
        vec![amiga_operations::MemorySeed {
            address: 0x4_0000,
            hex: Some("12345678".to_owned()),
            from: None,
            artifact: None,
        }],
    );

    let record = outcome.env_sandbox_call().expect("a record");
    let chips = record.custom_chips.as_ref().expect("the configuration");
    assert_eq!(chips.blitter.mode, "shadow");
    assert_eq!(chips.blitter.dma, None);
    assert_eq!(chips.blitter.maximum_words, None);
    // The registers took the writes and nothing blitted.
    assert_eq!(record.blits_total, 0);
    assert!(
        !record
            .changed_memory
            .iter()
            .any(|region| region.address == 0x4_0010),
        "shadow mode performs no blits"
    );
}

#[test]
fn a_call_with_no_chips_digests_exactly_as_it_did_before() {
    // `call` now always runs over a DeviceBus. A recipe that asks for no chips
    // must be byte-for-byte the run it always got, digest included.
    let outcome = call_with_chips(&[0x4e, 0x75], None, Vec::new(), Vec::new());
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.custom_chips.is_none());
    assert!(record.returned);
    assert_eq!(record.blits_total, 0);
}

/// Where the two relocation tests below map the CODE hunk.
const ORIGIN: u32 = 0x0002_0000;
/// Where the first of them maps the BSS hunk the relocation targets.
const BSS_BASE: u32 = 0x0004_0000;

/// A two-hunk executable whose CODE hunk carries one `HUNK_RELOC32` record
/// into the BSS hunk, with the addend `0xfffffffe`.
///
/// `MOVE.L (ORIGIN+8).L,D0 ; RTS ; DC.L $fffffffe` — the last longword is the
/// relocation site, so what D0 ends up holding is what the loader wrote there.
fn relocating_image() -> Vec<u8> {
    let mut code = vec![0x20, 0x39];
    code.extend_from_slice(&(ORIGIN + 8).to_be_bytes());
    code.extend_from_slice(&[0x4e, 0x75]);
    code.extend_from_slice(&0xffff_fffe_u32.to_be_bytes());

    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 2, 0, 1, 64, 64] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&(code.len() as u32 / 4).to_be_bytes());
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&0x0000_03ec_u32.to_be_bytes()); // HUNK_RELOC32
    for value in [1_u32, 1, 8, 0] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes.extend_from_slice(&0x0000_03eb_u32.to_be_bytes()); // HUNK_BSS
    bytes.extend_from_slice(&64_u32.to_be_bytes());
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// A relocation refused for want of a base names the record it is about.
///
/// The sibling diagnostics in `relocate` used to name no offsets at all — "a
/// relocation site address overflows" said neither the hunk, the record, nor
/// the addend — so a user could not tell a wrong `--hunk-base` from an odd
/// image. This is the one of them a synthetic fixture can reach, and it holds
/// the shape the other three share: the record's index, its source hunk, the
/// offset inside that hunk, and the base that offset was added to.
#[test]
fn a_relocation_refused_for_want_of_a_base_names_the_record() {
    let resolver = resolver(relocating_image());
    let context = ExecutionContext::new(&resolver);
    // No `hunk_bases` entry for hunk 1, so the record's target is unmapped.
    let run = SandboxRunArguments::new("game").at_origin(ORIGIN);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(run),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    let message = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(message.contains("relocation 0"), "{message}");
    assert!(message.contains("hunk 0"), "{message}");
    assert!(message.contains("offset 0x8"), "{message}");
    assert!(
        message.contains(&format!("base {ORIGIN:#x}")),
        "the base is what a wrong --hunk-base shows up in: {message}"
    );
    assert!(message.contains("hunk_bases"), "{message}");
}

/// A relocation addend below its hunk's base resolves to an address below the
/// hunk, as `LoadSeg` resolves it.
///
/// The addend is a longword the loader *adds* to the hunk base in 32-bit
/// wrapping arithmetic, so `0xFFFFFFFE` means "two bytes below this hunk" and
/// is a shape real images use. Resolving it with `checked_add` refused the whole
/// executable — for every non-zero base, since the sum overflows `u32` — so an
/// image carrying one record like this could not be run at any layout at all.
/// Measured on a real game whose BSS hunk carries exactly one.
///
/// This is the one place in the crate where `checked_*` is the wrong operation.
/// What bounds the result is the memory bus, which maps the address or faults;
/// arithmetic that disagrees with the loader would not be a bound, it would be
/// a different program.
#[test]
fn a_relocation_addend_below_its_hunk_resolves_below_it_rather_than_overflowing() {
    let resolver = resolver(relocating_image());
    let context = ExecutionContext::new(&resolver);
    let mut run = SandboxRunArguments::new("game").at_origin(ORIGIN);
    run.hunk_bases.push(amiga_operations::HunkBase {
        hunk: 1,
        address: BSS_BASE,
    });
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
            amiga_operations::SandboxCallArguments::new(run),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned, "stopped at {:?}", record.stop);
    assert_eq!(
        record.outputs.d[0],
        BSS_BASE - 2,
        "the addend must be added to the base the way the loader adds it"
    );
}

#[test]
fn boot_trace_follows_a_guest_installed_trap_handler() {
    let mut block = vec![0_u8; 1024];
    block[..4].copy_from_slice(b"DOS\0");
    // MOVE.L #$1040,$80 ; TRAP #0 ; RTS
    block[12..26].copy_from_slice(&[
        0x23, 0xfc, 0, 0, 0x10, 0x40, 0, 0, 0, 0x80, 0x4e, 0x40, 0x4e, 0x75,
    ]);
    // MOVEQ #42,D0 ; RTE
    block[0x40..0x44].copy_from_slice(&[0x70, 42, 0x4e, 0x73]);
    let resolver = resolver(block);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvBootTrace(
            amiga_operations::BootTraceArguments::new("game"),
        )),
        &ExecutionContext::new(&resolver),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.env_boot_trace().unwrap();
    assert_eq!(result.stop, amiga_operations::SandboxStop::Returned);
    assert_eq!(result.steps_executed, 5);
}

#[test]
fn every_execution_mode_preflights_the_complete_ram_map() {
    use amiga_operations::{
        DiagnosticCode, HunkBase, MappedRegion, OperationLimits, SandboxCallArguments,
        SandboxMatrixArguments, SandboxMatrixCase, SandboxTimelineArguments, StackRegion,
        TimelineStep,
    };
    for scenario in ["bss", "stack", "region", "aggregate"] {
        let bytes = if scenario == "bss" {
            code_and_bss(&[0x4e, 0x75], 4, 256 * 1024 * 1024)
        } else {
            image(&[0x4e, 0x75], 1)
        };
        let resolver = resolver(bytes);
        let context = ExecutionContext::new(&resolver)
            .with_limits(OperationLimits::default().with_maximum_sandbox_memory_bytes(1024));
        let mut run = SandboxRunArguments::new("game")
            .at_origin(0x20000)
            .with_maximum_steps(4);
        run.stack = Some(StackRegion {
            base: 0x100000,
            size: if scenario == "stack" { 2048 } else { 64 },
        });
        if scenario == "bss" {
            run.hunk = Some(0);
            run.hunk_bases = vec![HunkBase {
                hunk: 1,
                address: 0x200000,
            }];
        }
        let mut call = SandboxCallArguments::new(run.clone());
        call.mapped_regions = match scenario {
            "region" => vec![MappedRegion {
                address: 0x30000,
                size: 256 * 1024 * 1024,
            }],
            "aggregate" => (0..3)
                .map(|i| MappedRegion {
                    address: 0x30000 + i * 0x1000,
                    size: 400,
                })
                .collect(),
            _ => vec![],
        };
        let mut requests = vec![
            OperationRequestDocument::EnvSandboxCall(call.clone()),
            OperationRequestDocument::EnvSandboxTimeline(SandboxTimelineArguments::new(
                call.clone(),
                vec![TimelineStep::call("first", 0)],
            )),
            OperationRequestDocument::EnvSandboxMatrix(SandboxMatrixArguments::new(
                call,
                vec![SandboxMatrixCase::new("first")],
            )),
        ];
        if matches!(scenario, "bss" | "stack") {
            requests.push(OperationRequestDocument::EnvSandboxRun(run));
        }
        for request in requests {
            let outcome = Router::execute(&RequestEnvelope::read(request), &context);
            if let Some(matrix) = outcome.env_sandbox_matrix() {
                assert_eq!(matrix.cases_refused, 1, "{scenario}: {matrix:?}");
                assert_eq!(matrix.steps_executed_total, 0);
                assert_eq!(
                    matrix.cases[0].diagnostics[0].code,
                    DiagnosticCode::SandboxMemoryUnmappable
                );
                assert!(
                    matrix.cases[0].diagnostics[0]
                        .message
                        .contains("before allocation")
                );
            } else {
                assert_eq!(outcome.status, Status::Error, "{scenario}: {outcome:?}");
                assert_eq!(
                    outcome.diagnostics[0].code,
                    DiagnosticCode::SandboxMemoryUnmappable
                );
                assert!(outcome.diagnostics[0].message.contains("before allocation"));
            }
        }
    }
}

#[test]
fn exact_ram_budget_accepts_code_stack_and_additional_regions() {
    use amiga_operations::{MappedRegion, OperationLimits, SandboxCallArguments, StackRegion};
    let resolver = resolver(image(&[0x4e, 0x75], 1));
    let context = ExecutionContext::new(&resolver)
        .with_limits(OperationLimits::default().with_maximum_sandbox_memory_bytes(100));
    let mut run = SandboxRunArguments::new("game");
    run.stack = Some(StackRegion {
        base: 0x100000,
        size: 64,
    });
    let call = SandboxCallArguments::new(run).with_mapped_regions(vec![MappedRegion {
        address: 0x30000,
        size: 32,
    }]);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(call)),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{outcome:?}");
    assert!(outcome.env_sandbox_call().unwrap().returned);
}
