//! `env.sandbox.timeline`: one machine, and a sequence of steps that evolve it.
//!
//! The properties under test are the ones that make a timeline different from a
//! matrix, which is the operation it most resembles. A matrix's cases are
//! deliberately independent, each starting from the same state; a timeline's
//! steps share one machine, so what step *n+1* sees is what step *n* left. Every
//! test here is about that carrying-over, or about what the toolkit refuses to
//! do when it cannot be honoured.

use std::sync::Arc;

use amiga_operations::{
    CustomChips, ExecutionContext, InMemorySourceResolver, InterruptFrame, MappedRegion,
    MemoryExport, OperationRequestDocument, RequestEnvelope, ResolvedSource, Router,
    SandboxCallArguments, SandboxRunArguments, SandboxTimelineArguments,
    SandboxTimelineExportArguments, SandboxTimelineResult, ScheduledInterrupt, SourceLocator,
    SourceName, Status, TimelineStep, TimelineStepOutcome,
};

/// A one-hunk LoadSeg image whose CODE hunk holds `code`.
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

fn resolver(code: &[u8]) -> InMemorySourceResolver {
    let name = SourceName::parse("game").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(image(code, 64))))
}

/// Where the counter this suite ticks lives, inside a region the recipe maps.
const COUNTER: u32 = 0x0004_0000;

/// `ADDQ.W #1,($30000).L ; RTS` — a tick whose only effect is on memory that
/// outlives it, which is the smallest routine a timeline can say anything about.
fn ticker() -> InMemorySourceResolver {
    resolver(&[0x52, 0x79, 0x00, 0x04, 0x00, 0x00, 0x4e, 0x75])
}

fn base() -> SandboxCallArguments {
    SandboxCallArguments::new(
        SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64),
    )
    .with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: COUNTER,
        size: 0x100,
    }])
}

fn counter_checkpoint(name: &str) -> MemoryExport {
    MemoryExport {
        address: COUNTER,
        length: 2,
        name: name.to_owned(),
    }
}

#[test]
fn a_structured_timeline_round_trips_all_flattened_run_arguments() {
    let call = SandboxCallArguments::new(SandboxRunArguments::new("game"))
        .with_mapped_regions(vec![MappedRegion {
            address: COUNTER,
            size: 0x100,
        }])
        .with_interrupts(vec![ScheduledInterrupt {
            vector: None,
            address: Some(0x2_0020),
            after_steps: Some(3),
            every_steps: Some(1_000),
            deliveries: Some(2),
            frame: Some(InterruptFrame::Rts),
        }])
        .with_custom_chips(CustomChips::default());
    let envelope = RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimeline(
        SandboxTimelineArguments::new(call, vec![TimelineStep::call("tick", 0)]),
    ));

    let mut document = serde_json::to_value(envelope).expect("the request serializes");
    let parsed: RequestEnvelope =
        serde_json::from_value(document.clone()).expect("the serialized request parses");
    let OperationRequestDocument::EnvSandboxTimeline(timeline) = parsed.request else {
        panic!("the request changed operation while parsing");
    };
    let SourceLocator::File { path } = timeline.base.run.source else {
        panic!("the timeline source changed locator kind");
    };
    assert_eq!(path, "game");
    assert_eq!(timeline.base.mapped_regions.len(), 1);
    assert!(timeline.base.custom_chips.is_some());
    assert_eq!(timeline.base.interrupts[0].frame, Some(InterruptFrame::Rts));

    document["request"]["arguments"]["not_a_timeline_field"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<RequestEnvelope>(document).is_err(),
        "flattening accepted a field no timeline argument owns"
    );
}

#[test]
fn a_structured_timeline_export_round_trips_its_nested_flattened_arguments() {
    let timeline = SandboxTimelineArguments::new(
        SandboxCallArguments::new(SandboxRunArguments::new("game")),
        vec![TimelineStep::call("tick", 0)],
    );
    let envelope = RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimelineExport(
        SandboxTimelineExportArguments::new(timeline, "checkpoints"),
    ));

    let mut document = serde_json::to_value(envelope).expect("the request serializes");
    let parsed: RequestEnvelope =
        serde_json::from_value(document.clone()).expect("the serialized request parses");
    let OperationRequestDocument::EnvSandboxTimelineExport(export) = parsed.request else {
        panic!("the request changed operation while parsing");
    };
    let SourceLocator::File { path } = export.timeline.base.run.source else {
        panic!("the timeline source changed locator kind");
    };
    assert_eq!(path, "game");
    assert_eq!(export.destination, "checkpoints");

    document["request"]["arguments"]["not_an_export_field"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<RequestEnvelope>(document).is_err(),
        "flattening accepted a field no timeline export argument owns"
    );
}

#[test]
fn a_structured_timeline_delivers_a_fixed_rts_handler_with_a_subroutine_frame() {
    //   entry:   MOVE.W #1,($40000).L
    //   wait:    TST.W ($40000).L ; BNE.S wait ; RTS
    //   handler: CLR.W ($40000).L ; RTS
    let code = [
        0x33, 0xfc, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, // 0x00 MOVE.W #1,($40000).L
        0x4a, 0x79, 0x00, 0x04, 0x00, 0x00, // 0x08 TST.W ($40000).L
        0x66, 0xf8, // 0x0e BNE.S wait
        0x4e, 0x75, // 0x10 RTS
        0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e,
        0x71, // 0x12 padding, so the handler is at 0x20
        0x42, 0x79, 0x00, 0x04, 0x00, 0x00, // 0x20 CLR.W ($40000).L
        0x4e, 0x75, // 0x26 RTS
    ];
    let resolver = resolver(&code);
    let context = ExecutionContext::new(&resolver);
    let call = SandboxCallArguments::new(
        SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(500),
    )
    .with_mapped_regions(vec![MappedRegion {
        address: COUNTER,
        size: 0x100,
    }])
    .with_interrupts(vec![ScheduledInterrupt {
        vector: None,
        address: Some(0x2_0020),
        after_steps: Some(3),
        every_steps: None,
        deliveries: None,
        frame: Some(InterruptFrame::Rts),
    }]);
    let envelope = RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimeline(
        SandboxTimelineArguments::new(
            call,
            vec![
                TimelineStep::call("initialize", 0)
                    .with_checkpoints(vec![counter_checkpoint("wait-flag")]),
            ],
        ),
    ));
    let document = serde_json::to_value(envelope).expect("the request serializes");
    let parsed: RequestEnvelope =
        serde_json::from_value(document).expect("the serialized request parses");

    let outcome = Router::execute(&parsed, &context);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome.env_sandbox_timeline().expect("a timeline result");
    assert_eq!(result.steps_ran, 1);
    assert!(
        result.steps[0].returned,
        "the RTS handler did not return to and release the waiting routine: {:?}",
        result.steps[0].stop
    );
    assert_eq!(
        result.steps[0].checkpoints[0].sha256,
        amiga_core::sha256(&0_u16.to_be_bytes()),
        "the RTS handler did not clear the wait flag"
    );
    assert_eq!(result.interrupts_total, 1);
    assert!(!result.interrupts_truncated);
    let [delivery] = result.steps[0].interrupts_delivered.as_slice() else {
        panic!(
            "the delivery was not attributed to its step: {:?}",
            result.steps[0].interrupts_delivered
        );
    };
    assert_eq!(result.steps[0].interrupts_total, 1);
    assert!(!result.steps[0].interrupts_truncated);
    assert_eq!(delivery.index, 0);
    assert_eq!(delivery.handler, 0x2_0020);
    assert_eq!(delivery.resume, 0x2_000e);
}

#[test]
fn interrupt_deliveries_keep_global_order_and_are_reported_once_per_step() {
    // main: ADDQ.W #1,($40000).L ; RTS
    // handler at +0x20: RTS
    let mut code = vec![0x52, 0x79, 0x00, 0x04, 0x00, 0x00, 0x4e, 0x75];
    code.resize(0x20, 0x4e);
    code.extend_from_slice(&[0x4e, 0x75]);
    let resolver = resolver(&code);
    let context = ExecutionContext::new(&resolver);
    let recipe = base().with_interrupts(vec![ScheduledInterrupt {
        vector: None,
        address: Some(0x2_0020),
        after_steps: Some(1),
        every_steps: Some(4),
        deliveries: Some(2),
        frame: Some(InterruptFrame::Rts),
    }]);
    let result = run(
        SandboxTimelineArguments::new(
            recipe,
            vec![
                TimelineStep::call("first", 0),
                TimelineStep::call("second", 0),
            ],
        )
        .with_maximum_total_steps(256),
        &context,
    );

    assert_eq!(result.interrupts_total, 2);
    assert!(!result.interrupts_truncated);
    for step in &result.steps {
        assert_eq!(step.interrupts_total, 1, "{}", step.name);
        assert_eq!(step.interrupts_delivered.len(), 1, "{}", step.name);
        assert!(!step.interrupts_truncated, "{}", step.name);
    }
    let first = result.steps[0].interrupts_delivered[0];
    let second = result.steps[1].interrupts_delivered[0];
    assert_eq!((first.index, second.index), (0, 0));
    assert_eq!((first.step, second.step), (1, 5));
    assert_eq!((first.handler, second.handler), (0x2_0020, 0x2_0020));
    assert_eq!((first.resume, second.resume), (0x2_0000, 0x2_0006));
}

#[test]
fn the_timeline_delivery_cap_is_shared_and_each_step_keeps_its_true_total() {
    // Main is NOP; RTS and the handler is RTS. A delivery every two global
    // instructions produces more than the shared response cap across 256 calls.
    let mut code = vec![0x4e, 0x71, 0x4e, 0x75];
    code.resize(0x20, 0x4e);
    code.extend_from_slice(&[0x4e, 0x75]);
    let resolver = resolver(&code);
    let context = ExecutionContext::new(&resolver);
    let recipe = base().with_interrupts(vec![ScheduledInterrupt {
        vector: None,
        address: Some(0x2_0020),
        after_steps: Some(1),
        every_steps: Some(2),
        deliveries: Some(512),
        frame: Some(InterruptFrame::Rts),
    }]);
    let steps = (0..256)
        .map(|index| TimelineStep::call(format!("step-{index}"), 0))
        .collect();
    let result = run(
        SandboxTimelineArguments::new(recipe, steps).with_maximum_total_steps(1_024),
        &context,
    );

    assert!(result.interrupts_total > 256);
    assert!(result.interrupts_truncated);
    assert_eq!(
        result
            .steps
            .iter()
            .map(|step| step.interrupts_total)
            .sum::<u64>(),
        result.interrupts_total
    );
    assert_eq!(
        result
            .steps
            .iter()
            .map(|step| step.interrupts_delivered.len())
            .sum::<usize>(),
        256
    );
    assert!(result.steps.iter().all(|step| {
        step.interrupts_truncated
            == (step.interrupts_total > step.interrupts_delivered.len() as u64)
    }));
    assert!(result.steps.iter().any(|step| step.interrupts_truncated));
}

fn run(
    timeline: SandboxTimelineArguments,
    context: &ExecutionContext<'_>,
) -> SandboxTimelineResult {
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimeline(timeline)),
        context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome
        .env_sandbox_timeline()
        .expect("a timeline result")
        .clone()
}

fn refusal(timeline: SandboxTimelineArguments, context: &ExecutionContext<'_>) -> Vec<String> {
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimeline(timeline)),
        context,
    );
    assert_eq!(outcome.status, Status::Error);
    outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect()
}

/// The whole point: step *n+1* runs on the memory step *n* produced.
///
/// Three calls to a routine that increments one word leave three, not one. A
/// matrix of the same three cases would leave one three times over, and that
/// difference is the operation's reason to exist.
#[test]
fn each_step_runs_on_the_memory_the_previous_one_left() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxTimelineArguments::new(
            base(),
            vec![
                TimelineStep::call("tick-1", 0).with_checkpoints(vec![counter_checkpoint("count")]),
                TimelineStep::call("tick-2", 0).with_checkpoints(vec![counter_checkpoint("count")]),
                TimelineStep::call("tick-3", 0).with_checkpoints(vec![counter_checkpoint("count")]),
            ],
        )
        .with_maximum_total_steps(256),
        &context,
    );

    assert_eq!(result.steps_total, 3);
    assert_eq!(result.steps_ran, 3);
    assert_eq!(result.steps_refused, 0);
    assert_eq!(result.steps_not_run, 0);
    assert!(!result.budget_exhausted);
    let names: Vec<&str> = result.steps.iter().map(|step| step.name.as_str()).collect();
    assert_eq!(names, ["tick-1", "tick-2", "tick-3"]);

    // One, two, three — read from the checkpoint digests, so the assertion is
    // over what the result actually publishes rather than over internals.
    let digest_of = |value: u16| amiga_core::sha256(&value.to_be_bytes());
    for (index, expected) in [1_u16, 2, 3].into_iter().enumerate() {
        let checkpoint = &result.steps[index].checkpoints[0];
        assert_eq!(checkpoint.name, "count");
        assert_eq!(
            checkpoint.sha256,
            digest_of(expected),
            "step {index} should have left {expected}"
        );
    }
    // And the shared exports describe the machine the whole timeline left.
    assert!(result.final_exports.is_empty());
}

/// A step's seeds are inputs, not effects.
///
/// They are applied before the step's own baseline is taken, so what the step
/// reports as changed memory is what its execution did. A seed that appeared in
/// the changed regions would make a reviewed input read as an output of the
/// routine — which is exactly the confusion `env.sandbox.compare` exists to
/// prevent one level up.
#[test]
fn a_step_s_seeds_are_reported_as_inputs_and_not_as_what_it_changed() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxTimelineArguments::new(
            base(),
            vec![
                TimelineStep::call("tick", 0),
                TimelineStep::call("reset-then-tick", 0)
                    .with_memory_seeds(vec![amiga_operations::MemorySeed::hex(COUNTER, "00ff")])
                    .with_checkpoints(vec![counter_checkpoint("count")]),
            ],
        )
        .with_maximum_total_steps(256),
        &context,
    );

    let seeded = &result.steps[1];
    assert_eq!(seeded.memory_seeds.len(), 1);
    assert_eq!(seeded.memory_seeds[0].address, COUNTER);
    assert_eq!(seeded.memory_seeds[0].hex, "00ff");
    // The routine turned 0x00ff into 0x0100, and that one word is the whole of
    // what this step changed: the seed itself is not in the diff.
    assert_eq!(
        seeded.checkpoints[0].sha256,
        amiga_core::sha256(&0x0100_u16.to_be_bytes())
    );
    assert_eq!(seeded.changed_regions_total, 1);
    assert_eq!(seeded.changed_regions[0].address, COUNTER);
    assert_eq!(seeded.changed_regions[0].length, 2);
}

/// A step can stop mid-routine and the next one continues from exactly there.
///
/// The stop is a breakpoint, and the resumed step's `entry` is the address the
/// previous step stopped at — so the two rows read as one execution split in
/// two, which is what "continue execution" has to mean.
#[test]
fn a_step_stops_at_an_address_and_the_next_one_continues_from_it() {
    // MOVEQ #1,D0 ; MOVEQ #2,D1 ; ADD.W D1,D0 ; RTS
    let resolver = resolver(&[0x70, 0x01, 0x72, 0x02, 0xd0, 0x41, 0x4e, 0x75]);
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxTimelineArguments::new(
            base(),
            vec![
                // Stop at the ADD, which has not executed.
                TimelineStep::call("to-the-add", 0).stopping_at(vec![0x2_0004]),
                TimelineStep::resume("the-rest"),
            ],
        )
        .with_maximum_total_steps(256),
        &context,
    );

    assert_eq!(result.steps_ran, 2);
    let first = &result.steps[0];
    assert!(!first.resumed);
    assert_eq!(
        first.stop,
        Some(amiga_operations::SandboxStop::Breakpoint { site: 0x2_0004 })
    );
    assert!(!first.returned);
    // D1 is already loaded and D0 is not yet the sum: the breakpoint's
    // instruction has not run.
    let paused = first.outputs.expect("a step that ran has outputs");
    assert_eq!(paused.d[0], 1);
    assert_eq!(paused.d[1], 2);

    let second = &result.steps[1];
    assert!(second.resumed);
    assert_eq!(second.entry, Some(0x2_0004));
    assert!(second.returned);
    assert_eq!(
        second.outputs.expect("outputs").d[0],
        3,
        "the resumed half executed the ADD it had stopped in front of"
    );
    assert_eq!(result.final_registers.expect("final registers").d[0], 3);
}

/// A breakpoint at the address a step resumes from does not stop it again.
///
/// Without the rule a stepping timeline could never make progress: the resumed
/// step would stop having executed nothing, and every step after it would do the
/// same. The suppression lasts only while the program counter is still there,
/// which the second half of this asserts — the loop comes back and does stop.
#[test]
fn a_breakpoint_the_step_starts_on_does_not_stop_it_before_it_has_run() {
    // 0: SUBQ.W #1,D0 ; 2: BNE.S 0 ; 4: RTS
    let resolver = resolver(&[0x53, 0x40, 0x66, 0xfc, 0x4e, 0x75]);
    let context = ExecutionContext::new(&resolver);
    let mut recipe = base();
    recipe.run.data_registers = Some([3, 0, 0, 0, 0, 0, 0, 0]);
    let result = run(
        SandboxTimelineArguments::new(
            recipe,
            vec![
                TimelineStep::call("first-lap", 0).stopping_at(vec![0x2_0000]),
                TimelineStep::resume("second-lap").stopping_at(vec![0x2_0000]),
                TimelineStep::resume("to-the-end"),
            ],
        )
        .with_maximum_total_steps(256),
        &context,
    );

    assert_eq!(result.steps_ran, 3);
    // The first step starts at the breakpoint, runs a whole lap, and stops when
    // the loop comes back to it.
    assert_eq!(result.steps[0].steps_executed, 2);
    assert_eq!(
        result.steps[0].stop,
        Some(amiga_operations::SandboxStop::Breakpoint { site: 0x2_0000 })
    );
    // The second resumes *on* that breakpoint and makes progress rather than
    // stopping immediately with nothing executed.
    assert_eq!(result.steps[1].steps_executed, 2);
    assert!(result.steps[2].returned);
}

/// A resume after a routine returned is refused, and the timeline stops there.
///
/// The machine is sitting on the return marker, which is deliberately unmapped:
/// continuing would fault on the first fetch and report a fault in the program
/// rather than a mistake in the request. And a timeline does not run on past a
/// refusal, because every step after it would run against a machine the request
/// never described.
#[test]
fn a_resume_after_a_return_is_refused_and_nothing_after_it_runs() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimeline(
            SandboxTimelineArguments::new(
                base(),
                vec![
                    TimelineStep::call("tick", 0),
                    TimelineStep::resume("continue"),
                    TimelineStep::call("never", 0),
                ],
            )
            .with_maximum_total_steps(256),
        )),
        &context,
    );
    let result = outcome
        .env_sandbox_timeline()
        .expect("a refused step still returns the result that names it");

    assert_eq!(result.steps_ran, 1);
    assert_eq!(result.steps_refused, 1);
    assert_eq!(result.steps_not_run, 1);
    assert_eq!(result.steps[0].outcome, TimelineStepOutcome::Ran);
    assert_eq!(result.steps[1].outcome, TimelineStepOutcome::Refused);
    assert!(
        result.steps[1].diagnostics[0]
            .message
            .contains("return marker")
    );
    assert_eq!(result.steps[2].outcome, TimelineStepOutcome::NotRun);
}

/// The whole timeline is validated before any step runs.
///
/// A checkpoint over unmapped memory is a property of the request, not of the
/// run: the memory map does not change while a timeline runs. Refusing it up
/// front is the only answer that does not leave a machine half-evolved — and the
/// step it refuses for is the *last* one, which is the case a handler that
/// validated as it went would get wrong.
#[test]
fn a_fault_in_the_last_step_refuses_the_timeline_before_the_first_one_runs() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);
    let messages = refusal(
        SandboxTimelineArguments::new(
            base(),
            vec![
                TimelineStep::call("tick", 0),
                TimelineStep::call("bad", 0).with_checkpoints(vec![MemoryExport {
                    address: 0x00c0_0000,
                    length: 4,
                    name: "nowhere".to_owned(),
                }]),
            ],
        ),
        &context,
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("\"bad\"") && message.contains("not mapped")),
        "{messages:?}"
    );
}

/// A step never runs on a reduced budget.
///
/// It either runs with the budget it asked for or is reported as not run, for
/// the reason a matrix case is: a step stopped by the *timeline's* budget would
/// carry a stop reason that says nothing about the routine.
#[test]
fn a_step_that_does_not_fit_the_aggregate_budget_is_reported_as_not_run() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxTimelineArguments::new(
            base(),
            vec![
                TimelineStep::call("first", 0).with_maximum_steps(8),
                TimelineStep::call("second", 0).with_maximum_steps(8),
            ],
        )
        // Enough for the first step's budget and not for the second's.
        .with_maximum_total_steps(9),
        &context,
    );

    assert_eq!(result.steps_ran, 1);
    assert_eq!(result.steps_not_run, 1);
    assert!(result.budget_exhausted);
    assert_eq!(result.steps[1].outcome, TimelineStepOutcome::NotRun);
    assert_eq!(result.steps[1].steps_executed, 0);
}

/// A trace the shared recipe asked for is reported, and per step.
///
/// The alternative — accepting `trace` and reporting none — is exactly the
/// silent drop `env.sandbox.call` was fixed for, one operation later. Per step
/// rather than concatenated, because the boundaries are what say which tick an
/// instruction belongs to.
#[test]
fn a_trace_the_recipe_asked_for_is_reported_under_the_step_that_produced_it() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);
    let mut recipe = base();
    recipe.run.trace = true;
    let result = run(
        SandboxTimelineArguments::new(
            recipe,
            vec![
                TimelineStep::call("tick-1", 0),
                TimelineStep::call("tick-2", 0),
            ],
        )
        .with_maximum_total_steps(256),
        &context,
    );

    for step in &result.steps {
        // ADDQ.W and RTS, and nothing from the neighbouring step.
        assert_eq!(step.trace.len(), 2, "{}", step.name);
        assert_eq!(step.trace_total, 2);
        assert!(!step.trace_truncated);
        assert_eq!(step.trace[0].address, 0x2_0000);
    }
}

/// The shapes a step may not have, each refused by name.
#[test]
fn a_step_states_exactly_one_way_to_start_and_the_first_cannot_resume() {
    let resolver = ticker();
    let context = ExecutionContext::new(&resolver);

    let mut both = TimelineStep::call("both", 0);
    both.resume = true;
    assert!(
        refusal(SandboxTimelineArguments::new(base(), vec![both]), &context)[0]
            .contains("exactly one of the two")
    );

    assert!(
        refusal(
            SandboxTimelineArguments::new(base(), vec![TimelineStep::resume("first")]),
            &context,
        )[0]
        .contains("there is no machine to continue")
    );

    let mut seeded_registers = TimelineStep::resume("later");
    seeded_registers.data_registers = Some([1; 8]);
    assert!(
        refusal(
            SandboxTimelineArguments::new(
                base(),
                vec![TimelineStep::call("first", 0), seeded_registers],
            ),
            &context,
        )[0]
        .contains("cannot state data_registers")
    );

    assert!(
        refusal(
            SandboxTimelineArguments::new(
                base(),
                vec![TimelineStep::call("same", 0), TimelineStep::call("same", 0)],
            ),
            &context,
        )[0]
        .contains("two steps are both called")
    );
}
