//! `env.sandbox.slice` — why one value came out the way it did.
//!
//! `env.sandbox.compare` finds the first instruction two runs disagree at. It
//! does not say which earlier value made that instruction behave differently,
//! and that is the question a person retracing a divergence actually has. This
//! runs the recipe with its trace on and walks it backwards from one value,
//! through registers, the condition codes and memory, to the reviewed inputs
//! that influenced it.
//!
//! The model is `amiga_disasm::slice`, which is where the imprecision is stated:
//! definitions are exact and uses are an over-approximation, so the answer is a
//! superset rather than a minimum — the safe direction for evidence, and one the
//! result says out loud rather than leaving to be assumed.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::BoundedSink;
use crate::normalize::NormalizedSandboxSlice;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, SandboxSliceResult, SliceStepResult, SliceStopResult,
};

pub(crate) fn run(
    request: &NormalizedSandboxSlice,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxSlice,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match slice(request, context, &mut diagnostics, events) {
        Ok(result) => outcome(
            Status::Success,
            diagnostics,
            Some(OperationResult::EnvSandboxSlice(result)),
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

fn slice(
    request: &NormalizedSandboxSlice,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Result<SandboxSliceResult, Diagnostic> {
    let called = super::sandbox::call(&request.call, context, diagnostics, events)?;

    // The bytes the run started with, which is what the model decodes against:
    // a trace records what each instruction *did* and not what it was. Only the
    // hunk being run is read, so a step outside it ends its chain with a stated
    // `undecodable` rather than being followed into bytes nobody supplied.
    let length = usize::try_from(called.allocation_bytes).unwrap_or(usize::MAX);
    let code = called
        .baseline
        .slice(called.load_origin, length)
        .ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!(
                    "the hunk at {:#x} is not readable as {length} bytes, so there is \
                     nothing to decode the trace against",
                    called.load_origin
                ),
            )
        })?
        .to_vec();

    let input = amiga_disasm::SliceInput {
        steps: &called.steps,
        initial: called.entry_registers,
        code: &code,
        code_origin: called.load_origin,
        maximum_depth: request.maximum_depth,
        maximum_steps: request.maximum_entries,
    };
    let sliced = amiga_disasm::slice(&input, request.seed);

    if sliced.steps.is_empty() {
        // Worth saying out loud: an empty slice reads as "nothing influenced
        // this", and the ordinary cause is that the value was never written —
        // which the stops already say, but only to a reader who looks.
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::AnalysisRecordUnreadable,
            "the slice reached no instruction: the value the seed names was never written \
             during the run, or the trace holds no row that could have written it",
        ));
    }
    if called.record.trace_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the run traced {} rows and the trace kept fewer; a slice over a capped \
                 trace is bounded by it",
                called.record.trace_total
            ),
        ));
    }

    Ok(SandboxSliceResult {
        source: called.record.source,
        hunk: called.record.hunk,
        entry: called.record.entry,
        stop: called.record.stop,
        steps_executed: called.record.steps_executed,
        seed: match request.seed {
            amiga_disasm::SliceSeed::Final(location) => location.to_string(),
            amiga_disasm::SliceSeed::Instruction {
                address,
                occurrence,
            } => format!("{address:#010x}#{occurrence}"),
        },
        steps: sliced
            .steps
            .iter()
            .map(|step| SliceStepResult {
                index: step.index as u64,
                address: step.address,
                occurrence: step.occurrence,
                text: step.text.clone(),
                depth: step.depth as u64,
                defines: step.defines.iter().map(ToString::to_string).collect(),
                uses: step.uses.iter().map(ToString::to_string).collect(),
            })
            .collect(),
        steps_total: sliced.steps_total as u64,
        steps_truncated: sliced.steps_truncated,
        stops: sliced
            .stops
            .iter()
            .map(|stop| match stop {
                amiga_disasm::SliceStop::Input(location) => SliceStopResult::Input {
                    location: location.to_string(),
                },
                amiga_disasm::SliceStop::Undecodable { step, address } => {
                    SliceStopResult::Undecodable {
                        step: *step as u64,
                        address: *address,
                    }
                }
                amiga_disasm::SliceStop::DepthReached => SliceStopResult::DepthReached,
                amiga_disasm::SliceStop::StepsReached => SliceStopResult::StepsReached,
                amiga_disasm::SliceStop::NotExecuted {
                    address,
                    occurrence,
                    executed,
                } => SliceStopResult::NotExecuted {
                    address: *address,
                    occurrence: *occurrence,
                    executed: *executed,
                },
            })
            .collect(),
        uses_are_a_superset: sliced.uses_are_a_superset,
        trace_truncated: called.record.trace_truncated,
    })
}
