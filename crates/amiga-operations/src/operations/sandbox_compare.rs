//! `env.sandbox.compare`: two golden records, read in the terms that matter.
//!
//! A textual diff of two `env.sandbox.call` records answers the wrong question.
//! It has no idea which fields are *inputs*, so it reports a changed input
//! register and a changed output register as the same kind of finding — when one
//! is the question and the other is the answer. It reports every byte of a
//! changed region when what a reader wants is "these two regions differ". And it
//! aligns traces by row number, so one extra instruction early on makes every
//! row after it look different.
//!
//! So this compares field by field, splits the findings into what the routine
//! was *given* and what it *did*, and aligns traces by execution address.

use std::collections::{BTreeMap, BTreeSet};

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedSandboxCompare;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    CompareDifference, ComparedRecord, DivergentStep, OperationOutcome, OperationResult,
    SandboxCallResult, SandboxCompareResult, TraceComparison, TraceDivergence,
};
use crate::source::SourceError;

/// Compare a field across every record, listing it when they disagree.
///
/// Rendered through `Debug` rather than compared structurally, because the
/// fields are of a dozen different types and what the caller asked is *whether*
/// they differ. The record is where a typed value is read from.
fn compare<T: PartialEq + std::fmt::Debug>(
    field: &str,
    values: impl Iterator<Item = T>,
    into: &mut Vec<CompareDifference>,
) {
    let values: Vec<T> = values.collect();
    let Some(first) = values.first() else {
        return;
    };
    if values.iter().all(|value| value == first) {
        return;
    }
    into.push(CompareDifference {
        field: field.to_owned(),
        values: values.iter().map(|value| format!("{value:?}")).collect(),
    });
}

/// The changed-memory runs of one record, keyed by address and digested.
///
/// Digested rather than compared as hex so a difference says *that* a region
/// differs without carrying two copies of it. Two runs at one address in one
/// record cannot happen — `changed_regions` merges them — so the key is unique.
///
/// Through `sandbox::digest_hex` rather than over the hex text, which would
/// compare just as correctly and print a **different number** from the one
/// `env.sandbox.matrix` reports for the same memory. Two operations of one
/// toolkit that digest the same bytes differently are two operations a reader
/// cannot put side by side, which is exactly what these two are for.
fn regions(record: &SandboxCallResult) -> BTreeMap<u32, (usize, String)> {
    record
        .changed_memory
        .iter()
        .map(|region| {
            (
                region.address,
                (
                    region.hex.len() / 2,
                    super::sandbox::digest_hex(&region.hex),
                ),
            )
        })
        .collect()
}

/// A readable name for a record's locator.
///
/// The canonical form is a JSON document — it has to be, because a member of a
/// container has no single path — and printing that as a label is unreadable.
/// The digest beside it is the identity, so this only has to distinguish the
/// records a caller named.
fn display_name(source: &crate::normalize::NormalizedSource) -> String {
    let mut name = source.parent.as_str().to_owned();
    for member in &source.members {
        name.push('!');
        name.push_str(member.container());
    }
    name
}

pub(crate) fn run(
    request: &NormalizedSandboxCompare,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxCompare,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let mut records = Vec::with_capacity(request.records.len());
    let mut described = Vec::with_capacity(request.records.len());
    for (index, name) in request.records.iter().enumerate() {
        let at = format!("$.request.arguments.records[{index}]");
        let source = match context.resolve_source(name, request.maximum_input_bytes) {
            Ok(source) => source,
            Err(error) => {
                let code = match error {
                    SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                    SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                    SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
                };
                diagnostics.push(Diagnostic::error(code, error.to_string()).at(at));
                return outcome(Status::Error, diagnostics, None);
            }
        };
        // A record this build cannot read as its own record type is **refused**
        // rather than compared. `SandboxCallResult` is a closed shape: a record
        // from a build that added a field fails on the unknown one, and one from
        // a build that had not yet added it fails on the missing one. That is
        // what stands in for a version stamp the record does not carry, and it
        // is the whole point — a textual diff of two records this build does not
        // understand would still produce a plausible-looking answer.
        let record: SandboxCallResult = match serde_json::from_slice(source.bytes()) {
            Ok(record) => record,
            Err(error) => {
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!(
                            "{} is not an env.sandbox.call record this build can read: \
                             {error}",
                            name.canonical()
                        ),
                    )
                    .at(at),
                );
                return outcome(Status::Error, diagnostics, None);
            }
        };
        described.push(ComparedRecord {
            name: display_name(name),
            sha256: amiga_core::sha256(source.bytes()),
            source: record.source.clone(),
            has_trace: !record.trace.is_empty(),
            trace_truncated: record.trace_truncated,
        });
        records.push(record);
        events.emit(OperationEvent::Progress {
            phase: "read",
            completed: (index + 1) as u64,
            total: Some(request.records.len() as u64),
        });
    }

    // --- what the records were given -----------------------------------------
    let mut inputs = Vec::new();
    compare(
        "source.sha256",
        records.iter().map(|record| record.source.sha256.clone()),
        &mut inputs,
    );
    compare(
        "hunk",
        records.iter().map(|record| record.hunk),
        &mut inputs,
    );
    compare(
        "entry",
        records.iter().map(|record| record.entry),
        &mut inputs,
    );
    for index in 0..8 {
        compare(
            &format!("inputs.d{index}"),
            records.iter().map(|record| record.inputs.d[index]),
            &mut inputs,
        );
    }
    for index in 0..7 {
        compare(
            &format!("inputs.a{index}"),
            records.iter().map(|record| record.inputs.a[index]),
            &mut inputs,
        );
    }
    compare(
        "stack_arguments",
        records.iter().map(|record| record.stack_arguments.clone()),
        &mut inputs,
    );
    compare(
        "mapped_regions",
        records.iter().map(|record| record.mapped_regions.clone()),
        &mut inputs,
    );
    compare(
        "memory_seeds",
        records.iter().map(|record| record.memory_seeds.clone()),
        &mut inputs,
    );
    compare(
        "custom_chips",
        records.iter().map(|record| record.custom_chips.clone()),
        &mut inputs,
    );

    // --- what they did -------------------------------------------------------
    let mut behavior = Vec::new();
    compare(
        "stop",
        records.iter().map(|record| record.stop),
        &mut behavior,
    );
    compare(
        "returned",
        records.iter().map(|record| record.returned),
        &mut behavior,
    );
    compare(
        "steps_executed",
        records.iter().map(|record| record.steps_executed),
        &mut behavior,
    );
    for index in 0..8 {
        compare(
            &format!("outputs.d{index}"),
            records.iter().map(|record| record.outputs.d[index]),
            &mut behavior,
        );
    }
    for index in 0..7 {
        compare(
            &format!("outputs.a{index}"),
            records.iter().map(|record| record.outputs.a[index]),
            &mut behavior,
        );
    }
    compare(
        "watch_events_total",
        records.iter().map(|record| record.watch_events_total),
        &mut behavior,
    );
    compare(
        "interrupts_total",
        records.iter().map(|record| record.interrupts_total),
        &mut behavior,
    );
    compare(
        "blits_total",
        records.iter().map(|record| record.blits_total),
        &mut behavior,
    );

    // Changed memory, by address rather than positionally: a record that changed
    // one extra region early would otherwise make every later region compare
    // against the wrong one, which is the alignment mistake a textual diff makes.
    let mapped: Vec<_> = records.iter().map(regions).collect();
    let addresses: BTreeSet<u32> = mapped.iter().flat_map(BTreeMap::keys).copied().collect();
    for address in addresses {
        compare(
            &format!("changed_memory[{address:#010x}]"),
            // The whole digest, not a prefix of it. This is a value in a
            // machine-readable response, and a truncated hash is one a caller
            // cannot check against the full one `env.sandbox.matrix` reports for
            // the same memory. Shortening it for display is the frontend's.
            mapped.iter().map(|regions| {
                regions.get(&address).map_or_else(
                    || "unchanged".to_owned(),
                    |(length, digest)| format!("{length} bytes {digest}"),
                )
            }),
            &mut behavior,
        );
    }

    // Exports by name, for the same reason.
    let exported: Vec<BTreeMap<&str, &str>> = records
        .iter()
        .map(|record| {
            record
                .exported_regions
                .iter()
                .map(|export| (export.name.as_str(), export.sha256.as_str()))
                .collect()
        })
        .collect();
    let names: BTreeSet<&str> = exported.iter().flat_map(BTreeMap::keys).copied().collect();
    for name in names {
        compare(
            &format!("export.{name}"),
            exported
                .iter()
                .map(|exports| exports.get(name).copied().unwrap_or("absent")),
            &mut behavior,
        );
    }

    let (trace_comparison, first_divergence) = compare_traces(&records);
    if let Some(divergence) = &first_divergence {
        behavior.push(CompareDifference {
            field: "trace".to_owned(),
            values: divergence
                .records
                .iter()
                .map(|step| {
                    format!(
                        "{:#010x} {} (pass {})",
                        step.address,
                        step.text,
                        step.occurrence + 1
                    )
                })
                .collect(),
        });
    }

    let input_differences_total = inputs.len() as u64;
    let behavioral_differences_total = behavior.len() as u64;
    if inputs.len() > request.maximum_differences || behavior.len() > request.maximum_differences {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{input_differences_total} input and {behavioral_differences_total} \
                 behavioral difference(s); {} of each are listed",
                request.maximum_differences
            ),
        ));
    }
    inputs.truncate(request.maximum_differences);
    behavior.truncate(request.maximum_differences);

    let same_source = records
        .windows(2)
        .all(|pair| pair[0].source.sha256 == pair[1].source.sha256);

    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::EnvSandboxCompare(SandboxCompareResult {
            records: described,
            same_source,
            identical: input_differences_total == 0 && behavioral_differences_total == 0,
            same_behavior: behavioral_differences_total == 0,
            input_differences: inputs,
            input_differences_total,
            behavioral_differences: behavior,
            behavioral_differences_total,
            first_divergence,
            trace_comparison,
        })),
    )
}

/// Walk the retained traces in lockstep and report the first step at which the
/// records execute different addresses.
///
/// **Aligned by execution address plus occurrence, not by row number.** The row
/// number is an artifact of how the record was written; the address is what was
/// executed, and the occurrence — how many times this record had reached that
/// address already — is what makes a divergence inside a loop readable. Two
/// traces that both stop at `$21f4` say nothing until you know one was on its
/// third pass and the other on its ninth.
///
/// A record with no trace makes the comparison [`TraceComparison::Absent`]
/// rather than silently "no divergence found": an absent trace is not agreement.
fn compare_traces(records: &[SandboxCallResult]) -> (TraceComparison, Option<TraceDivergence>) {
    if records.iter().any(|record| record.trace.is_empty()) {
        return (TraceComparison::Absent, None);
    }
    let steps = records
        .iter()
        .map(|record| record.trace.len())
        .min()
        .unwrap_or(0);
    let truncated = records.iter().any(|record| record.trace_truncated);
    let comparison = TraceComparison::Compared {
        steps: steps as u64,
        truncated,
    };

    // How many times each record has reached each address so far. Counted as we
    // walk rather than precomputed, so the number reported is the occurrence at
    // the diverging step rather than the total over the whole trace.
    let mut seen: Vec<BTreeMap<u32, u64>> = vec![BTreeMap::new(); records.len()];
    for step in 0..steps {
        let addresses: Vec<u32> = records
            .iter()
            .map(|record| record.trace[step].address)
            .collect();
        let occurrences: Vec<u64> = addresses
            .iter()
            .zip(seen.iter_mut())
            .map(|(address, seen)| {
                let count = seen.entry(*address).or_insert(0);
                let occurrence = *count;
                *count += 1;
                occurrence
            })
            .collect();
        if addresses.windows(2).all(|pair| pair[0] == pair[1]) {
            continue;
        }
        return (
            comparison,
            Some(TraceDivergence {
                step: step as u64,
                records: records
                    .iter()
                    .zip(addresses)
                    .zip(occurrences)
                    .map(|((record, address), occurrence)| DivergentStep {
                        address,
                        text: record.trace[step].text.clone(),
                        occurrence,
                    })
                    .collect(),
            }),
        );
    }
    (comparison, None)
}
