//! `analysis.code.disassemble` — the instructions in a HUNK CODE segment or
//! pinned raw image, and how they were found.
//!
//! **What crosses the boundary is instructions and edges, never a listing.** A
//! listing is a display format: its labels, its column widths, its comment
//! marker, and its `DC.W` convention are one frontend's choices. Returning one
//! would freeze those choices into the machine contract and make every other
//! consumer inherit them. So this returns what a listing is rendered *from* —
//! per instruction the offset, the runtime address when an origin is in effect,
//! the encoded bytes, the mnemonic, and the entries that reached it; plus the
//! traversal's own edges and its coverage.
//!
//! Two modes, because they are two ways of answering one question. A linear
//! sweep decodes every word in a range whether or not anything reaches it,
//! which finds code control flow never arrives at and decodes data as
//! instructions where it is data. A flow traversal follows entry points, which
//! finds only what is reachable and says what it did not reach. A mode flag on
//! one request beats two operations differing by a boolean.
//!
//! The unreached runs carry their bytes. A caller rendering a full listing
//! needs them, and the alternative — opening the source a second time and
//! finding the hunk again — is the second implementation this whole layer
//! exists to remove.

use std::fmt::Write as _;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedCodeDisassemble;
use crate::protocol::Status;
use crate::request::{CodeDisassembleMode, CodeRegion, OperationName};
use crate::response::{
    CodeCallEdge, CodeCoverage, CodeDisassembleResult, CodeExternalFlow, CodeExternalKind,
    CodeFlowEdge, CodeFlowFacts, CodeFlowKind, CodeUnresolvedFlow, DisassembledInstruction,
    OperationOutcome, OperationResult, SourcePin, UnreachedRun,
};
use crate::source::SourceError;

/// Lowercase hex, the encoding every byte string in this response uses.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn run(
    request: &NormalizedCodeDisassemble,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisCodeDisassemble,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            let code = match error {
                SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    if let Err(diagnostic) = super::code::verify_pin(&source, request.expected_sha256.as_deref()) {
        diagnostics.push(diagnostic);
        return outcome(Status::Error, diagnostics, None);
    }

    let entries = match request.mode {
        CodeDisassembleMode::Linear => &[][..],
        CodeDisassembleMode::Flow => request.entries.as_slice(),
    };
    let (code, hunk_bytes, flow_analysis) = match request.region {
        CodeRegion::Hunk => match super::code::locate(source.bytes(), request.hunk, entries) {
            Ok(located) => {
                let analysis = (request.mode == CodeDisassembleMode::Flow)
                    .then(|| located.analyze(&request.entries, request.origin));
                (located.code, located.hunk_bytes, analysis)
            }
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                return outcome(Status::Error, diagnostics, None);
            }
        },
        CodeRegion::Raw => match super::code::raw_code_length(source.bytes(), entries) {
            Ok(length) => {
                let analysis = (request.mode == CodeDisassembleMode::Flow).then(|| {
                    amiga_disasm::analyze_entries_with(
                        source.bytes(),
                        &request.entries,
                        &amiga_disasm::FlowOptions {
                            rebase: request.origin.map(amiga_disasm::Rebase::new),
                            relocations: None,
                        },
                    )
                });
                (source.bytes(), length, analysis)
            }
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                return outcome(Status::Error, diagnostics, None);
            }
        },
        CodeRegion::BootBlock => unreachable!("normalization refuses boot blocks"),
    };

    let pin = SourcePin {
        size: source.size(),
        sha256: source.sha256().to_owned(),
    };
    // With an origin, every instruction reports the address the MC68000 would
    // fetch it from. Without one there is no such address, and inventing offset
    // zero as an address would be a claim nobody made.
    let address_of = |offset: u32| request.origin.and_then(|origin| origin.checked_add(offset));

    match request.mode {
        CodeDisassembleMode::Linear => {
            let end = request.end.unwrap_or(hunk_bytes);
            if request.start > hunk_bytes || end > hunk_bytes {
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!(
                            "range {:#x}..{end:#x} is outside the selected code region's \
                             {hunk_bytes:#x} bytes",
                            request.start
                        ),
                    )
                    .at("$.request.arguments.end"),
                );
                return outcome(Status::Error, diagnostics, None);
            }
            let swept = match amiga_disasm::sweep(code, request.start, end) {
                Ok(swept) => swept,
                Err(error) => {
                    diagnostics.push(Diagnostic::error(
                        DiagnosticCode::AnalysisCodeUndecodable,
                        error.to_string(),
                    ));
                    return outcome(Status::Error, diagnostics, None);
                }
            };
            events.emit(OperationEvent::Progress {
                phase: "sweep_instructions",
                completed: swept.len() as u64,
                total: Some(swept.len() as u64),
            });

            let total = swept.len();
            let truncated = total > request.maximum_instructions;
            if truncated {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::ResultEntriesTruncated,
                    format!(
                        "{total} instructions decoded; {} are reported",
                        request.maximum_instructions
                    ),
                ));
            }
            let result = CodeDisassembleResult {
                source: pin,
                region: request.region,
                hunk: (request.region == CodeRegion::Hunk).then_some(request.hunk),
                mode: request.mode,
                hunk_bytes: u64::from(hunk_bytes),
                origin: request.origin,
                start: request.start,
                end,
                instructions: swept
                    .into_iter()
                    .take(request.maximum_instructions)
                    .map(|instruction| DisassembledInstruction {
                        offset: instruction.address,
                        address: address_of(instruction.address),
                        bytes: hex(&instruction.encoded),
                        text: instruction.text,
                        // A sweep follows nothing, so nothing owns what it
                        // decoded. An empty owner list here is a fact about the
                        // mode, not a capped one.
                        owners: Vec::new(),
                        owner_total: 0,
                    })
                    .collect(),
                instruction_total: total as u64,
                instructions_truncated: truncated,
                flow: None,
            };
            outcome(
                Status::Success,
                diagnostics,
                Some(OperationResult::AnalysisCodeDisassemble(result)),
            )
        }
        CodeDisassembleMode::Flow => {
            let Some(analysis) = flow_analysis else {
                unreachable!("flow mode prepares a flow analysis")
            };
            events.emit(OperationEvent::Progress {
                phase: "analyze_flow",
                completed: analysis.instructions.len() as u64,
                total: Some(analysis.instructions.len() as u64),
            });
            let coverage = amiga_disasm::coverage(&analysis, code.len());

            let instruction_total = analysis.instructions.len();
            let instructions_truncated = instruction_total > request.maximum_instructions;
            let instructions: Vec<DisassembledInstruction> = analysis
                .instructions
                .values()
                .take(request.maximum_instructions)
                .map(|instruction| DisassembledInstruction {
                    offset: instruction.address,
                    address: address_of(instruction.address),
                    bytes: hex(&instruction.encoded),
                    text: instruction.text(),
                    owners: instruction.owners.iter().copied().collect(),
                    // The analysis caps its own owner set and counts what it
                    // refused; carrying only `owners` would undo that.
                    owner_total: instruction.owner_total as u64,
                })
                .collect();

            let unreached = unreached_runs(code, &analysis);
            let unreached_total = unreached.len();
            let unreached_truncated = unreached_total > request.maximum_edges;

            let cap = request.maximum_edges;
            let function_total = analysis.functions.len();
            let call_total = analysis.calls.len();
            let flow_total = analysis.flows.len();
            let unresolved_total = analysis.unresolved.len();
            let library_call_total = analysis.library_calls.len();
            let external_total = analysis.external.len();
            let truncated = unreached_truncated
                || function_total > cap
                || call_total > cap
                || flow_total > cap
                || unresolved_total > cap
                || library_call_total > cap
                || external_total > cap;

            if instructions_truncated {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::ResultEntriesTruncated,
                    format!(
                        "{instruction_total} instructions were reached; {} are reported",
                        request.maximum_instructions
                    ),
                ));
            }
            if truncated {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::ResultEntriesTruncated,
                    format!(
                        "at least one edge list holds more than {cap} entries; each reports its \
                         true total"
                    ),
                ));
            }

            let flow = CodeFlowFacts {
                entries: request.entries.clone(),
                unreached: unreached.into_iter().take(cap).collect(),
                unreached_total: unreached_total as u64,
                unreached_truncated,
                functions: analysis.functions.iter().copied().take(cap).collect(),
                function_total: function_total as u64,
                calls: analysis
                    .calls
                    .iter()
                    .take(cap)
                    .map(|call| CodeCallEdge {
                        caller: call.caller,
                        call_site: call.call_site,
                        callee: call.callee,
                    })
                    .collect(),
                call_total: call_total as u64,
                flows: analysis
                    .flows
                    .iter()
                    .take(cap)
                    .map(|edge| CodeFlowEdge {
                        owner: edge.owner,
                        site: edge.site,
                        target: edge.target,
                        kind: match edge.kind {
                            amiga_disasm::FlowKind::Fallthrough => CodeFlowKind::Fallthrough,
                            amiga_disasm::FlowKind::Branch => CodeFlowKind::Branch,
                            amiga_disasm::FlowKind::Call => CodeFlowKind::Call,
                        },
                    })
                    .collect(),
                flow_total: flow_total as u64,
                unresolved: analysis
                    .unresolved
                    .iter()
                    .take(cap)
                    .map(|unresolved| CodeUnresolvedFlow {
                        owner: unresolved.owner,
                        site: unresolved.address,
                    })
                    .collect(),
                unresolved_total: unresolved_total as u64,
                library_calls: analysis.library_calls.iter().copied().take(cap).collect(),
                library_call_total: library_call_total as u64,
                external: analysis
                    .external
                    .iter()
                    .take(cap)
                    .map(|external| CodeExternalFlow {
                        site: external.site,
                        kind: match external.kind {
                            amiga_disasm::ExternalKind::Call => CodeExternalKind::Call,
                            amiga_disasm::ExternalKind::Jump => CodeExternalKind::Jump,
                        },
                        relocation: external.relocation,
                        target_hunk: external.target_hunk,
                        target_offset: external.target_offset,
                    })
                    .collect(),
                external_total: external_total as u64,
                truncated,
                coverage: CodeCoverage {
                    total_bytes: coverage.total_bytes as u64,
                    decoded_bytes: coverage.decoded_bytes as u64,
                    instructions: coverage.instructions as u64,
                    functions: coverage.functions as u64,
                    calls: coverage.calls as u64,
                    library_calls: coverage.library_calls as u64,
                    unresolved: coverage.unresolved as u64,
                    external: coverage.external as u64,
                },
            };

            let result = CodeDisassembleResult {
                source: pin,
                region: request.region,
                hunk: (request.region == CodeRegion::Hunk).then_some(request.hunk),
                mode: request.mode,
                hunk_bytes: u64::from(hunk_bytes),
                origin: request.origin,
                // A traversal is not bounded by a range: it goes where the code
                // goes, so the whole hunk is what it covered.
                start: 0,
                end: hunk_bytes,
                instructions,
                instruction_total: instruction_total as u64,
                instructions_truncated,
                flow: Some(flow),
            };
            outcome(
                Status::Success,
                diagnostics,
                Some(OperationResult::AnalysisCodeDisassemble(result)),
            )
        }
    }
}

/// The maximal runs of bytes no decoded instruction covers.
///
/// Runs rather than single bytes, because that is what they are: the gap
/// between two reached blocks is one fact about the hunk, and reporting it byte
/// by byte would turn a jump table into hundreds of entries and hit the cap
/// long before saying anything useful.
fn unreached_runs(code: &[u8], analysis: &amiga_disasm::ControlFlowAnalysis) -> Vec<UnreachedRun> {
    let mut runs = Vec::new();
    let mut cursor = 0_usize;
    let mut run_start = 0_usize;
    while cursor < code.len() {
        let Ok(offset) = u32::try_from(cursor) else {
            break;
        };
        match analysis.instructions.get(&offset) {
            Some(decoded) => {
                if run_start < cursor
                    && let Ok(start) = u32::try_from(run_start)
                    && let Some(bytes) = code.get(run_start..cursor)
                {
                    runs.push(UnreachedRun {
                        offset: start,
                        bytes: hex(bytes),
                    });
                }
                // The analysis never yields a zero-length instruction, but a
                // stuck cursor would be an infinite loop, so guard anyway.
                cursor = (decoded.end as usize).max(cursor + 2).min(code.len());
                run_start = cursor;
            }
            None => cursor += 1,
        }
    }
    if run_start < code.len()
        && let Ok(start) = u32::try_from(run_start)
        && let Some(bytes) = code.get(run_start..)
    {
        runs.push(UnreachedRun {
            offset: start,
            bytes: hex(bytes),
        });
    }
    runs
}
