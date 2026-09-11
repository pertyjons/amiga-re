//! `analysis.code.facts` — the fact model, reachable through the API.
//!
//! The keystone of Milestone 3. `disasm annotate`, `disasm report`, and `disasm
//! query` are *renderings* of this list: each chooses an ordering, a narrowing,
//! and a text or JSON shape over the same facts. What they render belongs here;
//! how they render it does not, which is why none of the three is an operation.
//!
//! **The fact list is `amiga_disasm`'s own model**, serialized as that crate
//! defines it and versioned by its `schema_version`. Re-typing it here would
//! create a second definition of a wire shape `disasm report --format json` has
//! published since it landed — the duplication this plan exists to end, one
//! level down.
//!
//! **The library tables travel as data.** `collect` bakes library and function
//! names into every `LibraryCall` fact, from tables a frontend reads out of its
//! own fd files. Milestone 2 settled that *naming a vector* stays with the
//! frontend, but a fact that lost the name would be a worse fact. So the
//! request carries the vectors, no request names a host path, and two adapters
//! given the same table get the same facts.
//!
//! **The instructions travel beside the facts**, because every renderer needs
//! both: an annotated listing walks instructions and hangs facts off them. One
//! request, so the two cannot come from different traversals.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedCodeFacts;
use crate::protocol::Status;
use crate::request::{CodeRegion, OperationName};
use crate::response::{
    CodeFactsResult, DisassembledInstruction, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

/// One relocation patching the analyzed hunk, with its stored pointer read.
struct PatchedRelocation {
    source_offset: u32,
    target_hunk: u32,
    /// `None` when the stored longword could not be read.
    target_offset: Option<u32>,
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn run(
    request: &NormalizedCodeFacts,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisCodeFacts,
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

    // The two regions differ in where the code is and what the machine hands
    // the code on entry — not in what a fact is.
    let (code, code_offset, hunk, relocations, patched, default_library) = match request.region {
        CodeRegion::BootBlock => {
            let boot = match amiga_adf::Bootblock::parse(source.bytes()) {
                Ok(boot) => boot,
                Err(error) => {
                    diagnostics.push(Diagnostic::error(
                        DiagnosticCode::ContainerAdfUnreadable,
                        error.to_string(),
                    ));
                    return outcome(Status::Error, diagnostics, None);
                }
            };
            (
                boot.boot_code().to_vec(),
                amiga_adf::Bootblock::CODE_OFFSET as u64,
                None,
                None,
                Vec::new(),
                // A boot block starts with ExecBase in A6. The machine
                // guarantees it, so the fact model is told rather than left to
                // infer it from code that never opens exec.
                request
                    .default_library
                    .clone()
                    .or_else(|| Some("exec".to_owned())),
            )
        }
        CodeRegion::Hunk => {
            let located = match super::code::locate(source.bytes(), request.hunk, &request.entries)
            {
                Ok(located) => located,
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    return outcome(Status::Error, diagnostics, None);
                }
            };
            let file_offset = located
                .executable
                .segment(request.hunk)
                .map_or(0, |segment| segment.file_offset as u64);
            // Every record that patches this hunk, with its stored pointer
            // resolved once. A record whose longword could not be read is kept
            // — an unreadable site is a fact about the image — but it is left
            // out of the operand index, which must not act on a target it
            // cannot prove.
            let patched: Vec<PatchedRelocation> = located
                .executable
                .relocations
                .iter()
                .filter(|relocation| relocation.source_hunk == request.hunk)
                .map(|relocation| PatchedRelocation {
                    source_offset: relocation.source_offset,
                    target_hunk: relocation.target_hunk,
                    target_offset: located.executable.stored_pointer(relocation),
                })
                .collect();
            let relocations = amiga_disasm::Relocations::new(
                request.hunk,
                patched
                    .iter()
                    .filter_map(|relocation| {
                        Some(amiga_disasm::Relocation {
                            patched: relocation.source_offset,
                            target_hunk: relocation.target_hunk,
                            target_offset: relocation.target_offset?,
                        })
                    })
                    .collect::<Vec<_>>(),
            );
            (
                located.code.to_vec(),
                file_offset,
                Some(request.hunk),
                Some(relocations),
                patched,
                request.default_library.clone(),
            )
        }
        CodeRegion::Raw => {
            if let Err(diagnostic) = super::code::raw_code_length(source.bytes(), &request.entries)
            {
                diagnostics.push(diagnostic);
                return outcome(Status::Error, diagnostics, None);
            }
            (
                source.bytes().to_vec(),
                0,
                None,
                None,
                Vec::new(),
                request.default_library.clone(),
            )
        }
    };

    let options = amiga_disasm::FlowOptions {
        rebase: request.origin.map(amiga_disasm::Rebase::new),
        relocations,
    };
    let analysis = amiga_disasm::analyze_entries_with(&code, &request.entries, &options);
    events.emit(OperationEvent::Progress {
        phase: "analyze_flow",
        completed: analysis.instructions.len() as u64,
        total: Some(analysis.instructions.len() as u64),
    });

    // The request's vectors are indexed the way `collect` wants them: by
    // library, then by negative offset.
    let mut lvo_names: BTreeMap<amiga_disasm::Library, BTreeMap<i16, amiga_disasm::LvoEntry>> =
        BTreeMap::new();
    for vector in &request.library_vectors {
        let Some(library) = amiga_disasm::Library::from_name(&vector.library) else {
            diagnostics.push(
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("{:?} does not name a library", vector.library),
                )
                .at("$.request.arguments.library_vectors"),
            );
            return outcome(Status::Error, diagnostics, None);
        };
        lvo_names.entry(library).or_default().insert(
            vector.lvo,
            amiga_disasm::LvoEntry {
                name: vector.name.clone(),
                arguments: vector
                    .arguments
                    .iter()
                    // A table describes where an argument arrives and what it
                    // is called; what it *held* is resolved per call site by
                    // `collect`, which is why all result fields start empty.
                    .map(|argument| amiga_disasm::CallArgument {
                        name: argument.name.clone(),
                        register: argument.register.clone(),
                        value: None,
                        symbolic: None,
                        unresolved: None,
                    })
                    .collect(),
                public: vector.public,
            },
        );
    }
    let default_a6 = match &default_library {
        None => None,
        Some(name) => match amiga_disasm::Library::from_name(name) {
            Some(library) => Some(library),
            None => {
                diagnostics.push(
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!("{name:?} does not name a library"),
                    )
                    .at("$.request.arguments.default_library"),
                );
                return outcome(Status::Error, diagnostics, None);
            }
        },
    };

    let collect_options = amiga_disasm::CollectOptions {
        image_origin: request.origin,
        default_a6,
        global_base_register: request.base_register,
        custom_base: amiga_hw::CUSTOM_BASE,
        lvo_names,
    };
    let mut facts = amiga_disasm::collect(&analysis, &code, &collect_options);

    // The relocations patching this hunk are facts about the image, so they
    // belong in the model rather than being added by whichever frontend
    // composes it. `collect` does not see them: it is given the index for
    // resolving operands, not the records themselves.
    let mut relocation_sources: BTreeMap<u32, std::collections::BTreeSet<u32>> = BTreeMap::new();
    for relocation in patched {
        // The record, plus the instruction whose operand it patches when the
        // patched bytes lie inside decoded code. Asked of the same index the
        // traversal uses, so the facts cannot name a different instruction
        // than a listing does.
        let instruction =
            amiga_disasm::Relocations::covering_instruction(&analysis, relocation.source_offset);
        let mut evidence = vec![amiga_disasm::Evidence::Relocation {
            offset: relocation.source_offset,
        }];
        if let Some(site) = instruction {
            evidence.push(amiga_disasm::Evidence::Instruction { site });
        }
        facts.push(amiga_disasm::Fact {
            subject: relocation.source_offset,
            kind: amiga_disasm::FactKind::Relocation {
                target_hunk: relocation.target_hunk,
                target_offset: relocation.target_offset,
                instruction,
            },
            confidence: amiga_disasm::Confidence::Certain,
            producer: amiga_disasm::Producer::Relocations,
            evidence,
        });
        // A relocation landing back in the analyzed hunk lets its target cite
        // the sites that point at it, the way a call target cites its callers.
        if Some(relocation.target_hunk) != hunk {
            continue;
        }
        if let Some(target) = relocation
            .target_offset
            .filter(|offset| (*offset as usize) < code.len())
        {
            relocation_sources
                .entry(target)
                .or_default()
                .insert(relocation.source_offset);
        }
    }
    for (target, sources) in relocation_sources {
        facts.push(amiga_disasm::referenced_by(
            target,
            amiga_disasm::XrefVia::Relocation,
            &sources,
        ));
    }
    facts.sort();
    facts.dedup();
    events.emit(OperationEvent::Progress {
        phase: "collect_facts",
        completed: facts.len() as u64,
        total: Some(facts.len() as u64),
    });

    let fact_total = facts.len();
    let facts_truncated = fact_total > request.maximum_facts;
    let instruction_total = analysis.instructions.len();
    let instructions_truncated = instruction_total > request.maximum_instructions;
    if facts_truncated || instructions_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{fact_total} facts over {instruction_total} instructions; \
                 {} and {} are reported",
                request.maximum_facts, request.maximum_instructions
            ),
        ));
    }

    let address_of = |offset: u32| request.origin.and_then(|origin| origin.checked_add(offset));
    let result = CodeFactsResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        region: request.region,
        hunk,
        code_offset,
        code_bytes: code.len() as u64,
        origin: request.origin,
        entries: request.entries.clone(),
        schema_version: amiga_disasm::SCHEMA_VERSION,
        facts: facts.into_iter().take(request.maximum_facts).collect(),
        fact_total: fact_total as u64,
        facts_truncated,
        instructions: analysis
            .instructions
            .values()
            .take(request.maximum_instructions)
            .map(|instruction| DisassembledInstruction {
                offset: instruction.address,
                address: address_of(instruction.address),
                bytes: hex(&instruction.encoded),
                text: instruction.text(),
                owners: instruction.owners.iter().copied().collect(),
                owner_total: instruction.owner_total as u64,
            })
            .collect(),
        instruction_total: instruction_total as u64,
        instructions_truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisCodeFacts(result)),
    )
}
