//! Per-function summaries: what one function does, said once.
//!
//! A report of a large binary is unreadable as one listing, and the fix is not
//! a shorter listing but a *header* per function that answers the questions a
//! reader asks before reading any instructions: what does it call, what does it
//! touch, does it leave, is it a leaf.
//!
//! ## Summaries are derived from facts, never beside them
//!
//! Every field here is folded out of the [`Fact`] list the report already
//! carries. That is the acceptance criterion of this stage — every fact shown
//! in a summary also exists in the JSON — and it is enforced structurally: this
//! module reads facts and the control-flow analysis, and has no analysis of its
//! own to disagree with them. A summary is a *view*, so a reader who does not
//! believe one can find the facts it came from.
//!
//! ## What is deliberately absent
//!
//! No inferred purpose or naming. A header states what is supported by facts;
//! anything weaker belongs in the fact list with its own confidence, where a
//! reader can weigh it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::control_flow::ControlFlowAnalysis;
use crate::report::{Fact, FactKind, MemoryAddressing};

/// One function, as a header states it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FunctionSummary {
    /// Hunk offset of the entry, which is also the summary's identity and the
    /// anchor every cross-reference uses.
    pub entry: u32,
    /// Hunk offset one past the last byte of the last instruction this function
    /// owns. With `entry` this is the *span*, not a promise that the function
    /// owns every byte between: shared tails and interleaved code are normal in
    /// hand-written MC68000.
    pub end: u32,
    /// Instructions the traversal reached with this function as an owner.
    pub instruction_count: usize,
    /// Whether ownership was capped for any instruction in the span, so a
    /// caller list can be short without being wrong.
    pub ownership_truncated: bool,
    /// Entries that call this function, in offset order.
    pub callers: Vec<u32>,
    /// Entries this function calls, in offset order.
    pub callees: Vec<u32>,
    /// Transfers this function makes that leave the analyzed hunk.
    pub external_calls: usize,
    /// Library vectors this function calls, deduplicated and ordered.
    pub library_calls: Vec<LibraryCallSummary>,
    /// Memory slots this function reads, in address order.
    pub globals_read: Vec<String>,
    /// Memory slots this function writes, in address order.
    pub globals_written: Vec<String>,
    /// Custom-chip registers this function touches, as offsets from the custom
    /// base, in offset order.
    ///
    /// Offsets rather than subsystem names: this crate deliberately does not
    /// depend on the custom-chip knowledge, so naming — and grouping into
    /// subsystems — stays with whoever already names registers. The offset is
    /// the fact; the name is a rendering of it.
    pub hardware_registers: Vec<u16>,
    /// Sites of control flow this function makes whose target is unknown.
    pub unresolved_exits: Vec<u32>,
    /// Whether this function calls nothing at all — not into the hunk, not out
    /// of it, and not into a library.
    ///
    /// `None` when the question cannot be answered from what was folded. Every
    /// other field is a positive list that merely shrinks when facts are
    /// missing; this one is true precisely *because* facts are absent, so a
    /// partial fact list would turn a caller into a claimed leaf. Absence is
    /// only evidence when the list is known to be complete.
    ///
    /// A statically unresolved transfer does not clear this, because it is not
    /// known to be a call; `unresolved_exits` is what says the function may
    /// still leave, and the two are meant to be read together.
    pub leaf: Option<bool>,
    /// Register interface and frame facts folded from the report.
    pub signature: Option<crate::function::FunctionSignature>,
}

/// One library vector a function calls.
///
/// The library and function names stay optional because the inference can fail:
/// a vector whose base could not be established is still a library call, and
/// hiding it until it can be named would lose the only trace of it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LibraryCallSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The library vector offset, which identifies the call even unnamed.
    pub lvo: i16,
    /// How many sites in this function call it.
    pub sites: usize,
}

/// One library vector as a summary keys it: the names when they were inferred,
/// and the offset, which identifies it whether or not they were.
type LibraryVector = (Option<String>, Option<String>, i16);

/// Whether the fact list being folded is everything the analysis produced.
///
/// The caller is the only one that knows: a narrowed report hands over a subset
/// on purpose. It matters for exactly one field — [`FunctionSummary::leaf`] —
/// and getting it wrong there means printing a confident falsehood rather than
/// an incomplete truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completeness {
    /// Every fact the analysis produced.
    Complete,
    /// A filtered or narrowed subset.
    Partial,
}

/// Summarize every function the analysis found, in entry order.
///
/// `facts` must be the same list the report renders, or a summary could state
/// something the report does not carry, and `completeness` must say whether
/// that list was narrowed.
#[must_use]
pub fn summarize(
    analysis: &ControlFlowAnalysis,
    facts: &[Fact],
    completeness: Completeness,
) -> Vec<FunctionSummary> {
    // Ownership is capped per instruction, and a traversal refused at the cap
    // stops walking — so a function that was refused is missing from the call
    // facts *and* has no way to learn it. That makes every absence-derived
    // claim in this analysis unreliable, not just the capped instruction's.
    let capped = analysis
        .instructions
        .values()
        .any(|instruction| instruction.owner_total > instruction.owners.len());
    let absence_is_evidence = completeness == Completeness::Complete && !capped;
    let mut summaries: BTreeMap<u32, FunctionSummary> = analysis
        .functions
        .iter()
        .map(|entry| {
            (
                *entry,
                FunctionSummary {
                    entry: *entry,
                    end: *entry,
                    leaf: absence_is_evidence.then_some(true),
                    ..FunctionSummary::default()
                },
            )
        })
        .collect();

    // The span and the instruction count come from ownership, which is the only
    // record of which traversal reached an instruction. A function's span is
    // therefore what it *reached*, not a contiguous range someone assumed.
    for instruction in analysis.instructions.values() {
        let truncated = instruction.owner_total > instruction.owners.len();
        for owner in &instruction.owners {
            let Some(summary) = summaries.get_mut(owner) else {
                continue;
            };
            summary.instruction_count += 1;
            summary.end = summary.end.max(instruction.end);
            summary.ownership_truncated |= truncated;
        }
    }

    // One pass over the facts, folding each into the functions that own its
    // site. Facts are keyed by subject offset, and the owners of the
    // instruction at that offset are the functions the fact is about.
    let mut library_sites: BTreeMap<u32, BTreeMap<LibraryVector, usize>> = BTreeMap::new();
    let mut reads: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    let mut writes: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    let mut registers: BTreeMap<u32, BTreeSet<u16>> = BTreeMap::new();

    for fact in facts {
        match &fact.kind {
            FactKind::FunctionSignature { signature } => {
                if let Some(summary) = summaries.get_mut(&signature.entry) {
                    summary.signature = Some(signature.clone());
                }
            }
            FactKind::Call { callee, owners, .. } => {
                for owner in owners {
                    if let Some(summary) = summaries.get_mut(owner) {
                        if !summary.callees.contains(callee) {
                            summary.callees.push(*callee);
                        }
                        summary.leaf = summary.leaf.map(|_| false);
                    }
                    if let Some(target) = summaries.get_mut(callee)
                        && !target.callers.contains(owner)
                    {
                        target.callers.push(*owner);
                    }
                }
            }
            FactKind::ExternalFlow { owners, .. } => {
                for owner in owners {
                    if let Some(summary) = summaries.get_mut(owner) {
                        summary.external_calls += 1;
                        summary.leaf = summary.leaf.map(|_| false);
                    }
                }
            }
            FactKind::LibraryCall {
                lvo,
                library,
                function,
                ..
            } => {
                for owner in owners_of(analysis, fact.subject) {
                    *library_sites
                        .entry(owner)
                        .or_default()
                        .entry((library.clone(), function.clone(), *lvo))
                        .or_default() += 1;
                    if let Some(summary) = summaries.get_mut(&owner) {
                        summary.leaf = summary.leaf.map(|_| false);
                    }
                }
            }
            FactKind::HardwareAccess { offset, .. } => {
                for owner in owners_of(analysis, fact.subject) {
                    registers.entry(owner).or_default().insert(*offset);
                }
            }
            FactKind::MemoryAccess { target, access, .. } => {
                let slot = slot_name(target);
                for owner in owners_of(analysis, fact.subject) {
                    match access {
                        crate::AccessKind::Read => {
                            reads.entry(owner).or_default().insert(slot.clone());
                        }
                        crate::AccessKind::Write => {
                            writes.entry(owner).or_default().insert(slot.clone());
                        }
                        // A modify touches the slot both ways. Taking its
                        // address touches it neither way — a pointer is not a
                        // read of what it points at — and an undetermined
                        // direction is not evidence of either.
                        crate::AccessKind::Modify => {
                            reads.entry(owner).or_default().insert(slot.clone());
                            writes.entry(owner).or_default().insert(slot.clone());
                        }
                        crate::AccessKind::Address | crate::AccessKind::Other => {}
                    }
                }
            }
            FactKind::UnresolvedFlow => {
                for owner in owners_of(analysis, fact.subject) {
                    if let Some(summary) = summaries.get_mut(&owner)
                        && !summary.unresolved_exits.contains(&fact.subject)
                    {
                        summary.unresolved_exits.push(fact.subject);
                    }
                }
            }
            _ => {}
        }
    }

    for (entry, summary) in &mut summaries {
        summary.callers.sort_unstable();
        summary.callees.sort_unstable();
        summary.unresolved_exits.sort_unstable();
        summary.library_calls = library_sites
            .remove(entry)
            .unwrap_or_default()
            .into_iter()
            .map(|((library, function, lvo), sites)| LibraryCallSummary {
                library,
                function,
                lvo,
                sites,
            })
            .collect();
        summary.library_calls.sort();
        summary.globals_read = reads
            .remove(entry)
            .unwrap_or_default()
            .into_iter()
            .collect();
        summary.globals_written = writes
            .remove(entry)
            .unwrap_or_default()
            .into_iter()
            .collect();
        summary.hardware_registers = registers
            .remove(entry)
            .unwrap_or_default()
            .into_iter()
            .collect();
    }
    summaries.into_values().collect()
}

/// The functions that reached the instruction at `offset`.
///
/// Empty when nothing decoded there, which is the honest answer: a fact about
/// bytes no traversal reached belongs to no function.
fn owners_of(analysis: &ControlFlowAnalysis, offset: u32) -> Vec<u32> {
    analysis
        .instructions
        .get(&offset)
        .map(|instruction| instruction.owners.iter().copied().collect())
        .unwrap_or_default()
}

/// How a memory slot is written in a summary.
///
/// Base-relative and absolute slots keep their distinct spellings: `A5+0x8` and
/// `0x00021000` are different claims about where a global lives, and merging
/// them into one number would assert a base the report may not have.
fn slot_name(target: &MemoryAddressing) -> String {
    match target {
        MemoryAddressing::BaseRelative {
            register,
            displacement,
        } => {
            if *displacement < 0 {
                format!("A{register}-{:#x}", displacement.unsigned_abs())
            } else {
                format!("A{register}+{displacement:#x}")
            }
        }
        MemoryAddressing::Absolute { address } => format!("{address:#010x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Confidence, Producer};

    fn fact(subject: u32, kind: FactKind) -> Fact {
        Fact {
            subject,
            kind,
            confidence: Confidence::Certain,
            producer: Producer::ControlFlow,
            evidence: Vec::new(),
        }
    }

    /// `NOP` then `RTS`, repeated: two-instruction routines at every multiple
    /// of four, which is enough shape for ownership, spans, and counts.
    ///
    /// The analysis is the traversal's own rather than one the test asserted
    /// into place, so a summary that disagrees with real ownership fails here.
    fn routines(count: usize) -> Vec<u8> {
        let mut code = Vec::new();
        for _ in 0..count {
            code.extend_from_slice(&[0x4e, 0x71, 0x4e, 0x75]);
        }
        code
    }

    #[test]
    fn a_span_covers_every_instruction_the_traversal_reached() {
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0]);
        let summaries = summarize(&analysis, &[], Completeness::Complete);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].entry, 0);
        assert_eq!(
            summaries[0].end, 4,
            "NOP and RTS, so the span is four bytes"
        );
        assert_eq!(summaries[0].instruction_count, 2);
        assert_eq!(
            summaries[0].leaf,
            Some(true),
            "a routine that calls nothing is a leaf"
        );
    }

    #[test]
    fn shared_code_is_counted_by_every_owner_that_reached_it() {
        // Two entries into one routine: the second falls in at the RTS, so that
        // instruction is reached by both. Hand-written MC68000 shares tails
        // routinely, and each summary counts what it reached.
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0, 2]);
        let summaries = summarize(&analysis, &[], Completeness::Complete);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].entry, 0);
        assert_eq!(summaries[0].instruction_count, 2);
        assert_eq!(summaries[1].entry, 2);
        assert_eq!(summaries[1].instruction_count, 1);
    }

    #[test]
    fn calls_fill_both_sides_of_the_edge() {
        let code = routines(2);
        let analysis = crate::analyze_entries(&code, &[0, 4]);
        let facts = vec![fact(
            0,
            FactKind::Call {
                callee: 4,
                owners: vec![0],
                owner_total: 1,
            },
        )];
        let summaries = summarize(&analysis, &facts, Completeness::Complete);
        assert_eq!(summaries[0].callees, vec![4]);
        assert_eq!(
            summaries[0].leaf,
            Some(false),
            "a function that calls is not a leaf"
        );
        assert_eq!(summaries[1].callers, vec![0]);
        assert_eq!(
            summaries[1].leaf,
            Some(true),
            "the callee itself calls nothing"
        );
    }

    #[test]
    fn a_library_call_makes_a_function_non_leaf_even_unnamed() {
        // The base could not be inferred, so the vector has no name. It is
        // still a call, and hiding it until it can be named would lose the only
        // trace of it.
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = vec![fact(
            0,
            FactKind::LibraryCall {
                register: 6,
                lvo: -552,
                library: None,
                function: None,
                arguments: Vec::new(),
                public: true,
            },
        )];
        let summaries = summarize(&analysis, &facts, Completeness::Complete);
        assert_eq!(summaries[0].leaf, Some(false));
        assert_eq!(summaries[0].library_calls.len(), 1);
        assert_eq!(summaries[0].library_calls[0].lvo, -552);
        assert!(summaries[0].library_calls[0].library.is_none());
        assert_eq!(summaries[0].library_calls[0].sites, 1);
    }

    #[test]
    fn a_modify_counts_both_ways_and_an_address_of_counts_neither() {
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = vec![
            fact(
                0,
                FactKind::MemoryAccess {
                    target: MemoryAddressing::BaseRelative {
                        register: 5,
                        displacement: 8,
                    },
                    access: crate::AccessKind::Modify,
                    size: Some(2),
                    value: None,
                    library_base: false,
                },
            ),
            fact(
                2,
                FactKind::MemoryAccess {
                    target: MemoryAddressing::Absolute { address: 0x2_1000 },
                    access: crate::AccessKind::Address,
                    size: None,
                    value: None,
                    library_base: false,
                },
            ),
        ];
        let summaries = summarize(&analysis, &facts, Completeness::Complete);
        assert_eq!(summaries[0].globals_read, vec!["A5+0x8".to_owned()]);
        assert_eq!(summaries[0].globals_written, vec!["A5+0x8".to_owned()]);
        // Taking a pointer is not a read of what it points at.
        assert!(!summaries[0].globals_read.contains(&"0x00021000".to_owned()));
        assert!(
            !summaries[0]
                .globals_written
                .contains(&"0x00021000".to_owned())
        );
    }

    #[test]
    fn hardware_accesses_are_collected_as_register_offsets() {
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = vec![
            fact(
                0,
                FactKind::HardwareAccess {
                    offset: 0x180,
                    form: crate::AccessForm::Absolute,
                    access: crate::AccessKind::Write,
                },
            ),
            fact(
                2,
                FactKind::HardwareAccess {
                    offset: 0x096,
                    form: crate::AccessForm::Absolute,
                    access: crate::AccessKind::Write,
                },
            ),
        ];
        let summaries = summarize(&analysis, &facts, Completeness::Complete);
        // Offsets, in offset order: naming them is the renderer's job, and this
        // crate does not know the custom-chip map.
        assert_eq!(summaries[0].hardware_registers, vec![0x096, 0x180]);
    }

    #[test]
    fn an_unresolved_exit_is_listed_once_per_site() {
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = vec![
            fact(0, FactKind::UnresolvedFlow),
            fact(0, FactKind::UnresolvedFlow),
        ];
        let summaries = summarize(&analysis, &facts, Completeness::Complete);
        assert_eq!(summaries[0].unresolved_exits, vec![0]);
    }

    #[test]
    fn a_partial_fact_list_answers_the_leaf_question_with_nothing() {
        // The defect this guards: folding a filtered list would see no call
        // facts and announce a caller as a leaf. Absence is only evidence when
        // the list is known to be complete.
        let code = routines(2);
        let analysis = crate::analyze_entries(&code, &[0, 4]);
        let facts = vec![fact(
            0,
            FactKind::Call {
                callee: 4,
                owners: vec![0],
                owner_total: 1,
            },
        )];
        // The same analysis, folded from a list that dropped the call.
        let narrowed = summarize(&analysis, &[], Completeness::Partial);
        assert!(
            narrowed.iter().all(|summary| summary.leaf.is_none()),
            "a narrowed summary claimed to know what a function does not call"
        );
        // And with the whole list, the answer is available again.
        let complete = summarize(&analysis, &facts, Completeness::Complete);
        assert_eq!(complete[0].leaf, Some(false));
    }

    #[test]
    fn a_capped_ownership_makes_every_leaf_answer_unavailable() {
        // A traversal refused at the owner cap stops walking, so the refused
        // function is missing from the call facts and has no way to learn it.
        // That makes every absence-derived claim in the analysis unreliable.
        let entries: Vec<u32> = (0..=crate::control_flow::MAX_INSTRUCTION_OWNERS as u32)
            .map(|index| index * 4)
            .collect();
        let mut code = routines(entries.len());
        // Make every routine fall through into the last one, so one
        // instruction is reached by more owners than the cap accepts.
        for entry in &entries[..entries.len() - 1] {
            let index = *entry as usize;
            code[index] = 0x60; // BRA.W
            code[index + 1] = 0x00;
            let displacement = (code.len() - 2 - (index + 2)) as u16;
            code[index + 2] = (displacement >> 8) as u8;
            code[index + 3] = (displacement & 0xff) as u8;
        }
        let analysis = crate::analyze_entries(&code, &entries);
        let summaries = summarize(&analysis, &[], Completeness::Complete);
        assert!(
            summaries.iter().all(|summary| summary.leaf.is_none()),
            "a capped analysis still claimed to know what a function calls"
        );
    }

    #[test]
    fn a_fact_about_bytes_nothing_reached_belongs_to_no_function() {
        // The honest answer for a fact whose subject no traversal decoded: it
        // is in the report, and it is in no function's header.
        let code = routines(1);
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = vec![fact(0x400, FactKind::UnresolvedFlow)];
        let summaries = summarize(&analysis, &facts, Completeness::Complete);
        assert!(
            summaries
                .iter()
                .all(|summary| summary.unresolved_exits.is_empty())
        );
    }
}
