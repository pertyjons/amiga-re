//! How much of a program's library-call vocabulary the analysis actually
//! explains, and what stops the rest.
//!
//! ## Why this exists
//!
//! The roadmap's Stage 4 carries a stop decision: *measure how often arguments
//! resolve on real programs; do not proceed to a much larger ABI database if
//! the current dataflow cannot usefully consume it.* That decision needs a
//! number, and more than a number — it needs to know **which** limitation is
//! costing the values, because the answers point at different work:
//!
//! - a program dominated by [`Unresolved::UnknownRegister`] or by sites with no
//!   argument description at all is limited by its **tables**, and extending the
//!   fd/ABI coverage is what buys resolution;
//! - a program dominated by [`Unresolved::Join`], [`Unresolved::WriteNotValued`],
//!   or [`Unresolved::UnresolvedFlow`] is limited by the **walk**, and no
//!   quantity of new ABI entries will change it — a control-flow-aware abstract
//!   interpretation is what would.
//!
//! Without the split, a low resolution rate is unreadable: it looks equally like
//! a small table and a short-sighted tracker, and those want opposite next
//! steps.
//!
//! ## Folded from facts, never recomputed
//!
//! Everything here is derived from a [`Fact`] list, so the numbers a report
//! prints are reproducible from the JSON that report already emits. Nothing
//! re-runs the analysis, and there is no second path by which a count could
//! disagree with the facts it summarizes.
//!
//! That also fixes the scope: these describe **the facts they were given**. Fold
//! a narrowed report and the counters describe the narrowing, which is only
//! honest if the caller says so — see the scope labelling in the `disasm report`
//! renderers.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::constants::Unresolved;
use crate::report::{Fact, FactKind};

/// What a library-call site's arguments could be described as.
///
/// Exclusive: every site is exactly one of these, so the three counts partition
/// [`ResolutionStats::sites`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Description {
    /// The base register's library could not be inferred, so nothing could be
    /// looked up for the vector at all.
    UnknownLibrary,
    /// The library is known but no table describes the vector's arguments.
    /// The gap is in the tables.
    Undescribed,
    /// A table described at least one argument register.
    Described,
}

impl Description {
    /// Classify a site from whether its library was inferred and whether any
    /// table described its arguments.
    ///
    /// An unknown library outranks an empty argument list: a site nobody could
    /// attribute was never looked up, so calling it undescribed would blame the
    /// tables for a failure that happened before they were consulted.
    #[must_use]
    pub fn of(has_library: bool, has_arguments: bool) -> Self {
        match (has_library, has_arguments) {
            (false, _) => Self::UnknownLibrary,
            (true, false) => Self::Undescribed,
            (true, true) => Self::Described,
        }
    }
}

/// Library-call resolution counted over one fact list.
///
/// Two independent partitions of [`Self::sites`] are recorded, because "did we
/// name it" and "could we value it" are different questions with different
/// remedies:
///
/// - naming: [`Self::unknown_library`] + [`Self::named`] + [`Self::unnamed_vector`];
/// - description: [`Self::unknown_library`] + [`Self::described`] + [`Self::undescribed`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ResolutionStats {
    /// Library-call sites in the fact list.
    pub sites: usize,
    /// Sites whose base library could not be inferred — including the ones
    /// where several candidates conflicted, because a conflict is never given a
    /// winner. They are also the sites that can carry no arguments, which is
    /// why they appear in both partitions.
    pub unknown_library: usize,
    /// Sites with both a library and a name for the vector.
    pub named: usize,
    /// Sites with a library but no name for the vector.
    pub unnamed_vector: usize,
    /// Sites where a table described at least one argument register.
    pub described: usize,
    /// Sites with a library but no argument description.
    pub undescribed: usize,
    /// Described argument registers across every site.
    pub arguments: usize,
    /// Described arguments whose value bounded dataflow established.
    pub resolved: usize,
    /// Described arguments retained as a symbolic memory expression. These are
    /// useful findings, but deliberately do not count as exact resolutions.
    pub symbolic: usize,
    /// Why the rest have neither an exact nor symbolic value, counted per
    /// reason. Reasons with no
    /// occurrences are absent rather than zero, so the map lists what actually
    /// happened; iterate [`Unresolved::all`] to render a complete histogram.
    pub reasons: BTreeMap<Unresolved, usize>,
}

impl ResolutionStats {
    /// Fold every [`FactKind::LibraryCall`] in `facts` into one summary.
    #[must_use]
    pub fn from_facts(facts: &[Fact]) -> Self {
        let mut stats = Self::default();
        for fact in facts {
            let FactKind::LibraryCall {
                library,
                function,
                arguments,
                ..
            } = &fact.kind
            else {
                continue;
            };
            stats.sites += 1;
            match (library, function) {
                (None, _) => stats.unknown_library += 1,
                (Some(_), Some(_)) => stats.named += 1,
                (Some(_), None) => stats.unnamed_vector += 1,
            }
            match Description::of(library.is_some(), !arguments.is_empty()) {
                Description::UnknownLibrary => {}
                Description::Described => stats.described += 1,
                Description::Undescribed => stats.undescribed += 1,
            }
            for argument in arguments {
                stats.arguments += 1;
                match (&argument.value, &argument.symbolic, argument.unresolved) {
                    (Some(_), None, None) => stats.resolved += 1,
                    (None, Some(_), None) => stats.symbolic += 1,
                    (None, None, Some(reason)) => {
                        *stats.reasons.entry(reason).or_default() += 1;
                    }
                    // Neither: an argument description that never met a call
                    // site. `collect` does not produce one, so it is counted as
                    // unresolved-with-no-reason rather than silently as
                    // resolved, which would inflate the very rate this exists
                    // to measure.
                    (None, None, None) => {}
                    // Malformed external facts that claim more than one state
                    // contribute to no success category. `collect` itself
                    // maintains the exclusive-state invariant.
                    _ => {}
                }
            }
        }
        stats
    }

    /// Described arguments that were valued, as a percentage.
    ///
    /// Zero when nothing was described: a program whose vectors no table
    /// describes has resolved none of them, and reporting 100% of nothing would
    /// read as success.
    #[must_use]
    pub fn resolved_percent(&self) -> f64 {
        if self.arguments == 0 {
            0.0
        } else {
            self.resolved as f64 / self.arguments as f64 * 100.0
        }
    }

    /// Described arguments with neither an exact nor a symbolic value.
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.arguments
            .saturating_sub(self.resolved.saturating_add(self.symbolic))
    }

    /// The most common reason an argument had no value, with its count.
    ///
    /// Ties break toward the earlier [`Unresolved`] variant, so the answer is
    /// deterministic for the same fact list. `None` when nothing was
    /// unresolved — which includes the case where nothing was described.
    #[must_use]
    pub fn dominant_reason(&self) -> Option<(Unresolved, usize)> {
        self.reasons
            .iter()
            .max_by_key(|(reason, count)| (**count, std::cmp::Reverse(**reason)))
            .map(|(reason, count)| (*reason, *count))
    }

    /// How many unresolved arguments the walk itself refused, as opposed to
    /// ones no table could name a register for.
    ///
    /// This is the split the Stage 4 stop decision turns on: a large walk share
    /// means more ABI entries would not help, because the values would still be
    /// refused once the registers were known.
    #[must_use]
    pub fn refused_by_walk(&self) -> usize {
        self.reasons
            .iter()
            .filter(|(reason, _)| **reason != Unresolved::UnknownRegister)
            .map(|(_, count)| *count)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{
        ArgumentSymbolicValue, ArgumentValue, CallArgument, Confidence, Evidence, Producer,
        SymbolicMemorySource,
    };

    /// A library-call fact with the given identity and arguments.
    fn call(
        subject: u32,
        library: Option<&str>,
        function: Option<&str>,
        arguments: Vec<CallArgument>,
    ) -> Fact {
        Fact {
            subject,
            kind: FactKind::LibraryCall {
                register: 6,
                lvo: -552,
                library: library.map(str::to_owned),
                function: function.map(str::to_owned),
                arguments,
                public: true,
            },
            confidence: Confidence::Inferred,
            producer: Producer::LibraryInference,
            evidence: vec![Evidence::Instruction { site: subject }],
        }
    }

    fn resolved(register: &str) -> CallArgument {
        CallArgument {
            name: None,
            register: register.to_owned(),
            value: Some(ArgumentValue {
                value: 1,
                rendered: "1".to_owned(),
                site: 0,
                evidence: vec![0],
            }),
            symbolic: None,
            unresolved: None,
        }
    }

    fn refused(register: &str, reason: Unresolved) -> CallArgument {
        CallArgument {
            name: None,
            register: register.to_owned(),
            value: None,
            symbolic: None,
            unresolved: Some(reason),
        }
    }

    fn symbolic(register: &str) -> CallArgument {
        CallArgument {
            name: None,
            register: register.to_owned(),
            value: None,
            symbolic: Some(ArgumentSymbolicValue {
                rendered: "global(A5+$10)".to_owned(),
                subject: crate::report::SymbolicSubject::Contents,
                source: SymbolicMemorySource::GlobalRelative {
                    register: "A5".to_owned(),
                    displacement: 0x10,
                },
                offset: 0,
                site: 0,
                evidence: vec![0],
            }),
            unresolved: None,
        }
    }

    #[test]
    fn both_partitions_add_up_to_the_site_count() {
        // The two questions are independent, but each answer must cover every
        // site exactly once, or a reader could not tell a missing category from
        // a miscount.
        let facts = vec![
            call(0, None, None, Vec::new()),
            call(
                4,
                Some("exec.library"),
                Some("AllocMem"),
                vec![resolved("d0")],
            ),
            call(8, Some("exec.library"), None, Vec::new()),
            call(12, Some("dos.library"), Some("Read"), Vec::new()),
        ];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.sites, 4);
        assert_eq!(
            stats.unknown_library + stats.named + stats.unnamed_vector,
            stats.sites,
            "the naming partition lost a site"
        );
        assert_eq!(
            stats.unknown_library + stats.described + stats.undescribed,
            stats.sites,
            "the description partition lost a site"
        );
        assert_eq!(stats.described, 1);
        assert_eq!(stats.undescribed, 2);
    }

    #[test]
    fn reasons_are_counted_per_occurrence_not_per_site() {
        // Three refusals at one site are three lost values. Counting sites
        // would understate exactly the thing being measured.
        let facts = vec![call(
            0,
            Some("exec.library"),
            Some("AllocMem"),
            vec![
                refused("d0", Unresolved::Join),
                refused("d1", Unresolved::Join),
                refused("a1", Unresolved::WriteNotValued),
            ],
        )];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.arguments, 3);
        assert_eq!(stats.resolved, 0);
        assert_eq!(stats.unresolved(), 3);
        assert_eq!(stats.reasons[&Unresolved::Join], 2);
        assert_eq!(stats.reasons[&Unresolved::WriteNotValued], 1);
        assert_eq!(stats.dominant_reason(), Some((Unresolved::Join, 2)));
    }

    #[test]
    fn symbolic_arguments_are_counted_without_inflating_exact_resolution() {
        let facts = vec![call(
            0,
            Some("exec.library"),
            Some("AllocMem"),
            vec![
                resolved("d0"),
                symbolic("d1"),
                refused("a1", Unresolved::Call),
            ],
        )];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.arguments, 3);
        assert_eq!(stats.resolved, 1);
        assert_eq!(stats.symbolic, 1);
        assert_eq!(stats.unresolved(), 1);
        assert_eq!(stats.refused_by_walk(), 1);
    }

    #[test]
    fn a_tie_breaks_the_same_way_every_time() {
        // Two reasons with equal counts must not depend on map iteration luck;
        // a measurement that moves between runs cannot settle an argument.
        let facts = vec![call(
            0,
            Some("exec.library"),
            Some("AllocMem"),
            vec![
                refused("d0", Unresolved::WriteNotValued),
                refused("d1", Unresolved::Join),
            ],
        )];
        let stats = ResolutionStats::from_facts(&facts);
        for _ in 0..8 {
            assert_eq!(
                ResolutionStats::from_facts(&facts).dominant_reason(),
                stats.dominant_reason()
            );
        }
        // Join is declared before WriteNotValued, so it wins the tie.
        assert_eq!(stats.dominant_reason(), Some((Unresolved::Join, 1)));
    }

    #[test]
    fn the_walks_share_excludes_a_register_no_table_could_name() {
        // The whole point of the split: an unparsable register is a table
        // defect, and counting it as a walk refusal would argue for the wrong
        // next stage.
        let facts = vec![call(
            0,
            Some("exec.library"),
            Some("AllocMem"),
            vec![
                refused("d0", Unresolved::Join),
                refused("zz", Unresolved::UnknownRegister),
                refused("q9", Unresolved::UnknownRegister),
            ],
        )];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.unresolved(), 3);
        assert_eq!(stats.refused_by_walk(), 1);
    }

    #[test]
    fn nothing_described_resolves_none_of_it() {
        // Not 100%: a program no table describes has explained no arguments,
        // and a full-marks percentage over an empty set reads as success.
        let facts = vec![call(0, Some("exec.library"), Some("AllocMem"), Vec::new())];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.arguments, 0);
        assert!((stats.resolved_percent() - 0.0).abs() < f64::EPSILON);
        assert_eq!(stats.dominant_reason(), None);
    }

    #[test]
    fn an_argument_that_never_met_a_call_site_is_not_counted_as_resolved() {
        // `collect` never produces this empty state, but a caller assembling
        // facts by hand could. It must not inflate either success count.
        let facts = vec![call(
            0,
            Some("exec.library"),
            Some("AllocMem"),
            vec![CallArgument::new(None, "d0".to_owned())],
        )];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.arguments, 1);
        assert_eq!(stats.resolved, 0);
        assert_eq!(stats.unresolved(), 1);
        assert!(stats.reasons.is_empty());
    }

    #[test]
    fn facts_that_are_not_library_calls_are_ignored() {
        let facts = vec![
            Fact {
                subject: 0,
                kind: FactKind::UnresolvedFlow,
                confidence: Confidence::Certain,
                producer: Producer::ControlFlow,
                evidence: vec![Evidence::Instruction { site: 0 }],
            },
            call(
                4,
                Some("exec.library"),
                Some("AllocMem"),
                vec![resolved("d0")],
            ),
        ];
        let stats = ResolutionStats::from_facts(&facts);
        assert_eq!(stats.sites, 1);
        assert_eq!(stats.resolved, 1);
        assert!((stats.resolved_percent() - 100.0).abs() < f64::EPSILON);
    }
}
