//! Narrowing a report: which part of it, and which kinds of fact.
//!
//! A report of a whole hunk answers every question at once, which is the same
//! as answering none of them. Narrowing is therefore not a convenience but the
//! way the report is read: pick a function, a range, or an entry, and keep only
//! the categories of fact the question is about.
//!
//! ## A narrowed report says so
//!
//! Every narrowing produces an [`Exclusions`] record alongside the kept facts,
//! counting what each cut removed. That is the stage's acceptance criterion —
//! a filtered report states what it excluded, and a narrowed report is never
//! mistakable for a complete one — and it is why filtering returns a struct
//! instead of a plain `Vec`: a caller cannot render the kept facts without also
//! holding the count of what it dropped.
//!
//! ## Selection is by *ownership*, not by address
//!
//! Selecting a function keeps the facts about the instructions that function
//! reached, wherever they sit. Selecting an address range keeps the facts whose
//! subject falls inside it. Those are different questions — a shared tail
//! belongs to both of its owners but sits in one address range — and conflating
//! them would silently answer the other one.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::control_flow::ControlFlowAnalysis;
use crate::report::{Confidence, Fact, FactKind};

/// Which part of the report to keep.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Selection {
    /// Everything the analysis produced.
    #[default]
    Whole,
    /// The facts about instructions this function reached, plus the facts about
    /// the entry itself.
    Function { entry: u32 },
    /// The facts whose subject lies in `start..end`.
    Range { start: u32, end: u32 },
}

impl Selection {
    /// Whether this selection keeps everything.
    #[must_use]
    pub const fn is_whole(&self) -> bool {
        matches!(self, Self::Whole)
    }

    /// Whether a function belongs in a narrowed report's index.
    ///
    /// A range selects by address, so it keeps a function when any instruction
    /// that function reached lies inside it — the same ownership/address
    /// distinction the fact selection makes, applied to the header. Without
    /// this, a narrowed report's index would list functions whose facts it
    /// dropped, which is the contradiction the narrowing exists to avoid.
    #[must_use]
    pub fn admits_function(&self, analysis: &ControlFlowAnalysis, entry: u32) -> bool {
        match self {
            Self::Whole => true,
            Self::Function { entry: selected } => entry == *selected,
            Self::Range { start, end } => {
                analysis.instructions.iter().any(|(offset, instruction)| {
                    (*start..*end).contains(offset) && instruction.owners.contains(&entry)
                })
            }
        }
    }

    /// A one-line description, for the header a narrowed report must carry.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Whole => "whole hunk".to_owned(),
            Self::Function { entry } => format!("function {entry:#x}"),
            Self::Range { start, end } => format!("offsets {start:#x}..{end:#x}"),
        }
    }
}

/// Which categories of fact to keep.
///
/// A category is a *question*, not a fact kind: "what does this touch in
/// hardware" spans several kinds, and a reader asking it does not know or care
/// which producer emitted what.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Function entries, calls, and transfers that leave the hunk.
    Flow,
    /// Library vectors and the base inference behind them.
    Library,
    /// Custom-chip register accesses.
    Hardware,
    /// Memory slots this code reads.
    Reads,
    /// Memory slots this code writes.
    Writes,
    /// References, reverse references, relocations, and symbols.
    References,
    /// Fixed-point idioms, clamps, and Q scales.
    Arithmetic,
    /// Everything a reader should look at: unresolved flow, conflicting
    /// inferences, disputed targets, and undecoded referenced regions.
    Warnings,
}

impl Category {
    /// Every category, in the order a listing shows them.
    pub const ALL: &'static [Self] = &[
        Self::Flow,
        Self::Library,
        Self::Hardware,
        Self::Reads,
        Self::Writes,
        Self::References,
        Self::Arithmetic,
        Self::Warnings,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::Library => "library",
            Self::Hardware => "hardware",
            Self::Reads => "reads",
            Self::Writes => "writes",
            Self::References => "references",
            Self::Arithmetic => "arithmetic",
            Self::Warnings => "warnings",
        }
    }

    /// Parse a category name, or `None` when nothing goes by that name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|category| category.as_str() == name)
    }
}

/// Which categories one fact belongs to.
///
/// A memory access belongs to `Reads` or `Writes` by its direction, and a
/// read-modify-write belongs to both: asking for writes and being shown a
/// modify is right, and hiding it would be wrong.
#[must_use]
pub fn categories(fact: &Fact) -> Vec<Category> {
    match &fact.kind {
        FactKind::Function { .. }
        | FactKind::FunctionSignature { .. }
        | FactKind::Call { .. }
        | FactKind::ExternalFlow { .. } => {
            vec![Category::Flow]
        }
        FactKind::LibraryCall { .. } => vec![Category::Library],
        FactKind::LibraryConflict { .. } => vec![Category::Library, Category::Warnings],
        FactKind::HardwareAccess { access, .. } => {
            let mut categories = vec![Category::Hardware];
            categories.extend(access_categories(*access));
            categories
        }
        FactKind::MemoryAccess { access, .. } => access_categories(*access),
        FactKind::Reference { .. }
        | FactKind::ReferencedBy { .. }
        | FactKind::Relocation { .. }
        | FactKind::Symbol { .. } => vec![Category::References],
        FactKind::FixedPoint { .. } | FactKind::Clamp { .. } | FactKind::QScale { .. } => {
            vec![Category::Arithmetic]
        }
        FactKind::UnresolvedFlow => vec![Category::Flow, Category::Warnings],
        FactKind::DataRegion { .. } | FactKind::TargetConflict { .. } => vec![Category::Warnings],
    }
}

fn access_categories(access: crate::AccessKind) -> Vec<Category> {
    match access {
        crate::AccessKind::Read => vec![Category::Reads],
        crate::AccessKind::Write => vec![Category::Writes],
        crate::AccessKind::Modify => vec![Category::Reads, Category::Writes],
        // An address-of and an undetermined direction are neither a read nor a
        // write; claiming either would answer a question the access does not.
        crate::AccessKind::Address | crate::AccessKind::Other => Vec::new(),
    }
}

/// What to keep, as a request.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub selection: Selection,
    /// Categories to keep. Empty keeps every category, which is what a caller
    /// that named none meant.
    pub categories: BTreeSet<Category>,
    /// The weakest confidence to keep. `None` keeps every confidence.
    pub minimum_confidence: Option<Confidence>,
}

impl Filter {
    /// Whether this filter would keep everything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selection.is_whole() && self.categories.is_empty() && self.minimum_confidence.is_none()
    }
}

/// What one filtering removed, by reason.
///
/// Separate counts rather than a total: "outside the selection" and "below the
/// confidence floor" are different things to have hidden from a reader, and a
/// single number would let one hide behind the other.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Exclusions {
    pub by_selection: usize,
    pub by_category: usize,
    pub by_confidence: usize,
}

impl Exclusions {
    #[must_use]
    pub const fn total(self) -> usize {
        self.by_selection + self.by_category + self.by_confidence
    }

    #[must_use]
    pub const fn any(self) -> bool {
        self.total() > 0
    }
}

/// How strong a claim one confidence level makes, for the floor to compare.
///
/// Deliberately *not* `Confidence`'s own `Ord`: that order is the report's
/// deterministic sort order, and it happens to place `User` last. Filtering by
/// it would drop configured symbols and other user assertions first, which are
/// exactly the facts a reader most wants kept — a person saying "this is
/// `init_gfx`" is not weaker evidence than an observation.
///
/// `Certain` and `User` are peers rather than ranked against each other: one is
/// proved by the encoding, the other asserted by someone who knows the program,
/// and neither is a weaker kind of claim than the other.
const fn strength(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Certain | Confidence::User => 4,
        Confidence::Inferred => 3,
        Confidence::Probable => 2,
        Confidence::Observed => 1,
    }
}

/// The kept facts and what was left out.
#[derive(Clone, Debug, Default)]
pub struct Filtered {
    pub facts: Vec<Fact>,
    pub exclusions: Exclusions,
}

/// Apply `filter` to `facts`.
///
/// Each fact is tested against the selection first, then the categories, then
/// the confidence floor, and the first test it fails is the one it is counted
/// under. That ordering is what makes the counts readable: a fact outside the
/// selection was never a candidate for the other two.
#[must_use]
pub fn apply(analysis: &ControlFlowAnalysis, facts: &[Fact], filter: &Filter) -> Filtered {
    let mut filtered = Filtered::default();
    for fact in facts {
        if !selected(analysis, fact, &filter.selection) {
            filtered.exclusions.by_selection += 1;
            continue;
        }
        if !filter.categories.is_empty()
            && !categories(fact)
                .iter()
                .any(|category| filter.categories.contains(category))
        {
            filtered.exclusions.by_category += 1;
            continue;
        }
        if let Some(minimum) = filter.minimum_confidence
            && strength(fact.confidence) < strength(minimum)
        {
            filtered.exclusions.by_confidence += 1;
            continue;
        }
        filtered.facts.push(fact.clone());
    }
    filtered
}

/// Whether `fact` survives `selection`.
fn selected(analysis: &ControlFlowAnalysis, fact: &Fact, selection: &Selection) -> bool {
    match selection {
        Selection::Whole => true,
        Selection::Function { entry } => {
            // The entry's own facts, plus every fact about an instruction this
            // function reached. Ownership, not address: a shared tail belongs
            // to each owner that reached it.
            fact.subject == *entry
                || analysis
                    .instructions
                    .get(&fact.subject)
                    .is_some_and(|instruction| instruction.owners.contains(entry))
        }
        Selection::Range { start, end } => (*start..*end).contains(&fact.subject),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Producer;

    fn fact(subject: u32, kind: FactKind, confidence: Confidence) -> Fact {
        Fact {
            subject,
            kind,
            confidence,
            producer: Producer::ControlFlow,
            evidence: Vec::new(),
        }
    }

    /// Two `NOP; RTS` routines, analyzed from both entries.
    fn analysis() -> ControlFlowAnalysis {
        let code = [0x4e, 0x71, 0x4e, 0x75, 0x4e, 0x71, 0x4e, 0x75];
        crate::analyze_entries(&code, &[0, 4])
    }

    #[test]
    fn selecting_a_function_follows_ownership_rather_than_addresses() {
        let analysis = analysis();
        let facts = vec![
            fact(0, FactKind::UnresolvedFlow, Confidence::Certain),
            fact(4, FactKind::UnresolvedFlow, Confidence::Certain),
        ];
        let filter = Filter {
            selection: Selection::Function { entry: 4 },
            ..Filter::default()
        };
        let filtered = apply(&analysis, &facts, &filter);
        assert_eq!(filtered.facts.len(), 1);
        assert_eq!(filtered.facts[0].subject, 4);
        assert_eq!(filtered.exclusions.by_selection, 1);
        assert!(filtered.exclusions.any(), "a narrowed report says so");
    }

    #[test]
    fn selecting_a_range_is_a_different_question_from_selecting_a_function() {
        let analysis = analysis();
        let facts = vec![
            fact(0, FactKind::UnresolvedFlow, Confidence::Certain),
            fact(2, FactKind::UnresolvedFlow, Confidence::Certain),
            fact(4, FactKind::UnresolvedFlow, Confidence::Certain),
        ];
        let filter = Filter {
            selection: Selection::Range { start: 2, end: 5 },
            ..Filter::default()
        };
        let filtered = apply(&analysis, &facts, &filter);
        assert_eq!(
            filtered
                .facts
                .iter()
                .map(|fact| fact.subject)
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
        assert_eq!(filtered.exclusions.by_selection, 1);
    }

    #[test]
    fn a_narrowed_index_lists_only_the_functions_its_facts_belong_to() {
        let analysis = analysis();
        assert!(Selection::Whole.admits_function(&analysis, 4));
        assert!(Selection::Function { entry: 4 }.admits_function(&analysis, 4));
        assert!(!Selection::Function { entry: 4 }.admits_function(&analysis, 0));
        // A range selects by address, and keeps the functions that reached it.
        let range = Selection::Range { start: 4, end: 8 };
        assert!(range.admits_function(&analysis, 4));
        assert!(!range.admits_function(&analysis, 0));
    }

    #[test]
    fn a_modify_survives_a_filter_for_either_direction() {
        // Asking for writes and being shown a read-modify-write is right;
        // hiding it would be wrong.
        let analysis = analysis();
        let modify = fact(
            0,
            FactKind::MemoryAccess {
                target: crate::report::MemoryAddressing::Absolute { address: 0x100 },
                access: crate::AccessKind::Modify,
                size: Some(2),
                value: None,
                library_base: false,
            },
            Confidence::Certain,
        );
        for category in [Category::Reads, Category::Writes] {
            let filter = Filter {
                categories: BTreeSet::from([category]),
                ..Filter::default()
            };
            let filtered = apply(&analysis, std::slice::from_ref(&modify), &filter);
            assert_eq!(filtered.facts.len(), 1, "{category:?} lost the modify");
        }
    }

    #[test]
    fn a_confidence_floor_keeps_everything_at_least_as_strong() {
        let analysis = analysis();
        let facts = vec![
            fact(0, FactKind::UnresolvedFlow, Confidence::Certain),
            fact(0, FactKind::UnresolvedFlow, Confidence::Inferred),
            fact(0, FactKind::UnresolvedFlow, Confidence::Observed),
        ];
        let filter = Filter {
            minimum_confidence: Some(Confidence::Inferred),
            ..Filter::default()
        };
        let filtered = apply(&analysis, &facts, &filter);
        assert_eq!(filtered.facts.len(), 2);
        assert_eq!(filtered.exclusions.by_confidence, 1);
    }

    #[test]
    fn a_user_assertion_survives_every_floor_the_analysis_can_meet() {
        // A configured symbol is not weaker evidence than an observation, and a
        // floor that dropped it first would hide exactly what a reader most
        // wants kept.
        let analysis = analysis();
        let facts = vec![
            fact(
                0,
                FactKind::Symbol {
                    addr: 0,
                    name: "init_gfx".to_owned(),
                },
                Confidence::User,
            ),
            fact(0, FactKind::UnresolvedFlow, Confidence::Observed),
        ];
        let filter = Filter {
            minimum_confidence: Some(Confidence::Certain),
            ..Filter::default()
        };
        let filtered = apply(&analysis, &facts, &filter);
        assert_eq!(filtered.facts.len(), 1);
        assert_eq!(filtered.facts[0].confidence, Confidence::User);
        assert_eq!(filtered.exclusions.by_confidence, 1);
    }

    #[test]
    fn each_exclusion_is_counted_under_the_first_test_it_failed() {
        // A fact outside the selection was never a candidate for the category
        // or the confidence test, so counting it once, under the reason that
        // actually removed it, is what makes the numbers readable.
        let analysis = analysis();
        let facts = vec![fact(4, FactKind::UnresolvedFlow, Confidence::Observed)];
        let filter = Filter {
            selection: Selection::Function { entry: 0 },
            categories: BTreeSet::from([Category::Hardware]),
            minimum_confidence: Some(Confidence::Certain),
        };
        let filtered = apply(&analysis, &facts, &filter);
        assert_eq!(filtered.exclusions.by_selection, 1);
        assert_eq!(filtered.exclusions.by_category, 0);
        assert_eq!(filtered.exclusions.by_confidence, 0);
        assert_eq!(filtered.exclusions.total(), 1);
    }

    #[test]
    fn an_empty_filter_keeps_everything_and_excludes_nothing() {
        let analysis = analysis();
        let facts = vec![fact(0, FactKind::UnresolvedFlow, Confidence::Observed)];
        let filtered = apply(&analysis, &facts, &Filter::default());
        assert_eq!(filtered.facts.len(), 1);
        assert!(!filtered.exclusions.any());
        assert!(Filter::default().is_empty());
    }

    #[test]
    fn every_category_parses_from_the_name_it_prints() {
        for category in Category::ALL {
            assert_eq!(Category::parse(category.as_str()), Some(*category));
        }
        assert_eq!(Category::parse("nonsense"), None);
    }
}
