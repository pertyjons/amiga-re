//! Bounded forward dataflow over the control-flow graph's basic blocks.
//!
//! Analyses supply a deliberately small lattice and an instruction transfer.
//! This module supplies the shared mechanics: owner-local basic blocks,
//! deterministic worklist scheduling, conservative joins, and a hard work
//! bound. Exhaustion is an explicit result, so a caller can discard partial
//! precision instead of reporting a stale intermediate state.

use std::collections::{BTreeMap, BTreeSet};

use crate::control_flow::{ControlFlowAnalysis, DecodedInstruction, FlowKind};

/// Maximum block visits per owned instruction before a walk is refused.
///
/// A well-formed finite lattice converges in a small multiple of the graph
/// size. The multiplier leaves room for loops and joins while ensuring a bad
/// transfer or pathological graph degrades into fewer findings, not a hang.
const MAX_WORKLIST_STEPS_PER_INSTRUCTION: usize = 8;

/// State a forward analysis propagates through the graph.
pub(crate) trait Domain: Clone + Eq {
    /// Merge `incoming` into this block's stored input state.
    ///
    /// Returns whether the stored state changed and therefore needs to be
    /// propagated again. Implementations must only lose precision at a join.
    fn join(&mut self, incoming: &Self) -> bool;
}

/// The state entering every reached instruction of one function owner.
pub(crate) struct ForwardResult<State> {
    pub(crate) before: BTreeMap<u32, State>,
    pub(crate) exhausted: bool,
}

/// Run one owner's analysis in deterministic basic-block order.
pub(crate) fn forward<State, Enter, Transfer>(
    analysis: &ControlFlowAnalysis,
    owner: u32,
    seed: State,
    enter: Enter,
    transfer: Transfer,
) -> ForwardResult<State>
where
    State: Domain,
    Enter: FnMut(u32, &DecodedInstruction, &mut State),
    Transfer: FnMut(&DecodedInstruction, &mut State),
{
    forward_with_filter_and_schedule(
        analysis,
        owner,
        seed,
        |_| true,
        enter,
        transfer,
        Schedule::Ascending,
    )
}

/// Run one owner's analysis while excluding instructions rejected by
/// `include`. This is used when a terminal transfer gives a second discovered
/// function overlapping ownership with its tail-caller.
pub(crate) fn forward_filtered<State, Include, Enter, Transfer>(
    analysis: &ControlFlowAnalysis,
    owner: u32,
    seed: State,
    include: Include,
    enter: Enter,
    transfer: Transfer,
) -> ForwardResult<State>
where
    State: Domain,
    Include: Fn(&DecodedInstruction) -> bool,
    Enter: FnMut(u32, &DecodedInstruction, &mut State),
    Transfer: FnMut(&DecodedInstruction, &mut State),
{
    forward_with_filter_and_schedule(
        analysis,
        owner,
        seed,
        include,
        enter,
        transfer,
        Schedule::Ascending,
    )
}

#[cfg(test)]
fn forward_with_schedule<State, Enter, Transfer>(
    analysis: &ControlFlowAnalysis,
    owner: u32,
    seed: State,
    enter: Enter,
    transfer: Transfer,
    schedule: Schedule,
) -> ForwardResult<State>
where
    State: Domain,
    Enter: FnMut(u32, &DecodedInstruction, &mut State),
    Transfer: FnMut(&DecodedInstruction, &mut State),
{
    forward_with_filter_and_schedule(analysis, owner, seed, |_| true, enter, transfer, schedule)
}

fn forward_with_filter_and_schedule<State, Include, Enter, Transfer>(
    analysis: &ControlFlowAnalysis,
    owner: u32,
    seed: State,
    include: Include,
    mut enter: Enter,
    mut transfer: Transfer,
    schedule: Schedule,
) -> ForwardResult<State>
where
    State: Domain,
    Include: Fn(&DecodedInstruction) -> bool,
    Enter: FnMut(u32, &DecodedInstruction, &mut State),
    Transfer: FnMut(&DecodedInstruction, &mut State),
{
    let graph = BlockGraph::new(analysis, owner, include);
    let Some(entry) = graph.instruction_blocks.get(&owner).copied() else {
        return ForwardResult {
            before: BTreeMap::new(),
            exhausted: false,
        };
    };
    let budget = graph
        .instruction_blocks
        .len()
        .saturating_mul(MAX_WORKLIST_STEPS_PER_INSTRUCTION)
        .max(1);
    let mut incoming = BTreeMap::from([(entry, seed)]);
    let mut pending = BTreeSet::from([entry]);
    let mut before = BTreeMap::new();
    let mut steps = 0_usize;

    while let Some(start) = schedule.pop(&mut pending) {
        steps = steps.saturating_add(1);
        if steps > budget {
            return ForwardResult {
                before,
                exhausted: true,
            };
        }
        let Some(block) = graph.blocks.get(&start) else {
            continue;
        };
        let Some(mut state) = incoming.get(&start).cloned() else {
            continue;
        };
        for address in &block.instructions {
            let Some(decoded) = analysis.instructions.get(address) else {
                continue;
            };
            enter(owner, decoded, &mut state);
            before.insert(*address, state.clone());
            transfer(decoded, &mut state);
        }
        for successor in &block.successors {
            match incoming.get_mut(successor) {
                Some(existing) => {
                    if existing.join(&state) {
                        pending.insert(*successor);
                    }
                }
                None => {
                    incoming.insert(*successor, state.clone());
                    pending.insert(*successor);
                }
            }
        }
    }

    ForwardResult {
        before,
        exhausted: false,
    }
}

#[derive(Clone, Copy)]
enum Schedule {
    Ascending,
    #[cfg(test)]
    Descending,
}

impl Schedule {
    fn pop(self, pending: &mut BTreeSet<u32>) -> Option<u32> {
        match self {
            Self::Ascending => pending.pop_first(),
            #[cfg(test)]
            Self::Descending => pending.pop_last(),
        }
    }
}

struct Block {
    instructions: Vec<u32>,
    successors: BTreeSet<u32>,
}

struct BlockGraph {
    blocks: BTreeMap<u32, Block>,
    instruction_blocks: BTreeMap<u32, u32>,
}

impl BlockGraph {
    fn new<Include>(analysis: &ControlFlowAnalysis, owner: u32, include: Include) -> Self
    where
        Include: Fn(&DecodedInstruction) -> bool,
    {
        let owned: BTreeSet<u32> = analysis
            .instructions
            .values()
            .filter(|decoded| decoded.owners.contains(&owner) && include(decoded))
            .map(|decoded| decoded.address)
            .collect();
        let mut successors = BTreeMap::<u32, BTreeSet<u32>>::new();
        let mut predecessors = BTreeMap::<u32, BTreeSet<u32>>::new();
        let mut branch_sites = BTreeSet::new();
        for flow in &analysis.flows {
            if flow.owner != owner
                || flow.kind == FlowKind::Call
                || !owned.contains(&flow.site)
                || !owned.contains(&flow.target)
            {
                continue;
            }
            successors.entry(flow.site).or_default().insert(flow.target);
            predecessors
                .entry(flow.target)
                .or_default()
                .insert(flow.site);
            if flow.kind == FlowKind::Branch {
                branch_sites.insert(flow.site);
            }
        }

        let mut leaders = BTreeSet::from([owner]);
        leaders.extend(
            analysis
                .functions
                .iter()
                .filter(|address| owned.contains(address))
                .copied(),
        );
        for (site, targets) in &successors {
            if branch_sites.contains(site) || targets.len() != 1 {
                leaders.extend(targets);
            }
            for target in targets {
                if predecessors
                    .get(target)
                    .is_none_or(|sites| sites.len() != 1)
                {
                    leaders.insert(*target);
                }
            }
        }

        let mut blocks = BTreeMap::new();
        let mut instruction_blocks = BTreeMap::new();
        for start in leaders.iter().chain(owned.iter()).copied() {
            if !owned.contains(&start) || instruction_blocks.contains_key(&start) {
                continue;
            }
            let mut instructions = Vec::new();
            let mut current = start;
            loop {
                if instruction_blocks.insert(current, start).is_some() {
                    break;
                }
                instructions.push(current);
                let targets = successors.get(&current);
                let Some(next) = targets
                    .filter(|targets| targets.len() == 1 && !branch_sites.contains(&current))
                    .and_then(|targets| targets.first().copied())
                else {
                    break;
                };
                if leaders.contains(&next)
                    || predecessors.get(&next).is_none_or(|sites| sites.len() != 1)
                    || instruction_blocks.contains_key(&next)
                {
                    break;
                }
                current = next;
            }
            blocks.insert(
                start,
                Block {
                    instructions,
                    successors: BTreeSet::new(),
                },
            );
        }

        for (start, block) in &mut blocks {
            let Some(last) = block.instructions.last() else {
                continue;
            };
            block.successors = successors
                .get(last)
                .into_iter()
                .flatten()
                .filter_map(|target| instruction_blocks.get(target).copied())
                .filter(|target| target != start || branch_sites.contains(last))
                .collect();
        }

        Self {
            blocks,
            instruction_blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Exact {
        Unknown,
        Value(u8),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct NeverConverges(bool);

    impl Domain for NeverConverges {
        fn join(&mut self, _: &Self) -> bool {
            self.0 = !self.0;
            true
        }
    }

    impl Domain for Exact {
        fn join(&mut self, incoming: &Self) -> bool {
            if self == incoming || matches!(self, Self::Unknown) {
                return false;
            }
            *self = Self::Unknown;
            true
        }
    }

    fn joined_value(schedule: Schedule) -> ForwardResult<Exact> {
        // TST.W D1 ; BEQ.S right ; MOVEQ #7,D0 ; BRA.S join ;
        // right: MOVEQ #7,D0 ; join: RTS
        let code = [
            0x4a, 0x41, 0x67, 0x04, 0x70, 0x07, 0x60, 0x02, 0x70, 0x07, 0x4e, 0x75,
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        forward_with_schedule(
            &analysis,
            0,
            Exact::Unknown,
            |_, _, _| {},
            |decoded, state| {
                if matches!(decoded.address, 4 | 8) {
                    *state = Exact::Value(7);
                }
            },
            schedule,
        )
    }

    #[test]
    fn block_visitation_order_does_not_change_the_fixpoint() {
        let ascending = joined_value(Schedule::Ascending);
        let descending = joined_value(Schedule::Descending);
        assert!(!ascending.exhausted);
        assert!(!descending.exhausted);
        assert_eq!(ascending.before, descending.before);
        assert_eq!(ascending.before.get(&10), Some(&Exact::Value(7)));
    }

    #[test]
    fn a_non_converging_domain_is_stopped_by_the_work_bound() {
        // BRA.S 0: one self-looping block. A deliberately invalid domain that
        // claims every join changed must be refused rather than run forever.
        let analysis = crate::analyze_entries(&[0x60, 0xfe], &[0]);
        let result = forward(&analysis, 0, NeverConverges(false), |_, _, _| {}, |_, _| {});
        assert!(result.exhausted);
    }
}
