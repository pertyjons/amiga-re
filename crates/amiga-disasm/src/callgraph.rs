//! The function/call-edge graph of a control-flow analysis.
//!
//! [`callgraph`] reduces a [`ControlFlowAnalysis`] to its functions (nodes) and
//! the call edges between them, with per-node in/out-degree and a per-edge count
//! of distinct call sites. It is a thin projection of what `analyze` already
//! recorded, exposed so a large listing can be navigated and clustered instead
//! of scrolled.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::control_flow::ControlFlowAnalysis;

/// One function in the call graph, with its degree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CallGraphNode {
    /// Hunk-relative address of the function entry.
    pub function: u32,
    /// Number of distinct functions that call this one.
    pub in_degree: usize,
    /// Number of distinct functions this one calls.
    pub out_degree: usize,
}

/// A call relationship between two functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CallGraphEdge {
    pub caller: u32,
    pub callee: u32,
    /// Number of distinct call sites in `caller` that reach `callee`.
    pub calls: usize,
}

/// The functions and call edges of an analysis.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

/// Build the call graph of `analysis`: one node per discovered function, one
/// edge per distinct `(caller, callee)` pair (collapsing multiple call sites
/// into a `calls` count), with in/out-degree computed from the collapsed edges.
#[must_use]
pub fn callgraph(analysis: &ControlFlowAnalysis) -> CallGraph {
    // `analysis.calls` holds distinct (caller, call_site, callee) triples.
    build(
        analysis.functions.iter().copied(),
        analysis.calls.iter().map(|edge| (edge.caller, edge.callee)),
    )
}

/// The same graph from the functions and call sites alone.
///
/// For a consumer that has the edges without the traversal that found them —
/// one reading them out of an operation's answer rather than computing them.
/// The collapse and the degree counting are the part worth having once: two
/// implementations of them would disagree about how many callers a function has
/// as soon as one of them forgot to deduplicate call sites.
#[must_use]
pub fn callgraph_from_edges(
    functions: impl IntoIterator<Item = u32>,
    calls: impl IntoIterator<Item = (u32, u32)>,
) -> CallGraph {
    build(functions, calls)
}

fn build(
    functions: impl IntoIterator<Item = u32>,
    calls: impl IntoIterator<Item = (u32, u32)>,
) -> CallGraph {
    // Collapse the call sites onto (caller, callee) to count them per pair.
    let mut calls_per_pair: BTreeMap<(u32, u32), usize> = BTreeMap::new();
    for (caller, callee) in calls {
        *calls_per_pair.entry((caller, callee)).or_default() += 1;
    }

    let mut out_degree: BTreeMap<u32, usize> = BTreeMap::new();
    let mut in_degree: BTreeMap<u32, usize> = BTreeMap::new();
    for (caller, callee) in calls_per_pair.keys() {
        *out_degree.entry(*caller).or_default() += 1;
        *in_degree.entry(*callee).or_default() += 1;
    }

    let nodes = functions
        .into_iter()
        .map(|function| CallGraphNode {
            function,
            in_degree: in_degree.get(&function).copied().unwrap_or(0),
            out_degree: out_degree.get(&function).copied().unwrap_or(0),
        })
        .collect();
    let edges = calls_per_pair
        .into_iter()
        .map(|((caller, callee), calls)| CallGraphEdge {
            caller,
            callee,
            calls,
        })
        .collect();

    CallGraph { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;

    #[test]
    fn counts_degrees_and_collapses_call_sites() {
        // BSR +6 (->8) ; BSR +2 (->8) ; RTS: function 0 calls function 8 twice.
        let code = [0x61, 0x00, 0x00, 0x06, 0x61, 0x00, 0x00, 0x02, 0x4e, 0x75];
        let graph = callgraph(&analyze(&code, 0));

        assert_eq!(
            graph.edges,
            [CallGraphEdge {
                caller: 0,
                callee: 8,
                calls: 2,
            }]
        );
        assert!(graph.nodes.contains(&CallGraphNode {
            function: 0,
            in_degree: 0,
            out_degree: 1,
        }));
        assert!(graph.nodes.contains(&CallGraphNode {
            function: 8,
            in_degree: 1,
            out_degree: 0,
        }));
    }

    #[test]
    fn isolated_entry_is_a_zero_degree_node() {
        // A lone RTS: one function, no edges.
        let graph = callgraph(&analyze(&[0x4e, 0x75], 0));
        assert_eq!(
            graph.nodes,
            [CallGraphNode {
                function: 0,
                in_degree: 0,
                out_degree: 0,
            }]
        );
        assert!(graph.edges.is_empty());
    }
}
