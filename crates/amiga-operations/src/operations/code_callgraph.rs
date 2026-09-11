//! `analysis.code.callgraph` — which routine calls which.
//!
//! The graph reduction is separate from `analysis.code.disassemble`: traversal records
//! one edge per `(caller, site, callee)` triple, while the graph groups caller/callee
//! pairs, counts their sites, and derives degrees. Computing these once gives callers
//! consistent connectivity measurements.
//!
//! The names are not here. A node is an offset, and an address when an origin
//! is in effect; what a routine is *called* comes from a config table or a
//! project, both of which are a frontend's own.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedCodeCallgraph;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    CallgraphEdge, CallgraphNode, CodeCallgraphResult, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedCodeCallgraph,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisCodeCallgraph,
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

    let hunk = match super::code::locate(source.bytes(), request.hunk, &request.entries) {
        Ok(hunk) => hunk,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let analysis = hunk.analyze(&request.entries, request.origin);
    let graph = amiga_disasm::callgraph(&analysis);
    events.emit(OperationEvent::Progress {
        phase: "build_callgraph",
        completed: graph.nodes.len() as u64,
        total: Some(graph.nodes.len() as u64),
    });

    let node_total = graph.nodes.len();
    let edge_total = graph.edges.len();
    let nodes_truncated = node_total > request.maximum_nodes;
    let edges_truncated = edge_total > request.maximum_edges;
    if nodes_truncated || edges_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the graph has {node_total} nodes and {edge_total} edges; \
                 {} and {} are reported",
                request.maximum_nodes, request.maximum_edges
            ),
        ));
    }
    let address_of = |offset: u32| request.origin.and_then(|origin| origin.checked_add(offset));

    let result = CodeCallgraphResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        origin: request.origin,
        entries: request.entries.clone(),
        nodes: graph
            .nodes
            .iter()
            .take(request.maximum_nodes)
            .map(|node| CallgraphNode {
                function: node.function,
                address: address_of(node.function),
                in_degree: node.in_degree as u64,
                out_degree: node.out_degree as u64,
            })
            .collect(),
        node_total: node_total as u64,
        nodes_truncated,
        edges: graph
            .edges
            .iter()
            .take(request.maximum_edges)
            .map(|edge| CallgraphEdge {
                caller: edge.caller,
                callee: edge.callee,
                calls: edge.calls as u64,
            })
            .collect(),
        edge_total: edge_total as u64,
        edges_truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::AnalysisCodeCallgraph(result)),
    )
}
