//! Results of the `provenance.*` operations.
use super::*;

/// The `provenance.manifest` result: what a manifest for this source would say.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ManifestResult {
    pub source: SourcePin,
    /// The identity the request named, echoed back. A manifest is about a named
    /// thing, and the resolver's identity is the only name that means the same
    /// on another machine.
    pub name: String,
}

/// The `provenance.manifest.export` result: the same summary, plus the plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ManifestExportResult {
    pub manifest: ManifestResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}
