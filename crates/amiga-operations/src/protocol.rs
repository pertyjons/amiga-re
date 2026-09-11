//! The request transport envelope and the shared status vocabulary.
//!
//! Everything here is a **wire type**: it carries serde and a protocol version,
//! and its serialized shape is the contract. Wire types convert into the
//! separate internal representation in [`normalize`](mod@crate::normalize), which carries
//! neither, so internals stay free to change without moving a serialized field.

use serde::{Deserialize, Serialize};

use crate::request::OperationRequestDocument;

/// The protocol version this build reads and writes.
pub const PROTOCOL_VERSION: u32 = 1;

/// One operation request as it crosses a process boundary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub protocol_version: u32,
    /// Caller-chosen correlation id, echoed on the response. Never part of the
    /// request digest: it does not change what bytes are read or written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The project an operation runs against.
    ///
    /// Present from version 1, so the envelope never needed reshaping when the
    /// project operations landed. It is required by those, accepted but not
    /// required by `analysis.table.decode` — which reads bytes, but may be told
    /// what a record looks like by naming a struct the project defines — and
    /// refused by every other operation, which is decided once in `normalize`
    /// rather than per handler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectLocator>,
    #[serde(default)]
    pub execution: ExecutionOptions,
    pub request: OperationRequestDocument,
}

impl RequestEnvelope {
    /// A read-only request for `request` at the current protocol version.
    #[must_use]
    pub fn read(request: OperationRequestDocument) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: None,
            project: None,
            execution: ExecutionOptions::default(),
            request,
        }
    }

    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

/// How a caller names the project an operation runs against.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectLocator {
    Path { path: String },
}

/// How the caller wants the operation executed and reported.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOptions {
    #[serde(default)]
    pub mode: ExecutionMode,
    #[serde(default)]
    pub events: EventMode,
}

/// What the caller authorizes the operation to do.
///
/// A tagged union rather than a boolean, so committing a reviewed write plan
/// carries the digest it was authorized against instead of trusting that the
/// plan has not changed since the caller saw it.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionMode {
    /// Read and report. Nothing outside the process may change.
    #[default]
    Read,
    /// Produce a complete write plan for review, writing nothing.
    Prepare,
    /// Write the plan whose canonical digest is `approved_plan_sha256`.
    CommitReviewed { approved_plan_sha256: String },
}

/// Whether the caller wants intermediate events or only the final response.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventMode {
    #[default]
    FinalOnly,
    /// Progress and diagnostic events ahead of the final response.
    ///
    /// A hint to the adapter, not a change to the operation: a handler reports
    /// the same events either way, and this says whether the caller wants them
    /// written down. Never part of the request digest for that reason.
    Stream,
}

/// How an operation ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// A read completed or a reviewed write was committed.
    Success,
    /// A complete write plan exists and was deliberately not committed.
    Prepared,
    Cancelled,
    /// An input or a destination changed under an optimistic-concurrency check.
    Conflict,
    Error,
}

/// Process exit code for a status, before request-validation refinement.
///
/// Deliberately coarse: detail belongs in the status and the diagnostic codes,
/// not in the exit code.
impl Status {
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success | Self::Prepared => 0,
            Self::Error => 1,
            Self::Cancelled => 3,
            Self::Conflict => 4,
        }
    }
}

/// The exit code for a request refused before any work ran.
pub const EXIT_INVALID_REQUEST: u8 = 2;
