//! The JSON Lines framing an adapter writes when a caller wants progress.
//!
//! Every line carries an explicit `message_type`, and the last line is always
//! the response. A consumer dispatches on that tag and never infers a record's
//! kind from which fields happen to be present — which is what lets later
//! milestones add message kinds without breaking a reader written today.
//!
//! Note the distinction from [`crate::protocol::EventMode`]. `EventMode` is a
//! *request* field expressing an event preference; both modes are supported.
//! The framing here is an *adapter output* choice: this streaming entry point
//! forwards handler events in either request mode. Adapters requesting only a
//! final document use the non-streaming router entry point instead.

use serde::Serialize;

use crate::context::ExecutionContext;
use crate::document::ResponseEnvelope;
use crate::events::{EventSink, OperationEvent};
use crate::normalize::normalize;
use crate::protocol::{PROTOCOL_VERSION, RequestEnvelope};
use crate::request::OperationName;
use crate::response::OperationOutcome;
use crate::router::Router;

/// One line of a JSON Lines exchange.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
pub enum StreamMessage {
    /// The request was validated and normalized; the operation is about to run.
    /// Absent when the request was refused, because a refused request has no
    /// normalized form and therefore no digest to report.
    Accepted(AcceptedMessage),
    /// One event the operation reported while running. Always between
    /// [`Self::Accepted`] and [`Self::Response`].
    Event(EventMessage),
    /// The final response. Always the last line of an exchange.
    Response(Box<ResponseEnvelope>),
}

/// One event, tagged for the transport with the correlation the caller chose.
#[derive(Clone, Debug, Serialize)]
pub struct EventMessage {
    pub protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(flatten)]
    pub event: OperationEvent,
}

/// The request as accepted: what will run, and the digest of exactly what was
/// asked for, available before the operation produces anything.
#[derive(Clone, Debug, Serialize)]
pub struct AcceptedMessage {
    pub protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub operation: OperationName,
    pub normalized_request_sha256: String,
}

/// Execute `envelope`, handing each line of the exchange to `emit` as it is
/// produced, and return the outcome so the caller can still choose an exit code.
///
/// Emitting through a callback rather than returning a list is what makes this
/// a stream: an adapter writes and flushes each line immediately, and the
/// operation's own progress events arrive between `Accepted` and `Response` as
/// the handler reaches its phases rather than in a batch at the end.
pub fn execute_streaming(
    envelope: &RequestEnvelope,
    context: &ExecutionContext<'_>,
    emit: &mut dyn FnMut(StreamMessage),
) -> OperationOutcome {
    /// Turns typed events into stream lines as they arrive.
    struct ForwardingSink<'a, 'b> {
        request_id: Option<String>,
        emit: &'a mut (dyn FnMut(StreamMessage) + 'b),
    }

    impl EventSink for ForwardingSink<'_, '_> {
        fn emit(&mut self, event: OperationEvent) {
            (self.emit)(StreamMessage::Event(EventMessage {
                protocol_version: PROTOCOL_VERSION,
                request_id: self.request_id.clone(),
                event,
            }));
        }
    }

    let outcome = match normalize(envelope, context.limits()) {
        Ok(normalized) => {
            emit(StreamMessage::Accepted(AcceptedMessage {
                protocol_version: PROTOCOL_VERSION,
                request_id: envelope.request_id.clone(),
                operation: envelope.request.operation_name(),
                normalized_request_sha256: normalized.request.digest(),
            }));
            // Each event is handed to the adapter as the handler produces it,
            // so a stream is written and flushed line by line rather than
            // buffered until the operation ends.
            let mut sink = ForwardingSink {
                request_id: envelope.request_id.clone(),
                emit,
            };
            Router::execute_normalized_with(
                &normalized.request,
                context,
                normalized.diagnostics.clone(),
                &mut crate::events::BoundedSink::new(&mut sink),
            )
        }
        Err(diagnostics) => {
            OperationOutcome::refused(envelope.request.operation_name(), diagnostics)
        }
    };
    emit(StreamMessage::Response(Box::new(
        ResponseEnvelope::from_outcome(&outcome, envelope.request_id.as_deref()),
    )));
    outcome
}
