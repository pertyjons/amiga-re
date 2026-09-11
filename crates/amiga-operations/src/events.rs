//! Typed, bounded events an operation may report before its response.
//!
//! An event says something the caller can act on while work is still running —
//! a progress phase, a diagnostic that does not change the outcome. It is not a
//! log line and not a second copy of the result: the response is still the only
//! authoritative answer, and a caller that ignores every event loses nothing
//! but responsiveness.
//!
//! Two properties are load-bearing.
//!
//! **Bounded.** An event carries no byte buffer, no frontend handle, and no
//! borrowed data, so it can cross a channel or a process boundary unchanged.
//! The count is bounded too: [`BoundedSink`] stops forwarding once an operation
//! has emitted [`MAX_EVENTS`] of them and reports that it did, so a pathological
//! input cannot flood a consumer. Truncation is visible, never silent.
//!
//! **Ordered.** Events for one operation arrive in the order the handler
//! emitted them, and always before the response. That is what lets a consumer
//! treat "the response arrived" as the end of the exchange rather than a race.

use serde::Serialize;

use crate::diagnostics::Diagnostic;
use crate::request::OperationName;

/// The most events one operation may report.
///
/// Generous for a progress display, small enough that a consumer's queue is
/// bounded by a number it can reason about. An operation that wants finer
/// granularity should report a phase with a `completed`/`total` pair rather
/// than one event per unit.
pub const MAX_EVENTS: usize = 1024;

/// Something an operation reports before its response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum OperationEvent {
    /// Work has begun. Exactly one per operation that emits events at all,
    /// always first, so a consumer has a definite start to hang a UI on.
    Started { operation: OperationName },
    /// How far one named phase has got. `total` is absent when the handler
    /// genuinely does not know it yet; a consumer must render that as
    /// indeterminate rather than assuming zero.
    Progress {
        phase: &'static str,
        completed: u64,
        total: Option<u64>,
    },
    /// A finding that does not by itself decide the outcome. The same
    /// diagnostic also appears on the response, so a consumer that only reads
    /// responses still sees it; this is for showing it sooner.
    Diagnostic { diagnostic: Diagnostic },
    /// The event budget was exhausted. Always last if present, and emitted
    /// exactly once, so a truncated stream is never mistaken for a complete
    /// one.
    Truncated { emitted: usize },
}

/// Where an adapter receives events.
///
/// Implementations must not block for long: a handler calls this from inside
/// its work, and the whole point is that reporting progress costs less than the
/// progress being reported.
pub trait EventSink {
    fn emit(&mut self, event: OperationEvent);
}

/// A sink that discards everything.
///
/// The default, so a caller that wants only the final response — every
/// command-line invocation, most tests — pays nothing and no handler needs to
/// know whether anyone is listening.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEvents;

impl EventSink for NoEvents {
    fn emit(&mut self, _event: OperationEvent) {}
}

impl<T: EventSink + ?Sized> EventSink for &mut T {
    fn emit(&mut self, event: OperationEvent) {
        (**self).emit(event);
    }
}

/// Collects events into a `Vec`. For tests and for adapters that render the
/// whole exchange after the fact.
#[derive(Clone, Debug, Default)]
pub struct CollectingSink {
    events: Vec<OperationEvent>,
}

impl CollectingSink {
    #[must_use]
    pub fn events(&self) -> &[OperationEvent] {
        &self.events
    }
}

impl EventSink for CollectingSink {
    fn emit(&mut self, event: OperationEvent) {
        self.events.push(event);
    }
}

/// Wraps a sink and enforces [`MAX_EVENTS`].
///
/// The bound lives here rather than in each handler so that no handler can
/// forget it, and so the truncation notice is emitted in exactly one place.
pub struct BoundedSink<'a> {
    inner: &'a mut dyn EventSink,
    emitted: usize,
    announced: bool,
}

impl<'a> BoundedSink<'a> {
    #[must_use]
    pub fn new(inner: &'a mut dyn EventSink) -> Self {
        Self {
            inner,
            emitted: 0,
            announced: false,
        }
    }

    /// How many events reached the wrapped sink, not counting the truncation
    /// notice.
    #[must_use]
    pub const fn emitted(&self) -> usize {
        self.emitted
    }
}

impl EventSink for BoundedSink<'_> {
    fn emit(&mut self, event: OperationEvent) {
        if self.emitted < MAX_EVENTS {
            self.emitted += 1;
            self.inner.emit(event);
            return;
        }
        if !self.announced {
            self.announced = true;
            self.inner.emit(OperationEvent::Truncated {
                emitted: self.emitted,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounded_sink_stops_at_the_budget_and_says_it_did() {
        let mut collected = CollectingSink::default();
        {
            let mut bounded = BoundedSink::new(&mut collected);
            for completed in 0..(MAX_EVENTS as u64 + 50) {
                bounded.emit(OperationEvent::Progress {
                    phase: "scan",
                    completed,
                    total: None,
                });
            }
            assert_eq!(bounded.emitted(), MAX_EVENTS);
        }

        // The budget's worth, plus exactly one notice — not one per refusal.
        assert_eq!(collected.events().len(), MAX_EVENTS + 1);
        assert_eq!(
            collected.events()[MAX_EVENTS],
            OperationEvent::Truncated {
                emitted: MAX_EVENTS
            }
        );
        assert!(
            collected.events()[..MAX_EVENTS]
                .iter()
                .all(|event| matches!(event, OperationEvent::Progress { .. })),
            "the budget was spent on something other than the events emitted"
        );
    }

    #[test]
    fn a_sink_under_the_budget_gets_no_truncation_notice() {
        let mut collected = CollectingSink::default();
        {
            let mut bounded = BoundedSink::new(&mut collected);
            bounded.emit(OperationEvent::Started {
                operation: OperationName::SourceSurvey,
            });
        }
        assert_eq!(collected.events().len(), 1);
        assert!(
            !collected
                .events()
                .iter()
                .any(|event| matches!(event, OperationEvent::Truncated { .. })),
            "a complete stream was marked truncated"
        );
    }

    #[test]
    fn discarding_events_costs_the_handler_nothing_observable() {
        let mut sink = NoEvents;
        sink.emit(OperationEvent::Started {
            operation: OperationName::ContainerAdfList,
        });
        // Nothing to assert but that it compiles and does not panic: the point
        // is that a handler need not know whether anyone is listening.
    }

    #[test]
    fn every_event_names_its_kind_on_the_wire() {
        // A consumer dispatches on `event`, never on which fields are present.
        for (event, expected) in [
            (
                OperationEvent::Started {
                    operation: OperationName::SourceSurvey,
                },
                "started",
            ),
            (
                OperationEvent::Progress {
                    phase: "scan",
                    completed: 1,
                    total: Some(2),
                },
                "progress",
            ),
            (OperationEvent::Truncated { emitted: 3 }, "truncated"),
        ] {
            let json = serde_json::to_value(&event).expect("an event serializes");
            assert_eq!(json["event"], expected);
        }
    }
}
