//! Cancellation reaches inside the survey, not just around it.
//!
//! The point of the checkpoints is that a superseded request stops occupying
//! the worker. A test that only proved "cancelled requests are discarded" would
//! pass against the behavior this replaced, so these assert where the work
//! stops and that a stopped scan reports nothing at all.

use std::sync::atomic::{AtomicBool, Ordering};

/// A signal that fires after a fixed number of checks. Deterministic, so a test
/// can name exactly which checkpoint a scan is expected to stop at.
struct FireAfter(std::cell::Cell<usize>);

impl amiga_core::Cancel for FireAfter {
    fn is_cancelled(&self) -> bool {
        let remaining = self.0.get();
        if remaining == 0 {
            return true;
        }
        self.0.set(remaining - 1);
        false
    }
}

/// Several checkpoints' worth of input with locatable content near the end.
fn large_input() -> Vec<u8> {
    let mut bytes = vec![0_u8; amiga_core::BYTES_PER_CHECKPOINT * 4];
    bytes.extend_from_slice(b"A LOCATABLE STRING NEAR THE END");
    bytes
}

#[test]
fn an_uncancelled_survey_covers_the_whole_input() {
    let bytes = large_input();
    let survey = amiga_analysis::survey_detailed_cancellable(&bytes, 6, &amiga_core::Never)
        .expect("a signal that never fires cannot cancel");
    let last = survey.regions.last().expect("the survey covers the input");
    assert_eq!(last.end, bytes.len(), "the survey did not reach the end");
    assert!(
        survey
            .regions
            .iter()
            .any(|region| region.kind == amiga_analysis::SurveyKind::Strings),
        "the trailing string was not located: {:?}",
        survey.regions
    );
}

#[test]
fn a_cancelled_survey_reports_nothing_rather_than_a_partial_map() {
    let bytes = large_input();
    // Stop inside the very first locator, before the Copper, palette, and
    // module scans have run at all.
    let signal = FireAfter(std::cell::Cell::new(1));
    assert_eq!(
        amiga_analysis::survey_detailed_cancellable(&bytes, 6, &signal),
        Err(amiga_core::Cancelled),
        "a partial survey is indistinguishable from a complete map of a \
         featureless file, so it must not be returned"
    );
}

#[test]
fn a_survey_stops_before_the_hard_input_bound() {
    // The whole complaint: an already-cancelled scan must not run to the end of
    // its input first. `FireAfter(0)` fires at the first checkpoint, which the
    // string locator reaches before reading any byte.
    let bytes = large_input();
    let already = FireAfter(std::cell::Cell::new(0));
    assert_eq!(
        amiga_analysis::survey_detailed_cancellable(&bytes, 6, &already),
        Err(amiga_core::Cancelled)
    );

    // The same through the shared worker signal a frontend actually holds.
    let token = AtomicBool::new(true);
    assert_eq!(
        amiga_analysis::survey_detailed_cancellable(&bytes, 6, &token),
        Err(amiga_core::Cancelled)
    );
    token.store(false, Ordering::Relaxed);
    assert!(amiga_analysis::survey_detailed_cancellable(&bytes, 6, &token).is_ok());
}

#[test]
fn the_plain_survey_is_the_cancellable_one_with_a_signal_that_never_fires() {
    let bytes = large_input();
    let plain = amiga_analysis::survey_detailed(&bytes, 6);
    let cancellable = amiga_analysis::survey_detailed_cancellable(&bytes, 6, &amiga_core::Never)
        .expect("never cancels");
    assert_eq!(plain.regions, cancellable.regions);
    assert_eq!(plain.copper_lists.len(), cancellable.copper_lists.len());
}
