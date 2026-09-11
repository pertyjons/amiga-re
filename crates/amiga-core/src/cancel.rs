//! Cooperative cancellation for long scans.
//!
//! A frontend that discards a stale request still pays for the work already
//! running: a single worker occupied by a large scan cannot start the next
//! request until that scan returns. Checking a stop signal only *around* an
//! operation makes cancellation correct but unresponsive.
//!
//! The answer is a signal the scan itself polls at deterministic boundaries —
//! between input blocks, candidates, or queue items — and an explicit
//! [`Cancelled`] outcome rather than a partial result. A truncated scan that
//! looked like a complete one would be worse than no cancellation at all,
//! which is the same rule the rest of this toolkit applies to tolerated
//! corruption: recovery is reported, never silent.
//!
//! A scan only needs to ask whether it should stop. The caller chooses how to signal
//! cancellation; `Arc<AtomicBool>` implements this directly without requiring a channel
//! or an async runtime.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

/// Returned by a cancellable scan that observed a stop signal.
///
/// Carries nothing: how far the scan got is deliberately not reported, because
/// a caller must not be tempted to use a partial result.
#[derive(Clone, Copy, Debug, Default, Eq, Error, PartialEq)]
#[error("cancelled before the scan completed")]
pub struct Cancelled;

/// The result of work a caller may stop.
pub type Cancellable<T> = Result<T, Cancelled>;

/// A cooperative stop signal, polled at a scan's own checkpoints.
///
/// Implementations must be cheap: a scan calls this often, and a signal that
/// costs more than the work between checkpoints defeats the purpose.
pub trait Cancel {
    /// Whether the caller has asked for the work to stop.
    fn is_cancelled(&self) -> bool;
}

/// A signal that never fires.
///
/// The whole reason the plain, non-cancelling APIs can be thin wrappers: they
/// pass this, the checkpoint compiles down to a constant `false`, and there is
/// only one implementation of each scan to keep correct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Never;

impl Cancel for Never {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// The signal a worker thread shares with the frontend that spawned it.
///
/// `Relaxed` is the right ordering: the flag is the only thing communicated,
/// and observing it one checkpoint late costs a few thousand bytes of scanning,
/// never correctness.
impl Cancel for AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}

impl<T: Cancel + ?Sized> Cancel for &T {
    fn is_cancelled(&self) -> bool {
        (**self).is_cancelled()
    }
}

impl<T: Cancel + ?Sized> Cancel for Arc<T> {
    fn is_cancelled(&self) -> bool {
        (**self).is_cancelled()
    }
}

/// Stop the enclosing function with [`Cancelled`] if `signal` has fired.
///
/// A macro rather than a helper returning `Result`, so a checkpoint reads as
/// one line at the boundary it guards and cannot be accidentally ignored.
///
/// The error is converted through [`From`], so this also works inside a
/// function whose error type is a domain enum with a cancelled variant — a
/// planar decode, say, where "cancelled" belongs beside "truncated" rather than
/// in a second `Result` layer the caller would have to unwrap twice.
#[macro_export]
macro_rules! checkpoint {
    ($signal:expr) => {
        if $crate::cancel::Cancel::is_cancelled(&$signal) {
            return ::core::result::Result::Err(::core::convert::From::from(
                $crate::cancel::Cancelled,
            ));
        }
    };
}

/// How many input bytes a byte-wise scan covers between checkpoints.
///
/// Small enough that a cancelled scan stops promptly on any realistic input,
/// large enough that the check is lost in the noise of the work itself. Being a
/// constant rather than a tuning parameter is what makes a cancellation test
/// deterministic: a test can say exactly how many checkpoints an input has.
pub const BYTES_PER_CHECKPOINT: usize = 64 * 1024;

/// How many candidates or queue items a per-item scan covers between
/// checkpoints, where an "item" is far more expensive than a byte.
pub const ITEMS_PER_CHECKPOINT: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_never_signal_never_fires() {
        assert!(!Never.is_cancelled());
        assert!(!Cancel::is_cancelled(&&Never));
    }

    #[test]
    fn a_shared_flag_is_a_signal_through_every_indirection() {
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.is_cancelled());
        flag.store(true, Ordering::Relaxed);
        assert!(flag.is_cancelled());
        // The forms a caller actually holds: the Arc, a borrow of it, and the
        // bool inside. All must answer the same, or a scan's checkpoint would
        // depend on how the caller happened to pass it.
        assert!(Cancel::is_cancelled(&&flag));
        assert!((*flag).is_cancelled());
    }

    #[test]
    fn a_checkpoint_returns_cancelled_only_when_the_signal_fired() {
        fn work(signal: &impl Cancel) -> Cancellable<u32> {
            checkpoint!(signal);
            Ok(7)
        }
        assert_eq!(work(&Never), Ok(7));
        assert_eq!(work(&AtomicBool::new(true)), Err(Cancelled));
    }
}
