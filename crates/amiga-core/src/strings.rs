//! Printable-string scanning.
//!
//! The fastest way into an unknown Amiga binary is often its text: menu labels,
//! table names, and version stamps. This finds runs of printable ASCII and
//! reports each with the offset it started at.

/// A run of printable text found in a byte buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundString {
    /// Byte offset of the first character within the scanned buffer.
    pub offset: usize,
    pub text: String,
}

/// The default minimum run length.
pub const DEFAULT_MIN_LENGTH: usize = 4;

/// Whether `byte` is printable ASCII (a graphic character or a space).
fn is_printable(byte: u8) -> bool {
    byte.is_ascii_graphic() || byte == b' '
}

/// Find runs of printable ASCII at least `min_length` bytes long in `bytes`.
///
/// A `min_length` of zero is treated as one. Runs are separated by any
/// non-printable byte and returned in ascending offset order.
#[must_use]
pub fn scan(bytes: &[u8], min_length: usize) -> Vec<FoundString> {
    // The cancellable scan with a signal that never fires; there is one
    // implementation, so the two cannot disagree about what a string is. The
    // error arm is unreachable, since `Never` cannot fire.
    scan_cancellable(bytes, min_length, &crate::cancel::Never).unwrap_or_default()
}

/// [`scan`], stopping at a block boundary when `cancel` fires.
///
/// Checked every [`crate::cancel::BYTES_PER_CHECKPOINT`] bytes rather than per
/// byte: the check must be lost in the noise of the scan, and a block is small
/// enough that stopping is prompt on any realistic input.
///
/// # Errors
/// Returns [`crate::cancel::Cancelled`] rather than the strings found so far. A
/// truncated list that looked complete would be worse than not stopping.
pub fn scan_cancellable(
    bytes: &[u8],
    min_length: usize,
    cancel: &impl crate::cancel::Cancel,
) -> crate::cancel::Cancellable<Vec<FoundString>> {
    let min_length = min_length.max(1);
    let mut found = Vec::new();
    let mut start = 0;
    let mut run = 0_usize;
    for (index, byte) in bytes.iter().enumerate() {
        if index.is_multiple_of(crate::cancel::BYTES_PER_CHECKPOINT) {
            crate::checkpoint!(cancel);
        }
        if is_printable(*byte) {
            if run == 0 {
                start = index;
            }
            run += 1;
        } else {
            if run >= min_length {
                found.push(FoundString {
                    offset: start,
                    text: latin1(&bytes[start..index]),
                });
            }
            run = 0;
        }
    }
    if run >= min_length {
        found.push(FoundString {
            offset: start,
            text: latin1(&bytes[start..]),
        });
    }
    Ok(found)
}

/// Decode `bytes` as Latin-1 text: each byte maps to the code point of the same
/// value. This is how fixed-width names and labels are stored in Amiga
/// structures (BCPL names, IFF ids, LHA method tags).
#[must_use]
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// Like [`latin1`] but stops at the first NUL byte (a C-style string).
#[must_use]
pub fn latin1_cstr(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    latin1(&bytes[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_separated_runs_with_offsets() {
        let data = b"\x00\x011 PLAYER\x00\x00MAPSIZE\xff";
        let found = scan(data, 4);
        assert_eq!(
            found,
            vec![
                FoundString {
                    offset: 2,
                    text: "1 PLAYER".to_owned(),
                },
                FoundString {
                    offset: 12,
                    text: "MAPSIZE".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn respects_the_minimum_length() {
        let data = b"ok\x00longer";
        assert_eq!(
            scan(data, 4),
            vec![FoundString {
                offset: 3,
                text: "longer".to_owned()
            }]
        );
    }

    #[test]
    fn captures_a_run_that_reaches_the_end() {
        let data = b"\x00tail";
        assert_eq!(
            scan(data, 4),
            vec![FoundString {
                offset: 1,
                text: "tail".to_owned()
            }]
        );
    }

    #[test]
    fn a_zero_minimum_is_treated_as_one() {
        assert_eq!(
            scan(b"\x00a\x00", 0),
            vec![FoundString {
                offset: 1,
                text: "a".to_owned()
            }]
        );
    }

    /// A signal that fires after a fixed number of checks, so a test can say
    /// exactly where a scan is expected to stop.
    struct FireAfter(std::cell::Cell<usize>);

    impl crate::cancel::Cancel for FireAfter {
        fn is_cancelled(&self) -> bool {
            let remaining = self.0.get();
            if remaining == 0 {
                return true;
            }
            self.0.set(remaining - 1);
            false
        }
    }

    #[test]
    fn a_cancelled_scan_stops_before_the_end_and_reports_nothing() {
        use crate::cancel::{BYTES_PER_CHECKPOINT, Cancelled, Never};

        // Four checkpoints' worth of input, with a string at the very end that
        // only a complete scan can reach.
        let mut data = vec![0_u8; BYTES_PER_CHECKPOINT * 4];
        data.extend_from_slice(b"THE LAST STRING");

        // Uncancelled, the scan finds it.
        let complete = scan_cancellable(&data, 4, &Never).expect("never cancels");
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].text, "THE LAST STRING");

        // Cancelled at the second checkpoint, it stops — and reports nothing
        // rather than an empty-looking result a caller might install.
        let signal = FireAfter(std::cell::Cell::new(1));
        assert_eq!(scan_cancellable(&data, 4, &signal), Err(Cancelled));

        // Firing on the very first checkpoint stops before any byte is read.
        let immediate = FireAfter(std::cell::Cell::new(0));
        assert_eq!(scan_cancellable(&data, 4, &immediate), Err(Cancelled));
    }

    #[test]
    fn the_plain_scan_is_the_cancellable_one_with_a_signal_that_never_fires() {
        let data = b"\x00\x011 PLAYER\x00\x00MAPSIZE\xff";
        assert_eq!(
            scan(data, 4),
            scan_cancellable(data, 4, &crate::cancel::Never).expect("never cancels")
        );
    }

    #[test]
    fn latin1_maps_every_byte() {
        assert_eq!(latin1(b"SampleProject"), "SampleProject");
        assert_eq!(latin1(&[0xe9]), "é"); // Latin-1 0xE9
    }

    #[test]
    fn latin1_cstr_stops_at_the_first_nul() {
        assert_eq!(latin1_cstr(b"TEST\0junk"), "TEST");
        assert_eq!(latin1_cstr(b"nonul"), "nonul");
    }
}
