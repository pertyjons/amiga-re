//! Explicit bounded-work policy.
//!
//! An effective limit is the minimum of what the context allows and what the request
//! asks for. Every reduction is reported, so callers share a bounded-work policy.

/// Bytes of a single source an operation may read into memory.
///
/// The default ceiling is 64 MiB; callers can configure a bounded context for larger
/// sources.
pub const DEFAULT_MAXIMUM_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// Bytes one decompression operation may produce.
///
/// Compressed input can expand far beyond its source size, so the input ceiling
/// cannot bound the allocation. The decoder checks this output ceiling before
/// every append rather than trusting a stream-declared length.
pub const DEFAULT_MAXIMUM_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// Regions a single survey response may carry.
///
/// The region count grows with the input: string findings merge only within a
/// few bytes, so an input of short printable runs separated by wider gaps
/// yields roughly one region per run plus one per gap. At the input ceiling
/// above that is hundreds of thousands of regions, each with a detail string
/// and possibly a palette vector — not a response to hold in memory, let alone
/// send across a process boundary.
pub const DEFAULT_MAXIMUM_REGIONS: usize = 65_536;

/// Directory entries a single container listing may carry.
///
/// A floppy image cannot hold this many, but nothing restricts a caller to
/// floppy-sized images, and the directory walk is bounded by the image rather
/// than by anything the response can hold.
pub const DEFAULT_MAXIMUM_ENTRIES: usize = 65_536;

/// Pixels a single decoded bitmap may carry.
///
/// A planar decode's cost is its *output*, not its input: a few kilobytes of
/// source with an absurd width and height asks for gigabytes of indices. The
/// bound is checked from the declared geometry before anything is allocated.
/// 64 megapixels is far above any Amiga screen and still refuses a decode that
/// could only be a typo or an attack.
pub const DEFAULT_MAXIMUM_OUTPUT_PIXELS: usize = 64 * 1024 * 1024;

/// Shortest printable run `source.survey` reports when a request names none.
///
/// Six, because shorter runs are dominated by accidental ASCII in code and
/// data, and a survey whose regions are mostly noise is one nobody reads.
pub const DEFAULT_SURVEY_MIN_STRING_LENGTH: usize = 6;

// --- aggregate ceilings ------------------------------------------------------
//
// Every limit above bounds one *thing*: one source read, one response, one
// decode. The project operations are the first that fan out — `project.init`
// takes an arbitrary number of files, and `project.extract` recovers every
// member of every one of them into memory before writing anything — so a
// per-thing bound multiplied by a count nothing bounds is not a bound. These
// are ceilings on the aggregate, and they do not replace the per-thing ones:
// both apply.

/// Files one `project.init` may register.
///
/// A project is a person's working set — the disks of one game, a handful of
/// executables — not a corpus. Two hundred and fifty-six is far above any
/// plausible set and still refuses a directory glob that caught the wrong tree.
pub const DEFAULT_MAXIMUM_SOURCES: usize = 256;

/// Bytes an operation may read across *all* of its sources.
///
/// One gibibyte: sixteen sources at the per-source ceiling. The per-source
/// bound still applies to each, so this is what stops a hundred legal sources
/// from being an illegal amount of memory.
pub const DEFAULT_MAXIMUM_TOTAL_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// Objects one plan may create.
///
/// `maximum_entries` bounds one carrier's directory; this bounds the product of
/// that and the carrier count, which is what a multi-disk extraction actually
/// produces.
pub const DEFAULT_MAXIMUM_OBJECTS: usize = 65_536;

/// Instructions a sandbox run may execute when the context says nothing.
///
/// Sandbox code is unknown code, and a routine that never returns is common while
/// identifying one. The budget is therefore finite whatever a request asks for, with a
/// default of two hundred thousand steps.
pub const DEFAULT_MAXIMUM_SANDBOX_STEPS: usize = 200_000;

/// The highest ceiling a context may raise the sandbox budget to.
///
/// The default exists so an absent or mistyped budget cannot hang the process.
/// It is also below what a real initialization routine needs: one that decodes
/// graphics, builds geometry tables, and runs a palette-transition loop can
/// legitimately run for millions of instructions, and splitting such a run
/// loses the excluded call stack and so cannot reproduce the same state. A host
/// running local media the caller has reviewed may therefore raise it — to a
/// number, never to none.
///
/// **Fifty million, and the number is now bounded by time alone.** It used to
/// be bounded by memory: a run's peak grew with its length, because the write
/// log kept one entry per write — about sixty megabytes at the previous
/// five-million ceiling, and more with any raise. Both of the structures that
/// did that are capped now (`amiga_disasm::DEFAULT_RETAINED_WRITES` and
/// `amiga_disasm::DEFAULT_RETAINED_STEPS`), each counting past its cap so a
/// truncated record cannot read as a complete one, and the remaining cost —
/// the dirty bitmap `changed_regions` walks — is one bit per mapped byte
/// whatever the run does.
///
/// Measured, not estimated, by `amiga_disasm`'s `measure_run_cost`: a run of
/// fifty million instructions over a four-megabyte map peaks at **21.7 MB**,
/// against 21.4 MB for a run of five million over the same map. That is the
/// property the raise depends on — peak memory follows the map, not the step
/// count — and it is why the ceiling is a time budget now. The same run takes
/// 0.8 seconds; a write-heavy one driving emulated devices is an order of
/// magnitude slower, which puts the worst case in the tens of seconds.
///
/// The default below is unchanged and is what an absent or mistyped budget
/// gets. This is only what a host running local media the caller has reviewed
/// may raise it to — a number, never none.
pub const MAXIMUM_SANDBOX_STEPS_CEILING: usize = 50_000_000;

/// Cases one `env.sandbox.matrix` may expand when the context says nothing.
///
/// A matrix exists so that exhaustive verification stops being a shell loop, and
/// the real ones are not small: seven templates across four quadrants is 28, and
/// a surface-boundary sweep is in the hundreds. Two hundred and fifty-six covers
/// both with room, and is still a number rather than "as many as the request
/// asks for".
///
/// What actually bounds the *work* is [`DEFAULT_MAXIMUM_MATRIX_STEPS`]: the case
/// count alone would let 256 cases of fifty million instructions each through.
pub const DEFAULT_MAXIMUM_MATRIX_CASES: usize = 256;

/// The highest case count a context may raise a matrix to.
///
/// Four thousand and change, which is the same order as the largest sweep the
/// downstream request describes (1,335 surface-boundary comparisons) with room
/// for one an order of magnitude larger. Every case costs a full sandbox
/// preparation — the source is re-read, the map rebuilt, the seeds re-resolved —
/// so the count bounds setup work that the step budget does not see.
pub const MAXIMUM_MATRIX_CASES_CEILING: usize = 4096;

/// Instructions a whole matrix may execute when its request says nothing.
///
/// **The matrix as a whole gets one run's budget.** That is deliberately
/// conservative: the per-case cap already bounds a single case, and multiplying
/// it by the case ceiling would put the aggregate at fifty billion instructions,
/// which is hours. A caller who needs more raises this explicitly, and the
/// ceiling it may raise it to is [`MAXIMUM_SANDBOX_STEPS_CEILING`] — so a matrix
/// can cost as much as the longest single run a host permits, and no more.
///
/// A case is never given a *reduced* budget to fit what is left. It either runs
/// with the budget it asked for or is reported as not run: a case silently
/// clipped to the remaining allowance would stop for a reason that says nothing
/// about the routine, and read in the record exactly like one that ran out on
/// its own.
pub const DEFAULT_MAXIMUM_MATRIX_STEPS: usize = DEFAULT_MAXIMUM_SANDBOX_STEPS;

/// Datapath words a run's blits may perform when the context says nothing.
///
/// A datapath word is one iteration of the blitter's inner loop — `width ×
/// height` for a blit — counted regardless of how many channels are enabled and
/// regardless of whether the destination writes, because what is bounded is the
/// work rather than the traffic. Refused blits are charged too: the preflight
/// that refuses one is itself proportional to the blit, so a refusal loop that
/// cost nothing would leave the expensive half unbounded.
///
/// Four million and change is about 160 full-screen five-plane clears, which is
/// a frame's drawing with room to spare.
pub const DEFAULT_MAXIMUM_SANDBOX_BLIT_WORDS: u64 = 4_194_304;

/// The highest ceiling a context may raise the blit budget to.
///
/// **Measured, not estimated.** `crates/amiga-hw/benches/blit_throughput.rs`
/// reproduces the worst case this crate's own bounds permit — four channels, a
/// sixteen-region map scanned linearly, and 64 watchpoints compared on every
/// access — and on a Core i7-13700H it costs **177 ns per datapath word**. With
/// one mapped region and nothing watched the same blit costs **20 ns**, a
/// ninefold spread between two legal recipes, which is why the bound is set from
/// the expensive one.
///
/// So this ceiling is 5.9 seconds of worst-case blitting, the same order as
/// [`MAXIMUM_SANDBOX_STEPS_CEILING`]'s own justification, and the default above
/// is 0.74 seconds. Re-run the benchmark before changing either — an earlier
/// draft of this work put the ceiling at 2^28 and called it "a few seconds",
/// which measures at forty-seven.
///
/// Unlike the step ceiling, what binds here is **time rather than memory**: DMA
/// writes never enter the write log, so a long blit does not grow a run.
pub const MAXIMUM_SANDBOX_BLIT_WORDS_CEILING: u64 = 33_554_432;

/// Bytes a plan may hold recovered in memory at once.
///
/// Recovering every member of every carrier before writing is what makes an
/// extraction refusable rather than half-done, and it is also what makes it
/// expensive. Two gibibytes is generous for any floppy-based project and still
/// a number rather than "whatever the machine has".
pub const DEFAULT_MAXIMUM_TOTAL_RECOVERED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Total mapped RAM allowed before a sandbox allocates hunks, stack or regions.
/// Dirty maps and execution telemetry have their own bounded overhead.
pub const DEFAULT_MAXIMUM_SANDBOX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// The bounds a context imposes on every operation it executes.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationLimits {
    maximum_input_bytes: u64,
    maximum_output_bytes: u64,
    maximum_regions: usize,
    maximum_entries: usize,
    maximum_output_pixels: usize,
    maximum_sources: usize,
    maximum_total_input_bytes: u64,
    maximum_objects: usize,
    maximum_total_recovered_bytes: u64,
    maximum_sandbox_steps: usize,
    maximum_sandbox_memory_bytes: u64,
    maximum_sandbox_blit_words: u64,
    maximum_matrix_cases: usize,
}

impl Default for OperationLimits {
    fn default() -> Self {
        Self {
            maximum_input_bytes: DEFAULT_MAXIMUM_INPUT_BYTES,
            maximum_output_bytes: DEFAULT_MAXIMUM_OUTPUT_BYTES,
            maximum_regions: DEFAULT_MAXIMUM_REGIONS,
            maximum_entries: DEFAULT_MAXIMUM_ENTRIES,
            maximum_output_pixels: DEFAULT_MAXIMUM_OUTPUT_PIXELS,
            maximum_sources: DEFAULT_MAXIMUM_SOURCES,
            maximum_total_input_bytes: DEFAULT_MAXIMUM_TOTAL_INPUT_BYTES,
            maximum_objects: DEFAULT_MAXIMUM_OBJECTS,
            maximum_total_recovered_bytes: DEFAULT_MAXIMUM_TOTAL_RECOVERED_BYTES,
            maximum_sandbox_steps: DEFAULT_MAXIMUM_SANDBOX_STEPS,
            maximum_sandbox_memory_bytes: DEFAULT_MAXIMUM_SANDBOX_MEMORY_BYTES,
            maximum_sandbox_blit_words: DEFAULT_MAXIMUM_SANDBOX_BLIT_WORDS,
            maximum_matrix_cases: DEFAULT_MAXIMUM_MATRIX_CASES,
        }
    }
}

impl OperationLimits {
    /// Total mapped RAM permitted for each sandbox preparation.
    #[must_use]
    pub const fn maximum_sandbox_memory_bytes(self) -> u64 {
        self.maximum_sandbox_memory_bytes
    }

    /// Set the shared hunk, stack and additional-region allocation budget.
    #[must_use = "use the returned limits to configure the context"]
    pub const fn with_maximum_sandbox_memory_bytes(mut self, bytes: u64) -> Self {
        self.maximum_sandbox_memory_bytes = bytes;
        self
    }

    /// Source reading and graph retention bounds used by project verification.
    pub const fn verification_limits(self) -> amiga_project::verify::VerificationLimits {
        amiga_project::verify::VerificationLimits {
            maximum_source_bytes: self.maximum_input_bytes,
            maximum_total_source_bytes: self.maximum_total_input_bytes,
            maximum_object_bytes: self.maximum_output_bytes,
            maximum_retained_bytes: self.maximum_total_recovered_bytes,
        }
    }

    /// Instructions a sandbox run may execute under this context.
    #[must_use]
    pub const fn maximum_sandbox_steps(self) -> usize {
        self.maximum_sandbox_steps
    }

    /// Raise (or lower) the sandbox budget this context permits.
    ///
    /// Clamped to [`MAXIMUM_SANDBOX_STEPS_CEILING`]: a host may state that its
    /// media is local and reviewed, and it may not state that a run is
    /// unbounded. A request still names its own budget and still has it
    /// reduced, with `LIMIT_REDUCED`, when it asks for more than this.
    pub const fn with_maximum_sandbox_steps(mut self, steps: usize) -> Self {
        self.maximum_sandbox_steps = if steps > MAXIMUM_SANDBOX_STEPS_CEILING {
            MAXIMUM_SANDBOX_STEPS_CEILING
        } else {
            steps
        };
        self
    }

    /// Cases one matrix may expand under this context.
    ///
    /// Also the steps one `env.sandbox.timeline` may state. The two are the same
    /// bound — how many sandbox runs a single request expands into — and giving
    /// a timeline its own would be a second number nobody would keep in step
    /// with this one.
    #[must_use]
    pub const fn maximum_matrix_cases(self) -> usize {
        self.maximum_matrix_cases
    }

    /// Raise (or lower) the case count this context permits.
    ///
    /// Clamped to [`MAXIMUM_MATRIX_CASES_CEILING`], for the reason every other
    /// ceiling here exists: a host may say its media is local and reviewed, and
    /// may not say a run is unbounded.
    pub const fn with_maximum_matrix_cases(mut self, cases: usize) -> Self {
        self.maximum_matrix_cases = if cases > MAXIMUM_MATRIX_CASES_CEILING {
            MAXIMUM_MATRIX_CASES_CEILING
        } else {
            cases
        };
        self
    }

    /// Datapath words a run's blits may perform under this context.
    #[must_use]
    pub const fn maximum_sandbox_blit_words(self) -> u64 {
        self.maximum_sandbox_blit_words
    }

    /// Raise (or lower) the blit budget this context permits.
    ///
    /// Clamped to [`MAXIMUM_SANDBOX_BLIT_WORDS_CEILING`], for the same reason
    /// the step budget is clamped: a host may say its media is local and
    /// reviewed, and it may not say that a blit is unbounded.
    pub const fn with_maximum_sandbox_blit_words(mut self, words: u64) -> Self {
        self.maximum_sandbox_blit_words = if words > MAXIMUM_SANDBOX_BLIT_WORDS_CEILING {
            MAXIMUM_SANDBOX_BLIT_WORDS_CEILING
        } else {
            words
        };
        self
    }

    /// Maximum bytes read from one input, including a project artifact.
    #[must_use]
    pub const fn maximum_input_bytes(self) -> u64 {
        self.maximum_input_bytes
    }

    #[must_use]
    pub const fn maximum_regions(self) -> usize {
        self.maximum_regions
    }

    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn maximum_output_bytes(self) -> u64 {
        self.maximum_output_bytes
    }

    pub const fn with_maximum_output_bytes(mut self, bytes: u64) -> Self {
        self.maximum_output_bytes = bytes;
        self
    }

    pub const fn with_maximum_regions(mut self, regions: usize) -> Self {
        self.maximum_regions = regions;
        self
    }

    #[must_use]
    pub const fn maximum_entries(self) -> usize {
        self.maximum_entries
    }

    pub const fn with_maximum_entries(mut self, entries: usize) -> Self {
        self.maximum_entries = entries;
        self
    }

    #[must_use]
    pub const fn maximum_output_pixels(self) -> usize {
        self.maximum_output_pixels
    }

    pub const fn with_maximum_output_pixels(mut self, pixels: usize) -> Self {
        self.maximum_output_pixels = pixels;
        self
    }

    #[must_use]
    pub const fn maximum_sources(self) -> usize {
        self.maximum_sources
    }

    pub const fn with_maximum_sources(mut self, sources: usize) -> Self {
        self.maximum_sources = sources;
        self
    }

    /// Aggregate input allowance. Project verification gives the source pass
    /// and the artifact pass separate allowances of this size. Actual reads
    /// are charged even when the file's digest does not match its record;
    /// bounded readers may consume one extra byte per file to detect overflow.
    #[must_use]
    pub const fn maximum_total_input_bytes(self) -> u64 {
        self.maximum_total_input_bytes
    }

    pub const fn with_maximum_total_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_total_input_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn maximum_objects(self) -> usize {
        self.maximum_objects
    }

    pub const fn with_maximum_objects(mut self, objects: usize) -> Self {
        self.maximum_objects = objects;
        self
    }

    #[must_use]
    pub const fn maximum_total_recovered_bytes(self) -> u64 {
        self.maximum_total_recovered_bytes
    }

    pub const fn with_maximum_total_recovered_bytes(mut self, bytes: u64) -> Self {
        self.maximum_total_recovered_bytes = bytes;
        self
    }
}

/// A request-settable limit resolved against the context's own ceiling.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveLimit<T> {
    /// The value the operation will actually enforce.
    pub value: T,
    /// Whether the request asked for more than the context allows.
    pub reduced: bool,
}

impl<T: Ord + Copy> EffectiveLimit<T> {
    /// Resolve `requested` against `ceiling`, taking the smaller of the two.
    pub fn resolve(requested: Option<T>, ceiling: T) -> Self {
        match requested {
            Some(requested) if requested > ceiling => Self {
                value: ceiling,
                reduced: true,
            },
            Some(requested) => Self {
                value: requested,
                reduced: false,
            },
            None => Self {
                value: ceiling,
                reduced: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_aggregate_ceiling_is_never_tighter_than_the_per_thing_one() {
        // Both apply, so an aggregate below its per-thing counterpart would make
        // the per-thing bound unreachable — a source at exactly the per-source
        // ceiling would be refused for being one of one. That is the kind of
        // limit interaction nobody notices until a legal input is refused with a
        // message naming the wrong bound.
        let limits = OperationLimits::default();
        assert!(limits.maximum_input_bytes() <= limits.maximum_total_input_bytes());
        assert!(limits.maximum_entries() <= limits.maximum_objects());
        // And a project must be able to hold at least one source at the
        // per-source ceiling, or `project.init` could never accept a full disk.
        assert!(limits.maximum_sources() >= 1);
        assert!(limits.maximum_total_recovered_bytes() >= limits.maximum_input_bytes());
    }

    #[test]
    fn every_aggregate_ceiling_is_settable_and_reads_back() {
        let limits = OperationLimits::default()
            .with_maximum_sources(2)
            .with_maximum_total_input_bytes(3)
            .with_maximum_objects(4)
            .with_maximum_total_recovered_bytes(5);
        assert_eq!(limits.maximum_sources(), 2);
        assert_eq!(limits.maximum_total_input_bytes(), 3);
        assert_eq!(limits.maximum_objects(), 4);
        assert_eq!(limits.maximum_total_recovered_bytes(), 5);
    }

    #[test]
    fn the_decompressed_output_ceiling_is_settable_and_reads_back() {
        let limits = OperationLimits::default().with_maximum_output_bytes(123);
        assert_eq!(limits.maximum_output_bytes(), 123);
    }
}
