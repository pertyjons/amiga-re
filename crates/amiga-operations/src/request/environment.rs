//! Arguments for the `env.*` operations: what the bounded sandbox maps, seeds,
//! watches, interrupts and exports around one MC68000 routine or boot block.
use super::*;

/// Arguments for `env.boot.trace`.
///
/// The environment is fixed — a seeded Amiga with exec and trackdisk serviced
/// and the custom-chip range modelled — because a boot block is written against
/// *the* machine, not against a machine a caller describes. What a caller
/// chooses is how long to let it run and what to watch.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootTraceArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_steps: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watch: Vec<WatchRange>,
    #[serde(default)]
    pub stop_on_watch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl BootTraceArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_steps: None,
            watch: Vec::new(),
            stop_on_watch: false,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_steps(mut self, steps: usize) -> Self {
        self.maximum_steps = Some(steps);
        self
    }

    #[must_use]
    pub fn watching(mut self, watch: Vec<WatchRange>, stop: bool) -> Self {
        self.watch = watch;
        self.stop_on_watch = stop;
        self
    }
}

/// Arguments for `env.boot.trace.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootTraceExportArguments {
    #[serde(flatten)]
    pub trace: BootTraceArguments,
    /// Directory the served track dumps go in, as a destination identity. A
    /// *directory*, unlike every other export here: a boot run serves however
    /// many reads it serves, and there is no single file to name.
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl BootTraceExportArguments {
    #[must_use]
    pub fn new(trace: BootTraceArguments, destination: impl Into<String>) -> Self {
        Self {
            trace,
            destination: destination.into(),
            policy: None,
        }
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// One region mapped for the routine's use, beyond the hunks it runs in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MappedRegion {
    pub address: u32,
    pub size: u32,
}

/// Bytes written into the sandbox before entry.
///
/// Spelled out as hex, copied from a range of a source, or replayed from a
/// pinned artifact file. Exactly one of the three: a seed with two would have
/// two answers to what it seeds, and one with none would seed nothing while
/// looking like it seeded something.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySeed {
    pub address: u32,
    /// Lowercase hex. A JSON document cannot carry raw bytes, and a seed is
    /// part of the record a caller diffs, so it has to be spellable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    /// A range of a source to copy, instead of hex a caller had to convert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<SeedRange>,
    /// A file an earlier run produced, replayed under its own digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<SeedArtifact>,
}

impl MemorySeed {
    /// A seed spelled out as hex.
    #[must_use]
    pub fn hex(address: u32, hex: impl Into<String>) -> Self {
        Self {
            address,
            hex: Some(hex.into()),
            from: None,
            artifact: None,
        }
    }

    /// A seed copied from a range of a source.
    #[must_use]
    pub const fn from(address: u32, range: SeedRange) -> Self {
        Self {
            address,
            hex: None,
            from: Some(range),
            artifact: None,
        }
    }

    /// A seed replayed from a pinned artifact file.
    #[must_use]
    pub const fn artifact(address: u32, artifact: SeedArtifact) -> Self {
        Self {
            address,
            hex: None,
            from: None,
            artifact: Some(artifact),
        }
    }
}

/// A file an earlier run produced, replayed into the sandbox under its digest.
///
/// The other end of `memory_exports`. `call --save` preserves a decoded runtime
/// table so a later stage can be run against it, and until now replaying it
/// meant converting the whole file to a hexadecimal seed outside the toolkit —
/// which loses the one thing that made it evidence: which file it was.
///
/// **The digest is required, and it is the difference from [`SeedRange`].** A
/// `from` with no source names the image being run, which the record already
/// pins; an artifact is a file nothing else in the record mentions, so a seed
/// that did not pin it would make the run depend on bytes nobody checked. It is
/// compared before the routine runs, so a stale artifact is a refused request
/// rather than a run whose outputs mean nothing.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeedArtifact {
    /// The file, named as an identity the resolver interprets — never a host
    /// path, like every other source this API takes.
    pub source: SourceLocator,
    /// Lowercase hex SHA-256 of the whole file, as the run that wrote it
    /// reported.
    pub sha256: String,
    /// Where the replayed range starts in the file. Omitted means the start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// How many bytes to replay. Omitted means the rest of the file, which is
    /// the common case — the digest already fixes what "the rest" is. The
    /// record reports the resolved length either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
}

impl SeedArtifact {
    #[must_use]
    pub fn new(source: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            sha256: sha256.into(),
            offset: None,
            length: None,
        }
    }

    /// Replay one range of the artifact rather than the whole of it.
    #[must_use]
    pub const fn with_range(mut self, offset: u32, length: u32) -> Self {
        self.offset = Some(offset);
        self.length = Some(length);
        self
    }
}

/// Where a seed's bytes are copied from.
///
/// A self-relocating loader installing a small resident helper copies part of
/// its own image to low memory; reproducing that state should record the range
/// it came from, not a hexadecimal string somebody converted by hand and that
/// nothing can check against the image.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRange {
    /// The source to copy from. Omitted, it is the image being run — which is
    /// the case this exists for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocator>,
    /// Copy from this hunk's loaded bytes rather than from the file. A hunk's
    /// offset is what a disassembly shows, and converting it to a file offset
    /// by hand is the arithmetic this avoids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    pub offset: u32,
    pub length: u32,
}

/// One interrupt a recipe delivers while the routine runs.
///
/// Setup code commonly sets a synchronization flag and spins until an interrupt
/// handler clears it. The beam counter advances on its own, but nothing runs the
/// handler, so otherwise valid initialization never returns — and the only way
/// through was to patch each wait branch, which changes the code being studied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledInterrupt {
    /// The 68000 vector whose longword holds the handler — 27 for level 3, the
    /// Amiga's vertical-blank and Copper level. Read at delivery, so the
    /// handler the program installed is the one that runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<u8>,
    /// A fixed handler address, for a recipe that knows where the handler is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u32>,
    /// Instructions to execute before the first delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_steps: Option<u32>,
    /// Instructions between deliveries. Omitted, it delivers once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every_steps: Option<u32>,
    /// How many deliveries at most. Omitted, as many as the step budget allows,
    /// which is already finite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<u32>,
    /// How the handler returns: `rte` (the 68000 exception frame) or `rts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<InterruptFrame>,
}

/// How a scheduled handler returns.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterruptFrame {
    /// Status register at `SP`, program counter at `SP+2` — what `RTE` pops,
    /// which is what a hardware vector holds.
    #[default]
    Rte,
    /// A plain return address, for a handler ending in `RTS` — the shape an
    /// exec interrupt *server* has, since exec's own handler calls the chain.
    Rts,
}

/// One range of final sandbox memory the recipe names as an artifact.
///
/// A `call` already reports every run of memory the routine changed, but a
/// caller who wants the *bytes* of one region — a framebuffer the routine
/// decoded into, a table it generated — had to reapply thousands of recorded
/// changes to the original image and then carve the range back out. Naming the
/// range makes it an output of the recipe instead, digested in the record and
/// written by the export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryExport {
    pub address: u32,
    pub length: u32,
    /// What the range is called. One path component: the destination names the
    /// directory, and a name that could contain a separator would be deciding a
    /// second one.
    pub name: String,
}

/// Arguments for `env.sandbox.call`.
///
/// The sandbox `env.sandbox.run` builds, plus what a *call* needs: regions the
/// routine reads or writes, bytes seeded into them, and arguments laid out above
/// the return marker as a `JSR` would leave them.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCallArguments {
    #[serde(flatten)]
    pub run: SandboxRunArguments,
    /// Longwords placed above the return marker: at entry, `SP` holds the
    /// marker and `SP+4` is the first argument.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_arguments: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapped_regions: Vec<MappedRegion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_seeds: Vec<MemorySeed>,
    /// Ranges of final memory the recipe names as artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_exports: Vec<MemoryExport>,
    /// Interrupts delivered on a deterministic instruction schedule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interrupts: Vec<ScheduledInterrupt>,
    /// Model the custom chips at `$DFF000` rather than leaving the range to be
    /// whatever `mapped_regions` made of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_chips: Option<CustomChips>,
}

/// Which custom-chip behaviour a call runs under.
///
/// An empty object means an emulating OCS blitter with the defaults, so the
/// request cannot be spelled two ways that mean two things.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomChips {
    /// The chipset modelled. OCS is the only value; it is the extension point
    /// rather than a hole in the middle of the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chipset: Option<Chipset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blitter: Option<BlitterOptions>,
}

/// The chipset a call models.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Chipset {
    /// An OCS Agnus: `$05A`, `$05C` and `$05E` are not registers, and `BLTCON1`
    /// bit 7 is reserved.
    #[default]
    Ocs,
}

/// How the blitter behaves under a call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlitterOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<BlitterMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dma: Option<BlitterDma>,
    /// Datapath words this run's blits may perform, refusals included. Clamped
    /// to what the context allows, with `LIMIT_REDUCED` when it is reduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_words: Option<u64>,
}

/// Whether the blitter performs blits or only shadows its registers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlitterMode {
    /// Perform blits, changing memory.
    #[default]
    Emulate,
    /// Register cells only, as the page behaved before a blitter existed.
    /// `dma` and `maximum_words` have no effect and are dropped.
    Shadow,
}

/// What to do when a blit starts with `DMACON` saying blitter DMA is off.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlitterDma {
    /// Blit anyway and say so. A call starts in the middle of a program, after
    /// an initialization the sandbox never ran, so `DMACON` holding zero says
    /// nothing about what the program intended.
    #[default]
    AssumeEnabled,
    /// Refuse the blit. For a recipe that did run the initialization, where a
    /// blit with DMA off is a real finding rather than a missing prologue.
    RequireEnabled,
}

impl SandboxCallArguments {
    #[must_use]
    pub fn new(run: SandboxRunArguments) -> Self {
        Self {
            run,
            stack_arguments: Vec::new(),
            mapped_regions: Vec::new(),
            memory_seeds: Vec::new(),
            memory_exports: Vec::new(),
            interrupts: Vec::new(),
            custom_chips: None,
        }
    }

    /// Model the custom chips at `$DFF000`.
    #[must_use]
    pub fn with_custom_chips(mut self, chips: CustomChips) -> Self {
        self.custom_chips = Some(chips);
        self
    }

    #[must_use]
    pub fn with_stack_arguments(mut self, arguments: Vec<u32>) -> Self {
        self.stack_arguments = arguments;
        self
    }

    #[must_use]
    pub fn with_mapped_regions(mut self, regions: Vec<MappedRegion>) -> Self {
        self.mapped_regions = regions;
        self
    }

    #[must_use]
    pub fn with_memory_seeds(mut self, seeds: Vec<MemorySeed>) -> Self {
        self.memory_seeds = seeds;
        self
    }

    #[must_use]
    pub fn with_memory_exports(mut self, exports: Vec<MemoryExport>) -> Self {
        self.memory_exports = exports;
        self
    }

    #[must_use]
    pub fn with_interrupts(mut self, interrupts: Vec<ScheduledInterrupt>) -> Self {
        self.interrupts = interrupts;
        self
    }
}

/// Arguments for `env.sandbox.compare`.
///
/// Reads records that already exist rather than running anything. The question
/// it answers is the one a person asks with two golden records open side by
/// side — *which of these differences is the routine behaving differently, and
/// which is me having asked it something else* — and a textual diff cannot
/// answer it, because it has no idea which fields are inputs.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCompareArguments {
    /// The golden records to compare, in the order they are reported. At least
    /// two: comparing one record against nothing has no answer.
    pub records: Vec<SourceLocator>,
    /// Cap on the differences of each kind that are listed. The true totals are
    /// always reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_differences: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl SandboxCompareArguments {
    #[must_use]
    pub fn new(records: Vec<SourceLocator>) -> Self {
        Self {
            records,
            maximum_differences: None,
            maximum_input_bytes: None,
        }
    }

    /// Compare records named by path.
    #[must_use]
    pub fn of(paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(paths.into_iter().map(SourceLocator::file).collect())
    }
}

/// Arguments for `env.sandbox.matrix`.
///
/// One shared recipe and a list of named cases that vary its *inputs*. That
/// split is the whole point: the source, the load map, the stack, the chip
/// model, the watches and the exports are the experiment's apparatus, and a
/// case that could change them would not be a case of the same experiment. What
/// a case may change is what the routine is handed.
///
/// This is not a shell loop with a nicer spelling. Every case is expanded and
/// normalized before any of them runs, so a malformed case is a refused request
/// rather than a partial sweep; every case is digested on its own, so one can be
/// cited without citing the matrix; and the order is the request's, so a result
/// can be read against the list that produced it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxMatrixArguments {
    /// The recipe every case starts from.
    #[serde(flatten)]
    pub base: SandboxCallArguments,
    /// The cases, in the order they run and are reported.
    pub cases: Vec<SandboxMatrixCase>,
    /// Cap on expanded cases. Clamped by the context, with `LIMIT_REDUCED`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_cases: Option<usize>,
    /// Instructions the whole matrix may execute.
    ///
    /// Separate from the per-case budget, and not its multiple: a case is never
    /// clipped to what is left, it either runs with the budget it asked for or
    /// is reported as not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_total_steps: Option<usize>,
}

/// One case: a name, and the inputs it changes.
///
/// Every field but the name is an override. Absent means "as the shared recipe
/// has it", which is what makes a case readable as a difference rather than as
/// a whole recipe repeated.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxMatrixCase {
    /// Unique within the matrix, and usable as one path component so that a
    /// case can name an artifact later. Uniqueness is what lets a result be
    /// matched to a case by something other than its position.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_offset: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_registers: Option<[u32; 8]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_registers: Option<[u32; 7]>,
    /// Replaces the shared stack arguments outright rather than appending: a
    /// call's arguments are positional, and appending would shift them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_arguments: Option<Vec<u32>>,
    /// Applied *after* the shared seeds, so a case seeding an address the
    /// recipe also seeds overwrites it. Appending rather than replacing is what
    /// lets a case vary one field of a large shared structure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_seeds: Vec<MemorySeed>,
    /// What this case is for, in the record. Never interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl SandboxMatrixCase {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub const fn with_data_registers(mut self, registers: [u32; 8]) -> Self {
        self.data_registers = Some(registers);
        self
    }

    #[must_use]
    pub const fn with_address_registers(mut self, registers: [u32; 7]) -> Self {
        self.address_registers = Some(registers);
        self
    }

    #[must_use]
    pub const fn with_entry_offset(mut self, offset: u32) -> Self {
        self.entry_offset = Some(offset);
        self
    }

    #[must_use]
    pub fn with_stack_arguments(mut self, arguments: Vec<u32>) -> Self {
        self.stack_arguments = Some(arguments);
        self
    }

    #[must_use]
    pub fn with_memory_seeds(mut self, seeds: Vec<MemorySeed>) -> Self {
        self.memory_seeds = seeds;
        self
    }
}

impl SandboxMatrixArguments {
    #[must_use]
    pub fn new(base: SandboxCallArguments, cases: Vec<SandboxMatrixCase>) -> Self {
        Self {
            base,
            cases,
            maximum_cases: None,
            maximum_total_steps: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_total_steps(mut self, steps: usize) -> Self {
        self.maximum_total_steps = Some(steps);
        self
    }
}

/// Arguments for `env.sandbox.matrix.export`.
///
/// The sweep, plus where its cases' exported ranges go. Each case writes under
/// its own name, which is what the case-name rules exist for.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxMatrixExportArguments {
    #[serde(flatten)]
    pub matrix: SandboxMatrixArguments,
    pub destination: String,
    /// What the aggregate result is written as. Defaults to `matrix.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl SandboxMatrixExportArguments {
    #[must_use]
    pub fn new(matrix: SandboxMatrixArguments, destination: impl Into<String>) -> Self {
        Self {
            matrix,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `env.sandbox.timeline`.
///
/// One machine, and a sequence of steps that evolve it. The shared arguments
/// build the sandbox exactly as `env.sandbox.call` does — the image, the load
/// map, the stack, the mapped regions, the initial seeds, the chip model, the
/// watched ranges and the interrupt schedule — and then each step either enters
/// a routine or continues the machine the previous step left.
///
/// **This is not a matrix.** A matrix's cases are deliberately independent, each
/// starting from the same state, because that is what makes them comparable. A
/// timeline is the opposite claim: step *n+1* consumes the exact memory,
/// registers, chip state and interrupt state that step *n* produced, which is
/// the only way a game loop's second tick means anything.
///
/// The shared `memory_exports` are ranges of the memory the *whole* timeline
/// leaves behind; a step's own `checkpoints` are ranges as that step left them.
///
/// This outer type deliberately has no `deny_unknown_fields`: Serde applies it
/// before the nested flattened [`SandboxCallArguments`] can claim fields from
/// [`SandboxRunArguments`]. Unknown fields still reach the flattened call,
/// which rejects them after all three layers have had a chance to claim their
/// own fields.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SandboxTimelineArguments {
    /// The machine every step runs in, and the defaults a step may override.
    #[serde(flatten)]
    pub base: SandboxCallArguments,
    /// The steps, in the order they run and are reported.
    pub steps: Vec<TimelineStep>,
    /// Instructions the whole timeline may execute.
    ///
    /// Separate from a step's own budget and not its multiple: a step is never
    /// clipped to what is left, it either runs with the budget it asked for or
    /// is reported as not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_total_steps: Option<usize>,
}

impl SandboxTimelineArguments {
    #[must_use]
    pub fn new(base: SandboxCallArguments, steps: Vec<TimelineStep>) -> Self {
        Self {
            base,
            steps,
            maximum_total_steps: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_total_steps(mut self, steps: usize) -> Self {
        self.maximum_total_steps = Some(steps);
        self
    }
}

/// Arguments for `env.sandbox.timeline.export`.
///
/// The timeline, plus where each step's checkpointed ranges go. A step writes
/// under its own name, which is what the single-path-component rule on a step
/// name exists for.
///
/// This is the reconstruction problem one level up from
/// `env.sandbox.call.export`. `env.sandbox.timeline` reports a digest per
/// checkpoint and no bytes — right for the read-only half, since sixty ticks
/// each checkpointing a framebuffer is a response nobody can read — and the
/// workaround, re-running the interesting step through `call` with `--save`,
/// only works when the step can be reproduced as a standalone call. A step deep
/// in an evolving timeline cannot: its inputs are the machine every step before
/// it produced.
///
/// As with [`SandboxTimelineArguments`], the innermost flattened call owns
/// unknown-field rejection; applying it here would reject the call's own
/// flattened run fields before they reached it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SandboxTimelineExportArguments {
    #[serde(flatten)]
    pub timeline: SandboxTimelineArguments,
    pub destination: String,
    /// What the aggregate result is written as. Defaults to `timeline.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl SandboxTimelineExportArguments {
    #[must_use]
    pub fn new(timeline: SandboxTimelineArguments, destination: impl Into<String>) -> Self {
        Self {
            timeline,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// One step of a timeline: what it does to the machine, and what it records.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineStep {
    /// Unique within the timeline, and usable as one path component. Uniqueness
    /// is what lets a result be matched to a step by something other than its
    /// position.
    pub name: String,
    /// Enter this hunk offset as a fresh call, with the return marker below the
    /// stated arguments.
    ///
    /// Exactly one of this and `resume`: a step that stated both would have two
    /// answers to where it starts, and one that stated neither would have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_offset: Option<u32>,
    /// Continue the machine the previous step left, from the address it stopped
    /// at and with the register file it left behind.
    ///
    /// The first step cannot resume: there is no machine to continue.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resume: bool,
    /// `D0`–`D7` at entry. Only for a step that enters: a resumed step continues
    /// with the registers it stopped with, and seeding them would be a different
    /// machine wearing the previous step's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_registers: Option<[u32; 8]>,
    /// `A0`–`A6` at entry, on the same terms as `data_registers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_registers: Option<[u32; 7]>,
    /// Replaces the shared stack arguments outright rather than appending: a
    /// call's arguments are positional, and appending would shift them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_arguments: Option<Vec<u32>>,
    /// Bytes written into the machine *before* this step runs — the reviewed
    /// input change a tick consumes.
    ///
    /// They are part of the step's inputs rather than of its effects, so the
    /// changed memory this step reports is what its execution did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_seeds: Vec<MemorySeed>,
    /// Instructions this step may execute. Defaults to the shared budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_steps: Option<usize>,
    /// Absolute addresses to stop at, before the instruction there executes.
    ///
    /// A breakpoint at the address the step starts from does not stop it before
    /// it has executed anything; otherwise a step resuming at its own breakpoint
    /// could never make progress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop_at: Vec<u32>,
    /// Ranges of memory recorded as this step left them, each under a name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoints: Vec<MemoryExport>,
    /// What this step is for, in the record. Never interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl TimelineStep {
    /// A step that enters `entry_offset` as a fresh call.
    #[must_use]
    pub fn call(name: impl Into<String>, entry_offset: u32) -> Self {
        Self {
            name: name.into(),
            entry_offset: Some(entry_offset),
            ..Self::default()
        }
    }

    /// A step that continues the machine the previous step left.
    #[must_use]
    pub fn resume(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            resume: true,
            ..Self::default()
        }
    }

    #[must_use]
    pub const fn with_maximum_steps(mut self, steps: usize) -> Self {
        self.maximum_steps = Some(steps);
        self
    }

    #[must_use]
    pub fn stopping_at(mut self, addresses: Vec<u32>) -> Self {
        self.stop_at = addresses;
        self
    }

    #[must_use]
    pub fn with_checkpoints(mut self, checkpoints: Vec<MemoryExport>) -> Self {
        self.checkpoints = checkpoints;
        self
    }

    #[must_use]
    pub fn with_memory_seeds(mut self, seeds: Vec<MemorySeed>) -> Self {
        self.memory_seeds = seeds;
        self
    }
}

/// Arguments for `env.sandbox.call.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCallExportArguments {
    #[serde(flatten)]
    pub call: SandboxCallArguments,
    /// Directory the golden record goes in, as a destination identity.
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl SandboxCallExportArguments {
    #[must_use]
    pub fn new(call: SandboxCallArguments, destination: impl Into<String>) -> Self {
        Self {
            call,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `env.boot.info`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootInfoArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl BootInfoArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }
}

/// Where an additional hunk is mapped.
///
/// A hunk that is relocated *into* must be mapped somewhere, or its relocations
/// have no target. Naming the address rather than deriving one keeps a run
/// reproducible: a derived layout would change with the allocation sizes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkBase {
    pub hunk: u32,
    pub address: u32,
}

/// Which direction a watchpoint observes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAccess {
    Read,
    Write,
    #[default]
    Both,
}

/// One watched absolute address range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatchRange {
    pub start: u32,
    /// Length in bytes. Must be at least 1: a zero-length range watches nothing
    /// and would silently never match.
    pub length: u32,
    #[serde(default)]
    pub access: WatchAccess,
}

/// Where the sandbox stack lives.
///
/// Optional as a whole. Omitted, the stack is placed above the mapped hunk with
/// an unmapped gap between them, so a stack that grows past its own region
/// faults instead of quietly overwriting the code being run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackRegion {
    pub base: u32,
    pub size: u32,
}

/// Arguments for `env.sandbox.run`.
///
/// Everything that bounds the run is part of the request rather than a default
/// hidden behind it. Sandbox code is unknown code, and a routine that never
/// returns is the normal case while identifying one — so the step budget, the
/// memory map, and the watchpoints are things a caller states and a response
/// echoes back.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRunArguments {
    pub source: SourceLocator,
    /// Which CODE hunk to run. Defaults to the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Absolute address the selected hunk is mapped at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_origin: Option<u32>,
    /// Byte offset within the hunk to start at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_offset: Option<u32>,
    /// Additional hunks to map, for relocations that target them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunk_bases: Vec<HunkBase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<StackRegion>,
    /// Instructions to execute before stopping. Capped by the context's limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_steps: Option<usize>,
    /// Initial `D0`–`D7`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_registers: Option<[u32; 8]>,
    /// Initial `A0`–`A6`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_registers: Option<[u32; 7]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watch: Vec<WatchRange>,
    /// Stop at the first instruction that touches a watched range.
    #[serde(default)]
    pub stop_on_watch: bool,
    /// Whether to return the per-instruction trace.
    #[serde(default)]
    pub trace: bool,
    /// Cap on returned trace rows. The true total is always reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_trace_rows: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl SandboxRunArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            load_origin: None,
            entry_offset: None,
            hunk_bases: Vec::new(),
            stack: None,
            maximum_steps: None,
            data_registers: None,
            address_registers: None,
            watch: Vec::new(),
            stop_on_watch: false,
            trace: false,
            maximum_trace_rows: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub const fn at_origin(mut self, origin: u32) -> Self {
        self.load_origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn with_entry_offset(mut self, offset: u32) -> Self {
        self.entry_offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_steps(mut self, steps: usize) -> Self {
        self.maximum_steps = Some(steps);
        self
    }

    #[must_use]
    pub const fn tracing(mut self) -> Self {
        self.trace = true;
        self
    }

    #[must_use]
    pub fn watching(mut self, watch: Vec<WatchRange>, stop: bool) -> Self {
        self.watch = watch;
        self.stop_on_watch = stop;
        self
    }
}

/// Arguments for `env.frame.capture`.
///
/// Run a custom-chip sandbox and reconstruct the frame the display hardware
/// would have shown at the end of it — not a byte range, but the picture the
/// bitplane pointers, `BPLCON0`, the display window, the data fetch, the
/// modulos, the palette and the Copper together select.
///
/// A raw framebuffer range is insufficient for the reason the capture exists: a
/// program that double-buffers is showing one of two buffers and the range says
/// nothing about which, and a program that swaps a palette or a pointer part-way
/// down the frame is showing several things at once.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrameCaptureArguments {
    /// The run the frame is captured at the end of.
    ///
    /// `custom_chips` is not optional here in practice: without the chip page
    /// there is no register state to reconstruct from, and the capture says so
    /// rather than reporting an unconfigured display.
    #[serde(flatten)]
    pub call: SandboxCallArguments,
    /// Run until the beam reaches this raster line, instead of to the step
    /// budget.
    ///
    /// The beam is derived from the instruction counter, so a raster line *is*
    /// an instruction count: line `n` is reached after `n * 227` instructions.
    /// That is why this is expressible at all without a hook in the run loop,
    /// and why it is exactly reproducible — the same recipe stops at the same
    /// instruction on every machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_raster_line: Option<u16>,
    /// Pixels the reconstructed frame may hold. Clamped by the context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_pixels: Option<u64>,
}

impl FrameCaptureArguments {
    #[must_use]
    pub fn new(call: SandboxCallArguments) -> Self {
        Self {
            call,
            until_raster_line: None,
            maximum_pixels: None,
        }
    }

    #[must_use]
    pub const fn until_raster_line(mut self, line: u16) -> Self {
        self.until_raster_line = Some(line);
        self
    }
}

/// Arguments for `env.frame.capture.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrameCaptureExportArguments {
    #[serde(flatten)]
    pub capture: FrameCaptureArguments,
    /// Directory the frame goes in, as a destination identity.
    pub destination: String,
    /// What the indexed PNG is called. The RGBA one and the manifest are named
    /// from it, so one name decides all three.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl FrameCaptureExportArguments {
    #[must_use]
    pub fn new(capture: FrameCaptureArguments, destination: impl Into<String>) -> Self {
        Self {
            capture,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// What a dependency slice is asked to explain.
///
/// A closed union rather than three optional fields: a slice with two seeds
/// would have two answers, and one with none would have no question.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SliceSeedArgument {
    /// A register as the run left it: `d0`–`d7`, `a0`–`a7`, or `ccr`.
    Register { register: String },
    /// A byte of memory as the run left it. The last write to it, and
    /// everything behind that write.
    Memory { address: u32 },
    /// Everything the instruction at `address` read on its `occurrence`-th
    /// execution, counted from one — which is what makes a loop unambiguous.
    Instruction {
        address: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        occurrence: Option<u32>,
    },
}

/// Arguments for `env.sandbox.slice`.
///
/// Run a routine and follow one value backwards through the instructions that
/// produced it. Trace comparison identifies the first instruction two runs
/// disagree at; this says *why* — which earlier value made that instruction
/// behave differently, and which reviewed input made that one.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSliceArguments {
    #[serde(flatten)]
    pub call: SandboxCallArguments,
    pub seed: SliceSeedArgument,
    /// Edges to follow before stopping. The bound is stated in the result
    /// rather than producing a shorter answer that reads as a complete one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_depth: Option<usize>,
    /// Steps to report. The true total is always reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_entries: Option<usize>,
}

impl SandboxSliceArguments {
    #[must_use]
    pub fn new(call: SandboxCallArguments, seed: SliceSeedArgument) -> Self {
        Self {
            call,
            seed,
            maximum_depth: None,
            maximum_entries: None,
        }
    }
}
