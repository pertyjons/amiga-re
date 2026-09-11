//! Results of the `env.*` operations.
use super::*;

/// One custom-chip register write a boot run made.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ChipWrite {
    pub address: u32,
    /// The register's name, when the chip map knows one. Hardware knowledge,
    /// not configuration, so it belongs in the answer rather than in whichever
    /// frontend happens to render it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
    pub value: u16,
}

/// One exec/library vector the host actually serviced.
///
/// The *ground truth* of which OS calls were made, unlike a static
/// disassembly's guess. Named by offset only: an fd table names it, and those
/// are the frontend's configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BootExecCall {
    pub site: u32,
    pub offset: i32,
}

/// One disk transfer the emulated trackdisk device served.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ServedRead {
    pub index: u64,
    /// The trackdisk command name, e.g. `CMD_READ`.
    pub command: String,
    /// Byte offset into the source image the read started at.
    pub offset: u64,
    /// Destination address the bytes were copied to.
    pub destination: u32,
    pub requested: u32,
    pub actual: u32,
    /// The `io_Error` status the request was left with. Zero is success.
    pub status: i32,
}

/// The `env.boot.trace` result.
///
/// The environment's layout is reported because it is what every address here
/// means. The stop reason is structured for the same reason the golden record's
/// is: a persisted trace whose outcome was rendered through a frontend's fd
/// tables would differ between machines that ran the same disk.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BootTraceResult {
    pub source: SourcePin,
    /// What the boot block declares, as `env.boot.info` reports it.
    pub boot: BootInfoResult,
    /// Absolute address the boot code was loaded at.
    pub load_address: u32,
    /// Absolute address execution started at.
    pub entry: u32,
    pub exec_base: u32,
    pub io_request: u32,
    pub stop: SandboxStop,
    pub steps_executed: u64,
    /// Custom-chip register writes the boot code made, capped.
    pub chip_writes: Vec<ChipWrite>,
    /// Register writes the boot code made before the cap. Always the true
    /// total: a loader that writes a register in a loop is exactly the case
    /// where the count matters and the thousandth repetition does not.
    pub chip_writes_total: u64,
    /// Whether more registers were written than are reported, so `chip_writes`
    /// is a prefix rather than the whole set.
    pub chip_writes_truncated: bool,
    pub exec_calls: Vec<BootExecCall>,
    pub watch_hits: Vec<SandboxAccess>,
    /// Accesses that matched a watched range, counted across the whole boot.
    ///
    /// Not the same as `watch_hits.len()`: the hits are gathered from the
    /// retained trace rows, and both retention and the trace are capped.
    pub watch_events_total: u64,
    /// Whether more accesses matched than were retained, so `watch_hits` is a
    /// prefix rather than the whole set.
    pub watch_events_truncated: bool,
    pub served_reads: Vec<ServedRead>,
    /// Bytes the served reads transferred in total.
    pub bytes_served: u64,
}

/// The `env.boot.trace.export` result: the trace, plus the write plan for the
/// tracks it served.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BootTraceExportResult {
    pub trace: BootTraceResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// Which direction a recorded access went.
///
/// An enum rather than the `&'static str` this used to be, because a record has
/// to be *readable* as well as writable — `env.sandbox.compare` reads one back —
/// and a borrowed static string has nothing to borrow from when deserializing.
/// The wire spelling is unchanged, `read` and `write`, which is what the bundled
/// schemas already state; so this is a change to the Rust type and to nothing a
/// consumer sees.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDirection {
    Read,
    Write,
}

impl AccessDirection {
    /// The word this serializes as, for rendering.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl std::fmt::Display for AccessDirection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One contiguous run of memory a routine changed, as lowercase hex.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxRegionResult {
    pub address: u32,
    pub hex: String,
}

/// The `env.sandbox.call` result: a diffable input→output record.
///
/// The stop reason is **structured**, not prose. The record this replaces
/// carried a rendered `outcome` string produced through the frontend's fd
/// tables, so the same routine on the same bytes produced a different record
/// depending on what `amiga-re.toml` said — unstable in exactly the dimension a
/// diffable record exists to be stable in. Naming a vector is still the
/// frontend's; it is no longer baked into the artifact.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCallResult {
    pub source: SourcePin,
    pub hunk: u32,
    pub entry: u32,
    /// The register file at entry, as the request seeded it.
    pub inputs: SandboxRegisters,
    pub stack_arguments: Vec<u32>,
    pub mapped_regions: Vec<crate::request::MappedRegion>,
    pub memory_seeds: Vec<SandboxSeedResult>,
    pub stop: SandboxStop,
    /// Whether the routine returned cleanly, which is the one thing a caller
    /// checks before trusting the outputs.
    pub returned: bool,
    pub steps_executed: u64,
    /// The register file when it stopped.
    pub outputs: SandboxRegisters,
    /// Every run of memory the routine changed, excluding the stack: the stack
    /// is scratch, and including it would make every record differ from every
    /// other for reasons that say nothing about the routine.
    pub changed_memory: Vec<SandboxRegionResult>,
    /// The per-instruction trace, capped. Empty unless the request asked for
    /// one: a golden record is about inputs and outputs, and a trace kept by
    /// default would make two runs with identical outputs produce records that
    /// differ.
    pub trace: Vec<SandboxStep>,
    /// Rows the call produced before the cap. Non-zero even without `trace`
    /// when a watched range forced recording, because that is what was run.
    pub trace_total: u64,
    pub trace_truncated: bool,
    /// Accesses that matched a watched range, counted across the whole run.
    ///
    /// Not the same as the number of `watch_hits` the trace carries: the trace
    /// is capped in rows, retention is capped in events, and an attached device
    /// can make one instruction produce more matching accesses than a run makes
    /// instructions. This is the true total either way.
    pub watch_events_total: u64,
    /// Whether more accesses matched than were retained, so the `watch_hits` on
    /// the trace rows are a prefix rather than the whole set.
    pub watch_events_truncated: bool,
    /// The ranges of final memory the recipe named, digested rather than
    /// carried. A recipe plus a digest reproduces the bytes and is bounded; the
    /// bytes themselves are what `env.sandbox.call.export` writes.
    pub exported_regions: Vec<SandboxExportResult>,
    /// Every scheduled interrupt that was delivered, in order, capped.
    pub interrupts_delivered: Vec<SandboxInterruptDelivery>,
    /// Deliveries the run made before the cap.
    pub interrupts_total: u64,
    /// The custom-chip configuration the call ran under, as normalization
    /// resolved it. Absent when none was asked for.
    ///
    /// The record says what drew the pixels. A response that carried the bytes
    /// and not the chipset would be a picture nobody could reproduce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_chips: Option<SandboxCustomChips>,
    /// The blits the run performed or refused, capped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blits: Vec<SandboxBlit>,
    /// Blits triggered, refused ones included. Always the true total.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub blits_total: u64,
    /// Datapath words every triggered blit asked for, refusals included: what
    /// the budget was charged.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub attempted_blit_words_total: u64,
    /// Datapath words the blits that ran actually performed. Two named fields
    /// rather than one, so a run that spent its budget on refusals says so.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub executed_blit_words_total: u64,
    /// Run-level chip observations, aggregated by kind and register rather than
    /// accumulated, so a loop writing one register is one row with a count.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chip_observations: Vec<SandboxChipObservation>,
}

/// A zero total is the ordinary case for a call with no chips, and omitting it
/// keeps those records byte-identical to the ones from before this existed.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if"
)]
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// The resolved custom-chip configuration a call ran under.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxCustomChips {
    /// `ocs`.
    pub chipset: String,
    pub blitter: SandboxBlitterConfig,
}

/// The blitter half of a resolved configuration.
///
/// `dma` and `maximum_words` are absent under `shadow`, where they have no
/// effect: reporting a policy that did not apply would be a claim.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxBlitterConfig {
    /// `emulate` or `shadow`.
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dma: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_words: Option<u64>,
}

/// One blit the run performed or refused.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxBlit {
    /// Position in the run, counting refused blits.
    pub index: u64,
    /// Words per row, 1..=64, decoded from `BLTSIZE`.
    pub width: u16,
    /// Rows, 1..=1024, decoded from `BLTSIZE`.
    pub height: u16,
    pub bltcon0: u16,
    pub bltcon1: u16,
    /// The channel pointers when the blit was triggered, `[a, b, c, d]`.
    pub initial_pointers: [u32; 4],
    /// And afterwards. Equal to the initial ones when the blit was refused.
    pub final_pointers: [u32; 4],
    /// `width × height`, charged to the budget whether or not the blit ran.
    pub datapath_words: u64,
    /// Words the destination channel wrote.
    pub words_written: u64,
    /// `BZERO`. Absent when no blit ran — `false` there would be a claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero: Option<bool>,
    /// Whether the blit ran with `DMACON` saying DMA was off.
    pub dma_assumed: bool,
    /// Why the blit did not run, if it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<SandboxBlitRefusal>,
    /// What is true about this blit that a reader needs in order to distrust the
    /// right pixel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<SandboxChipObservation>,
}

/// Why a blit did not run.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxBlitRefusal {
    /// A stable name: `line_mode`, `unmapped`, `address_overflow`,
    /// `dma_disabled` or `budget_exceeded`.
    pub kind: String,
    /// The channel it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The address it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u32>,
    /// Human-readable, for a reader rather than for a consumer: the structured
    /// fields above are what a consumer reads.
    pub message: String,
}

/// One chip observation, with how many times it happened.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxChipObservation {
    /// A stable kind name, e.g. `ecs_register_written`.
    pub kind: String,
    /// The register it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<u16>,
    /// The channel it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// How many times it happened. Always 1 on a per-blit list, which is
    /// bounded by the number of things one blit can be unusual about.
    pub occurrences: u64,
}

/// One interrupt delivery that happened, as the record reports it.
///
/// A run whose outcome depended on a handler running must say that it ran, and
/// where: an initialization that only completes because a flag was cleared is
/// not reproducible from a record that does not mention the clearing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxInterruptDelivery {
    /// Which entry of the request's schedule delivered.
    pub index: u64,
    /// The instruction count at which it was delivered.
    pub step: u64,
    /// The handler address that ran — resolved from the vector table at
    /// delivery, when the schedule named a vector.
    pub handler: u32,
    /// The address it interrupted, which is where the handler returned.
    pub resume: u32,
}

/// One seed, as the record reports it: the bytes, and where they came from.
///
/// The bytes are always spelled out — a record a caller diffs has to say what
/// entered the sandbox. `from` is present only where the recipe named a range
/// rather than the bytes, and it is what tells a reader that a seed was the
/// image's own bytes rather than a hexadecimal string somebody typed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxSeedResult {
    pub address: u32,
    /// Lowercase hex. A JSON document cannot carry raw bytes, and a seed is
    /// part of the record a caller diffs, so it has to be spellable.
    pub hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<SandboxSeedOrigin>,
}

/// The range a seed copied, when it copied one.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxSeedOrigin {
    /// The source copied from. Absent means the image being run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The hunk whose loaded bytes were copied, when the range named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    pub offset: u32,
    /// The resolved length, which for an artifact replayed whole is the file's
    /// own — stated here rather than left as "the rest of it".
    pub length: u32,
    /// The digest of the file this range was replayed from, present only for an
    /// artifact seed and checked before the routine ran.
    ///
    /// This is what tells a reader the two apart. A `from` with no source is a
    /// range of the image the record already pins; an artifact is a file
    /// nothing else in the record mentions, so a seed that did not pin it would
    /// make the run depend on bytes nobody checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// One named range of final memory, as the record reports it.
///
/// The digest is over the bytes the run left there, so a record from a build
/// whose decoder changed no longer matches the artifact the old one wrote —
/// which is the whole reason a golden record carries digests.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxExportResult {
    pub name: String,
    pub address: u32,
    pub length: u32,
    pub sha256: String,
    /// What produced these bytes, as one sentence, for
    /// `project.edit`'s `register_capture` to record.
    ///
    /// **Composed here rather than by whoever registers it.** A capture is bytes
    /// no one can obtain again, so the note is the only provenance they will
    /// ever have — and a person writing it from memory writes prose that happens
    /// to be true. This is written from the recipe: the image's digest, the hunk
    /// and entry that ran, the range, and how the run stopped.
    ///
    /// Deterministic, like every other field of a record meant to be diffed: the
    /// same recipe over the same bytes composes the same sentence.
    pub capture_note: String,
}

/// One record the comparison read, and what identifies it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ComparedRecord {
    /// The locator the request named it by, so a difference's positional values
    /// can be read back to a file.
    pub name: String,
    /// The digest of the record *file*, which is what pins the comparison.
    pub sha256: String,
    /// The image the recorded run read, as the record pins it.
    pub source: SourcePin,
    /// Whether the record carried a trace, and whether it was capped.
    pub has_trace: bool,
    pub trace_truncated: bool,
}

/// One field two or more records disagree about.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CompareDifference {
    /// What differs, in the record's own vocabulary: `inputs.d1`,
    /// `outputs.a0`, `stop`, `changed_memory[0x00021000]`, `export.frame`.
    pub field: String,
    /// Each record's value, in the order the request named them, rendered.
    ///
    /// Rendered rather than typed because one list holds registers, stop
    /// reasons and digests, and a caller comparing them is comparing *whether*
    /// they differ. The record itself is where a typed value is read from.
    pub values: Vec<String>,
}

/// Where two traces first execute different instructions.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TraceDivergence {
    /// The step index, counted from the start of the retained trace.
    pub step: u64,
    /// Each record's state at that step, in request order.
    pub records: Vec<DivergentStep>,
}

/// One record's instruction at the diverging step.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DivergentStep {
    pub address: u32,
    pub text: String,
    /// How many times this record had already executed *this address* before
    /// this step.
    ///
    /// The occurrence is what makes a divergence inside a loop readable: two
    /// traces that both stop at the same address say nothing until you know one
    /// was on its third pass and the other on its ninth. Aligning by address
    /// plus occurrence rather than by row number is what this field is for.
    pub occurrence: u64,
}

/// Whether the traces could be compared, and what limits the answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceComparison {
    /// Compared over this many steps — the shortest retained trace.
    ///
    /// `truncated` says at least one record's trace was capped, so a divergence
    /// after `steps` is invisible and "no divergence" means "none in the part
    /// that was kept". Stating that is the difference between a comparison and
    /// a claim.
    Compared { steps: u64, truncated: bool },
    /// At least one record carried no trace, so there was nothing to align.
    /// Records are compared on everything else.
    Absent,
}

/// The `env.sandbox.compare` result.
///
/// The two difference lists are the point. A record holds what a routine was
/// *given* and what it *did*, and a textual diff cannot tell them apart — so it
/// reports a changed input register and a changed output register as the same
/// kind of finding, when one is the question and the other is the answer.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxCompareResult {
    pub records: Vec<ComparedRecord>,
    /// Whether every record read the same image. When false, a behavioral
    /// difference may be a difference between two programs.
    pub same_source: bool,
    /// Whether the records agree on everything, inputs included.
    pub identical: bool,
    /// Whether they agree on everything they *did*, whatever they were given.
    ///
    /// The useful answer when the inputs deliberately differ: two cases of a
    /// sweep that behaved identically under different inputs is a finding.
    pub same_behavior: bool,
    /// Differences in what the records were given.
    pub input_differences: Vec<CompareDifference>,
    pub input_differences_total: u64,
    /// Differences in what they did.
    pub behavioral_differences: Vec<CompareDifference>,
    pub behavioral_differences_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_divergence: Option<TraceDivergence>,
    pub trace_comparison: TraceComparison,
}

/// What became of one case of a matrix.
///
/// Three outcomes, and the two that are not "it ran" exist so that a case cannot
/// leave the result by being absent. A sweep of three hundred cases is read by
/// counting, and a count that silently omitted the refusals would report a
/// coverage the run did not have.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCaseOutcome {
    /// It ran. `stop` says how it ended, and `returned` whether that was cleanly.
    Ran,
    /// It was refused before executing anything — a seed outside the source, a
    /// region that would not map. `diagnostics` says which.
    Refused,
    /// It was never attempted: the matrix's aggregate step budget was already
    /// too small for this case's own budget.
    ///
    /// A distinct outcome rather than a refusal, because nothing is wrong with
    /// the case. Running it needs a larger `maximum_total_steps`, which is a
    /// different remedy from fixing a request.
    NotRun,
}

/// One run of memory a case changed, digested rather than carried.
///
/// A matrix returns the shape of a change and not the bytes: three hundred cases
/// carrying their changed memory is a response nobody can read and a size nobody
/// bounded. The digest is what two cases are compared by, and
/// `env.sandbox.call` on the case's own recipe is what produces the bytes when
/// one of them turns out to matter.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MatrixRegionDigest {
    pub address: u32,
    pub length: u32,
    pub sha256: String,
}

/// One case of a matrix, as the aggregate reports it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxMatrixCaseResult {
    pub name: String,
    /// The digest of *this case's* normalized request, not the matrix's.
    ///
    /// So a case can be cited, re-run through `env.sandbox.call`, and shown to
    /// be the same recipe — which is what makes a matrix a set of ordinary
    /// calls rather than a second execution path.
    pub recipe_sha256: String,
    pub outcome: MatrixCaseOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// The absolute address this case entered at. Present when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<SandboxRegisters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<SandboxRegisters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<SandboxStop>,
    /// Whether the routine returned cleanly. False for a case that did not run,
    /// which is why `outcome` is what a reader counts rather than this.
    pub returned: bool,
    pub steps_executed: u64,
    pub changed_regions: Vec<MatrixRegionDigest>,
    /// Runs of changed memory this case produced before the report cap.
    pub changed_regions_total: u64,
    pub changed_regions_truncated: bool,
    pub exported_regions: Vec<SandboxExportResult>,
    /// Why this case was refused. Empty unless `outcome` is `refused`.
    pub diagnostics: Vec<crate::diagnostics::Diagnostic>,
}

/// The `env.sandbox.matrix` result: every case, and the totals over them.
///
/// The totals are stated rather than left to be counted, because they are what a
/// sweep is read by, and a reader who has to count three hundred entries to
/// learn that two failed will not.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxMatrixResult {
    /// The image every case ran over, read from the first case that ran.
    ///
    /// `None` only when *no* case ran — and the result is still returned then,
    /// carrying every case's own refusal. A matrix that answered with nothing
    /// because nothing succeeded would lose the diagnostics that say why, which
    /// is the one thing a failed sweep is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourcePin>,
    /// Which CODE hunk the cases ran, read from the first that ran.
    ///
    /// Absent for the same reason `source` is, and not defaulted to zero: hunk 0
    /// is a real answer, and reporting it for a matrix that ran nothing would be
    /// a fact nothing established.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// The shared recipe's digest. Every case's digest differs from it and from
    /// each other's; this is what says which experiment they are cases of.
    pub base_recipe_sha256: String,
    pub cases_total: u64,
    /// Cases that executed, whether or not they returned cleanly.
    pub cases_ran: u64,
    /// Cases that ran *and* returned cleanly — the count a caller checks.
    pub cases_returned: u64,
    /// Cases refused before executing anything.
    pub cases_refused: u64,
    /// Cases never attempted because the aggregate budget was spent.
    pub cases_not_run: u64,
    pub steps_executed_total: u64,
    /// The aggregate budget this matrix ran under, after clamping.
    pub maximum_total_steps: u64,
    /// Whether the aggregate budget stopped the matrix short.
    pub budget_exhausted: bool,
    pub cases: Vec<SandboxMatrixCaseResult>,
}

/// What became of one step of a timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineStepOutcome {
    /// It ran. `stop` says how it ended.
    Ran,
    /// It was refused before executing anything — a seed outside the source, a
    /// checkpoint over unmapped memory, a resume after a step that returned.
    /// `diagnostics` says which.
    Refused,
    /// It was never attempted.
    ///
    /// Either the aggregate budget was already too small for this step's own,
    /// or an earlier step was refused — and a timeline does not continue past a
    /// refusal, because every step after it would run against a machine the
    /// request never described and report outputs that look valid.
    NotRun,
}

/// One range of memory as one step left it.
///
/// Digested rather than carried, for the reason a matrix digests its changed
/// regions: a timeline of sixty ticks each checkpointing a framebuffer is a
/// response nobody can read. `env.sandbox.call.export` on the same recipe is
/// what produces the bytes when one of them turns out to matter.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TimelineCheckpoint {
    pub name: String,
    pub address: u32,
    pub length: u32,
    pub sha256: String,
}

/// One step of a timeline, as the result reports it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxTimelineStepResult {
    pub name: String,
    pub outcome: TimelineStepOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Whether this step continued the previous one rather than entering a
    /// routine. What makes the sequence readable as a sequence.
    pub resumed: bool,
    /// The absolute address the step started executing at. Present when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<u32>,
    /// The register file the step started with, and the one it left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<SandboxRegisters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<SandboxRegisters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<SandboxStop>,
    /// Whether the step's routine returned to the marker. Always false for a
    /// step that did not run, which is why `outcome` is what a reader counts.
    pub returned: bool,
    pub steps_executed: u64,
    /// Runs of memory *this step's execution* changed, digested. The step's own
    /// seeds are applied before the baseline is taken, so they are inputs here
    /// rather than effects.
    pub changed_regions: Vec<MatrixRegionDigest>,
    pub changed_regions_total: u64,
    pub changed_regions_truncated: bool,
    /// The bytes the step's seeds wrote, so a reader can see what was injected
    /// between two ticks without opening the request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_seeds: Vec<SandboxSeedResult>,
    /// This step's own trace rows, when the shared recipe asked for a trace.
    ///
    /// Per step rather than one run of them, because a timeline's whole claim is
    /// that its steps are separable: a single concatenated trace would lose the
    /// boundaries that say which tick an instruction belongs to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<SandboxStep>,
    /// Rows this step would have traced. Always the true total, so a capped
    /// trace never reads as a short step.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub trace_total: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trace_truncated: bool,
    /// Accesses that matched a watched range while this step ran.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub watch_events_total: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub watch_events_truncated: bool,
    /// Interrupts delivered while this step ran, in global schedule order.
    ///
    /// The `step` inside each row is the schedule's instruction count across
    /// the whole timeline, not a count restarted at this step boundary.
    pub interrupts_delivered: Vec<SandboxInterruptDelivery>,
    /// Deliveries made while this step ran, including rows past the shared
    /// timeline retention cap.
    pub interrupts_total: u64,
    /// Whether this step delivered rows that the shared cap could not retain.
    pub interrupts_truncated: bool,
    pub checkpoints: Vec<TimelineCheckpoint>,
    /// Why this step was refused. Empty unless `outcome` is `refused`.
    pub diagnostics: Vec<crate::diagnostics::Diagnostic>,
}

/// The `env.sandbox.timeline` result: one machine's history, step by step.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxTimelineResult {
    /// The image the timeline ran over.
    pub source: SourcePin,
    /// Which CODE hunk it ran.
    pub hunk: u32,
    /// The shared recipe's digest: what says which machine these are steps of.
    pub base_recipe_sha256: String,
    pub steps_total: u64,
    pub steps_ran: u64,
    pub steps_refused: u64,
    pub steps_not_run: u64,
    pub instructions_executed_total: u64,
    /// The aggregate budget this timeline ran under, after clamping.
    pub maximum_total_steps: u64,
    /// Whether the aggregate budget stopped the timeline short.
    pub budget_exhausted: bool,
    /// Interrupt deliveries made across every step, including unretained rows.
    pub interrupts_total: u64,
    /// Whether the per-step delivery lists omit rows past the timeline-wide
    /// retention cap.
    pub interrupts_truncated: bool,
    pub steps: Vec<SandboxTimelineStepResult>,
    /// The registers and memory the whole timeline left behind: the shared
    /// recipe's `memory_exports`, digested against the final machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_registers: Option<SandboxRegisters>,
    pub final_exports: Vec<TimelineCheckpoint>,
    /// The custom-chip configuration the timeline ran under. Absent when none
    /// was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_chips: Option<SandboxCustomChips>,
    /// The blits the whole timeline performed or refused, capped.
    ///
    /// At the timeline's level rather than at each step's, because the blitter
    /// is one device driven by one machine: its own retention cap is run-wide,
    /// so a per-step split would report a prefix under each step and let a
    /// reader add them up into a number no run had.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blits: Vec<SandboxBlit>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub blits_total: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub attempted_blit_words_total: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub executed_blit_words_total: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chip_observations: Vec<SandboxChipObservation>,
}

/// The `env.sandbox.timeline.export` result: the timeline, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxTimelineExportResult {
    pub result: SandboxTimelineResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `env.sandbox.matrix.export` result: the sweep, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxMatrixExportResult {
    pub result: SandboxMatrixResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `env.sandbox.call.export` result: the record, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxCallExportResult {
    pub record: SandboxCallResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// The `env.boot.info` result: what a floppy's boot block declares about itself.
///
/// The checksum is reported as *stored* beside whether it verifies, rather than
/// as a pass or a fail. A trackloader disk with a deliberately wrong checksum is
/// a normal thing to find, and a result that only said "invalid" would lose the
/// number a reader needs to recognize which one.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BootInfoResult {
    pub source: SourcePin,
    /// The four-byte tag, as text. `DOS` for an AmigaDOS disk.
    pub tag: String,
    /// The fourth tag byte: the filesystem flags.
    pub flags: u8,
    /// Whether the tag is `DOS`. A disk that is not is usually a trackloader.
    pub is_dos: bool,
    /// The filesystem the flags name, e.g. `OFS` or `FFS`.
    pub filesystem: String,
    pub stored_checksum: u32,
    pub checksum_valid: bool,
    pub root_block: u32,
    /// Whether the boot code area holds anything but zeroes.
    pub has_boot_code: bool,
    /// Bytes of boot code, from `Bootblock::CODE_OFFSET` to the end of the two
    /// blocks. Constant for a floppy, reported so a caller need not know it.
    pub boot_code_bytes: u64,
}

/// Why a sandbox run stopped.
///
/// Every variant is a distinct fact about the code, not a shade of failure:
/// returning, exhausting the budget, executing `STOP`, faulting on an unmapped
/// address, trapping, touching a watched range, or calling a vector nothing
/// emulates. Collapsing them into "it stopped" would throw away the only thing
/// the run was for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum SandboxStop {
    /// The routine executed `RTS` and popped the seeded return marker.
    Returned,
    /// The step budget was exhausted.
    StepLimit,
    /// A `STOP` instruction halted the CPU.
    Stopped,
    /// An unmapped access trapped execution.
    Fault {
        address: u32,
        access: AccessDirection,
        /// Access width in bytes.
        size: u8,
        /// Address of the instruction that made it.
        site: u32,
    },
    /// An exception vector other than an unmapped access was raised.
    Trap { vector: u8, site: u32 },
    /// A watched access matched and stop-on-watch was requested.
    Watch {
        address: u32,
        access: AccessDirection,
        size: u8,
        site: u32,
    },
    /// A library vector nothing emulates was called. `offset` is its signed
    /// library-vector offset, which is what names it against an fd table — the
    /// naming itself is the frontend's, because the tables are its configuration.
    UnhandledCall { site: u32, offset: i32 },
    /// Execution reached an address the recipe asked it to stop at.
    ///
    /// Only `env.sandbox.timeline` states such addresses, so only its steps can
    /// stop this way. The instruction at `site` has not executed: it is where
    /// the machine is now, and a step that resumes from here executes it.
    Breakpoint { site: u32 },
}

/// One executed instruction, as a trace row.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxStep {
    /// Zero-based index of the executing iteration.
    pub index: u64,
    /// Address of the instruction.
    pub address: u32,
    /// Disassembled instruction text.
    pub text: String,
    /// Registers this instruction changed. The program counter is excluded: the
    /// following row's address already says where it went.
    pub register_deltas: Vec<SandboxRegisterDelta>,
    /// Memory writes this instruction performed, as far as the bounded write
    /// log retained them.
    pub writes: Vec<SandboxWrite>,
    /// Whether this instruction wrote more than `writes` lists, because the
    /// write log had reached its retention cap.
    ///
    /// Present only when it is true. Without it an empty `writes` cannot be told
    /// apart from an instruction that wrote nothing, and past the cap that is
    /// every remaining row — including the one that straddles the boundary and
    /// lists only part of what it wrote.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub writes_truncated: bool,
    /// Accesses that matched a watched range.
    pub watch_hits: Vec<SandboxAccess>,
    /// The exception vector this instruction raised, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<u8>,
}

/// One register an instruction changed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxRegisterDelta {
    /// The register's name as the disassembler spells it, e.g. `d0` or `a6`.
    pub register: String,
    pub before: u32,
    pub after: u32,
}

/// One memory write a trace row records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxWrite {
    pub address: u32,
    pub size: u8,
    pub value: u32,
}

/// One watched access, with both sides of it.
///
/// A read has `before == after`; a write does not. Both are reported because
/// what a watch is usually for is seeing what a value *became*.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxAccess {
    pub address: u32,
    pub access: AccessDirection,
    pub size: u8,
    pub before: u32,
    pub after: u32,
}

/// The register file when a run stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SandboxRegisters {
    pub d: [u32; 8],
    pub a: [u32; 7],
    pub usp: u32,
    pub ssp: u32,
    pub pc: u32,
    pub sr: u16,
}

/// The `env.sandbox.run` result.
///
/// The memory map is reported because it is what the addresses in the trace
/// mean: a run whose layout a reader has to reconstruct from the request is a
/// run whose trace they cannot check.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxRunResult {
    pub source: SourcePin,
    /// Which CODE hunk ran.
    pub hunk: u32,
    /// Absolute address the hunk was mapped at.
    pub load_origin: u32,
    /// Bytes of the hunk's allocation.
    pub allocation_bytes: u64,
    /// Absolute address execution started at.
    pub entry: u32,
    pub stack_base: u32,
    pub stack_top: u32,
    /// Instructions executed, whether or not a trace was kept.
    pub steps_executed: u64,
    pub stop: SandboxStop,
    pub registers: SandboxRegisters,
    /// The per-instruction trace, capped. Empty when none was asked for.
    pub trace: Vec<SandboxStep>,
    /// Rows the run produced before the cap. Always the true total.
    pub trace_total: u64,
    pub trace_truncated: bool,
    /// Accesses that matched a watched range, counted across the whole run.
    ///
    /// Not the same as the number of `watch_hits` the trace carries: the trace
    /// is capped in rows, retention is capped in events, and an attached device
    /// can make one instruction produce more matching accesses than a run makes
    /// instructions. This is the true total either way.
    pub watch_events_total: u64,
    /// Whether more accesses matched than were retained, so the `watch_hits` on
    /// the trace rows are a prefix rather than the whole set.
    pub watch_events_truncated: bool,
    /// Every write the run made, capped. Reported whether or not a trace was
    /// kept: what a sandbox run changed is the answer even when *how* it got
    /// there was not asked for.
    pub writes: Vec<SandboxWrite>,
    /// Writes the run made before the cap. Always the true total.
    pub writes_total: u64,
    pub writes_truncated: bool,
}

/// One band of raster lines and the registers that produced it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FrameInterval {
    /// First and last image row this band covers.
    pub first_line: u64,
    pub last_line: u64,
    /// The raster line the band starts at, so it reads against a Copper
    /// listing, which counts in raster lines.
    pub first_raster_line: u64,
    /// The bitplane pointers this band was fetched through — the field that
    /// says *which buffer* a double-buffered program was showing.
    pub bitplanes: Vec<u32>,
    /// The eight sprite pointers this band was fetched through.
    pub sprites: Vec<u32>,
    /// Sprite/playfield priority in force across this band.
    pub bplcon2: u16,
    /// The palette in force across this band, as RGB4 words.
    pub palette: Vec<u16>,
}

/// The `env.frame.capture` result: the picture, and where each band came from.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FrameCaptureResult {
    pub source: SourcePin,
    pub hunk: u32,
    pub entry: u32,
    /// How the run that produced the frame ended.
    pub stop: SandboxStop,
    pub steps_executed: u64,
    pub width: u64,
    pub height: u64,
    pub planes: u8,
    /// One palette index per pixel, row-major, hex-encoded.
    ///
    /// Preserved beside the RGBA rather than instead of it: an index is what
    /// the program wrote and a colour is only what one palette made of it, so a
    /// comparison that had lost the indices could not tell a palette change from
    /// a geometry change.
    pub indices: String,
    /// The digest of the raw index bytes, so a frame can be cited without
    /// carrying it.
    pub indices_sha256: String,
    /// One source code per pixel, row-major and hex-encoded: zero is the
    /// playfield, while 1–8 identify the winning sprite channel plus one.
    pub pixel_sources: String,
    /// The digest of the raw pixel-source bytes.
    pub pixel_sources_sha256: String,
    /// The digest of the RGBA the indices resolve to under the per-band
    /// palettes.
    pub rgba_sha256: String,
    pub intervals: Vec<FrameInterval>,
    /// The display registers as the run left them, for a reader checking the
    /// geometry against the program rather than against this reconstruction.
    pub registers: FrameRegisters,
}

/// The display registers a capture reconstructed from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FrameRegisters {
    pub bplcon0: u16,
    pub bplcon1: u16,
    pub bplcon2: u16,
    pub diwstrt: u16,
    pub diwstop: u16,
    pub ddfstrt: u16,
    pub ddfstop: u16,
    pub bpl1mod: i32,
    pub bpl2mod: i32,
    pub dmacon: u16,
    /// `SPR0PT`–`SPR7PT`, assembled from their high and low words.
    pub sprite_pointers: [u32; 8],
}

/// The `env.frame.capture.export` result: the frame, plus the write plan.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FrameCaptureExportResult {
    pub frame: FrameCaptureResult,
    pub plan: crate::output::WritePlan,
    pub committed: bool,
}

/// One instruction a dependency slice reached.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SliceStepResult {
    /// The trace row's index, which together with the address is what makes a
    /// loop unambiguous.
    pub index: u64,
    pub address: u32,
    /// How many times this address had already been executed when this row ran,
    /// counted from one.
    pub occurrence: u32,
    pub text: String,
    /// How many edges away from the seed this step was first reached.
    pub depth: u64,
    /// The locations this step defined that the slice depends on, as `d0`,
    /// `a5`, `ccr` or `[0x00021000]`.
    pub defines: Vec<String>,
    /// The locations this step read, as far as the model resolves them.
    pub uses: Vec<String>,
}

/// Why one chain of a slice ended.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SliceStopResult {
    /// The location was never written during the run, so its value is an input:
    /// a seeded register, a memory seed, or a byte of the loaded image. The
    /// answer a slice is looking for.
    Input { location: String },
    /// A step this build could not decode against the memory the run started
    /// with, so what it read is unknown — self-modifying code, or an
    /// instruction outside the hunk the slice reads.
    Undecodable { step: u64, address: u32 },
    /// The depth bound stopped the walk. The chain continues past here and this
    /// slice does not say where.
    DepthReached,
    /// The step budget stopped the walk, for the same reason.
    StepsReached,
    /// The seed named an execution the run never performed: `address` was
    /// executed `executed` times and the question asked about the
    /// `occurrence`-th. A fact about an execution rather than about a byte of
    /// memory, which is why it is not `input`.
    NotExecuted {
        address: u32,
        occurrence: u32,
        executed: u32,
    },
}

/// The `env.sandbox.slice` result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SandboxSliceResult {
    pub source: SourcePin,
    pub hunk: u32,
    pub entry: u32,
    pub stop: SandboxStop,
    pub steps_executed: u64,
    /// What the slice was asked to explain, as it was resolved.
    pub seed: String,
    /// The instructions it reached, newest first — the order the question was
    /// asked in, since a reader starts at the value and walks back.
    pub steps: Vec<SliceStepResult>,
    pub steps_total: u64,
    pub steps_truncated: bool,
    pub stops: Vec<SliceStopResult>,
    /// Whether the reported uses are an over-approximation.
    ///
    /// Always true for a slice that reached anything, and stated rather than
    /// implied: a superset presented as a minimum is a different claim. The
    /// slice may include a dependency the run did not really have and will not
    /// miss one it did, which is the safe direction for evidence.
    pub uses_are_a_superset: bool,
    /// Whether the run's own trace was capped before the slice walked it. A
    /// capped trace bounds what any slice over it can find, and a slice that
    /// did not say so would read as a complete answer.
    pub trace_truncated: bool,
}
