//! The normalized `env.*` requests, and what filling their defaults decides.
use std::collections::BTreeSet;

use super::*;

/// The file name a golden record uses when the request names none.
const DEFAULT_GOLDEN_FILE_NAME: &str = "golden.json";

/// The step budget a sandbox run uses when the request names none.
const DEFAULT_SANDBOX_STEPS: usize = 100_000;

/// Trace rows returned when the request names no cap.
const DEFAULT_TRACE_ROWS: usize = 20_000;

/// Watched ranges one request may state.
///
/// Every watchpoint is compared against every memory access, so the list is a
/// per-access cost rather than a per-request one, and an attached device can
/// make a single instruction perform a quarter of a million accesses.
///
/// The excess is **refused rather than truncated**. Silently dropping a
/// watchpoint would make a run that observed nothing indistinguishable from one
/// that had nothing to observe, which is the worst answer a watch can give.
const MAXIMUM_WATCHPOINTS: usize = 64;

/// Lowercase or uppercase hex into bytes, or `None` for anything else.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// Fully resolved `env.boot.trace` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBootTrace {
    pub source: NormalizedSource,
    pub maximum_steps: usize,
    pub watch: Vec<crate::request::WatchRange>,
    pub stop_on_watch: bool,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `env.boot.trace.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBootTraceExport {
    pub trace: NormalizedBootTrace,
    pub destination: DestinationName,
    pub policy: OutputPolicy,
}

/// Fully resolved `env.sandbox.call` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxCall {
    pub run: NormalizedSandboxRun,
    pub stack_arguments: Vec<u32>,
    pub mapped_regions: Vec<crate::request::MappedRegion>,
    /// Decoded once, here, so the handler never parses hex and a malformed seed
    /// is a bad request rather than a failed run.
    pub memory_seeds: Vec<NormalizedMemorySeed>,
    /// Ranges of final memory the recipe names as artifacts.
    pub memory_exports: Vec<crate::request::MemoryExport>,
    /// Interrupts delivered on a deterministic instruction schedule.
    pub interrupts: Vec<NormalizedInterrupt>,
    /// The custom-chip configuration, resolved. `None` means the `$DFF000`
    /// range is whatever `mapped_regions` made of it, as it always was.
    pub custom_chips: Option<NormalizedCustomChips>,
}

/// A resolved custom-chip configuration.
///
/// Two normalization rules keep equal recipes equal. An empty `custom_chips`
/// object means an emulating OCS blitter with the defaults, so one request
/// cannot be spelled two ways that mean two things. And under
/// [`NormalizedBlitterMode::Shadow`] the DMA policy and the word budget have no
/// effect, so they are **dropped** here: two shadow recipes differing only in a
/// field that does nothing must not produce different digests, and the record
/// must not report a policy that did not apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedCustomChips {
    pub chipset: crate::request::Chipset,
    pub mode: NormalizedBlitterMode,
}

/// The blitter half of a resolved configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizedBlitterMode {
    /// Blits are performed, under this policy and this budget.
    Emulate {
        dma: crate::request::BlitterDma,
        maximum_words: u64,
    },
    /// Register cells only. Carries nothing, because nothing else applies.
    Shadow,
}

/// One fully resolved interrupt delivery schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedInterrupt {
    pub handler: crate::request::ScheduledInterrupt,
    pub after_steps: usize,
    pub every_steps: Option<usize>,
    pub deliveries: Option<usize>,
}

/// One resolved seed: where it goes, and where its bytes come from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedMemorySeed {
    pub address: u32,
    pub bytes: SeedBytes,
}

/// A seed's bytes, decoded where they could be and named where they could not.
///
/// Hex is decoded at normalization, so a malformed seed is a bad request rather
/// than a failed run. A range names a source, and resolving a source needs the
/// execution context — so that one is carried as a recipe and read by the
/// handler, which is also where the bytes it names can be bounds-checked
/// against the source that actually holds them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SeedBytes {
    Literal(Vec<u8>),
    Range {
        source: Option<NormalizedSource>,
        hunk: Option<u32>,
        offset: u32,
        length: u32,
    },
    /// A file an earlier run wrote, pinned by digest. The length is optional
    /// here and resolved by the handler, because "the rest of the file" is a
    /// fact about the file and normalization has not opened it — the digest is
    /// what makes that exact rather than a guess.
    Artifact {
        source: NormalizedSource,
        sha256: String,
        offset: u32,
        length: Option<u32>,
    },
}

/// Fully resolved `env.sandbox.call.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxCallExport {
    pub call: NormalizedSandboxCall,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// Fully resolved `env.boot.info` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBootInfo {
    pub source: NormalizedSource,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `env.sandbox.run` arguments.
///
/// Everything is materialized: a caller who omitted the step budget and one who
/// spelled out the default produce the same request digest, and every bound the
/// run honours is visible here rather than applied later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxRun {
    pub source: NormalizedSource,
    pub hunk: Option<u32>,
    pub load_origin: Option<u32>,
    pub entry_offset: u32,
    pub hunk_bases: Vec<crate::request::HunkBase>,
    pub stack: Option<crate::request::StackRegion>,
    pub maximum_steps: usize,
    pub data_registers: [u32; 8],
    pub address_registers: [u32; 7],
    pub watch: Vec<crate::request::WatchRange>,
    pub stop_on_watch: bool,
    pub trace: bool,
    pub maximum_trace_rows: usize,
    pub maximum_input_bytes: u64,
}

/// The canonical form of one boot trace, shared by the read and the export.
pub(super) fn boot_trace_document(trace: &NormalizedBootTrace) -> Value {
    json!({
        "source": trace.source.canonical(),
        "maximum_steps": trace.maximum_steps,
        "watch": trace.watch
            .iter()
            .map(|watch| json!({
                "start": watch.start,
                "length": watch.length,
                "access": watch.access,
            }))
            .collect::<Vec<_>>(),
        "stop_on_watch": trace.stop_on_watch,
        "maximum_input_bytes": trace.maximum_input_bytes,
    })
}

/// The canonical form of one sandbox run, shared by `run` and `call`.
pub(super) fn sandbox_run_document(run: &NormalizedSandboxRun) -> Value {
    json!({
        "source": run.source.canonical(),
        "hunk": run.hunk,
        "load_origin": run.load_origin,
        "entry_offset": run.entry_offset,
        "hunk_bases": run.hunk_bases
            .iter()
            .map(|base| json!({ "hunk": base.hunk, "address": base.address }))
            .collect::<Vec<_>>(),
        "stack": run.stack.map(|stack| json!({ "base": stack.base, "size": stack.size })),
        "maximum_steps": run.maximum_steps,
        "data_registers": run.data_registers,
        "address_registers": run.address_registers,
        "watch": run.watch
            .iter()
            .map(|watch| json!({
                "start": watch.start,
                "length": watch.length,
                "access": watch.access,
            }))
            .collect::<Vec<_>>(),
        "stop_on_watch": run.stop_on_watch,
        // The trace is a *view* of the run, not a change to it: the same code
        // executes either way. It is in the digest anyway because it changes the
        // response, and a cache keyed on the digest must not serve a traceless
        // answer to a trace request.
        "trace": run.trace,
        "maximum_trace_rows": run.maximum_trace_rows,
        "maximum_input_bytes": run.maximum_input_bytes,
    })
}

/// The canonical form of one call, shared by the read and the export.
pub(super) fn sandbox_call_document(call: &NormalizedSandboxCall) -> Value {
    json!({
        "run": sandbox_run_document(&call.run),
        "stack_arguments": call.stack_arguments,
        "mapped_regions": call.mapped_regions
            .iter()
            .map(|region| json!({ "address": region.address, "size": region.size }))
            .collect::<Vec<_>>(),
        "memory_seeds": seeds_document(&call.memory_seeds),
        "memory_exports": call.memory_exports
            .iter()
            .map(|export| json!({
                "address": export.address,
                "length": export.length,
                "name": export.name,
            }))
            .collect::<Vec<_>>(),
        "interrupts": call.interrupts
            .iter()
            .map(|interrupt| json!({
                "vector": interrupt.handler.vector,
                "address": interrupt.handler.address,
                "after_steps": interrupt.after_steps,
                "every_steps": interrupt.every_steps,
                "deliveries": interrupt.deliveries,
                "frame": interrupt.handler.frame.unwrap_or_default(),
            }))
            .collect::<Vec<_>>(),
        // What drew the pixels is part of the recipe: two calls that ran under
        // different chips must not share a digest, and two that ran under the
        // same chips spelled differently must.
        "custom_chips": call.custom_chips.map(custom_chips_document),
    })
}

/// The canonical form of one list of resolved seeds.
///
/// The decoded bytes, not the hex the request spelled them with: two requests
/// differing only in letter case describe the same run. Shared by a call and by
/// a timeline step, so the two cannot come to digest one seed differently.
pub(super) fn seeds_document(seeds: &[NormalizedMemorySeed]) -> Value {
    seeds
        .iter()
        .map(|seed| match &seed.bytes {
            SeedBytes::Literal(bytes) => json!({ "address": seed.address, "bytes": bytes }),
            SeedBytes::Artifact {
                source,
                sha256,
                offset,
                length,
            } => json!({
                "address": seed.address,
                // The digest is part of the question, not decoration: two
                // requests replaying different files into the same address are
                // two different runs.
                "artifact": source.canonical(),
                "sha256": sha256,
                "offset": offset,
                "length": length,
            }),
            SeedBytes::Range {
                source,
                hunk,
                offset,
                length,
            } => json!({
                "address": seed.address,
                "from": {
                    "source": source.as_ref().map(NormalizedSource::canonical),
                    "hunk": hunk,
                    "offset": offset,
                    "length": length,
                },
            }),
        })
        .collect::<Vec<_>>()
        .into()
}

/// The canonical form of a resolved custom-chip configuration.
pub(super) fn custom_chips_document(chips: NormalizedCustomChips) -> Value {
    match chips.mode {
        NormalizedBlitterMode::Emulate { dma, maximum_words } => json!({
            "chipset": chips.chipset,
            "blitter": {
                "mode": "emulate",
                "dma": dma,
                "maximum_words": maximum_words,
            },
        }),
        // Deliberately without `dma` or `maximum_words`: under shadow mode they
        // do nothing, and a digest that changed with them would make two
        // identical runs look different.
        NormalizedBlitterMode::Shadow => json!({
            "chipset": chips.chipset,
            "blitter": { "mode": "shadow" },
        }),
    }
}

/// The canonical form of one `env.sandbox.call.export`.
/// Fully resolved `env.sandbox.compare` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxCompare {
    pub records: Vec<NormalizedSource>,
    pub maximum_differences: usize,
    pub maximum_input_bytes: u64,
}

/// The canonical form of one `env.sandbox.compare`.
///
/// The record order is part of the question rather than a detail of how it was
/// asked: a difference reports one value per record positionally, so two
/// requests naming the same files in a different order produce answers a reader
/// cannot interchange.
pub(super) fn sandbox_compare_document(compare: &NormalizedSandboxCompare) -> Value {
    json!({
        "records": compare.records
            .iter()
            .map(NormalizedSource::canonical)
            .collect::<Vec<_>>(),
        "maximum_differences": compare.maximum_differences,
        "maximum_input_bytes": compare.maximum_input_bytes,
    })
}

/// Fully resolved `env.sandbox.matrix` arguments.
///
/// Every case is already a complete, validated call by the time this exists.
/// Expansion is normalization's job rather than the handler's, because the
/// request's own promise is that a malformed case refuses the *matrix* — a
/// handler that expanded as it went would have run half a sweep before finding
/// out, and the half it ran would be the misleading partial result the project's
/// recover-then-commit rule exists to prevent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxMatrix {
    /// The shared recipe, kept so the result can say which experiment these are
    /// cases of.
    pub base: NormalizedSandboxCall,
    /// The shared recipe's own digest, over the same document a case's is over.
    ///
    /// Computed here rather than by the handler because this is where the
    /// canonical document lives: a digest taken anywhere else would be a second
    /// definition of what a recipe is, and the two could drift.
    pub base_digest: String,
    pub cases: Vec<NormalizedMatrixCase>,
    /// Instructions the whole matrix may execute.
    pub maximum_total_steps: usize,
}

/// One expanded case: its name, its own complete call, and its own digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedMatrixCase {
    pub name: String,
    pub notes: Option<String>,
    pub call: NormalizedSandboxCall,
    /// The digest of this case's canonical call document.
    ///
    /// Computed here, over the same document `env.sandbox.call` would digest,
    /// so a case cited out of a matrix and re-run on its own is provably the
    /// same recipe.
    pub digest: String,
}

/// Fully resolved `env.sandbox.timeline` arguments.
///
/// Every step is complete and validated by the time this exists, for the reason
/// a matrix expands at normalization: the request's promise is that a malformed
/// step refuses the *timeline*. It is stronger here than there. A timeline's
/// steps share one evolving machine, so a step refused halfway through would
/// leave the machine in a state the request never described — and every step
/// after it would run against that state and report outputs that look valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxTimeline {
    /// The machine every step runs in.
    pub base: NormalizedSandboxCall,
    /// The shared recipe's own digest, over the document `env.sandbox.call`
    /// digests, so the apparatus can be cited on its own.
    pub base_digest: String,
    pub steps: Vec<NormalizedTimelineStep>,
    /// Instructions the whole timeline may execute.
    pub maximum_total_steps: usize,
}

/// One resolved step: where it starts, what it is handed, and what it records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTimelineStep {
    pub name: String,
    pub notes: Option<String>,
    pub start: TimelineStart,
    pub memory_seeds: Vec<NormalizedMemorySeed>,
    pub maximum_steps: usize,
    /// Sorted and deduplicated: two spellings of one breakpoint are one
    /// breakpoint, and an order the request happened to write them in is not
    /// part of what it asked.
    pub stop_at: Vec<u32>,
    pub checkpoints: Vec<crate::request::MemoryExport>,
}

/// How one step starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimelineStart {
    /// Enter a routine: the registers are seeded, the arguments laid out, and
    /// the return marker pushed below them, exactly as `env.sandbox.call` does.
    Enter {
        entry_offset: u32,
        data_registers: [u32; 8],
        address_registers: [u32; 7],
        stack_arguments: Vec<u32>,
    },
    /// Continue the machine the previous step left.
    Resume,
}

/// The canonical form of one `env.sandbox.timeline`.
///
/// The steps carry their names because a timeline that renamed or reordered them
/// is a different experiment even when every run in it is identical: the name is
/// how a result is read back against the request, and the order *is* the
/// experiment.
pub(super) fn sandbox_timeline_document(timeline: &NormalizedSandboxTimeline) -> Value {
    json!({
        "base": sandbox_call_document(&timeline.base),
        "steps": timeline.steps
            .iter()
            .map(|step| json!({
                "name": step.name,
                "notes": step.notes,
                "start": match &step.start {
                    TimelineStart::Enter {
                        entry_offset,
                        data_registers,
                        address_registers,
                        stack_arguments,
                    } => json!({
                        "kind": "enter",
                        "entry_offset": entry_offset,
                        "data_registers": data_registers,
                        "address_registers": address_registers,
                        "stack_arguments": stack_arguments,
                    }),
                    TimelineStart::Resume => json!({ "kind": "resume" }),
                },
                "memory_seeds": seeds_document(&step.memory_seeds),
                "maximum_steps": step.maximum_steps,
                "stop_at": step.stop_at,
                "checkpoints": step.checkpoints
                    .iter()
                    .map(|checkpoint| json!({
                        "address": checkpoint.address,
                        "length": checkpoint.length,
                        "name": checkpoint.name,
                    }))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "maximum_total_steps": timeline.maximum_total_steps,
    })
}

/// Fill in what an `env.sandbox.timeline` request left unsaid.
///
/// The shared recipe normalizes first, so a fault in the apparatus is reported
/// where the caller wrote it rather than blamed on the first step that inherits
/// it — the same order, and for the same reason, as a matrix.
#[expect(
    clippy::too_many_lines,
    reason = "one step's rules, told in order; the refusals read as a list of what a step may not be"
)]
pub(super) fn sandbox_timeline(
    arguments: &crate::request::SandboxTimelineArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let base = normalize_sandbox_call(&arguments.base, limits, diagnostics)?;

    if arguments.steps.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a timeline needs at least one step; an empty one would report a run \
                 that executed nothing as a run that succeeded",
            )
            .at("$.request.arguments.steps"),
        ]);
    }
    let allowed = limits.maximum_matrix_cases();
    if arguments.steps.len() > allowed {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "the timeline has {} steps and at most {allowed} are permitted",
                    arguments.steps.len()
                ),
            )
            .at("$.request.arguments.steps"),
        ]);
    }

    let requested_total = arguments
        .maximum_total_steps
        .unwrap_or_else(|| limits.maximum_sandbox_steps());
    let maximum_total_steps = if requested_total > crate::limits::MAXIMUM_SANDBOX_STEPS_CEILING {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "aggregate step budget reduced from {requested_total} to {}",
                    crate::limits::MAXIMUM_SANDBOX_STEPS_CEILING
                ),
            )
            .at("$.request.arguments.maximum_total_steps"),
        );
        crate::limits::MAXIMUM_SANDBOX_STEPS_CEILING
    } else {
        requested_total
    };
    if maximum_total_steps == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a timeline with no step budget runs nothing, and would report every \
                 step of it as not run",
            )
            .at("$.request.arguments.maximum_total_steps"),
        ]);
    }

    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut steps = Vec::with_capacity(arguments.steps.len());
    for (index, step) in arguments.steps.iter().enumerate() {
        let at = |field: &str| format!("$.request.arguments.steps[{index}].{field}");
        if step.name.is_empty()
            || step.name.len() > 255
            || step.name.contains(['/', '\\'])
            || step.name == "."
            || step.name == ".."
        {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("step name {:?} is not a single path component", step.name),
                )
                .at(at("name")),
            ]);
        }
        if !names.insert(step.name.as_str()) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("two steps are both called {:?}", step.name),
                )
                .at(at("name")),
            ]);
        }

        let start = match (step.entry_offset, step.resume) {
            (Some(_), true) | (None, false) => {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        "a step enters a routine with `entry_offset` or continues the \
                         previous one with `resume`, and must state exactly one of the two",
                    )
                    .at(at("entry_offset")),
                ]);
            }
            (None, true) => {
                if index == 0 {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            "the first step cannot resume: there is no machine to continue",
                        )
                        .at(at("resume")),
                    ]);
                }
                // A resumed machine's registers are its own. Seeding them would
                // build a state no execution produced and attribute it to the
                // routine that is still running; memory seeds are how a step
                // injects a reviewed change.
                for (field, stated) in [
                    ("data_registers", step.data_registers.is_some()),
                    ("address_registers", step.address_registers.is_some()),
                    ("stack_arguments", step.stack_arguments.is_some()),
                ] {
                    if stated {
                        return Err(vec![
                            Diagnostic::error(
                                DiagnosticCode::RequestArgumentOutOfRange,
                                format!(
                                    "a resuming step cannot state {field}: it continues the \
                                     machine the previous step left, and replacing part of \
                                     that machine's state would build one no execution \
                                     produced. Use memory_seeds to inject a reviewed change."
                                ),
                            )
                            .at(at(field)),
                        ]);
                    }
                }
                TimelineStart::Resume
            }
            (Some(entry_offset), false) => {
                if !entry_offset.is_multiple_of(2) {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            format!(
                                "entry_offset {entry_offset:#x} is odd; an MC68000 raises an \
                                 address error on the first instruction fetch"
                            ),
                        )
                        .at(at("entry_offset")),
                    ]);
                }
                TimelineStart::Enter {
                    entry_offset,
                    data_registers: step.data_registers.unwrap_or(base.run.data_registers),
                    address_registers: step.address_registers.unwrap_or(base.run.address_registers),
                    stack_arguments: step
                        .stack_arguments
                        .clone()
                        .unwrap_or_else(|| base.stack_arguments.clone()),
                }
            }
        };

        let maximum_steps = match step.maximum_steps {
            None => base.run.maximum_steps,
            Some(0) => {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        "maximum_steps must be at least 1",
                    )
                    .at(at("maximum_steps")),
                ]);
            }
            Some(requested) => clamp_sandbox_steps(requested, limits, diagnostics),
        };

        for address in &step.stop_at {
            if !address.is_multiple_of(2) {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!(
                            "stop_at names the odd address {address:#x}; no instruction \
                             begins there, so the run could never reach it"
                        ),
                    )
                    .at(at("stop_at")),
                ]);
            }
        }
        let mut stop_at = step.stop_at.clone();
        stop_at.sort_unstable();
        stop_at.dedup();

        validate_memory_exports(&step.checkpoints, &at("checkpoints"))?;
        // The step's seeds go through the same decoding a call's do, so a
        // malformed one is a bad request rather than a timeline that stopped
        // halfway with a machine nobody described.
        let memory_seeds = normalize_memory_seeds(&step.memory_seeds, &at("memory_seeds"))?;

        steps.push(NormalizedTimelineStep {
            name: step.name.clone(),
            notes: step.notes.clone(),
            start,
            memory_seeds,
            maximum_steps,
            stop_at,
            checkpoints: step.checkpoints.clone(),
        });
    }

    Ok(NormalizedOperation::EnvSandboxTimeline(
        NormalizedSandboxTimeline {
            base_digest: amiga_core::sha256(sandbox_call_document(&base).to_string().as_bytes()),
            base,
            steps,
            maximum_total_steps,
        },
    ))
}

/// Fully resolved `env.sandbox.timeline.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxTimelineExport {
    pub timeline: NormalizedSandboxTimeline,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// The canonical form of one `env.sandbox.timeline.export`.
pub(super) fn sandbox_timeline_export_document(export: &NormalizedSandboxTimelineExport) -> Value {
    json!({
        "timeline": sandbox_timeline_document(&export.timeline),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// Fully resolved `env.sandbox.matrix.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxMatrixExport {
    pub matrix: NormalizedSandboxMatrix,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// The canonical form of one `env.sandbox.matrix.export`.
pub(super) fn sandbox_matrix_export_document(export: &NormalizedSandboxMatrixExport) -> Value {
    json!({
        "matrix": sandbox_matrix_document(&export.matrix),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one `env.sandbox.matrix`.
///
/// The cases carry their names because a matrix that reordered or renamed them
/// is a different experiment even when every call in it is identical: the name
/// is how a result is read back against the request.
pub(super) fn sandbox_matrix_document(matrix: &NormalizedSandboxMatrix) -> Value {
    json!({
        "base": sandbox_call_document(&matrix.base),
        "cases": matrix.cases
            .iter()
            .map(|case| json!({
                "name": case.name,
                "notes": case.notes,
                "call": sandbox_call_document(&case.call),
            }))
            .collect::<Vec<_>>(),
        "maximum_total_steps": matrix.maximum_total_steps,
    })
}

pub(super) fn sandbox_call_export_document(export: &NormalizedSandboxCallExport) -> Value {
    json!({
        "call": sandbox_call_document(&export.call),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The canonical form of one `env.boot.trace.export`.
///
/// Without a `file_name`: a boot trace export writes a directory of records
/// rather than one file, so there is no single name to configure.
pub(super) fn boot_trace_export_document(export: &NormalizedBootTraceExport) -> Value {
    json!({
        "trace": boot_trace_document(&export.trace),
        "destination": export.destination.as_str(),
        "policy": export.policy,
    })
}

/// The canonical form of one `env.boot.info`.
pub(super) fn boot_info_document(info: &NormalizedBootInfo) -> Value {
    source_only_document(&info.source, info.maximum_input_bytes)
}

/// Reduce a requested step budget to what this context permits, saying so.
///
/// Shared by every sandbox entry point, so a run, a call, and a boot cannot end
/// up with three ceilings that agree only by coincidence.
pub(super) fn clamp_sandbox_steps(
    requested: usize,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> usize {
    let ceiling = limits.maximum_sandbox_steps();
    if requested <= ceiling {
        return requested;
    }
    diagnostics.push(
        Diagnostic::warning(
            DiagnosticCode::LimitReduced,
            format!(
                "maximum_steps reduced from {requested} to the {ceiling} \
                 instructions this context allows"
            ),
        )
        .at("$.request.arguments.maximum_steps"),
    );
    ceiling
}

/// Resolve sandbox-run arguments, shared by `run` and `call`.
pub(super) fn normalize_sandbox_run(
    arguments: &crate::request::SandboxRunArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedSandboxRun, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    // An odd entry is an address error on an MC68000 the instant the
    // first fetch happens. Refusing it here says so, instead of letting
    // the run trap and making the caller work out why.
    let entry_offset = arguments.entry_offset.unwrap_or(0);
    if !entry_offset.is_multiple_of(2) {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "entry_offset {entry_offset:#x} is odd; an MC68000 raises an \
                         address error on the first instruction fetch"
                ),
            )
            .at("$.request.arguments.entry_offset"),
        ]);
    }
    let maximum_steps = arguments.maximum_steps.unwrap_or(DEFAULT_SANDBOX_STEPS);
    if maximum_steps == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "maximum_steps must be at least 1",
            )
            .at("$.request.arguments.maximum_steps"),
        ]);
    }
    // The ceiling is the context's, not the caller's. Sandbox code is unknown
    // code; a request that asked for an unbounded run would be asking the
    // process to hang. A host running local media it has reviewed may raise
    // the ceiling — to a larger number, never to none.
    let maximum_steps = clamp_sandbox_steps(maximum_steps, limits, diagnostics);
    validate_watch(&arguments.watch)?;
    let maximum_trace_rows = normalize_count(
        arguments.maximum_trace_rows.or(Some(DEFAULT_TRACE_ROWS)),
        limits.maximum_entries(),
        "maximum_trace_rows",
        "trace rows",
        diagnostics,
    )?;
    Ok(NormalizedSandboxRun {
        source,
        hunk: arguments.hunk,
        load_origin: arguments.load_origin,
        entry_offset,
        hunk_bases: arguments.hunk_bases.clone(),
        stack: arguments.stack,
        maximum_steps,
        data_registers: arguments.data_registers.unwrap_or([0; 8]),
        address_registers: arguments.address_registers.unwrap_or([0; 7]),
        watch: arguments.watch.clone(),
        stop_on_watch: arguments.stop_on_watch,
        trace: arguments.trace,
        maximum_trace_rows,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    })
}

/// Check the watched ranges a request states: how many, and that each one can
/// match something.
///
/// Shared by `env.sandbox.run` (and so by `env.sandbox.call`, which normalizes
/// its run arguments through it) and `env.boot.trace`, because all three watch
/// the same way and three copies of this rule would be three rules.
pub(super) fn validate_watch(watch: &[crate::request::WatchRange]) -> Result<(), Vec<Diagnostic>> {
    if watch.len() > MAXIMUM_WATCHPOINTS {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "{} watched ranges were stated; at most {MAXIMUM_WATCHPOINTS} are \
                     accepted, because every one of them is compared against every \
                     memory access",
                    watch.len()
                ),
            )
            .at("$.request.arguments.watch"),
        ]);
    }
    for (index, range) in watch.iter().enumerate() {
        if range.length == 0 {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "a watch range must be at least one byte; a zero-length one \
                     would silently never match",
                )
                .at(format!("$.request.arguments.watch[{index}].length")),
            ]);
        }
        if range.start.checked_add(range.length).is_none() {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "a watch range must not wrap the address space",
                )
                .at(format!("$.request.arguments.watch[{index}].length")),
            ]);
        }
    }
    Ok(())
}

/// Resolve boot-trace arguments, shared by the read and the export.
pub(super) fn normalize_boot_trace(
    arguments: &crate::request::BootTraceArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedBootTrace, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    let requested = arguments.maximum_steps.unwrap_or(DEFAULT_SANDBOX_STEPS);
    if requested == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "maximum_steps must be at least 1",
            )
            .at("$.request.arguments.maximum_steps"),
        ]);
    }
    // The same ceiling a sandbox run gets, for the same reason: boot code is
    // unknown code, and a trackloader that spins forever is the normal case.
    let maximum_steps = clamp_sandbox_steps(requested, limits, diagnostics);
    validate_watch(&arguments.watch)?;
    Ok(NormalizedBootTrace {
        source,
        maximum_steps,
        watch: arguments.watch.clone(),
        stop_on_watch: arguments.stop_on_watch,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    })
}

/// Resolve call arguments, shared by the read and the export.
///
/// The hex seeds are decoded here, so a malformed one is a bad request rather
/// than a run that failed halfway through setting up its own inputs.
pub(super) fn normalize_sandbox_call(
    arguments: &crate::request::SandboxCallArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedSandboxCall, Vec<Diagnostic>> {
    let run = normalize_sandbox_run(&arguments.run, limits, diagnostics)?;
    for (index, region) in arguments.mapped_regions.iter().enumerate() {
        if region.size == 0 {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "a mapped region must be at least one byte",
                )
                .at(format!("$.request.arguments.mapped_regions[{index}].size")),
            ]);
        }
    }
    let memory_seeds =
        normalize_memory_seeds(&arguments.memory_seeds, "$.request.arguments.memory_seeds")?;
    validate_memory_exports(
        &arguments.memory_exports,
        "$.request.arguments.memory_exports",
    )?;

    // An interrupt names its handler exactly one way, for the reason a seed
    // names its bytes exactly one way: with both there are two answers, and
    // with neither there is nothing to deliver.
    let mut interrupts = Vec::with_capacity(arguments.interrupts.len());
    for (index, interrupt) in arguments.interrupts.iter().enumerate() {
        let at = |field: &str| format!("$.request.arguments.interrupts[{index}].{field}");
        if interrupt.vector.is_some() == interrupt.address.is_some() {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "an interrupt names its handler with `vector` or with `address`, \
                     and must name exactly one of the two",
                )
                .at(at("vector")),
            ]);
        }
        if interrupt.every_steps == Some(0) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "every_steps must be at least 1; a period of zero would deliver \
                     without ever letting the handler run",
                )
                .at(at("every_steps")),
            ]);
        }
        if interrupt.deliveries == Some(0) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "deliveries must be at least 1; a schedule that delivers nothing \
                     is a schedule that was not meant",
                )
                .at(at("deliveries")),
            ]);
        }
        interrupts.push(NormalizedInterrupt {
            handler: *interrupt,
            after_steps: interrupt.after_steps.unwrap_or(0) as usize,
            every_steps: interrupt.every_steps.map(|period| period as usize),
            deliveries: interrupt.deliveries.map(|count| count as usize),
        });
    }

    let custom_chips = arguments
        .custom_chips
        .as_ref()
        .map(|chips| normalize_custom_chips(chips, limits, diagnostics))
        .transpose()?;
    if custom_chips.is_some() {
        // Only when custom chips were asked for: a recipe that deliberately uses
        // this range as ordinary RAM is a recipe that must keep working.
        for (index, region) in arguments.mapped_regions.iter().enumerate() {
            if overlaps_custom_chips(region.address, u64::from(region.size)) {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!(
                            "mapped region [{:#x}..+{:#x}) overlaps the custom-chip page                              [{CUSTOM_CHIP_BASE:#x}..+{CUSTOM_CHIP_SIZE:#x}), which this                              request asked to model; RAM and the chips cannot both answer                              an address",
                            region.address, region.size
                        ),
                    )
                    .at(format!("$.request.arguments.mapped_regions[{index}].address")),
                ]);
            }
        }
    }

    Ok(NormalizedSandboxCall {
        run,
        stack_arguments: arguments.stack_arguments.clone(),
        mapped_regions: arguments.mapped_regions.clone(),
        memory_seeds,
        memory_exports: arguments.memory_exports.clone(),
        interrupts,
        custom_chips,
    })
}

/// Decode and check one list of memory seeds, reporting against `prefix`.
///
/// Shared by `env.sandbox.call` and by a timeline step, because a seed means the
/// same thing wherever it is written and two copies of these rules would be two
/// rules. `prefix` is the JSON path of the list itself; each refusal names the
/// element and the field inside it.
fn normalize_memory_seeds(
    seeds: &[crate::request::MemorySeed],
    prefix: &str,
) -> Result<Vec<NormalizedMemorySeed>, Vec<Diagnostic>> {
    let mut memory_seeds = Vec::with_capacity(seeds.len());
    for (index, seed) in seeds.iter().enumerate() {
        let at = |field: &str| format!("{prefix}[{index}].{field}");
        // Serde cannot say "one or the other", so the shape is checked here. A
        // seed with both would have two answers to what it seeds; one with
        // neither would seed nothing while looking like it seeded something.
        let bytes = match (&seed.hex, &seed.from) {
            (Some(hex), None) if seed.artifact.is_none() => {
                let bytes = decode_hex(hex).ok_or_else(|| {
                    vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            "a memory seed must be an even-length string of hex digits",
                        )
                        .at(at("hex")),
                    ]
                })?;
                if bytes.is_empty() {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            "a memory seed must carry at least one byte",
                        )
                        .at(at("hex")),
                    ]);
                }
                SeedBytes::Literal(bytes)
            }
            (None, Some(range)) if seed.artifact.is_none() => {
                if range.length == 0 {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            "a memory seed must carry at least one byte",
                        )
                        .at(at("from.length")),
                    ]);
                }
                if range.offset.checked_add(range.length).is_none() {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            format!(
                                "seed range [{:#x}..+{:#x}) wraps",
                                range.offset, range.length
                            ),
                        )
                        .at(at("from.offset")),
                    ]);
                }
                SeedBytes::Range {
                    source: range.source.as_ref().map(normalize_source).transpose()?,
                    hunk: range.hunk,
                    offset: range.offset,
                    length: range.length,
                }
            }
            (None, None) if seed.artifact.is_some() => {
                // Unreachable: the match above is on `(hex, from)` and this arm
                // is the one where neither is set, so the artifact is the only
                // spelling left. Written as a guard rather than restructured so
                // the three-way exclusivity stays one refusal below.
                let artifact = seed.artifact.as_ref().unwrap_or_else(|| unreachable!());
                if artifact.length == Some(0) {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            "a memory seed must carry at least one byte",
                        )
                        .at(at("artifact.length")),
                    ]);
                }
                let offset = artifact.offset.unwrap_or(0);
                if let Some(length) = artifact.length
                    && offset.checked_add(length).is_none()
                {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            format!("seed range [{offset:#x}..+{length:#x}) wraps"),
                        )
                        .at(at("artifact.offset")),
                    ]);
                }
                // Checked here so a mistyped digest costs nothing to refuse,
                // and so the comparison the handler makes is against a value
                // that can only fail by being the wrong file.
                if artifact.sha256.len() != 64
                    || !artifact
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(vec![
                        Diagnostic::error(
                            DiagnosticCode::RequestArgumentOutOfRange,
                            "an artifact seed pins its file with a 64-character lowercase \
                             hex SHA-256",
                        )
                        .at(at("artifact.sha256")),
                    ]);
                }
                SeedBytes::Artifact {
                    source: normalize_source(&artifact.source)?,
                    sha256: artifact.sha256.clone(),
                    offset,
                    length: artifact.length,
                }
            }
            _ => {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        "a memory seed states its bytes as `hex`, copies them with \
                         `from`, or replays them from a pinned `artifact`, and must \
                         state exactly one of the three",
                    )
                    .at(at("hex")),
                ]);
            }
        };
        memory_seeds.push(NormalizedMemorySeed {
            address: seed.address,
            bytes,
        });
    }
    Ok(memory_seeds)
}

/// Check one list of named memory ranges, reporting against `prefix`.
///
/// A named range is an artifact, so its name has to be usable as a file name and
/// has to be the only one claiming it: two ranges under one name would write one
/// file and silently lose the other. Shared by a call's `memory_exports` and a
/// timeline step's `checkpoints`, which are the same thing recorded at two
/// different moments.
fn validate_memory_exports(
    exports: &[crate::request::MemoryExport],
    prefix: &str,
) -> Result<(), Vec<Diagnostic>> {
    let mut named: Vec<&str> = Vec::with_capacity(exports.len());
    for (index, export) in exports.iter().enumerate() {
        let at = |field: &str| format!("{prefix}[{index}].{field}");
        if export.length == 0 {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    "a memory export must be at least one byte; a zero-length range \
                     would write an empty file that looks like a successful export",
                )
                .at(at("length")),
            ]);
        }
        if export.address.checked_add(export.length).is_none() {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!(
                        "memory export [{:#x}..+{:#x}) wraps the address space",
                        export.address, export.length
                    ),
                )
                .at(at("address")),
            ]);
        }
        if export.name.is_empty()
            || export.name.len() > 255
            || export.name.contains(['/', '\\'])
            || export.name == "."
            || export.name == ".."
        {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!(
                        "memory export name {:?} is not a single path component",
                        export.name
                    ),
                )
                .at(at("name")),
            ]);
        }
        if named.contains(&export.name.as_str()) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("two memory exports are both called {:?}", export.name),
                )
                .at(at("name")),
            ]);
        }
        named.push(&export.name);
    }
    Ok(())
}

/// Where the custom-chip register page lives, and how big it is.
///
/// Stated here rather than imported from `amiga-env` so normalization does not
/// depend on the environment crate for a constant the request schema documents.
pub(crate) const CUSTOM_CHIP_BASE: u32 = 0x00df_f000;
pub(crate) const CUSTOM_CHIP_SIZE: u32 = 0x200;

/// Whether `[address, address + size)` meets the custom-chip page.
pub(crate) fn overlaps_custom_chips(address: u32, size: u64) -> bool {
    let end = u64::from(address) + size;
    u64::from(address) < u64::from(CUSTOM_CHIP_BASE) + u64::from(CUSTOM_CHIP_SIZE)
        && u64::from(CUSTOM_CHIP_BASE) < end
}

/// Resolve a custom-chip configuration, applying both canonicalization rules.
pub(super) fn normalize_custom_chips(
    chips: &crate::request::CustomChips,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedCustomChips, Vec<Diagnostic>> {
    let blitter = chips.blitter.unwrap_or_default();
    // An absent `blitter` is an emulating one with the defaults, so
    // `custom_chips: {}` and a fully spelled-out default request are the same
    // recipe rather than two.
    let mode = match blitter.mode.unwrap_or_default() {
        crate::request::BlitterMode::Shadow => NormalizedBlitterMode::Shadow,
        crate::request::BlitterMode::Emulate => NormalizedBlitterMode::Emulate {
            dma: blitter.dma.unwrap_or_default(),
            maximum_words: clamp_blit_words(blitter.maximum_words, limits, diagnostics)?,
        },
    };
    Ok(NormalizedCustomChips {
        chipset: chips.chipset.unwrap_or_default(),
        mode,
    })
}

/// Reduce a requested blit budget to what this context permits, saying so.
///
/// Zero is refused rather than clamped up. The bundled schemas declare a minimum
/// of 1, so accepting it would let a typed caller run a request a JSON caller
/// cannot write — and the run it would produce reports every blit as
/// budget-exceeded, which reads as a program whose blits were too large rather
/// than as a request that asked for none.
pub(super) fn clamp_blit_words(
    requested: Option<u64>,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<u64, Vec<Diagnostic>> {
    let ceiling = limits.maximum_sandbox_blit_words();
    let Some(requested) = requested else {
        return Ok(ceiling);
    };
    if requested == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "custom_chips.blitter.maximum_words must be at least 1; omit it to \
                 accept this context's ceiling, or use blitter.mode shadow for a run \
                 that performs no blits",
            )
            .at("$.request.arguments.custom_chips.blitter.maximum_words"),
        ]);
    }
    if requested <= ceiling {
        return Ok(requested);
    }
    diagnostics.push(
        Diagnostic::warning(
            DiagnosticCode::LimitReduced,
            format!(
                "custom_chips.blitter.maximum_words reduced from {requested} to the \
                 {ceiling} datapath words this context allows"
            ),
        )
        .at("$.request.arguments.custom_chips.blitter.maximum_words"),
    );
    Ok(ceiling)
}

/// Fill in what an `env.sandbox.call.export` request left unsaid.
pub(super) fn sandbox_call_export(
    arguments: &crate::request::SandboxCallExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let call = normalize_sandbox_call(&arguments.call, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_GOLDEN_FILE_NAME,
    )?;
    Ok(NormalizedOperation::EnvSandboxCallExport(
        NormalizedSandboxCallExport {
            call,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Differences of each kind reported when the request names no cap.
const DEFAULT_REPORTED_DIFFERENCES: usize = 256;

/// Fill in what an `env.sandbox.compare` request left unsaid.
pub(super) fn sandbox_compare(
    arguments: &crate::request::SandboxCompareArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    if arguments.records.len() < 2 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a comparison needs at least two records; one compared against \
                 nothing has no answer",
            )
            .at("$.request.arguments.records"),
        ]);
    }
    let mut records = Vec::with_capacity(arguments.records.len());
    for record in &arguments.records {
        records.push(normalize_source(record)?);
    }
    Ok(NormalizedOperation::EnvSandboxCompare(
        NormalizedSandboxCompare {
            records,
            maximum_differences: arguments
                .maximum_differences
                .unwrap_or(DEFAULT_REPORTED_DIFFERENCES),
            maximum_input_bytes: normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?,
        },
    ))
}

/// The file name a sweep's aggregate uses when the request names none.
const DEFAULT_MATRIX_FILE_NAME: &str = "matrix.json";
const DEFAULT_TIMELINE_FILE_NAME: &str = "timeline.json";

/// Fill in what an `env.sandbox.timeline.export` request left unsaid.
///
/// The timeline normalizes first, for the reason its sibling does: a malformed
/// step refuses the export before a destination is resolved, which is half of
/// what makes "nothing is written until every step has run" true. The timeline
/// satisfies the other half more strongly than the matrix does — the whole
/// request, every step's seeds and every checkpoint range, is validated against
/// the map before the first instruction executes.
pub(super) fn sandbox_timeline_export(
    arguments: &crate::request::SandboxTimelineExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let NormalizedOperation::EnvSandboxTimeline(timeline) =
        sandbox_timeline(&arguments.timeline, limits, diagnostics)?
    else {
        // `sandbox_timeline` returns that variant or an error, and nothing else.
        return Err(vec![Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            "the timeline arguments did not normalize to a timeline",
        )]);
    };
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_TIMELINE_FILE_NAME,
    )?;
    Ok(NormalizedOperation::EnvSandboxTimelineExport(
        NormalizedSandboxTimelineExport {
            timeline,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `env.sandbox.matrix.export` request left unsaid.
///
/// The sweep normalizes first, so a malformed case refuses the export before a
/// destination is even resolved — which is what makes "nothing is written until
/// every case has run" true of the last case as well as the first.
pub(super) fn sandbox_matrix_export(
    arguments: &crate::request::SandboxMatrixExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let NormalizedOperation::EnvSandboxMatrix(matrix) =
        sandbox_matrix(&arguments.matrix, limits, diagnostics)?
    else {
        // `sandbox_matrix` returns that variant or an error, and nothing else.
        return Err(vec![Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            "the matrix arguments did not normalize to a matrix",
        )]);
    };
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_MATRIX_FILE_NAME,
    )?;
    Ok(NormalizedOperation::EnvSandboxMatrixExport(
        NormalizedSandboxMatrixExport {
            matrix,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fill in what an `env.sandbox.matrix` request left unsaid, and expand it.
///
/// The order is load-bearing. The shared recipe normalizes **first**, so a fault
/// in the apparatus is reported at the path the caller wrote it at rather than
/// blamed on the first case that inherits it. Only then is each case expanded,
/// which means any fault a case's expansion produces was introduced by that
/// case's own overrides — and that is what makes the path rewriting below
/// truthful rather than a guess.
pub(super) fn sandbox_matrix(
    arguments: &crate::request::SandboxMatrixArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let base = normalize_sandbox_call(&arguments.base, limits, diagnostics)?;

    if arguments.cases.is_empty() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a matrix needs at least one case; an empty one would report a sweep \
                 that covered nothing as a sweep that passed",
            )
            .at("$.request.arguments.cases"),
        ]);
    }
    let ceiling = limits.maximum_matrix_cases();
    let allowed = match arguments.maximum_cases {
        Some(requested) if requested > ceiling => {
            diagnostics.push(
                Diagnostic::warning(
                    DiagnosticCode::LimitReduced,
                    format!("case limit reduced from {requested} to {ceiling}"),
                )
                .at("$.request.arguments.maximum_cases"),
            );
            ceiling
        }
        Some(requested) => requested,
        None => ceiling,
    };
    if arguments.cases.len() > allowed {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "the matrix has {} cases and at most {allowed} are permitted",
                    arguments.cases.len()
                ),
            )
            .at("$.request.arguments.cases"),
        ]);
    }

    // The aggregate budget defaults to one run's, which is deliberately
    // conservative — see `DEFAULT_MAXIMUM_MATRIX_STEPS`.
    let requested_total = arguments
        .maximum_total_steps
        .unwrap_or_else(|| limits.maximum_sandbox_steps());
    let maximum_total_steps = if requested_total > crate::limits::MAXIMUM_SANDBOX_STEPS_CEILING {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "aggregate step budget reduced from {requested_total} to {}",
                    crate::limits::MAXIMUM_SANDBOX_STEPS_CEILING
                ),
            )
            .at("$.request.arguments.maximum_total_steps"),
        );
        crate::limits::MAXIMUM_SANDBOX_STEPS_CEILING
    } else {
        requested_total
    };
    if maximum_total_steps == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a matrix with no step budget runs no case, and would report every one \
                 of them as not run",
            )
            .at("$.request.arguments.maximum_total_steps"),
        ]);
    }

    let base_seed_count = arguments.base.memory_seeds.len();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut cases = Vec::with_capacity(arguments.cases.len());
    for (index, case) in arguments.cases.iter().enumerate() {
        let at = |field: &str| format!("$.request.arguments.cases[{index}].{field}");
        // The same rule a memory export's name goes through, and for the same
        // reason: a case names an artifact, so it has to be usable as one path
        // component and has to be the only one claiming it. Two cases under one
        // name would also make the totals unreadable — a reader matching a
        // result to a case would have two candidates.
        if case.name.is_empty()
            || case.name.len() > 255
            || case.name.contains(['/', '\\'])
            || case.name == "."
            || case.name == ".."
        {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("case name {:?} is not a single path component", case.name),
                )
                .at(at("name")),
            ]);
        }
        if !names.insert(case.name.as_str()) {
            return Err(vec![
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("two cases are both called {:?}", case.name),
                )
                .at(at("name")),
            ]);
        }

        let mut expanded = arguments.base.clone();
        if let Some(offset) = case.entry_offset {
            expanded.run.entry_offset = Some(offset);
        }
        if let Some(registers) = case.data_registers {
            expanded.run.data_registers = Some(registers);
        }
        if let Some(registers) = case.address_registers {
            expanded.run.address_registers = Some(registers);
        }
        if let Some(stack_arguments) = &case.stack_arguments {
            expanded.stack_arguments.clone_from(stack_arguments);
        }
        expanded
            .memory_seeds
            .extend(case.memory_seeds.iter().cloned());

        let call = normalize_sandbox_call(&expanded, limits, diagnostics)
            .map_err(|problems| repath_case(problems, index, base_seed_count))?;
        let digest = amiga_core::sha256(sandbox_call_document(&call).to_string().as_bytes());
        cases.push(NormalizedMatrixCase {
            name: case.name.clone(),
            notes: case.notes.clone(),
            call,
            digest,
        });
    }

    Ok(NormalizedOperation::EnvSandboxMatrix(
        NormalizedSandboxMatrix {
            base_digest: amiga_core::sha256(sandbox_call_document(&base).to_string().as_bytes()),
            base,
            cases,
            maximum_total_steps,
        },
    ))
}

/// Move a diagnostic from the expanded call it was raised against to the case
/// that introduced it.
///
/// The shared recipe has already normalized cleanly by the time a case is
/// expanded, so anything failing here came from this case's overrides. A seed's
/// index has to be shifted as well as prefixed: case seeds are appended after
/// the shared ones, so seed `n` of the expanded call is seed `n - base_seeds` of
/// the case. Leaving the expanded index in place would produce a path that
/// resolves to a different seed, or to none — which is worse than no path at
/// all, because a reader would act on it.
fn repath_case(problems: Vec<Diagnostic>, case: usize, base_seeds: usize) -> Vec<Diagnostic> {
    const SEEDS: &str = "$.request.arguments.memory_seeds[";
    let prefix = format!("$.request.arguments.cases[{case}]");
    problems
        .into_iter()
        .map(|mut problem| {
            let Some(path) = problem.json_path.take() else {
                return problem;
            };
            problem.json_path = Some(match path.strip_prefix(SEEDS) {
                Some(rest) => match rest.split_once(']') {
                    Some((index, tail)) => match index.parse::<usize>() {
                        Ok(index) => format!(
                            "{prefix}.memory_seeds[{}]{tail}",
                            index.saturating_sub(base_seeds)
                        ),
                        // An index we cannot read is one we must not rewrite:
                        // pointing at the case with a number we invented is the
                        // failure this whole function exists to avoid.
                        Err(_) => prefix.clone(),
                    },
                    None => prefix.clone(),
                },
                None => match path.strip_prefix("$.request.arguments.") {
                    Some(field) => format!("{prefix}.{field}"),
                    None => path,
                },
            });
            problem
        })
        .collect()
}

/// Fill in what an `env.boot.info` request left unsaid.
pub(super) fn boot_info(
    arguments: &crate::request::BootInfoArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::EnvBootInfo(NormalizedBootInfo {
        source: normalize_source(&arguments.source)?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    }))
}

/// Fill in what an `env.boot.trace.export` request left unsaid.
pub(super) fn boot_trace_export(
    arguments: &crate::request::BootTraceExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let trace = normalize_boot_trace(&arguments.trace, limits, diagnostics)?;
    let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
        vec![
            Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                .at("$.request.arguments.destination"),
        ]
    })?;
    Ok(NormalizedOperation::EnvBootTraceExport(
        NormalizedBootTraceExport {
            trace,
            destination,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sandbox-run arguments carrying `watch`, for the shapes that reject.
    fn run_watching(watch: Vec<crate::request::WatchRange>) -> crate::request::SandboxRunArguments {
        let mut run = crate::request::SandboxRunArguments::new("sample.bin");
        run.watch = watch;
        run
    }

    fn refusal_path(document: OperationRequestDocument) -> String {
        let refused = normalize(&RequestEnvelope::read(document), OperationLimits::default())
            .expect_err("the argument is refused");
        assert_eq!(refused[0].code, DiagnosticCode::RequestArgumentOutOfRange);
        refused[0]
            .json_path
            .clone()
            .expect("a refused argument names the field it came from")
    }

    /// `env.sandbox.call` reports a shared run argument at the **top level**,
    /// because that is where the caller wrote it.
    ///
    /// `SandboxCallArguments::run` is `#[serde(flatten)]`, so the nesting is a
    /// fact about the Rust type and not about the request document: on the wire
    /// there is no `run` object at all, and the bundled request schema has no
    /// `run` key. A diagnostic naming `$.request.arguments.run.watch[0].length`
    /// would point at a field the request cannot have — and the whole reason
    /// these paths are structured is that a consumer reads them instead of
    /// parsing the message. This is pinned because it was once "fixed" the
    /// other way round.
    #[test]
    fn a_flattened_run_argument_is_reported_where_the_caller_wrote_it() {
        let zero_length = vec![crate::request::WatchRange {
            start: 0x1000,
            length: 0,
            access: crate::request::WatchAccess::default(),
        }];
        let too_many: Vec<_> = (0..=MAXIMUM_WATCHPOINTS)
            .map(|index| crate::request::WatchRange {
                start: 0x1000 + index as u32 * 4,
                length: 4,
                access: crate::request::WatchAccess::default(),
            })
            .collect();

        for (watch, expected) in [
            (zero_length, "$.request.arguments.watch[0].length"),
            (too_many, "$.request.arguments.watch"),
        ] {
            // The two operations agree, because their requests have the same
            // shape at the point the argument was written.
            assert_eq!(
                refusal_path(OperationRequestDocument::EnvSandboxCall(
                    crate::request::SandboxCallArguments::new(run_watching(watch.clone()))
                )),
                expected
            );
            assert_eq!(
                refusal_path(OperationRequestDocument::EnvSandboxRun(run_watching(watch))),
                expected
            );
        }

        // The same for the other arguments the two share.
        let mut odd_entry = run_watching(Vec::new());
        odd_entry.entry_offset = Some(3);
        assert_eq!(
            refusal_path(OperationRequestDocument::EnvSandboxCall(
                crate::request::SandboxCallArguments::new(odd_entry)
            )),
            "$.request.arguments.entry_offset"
        );

        let mut no_steps = run_watching(Vec::new());
        no_steps.maximum_steps = Some(0);
        assert_eq!(
            refusal_path(OperationRequestDocument::EnvSandboxCall(
                crate::request::SandboxCallArguments::new(no_steps)
            )),
            "$.request.arguments.maximum_steps"
        );
    }

    /// The request schema is the authority on that shape, so it is asserted
    /// rather than described: if `run` ever stops being flattened, this fails
    /// alongside the paths above rather than leaving them quietly wrong.
    #[test]
    fn the_call_request_schema_states_its_run_arguments_at_the_top_level() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../schemas/v1/operations/env.sandbox.call.request.schema.json"
        ))
        .expect("the bundled schema is valid JSON");
        let arguments = &schema["properties"]["arguments"]["properties"];
        assert!(
            arguments.get("run").is_none(),
            "the call request has no `run` object"
        );
        for field in ["source", "watch", "entry_offset", "maximum_steps"] {
            assert!(
                arguments.get(field).is_some(),
                "{field} is stated at the top level"
            );
        }
    }
}

/// Pixels a reconstructed frame may hold when the request names no cap.
///
/// A PAL overscan display is 368x290; four times that covers anything an OCS
/// program can put on a screen and is still a number rather than "as many as the
/// registers ask for", which matters because the geometry comes from registers a
/// half-initialized run may have left at anything.
const DEFAULT_MAXIMUM_FRAME_PIXELS: u64 = 400 * 320;

/// The highest a context may raise the frame bound to.
const MAXIMUM_FRAME_PIXELS_CEILING: u64 = 1 << 22;

/// Fully resolved `env.frame.capture` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedFrameCapture {
    pub call: NormalizedSandboxCall,
    /// The raster line the run stops at, when the request named one. Already
    /// folded into the call's step budget; kept so the result can say what was
    /// asked rather than only what was run.
    pub until_raster_line: Option<u16>,
    pub maximum_pixels: u64,
}

/// Fully resolved `env.frame.capture.export` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedFrameCaptureExport {
    pub capture: NormalizedFrameCapture,
    pub destination: DestinationName,
    pub file_name: String,
    pub policy: OutputPolicy,
}

/// The canonical form of one `env.frame.capture`.
pub(super) fn frame_capture_document(capture: &NormalizedFrameCapture) -> Value {
    json!({
        "call": sandbox_call_document(&capture.call),
        "until_raster_line": capture.until_raster_line,
        "maximum_pixels": capture.maximum_pixels,
    })
}

/// The canonical form of one `env.frame.capture.export`.
pub(super) fn frame_capture_export_document(export: &NormalizedFrameCaptureExport) -> Value {
    json!({
        "capture": frame_capture_document(&export.capture),
        "destination": export.destination.as_str(),
        "file_name": export.file_name,
        "policy": export.policy,
    })
}

/// The file name a captured frame uses when the request names none.
const DEFAULT_FRAME_FILE_NAME: &str = "frame.png";

/// Fill in what an `env.frame.capture` request left unsaid.
///
/// The raster line is turned into an instruction budget **here**, so the
/// canonical request carries the budget the run honours rather than a stop
/// condition a handler would have to re-derive. The beam is the instruction
/// counter, so the conversion is exact rather than an estimate.
pub(super) fn normalize_frame_capture(
    arguments: &crate::request::FrameCaptureArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedFrameCapture, Vec<Diagnostic>> {
    let mut call = arguments.call.clone();
    if let Some(line) = arguments.until_raster_line {
        let budget = u64::from(line).saturating_mul(amiga_env::HORIZONTAL);
        let budget = usize::try_from(budget).unwrap_or(usize::MAX).max(1);
        // The smaller of the two, and reported when it is this one: a caller who
        // asked for both a line and a budget asked for whichever comes first,
        // and a line the budget cannot reach is a capture of a display the run
        // never got to.
        call.run.maximum_steps = Some(match call.run.maximum_steps {
            Some(requested) => requested.min(budget),
            None => budget,
        });
    }
    let call = normalize_sandbox_call(&call, limits, diagnostics)?;
    if call.custom_chips.is_none() {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "a frame capture models the custom chips: without the chip page there is \
                 no register state to reconstruct a display from, and $DFF000 would be \
                 whatever mapped_regions made of it",
            )
            .at("$.request.arguments.custom_chips"),
        ]);
    }
    let requested = arguments
        .maximum_pixels
        .unwrap_or(DEFAULT_MAXIMUM_FRAME_PIXELS);
    if requested == 0 {
        return Err(vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                "maximum_pixels must be at least 1",
            )
            .at("$.request.arguments.maximum_pixels"),
        ]);
    }
    let maximum_pixels = if requested > MAXIMUM_FRAME_PIXELS_CEILING {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "maximum_pixels reduced from {requested} to the \
                     {MAXIMUM_FRAME_PIXELS_CEILING} this build allows"
                ),
            )
            .at("$.request.arguments.maximum_pixels"),
        );
        MAXIMUM_FRAME_PIXELS_CEILING
    } else {
        requested
    };
    Ok(NormalizedFrameCapture {
        call,
        until_raster_line: arguments.until_raster_line,
        maximum_pixels,
    })
}

/// Fill in what an `env.frame.capture` request left unsaid.
pub(super) fn frame_capture(
    arguments: &crate::request::FrameCaptureArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::EnvFrameCapture(
        normalize_frame_capture(arguments, limits, diagnostics)?,
    ))
}

/// Fill in what an `env.frame.capture.export` request left unsaid.
pub(super) fn frame_capture_export(
    arguments: &crate::request::FrameCaptureExportArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let capture = normalize_frame_capture(&arguments.capture, limits, diagnostics)?;
    let (destination, file_name) = normalize_single_file_destination(
        &arguments.destination,
        arguments.file_name.as_deref(),
        DEFAULT_FRAME_FILE_NAME,
    )?;
    Ok(NormalizedOperation::EnvFrameCaptureExport(
        NormalizedFrameCaptureExport {
            capture,
            destination,
            file_name,
            policy: arguments.policy.unwrap_or_default(),
        },
    ))
}

/// Fully resolved `env.sandbox.slice` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSandboxSlice {
    pub call: NormalizedSandboxCall,
    pub seed: amiga_disasm::SliceSeed,
    pub maximum_depth: usize,
    pub maximum_entries: usize,
}

/// The canonical form of one `env.sandbox.slice`.
pub(super) fn sandbox_slice_document(slice: &NormalizedSandboxSlice) -> Value {
    json!({
        "call": sandbox_call_document(&slice.call),
        "seed": match slice.seed {
            amiga_disasm::SliceSeed::Final(location) => json!({
                "kind": "final",
                "location": location.to_string(),
            }),
            amiga_disasm::SliceSeed::Instruction { address, occurrence } => json!({
                "kind": "instruction",
                "address": address,
                "occurrence": occurrence,
            }),
        },
        "maximum_depth": slice.maximum_depth,
        "maximum_entries": slice.maximum_entries,
    })
}

/// Edges a slice follows when the request names no bound.
const DEFAULT_SLICE_DEPTH: usize = 256;

/// Steps a slice reports when the request names no cap.
const DEFAULT_SLICE_ENTRIES: usize = 512;

/// Fill in what an `env.sandbox.slice` request left unsaid.
///
/// The trace is forced on here rather than required of the caller: a slice over
/// a run that recorded nothing would be an empty answer to a question the
/// request plainly asked, and turning it on is not a change to what the routine
/// does.
pub(super) fn sandbox_slice(
    arguments: &crate::request::SandboxSliceArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let mut traced = arguments.call.clone();
    traced.run.trace = true;
    let call = normalize_sandbox_call(&traced, limits, diagnostics)?;
    let seed = match &arguments.seed {
        crate::request::SliceSeedArgument::Register { register } => {
            amiga_disasm::SliceSeed::Final(parse_location(register)?)
        }
        crate::request::SliceSeedArgument::Memory { address } => {
            amiga_disasm::SliceSeed::Final(amiga_disasm::Location::Memory(*address))
        }
        crate::request::SliceSeedArgument::Instruction {
            address,
            occurrence,
        } => {
            if !address.is_multiple_of(2) {
                return Err(vec![
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!(
                            "the seed names the odd address {address:#x}; no instruction \
                             begins there, so the run never executed one"
                        ),
                    )
                    .at("$.request.arguments.seed.address"),
                ]);
            }
            amiga_disasm::SliceSeed::Instruction {
                address: *address,
                // Counted from one, as the result reports it: an occurrence of
                // zero would name an execution that cannot exist.
                occurrence: match occurrence {
                    Some(0) => {
                        return Err(vec![
                            Diagnostic::error(
                                DiagnosticCode::RequestArgumentOutOfRange,
                                "occurrence counts from one; a zeroth execution is not one \
                                 the run could have made",
                            )
                            .at("$.request.arguments.seed.occurrence"),
                        ]);
                    }
                    Some(count) => *count,
                    None => 1,
                },
            }
        }
    };
    Ok(NormalizedOperation::EnvSandboxSlice(
        NormalizedSandboxSlice {
            call,
            seed,
            maximum_depth: normalize_count(
                arguments.maximum_depth.or(Some(DEFAULT_SLICE_DEPTH)),
                limits.maximum_entries(),
                "maximum_depth",
                "edges",
                diagnostics,
            )?,
            maximum_entries: normalize_count(
                arguments.maximum_entries.or(Some(DEFAULT_SLICE_ENTRIES)),
                limits.maximum_entries(),
                "maximum_entries",
                "steps",
                diagnostics,
            )?,
        },
    ))
}

/// One register name, as a location the slice tracks.
fn parse_location(name: &str) -> Result<amiga_disasm::Location, Vec<Diagnostic>> {
    let lowered = name.to_ascii_lowercase();
    let refuse = || {
        vec![
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("{name:?} names no register; use d0-d7, a0-a7, or ccr"),
            )
            .at("$.request.arguments.seed.register"),
        ]
    };
    if lowered == "ccr" || lowered == "sr" {
        return Ok(amiga_disasm::Location::Flags);
    }
    let index: u8 = lowered
        .get(1..)
        .and_then(|digits| digits.parse().ok())
        .ok_or_else(refuse)?;
    match lowered.as_bytes().first() {
        Some(b'd') if index < 8 => Ok(amiga_disasm::Location::Data(index)),
        Some(b'a') if index < 8 => Ok(amiga_disasm::Location::Address(index)),
        _ => Err(refuse()),
    }
}
