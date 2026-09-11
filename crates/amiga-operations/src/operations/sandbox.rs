//! `env.sandbox.run` — execute one CODE hunk under stated bounds and report
//! what happened.
//!
//! This operation wraps `amiga_disasm::run` with a bounded memory layout, step budget,
//! watched ranges, and structured stop reasons. Callers describe execution inputs
//! through the shared request vocabulary.
//!
//! ## Why every bound is in the request
//!
//! Sandbox code is unknown code, and a routine that never returns is the normal
//! case while identifying one. The step budget, the memory map, and the watched
//! ranges are therefore stated by the caller and echoed back in the result —
//! not defaults hidden behind the interface. The one thing a caller cannot do
//! is remove the ceiling: a request asking for an unbounded run would be asking
//! the process to hang, so `maximum_steps` is clamped and the reduction is
//! reported. The ceiling itself is the *context's*
//! ([`OperationLimits::maximum_sandbox_steps`]), so a host running local media
//! it has reviewed can raise it for an initialization routine that legitimately
//! runs for millions of instructions — to a larger number, never to none.
//!
//! [`OperationLimits::maximum_sandbox_steps`]:
//!     crate::OperationLimits::maximum_sandbox_steps
//!
//! ## Why the stack sits above the hunk with a gap
//!
//! An unmapped gap between the code and the stack turns a runaway stack into a
//! fault. Without it, a stack that grew past its own region would quietly
//! overwrite the code being run, and the trace would show a program that
//! rewrote itself for no reason a reader could see.
//!
//! Nothing here emulates an operating system. A library vector that nothing
//! services stops the run and is reported by its offset; *naming* it is the
//! frontend's, because the fd tables that name it are the frontend's
//! configuration.

use std::collections::BTreeMap;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{
    NormalizedBootInfo, NormalizedBootTrace, NormalizedBootTraceExport, NormalizedMode,
    NormalizedSandboxCall, NormalizedSandboxCallExport, NormalizedSandboxRun,
};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::{OperationName, WatchAccess};
use crate::response::{
    BootExecCall, BootInfoResult, BootTraceExportResult, BootTraceResult, ChipWrite,
    OperationOutcome, OperationResult, SandboxAccess, SandboxCallExportResult, SandboxCallResult,
    SandboxRegionResult as SandboxRegion, SandboxRegisterDelta, SandboxRegisters, SandboxRunResult,
    SandboxStep, SandboxStop, SandboxWrite, ServedRead, SourcePin,
};
use crate::source::SourceError;

/// The return address pushed under the routine: reaching it means it returned.
///
/// Deliberately unmapped and odd-looking, so a routine that jumps to it by
/// accident faults rather than continuing into whatever happened to be there.
const RETURN_MARKER: u32 = 0xdead_0000;

/// Unmapped bytes between the hunk and the stack when the stack is derived.
const STACK_GAP: u32 = 0x1000;

/// Bytes of stack when the request names no region.
///
/// The default stack region is 64 KiB. A request can provide an explicit region
/// instead.
const STACK_BYTES: usize = 64 * 1024;

/// Where the hunk goes when the request names no origin.
const DEFAULT_LOAD_ORIGIN: u32 = 0x0002_0000;

/// Writes reported in the summary. Bounded because a long run writes a lot and
/// the summary is meant to be read; the true total is always beside it.
const MAX_REPORTED_WRITES: usize = 1024;

/// Interrupt deliveries reported in a record. A periodic schedule over a long
/// run delivers many; the true total is always beside them.
const MAX_REPORTED_DELIVERIES: usize = 256;

/// Blit rows reported in a record. A frame's drawing is thousands of blits; the
/// true total and the word totals are always beside them.
const MAX_REPORTED_BLITS: usize = 256;

/// Attach the custom-chip page a call asked for, and return the telemetry
/// handle — or `None` when it asked for none.
///
/// The `$DFF000` overlap is checked **again** here, and against every mapping
/// rather than only `mapped_regions`. Normalization can only see what the
/// request named; the selected hunk's span, the `hunk_bases`, and a derived
/// stack are known only after `prepare`, and any of them could land on the chip
/// page. Attaching over RAM would fail anyway, but with a message about a device
/// range rather than about the recipe.
fn attach_custom_chips(
    bus: &mut amiga_disasm::DeviceBus,
    request: &NormalizedSandboxCall,
    beam: &std::rc::Rc<std::cell::Cell<u64>>,
) -> Result<ChipHandles, Diagnostic> {
    let Some(chips) = request.custom_chips else {
        return Ok(ChipHandles::default());
    };
    for region in bus.ram().mapped_spans() {
        if crate::normalize::overlaps_custom_chips(region.0, u64::from(region.1)) {
            return Err(Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!(
                    "the mapping [{:#x}..+{:#x}) covers the custom-chip page, which this \
                     request asked to model; RAM and the chips cannot both answer an address",
                    region.0, region.1
                ),
            )
            .at("$.request.arguments.custom_chips"));
        }
    }

    let options = amiga_env::ChipsOptions {
        blitter_dma: match chips.mode {
            crate::normalize::NormalizedBlitterMode::Emulate { dma, .. } => match dma {
                crate::request::BlitterDma::AssumeEnabled => amiga_hw::DmaPolicy::AssumeEnabled,
                crate::request::BlitterDma::RequireEnabled => amiga_hw::DmaPolicy::RequireEnabled,
            },
            crate::normalize::NormalizedBlitterMode::Shadow => amiga_hw::DmaPolicy::AssumeEnabled,
        },
        maximum_blit_words: match chips.mode {
            crate::normalize::NormalizedBlitterMode::Emulate { maximum_words, .. } => maximum_words,
            crate::normalize::NormalizedBlitterMode::Shadow => 0,
        },
        maximum_reported_blits: MAX_REPORTED_BLITS,
        chipset: match chips.chipset {
            crate::request::Chipset::Ocs => amiga_hw::Chipset::Ocs,
        },
    };

    // Shadow mode is the page without a blitter behind it: register cells, no
    // blits, and therefore no telemetry to report.
    if matches!(chips.mode, crate::normalize::NormalizedBlitterMode::Shadow) {
        let page = amiga_env::CustomChips::new(std::rc::Rc::clone(beam));
        let registers = page.register_handle();
        bus.attach(Box::new(page)).map_err(|error| {
            Diagnostic::error(DiagnosticCode::SandboxMemoryUnmappable, error.to_string())
                .at("$.request.arguments.custom_chips")
        })?;
        return Ok(ChipHandles {
            telemetry: None,
            registers: Some(registers),
        });
    }

    let (page, telemetry) = amiga_env::CustomChips::with_blitter(std::rc::Rc::clone(beam), options);
    // Taken before the page is boxed: a `DeviceBus` owns its devices as
    // `Box<dyn Device>` and offers no downcast, so this is the only moment a
    // handle can be had at all.
    let registers = page.register_handle();
    bus.attach(Box::new(page)).map_err(|error| {
        Diagnostic::error(DiagnosticCode::SandboxMemoryUnmappable, error.to_string())
            .at("$.request.arguments.custom_chips")
    })?;
    Ok(ChipHandles {
        telemetry: Some(telemetry),
        registers: Some(registers),
    })
}

/// What a caller keeps hold of after the chip page has been attached.
///
/// Both are `None` for a recipe that asked for no chips, which is the ordinary
/// case: there is then no page, and therefore nothing to observe.
#[derive(Clone, Default)]
pub(crate) struct ChipHandles {
    pub telemetry: Option<std::rc::Rc<std::cell::RefCell<amiga_env::BlitterTelemetry>>>,
    /// Every register's effective value as the run left it — complete, unlike
    /// the write log, which is a bounded prefix. A display reconstructed from a
    /// prefix would be a display the run never had.
    pub registers: Option<std::rc::Rc<std::cell::RefCell<amiga_env::ChipRegisters>>>,
}

/// The resolved configuration, as the record reports it.
fn custom_chips_result(
    chips: crate::normalize::NormalizedCustomChips,
) -> crate::response::SandboxCustomChips {
    use crate::normalize::NormalizedBlitterMode;
    let chipset = match chips.chipset {
        crate::request::Chipset::Ocs => "ocs",
    }
    .to_owned();
    let blitter = match chips.mode {
        NormalizedBlitterMode::Emulate { dma, maximum_words } => {
            crate::response::SandboxBlitterConfig {
                mode: "emulate".to_owned(),
                dma: Some(
                    match dma {
                        crate::request::BlitterDma::AssumeEnabled => "assume_enabled",
                        crate::request::BlitterDma::RequireEnabled => "require_enabled",
                    }
                    .to_owned(),
                ),
                maximum_words: Some(maximum_words),
            }
        }
        // Nothing else applied, so nothing else is claimed.
        NormalizedBlitterMode::Shadow => crate::response::SandboxBlitterConfig {
            mode: "shadow".to_owned(),
            dma: None,
            maximum_words: None,
        },
    };
    crate::response::SandboxCustomChips { chipset, blitter }
}

/// One observation, as the record reports it.
fn chip_observation(
    observation: amiga_hw::BlitObservation,
    occurrences: u64,
) -> crate::response::SandboxChipObservation {
    crate::response::SandboxChipObservation {
        kind: observation.kind().to_owned(),
        register: observation.register(),
        channel: observation
            .channel()
            .map(|channel| channel.name().to_owned()),
        occurrences,
    }
}

/// One refusal, as the record reports it.
fn blit_refusal(refusal: amiga_hw::BlitRefusal) -> crate::response::SandboxBlitRefusal {
    crate::response::SandboxBlitRefusal {
        kind: refusal.kind().to_owned(),
        channel: refusal.channel().map(|channel| channel.name().to_owned()),
        address: match refusal {
            amiga_hw::BlitRefusal::Unmapped { address, .. } => Some(address),
            amiga_hw::BlitRefusal::AddressOverflow { at, .. } => Some(at),
            _ => None,
        },
        message: refusal.to_string(),
    }
}

/// Turn the blitter's telemetry into the record's rows and this run's
/// diagnostics.
///
/// The diagnostics are **deduplicated by `(code, kind, channel)`** for refusals
/// and by `(code, kind, register)` for observations — two codes times a small
/// closed enum times four channels or the offsets one page holds, so the number
/// of distinct diagnostics is bounded by construction. An address is
/// deliberately not part of either key: a loop touching new addresses would
/// defeat the bound. The first occurrence's address goes in the message as a
/// representative example, and the counts live in the response's own structured
/// fields, where a consumer may read them without parsing prose.
///
/// Everything here is read from the telemetry's run-level tallies rather than
/// from its retained rows, which are capped: a refusal, an assumed DMA policy or
/// an unmodelled start trigger past the cap is still what the run did.
fn report_blits(
    telemetry: Option<&std::cell::RefCell<amiga_env::BlitterTelemetry>>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (
    Vec<crate::response::SandboxBlit>,
    u64,
    u64,
    u64,
    Vec<crate::response::SandboxChipObservation>,
) {
    let Some(telemetry) = telemetry else {
        return (Vec::new(), 0, 0, 0, Vec::new());
    };
    let telemetry = telemetry.borrow();

    // From the telemetry's own tallies rather than from the retained rows: a
    // refusal that happened past the row cap is still a refusal, and a run whose
    // only one fell off the end of the list must not report a clean run.
    for tally in telemetry.refusals() {
        // Line mode is hardware this build does not implement; everything else
        // is a blit this run would not perform.
        let code = if tally.kind == "line_mode" {
            DiagnosticCode::SandboxBlitterUnsupported
        } else {
            DiagnosticCode::SandboxBlitterRefused
        };
        let occurrences = if tally.occurrences == 1 {
            String::new()
        } else {
            format!(" ({} blits refused this way)", tally.occurrences)
        };
        diagnostics.push(
            Diagnostic::warning(
                code,
                format!("blit {}: {}{occurrences}", tally.first_index, tally.message),
            )
            .at("$.result.blits"),
        );
    }

    let mut rows = Vec::with_capacity(telemetry.blits().len());
    for blit in telemetry.blits() {
        rows.push(crate::response::SandboxBlit {
            index: blit.index,
            width: blit.width,
            height: blit.height,
            bltcon0: blit.bltcon0,
            bltcon1: blit.bltcon1,
            initial_pointers: [
                blit.initial_pointers.a,
                blit.initial_pointers.b,
                blit.initial_pointers.c,
                blit.initial_pointers.d,
            ],
            final_pointers: [
                blit.final_pointers.a,
                blit.final_pointers.b,
                blit.final_pointers.c,
                blit.final_pointers.d,
            ],
            datapath_words: blit.datapath_words,
            words_written: blit.words_written,
            zero: blit.zero,
            dma_assumed: blit.dma_assumed,
            refused: blit.refused.map(blit_refusal),
            observations: blit
                .observations
                .iter()
                .map(|observation| chip_observation(*observation, 1))
                .collect(),
        });
    }

    if telemetry.blits_truncated() {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the run performed {} blits; {MAX_REPORTED_BLITS} are reported",
                telemetry.blits_total()
            ),
        ));
    }
    // Once per run, not once per blit: the assumption is about the recipe.
    if telemetry.any_dma_assumed() {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::SandboxBlitterDmaAssumed,
            "a blit ran with DMACON saying blitter DMA was off; the call starts in the \
             middle of a program, so DMACON holding zero says nothing about what the \
             program intended. Use require_enabled for a recipe that ran the \
             initialization.",
        ));
    }

    // An observation that names a start trigger this build does not model is a
    // blit that never happened, which is a missing image with nothing in the
    // record to explain it. The other ECS offsets change no state on either
    // chipset and stay observations, so the question asked is about the trigger
    // rather than about ECS.
    for tally in telemetry.observations() {
        let Some(register) = tally.register else {
            continue;
        };
        if !amiga_hw::is_unmodelled_start_trigger(register) {
            continue;
        }
        let occurrences = if tally.occurrences == 1 {
            String::new()
        } else {
            format!(" ({} writes)", tally.occurrences)
        };
        let name = amiga_hw::registers::register_name(register)
            .unwrap_or_else(|| format!("${register:03x}"));
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::SandboxBlitterUnsupported,
                format!(
                    "{name} (${register:03x}) was written{occurrences}; it starts a blit on \
                     ECS, and this build models an OCS blitter where the write changes \
                     nothing. The blits that register would have started did not happen."
                ),
            )
            .at("$.result.chip_observations"),
        );
    }

    let observations = telemetry
        .observations()
        .map(|tally| crate::response::SandboxChipObservation {
            kind: tally.kind.to_owned(),
            register: tally.register,
            channel: None,
            occurrences: tally.occurrences,
        })
        .collect();
    (
        rows,
        telemetry.blits_total(),
        telemetry.attempted_blit_words_total(),
        telemetry.executed_blit_words_total(),
        observations,
    )
}

/// The sandbox both `run` and `call` execute in, once it is laid out.
///
/// Extracted so the two share one memory map rather than two that agree by
/// coincidence — which is the failure this whole operation exists to end, one
/// level down.
pub(crate) struct Prepared {
    pub memory: amiga_disasm::Memory,
    pub source: SourcePin,
    /// The image being run, kept so a seed can copy from it without resolving
    /// the same source a second time. Cheap: the bytes are behind an `Arc`.
    pub image: crate::source::ResolvedSource,
    pub hunk: u32,
    pub load_origin: u32,
    pub allocation_bytes: u64,
    pub entry: u32,
    pub stack_base: u32,
    pub stack_top: u32,
}

/// Everything that decides the memory map, and nothing that decides what runs
/// in it.
///
/// A borrowed view rather than a copy, so a request that grows a field does not
/// grow a second place to forget it.
pub(crate) struct Layout<'a> {
    pub source: &'a crate::normalize::NormalizedSource,
    pub maximum_input_bytes: u64,
    pub hunk: Option<u32>,
    pub load_origin: Option<u32>,
    pub entry_offset: u32,
    pub hunk_bases: &'a [crate::request::HunkBase],
    pub stack: Option<crate::request::StackRegion>,
    pub mapped_regions: &'a [crate::request::MappedRegion],
}

/// Resolve the image, map every hunk the layout names, apply relocations, and
/// map the stack. The whole map, and nothing that depends on what runs.
#[expect(
    clippy::too_many_lines,
    reason = "one layout, told in order; splitting it would hide which failure precedes which"
)]
fn prepare(layout: &Layout<'_>, context: &ExecutionContext<'_>) -> Result<Prepared, Diagnostic> {
    let Layout {
        source: source_name,
        maximum_input_bytes,
        hunk,
        load_origin: requested_origin,
        entry_offset,
        hunk_bases,
        stack,
        mapped_regions,
    } = *layout;
    let source = context
        .resolve_source(source_name, maximum_input_bytes)
        .map_err(|error| Diagnostic::error(source_error_code(&error), error.to_string()))?;

    let executable = amiga_hunk::Executable::parse(source.bytes()).map_err(|error| {
        Diagnostic::error(DiagnosticCode::AnalysisHunkUnreadable, error.to_string())
    })?;
    let hunk = select_hunk(&executable, hunk)?;
    let segment = executable.segment(hunk).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::AnalysisHunkUnreadable,
            format!("the image has no hunk {hunk}"),
        )
        .at("$.request.arguments.hunk")
    })?;
    let load_origin = requested_origin.unwrap_or(DEFAULT_LOAD_ORIGIN);

    let mut memory = amiga_disasm::Memory::new();
    let mut bases = BTreeMap::from([(hunk, load_origin)]);
    for base in hunk_bases {
        if base.hunk == hunk {
            return Err(Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "hunk_bases names hunk {hunk}, which is the hunk being run; \
                     use load_origin for that one"
                ),
            )
            .at("$.request.arguments.hunk_bases"));
        }
        if bases.insert(base.hunk, base.address).is_some() {
            return Err(Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("hunk {} has more than one load address", base.hunk),
            )
            .at("$.request.arguments.hunk_bases"));
        }
    }

    // Check the complete declared map before the first RAM allocation. Every
    // execution mode, including project recipe replay, prepares through here.
    let sizes = bases
        .keys()
        .map(|hunk| {
            executable
                .segment(*hunk)
                .map(|segment| segment.allocation_size as u64)
                .ok_or_else(|| {
                    Diagnostic::error(
                        DiagnosticCode::RequestArgumentOutOfRange,
                        format!("hunk_bases names missing hunk {hunk}"),
                    )
                    .at("$.request.arguments.hunk_bases")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut sizes = sizes
        .into_iter()
        .chain(std::iter::once(
            stack.map_or(STACK_BYTES as u64, |s| u64::from(s.size)),
        ))
        .chain(mapped_regions.iter().map(|region| u64::from(region.size)));
    let total = sizes.try_fold(0_u64, |total, size| total.checked_add(size));
    let maximum = context.limits().maximum_sandbox_memory_bytes();
    if total.is_none_or(|total| total > maximum) {
        return Err(Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            format!("sandbox RAM exceeds the {maximum}-byte context limit before allocation"),
        ));
    }

    for (&mapped_hunk, &address) in &bases {
        let mapped = executable.segment(mapped_hunk).ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!("hunk_bases names missing hunk {mapped_hunk}"),
            )
            .at("$.request.arguments.hunk_bases")
        })?;
        memory
            .map(address, mapped.allocation_size)
            .map_err(|error| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("mapping hunk {mapped_hunk} at {address:#x}: {error}"),
                )
            })?;
        if !mapped.bytes.is_empty() {
            memory.load(address, mapped.bytes).map_err(|error| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("loading hunk {mapped_hunk}: {error}"),
                )
            })?;
        }
    }

    // Relocations are applied for every mapped hunk. A hunk that relocates into
    // one nobody mapped is an error rather than a silent skip: the code would
    // run with an address that means nothing, and the trace would not say so.
    relocate(&executable, &bases, &mut memory)?;

    let (stack_base, stack_size) = match stack {
        Some(stack) => (stack.base, stack.size as usize),
        None => {
            let base = load_origin
                .checked_add(segment.allocation_size as u32)
                .and_then(|end| end.checked_add(STACK_GAP))
                .ok_or_else(|| {
                    Diagnostic::error(
                        DiagnosticCode::SandboxMemoryUnmappable,
                        "the derived stack does not fit above the hunk",
                    )
                })?;
            (base, STACK_BYTES)
        }
    };
    memory.map(stack_base, stack_size).map_err(|error| {
        Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            format!("mapping the stack at {stack_base:#x}: {error}"),
        )
    })?;
    let stack_top = stack_base.checked_add(stack_size as u32).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            "the stack top overflows the address space",
        )
    })?;

    let entry = load_origin.checked_add(entry_offset).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            "the entry address overflows the address space",
        )
        .at("$.request.arguments.entry_offset")
    })?;
    if u64::from(entry_offset) >= segment.allocation_size as u64 {
        return Err(Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            format!(
                "entry_offset {entry_offset} is outside hunk {hunk}'s {} allocated bytes",
                segment.allocation_size
            ),
        )
        .at("$.request.arguments.entry_offset"));
    }

    for region in mapped_regions {
        memory
            .map(region.address, region.size as usize)
            .map_err(|error| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("mapping region at {:#x}: {error}", region.address),
                )
                .at("$.request.arguments.mapped_regions")
            })?;
    }

    Ok(Prepared {
        memory,
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        image: source.clone(),
        hunk,
        load_origin,
        allocation_bytes: segment.allocation_size as u64,
        entry,
        stack_base,
        stack_top,
    })
}

pub(crate) fn run(
    request: &NormalizedSandboxRun,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxRun,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let Prepared {
        mut memory,
        source,
        image: _,
        hunk,
        load_origin,
        allocation_bytes,
        entry,
        stack_base,
        stack_top,
    } = match prepare(
        &Layout {
            source: &request.source,
            maximum_input_bytes: request.maximum_input_bytes,
            hunk: request.hunk,
            load_origin: request.load_origin,
            entry_offset: request.entry_offset,
            hunk_bases: &request.hunk_bases,
            stack: request.stack,
            mapped_regions: &[],
        },
        context,
    ) {
        Ok(prepared) => prepared,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let mut options = amiga_disasm::RunOptions::new(stack_top, RETURN_MARKER);
    options.max_steps = request.maximum_steps;
    options.data = request.data_registers;
    options.address = request.address_registers;
    // A watched range is only observable through the trace, so watching implies
    // recording even when the caller asked for no trace: otherwise a watch hit
    // would stop the run and then have nothing to point at.
    options.record_steps = request.trace || !request.watch.is_empty();
    // Only as many rows as could be reported are kept. A step row holds the
    // instruction's text, its register deltas, and its writes, so a budget a
    // context can raise is finite in instructions only if the trace is finite
    // in memory too; the true total is counted either way.
    options.retained_steps = Some(request.maximum_trace_rows);
    options.stop_on_watch = request.stop_on_watch;
    options.watchpoints = watchpoints(&request.watch);

    events.emit(OperationEvent::Progress {
        phase: "map_memory",
        completed: 1,
        total: Some(1),
    });
    let execution = amiga_disasm::run(&mut memory, entry, &options);
    events.emit(OperationEvent::Progress {
        phase: "execute",
        completed: execution.steps_executed as u64,
        total: Some(request.maximum_steps as u64),
    });

    let trace_total = execution.steps_traced;
    let truncated = request.trace && trace_total > request.maximum_trace_rows;
    if truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the trace holds {trace_total} rows; {} are reported",
                request.maximum_trace_rows
            ),
        ));
    }
    let trace = if request.trace {
        execution
            .steps
            .iter()
            .take(request.maximum_trace_rows)
            .map(step_row)
            .collect()
    } else {
        Vec::new()
    };

    // The total comes from the counter, not from the log's length: the log is
    // itself a capped prefix, so measuring it would report a run's write count
    // as whichever of the two caps is lower and call a truncated answer whole.
    let writes_total = memory.writes_total();
    let writes_truncated = writes_total > MAX_REPORTED_WRITES as u64;
    if writes_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!("the run made {writes_total} writes; {MAX_REPORTED_WRITES} are reported"),
        ));
    }
    let writes = memory
        .writes()
        .iter()
        .take(MAX_REPORTED_WRITES)
        .map(|write| SandboxWrite {
            address: write.address,
            size: write.size,
            value: write.value,
        })
        .collect();

    let result = SandboxRunResult {
        source,
        hunk,
        load_origin,
        allocation_bytes,
        entry,
        stack_base,
        stack_top,
        steps_executed: execution.steps_executed as u64,
        stop: stop(&execution.stop),
        registers: registers(&execution.registers),
        trace,
        // The true total, always: a capped trace that read as a complete one
        // would make a step limit look like a short routine.
        trace_total: trace_total as u64,
        trace_truncated: truncated,
        watch_events_total: execution.watch_events_total,
        watch_events_truncated: execution.watch_events_truncated,
        writes,
        writes_total,
        writes_truncated,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::EnvSandboxRun(result)),
    )
}

/// What one boot run produced: the reported trace, and the served track bytes
/// an export would write.
type Booted = (BootTraceResult, Vec<(String, Vec<u8>)>);

/// `env.boot.trace` — boot a floppy in a seeded Amiga and report what it did.
///
/// The environment is fixed: exec and trackdisk serviced, the custom-chip range
/// modelled, the boot block loaded where a real machine loads it. A boot block
/// is written against *the* machine, not against a machine a caller describes,
/// so what a caller chooses is only how long to let it run and what to watch.
///
/// The exec calls are ground truth — the vectors the host actually serviced —
/// rather than a static disassembly's guess. They are reported by offset alone;
/// an fd table names them, and those are the frontend's configuration.
fn trace(
    request: &NormalizedBootTrace,
    context: &ExecutionContext<'_>,
    events: &mut BoundedSink<'_>,
) -> Result<Booted, Diagnostic> {
    let source = context
        .resolve_source(&request.source, request.maximum_input_bytes)
        .map_err(|error| Diagnostic::error(source_error_code(&error), error.to_string()))?;

    let boot = amiga_adf::Bootblock::parse(source.bytes()).map_err(|error| {
        Diagnostic::error(DiagnosticCode::ContainerAdfUnreadable, error.to_string())
    })?;
    let magic = boot.magic();
    let pin = SourcePin {
        size: source.size(),
        sha256: source.sha256().to_owned(),
    };
    let summary = BootInfoResult {
        source: pin.clone(),
        tag: amiga_core::latin1(&magic[0..3]),
        flags: boot.flags(),
        is_dos: boot.is_dos(),
        filesystem: boot.filesystem().to_string(),
        stored_checksum: boot.stored_checksum(),
        checksum_valid: boot.has_valid_checksum(),
        root_block: boot.root_block(),
        has_boot_code: boot.has_boot_code(),
        boot_code_bytes: boot.boot_code().len() as u64,
    };

    let mut environment = amiga_env::Environment::boot(source.bytes()).map_err(|error| {
        Diagnostic::error(DiagnosticCode::SandboxMemoryUnmappable, error.to_string())
    })?;
    let run = environment.run(
        request.maximum_steps,
        watchpoints(&request.watch),
        request.stop_on_watch,
    );
    events.emit(OperationEvent::Progress {
        phase: "boot",
        completed: run.execution.steps_executed as u64,
        total: Some(request.maximum_steps as u64),
    });

    // Taken from the chip page itself, which recorded each write as it
    // happened. It used to be recovered by scanning the whole memory write log
    // afterwards, which is what forced that log to stay complete; and the page
    // already resolves a `MOVE.L` into a pointer pair to its two register
    // writes, so reading them from it is one decomposition rather than two that
    // could disagree.
    let recorded = environment.chip_writes();
    let chip_writes: Vec<ChipWrite> = recorded
        .writes()
        .iter()
        .map(|write| chip_write(write.address, write.offset, write.value))
        .collect();
    let chip_writes_total = recorded.total();
    let chip_writes_truncated = recorded.truncated();
    drop(recorded);

    // From the bus, not from the trace rows. The rows are capped separately,
    // and at the default step budget a boot trace exceeds that cap — so a
    // row-derived answer drops hits while `watch_events_truncated`, which
    // measures the bus's own retention, keeps reporting nothing was lost.
    let watch_hits = environment
        .watch_events()
        .iter()
        .map(|event| SandboxAccess {
            address: event.address,
            access: access(event.access),
            size: event.size,
            before: event.before,
            after: event.after,
        })
        .collect();

    let mut dumps = Vec::new();
    let mut served_reads = Vec::new();
    let mut bytes_served = 0_u64;
    for read in &run.served_reads {
        bytes_served += u64::from(read.actual);
        served_reads.push(ServedRead {
            index: read.index as u64,
            command: read.command.clone(),
            offset: read.offset,
            destination: read.dest,
            requested: read.requested,
            actual: read.actual,
            status: i32::from(read.status),
        });
        if read.actual == 0 {
            continue;
        }
        // Served straight from the source image: the bytes a dump holds are the
        // bytes the device transferred, not a re-read that could differ.
        let start = usize::try_from(read.offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(read.actual as usize);
        let Some(bytes) = source.bytes().get(start..end) else {
            return Err(Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "served read {} covers [{}..{end}), outside the {}-byte source",
                    read.index,
                    read.offset,
                    source.bytes().len()
                ),
            ));
        };
        dumps.push((
            // Chronological, never `track_NN`: reads can be partial,
            // overlapping, or repeated, and a name that implied otherwise would
            // make two different reads collide.
            format!(
                "read_{:03}_offset_{:07x}_len_{:05}.bin",
                read.index, read.offset, read.actual
            ),
            bytes.to_vec(),
        ));
    }

    Ok((
        BootTraceResult {
            source: pin,
            boot: summary,
            load_address: amiga_env::layout::BOOT_LOAD,
            entry: amiga_env::layout::entry(),
            exec_base: amiga_env::layout::EXEC_BASE,
            io_request: amiga_env::layout::IOREQ,
            stop: stop(&run.execution.stop),
            steps_executed: run.execution.steps_executed as u64,
            chip_writes,
            chip_writes_total,
            chip_writes_truncated,
            exec_calls: run
                .exec_calls
                .iter()
                .map(|call| BootExecCall {
                    site: call.site,
                    offset: i32::from(call.offset),
                })
                .collect(),
            watch_hits,
            watch_events_total: run.execution.watch_events_total,
            watch_events_truncated: run.execution.watch_events_truncated,
            served_reads,
            bytes_served,
        },
        dumps,
    ))
}

/// Say so when the chip-write record is a prefix.
///
/// The fields carry the fact, but a caller reading the printed list is owed the
/// same warning the write log's own cap produces: a tolerated gap warns rather
/// than passing silently.
fn warn_if_chip_writes_truncated(result: &BootTraceResult, diagnostics: &mut Vec<Diagnostic>) {
    if result.chip_writes_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the boot code wrote {} custom-chip registers; {} are reported",
                result.chip_writes_total,
                result.chip_writes.len()
            ),
        ));
    }
}

fn chip_write(address: u32, offset: u16, value: u16) -> ChipWrite {
    ChipWrite {
        address,
        register: amiga_hw::registers::register_name(offset),
        value,
    }
}

pub(crate) fn boot_trace(
    request: &NormalizedBootTrace,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvBootTrace,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match trace(request, context, events) {
        Ok((result, _)) => {
            warn_if_chip_writes_truncated(&result, &mut diagnostics);
            outcome(
                Status::Success,
                diagnostics,
                Some(OperationResult::EnvBootTrace(result)),
            )
        }
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

pub(crate) fn boot_trace_export(
    request: &NormalizedBootTraceExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvBootTraceExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (result, dumps) = match trace(&request.trace, context, events) {
        Ok(pair) => pair,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };
    warn_if_chip_writes_truncated(&result, &mut diagnostics);

    let manifest = match serde_json::to_vec_pretty(&result) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let mut files: Vec<PlannedOutput> = dumps
        .iter()
        .map(|(name, bytes)| PlannedOutput {
            path: name.clone(),
            size: bytes.len() as u64,
            sha256: amiga_core::sha256(bytes),
        })
        .collect();
    files.push(PlannedOutput {
        path: MANIFEST_NAME.to_owned(),
        size: manifest.len() as u64,
        sha256: amiga_core::sha256(&manifest),
    });
    // A directory destination, unlike every other export: a boot run serves
    // however many reads it serves, and there is no single file to name.
    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::Directory,
        request.policy,
        files,
        Vec::new(),
    );
    let planned = |plan: WritePlan, committed| {
        Some(OperationResult::EnvBootTraceExport(BootTraceExportResult {
            trace: result.clone(),
            plan,
            committed,
        }))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, planned(plan, false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this boot run, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, planned(plan, false));
    }

    let write_plan = match amiga_core::ExtractionPlan::new(
        dumps
            .into_iter()
            .map(|(name, bytes)| amiga_core::PlannedFile {
                path: std::path::PathBuf::from(name),
                bytes,
            })
            .collect(),
        Vec::new(),
    ) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    match write_plan.commit(
        &destination,
        request.policy.permits_replacement(),
        MANIFEST_NAME,
        &manifest,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, planned(plan, true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, planned(plan, false))
        }
    }
}

/// The manifest a directory destination carries at its top.
const MANIFEST_NAME: &str = "manifest.json";

/// `env.sandbox.call` — invoke one routine to `RTS` and report a diffable
/// input→output record.
///
/// The same sandbox `run` builds, plus what a call needs: regions the routine
/// reads or writes, bytes seeded into them, and arguments laid out above the
/// return marker as a `JSR` would leave them.
///
/// What one call produced.
///
/// More than the record, because two other operations are built on this one and
/// each needs a different part: an export wants the bytes of every named range,
/// and a frame capture wants the memory and the chip registers the run left. A
/// second execution path for either would be a second answer to what a call
/// does, which is the divergence this crate exists to prevent.
pub(crate) struct Called {
    pub record: SandboxCallResult,
    pub exports: Vec<(String, Vec<u8>)>,
    pub memory: amiga_disasm::Memory,
    pub chips: ChipHandles,
    /// The memory as it stood before the routine ran, which is what a
    /// dependency slice decodes its instructions against: a trace records what
    /// each instruction *did* and not what it was.
    pub baseline: amiga_disasm::Memory,
    /// The executor's own trace rows, which carry more than the record's do —
    /// the register deltas a slice replays and the writes it follows.
    pub steps: Vec<amiga_disasm::Step>,
    /// The register file at entry, from which every step's pre-state is
    /// reconstructed.
    pub entry_registers: amiga_disasm::RegisterFile,
    /// Where the hunk was mapped and how much of it there is, so a slice can
    /// read the bytes an instruction was decoded from.
    pub load_origin: u32,
    pub allocation_bytes: u64,
}

/// The stack is excluded from the memory diff. It is scratch, and including it
/// would make every record differ from every other for reasons that say nothing
/// about the routine.
///
/// The trace and the watched ranges are honoured here exactly as `run` honours
/// them. They were once accepted and dropped — the request could name a watch
/// and ask to stop on it, and the executor kept no steps, so `stop_on_watch`
/// could never fire and a fault after a long initialization had nothing to be
/// traced back to. What a request advertises and what the run does are one
/// thing now, and the two operations share the rule that watching implies
/// recording.
pub(crate) fn call(
    request: &NormalizedSandboxCall,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Result<Called, Diagnostic> {
    let Prepared {
        mut memory,
        source,
        image,
        hunk,
        entry,
        stack_base,
        stack_top,
        load_origin,
        allocation_bytes,
    } = prepare(
        &Layout {
            source: &request.run.source,
            maximum_input_bytes: request.run.maximum_input_bytes,
            hunk: request.run.hunk,
            load_origin: request.run.load_origin,
            entry_offset: request.run.entry_offset,
            hunk_bases: &request.run.hunk_bases,
            stack: request.run.stack,
            mapped_regions: &request.mapped_regions,
        },
        context,
    )?;

    // Resolved before anything is written: a seed naming a range the source
    // does not hold is a refusal, not a run that seeded some of what it said.
    let seeds = resolve_seeds(&request.memory_seeds, &image, context)?;
    for (seed, bytes) in &seeds {
        memory.load(seed.address, bytes).map_err(|error| {
            Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!("seeding {:#x}: {error}", seed.address),
            )
            .at("$.request.arguments.memory_seeds")
        })?;
    }

    // Arguments sit above the simulated return address, as a JSR would leave
    // them: at entry SP holds the return marker and SP+4 is the first argument.
    let argument_bytes = u32::try_from(request.stack_arguments.len() * 4).map_err(|_| {
        Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            "too many stack arguments",
        )
        .at("$.request.arguments.stack_arguments")
    })?;
    let call_sp = stack_top.checked_sub(argument_bytes).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            "the stack arguments underflow the stack region",
        )
        .at("$.request.arguments.stack_arguments")
    })?;
    for (index, argument) in request.stack_arguments.iter().enumerate() {
        let at = call_sp
            .checked_add(u32::try_from(index * 4).unwrap_or(u32::MAX))
            .ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    "a stack argument address overflows",
                )
            })?;
        memory.write_long(at, *argument).map_err(|error| {
            Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!("stack argument at {at:#x}: {error}"),
            )
        })?;
    }

    let mut options = amiga_disasm::RunOptions::new(call_sp, RETURN_MARKER);
    options.max_steps = request.run.maximum_steps;
    options.data = request.run.data_registers;
    options.address = request.run.address_registers;
    // A golden record is about inputs and outputs, so nothing is recorded
    // unless the request asked for it: recording megabytes to discard them is
    // work nobody wanted, and a record that carried a trace by default would
    // differ between two runs that produced the same outputs. Watching implies
    // recording even without `trace`, or a watch hit would stop the run and
    // then have nothing to point at.
    options.record_steps = request.run.trace || !request.run.watch.is_empty();
    options.retained_steps = Some(request.run.maximum_trace_rows);
    options.stop_on_watch = request.run.stop_on_watch;
    options.watchpoints = watchpoints(&request.run.watch);

    let inputs = SandboxRegisters {
        d: options.data,
        a: options.address,
        usp: 0,
        ssp: call_sp,
        pc: entry,
        // Supervisor, interrupts masked: the state a sandboxed routine starts in.
        sr: 0x2700,
    };
    let baseline = memory.clone();

    // `call` runs over a `DeviceBus` always — one code path, and an empty device
    // list costs an `is_empty` check per access. A recipe that asks for no chips
    // gets exactly the run it always got.
    let mut bus = amiga_disasm::DeviceBus::new(memory);
    let beam = std::rc::Rc::new(std::cell::Cell::new(0_u64));
    let chips = attach_custom_chips(&mut bus, request, &beam)?;

    // A schedule, or none — and with none, `run_with_host` over a `NoHost` is
    // byte-for-byte what `run` did, so a recipe that schedules nothing gets the
    // run it always got.
    let mut schedule =
        amiga_disasm::InterruptSchedule::new(scheduled_interrupts(&request.interrupts));
    let mut nothing = amiga_disasm::NoHost;
    let mut beam_host = amiga_env::BeamHost::new(std::rc::Rc::clone(&beam));
    // The chip page derives VPOSR/VHPOSR from the beam counter, and nothing
    // under `call` advanced one before: a beam-wait loop would have spun to the
    // step budget with no explanation. The chain is only built when there is
    // more than one policy to run, so a recipe with neither keeps the identical
    // `NoHost` path.
    let mut chain;
    let host: &mut dyn amiga_disasm::Host = match (
        request.interrupts.is_empty(),
        request.custom_chips.is_some(),
    ) {
        (true, false) => &mut nothing,
        (false, false) => &mut schedule,
        (true, true) => &mut beam_host,
        (false, true) => {
            chain = amiga_disasm::HostChain::new(vec![&mut beam_host, &mut schedule]);
            &mut chain
        }
    };
    let execution = amiga_disasm::run_with_host(&mut bus, entry, host, &options);
    let memory = bus.ram().clone();
    events.emit(OperationEvent::Progress {
        phase: "execute",
        completed: execution.steps_executed as u64,
        total: Some(request.run.maximum_steps as u64),
    });

    let changed_memory =
        amiga_disasm::changed_regions(&baseline, &memory, &(stack_base..stack_top))
            .into_iter()
            .map(|region| SandboxRegion {
                address: region.address,
                hex: hex_encode(&region.bytes),
            })
            .collect();

    let trace_total = execution.steps_traced;
    let trace_truncated = request.run.trace && trace_total > request.run.maximum_trace_rows;
    if trace_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the trace holds {trace_total} rows; {} are reported",
                request.run.maximum_trace_rows
            ),
        ));
    }
    let trace = if request.run.trace {
        execution
            .steps
            .iter()
            .take(request.run.maximum_trace_rows)
            .map(step_row)
            .collect()
    } else {
        Vec::new()
    };

    // Recovered from the sandbox's final state, not replayed from the write
    // log: what a caller wants is the bytes that ended up there, including the
    // ones a seed put there and the routine never touched.
    let mut exports = Vec::with_capacity(request.memory_exports.len());
    let mut exported_regions = Vec::with_capacity(request.memory_exports.len());
    for export in &request.memory_exports {
        let bytes = memory
            .slice(export.address, export.length as usize)
            .ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!(
                        "memory export {:?} covers [{:#x}..+{:#x}), which is not mapped; \
                         name the region in mapped_regions",
                        export.name, export.address, export.length
                    ),
                )
                .at("$.request.arguments.memory_exports")
            })?
            .to_vec();
        exported_regions.push(crate::response::SandboxExportResult {
            name: export.name.clone(),
            address: export.address,
            length: export.length,
            sha256: amiga_core::sha256(&bytes),
            capture_note: capture_note(&source, hunk, entry, export, &execution),
        });
        exports.push((export.name.clone(), bytes));
    }

    let (
        blits,
        blits_total,
        attempted_blit_words_total,
        executed_blit_words_total,
        chip_observations,
    ) = report_blits(chips.telemetry.as_deref(), diagnostics);

    Ok(Called {
        record: SandboxCallResult {
            source,
            hunk,
            entry,
            inputs,
            stack_arguments: request.stack_arguments.clone(),
            mapped_regions: request.mapped_regions.clone(),
            memory_seeds: seeds
                .iter()
                .map(|(seed, bytes)| crate::response::SandboxSeedResult {
                    address: seed.address,
                    hex: hex_encode(bytes),
                    // Where the bytes came from, when the recipe named a range
                    // rather than spelling them out. A record carrying only the
                    // hex would say what was seeded and not that it was the
                    // image's own bytes, which is the fact a reader checks.
                    from: seed_origin(&seed.bytes, bytes.len() as u32),
                })
                .collect(),
            returned: matches!(execution.stop, amiga_disasm::StopReason::Returned),
            stop: stop(&execution.stop),
            steps_executed: execution.steps_executed as u64,
            outputs: registers(&execution.registers),
            changed_memory,
            trace,
            // The true total, always, as `run` reports it: a capped trace that read
            // as a complete one would make a step limit look like a short routine.
            trace_total: trace_total as u64,
            trace_truncated,
            watch_events_total: execution.watch_events_total,
            watch_events_truncated: execution.watch_events_truncated,
            exported_regions,
            interrupts_delivered: schedule
                .delivered()
                .iter()
                .take(MAX_REPORTED_DELIVERIES)
                .map(|delivery| crate::response::SandboxInterruptDelivery {
                    index: delivery.index as u64,
                    step: delivery.step,
                    handler: delivery.handler,
                    resume: delivery.resume,
                })
                .collect(),
            interrupts_total: schedule.delivered().len() as u64,
            custom_chips: request.custom_chips.map(custom_chips_result),
            blits,
            blits_total,
            attempted_blit_words_total,
            executed_blit_words_total,
            chip_observations,
        },
        exports,
        memory,
        chips,
        baseline,
        steps: execution.steps.clone(),
        entry_registers: amiga_disasm::RegisterFile {
            d: inputs.d,
            a: inputs.a,
            usp: inputs.usp,
            ssp: inputs.ssp,
            pc: inputs.pc,
            sr: inputs.sr,
        },
        load_origin,
        allocation_bytes,
    })
}

/// The same call, with the machine it left.
///
/// `env.frame.capture` reconstructs a display from the register state and the
/// memory a run produced, and neither is in the record: the record is about
/// inputs and outputs, and a display is about what the chips were left holding.
pub(crate) fn call_with_chip_state(
    request: &NormalizedSandboxCall,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Result<
    (
        SandboxCallResult,
        amiga_disasm::Memory,
        std::rc::Rc<std::cell::RefCell<amiga_env::ChipRegisters>>,
    ),
    Diagnostic,
> {
    let called = call(request, context, diagnostics, events)?;
    // Normalization refuses a capture with no chip page, so this is unreachable
    // through a request; refused rather than unwrapped, because the alternative
    // is a panic in the one place a caller could reach it from Rust.
    let registers = called.chips.registers.ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            "the run modelled no custom chips, so there is no register state to \
             reconstruct a display from",
        )
    })?;
    Ok((called.record, called.memory, registers))
}

pub(crate) fn call_run(
    request: &NormalizedSandboxCall,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxCall,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match call(request, context, &mut diagnostics, events) {
        Ok(called) => outcome(
            Status::Success,
            diagnostics,
            Some(OperationResult::EnvSandboxCall(called.record)),
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

/// Runs of changed memory reported per matrix case. The true total is beside
/// them, as everywhere else a record is capped.
const MAX_REPORTED_MATRIX_REGIONS: usize = 64;

/// The SHA-256 of the bytes a hex string spells.
///
/// Digested as *bytes* rather than as the text that spells them, which is what
/// it has to be: the same range digested here and by `exported_regions` must
/// agree, or two fields of one record would describe the same memory
/// differently. The hex is what `changed_memory` already carries, so this
/// decodes rather than the caller re-reading memory.
pub(crate) fn digest_hex(hex: &str) -> String {
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
            let low = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
            (high << 4) | low
        })
        .collect();
    amiga_core::sha256(&bytes)
}

/// The bytes one case exported, under the case's own name.
///
/// Carried beside the result rather than inside it for the reason
/// `env.sandbox.call` keeps them apart: a read-only matrix reports digests and a
/// response holding three hundred cases' memory is one nobody can read. The
/// export operation is the only caller that wants them.
type MatrixExports = Vec<(String, Vec<(String, Vec<u8>)>)>;

/// Run every case, and return the aggregate plus whatever each case exported.
///
/// Shared by the read and the export so that a matrix means one thing. An
/// exporting sweep that ran its cases through a second path could disagree with
/// the read-only one about what a case did, which is the divergence the
/// operation layer exists to prevent.
fn run_matrix(
    request: &crate::normalize::NormalizedSandboxMatrix,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> (crate::response::SandboxMatrixResult, MatrixExports) {
    let base_recipe_sha256 = request.base_digest.clone();
    let mut exports: MatrixExports = Vec::new();

    let mut cases = Vec::with_capacity(request.cases.len());
    let mut steps_remaining = request.maximum_total_steps;
    let mut steps_executed_total = 0_u64;
    let mut cases_ran = 0_u64;
    let mut cases_returned = 0_u64;
    let mut cases_refused = 0_u64;
    let mut cases_not_run = 0_u64;
    let mut budget_exhausted = false;
    // Read from the first case that runs. Every case shares the recipe's source
    // and hunk, so whichever answers first answers for all of them.
    let mut source: Option<crate::response::SourcePin> = None;
    let mut hunk: Option<u32> = None;

    for case in &request.cases {
        let empty = |outcome| crate::response::SandboxMatrixCaseResult {
            name: case.name.clone(),
            recipe_sha256: case.digest.clone(),
            outcome,
            notes: case.notes.clone(),
            entry: None,
            inputs: None,
            outputs: None,
            stop: None,
            returned: false,
            steps_executed: 0,
            changed_regions: Vec::new(),
            changed_regions_total: 0,
            changed_regions_truncated: false,
            exported_regions: Vec::new(),
            diagnostics: Vec::new(),
        };

        // A case is never clipped to what is left. One that would have to be is
        // reported as not run, because a case stopped by the *matrix's* budget
        // would carry a stop reason that says nothing about the routine and
        // reads exactly like one that ran out on its own.
        //
        // Every case shares the recipe's `maximum_steps` — a case may override
        // its inputs and not its budget — so once one case does not fit, none
        // after it will, and the sweep truncates in order. **If a per-case step
        // budget is ever added, revisit this**: it would let a cheap case run
        // after an expensive one was skipped, and a reader counting `not_run`
        // could no longer tell where the sweep stopped.
        if case.call.run.maximum_steps > steps_remaining {
            budget_exhausted = true;
            cases_not_run += 1;
            cases.push(empty(crate::response::MatrixCaseOutcome::NotRun));
            continue;
        }

        // Each case's own diagnostics, so one case's warning is not attributed
        // to the matrix or to its neighbour.
        let mut case_diagnostics = Vec::new();
        match call(&case.call, context, &mut case_diagnostics, events) {
            Ok(Called {
                record,
                exports: exported,
                ..
            }) => {
                if !exported.is_empty() {
                    exports.push((case.name.clone(), exported));
                }
                steps_remaining = steps_remaining
                    .saturating_sub(usize::try_from(record.steps_executed).unwrap_or(usize::MAX));
                steps_executed_total = steps_executed_total.saturating_add(record.steps_executed);
                cases_ran += 1;
                if record.returned {
                    cases_returned += 1;
                }
                if source.is_none() {
                    source = Some(record.source.clone());
                    hunk = Some(record.hunk);
                }
                let changed_regions_total = record.changed_memory.len() as u64;
                let changed_regions: Vec<_> = record
                    .changed_memory
                    .iter()
                    .take(MAX_REPORTED_MATRIX_REGIONS)
                    .map(|region| crate::response::MatrixRegionDigest {
                        address: region.address,
                        length: (region.hex.len() / 2) as u32,
                        sha256: digest_hex(&region.hex),
                    })
                    .collect();
                cases.push(crate::response::SandboxMatrixCaseResult {
                    name: case.name.clone(),
                    recipe_sha256: case.digest.clone(),
                    outcome: crate::response::MatrixCaseOutcome::Ran,
                    notes: case.notes.clone(),
                    entry: Some(record.entry),
                    inputs: Some(record.inputs),
                    outputs: Some(record.outputs),
                    stop: Some(record.stop),
                    returned: record.returned,
                    steps_executed: record.steps_executed,
                    changed_regions,
                    changed_regions_total,
                    changed_regions_truncated: changed_regions_total
                        > MAX_REPORTED_MATRIX_REGIONS as u64,
                    exported_regions: record.exported_regions,
                    diagnostics: case_diagnostics,
                });
            }
            // A refused case does not end the matrix. The sweep exists to find
            // out which inputs behave differently, and one that faulted on
            // input is a finding rather than a reason to lose the other 299.
            Err(problem) => {
                cases_refused += 1;
                case_diagnostics.push(problem);
                let mut result = empty(crate::response::MatrixCaseOutcome::Refused);
                result.diagnostics = case_diagnostics;
                cases.push(result);
            }
        }
    }

    if budget_exhausted {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "{cases_not_run} of {} cases did not run: the matrix's {} step budget \
                     was spent",
                    request.cases.len(),
                    request.maximum_total_steps
                ),
            )
            .at("$.request.arguments.maximum_total_steps"),
        );
    }

    // Every case refused, and none ran. The individual refusals are all present
    // and each says why; this is the aggregate saying the sweep measured
    // nothing, which a reader counting successes could otherwise miss.
    if source.is_none() {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            "no case of the matrix ran, so it observed nothing; each case's own \
             diagnostics say why",
        ));
    }

    (
        crate::response::SandboxMatrixResult {
            source,
            hunk,
            base_recipe_sha256,
            cases_total: request.cases.len() as u64,
            cases_ran,
            cases_returned,
            cases_refused,
            cases_not_run,
            steps_executed_total,
            maximum_total_steps: request.maximum_total_steps as u64,
            budget_exhausted,
            cases,
        },
        exports,
    )
}

pub(crate) fn matrix(
    request: &crate::normalize::NormalizedSandboxMatrix,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let (result, _) = run_matrix(request, context, &mut diagnostics, events);
    OperationOutcome {
        operation: OperationName::EnvSandboxMatrix,
        // A sweep in which nothing ran is an error, and still answers: the
        // per-case refusals are the only thing such a sweep is for.
        status: if result.cases_ran == 0 {
            Status::Error
        } else {
            Status::Success
        },
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::EnvSandboxMatrix(result)),
    }
}

/// The bytes each step checkpointed, by step name and then by checkpoint name.
///
/// The same shape `run_matrix` returns for a sweep's exports, so
/// [`timeline_export`] and [`matrix_export`] plan their writes the same way.
type TimelineExports = Vec<(String, Vec<(String, Vec<u8>)>)>;

/// `env.sandbox.timeline` — one machine, and a sequence of steps that evolve it.
///
/// The apparatus is built exactly once and then *kept*: the memory map, the
/// custom-chip page, the beam counter and the interrupt schedule are the same
/// objects for every step, so step *n+1* sees precisely the state step *n*
/// produced. That is the whole difference from a matrix, whose cases are
/// deliberately independent.
///
/// **Everything that can be checked against the static machine is checked before
/// any step runs.** The memory map does not change while a timeline runs, so a
/// seed, a checkpoint or an entry offset outside it is a property of the request
/// rather than of the run — and refusing the timeline is the only honest answer,
/// since a half-run timeline leaves a machine the request never described.
///
/// What is left dynamic is exactly what has to be: whether a step that resumes
/// has a machine to continue.
#[expect(
    clippy::too_many_lines,
    reason = "one machine's history, told in order: preflight, then the step loop, then what \
              the whole timeline left behind"
)]
fn run_timeline(
    request: &crate::normalize::NormalizedSandboxTimeline,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Result<(crate::response::SandboxTimelineResult, TimelineExports), Diagnostic> {
    use crate::normalize::TimelineStart;
    use crate::response::TimelineStepOutcome;

    let base = &request.base;
    let Prepared {
        mut memory,
        source,
        image,
        hunk,
        load_origin,
        allocation_bytes,
        stack_base,
        stack_top,
        ..
    } = prepare(
        &Layout {
            source: &base.run.source,
            maximum_input_bytes: base.run.maximum_input_bytes,
            hunk: base.run.hunk,
            load_origin: base.run.load_origin,
            entry_offset: base.run.entry_offset,
            hunk_bases: &base.run.hunk_bases,
            stack: base.run.stack,
            mapped_regions: &base.mapped_regions,
        },
        context,
    )?;

    // Every seed of every step, resolved before the first one runs. A seed
    // naming a range no source holds is a refusal of the timeline, not a
    // timeline that stopped in the middle with a machine nobody described.
    let shared_seeds = resolve_seeds(&base.memory_seeds, &image, context)?;
    let mut step_seeds = Vec::with_capacity(request.steps.len());
    for step in &request.steps {
        step_seeds.push(resolve_seeds(&step.memory_seeds, &image, context)?);
    }

    for (seed, bytes) in &shared_seeds {
        memory.load(seed.address, bytes).map_err(|error| {
            Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!("seeding {:#x}: {error}", seed.address),
            )
            .at("$.request.arguments.memory_seeds")
        })?;
    }

    // The map is complete and does not change while the timeline runs, so every
    // address the request names can be checked now — and a step that could never
    // record its checkpoint is a request to fix rather than a run to start.
    for (index, step) in request.steps.iter().enumerate() {
        if let TimelineStart::Enter { entry_offset, .. } = step.start
            && u64::from(entry_offset) >= allocation_bytes
        {
            return Err(Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "step {:?} enters at offset {entry_offset}, outside hunk {hunk}'s \
                     {allocation_bytes} allocated bytes",
                    step.name
                ),
            )
            .at(format!("$.request.arguments.steps[{index}].entry_offset")));
        }
        for (seed, bytes) in &step_seeds[index] {
            if memory.slice(seed.address, bytes.len()).is_none() {
                return Err(Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!(
                        "step {:?} seeds [{:#x}..+{:#x}), which is not mapped; name the \
                         region in mapped_regions",
                        step.name,
                        seed.address,
                        bytes.len()
                    ),
                )
                .at(format!("$.request.arguments.steps[{index}].memory_seeds")));
            }
        }
        for checkpoint in &step.checkpoints {
            if memory
                .slice(checkpoint.address, checkpoint.length as usize)
                .is_none()
            {
                return Err(Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!(
                        "step {:?} checkpoints {:?} over [{:#x}..+{:#x}), which is not \
                         mapped; name the region in mapped_regions",
                        step.name, checkpoint.name, checkpoint.address, checkpoint.length
                    ),
                )
                .at(format!("$.request.arguments.steps[{index}].checkpoints")));
            }
        }
    }
    for export in &base.memory_exports {
        if memory
            .slice(export.address, export.length as usize)
            .is_none()
        {
            return Err(Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!(
                    "memory export {:?} covers [{:#x}..+{:#x}), which is not mapped; \
                     name the region in mapped_regions",
                    export.name, export.address, export.length
                ),
            )
            .at("$.request.arguments.memory_exports"));
        }
    }

    let mut bus = amiga_disasm::DeviceBus::new(memory);
    let beam = std::rc::Rc::new(std::cell::Cell::new(0_u64));
    let chips = attach_custom_chips(&mut bus, base, &beam)?;
    // Built once and driven by every step, which is what "deterministic
    // interrupt state is preserved between steps" means: the schedule's own
    // instruction counter runs across the whole timeline rather than restarting
    // at each step, so a handler due every thousand instructions arrives at the
    // thousandth instruction of the timeline and not of the step.
    let mut schedule = amiga_disasm::InterruptSchedule::new(scheduled_interrupts(&base.interrupts));
    let mut beam_host = amiga_env::BeamHost::new(std::rc::Rc::clone(&beam));
    let watchpoints = watchpoints(&base.run.watch);

    let mut results = Vec::with_capacity(request.steps.len());
    let mut exports: TimelineExports = Vec::new();
    let mut previous: Option<(amiga_disasm::RegisterFile, amiga_disasm::StopReason)> = None;
    let mut remaining = request.maximum_total_steps;
    let mut executed_total = 0_u64;
    let mut ran = 0_u64;
    let mut refused = 0_u64;
    let mut not_run = 0_u64;
    let mut budget_exhausted = false;
    // Once one step does not run, none after it can: the order is the
    // experiment, and a later step continuing a machine that skipped its
    // predecessor would be a different timeline reported under this one's name.
    let mut halted = false;

    for (index, step) in request.steps.iter().enumerate() {
        let empty = |outcome| crate::response::SandboxTimelineStepResult {
            name: step.name.clone(),
            outcome,
            notes: step.notes.clone(),
            resumed: matches!(step.start, TimelineStart::Resume),
            entry: None,
            inputs: None,
            outputs: None,
            stop: None,
            returned: false,
            steps_executed: 0,
            changed_regions: Vec::new(),
            changed_regions_total: 0,
            changed_regions_truncated: false,
            memory_seeds: Vec::new(),
            trace: Vec::new(),
            trace_total: 0,
            trace_truncated: false,
            watch_events_total: 0,
            watch_events_truncated: false,
            interrupts_delivered: Vec::new(),
            interrupts_total: 0,
            interrupts_truncated: false,
            checkpoints: Vec::new(),
            diagnostics: Vec::new(),
        };

        if halted {
            not_run += 1;
            results.push(empty(TimelineStepOutcome::NotRun));
            continue;
        }
        if step.maximum_steps > remaining {
            budget_exhausted = true;
            halted = true;
            not_run += 1;
            results.push(empty(TimelineStepOutcome::NotRun));
            continue;
        }

        // Where the step starts, and the options that put it there. The only
        // thing that could not be settled before the timeline began is whether
        // a resuming step has a machine to continue.
        let started = match &step.start {
            TimelineStart::Enter {
                entry_offset,
                data_registers,
                address_registers,
                stack_arguments,
            } => enter(
                &mut bus,
                stack_top,
                load_origin.wrapping_add(*entry_offset),
                *data_registers,
                *address_registers,
                stack_arguments,
            ),
            TimelineStart::Resume => match previous {
                Some((_, amiga_disasm::StopReason::Returned)) => Err(Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!(
                        "step {:?} resumes, but the previous step's routine returned: the \
                         machine is sitting on the return marker and there is nothing left \
                         to continue. Enter a routine instead.",
                        step.name
                    ),
                )),
                Some((registers, _)) => {
                    let mut options = amiga_disasm::RunOptions::new(registers.ssp, RETURN_MARKER);
                    options.resume = Some(registers);
                    Ok((registers.pc, options))
                }
                // Unreachable through a request — normalization refuses a first
                // step that resumes, and a refusal before this one already
                // halted the timeline.
                None => Err(Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("step {:?} resumes, but no step before it ran", step.name),
                )),
            },
        };

        let (entry, mut options) = match started {
            Ok(started) => started,
            Err(problem) => {
                refused += 1;
                halted = true;
                let mut result = empty(TimelineStepOutcome::Refused);
                result.diagnostics = vec![problem];
                results.push(result);
                continue;
            }
        };
        let mut step_diagnostics = Vec::new();

        // The step's own seeds go in before the baseline is taken, so what the
        // step reports as changed is what its *execution* did. The seeds are
        // reported beside it as the inputs they are.
        for (seed, bytes) in &step_seeds[index] {
            // Pre-checked against the map above, so this cannot fail through a
            // request; a failure here would be a bug rather than bad input.
            if let Err(error) = bus.load(seed.address, bytes) {
                step_diagnostics.push(Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("seeding {:#x}: {error}", seed.address),
                ));
            }
        }

        options.max_steps = step.maximum_steps;
        // The shared recipe's trace and watch settings, honoured exactly as
        // `call` honours them — including the rule that watching implies
        // recording, or a watch that stopped a step would have nothing to point
        // at. A timeline that accepted `trace` and reported none would be the
        // silent drop `env.sandbox.call` was fixed for.
        options.record_steps = base.run.trace || !base.run.watch.is_empty();
        options.retained_steps = Some(base.run.maximum_trace_rows);
        options.stop_on_watch = base.run.stop_on_watch;
        options.watchpoints.clone_from(&watchpoints);

        // What the machine actually starts this step with. A resuming step's
        // whole register file comes from the run before it — `RunOptions::data`
        // and `::address` are not read on that path, so reporting them would
        // show every data and address register as zero for a step that inherited
        // a machine full of live values.
        let inputs = match options.resume {
            Some(file) => SandboxRegisters {
                d: file.d,
                a: file.a,
                usp: file.usp,
                ssp: file.ssp,
                pc: entry,
                sr: file.sr,
            },
            None => SandboxRegisters {
                d: options.data,
                a: options.address,
                usp: 0,
                ssp: options.stack_pointer,
                pc: entry,
                sr: 0x2700,
            },
        };
        let baseline = bus.ram().clone();
        let deliveries_before = schedule.delivered().len();

        let mut breakpoints = amiga_disasm::Breakpoints::new(step.stop_at.iter().copied(), entry);
        let mut nothing = amiga_disasm::NoHost;
        let mut hosts: Vec<&mut dyn amiga_disasm::Host> = Vec::new();
        if !breakpoints.is_empty() {
            hosts.push(&mut breakpoints);
        }
        if base.custom_chips.is_some() {
            hosts.push(&mut beam_host);
        }
        if !base.interrupts.is_empty() {
            hosts.push(&mut schedule);
        }
        let mut chain;
        let host: &mut dyn amiga_disasm::Host = if hosts.is_empty() {
            &mut nothing
        } else {
            chain = amiga_disasm::HostChain::new(hosts);
            &mut chain
        };
        let execution = amiga_disasm::run_with_host(&mut bus, entry, host, &options);
        let deliveries_after = schedule.delivered().len();
        events.emit(OperationEvent::Progress {
            phase: "execute",
            completed: index as u64 + 1,
            total: Some(request.steps.len() as u64),
        });

        remaining = remaining.saturating_sub(execution.steps_executed);
        executed_total = executed_total.saturating_add(execution.steps_executed as u64);
        ran += 1;
        previous = Some((execution.registers, execution.stop));

        let changed = amiga_disasm::changed_regions(&baseline, bus.ram(), &(stack_base..stack_top));
        let changed_regions_total = changed.len() as u64;
        let changed_regions = changed
            .iter()
            .take(MAX_REPORTED_MATRIX_REGIONS)
            .map(|region| crate::response::MatrixRegionDigest {
                address: region.address,
                length: region.bytes.len() as u32,
                sha256: amiga_core::sha256(&region.bytes),
            })
            .collect();
        let interrupts_total = deliveries_after.saturating_sub(deliveries_before) as u64;
        let retained_start = deliveries_before.min(MAX_REPORTED_DELIVERIES);
        let retained_end = deliveries_after.min(MAX_REPORTED_DELIVERIES);
        let interrupts_delivered: Vec<_> = schedule.delivered()[retained_start..retained_end]
            .iter()
            .map(|delivery| crate::response::SandboxInterruptDelivery {
                index: delivery.index as u64,
                step: delivery.step,
                handler: delivery.handler,
                resume: delivery.resume,
            })
            .collect();
        let interrupts_truncated = interrupts_total > interrupts_delivered.len() as u64;

        // Digested and kept together, so the bytes `env.sandbox.timeline.export`
        // writes are the bytes this step's `sha256` is over. A step that did not
        // run contributes nothing, which is why this is here and not beside
        // `empty`.
        let (checkpoints, checkpoint_bytes) = checkpoint_ranges(bus.ram(), &step.checkpoints);
        if !checkpoint_bytes.is_empty() {
            exports.push((step.name.clone(), checkpoint_bytes));
        }

        results.push(crate::response::SandboxTimelineStepResult {
            name: step.name.clone(),
            outcome: TimelineStepOutcome::Ran,
            notes: step.notes.clone(),
            resumed: matches!(step.start, TimelineStart::Resume),
            entry: Some(entry),
            inputs: Some(inputs),
            outputs: Some(registers(&execution.registers)),
            stop: Some(stop(&execution.stop)),
            returned: matches!(execution.stop, amiga_disasm::StopReason::Returned),
            steps_executed: execution.steps_executed as u64,
            changed_regions,
            changed_regions_total,
            changed_regions_truncated: changed_regions_total > MAX_REPORTED_MATRIX_REGIONS as u64,
            memory_seeds: step_seeds[index]
                .iter()
                .map(|(seed, bytes)| crate::response::SandboxSeedResult {
                    address: seed.address,
                    hex: hex_encode(bytes),
                    from: seed_origin(&seed.bytes, bytes.len() as u32),
                })
                .collect(),
            trace: if base.run.trace {
                execution
                    .steps
                    .iter()
                    .take(base.run.maximum_trace_rows)
                    .map(step_row)
                    .collect()
            } else {
                Vec::new()
            },
            trace_total: execution.steps_traced as u64,
            trace_truncated: base.run.trace && execution.steps_traced > base.run.maximum_trace_rows,
            watch_events_total: execution.watch_events_total,
            watch_events_truncated: execution.watch_events_truncated,
            interrupts_delivered,
            interrupts_total,
            interrupts_truncated,
            checkpoints,
            diagnostics: step_diagnostics,
        });
    }

    if budget_exhausted {
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::LimitReduced,
                format!(
                    "{not_run} of {} steps did not run: the timeline's {} step budget was \
                     spent",
                    request.steps.len(),
                    request.maximum_total_steps
                ),
            )
            .at("$.request.arguments.maximum_total_steps"),
        );
    }
    if refused > 0 {
        // A warning while anything ran, an error only when nothing did — the
        // rule a matrix follows, and for a stronger reason here. The operation
        // deliberately returns the steps that *did* run beside the refusal that
        // stopped them, and a frontend that treats an error diagnostic as fatal
        // would throw exactly that record away and print the aggregate instead.
        let message = "a step of the timeline was refused, so the steps after it did not run: \
                       they would have continued a machine this request never described";
        diagnostics.push(if ran == 0 {
            Diagnostic::error(DiagnosticCode::SandboxMemoryUnmappable, message)
        } else {
            Diagnostic::warning(DiagnosticCode::SandboxMemoryUnmappable, message)
        });
    }

    let (
        blits,
        blits_total,
        attempted_blit_words_total,
        executed_blit_words_total,
        chip_observations,
    ) = report_blits(chips.telemetry.as_deref(), diagnostics);

    Ok((
        crate::response::SandboxTimelineResult {
            source,
            hunk,
            base_recipe_sha256: request.base_digest.clone(),
            steps_total: request.steps.len() as u64,
            steps_ran: ran,
            steps_refused: refused,
            steps_not_run: not_run,
            instructions_executed_total: executed_total,
            maximum_total_steps: request.maximum_total_steps as u64,
            budget_exhausted,
            interrupts_total: schedule.delivered().len() as u64,
            interrupts_truncated: schedule.delivered().len() > MAX_REPORTED_DELIVERIES,
            steps: results,
            final_registers: previous.map(|(file, _)| registers(&file)),
            final_exports: checkpoint_digests(bus.ram(), &base.memory_exports),
            custom_chips: base.custom_chips.map(custom_chips_result),
            blits,
            blits_total,
            attempted_blit_words_total,
            executed_blit_words_total,
            chip_observations,
        },
        exports,
    ))
}

/// Lay a call frame out for a step that enters a routine.
///
/// The arguments sit above the return marker exactly as `env.sandbox.call`
/// leaves them, so a timeline step that enters is the same call the standalone
/// operation would have made.
fn enter(
    bus: &mut amiga_disasm::DeviceBus,
    stack_top: u32,
    entry: u32,
    data: [u32; 8],
    address: [u32; 7],
    stack_arguments: &[u32],
) -> Result<(u32, amiga_disasm::RunOptions), Diagnostic> {
    let argument_bytes = u32::try_from(stack_arguments.len() * 4).unwrap_or(u32::MAX);
    let call_sp = stack_top.checked_sub(argument_bytes).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::SandboxMemoryUnmappable,
            "the stack arguments underflow the stack region",
        )
    })?;
    for (position, argument) in stack_arguments.iter().enumerate() {
        let at = call_sp.wrapping_add(u32::try_from(position * 4).unwrap_or(u32::MAX));
        bus.load(at, &argument.to_be_bytes()).map_err(|error| {
            Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!("stack argument at {at:#x}: {error}"),
            )
        })?;
    }
    let mut options = amiga_disasm::RunOptions::new(call_sp, RETURN_MARKER);
    options.data = data;
    options.address = address;
    Ok((entry, options))
}

/// Digest each named range against the memory as it stands.
///
/// Every range was proven mapped before the timeline started, so a range that
/// cannot be read here is reported as empty rather than refused: the check that
/// would have refused it has already run, and failing at this point would blame
/// the step for a fault in the preflight.
fn checkpoint_ranges(
    memory: &amiga_disasm::Memory,
    ranges: &[crate::request::MemoryExport],
) -> (
    Vec<crate::response::TimelineCheckpoint>,
    Vec<(String, Vec<u8>)>,
) {
    let mut digests = Vec::with_capacity(ranges.len());
    let mut bytes = Vec::with_capacity(ranges.len());
    for range in ranges {
        let recovered = memory
            .slice(range.address, range.length as usize)
            .unwrap_or(&[])
            .to_vec();
        digests.push(crate::response::TimelineCheckpoint {
            name: range.name.clone(),
            address: range.address,
            length: range.length,
            // Over the same bytes the export writes, and taken from them: a
            // digest computed from a second read could disagree with the file
            // beside it, which is the one thing a checkpoint must not do.
            sha256: amiga_core::sha256(&recovered),
        });
        bytes.push((range.name.clone(), recovered));
    }
    (digests, bytes)
}

/// The digests alone, for the ranges nothing writes.
fn checkpoint_digests(
    memory: &amiga_disasm::Memory,
    ranges: &[crate::request::MemoryExport],
) -> Vec<crate::response::TimelineCheckpoint> {
    checkpoint_ranges(memory, ranges).0
}

/// Resolve one list of seeds to the bytes they carry.
///
/// Shared by `call` and by the timeline's preflight, so a seed is read the same
/// way whichever operation states it.
fn resolve_seeds<'a>(
    seeds: &'a [crate::normalize::NormalizedMemorySeed],
    image: &crate::source::ResolvedSource,
    context: &ExecutionContext<'_>,
) -> Result<Vec<(&'a crate::normalize::NormalizedMemorySeed, Vec<u8>)>, Diagnostic> {
    let mut resolved = Vec::with_capacity(seeds.len());
    for (index, seed) in seeds.iter().enumerate() {
        resolved.push((seed, resolve_seed(seed, image, context, index)?));
    }
    Ok(resolved)
}

/// The executor's schedule for the interrupts a recipe states.
///
/// One function rather than one per operation: `call` and `timeline` deliver on
/// the same terms, and two copies of this mapping would be two places for a new
/// field to be forgotten in one of them.
fn scheduled_interrupts(
    interrupts: &[crate::normalize::NormalizedInterrupt],
) -> Vec<amiga_disasm::ScheduledInterrupt> {
    interrupts
        .iter()
        .map(|interrupt| amiga_disasm::ScheduledInterrupt {
            handler: match (interrupt.handler.address, interrupt.handler.vector) {
                (Some(address), _) => amiga_disasm::InterruptHandler::Address(address),
                (None, Some(vector)) => amiga_disasm::InterruptHandler::Vector(vector),
                // Normalization refuses a schedule naming neither, so this is
                // unreachable through a request.
                (None, None) => amiga_disasm::InterruptHandler::Address(0),
            },
            after_steps: interrupt.after_steps,
            every_steps: interrupt.every_steps,
            deliveries: interrupt.deliveries,
            frame: match interrupt.handler.frame.unwrap_or_default() {
                crate::request::InterruptFrame::Rte => amiga_disasm::InterruptFrame::Exception,
                crate::request::InterruptFrame::Rts => amiga_disasm::InterruptFrame::Subroutine,
            },
        })
        .collect()
}

pub(crate) fn timeline(
    request: &crate::normalize::NormalizedSandboxTimeline,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxTimeline,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match run_timeline(request, context, &mut diagnostics, events) {
        // The read-only operation drops the checkpointed bytes: sixty ticks each
        // checkpointing a framebuffer is a response nobody can read, which is
        // what `env.sandbox.timeline.export` exists for.
        Ok((result, _)) => {
            // A timeline in which nothing ran still answers, for the reason a
            // matrix does: the per-step diagnostics are the only thing such a
            // run is for.
            let status = if result.steps_ran == 0 {
                Status::Error
            } else {
                Status::Success
            };
            outcome(
                status,
                diagnostics,
                Some(OperationResult::EnvSandboxTimeline(result)),
            )
        }
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

/// Write each step's checkpointed ranges under the step's own name.
///
/// The read-only timeline reports a digest per checkpoint and no bytes, and
/// there was no other way to get them: re-running the interesting step through
/// `env.sandbox.call` with an export only works when the step can be reproduced
/// as a standalone call, and a step deep in an evolving timeline cannot — its
/// inputs are the machine every step before it produced.
///
/// Two properties make this more than a loop over `matrix_export`. **Nothing is
/// written until every step has run**, which the timeline satisfies more
/// strongly than the sweep does: the whole request — every step's seeds, every
/// checkpoint range, every entry offset — is validated against the map before
/// the first instruction executes, so a step that could never record its
/// checkpoint is a refused request rather than a directory half full of files
/// from a run that stopped. And the manifest records each file's **step and the
/// timeline's own recipe digest**, so a later run can tell its outputs from
/// another's that reused the step names.
pub(crate) fn timeline_export(
    request: &crate::normalize::NormalizedSandboxTimelineExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxTimelineExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (result, exports) = match run_timeline(&request.timeline, context, &mut diagnostics, events)
    {
        Ok(pair) => pair,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };
    // Nothing ran, so there is nothing to write and no plan to review. The
    // per-step refusals are already on the diagnostics.
    if result.steps_ran == 0 {
        return outcome(Status::Error, diagnostics, None);
    }

    let aggregate = match serde_json::to_vec_pretty(&result) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // `<step>/<checkpoint>`, which is what the single-path-component rule on a
    // step name is for: two steps checkpointing a range under one name write two
    // files rather than one, and a name carrying a separator would be choosing a
    // directory layout the request never stated.
    let mut files = vec![PlannedOutput {
        path: request.file_name.clone(),
        size: aggregate.len() as u64,
        sha256: amiga_core::sha256(&aggregate),
    }];
    let mut staged = vec![amiga_core::PlannedFile {
        path: std::path::PathBuf::from(&request.file_name),
        bytes: aggregate,
    }];
    let mut provenance = Vec::new();
    for (step, checkpoints) in &exports {
        for (name, bytes) in checkpoints {
            let path = format!("{step}/{name}");
            files.push(PlannedOutput {
                path: path.clone(),
                size: bytes.len() as u64,
                sha256: amiga_core::sha256(bytes),
            });
            provenance.push(serde_json::json!({
                "path": path,
                "step": step,
                "checkpoint": name,
            }));
            staged.push(amiga_core::PlannedFile {
                path: std::path::PathBuf::from(&path),
                bytes: bytes.clone(),
            });
        }
    }

    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::DirectoryContents,
        request.policy,
        files,
        Vec::new(),
    );
    let reply = |plan: WritePlan, committed| {
        Some(OperationResult::EnvSandboxTimelineExport(
            crate::response::SandboxTimelineExportResult {
                result: result.clone(),
                plan,
                committed,
            },
        ))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, reply(plan, false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this timeline, which now \
                 has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, reply(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::EnvSandboxTimelineExport.as_str(),
        "source": {"size": result.source.size, "sha256": result.source.sha256},
        "hunk": result.hunk,
        // The experiment, and then each file's place in it. A manifest that
        // listed the paths without their step would not let a later run tell its
        // own outputs from another's that reused the step names.
        "base_recipe_sha256": result.base_recipe_sha256,
        "normalized_request_sha256": digest,
        "steps_total": result.steps_total,
        "steps_ran": result.steps_ran,
        "steps_refused": result.steps_refused,
        "steps_not_run": result.steps_not_run,
        "files": provenance,
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let write_plan = match amiga_core::ExtractionPlan::new(staged, Vec::new()) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let manifest_name = format!("{}.manifest.json", request.file_name);
    match write_plan.commit_into(
        &destination,
        request.policy.permits_replacement(),
        &manifest_name,
        &manifest,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, reply(plan, true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, reply(plan, false))
        }
    }
}

/// Write each case's exported ranges under the case's own name.
///
/// Two rules the read-only sweep does not need. **Nothing is written until every
/// case has run**: expansion and validation happen in normalization, so a
/// malformed case — including the last one — refuses the matrix before a byte is
/// planned, and the plan itself is built from the whole sweep. And the manifest
/// records each file's **case name and that case's recipe digest**, so a later
/// sweep can tell whether a file on disk came from the same experiment or from a
/// different one that happened to use the same case names.
pub(crate) fn matrix_export(
    request: &crate::normalize::NormalizedSandboxMatrixExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxMatrixExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (result, exports) = run_matrix(&request.matrix, context, &mut diagnostics, events);
    // Nothing ran, so there is nothing to write and no plan to review. The
    // per-case refusals are already on the diagnostics.
    if result.cases_ran == 0 {
        return outcome(Status::Error, diagnostics, None);
    }

    let aggregate = match serde_json::to_vec_pretty(&result) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // `<case>/<range>`, which is why a case name is validated as one path
    // component: two cases exporting a range under one name write two files
    // rather than one, and a name with a separator in it would be choosing a
    // directory layout the request never stated.
    let mut files = vec![PlannedOutput {
        path: request.file_name.clone(),
        size: aggregate.len() as u64,
        sha256: amiga_core::sha256(&aggregate),
    }];
    let mut staged = vec![amiga_core::PlannedFile {
        path: std::path::PathBuf::from(&request.file_name),
        bytes: aggregate,
    }];
    // The identity behind each written path: which case produced it, and the
    // digest of that case's own recipe.
    let mut provenance = Vec::new();
    for (case, ranges) in &exports {
        let recipe = result
            .cases
            .iter()
            .find(|reported| reported.name == *case)
            .map(|reported| reported.recipe_sha256.clone())
            .unwrap_or_default();
        for (name, bytes) in ranges {
            let path = format!("{case}/{name}");
            files.push(PlannedOutput {
                path: path.clone(),
                size: bytes.len() as u64,
                sha256: amiga_core::sha256(bytes),
            });
            provenance.push(serde_json::json!({
                "path": path,
                "case": case,
                "recipe_sha256": recipe,
            }));
            staged.push(amiga_core::PlannedFile {
                path: std::path::PathBuf::from(&path),
                bytes: bytes.clone(),
            });
        }
    }

    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::DirectoryContents,
        request.policy,
        files,
        Vec::new(),
    );
    let reply = |plan: WritePlan, committed| {
        Some(OperationResult::EnvSandboxMatrixExport(
            crate::response::SandboxMatrixExportResult {
                result: result.clone(),
                plan,
                committed,
            },
        ))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, reply(plan, false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this sweep, which now \
                 has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, reply(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::EnvSandboxMatrixExport.as_str(),
        "source": result.source.as_ref().map(|source| serde_json::json!({
            "size": source.size, "sha256": source.sha256,
        })),
        "hunk": result.hunk,
        // The experiment, and then each file's place in it. A manifest that
        // listed the paths without their case would not let a later sweep tell
        // its own outputs from another's that reused the case names.
        "base_recipe_sha256": result.base_recipe_sha256,
        "normalized_request_sha256": digest,
        "cases_total": result.cases_total,
        "cases_ran": result.cases_ran,
        "cases_returned": result.cases_returned,
        "cases_refused": result.cases_refused,
        "cases_not_run": result.cases_not_run,
        "files": provenance,
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let write_plan = match amiga_core::ExtractionPlan::new(staged, Vec::new()) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let manifest_name = format!("{}.manifest.json", request.file_name);
    match write_plan.commit_into(
        &destination,
        request.policy.permits_replacement(),
        &manifest_name,
        &manifest,
    ) {
        Ok(_) => outcome(Status::Success, diagnostics, reply(plan, true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, reply(plan, false))
        }
    }
}

pub(crate) fn call_export(
    request: &NormalizedSandboxCallExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvSandboxCallExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            diagnostics.push(Diagnostic::error(code, error.to_string()));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let (record, exports) = match call(&request.call, context, &mut diagnostics, events) {
        Ok(called) => (called.record, called.exports),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    // Serialized once: the plan's digest and the bytes written come from one
    // value, so a reviewer cannot be shown one record and given another.
    let bytes = match serde_json::to_vec_pretty(&record) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    // One file, or the record plus every range the recipe named. The kind
    // changes with it, because the guarantee does: `File` says the policy
    // governs that one file and its manifest and nothing else in the directory
    // is read or written, and that is no longer true once the export writes
    // several. `DirectoryContents` is the wider claim — these files, and still
    // nothing else in a directory this toolkit does not own.
    let mut files = vec![PlannedOutput {
        path: request.file_name.clone(),
        size: bytes.len() as u64,
        sha256: amiga_core::sha256(&bytes),
    }];
    files.extend(exports.iter().map(|(name, bytes)| PlannedOutput {
        path: name.clone(),
        size: bytes.len() as u64,
        sha256: amiga_core::sha256(bytes),
    }));
    let kind = if exports.is_empty() {
        crate::output::DestinationKind::File
    } else {
        crate::output::DestinationKind::DirectoryContents
    };
    let plan = WritePlan::new(
        &request.destination,
        kind,
        request.policy,
        files,
        Vec::new(),
    );
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::EnvSandboxCallExport(
            SandboxCallExportResult {
                record: record.clone(),
                plan,
                committed,
            },
        ))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(plan, false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RequestExecutionModeUnsupported,
                "an export reached the handler in `read` mode".to_owned(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this record, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::EnvSandboxCallExport.as_str(),
        "source": { "size": record.source.size, "sha256": record.source.sha256 },
        "hunk": record.hunk,
        "entry": record.entry,
        "returned": record.returned,
        "files": plan
            .files
            .iter()
            .map(|file| serde_json::json!({ "path": file.path, "sha256": file.sha256 }))
            .collect::<Vec<_>>(),
        // The recipe, not just its output: an exported range is only meaningful
        // beside the run that produced it. That includes the chips — a manifest
        // that carried the exported pixels and not what drew them would describe
        // a picture nobody could reproduce — and the request digest, which is
        // the one field that identifies the whole recipe in a line.
        "exported_regions": record.exported_regions,
        "mapped_regions": record.mapped_regions,
        "custom_chips": record.custom_chips,
        "normalized_request_sha256": digest,
        "stop": record.stop,
        "inputs": record.inputs,
    })) {
        Ok(manifest) => manifest,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let staged = std::iter::once((request.file_name.clone(), bytes))
        .chain(exports)
        .map(|(name, bytes)| amiga_core::PlannedFile {
            path: std::path::PathBuf::from(name),
            bytes,
        })
        .collect();
    let write_plan = match amiga_core::ExtractionPlan::new(staged, Vec::new()) {
        Ok(write_plan) => write_plan,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationUnusable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    // The manifest travels under a name derived from the record's, in both
    // shapes: a bare `manifest.json` would be this toolkit claiming a directory
    // it was only asked to write files into.
    let manifest_name = format!("{}.manifest.json", request.file_name);
    let written = if matches!(kind, crate::output::DestinationKind::File) {
        write_plan.commit_file(
            &destination.join(&request.file_name),
            request.policy.permits_replacement(),
            &manifest,
        )
    } else {
        write_plan.commit_into(
            &destination,
            request.policy.permits_replacement(),
            &manifest_name,
            &manifest,
        )
    };
    match written {
        Ok(_) => outcome(Status::Success, diagnostics, result(plan, true)),
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
            ));
            outcome(Status::Error, diagnostics, result(plan, false))
        }
    }
}

/// The range a seed named, as the record reports it.
fn seed_origin(
    bytes: &crate::normalize::SeedBytes,
    resolved_length: u32,
) -> Option<crate::response::SandboxSeedOrigin> {
    match bytes {
        crate::normalize::SeedBytes::Literal(_) => None,
        crate::normalize::SeedBytes::Range {
            source,
            hunk,
            offset,
            length,
        } => Some(crate::response::SandboxSeedOrigin {
            source: source
                .as_ref()
                .map(crate::normalize::NormalizedSource::display_name),
            hunk: *hunk,
            offset: *offset,
            length: *length,
            sha256: None,
        }),
        // The length is the resolved one — an artifact replayed whole reports
        // the file's own length rather than the absence the request spelled.
        crate::normalize::SeedBytes::Artifact {
            source,
            sha256,
            offset,
            length,
        } => Some(crate::response::SandboxSeedOrigin {
            source: Some(source.display_name()),
            hunk: None,
            offset: *offset,
            length: length.unwrap_or(resolved_length),
            sha256: Some(sha256.clone()),
        }),
    }
}

/// The bytes one seed carries, reading a named range where it names one.
///
/// A `hunk` reads that hunk's *loaded* bytes rather than the file, because a
/// hunk offset is what a disassembly shows and converting it to a file offset by
/// hand is exactly the arithmetic this exists to remove. A BSS hunk holds no
/// bytes at all, so a seed naming one is refused rather than reading zeros that
/// are not in the file.
fn resolve_seed(
    seed: &crate::normalize::NormalizedMemorySeed,
    image: &crate::source::ResolvedSource,
    context: &ExecutionContext<'_>,
    index: usize,
) -> Result<Vec<u8>, Diagnostic> {
    use crate::normalize::SeedBytes;
    let at = format!("$.request.arguments.memory_seeds[{index}].from");
    let (source, hunk, offset, length) = match &seed.bytes {
        SeedBytes::Literal(bytes) => return Ok(bytes.clone()),
        SeedBytes::Range {
            source,
            hunk,
            offset,
            length,
        } => (source, *hunk, *offset as usize, *length as usize),
        SeedBytes::Artifact {
            source,
            sha256,
            offset,
            length,
        } => return resolve_artifact(source, sha256, *offset, *length, context, index),
    };

    // Naming no source means the image being run, which is the case this exists
    // for, and which is already in hand rather than resolved a second time.
    let named;
    let bytes: &[u8] = match source {
        None => image.bytes(),
        Some(source) => {
            named = context
                .resolve_source(source, u64::MAX)
                .map_err(|error| Diagnostic::error(source_error_code(&error), error.to_string()))?;
            named.bytes()
        }
    };

    let region: &[u8] = match hunk {
        None => bytes,
        Some(index) => {
            let executable = amiga_hunk::Executable::parse(bytes).map_err(|error| {
                Diagnostic::error(DiagnosticCode::AnalysisHunkUnreadable, error.to_string())
            })?;
            let segment = executable.segment(index).ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!("a memory seed copies from hunk {index}, which the image has not"),
                )
                .at(at.clone())
            })?;
            if segment.bytes.is_empty() {
                return Err(Diagnostic::error(
                    DiagnosticCode::RequestArgumentOutOfRange,
                    format!(
                        "a memory seed copies from hunk {index}, a {} hunk that holds no \
                         bytes in the file; seeding it would copy zeros that are not there",
                        segment.kind
                    ),
                )
                .at(at));
            }
            segment.bytes
        }
    };

    region
        .get(offset..offset.saturating_add(length))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "a memory seed copies [{offset:#x}..+{length:#x}), outside the {} \
                     bytes it names",
                    region.len()
                ),
            )
            .at(at)
        })
}

/// The bytes an artifact seed replays, with its digest checked first.
///
/// **The digest is compared before the range is cut, and both before anything
/// runs.** This is the other end of `memory_exports`: `call --save` writes a
/// decoded runtime table so a later stage can be run against it, and the whole
/// value of that is knowing *which* table. A run seeded from a file that has
/// since been rewritten produces outputs that look like evidence and are not,
/// so a stale artifact is a refused request rather than a completed run.
///
/// The digest covers the whole file, not the replayed range: it is the export's
/// own digest, so a caller pastes the number the earlier record reported rather
/// than computing a new one over a slice.
fn resolve_artifact(
    source: &crate::normalize::NormalizedSource,
    sha256: &str,
    offset: u32,
    length: Option<u32>,
    context: &ExecutionContext<'_>,
    index: usize,
) -> Result<Vec<u8>, Diagnostic> {
    let at = format!("$.request.arguments.memory_seeds[{index}].artifact");
    let resolved = context
        .resolve_source(source, u64::MAX)
        .map_err(|error| Diagnostic::error(source_error_code(&error), error.to_string()))?;
    if resolved.sha256() != sha256 {
        return Err(Diagnostic::error(
            DiagnosticCode::SourceDigestMismatch,
            format!(
                "the artifact {} hashes to {}, not the pinned {sha256}; seeding it would \
                 produce outputs that describe a file this recipe does not name",
                source.display_name(),
                resolved.sha256()
            ),
        )
        .at(at));
    }
    let bytes = resolved.bytes();
    let offset = offset as usize;
    // Absent means the rest of the file, which the digest has just made exact.
    let length = match length {
        Some(length) => length as usize,
        None => bytes.len().saturating_sub(offset),
    };
    if length == 0 {
        return Err(Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            format!(
                "the artifact {} has no bytes at or after {offset:#x}, so the seed would \
                 write nothing",
                source.display_name()
            ),
        )
        .at(at));
    }
    bytes
        .get(offset..offset.saturating_add(length))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "a memory seed replays [{offset:#x}..+{length:#x}) of the artifact {}, \
                     which holds {} bytes",
                    source.display_name(),
                    bytes.len()
                ),
            )
            .at(at)
        })
}

/// Lowercase hex, written here rather than pulled in as a dependency.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// `env.boot.info` — what a floppy's boot block declares about itself.
///
/// A read with nothing to configure. The checksum is reported as *stored*
/// beside whether it verifies rather than as a pass or a fail: a trackloader
/// disk with a deliberately wrong checksum is a normal thing to find, and a
/// result that only said "invalid" would lose the number that recognizes it.
pub(crate) fn boot_info(
    request: &NormalizedBootInfo,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvBootInfo,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let boot = match amiga_adf::Bootblock::parse(source.bytes()) {
        Ok(boot) => boot,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ContainerAdfUnreadable,
                error.to_string(),
            ));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "read_bootblock",
        completed: amiga_adf::Bootblock::SIZE as u64,
        total: Some(amiga_adf::Bootblock::SIZE as u64),
    });

    // A boot block whose checksum does not verify is reported, not refused: the
    // filesystem does not depend on it, and a custom-boot disk that deliberately
    // breaks it is exactly the kind of disk this command exists to identify.
    if !boot.has_valid_checksum() {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ContainerAdfBootChecksumInvalid,
            "the boot block's checksum does not verify",
        ));
    }

    let magic = boot.magic();
    let result = BootInfoResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        tag: amiga_core::latin1(&magic[0..3]),
        flags: boot.flags(),
        is_dos: boot.is_dos(),
        filesystem: boot.filesystem().to_string(),
        stored_checksum: boot.stored_checksum(),
        checksum_valid: boot.has_valid_checksum(),
        root_block: boot.root_block(),
        has_boot_code: boot.has_boot_code(),
        boot_code_bytes: boot.boot_code().len() as u64,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::EnvBootInfo(result)),
    )
}

/// The hunk to run: the one named, or the first CODE hunk.
fn select_hunk(
    executable: &amiga_hunk::Executable,
    requested: Option<u32>,
) -> Result<u32, Diagnostic> {
    if let Some(hunk) = requested {
        return Ok(hunk);
    }
    executable
        .segments
        .iter()
        .find(|segment| segment.kind == amiga_hunk::SegmentKind::Code)
        .map(|segment| segment.index)
        .ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::AnalysisHunkUnreadable,
                "the image holds no CODE hunk to run",
            )
        })
}

/// Apply every relocation whose source hunk is mapped.
fn relocate(
    executable: &amiga_hunk::Executable,
    bases: &BTreeMap<u32, u32>,
    memory: &mut amiga_disasm::Memory,
) -> Result<(), Diagnostic> {
    // Each diagnostic below names the record it is about: its index, its source
    // hunk, the offset inside that hunk, and the base the offset was added to.
    // Without them "a relocation site address overflows" is a sentence a user
    // cannot act on — it distinguishes a wrong `--hunk-base` from an odd image
    // in neither direction, and both are things a reader of a real executable
    // meets.
    for (index, relocation) in executable.relocations.iter().enumerate() {
        let Some(&source_base) = bases.get(&relocation.source_hunk) else {
            continue;
        };
        let record = format!(
            "relocation {index} (hunk {} offset {:#x}, base {source_base:#x})",
            relocation.source_hunk, relocation.source_offset
        );
        let Some(&target_base) = bases.get(&relocation.target_hunk) else {
            return Err(Diagnostic::error(
                DiagnosticCode::RequestArgumentOutOfRange,
                format!(
                    "{record}: relocates into hunk {}, which nothing maps; \
                     name it in hunk_bases",
                    relocation.target_hunk
                ),
            )
            .at("$.request.arguments.hunk_bases"));
        };
        let site = source_base
            .checked_add(relocation.source_offset)
            .ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("{record}: the site address overflows"),
                )
            })?;
        let stored = memory
            .slice(site, 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::SandboxMemoryUnmappable,
                    format!("{record}: site {site:#x} is outside its mapped hunk"),
                )
            })?;
        // Wrapping, and deliberately so — this is the one place in the crate
        // where `checked_*` is the wrong arithmetic. AmigaDOS `LoadSeg` adds
        // the hunk base to the stored longword in 32-bit wrapping arithmetic,
        // so an addend the record spells as `0xfffffffe` means *two bytes below
        // the hunk*, and it is a shape real images use. Refusing it rejected a
        // whole executable over a relocation the platform resolves without
        // complaint — measured on a real game whose BSS hunk carries exactly
        // one such record, and refused at every layout, since the sum overflows
        // for any non-zero base. What bounds the result is the memory bus: an
        // address this produces is only ever reached through `Memory`, which
        // maps it or faults. Arithmetic that disagrees with the loader would
        // not be a bound, it would be a different program.
        let relocated = target_base.wrapping_add(stored);
        memory.write_long(site, relocated).map_err(|error| {
            Diagnostic::error(
                DiagnosticCode::SandboxMemoryUnmappable,
                format!(
                    "{record}: site {site:#x} is not writable; addend {stored:#010x} into hunk \
                     {} at {target_base:#x} resolves to {relocated:#010x}: {error}",
                    relocation.target_hunk
                ),
            )
        })?;
    }
    Ok(())
}

/// The watched ranges a request states, as the executor's watchpoints.
///
/// One function rather than one per caller: `run`, `call`, and the boot trace
/// all watch the same way, and three copies of this mapping would be three
/// places for a new access mode to be forgotten in two of them.
fn watchpoints(watch: &[crate::request::WatchRange]) -> Vec<amiga_disasm::Watchpoint> {
    watch
        .iter()
        .filter_map(|watch| {
            amiga_disasm::Watchpoint::new(
                watch.start,
                watch.length,
                match watch.access {
                    WatchAccess::Read => amiga_disasm::WatchAccess::Read,
                    WatchAccess::Write => amiga_disasm::WatchAccess::Write,
                    WatchAccess::Both => amiga_disasm::WatchAccess::Both,
                },
            )
        })
        .collect()
}

const fn access(access: amiga_disasm::Access) -> crate::response::AccessDirection {
    match access {
        amiga_disasm::Access::Read => crate::response::AccessDirection::Read,
        amiga_disasm::Access::Write => crate::response::AccessDirection::Write,
    }
}

/// The sentence a capture of one exported range carries as its provenance.
///
/// Every clause is a fact the record already states — the pinned source, the
/// hunk and entry, the range, and how the run stopped — so the note and the
/// record cannot come to disagree. It names the operation first because a reader
/// meeting it in a sources document a year later needs to know what kind of
/// thing produced these bytes before anything else.
fn capture_note(
    source: &SourcePin,
    hunk: u32,
    entry: u32,
    export: &crate::request::MemoryExport,
    execution: &amiga_disasm::Execution,
) -> String {
    format!(
        "env.sandbox.call: {:?} — [{:#x}..+{:#x}) of the final memory after running \
         hunk {hunk} entry {entry:#x} of sha256:{} for {} instructions, stopping {}",
        export.name,
        export.address,
        export.length,
        source.sha256,
        execution.steps_executed,
        stop_phrase(&execution.stop),
    )
}

/// How a run ended, as prose for a capture note. Short by design: the record
/// carries the structured stop, and this is the half a person reads.
fn stop_phrase(reason: &amiga_disasm::StopReason) -> String {
    match *reason {
        amiga_disasm::StopReason::Returned => "on return".to_owned(),
        amiga_disasm::StopReason::StepLimit => "at the step limit".to_owned(),
        amiga_disasm::StopReason::Stopped => "on STOP".to_owned(),
        amiga_disasm::StopReason::Fault { fault, site } => {
            format!("on a fault at {:#x} from {site:#x}", fault.address)
        }
        amiga_disasm::StopReason::Trap { vector, site } => {
            format!("on trap {vector} from {site:#x}")
        }
        amiga_disasm::StopReason::Watch { event, site } => {
            format!("on a watched access to {:#x} from {site:#x}", event.address)
        }
        amiga_disasm::StopReason::UnhandledCall { site, offset } => {
            format!("on an unhandled library call {offset} from {site:#x}")
        }
        amiga_disasm::StopReason::Breakpoint { site } => {
            format!("at the breakpoint {site:#x}")
        }
    }
}

fn stop(reason: &amiga_disasm::StopReason) -> SandboxStop {
    match *reason {
        amiga_disasm::StopReason::Returned => SandboxStop::Returned,
        amiga_disasm::StopReason::StepLimit => SandboxStop::StepLimit,
        amiga_disasm::StopReason::Stopped => SandboxStop::Stopped,
        amiga_disasm::StopReason::Fault { fault, site } => SandboxStop::Fault {
            address: fault.address,
            access: access(fault.access),
            size: fault.size,
            site,
        },
        amiga_disasm::StopReason::Trap { vector, site } => SandboxStop::Trap { vector, site },
        amiga_disasm::StopReason::Watch { event, site } => SandboxStop::Watch {
            address: event.address,
            access: access(event.access),
            size: event.size,
            site,
        },
        amiga_disasm::StopReason::UnhandledCall { site, offset } => SandboxStop::UnhandledCall {
            site,
            offset: i32::from(offset),
        },
        amiga_disasm::StopReason::Breakpoint { site } => SandboxStop::Breakpoint { site },
    }
}

const fn registers(file: &amiga_disasm::RegisterFile) -> SandboxRegisters {
    SandboxRegisters {
        d: file.d,
        a: file.a,
        usp: file.usp,
        ssp: file.ssp,
        pc: file.pc,
        sr: file.sr,
    }
}

fn step_row(step: &amiga_disasm::Step) -> SandboxStep {
    SandboxStep {
        index: step.index as u64,
        address: step.address,
        text: step.text.clone(),
        writes: step
            .writes
            .iter()
            .map(|write| SandboxWrite {
                address: write.address,
                size: write.size,
                value: write.value,
            })
            .collect(),
        writes_truncated: step.writes_truncated,
        register_deltas: step
            .register_deltas
            .iter()
            .map(|delta| SandboxRegisterDelta {
                register: delta.register.to_string(),
                before: delta.before,
                after: delta.after,
            })
            .collect(),
        watch_hits: step
            .watch_events
            .iter()
            .map(|event| SandboxAccess {
                address: event.address,
                access: access(event.access),
                size: event.size,
                before: event.before,
                after: event.after,
            })
            .collect(),
        trap: step.trap,
    }
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
