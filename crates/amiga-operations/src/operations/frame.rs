//! `env.frame.capture` — the frame the display would have shown, not the bytes
//! a range happens to hold.
//!
//! The run is an ordinary `env.sandbox.call` with the chip page attached; what
//! this adds is what happens *after* it stops. The chip page's final register
//! state and the memory the run left are handed to `amiga_hw::display`, which
//! resolves the bitplane pointers, the plane count, the display window, the data
//! fetch, the modulos and the palette — and follows the Copper list, so a
//! pointer or palette the program swaps part-way down the frame appears as a
//! band rather than being applied to all of the picture or to none of it.
//!
//! ## Why the register state and not the write log
//!
//! The page's write log is a bounded prefix. A display rebuilt by replaying a
//! prefix would be a display the run never had, and a long initialization is
//! exactly the case where the prefix runs out. `amiga_env::ChipRegisters` is 256
//! words whatever the run does, and it is what this reads.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::BoundedSink;
use crate::normalize::{NormalizedFrameCapture, NormalizedFrameCaptureExport, NormalizedMode};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    FrameCaptureExportResult, FrameCaptureResult, FrameInterval, FrameRegisters, OperationOutcome,
    OperationResult,
};

/// The `$DFF000` offset of `COP1LC`, whose longword is the Copper list the
/// chipset fetches from at the top of a frame.
const COP1LCH: u16 = 0x080;

/// Copper instructions decoded from the list a program points the chipset at.
///
/// A list is a few hundred instructions in practice; the cap exists because
/// `COP1LC` may point anywhere at all in a half-initialized run, and a decoder
/// walking whatever it finds should stop rather than read a megabyte of data as
/// a program.
const MAXIMUM_COPPER_INSTRUCTIONS: usize = 4096;

/// What one capture produced: the record, two images, and its source plane.
type Captured = (FrameCaptureResult, Vec<(String, Vec<u8>)>);

pub(crate) fn capture(
    request: &NormalizedFrameCapture,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvFrameCapture,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match run_capture(request, context, &mut diagnostics, events, "frame.png") {
        Ok((frame, _)) => outcome(
            Status::Success,
            diagnostics,
            Some(OperationResult::EnvFrameCapture(frame)),
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

/// Run the recipe, then reconstruct the display it left.
fn run_capture(
    request: &NormalizedFrameCapture,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
    file_name: &str,
) -> Result<Captured, Diagnostic> {
    let (record, memory, registers) =
        super::sandbox::call_with_chip_state(&request.call, context, diagnostics, events)?;

    let (display, configured) =
        amiga_hw::DisplayRegisters::from_page(|offset| registers.borrow().value(offset));

    // The Copper list the chipset was pointed at, decoded out of the memory the
    // run left. Read through the same memory the display is fetched from, so a
    // list the program built at run time is the one that is followed.
    let copper_base = pointer(&registers, COP1LCH);
    let copper = decode_copper(&memory, copper_base);

    let read = |address: u32, length: usize| memory.slice(address, length).map(<[u8]>::to_vec);
    let frame = amiga_hw::reconstruct(&display, configured, &copper, &read, request.maximum_pixels)
        .map_err(|error| {
            Diagnostic::error(DiagnosticCode::GraphicsPlanarUndecodable, error.to_string())
                .at("$.result.frame")
        })?;

    for warning in &frame.warnings {
        diagnostics.push(warning_of(warning));
    }

    let indices_sha256 = amiga_core::sha256(&frame.indices);
    let pixel_sources = frame
        .pixel_sources
        .iter()
        .map(|source| source.code())
        .collect::<Vec<_>>();
    let pixel_sources_sha256 = amiga_core::sha256(&pixel_sources);
    let rgba_sha256 = amiga_core::sha256(&frame.rgba);
    let indexed = amiga_hw::encode_indexed_png(
        &amiga_hw::IndexedImage {
            width: frame.width,
            height: frame.height,
            planes: frame.planes,
            pixels: frame.indices.clone(),
        },
        &palette_bytes(&frame),
        None,
    )
    .map_err(|error| Diagnostic::error(DiagnosticCode::GraphicsEncodeFailed, error.to_string()))?;
    let rgba =
        amiga_hw::encode_rgba_png(frame.width, frame.height, &frame.rgba).map_err(|error| {
            Diagnostic::error(DiagnosticCode::GraphicsEncodeFailed, error.to_string())
        })?;

    let result = FrameCaptureResult {
        source: record.source,
        hunk: record.hunk,
        entry: record.entry,
        stop: record.stop,
        steps_executed: record.steps_executed,
        width: frame.width as u64,
        height: frame.height as u64,
        planes: frame.planes,
        indices: hex(&frame.indices),
        indices_sha256,
        pixel_sources: hex(&pixel_sources),
        pixel_sources_sha256,
        rgba_sha256,
        intervals: frame
            .intervals
            .iter()
            .map(|interval| FrameInterval {
                first_line: interval.first_line as u64,
                last_line: interval.last_line as u64,
                first_raster_line: interval.first_raster_line as u64,
                bitplanes: interval.bitplanes[..usize::from(frame.planes)].to_vec(),
                sprites: interval.sprites.to_vec(),
                bplcon2: interval.bplcon2,
                palette: interval.palette.to_vec(),
            })
            .collect(),
        registers: FrameRegisters {
            bplcon0: display.bplcon0,
            bplcon1: display.bplcon1,
            bplcon2: display.bplcon2,
            diwstrt: display.diwstrt,
            diwstop: display.diwstop,
            ddfstrt: display.ddfstrt,
            ddfstop: display.ddfstop,
            bpl1mod: i32::from(display.bpl1mod),
            bpl2mod: i32::from(display.bpl2mod),
            dmacon: display.dmacon,
            sprite_pointers: display.sprites,
        },
    };
    // The indexed image and the RGBA one, because the two answer different
    // questions: the indices are what the program wrote, and the colours are
    // only what one palette made of them. Neither is derivable from the other
    // once a Copper list has changed the palette part-way down the frame.
    let images = vec![
        (file_name.to_owned(), indexed),
        (format!("{file_name}.rgba.png"), rgba),
        (format!("{file_name}.pixel-sources.bin"), pixel_sources),
    ];
    Ok((result, images))
}

/// The palette an indexed PNG is written with.
///
/// The **first** interval's, because a PNG carries one palette and the frame may
/// have had several. The RGBA image beside it is the one that shows every band
/// under the palette that was in force there, and the intervals in the record
/// say which was which — so nothing is lost, and the indexed image is not
/// quietly recoloured.
fn palette_bytes(frame: &amiga_hw::Frame) -> Vec<u8> {
    let palette = frame
        .intervals
        .first()
        .map_or([0_u16; 32], |interval| interval.palette);
    palette
        .iter()
        .flat_map(|colour| amiga_hw::rgb4_to_rgb8(*colour))
        .collect()
}

/// The longword at a register pair, or `None` when nothing wrote it.
fn pointer(
    registers: &std::rc::Rc<std::cell::RefCell<amiga_env::ChipRegisters>>,
    high: u16,
) -> Option<u32> {
    let registers = registers.borrow();
    let top = registers.value(high)?;
    let bottom = registers.value(high + 2)?;
    Some((u32::from(top) << 16) | u32::from(bottom))
}

/// Decode the Copper list at `base` out of the memory the run left.
///
/// An absent or unmapped pointer is an empty list rather than a refusal: a
/// capture taken before the program pointed the Copper anywhere is an ordinary
/// case, and it means the frame is whatever the registers alone select.
fn decode_copper(
    memory: &amiga_disasm::Memory,
    base: Option<u32>,
) -> Vec<amiga_hw::CopperInstruction> {
    let Some(base) = base else {
        return Vec::new();
    };
    // Read a bounded window and decode inside it, so a pointer into the middle
    // of a large mapping cannot turn into a walk over the whole of it.
    let window = MAXIMUM_COPPER_INSTRUCTIONS * 4;
    let mut bytes = None;
    for length in [window, window / 2, window / 4, 64] {
        if let Some(slice) = memory.slice(base, length) {
            bytes = Some(slice.to_vec());
            break;
        }
    }
    let Some(bytes) = bytes else {
        return Vec::new();
    };
    let mut decoded = amiga_hw::copper::decode(&bytes, 0);
    decoded.truncate(MAXIMUM_COPPER_INSTRUCTIONS);
    // The offsets are relative to the window; a reader comparing them against a
    // Copper listing wants the addresses the program uses.
    for instruction in &mut decoded {
        instruction.offset = instruction.offset.wrapping_add(base);
    }
    decoded
}

/// One display warning, as a diagnostic.
fn warning_of(warning: &amiga_hw::DisplayWarning) -> Diagnostic {
    match warning {
        amiga_hw::DisplayWarning::DmaOff { dmacon } => Diagnostic::warning(
            DiagnosticCode::SandboxBlitterDmaAssumed,
            format!(
                "DMACON is {dmacon:#06x}: bitplane or master DMA is off, so the hardware \
                 would have shown nothing. The frame is what the pointers select, not what \
                 a screen held."
            ),
        ),
        amiga_hw::DisplayWarning::CopperChangedDisplay { changes } => Diagnostic::warning(
            DiagnosticCode::GraphicsPlanarUndecodable,
            format!(
                "the Copper changed a display register {changes} time(s) part-way down the \
                 frame, so the picture is several bands; `intervals` says which pointers \
                 and palette produced each"
            ),
        ),
        amiga_hw::DisplayWarning::CopperSkipped { at } => Diagnostic::warning(
            DiagnosticCode::GraphicsPlanarUndecodable,
            format!(
                "Copper instruction {at} is a SKIP, which needs a comparison against the \
                 live beam that a still frame does not have; the registers below it are the \
                 state before it"
            ),
        ),
        amiga_hw::DisplayWarning::ScrollFetchedExtraWord { pixels } => Diagnostic::warning(
            DiagnosticCode::GraphicsPlanarUndecodable,
            format!(
                "BPLCON1 delays the playfield by {pixels} pixel(s), so every row's leading \
                 pixels were taken from the word before it; the frame reads two bytes below \
                 each bitplane pointer, which a --map that covers only the window does not \
                 hold"
            ),
        ),
        amiga_hw::DisplayWarning::SpriteDmaOff { dmacon } => Diagnostic::warning(
            DiagnosticCode::GraphicsPlanarUndecodable,
            format!(
                "DMACON is {dmacon:#06x}: sprite pointers are configured while sprite or \
                 master DMA is off, so the frame leaves those stale pointers out"
            ),
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn capture_export(
    request: &NormalizedFrameCaptureExport,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::EnvFrameCaptureExport,
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

    let (frame, images) = match run_capture(
        &request.capture,
        context,
        &mut diagnostics,
        events,
        &request.file_name,
    ) {
        Ok(captured) => captured,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };

    let files: Vec<PlannedOutput> = images
        .iter()
        .map(|(name, bytes)| PlannedOutput {
            path: name.clone(),
            size: bytes.len() as u64,
            sha256: amiga_core::sha256(bytes),
        })
        .collect();
    // Several files, so the wider claim: these files, and still nothing else in a
    // directory this toolkit does not own.
    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::DirectoryContents,
        request.policy,
        files,
        Vec::new(),
    );
    let result = |plan: WritePlan, committed| {
        Some(OperationResult::EnvFrameCaptureExport(
            FrameCaptureExportResult {
                frame: frame.clone(),
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
                "the approved plan {approved} no longer describes this frame, which now \
                 has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    // The recipe, not just the picture: a frame is only evidence beside the run
    // that drew it and the registers that selected it.
    let manifest = match serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "operation": OperationName::EnvFrameCaptureExport.as_str(),
        "source": { "size": frame.source.size, "sha256": frame.source.sha256 },
        "hunk": frame.hunk,
        "entry": frame.entry,
        "stop": frame.stop,
        "width": frame.width,
        "height": frame.height,
        "planes": frame.planes,
        "indices_sha256": frame.indices_sha256,
        "pixel_sources_sha256": frame.pixel_sources_sha256,
        "rgba_sha256": frame.rgba_sha256,
        "registers": frame.registers,
        "intervals": frame.intervals,
        "normalized_request_sha256": digest,
        "files": plan
            .files
            .iter()
            .map(|file| serde_json::json!({ "path": file.path, "sha256": file.sha256 }))
            .collect::<Vec<_>>(),
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
    let staged = images
        .into_iter()
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
    let manifest_name = format!("{}.manifest.json", request.file_name);
    match write_plan.commit_into(
        &destination,
        request.policy.permits_replacement(),
        &manifest_name,
        &manifest,
    ) {
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
