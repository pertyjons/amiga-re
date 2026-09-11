//! `frame capture` — the picture the display would have shown, not a byte range.
//!
//! An adapter over `env.frame.capture` and its export: what stays here is the
//! spelling of a memory map on a command line, and the rendering of the bands
//! the reconstruction found.

use super::*;

/// Run a custom-chip sandbox and reconstruct the frame it left.
pub(crate) fn frame_capture(
    config_override: Option<&Path>,
    target: &ExecArgs,
    watch: &WatchArgs,
    options: &FrameArgs,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(&target.executable)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;

    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = target.base.resolve(config.as_ref());
    let (load_origin, entry_offset) = match base {
        Some(base) => {
            let entry = target.entry.unwrap_or_else(|| base.default_entry());
            let offset = entry
                .checked_sub(base.origin)
                .with_context(|| format!("entry {entry:#x} is below the mapped origin"))?;
            (base.origin, offset)
        }
        None => (0x1000, target.entry.unwrap_or(0)),
    };

    let mut run = amiga_operations::SandboxRunArguments::new(source_name.as_str())
        .with_hunk(target.hunk)
        .at_origin(load_origin)
        .with_entry_offset(entry_offset)
        .with_maximum_steps(target.max_steps);
    run.stack = Some(amiga_operations::StackRegion {
        base: target.stack_base,
        size: target.stack_size,
    });
    run.stop_on_watch = watch.watch_stop;
    run.watch = watch
        .watch
        .iter()
        .map(|spec| parse_watchpoint(spec))
        .collect::<Result<Vec<_>>>()?;
    for spec in &target.hunk_base {
        let (hunk, address) = parse_hunk_base(spec)?;
        run.hunk_bases
            .push(amiga_operations::HunkBase { hunk, address });
    }
    let (data, address) = register_seeds(&target.reg)?;
    run.data_registers = Some(data);
    run.address_registers = Some(address);

    let mut call = amiga_operations::SandboxCallArguments::new(run)
        // Always: a frame is reconstructed from the chip page's registers, and
        // a capture without one has nothing to reconstruct from. That is why
        // there is no flag to turn it off here as there is on `call`.
        .with_custom_chips(amiga_operations::CustomChips::default());
    for spec in &options.map {
        let (address, size) = parse_map_spec(spec)?;
        call.mapped_regions.push(amiga_operations::MappedRegion {
            address,
            size: u32::try_from(size).context("--map size does not fit an address")?,
        });
    }
    for spec in &options.poke {
        let (address, bytes) = parse_poke_spec(spec)?;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in &bytes {
            let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
        }
        call.memory_seeds
            .push(amiga_operations::MemorySeed::hex(address, hex));
    }

    let mut capture = amiga_operations::FrameCaptureArguments::new(call);
    capture.until_raster_line = options.until_line;

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let frame = match options.output.as_deref() {
        None => {
            let context =
                amiga_operations::ExecutionContext::new(&sources).with_limits(sandbox_limits());
            let outcome = amiga_operations::Router::execute(
                &amiga_operations::RequestEnvelope::read(
                    amiga_operations::OperationRequestDocument::EnvFrameCapture(capture),
                ),
                &context,
            );
            fail_on_errors(&outcome)
                .with_context(|| format!("failed to capture a frame of {}", resolved.display()))?;
            let frame = outcome
                .env_frame_capture()
                .context("the capture returned no result")?
                .clone();
            row!(out, "{}", serde_json::to_string_pretty(&frame)?);
            out.print()?;
            print_warnings(&outcome);
            frame
        }
        Some(path) => {
            let (output_base, destination) = split_destination_dir(path)?;
            let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
            let context = amiga_operations::ExecutionContext::new(&sources)
                .with_destinations(&destinations)
                .with_limits(sandbox_limits());
            let committed = commit_reviewed(
                amiga_operations::OperationRequestDocument::EnvFrameCaptureExport(
                    amiga_operations::FrameCaptureExportArguments::new(
                        capture,
                        destination.as_str(),
                    )
                    .with_policy(output_policy(options.force)),
                ),
                &context,
                "frame",
                |outcome| {
                    outcome
                        .env_frame_capture_export()
                        .map(|export| export.plan.plan_sha256.clone())
                },
            )?;
            let export = committed
                .env_frame_capture_export()
                .context("the frame export returned no result")?;
            eprintln!(
                "Wrote {} file(s) to {}",
                export.plan.files.len(),
                path.display()
            );
            eprintln!("Plan SHA-256: {}", export.plan.plan_sha256);
            print_warnings(&committed);
            export.frame.clone()
        }
    };

    // On stderr, so the JSON on stdout stays pipeable. The bands are what a
    // reader of a *frame* needs and a picture cannot show: which buffer each
    // came from is the whole answer to "which of the two was on screen".
    eprintln!(
        "{}x{} at {} bitplane(s), {} band(s)",
        frame.width,
        frame.height,
        frame.planes,
        frame.intervals.len()
    );
    for interval in &frame.intervals {
        let pointers: Vec<String> = interval
            .bitplanes
            .iter()
            .map(|address| format!("{address:#010x}"))
            .collect();
        eprintln!(
            "  lines {}..={} (raster {}): {}",
            interval.first_line,
            interval.last_line,
            interval.first_raster_line,
            pointers.join(" ")
        );
    }
    Ok(())
}
