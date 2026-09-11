use super::*;

// --- run / trace -----------------------------------------------------------

/// The default load address for a relocatable hunk with no fixed base, chosen so
/// low memory (e.g. ExecBase at absolute 4) stays unmapped and faults visibly.
const DEFAULT_SANDBOX_LOAD: u32 = 0x1000;

/// Run `env.sandbox.run` through the shared router and render its result.
///
/// The operation owns the memory map, budget, and watched ranges. This adapter supplies
/// the configured load origin, reads fd tables for naming unhandled library vectors,
/// and renders results.
pub(crate) fn execute_routine(
    config_override: Option<&Path>,
    target: &ExecArgs,
    watch: &WatchArgs,
    trace: bool,
    watch_only: bool,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(&target.executable)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;

    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = target.base.resolve(config.as_ref());
    // The config's `[base]` is the frontend's: it turns an absolute entry the
    // user typed into the offset the operation takes.
    let (load_origin, entry_offset) = match base {
        Some(base) => {
            let entry = target.entry.unwrap_or_else(|| base.default_entry());
            let offset = entry
                .checked_sub(base.origin)
                .with_context(|| format!("entry {entry:#x} is below the mapped origin"))?;
            (base.origin, offset)
        }
        None => (DEFAULT_SANDBOX_LOAD, target.entry.unwrap_or(0)),
    };

    let mut arguments = amiga_operations::SandboxRunArguments::new(source_name.as_str())
        .with_hunk(target.hunk)
        .at_origin(load_origin)
        .with_entry_offset(entry_offset)
        .with_maximum_steps(target.max_steps);
    arguments.stack = Some(amiga_operations::StackRegion {
        base: target.stack_base,
        size: target.stack_size,
    });
    arguments.trace = trace;
    arguments.stop_on_watch = watch.watch_stop;
    arguments.watch = watch
        .watch
        .iter()
        .map(|spec| parse_watchpoint(spec))
        .collect::<Result<Vec<_>>>()?;
    for spec in &target.hunk_base {
        let (hunk, address) = parse_hunk_base(spec)?;
        arguments
            .hunk_bases
            .push(amiga_operations::HunkBase { hunk, address });
    }
    let (data, address) = register_seeds(&target.reg)?;
    arguments.data_registers = Some(data);
    arguments.address_registers = Some(address);

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let context = amiga_operations::ExecutionContext::new(&sources).with_limits(sandbox_limits());
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::EnvSandboxRun(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to run {}", resolved.display()))?;
    let run = outcome
        .env_sandbox_run()
        .context("the sandbox operation returned no result")?;

    let fd_names = config_fd_names(config_override)?;
    row!(
        out,
        "; MC68000 sandbox execution: {}",
        target.executable.display()
    );
    row!(out, "; Source SHA-256: {}", run.source.sha256);
    row!(
        out,
        "; Hunk {} (CODE, {:#x} bytes) mapped at {:#x}; entry {:#x}; stack [{:#x}..{:#x})",
        run.hunk,
        run.allocation_bytes,
        run.load_origin,
        run.entry,
        run.stack_base,
        run.stack_top,
    );
    row!(out, ";");
    if trace || !watch.watch.is_empty() {
        print_trace(&mut out, &run.trace, watch_only);
        if run.trace_truncated {
            row!(
                out,
                "; … {} of {} trace row(s) shown",
                run.trace.len(),
                run.trace_total
            );
        }
    }
    print_execution_summary(&mut out, run, &fd_names);
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Parse one `ACCESS:ADDR[:LENGTH]` watch specification.
///
/// The command line parses the spelling; the operation validates the resulting range
/// with the same checks used for typed requests.
pub(crate) fn parse_watchpoint(spec: &str) -> Result<amiga_operations::WatchRange> {
    let mut fields = spec.split(':');
    let access = match fields.next() {
        Some("r") => amiga_operations::WatchAccess::Read,
        Some("w") => amiga_operations::WatchAccess::Write,
        Some("rw" | "wr") => amiga_operations::WatchAccess::Both,
        _ => bail!("--watch expects ACCESS:ADDR[:LENGTH], with ACCESS r, w, or rw"),
    };
    let address_text = fields.next().context("--watch is missing its address")?;
    let start = amiga_core::parse_u32(address_text)
        .map_err(|message| anyhow::anyhow!("--watch address: {message}"))?;
    let length = match fields.next() {
        Some(text) => amiga_core::parse_u32(text)
            .map_err(|message| anyhow::anyhow!("--watch length: {message}"))?,
        None => 1,
    };
    if fields.next().is_some() {
        bail!("--watch expects ACCESS:ADDR[:LENGTH], got {spec:?}");
    }
    Ok(amiga_operations::WatchRange {
        start,
        length,
        access,
    })
}

/// Turn `--reg NAME=VALUE` seeds into the two register arrays a request carries.
pub(crate) fn register_seeds(seeds: &[String]) -> Result<([u32; 8], [u32; 7])> {
    let mut data = [0_u32; 8];
    let mut address = [0_u32; 7];
    for seed in seeds {
        let (name, value) = seed
            .split_once('=')
            .with_context(|| format!("--reg expects NAME=VALUE, got {seed:?}"))?;
        let value = amiga_core::parse_u32(value.trim())
            .map_err(|message| anyhow::anyhow!("--reg {name}: {message}"))?;
        let name = name.trim().to_ascii_lowercase();
        let index: usize = name
            .get(1..)
            .and_then(|digits| digits.parse().ok())
            .with_context(|| format!("--reg names no register: {name:?}"))?;
        match name.as_bytes().first() {
            Some(b'd') if index < 8 => data[index] = value,
            Some(b'a') if index < 7 => address[index] = value,
            _ => bail!("--reg accepts d0-d7 and a0-a6, got {name:?}"),
        }
    }
    Ok((data, address))
}

pub(crate) fn parse_hunk_base(spec: &str) -> Result<(u32, u32)> {
    let (hunk, address) = spec
        .split_once('=')
        .with_context(|| format!("--hunk-base expects HUNK=ADDR, got {spec:?}"))?;
    let hunk = amiga_core::parse_u32(hunk.trim())
        .map_err(|message| anyhow::anyhow!("--hunk-base hunk: {message}"))?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--hunk-base address: {message}"))?;
    Ok((hunk, address))
}

pub(crate) fn print_trace(
    out: &mut Document,
    rows: &[amiga_operations::SandboxStep],
    watch_only: bool,
) {
    for step in rows {
        if watch_only && step.watch_hits.is_empty() {
            continue;
        }
        let deltas = step
            .register_deltas
            .iter()
            .map(|delta| format!("{}={:#x}", delta.register, delta.after))
            .collect::<Vec<_>>()
            .join(" ");
        let writes = step
            .writes
            .iter()
            .map(|write| {
                format!(
                    "[{:#x}].{}={:#x}",
                    write.address,
                    size_suffix(write.size),
                    write.value
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let watched = step
            .watch_hits
            .iter()
            .map(|event| {
                format!(
                    "{}[{:#x}].{}:{:#x}->{:#x}",
                    event.access.as_str().to_uppercase(),
                    event.address,
                    size_suffix(event.size),
                    event.before,
                    event.after
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let mut annotation = String::new();
        if !deltas.is_empty() {
            annotation.push_str(&deltas);
        }
        if !writes.is_empty() {
            if !annotation.is_empty() {
                annotation.push_str("  ");
            }
            let _ = write!(annotation, "W {writes}");
        }
        if !watched.is_empty() {
            if !annotation.is_empty() {
                annotation.push_str("  ");
            }
            let _ = write!(annotation, "WATCH {watched}");
        }
        if annotation.is_empty() {
            row!(out, "{:08x}  {}", step.address, step.text);
        } else {
            row!(
                out,
                "{:08x}  {:<32} ; {annotation}",
                step.address,
                step.text
            );
        }
    }
}

/// Print the stop reason, final register file, and memory writes.
pub(crate) fn print_execution_summary(
    out: &mut Document,
    run: &amiga_operations::SandboxRunResult,
    fd_names: &FdNames,
) {
    let registers = &run.registers;
    row!(out, ";");
    row!(out, "; {}", stop_reason_text(&run.stop, fd_names));
    row!(out, "; {} instruction(s) executed", run.steps_executed);
    for row in 0..2 {
        let cells = (0..4)
            .map(|column| {
                let index = row * 4 + column;
                format!("D{index}={:#010x}", registers.d[index])
            })
            .collect::<Vec<_>>()
            .join("  ");
        row!(out, "; {cells}");
    }
    for row in 0..2 {
        let cells = (0..4)
            .filter_map(|column| {
                let index = row * 4 + column;
                (index < 7).then(|| format!("A{index}={:#010x}", registers.a[index]))
            })
            .collect::<Vec<_>>()
            .join("  ");
        row!(out, "; {cells}");
    }
    row!(
        out,
        "; PC={:#010x}  SP={:#010x}  SR={:#06x}",
        registers.pc,
        registers.ssp,
        registers.sr
    );

    row!(out, "; {} memory write(s)", run.writes_total);
    const WRITE_CAP: usize = 32;
    for write in run.writes.iter().take(WRITE_CAP) {
        row!(
            out,
            ";   [{:#x}].{} = {:#x}",
            write.address,
            size_suffix(write.size),
            write.value
        );
    }
    if run.writes_total as usize > WRITE_CAP {
        row!(
            out,
            ";   … and {} more",
            run.writes_total as usize - WRITE_CAP
        );
    }
}

pub(crate) fn size_suffix(size: u8) -> char {
    match size {
        1 => 'b',
        2 => 'w',
        _ => 'l',
    }
}

/// Render one stop reason for a person, naming a library vector where the
/// project's fd tables can.
///
/// The naming is deliberately here rather than in the operation: the tables are
/// this frontend's configuration, and an operation that read them would be
/// reaching into a caller's setup to describe its own answer.
pub(crate) fn stop_reason_text(stop: &amiga_operations::SandboxStop, fd_names: &FdNames) -> String {
    match *stop {
        amiga_operations::SandboxStop::Returned => {
            "stopped: routine returned (RTS to marker)".to_owned()
        }
        amiga_operations::SandboxStop::StepLimit => {
            "stopped: step limit reached before returning".to_owned()
        }
        amiga_operations::SandboxStop::Stopped => "stopped: STOP instruction".to_owned(),
        amiga_operations::SandboxStop::Fault {
            address,
            access,
            size,
            site,
        } => format!(
            "stopped: unmapped {access} of {size} byte(s) at {address:#x} \
             (instruction {site:#x})"
        ),
        amiga_operations::SandboxStop::Trap { vector, site } => format!(
            "stopped: exception vector {vector} ({}) at instruction {site:#x}",
            vector_name(vector)
        ),
        amiga_operations::SandboxStop::Watch {
            address,
            access,
            size,
            site,
        } => format!(
            "stopped: watched {access} of {size} byte(s) at {address:#x} \
             (instruction {site:#x})"
        ),
        amiga_operations::SandboxStop::UnhandledCall { site, offset } => {
            let named = i16::try_from(offset)
                .ok()
                .and_then(|offset| lvo_display_name(fd_names, &amiga_disasm::Library::Exec, offset))
                .map(|name| format!(" (exec.library/{name})"))
                .unwrap_or_default();
            format!("stopped: unhandled OS call (vector {offset:+#x}{named}) at {site:#x}")
        }
        amiga_operations::SandboxStop::Breakpoint { site } => {
            format!("stopped: reached the breakpoint {site:#x}, which has not executed")
        }
    }
}

/// A short name for a common MC68000 exception vector.
pub(crate) fn vector_name(vector: u8) -> &'static str {
    match vector {
        2 => "bus error",
        3 => "address error",
        4 => "illegal instruction",
        5 => "zero divide",
        6 => "CHK",
        7 => "TRAPV",
        8 => "privilege violation",
        9 => "trace",
        10 => "line-A",
        11 => "line-F",
        32..=47 => "TRAP",
        _ => "exception",
    }
}

// --- call / golden-trace ---------------------------------------------------

/// Run `env.sandbox.call.export` — or its read half when no `--output` is
/// given — through the shared router.
///
/// The golden record's `outcome` used to be prose rendered through this
/// frontend's fd tables, so the same routine on the same bytes produced a
/// different record depending on what `amiga-re.toml` said. The record carries
/// the structured stop reason now; the prose is printed here, where the tables
/// are, instead of being baked into an artifact meant for diffing.
pub(crate) fn call_routine(
    config_override: Option<&Path>,
    target: &ExecArgs,
    watch: &WatchArgs,
    recipe: &CallArgs,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(&target.executable)?;
    // The image and every artifact seed are named against one root, and which
    // root that is depends on where they all sit — so it is decided once, here,
    // before anything is named.
    let CallSources {
        base: source_base,
        image: source_name,
        seeds: artifact_seeds,
    } = resolve_call_sources(&resolved, &recipe.poke_artifact)?;

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
        None => (DEFAULT_SANDBOX_LOAD, target.entry.unwrap_or(0)),
    };

    // The reviewed contract of whatever is being called, if a project states
    // one. Read before the request is built, because it decides both whether
    // this run is a template and whether the arguments are complete.
    let signature = signature_at(&resolved, target.hunk, u64::from(entry_offset));
    if recipe.template {
        let signature = signature.as_ref().with_context(|| {
            format!(
                "no project annotates hunk {} offset {entry_offset:#x} of {} with a \
                 callable type, so there is no signature to build a template from",
                target.hunk,
                resolved.display()
            )
        })?;
        print_call_template(&mut out, &target.executable, signature)?;
        return out.print();
    }
    if let Some(signature) = &signature
        && !recipe.partial_arguments
    {
        refuse_unsupplied_arguments(signature, &target.reg, recipe.args.len())?;
    }

    let mut run = amiga_operations::SandboxRunArguments::new(source_name.as_str())
        .with_hunk(target.hunk)
        .at_origin(load_origin)
        .with_entry_offset(entry_offset)
        .with_maximum_steps(target.max_steps);
    run.stack = Some(amiga_operations::StackRegion {
        base: target.stack_base,
        size: target.stack_size,
    });
    for spec in &target.hunk_base {
        let (hunk, address) = parse_hunk_base(spec)?;
        run.hunk_bases
            .push(amiga_operations::HunkBase { hunk, address });
    }
    let (data, address) = register_seeds(&target.reg)?;
    run.data_registers = Some(data);
    run.address_registers = Some(address);
    run.trace = recipe.trace;
    run.stop_on_watch = watch.watch_stop;
    run.watch = watch
        .watch
        .iter()
        .map(|spec| parse_watchpoint(spec))
        .collect::<Result<Vec<_>>>()?;

    let call = amiga_operations::SandboxCallArguments::new(run)
        .with_stack_arguments(recipe.args.clone())
        .with_mapped_regions(
            recipe
                .map
                .iter()
                .map(|spec| {
                    parse_map_spec(spec).and_then(|(address, size)| {
                        Ok(amiga_operations::MappedRegion {
                            address,
                            size: u32::try_from(size).context("--map region is too large")?,
                        })
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        )
        .with_memory_seeds(
            recipe
                .poke
                .iter()
                .map(|spec| {
                    parse_poke_spec(spec).map(|(address, data)| {
                        amiga_operations::MemorySeed::hex(address, hex::encode(data))
                    })
                })
                .chain(
                    recipe
                        .poke_from
                        .iter()
                        .map(|spec| parse_poke_from_spec(spec)),
                )
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .chain(artifact_seeds)
                .collect::<Vec<_>>(),
        )
        .with_interrupts(
            recipe
                .interrupt
                .iter()
                .map(|spec| parse_interrupt_spec(spec))
                .collect::<Result<Vec<_>>>()?,
        )
        .with_memory_exports(
            recipe
                .save
                .iter()
                .map(|spec| parse_save_spec(spec))
                .collect::<Result<Vec<_>>>()?,
        );
    // `--custom-chips` alone is an emulating blitter with the defaults, which is
    // the same thing `custom_chips: {}` means through the operation.
    // `--blitter-dma` without it is refused by clap rather than silently
    // ignored: a flag that changes nothing is worse than a missing one.
    let call = if recipe.custom_chips {
        call.with_custom_chips(amiga_operations::CustomChips {
            chipset: None,
            blitter: recipe
                .blitter_dma
                .map(|dma| amiga_operations::BlitterOptions {
                    mode: None,
                    dma: Some(match dma {
                        crate::BlitterDmaArg::Assume => amiga_operations::BlitterDma::AssumeEnabled,
                        crate::BlitterDmaArg::Require => {
                            amiga_operations::BlitterDma::RequireEnabled
                        }
                    }),
                    maximum_words: None,
                }),
        })
    } else {
        call
    };

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let fd_names = config_fd_names(config_override)?;

    // `--save` names a range; what happens to it depends on which of the two
    // modes asked. Neither means the range would be named and then dropped, so
    // it is refused here rather than by `clap`: the flag is legal with either,
    // and `requires` cannot say "one of these two".
    if !recipe.save.is_empty()
        && recipe.output.is_none()
        && recipe.cases.is_none()
        && recipe.steps.is_none()
    {
        bail!(
            "--save needs --output to write the bytes, or --cases or --steps to report \
             their digests"
        );
    }
    // `--max-total-steps` bounds a sweep or a timeline and means nothing to a
    // single call. Refused here rather than by `clap`, which cannot say "one of
    // these two".
    if recipe.max_total_steps.is_some() && recipe.cases.is_none() && recipe.steps.is_none() {
        bail!("--max-total-steps bounds a sweep or a timeline; it needs --cases or --steps");
    }

    // A matrix or a timeline returns before any of the single-call reporting
    // below: neither has one record to warn about, and a run that also printed
    // "the routine did not return cleanly" would be describing whichever case
    // or step happened to be last.
    if let Some(path) = recipe.cases.as_deref() {
        return call_matrix(call, path, recipe, &sources, &resolved, out);
    }
    if let Some(path) = recipe.steps.as_deref() {
        return call_timeline(call, path, recipe, &sources, &resolved, out);
    }
    if let Some(seed) = recipe.slice.as_deref() {
        return call_slice(call, seed, recipe, &sources, &resolved, out);
    }

    let record = match recipe.output.as_deref() {
        None => {
            let context =
                amiga_operations::ExecutionContext::new(&sources).with_limits(sandbox_limits());
            let outcome = amiga_operations::Router::execute(
                &amiga_operations::RequestEnvelope::read(
                    amiga_operations::OperationRequestDocument::EnvSandboxCall(call),
                ),
                &context,
            );
            fail_on_errors(&outcome)
                .with_context(|| format!("failed to call into {}", resolved.display()))?;
            let record = outcome
                .env_sandbox_call()
                .context("the call operation returned no result")?
                .clone();
            row!(out, "{}", serde_json::to_string_pretty(&record)?);
            print_warnings(&outcome);
            record
        }
        Some(path) => {
            let (output_base, destination, file_name) = split_destination_file(path)?;
            let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
            let context = amiga_operations::ExecutionContext::new(&sources)
                .with_destinations(&destinations)
                .with_limits(sandbox_limits());
            let committed = commit_reviewed(
                amiga_operations::OperationRequestDocument::EnvSandboxCallExport(
                    amiga_operations::SandboxCallExportArguments::new(call, destination.as_str())
                        .with_file_name(file_name)
                        .with_policy(output_policy(recipe.force)),
                ),
                &context,
                "golden record",
                |outcome| {
                    outcome
                        .env_sandbox_call_export()
                        .map(|export| export.plan.plan_sha256.clone())
                },
            )?;
            let export = committed
                .env_sandbox_call_export()
                .context("the export operation returned no result")?;
            row!(out, "Wrote golden record to {}", path.display());
            row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
            print_warnings(&committed);
            export.record.clone()
        }
    };

    // Printed before the prose below, which goes to stderr: a caveat about a
    // record is only useful beside the record it is about.
    out.print()?;

    // The prose stays here, where the fd tables that name a vector are.
    if !record.returned {
        eprintln!(
            "warning: routine did not return cleanly: {}",
            stop_reason_text(&record.stop, &fd_names)
        );
    }
    print_blit_log(&record, recipe.custom_chips);
    Ok(())
}

/// The reviewed contract of the routine at one hunk offset of one executable.
///
/// Reads the file, because a project's names are matched by the *digest* of the
/// bytes and never by their path — the same rule the annotated listing goes
/// through, and the reason a project cannot put one module's contract on
/// another's offsets. An unreadable file is not this function's error to report:
/// the run that follows will fail on it with a better message.
fn signature_at(executable: &Path, hunk: u32, offset: u64) -> Option<crate::commands::Signature> {
    let bytes = std::fs::read(executable).ok()?;
    let names = crate::commands::ProjectNames::for_bytes(None, &bytes)?;
    names.signature(hunk, offset).cloned()
}

/// Print the arguments a signature states, with no value for any of them.
///
/// **Deliberately not runnable as it stands.** Every parameter is a placeholder,
/// because the signature says where an argument goes and never what it should
/// be: a template that filled in zeroes would produce a command line that runs
/// and a record of a call nobody meant to make.
fn print_call_template(
    out: &mut crate::commands::Document,
    executable: &Path,
    signature: &crate::commands::Signature,
) -> Result<()> {
    row!(out, "; {}", signature.rendered);
    row!(
        out,
        "; Fill in every VALUE. The signature says where each argument goes and \
         not what it is."
    );
    let mut line = format!("amiga-re call {}", executable.display());
    let mut stack: Vec<Option<&str>> = Vec::new();
    for parameter in &signature.parameters {
        match &parameter.location {
            crate::commands::SignatureLocation::Register(register) => {
                let _ = write!(line, " \\\n    --reg {register}=VALUE");
            }
            location => match location.stack_argument_index() {
                Some(index) => {
                    if stack.len() <= index {
                        stack.resize(index + 1, None);
                    }
                    stack[index] = Some(parameter.name.as_str());
                }
                // An offset that names no whole longword slot cannot become an
                // `--arg`, and guessing a neighbouring one would put the value
                // somewhere the routine does not read it.
                None => row!(
                    out,
                    "; {} is at {} and is not a whole stack argument; seed it with \
                     --poke",
                    parameter.name,
                    location.label()
                ),
            },
        }
    }
    // Which `--arg` is which, on its **own comment row** rather than beside the
    // arguments. A trailing `# name` on a continued line puts the backslash
    // inside a shell comment, so the continuation is swallowed and every
    // argument after the first becomes a separate command — a template that
    // cannot be pasted is worse than none.
    if !stack.is_empty() {
        let order: Vec<String> = stack
            .iter()
            .enumerate()
            // `--arg` is positional, so a slot the signature does not name still
            // has to be passed to keep the later ones in place; it is named as a
            // gap rather than silently zeroed.
            .map(|(index, name)| format!("{} {}", index + 1, name.unwrap_or("(unnamed slot)")))
            .collect();
        row!(out, "; --arg order: {}", order.join(", "));
    }
    for _ in &stack {
        let _ = write!(line, " \\\n    --arg VALUE");
    }
    row!(out, "{line}");
    Ok(())
}

/// Refuse a call whose signature names a parameter the command line leaves out.
///
/// An unsupplied argument is **not** zero: it is whatever the sandbox happens to
/// start that register at, and a golden record of such a run reads exactly like
/// a record of a call that was made properly. Named rather than counted, because
/// a reader has to know *which* one to supply.
fn refuse_unsupplied_arguments(
    signature: &crate::commands::Signature,
    seeded: &[String],
    supplied_stack: usize,
) -> Result<()> {
    let named: std::collections::BTreeSet<String> = seeded
        .iter()
        .filter_map(|seed| seed.split_once('='))
        .map(|(name, _)| name.trim().to_ascii_lowercase())
        .collect();
    let mut missing = Vec::new();
    for parameter in &signature.parameters {
        let present = match &parameter.location {
            crate::commands::SignatureLocation::Register(register) => named.contains(register),
            location => match location.stack_argument_index() {
                Some(index) => index < supplied_stack,
                // Not a whole stack slot, so `--arg` cannot supply it and this
                // check has nothing to say — `--poke` is the mechanism, and a
                // seed is not attributable to a parameter.
                None => true,
            },
        };
        if !present {
            missing.push(format!(
                "{} ({})",
                parameter.name,
                parameter.location.label()
            ));
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "{} does not supply {}. An unsupplied argument is not zero — it is whatever \
         the register started at. Run with --template to see the arguments, or \
         --partial-arguments to call it anyway.",
        signature.rendered,
        missing.join(", ")
    )
}

/// Compare golden records through `env.sandbox.compare`.
///
/// The default rendering is the summary, because the useful answer to "are these
/// two the same run" is usually one line and a short list. `--json` is the whole
/// comparison, for a caller that wants to act on it.
pub(crate) fn compare_records(
    records: &[PathBuf],
    maximum_differences: Option<usize>,
    json: bool,
) -> Result<()> {
    let mut out = Document::new();
    // Every record has to resolve under one root, because the source resolver
    // has one. Records from two directories are a real case and are refused by
    // name rather than half-read: a comparison missing one of its sides would
    // answer a question nobody asked.
    let mut base: Option<PathBuf> = None;
    let mut names = Vec::with_capacity(records.len());
    for record in records {
        let resolved = resolve_media_path(record)?;
        let (root, name) = amiga_operations::split_host_path(&resolved)
            .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
        match &base {
            None => base = Some(root),
            Some(first) if *first == root => {}
            Some(first) => bail!(
                "every record must live in one directory; {} is in {} but the first is in {}",
                resolved.display(),
                root.display(),
                first.display()
            ),
        }
        names.push(name.as_str().to_owned());
    }
    let base = base.context("no records to compare")?;

    let mut arguments = amiga_operations::SandboxCompareArguments::of(names);
    arguments.maximum_differences = maximum_differences;

    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::EnvSandboxCompare(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).context("failed to compare the records")?;
    let result = outcome
        .env_sandbox_compare()
        .context("the compare operation returned no result")?;

    if json {
        row!(out, "{}", serde_json::to_string_pretty(result)?);
        out.print()?;
        print_warnings(&outcome);
        return Ok(());
    }

    for (index, record) in result.records.iter().enumerate() {
        // Shortened for reading, and by `get` rather than by slicing: a digest
        // is always 64 characters, and a renderer that panics when one is not is
        // a renderer that turns a surprising response into a crash.
        let short = record.sha256.get(..16).unwrap_or(record.sha256.as_str());
        row!(out, "[{index}] {} ({short})", record.name);
    }
    if !result.same_source {
        row!(
            out,
            "; the records read different images, so a behavioral difference may be \
             a difference between two programs"
        );
    }
    row!(out, ";");
    let section = |out: &mut Document,
                   title: &str,
                   listed: &[amiga_operations::CompareDifference],
                   total: u64| {
        if total == 0 {
            row!(out, "{title}: none");
            return;
        }
        row!(out, "{title}: {total}");
        for difference in listed {
            row!(out, "  {}", difference.field);
            for (index, value) in difference.values.iter().enumerate() {
                row!(out, "    [{index}] {value}");
            }
        }
        if listed.len() as u64 != total {
            row!(out, "  … {} of {total} listed", listed.len());
        }
    };
    section(
        &mut out,
        "Inputs",
        &result.input_differences,
        result.input_differences_total,
    );
    section(
        &mut out,
        "Behavior",
        &result.behavioral_differences,
        result.behavioral_differences_total,
    );

    match result.trace_comparison {
        amiga_operations::TraceComparison::Absent => {
            row!(
                out,
                "Traces: not compared — at least one record carries none, which is not \
                 the same as agreeing"
            );
        }
        amiga_operations::TraceComparison::Compared { steps, truncated } => {
            let caveat = if truncated {
                " (capped, so a later divergence is invisible)"
            } else {
                ""
            };
            match &result.first_divergence {
                None => row!(out, "Traces: identical over {steps} step(s){caveat}"),
                Some(divergence) => {
                    row!(out, "Traces: diverge at step {}{caveat}", divergence.step);
                    for (index, step) in divergence.records.iter().enumerate() {
                        row!(
                            out,
                            "    [{index}] {:#010x}  {}  (pass {})",
                            step.address,
                            step.text,
                            step.occurrence + 1
                        );
                    }
                }
            }
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run a matrix of cases over one shared recipe.
///
/// The result goes to stdout as JSON like a single record does, and the counts
/// go to stderr — so `--cases … | jq` still works, and a person watching still
/// learns that four of three hundred cases were refused without reading the
/// JSON. The counts are what a sweep is read by; the per-case detail is what it
/// is read *into* afterwards.
fn call_matrix(
    call: amiga_operations::SandboxCallArguments,
    cases_path: &std::path::Path,
    recipe: &CallArgs,
    sources: &amiga_operations::FilesystemSourceResolver,
    resolved: &std::path::Path,
    mut out: crate::commands::Document,
) -> Result<()> {
    let maximum_total_steps = recipe.max_total_steps;
    let cases_output = recipe.cases_output.as_deref();
    let force = recipe.force;
    let text = std::fs::read_to_string(cases_path)
        .with_context(|| format!("failed to read cases from {}", cases_path.display()))?;
    let cases: Vec<amiga_operations::SandboxMatrixCase> = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a JSON array of cases", cases_path.display()))?;

    let mut matrix = amiga_operations::SandboxMatrixArguments::new(call, cases);
    matrix.maximum_total_steps = maximum_total_steps;

    // Two shapes over one operation pair, so the summary below reads the same
    // either way: the read-only sweep, or the export that also writes what each
    // case saved.
    let (outcome, result) = match cases_output {
        None => {
            let context =
                amiga_operations::ExecutionContext::new(sources).with_limits(sandbox_limits());
            let outcome = amiga_operations::Router::execute(
                &amiga_operations::RequestEnvelope::read(
                    amiga_operations::OperationRequestDocument::EnvSandboxMatrix(matrix),
                ),
                &context,
            );
            fail_on_errors(&outcome)
                .with_context(|| format!("failed to run the matrix over {}", resolved.display()))?;
            let result = outcome
                .env_sandbox_matrix()
                .context("the matrix operation returned no result")?
                .clone();
            (outcome, result)
        }
        Some(path) => {
            let (output_base, destination) = split_destination_dir(path)?;
            let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
            let context = amiga_operations::ExecutionContext::new(sources)
                .with_destinations(&destinations)
                .with_limits(sandbox_limits());
            let committed = commit_reviewed(
                amiga_operations::OperationRequestDocument::EnvSandboxMatrixExport(
                    amiga_operations::SandboxMatrixExportArguments::new(
                        matrix,
                        destination.as_str(),
                    )
                    .with_policy(output_policy(force)),
                ),
                &context,
                "sweep",
                |outcome| {
                    outcome
                        .env_sandbox_matrix_export()
                        .map(|export| export.plan.plan_sha256.clone())
                },
            )?;
            let export = committed
                .env_sandbox_matrix_export()
                .context("the matrix export returned no result")?;
            let result = export.result.clone();
            eprintln!(
                "Wrote {} file(s) to {}",
                export.plan.files.len(),
                path.display()
            );
            eprintln!("Plan SHA-256: {}", export.plan.plan_sha256);
            (committed, result)
        }
    };

    row!(out, "{}", serde_json::to_string_pretty(&result)?);
    out.print()?;
    print_warnings(&outcome);

    eprintln!(
        "{} cases: {} returned cleanly, {} ran, {} refused, {} not run ({} steps)",
        result.cases_total,
        result.cases_returned,
        result.cases_ran,
        result.cases_refused,
        result.cases_not_run,
        result.steps_executed_total,
    );
    // Named rather than counted. A refusal a reader cannot locate is a refusal
    // they will not act on, and the whole point of reporting one per case is
    // that the case is identifiable.
    for case in &result.cases {
        if matches!(case.outcome, amiga_operations::MatrixCaseOutcome::Refused) {
            let why = case
                .diagnostics
                .first()
                .map_or("no reason given", |diagnostic| &diagnostic.message);
            eprintln!("  refused: {} — {why}", case.name);
        }
    }
    Ok(())
}

/// Run a sequence of steps over one evolving machine.
///
/// The result goes to stdout as JSON and the counts go to stderr, exactly as a
/// sweep's do, so `--steps … | jq` still works. What the prose adds is the shape
/// a reader of a *timeline* needs and a sweep's does not: the order, and where
/// it stopped being one — a refused step is named, and so is the fact that the
/// steps after it were never attempted.
fn call_timeline(
    call: amiga_operations::SandboxCallArguments,
    steps_path: &std::path::Path,
    recipe: &CallArgs,
    sources: &amiga_operations::FilesystemSourceResolver,
    resolved: &std::path::Path,
    mut out: crate::commands::Document,
) -> Result<()> {
    let text = std::fs::read_to_string(steps_path)
        .with_context(|| format!("failed to read steps from {}", steps_path.display()))?;
    let steps: Vec<amiga_operations::TimelineStep> = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a JSON array of steps", steps_path.display()))?;

    let mut timeline = amiga_operations::SandboxTimelineArguments::new(call, steps);
    timeline.maximum_total_steps = recipe.max_total_steps;

    // Two shapes over one operation pair, exactly as a sweep has: the read-only
    // timeline, or the export that also writes what each step checkpointed. The
    // summary below reads the same either way.
    let (outcome, result) = match recipe.steps_output.as_deref() {
        None => {
            let context =
                amiga_operations::ExecutionContext::new(sources).with_limits(sandbox_limits());
            let outcome = amiga_operations::Router::execute(
                &amiga_operations::RequestEnvelope::read(
                    amiga_operations::OperationRequestDocument::EnvSandboxTimeline(timeline),
                ),
                &context,
            );
            fail_on_errors(&outcome).with_context(|| {
                format!("failed to run the timeline over {}", resolved.display())
            })?;
            let result = outcome
                .env_sandbox_timeline()
                .context("the timeline operation returned no result")?
                .clone();
            (outcome, result)
        }
        Some(path) => {
            let (output_base, destination) = split_destination_dir(path)?;
            let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
            let context = amiga_operations::ExecutionContext::new(sources)
                .with_destinations(&destinations)
                .with_limits(sandbox_limits());
            let committed = commit_reviewed(
                amiga_operations::OperationRequestDocument::EnvSandboxTimelineExport(
                    amiga_operations::SandboxTimelineExportArguments::new(
                        timeline,
                        destination.as_str(),
                    )
                    .with_policy(output_policy(recipe.force)),
                ),
                &context,
                "timeline",
                |outcome| {
                    outcome
                        .env_sandbox_timeline_export()
                        .map(|export| export.plan.plan_sha256.clone())
                },
            )?;
            let export = committed
                .env_sandbox_timeline_export()
                .context("the timeline export returned no result")?;
            let result = export.result.clone();
            eprintln!(
                "Wrote {} file(s) to {}",
                export.plan.files.len(),
                path.display()
            );
            eprintln!("Plan SHA-256: {}", export.plan.plan_sha256);
            (committed, result)
        }
    };

    row!(out, "{}", serde_json::to_string_pretty(&result)?);
    out.print()?;
    print_warnings(&outcome);

    eprintln!(
        "{} steps: {} ran, {} refused, {} not run ({} instructions)",
        result.steps_total,
        result.steps_ran,
        result.steps_refused,
        result.steps_not_run,
        result.instructions_executed_total,
    );
    for step in &result.steps {
        if matches!(step.outcome, amiga_operations::TimelineStepOutcome::Refused) {
            let why = step
                .diagnostics
                .first()
                .map_or("no reason given", |diagnostic| &diagnostic.message);
            eprintln!("  refused: {} — {why}", step.name);
        }
    }
    Ok(())
}

/// Follow one value backwards through the instructions that produced it.
///
/// The result goes to stdout as JSON and the chain goes to stderr, so
/// `--slice … | jq` still works and a person watching reads the answer without
/// opening the JSON. The stops are printed last and loudest: an `input` is what
/// a slice is looking for, and a bound that cut a chain short is what stops the
/// absence of one being read as an answer.
fn call_slice(
    call: amiga_operations::SandboxCallArguments,
    seed: &str,
    recipe: &CallArgs,
    sources: &amiga_operations::FilesystemSourceResolver,
    resolved: &std::path::Path,
    mut out: crate::commands::Document,
) -> Result<()> {
    let seed = parse_slice_seed(seed)?;
    let mut arguments = amiga_operations::SandboxSliceArguments::new(call, seed);
    arguments.maximum_depth = recipe.slice_depth;

    let context = amiga_operations::ExecutionContext::new(sources).with_limits(sandbox_limits());
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::EnvSandboxSlice(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to slice a run of {}", resolved.display()))?;
    let slice = outcome
        .env_sandbox_slice()
        .context("the slice operation returned no result")?;

    row!(out, "{}", serde_json::to_string_pretty(slice)?);
    out.print()?;
    print_warnings(&outcome);

    eprintln!(
        "{} of {} step(s) influenced {}",
        slice.steps.len(),
        slice.steps_total,
        slice.seed
    );
    for step in &slice.steps {
        eprintln!(
            "  {:#010x}#{:<3} +{:<3} {:<28} defines {}  uses {}",
            step.address,
            step.occurrence,
            step.depth,
            step.text,
            step.defines.join(","),
            step.uses.join(","),
        );
    }
    for stop in &slice.stops {
        match stop {
            amiga_operations::SliceStopResult::Input { location } => {
                eprintln!("  input: {location} was never written during the run");
            }
            amiga_operations::SliceStopResult::Undecodable { step, address } => {
                eprintln!(
                    "  undecodable: step {step} at {address:#010x} is not the instruction \
                     the run started with"
                );
            }
            amiga_operations::SliceStopResult::DepthReached => {
                eprintln!("  a chain reached the depth bound and continues past it");
            }
            amiga_operations::SliceStopResult::StepsReached => {
                eprintln!("  a chain reached the step bound and continues past it");
            }
            amiga_operations::SliceStopResult::NotExecuted {
                address,
                occurrence,
                executed,
            } => {
                eprintln!(
                    "  not executed: the run executed {address:#010x} {executed} times, and \
                     the seed asked about execution {occurrence}"
                );
            }
        }
    }
    Ok(())
}

/// Parse one `REG`, `mem:ADDR` or `at:ADDR[#N]` slice seed.
fn parse_slice_seed(spec: &str) -> Result<amiga_operations::SliceSeedArgument> {
    if let Some(address) = spec.strip_prefix("mem:") {
        return Ok(amiga_operations::SliceSeedArgument::Memory {
            address: amiga_core::parse_u32(address.trim())
                .map_err(|message| anyhow::anyhow!("--slice memory address: {message}"))?,
        });
    }
    if let Some(rest) = spec.strip_prefix("at:") {
        let (address, occurrence) = match rest.split_once('#') {
            Some((address, count)) => (
                address,
                Some(
                    count
                        .trim()
                        .parse()
                        .with_context(|| format!("--slice occurrence: {count:?}"))?,
                ),
            ),
            None => (rest, None),
        };
        return Ok(amiga_operations::SliceSeedArgument::Instruction {
            address: amiga_core::parse_u32(address.trim())
                .map_err(|message| anyhow::anyhow!("--slice address: {message}"))?,
            occurrence,
        });
    }
    Ok(amiga_operations::SliceSeedArgument::Register {
        register: spec.trim().to_owned(),
    })
}

/// The human-readable blit log.
///
/// **On stderr, always.** Without `--output` the record itself goes to stdout as
/// JSON, and prose printed under it would stop that being valid JSON — which is
/// the whole reason a caller can pipe it anywhere.
fn print_blit_log(record: &amiga_operations::SandboxCallResult, asked_for_chips: bool) {
    if !asked_for_chips {
        return;
    }
    if record.blits_total == 0 {
        // Worth saying out loud: a recipe that asked for a blitter and got no
        // blits usually means the routine never reached the code that draws,
        // and silence there looks like success.
        eprintln!("note: custom chips were modelled, but the routine started no blits");
        return;
    }
    eprintln!(
        "{} blit{} ({} datapath words attempted, {} executed)",
        record.blits_total,
        if record.blits_total == 1 { "" } else { "s" },
        record.attempted_blit_words_total,
        record.executed_blit_words_total,
    );
    for blit in &record.blits {
        match &blit.refused {
            Some(refusal) => eprintln!(
                "  blit {:>4}: {}x{} REFUSED: {}",
                blit.index, blit.width, blit.height, refusal.message
            ),
            None => eprintln!(
                "  blit {:>4}: {}x{} -> {} words at {:#010x}{}",
                blit.index,
                blit.width,
                blit.height,
                blit.words_written,
                blit.initial_pointers[3],
                if blit.dma_assumed {
                    " (DMA assumed)"
                } else {
                    ""
                },
            ),
        }
        for observation in &blit.observations {
            eprintln!("            {}", observation.kind);
        }
    }
    for observation in &record.chip_observations {
        match observation.register {
            Some(register) => eprintln!(
                "  {} at ${register:03x} x{}",
                observation.kind, observation.occurrences
            ),
            None => eprintln!("  {} x{}", observation.kind, observation.occurrences),
        }
    }
}

pub(crate) fn parse_map_spec(spec: &str) -> Result<(u32, usize)> {
    let (address, size) = spec
        .split_once(':')
        .with_context(|| format!("--map expects ADDR:SIZE, got {spec:?}"))?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--map address: {message}"))?;
    let size = amiga_core::parse_u32(size.trim())
        .map_err(|message| anyhow::anyhow!("--map size: {message}"))?;
    Ok((
        address,
        usize::try_from(size).context("--map size too large")?,
    ))
}

/// Parse a `--poke-from ADDR=[HUNK/]OFFSET:LENGTH` specification.
///
/// The hunk is optional and comes first because it qualifies the offset: an
/// offset without one is into the file, and with one is into that hunk's loaded
/// bytes — which is the number a disassembly shows.
pub(crate) fn parse_poke_from_spec(spec: &str) -> Result<amiga_operations::MemorySeed> {
    let (address, range) = spec
        .split_once('=')
        .with_context(|| format!("--poke-from expects ADDR=[HUNK/]OFF:LEN, got {spec:?}"))?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--poke-from address: {message}"))?;
    let (offset, length) = range
        .split_once(':')
        .with_context(|| format!("--poke-from expects ADDR=[HUNK/]OFF:LEN, got {spec:?}"))?;
    let (hunk, offset) = match offset.split_once('/') {
        Some((hunk, offset)) => (
            Some(
                amiga_core::parse_u32(hunk.trim())
                    .map_err(|message| anyhow::anyhow!("--poke-from hunk: {message}"))?,
            ),
            offset,
        ),
        None => (None, offset),
    };
    Ok(amiga_operations::MemorySeed::from(
        address,
        amiga_operations::SeedRange {
            source: None,
            hunk,
            offset: amiga_core::parse_u32(offset.trim())
                .map_err(|message| anyhow::anyhow!("--poke-from offset: {message}"))?,
            length: amiga_core::parse_u32(length.trim())
                .map_err(|message| anyhow::anyhow!("--poke-from length: {message}"))?,
        },
    ))
}

/// One `--poke-artifact` specification, parsed but not yet named.
///
/// The file is kept as a host path because *which root it is named against* is
/// not a per-artifact decision: it depends on where the image and every other
/// artifact sit, so the naming happens once, in [`resolve_call_sources`].
struct PokeArtifact {
    address: u32,
    /// The directory holding the file, as the caller spelled it.
    base: PathBuf,
    /// The file itself, as [`amiga_operations::split_host_path`] validated it.
    file: amiga_operations::SourceName,
    /// The whole path again, for the refusals — a caller who mistyped a path
    /// wants to see what they typed, not the two halves it was cut into.
    path: PathBuf,
    sha256: String,
    range: Option<(u32, u32)>,
}

impl PokeArtifact {
    /// The seed this artifact becomes once its identity under the chosen root
    /// is known.
    fn into_seed(self, name: &amiga_operations::SourceName) -> amiga_operations::MemorySeed {
        let artifact = amiga_operations::SeedArtifact::new(name.as_str(), self.sha256);
        let artifact = match self.range {
            None => artifact,
            Some((offset, length)) => artifact.with_range(offset, length),
        };
        amiga_operations::MemorySeed::artifact(self.address, artifact)
    }
}

/// The one root a call's sources are named against, and the names themselves.
///
/// An operation resolves every source it reads through a single resolver rooted
/// at one directory, so the image and its artifacts have to share one. Deciding
/// that root — and refusing when there is no defensible one — is this type's
/// whole reason to exist.
struct CallSources {
    /// The directory the filesystem resolver owns.
    base: PathBuf,
    /// The image's identity under that base.
    image: amiga_operations::SourceName,
    /// One artifact seed per `--poke-artifact`, named under the same base.
    seeds: Vec<amiga_operations::MemorySeed>,
}

/// Decide the root a call's image and `--poke-artifact` files are named against.
///
/// **Beside the image is the unwidened case, and it is unchanged.** With every
/// artifact in the image's own directory the resolver stays there and a record
/// names the image by its bare file name, exactly as it always has.
///
/// **A file elsewhere is allowed only from a place the project declared.** A
/// project that prohibits provisional outputs beside its private source media
/// states where they go instead (`directories.scratch`), and that declaration —
/// not the caller's path — is what opens the door. The resolver then roots at
/// the project, so the image and the artifact are named relative to one thing
/// and the record says which project the replayed bytes came out of. Refusing
/// is the answer whenever the door was not opened deliberately: no project, no
/// declared scratch directory, a file outside it, or an image outside the
/// project entirely.
///
/// Every check the unwidened path made survives it. The digest is still
/// required and still compared before the routine runs, the range is still the
/// operation's to bound, and the resolver still walks each name component and
/// refuses a symbolic link — which is why containment is decided against
/// canonical *directories* while the file's own name is left for that walk.
fn resolve_call_sources(image: &Path, specs: &[String]) -> Result<CallSources> {
    let (image_base, image_name) = amiga_operations::split_host_path(image)
        .with_context(|| format!("{} does not name a readable file", image.display()))?;
    let artifacts = specs
        .iter()
        .map(|spec| parse_poke_artifact_spec(spec))
        .collect::<Result<Vec<_>>>()?;
    if artifacts.is_empty() {
        return Ok(CallSources {
            base: image_base,
            image: image_name,
            seeds: Vec::new(),
        });
    }

    // Resolved once and reused: two spellings of one directory have to compare
    // equal, and asking the filesystem per artifact would only be slower.
    let image_directory = canonical_directory(&image_base)?;
    let mut directories = Vec::with_capacity(artifacts.len());
    for artifact in &artifacts {
        directories.push(canonical_directory(&artifact.base)?);
    }
    let elsewhere = artifacts
        .iter()
        .zip(&directories)
        .find(|(_, directory)| **directory != image_directory)
        .map(|(artifact, _)| artifact.path.clone());

    let Some(elsewhere) = elsewhere else {
        let seeds = artifacts
            .into_iter()
            .map(|artifact| {
                let name = artifact.file.clone();
                artifact.into_seed(&name)
            })
            .collect();
        return Ok(CallSources {
            base: image_base,
            image: image_name,
            seeds,
        });
    };

    let project = scratch_project(&elsewhere)?;
    let image_identity = source_name_under(&project.root, &image_directory, image_name.as_str())
        .with_context(|| {
            format!(
                "--poke-artifact reads {}, which is outside the image's directory, so the call \
                 is named against the project at {}; but the image {} is not under it, and two \
                 sources with no shared root cannot both be named",
                elsewhere.display(),
                project.root.display(),
                image.display(),
            )
        })?;

    let mut seeds = Vec::with_capacity(artifacts.len());
    for (artifact, directory) in artifacts.into_iter().zip(directories) {
        if directory != image_directory && !directory.starts_with(&project.scratch) {
            bail!(
                "--poke-artifact reads {}, which is neither beside the image in {} nor under \
                 the scratch directory {} that the project at {} declares",
                artifact.path.display(),
                image_directory.display(),
                project.scratch.display(),
                project.root.display(),
            );
        }
        let name = source_name_under(&project.root, &directory, artifact.file.as_str())
            .with_context(|| {
                format!(
                    "--poke-artifact reads {}, which is not under the project at {}",
                    artifact.path.display(),
                    project.root.display(),
                )
            })?;
        seeds.push(artifact.into_seed(&name));
    }
    Ok(CallSources {
        base: project.root,
        image: image_identity,
        seeds,
    })
}

/// A project that declares where provisional outputs live.
struct ScratchProject {
    /// The project's own directory, canonical.
    root: PathBuf,
    /// The declared scratch directory below it, canonical.
    scratch: PathBuf,
}

/// Find the project whose declared scratch directory an artifact may come from.
///
/// Each refusal names the step that was missing rather than the outcome, because
/// "not allowed" is three different situations here and only one of them is the
/// caller pointing at the wrong file.
fn scratch_project(elsewhere: &Path) -> Result<ScratchProject> {
    let named = crate::project_override();
    let root = match named {
        Some(path) => path.to_path_buf(),
        None => {
            let cwd = std::env::current_dir().context("failed to read the current directory")?;
            amiga_project::discover(&cwd).with_context(|| {
                format!(
                    "--poke-artifact reads {}, which is not beside the image; a file elsewhere \
                     is replayed only from a project's declared scratch directory, and no {} \
                     was found in {} or its parents (name one with --project)",
                    elsewhere.display(),
                    amiga_project::load::ROOT_FILE_NAME,
                    cwd.display(),
                )
            })?
        }
    };
    let root = if root.is_dir() {
        root
    } else {
        root.parent().unwrap_or(Path::new(".")).to_path_buf()
    };
    let root = canonical_directory(&root)?;
    let loaded = amiga_project::load(&root)
        .with_context(|| format!("the project at {} could not be loaded", root.display()))?;
    let scratch = loaded.project.scratch_directory().with_context(|| {
        format!(
            "--poke-artifact reads {}, which is not beside the image; the project at {} \
             declares no scratch directory, so it names no place a provisional file may be \
             replayed from — add `directories.scratch` to {}",
            elsewhere.display(),
            root.display(),
            amiga_project::load::ROOT_FILE_NAME,
        )
    })?;
    let declared = root.join(scratch);
    let scratch = canonical_directory(&declared).with_context(|| {
        format!(
            "the project at {} declares the scratch directory {scratch:?}, which is not a \
             readable directory",
            root.display(),
        )
    })?;
    Ok(ScratchProject { root, scratch })
}

/// The canonical form of a directory, for comparing two paths that name it.
///
/// Directories only. Canonicalizing the file itself would resolve a symbolic
/// link that [`amiga_operations::FilesystemSourceResolver`] exists to refuse,
/// turning a check into a silent redirection.
fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    path.canonicalize()
        .with_context(|| format!("{} is not a readable directory", path.display()))
}

/// Name `file`, which sits in `directory`, as an identity under `root`.
///
/// `None` when `directory` is not below `root`, or when a component is not
/// usable in a source identity — either way the two have no name in common and
/// saying so is the only honest answer.
fn source_name_under(
    root: &Path,
    directory: &Path,
    file: &str,
) -> Option<amiga_operations::SourceName> {
    let relative = directory.strip_prefix(root).ok()?;
    let mut name = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return None;
        };
        name.push_str(part.to_str()?);
        name.push('/');
    }
    name.push_str(file);
    amiga_operations::SourceName::parse(&name).ok()
}

/// Parse a `--poke-artifact ADDR=FILE@SHA256[:OFFSET:LENGTH]` specification.
///
/// The digest is not optional and is not a flag: it is part of naming the file,
/// which is why it is spelled with `@` rather than as a separate argument a
/// caller could forget. Without it a replay depends on bytes nobody checked, and
/// the golden record it produces describes a file it never read.
fn parse_poke_artifact_spec(spec: &str) -> Result<PokeArtifact> {
    let shape = || format!("--poke-artifact expects ADDR=FILE@SHA256[:OFF:LEN], got {spec:?}");
    let (address, rest) = spec.split_once('=').with_context(shape)?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--poke-artifact address: {message}"))?;
    // The file comes first and may itself contain `:` on some systems, so the
    // digest is what the range is measured from: everything after the `@` up to
    // the first `:` is the digest, and the rest is the range.
    let (file, pinned) = rest.rsplit_once('@').with_context(shape)?;
    let (sha256, range) = match pinned.split_once(':') {
        Some((sha256, range)) => (sha256, Some(range)),
        None => (pinned, None),
    };
    let path = resolve_media_path(Path::new(file.trim()))?;
    let (base, name) = amiga_operations::split_host_path(&path)
        .with_context(|| format!("{} does not name a readable file", path.display()))?;
    let range = match range {
        None => None,
        Some(range) => {
            let (offset, length) = range.split_once(':').with_context(shape)?;
            Some((
                amiga_core::parse_u32(offset.trim())
                    .map_err(|message| anyhow::anyhow!("--poke-artifact offset: {message}"))?,
                amiga_core::parse_u32(length.trim())
                    .map_err(|message| anyhow::anyhow!("--poke-artifact length: {message}"))?,
            ))
        }
    };
    Ok(PokeArtifact {
        address,
        base,
        file: name,
        path,
        sha256: sha256.trim().to_owned(),
        range,
    })
}

/// Parse an `--interrupt vNN|ADDR[/rte|/rts]=AFTER[:EVERY]` specification.
///
/// A `v`-prefixed handler is a 68000 vector, read from the table at delivery so
/// the handler the program installed is the one that runs; anything else is a
/// fixed address, for a recipe that already knows where the handler is. A fixed
/// handler may select the plain subroutine frame used by an Exec interrupt
/// server; a vector always receives the hardware exception frame it names.
pub(crate) fn parse_interrupt_spec(spec: &str) -> Result<amiga_operations::ScheduledInterrupt> {
    let (handler, schedule) = spec.split_once('=').with_context(|| {
        format!("--interrupt expects vNN|ADDR[/rte|/rts]=AFTER[:EVERY], got {spec:?}")
    })?;
    let (handler, frame) = match handler.trim().split_once('/') {
        Some((handler, frame)) => {
            let frame = match frame.trim() {
                "rte" => amiga_operations::InterruptFrame::Rte,
                "rts" => amiga_operations::InterruptFrame::Rts,
                frame => anyhow::bail!("--interrupt frame must be rte or rts, got {frame:?}"),
            };
            (handler.trim(), Some(frame))
        }
        None => (handler.trim(), None),
    };
    let (vector, address) = match handler.strip_prefix('v') {
        Some(vector) => {
            anyhow::ensure!(
                frame.is_none(),
                "--interrupt vectors always use an rte frame; frame selectors belong to fixed handlers"
            );
            (
                Some(
                    vector
                        .trim()
                        .parse::<u8>()
                        .with_context(|| format!("--interrupt vector: {vector:?}"))?,
                ),
                None,
            )
        }
        None => (
            None,
            Some(
                amiga_core::parse_u32(handler)
                    .map_err(|message| anyhow::anyhow!("--interrupt address: {message}"))?,
            ),
        ),
    };
    let (after, every) = match schedule.split_once(':') {
        Some((after, every)) => (after, Some(every)),
        None => (schedule, None),
    };
    Ok(amiga_operations::ScheduledInterrupt {
        vector,
        address,
        after_steps: Some(
            amiga_core::parse_u32(after.trim())
                .map_err(|message| anyhow::anyhow!("--interrupt after: {message}"))?,
        ),
        every_steps: every
            .map(|every| {
                amiga_core::parse_u32(every.trim())
                    .map_err(|message| anyhow::anyhow!("--interrupt every: {message}"))
            })
            .transpose()?,
        deliveries: None,
        frame,
    })
}

/// Parse a `--save NAME=ADDR:LEN` specification.
///
/// The name comes first because it is what the artifact is called, and a reader
/// scanning a command line for "what did this produce" should find it there
/// rather than at the end of a range.
pub(crate) fn parse_save_spec(spec: &str) -> Result<amiga_operations::MemoryExport> {
    let (name, range) = spec
        .split_once('=')
        .with_context(|| format!("--save expects NAME=ADDR:LEN, got {spec:?}"))?;
    let (address, length) = range
        .split_once(':')
        .with_context(|| format!("--save expects NAME=ADDR:LEN, got {spec:?}"))?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--save {name} address: {message}"))?;
    let length = amiga_core::parse_u32(length.trim())
        .map_err(|message| anyhow::anyhow!("--save {name} length: {message}"))?;
    Ok(amiga_operations::MemoryExport {
        address,
        length,
        name: name.trim().to_owned(),
    })
}

/// Parse a `--poke ADDR=HEXBYTES` specification.
pub(crate) fn parse_poke_spec(spec: &str) -> Result<(u32, Vec<u8>)> {
    let (address, digits) = spec
        .split_once('=')
        .with_context(|| format!("--poke expects ADDR=HEX, got {spec:?}"))?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--poke address: {message}"))?;
    let data =
        hex::decode(digits.trim()).with_context(|| format!("--poke {address:#x}: invalid hex"))?;
    Ok((address, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poke_and_map_specs_parse_into_what_a_request_carries() {
        // The golden record itself is the operation's now, and
        // `crates/amiga-operations/tests/sandbox.rs` covers its shape. What is
        // still this frontend's is turning what the user typed into a request,
        // so that is what is tested here.
        let (address, data) = parse_poke_spec("0x2004=deadbeef")
            .unwrap_or_else(|error| panic!("poke did not parse: {error}"));
        assert_eq!(address, 0x2004);
        assert_eq!(hex::encode(data), "deadbeef");

        let (address, size) = parse_map_spec("0x2000:16")
            .unwrap_or_else(|error| panic!("map did not parse: {error}"));
        assert_eq!(address, 0x2000);
        assert_eq!(size, 16);

        assert!(parse_poke_spec("0x2004=nothex").is_err());
        assert!(parse_map_spec("0x2000").is_err());
    }

    #[test]
    fn the_new_call_spellings_turn_into_what_a_request_carries() {
        let seed = parse_poke_from_spec("0x2000=1/0x40:16")
            .unwrap_or_else(|error| panic!("poke-from did not parse: {error}"));
        assert_eq!(seed.address, 0x2000);
        assert!(seed.hex.is_none(), "a range seed spelled out bytes too");
        let range = seed.from.expect("the range it copies");
        assert_eq!(range.hunk, Some(1));
        assert_eq!(range.offset, 0x40);
        assert_eq!(range.length, 16);
        // Without a hunk the offset is into the file, which is a different
        // number, so the two spellings must not collapse.
        let plain = parse_poke_from_spec("0x2000=0x40:16")
            .unwrap_or_else(|error| panic!("poke-from did not parse: {error}"));
        assert_eq!(plain.from.expect("a range").hunk, None);
        assert!(parse_poke_from_spec("0x2000=0x40").is_err());

        let save = parse_save_spec("frame.bin=0x50000:0x2800")
            .unwrap_or_else(|error| panic!("save did not parse: {error}"));
        assert_eq!(save.name, "frame.bin");
        assert_eq!(save.address, 0x5_0000);
        assert_eq!(save.length, 0x2800);
        assert!(parse_save_spec("frame.bin=0x50000").is_err());

        let vector = parse_interrupt_spec("v27=3:1000")
            .unwrap_or_else(|error| panic!("interrupt did not parse: {error}"));
        assert_eq!(vector.vector, Some(27));
        assert_eq!(vector.address, None);
        assert_eq!(vector.after_steps, Some(3));
        assert_eq!(vector.every_steps, Some(1000));
        let fixed = parse_interrupt_spec("0x20020=3")
            .unwrap_or_else(|error| panic!("interrupt did not parse: {error}"));
        assert_eq!(fixed.vector, None);
        assert_eq!(fixed.address, Some(0x2_0020));
        assert_eq!(fixed.every_steps, None, "a one-shot gained a period");
        assert_eq!(fixed.frame, None, "the default frame became explicit");
        let fixed_rts = parse_interrupt_spec("0x20020/rts=3:1000")
            .unwrap_or_else(|error| panic!("RTS interrupt did not parse: {error}"));
        assert_eq!(fixed_rts.address, Some(0x2_0020));
        assert_eq!(fixed_rts.frame, Some(amiga_operations::InterruptFrame::Rts));
        let fixed_rte = parse_interrupt_spec("0x20020/rte=3")
            .unwrap_or_else(|error| panic!("explicit RTE interrupt did not parse: {error}"));
        assert_eq!(fixed_rte.frame, Some(amiga_operations::InterruptFrame::Rte));
        assert!(parse_interrupt_spec("0x20020/return=3").is_err());
        assert!(parse_interrupt_spec("v27/rts=3").is_err());
        assert!(parse_interrupt_spec("v27").is_err());
    }

    #[test]
    fn parses_read_write_watch_ranges() {
        let watch = parse_watchpoint("rw:0x1000:0x20")
            .unwrap_or_else(|error| panic!("watchpoint did not parse: {error}"));
        assert_eq!(watch.start, 0x1000);
        assert_eq!(watch.length, 0x20);
        assert_eq!(watch.access, amiga_operations::WatchAccess::Both);
        assert!(parse_watchpoint("x:0x1000").is_err());
        // A range that wraps the address space parses here and is refused by the
        // operation, which owns range validation for every request.
        let wrapping = parse_watchpoint("w:0xffffffff:2")
            .unwrap_or_else(|error| panic!("a wrapping range should still parse: {error}"));
        assert!(wrapping.start.checked_add(wrapping.length).is_none());
    }
}
