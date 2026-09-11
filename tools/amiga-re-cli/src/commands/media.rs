use super::*;

// --- adf -------------------------------------------------------------------

/// Run `container.adf.list` through the shared operation router and render its
/// typed result.
pub(crate) fn adf_list(path: &Path, max_entries: Option<usize>) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;

    let mut arguments = amiga_operations::AdfListArguments::new(name.as_str());
    if let Some(entries) = max_entries {
        arguments = arguments.with_maximum_entries(entries);
    }
    let limits = amiga_operations::OperationLimits::default().with_maximum_entries(
        max_entries.unwrap_or(amiga_operations::limits::DEFAULT_MAXIMUM_ENTRIES),
    );

    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver).with_limits(limits);
    let request = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ContainerAdfList(arguments),
    );

    let outcome = amiga_operations::Router::execute(&request, &context);
    fail_on_errors(&outcome).with_context(|| format!("failed to list {}", resolved.display()))?;
    let listing = outcome
        .container_adf_list()
        .context("the listing operation returned no result")?;

    row!(
        out,
        "Volume: {:?} ({}, root block {})",
        listing.volume.name,
        listing.volume.filesystem.to_uppercase(),
        listing.volume.root_block
    );
    for entry in &listing.entries {
        row!(
            out,
            "{:<9} {:>8}  block {:>4}  {}",
            entry.kind.as_str(),
            entry.size,
            entry.header_block,
            entry.path
        );
    }
    if listing.entries_truncated {
        row!(
            out,
            "... {} of {} entries shown",
            listing.entries.len(),
            listing.entry_total
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `container.adf.extract` through the shared router.
///
/// A convenience wrapper does the reviewing on the user's behalf: it prepares,
/// prints what would be written, and commits the plan it just showed. The two
/// halves are the same ones automation drives separately with `operations run`,
/// so a human at a terminal and a script commit the same bytes under the same
/// checks — this only removes the round trip.
pub(crate) fn adf_extract(source: &Path, output: &Path, force: bool) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(source)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, output_name) = split_output_path(output)?;

    // `--force` picks a replacing policy; without it the destination must not
    // exist. Which of the two replacing policies applied is recorded in the
    // plan, so provenance is no longer ambiguous about why it was allowed.
    let policy = if force {
        amiga_operations::OutputPolicy::ReplaceMatchingProvenance
    } else {
        amiga_operations::OutputPolicy::CreateOnly
    };
    let arguments = amiga_operations::ContainerExtractArguments::new(
        source_name.as_str(),
        output_name.as_str(),
    )
    .with_policy(policy);

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let mut prepare = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ContainerAdfExtract(arguments.clone()),
    );
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    fail_on_errors(&prepared)
        .with_context(|| format!("failed to extract {}", resolved.display()))?;
    let extraction = prepared
        .container_extract()
        .context("the extraction operation produced no plan")?;
    let plan = extraction.plan.clone();
    let unreadable = extraction.unreadable.clone();

    let mut commit = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ContainerAdfExtract(arguments),
    );
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256.clone(),
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    fail_on_errors(&committed)
        .with_context(|| format!("failed to extract {}", resolved.display()))?;

    row!(
        out,
        "Extracted {} files from {} to {}",
        plan.files.len(),
        resolved.display(),
        output.display(),
    );
    row!(out, "Plan SHA-256: {}", plan.plan_sha256);
    out.print()?;
    print_warnings(&prepared);
    // The files are on disk and the refusals are on stderr; what is left is to
    // exit non-zero, because a volume that lost a file is not a successful
    // extraction even though everything recoverable was recovered. Printed
    // first and failed after, so the listing this failure is about is not lost
    // to the error.
    if !unreadable.is_empty() {
        bail!(
            "{} of {} file(s) on {} are damaged and were not extracted: {}",
            unreadable.len(),
            plan.files.len() + unreadable.len(),
            resolved.display(),
            unreadable
                .iter()
                .map(|member| member.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// Split a host output *directory* into the root an adapter serves and the
/// identity a request names, the same way `split_host_path` does for a source.
///
/// The destination need not exist yet, so this cannot canonicalize it; it takes
/// the parent as the root and the final component as the name.
///
/// For a command that writes **one** file, use `split_destination_file` instead:
/// that one names the file the user typed. This is only for a destination the
/// user really is naming as a directory, which on the command line is now just
/// `adf extract` — an extraction produces a whole tree, so there is no single
/// file to name.
pub(crate) fn split_output_path(
    output: &Path,
) -> Result<(PathBuf, amiga_operations::DestinationName)> {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} does not name a directory", output.display()))?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let base = if parent.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        parent.to_path_buf()
    };
    let name = amiga_operations::DestinationName::parse(name)
        .with_context(|| format!("{} is not a usable destination", output.display()))?;
    Ok((base, name))
}

// --- hunk ------------------------------------------------------------------

/// Rewrite a one-file loader's compact relocation records as standard ones.
///
/// Refuses an image that already parses rather than rewriting it: the compact and
/// standard encodings are not distinguishable, so "normalize anything" would read
/// an ordinary 32-bit count as a 16-bit one and shift every record after it. The
/// rewriter proves its own output by re-parsing it, and this reports what that
/// parse found so the count is the toolkit's reading rather than the file's claim.
/// Run `analysis.hunk.normalize.export` through the shared router.
///
/// The refusal of an image that already parses is the operation's now, not this
/// command's: nothing in a one-file image says which relocation encoding it
/// uses, so "normalizing" an ordinary one would read its records as compact and
/// shift every record after the first into a file that looks finished.
pub(crate) fn hunk_normalize(path: &Path, output: &Path, force: bool) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let arguments = amiga_operations::HunkNormalizeExportArguments::new(
        amiga_operations::HunkNormalizeArguments::new(source_name.as_str()),
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_policy(output_policy(force));

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::AnalysisHunkNormalizeExport(arguments),
        &context,
        "normalization",
        |outcome| {
            outcome
                .analysis_hunk_normalize_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .analysis_hunk_normalize_export()
        .context("the normalization returned no result")?;

    row!(
        out,
        "Normalized {} hunk(s) and {} relocation(s) to {}",
        export.normalized.segments,
        export.normalized.relocations,
        output.display()
    );
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

/// Run `analysis.hunk.list` through the shared router and render its result.
pub(crate) fn hunk_list(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let list = hunk_listing(path)?;
    row!(out, "Hunks {}..={}", list.first_hunk, list.last_hunk);
    for segment in &list.segments {
        row!(
            out,
            "{:>3} {:<4} allocation={:#x} file_offset={:#x} file_size={:#x} relocations={}",
            segment.index,
            segment.kind,
            segment.allocation_bytes,
            segment.file_offset,
            segment.file_bytes,
            segment.relocation_total
        );
    }
    out.print()
}

/// The shared read behind `hunk list` and `xref relocs`.
///
/// Both asked the same question of the same image and answered it with two
/// separate parses. One request now; what differs is only which part of the
/// answer each command renders.
pub(crate) fn hunk_listing(path: &Path) -> Result<amiga_operations::HunkListResult> {
    let resolved = resolve_media_path(path)?;
    let (base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisHunkList(
                amiga_operations::HunkListArguments::new(name.as_str()),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to read {}", resolved.display()))?;
    let list = outcome
        .analysis_hunk_list()
        .context("the hunk listing returned no result")?
        .clone();
    print_warnings(&outcome);
    Ok(list)
}

// --- boot ------------------------------------------------------------------

/// Run `env.boot.info` through the shared router and render its result.
pub(crate) fn boot_info(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::EnvBootInfo(
                amiga_operations::BootInfoArguments::new(name.as_str()),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to read {}", resolved.display()))?;
    let info = outcome
        .env_boot_info()
        .context("the boot operation returned no result")?;

    row!(out, "Tag:       {:?}  flag {:#04x}", info.tag, info.flags);
    row!(
        out,
        "Checksum:  stored {:#010x}  {}",
        info.stored_checksum,
        if info.checksum_valid {
            "valid"
        } else {
            "INVALID"
        }
    );
    row!(out, "Root block: {}", info.root_block);
    row!(
        out,
        "Boot code:  {}",
        if info.has_boot_code {
            "present"
        } else {
            "none (all zero)"
        }
    );
    if !info.is_dos {
        row!(
            out,
            "Note: non-DOS tag — likely a custom-boot (trackloader) disk"
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Disassemble a boot block's code, annotated, from `analysis.code.facts`.
///
/// The boot region is a selector on the fact model rather than an operation of
/// its own: a boot block's code is not a hunk's, but the same question is asked
/// of it, and two fact models for one question is exactly what this migration
/// removes. The listing is rendered here from the facts and the instructions
/// the operation returned together.
pub(crate) fn boot_disasm(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeFacts(
                amiga_operations::CodeFactsArguments::new(name.as_str()).in_boot_block(),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to disassemble {}", resolved.display()))?;
    let facts = outcome
        .analysis_code_facts()
        .context("the fact composition returned no result")?;

    let resolver = Resolver::unmapped();
    row!(
        out,
        "; Boot code disassembly (offset 0 = bootblock+{}, A6 = ExecBase)",
        facts.code_offset
    );
    row!(out, "; Source: {}", path.display());
    row!(out, "; Source SHA-256: {}", facts.source.sha256);
    row!(out, "{ANNOTATION_LEGEND}");
    row!(out);
    // Appended to the same document rather than printed on its own. Printing
    // the listing first and the collected rows afterwards put this listing's
    // provenance header — what it is, which file, which digest, what the
    // annotation marks mean — *below* the several hundred lines it introduces,
    // and out of reach of anyone reading through `head`.
    part!(
        out,
        "{}",
        render_annotated(&facts.instructions, &facts.facts, &resolver, false)?
    );
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

// --- boot trace (dynamic) --------------------------------------------------

/// Run `env.boot.trace` — or its export half when `--output` names a directory
/// — through the shared router.
///
/// What stays here is the rendering and the fd tables that *name* an exec
/// vector. The manifest the export writes carries the structured stop reason
/// and the offsets, not the prose: a persisted record whose outcome came from
/// this frontend's configuration would differ between machines that ran the
/// same disk.
pub(crate) fn boot_trace(
    config_override: Option<&Path>,
    path: &Path,
    max_steps: usize,
    watch: &[String],
    watch_stop: bool,
    output: Option<&Path>,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let fd_names = config_fd_names(config_override)?;

    let arguments = amiga_operations::BootTraceArguments::new(source_name.as_str())
        .with_maximum_steps(max_steps)
        .watching(
            watch
                .iter()
                .map(|spec| parse_watchpoint(spec))
                .collect::<Result<Vec<_>>>()?,
            watch_stop,
        );
    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);

    let (trace, plan_digest) = match output {
        None => {
            let context =
                amiga_operations::ExecutionContext::new(&sources).with_limits(sandbox_limits());
            let outcome = amiga_operations::Router::execute(
                &amiga_operations::RequestEnvelope::read(
                    amiga_operations::OperationRequestDocument::EnvBootTrace(arguments),
                ),
                &context,
            );
            fail_on_errors(&outcome)
                .with_context(|| format!("failed to boot {}", resolved.display()))?;
            let trace = outcome
                .env_boot_trace()
                .context("the boot operation returned no result")?
                .clone();
            print_warnings(&outcome);
            (trace, None)
        }
        Some(directory) => {
            let (output_base, destination) = split_output_path(directory)?;
            let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
            let context = amiga_operations::ExecutionContext::new(&sources)
                .with_destinations(&destinations)
                .with_limits(sandbox_limits());
            let committed = commit_reviewed(
                amiga_operations::OperationRequestDocument::EnvBootTraceExport(
                    amiga_operations::BootTraceExportArguments::new(
                        arguments,
                        destination.as_str(),
                    )
                    .with_policy(output_policy(force)),
                ),
                &context,
                "boot trace",
                |outcome| {
                    outcome
                        .env_boot_trace_export()
                        .map(|export| export.plan.plan_sha256.clone())
                },
            )?;
            let export = committed
                .env_boot_trace_export()
                .context("the export operation returned no result")?;
            print_warnings(&committed);
            (export.trace.clone(), Some(export.plan.plan_sha256.clone()))
        }
    };

    row!(out, "; boot trace: {}", path.display());
    row!(out, "; Source SHA-256: {}", trace.source.sha256);
    row!(
        out,
        "; Boot block: tag {:?}{}, checksum {}",
        trace.boot.tag,
        if trace.boot.is_dos {
            ""
        } else {
            " (non-DOS trackloader)"
        },
        if trace.boot.checksum_valid {
            "valid"
        } else {
            "INVALID"
        }
    );
    row!(
        out,
        "; Environment: block@{:#x} entry {:#x}; A6=ExecBase {:#x}; A1=IORequest {:#x}; exec + trackdisk serviced, $DFF000 modelled",
        trace.load_address,
        trace.entry,
        trace.exec_base,
        trace.io_request
    );
    row!(out, ";");
    row!(out, "; {}", stop_reason_text(&trace.stop, &fd_names));
    row!(out, "; {} instruction(s) executed", trace.steps_executed);

    row!(out, ";");
    row!(
        out,
        "; custom-chip register writes ({}):",
        trace.chip_writes.len()
    );
    for write in &trace.chip_writes {
        row!(
            out,
            ";   {:#010x}  {:<9} <- {:#x}",
            write.address,
            write.register.as_deref().unwrap_or("?"),
            write.value
        );
    }

    row!(out, ";");
    row!(
        out,
        "; exec/library calls made ({}):",
        trace.exec_calls.len()
    );
    for call in &trace.exec_calls {
        let named = i16::try_from(call.offset)
            .ok()
            .and_then(|offset| lvo_display_name(&fd_names, &amiga_disasm::Library::Exec, offset))
            .map(|name| format!("  = exec.library/{name}"))
            .unwrap_or_default();
        row!(
            out,
            ";   {:#010x}  JSR ({},A6){named}",
            call.site,
            signed_hex(i16::try_from(call.offset).unwrap_or(0))
        );
    }

    if !trace.watch_hits.is_empty() {
        row!(out, ";");
        row!(out, "; watch hits ({}):", trace.watch_hits.len());
        for event in &trace.watch_hits {
            row!(
                out,
                ";   {}[{:#x}].{}  {:#x} -> {:#x}",
                event.access.as_str().to_uppercase(),
                event.address,
                size_suffix(event.size),
                event.before,
                event.after
            );
        }
    }

    row!(out, ";");
    row!(
        out,
        "; disk reads served: {} ({} bytes)",
        trace.served_reads.len(),
        trace.bytes_served
    );
    for read in &trace.served_reads {
        let note = if read.status == 0 { "" } else { " ERROR" };
        row!(
            out,
            ";   read {:>3}  {:<9} offset {:#09x}  {} / {} bytes  status {}{note}",
            read.index,
            read.command,
            read.offset,
            read.actual,
            read.requested,
            read.status
        );
    }

    if let Some(digest) = plan_digest {
        row!(out, ";");
        row!(out, "; Plan SHA-256: {digest}");
    }
    out.print()
}
