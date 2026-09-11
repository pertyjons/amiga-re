use super::*;

// --- iff -------------------------------------------------------------------

/// Describe an ILBM form, from `graphics.ilbm.decode`.
///
/// The operation returns what the form *is*; the columns, the palette dump, and
/// where the warnings go are this frontend's. A HAM or Extra-Halfbrite form is
/// refused by name inside the operation, so it arrives here as a failed outcome
/// rather than as a description with flat indices that would look plausible.
pub(crate) fn iff_image(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::GraphicsIlbmDecode(
                amiga_operations::IlbmDecodeArguments::new(name.as_str()),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to decode {} as ILBM", resolved.display()))?;
    let ilbm = outcome
        .graphics_ilbm_decode()
        .context("the ILBM decode returned no result")?;

    row!(
        out,
        "Image: {}x{}, {} plane(s), {} colour(s) indexable",
        ilbm.width,
        ilbm.height,
        ilbm.planes,
        ilbm.indexable_colours
    );
    row!(
        out,
        "Masking: {}",
        match ilbm.masking {
            amiga_operations::IlbmMasking::None => "none".to_owned(),
            amiga_operations::IlbmMasking::MaskPlane => "mask plane".to_owned(),
            amiga_operations::IlbmMasking::TransparentColour =>
                format!("transparent colour {}", ilbm.transparent_colour),
            amiga_operations::IlbmMasking::Lasso => "lasso".to_owned(),
        }
    );
    row!(out, "Aspect: {}:{}", ilbm.aspect[0], ilbm.aspect[1]);
    match ilbm.viewport_mode {
        Some(mode) => row!(out, "Viewport mode: {mode:#010x}"),
        None => row!(out, "Viewport mode: (no CAMG)"),
    }
    if ilbm.palette.is_empty() {
        row!(out, "Palette: none");
    } else {
        row!(out, "Palette: {} entry(ies)", ilbm.palette.len());
        for (index, colour) in ilbm.palette.iter().enumerate() {
            row!(
                out,
                "  {index:>3}  #{:02x}{:02x}{:02x}",
                colour[0],
                colour[1],
                colour[2]
            );
        }
    }
    // Tolerated inconsistencies go to standard error, so the description above
    // stays a clean summary when piped.
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

pub(crate) fn iff_samples(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let request = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AudioSampleDecode(
            amiga_operations::AudioSampleArguments::new(name.as_str()),
        ),
    );

    let outcome = amiga_operations::Router::execute(&request, &context);
    fail_on_errors(&outcome).with_context(|| format!("failed to read {}", resolved.display()))?;
    let sample = outcome
        .audio_sample_decode()
        .context("the sample operation returned no result")?;

    row!(out, "Name: {:?}", sample.name);
    row!(out, "Sample rate: {} Hz", sample.sample_rate);
    row!(out, "One-shot: {} samples", sample.one_shot_frames);
    row!(out, "Loop: {} samples", sample.loop_frames);
    row!(out, "Volume: {}", sample.volume);
    row!(out, "PCM: {} bytes", sample.frames);
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `audio.sample.export` through the shared router.
///
/// The convenience wrapper reviews on the user's behalf, as `adf extract` and
/// `diff --output` do: it prepares, then commits the plan it just built.
///
/// `output` names the WAV itself, not a directory to put one in — the same rule
/// as `carve`, `bitmap render`, `bob extract`, and the raw-PCM `sample to-wav`
/// next door. The request still spells a destination plus a file name within it;
/// taking the path apart here is what keeps that split from reaching the user.
pub(crate) fn iff_to_wav(path: &Path, output: &Path, force: bool) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;
    let policy = if force {
        amiga_operations::OutputPolicy::ReplaceMatchingProvenance
    } else {
        amiga_operations::OutputPolicy::CreateOnly
    };
    let arguments = amiga_operations::AudioSampleExportArguments::new(
        amiga_operations::AudioSampleArguments::new(name.as_str()),
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_policy(policy);

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let mut prepare = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AudioSampleExport(arguments.clone()),
    );
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    fail_on_errors(&prepared)
        .with_context(|| format!("failed to convert {}", resolved.display()))?;
    let plan = prepared
        .audio_sample_export()
        .context("the export operation produced no plan")?
        .plan
        .clone();

    let mut commit = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AudioSampleExport(arguments),
    );
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256.clone(),
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    fail_on_errors(&committed)
        .with_context(|| format!("failed to convert {}", resolved.display()))?;

    row!(out, "Wrote the WAV to {}", output.display());
    row!(out, "Plan SHA-256: {}", plan.plan_sha256);
    out.print()?;
    print_warnings(&prepared);
    Ok(())
}

// --- sample (raw Paula PCM) ------------------------------------------------

/// Report candidate raw-PCM regions, from `audio.pcm.scan`.
pub(crate) fn sample_scan(path: &Path, block: usize, min_len: usize) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AudioPcmScan(
                amiga_operations::PcmScanArguments::new(name.as_str())
                    .with_block(block)
                    .with_minimum_length(min_len),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to scan {}", resolved.display()))?;
    let scan = outcome
        .audio_pcm_scan()
        .context("the PCM scan returned no result")?;

    row!(
        out,
        "Found {} candidate PCM region(s) in {}",
        scan.region_total,
        path.display()
    );
    for region in &scan.regions {
        let end = region.offset.saturating_add(region.length);
        row!(
            out,
            "  {:#010x}..{end:#010x}  {} bytes  amp {:.1}  smoothness {:.2}",
            region.offset,
            region.length,
            region.mean_amplitude,
            region.smoothness
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `audio.pcm.export` through the shared router.
///
/// The region bounds and the rate are the request's, because raw Paula PCM
/// carries none of them: the operation echoes them back beside a digest of
/// exactly the bytes they selected, which is what makes a guess checkable.
pub(crate) fn sample_to_wav(
    path: &Path,
    output: &Path,
    offset: u32,
    length: u32,
    rate: u16,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let arguments = amiga_operations::PcmExportArguments::new(
        amiga_operations::PcmArguments::new(
            source_name.as_str(),
            offset as usize,
            length as usize,
            rate,
        ),
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_policy(output_policy(force));

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::AudioPcmExport(arguments),
        &context,
        "WAV export",
        |outcome| {
            outcome
                .audio_pcm_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .audio_pcm_export()
        .context("the export operation returned no result")?;

    row!(
        out,
        "Wrote {} sample(s) at {rate} Hz ({} bytes of WAV) to {}",
        export.pcm.frames,
        export.plan.files.first().map_or(0, |file| file.size),
        output.display()
    );
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

// --- mod -------------------------------------------------------------------

/// Report tracker modules found by signature, from `audio.module.scan`.
pub(crate) fn mod_scan(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AudioModuleScan(
                amiga_operations::ModuleScanArguments::new(name.as_str()),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to scan {}", resolved.display()))?;
    let scan = outcome
        .audio_module_scan()
        .context("the module scan returned no result")?;

    row!(
        out,
        "Found {} tracker module(s) in {}",
        scan.module_total,
        path.display()
    );
    for module in &scan.modules {
        row!(
            out,
            "  {:#010x}  {:<4} {}ch  {} patterns, {} samples, {} bytes  {:?}",
            module.offset,
            module.signature,
            module.channels,
            module.pattern_count,
            module.used_samples,
            module.total_length,
            module.title
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `audio.module.export` through the shared router.
///
/// The listing below is rendered from the operation's own result rather than
/// from a second parse, so what is printed describes the bytes that were
/// written. Only used slots are shown — the operation reports every slot,
/// because a tracker addresses samples by number and dropping the empty ones
/// would renumber the rest, but an empty slot is not worth a line here.
pub(crate) fn mod_extract(path: &Path, output: &Path, offset: u32, force: bool) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let arguments = amiga_operations::ModuleExportArguments::new(
        amiga_operations::ModuleArguments::new(source_name.as_str()).with_offset(offset as usize),
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_policy(output_policy(force));

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::AudioModuleExport(arguments),
        &context,
        "module extraction",
        |outcome| {
            outcome
                .audio_module_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .audio_module_export()
        .context("the export operation returned no result")?;
    let module = &export.module;

    row!(
        out,
        "Module {:?} ({} {}ch, {} patterns, {} bytes)",
        module.title,
        module.signature,
        module.channels,
        module.pattern_count,
        module.total_bytes
    );
    for sample in module.samples.iter().filter(|sample| sample.length > 0) {
        row!(
            out,
            "  sample {:>2}: {:<22} {:>6} bytes  vol {:>2}  loop {:#x}+{:#x}",
            sample.slot,
            format!("{:?}", sample.name),
            sample.length,
            sample.volume,
            sample.repeat_start,
            sample.repeat_length
        );
    }
    row!(
        out,
        "Extracted {} bytes to {}",
        module.total_bytes,
        output.display()
    );
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

// --- unpack ----------------------------------------------------------------

pub(crate) fn parse_modes(modes: &str) -> Result<[u8; 4]> {
    let values = modes
        .split(',')
        .map(|value| value.trim().parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("invalid mode table {modes:?}"))?;
    <[u8; 4]>::try_from(values.as_slice())
        .map_err(|_| anyhow::anyhow!("mode table must have exactly four entries"))
}

/// Run `compress.powerpacker.export` through the shared router.
///
/// The convenience wrapper reviews on the user's behalf, as every other export
/// does: it prepares, prints the plan, and commits the plan it just showed. This
/// used to decode and `fs::write` in place, so the plan digest a user is meant
/// to review did not exist for it.
pub(crate) fn unpack_powerpacker(
    input: &Path,
    output: &Path,
    modes: &str,
    maximum_output_bytes: Option<u64>,
    force: bool,
) -> Result<()> {
    let modes = parse_modes(modes)?;
    unpack(
        input,
        output,
        force,
        |source, destination, file_name, policy| {
            let mut decode = amiga_operations::PowerpackerArguments::new(source, modes);
            if let Some(bytes) = maximum_output_bytes {
                decode = decode.with_maximum_output_bytes(bytes);
            }
            amiga_operations::OperationRequestDocument::CompressPowerpackerExport(
                amiga_operations::PowerpackerExportArguments::new(decode, destination)
                    .with_file_name(file_name)
                    .with_policy(policy),
            )
        },
    )
}

/// Run `compress.rle-xor.export` through the shared router.
pub(crate) fn unpack_rle_xor(
    input: &Path,
    output: &Path,
    layout: &crate::RleXorArgs,
    force: bool,
) -> Result<()> {
    let marker =
        u8::try_from(layout.marker).map_err(|_| anyhow::anyhow!("--marker must be a byte"))?;
    unpack(
        input,
        output,
        force,
        |source, destination, file_name, policy| {
            let mut decode = amiga_operations::RleXorArguments::new(source, marker)
                .with_xor(!layout.no_xor)
                .with_inline_marker(layout.inline_marker)
                .with_size_field(layout.size_bytes, layout.size_includes_field);
            if let Some(bytes) = layout.maximum_output_bytes {
                decode = decode.with_maximum_output_bytes(bytes);
            }
            amiga_operations::OperationRequestDocument::CompressRleXorExport(
                amiga_operations::RleXorExportArguments::new(decode, destination)
                    .with_file_name(file_name)
                    .with_policy(policy),
            )
        },
    )
}

/// The prepare-and-commit both `unpack` commands share.
///
/// The two differ only in which request document names the codec, so the review
/// dance is written once: two copies of it is how two commands end up
/// disagreeing about when a plan is stale.
fn unpack(
    input: &Path,
    output: &Path,
    force: bool,
    request: impl FnOnce(
        &str,
        &str,
        String,
        amiga_operations::OutputPolicy,
    ) -> amiga_operations::OperationRequestDocument,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(input)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;
    let document = request(
        source_name.as_str(),
        destination.as_str(),
        file_name,
        output_policy(force),
    );

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let committed = commit_reviewed(document, &context, "decompression", |outcome| {
        outcome
            .compress_export()
            .map(|export| export.plan.plan_sha256.clone())
    })?;
    let export = committed
        .compress_export()
        .context("the export operation returned no result")?;

    row!(
        out,
        "Decoded {} bytes from {} to {}",
        export.decoded.decoded_bytes,
        resolved.display(),
        output.display()
    );
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    // The declared-size disagreement the codec reports arrives as a warning
    // diagnostic now, so it is printed by the same path as every other warning
    // rather than by an `eprintln!` this command kept to itself.
    out.print()?;
    print_warnings(&committed);
    Ok(())
}
