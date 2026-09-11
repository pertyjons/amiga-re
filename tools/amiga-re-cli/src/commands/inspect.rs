use super::*;

// --- survey -----------------------------------------------------------------

/// Run `source.survey` through the shared operation router and render its
/// typed result.
///
/// The request names the source by file name only; the directory it lives in is
/// the adapter's own and reaches the router as a resolver root, so nothing that
/// crosses the API carries a host path.
pub(crate) fn survey(
    path: &Path,
    min_string: usize,
    max_input_bytes: Option<u64>,
    max_regions: Option<usize>,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;

    let mut arguments = amiga_operations::SourceSurveyArguments::new(name.as_str())
        .with_minimum_string_length(min_string);
    if let Some(bytes) = max_input_bytes {
        arguments = arguments.with_maximum_input_bytes(bytes);
    }
    if let Some(regions) = max_regions {
        arguments = arguments.with_maximum_regions(regions);
    }

    // A request may raise a limit only up to what this context allows, so give
    // the command-line adapter a ceiling that matches what a request may ask
    // for: an interactive user with a large image is not a threat model.
    let limits = amiga_operations::OperationLimits::default()
        .with_maximum_input_bytes(
            max_input_bytes.unwrap_or(amiga_operations::limits::DEFAULT_MAXIMUM_INPUT_BYTES),
        )
        .with_maximum_regions(
            max_regions.unwrap_or(amiga_operations::limits::DEFAULT_MAXIMUM_REGIONS),
        );

    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver).with_limits(limits);
    let request = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::SourceSurvey(arguments),
    );

    let outcome = amiga_operations::Router::execute(&request, &context);
    fail_on_errors(&outcome).with_context(|| format!("failed to survey {}", resolved.display()))?;
    let survey = outcome
        .source_survey()
        .context("the survey operation returned no result")?;

    row!(
        out,
        "Survey of {} ({} bytes):",
        resolved.display(),
        survey.source.size
    );
    for region in &survey.regions {
        row!(
            out,
            "  {:#010x}..{:#010x}  {:<14} {}",
            region.start,
            region.end,
            region.kind.as_str(),
            region.detail
        );
    }
    if survey.regions_truncated {
        row!(
            out,
            "  ... {} of {} regions shown",
            survey.regions.len(),
            survey.region_total
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

// --- diff ------------------------------------------------------------------

/// Bytes of a changed range shown per side before truncating.
const DIFF_RANGE_CAP: usize = 64;

/// Disassemble a word-aligned window of `bytes` covering `[start, end)`,
/// extending the end by up to 16 bytes so a straddling instruction still fits.
/// Returns `None` when the bytes do not decode (then the caller shows hex).
fn disasm_window(bytes: &[u8], start: u32, end: u32) -> Option<String> {
    let aligned_start = start & !1;
    let limit = u32::try_from(bytes.len()).ok()?;
    for extra in (0..=16).step_by(2) {
        let candidate_end = end.saturating_add(extra).min(limit);
        if candidate_end <= aligned_start {
            return None;
        }
        match amiga_disasm::linear(bytes, aligned_start, candidate_end) {
            Ok(listing) => return Some(listing),
            Err(amiga_disasm::DisasmError::RunsPastEnd { .. }) => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Print one side's view of a changed range: a disassembly when it is code and
/// decodes, else a hex line. Both are capped at [`DIFF_RANGE_CAP`] bytes.
fn print_range_side(
    out: &mut Document,
    label: char,
    bytes: &[u8],
    range: amiga_hunk::ByteRange,
    is_code: bool,
) {
    let start = range.start as usize;
    let end = (start + range.len as usize).min(bytes.len());
    let shown = end.min(start + DIFF_RANGE_CAP);
    let more = end.saturating_sub(shown);
    let suffix = if more > 0 {
        format!(" (+{more} more byte(s))")
    } else {
        String::new()
    };
    // Cap the disassembly window at the same byte budget as the hex view.
    let window_end = u32::try_from(shown).unwrap_or(range.end());
    if is_code && let Some(listing) = disasm_window(bytes, range.start, window_end) {
        row!(out, "    {label}:");
        for line in listing.lines() {
            row!(out, "      {line}");
        }
        if more > 0 {
            row!(out, "      … (+{more} more byte(s))");
        }
        return;
    }
    let slice = bytes.get(start..shown).unwrap_or(&[]);
    row!(out, "    {label}: {}{suffix}", hex::encode(slice));
}

/// The `CODE, 0x1234 bytes` style description of a hunk on one side.
fn hunk_side_desc(kind: Option<&str>, allocation: Option<u64>) -> String {
    match (kind, allocation) {
        (Some(kind), Some(size)) => format!("{kind}, {size:#x} bytes"),
        _ => "absent".to_owned(),
    }
}

/// Compare two HUNK executables through `analysis.hunk.diff`.
///
/// With `--output`, `analysis.hunk.diff.export` writes the comparison as a report. The
/// write uses the shared review plan, provenance manifest, and overwrite policy so
/// automation does not need to scrape human-readable output.
///
/// The byte-level context under each changed range stays here, because it is
/// presentation: the operation answers *what* differs, and this renders the
/// bytes and the disassembly around it.
pub(crate) fn diff(
    path_a: &Path,
    path_b: &Path,
    output: Option<&Path>,
    format: DiffFormat,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let canonical_a =
        fs::canonicalize(path_a).with_context(|| format!("failed to open {}", path_a.display()))?;
    let canonical_b =
        fs::canonicalize(path_b).with_context(|| format!("failed to open {}", path_b.display()))?;
    let (base, names) = amiga_operations::split_host_paths(&[&canonical_a, &canonical_b])
        .with_context(|| {
            format!(
                "{} and {} cannot both be named under one root",
                path_a.display(),
                path_b.display()
            )
        })?;
    let arguments = amiga_operations::HunkDiffArguments::new(names[0].as_str(), names[1].as_str());
    let sources = amiga_operations::FilesystemSourceResolver::new(base);

    if let Some(destination) = output {
        return export_diff(&sources, arguments, destination, format, force);
    }

    let context = amiga_operations::ExecutionContext::new(&sources);
    let request = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AnalysisHunkDiff(arguments),
    );
    let outcome = amiga_operations::Router::execute(&request, &context);
    fail_on_errors(&outcome).with_context(|| {
        format!(
            "failed to compare {} and {}",
            path_a.display(),
            path_b.display()
        )
    })?;
    let result = outcome
        .analysis_hunk_diff()
        .context("the comparison operation returned no result")?;

    row!(out, "diff A={} B={}", path_a.display(), path_b.display());
    row!(out, "  A SHA-256: {}", result.a.sha256);
    row!(out, "  B SHA-256: {}", result.b.sha256);
    if result.identical {
        row!(out, "images are structurally identical");
        out.print()?;
        print_warnings(&outcome);
        return Ok(());
    }

    // Re-read for the byte context only. The comparison itself is the
    // operation's; this is the rendering of the ranges it reported.
    let bytes_a = load(path_a)?;
    let bytes_b = load(path_b)?;
    let exe_a = amiga_hunk::Executable::parse(&bytes_a)?;
    let exe_b = amiga_hunk::Executable::parse(&bytes_b)?;

    for hunk in result.hunks.iter().filter(|hunk| !hunk.unchanged) {
        match hunk.presence {
            amiga_operations::HunkPresence::OnlyA => {
                row!(
                    out,
                    "hunk {}: present only in A ({})",
                    hunk.index,
                    hunk_side_desc(hunk.kind_a.as_deref(), hunk.allocation_a)
                );
                continue;
            }
            amiga_operations::HunkPresence::OnlyB => {
                row!(
                    out,
                    "hunk {}: present only in B ({})",
                    hunk.index,
                    hunk_side_desc(hunk.kind_b.as_deref(), hunk.allocation_b)
                );
                continue;
            }
            amiga_operations::HunkPresence::Both => {}
        }

        row!(
            out,
            "hunk {}: {} changed range(s), +{} / -{} relocation(s)",
            hunk.index,
            hunk.changed_range_total,
            hunk.added_relocations.len(),
            hunk.removed_relocations.len()
        );
        if hunk.kind_a != hunk.kind_b {
            row!(
                out,
                "  kind {} -> {}",
                hunk.kind_a.as_deref().unwrap_or("?"),
                hunk.kind_b.as_deref().unwrap_or("?")
            );
        }
        if hunk.allocation_a != hunk.allocation_b {
            row!(
                out,
                "  allocation {} -> {}",
                hunk.allocation_a
                    .map_or("?".to_owned(), |size| format!("{size:#x}")),
                hunk.allocation_b
                    .map_or("?".to_owned(), |size| format!("{size:#x}"))
            );
        }

        let is_code =
            hunk.kind_a.as_deref() == Some("CODE") && hunk.kind_b.as_deref() == Some("CODE");
        let seg_a = exe_a.segment(hunk.index).map(|segment| segment.bytes);
        let seg_b = exe_b.segment(hunk.index).map(|segment| segment.bytes);
        for reported in &hunk.changed_ranges {
            let range = amiga_hunk::ByteRange {
                start: reported.start,
                len: reported.length,
            };
            row!(
                out,
                "  [{:#x}..{:#x})  {} byte(s)",
                range.start,
                range.end(),
                range.len
            );
            if let Some(bytes) = seg_a {
                print_range_side(&mut out, 'A', bytes, range, is_code);
            }
            if let Some(bytes) = seg_b {
                print_range_side(&mut out, 'B', bytes, range, is_code);
            }
        }
        if hunk.changed_ranges_truncated {
            row!(
                out,
                "  ... {} further changed range(s) are not listed",
                hunk.changed_range_total - hunk.changed_ranges.len()
            );
        }
        for relocation in &hunk.added_relocations {
            row!(
                out,
                "  + reloc {:#x} -> hunk{}",
                relocation.source_offset,
                relocation.target_hunk
            );
        }
        for relocation in &hunk.removed_relocations {
            row!(
                out,
                "  - reloc {:#x} -> hunk{}",
                relocation.source_offset,
                relocation.target_hunk
            );
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Which rendering an exported comparison uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DiffFormat {
    /// The structured report another program reads.
    #[default]
    Json,
    /// The rendered report a person reads.
    Text,
}

impl DiffFormat {
    const fn operation_format(self) -> amiga_operations::HunkDiffFormat {
        match self {
            Self::Json => amiga_operations::HunkDiffFormat::Json,
            Self::Text => amiga_operations::HunkDiffFormat::Text,
        }
    }
}

/// Prepare and commit `analysis.hunk.diff.export`.
///
/// The convenience wrapper reviews on the user's behalf, exactly as `adf
/// extract` does: it prepares, shows what would be written, and commits the
/// plan it just showed. Automation drives the same two halves separately.
///
/// `--output` names the report file, not a directory to drop one in, so a
/// command line that writes one file reads the same here as everywhere else.
fn export_diff(
    sources: &amiga_operations::FilesystemSourceResolver,
    arguments: amiga_operations::HunkDiffArguments,
    destination: &Path,
    format: DiffFormat,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let (output_base, output_destination, file_name) = split_destination_file(destination)?;
    let policy = if force {
        amiga_operations::OutputPolicy::ReplaceMatchingProvenance
    } else {
        amiga_operations::OutputPolicy::CreateOnly
    };
    let arguments =
        amiga_operations::HunkDiffExportArguments::new(arguments, output_destination.as_str())
            .with_file_name(file_name)
            .with_format(format.operation_format())
            .with_policy(policy);

    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context = amiga_operations::ExecutionContext::new(sources).with_destinations(&destinations);

    let mut prepare = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AnalysisHunkDiffExport(arguments.clone()),
    );
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    fail_on_errors(&prepared).context("failed to prepare the comparison report")?;
    let plan = prepared
        .analysis_hunk_diff_export()
        .context("the export operation produced no plan")?
        .plan
        .clone();

    let mut commit = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AnalysisHunkDiffExport(arguments),
    );
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256.clone(),
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    fail_on_errors(&committed).context("failed to write the comparison report")?;

    row!(out, "Wrote the comparison to {}", destination.display());
    row!(out, "Plan SHA-256: {}", plan.plan_sha256);
    out.print()?;
    print_warnings(&prepared);
    Ok(())
}

// --- dump ------------------------------------------------------------------

/// Resolve an absolute address to a file/hunk offset through `base`, erroring if
/// no base is available or the address is below the mapped origin.
pub(crate) fn resolve_abs(base: Option<amiga_core::config::Base>, offset: u32) -> Result<u32> {
    let base = base.context("--address needs a base (pass --base or set config [base])")?;
    base.abs_to_offset(offset).with_context(|| {
        format!(
            "address {offset:#x} is below the mapped origin {:#x}",
            base.origin
        )
    })
}

/// A hex-and-ASCII view of a window, from `source.read`.
///
/// The columns, the address frame, and the relocation marking are display, and
/// stay here. The bytes and the relocation sites under them are not the
/// frontend's to fetch — which is the last place a command reached a domain
/// crate for *data*.
pub(crate) fn dump(
    config_override: Option<&Path>,
    path: &Path,
    offset: u32,
    length: u32,
    hunk: Option<u32>,
    address: bool,
    base_args: &BaseArgs,
) -> Result<()> {
    let mut out = Document::new();
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = base_args.resolve(config.as_ref());
    // Which frame `--offset` is in is this frontend's convention, so the
    // conversion happens here and the request carries a plain offset.
    let (read_offset, display_start) = if address {
        (resolve_abs(base, offset)?, u64::from(offset))
    } else {
        (offset, u64::from(offset))
    };

    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments =
        amiga_operations::SourceReadArguments::new(name.as_str()).window(read_offset, length);
    if let Some(index) = hunk {
        arguments = arguments.in_hunk(index);
    }
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::SourceRead(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to read {}", resolved.display()))?;
    let read = outcome
        .source_read()
        .context("the read returned no result")?;
    let region = decode_hex(&read.bytes)?;

    let header = match (hunk, address) {
        (Some(index), true) => format!(
            "; dump {} hunk {index} @ abs {offset:#x}  {} bytes",
            path.display(),
            read.length
        ),
        (Some(index), false) => format!(
            "; dump {} hunk {index} @ hunk-rel {offset:#x}  {} bytes",
            path.display(),
            read.length
        ),
        (None, true) => format!(
            "; dump {} @ abs {offset:#x} (file {read_offset:#x})  {} bytes",
            path.display(),
            read.length
        ),
        (None, false) => format!(
            "; dump {} @ file {offset:#x}  {} bytes",
            path.display(),
            read.length
        ),
    };
    let sites: Vec<usize> = read
        .relocation_sites
        .iter()
        .map(|site| *site as usize)
        .collect();

    row!(out, "{header}");
    part!(
        out,
        "{}",
        amiga_core::hexdump::render(&region, display_start, &sites)
    );
    out.print()
}

// --- config ----------------------------------------------------------------

/// Load the config named by `--config`, or discovered upward from the CWD.
/// Returns `None` only when neither is present (an explicit `--config` that
/// cannot be read is an error).
pub(crate) fn optional_config(
    override_path: Option<&Path>,
) -> Result<Option<(PathBuf, amiga_core::Config)>> {
    let path = match override_path {
        Some(path) => Some(path.to_path_buf()),
        None => {
            let cwd = std::env::current_dir().context("failed to read the current directory")?;
            amiga_core::config::discover(&cwd)
        }
    };
    match path {
        Some(path) => {
            let config = amiga_core::Config::load(&path)?;
            Ok(Some((path, config)))
        }
        None => Ok(None),
    }
}

pub(crate) fn resolve_config(
    override_path: Option<&Path>,
) -> Result<(PathBuf, amiga_core::Config)> {
    optional_config(override_path)?
        .context("no amiga-re.toml found in the current directory or its parents")
}

pub(crate) fn config_show(override_path: Option<&Path>) -> Result<()> {
    let mut out = Document::new();
    let (path, config) = resolve_config(override_path)?;
    row!(out, "Config: {}", path.display());
    if let Some(name) = &config.project.name {
        row!(out, "Project: {name}");
    }
    if let Some(output) = &config.project.output {
        row!(out, "Output: {}", output.display());
    }
    if !config.media.is_empty() {
        row!(out, "Media:");
        for media in &config.media {
            match &media.sha256 {
                Some(hash) => {
                    row!(
                        out,
                        "  {:<12} {}  sha256={hash}",
                        media.name,
                        media.path.display()
                    )
                }
                None => row!(out, "  {:<12} {}", media.name, media.path.display()),
            }
        }
    }
    if let Some(base) = &config.base {
        part!(out, "Base: origin={:#x}", base.origin);
        if let Some(entry) = base.entry {
            part!(out, " entry={entry:#x}");
        }
        row!(out);
    }
    if let Some(bitmap) = &config.bitmap {
        row!(
            out,
            "Bitmap: {}x{} {} planes, {} palette color(s)",
            bitmap.width,
            bitmap.height,
            bitmap.planes,
            bitmap.palette.len()
        );
    }
    if !config.symbols.is_empty() {
        row!(out, "Symbols: {}", config.symbols.len());
        for symbol in &config.symbols {
            row!(out, "  {:#010x} {}", symbol.addr, symbol.name);
        }
    }
    out.print()
}

pub(crate) fn config_check(override_path: Option<&Path>) -> Result<()> {
    let mut out = Document::new();
    let (path, config) = resolve_config(override_path)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut checked = 0;
    let mut failures = 0;
    for media in &config.media {
        let Some(expected) = &media.sha256 else {
            row!(
                out,
                "  {:<12} (no pinned hash)  {}",
                media.name,
                media.path.display()
            );
            continue;
        };
        checked += 1;
        let media_path = directory.join(&media.path);
        match fs::read(&media_path) {
            Ok(bytes) => {
                let actual = sha256(&bytes);
                if actual.eq_ignore_ascii_case(expected) {
                    row!(
                        out,
                        "  {:<12} OK        {}",
                        media.name,
                        media.path.display()
                    );
                } else {
                    failures += 1;
                    row!(
                        out,
                        "  {:<12} MISMATCH  {}",
                        media.name,
                        media.path.display()
                    );
                    row!(out, "    expected {expected}");
                    row!(out, "    actual   {actual}");
                }
            }
            Err(error) => {
                failures += 1;
                row!(
                    out,
                    "  {:<12} MISSING   {} ({error})",
                    media.name,
                    media.path.display()
                );
            }
        }
    }
    out.print()?;
    if failures > 0 {
        bail!("{failures} of {checked} pinned media file(s) failed verification");
    }
    row!(
        out,
        "Verified {checked} pinned media file(s) against {}",
        path.display()
    );
    out.print()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_archive_path_retains_only_validated_hierarchy() {
        // Backslash is a separator on some platforms and must be rejected so the
        // on-disk name and the `/`-normalized manifest name cannot diverge. LHA
        // normalizes its format-specific spelling before this boundary.
        assert!(safe_archive_path("a\\b").is_err());
        assert!(safe_archive_path("../secret").is_err());
        assert!(safe_archive_path("/abs").is_err());
        assert!(safe_archive_path("a//b").is_err());
        assert!(safe_archive_path("vol:file").is_err());
        let path = safe_archive_path("dir/file.bin").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, PathBuf::from("dir").join("file.bin"));
    }
}
