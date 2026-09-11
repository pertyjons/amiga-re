use super::*;

// --- strings ---------------------------------------------------------------

/// Run `analysis.strings.scan` through the shared router and render its result.
///
/// The `--contains` filter goes into the request rather than being applied to
/// the answer: filtering a capped list would drop matches the scan found and
/// the cap discarded, and nothing in the output would say so.
pub(crate) fn strings_dump(
    path: &Path,
    min: usize,
    hunk: Option<u32>,
    contains: Option<&str>,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments =
        amiga_operations::StringsScanArguments::new(name.as_str()).with_minimum_length(min);
    if let Some(index) = hunk {
        arguments = arguments.in_hunk(index);
    }
    if let Some(needle) = contains {
        arguments = arguments.containing(needle);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisStringsScan(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to scan {}", resolved.display()))?;
    let scan = outcome
        .analysis_strings_scan()
        .context("the string scan returned no result")?;

    for string in &scan.strings {
        row!(out, "{:08x}  {}", string.offset, string.text);
    }
    if scan.strings_truncated {
        row!(
            out,
            "... {} of {} string(s) shown",
            scan.strings.len(),
            scan.string_total
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Report candidate pointer tables, from `analysis.pointers.scan`.
///
/// The seeds `--seed-flow` analyzes from are the operation's `entry_offsets`
/// rather than something derived here from the printed targets: those lists are
/// capped, and seeding from a capped list would analyze less of the hunk the
/// larger the answer got.
pub(crate) fn scan_pointers(
    config_override: Option<&Path>,
    path: &Path,
    hunk: u32,
    minimum: usize,
    word_scale: Option<u32>,
    seed_flow: bool,
    base_args: &BaseArgs,
) -> Result<()> {
    let mut out = Document::new();
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = base_args.resolve(config.as_ref());
    let origin = base.map_or(0, |base| base.origin);

    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments = amiga_operations::PointerScanArguments::new(name.as_str())
        .in_hunk(hunk)
        .mapped_at(origin)
        .with_minimum_entries(minimum);
    if let Some(scale) = word_scale {
        arguments = arguments.with_word_scale(scale);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisPointersScan(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to scan {}", resolved.display()))?;
    let scan = outcome
        .analysis_pointers_scan()
        .context("the pointer scan returned no result")?;

    if scan.tables.is_empty() {
        row!(out, "no pointer tables found");
        out.print()?;
        print_warnings(&outcome);
        return Ok(());
    }
    for table in &scan.tables {
        row!(
            out,
            "  {:#010x}  {} x{}  targets {:#010x}..={:#010x}",
            table.offset,
            match table.encoding {
                amiga_operations::PointerEncoding::Long => "u32",
                amiga_operations::PointerEncoding::ScaledWord => "u16-scaled",
            },
            table.target_total,
            table.target_lowest,
            table.target_highest
        );
    }
    if scan.tables_truncated {
        row!(
            out,
            "... {} of {} table(s) shown",
            scan.tables.len(),
            scan.table_total
        );
    }

    // Printed before delegating, because `seed_flow_from` prints a listing of
    // its own: the table is what the seeds were taken from and belongs above
    // them.
    out.print()?;
    if seed_flow {
        seed_flow_from(path, hunk, base, &scan.entry_offsets)?;
    }
    print_warnings(&outcome);
    Ok(())
}

/// Analyze a CODE hunk from every discovered target as an additional entry.
///
/// Still reaching for `amiga-disasm` directly: the disassembly this renders is
/// `analysis.code.disassemble`'s to answer, and it does not exist yet. Kept in
/// its own function so the one remaining direct call is visible rather than
/// buried in the middle of a routed command.
fn seed_flow_from(
    path: &Path,
    hunk: u32,
    base: Option<amiga_core::config::Base>,
    entries: &[u32],
) -> Result<()> {
    let mut out = Document::new();
    let bytes = load(path)?;
    let executable = amiga_hunk::Executable::parse(&bytes)?;
    let segment = executable
        .segment(hunk)
        .with_context(|| format!("hunk {hunk} does not exist"))?;
    if segment.kind != amiga_hunk::SegmentKind::Code {
        bail!(
            "--seed-flow requires a CODE hunk (hunk {hunk} is {})",
            segment.kind
        );
    }
    let relocations = prepared_relocations(&executable, hunk);
    let options = amiga_disasm::FlowOptions {
        rebase: base.map(|base| amiga_disasm::Rebase::new(base.origin)),
        relocations: Some(flow_relocations(hunk, &relocations)),
    };
    let analysis = amiga_disasm::analyze_entries_with(segment.bytes, entries, &options);
    let coverage = amiga_disasm::coverage(&analysis, segment.bytes.len());
    row!(
        out,
        "seeded flow: {} entries, {} instructions, {} functions, {}/{} bytes ({:.2}%)",
        entries.len(),
        coverage.instructions,
        coverage.functions,
        coverage.decoded_bytes,
        coverage.total_bytes,
        coverage.percent()
    );
    row!(out);
    part!(out, "{}", amiga_disasm::render(segment.bytes, &analysis)?);
    out.print()
}

// --- disasm ----------------------------------------------------------------

pub(crate) fn code_hunk<'a>(
    executable: &'a amiga_hunk::Executable<'a>,
    hunk: u32,
) -> Result<&'a amiga_hunk::Segment<'a>> {
    let segment = executable
        .segment(hunk)
        .with_context(|| format!("hunk {hunk} does not exist"))?;
    if segment.kind != amiga_hunk::SegmentKind::Code {
        bail!("hunk {hunk} is {}, not CODE", segment.kind);
    }
    Ok(segment)
}

/// The default single entry point (offset 0) when none was supplied.
pub(crate) fn entries_or_default(entries: &[u32]) -> &[u32] {
    if entries.is_empty() { &[0] } else { entries }
}

/// The shared setup every entry-point analysis needs: the file loaded, its CODE
/// hunk located, config resolved, and control flow traced from the (possibly
/// rebased) entry points. Produced by [`prepare_code_analysis`].
pub(crate) struct Prepared {
    /// The whole source file.
    pub(crate) bytes: Vec<u8>,
    /// Human-readable source identity for listing headers and errors.
    source_label: String,
    /// Whether `bytes` are a HUNK container or a pinned raw image.
    region: amiga_operations::CodeRegion,
    /// The explicit pin required for a raw image.
    expected_sha256: Option<String>,
    /// Index of the analyzed hunk.
    hunk: u32,
    /// The analyzed CODE hunk, as a sub-range of `bytes`.
    code_range: Range<usize>,
    pub(crate) config: Option<amiga_core::Config>,
    /// Directory of the resolved config file, for config-relative paths.
    pub(crate) config_dir: Option<PathBuf>,
    /// The resolved config file itself, so a report can pin it by content.
    pub(crate) config_path: Option<PathBuf>,
    /// Reviewed names from the project describing these exact bytes, when one
    /// does. The config table is the fallback, not the only source.
    pub(crate) names: Option<crate::commands::ProjectNames>,
    /// The same records indexed for operand resolution, built once so the
    /// traversal and every later composition read one index.
    flow_relocations: amiga_disasm::Relocations,
    /// The resolved mapped origin/default entry (flags override config), if any.
    pub(crate) base: Option<amiga_core::config::Base>,
    /// Entry points in file-offset space.
    pub(crate) entries: Vec<u32>,
    pub(crate) analysis: amiga_disasm::ControlFlowAnalysis,
}

impl Prepared {
    /// What the analysis read, as a display identity rather than a host path.
    pub(crate) fn source_label(&self) -> &str {
        &self.source_label
    }

    /// The bytes of the analyzed code region.
    pub(crate) fn code(&self) -> &[u8] {
        &self.bytes[self.code_range.clone()]
    }

    /// Index of the analyzed hunk.
    pub(crate) const fn hunk(&self) -> u32 {
        self.hunk
    }

    pub(crate) const fn region(&self) -> amiga_operations::CodeRegion {
        self.region
    }

    pub(crate) fn expected_sha256(&self) -> Option<&str> {
        self.expected_sha256.as_deref()
    }

    /// The analyzed hunk's relocations, indexed for operand resolution.
    pub(crate) const fn flow_relocations(&self) -> &amiga_disasm::Relocations {
        &self.flow_relocations
    }

    /// Checked conversions between the analyzed code region's offsets, the whole-file
    /// offsets they were read from, and the addresses they are mapped at.
    ///
    /// A code region longer than the 32-bit offset space this toolkit addresses is
    /// clamped to `u32::MAX`, which is the conservative direction: every
    /// offset that can be named does lie inside such a region.
    pub(crate) fn address_map(&self) -> amiga_core::AddressMap {
        let size = u32::try_from(self.code_range.len()).unwrap_or(u32::MAX);
        let mut map = amiga_core::AddressMap::new(amiga_core::HunkId::new(self.hunk), size);
        if let Ok(start) = u64::try_from(self.code_range.start) {
            map = map.with_file_start(amiga_core::FileOffset::new(start));
        }
        if let Some(base) = self.base {
            map = map.with_origin(amiga_core::RuntimeAddress::new(base.origin));
        }
        map
    }
}

/// A relocation of the analyzed hunk, with its stored pointer resolved.
pub(crate) struct PreparedRelocation {
    pub(crate) source_offset: u32,
    pub(crate) target_hunk: u32,
    /// The stored pointer's offset into the target hunk; `None` when the
    /// stored longword could not be read.
    pub(crate) target_offset: Option<u32>,
}

/// The relocations patching `hunk`, with each stored pointer resolved once so
/// no later pass re-reads the executable for it.
fn prepared_relocations(
    executable: &amiga_hunk::Executable<'_>,
    hunk: u32,
) -> Vec<PreparedRelocation> {
    executable
        .relocations
        .iter()
        .filter(|relocation| relocation.source_hunk == hunk)
        .map(|relocation| PreparedRelocation {
            source_offset: relocation.source_offset,
            target_hunk: relocation.target_hunk,
            target_offset: executable.stored_pointer(relocation),
        })
        .collect()
}

/// The relocations the traversal can read an absolute operand through: those
/// whose stored longword was readable, so the record names an actual target.
/// A record whose pointer could not be read proves nothing about where the
/// operand points, and the traversal must not act on it.
fn flow_relocations(hunk: u32, relocations: &[PreparedRelocation]) -> amiga_disasm::Relocations {
    amiga_disasm::Relocations::new(
        hunk,
        relocations
            .iter()
            .filter_map(|relocation| {
                Some(amiga_disasm::Relocation {
                    patched: relocation.source_offset,
                    target_hunk: relocation.target_hunk,
                    target_offset: relocation.target_offset?,
                })
            })
            .collect::<Vec<_>>(),
    )
}

struct PreparedBytes {
    bytes: Vec<u8>,
    source_label: String,
    region: amiga_operations::CodeRegion,
    expected_sha256: Option<String>,
    hunk: u32,
    code_range: Range<usize>,
    relocations: Vec<PreparedRelocation>,
    project_origin: Option<u32>,
    project_entries: Option<Vec<u32>>,
    project_root: Option<PathBuf>,
}

fn parse_project_address(text: &str) -> Result<u32> {
    let hex = text
        .strip_prefix("0x")
        .with_context(|| format!("project address {text:?} has no 0x prefix"))?;
    u32::from_str_radix(hex, 16)
        .with_context(|| format!("project address {text:?} is not a 32-bit hexadecimal value"))
}

fn project_root() -> Result<PathBuf> {
    let selected = match crate::project_override() {
        Some(root) => root.to_path_buf(),
        None => {
            let cwd = std::env::current_dir().context("could not read the current directory")?;
            amiga_project::discover(&cwd).context(
                "--image needs a project; pass --project DIR or run below a project directory",
            )?
        }
    };
    Ok(crate::project_directory(&selected))
}

fn prepare_project_image(
    image_id: &str,
    load_map_id: Option<&str>,
    hunk: u32,
) -> Result<PreparedBytes> {
    if hunk != 0 {
        bail!("a raw project image has no hunk {hunk}; omit --hunk or use 0");
    }
    let root = project_root()?;
    let loaded = amiga_project::load(&root)
        .with_context(|| format!("could not load project {}", root.display()))?;
    let project = &loaded.project;
    let image = project
        .programs
        .iter()
        .flat_map(|program| &program.images)
        .find(|image| image.id == image_id)
        .with_context(|| format!("project {} has no image {image_id}", root.display()))?;
    if image.format != "raw" {
        bail!(
            "project image {image_id} has format {:?}; --image currently accepts raw images",
            image.format
        );
    }
    if image.architecture != "mc68000" {
        bail!(
            "project image {image_id} has architecture {:?}, not mc68000",
            image.architecture
        );
    }
    let object = project
        .sources
        .objects
        .iter()
        .find(|object| object.id == image.object_id)
        .with_context(|| {
            format!(
                "project image {image_id} names missing object {}",
                image.object_id
            )
        })?;
    let (bindings, diagnostics) = amiga_operations::load_bindings(&root);
    for diagnostic in diagnostics {
        eprintln!("warning: {}", diagnostic.message);
    }
    let bytes = amiga_project::verify::recover_object(
        project,
        &bindings,
        &amiga_operations::ContainerRecovery::default(),
        &image.object_id,
    )
    .map_err(anyhow::Error::msg)
    .with_context(|| format!("could not recover project image {image_id}"))?;

    let selected_map = match (load_map_id, image.load_maps.as_slice()) {
        (Some(id), maps) => Some(
            maps.iter()
                .find(|map| map.id == id)
                .with_context(|| format!("image {image_id} has no load map {id}"))?,
        ),
        (None, []) => None,
        (None, [map]) => Some(map),
        (None, maps) => bail!(
            "image {image_id} has {} load maps; select one with --load-map",
            maps.len()
        ),
    };
    let (project_origin, project_entries) = match selected_map {
        None => (None, None),
        Some(map) => {
            let segment = map
                .segments
                .iter()
                .find(|segment| segment.hunk == 0)
                .with_context(|| {
                    format!("load map {} has no segment for raw image hunk 0", map.id)
                })?;
            let origin = parse_project_address(&segment.runtime_base)?;
            let mut entries = Vec::with_capacity(map.entry_points.len());
            for entry in &map.entry_points {
                let address = parse_project_address(&entry.address)?;
                entries.push(address.checked_sub(origin).with_context(|| {
                    format!(
                        "entry {} in load map {} lies below raw image origin {origin:#x}",
                        entry.address, map.id
                    )
                })?);
            }
            (Some(origin), Some(entries))
        }
    };
    let length = bytes.len();
    Ok(PreparedBytes {
        bytes,
        source_label: format!("{} image {image_id}", root.display()),
        region: amiga_operations::CodeRegion::Raw,
        expected_sha256: Some(object.sha256.clone()),
        hunk: 0,
        code_range: 0..length,
        relocations: Vec::new(),
        project_origin,
        project_entries,
        project_root: Some(root),
    })
}

fn prepare_file(target: &impl CodeTargetArgs) -> Result<PreparedBytes> {
    let path = target
        .executable()
        .context("name an executable or select a raw project image with --image")?;
    let resolved = resolve_media_path(path)?;
    let bytes = load(&resolved)?;
    if let Some(expected) = target.raw_sha256() {
        if target.hunk() != 0 {
            bail!(
                "a raw file has no hunk {}; omit --hunk or use 0",
                target.hunk()
            );
        }
        let found = sha256(&bytes);
        if !found.eq_ignore_ascii_case(expected) {
            bail!(
                "{} hashes to {found}, not the pinned {expected}",
                resolved.display()
            );
        }
        let length = bytes.len();
        return Ok(PreparedBytes {
            bytes,
            source_label: resolved.display().to_string(),
            region: amiga_operations::CodeRegion::Raw,
            expected_sha256: Some(expected.to_owned()),
            hunk: 0,
            code_range: 0..length,
            relocations: Vec::new(),
            project_origin: None,
            project_entries: None,
            project_root: None,
        });
    }

    let executable = amiga_hunk::Executable::parse(&bytes)?;
    let segment = code_hunk(&executable, target.hunk())?;
    let code_range = segment.file_offset..segment.file_offset + segment.bytes.len();
    let relocations = prepared_relocations(&executable, target.hunk());
    Ok(PreparedBytes {
        bytes,
        source_label: resolved.display().to_string(),
        region: amiga_operations::CodeRegion::Hunk,
        expected_sha256: None,
        hunk: target.hunk(),
        code_range,
        relocations,
        project_origin: None,
        project_entries: None,
        project_root: None,
    })
}

/// Run the common prologue for a control-flow command over a HUNK executable,
/// a pinned raw file, or a project-recorded raw image.
pub(crate) fn prepare_code_analysis(
    config_override: Option<&Path>,
    target: &impl CodeTargetArgs,
) -> Result<Prepared> {
    let prepared = match target.image() {
        Some(image) => prepare_project_image(image, target.load_map(), target.hunk())?,
        None => prepare_file(target)?,
    };
    let discovered = optional_config(config_override)?;
    let config_dir = discovered
        .as_ref()
        .and_then(|(path, _)| path.parent().map(Path::to_path_buf));
    let config_path = discovered.as_ref().map(|(path, _)| path.clone());
    let config = discovered.map(|(_, config)| config);
    let base = match target.explicit_base() {
        Some(origin) => Some(amiga_core::config::Base {
            origin,
            entry: None,
        }),
        None if prepared.region == amiga_operations::CodeRegion::Raw => prepared
            .project_origin
            .map(|origin| amiga_core::config::Base {
                origin,
                entry: None,
            }),
        None => config.as_ref().and_then(|config| config.base),
    };
    let entries = if !target.entries().is_empty() {
        rebase_and_entries(base, target.entries(), prepared.code_range.len())?.1
    } else if let Some(entries) = prepared.project_entries.as_deref() {
        rebase_and_entries(None, entries, prepared.code_range.len())?.1
    } else {
        rebase_and_entries(base, &[], prepared.code_range.len())?.1
    };
    let rebase = base.map(|base| amiga_disasm::Rebase::new(base.origin));
    let flow_relocations = flow_relocations(prepared.hunk, &prepared.relocations);
    let options = amiga_disasm::FlowOptions {
        rebase,
        relocations: (prepared.region == amiga_operations::CodeRegion::Hunk)
            .then(|| flow_relocations.clone()),
    };
    let analysis = amiga_disasm::analyze_entries_with(
        &prepared.bytes[prepared.code_range.clone()],
        &entries,
        &options,
    );
    let names = crate::commands::ProjectNames::for_bytes(
        prepared
            .project_root
            .as_deref()
            .or(crate::project_override()),
        &prepared.bytes,
    );
    Ok(Prepared {
        bytes: prepared.bytes,
        source_label: prepared.source_label,
        region: prepared.region,
        expected_sha256: prepared.expected_sha256,
        hunk: prepared.hunk,
        code_range: prepared.code_range,
        config,
        config_dir,
        config_path,
        names,
        flow_relocations,
        base,
        entries,
        analysis,
    })
}

/// Run `analysis.code.disassemble` and render the result.
///
/// The response carries instructions, never a listing — the label, the column
/// widths, and the comment marker are this frontend's, and putting them in the
/// operation would make every other consumer inherit them.
fn disassemble(
    path: &Path,
    arguments: amiga_operations::CodeDisassembleArguments,
) -> Result<(amiga_operations::CodeDisassembleResult, PathBuf)> {
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let arguments = amiga_operations::CodeDisassembleArguments {
        source: amiga_operations::SourceLocator::file(name.as_str()),
        ..arguments
    };

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeDisassemble(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to disassemble {}", resolved.display()))?;
    let result = outcome
        .analysis_code_disassemble()
        .context("the disassembly returned no result")?
        .clone();
    print_warnings(&outcome);
    Ok((result, resolved))
}

fn disassemble_prepared(
    prepared: &Prepared,
    mut arguments: amiga_operations::CodeDisassembleArguments,
) -> Result<amiga_operations::CodeDisassembleResult> {
    let name = amiga_operations::SourceName::parse("analysis-input")?;
    arguments.source = amiga_operations::SourceLocator::file(name.as_str());
    arguments.region = prepared.region();
    arguments.hunk =
        (prepared.region() == amiga_operations::CodeRegion::Hunk).then_some(prepared.hunk());
    arguments.expected_sha256 = prepared.expected_sha256().map(str::to_owned);
    let sources = amiga_operations::InMemorySourceResolver::new(
        amiga_operations::ResolvedSource::new(name, prepared.bytes.clone().into()),
    );
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeDisassemble(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to disassemble {}", prepared.source_label()))?;
    let result = outcome
        .analysis_code_disassemble()
        .context("the disassembly returned no result")?
        .clone();
    print_warnings(&outcome);
    Ok(result)
}

pub(crate) fn disasm_linear(path: &Path, hunk: u32, start: u32, end: Option<u32>) -> Result<()> {
    let (result, _) = disassemble(
        path,
        amiga_operations::CodeDisassembleArguments::new("")
            .in_hunk(hunk)
            .over_range(start, end),
    )?;
    let mut listing = String::new();
    for instruction in &result.instructions {
        writeln!(
            listing,
            "{:08x}: {:<18} {}",
            instruction.offset, instruction.bytes, instruction.text
        )?;
    }
    print_document(&listing)
}

/// Which lines of a flow listing are printed, in hunk-offset space.
///
/// Resolved from [`FlowBoundsArgs`] once the base is known, because a bound is
/// an absolute address exactly when an entry point is — the same convention,
/// resolved by the same conversion, so `--entry 0x21000 --function 0x21044`
/// means what a reader assumes it means.
pub(crate) struct FlowBounds {
    /// Selected function entries, sorted; empty selects every function.
    functions: Vec<u32>,
    /// Half-open offset window; `end` of `None` runs to the end of the hunk.
    start: Option<u32>,
    end: Option<u32>,
    no_data: bool,
}

impl FlowBounds {
    /// Whether anything was asked for at all. An unbounded listing prints
    /// exactly what it always printed, down to the absent bounds header.
    const fn is_bounded(&self) -> bool {
        !self.functions.is_empty() || self.start.is_some() || self.end.is_some() || self.no_data
    }

    /// Whether the window admits `[offset, end)`.
    fn window_admits(&self, offset: u32, end: u32) -> bool {
        self.start.is_none_or(|start| end > start) && self.end.is_none_or(|limit| offset < limit)
    }

    /// Whether an instruction owned by `owners` is selected.
    fn owns(&self, owners: &[u32]) -> bool {
        self.functions.is_empty() || owners.iter().any(|owner| self.functions.contains(owner))
    }
}

/// Resolve `--function`/`--start`/`--end` against the base, and refuse a
/// function the traversal never found.
///
/// Refusing is the point. A mistyped entry that silently printed an empty
/// listing would read as "this function has no code", which is the one
/// conclusion a bounded listing must never invite. The message carries the
/// nearest entries so the correction is one glance rather than a second run.
fn resolve_flow_bounds(
    naming: &Naming,
    bounds: &FlowBoundsArgs,
    flow: &amiga_operations::CodeFlowFacts,
) -> Result<FlowBounds> {
    let convert = |value: u32, what: &str| -> Result<u32> {
        naming.base.map_or(Ok(value), |base| {
            base.abs_to_offset(value)
                .with_context(|| format!("{what} {value:#x} is below the mapped origin"))
        })
    };

    let mut functions = Vec::with_capacity(bounds.function.len());
    for &requested in &bounds.function {
        let offset = convert(requested, "--function")?;
        if !flow.functions.contains(&offset) {
            let near = nearest_functions(&flow.functions, offset);
            bail!(
                "{requested:#x} (hunk offset {offset:#x}) is not a function entry this traversal \
                 found{near}"
            );
        }
        functions.push(offset);
    }
    functions.sort_unstable();
    functions.dedup();

    let start = bounds
        .start
        .map(|value| convert(value, "--start"))
        .transpose()?;
    let end = bounds
        .end
        .map(|value| convert(value, "--end"))
        .transpose()?;
    if let (Some(start), Some(end)) = (start, end)
        && end <= start
    {
        bail!("--end {end:#x} is not above --start {start:#x}");
    }

    Ok(FlowBounds {
        functions,
        start,
        end,
        no_data: bounds.no_data,
    })
}

/// The entries either side of `offset`, for a refusal message.
fn nearest_functions(functions: &[u32], offset: u32) -> String {
    let mut sorted: Vec<u32> = functions.to_vec();
    sorted.sort_unstable();
    let below = sorted.iter().rev().find(|&&entry| entry < offset);
    let above = sorted.iter().find(|&&entry| entry > offset);
    match (below, above) {
        (Some(below), Some(above)) => format!("; the nearest are {below:#x} and {above:#x}"),
        (Some(below), None) => format!("; the nearest is {below:#x}"),
        (None, Some(above)) => format!("; the nearest is {above:#x}"),
        (None, None) => String::new(),
    }
}

pub(crate) fn disasm_flow(
    config_override: Option<&Path>,
    target: &DisasmTargetArgs,
    bounds: &FlowBoundsArgs,
) -> Result<()> {
    // Names are the frontend's: a project describes these exact bytes, and
    // which project is open is session state rather than a fact about them.
    // `Naming` is what `annotate` resolves them through, so both listings label
    // from one lookup over one project rather than from two that agree by
    // coincidence.
    let prepared = prepare_code_analysis(config_override, target)?;
    let naming = Naming::from_prepared(&prepared);
    let result = disassemble_prepared(
        &prepared,
        flow_request(&naming, target, Some(&prepared.entries))?,
    )?;
    let flow = result
        .flow
        .as_ref()
        .context("the flow disassembly reported no traversal")?;
    let names = naming.names.as_ref();

    let mut listing = String::new();
    writeln!(
        listing,
        "; Control-flow-aware MC68000 disassembly by amiga-re"
    )?;
    writeln!(listing, "; Source: {}", prepared.source_label())?;
    writeln!(listing, "; Source SHA-256: {}", result.source.sha256)?;
    if let Some(names) = names {
        writeln!(listing, "; Names: {}", names.provenance())?;
    }
    if result.origin.is_some() {
        let offsets = flow
            .entries
            .iter()
            .map(|offset| format!("{offset:#x}"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(listing, "; Rebased; entry offsets: {offsets}")?;
    }
    match result.region {
        amiga_operations::CodeRegion::Hunk => writeln!(
            listing,
            "; Hunk: {} (CODE, {:#x} bytes)",
            result.hunk.context("a HUNK result named no hunk")?,
            result.hunk_bytes
        )?,
        amiga_operations::CodeRegion::Raw => {
            writeln!(listing, "; Raw image: {:#x} bytes", result.hunk_bytes)?
        }
        amiga_operations::CodeRegion::BootBlock => {
            unreachable!("analysis.code.disassemble refuses boot blocks")
        }
    }
    let coverage = &flow.coverage;
    let percent = if coverage.total_bytes == 0 {
        0.0
    } else {
        coverage.decoded_bytes as f64 / coverage.total_bytes as f64 * 100.0
    };
    writeln!(
        listing,
        "; Coverage: {}/{} bytes ({percent:.2}%), {} instructions, {} functions, {} calls, {} library calls, {} external, {} unresolved",
        coverage.decoded_bytes,
        coverage.total_bytes,
        coverage.instructions,
        coverage.functions,
        coverage.calls,
        coverage.library_calls,
        coverage.external,
        coverage.unresolved
    )?;
    if !bounds.no_data {
        writeln!(
            listing,
            "; DC.W/DC.B marks bytes not reached by direct static control flow; it does not prove data."
        )?;
    }
    let bounds = resolve_flow_bounds(&naming, bounds, flow)?;
    write_bounds_header(&mut listing, &result, flow, &bounds)?;
    writeln!(listing)?;
    render_flow_listing(&mut listing, &result, flow, &naming.resolver(), &bounds)?;
    print_document(&listing)
}

/// What a bounded listing leaves out, and what it would otherwise hide.
///
/// A bound removes lines, so everything a removed line would have told the
/// reader has to be said here instead — otherwise the quiet listing reads as a
/// complete one. Three things are said: that the coverage line above counts the
/// whole code region rather than the selection, which calls leave the selection, and
/// where flow inside it went unresolved. The last two are exactly what a reader
/// would have noticed while scrolling past the parts now missing.
fn write_bounds_header(
    listing: &mut String,
    result: &amiga_operations::CodeDisassembleResult,
    flow: &amiga_operations::CodeFlowFacts,
    bounds: &FlowBounds,
) -> Result<()> {
    if !bounds.is_bounded() {
        return Ok(());
    }
    let mut asked = Vec::new();
    if !bounds.functions.is_empty() {
        asked.push(format!(
            "{} of {} function(s): {}",
            bounds.functions.len(),
            flow.function_total,
            offsets(&bounds.functions)
        ));
    }
    if bounds.start.is_some() || bounds.end.is_some() {
        let start = bounds
            .start
            .map_or_else(|| "start".to_owned(), |at| format!("{at:#x}"));
        let end = bounds
            .end
            .map_or_else(|| "end".to_owned(), |at| format!("{at:#x}"));
        asked.push(format!("offsets [{start}..{end})"));
    }
    if bounds.no_data {
        asked.push("reached instructions only".to_owned());
    }
    writeln!(listing, "; Bounded to {}", asked.join("; "))?;
    let region = match result.region {
        amiga_operations::CodeRegion::Hunk => "hunk",
        amiga_operations::CodeRegion::Raw => "raw image",
        amiga_operations::CodeRegion::BootBlock => {
            unreachable!("analysis.code.disassemble refuses boot blocks")
        }
    };
    writeln!(
        listing,
        "; The coverage above is the whole {region}'s: the traversal is unbounded and only this listing is not."
    )?;

    if !bounds.functions.is_empty() {
        let leaving: Vec<u32> = sorted_unique(
            flow.calls
                .iter()
                .filter(|edge| {
                    bounds.functions.contains(&edge.caller)
                        && !bounds.functions.contains(&edge.callee)
                })
                .map(|edge| edge.callee),
        );
        if !leaving.is_empty() {
            writeln!(
                listing,
                "; Calls leaving the selection: {}",
                offsets(&leaving)
            )?;
        }
        if flow.call_total > flow.calls.len() as u64 {
            writeln!(
                listing,
                "; The call list was capped by the analysis, so the line above can be short."
            )?;
        }
        let unresolved: Vec<u32> = sorted_unique(
            flow.unresolved
                .iter()
                .filter(|site| bounds.functions.contains(&site.owner))
                .map(|site| site.site),
        );
        if !unresolved.is_empty() {
            writeln!(
                listing,
                "; Unresolved flow inside the selection: {}",
                offsets(&unresolved)
            )?;
        }
        // Ownership is what a --function bound selects on, so a capped owner
        // set can drop an instruction that really does belong to the selection.
        // The analysis reports the cap per instruction; a bounded listing has
        // to repeat it, because here it costs lines rather than a column.
        if result
            .instructions
            .iter()
            .any(|instruction| instruction.owner_total > instruction.owners.len() as u64)
        {
            writeln!(
                listing,
                "; Ownership was capped for some instructions, so a --function bound can be short."
            )?;
        }
    }
    Ok(())
}

/// `0x2a, 0x1f0` — the spelling every offset list in this listing uses.
fn offsets(values: &[u32]) -> String {
    values
        .iter()
        .map(|value| format!("{value:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sorted_unique(values: impl Iterator<Item = u32>) -> Vec<u32> {
    let mut collected: Vec<u32> = values.collect();
    collected.sort_unstable();
    collected.dedup();
    collected
}

/// The labelled listing: reached instructions, and `DC.W`/`DC.B` for the rest.
///
/// Every choice here is this frontend's — the `L########:` label, the comment
/// marker, and the word-then-byte split of an unreached run. The operation
/// carries no labels at all, which is why `flow` and `annotate` can render the
/// same facts differently without either being wrong. The column width is the
/// one exception: it comes from `amiga_disasm` so that a listing rendered here
/// and one rendered by `amiga_disasm::render` are the same bytes.
///
/// The *reviewed* names are not a rendering choice, and are read through the
/// same [`Resolver::label_at`] `annotate` labels from. What is left different
/// is what a listing invents for itself: `annotate` gives a discovered function
/// entry a `sub_` stub, and this one does not, because a traversal's entries
/// are not names anybody wrote down.
fn render_flow_listing(
    listing: &mut String,
    result: &amiga_operations::CodeDisassembleResult,
    flow: &amiga_operations::CodeFlowFacts,
    resolver: &Resolver<'_>,
    bounds: &FlowBounds,
) -> Result<()> {
    const COLUMN: usize = amiga_disasm::listing::FLOW_INSTRUCTION_COLUMN;

    #[derive(Debug)]
    enum Line<'a> {
        Instruction(&'a amiga_operations::DisassembledInstruction),
        Unreached(&'a amiga_operations::UnreachedRun),
    }

    // Selected instructions decide the window an unreached run is judged
    // against: a `--function` bound says nothing directly about bytes no
    // traversal reached, and the useful reading of it is "the holes inside what
    // I asked for". Without a function bound the span is the whole region, so
    // only `--start`/`--end` narrow it.
    let selected: Vec<&amiga_operations::DisassembledInstruction> = result
        .instructions
        .iter()
        .filter(|instruction| {
            bounds.owns(&instruction.owners)
                && bounds.window_admits(instruction.offset, instruction_end(instruction))
        })
        .collect();
    let span = if bounds.functions.is_empty() {
        None
    } else {
        selected
            .first()
            .map(|first| first.offset)
            .zip(selected.iter().map(|last| instruction_end(last)).max())
    };

    let mut lines: Vec<(u32, Line<'_>)> = selected
        .into_iter()
        .map(|instruction| (instruction.offset, Line::Instruction(instruction)))
        .chain(
            flow.unreached
                .iter()
                .filter(|_| !bounds.no_data)
                .filter_map(|run| {
                    let end = run.offset.saturating_add(hex_len(&run.bytes));
                    let inside = span.is_none_or(|(low, high)| run.offset < high && end > low);
                    (inside && bounds.window_admits(run.offset, end))
                        .then_some((run.offset, Line::Unreached(run)))
                }),
        )
        .collect();
    lines.sort_by_key(|(offset, _)| *offset);

    for (offset, line) in lines {
        match line {
            // Padded to `amiga_disasm`'s own column so that this renderer and
            // `amiga_disasm::render` emit byte-identical lines. Both pad; the
            // shared constant is what stops them drifting apart again.
            Line::Instruction(instruction) => {
                if let Some(label) = resolver.label_at(offset) {
                    writeln!(listing, "{label}:")?;
                }
                writeln!(
                    listing,
                    "L{offset:08X}:  {:<COLUMN$} ; {}",
                    instruction.text, instruction.bytes
                )?;
            }
            Line::Unreached(run) => {
                let bytes = decode_hex(&run.bytes)?;
                let mut cursor = 0;
                while cursor < bytes.len() {
                    let at = offset.saturating_add(cursor as u32);
                    let width = if cursor + 1 < bytes.len() { 2 } else { 1 };
                    // Clipped per word rather than per run: a run that straddles
                    // a bound would otherwise carry the listing past it, and the
                    // bound a reader asked for is about lines, not about which
                    // record they happen to sit in.
                    let past = at.saturating_add(width);
                    if !bounds.window_admits(at, past)
                        || span.is_some_and(|(low, high)| at >= high || past <= low)
                    {
                        cursor += width as usize;
                        continue;
                    }
                    let text = if width == 2 {
                        let word = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
                        format!("DC.W    ${word:04X}")
                    } else {
                        format!("DC.B    ${:02X}", bytes[cursor])
                    };
                    writeln!(
                        listing,
                        "L{at:08X}:  {text:<COLUMN$} ; not directly reached"
                    )?;
                    cursor += width as usize;
                }
            }
        }
    }
    Ok(())
}

/// One past the last byte of an instruction, from the hex its response carries.
fn instruction_end(instruction: &amiga_operations::DisassembledInstruction) -> u32 {
    instruction
        .offset
        .saturating_add(hex_len(&instruction.bytes))
}

/// How many bytes a lowercase-hex byte string stands for. An odd length cannot
/// come from this vocabulary; rounding down keeps a bound conservative rather
/// than claiming a byte that is not there.
fn hex_len(hex: &str) -> u32 {
    u32::try_from(hex.len() / 2).unwrap_or(u32::MAX)
}

/// Bytes from the lowercase hex every byte string in a response uses.
pub(crate) fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("{text:?} is not a whole number of hex bytes");
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .with_context(|| format!("{text:?} is not hex"))
        })
        .collect()
}

/// Format a signed displacement as `+0x..` / `-0x..` (not two's-complement hex).
pub(crate) fn signed_hex(value: i16) -> String {
    if value < 0 {
        format!("-{:#x}", -i32::from(value))
    } else {
        format!("+{value:#x}")
    }
}

#[derive(Default)]
struct GlobalSlot {
    count: usize,
    sizes: std::collections::BTreeSet<u8>,
    kinds: std::collections::BTreeSet<GlobalAccessOrder>,
    values: std::collections::BTreeSet<u32>,
    pointer: bool,
    library_base: bool,
}

/// The operation's access kind, ordered so the R/W/M/A/O flag column keeps the
/// order it has always printed in. `GlobalAccessKind` is a wire type and gains
/// no ordering of its own for one renderer's benefit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GlobalAccessOrder {
    Read,
    Write,
    Modify,
    Address,
    Other,
}

impl From<amiga_operations::GlobalAccessKind> for GlobalAccessOrder {
    fn from(kind: amiga_operations::GlobalAccessKind) -> Self {
        match kind {
            amiga_operations::GlobalAccessKind::Read => Self::Read,
            amiga_operations::GlobalAccessKind::Write => Self::Write,
            amiga_operations::GlobalAccessKind::Modify => Self::Modify,
            amiga_operations::GlobalAccessKind::Address => Self::Address,
            amiga_operations::GlobalAccessKind::Other => Self::Other,
        }
    }
}

const fn order_letter(kind: GlobalAccessOrder) -> char {
    match kind {
        GlobalAccessOrder::Read => 'R',
        GlobalAccessOrder::Write => 'W',
        GlobalAccessOrder::Modify => 'M',
        GlobalAccessOrder::Address => 'A',
        GlobalAccessOrder::Other => 'O',
    }
}

impl GlobalSlot {
    fn record(
        &mut self,
        size: Option<u8>,
        kind: amiga_operations::GlobalAccessKind,
        value: Option<u32>,
        pointer: bool,
        library_base: bool,
    ) {
        self.count += 1;
        if let Some(size) = size {
            self.sizes.insert(size);
        }
        self.kinds.insert(kind.into());
        self.values.extend(value);
        self.pointer |= pointer;
        self.library_base |= library_base;
    }

    /// The `size=` column: the distinct operand sizes seen, or `-`.
    fn sizes(&self) -> String {
        if self.sizes.is_empty() {
            "-".to_owned()
        } else {
            self.sizes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("/")
        }
    }

    /// The R/W/M/A/O access-kind flags column.
    fn flags(&self) -> String {
        self.kinds.iter().copied().map(order_letter).collect()
    }

    /// Inferred semantic roles for the slot.
    fn roles(&self) -> String {
        let mut roles = Vec::new();
        if self.pointer {
            roles.push("pointer");
        }
        if self.library_base {
            roles.push("library-base");
        }
        if roles.is_empty() {
            String::new()
        } else {
            format!(" type={}", roles.join("/"))
        }
    }

    /// Constants directly stored in the slot.
    fn values(&self) -> String {
        if self.values.is_empty() {
            String::new()
        } else {
            format!(
                " values={}",
                self.values
                    .iter()
                    .map(|value| format!("{value:#x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

/// Map the globals a hunk's code reaches, from `analysis.code.globals`.
///
/// The grouping into slots — the counts, the size and flag columns, the roles —
/// stays here. It is one reading of the access list; another frontend may want
/// them in site order, and both are renderings of the same facts.
pub(crate) fn disasm_globals(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    base_register: u8,
    absolute: bool,
    derived: bool,
) -> Result<()> {
    let naming = Naming::resolve(config_override, target)?;
    if absolute && naming.base.is_none() {
        bail!("--absolute needs a base (pass --base or set config [base])");
    }
    let resolved = resolve_media_path(&target.executable)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments = amiga_operations::CodeGlobalsArguments::new(name.as_str())
        .in_hunk(target.hunk)
        .from_entries(entry_offsets(naming.base, &target.entry)?)
        .through_register(base_register);
    if let Some(base) = naming.base {
        arguments = arguments.mapped_at(base.origin);
    }
    if derived {
        arguments = arguments.with_derived();
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeGlobals(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to map globals in {}", resolved.display()))?;
    let globals = outcome
        .analysis_code_globals()
        .context("the globals map returned no result")?;

    let mut out = Document::new();
    if absolute {
        print_absolute_globals(&mut out, globals, &naming);
    } else {
        print_relative_globals(&mut out, globals, base_register, &naming);
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

fn print_relative_globals(
    out: &mut Document,
    globals: &amiga_operations::CodeGlobalsResult,
    base_register: u8,
    naming: &Naming,
) {
    let accesses = &globals.base_relative;
    if accesses.is_empty() {
        row!(out, "no A{base_register}-relative accesses found");
        return;
    }

    let mut slots: std::collections::BTreeMap<i32, GlobalSlot> = std::collections::BTreeMap::new();
    for access in accesses {
        slots.entry(access.displacement).or_default().record(
            access.size,
            access.kind,
            access.value,
            access.value_points_into_image,
            access.library_base,
        );
    }

    row!(
        out,
        "{} A{base_register}-relative slot(s), {} access(es):",
        slots.len(),
        accesses.len()
    );
    // The project can name a slot the analysis can only locate. That is the
    // whole point of the `base_register` annotation target: `disasm globals`
    // reports `A5-0x8`, and only a person can say it is the map seed.
    let register = format!("a{base_register}");
    for (displacement, slot) in &slots {
        row!(
            out,
            "  A{base_register}{:<7} size={:<5} {:<5} x{}{}{}{}",
            signed_hex_i32(*displacement),
            slot.sizes(),
            slot.flags(),
            slot.count,
            slot.roles(),
            slot.values(),
            symbol_suffix(naming.global(&register, *displacement))
        );
    }
    for access in accesses {
        if let Some(value) = access.value {
            row!(
                out,
                "    L{:08X} writes {value:#x} to A{base_register}{}",
                access.site,
                signed_hex_i32(access.displacement)
            );
        }
    }
}

/// Fixed-address mode: absolute-long accesses whose target lies inside the
/// loaded image.
fn print_absolute_globals(
    out: &mut Document,
    globals: &amiga_operations::CodeGlobalsResult,
    naming: &Naming,
) {
    let accesses = &globals.absolute;
    let origin = globals.origin.unwrap_or_default();
    let size = globals.hunk_bytes;
    if accesses.is_empty() {
        row!(
            out,
            "no absolute global accesses within [{origin:#x}..+{size:#x})"
        );
    }

    let mut slots: std::collections::BTreeMap<u32, GlobalSlot> = std::collections::BTreeMap::new();
    for access in accesses {
        slots.entry(access.address).or_default().record(
            access.size,
            access.kind,
            access.value,
            access.value_points_into_image,
            access.library_base,
        );
    }

    if !accesses.is_empty() {
        row!(
            out,
            "{} absolute slot(s), {} access(es), image [{origin:#x}..+{size:#x}):",
            slots.len(),
            accesses.len()
        );
    }
    for (address, slot) in &slots {
        let file = address
            .checked_sub(origin)
            .filter(|offset| u64::from(*offset) < size)
            .map(|offset| format!("  (+{offset:#x})"))
            .unwrap_or_default();
        row!(
            out,
            "  {address:#010x} size={:<5} {:<5} x{}{}{}{file}{}",
            slot.sizes(),
            slot.flags(),
            slot.count,
            slot.roles(),
            slot.values(),
            symbol_suffix(naming.symbol_at_absolute(*address).as_deref())
        );
    }
    for access in accesses {
        if let Some(value) = access.value {
            row!(
                out,
                "    L{:08X} writes {value:#x} to {:#x}",
                access.site,
                access.address
            );
        }
    }
    if let Some(derived) = &globals.derived {
        print_derived_accesses(out, derived, origin, size);
    }
}

fn print_derived_accesses(
    out: &mut Document,
    accesses: &[amiga_operations::DerivedGlobalAccess],
    origin: u32,
    size: u64,
) {
    let end = origin.saturating_add(u32::try_from(size).unwrap_or(u32::MAX));
    let relevant = accesses
        .iter()
        .filter(|access| match access.target {
            amiga_operations::DerivedTarget::Exact { address } => (origin..end).contains(&address),
            amiga_operations::DerivedTarget::Range {
                start,
                end: range_end,
            } => start < end && range_end >= origin,
            amiga_operations::DerivedTarget::Unknown => true,
        })
        .collect::<Vec<_>>();
    if relevant.is_empty() {
        row!(out, "no derived accesses into the loaded image");
        return;
    }
    row!(out, "derived indirect accesses:");
    for access in relevant {
        let target = match access.target {
            amiga_operations::DerivedTarget::Exact { address } => format!("{address:#010x}"),
            amiga_operations::DerivedTarget::Range { start, end } => {
                format!("{start:#010x}..={end:#010x}")
            }
            amiga_operations::DerivedTarget::Unknown => "unknown".to_owned(),
        };
        row!(
            out,
            "    L{:08X} A{} -> {target} size={} {}",
            access.site,
            access.register,
            access
                .size
                .map_or_else(|| "?".to_owned(), |size| size.to_string()),
            access_kind_name(access.kind)
        );
    }
}

const fn access_kind_name(kind: amiga_operations::GlobalAccessKind) -> &'static str {
    match kind {
        amiga_operations::GlobalAccessKind::Read => "read",
        amiga_operations::GlobalAccessKind::Write => "write",
        amiga_operations::GlobalAccessKind::Modify => "modify",
        amiga_operations::GlobalAccessKind::Address => "address",
        amiga_operations::GlobalAccessKind::Other => "other",
    }
}

/// Format a signed displacement as `+0x..` / `-0x..` (not two's-complement hex).
fn signed_hex_i32(value: i32) -> String {
    if value < 0 {
        format!("-{:#x}", i64::from(value).unsigned_abs())
    } else {
        format!("+{value:#x}")
    }
}

/// Report fixed-point idioms, clamps, and Q scales, from
/// `analysis.code.fixed-point`.
pub(crate) fn disasm_fixed_point(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
) -> Result<()> {
    let mut out = Document::new();
    let naming = Naming::resolve(config_override, target)?;
    let resolved = resolve_media_path(&target.executable)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments = amiga_operations::CodeFixedPointArguments::new(name.as_str())
        .in_hunk(target.hunk)
        .from_entries(entry_offsets(naming.base, &target.entry)?);
    if let Some(base) = naming.base {
        arguments = arguments.mapped_at(base.origin);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeFixedPoint(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to scan {} for fixed point", resolved.display()))?;
    let fixed = outcome
        .analysis_code_fixed_point()
        .context("the fixed-point scan returned no result")?;

    if fixed.hints.is_empty() && fixed.clamps.is_empty() && fixed.scales.is_empty() {
        row!(
            out,
            "no fixed-point idioms, clamps, or propagated Q scales found"
        );
        out.print()?;
        print_warnings(&outcome);
        return Ok(());
    }
    if !fixed.hints.is_empty() {
        row!(out, "{} fixed-point idiom(s):", fixed.hints.len());
        for hint in &fixed.hints {
            // A register-count shift has no statically known scale, and the
            // rendering says so rather than picking one.
            let format = hint.fractional_bits.map_or_else(
                || "Q? (register-count shift)".to_owned(),
                |bits| format!("Q{bits}"),
            );
            let (idiom, role) = match hint.kind {
                amiga_operations::FixedPointKind::ScaledMultiply => {
                    ("scaled multiply", "normalise")
                }
                amiga_operations::FixedPointKind::ScaledDivide => ("scaled divide", "pre-scale"),
            };
            row!(
                out,
                "  L{:08X}  {idiom} D{}, {role} shift at L{:08X}  ({format})",
                hint.site,
                hint.register,
                hint.shift_site
            );
        }
    }
    if !fixed.clamps.is_empty() {
        row!(out, "{} saturating clamp(s):", fixed.clamps.len());
        for clamp in &fixed.clamps {
            let kind = match clamp.kind {
                amiga_operations::ClampKind::Lower => "lower",
                amiga_operations::ClampKind::Upper => "upper",
            };
            row!(
                out,
                "  L{:08X}  D{} {kind} bound {:#x} ({} byte(s)); assignment at L{:08X}",
                clamp.site,
                clamp.register,
                clamp.bound,
                clamp.size,
                clamp.assign_site
            );
        }
    }
    if !fixed.scales.is_empty() {
        row!(
            out,
            "{} propagated Q-scale assignment(s):",
            fixed.scales.len()
        );
        for scale in &fixed.scales {
            row!(
                out,
                "  L{:08X}  D{} = Q{}",
                scale.site,
                scale.register,
                scale.fractional_bits
            );
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// The default stub name for a discovered function entry at `address`, used to
/// seed a `[[symbols]]` table before the routine is understood and renamed.
pub(crate) fn stub_symbol_name(address: u32) -> String {
    format!("sub_{address:x}")
}

/// Emit the function entries discovered by control-flow analysis as a pasteable
/// `[[symbols]]` stub. Addresses are absolute when a base is set, else
/// hunk-relative. An entry already named by the config keeps that name, so
/// re-seeding after some routines are renamed does not lose the names.
/// Emit the discovered function entries as a pasteable `[[symbols]]` stub.
///
/// Answered by `analysis.code.disassemble` in flow mode rather than by an
/// operation of its own: the function set it needs is already in that
/// operation's flow facts, and a second operation returning the same field
/// would be the duplication this migration exists to end. The naming chain —
/// project, then config table, then the `sub_` stub — stays here.
pub(crate) fn disasm_symbols(config_override: Option<&Path>, target: &AnalysisArgs) -> Result<()> {
    let mut out = Document::new();
    let analysis = code_analysis(config_override, target)?;
    let entries = &analysis.flow.functions;
    row!(
        out,
        "# {} function entr{} discovered by disasm flow; rename as routines are understood.",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    for offset in entries {
        // Name/address in absolute space when a base is configured, so the stub
        // matches how `disasm annotate` and the rest of the toolkit address code.
        let address = analysis.naming.address_of(*offset);
        let name = analysis.naming.resolver().function_name(*offset);
        row!(out, "[[symbols]]");
        row!(out, "addr = {address:#x}");
        row!(out, "name = {name:?}");
    }
    out.print()
}

/// What this frontend needs to name what an operation returned: the config
/// table, the open project's reviewed names, and the mapped origin they are
/// read through. None of the three is a fact about the bytes.
pub(crate) struct Naming {
    names: Option<crate::commands::ProjectNames>,
    config: Option<amiga_core::Config>,
    pub(crate) base: Option<amiga_core::config::Base>,
    hunk: u32,
}

impl Naming {
    fn from_prepared(prepared: &Prepared) -> Self {
        Self {
            names: prepared.names.clone(),
            config: prepared.config.clone(),
            base: prepared.base,
            hunk: prepared.hunk(),
        }
    }

    /// Resolve the config, the project names, and the mapped origin a `disasm`
    /// subcommand will render through.
    pub(crate) fn resolve(config_override: Option<&Path>, target: &AnalysisArgs) -> Result<Self> {
        let config = optional_config(config_override)?.map(|(_, config)| config);
        let base = target.base.resolve(config.as_ref());
        let resolved = resolve_media_path(&target.executable)?;
        let names =
            crate::commands::ProjectNames::for_bytes(crate::project_override(), &load(&resolved)?);
        Ok(Self {
            names,
            config,
            base,
            hunk: target.hunk,
        })
    }

    /// The absolute address of a hunk offset, via the mapped origin when set,
    /// else the raw offset — how the rest of the toolkit addresses code.
    pub(crate) fn address_of(&self, offset: u32) -> u32 {
        self.base
            .and_then(|base| base.offset_to_abs(offset))
            .unwrap_or(offset)
    }

    /// The project's reviewed name for a base-register slot, e.g. `a5` at
    /// `-0x8`. Only a person can say what a slot is for, which is why this is
    /// the project's answer and not the analysis's.
    pub(crate) fn global(&self, register: &str, displacement: i32) -> Option<&str> {
        self.names
            .as_ref()
            .and_then(|names| names.global(register, displacement))
    }

    /// The reviewed name for an absolute address: the project's where one
    /// describes these bytes, and the config table's otherwise.
    pub(crate) fn symbol_at_absolute(&self, address: u32) -> Option<String> {
        symbol_at_absolute(
            self.config.as_ref(),
            self.names.as_ref(),
            self.base,
            self.hunk,
            address,
        )
    }

    /// A resolver over the names alone. It carries no analysis, so it answers
    /// only the questions that need none — which is every question a name is
    /// the answer to.
    pub(crate) fn resolver(&self) -> Resolver<'_> {
        Resolver::for_names(
            self.config.as_ref(),
            self.names.as_ref(),
            self.hunk,
            self.base,
        )
    }
}

/// A routed control-flow analysis and the names to render it with.
pub(crate) struct CodeAnalysis {
    pub(crate) flow: amiga_operations::CodeFlowFacts,
    pub(crate) naming: Naming,
}

/// The request every routed `disasm` subcommand builds: the same hunk, entries,
/// and mapped origin, so two of them can never analyze the same image
/// differently.
fn flow_request(
    naming: &Naming,
    target: &impl CodeTargetArgs,
    resolved_entries: Option<&[u32]>,
) -> Result<amiga_operations::CodeDisassembleArguments> {
    let mut arguments = amiga_operations::CodeDisassembleArguments::new("").in_hunk(target.hunk());
    if let Some(base) = naming.base {
        arguments = arguments.mapped_at(base.origin);
    }
    let entries = match resolved_entries {
        Some(entries) => entries.to_vec(),
        None => entry_offsets(naming.base, target.entries())?,
    };
    Ok(arguments.following_flow(entries))
}

/// Run `analysis.code.disassemble` in flow mode for a `disasm` subcommand.
pub(crate) fn code_analysis(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
) -> Result<CodeAnalysis> {
    let naming = Naming::resolve(config_override, target)?;
    let arguments = flow_request(&naming, target, None)?;
    let (result, _) = disassemble(&target.executable, arguments)?;
    let flow = result
        .flow
        .context("the flow analysis reported no traversal")?;
    Ok(CodeAnalysis { flow, naming })
}

/// Run `analysis.code.callgraph` for `disasm callgraph`.
fn callgraph(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
) -> Result<(amiga_operations::CodeCallgraphResult, Naming)> {
    let naming = Naming::resolve(config_override, target)?;
    let resolved = resolve_media_path(&target.executable)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments = amiga_operations::CodeCallgraphArguments::new(name.as_str())
        .in_hunk(target.hunk)
        .from_entries(entry_offsets(naming.base, &target.entry)?);
    if let Some(base) = naming.base {
        arguments = arguments.mapped_at(base.origin);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeCallgraph(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to graph {}", resolved.display()))?;
    let graph = outcome
        .analysis_code_callgraph()
        .context("the call graph returned no result")?
        .clone();
    print_warnings(&outcome);
    Ok((graph, naming))
}

#[derive(Serialize)]
struct CallgraphNodeView {
    addr: String,
    name: String,
    in_degree: usize,
    out_degree: usize,
}

#[derive(Serialize)]
struct CallgraphEdgeView {
    from: String,
    to: String,
    calls: usize,
}

#[derive(Serialize)]
struct CallgraphView {
    nodes: Vec<CallgraphNodeView>,
    edges: Vec<CallgraphEdgeView>,
}

pub(crate) fn disasm_callgraph(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    format: &str,
) -> Result<()> {
    let mut out = Document::new();
    let (graph, naming) = callgraph(config_override, target)?;
    let function_label = |offset: u32| {
        (
            naming.address_of(offset),
            naming.resolver().function_name(offset),
        )
    };
    let address = |offset: u32| naming.address_of(offset);
    match format {
        "json" => {
            let view = CallgraphView {
                nodes: graph
                    .nodes
                    .iter()
                    .map(|node| {
                        let (at, name) = function_label(node.function);
                        CallgraphNodeView {
                            addr: format!("{at:#x}"),
                            name,
                            in_degree: node.in_degree as usize,
                            out_degree: node.out_degree as usize,
                        }
                    })
                    .collect(),
                edges: graph
                    .edges
                    .iter()
                    .map(|edge| CallgraphEdgeView {
                        from: format!("{:#x}", address(edge.caller)),
                        to: format!("{:#x}", address(edge.callee)),
                        calls: edge.calls as usize,
                    })
                    .collect(),
            };
            row!(out, "{}", serde_json::to_string_pretty(&view)?);
        }
        "dot" => {
            row!(out, "digraph callgraph {{");
            row!(out, "  node [shape=box];");
            for node in &graph.nodes {
                let (at, name) = function_label(node.function);
                row!(
                    out,
                    "  {:?} [label=\"{name}\\nin={} out={}\"];",
                    format!("{at:#x}"),
                    node.in_degree,
                    node.out_degree
                );
            }
            for edge in &graph.edges {
                let from = format!("{:#x}", address(edge.caller));
                let to = format!("{:#x}", address(edge.callee));
                let label = if edge.calls > 1 {
                    format!(" [label=\"x{}\"]", edge.calls)
                } else {
                    String::new()
                };
                row!(out, "  {from:?} -> {to:?}{label};");
            }
            row!(out, "}}");
        }
        other => bail!("unknown --format {other:?} (use json or dot)"),
    }
    out.print()
}

// --- xref ------------------------------------------------------------------

/// Resolve an optional control-flow rebase and convert `entries` to file-offset
/// space. With a `base`, entries are absolute addresses and absolute operands
/// get rebased during traversal; without one, entries are offsets and the
/// default entry is offset 0.
pub(crate) fn rebase_and_entries(
    base: Option<amiga_core::config::Base>,
    entries: &[u32],
    len: usize,
) -> Result<(Option<amiga_disasm::Rebase>, Vec<u32>)> {
    let offsets = entry_offsets(base, entries)?;
    // Bounds-checked whether or not a base is configured. It used to be checked
    // only with one, so an entry past the end was passed through and the
    // traversal reached nothing — reporting an empty analysis of a real hunk,
    // which reads as "there is no code here" rather than "you named an offset
    // that is not in it". Every `analysis.code.*` operation refuses it, and now
    // so does this.
    if offsets.iter().any(|offset| (*offset as usize) >= len) {
        bail!("configured entry is outside the loaded image");
    }
    Ok((
        base.map(|base| amiga_disasm::Rebase::new(base.origin)),
        offsets,
    ))
}

/// Convert `--entry` arguments to hunk offsets.
///
/// An entry is an absolute address when a base is configured and an offset
/// otherwise, and which of the two a flag means is this frontend's own
/// convention — so the conversion happens here and a request carries offsets.
/// Whether an offset lies inside the hunk is not checked here: the caller that
/// knows the hunk's length checks it, and `analysis.code.disassemble` checks it
/// for the caller that does not.
pub(crate) fn entry_offsets(
    base: Option<amiga_core::config::Base>,
    entries: &[u32],
) -> Result<Vec<u32>> {
    let Some(base) = base else {
        return Ok(entries_or_default(entries).to_vec());
    };
    if entries.is_empty() {
        return Ok(vec![
            base.abs_to_offset(base.default_entry()).with_context(|| {
                format!(
                    "configured entry {:#x} is below mapped origin {:#x}",
                    base.default_entry(),
                    base.origin
                )
            })?,
        ]);
    }
    entries
        .iter()
        .map(|&entry| {
            base.abs_to_offset(entry)
                .with_context(|| format!("entry {entry:#x} is below the mapped origin"))
        })
        .collect()
}

pub(crate) fn ref_kind_str(kind: amiga_disasm::RefKind) -> &'static str {
    match kind {
        amiga_disasm::RefKind::Absolute => "abs",
        // The assembler's own spelling of the distinction, `(x).W` against
        // `(x).L`, because the distinction *is* the encoding width.
        amiga_disasm::RefKind::AbsoluteShort => "abs.w",
        amiga_disasm::RefKind::PcRelative => "pcrel",
    }
}

pub(crate) fn symbol_suffix(symbol: Option<&str>) -> String {
    symbol.map(|name| format!("  ({name})")).unwrap_or_default()
}

pub(crate) fn symbol_suffix_for(config: Option<&amiga_core::Config>, address: u32) -> String {
    symbol_suffix(config.and_then(|config| config.symbol_name(address)))
}

/// Append `, whole-file 0x..` when the reading reaches that frame; silent
/// otherwise.
///
/// The position itself is the operation's — the frontend renders it and no
/// longer recomputes it, which is what stops the two from disagreeing.
fn whole_file_suffix(whole_file: Option<u64>) -> String {
    match whole_file {
        Some(whole) => format!(", whole-file {whole:#x}"),
        None => String::new(),
    }
}

/// Report one number in every frame it could have come from, from
/// `analysis.address.resolve`.
///
/// The arithmetic is the operation's; the symbol names are this frontend's,
/// because the table they come from is its configuration rather than a fact
/// about the bytes.
pub(crate) fn xref_addr(
    config_override: Option<&Path>,
    value: u32,
    executable: Option<&Path>,
    hunk: u32,
    base: &BaseArgs,
) -> Result<()> {
    let mut out = Document::new();
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = base
        .resolve(config.as_ref())
        .context("no base available (pass --base or set config [base])")?;

    let mut arguments = amiga_operations::AddressResolveArguments::new(value, base.origin);
    // The anchor is what lets the whole-file frame be answered at all.
    let mut roots = None;
    if let Some(path) = executable {
        let resolved = resolve_media_path(path)?;
        let (root, name) = amiga_operations::split_host_path(&resolved)
            .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
        arguments =
            arguments.anchored_on(amiga_operations::HunkAnchor::new(name.as_str()).in_hunk(hunk));
        roots = Some(root);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(roots.unwrap_or_default());
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisAddressResolve(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to resolve {value:#x}"))?;
    let resolved = outcome
        .analysis_address_resolve()
        .context("the address resolution returned no result")?;

    row!(out, "{value:#x}:");
    match resolved.as_absolute.hunk_relative {
        Some(offset) => row!(
            out,
            "  as absolute    -> hunk-rel {offset:#x}{}{}",
            whole_file_suffix(resolved.as_absolute.whole_file),
            symbol_suffix_for(config.as_ref(), value)
        ),
        None => row!(
            out,
            "  as absolute    -> below the mapped origin {:#x}",
            resolved.origin
        ),
    }
    if let Some(absolute) = resolved.as_hunk_relative.absolute {
        row!(
            out,
            "  as hunk-rel    -> absolute {absolute:#x}{}{}",
            whole_file_suffix(resolved.as_hunk_relative.whole_file),
            symbol_suffix_for(config.as_ref(), absolute)
        );
    }
    // With a hunk anchor, the input is also read as a whole-file offset.
    if let Some(reading) = &resolved.as_whole_file {
        match reading.hunk_relative {
            Some(hunk_relative) => {
                let absolute_text = reading
                    .absolute
                    .map(|address| format!(", absolute {address:#x}"))
                    .unwrap_or_default();
                let symbol = reading
                    .absolute
                    .map(|address| symbol_suffix_for(config.as_ref(), address))
                    .unwrap_or_default();
                row!(
                    out,
                    "  as whole-file  -> hunk-rel {hunk_relative:#x}{absolute_text}{symbol}"
                );
            }
            None => row!(
                out,
                "  as whole-file  -> before hunk {hunk} at file {:#x}",
                resolved.hunk_file_offset.unwrap_or_default()
            ),
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Render every relocation site, from `analysis.hunk.list`.
///
/// The absolute address and the symbol name are the frontend's: both come from
/// the config's `[base]` and symbol table, which are this frontend's own.
pub(crate) fn xref_relocs(config_override: Option<&Path>, path: &Path) -> Result<()> {
    let mut out = Document::new();
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = config.as_ref().and_then(|config| config.base);
    let list = hunk_listing(path)?;

    let mut any = false;
    for segment in &list.segments {
        for relocation in &segment.relocations {
            any = true;
            match relocation.stored_offset {
                Some(target) => {
                    let mut line = format!(
                        "hunk{}+{:#x} -> hunk{}+{target:#x}",
                        relocation.source_hunk, relocation.source_offset, relocation.target_hunk
                    );
                    if let Some(absolute) = base.and_then(|base| base.offset_to_abs(target)) {
                        line.push_str(&format!(
                            "  = {absolute:#x}{}",
                            symbol_suffix_for(config.as_ref(), absolute)
                        ));
                    }
                    row!(out, "{line}");
                }
                None => row!(
                    out,
                    "hunk{}+{:#x} -> hunk{} (stored pointer unreadable)",
                    relocation.source_hunk,
                    relocation.source_offset,
                    relocation.target_hunk
                ),
            }
        }
        if segment.relocations_truncated {
            row!(
                out,
                "... {} of {} relocation(s) shown for hunk {}",
                segment.relocations.len(),
                segment.relocation_total,
                segment.index
            );
        }
    }
    if !any {
        row!(out, "no relocations");
    }
    out.print()
}

/// Every address the analyzed hunk's code names, from
/// `analysis.address.references`.
///
/// The names beside them are this frontend's: they come from the config's
/// symbol table and from whichever project happens to be open, neither of which
/// is a fact about these bytes.
pub(crate) fn xref_refs(config_override: Option<&Path>, target: &AnalysisArgs) -> Result<()> {
    let mut out = Document::new();
    let CrossReferences {
        result,
        names,
        config,
        base,
    } = address_references(config_override, target, None)?;
    if result.references.is_empty() {
        row!(out, "no references");
        return out.print();
    }
    for reference in &result.references {
        let suffix = reference
            .target_address
            .map_or_else(String::new, |address| {
                symbol_suffix(
                    symbol_at_absolute(config.as_ref(), names.as_ref(), base, result.hunk, address)
                        .as_deref(),
                )
            });
        row!(
            out,
            "{:#010x}  {:<5} -> {:#x}{suffix}",
            reference.site,
            reference_kind_str(reference.kind),
            reference.target
        );
    }
    out.print()
}

/// A cross-reference answer and what this frontend needs to name it: the
/// config's symbol table, the open project's reviewed names, and the mapped
/// origin the two are read through.
struct CrossReferences {
    result: amiga_operations::AddressReferencesResult,
    names: Option<crate::commands::ProjectNames>,
    config: Option<amiga_core::Config>,
    base: Option<amiga_core::config::Base>,
}

/// Run `analysis.address.references`, with everything the frontend needs to
/// name what came back.
fn address_references(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    naming: Option<u32>,
) -> Result<CrossReferences> {
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = target.base.resolve(config.as_ref());
    let resolved = resolve_media_path(&target.executable)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments = amiga_operations::AddressReferencesArguments::new(name.as_str())
        .in_hunk(target.hunk)
        .from_entries(entry_offsets(base, &target.entry)?);
    if let Some(base) = base {
        arguments = arguments.mapped_at(base.origin);
    }
    if let Some(address) = naming {
        arguments = arguments.naming(address);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisAddressReferences(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to cross-reference {}", resolved.display()))?;
    let result = outcome
        .analysis_address_references()
        .context("the cross-reference returned no result")?
        .clone();
    print_warnings(&outcome);
    let names =
        crate::commands::ProjectNames::for_bytes(crate::project_override(), &load(&resolved)?);
    Ok(CrossReferences {
        result,
        names,
        config,
        base,
    })
}

/// The reviewed name for an absolute address: the open project's where one
/// describes these bytes, and the config table's otherwise.
fn symbol_at_absolute(
    config: Option<&amiga_core::Config>,
    names: Option<&crate::commands::ProjectNames>,
    base: Option<amiga_core::config::Base>,
    hunk: u32,
    address: u32,
) -> Option<String> {
    names
        .zip(base)
        .and_then(|(names, base)| {
            let offset = base.abs_to_offset(address)?;
            names.at(hunk, u64::from(offset))
        })
        .map(str::to_owned)
        .or_else(|| {
            config
                .and_then(|config| config.symbol_name(address))
                .map(str::to_owned)
        })
}

pub(crate) const fn reference_kind_str(kind: amiga_operations::ReferenceKind) -> &'static str {
    match kind {
        amiga_operations::ReferenceKind::Absolute => "abs",
        amiga_operations::ReferenceKind::AbsoluteShort => "abs.w",
        amiga_operations::ReferenceKind::PcRelative => "pcrel",
    }
}

/// The relocation sites and code operands that name one address, from
/// `analysis.address.references`.
///
/// The same operation `xref refs` uses, with a target — which is what stopped
/// the two from being answered by different traversals. This one used to
/// analyze *without* the image's relocations, so a `JMP` patched into another
/// hunk was followed to its addend inside this one, and whatever bytes sat
/// there were decoded as instructions and their operands reported as
/// references. They are references made by code that never runs here.
pub(crate) fn xref_to(
    config_override: Option<&Path>,
    path: &Path,
    address: u32,
    hunk: u32,
) -> Result<()> {
    let mut out = Document::new();
    let target = AnalysisArgs {
        executable: path.to_path_buf(),
        hunk,
        entry: Vec::new(),
        base: BaseArgs::default(),
    };
    let CrossReferences { result, .. } =
        address_references(config_override, &target, Some(address))?;
    let config = optional_config(config_override)?.map(|(_, config)| config);
    if let Some(name) = config
        .as_ref()
        .and_then(|config| config.symbol_name(address))
    {
        row!(out, "target {address:#x} is {name}");
    }

    for relocation in &result.relocations {
        row!(
            out,
            "reloc  hunk{}+{:#x}",
            relocation.source_hunk,
            relocation.source_offset
        );
    }
    for reference in &result.references {
        row!(
            out,
            "code   hunk{hunk} {:#010x} ({})",
            reference.site,
            reference_kind_str(reference.kind)
        );
    }
    if result.relocations.is_empty() && result.references.is_empty() {
        row!(out, "nothing references {address:#x}");
    }
    out.print()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_symbol_name_is_a_lowercase_hex_sub_label() {
        assert_eq!(stub_symbol_name(0x1ba08), "sub_1ba08");
        assert_eq!(stub_symbol_name(0), "sub_0");
    }

    #[test]
    fn configured_entry_is_rebased_from_the_mapped_origin() {
        let base = amiga_core::config::Base {
            origin: 0xe63e,
            entry: Some(0xe700),
        };
        let (_, entries) = rebase_and_entries(Some(base), &[], 0x1000)
            .unwrap_or_else(|error| panic!("entry did not resolve: {error}"));
        assert_eq!(entries, [0xc2]);
    }
}
