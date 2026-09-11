use super::*;

// --- copper ----------------------------------------------------------------

/// Report plausible Copper lists, from `hardware.copper.scan`.
pub(crate) fn copper_scan(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let (outcome, resolved) = route(
        path,
        |name| {
            amiga_operations::OperationRequestDocument::HardwareCopperScan(
                amiga_operations::CopperScanArguments::new(name),
            )
        },
        "scan",
    )?;
    let scan = outcome
        .hardware_copper_scan()
        .context("the Copper scan returned no result")?;
    let _ = resolved;
    row!(
        out,
        "Found {} Copper list(s) in {}",
        scan.list_total,
        path.display()
    );
    for list in &scan.lists {
        row!(
            out,
            "  {:#010x}..{:#010x}  {} instructions, {} palette run(s), {} bitplane pointer(s)",
            list.start,
            list.end,
            list.instruction_count,
            list.palettes.len(),
            list.bitplane_pointers.len()
        );
        for palette in &list.palettes {
            row!(
                out,
                "    palette @ {:#x}: {} colors from COLOR{:02}",
                palette.start_offset,
                palette.rgb12.len(),
                palette.first_colour
            );
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Build a read request naming `path`'s file and execute it through the router.
///
/// Every `copper`/`palette` read here has the same three lines of adapter
/// around it, so they share one.
fn route(
    path: &Path,
    build: impl FnOnce(&str) -> amiga_operations::OperationRequestDocument,
    what: &str,
) -> Result<(amiga_operations::OperationOutcome, PathBuf)> {
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(build(name.as_str())),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to {what} {}", resolved.display()))?;
    Ok((outcome, resolved))
}

/// Decode a Copper stream, from `hardware.copper.decode`.
///
/// The listing is rendered here — the register column, the `#RRGGBB` comment,
/// and the resolved pointer pairs are this frontend's layout. The register
/// *names* come from the operation, because a name is hardware knowledge.
pub(crate) fn copper_decode(path: &Path, offset: u32) -> Result<()> {
    let mut out = Document::new();
    let (outcome, _) = route(
        path,
        |name| {
            amiga_operations::OperationRequestDocument::HardwareCopperDecode(
                amiga_operations::CopperDecodeArguments::new(name).at_offset(offset),
            )
        },
        "decode",
    )?;
    let decode = outcome
        .hardware_copper_decode()
        .context("the Copper decode returned no result")?;
    if decode.instructions.is_empty() {
        row!(out, "no Copper instructions at {offset:#x}");
        out.print()?;
        print_warnings(&outcome);
        return Ok(());
    }
    print_document(&format_copper_listing(&decode.instructions))?;
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Render a decoded Copper stream as a `copper decode`-style listing: named
/// registers, color MOVEs as `#RRGGBB`, and resolved `BPLxPT`/`SPRxPT` pointer
/// pairs. Shared by `copper decode` and the `patch-xref --apply` effective list.
fn format_copper_listing(instructions: &[amiga_operations::CopperInstruction]) -> String {
    let mut out = String::new();
    let mut previous_move: Option<(u16, u16)> = None;
    for instruction in instructions {
        match &instruction.op {
            amiga_operations::CopperOp::Move {
                register,
                value,
                name,
                rgb8,
            } => {
                // The name is the operation's; the `$1f2` fallback for an
                // offset it does not know is this listing's own.
                let label = name.clone().unwrap_or_else(|| format!("${register:03x}"));
                let mut line = format!(
                    "{:#06x}  MOVE  {label:<9} #{value:#06x}",
                    instruction.offset
                );
                if let Some([red, green, blue]) = rgb8 {
                    line.push_str(&format!("  #{red:02X}{green:02X}{blue:02X}"));
                }
                if amiga_hw::is_pointer_low(*register)
                    && let Some((high_register, high_value)) = previous_move
                    && high_register + 2 == *register
                {
                    let address = (u32::from(high_value) << 16) | u32::from(*value);
                    line.push_str(&format!("  -> {address:#010x}"));
                }
                line.push('\n');
                out.push_str(&line);
                previous_move = Some((*register, *value));
            }
            amiga_operations::CopperOp::Wait {
                vpos,
                hpos,
                blitter_finish_disable,
                terminator,
                ..
            } => {
                if *terminator {
                    out.push_str(&format!("{:#06x}  WAIT  end of list\n", instruction.offset));
                } else {
                    out.push_str(&format!(
                        "{:#06x}  WAIT  vpos={vpos:#04x} hpos={hpos:#04x}{}\n",
                        instruction.offset,
                        if *blitter_finish_disable { " BFD" } else { "" }
                    ));
                }
                previous_move = None;
            }
            amiga_operations::CopperOp::Skip {
                vpos,
                hpos,
                blitter_finish_disable,
                ..
            } => {
                out.push_str(&format!(
                    "{:#06x}  SKIP  vpos={vpos:#04x} hpos={hpos:#04x}{}\n",
                    instruction.offset,
                    if *blitter_finish_disable { " BFD" } else { "" }
                ));
                previous_move = None;
            }
        }
    }
    out
}

/// A compact one-line description of a single Copper op, for the changed-field
/// diff under `patch-xref --apply`.
fn format_copper_op_compact(op: &amiga_operations::CopperOp) -> String {
    match op {
        amiga_operations::CopperOp::Move {
            register,
            value,
            name,
            rgb8,
        } => {
            let label = name.clone().unwrap_or_else(|| format!("${register:03x}"));
            match rgb8 {
                Some([red, green, blue]) => {
                    format!("{label} #{value:#06x} (#{red:02x}{green:02x}{blue:02x})")
                }
                None => format!("{label} #{value:#06x}"),
            }
        }
        amiga_operations::CopperOp::Wait { vpos, hpos, .. } => {
            format!("WAIT vpos={vpos:#04x} hpos={hpos:#04x}")
        }
        amiga_operations::CopperOp::Skip { vpos, hpos, .. } => {
            format!("SKIP vpos={vpos:#04x} hpos={hpos:#04x}")
        }
    }
}

/// Trace the CPU writes that patch a runtime Copper list, from
/// `hardware.copper.references`.
///
/// The write-to-field matching, the effective list, and the before/after diff
/// are the operation's — they are facts about the bytes. The columns and the
/// listing layout are this frontend's.
pub(crate) fn copper_patch_xref(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    copper_offset: u32,
    copper_file: Option<&Path>,
    pointer_reg: u8,
    copper_address: Option<u32>,
    apply: bool,
) -> Result<()> {
    let mut out = Document::new();
    // Named here as well as in the operation, and for a different reason: the
    // operation refuses an empty entry list, but `entry_offsets` would fill in
    // offset zero first. This is about the flag, so it says so.
    if target.entry.is_empty() {
        bail!("--entry (the patch routine's entry) is required for patch-xref");
    }
    let naming = Naming::resolve(config_override, target)?;
    let resolved = resolve_media_path(&target.executable)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    // A template in another file has to resolve under the same root, which is
    // what `--copper-file` beside the executable has always meant in practice.
    let template_name = match copper_file {
        None => None,
        Some(path) => {
            let template = resolve_media_path(path)?;
            let (template_root, template_name) = amiga_operations::split_host_path(&template)
                .with_context(|| format!("{} does not name a readable file", template.display()))?;
            if template_root != root {
                bail!(
                    "{} and {} must sit in one directory for a single request to name both",
                    resolved.display(),
                    template.display()
                );
            }
            Some(template_name.as_str().to_owned())
        }
    };

    let mut arguments = amiga_operations::CopperReferencesArguments::new(
        name.as_str(),
        entry_offsets(naming.base, &target.entry)?,
        pointer_reg,
    )
    .in_hunk(target.hunk)
    .with_template(template_name, copper_offset);
    if let Some(address) = copper_address {
        arguments = arguments.with_template_address(address);
    }
    if let Some(base) = naming.base {
        arguments = arguments.mapped_at(base.origin);
    }
    if apply {
        arguments = arguments.applying();
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::HardwareCopperReferences(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to cross-reference {}", resolved.display()))?;
    let references = outcome
        .hardware_copper_references()
        .context("the Copper cross-reference returned no result")?;

    let template_display = copper_file.unwrap_or(&target.executable);
    row!(
        out,
        "Copper template {} @ file {copper_offset:#x} (whole-file offset): {} instruction(s), {:#x} bytes",
        template_display.display(),
        references.template_total,
        references.list_bytes
    );
    row!(
        out,
        "Patch routine A{pointer_reg}-relative writes into the runtime copy ({} store(s) found):",
        references.write_total
    );

    for write in &references.writes {
        // A write through the pointer that misses the copied list is reported
        // by the operation and not shown here — the header's store count
        // already accounts for it.
        let Some(patches) = &write.patches else {
            continue;
        };
        let site = write.address.unwrap_or(write.site);
        let value = write
            .value
            .map_or_else(|| "?".to_owned(), |value| format!("{value:#x}"));
        let size = write
            .size
            .map_or_else(|| "?".to_owned(), |size| size.to_string());
        // Which base the offset was measured from, because the two are not
        // equally trustworthy: an entry-relative offset rests on --pointer-reg
        // being right, and a loaded one rests on the code.
        let base = write
            .base_site
            .map_or_else(String::new, |base| format!("  [base loaded at +{base:#x}]"));
        row!(
            out,
            "  L{site:08X}  +{:#06x} = {value:<8} ({size}b)  -> {}{base}",
            write.offset,
            patches.description
        );
    }
    if references.writes_in_list == 0 {
        row!(out, "  (no writes land inside the Copper list)");
        // The one case where the answer is likely an unstated fact rather than
        // an absent one: a routine that loads the list's address itself has no
        // base until the request says where the list runs.
        if copper_address.is_none() {
            row!(
                out,
                "  (if the routine loads the list address itself, pass --copper-address \
                 <ADDRESS> so that load establishes the base)"
            );
        }
    }

    // Printed before delegating: `print_effective_list` prints a listing of its
    // own, and the references above it are what the patches were found in.
    out.print()?;
    if let Some(effective) = &references.effective {
        print_effective_list(effective)?;
    }
    print_warnings(&outcome);
    Ok(())
}

/// Render the effective list: the full listing, a before/after diff of every
/// field that changed, and the palette it installs.
fn print_effective_list(effective: &amiga_operations::CopperEffectiveList) -> Result<()> {
    let mut out = Document::new();
    row!(
        out,
        "Effective Copper list after applying {} immediate write(s):",
        effective.applied
    );
    // Into the same document, so the heading above stays above the listing it
    // heads: printing this separately emitted it first and left every collected
    // row — the heading, the changed instructions, the palette — underneath it.
    part!(out, "{}", format_copper_listing(&effective.instructions));

    if effective.changes.is_empty() {
        row!(out, "(no decoded instruction changed)");
    } else {
        row!(out, "Changed instructions:");
        for change in &effective.changes {
            row!(
                out,
                "  {:#06x}  {}  ->  {}",
                change.offset,
                format_copper_op_compact(&change.before),
                format_copper_op_compact(&change.after)
            );
        }
    }

    if !effective.palette_rgb12.is_empty() {
        row!(
            out,
            "Effective palette: {}",
            preview_colors(&effective.palette_rgb12, effective.palette_rgb12.len())
        );
    }
    out.print()
}

// --- hw --------------------------------------------------------------------

/// The custom-chip register name, or `$1f2`-style hex for an unknown offset.
pub(crate) fn hardware_register_label(offset: u16) -> String {
    amiga_hw::register_name(offset).unwrap_or_else(|| format!("${offset:03x}"))
}

/// Print the custom-chip register map, from `hardware.register.list`.
///
/// This command reads no source file. The operation API supplies the hardware register
/// map so the CLI does not maintain its own copy.
pub(crate) fn hw_registers() -> Result<()> {
    let mut out = Document::new();
    let sources = amiga_operations::FilesystemSourceResolver::new(".");
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::HardwareRegisterList(
                amiga_operations::HardwareRegisterListArguments::new(),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome).context("failed to list the custom-chip registers")?;
    let list = outcome
        .hardware_register_list()
        .context("the register listing returned no result")?;
    for register in &list.registers {
        row!(out, "{:#08x}  {}", register.address, register.name);
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Report the custom-chip registers a hunk's code touches, from
/// `hardware.register.references`.
///
/// The subsystem filter stays here. Every access names its subsystem, so
/// narrowing to one is a choice about what to show over a list that is already
/// complete — unlike `--contains`, which decides which strings survive a cap.
pub(crate) fn hw_xref(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    subsystem_filter: Option<&str>,
) -> Result<()> {
    let mut out = Document::new();
    let naming = Naming::resolve(config_override, target)?;
    let resolved = resolve_media_path(&target.executable)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let mut arguments = amiga_operations::RegisterReferencesArguments::new(name.as_str())
        .in_hunk(target.hunk)
        .from_entries(entry_offsets(naming.base, &target.entry)?);
    if let Some(base) = naming.base {
        arguments = arguments.mapped_at(base.origin);
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::HardwareRegisterReferences(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to cross-reference {}", resolved.display()))?;
    let references = outcome
        .hardware_register_references()
        .context("the register cross-reference returned no result")?;

    let mut shown = 0;
    for access in &references.accesses {
        if subsystem_filter.is_some_and(|filter| !access.subsystem.eq_ignore_ascii_case(filter)) {
            continue;
        }
        // The `$1f2` fallback for an offset the map does not name is this
        // listing's own; the name itself is the operation's.
        let label = access
            .name
            .clone()
            .unwrap_or_else(|| format!("${:03x}", access.offset));
        let form = match access.form {
            amiga_operations::RegisterAccessForm::Absolute => "abs",
            amiga_operations::RegisterAccessForm::BaseRelative => "(An)",
        };
        let direction = operation_access_kind_str(access.kind);
        row!(
            out,
            "{:#010x}  {label:<9} {direction:<5} {form:<5} {}",
            access.site,
            access.subsystem
        );
        shown += 1;
    }
    if shown == 0 {
        row!(out, "no custom-chip register accesses found");
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// A short label for how an operand is accessed.
/// The direction column for an operation's access kind.
pub(crate) const fn operation_access_kind_str(
    kind: amiga_operations::GlobalAccessKind,
) -> &'static str {
    match kind {
        amiga_operations::GlobalAccessKind::Read => "read",
        amiga_operations::GlobalAccessKind::Write => "write",
        amiga_operations::GlobalAccessKind::Modify => "rmw",
        amiga_operations::GlobalAccessKind::Address => "addr",
        amiga_operations::GlobalAccessKind::Other => "?",
    }
}

pub(crate) fn access_kind_str(kind: amiga_disasm::AccessKind) -> &'static str {
    match kind {
        amiga_disasm::AccessKind::Read => "read",
        amiga_disasm::AccessKind::Write => "write",
        amiga_disasm::AccessKind::Modify => "rmw",
        amiga_disasm::AccessKind::Address => "addr",
        amiga_disasm::AccessKind::Other => "?",
    }
}

// --- bitmap ----------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) fn bitmap_render(
    config_override: Option<&Path>,
    path: &Path,
    output: &Path,
    offset: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
    planes: Option<u8>,
    plane_order: &str,
    from_copper: Option<u32>,
    copper_file: Option<&Path>,
    base_args: &BaseArgs,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let order = parse_plane_order(plane_order)?;
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let bitmap = config.as_ref().and_then(|config| config.bitmap.as_ref());
    let base = base_args.resolve(config.as_ref());
    let resolved = resolve_media_path(path)?;
    let bytes = load(path)?;

    // Optionally read plane count and palette from a located Copper list.
    let spec = from_copper
        .map(|copper_offset| -> Result<_> {
            let copper_path = copper_file.unwrap_or(path);
            let separate_bytes = (copper_path != path)
                .then(|| load(copper_path))
                .transpose()?;
            let copper_bytes = separate_bytes.as_deref().unwrap_or(&bytes);
            let copper_offset_usize = usize::try_from(copper_offset)
                .context("Copper-list offset does not fit this host")?;
            let spec = amiga_hw::display_spec(&amiga_hw::copper::decode(
                copper_bytes,
                copper_offset_usize,
            ));
            eprintln!(
                "Copper {} @ {copper_offset:#x}: {} planes, {} palette color(s), bitplanes {:x?}",
                copper_path.display(),
                spec.planes
                    .map_or_else(|| "?".to_owned(), |count| count.to_string()),
                spec.palette.len(),
                spec.bitplane_addresses
            );
            Ok(spec)
        })
        .transpose()?;

    let width = usize::try_from(
        width
            .or_else(|| bitmap.map(|bitmap| bitmap.width))
            .context("width is required (pass --width or set config [bitmap].width)")?,
    )?;
    let height = usize::try_from(
        height
            .or_else(|| bitmap.map(|bitmap| bitmap.height))
            .context("height is required (pass --height or set config [bitmap].height)")?,
    )?;
    // Precedence: explicit --planes, then the Copper list, then config, else 4.
    let planes = planes
        .or_else(|| spec.as_ref().and_then(|spec| spec.planes))
        .or_else(|| bitmap.map(|bitmap| bitmap.planes))
        .unwrap_or(4);
    if planes == 0 {
        bail!("bitplane count must be at least 1");
    }

    let bytes_per_row = width.div_ceil(8);
    let offset = resolve_bitmap_offset(
        offset,
        spec.as_ref(),
        base,
        bytes_per_row,
        height,
        planes,
        order,
    )?;
    // Everything above is legitimately the frontend's: config-supplied defaults,
    // the `--from-copper` lookup, and the address-map translation. The region
    // bounds, the decode, the PNG, and the reviewed write are the operation's, so
    // they are no longer recomputed here to be checked twice and disagree once.
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let mut decode =
        amiga_operations::BitmapDecodeArguments::new(source_name.as_str(), width, height, planes);
    decode.offset = Some(offset);
    decode.plane_order = Some(order);

    let mut arguments = amiga_operations::BitmapExportArguments::new(decode, destination.as_str())
        .with_file_name(file_name)
        .with_policy(output_policy(force));
    // Palette precedence: the Copper list's colors, then config, else the
    // operation's documented grayscale ramp. A palette too short to index every
    // plane is not passed on — the ramp is a better answer than a refusal the
    // user cannot act on, and the plan records which was used either way.
    let palette_words = spec
        .as_ref()
        .filter(|spec| !spec.palette.is_empty())
        .map(|spec| spec.palette.as_slice())
        .or_else(|| bitmap.map(|bitmap| bitmap.palette.as_slice()))
        .unwrap_or(&[]);
    if palette_words.len() >= 1 << u32::from(planes) {
        arguments = arguments.with_palette(palette_words.to_vec());
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::GraphicsBitmapExport(arguments),
        &context,
        "PNG export",
        |outcome| {
            outcome
                .graphics_bitmap_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .graphics_bitmap_export()
        .context("the export operation returned no result")?;
    row!(
        out,
        "Rendered {width}x{height} {planes}-plane bitmap to {}",
        export
            .plan
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

/// Resolve the bitmap start from an explicit file offset or from Copper
/// bitplane pointers translated through the configured address map.
#[allow(clippy::too_many_arguments)]
fn resolve_bitmap_offset(
    explicit: Option<u32>,
    spec: Option<&amiga_hw::DisplaySpec>,
    base: Option<amiga_core::config::Base>,
    bytes_per_row: usize,
    height: usize,
    planes: u8,
    order: amiga_operations::PlaneOrder,
) -> Result<usize> {
    if let Some(offset) = explicit {
        return usize::try_from(offset).context("bitmap offset does not fit this host");
    }
    let Some(spec) = spec else {
        return Ok(0);
    };
    let plane_count = usize::from(planes);
    if plane_count == 0 {
        bail!("Copper-derived bitmap has 0 bitplanes");
    }
    if spec.bitplane_addresses.len() < plane_count {
        bail!(
            "Copper list resolves {} of {plane_count} bitplane pointers; pass --offset explicitly",
            spec.bitplane_addresses.len()
        );
    }
    let base = base.context(
        "Copper bitplane pointers need a base map (pass --base or set config [base]), or pass --offset",
    )?;
    let offsets = spec
        .bitplane_addresses
        .iter()
        .take(plane_count)
        .map(|address| {
            base.abs_to_offset(*address).with_context(|| {
                format!("Copper bitplane address {address:#x} precedes the mapped file origin")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let first = offsets[0];
    // A Copper bitplane pointer names a plane of the bitmap the chipset
    // displays, so the distance between two of them says where the next plane
    // starts — which only exists for the two layouts a display uses. A
    // chunk-interleaved region is what code scatters *into* such a bitmap, and
    // has no per-plane start to point at.
    let stride = match order {
        amiga_operations::PlaneOrder::Interleaved => bytes_per_row,
        amiga_operations::PlaneOrder::Contiguous => bytes_per_row
            .checked_mul(height)
            .context("bitplane size overflows")?,
        chunked => bail!(
            "--from-copper cannot resolve a {} region: Copper bitplane pointers describe the \
             bitmap the chipset displays, not the storage layout code scatters into one. Pass \
             --offset.",
            plane_order_name(chunked)
        ),
    };
    for (plane, &actual) in offsets.iter().enumerate().skip(1) {
        let expected = u32::try_from(stride)
            .ok()
            .and_then(|stride| stride.checked_mul(u32::try_from(plane).ok()?))
            .and_then(|delta| first.checked_add(delta))
            .context("bitplane pointer layout overflows")?;
        if actual != expected {
            bail!(
                "Copper bitplane {} maps to offset {actual:#x}, expected {expected:#x} for the selected {} layout; pass --offset or change --plane-order",
                plane + 1,
                plane_order_name(order)
            );
        }
    }
    usize::try_from(first).context("bitmap offset does not fit this host")
}

/// Run `graphics.bitmap.export` in glyph-sheet mode through the shared router.
///
/// No new operation: `graphics.bitmap.export` has had a `glyph_sheet` shape
/// since it landed, and this call site was the one that had not been moved onto
/// it. It rendered the sheet itself and `fs::write`-d the PNG, so the plan
/// digest a user is meant to review did not exist for the one bitmap command
/// that took a flag.
#[expect(
    clippy::too_many_arguments,
    reason = "the glyph geometry a contact sheet needs, each independently settable"
)]
pub(crate) fn bitmap_glyphs(
    config_override: Option<&Path>,
    path: &Path,
    output: &Path,
    offset: u32,
    glyph_spec: &str,
    planes: Option<u8>,
    plane_order: &str,
    count: u32,
    columns: usize,
    gap: usize,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let order = parse_plane_order(plane_order)?;
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let bitmap = config.as_ref().and_then(|config| config.bitmap.as_ref());
    let (glyph_width, glyph_height) = parse_dimensions(glyph_spec)?;
    let planes = planes
        .or_else(|| bitmap.map(|bitmap| bitmap.planes))
        .unwrap_or(1);

    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let mut decode = amiga_operations::BitmapDecodeArguments::new(
        source_name.as_str(),
        glyph_width,
        glyph_height,
        planes,
    )
    .at_offset(offset as usize)
    .with_glyphs(
        usize::try_from(count).context("glyph count too large")?,
        columns,
        gap,
    );
    decode.shape = Some(amiga_operations::BitmapShape::GlyphSheet);
    decode.plane_order = Some(order);

    let mut arguments = amiga_operations::BitmapExportArguments::new(decode, destination.as_str())
        .with_file_name(file_name)
        .with_policy(output_policy(force));
    // Same palette rule as a plain render: a palette too short to index every
    // plane is not passed on, and the operation's grayscale ramp answers instead.
    let palette_words = bitmap
        .map(|bitmap| bitmap.palette.as_slice())
        .unwrap_or(&[]);
    if palette_words.len() >= 1 << u32::from(planes) {
        arguments = arguments.with_palette(palette_words.to_vec());
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::GraphicsBitmapExport(arguments),
        &context,
        "glyph sheet export",
        |outcome| {
            outcome
                .graphics_bitmap_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .graphics_bitmap_export()
        .context("the export operation returned no result")?;
    row!(
        out,
        "Rendered {count} {glyph_width}x{glyph_height} {planes}-plane glyph(s), {columns} per row, to {}",
        output.display()
    );
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

// --- bob -------------------------------------------------------------------

/// Extract a blitter object at `offset` to an indexed PNG, making mask-cut
/// pixels transparent.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bob_extract(
    config_override: Option<&Path>,
    path: &Path,
    output: &Path,
    offset: u32,
    width: Option<u32>,
    height: Option<u32>,
    planes: Option<u8>,
    plane_order: &str,
    mask_spec: &str,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let order = parse_plane_order(plane_order)?;
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let bitmap = config.as_ref().and_then(|config| config.bitmap.as_ref());
    let resolved = resolve_media_path(path)?;

    let width = usize::try_from(
        width
            .or_else(|| bitmap.map(|bitmap| bitmap.width))
            .context("width is required (pass --width or set config [bitmap].width)")?,
    )?;
    let height = usize::try_from(
        height
            .or_else(|| bitmap.map(|bitmap| bitmap.height))
            .context("height is required (pass --height or set config [bitmap].height)")?,
    )?;
    let planes = planes
        .or_else(|| bitmap.map(|bitmap| bitmap.planes))
        .unwrap_or(4);
    let offset = usize::try_from(offset).context("BOB offset does not fit this host")?;
    // Default location for a separate mask: right after the bitplane data. The
    // *default* is the frontend's, because it is a convenience for the flag
    // spelling; where the mask actually is remains the request's.
    let data_planes_end = width
        .div_ceil(8)
        .checked_mul(height)
        .and_then(|plane| plane.checked_mul(usize::from(planes)))
        .context("bitmap dimensions overflow")?;
    let mask = parse_bob_mask(mask_spec, offset, data_planes_end)?;

    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let mut decode =
        amiga_operations::BitmapDecodeArguments::new(source_name.as_str(), width, height, planes);
    decode.offset = Some(offset);
    decode.shape = Some(amiga_operations::BitmapShape::Bob);
    decode.plane_order = Some(order);
    decode.bob_mask = Some(request_bob_mask(mask));

    let mut arguments = amiga_operations::BitmapExportArguments::new(decode, destination.as_str())
        .with_file_name(file_name)
        .with_policy(output_policy(force));
    let palette_words = bitmap
        .map(|bitmap| bitmap.palette.as_slice())
        .unwrap_or(&[]);
    if palette_words.len() >= 1 << u32::from(planes) {
        arguments = arguments.with_palette(palette_words.to_vec());
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::GraphicsBitmapExport(arguments),
        &context,
        "BOB export",
        |outcome| {
            outcome
                .graphics_bitmap_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .graphics_bitmap_export()
        .context("the export operation returned no result")?;
    row!(
        out,
        "Extracted {width}x{height} {planes}-plane BOB to {}",
        export
            .plan
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

/// The request spelling of a mask this command parsed from a flag.
///
/// Exhaustive over `amiga_hw::BobMask`, so a new mask kind cannot reach the
/// operation as whichever one happened to be listed last.
const fn request_bob_mask(mask: amiga_hw::BobMask) -> amiga_operations::BobMask {
    match mask {
        amiga_hw::BobMask::None => amiga_operations::BobMask::None,
        amiga_hw::BobMask::Interleaved => amiga_operations::BobMask::Interleaved,
        amiga_hw::BobMask::Separate { offset } => amiga_operations::BobMask::Separate { offset },
        amiga_hw::BobMask::ColorKey { index } => amiga_operations::BobMask::ColorKey { index },
    }
}

/// A plane order as `--plane-order` spells it, for messages about one.
const fn plane_order_name(order: amiga_operations::PlaneOrder) -> &'static str {
    match order {
        amiga_operations::PlaneOrder::Contiguous => "contiguous",
        amiga_operations::PlaneOrder::Interleaved => "interleaved",
        amiga_operations::PlaneOrder::ByteInterleaved => "byte-interleaved",
        amiga_operations::PlaneOrder::WordInterleaved => "word-interleaved",
        amiga_operations::PlaneOrder::LongwordInterleaved => "longword-interleaved",
    }
}

/// Parse a `--plane-order` value.
///
/// The names are the ones the operation schema and a project's `plane_order`
/// field use, so a value copied out of a project document is the value to type;
/// a hyphen is accepted for each underscore because that is how a command line
/// usually spells a compound word.
fn parse_plane_order(spec: &str) -> Result<amiga_operations::PlaneOrder> {
    match spec.replace('-', "_").as_str() {
        "contiguous" => Ok(amiga_operations::PlaneOrder::Contiguous),
        "interleaved" => Ok(amiga_operations::PlaneOrder::Interleaved),
        "byte_interleaved" => Ok(amiga_operations::PlaneOrder::ByteInterleaved),
        "word_interleaved" => Ok(amiga_operations::PlaneOrder::WordInterleaved),
        "longword_interleaved" => Ok(amiga_operations::PlaneOrder::LongwordInterleaved),
        _ => bail!(
            "unknown --plane-order {spec:?} (use contiguous, interleaved, byte-interleaved, \
             word-interleaved, or longword-interleaved)"
        ),
    }
}

/// Parse a `--mask` specification: `none`, `interleaved`, `separate[:OFFSET]`
/// (OFFSET is a whole-file offset; without it the mask follows the data), or
/// `color:INDEX`.
fn parse_bob_mask(
    spec: &str,
    data_offset: usize,
    default_separate: usize,
) -> Result<amiga_hw::BobMask> {
    match spec {
        "none" => Ok(amiga_hw::BobMask::None),
        "interleaved" => Ok(amiga_hw::BobMask::Interleaved),
        "separate" => Ok(amiga_hw::BobMask::Separate {
            offset: default_separate,
        }),
        _ => {
            if let Some(file_offset) = spec.strip_prefix("separate:") {
                let file_offset = usize::try_from(
                    amiga_core::parse_u32(file_offset.trim())
                        .map_err(|message| anyhow::anyhow!("--mask separate offset: {message}"))?,
                )?;
                let offset = file_offset
                    .checked_sub(data_offset)
                    .context("--mask separate offset is before the bitplane data offset")?;
                Ok(amiga_hw::BobMask::Separate { offset })
            } else if let Some(index) = spec.strip_prefix("color:") {
                let index = amiga_core::parse_u32(index.trim())
                    .map_err(|message| anyhow::anyhow!("--mask color index: {message}"))?;
                let index = u8::try_from(index).context("--mask color index must be 0-255")?;
                Ok(amiga_hw::BobMask::ColorKey { index })
            } else {
                bail!(
                    "unknown --mask {spec:?} (use none, interleaved, separate[:OFFSET], or color:INDEX)"
                );
            }
        }
    }
}

/// Encode a decoded BOB as an indexed PNG. When the mask cuts any pixel, a spare
/// palette index (one beyond the image's colors) is reserved as fully
/// Parse a `WxH` dimension string (e.g. `8x8`).
pub(crate) fn parse_dimensions(spec: &str) -> Result<(usize, usize)> {
    let (width, height) = spec
        .split_once(['x', 'X'])
        .with_context(|| format!("expected WxH, got {spec:?}"))?;
    let width = width
        .trim()
        .parse::<usize>()
        .with_context(|| format!("invalid width in {spec:?}"))?;
    let height = height
        .trim()
        .parse::<usize>()
        .with_context(|| format!("invalid height in {spec:?}"))?;
    Ok((width, height))
}

/// Merge consecutive entropy blocks of the same class into ranges and print
/// each with its average entropy.
/// The short label for a block's class. A rendering choice, so it is here and
/// not in the operation, which names the class itself.
const fn class_label(class: amiga_operations::RegionClass) -> &'static str {
    match class {
        amiga_operations::RegionClass::Sparse => "sparse",
        amiga_operations::RegionClass::CodeOrBitmap => "code-or-bitmap",
        amiga_operations::RegionClass::Packed => "packed",
    }
}

pub(crate) fn print_entropy_map(out: &mut Document, blocks: &[amiga_operations::EntropyBlock]) {
    row!(out, "Entropy map ({} block(s)):", blocks.len());
    let mut index = 0;
    while index < blocks.len() {
        let class = blocks[index].class;
        let start = blocks[index].offset as usize;
        let mut end = start;
        let mut entropy_sum = 0.0_f64;
        let mut merged = 0;
        while index < blocks.len() && blocks[index].class == class {
            entropy_sum += f64::from(blocks[index].entropy);
            end = blocks[index].offset as usize + blocks[index].length as usize;
            merged += 1;
            index += 1;
        }
        row!(
            out,
            "  {:#010x}..{:#010x}  {:<14} ({:.2} avg entropy)",
            start,
            end,
            class_label(class),
            entropy_sum / f64::from(merged)
        );
    }
}

/// Score a region for bitmap geometry, from `graphics.bitmap.detect`.
///
/// The width candidates come from the operation. The division that produces
/// them is the same everywhere, and it is the answer someone dialling width,
/// height, and plane count by hand is actually after.
pub(crate) fn bitmap_detect(
    path: &Path,
    offset: u32,
    length: Option<u32>,
    block: u32,
    max_stride: usize,
    top: usize,
) -> Result<()> {
    let mut out = Document::new();
    let (outcome, _) = route(
        path,
        |name| {
            amiga_operations::OperationRequestDocument::GraphicsBitmapDetect(
                amiga_operations::BitmapDetectArguments::new(name)
                    .over(offset, length)
                    .with_block(block)
                    .with_maximum_stride(max_stride),
            )
        },
        "examine",
    )?;
    let detect = outcome
        .graphics_bitmap_detect()
        .context("the bitmap detection returned no result")?;

    print_entropy_map(&mut out, &detect.blocks);

    // Autocorrelation only makes sense on a single bounded region, so the
    // operation runs it only when one was named.
    if length.is_some() {
        row!(
            out,
            "\nRow-stride autocorrelation for {:#x}..{:#x}:",
            detect.offset,
            u64::from(detect.offset) + detect.length
        );
        for score in detect.strides.iter().take(top) {
            row!(
                out,
                "  stride {:>4}  score {:.3}",
                score.stride,
                score.score
            );
        }
        if let Some(best) = detect.strides.first() {
            let candidates = detect
                .geometry
                .iter()
                .map(|candidate| format!("{}p={}px", candidate.planes, candidate.width))
                .collect::<Vec<_>>()
                .join("  ");
            row!(
                out,
                "  best stride {} -> width candidates: {candidates}",
                best.stride
            );
        }
    } else {
        row!(
            out,
            "\n(pass --length to autocorrelate a region for bitmap geometry)"
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

// --- palette ---------------------------------------------------------------

/// Format up to `limit` colors as `#RRGGBB`, appending `…` when truncated.
pub(crate) fn preview_colors(colors: &[u16], limit: usize) -> String {
    let mut preview = colors
        .iter()
        .take(limit)
        .map(|word| {
            let [red, green, blue] = amiga_hw::rgb4_to_rgb8(*word);
            format!("#{red:02x}{green:02x}{blue:02x}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    if colors.len() > limit {
        preview.push_str(" …");
    }
    preview
}

/// Report candidate palette tables, from `graphics.palette.scan`.
pub(crate) fn palette_scan(path: &Path, min: usize) -> Result<()> {
    let mut out = Document::new();
    let (outcome, _) = route(
        path,
        |name| {
            amiga_operations::OperationRequestDocument::GraphicsPaletteScan(
                amiga_operations::PaletteScanArguments::new(name).with_minimum_colours(min),
            )
        },
        "scan",
    )?;
    let scan = outcome
        .graphics_palette_scan()
        .context("the palette scan returned no result")?;
    row!(
        out,
        "Found {} palette table(s) in {}",
        scan.table_total,
        path.display()
    );
    for table in &scan.tables {
        row!(
            out,
            "  {:#010x}  {} colors: {}",
            table.offset,
            table.rgb12.len(),
            preview_colors(&table.rgb12, 8)
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `graphics.palette.export` through the shared router.
///
/// A word whose high nibble is not zero arrives as a warning diagnostic rather
/// than an `eprintln!` this command kept to itself — and it is still a count,
/// not a refusal: a table with one stray entry is still the table, and the count
/// is what tells the user whether the offset guess was good.
pub(crate) fn palette_export(
    path: &Path,
    output: &Path,
    offset: u32,
    count: u32,
    block: usize,
    columns: usize,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let arguments = amiga_operations::PaletteExportArguments::new(
        amiga_operations::PaletteArguments::new(
            source_name.as_str(),
            usize::try_from(count).context("colour count too large")?,
        )
        .at_offset(offset as usize),
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_swatches(block, columns)
    .with_policy(output_policy(force));

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::GraphicsPaletteExport(arguments),
        &context,
        "palette export",
        |outcome| {
            outcome
                .graphics_palette_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .graphics_palette_export()
        .context("the export operation returned no result")?;

    for (index, word) in export.palette.colors_rgb4.iter().enumerate() {
        let [red, green, blue] = export.palette.colors_rgb8[index];
        row!(
            out,
            "  {index:>3}  {word:#06x}  #{red:02x}{green:02x}{blue:02x}"
        );
    }
    row!(
        out,
        "Wrote {} swatch(es) to {}",
        export.palette.colors_rgb4.len(),
        output.display()
    );
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display_spec(addresses: &[u32]) -> amiga_hw::DisplaySpec {
        amiga_hw::DisplaySpec {
            planes: Some(addresses.len() as u8),
            palette: Vec::new(),
            bitplane_addresses: addresses.to_vec(),
        }
    }

    const CONTIGUOUS: amiga_operations::PlaneOrder = amiga_operations::PlaneOrder::Contiguous;
    const SCANLINE: amiga_operations::PlaneOrder = amiga_operations::PlaneOrder::Interleaved;

    #[test]
    fn copper_pointers_resolve_a_contiguous_bitmap_offset() {
        let spec = display_spec(&[0x2100, 0x2120]);
        let base = amiga_core::config::Base {
            origin: 0x2000,
            entry: None,
        };
        let offset = resolve_bitmap_offset(None, Some(&spec), Some(base), 4, 8, 2, CONTIGUOUS)
            .unwrap_or_else(|error| panic!("offset did not resolve: {error}"));
        assert_eq!(offset, 0x100);
    }

    #[test]
    fn copper_pointers_resolve_an_interleaved_bitmap_offset() {
        let spec = display_spec(&[0x2100, 0x2104]);
        let base = amiga_core::config::Base {
            origin: 0x2000,
            entry: None,
        };
        let offset = resolve_bitmap_offset(None, Some(&spec), Some(base), 4, 8, 2, SCANLINE)
            .unwrap_or_else(|error| panic!("offset did not resolve: {error}"));
        assert_eq!(offset, 0x100);
    }

    #[test]
    fn explicit_bitmap_offset_does_not_need_a_base_map() {
        let spec = display_spec(&[0x9000]);
        let offset = resolve_bitmap_offset(Some(0x40), Some(&spec), None, 4, 8, 1, CONTIGUOUS)
            .unwrap_or_else(|error| panic!("explicit offset was rejected: {error}"));
        assert_eq!(offset, 0x40);
    }

    #[test]
    fn copper_pointer_layout_must_match_the_selected_plane_order() {
        let spec = display_spec(&[0x2100, 0x2104]);
        let base = amiga_core::config::Base {
            origin: 0x2000,
            entry: None,
        };
        let error = resolve_bitmap_offset(None, Some(&spec), Some(base), 4, 8, 2, CONTIGUOUS)
            .expect_err("interleaved pointers were accepted as contiguous");
        assert!(error.to_string().contains("expected 0x120"));
    }

    #[test]
    fn a_chunk_interleaved_region_has_no_copper_derived_offset() {
        // The two display layouts have a per-plane start a bitplane pointer can
        // name. A stored, chunk-interleaved region does not, and saying so beats
        // resolving an offset from a stride that means nothing.
        let spec = display_spec(&[0x2100, 0x2104]);
        let base = amiga_core::config::Base {
            origin: 0x2000,
            entry: None,
        };
        let error = resolve_bitmap_offset(
            None,
            Some(&spec),
            Some(base),
            4,
            8,
            2,
            amiga_operations::PlaneOrder::WordInterleaved,
        )
        .expect_err("a word-interleaved region resolved a Copper-derived offset");
        assert!(error.to_string().contains("word-interleaved"), "{error}");
    }

    #[test]
    fn every_plane_order_name_round_trips_through_the_parser() {
        for order in [
            amiga_operations::PlaneOrder::Contiguous,
            amiga_operations::PlaneOrder::Interleaved,
            amiga_operations::PlaneOrder::ByteInterleaved,
            amiga_operations::PlaneOrder::WordInterleaved,
            amiga_operations::PlaneOrder::LongwordInterleaved,
        ] {
            let name = plane_order_name(order);
            assert_eq!(
                parse_plane_order(name).unwrap_or_else(|error| panic!("{name}: {error}")),
                order
            );
            // The document spelling is accepted too, so a value copied out of a
            // project's `plane_order` field is the value to type.
            let underscored = name.replace('-', "_");
            assert_eq!(
                parse_plane_order(&underscored)
                    .unwrap_or_else(|error| panic!("{underscored}: {error}")),
                order
            );
        }
        assert!(parse_plane_order("planar").is_err());
    }

    #[test]
    fn zero_plane_bitmap_is_rejected_before_pointer_indexing() {
        let spec = display_spec(&[]);
        let error = resolve_bitmap_offset(None, Some(&spec), None, 4, 8, 0, CONTIGUOUS)
            .expect_err("zero-plane bitmap resolved an offset");
        assert!(error.to_string().contains("0 bitplanes"));
    }
}
