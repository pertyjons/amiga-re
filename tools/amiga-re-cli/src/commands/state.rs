//! `state snapshot` and `state compare` — a machine's state in the project's
//! own vocabulary.
//!
//! Both are adapters over `analysis.state.*`: what stays here is the spelling of
//! a memory range on a command line, and the rendering.

use super::*;

/// Decode a machine's memory into named, typed values.
///
/// The project is discovered from the working directory, and every memory file
/// has to live under the directory that serves it. That is not a limitation of
/// this command so much as of what a snapshot *is*: the operation names its
/// sources by identity against one root, and a snapshot half of whose bytes came
/// from somewhere the request could not name would describe a machine nobody can
/// reconstruct.
pub(crate) fn state_snapshot(
    memory: &[String],
    image: Option<&str>,
    registers: &[String],
    hunk_bases: &[String],
    maximum_fields: Option<usize>,
) -> Result<()> {
    let mut out = Document::new();
    let cwd = std::env::current_dir().context("failed to read the current directory")?;
    let project = amiga_project::discover(&cwd).with_context(|| {
        format!(
            "no {} found in {} or its parents",
            amiga_project::load::ROOT_FILE_NAME,
            cwd.display()
        )
    })?;
    let (base, name) = split_project_root(&project)?;

    let mut regions = Vec::with_capacity(memory.len());
    for spec in memory {
        regions.push(parse_region(spec, &base)?);
    }
    let mut arguments = amiga_operations::StateSnapshotArguments::new(regions);
    arguments.image = image.map(ToOwned::to_owned);
    arguments.maximum_fields = maximum_fields;
    for spec in hunk_bases {
        let (hunk, address) = parse_hunk_base(spec)?;
        arguments
            .hunk_bases
            .push(amiga_operations::HunkBase { hunk, address });
    }
    // Always sent, and always complete. A register file with only the registers
    // a caller mentioned would make an unmentioned base register read as zero,
    // which is a plausible address and the wrong one.
    if !registers.is_empty() {
        let (data, address) = register_seeds(registers)?;
        arguments.registers = Some(amiga_operations::SandboxRegisters {
            d: data,
            a: address,
            usp: 0,
            ssp: 0,
            pc: 0,
            sr: 0x2700,
        });
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let mut envelope = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AnalysisStateSnapshot(arguments),
    );
    envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name });
    let outcome = amiga_operations::Router::execute(&envelope, &context);
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to snapshot the state of {}", project.display()))?;
    let snapshot = outcome
        .analysis_state_snapshot()
        .context("the snapshot operation returned no result")?;

    // JSON on stdout, because this document is an input: `state compare` reads
    // it, and so does whatever a clean-room port writes to be checked against.
    row!(out, "{}", serde_json::to_string_pretty(snapshot)?);
    out.print()?;
    print_warnings(&outcome);
    eprintln!(
        "{} field(s) from {} region(s) of {}",
        snapshot.fields_total,
        snapshot.regions.len(),
        snapshot.image_id,
    );
    Ok(())
}

/// Compare state snapshots field by field.
pub(crate) fn state_compare(
    snapshots: &[PathBuf],
    maximum_differences: Option<usize>,
    json: bool,
) -> Result<()> {
    let mut out = Document::new();
    // One root, for the reason `compare` gives for records: the resolver has
    // one, and a comparison missing one of its sides would answer a question
    // nobody asked.
    let mut base: Option<PathBuf> = None;
    let mut names = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let resolved = resolve_media_path(snapshot)?;
        let (root, name) = amiga_operations::split_host_path(&resolved)
            .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
        match &base {
            None => base = Some(root),
            Some(first) if *first == root => {}
            Some(first) => bail!(
                "every snapshot must live in one directory; {} is in {} but the first is in {}",
                resolved.display(),
                root.display(),
                first.display()
            ),
        }
        names.push(name.as_str().to_owned());
    }
    let base = base.context("no snapshots to compare")?;

    let mut arguments = amiga_operations::StateCompareArguments::of(names);
    arguments.maximum_differences = maximum_differences;
    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisStateCompare(arguments),
        ),
        &context,
    );
    fail_on_errors(&outcome).context("failed to compare the snapshots")?;
    let result = outcome
        .analysis_state_compare()
        .context("the comparison returned no result")?;

    if json {
        row!(out, "{}", serde_json::to_string_pretty(result)?);
        out.print()?;
        print_warnings(&outcome);
        return Ok(());
    }

    for (index, snapshot) in result.snapshots.iter().enumerate() {
        let short = snapshot
            .sha256
            .get(..16)
            .unwrap_or(snapshot.sha256.as_str());
        row!(
            out,
            "[{index}] {} ({short}) — {} field(s) of {}",
            snapshot.name,
            snapshot.fields_total,
            snapshot.image_id,
        );
    }
    if result.identical {
        row!(
            out,
            "identical: {} field(s) agree in every snapshot",
            result.paths_total
        );
    } else {
        row!(
            out,
            "{} of {} field(s) differ",
            result.differences_total,
            result.paths_total
        );
        for difference in &result.differences {
            let rendered: Vec<String> = difference.values.iter().map(render).collect();
            row!(out, "  {}: {}", difference.path, rendered.join("  |  "));
        }
        if result.differences_truncated {
            row!(
                out,
                "  … {} of {} difference(s) shown",
                result.differences.len(),
                result.differences_total
            );
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// One value as a person reads it.
///
/// Absent renders as `—` rather than as a value, because a field the snapshot
/// does not have and a field holding zero are different findings.
fn render(value: &Option<amiga_operations::StateValue>) -> String {
    match value {
        None => "—".to_owned(),
        Some(amiga_operations::StateValue::Integer { value, .. }) => value.to_string(),
        Some(amiga_operations::StateValue::Pointer {
            address,
            address_space,
        }) => format!("{address:#010x} ({address_space})"),
        Some(amiga_operations::StateValue::Enum { value, member }) => match member {
            Some(member) => format!("{member} ({value})"),
            None => format!("{value} (unnamed)"),
        },
        Some(amiga_operations::StateValue::Bytes { hex }) => format!("0x{hex}"),
    }
}

/// Parse one `ADDR=FILE[@SHA256]` memory range.
fn parse_region(spec: &str, base: &Path) -> Result<amiga_operations::StateRegion> {
    let (address, rest) = spec
        .split_once('=')
        .with_context(|| format!("--memory expects ADDR=FILE[@SHA256], got {spec:?}"))?;
    let address = amiga_core::parse_u32(address.trim())
        .map_err(|message| anyhow::anyhow!("--memory address: {message}"))?;
    let (path, sha256) = match rest.split_once('@') {
        Some((path, digest)) => (path, Some(digest.trim().to_ascii_lowercase())),
        None => (rest, None),
    };
    let resolved = resolve_media_path(Path::new(path.trim()))?;
    // Canonicalized before the roots are compared, or `../mem.bin` names the
    // directory `..` and is refused for sitting somewhere it is not. The
    // project root arrives canonical for the same reason.
    let resolved = resolved
        .canonicalize()
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    // Named against the root that serves the project, so one request can name
    // both. A file elsewhere is refused rather than resolved against a root it
    // is not under.
    if root != base {
        bail!(
            "{} is in {}, and this snapshot names its sources against {}; put the memory \
             beside the project",
            resolved.display(),
            root.display(),
            base.display()
        );
    }
    let mut region = amiga_operations::StateRegion::new(address, name.as_str());
    region.sha256 = sha256;
    Ok(region)
}

/// The directory that serves a project, and the identity a request names it by.
fn split_project_root(project: &Path) -> Result<(PathBuf, String)> {
    let directory = if project.is_dir() {
        project.to_path_buf()
    } else {
        project.parent().unwrap_or(Path::new(".")).to_path_buf()
    };
    let canonical = directory
        .canonicalize()
        .with_context(|| format!("{} is not a readable directory", directory.display()))?;
    let name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .context("the project directory has no usable name")?
        .to_owned();
    let base = canonical
        .parent()
        .context("the project directory has no parent to serve it")?
        .to_path_buf();
    Ok((base, name))
}
