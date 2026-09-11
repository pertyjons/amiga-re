use super::*;

// --- lha -------------------------------------------------------------------

/// List an archive's members, from `container.lha.list`.
///
/// The asymmetry this closes: `lha extract` has routed since the operation API
/// landed, so the archive one command could extract was one the other could
/// only describe outside the vocabulary.
pub(crate) fn lha_list(path: &Path) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(root);
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::ContainerLhaList(
                amiga_operations::LhaListArguments::new(name.as_str()),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome).with_context(|| format!("failed to list {}", resolved.display()))?;
    let list = outcome
        .container_lha_list()
        .context("the archive listing returned no result")?;

    row!(out, "{} member(s) in {}", list.member_total, path.display());
    for member in &list.members {
        row!(
            out,
            "{}  {:>9} -> {:<9}  crc {:#06x}  {}",
            member.method,
            member.compressed_size,
            member.original_size,
            member.crc16,
            member.name
        );
    }
    if list.members_truncated {
        row!(
            out,
            "... {} of {} member(s) shown",
            list.members.len(),
            list.member_total
        );
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `container.lha.extract` through the shared router.
///
/// The operation owns extraction planning, provenance, and replacement checks; this
/// adapter renders the plan and submits the reviewed write.
///
/// The convenience wrapper reviews on the user's behalf, exactly as `adf
/// extract` does: it prepares, then commits the plan it just built. Automation
/// drives the same two halves separately with `operations run`.
pub(crate) fn lha_extract(source: &Path, output: &Path, force: bool) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(source)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, output_name) = split_output_path(output)?;

    let arguments = amiga_operations::ContainerExtractArguments::new(
        source_name.as_str(),
        output_name.as_str(),
    )
    .with_policy(output_policy(force));

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let mut prepare = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ContainerLhaExtract(arguments.clone()),
    );
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    fail_on_errors(&prepared)
        .with_context(|| format!("failed to extract {}", resolved.display()))?;
    let plan = prepared
        .container_extract()
        .context("the extraction operation produced no plan")?
        .plan
        .clone();

    let mut commit = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ContainerLhaExtract(arguments),
    );
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256.clone(),
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    fail_on_errors(&committed)
        .with_context(|| format!("failed to extract {}", resolved.display()))?;

    row!(
        out,
        "Extracted {} member(s) from {} to {}",
        plan.files.len(),
        resolved.display(),
        output.display(),
    );
    row!(out, "Plan SHA-256: {}", plan.plan_sha256);
    out.print()?;
    print_warnings(&prepared);
    Ok(())
}
