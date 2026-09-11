use super::*;

// --- manifest --------------------------------------------------------------

/// Run `provenance.manifest` — or its export half when a destination is named.
///
/// The read half is what this printed all along; the write half is new only in
/// that it now goes through the same reviewed plan as every other write this
/// toolkit makes.
pub(crate) fn manifest(path: &Path, output: Option<&Path>, force: bool) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, source_name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);

    let Some(destination_path) = output else {
        let context = amiga_operations::ExecutionContext::new(&sources);
        let outcome = amiga_operations::Router::execute(
            &amiga_operations::RequestEnvelope::read(
                amiga_operations::OperationRequestDocument::ProvenanceManifest(
                    amiga_operations::ManifestArguments::new(source_name.as_str()),
                ),
            ),
            &context,
        );
        fail_on_errors(&outcome)
            .with_context(|| format!("failed to read {}", resolved.display()))?;
        let manifest = outcome
            .provenance_manifest()
            .context("the manifest operation returned no result")?;
        row!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": manifest.name,
                "size": manifest.source.size,
                "sha256": manifest.source.sha256,
            }))?
        );
        print_warnings(&outcome);
        return out.print();
    };

    let (output_base, destination, file_name) = split_destination_file(destination_path)?;
    let arguments = amiga_operations::ManifestExportArguments::new(
        amiga_operations::ManifestArguments::new(source_name.as_str()),
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_policy(output_policy(force));

    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::ProvenanceManifestExport(arguments),
        &context,
        "manifest export",
        |outcome| {
            outcome
                .provenance_manifest_export()
                .map(|export| export.plan.plan_sha256.clone())
        },
    )?;
    let export = committed
        .provenance_manifest_export()
        .context("the manifest export returned no result")?;

    row!(out, "Wrote manifest to {}", destination_path.display());
    row!(out, "Plan SHA-256: {}", export.plan.plan_sha256);
    out.print()?;
    print_warnings(&committed);
    Ok(())
}

/// Write one byte range of a source as its own file, through `source.carve`.
///
/// Routed rather than written here: the operation owns the bounds, the sibling
/// provenance manifest, and the reviewed write plan. The hand-rolled
/// `CarveManifest` that used to live here is gone with it — two implementations
/// of one write path drift, and the one without the plan digest is the one that
/// drifts silently.
pub(crate) fn carve(
    path: &Path,
    output: &Path,
    offset: u32,
    length: u32,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (output_base, destination, file_name) = split_destination_file(output)?;

    let arguments = amiga_operations::CarveArguments::new(
        name.as_str(),
        usize::try_from(offset).context("carve offset does not fit this host")?,
        usize::try_from(length).context("carve length does not fit this host")?,
        destination.as_str(),
    )
    .with_file_name(file_name)
    .with_policy(output_policy(force));

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let committed = commit_reviewed(
        amiga_operations::OperationRequestDocument::SourceCarve(arguments),
        &context,
        "byte carve",
        |outcome| {
            outcome
                .source_carve()
                .map(|carve| carve.plan.plan_sha256.clone())
        },
    )?;
    let carved = committed
        .source_carve()
        .context("the carve operation returned no result")?;

    // The written files come from the plan, so the summary cannot claim a file
    // the operation did not write.
    row!(
        out,
        "Carved {} bytes at {:#x} to {}",
        carved.length,
        carved.offset,
        carved
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

// --- table -----------------------------------------------------------------

/// Render one decoded field, adding what the local config knows about it.
///
/// The pointer annotations are the CLI's own: the operation reports a pointer
/// as a pointer and stops there, because a base address and a symbol table are
/// this frontend's session knowledge rather than facts about the bytes.
pub(crate) fn format_field(
    value: &amiga_operations::TableField,
    base: Option<amiga_core::config::Base>,
    config: Option<&amiga_core::Config>,
) -> String {
    use amiga_operations::TableField;
    match value {
        TableField::Unsigned(number) => format!("{number:#x}"),
        TableField::Signed(number) => format!("{number}"),
        TableField::Pointer(pointer) => {
            let mut text = format!("{pointer:#x}");
            if let Some(offset) = base.and_then(|base| base.abs_to_offset(*pointer)) {
                text.push_str(&format!("(+{offset:#x})"));
            }
            if let Some(name) = config.and_then(|config| config.symbol_name(*pointer)) {
                text.push_str(&format!("({name})"));
            }
            text
        }
        TableField::Text(string) => format!("{string:?}"),
        TableField::Bytes(bytes) => hex::encode(bytes),
    }
}

/// Run `analysis.table.decode` through the shared router and render its rows.
pub(crate) fn table_dump(
    config_override: Option<&Path>,
    path: &Path,
    layout_spec: &str,
    offset: u32,
    count: u32,
    base: &BaseArgs,
) -> Result<()> {
    let mut out = Document::new();
    let resolved = resolve_media_path(path)?;
    let (source_base, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = base.resolve(config.as_ref());

    let arguments =
        amiga_operations::TableDecodeArguments::new(name.as_str(), layout_spec, count as usize)
            .with_offset(offset as usize);
    let resolver = amiga_operations::FilesystemSourceResolver::new(source_base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let request = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AnalysisTableDecode(arguments),
    );

    let outcome = amiga_operations::Router::execute(&request, &context);
    fail_on_errors(&outcome).with_context(|| format!("failed to read {}", resolved.display()))?;
    let table = outcome
        .analysis_table_decode()
        .context("the table operation returned no rows")?;

    for row in &table.rows {
        let fields: Vec<String> = row
            .fields
            .iter()
            .map(|value| format_field(value, base, config.as_ref()))
            .collect();
        row!(out, "{:#08x}  {}", row.offset, fields.join("  "));
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

/// Run `analysis.table.summarize` through the shared router and render it.
///
/// Two sections, because they answer two questions. Per file, what each column
/// holds; then, with more than one file, where the columns disagree — which is
/// the question that needed an external sort and a throwaway program.
///
/// Every file is resolved against one base directory, because the operation
/// names its sources by identity and a resolver serves one root. Files from two
/// directories are refused here, by name, rather than silently read from
/// whichever root happened to win.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one field of the request being built"
)]
pub(crate) fn table_summary(
    config_override: Option<&Path>,
    paths: &[PathBuf],
    layout_spec: &str,
    offset: u32,
    count: u32,
    max_values: usize,
    max_differences: usize,
    base: &BaseArgs,
) -> Result<()> {
    let mut out = Document::new();
    let mut source_base: Option<PathBuf> = None;
    let mut names = Vec::with_capacity(paths.len());
    for path in paths {
        let resolved = resolve_media_path(path)?;
        let (root, name) = amiga_operations::split_host_path(&resolved)
            .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
        match &source_base {
            None => source_base = Some(root),
            Some(existing) if *existing == root => {}
            Some(existing) => bail!(
                "every table must live in one directory: {} is not in {}",
                resolved.display(),
                existing.display()
            ),
        }
        names.push(name.as_str().to_owned());
    }
    let Some(source_base) = source_base else {
        bail!("name at least one table to summarize");
    };
    let config = optional_config(config_override)?.map(|(_, config)| config);
    let base = base.resolve(config.as_ref());

    let arguments =
        amiga_operations::TableSummarizeArguments::new(names, layout_spec, count as usize)
            .with_offset(offset as usize);
    let arguments = amiga_operations::TableSummarizeArguments {
        maximum_values: Some(max_values),
        maximum_differences: Some(max_differences),
        ..arguments
    };
    let resolver = amiga_operations::FilesystemSourceResolver::new(source_base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let request = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::AnalysisTableSummarize(arguments),
    );

    let outcome = amiga_operations::Router::execute(&request, &context);
    fail_on_errors(&outcome).context("failed to summarize the table")?;
    let summary = outcome
        .analysis_table_summarize()
        .context("the summarize operation returned no summary")?;

    let render = |value: &amiga_operations::TableField| format_field(value, base, config.as_ref());
    for (table, path) in summary.tables.iter().zip(paths) {
        row!(
            out,
            "{} — {} of {} row(s) of {} byte(s) from {:#x}",
            path.display(),
            table.rows_read,
            table.row_total,
            summary.record_size,
            summary.offset
        );
        for column in &table.columns {
            let extremes = match (column.minimum, column.maximum) {
                (Some(low), Some(high)) => format!("  [{low}..{high}]"),
                _ => String::new(),
            };
            // The distinct count is what says whether the list below it is the
            // whole story, so it leads.
            row!(
                out,
                "  +{:<4x} {} distinct{}{}",
                column.field_offset,
                column.distinct_total,
                extremes,
                if column.values_truncated {
                    "  (listing the most frequent)"
                } else {
                    ""
                }
            );
            for entry in &column.values {
                row!(
                    out,
                    "         {:>6}x  {}",
                    entry.count,
                    render(&entry.value)
                );
            }
        }
        row!(out);
    }

    if summary.comparisons.is_empty() {
        print_warnings(&outcome);
        return out.print();
    }
    row!(out, "Comparison over {} row(s):", summary.compared_rows);
    // Named the way the listing above names it. The comparison carries a column
    // *index* and the listing prints a field *offset*, so "column 1" and "+2"
    // were the same column under two spellings and a reader had to count the
    // rows between them to find out.
    let field_offset = |column: u32| {
        summary
            .tables
            .first()
            .and_then(|table| table.columns.get(column as usize))
            .map_or_else(String::new, |field| format!(" (+{:x})", field.field_offset))
    };
    for comparison in &summary.comparisons {
        if comparison.identical {
            row!(
                out,
                "  column {}{}: identical",
                comparison.column,
                field_offset(comparison.column)
            );
            continue;
        }
        row!(
            out,
            "  column {}{}: {} differing row(s)",
            comparison.column,
            field_offset(comparison.column),
            comparison.differing_total
        );
        for difference in &comparison.differences {
            let values: Vec<String> = difference.values.iter().map(render).collect();
            row!(out, "    row {:<6} {}", difference.row, values.join("  "));
        }
        if comparison.differences.len() as u64 != comparison.differing_total {
            row!(
                out,
                "    ... {} more",
                comparison.differing_total - comparison.differences.len() as u64
            );
        }
    }
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}
