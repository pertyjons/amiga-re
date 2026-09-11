//! `bitmap compare` — which pixels two images disagree about.
//!
//! An adapter over `graphics.bitmap.compare` and its export: what stays here is
//! the spelling of an alignment and a pinned mask on a command line, and the
//! rendering of the findings.

use super::*;

/// Everything the command line states about one comparison.
///
/// Bundled because a comparison is symmetric in two images and asymmetric in
/// everything else, and a function taking ten positional arguments would let the
/// two sides be swapped by a mistake nothing catches.
pub(crate) struct CompareRequest<'a> {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) planes: Option<u8>,
    pub(crate) align: Option<&'a str>,
    pub(crate) mask: Option<&'a str>,
    pub(crate) maximum_entries: Option<usize>,
    pub(crate) output: Option<&'a Path>,
    pub(crate) force: bool,
}

/// Compare two decoded images and report where they differ.
pub(crate) fn compare_images(a: &Path, b: &Path, request: &CompareRequest<'_>) -> Result<()> {
    let mut out = Document::new();
    // One root, for the reason every multi-source command has one: the resolver
    // has one, and a comparison missing one of its sides would answer a question
    // nobody asked.
    let (base, a_name) = split_under(a, None)?;
    let (_, b_name) = split_under(b, Some(&base))?;

    let mut left = amiga_operations::ComparedBitmap::new(a_name, request.width, request.height);
    let mut right = amiga_operations::ComparedBitmap::new(b_name, request.width, request.height);
    left.planes = request.planes;
    right.planes = request.planes;
    if let Some(spec) = request.align {
        let (x, y) = spec
            .split_once(',')
            .with_context(|| format!("--align expects X,Y, got {spec:?}"))?;
        right.align = Some(amiga_operations::PixelOffset {
            x: x.trim()
                .parse()
                .with_context(|| format!("--align x: {x:?}"))?,
            y: y.trim()
                .parse()
                .with_context(|| format!("--align y: {y:?}"))?,
        });
    }

    let mut arguments = amiga_operations::BitmapCompareArguments::new(left, right);
    arguments.maximum_entries = request.maximum_entries;
    if let Some(spec) = request.mask {
        let (path, digest) = spec.split_once('@').with_context(|| {
            format!(
                "--mask expects FILE@SHA256, got {spec:?}: a mask decides what the \
                     comparison ignores, so it is pinned"
            )
        })?;
        let (_, name) = split_under(Path::new(path.trim()), Some(&base))?;
        arguments.mask = Some(amiga_operations::ValidityMask {
            source: amiga_operations::SourceLocator::file(name),
            sha256: digest.trim().to_ascii_lowercase(),
            offset: None,
            maximum_input_bytes: None,
        });
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(base);
    let comparison = match request.output {
        None => {
            let context = amiga_operations::ExecutionContext::new(&sources);
            let outcome = amiga_operations::Router::execute(
                &amiga_operations::RequestEnvelope::read(
                    amiga_operations::OperationRequestDocument::GraphicsBitmapCompare(arguments),
                ),
                &context,
            );
            fail_on_errors(&outcome).context("failed to compare the images")?;
            let comparison = outcome
                .graphics_bitmap_compare()
                .context("the comparison returned no result")?
                .clone();
            print_warnings(&outcome);
            comparison
        }
        Some(path) => {
            let (output_base, destination) = split_destination_dir(path)?;
            let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
            let context =
                amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
            let committed = commit_reviewed(
                amiga_operations::OperationRequestDocument::GraphicsBitmapCompareExport(
                    amiga_operations::BitmapCompareExportArguments::new(
                        arguments,
                        destination.as_str(),
                    )
                    .with_policy(output_policy(request.force)),
                ),
                &context,
                "comparison",
                |outcome| {
                    outcome
                        .graphics_bitmap_compare_export()
                        .map(|export| export.plan.plan_sha256.clone())
                },
            )?;
            let export = committed
                .graphics_bitmap_compare_export()
                .context("the comparison export returned no result")?;
            eprintln!(
                "Wrote {} file(s) to {}",
                export.plan.files.len(),
                path.display()
            );
            eprintln!("Plan SHA-256: {}", export.plan.plan_sha256);
            print_warnings(&committed);
            export.comparison.clone()
        }
    };

    row!(
        out,
        "{} of {} pixel(s) differ ({} masked out)",
        comparison.differing_pixels,
        comparison.compared_pixels,
        comparison.masked_pixels,
    );
    // Said out loud, because it is the finding a reader of a port most wants and
    // the one an "N pixels differ" line hides: the picture is the same and only
    // the palette moved.
    if comparison.palette_only {
        row!(
            out,
            "the indices agree everywhere: {} pixel(s) differ in colour alone",
            comparison.differing_colour_pixels
        );
    }
    if let Some(bounds) = comparison.differing_bounds {
        row!(
            out,
            "inside [{},{} {}x{}], in {} region(s)",
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height,
            comparison.regions_total,
        );
    }
    for substitution in &comparison.substitutions {
        row!(
            out,
            "  index {} -> {} in {} pixel(s)",
            substitution.from,
            substitution.to,
            substitution.pixels
        );
    }
    if comparison.substitutions_truncated || comparison.regions_truncated {
        row!(
            out,
            "  … {} substitution(s) and {} region(s) found",
            comparison.substitutions_total,
            comparison.regions_total
        );
    }
    out.print()?;
    Ok(())
}

/// Split a path into the root that serves it and the identity a request names,
/// refusing one that is not under `base`.
fn split_under(path: &Path, base: Option<&PathBuf>) -> Result<(PathBuf, String)> {
    let resolved = resolve_media_path(path)?;
    let resolved = resolved
        .canonicalize()
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    let (root, name) = amiga_operations::split_host_path(&resolved)
        .with_context(|| format!("{} does not name a readable file", resolved.display()))?;
    if let Some(base) = base
        && *base != root
    {
        bail!(
            "every image must live in one directory; {} is in {} but the first is in {}",
            resolved.display(),
            root.display(),
            base.display()
        );
    }
    Ok((root, name.as_str().to_owned()))
}
