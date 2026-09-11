//! Every `project` subcommand: the read-only surface, the reviewed edits, and
//! the three that write a directory.
//!
//! `check` loads the complete project, runs every semantic rule, and reports stable
//! problem codes. Scripts can act on `STALE_ANNOTATION` without parsing the
//! human-readable explanation.
//!
//! Every command that *changes* a project goes through [`run_edit`], which
//! prepares, prints what would change, and commits against the digest the
//! preparation produced. The three that do not are the three that write a
//! directory rather than editing documents inside one: `init`, `extract` and
//! `migrate`.

use super::*;

/// Locate the project the user meant: an explicit path, or the nearest root at
/// or above the working directory.
fn resolve_project(path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = path {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().context("failed to read the current directory")?;
    amiga_project::discover(&cwd).with_context(|| {
        format!(
            "no {} found in {} or its parents",
            amiga_project::load::ROOT_FILE_NAME,
            cwd.display()
        )
    })
}

/// The leading half of a digest, for a listing.
///
/// Deliberately not `&digest[..16]`. A digest rendered by these commands may
/// have come out of a project *document* rather than out of a computation over
/// bytes, and nothing at load time enforces the bundled schema's
/// `^[0-9a-f]{64}$`: the loader is typed rather than schema-driven, and
/// `project.check`'s semantic rules ask whether a digest is *present*, not how
/// long it is. A hand-edited short digest therefore reached a listing and
/// panicked it, on a project the reader had not written.
fn short_digest(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

/// Split a project path into the root an adapter serves and the identity a
/// request names, the same way a source path is split.
fn split_project_path(path: &Path) -> Result<(PathBuf, String)> {
    let directory = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
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
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    Ok((base, name))
}

/// Run `project.check` through the shared router.
///
/// A project with non-fatal problems still loads, but this check exits non-zero to
/// signal that it needs attention. The result follows the status returned by the
/// operation.
pub(crate) fn project_check(path: Option<&Path>) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let (base, name) = split_project_path(&root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);

    let mut envelope = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ProjectCheck(
            amiga_operations::ProjectArguments::default(),
        ),
    );
    envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name });

    let outcome = amiga_operations::Router::execute(&envelope, &context);
    fail_on_errors(&outcome).with_context(|| format!("failed to check {}", root.display()))?;
    let check = outcome
        .project_check()
        .context("the check operation returned no result")?;

    row!(
        out,
        "{}: {} source(s), {} object(s), {} annotation(s)",
        check.name,
        check.sources,
        check.objects,
        check.annotations
    );
    if check.problems.is_empty() {
        row!(out, "no problems");
        return out.print();
    }
    // Codes first so the output is greppable; the message is for the human.
    for problem in &check.problems {
        match &problem.subject {
            Some(subject) => row!(out, "{}: {subject}: {}", problem.code, problem.message),
            None => row!(out, "{}: {}", problem.code, problem.message),
        }
    }
    // The problems are the answer, so they are printed before the failure they
    // add up to is raised.
    out.print()?;
    bail!(
        "{} problem(s); the project opened, but they need attention",
        check.problems.len()
    )
}

/// Summarize what a project contains, from `project.describe`.
///
/// The columns, the ordering, and what goes to standard error are this
/// frontend's. Every id, digest, and count under them is the operation's.
pub(crate) fn project_show(path: Option<&Path>) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let outcome = route_project(&root, |arguments| {
        amiga_operations::OperationRequestDocument::ProjectDescribe(arguments)
    })?;
    fail_on_errors(&outcome).with_context(|| format!("failed to load {}", root.display()))?;
    let project = outcome
        .project_describe()
        .context("the project summary returned no result")?;

    row!(out, "{} ({})", project.name, project.id);
    if let Some(notes) = &project.notes {
        row!(out, "{notes}");
    }
    row!(out);

    row!(out, "Sources ({}):", project.sources.len());
    for source in &project.sources {
        // A capture is marked, because a digest alone says the same thing for
        // both kinds and only one of them can be checked against anything
        // outside the project.
        let provenance = if source.reproducible {
            ""
        } else {
            "  [captured — not reproducible]"
        };
        row!(
            out,
            "  {:<28} {:<10} {}{provenance}",
            source.id,
            source.kind,
            source
                .sha256
                .as_ref()
                .map_or("(unpinned)", |digest| short_digest(digest))
        );
    }

    if !project.source_sets.is_empty() {
        row!(out, "\nSource sets ({}):", project.source_sets.len());
        for set in &project.source_sets {
            row!(out, "  {:<28} {} member(s)", set.id, set.member_count);
        }
    }

    row!(out, "\nObjects ({}):", project.objects.len());
    for object in &project.objects {
        // How, not only from what. A decompressed object and a byte range of
        // the same parent are different claims, and a summary that showed them
        // identically would hide the one that needs a decoder to check.
        let how = object
            .derivation
            .as_ref()
            .map_or_else(String::new, |how| format!(" ({how})"));
        row!(
            out,
            "  {:<28} {:>10} bytes  from {}{how}",
            object.id,
            object.size,
            object.parent_id
        );
    }

    for program in &project.programs {
        row!(out, "\nProgram {} ({}):", program.name, program.id);
        for image in &program.images {
            row!(out, "  {} <- {}", image.id, image.object_id);
            for map in &image.load_maps {
                let bases: Vec<String> = map
                    .segments
                    .iter()
                    .map(|segment| format!("hunk{}@{}", segment.hunk, segment.runtime_base))
                    .collect();
                row!(out, "    {:<28} {}", map.id, bases.join(" "));
            }
        }
    }

    if !project.resources.is_empty() {
        row!(out, "\nResources ({}):", project.resources.len());
        for resource in &project.resources {
            let target = project_resource_target(&resource.target);
            row!(
                out,
                "  {:<28} {:<8} {} ({target}{}) → {}",
                resource.id,
                resource.kind,
                resource.name,
                if resource.target_resolved {
                    ""
                } else {
                    ", unresolved"
                },
                resource.export_media_type
            );
            // The state an export surface renders: a resource with no artifact
            // has never been produced, and one whose key moved needs remaking.
            // Both are ordinary, and neither is an error.
            if resource.artifacts.is_empty() {
                row!(out, "      not exported");
            }
            for artifact in &resource.artifacts {
                row!(
                    out,
                    "      {} · {} bytes · {}",
                    artifact.path,
                    artifact.size,
                    if artifact.current {
                        "current"
                    } else {
                        "stale — the project's recipe has changed since"
                    }
                );
            }
        }
    }

    row!(
        out,
        "\n{} annotation(s), {} resource(s), {} type(s)",
        project.annotation_count,
        project.resource_count,
        project.type_count
    );

    // Non-fatal problems belong on standard error, so `project show` piped
    // into something stays a clean summary.
    out.print()?;
    print_warnings(&outcome);
    Ok(())
}

fn project_resource_target(target: &amiga_operations::ProjectResourceTarget) -> String {
    use amiga_operations::ProjectResourceTarget;

    match target {
        ProjectResourceTarget::Object {
            object_id,
            offset,
            length,
            ..
        } => format!(
            "{object_id} {offset:#010x}..{:#010x}",
            offset.saturating_add(*length)
        ),
        ProjectResourceTarget::Hunk {
            image_id,
            hunk,
            offset,
            length,
            ..
        } => format!(
            "{image_id} hunk {hunk} {offset:#x}..{:#x}",
            offset.saturating_add(*length)
        ),
        ProjectResourceTarget::Runtime {
            image_id,
            load_map_id,
            address,
            length,
            ..
        } => format!("{image_id} {load_map_id} runtime {address} + {length:#x}"),
        ProjectResourceTarget::BaseRegister {
            image_id,
            base_register,
            displacement,
            width,
            ..
        } => format!("{image_id} {base_register}{displacement:+#x} ({width} bytes)"),
        ProjectResourceTarget::Entity { entity_id } => format!("entity {entity_id}"),
    }
}

/// Execute a project-backed read, naming the project the way every one of them
/// does: through the envelope's locator rather than an argument.
fn route_project(
    root: &Path,
    build: impl FnOnce(amiga_operations::ProjectArguments) -> amiga_operations::OperationRequestDocument,
) -> Result<amiga_operations::OperationOutcome> {
    let (base, name) = split_project_path(root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let mut envelope = amiga_operations::RequestEnvelope::read(build(
        amiga_operations::ProjectArguments::default(),
    ));
    envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name });
    Ok(amiga_operations::Router::execute(&envelope, &context))
}

/// Print one bundled schema, or emit the whole set.
///
/// The schemas are compiled into the binary. `--output` writes *copies* for an
/// editor to point at; a loader never fetches a schema a project names.
pub(crate) fn project_schema(
    document_kind: Option<&str>,
    output: Option<&Path>,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    if let Some(directory) = output {
        let planned: Vec<PlannedFile> = amiga_project::schemas::ALL
            .iter()
            .map(|(name, text)| PlannedFile {
                path: PathBuf::from(*name),
                bytes: text.as_bytes().to_vec(),
            })
            .collect();
        let manifest = serde_json::to_vec_pretty(&serde_json::json!({
            "format_version": 1,
            "project_format_version": amiga_project::FORMAT_VERSION,
            "files": planned
                .iter()
                .map(|file| serde_json::json!({
                    "path": file.path.display().to_string(),
                    "sha256": sha256(&file.bytes),
                }))
                .collect::<Vec<_>>(),
        }))?;
        let count = planned.len();
        let plan = ExtractionPlan::new(planned, Vec::new())?;
        plan.commit(directory, force, "manifest.json", &manifest)?;
        row!(
            out,
            "Wrote {count} schema file(s) to {}",
            directory.display()
        );
        return out.print();
    }

    let kind = document_kind.unwrap_or("project");
    let schema = amiga_project::schemas::for_document_kind(kind).with_context(|| {
        format!(
            "unknown document kind {kind:?}; this build serves project, sources, \
             inventory, program, annotations, resources, types"
        )
    })?;
    print_document(schema)
}

/// Verify every source and object against the bytes on disk.
///
/// Writes nothing and routes through `project.verify`: the recovery capabilities of
/// this build live in `amiga-operations` and are shared with downstream callers.
///
/// A source this machine cannot find is reported, never skipped — a verify that
/// only checked what it could reach and then said "all good" would be worse than
/// no verify at all.
pub(crate) fn project_verify(path: Option<&Path>) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let (base, name) = split_project_path(&root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);

    let mut envelope = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ProjectVerify(
            amiga_operations::ProjectArguments::default(),
        ),
    );
    envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name });

    let outcome = amiga_operations::Router::execute(&envelope, &context);
    // A contradiction is reported as an error diagnostic *and* in the result, so
    // the listing below has to be printed before the failure is raised: the
    // point of a verify is what it found, not that it failed.
    let Some(report) = outcome.project_verify() else {
        fail_on_errors(&outcome).with_context(|| format!("failed to verify {}", root.display()))?;
        bail!("the verify operation returned no result");
    };

    for entity in report.sources.iter().chain(&report.objects) {
        row!(out, "{:<28} {}", entity.id, describe(entity));
    }
    // Artifacts are listed apart from the sources and objects because they are
    // not project truth: a missing one is regenerable, and printing it beside a
    // contradicted object would read as the same kind of trouble.
    for artifact in &report.artifacts {
        row!(
            out,
            "{:<28} {}: {}",
            artifact.id,
            artifact.status,
            artifact.detail
        );
    }
    row!(
        out,
        "
{}/{} source(s) and {}/{} object(s) verified",
        report.verified_sources,
        report.sources.len(),
        report.verified_objects,
        report.objects.len()
    );
    let stale = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.status == "stale")
        .count();
    if stale > 0 {
        row!(out, "{stale} artifact(s) need re-exporting");
    }

    if report
        .sources
        .iter()
        .chain(&report.objects)
        .any(|entity| entity.contradicted)
        || report
            .artifacts
            .iter()
            .any(|artifact| artifact.contradicted)
    {
        out.print()?;
        bail!("the bytes on disk contradict what the project pins");
    }
    out.print()
}

/// One verified entity as a line of terminal output.
///
/// Rendered from the stable `status` code, never by matching on `detail`: the
/// prose is the operation's to reword, and a frontend that parsed it would break
/// the next time it was improved.
fn describe(entity: &amiga_operations::VerifiedEntity) -> String {
    match entity.status {
        "verified" => "verified".to_owned(),
        // The heading is the code, not the word "mismatch" for everything that
        // contradicts: a size disagreement and an unreadable file are not
        // digest failures, and heading them as one sent readers hunting for
        // corruption that was never there.
        _ if entity.contradicted => format!(
            "{}: {}",
            entity.status.replace('_', " ").to_uppercase(),
            entity.detail
        ),
        _ => entity.detail.clone(),
    }
}

/// Print the inventory a directory source would pin, from `project.inventory`.
///
/// Follows no symbolic link, and prints what it left out and why: an inventory
/// that skipped something quietly would claim a completeness it does not have.
pub(crate) fn project_inventory(directory: &Path) -> Result<()> {
    let mut out = Document::new();
    let absolute = std::path::absolute(directory)
        .with_context(|| format!("failed to resolve {}", directory.display()))?;
    let (base, name) = amiga_operations::split_host_path(&absolute)
        .with_context(|| format!("{} does not name a directory", directory.display()))?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::ProjectInventory(
                amiga_operations::ProjectInventoryArguments::new(name.as_str()),
            ),
        ),
        &context,
    );
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to inventory {}", directory.display()))?;
    let inventory = outcome
        .project_inventory()
        .context("the inventory returned no result")?;

    for file in &inventory.files {
        row!(
            out,
            "{:>10}  {}  {}",
            file.size,
            short_digest(&file.sha256),
            file.path
        );
    }
    for omitted in &inventory.omitted {
        eprintln!("omitted ({}): {}", omitted.reason, omitted.path);
    }
    row!(
        out,
        "
{} file(s), {} omitted, tree SHA-256 {}",
        inventory.file_total,
        inventory.omitted.len(),
        inventory.tree_sha256
    );
    out.print()
}

/// List a project's reviewed knowledge about one image or one object, from
/// `project.annotations`.
///
/// Print annotations for one image or object. Every lookup uses the operation API and
/// preserves the target identity, so identical offsets in different images cannot be
/// confused. The CLI chooses the layout and sends stale annotations to standard error.
///
/// The two scopes print differently because they answer differently: an image
/// resolves to hunk offsets, and an object lists the claims made about its
/// bytes, each with whether the bytes it was established against are still
/// there.
pub(crate) fn project_annotations(
    path: Option<&Path>,
    image: Option<&str>,
    object: Option<&str>,
) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let arguments = match (image, object) {
        (Some(image), None) => amiga_operations::ProjectAnnotationsArguments::image(image),
        (None, Some(object)) => amiga_operations::ProjectAnnotationsArguments::object(object),
        // Refused here rather than sent as an empty scope, so the message names
        // the two spellings instead of the operation's argument path.
        _ => anyhow::bail!(
            "name an image or --object, not both and not neither: an offset means nothing \
             until you say what it is an offset into"
        ),
    };
    let outcome = route_project(&root, |_| {
        amiga_operations::OperationRequestDocument::ProjectAnnotations(arguments.clone())
    })?;
    fail_on_errors(&outcome)
        .with_context(|| format!("failed to read annotations from {}", root.display()))?;
    let annotations = outcome
        .project_annotations()
        .context("the annotation listing returned no result")?;

    // Object scope: the claims made about these bytes, in file order. Each
    // prints its own id, because the three edits a reader reaches for next —
    // rename, rebase, remove — all name an annotation rather than an offset.
    for range in &annotations.ranges {
        row!(
            out,
            "{:#010x}..{:#010x}  {:<8} {}{}",
            range.offset,
            range.offset.saturating_add(range.length),
            range.kind,
            range.label,
            if range.established && !range.marked_stale {
                String::new()
            } else {
                // Loud, and named: the offsets describe bytes that are no
                // longer there, so the row is knowledge to rebase rather than
                // knowledge to read.
                "  [stale: rebase it rather than trusting the offset]".to_owned()
            }
        );
        row!(
            out,
            "                        {} · {}{}",
            range.id,
            range.origin,
            range
                .confidence
                .as_ref()
                .map_or_else(String::new, |confidence| format!(" · {confidence}"))
        );
        if let Some(notes) = &range.notes {
            row!(out, "                        ; {notes}");
        }
    }
    if annotations.ranges_truncated {
        eprintln!(
            "{} of {} ranges reported; raise maximum_locations to see the rest",
            annotations.ranges.len(),
            annotations.range_total
        );
    }

    for location in &annotations.locations {
        part!(out, "hunk{}+{:#06x}  ", location.hunk, location.offset);
        if let Some(function) = &location.function {
            part!(out, "fn {function}  ");
        }
        for symbol in &location.symbols {
            part!(out, "sym {symbol}  ");
        }
        for region in &location.regions {
            part!(out, "[{region}]  ");
        }
        for bookmark in &location.bookmarks {
            part!(out, "★ {bookmark}  ");
        }
        row!(out);
        for comment in &location.comments {
            for line in comment.text.lines() {
                row!(out, "               ; {} {line}", comment.placement);
            }
        }
    }

    // Locals, listed under the function that scopes them.
    for local in &annotations.locals {
        let storage = match &local.storage {
            amiga_operations::LocalStorage::Register { register } => register.clone(),
            amiga_operations::LocalStorage::Stack { base, displacement } => {
                format!("({displacement},{base})")
            }
        };
        let live = local.lifetime.map_or_else(
            || " (whole function)".to_owned(),
            |[start, end]| format!(" live {start:#x}..{end:#x}"),
        );
        row!(
            out,
            "               local {}/{} = {storage}{live}",
            local.function_name,
            local.name
        );
    }

    // Base-register globals, which belong to no function and therefore to no
    // offset. Listed after the located annotations rather than folded into
    // them: they are a location in the loaded program, not a place in the file,
    // and printing them under a hunk offset would invent one.
    for global in &annotations.globals {
        let sign = if global.displacement < 0 { "-" } else { "+" };
        row!(
            out,
            "{}{sign}{:#x}  global {} ({} byte(s))",
            global.base.to_uppercase(),
            global.displacement.unsigned_abs(),
            global.name,
            global.width
        );
    }

    // Stale annotations are excluded from every lookup above, so they are
    // reported here or nowhere.
    out.print()?;
    for id in &annotations.stale {
        eprintln!("stale, project-wide (excluded until rebased): {id}");
    }
    print_warnings(&outcome);
    Ok(())
}

/// Prepare an edit, show what it would change, and apply it unless `--dry-run`.
///
/// The two halves are the ones automation would drive separately: preparing
/// re-reads nothing the review did not see, and applying re-checks every digest
/// so an edit made while the review was open is refused rather than discarded.
fn run_edit(path: Option<&Path>, edit: amiga_operations::ProjectEdit, dry_run: bool) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let (base, name) = split_project_path(&root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let document = amiga_operations::OperationRequestDocument::ProjectEdit(
        amiga_operations::ProjectEditArguments::new(vec![edit]),
    );
    let envelope = |mode| {
        let mut envelope = amiga_operations::RequestEnvelope::read(document.clone());
        envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name.clone() });
        envelope.execution.mode = mode;
        envelope
    };

    let prepared = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    fail_on_errors(&prepared)
        .with_context(|| format!("failed to plan the edit to {}", root.display()))?;
    let plan = prepared
        .project_edit()
        .context("the edit operation produced no plan")?;

    // The rebase's target is the operation's answer, printed before the plan it
    // produced — the same line this command has always shown.
    for rebase in &plan.rebases {
        row!(
            out,
            "Rebasing {} onto {} at {}",
            rebase.id,
            rebase.object_id,
            short_digest(&rebase.object_sha256)
        );
    }
    for document in &plan.documents {
        if !document.changed {
            continue;
        }
        row!(
            out,
            "{}: would be rewritten ({} bytes)",
            document.path,
            document.size
        );
    }
    for document in &plan.documents {
        row!(
            out,
            "  expects {} at {}",
            document.path,
            short_digest(&document.expected_sha256)
        );
    }

    if dry_run {
        row!(out, "\nDry run: nothing was written.");
        return out.print();
    }
    // The digest the plan just produced is what authorizes the write. Preparing
    // twice is not waste, it is the check: anything that changed between the
    // two comes back as a conflict rather than as a surprise write.
    let committed = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan_sha256.clone(),
        }),
        &context,
    );
    fail_on_errors(&committed)
        .with_context(|| format!("failed to write the edit to {}", root.display()))?;
    let applied = committed
        .project_edit()
        .context("the edit operation produced no plan")?;
    // Both numbers, because they are different facts and the preview above
    // already showed the smaller one. A changeset installs the whole document
    // set so the install is all-or-nothing, so a document whose content did not
    // change is still written — and reporting only the file count told a reader
    // who had just been shown one "would be rewritten" that two had been.
    let changed = applied
        .documents
        .iter()
        .filter(|document| document.changed)
        .count();
    row!(
        out,
        "\nWrote {} document(s), {changed} changed.",
        applied.written.len()
    );
    out.print()
}

/// Rename a function or symbol.
pub(crate) fn project_rename(
    path: Option<&Path>,
    id: &str,
    name: &str,
    dry_run: bool,
) -> Result<()> {
    run_edit(
        path,
        amiga_operations::ProjectEdit::Rename {
            id: id.to_owned(),
            name: name.to_owned(),
        },
        dry_run,
    )
}

/// Accept that an annotation's object has changed, recording its current digest.
///
/// Nothing rebases automatically: a rebase asserts that the offsets still mean
/// what they meant, which only a person can decide.
///
/// *Which* object, and at what digest, is derived by the operation from the
/// project's own object record: it is a fact about the project, and a caller
/// supplying it would let two callers rebase one annotation onto two different
/// digests and both be accepted.
pub(crate) fn project_rebase(path: Option<&Path>, id: &str, dry_run: bool) -> Result<()> {
    run_edit(
        path,
        amiga_operations::ProjectEdit::Rebase { id: id.to_owned() },
        dry_run,
    )
}

/// Register bytes a capture produced as a project source.
///
/// The size and digest are not arguments: they are facts about the file, read
/// here so that the two numbers a caller would otherwise transcribe cannot
/// disagree with the bytes they describe. The operation reads it again and
/// refuses a pin the bytes contradict — this is convenience, not the check.
pub(crate) fn project_register_capture(
    path: Option<&Path>,
    id: &str,
    name: &str,
    file: &str,
    notes: &str,
    dry_run: bool,
) -> Result<()> {
    let root = resolve_project(path)?;
    // The rule the format applies to a location it records, applied before the
    // read rather than after it. The operation checks the same three things and
    // is what actually guards the document; doing it here too means an absolute
    // or climbing `--file` is refused naming the argument the caller wrote,
    // instead of the toolkit reading a path its own rule forbids and reporting
    // the refusal as a project contradiction.
    if !amiga_project::validate::is_safe_relative(file) {
        bail!("--file {file:?} is not a project-relative path with ordinary components");
    }
    let full = crate::project_directory(&root).join(file);
    amiga_core::safepath::reject_symlink(&full)?;
    let bytes =
        std::fs::read(&full).with_context(|| format!("the capture at {file} could not be read"))?;
    run_edit(
        path,
        amiga_operations::ProjectEdit::RegisterCapture {
            id: id.to_owned(),
            name: name.to_owned(),
            size: bytes.len() as u64,
            sha256: amiga_core::sha256(&bytes),
            notes: notes.to_owned(),
            path: Some(file.to_owned()),
        },
        dry_run,
    )
}

/// Record what a range of bytes is.
///
/// The target is spelled as an object, an offset and a length, and nothing
/// else: the digest an annotation is established against is a fact about the
/// project, so the operation derives it — a caller supplying one could pin an
/// annotation to bytes the project does not describe.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one field of the annotation being created; \
              bundling them into a struct here would only move the list"
)]
pub(crate) fn project_annotate(
    path: Option<&Path>,
    id: &str,
    kind: &str,
    object: &str,
    offset: u64,
    length: u64,
    name: Option<&str>,
    classification: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    run_edit(
        path,
        amiga_operations::ProjectEdit::Annotate {
            id: id.to_owned(),
            kind: kind.to_owned(),
            target: amiga_operations::ProjectEditTarget::Object {
                object_id: object.to_owned(),
                offset,
                length,
            },
            name: name.map(ToOwned::to_owned),
            classification: classification.map(ToOwned::to_owned),
        },
        dry_run,
    )
}

/// Say why, about bytes or about an annotation.
///
/// Both subjects stay, and neither is a special case of the other: commenting
/// on a selection and commenting on a name someone already recorded are
/// different acts.
#[expect(
    clippy::too_many_arguments,
    reason = "the same list as project_annotate, for the same reason"
)]
pub(crate) fn project_comment(
    path: Option<&Path>,
    id: &str,
    text: &str,
    about: Option<&str>,
    object: Option<&str>,
    offset: u64,
    length: Option<u64>,
    placement: &str,
    dry_run: bool,
) -> Result<()> {
    // One subject, named here rather than left to produce a comment about
    // nothing. `clap` refuses the pair; this refuses neither.
    let target = match (about, object, length) {
        (Some(entity), None, _) => amiga_operations::ProjectEditTarget::Entity {
            entity_id: entity.to_owned(),
        },
        (None, Some(object), Some(length)) => amiga_operations::ProjectEditTarget::Object {
            object_id: object.to_owned(),
            offset,
            length,
        },
        _ => bail!("a comment is about something: pass --about <ID>, or --object with --length"),
    };
    run_edit(
        path,
        amiga_operations::ProjectEdit::Comment {
            id: id.to_owned(),
            target,
            placement: placement.to_owned(),
            text: text.to_owned(),
        },
        dry_run,
    )
}

/// Record, or correct, how a range of bytes decodes.
///
/// `define` and `update` are one function because they write one record; only
/// whether the ID must already exist differs, and that is the operation's
/// question rather than this frontend's.
pub(crate) fn project_resource_write(
    path: Option<&Path>,
    resource: crate::ResourceArgs,
    define: bool,
    dry_run: bool,
) -> Result<()> {
    let mut parameters = serde_json::Map::new();
    for parameter in &resource.parameters {
        let (key, value) = parameter
            .split_once('=')
            .with_context(|| format!("--parameter {parameter:?} is not KEY=VALUE"))?;
        // JSON first, so `width=8` is the number the schema wants; a bare word
        // is not valid JSON and stays the string it obviously is.
        let value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.to_owned()));
        parameters.insert(key.to_owned(), value);
    }
    let target = amiga_operations::ProjectEditTarget::Object {
        object_id: resource.object.clone(),
        offset: resource.offset,
        length: resource.length,
    };
    let edit = if define {
        amiga_operations::ProjectEdit::DefineResource {
            id: resource.id.clone(),
            kind: resource.kind.clone(),
            name: resource.name.clone(),
            target,
            parameters,
            export_media_type: resource.export_media_type.clone(),
            notes: resource.notes.clone(),
        }
    } else {
        amiga_operations::ProjectEdit::UpdateResource {
            id: resource.id.clone(),
            kind: resource.kind.clone(),
            name: resource.name.clone(),
            target,
            parameters,
            export_media_type: resource.export_media_type.clone(),
            notes: resource.notes.clone(),
        }
    };
    run_edit(path, edit, dry_run)
}

/// Produce a resource's file from the project alone.
///
/// Nothing about the output is this command's to decide: the bytes, the
/// recipe, the encoding and the destination all come from the project, which is
/// what makes the file reproducible rather than a one-off.
pub(crate) fn project_resource_export(path: Option<&Path>, resource: &str) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let (base, name) = split_project_path(&root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let envelope = |mode| {
        let mut envelope = amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::ProjectResourceExport(
                amiga_operations::ResourceExportArguments::new(resource),
            ),
        );
        envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name.clone() });
        envelope.execution.mode = mode;
        envelope
    };

    let prepared = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    fail_on_errors(&prepared)
        .with_context(|| format!("failed to plan the export of {resource}"))?;
    let plan = prepared
        .project_resource_export()
        .context("the export operation produced no plan")?;
    row!(
        out,
        "{} -> {} ({} bytes, {})",
        plan.resource_id,
        plan.path,
        plan.size,
        plan.media_type
    );

    let committed = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan.plan_sha256.clone(),
        }),
        &context,
    );
    fail_on_errors(&committed).with_context(|| format!("failed to export {resource}"))?;
    let written = committed
        .project_resource_export()
        .context("the export operation produced no plan")?;
    row!(out, "recorded {}", written.artifact_id);
    // Reported, never deleted: the superseded file is still on disk, and
    // removing it is the user's decision.
    for artifact in &written.superseded {
        row!(
            out,
            "superseded {} — {} can be removed",
            artifact.id,
            artifact.path
        );
    }
    out.print()
}

/// Delete a resource.
pub(crate) fn project_resource_remove(path: Option<&Path>, id: &str, dry_run: bool) -> Result<()> {
    run_edit(
        path,
        amiga_operations::ProjectEdit::RemoveResource { id: id.to_owned() },
        dry_run,
    )
}

/// Forget a produced file.
///
/// Removes the record only. Nothing here deletes an artifact: the file is the
/// user's to remove, and a command that swept it away would delete output
/// nobody asked it to.
pub(crate) fn project_artifact_forget(path: Option<&Path>, id: &str, dry_run: bool) -> Result<()> {
    run_edit(
        path,
        amiga_operations::ProjectEdit::RemoveArtifact { id: id.to_owned() },
        dry_run,
    )
}

/// Delete an annotation.
pub(crate) fn project_remove(path: Option<&Path>, id: &str, dry_run: bool) -> Result<()> {
    run_edit(
        path,
        amiga_operations::ProjectEdit::Remove { id: id.to_owned() },
        dry_run,
    )
}

/// Bring every listed document into canonical form, from `project.format`.
///
/// Idempotent, so it is safe in a pre-commit hook: a second run never produces
/// a third form.
///
/// `--check` is the prepared half of the same request, so "check" and "fix"
/// cannot disagree about what canonical form is: they are one computation, and
/// only the execution mode differs.
pub(crate) fn project_format(path: Option<&Path>, check: bool) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let (base, name) = split_project_path(&root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let envelope = |mode| {
        let mut envelope = amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::ProjectFormat(
                amiga_operations::ProjectArguments::default(),
            ),
        );
        envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name.clone() });
        envelope.execution.mode = mode;
        envelope
    };

    let prepared = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    fail_on_errors(&prepared).with_context(|| format!("failed to load {}", root.display()))?;
    let plan = prepared
        .project_format()
        .context("the format operation produced no plan")?;

    if check {
        for document in &plan.documents {
            if !document.canonical {
                row!(out, "{} is not in canonical form", document.path);
            }
        }
        if plan.unformatted > 0 {
            out.print()?;
            bail!("{} document(s) need formatting", plan.unformatted);
        }
        return out.print();
    }

    let committed = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan_sha256.clone(),
        }),
        &context,
    );
    fail_on_errors(&committed).with_context(|| format!("failed to format {}", root.display()))?;
    let applied = committed
        .project_format()
        .context("the format operation produced no plan")?;
    for written in &applied.written {
        row!(out, "formatted {written}");
    }
    out.print()
}

/// Convert a legacy `amiga-re.toml` into project documents, from
/// `project.migrate`.
///
/// Writes nothing without `--output` or `--in-place`, and refuses to guess:
/// every field the importer cannot place with confidence is reported as an
/// ambiguity, because a silently invented load map is worse than no load map.
///
/// The two destination shapes are the operation's: `--output` writes a
/// directory this toolkit owns, `--in-place` writes the documents beside the
/// config and touches nothing else there.
pub(crate) fn project_migrate(
    config_override: Option<&Path>,
    name: &str,
    image: Option<&str>,
    image_media: Option<&str>,
    output: Option<&Path>,
    in_place: bool,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let (config_path, _) = resolve_config(config_override)?;
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    // An image needs both halves: which image the `[base]` maps, and which
    // media its bytes are. Half of it names an object that does not exist, so
    // the importer is told nothing rather than half a decision.
    if image.is_some() && image_media.is_none() {
        bail!(
            "--image needs --image-media <NAME>: an image is an object, and a legacy config \
             has no vocabulary for one"
        );
    }

    let (source_base, config_name) = amiga_operations::split_host_path(&config_path)
        .with_context(|| format!("{} does not name a readable file", config_path.display()))?;
    // Both destination shapes resolve the same way; only what the operation
    // does with the directory differs.
    let destination_target = output.map_or_else(|| config_dir.clone(), Path::to_path_buf);
    let absolute = std::path::absolute(&destination_target)
        .with_context(|| format!("failed to resolve {}", destination_target.display()))?;
    let destination_base = absolute
        .parent()
        .with_context(|| format!("{} has no directory to name", destination_target.display()))?;
    let destination = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| amiga_operations::DestinationName::parse(name).ok())
        .with_context(|| {
            format!(
                "{} is not a usable destination",
                destination_target.display()
            )
        })?;

    let mut arguments = amiga_operations::ProjectMigrateArguments::new(
        config_name.as_str(),
        name,
        destination.as_str(),
    )
    .with_policy(output_policy(force));
    if let (Some(id), Some(media)) = (image, image_media) {
        arguments = arguments.with_image(id, media);
    }
    if output.is_none() {
        arguments = arguments.into_existing_directory();
    }

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(destination_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = amiga_operations::OperationRequestDocument::ProjectMigrate(arguments);
    let envelope = |mode| {
        let mut envelope = amiga_operations::RequestEnvelope::read(document.clone());
        envelope.execution.mode = mode;
        envelope
    };

    let prepared = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    fail_on_errors(&prepared)
        .with_context(|| format!("failed to import {}", config_path.display()))?;
    let import = prepared
        .project_migrate()
        .context("the import operation produced no plan")?;

    for file in &import.plan.files {
        row!(out, "{} ({} bytes)", file.path, file.size);
    }
    for ambiguity in &import.ambiguities {
        eprintln!("ambiguous: {}: {}", ambiguity.field, ambiguity.message);
    }
    row!(
        out,
        "\n{} document(s) from {}, {} ambiguity(ies)",
        import.plan.files.len(),
        config_path.display(),
        import.ambiguities.len()
    );

    if output.is_none() && !in_place {
        row!(out, "Dry run: pass --output or --in-place to write.");
        return out.print();
    }

    let count = import.plan.files.len();
    let digest = import.plan.plan_sha256.clone();
    let committed = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest,
        }),
        &context,
    );
    fail_on_errors(&committed)
        .with_context(|| format!("failed to write into {}", destination_target.display()))?;
    match output {
        Some(directory) => row!(out, "Wrote {count} document(s) to {}", directory.display()),
        None => row!(
            out,
            "Wrote {count} document(s) into {}",
            config_dir.display()
        ),
    }
    out.print()
}

/// Create a project from chosen source files, from `project.init`.
///
/// Prepares and commits in one invocation, as every other convenience wrapper
/// does. Preparing twice is not waste: the commit names the digest it was
/// authorized against, so anything that changed between the two comes back as a
/// conflict rather than a surprise write.
pub(crate) fn project_init(
    name: &str,
    output: &Path,
    files: &[PathBuf],
    in_place: bool,
) -> Result<()> {
    let mut out = Document::new();
    let resolved: Vec<PathBuf> = files
        .iter()
        .map(|path| {
            std::path::absolute(path)
                .with_context(|| format!("failed to resolve {}", path.display()))
        })
        .collect::<Result<_>>()?;
    let borrowed: Vec<&Path> = resolved.iter().map(PathBuf::as_path).collect();
    let (source_base, source_names) = amiga_operations::split_host_paths(&borrowed)
        .context("the chosen sources share no directory a resolver could serve")?;
    let (output_base, destination) = split_destination_dir(output)?;

    let arguments = amiga_operations::ProjectInitArguments::new(
        name,
        destination.as_str(),
        source_names
            .iter()
            .map(|source| source.as_str().to_owned())
            .collect(),
    )
    .with_media(if in_place {
        amiga_operations::MediaPolicy::InPlace
    } else {
        amiga_operations::MediaPolicy::Copy
    });

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(output_base);
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let mut prepare = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ProjectInit(arguments.clone()),
    );
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    fail_on_errors(&prepared).with_context(|| format!("failed to plan {}", output.display()))?;
    let plan = prepared
        .project_init()
        .context("the init operation produced no plan")?;

    let mut commit = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ProjectInit(arguments),
    );
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan.plan_sha256.clone(),
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    fail_on_errors(&committed).with_context(|| format!("failed to create {}", output.display()))?;
    let created = committed
        .project_init()
        .context("the init operation produced no plan")?;

    row!(out, "{} ({})", created.name, created.project_id);
    for source in &created.sources {
        let placement = match (&source.location, source.bound_locally) {
            (Some(location), _) => location.clone(),
            // Worth naming rather than leaving blank: this source is findable on
            // this machine and nowhere else, which is the trade `--in-place` is.
            (None, true) => "bound in .amiga-re/local.json".to_owned(),
            (None, false) => "unbound".to_owned(),
        };
        row!(
            out,
            "  {} -> {} ({} bytes, {})",
            source.id,
            source.object_id,
            source.size,
            placement
        );
    }
    row!(out, "{} file(s) written", created.written.len());
    out.print()
}

/// Take a project's registered carriers apart, from `project.extract`.
pub(crate) fn project_extract(path: Option<&Path>, sources: Vec<String>) -> Result<()> {
    let mut out = Document::new();
    let root = resolve_project(path)?;
    let (base, name) = split_project_path(&root)?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(base);
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let envelope = |mode| {
        let mut envelope = amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::ProjectExtract(
                amiga_operations::ProjectExtractArguments::for_sources(sources.clone()),
            ),
        );
        envelope.project = Some(amiga_operations::ProjectLocator::Path { path: name.clone() });
        envelope.execution.mode = mode;
        envelope
    };

    let prepared = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::Prepare),
        &context,
    );
    fail_on_errors(&prepared).with_context(|| format!("failed to plan {}", root.display()))?;
    let plan = prepared
        .project_extract()
        .context("the extract operation produced no plan")?;

    for carrier in &plan.carriers {
        // The detail is the point for a carrier that enumerated nothing: an
        // empty line would read as "covered", which is the failure this reports.
        match &carrier.detail {
            Some(detail) => row!(out, "{} [{}]: {}", carrier.source_id, carrier.kind, detail),
            None => row!(
                out,
                "{} [{}]: {} member(s)",
                carrier.source_id,
                carrier.kind,
                carrier.members
            ),
        }
    }
    if plan.objects.is_empty() {
        row!(out, "nothing to extract");
        return out.print();
    }

    let committed = amiga_operations::Router::execute(
        &envelope(amiga_operations::ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan.plan_sha256.clone(),
        }),
        &context,
    );
    fail_on_errors(&committed).with_context(|| format!("failed to extract {}", root.display()))?;
    let applied = committed
        .project_extract()
        .context("the extract operation produced no plan")?;
    for object in &applied.objects {
        row!(
            out,
            "  {} -> {} ({} bytes)",
            object.id,
            object.path,
            object.size
        );
    }
    row!(out, "{} file(s) written", applied.written.len());
    out.print()
}
