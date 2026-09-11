//! The structured operation boundary: `operations`, `operations run`, `schema`.
//!
//! This is the surface automation talks to. Nothing here renders for a human
//! except the deliberately-text listing modes; a caller that wants a machine
//! contract asks for JSON and gets exactly one response document, or JSON Lines
//! whose every record names its own type.
//!
//! The convenience commands (`survey`, `adf list`, …) build the *same* typed
//! requests and call the *same* router. They exist so an interactive user need
//! not write JSON, not so there is a second way for the toolkit to behave.

use std::io::{IsTerminal as _, Read as _, Write as _};

use super::*;

/// How a caller wants an operation's outcome written down.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ResponseMode {
    /// Human-readable rendering. Never a machine contract.
    #[default]
    Text,
    /// Exactly one response document on standard output.
    Json,
    /// One JSON object per line, each naming its `message_type`, ending with
    /// the response.
    Jsonl,
}

/// Which half of an operation's contract to emit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum SchemaKind {
    #[default]
    Request,
    Response,
}

/// Where a request document comes from: a file, or standard input as `-`.
///
/// Files and standard input are preferred over inline JSON because shell
/// quoting and command-line length limits make a large inline object fragile.
fn read_request_document(source: &Path) -> Result<String> {
    if source == Path::new("-") {
        if std::io::stdin().is_terminal() {
            bail!(
                "--request - reads the request from standard input, but standard input is a terminal"
            );
        }
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("failed to read the request from standard input")?;
        return Ok(text);
    }
    fs::read_to_string(source)
        .with_context(|| format!("failed to read the request {}", source.display()))
}

/// List every operation this build serves.
pub(crate) fn operations_list(response: ResponseMode) -> Result<()> {
    let mut out = Document::new();
    let catalog = amiga_operations::catalog();
    match response {
        ResponseMode::Json | ResponseMode::Jsonl => {
            // One document either way: a catalog listing is not an operation
            // exchange, so it has no events to interleave and no response
            // envelope to end with.
            let document = serde_json::json!({
                "protocol_version": amiga_operations::PROTOCOL_VERSION,
                "operations": catalog
                    .iter()
                    .map(|descriptor| serde_json::json!({
                        "operation": descriptor.name.as_str(),
                        "access": descriptor.access.as_str(),
                        "summary": descriptor.summary,
                    }))
                    .collect::<Vec<_>>(),
            });
            row!(out, "{}", serde_json::to_string_pretty(&document)?);
        }
        ResponseMode::Text => {
            let width = catalog
                .iter()
                .map(|descriptor| descriptor.name.as_str().len())
                .max()
                .unwrap_or(0);
            for descriptor in catalog {
                row!(
                    out,
                    "{:<width$}  {:<11}  {}",
                    descriptor.name.as_str(),
                    descriptor.access.as_str(),
                    descriptor.summary
                );
            }
        }
    }
    out.print()
}

/// Print, or write out, the bundled Draft 2020-12 schemas.
///
/// The schemas are compiled into the binary. Nothing here fetches a schema a
/// document names; `--output` emits *copies* for an editor to point at.
pub(crate) fn operations_schema(
    operation: Option<&str>,
    kind: SchemaKind,
    output: Option<&Path>,
    force: bool,
) -> Result<()> {
    if let Some(directory) = output {
        return write_schema_set(directory, force);
    }
    let text = match operation {
        Some(name) => {
            let descriptor = find_descriptor(name)?;
            match kind {
                SchemaKind::Request => descriptor.request_schema,
                SchemaKind::Response => descriptor.response_schema,
            }
        }
        // With no operation named, the envelope is what a caller needs: it is
        // the document they actually write.
        None => match kind {
            SchemaKind::Request => amiga_operations::descriptor::schemas::REQUEST,
            SchemaKind::Response => amiga_operations::descriptor::schemas::RESPONSE,
        },
    };
    print_document(text)
}

/// The descriptor for `name`, with the catalog listed on a miss so the user
/// does not have to guess.
fn find_descriptor(name: &str) -> Result<&'static amiga_operations::OperationDescriptor> {
    amiga_operations::catalog()
        .into_iter()
        .find(|descriptor| descriptor.name.as_str() == name)
        .with_context(|| {
            format!(
                "unknown operation {name:?}; this build serves {}",
                amiga_operations::catalog()
                    .iter()
                    .map(|descriptor| descriptor.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Write every bundled schema into `directory`, preserving the layout their
/// `$ref`s resolve against so the emitted set stays offline-resolvable.
fn write_schema_set(directory: &Path, force: bool) -> Result<()> {
    let mut out = Document::new();
    let schemas = amiga_operations::descriptor::schemas::ALL;
    let mut planned = Vec::new();
    for (name, text) in schemas {
        planned.push(PlannedFile {
            path: PathBuf::from(*name),
            bytes: text.as_bytes().to_vec(),
        });
    }
    for descriptor in amiga_operations::catalog() {
        planned.push(PlannedFile {
            path: PathBuf::from(format!(
                "operations/{}.request.schema.json",
                descriptor.name.as_str()
            )),
            bytes: descriptor.request_schema.as_bytes().to_vec(),
        });
        planned.push(PlannedFile {
            path: PathBuf::from(format!(
                "operations/{}.response.schema.json",
                descriptor.name.as_str()
            )),
            bytes: descriptor.response_schema.as_bytes().to_vec(),
        });
    }
    let count = planned.len();
    // The manifest governs replacement: `--force` may only replace files a
    // prior amiga-re emission recorded, so the emitted set must list itself.
    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "protocol_version": amiga_operations::PROTOCOL_VERSION,
        "files": planned
            .iter()
            .map(|file| serde_json::json!({
                "path": file.path.display().to_string(),
                "sha256": sha256(&file.bytes),
            }))
            .collect::<Vec<_>>(),
    }))?;
    let plan = ExtractionPlan::new(planned, Vec::new())?;
    plan.commit(directory, force, "manifest.json", &manifest)?;
    row!(
        out,
        "Wrote {count} schema file(s) to {}",
        directory.display()
    );
    out.print()
}

/// Execute one request document and write the exchange in the chosen framing.
///
/// Returns the process exit code rather than an error for a request the router
/// refused: a refusal is a *result* the caller asked for, reported through the
/// response document with a status and stable diagnostic codes. Only a failure
/// to obtain a request at all — unreadable file, malformed JSON — is an error
/// here, because in that case there is no operation to report about.
pub(crate) fn operations_run(
    request_path: &Path,
    response: ResponseMode,
    quiet: bool,
) -> Result<u8> {
    let text = read_request_document(request_path)?;
    let envelope: amiga_operations::RequestEnvelope = serde_json::from_str(&text)
        .context("the request is not a valid amiga-re operation request document")?;

    // A request names its source by identity, never by host path, so the
    // adapter decides what directory those identities resolve against. The
    // command line's answer is the working directory, which is the only one a
    // shell user could have meant.
    let root = std::env::current_dir().context("failed to read the current directory")?;
    let resolver = amiga_operations::FilesystemSourceResolver::new(&root);
    let context = amiga_operations::ExecutionContext::new(&resolver);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let outcome = match response {
        ResponseMode::Jsonl => {
            let mut write_error = None;
            let outcome =
                amiga_operations::execute_streaming(&envelope, &context, &mut |message| {
                    if write_error.is_some() {
                        return;
                    }
                    // Each line is written and flushed as it is produced: a
                    // consumer reading incrementally must not wait on a buffer.
                    if let Err(error) = serde_json::to_writer(&mut out, &message)
                        .map_err(anyhow::Error::from)
                        .and_then(|()| writeln!(out).map_err(anyhow::Error::from))
                        .and_then(|()| out.flush().map_err(anyhow::Error::from))
                    {
                        write_error = Some(error);
                    }
                });
            if let Some(error) = write_error {
                return Err(error).context("failed to write the response stream");
            }
            outcome
        }
        ResponseMode::Json => {
            let outcome = amiga_operations::Router::execute(&envelope, &context);
            let document = amiga_operations::ResponseEnvelope::from_outcome(
                &outcome,
                envelope.request_id.as_deref(),
            );
            writeln!(out, "{}", serde_json::to_string_pretty(&document)?)
                .context("failed to write the response")?;
            outcome
        }
        ResponseMode::Text => {
            let outcome = amiga_operations::Router::execute(&envelope, &context);
            writeln!(
                out,
                "{}: {}",
                outcome.operation.as_str(),
                status_text(outcome.status)
            )
            .context("failed to write the outcome")?;
            if let Some(digest) = &outcome.normalized_request_sha256 {
                writeln!(out, "normalized request SHA-256: {digest}")
                    .context("failed to write the digest")?;
            }
            // Text mode is the only framing in which the diagnostics are not
            // already on standard output, so it prints them itself.
            for diagnostic in &outcome.diagnostics {
                writeln!(
                    out,
                    "{}: {:?} {}",
                    if diagnostic.is_error() {
                        "error"
                    } else {
                        "note"
                    },
                    diagnostic.code,
                    diagnostic.message
                )
                .context("failed to write a diagnostic")?;
            }
            outcome
        }
    };

    // Every framing carries the diagnostics in its own documents, so this is a
    // convenience echo for a human watching a machine-readable run. It goes to
    // standard error, which is what keeps `--response json` to exactly one
    // document on standard output.
    if !quiet && response != ResponseMode::Text {
        for diagnostic in &outcome.diagnostics {
            eprintln!("{:?}: {}", diagnostic.code, diagnostic.message);
        }
    }
    Ok(outcome.exit_code())
}

const fn status_text(status: amiga_operations::Status) -> &'static str {
    match status {
        amiga_operations::Status::Success => "success",
        amiga_operations::Status::Prepared => "prepared",
        amiga_operations::Status::Cancelled => "cancelled",
        amiga_operations::Status::Conflict => "conflict",
        amiga_operations::Status::Error => "error",
    }
}
