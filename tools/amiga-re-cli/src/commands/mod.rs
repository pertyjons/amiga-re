//! Domain-oriented command implementations.

use super::*;

mod archive;
mod audio;
mod compare;
mod disasm;
mod execute;
mod fd;
mod frame;
mod hardware;
mod inspect;
mod media;
mod names;
mod operations;
mod output;
mod project;
mod query;
mod report;
mod state;

pub(super) use archive::*;
pub(super) use audio::*;
pub(super) use compare::*;
pub(super) use disasm::*;
pub(super) use execute::*;
pub(super) use fd::*;
pub(super) use frame::*;
pub(super) use hardware::*;
pub(super) use inspect::*;
pub(super) use media::*;
pub(super) use names::*;
pub(super) use operations::*;
pub(super) use output::*;
pub(super) use project::*;
pub(super) use query::*;
pub(super) use report::*;
pub(super) use state::*;

/// Write a rendered document to stdout, treating a closed pipe as success.
///
/// `print!` panics when stdout is gone, and stdout is gone whenever a reader
/// pipes a long listing into something that exits early — `head`, a pager
/// quitted at the first screen, a `grep -m1`. That is the *normal* end of a
/// long listing, not a failure of the command that produced it, and a panic
/// there is both a wrong diagnosis and a stack trace over the reader's output.
///
/// Every command in this crate prints through this, either directly with a
/// rendered listing or by way of the [`Document`] its rows were collected in.
pub(crate) fn print_document(document: &str) -> Result<()> {
    use std::io::Write as _;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    tolerate_closed_pipe(
        out.write_all(document.as_bytes())
            .and_then(|()| out.flush()),
    )
}

/// A reader that stopped reading is not this command's failure.
///
/// Split out from [`print_document`] so the rule can be tested without a real
/// pipe: closing one from inside a test races the write that is supposed to
/// observe it, and a flaky test about a panic is worse than none.
fn tolerate_closed_pipe(result: std::io::Result<()>) -> Result<()> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.context("failed to write to stdout"),
    }
}

/// A command's output, collected row by row and printed once.
///
/// Commands that emit tables used to `println!` each row as they computed it,
/// which panics the moment a reader stops reading — and a reader stopping is
/// how `| head` and a quitted pager normally end. Collecting the rows first
/// means one write, through [`print_document`], which ends quietly instead.
///
/// The rows are also bounded: every table here is folded out of a list an
/// operation already returned under its own limits, so holding one before
/// printing it costs what the list already cost.
#[derive(Debug, Default)]
pub(crate) struct Document(String);

impl Document {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append one line.
    ///
    /// Takes no `Result`, because writing to a `String` cannot fail:
    /// `fmt::Write for String` returns `Ok` unconditionally. Saying that once
    /// here is what keeps three hundred call sites from threading a `?` through
    /// a row loop for an error that does not exist.
    pub(crate) fn row(&mut self, arguments: std::fmt::Arguments<'_>) {
        use std::fmt::Write as _;
        let _ = self.0.write_fmt(arguments);
        self.0.push('\n');
    }

    /// Append part of a line, for a row assembled from several pieces.
    pub(crate) fn part(&mut self, arguments: std::fmt::Arguments<'_>) {
        use std::fmt::Write as _;
        let _ = self.0.write_fmt(arguments);
    }

    /// End the line a `part` sequence was building, or emit a blank one.
    pub(crate) fn blank(&mut self) {
        self.0.push('\n');
    }

    /// Print everything collected, ending quietly if the reader has gone.
    pub(crate) fn print(&self) -> Result<()> {
        print_document(&self.0)
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// `row!(out, "…", …)` — one line into a [`Document`], shaped like `println!`.
macro_rules! row {
    ($out:expr) => {
        $out.blank()
    };
    ($out:expr, $($arguments:tt)*) => {
        $out.row(format_args!($($arguments)*))
    };
}

/// `part!(out, "…", …)` — the same without the newline, for a row built in
/// pieces.
macro_rules! part {
    ($out:expr, $($arguments:tt)*) => {
        $out.part(format_args!($($arguments)*))
    };
}

pub(crate) use {part, row};

/// Split a file path into the destination root an adapter serves and the
/// directory identity a request names.
///
/// A request names a *directory* plus a file name within it, never a host path,
/// so the path the user typed has to be taken apart. Made absolute first, so a
/// bare `piece.bin` still has a directory to name: a request that could not spell
/// its destination would fail for a reason the user has no way to see.
pub(crate) fn split_destination_file(
    destination: &Path,
) -> Result<(PathBuf, amiga_operations::DestinationName, String)> {
    let absolute = std::path::absolute(destination)
        .with_context(|| format!("failed to resolve {}", destination.display()))?;
    let file_name = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} does not name a file", destination.display()))?
        .to_owned();
    let directory = absolute
        .parent()
        .with_context(|| format!("{} has no parent directory", destination.display()))?;
    let base = directory
        .parent()
        .with_context(|| format!("{} has no directory to name", destination.display()))?;
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| amiga_operations::DestinationName::parse(name).ok())
        .with_context(|| format!("{} is not a usable destination", destination.display()))?;
    Ok((base.to_path_buf(), name, file_name))
}

/// The output policy a `--force` flag authorizes.
///
/// `--force` does not mean "overwrite anything": it means "replace a file this
/// toolkit wrote", which the operation checks by provenance.
pub(crate) const fn output_policy(force: bool) -> amiga_operations::OutputPolicy {
    if force {
        amiga_operations::OutputPolicy::ReplaceMatchingProvenance
    } else {
        amiga_operations::OutputPolicy::CreateOnly
    }
}

/// Prepare a write plan, then commit the plan just built.
///
/// The convenience wrapper reviews on the user's behalf, as `adf extract` and
/// `iff to-wav` do. Preparing twice is not waste, it is the check: the commit
/// names the digest it was authorized against, so anything that changed between
/// the two — the source, the request, the files already there — comes back as a
/// conflict rather than as a surprise write.
pub(crate) fn commit_reviewed(
    document: amiga_operations::OperationRequestDocument,
    context: &amiga_operations::ExecutionContext<'_>,
    what: &str,
    plan_digest: impl Fn(&amiga_operations::OperationOutcome) -> Option<String>,
) -> Result<amiga_operations::OperationOutcome> {
    let mut prepare = amiga_operations::RequestEnvelope::read(document.clone());
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, context);
    fail_on_errors(&prepared).with_context(|| format!("failed to prepare the {what}"))?;
    let digest = plan_digest(&prepared)
        .with_context(|| format!("the {what} operation produced no write plan"))?;

    let mut commit = amiga_operations::RequestEnvelope::read(document);
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    let committed = amiga_operations::Router::execute(&commit, context);
    fail_on_errors(&committed).with_context(|| format!("failed to write the {what}"))?;
    Ok(committed)
}

/// The bounds a sandbox run gets from this frontend.
///
/// The default step ceiling exists so that an absent or mistyped budget cannot
/// hang a process running unknown code. That reasoning is about a caller who
/// did not choose; here, someone typed `--max-steps` against media on their own
/// disk, which is precisely the reviewed local recipe the ceiling is willing to
/// make room for. So the command line raises the ceiling to the operation
/// crate's absolute maximum and lets `--max-steps` be the budget — an
/// initialization routine that decodes graphics and builds tables can run to
/// completion, and a run that asks for more than the absolute maximum is still
/// reduced and still says so.
pub(crate) fn sandbox_limits() -> amiga_operations::OperationLimits {
    amiga_operations::OperationLimits::default()
        .with_maximum_sandbox_steps(amiga_operations::MAXIMUM_SANDBOX_STEPS_CEILING)
}

/// Fail on an operation's error diagnostics, before anything is rendered.
///
/// Diagnostic codes are the machine contract; this renders them for a human
/// without inventing a second vocabulary beside them. Shared by every command
/// that routes through `amiga-operations`, so one operation's diagnostics never
/// read differently from another's.
pub(crate) fn fail_on_errors(outcome: &amiga_operations::OperationOutcome) -> Result<()> {
    let errors: Vec<&str> = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.is_error())
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

/// Print an operation's non-fatal diagnostics.
///
/// Called after the result is rendered: a caveat about a long listing is only
/// useful where the reader still is when the listing ends.
pub(crate) fn print_warnings(outcome: &amiga_operations::OperationOutcome) {
    for diagnostic in &outcome.diagnostics {
        if !diagnostic.is_error() {
            eprintln!("warning: {}", diagnostic.message);
        }
    }
}

/// Split a directory path into the root an adapter serves and the identity a
/// request names.
///
/// The directory-shaped counterpart of [`split_destination_file`], for an
/// operation whose whole output is a tree rather than one file in one.
pub(crate) fn split_destination_dir(
    destination: &Path,
) -> Result<(PathBuf, amiga_operations::DestinationName)> {
    let absolute = std::path::absolute(destination)
        .with_context(|| format!("failed to resolve {}", destination.display()))?;
    let base = absolute
        .parent()
        .with_context(|| format!("{} has no directory to name", destination.display()))?;
    let name = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| amiga_operations::DestinationName::parse(name).ok())
        .with_context(|| format!("{} is not a usable destination", destination.display()))?;
    Ok((base.to_path_buf(), name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_lays_its_rows_out_the_way_the_print_macros_did() {
        // The conversion from `println!`/`print!` was mechanical, so what has
        // to hold is that the shapes still agree: a row ends its line, a part
        // does not, and a bare `row!` is the blank line `println!()` was.
        let mut out = Document::new();
        row!(out, "{:<4} {}", "id", 3);
        part!(out, "a ");
        part!(out, "b");
        row!(out);
        row!(out);
        assert_eq!(out.as_str(), "id   3\na b\n\n");
    }

    #[test]
    fn a_closed_stdout_ends_a_listing_rather_than_failing_it() {
        // `head`, a quitted pager, `grep -m1`: every one of them closes the
        // pipe while a long listing is still being written, and `print!` turns
        // that into a panic over the reader's own output.
        let closed = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed");
        assert!(tolerate_closed_pipe(Err(closed)).is_ok());

        // Anything else is a real write failure and still reported as one: a
        // full disk must not read as a reader who had seen enough.
        let full = std::io::Error::new(std::io::ErrorKind::StorageFull, "no space");
        assert!(tolerate_closed_pipe(Err(full)).is_err());
        assert!(tolerate_closed_pipe(Ok(())).is_ok());
    }
}
