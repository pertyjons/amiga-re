//! `container.adf.list` — read an AmigaDOS volume's directory tree.

use std::path::{Component, Path};

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedAdfList;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    AdfEntry, AdfEntryKind, AdfListResult, AdfVolume, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

pub(crate) fn run(
    request: &NormalizedAdfList,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let failed = |diagnostics: Vec<Diagnostic>| OperationOutcome {
        operation: OperationName::ContainerAdfList,
        status: Status::Error,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result: None,
    };

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                source_error_code(&error),
                error.to_string(),
            ));
            return failed(diagnostics);
        }
    };

    let image = match amiga_adf::Image::open(source.bytes()) {
        Ok(image) => image,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::ContainerAdfUnreadable,
                error.to_string(),
            ));
            return failed(diagnostics);
        }
    };

    events.emit(OperationEvent::Progress {
        phase: "open_volume",
        completed: source.size(),
        total: Some(source.size()),
    });

    // Tolerated inconsistencies are reported, never dropped: a listing that
    // silently omits them would claim more confidence than the reader has.
    for warning in image.warnings() {
        let diagnostic = Diagnostic::warning(tolerated_code(warning.kind), warning.message.clone())
            .about(format!("block:{}", warning.block));
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }

    let entry_total = image.entries().len();
    events.emit(OperationEvent::Progress {
        phase: "walk_directories",
        completed: entry_total as u64,
        total: Some(entry_total as u64),
    });
    let entries_truncated = entry_total > request.maximum_entries;
    let entries: Vec<AdfEntry> = image
        .entries()
        .iter()
        .take(request.maximum_entries)
        .map(|entry| AdfEntry {
            path: volume_path(&entry.path),
            kind: match entry.kind {
                amiga_adf::EntryKind::File => AdfEntryKind::File,
                amiga_adf::EntryKind::Directory => AdfEntryKind::Directory,
            },
            size: entry.size.get(),
            header_block: entry.header_block.get(),
        })
        .collect();
    if entries_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "reporting the first {} of {entry_total} entries",
                request.maximum_entries
            ),
        ));
    }

    OperationOutcome {
        operation: OperationName::ContainerAdfList,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::ContainerAdfList(AdfListResult {
            source: SourcePin {
                size: source.size(),
                sha256: source.sha256().to_owned(),
            },
            volume: AdfVolume {
                name: image.volume_name().to_owned(),
                filesystem: filesystem_name(image.filesystem()),
                block_size: amiga_adf::BLOCK_SIZE as u32,
                root_block: image.root_block().get(),
            },
            entries,
            entry_total,
            entries_truncated,
        })),
    }
}

/// Render a walked path as a volume-relative, `/`-separated string.
///
/// Built explicitly from components rather than through `Display`, so the wire
/// contract does not depend on the host's path separator.
fn volume_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The stable name for the filesystem an image was read as.
///
/// Exhaustive over `amiga_adf::FileSystem`, so a third filesystem cannot reach
/// the wire as whatever the previous one was called.
const fn filesystem_name(filesystem: amiga_adf::FileSystem) -> &'static str {
    match filesystem {
        amiga_adf::FileSystem::Ofs => "ofs",
        amiga_adf::FileSystem::Ffs => "ffs",
    }
}

/// The stable code for one tolerated inconsistency.
///
/// Exhaustive by construction: `amiga_adf::WarningKind` is not
/// `#[non_exhaustive]`, so a new kind fails to compile here until its code is
/// decided. That is the point — the code is the machine contract, the message
/// is not, so a new kind must never fall into a catch-all.
const fn tolerated_code(kind: amiga_adf::WarningKind) -> DiagnosticCode {
    match kind {
        amiga_adf::WarningKind::BootBlockChecksumInvalid => {
            DiagnosticCode::ContainerAdfBootChecksumInvalid
        }
        amiga_adf::WarningKind::EmptyFileWithDataPointer => {
            DiagnosticCode::ContainerAdfEmptyFileWithDataPointer
        }
    }
}

const fn source_error_code(error: &SourceError) -> DiagnosticCode {
    match error {
        SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
        SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
        SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
    }
}
