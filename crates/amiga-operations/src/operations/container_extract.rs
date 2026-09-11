//! `container.adf.extract` and `container.lha.extract` — recover a container's
//! members to disk.
//!
//! The first operation with an access class of `prepared_output`, and the shape
//! every later one follows.
//!
//! Both execution modes run the *same* preparation. `prepare` stops there and
//! reports the plan; `commit_reviewed` compares the plan it just built against
//! the digest the caller approved and writes only if they match. Preparing
//! twice is not waste — it is the check. Anything that changed between review
//! and commit (the source, the request, the files already in the destination)
//! changes the plan, and a changed plan is a `conflict` rather than a surprise.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{ContainerKind, NormalizedContainerExtract, NormalizedMode};
use crate::output::{DestinationError, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::response::{ContainerExtractResult, OperationOutcome, OperationResult, SourcePin};
use crate::source::SourceError;

/// The manifest an extraction writes beside its files, and the name a later
/// replacement checks for. Shared with the CLI's own extraction so a directory
/// written by either is governed the same way.
const MANIFEST_NAME: &str = "manifest.json";

pub(crate) fn run(
    request: &NormalizedContainerExtract,
    mode: &NormalizedMode,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: request.kind.operation(),
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let failed = |code, message: String, diagnostics: &mut Vec<Diagnostic>| {
        diagnostics.push(Diagnostic::error(code, message));
        diagnostics.clone()
    };

    // Resolve the destination first. An adapter that offered no output root has
    // authorized no write, and finding that out before reading a disk image is
    // both faster and clearer.
    let destination = match context.destinations().resolve(&request.destination) {
        Ok(path) => path,
        Err(error) => {
            let code = match error {
                DestinationError::Unavailable => DiagnosticCode::OutputDestinationUnavailable,
                DestinationError::Unusable { .. } => DiagnosticCode::OutputDestinationUnusable,
            };
            return outcome(
                Status::Error,
                failed(code, error.to_string(), &mut diagnostics),
                None,
            );
        }
    };

    let source = match context.resolve_source(&request.source, request.maximum_input_bytes) {
        Ok(source) => source,
        Err(error) => {
            let code = match error {
                SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
            };
            return outcome(
                Status::Error,
                failed(code, error.to_string(), &mut diagnostics),
                None,
            );
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "resolve_source",
        completed: source.size(),
        total: Some(source.size()),
    });

    // Everything is recovered and validated in memory before anything is
    // written, so malformed input cannot leave a misleading partial directory.
    let recovered = match request.kind {
        ContainerKind::Adf => amiga_analysis::prepare_adf_extraction(
            request.source.display_name(),
            source.bytes(),
            amiga_analysis::AdfExtractionLimits::new(
                context.limits().maximum_total_recovered_bytes(),
                context.limits().maximum_objects(),
            ),
        ),
        ContainerKind::Lha => amiga_analysis::prepare_lha_extraction(
            request.source.display_name(),
            source.bytes(),
            amiga_lha::OutputLimit::new(context.limits().maximum_total_recovered_bytes()),
        ),
    };
    let prepared = match recovered {
        Ok(prepared) => prepared,
        Err(error) => {
            use amiga_analysis::ExtractionPreparationError;
            let code = match &error {
                ExtractionPreparationError::MemberLimitExceeded { .. }
                | ExtractionPreparationError::OutputLimitExceeded { .. }
                | ExtractionPreparationError::Lha(amiga_lha::LhaError::OutputLimitExceeded {
                    ..
                }) => DiagnosticCode::LimitExceeded,
                _ => DiagnosticCode::ContainerUnreadable,
            };
            return outcome(
                Status::Error,
                failed(code, error.to_string(), &mut diagnostics),
                None,
            );
        }
    };
    for warning in &prepared.warnings {
        let diagnostic =
            Diagnostic::warning(DiagnosticCode::ContainerMemberSkipped, warning.clone());
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }
    // A damaged member gets a code of its own, and a warning rather than an
    // error: the request was well-formed and the operation did all it could,
    // which is recover the rest. What must not be quiet is *which* member and
    // why, because a directory silently missing a file reads as a complete one.
    // The commit is still all-or-nothing over what was recovered.
    for member in &prepared.unreadable {
        let diagnostic = Diagnostic::warning(
            DiagnosticCode::ContainerMemberUnreadable,
            format!(
                "{} is damaged and was not extracted: {}",
                member.path, member.reason
            ),
        );
        events.emit(OperationEvent::Diagnostic {
            diagnostic: diagnostic.clone(),
        });
        diagnostics.push(diagnostic);
    }
    // Nothing came out and something was refused: there is no extraction here,
    // only a directory holding a manifest that says so. Committing it would
    // consume the destination — `create_only` refuses a second attempt at a
    // path that already exists — so a user who repaired the image would find
    // the toolkit refusing to write the files it can now recover. An *empty*
    // volume is a different case and still extracts to an empty directory,
    // which is why this tests the refusals rather than the count.
    if prepared.plan.file_count() == 0 && !prepared.unreadable.is_empty() {
        return outcome(
            Status::Error,
            failed(
                DiagnosticCode::ContainerMemberUnreadable,
                format!(
                    "all {} file(s) this container holds are damaged, so there is nothing to \
                     extract",
                    prepared.unreadable.len()
                ),
                &mut diagnostics,
            ),
            None,
        );
    }
    let unreadable: Vec<crate::response::UnreadableMember> = prepared
        .unreadable
        .iter()
        .map(|member| crate::response::UnreadableMember {
            path: member.path.clone(),
            reason: member.reason.clone(),
        })
        .collect();
    events.emit(OperationEvent::Progress {
        phase: "recover_files",
        completed: prepared.plan.file_count() as u64,
        total: Some(prepared.plan.file_count() as u64),
    });

    let plan = WritePlan::new(
        &request.destination,
        crate::output::DestinationKind::Directory,
        request.policy,
        planned_outputs(&prepared),
        prepared.plan.directories().map(volume_path).collect(),
    );

    let approved = match mode {
        // `prepare` is the whole answer: the plan, and nothing on disk.
        NormalizedMode::Prepare => {
            return outcome(
                Status::Prepared,
                diagnostics,
                Some(OperationResult::ContainerExtract(ContainerExtractResult {
                    source: SourcePin {
                        size: source.size(),
                        sha256: source.sha256().to_owned(),
                    },
                    plan,
                    committed: false,
                    unreadable,
                })),
            );
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        // Refused in `normalize` against the access class, so this cannot
        // happen; failing loudly beats writing under an unexamined mode.
        NormalizedMode::Read => {
            return outcome(
                Status::Error,
                failed(
                    DiagnosticCode::RequestExecutionModeUnsupported,
                    "an extraction reached the handler in `read` mode".to_owned(),
                    &mut diagnostics,
                ),
                None,
            );
        }
    };

    if !plan.is_approved_by(approved) {
        // Not an error: the request was well-formed and the operation ran. What
        // it found is that the world no longer matches what the caller
        // approved, which is exactly what `conflict` means.
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} no longer describes this extraction, \
                 which now has digest {}; review it again",
                plan.plan_sha256
            ),
        ));
        return outcome(
            Status::Conflict,
            diagnostics,
            Some(OperationResult::ContainerExtract(ContainerExtractResult {
                source: SourcePin {
                    size: source.size(),
                    sha256: source.sha256().to_owned(),
                },
                plan,
                committed: false,
                unreadable,
            })),
        );
    }

    match prepared.plan.commit(
        &destination,
        request.policy.permits_replacement(),
        MANIFEST_NAME,
        &prepared.manifest,
    ) {
        Ok(_) => {
            events.emit(OperationEvent::Progress {
                phase: "commit",
                completed: plan.files.len() as u64,
                total: Some(plan.files.len() as u64),
            });
            outcome(
                Status::Success,
                diagnostics,
                Some(OperationResult::ContainerExtract(ContainerExtractResult {
                    source: SourcePin {
                        size: source.size(),
                        sha256: source.sha256().to_owned(),
                    },
                    plan,
                    committed: true,
                    unreadable,
                })),
            )
        }
        // A destination that refuses the write — present without a manifest
        // under `create_only`, or holding files the manifest does not govern —
        // is the other half of optimistic concurrency, and reports the same
        // status as a changed plan.
        Err(error) => outcome(
            Status::Conflict,
            failed(
                DiagnosticCode::OutputDestinationRefused,
                error.to_string(),
                &mut diagnostics,
            ),
            None,
        ),
    }
}

/// The plan entries for a prepared extraction, hashing each recovered file.
fn planned_outputs(prepared: &amiga_analysis::PreparedExtraction) -> Vec<PlannedOutput> {
    prepared
        .plan
        .files()
        .iter()
        .map(|file| PlannedOutput {
            path: volume_path(&file.path),
            size: file.bytes.len() as u64,
            sha256: amiga_core::sha256(&file.bytes),
        })
        .collect()
}

/// A planned path as the wire spells it: `/`-separated, so the plan digest does
/// not depend on the host's path separator.
fn volume_path(path: &std::path::Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}
