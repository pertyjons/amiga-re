//! `hardware.copper.references` — the CPU writes that edit a Copper list.
//!
//! A loader copies a Copper template into chip RAM and then patches the copy:
//! a colour here, a bitplane pointer there, a WAIT position for the split. The
//! template in the file is therefore not what the Copper executes, and reading
//! it alone gives the wrong display.
//!
//! Two sources, because the code and the list it edits need not be the same
//! bytes. The template is decoded from its *own* bytes so its instruction
//! offsets are list-relative — the same frame the pointer-relative writes are
//! measured in, which is what lets a write be matched to the field it patches.
//!
//! A write through the pointer that lands *outside* the copied list is reported
//! with no patch site rather than dropped. It is still a fact about the routine,
//! and a list that silently omitted it would read as "this routine only touches
//! the Copper list" — which is exactly the claim it disproves.

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::NormalizedCopperReferences;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    CopperChange, CopperEffectiveList, CopperPatchSite, CopperPatchWrite, CopperReferencesResult,
    CopperWord, OperationOutcome, OperationResult, SourcePin,
};
use crate::source::SourceError;

/// Write `value` into `buffer` at `offset`, `size` bytes wide, big-endian.
///
/// Out-of-range writes are ignored rather than refused: the routine may store
/// through the pointer beyond the list it copied, and that is what the missing
/// patch site already says.
fn apply_write(buffer: &mut [u8], offset: usize, size: usize, value: u32) {
    let Some(slot) = offset
        .checked_add(size)
        .and_then(|end| buffer.get_mut(offset..end))
    else {
        return;
    };
    let bytes = value.to_be_bytes();
    if let Some(source) = bytes.get(4 - size..) {
        slot.copy_from_slice(source);
    }
}

pub(crate) fn run(
    request: &NormalizedCopperReferences,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::HardwareCopperReferences,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let resolve = |name: &crate::normalize::NormalizedSource| {
        context
            .resolve_source(name, request.maximum_input_bytes)
            .map_err(|error| {
                let code = match error {
                    SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                    SourceError::TooLarge { .. } => DiagnosticCode::SourceTooLarge,
                    SourceError::Unreadable { .. } => DiagnosticCode::SourceUnreadable,
                };
                Diagnostic::error(code, error.to_string())
            })
    };

    let source = match resolve(&request.source) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let template_source = match resolve(&request.template_source) {
        Ok(source) => source,
        Err(diagnostic) => {
            diagnostics.push(diagnostic.at("$.request.arguments.template.source"));
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let hunk = match super::code::locate(source.bytes(), request.hunk, &request.entries) {
        Ok(hunk) => hunk,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            return outcome(Status::Error, diagnostics, None);
        }
    };
    let analysis = hunk.analyze(&request.entries, request.origin);

    let Some(slice) = template_source
        .bytes()
        .get(request.template_offset as usize..)
    else {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::SourceRangeOutsideSource,
                format!(
                    "template offset {:#x} is past the end of the {}-byte source",
                    request.template_offset,
                    template_source.size()
                ),
            )
            .at("$.request.arguments.template.offset"),
        );
        return outcome(Status::Error, diagnostics, None);
    };
    let template = amiga_hw::copper::decode(slice, 0);
    if template.is_empty() {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticCode::AnalysisRecordUnreadable,
                format!(
                    "no Copper instructions at {:#x} in the template source",
                    request.template_offset
                ),
            )
            .at("$.request.arguments.template.offset"),
        );
        return outcome(Status::Error, diagnostics, None);
    }
    let list_bytes = template
        .last()
        .and_then(|last| last.offset.checked_add(4))
        .unwrap_or(0) as usize;

    // The first entry is the routine's, and the pointer register's value there
    // is offset zero for every write the traversal finds. A routine that loads
    // the list's address itself establishes the same base at that instruction,
    // but only when the request says where the list runs — the decoded template
    // gives the length that keeps such a match inside the list.
    let entry = request.entries.first().copied().unwrap_or(0);
    let block = request
        .template_address
        .map(|address| amiga_disasm::BlockAddress {
            address,
            length: u32::try_from(list_bytes).unwrap_or(u32::MAX),
        });
    let writes = amiga_disasm::pointer_relative_writes(
        &analysis,
        entry,
        request.pointer_register,
        block,
        request.origin,
    );

    events.emit(OperationEvent::Progress {
        phase: "match_patch_sites",
        completed: writes.len() as u64,
        total: Some(writes.len() as u64),
    });

    let mut writes_in_list = 0_u64;
    let described: Vec<CopperPatchWrite> = writes
        .iter()
        .map(|write| {
            let patches = amiga_hw::patch_site(&template, write.offset);
            if patches.is_some() {
                writes_in_list += 1;
            }
            CopperPatchWrite {
                site: write.site,
                address: request
                    .origin
                    .and_then(|origin| origin.checked_add(write.site)),
                offset: write.offset,
                size: write.size,
                value: write.value,
                patches: patches.map(|site| CopperPatchSite {
                    instruction_offset: site.instruction_offset,
                    word: match site.word {
                        amiga_hw::CopperWord::Control => CopperWord::Control,
                        amiga_hw::CopperWord::Data => CopperWord::Data,
                    },
                    description: site.description,
                }),
                base_site: match write.base {
                    amiga_disasm::PointerBase::Entry => None,
                    amiga_disasm::PointerBase::Loaded(site) => Some(site),
                },
            }
        })
        .collect();

    let effective = request.apply.then(|| {
        let mut bytes = slice.get(..list_bytes).unwrap_or(slice).to_vec();
        let mut applied = 0_u64;
        for write in &writes {
            let Some(value) = write.value else { continue };
            if amiga_hw::patch_site(&template, write.offset).is_none() {
                continue;
            }
            apply_write(
                &mut bytes,
                write.offset as usize,
                usize::from(write.size.unwrap_or(2)),
                value,
            );
            applied += 1;
        }
        let decoded = amiga_hw::copper::decode(&bytes, 0);
        // Applying immediates only rewrites words, so the effective list has
        // the template's structure and the two zip instruction for instruction.
        let changes: Vec<CopperChange> = template
            .iter()
            .zip(decoded.iter())
            .filter(|(before, after)| before.op != after.op)
            .map(|(before, after)| CopperChange {
                offset: after.offset,
                before: super::graphics_scan::as_response_op(before),
                after: super::graphics_scan::as_response_op(after),
            })
            .collect();
        let palette = amiga_hw::display_spec(&decoded).palette;
        let instruction_total = decoded.len();
        CopperEffectiveList {
            applied,
            instructions: decoded
                .iter()
                .take(request.maximum_instructions)
                .map(super::graphics_scan::as_response_instruction)
                .collect(),
            instruction_total: instruction_total as u64,
            instructions_truncated: instruction_total > request.maximum_instructions,
            changes,
            palette_rgb12: palette.clone(),
            palette_rgb8: palette
                .iter()
                .copied()
                .map(amiga_hw::rgb4_to_rgb8)
                .collect(),
        }
    });

    let write_total = described.len();
    let template_total = template.len();
    let writes_truncated = write_total > request.maximum_writes;
    let template_truncated = template_total > request.maximum_instructions;
    if writes_truncated || template_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the routine makes {write_total} writes into a {template_total}-instruction \
                 list; each list reports its true total"
            ),
        ));
    }

    let result = CopperReferencesResult {
        source: SourcePin {
            size: source.size(),
            sha256: source.sha256().to_owned(),
        },
        hunk: request.hunk,
        origin: request.origin,
        entries: request.entries.clone(),
        pointer_register: request.pointer_register,
        template_source: SourcePin {
            size: template_source.size(),
            sha256: template_source.sha256().to_owned(),
        },
        template_offset: request.template_offset,
        template_address: request.template_address,
        template: template
            .iter()
            .take(request.maximum_instructions)
            .map(super::graphics_scan::as_response_instruction)
            .collect(),
        template_total: template_total as u64,
        template_truncated,
        list_bytes: list_bytes as u64,
        writes: described.into_iter().take(request.maximum_writes).collect(),
        write_total: write_total as u64,
        writes_truncated,
        writes_in_list,
        effective,
    };
    outcome(
        Status::Success,
        diagnostics,
        Some(OperationResult::HardwareCopperReferences(result)),
    )
}
