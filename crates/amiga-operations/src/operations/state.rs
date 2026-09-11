//! `analysis.state.snapshot` and `analysis.state.compare` — a machine's state
//! in the project's own vocabulary, and what two of them disagree about.
//!
//! ## Why a digest is not enough
//!
//! `env.sandbox.call` reports changed memory as runs of bytes and
//! `env.sandbox.compare` compares them by address. That is the right answer when
//! the question is *did this run behave differently*. It is the wrong answer
//! when the question is *what state changed*: a digest over a region says two
//! runs differ and nothing about which of the forty values in it moved, and a
//! clean-room port with the same fields laid out differently compares as wholly
//! different memory while being wholly correct.
//!
//! A snapshot names each value. `vehicle.velocity.x` is a path, not an address,
//! so two runs under different load maps align on it — which is the property
//! that makes a comparison mean something, since aligning on the address would
//! report a relocation as a change in the data.
//!
//! ## What is refused rather than reported
//!
//! A snapshot's whole value is that a field's absence means the machine did not
//! hold it. So everything that would make a field silently missing is a refusal
//! of the snapshot: a stale annotation, a type the project does not define, a
//! type whose size disagrees with the storage, two variables over the same
//! bytes, and storage no supplied region covers. The alternative — omitting the
//! field and carrying on — produces a document that compares cleanly against one
//! that had it, and reads as agreement.

use std::collections::BTreeMap;

use amiga_project::document::{Annotation, Target, TypeDefinition};

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedStateCompare, NormalizedStateSnapshot};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    ComparedSnapshot, OperationOutcome, OperationResult, StateCompareResult, StateDifference,
    StateField, StateRegionPin, StateSnapshotResult, StateValue,
};

/// How deep a type may nest before the walk gives up.
///
/// An alias cycle is already refused by the format, but an array of structs of
/// arrays is legal and unbounded in principle. Sixteen is far past anything a
/// reviewed game structure reaches, and it is a bound rather than a hope.
const MAXIMUM_DEPTH: usize = 16;

/// The machine's memory, as the ranges a request supplied.
///
/// Ordered by address so a lookup is a search rather than a scan, and because a
/// snapshot reports its regions in a stable order whatever order they arrived.
struct Machine {
    regions: Vec<(u32, Vec<u8>)>,
}

impl Machine {
    /// The bytes at `[address, address + length)`, when one region holds all of
    /// them.
    ///
    /// Deliberately not stitched across two regions: two ranges that happen to
    /// abut in a request are two files, and a value read across the seam would
    /// be half of one and half of the other with nothing saying so.
    fn slice(&self, address: u32, length: u64) -> Option<&[u8]> {
        for (base, bytes) in &self.regions {
            let Some(offset) = address.checked_sub(*base) else {
                continue;
            };
            let start = offset as usize;
            let end = start.checked_add(usize::try_from(length).ok()?)?;
            if end <= bytes.len() {
                return bytes.get(start..end);
            }
        }
        None
    }
}

/// One variable to decode: its name, where it is, and what it is.
struct Located {
    name: String,
    address: u32,
    length: u64,
    type_id: String,
    object_sha256: String,
}

pub(crate) fn snapshot(
    request: &NormalizedStateSnapshot,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisStateSnapshot,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match decode(request, context, &mut diagnostics, events) {
        Ok(result) => outcome(
            Status::Success,
            diagnostics,
            Some(OperationResult::AnalysisStateSnapshot(result)),
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

/// Read the project, resolve every global of the selected image, and decode it.
#[expect(
    clippy::too_many_lines,
    reason = "one snapshot, told in order: the project, the machine, the variables, the values"
)]
fn decode(
    request: &NormalizedStateSnapshot,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Result<StateSnapshotResult, Diagnostic> {
    let root = context
        .resolver()
        .root()
        .map(|root| root.join(request.project.path.as_str()))
        .ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::ProjectUnreadable,
                "this context serves no directory, so no project can be located",
            )
        })?;
    let loaded = amiga_project::load(&root)
        .map_err(|error| Diagnostic::error(DiagnosticCode::ProjectUnreadable, error.to_string()))?;
    // Fatal problems already refused the load. What is left is reviewed but
    // imperfect, and a snapshot is evidence: a reader is owed the same warnings
    // `project check` would have given them.
    for problem in &loaded.problems {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ProjectHasProblems,
            format!("the project reports {}: {}", problem.code, problem.message),
        ));
    }
    let project = &loaded.project;
    let image_id = select_image(project, request.image.as_deref())?;
    let sizes = amiga_project::layout::TypeSizes::of(project);

    // The machine, read before any variable is resolved: a snapshot that
    // decoded half its fields and then found a region missing would have
    // spent the reader's attention on a document it was going to refuse.
    let mut regions = Vec::with_capacity(request.regions.len());
    let mut pins = Vec::with_capacity(request.regions.len());
    for region in &request.regions {
        let resolved = context
            .resolve_source(&region.source, request.maximum_input_bytes)
            .map_err(|error| {
                Diagnostic::error(
                    match error {
                        crate::source::SourceError::Missing { .. } => DiagnosticCode::SourceMissing,
                        crate::source::SourceError::TooLarge { .. } => {
                            DiagnosticCode::SourceTooLarge
                        }
                        crate::source::SourceError::Unreadable { .. } => {
                            DiagnosticCode::SourceUnreadable
                        }
                    },
                    error.to_string(),
                )
            })?;
        if let Some(pinned) = &region.sha256
            && resolved.sha256() != pinned
        {
            return Err(Diagnostic::error(
                DiagnosticCode::SourceDigestMismatch,
                format!(
                    "the region {} hashes to {}, not the pinned {pinned}; a snapshot of \
                     bytes this request does not name would describe a machine nobody ran",
                    region.source.display_name(),
                    resolved.sha256()
                ),
            )
            .at("$.request.arguments.regions"));
        }
        let bytes = resolved.bytes();
        let offset = region.offset as usize;
        let length = match region.length {
            Some(length) => length as usize,
            None => bytes.len().saturating_sub(offset),
        };
        let taken = bytes
            .get(offset..offset.saturating_add(length))
            .ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::SourceRangeOutsideSource,
                    format!(
                        "a region reads [{offset:#x}..+{length:#x}) of {}, which holds {} bytes",
                        region.source.display_name(),
                        bytes.len()
                    ),
                )
                .at("$.request.arguments.regions")
            })?
            .to_vec();
        pins.push(StateRegionPin {
            address: region.address,
            length: u32::try_from(taken.len()).unwrap_or(u32::MAX),
            source: region.source.display_name(),
            sha256: amiga_core::sha256(&taken),
        });
        regions.push((region.address, taken));
    }
    regions.sort_by_key(|(address, _)| *address);
    pins.sort_by_key(|pin| pin.address);
    let machine = Machine { regions };

    let located = locate(project, &image_id, request)?;
    events.emit(OperationEvent::Progress {
        phase: "resolve_variables",
        completed: located.len() as u64,
        total: Some(located.len() as u64),
    });

    // Two variables over one set of bytes is a contradiction the project should
    // have been refused for, and a snapshot cannot paper over it: whichever it
    // decoded second would name the same memory a second way.
    let mut covered: Vec<(u32, u64, &str)> = Vec::with_capacity(located.len());
    for variable in &located {
        let end = u64::from(variable.address) + variable.length;
        for (address, length, name) in &covered {
            let other_end = u64::from(*address) + length;
            if u64::from(variable.address) < other_end && u64::from(*address) < end {
                return Err(Diagnostic::error(
                    DiagnosticCode::ProjectHasProblems,
                    format!(
                        "the variables {:?} and {name:?} both cover [{:#x}..+{:#x}); a \
                         snapshot naming one set of bytes twice would report one machine \
                         as two",
                        variable.name, variable.address, variable.length
                    ),
                ));
            }
        }
        covered.push((variable.address, variable.length, &variable.name));
    }

    let mut fields = Vec::new();
    for variable in &located {
        let size = sizes.size_of(&variable.type_id).ok_or_else(|| {
            Diagnostic::error(
                DiagnosticCode::ProjectHasProblems,
                format!(
                    "the variable {:?} names the type {:?}, whose size this project does \
                     not settle; a snapshot cannot read a value whose width is unknown",
                    variable.name, variable.type_id
                ),
            )
        })?;
        if size != variable.length {
            return Err(Diagnostic::error(
                DiagnosticCode::ProjectHasProblems,
                format!(
                    "the variable {:?} has {} bytes of storage and names the type {:?}, \
                     which is {size}; the two are reviewed claims about one set of bytes \
                     and a snapshot cannot pick one",
                    variable.name, variable.length, variable.type_id
                ),
            ));
        }
        walk(
            &sizes,
            &variable.type_id,
            &variable.name,
            variable.address,
            &machine,
            &variable.object_sha256,
            0,
            &mut fields,
        )?;
    }

    fields.sort_by(|left, right| left.path.cmp(&right.path));
    let fields_total = fields.len() as u64;
    let fields_truncated = fields.len() > request.maximum_fields;
    if fields_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "the snapshot holds {fields_total} fields; {} are reported",
                request.maximum_fields
            ),
        ));
    }
    fields.truncate(request.maximum_fields);

    Ok(StateSnapshotResult {
        image_id,
        regions: pins,
        registers: request.registers,
        fields,
        fields_total,
        fields_truncated,
    })
}

/// Which image the snapshot is of.
///
/// A project with one image needs no argument; one with several is refused
/// rather than having one picked for it, because the wrong choice produces a
/// complete, plausible snapshot of the wrong program.
fn select_image(
    project: &amiga_project::document::Project,
    requested: Option<&str>,
) -> Result<String, Diagnostic> {
    let images: Vec<&str> = project
        .programs
        .iter()
        .flat_map(|program| program.images.iter())
        .map(|image| image.id.as_str())
        .collect();
    match requested {
        Some(image) if images.contains(&image) => Ok(image.to_owned()),
        Some(image) => Err(Diagnostic::error(
            DiagnosticCode::ProjectHasProblems,
            format!(
                "the project describes no image {image:?}; it describes {}",
                if images.is_empty() {
                    "none".to_owned()
                } else {
                    images.join(", ")
                }
            ),
        )
        .at("$.request.arguments.image")),
        None if images.len() == 1 => Ok(images[0].to_owned()),
        None if images.is_empty() => Err(Diagnostic::error(
            DiagnosticCode::ProjectHasProblems,
            "the project describes no image, so it names no variables to decode",
        )),
        None => Err(Diagnostic::error(
            DiagnosticCode::ProjectHasProblems,
            format!(
                "the project describes {} images ({}); name the one this snapshot is of",
                images.len(),
                images.join(", ")
            ),
        )
        .at("$.request.arguments.image")),
    }
}

/// Every global variable of one image, resolved to an absolute address.
fn locate(
    project: &amiga_project::document::Project,
    image_id: &str,
    request: &NormalizedStateSnapshot,
) -> Result<Vec<Located>, Diagnostic> {
    let bases: BTreeMap<u32, u32> = request
        .hunk_bases
        .iter()
        .map(|base| (base.hunk, base.address))
        .collect();
    let mut located = Vec::new();
    for document in &project.annotations {
        for annotation in &document.annotations {
            let Annotation::Variable {
                name,
                target,
                type_id,
                ..
            } = annotation
            else {
                continue;
            };
            // A local is scoped to a function and lives in a register or a
            // stack slot for part of one call. It is not machine state a
            // snapshot can name, and skipping it is not a gap: the project
            // itself says it belongs to a frame rather than to the program.
            let Some(target) = target.as_deref() else {
                continue;
            };
            // Another image's variable is not this snapshot's business. A target
            // that names *no* image is not skipped, though: only `object` and
            // `entity` targets do that, and both are places that are not a
            // running machine — [`address_of`] refuses them by name, which is
            // the whole promise this module makes. Skipping them here instead
            // would answer a project whose globals are all object ranges with an
            // empty snapshot and no explanation.
            if target.image_id().is_some_and(|id| id.as_str() != image_id) {
                continue;
            }
            // The format's own test, and reachable: `variable` carries the
            // `stale` flag as `function` and `symbol` do. A reviewer who has
            // found that a global moved says so here, and a snapshot must then
            // refuse rather than decode whatever now lives at the address — the
            // per-field `object_sha256` says the bytes changed, and only this
            // says a person looked and agreed the annotation is wrong.
            if annotation.is_stale() {
                return Err(Diagnostic::error(
                    DiagnosticCode::ProjectContradicted,
                    format!(
                        "the variable {name:?} is marked stale, so the project no longer \
                         claims it is where it says; rebase it before snapshotting"
                    ),
                ));
            }
            let type_id = type_id.as_ref().ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::ProjectHasProblems,
                    format!(
                        "the variable {name:?} names no type, so a snapshot has nothing to \
                         read its storage as"
                    ),
                )
            })?;
            let length = target.byte_length().ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::ProjectHasProblems,
                    format!("the variable {name:?} targets an entity rather than bytes"),
                )
            })?;
            let address = address_of(target, &bases, request).map_err(|why| {
                Diagnostic::error(
                    DiagnosticCode::ProjectHasProblems,
                    format!("the variable {name:?} cannot be placed: {why}"),
                )
            })?;
            located.push(Located {
                name: name.clone(),
                address,
                length,
                type_id: type_id.as_str().to_owned(),
                object_sha256: target
                    .object_sha256()
                    .map(|digest| digest.as_str().to_owned())
                    .unwrap_or_default(),
            });
        }
    }
    located.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(located)
}

/// Where one target sits in the snapshot's address space.
fn address_of(
    target: &Target,
    bases: &BTreeMap<u32, u32>,
    request: &NormalizedStateSnapshot,
) -> Result<u32, String> {
    match target {
        Target::Runtime { address, .. } => amiga_core::parse_u32(address)
            .map_err(|message| format!("its runtime address {address:?} is unreadable: {message}")),
        Target::Hunk { hunk, offset, .. } => {
            let base = bases.get(hunk).copied().ok_or_else(|| {
                format!(
                    "it targets hunk {hunk}, which this request does not place; name it in \
                     hunk_bases with the address the run mapped it at"
                )
            })?;
            u32::try_from(*offset)
                .ok()
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| format!("hunk {hunk} offset {offset} overflows the address space"))
        }
        Target::BaseRegister {
            base_register,
            displacement,
            ..
        } => {
            let registers = request.registers.as_ref().ok_or_else(|| {
                format!(
                    "it is a small-data global at {}{displacement:+}, and this request \
                     supplied no register file to take {base_register} from",
                    base_register.to_uppercase()
                )
            })?;
            let index: usize = base_register
                .strip_prefix(['a', 'A'])
                .and_then(|digits| digits.parse().ok())
                .ok_or_else(|| format!("its base register {base_register:?} names no register"))?;
            let base =
                registers.a.get(index).copied().ok_or_else(|| {
                    format!("its base register {base_register:?} is out of range")
                })?;
            Ok(base.wrapping_add(*displacement as u32))
        }
        // An object range is an offset in a file, not an address in a machine.
        // Refused by name rather than skipped: a project that named its state
        // that way would otherwise get an empty snapshot and no explanation.
        Target::Object { .. } => Err(
            "it targets a range of an object, which is a place in a file rather than in a \
             running machine; a snapshot reads runtime, hunk and base-register targets"
                .to_owned(),
        ),
        Target::Entity { .. } => Err("it targets another annotation rather than bytes".to_owned()),
    }
}

/// Decode one type at one address into leaves, appending to `fields`.
#[expect(
    clippy::too_many_arguments,
    reason = "the walk carries the whole decoding context; bundling it would name one struct \
              used in exactly one place"
)]
fn walk(
    sizes: &amiga_project::layout::TypeSizes<'_>,
    type_id: &str,
    path: &str,
    address: u32,
    machine: &Machine,
    object_sha256: &str,
    depth: usize,
    fields: &mut Vec<StateField>,
) -> Result<(), Diagnostic> {
    if depth > MAXIMUM_DEPTH {
        return Err(Diagnostic::error(
            DiagnosticCode::ProjectHasProblems,
            format!("the type of {path:?} nests deeper than {MAXIMUM_DEPTH} levels"),
        ));
    }
    let definition = sizes.definition(type_id).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::ProjectHasProblems,
            format!("{path:?} names the type {type_id:?}, which the project does not define"),
        )
    })?;
    let size = sizes.size_of(type_id).ok_or_else(|| {
        Diagnostic::error(
            DiagnosticCode::ProjectHasProblems,
            format!("{path:?} names the type {type_id:?}, whose size this project does not settle"),
        )
    })?;

    match definition {
        TypeDefinition::Alias { aliased_id, .. } => walk(
            sizes,
            aliased_id.as_str(),
            path,
            address,
            machine,
            object_sha256,
            depth + 1,
            fields,
        ),
        TypeDefinition::Struct {
            fields: members, ..
        } => {
            for member in members {
                let at = u32::try_from(member.offset)
                    .ok()
                    .and_then(|offset| address.checked_add(offset))
                    .ok_or_else(|| {
                        Diagnostic::error(
                            DiagnosticCode::ProjectHasProblems,
                            format!("the field {:?} of {path:?} overflows", member.name),
                        )
                    })?;
                walk(
                    sizes,
                    member.type_id.as_str(),
                    &format!("{path}.{}", member.name),
                    at,
                    machine,
                    object_sha256,
                    depth + 1,
                    fields,
                )?;
            }
            Ok(())
        }
        TypeDefinition::Array {
            element_id, count, ..
        } => {
            let stride = sizes.size_of(element_id.as_str()).ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::ProjectHasProblems,
                    format!(
                        "the element type {:?} of {path:?} has no settled size",
                        element_id.as_str()
                    ),
                )
            })?;
            for index in 0..*count {
                let at = u64::from(address) + u64::from(index) * stride;
                let at = u32::try_from(at).map_err(|_| {
                    Diagnostic::error(
                        DiagnosticCode::ProjectHasProblems,
                        format!("element {index} of {path:?} overflows the address space"),
                    )
                })?;
                walk(
                    sizes,
                    element_id.as_str(),
                    &format!("{path}[{index}]"),
                    at,
                    machine,
                    object_sha256,
                    depth + 1,
                    fields,
                )?;
            }
            Ok(())
        }
        // A leaf. Read the bytes once here so every scalar form goes through
        // one bounds check and one "not covered" refusal.
        _ => {
            let bytes = machine.slice(address, size).ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::SourceRangeOutsideSource,
                    format!(
                        "{path:?} lives at [{address:#x}..+{size:#x}), which no region of \
                         this snapshot covers; a field left out would compare cleanly \
                         against one that had it"
                    ),
                )
                .at("$.request.arguments.regions")
            })?;
            let value = leaf(sizes, definition, bytes)?;
            fields.push(StateField {
                path: path.to_owned(),
                address,
                size,
                type_id: type_id.to_owned(),
                object_sha256: object_sha256.to_owned(),
                value,
            });
            Ok(())
        }
    }
}

/// One scalar, read as its type says.
fn leaf(
    sizes: &amiga_project::layout::TypeSizes<'_>,
    definition: &TypeDefinition,
    bytes: &[u8],
) -> Result<StateValue, Diagnostic> {
    match definition {
        TypeDefinition::Integer {
            signed, byte_order, ..
        } => Ok(match integer(bytes, *signed, byte_order) {
            Some(value) => StateValue::Integer {
                value,
                signed: *signed,
                byte_order: byte_order.clone(),
            },
            None => StateValue::Bytes { hex: hex(bytes) },
        }),
        TypeDefinition::Pointer { address_space, .. } => match integer(bytes, false, "big") {
            Some(value) => Ok(StateValue::Pointer {
                address: value as u32,
                address_space: address_space.clone(),
            }),
            None => Ok(StateValue::Bytes { hex: hex(bytes) }),
        },
        TypeDefinition::Enum {
            base_id, members, ..
        } => {
            let base = sizes.definition(base_id.as_str()).ok_or_else(|| {
                Diagnostic::error(
                    DiagnosticCode::ProjectHasProblems,
                    format!("an enum's base type {:?} is not defined", base_id.as_str()),
                )
            })?;
            let (signed, byte_order) = match base {
                TypeDefinition::Integer {
                    signed, byte_order, ..
                } => (*signed, byte_order.as_str()),
                // An enum over something that is not an integer is a document
                // fault; reading it as bytes says so without inventing a number.
                _ => return Ok(StateValue::Bytes { hex: hex(bytes) }),
            };
            Ok(match integer(bytes, signed, byte_order) {
                Some(value) => StateValue::Enum {
                    value,
                    member: members
                        .iter()
                        .find(|member| member.value == value)
                        .map(|member| member.name.clone()),
                },
                None => StateValue::Bytes { hex: hex(bytes) },
            })
        }
        // A function is code, not storage, and a variable that named one would
        // already have failed the size check — a signature has no size at all.
        // Reported rather than refused a second time here.
        _ => Ok(StateValue::Bytes { hex: hex(bytes) }),
    }
}

/// Read `bytes` as one integer, or `None` when the width is not one this build
/// reads as a scalar.
fn integer(bytes: &[u8], signed: bool, byte_order: &str) -> Option<i64> {
    let little = byte_order.eq_ignore_ascii_case("little");
    let mut value: u64 = 0;
    match bytes.len() {
        1 | 2 | 4 | 8 => {
            if little {
                for byte in bytes.iter().rev() {
                    value = (value << 8) | u64::from(*byte);
                }
            } else {
                for byte in bytes {
                    value = (value << 8) | u64::from(*byte);
                }
            }
        }
        _ => return None,
    }
    if !signed {
        return i64::try_from(value).ok();
    }
    // Sign-extend from the stored width, which is what makes `0xff` at one byte
    // read as -1 rather than as 255.
    let bits = bytes.len() * 8;
    Some(if bits == 64 {
        value as i64
    } else {
        let sign = 1_u64 << (bits - 1);
        if value & sign == 0 {
            value as i64
        } else {
            (value as i64) - (1_i64 << bits)
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn compare(
    request: &NormalizedStateCompare,
    context: &ExecutionContext<'_>,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::AnalysisStateCompare,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    match compare_snapshots(request, context, &mut diagnostics, events) {
        Ok(result) => outcome(
            Status::Success,
            diagnostics,
            Some(OperationResult::AnalysisStateCompare(result)),
        ),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            outcome(Status::Error, diagnostics, None)
        }
    }
}

/// Read every snapshot and report the paths they disagree about.
fn compare_snapshots(
    request: &NormalizedStateCompare,
    context: &ExecutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    events: &mut BoundedSink<'_>,
) -> Result<StateCompareResult, Diagnostic> {
    let mut read = Vec::with_capacity(request.snapshots.len());
    for source in &request.snapshots {
        let resolved = context
            .resolve_source(source, request.maximum_input_bytes)
            .map_err(|error| {
                Diagnostic::error(DiagnosticCode::SourceUnreadable, error.to_string())
            })?;
        // Strictly, and `deny_unknown_fields` in both directions: a document a
        // build did not fully understand would still produce a plausible
        // comparison, which is the one answer this operation must not give.
        let snapshot: StateSnapshotResult =
            serde_json::from_slice(resolved.bytes()).map_err(|error| {
                Diagnostic::error(
                    DiagnosticCode::AnalysisRecordUnreadable,
                    format!(
                        "{} is not a state snapshot this build understands: {error}",
                        source.display_name()
                    ),
                )
            })?;
        read.push((
            ComparedSnapshot {
                name: source.display_name(),
                sha256: resolved.sha256().to_owned(),
                image_id: snapshot.image_id.clone(),
                fields_total: snapshot.fields_total,
                fields_truncated: snapshot.fields_truncated,
            },
            snapshot,
        ));
    }
    events.emit(OperationEvent::Progress {
        phase: "read_snapshots",
        completed: read.len() as u64,
        total: Some(read.len() as u64),
    });

    // A capped snapshot cannot tell an absent field from one truncated away, so
    // the comparison says so once rather than reporting every missing path as a
    // difference the reader would have to discount by hand.
    for (compared, _) in &read {
        if compared.fields_truncated {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::ResultEntriesTruncated,
                format!(
                    "the snapshot {} reports {} of its fields; a path missing from it may \
                     have been truncated rather than absent from the machine",
                    compared.name, compared.fields_total
                ),
            ));
        }
    }
    // Two snapshots of different images is a comparison of two programs. Worth
    // saying, and not worth refusing: comparing an original against a port is
    // exactly what this is for, and the port's image will not share an id.
    let images: std::collections::BTreeSet<&str> = read
        .iter()
        .map(|(compared, _)| compared.image_id.as_str())
        .collect();
    if images.len() > 1 {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ProjectHasProblems,
            format!(
                "the snapshots describe different images ({}); they are compared by field \
                 path, which is what makes that meaningful",
                images.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }

    let compared: Vec<ComparedSnapshot> =
        read.iter().map(|(compared, _)| compared.clone()).collect();
    let mut paths: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut by_path: Vec<BTreeMap<&str, &StateValue>> = Vec::with_capacity(read.len());
    for (_, snapshot) in &read {
        let mut index: BTreeMap<&str, &StateValue> = BTreeMap::new();
        for field in &snapshot.fields {
            paths.insert(field.path.as_str());
            index.insert(field.path.as_str(), &field.value);
        }
        by_path.push(index);
    }

    let mut differences = Vec::new();
    let mut differences_total = 0_u64;
    for path in &paths {
        let values: Vec<Option<&StateValue>> = by_path
            .iter()
            .map(|index| index.get(path).copied())
            .collect();
        let first = values.first().copied().flatten();
        if values.iter().all(|value| *value == first) {
            continue;
        }
        differences_total += 1;
        if differences.len() < request.maximum_differences {
            differences.push(StateDifference {
                path: (*path).to_owned(),
                values: values.into_iter().map(|value| value.cloned()).collect(),
            });
        }
    }
    let differences_truncated = differences_total > differences.len() as u64;
    if differences_truncated {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ResultEntriesTruncated,
            format!(
                "{differences_total} fields differ; {} are reported",
                differences.len()
            ),
        ));
    }

    Ok(StateCompareResult {
        snapshots: compared,
        identical: differences_total == 0,
        paths_total: paths.len() as u64,
        differences,
        differences_total,
        differences_truncated,
    })
}
