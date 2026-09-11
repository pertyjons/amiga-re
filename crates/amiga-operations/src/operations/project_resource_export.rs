//! `project.resource.export` — a resource turned back into a file.
//!
//! The path from reviewed knowledge to bytes, which the toolkit did not have:
//! a project could say what a range of bytes is and how it decodes, and nothing
//! could execute that. Every other export operation takes its parameters from
//! the caller, which makes the file a one-off; this one takes them from the
//! project, which is what makes it reproducible.
//!
//! It deliberately does **not** need `SourceLocator` to grow a container
//! variant. The project already knows how to get the bytes — the same selector
//! chain `project.verify` walks, through the same `ContainerRecovery` — and a
//! materialised extraction file is not even reachable from an `Object`, which
//! carries no path.
//!
//! **The destination is derived, never given.** `recipe::artifact_path` decides
//! it from the resource's ID and its recipe key, and the extension comes from
//! the export profile. A caller that could name the file would be deciding the
//! output outside the record that claims to reproduce it.
//!
//! **The key is in the path, and that is what makes re-export safe.** Files are
//! written before documents everywhere in this toolkit, which is right the first
//! time — a document failure leaves an unregistered file, and re-exporting fixes
//! it. On a *re*-export the same ordering would overwrite the previous output
//! first, leaving the old `Artifact` record describing new bytes with the old
//! digest: confidently wrong, which is worse than missing. A keyed path means a
//! new export never occupies the old one's place, recording the new artifact is
//! what makes it live, and the superseded file is reported as removable rather
//! than deleted.

use amiga_project::document::Resource;

use crate::context::ExecutionContext;
use crate::diagnostics::{Diagnostic, DiagnosticCode};
use crate::events::{BoundedSink, EventSink, OperationEvent};
use crate::normalize::{NormalizedMode, NormalizedResourceExport};
use crate::output::{DestinationKind, PlannedOutput, WritePlan};
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    OperationOutcome, OperationResult, ResourceExportResult, SupersededArtifact,
};

/// What this build calls itself in an artifact's provenance, and in its key.
///
/// The version is part of the key on purpose: a decoder fix must invalidate
/// what the old one produced.
pub(crate) const TOOL: &str = "amiga-re";
pub(crate) const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn run(
    request: &NormalizedResourceExport,
    context: &ExecutionContext<'_>,
    mode: &NormalizedMode,
    mut diagnostics: Vec<Diagnostic>,
    digest: String,
    events: &mut BoundedSink<'_>,
) -> OperationOutcome {
    let outcome = |status, diagnostics, result| OperationOutcome {
        operation: OperationName::ProjectResourceExport,
        status,
        diagnostics,
        normalized_request_sha256: Some(digest.clone()),
        result,
    };
    let refuse = |code, message: String, mut diagnostics: Vec<Diagnostic>| {
        diagnostics.push(Diagnostic::error(code, message));
        diagnostics
    };

    let Some(root) = context
        .resolver()
        .root()
        .map(|root| root.join(request.project.path.as_str()))
    else {
        return outcome(
            Status::Error,
            refuse(
                DiagnosticCode::ProjectUnreadable,
                "this context serves no directory, so no project can be located".to_owned(),
                diagnostics,
            ),
            None,
        );
    };
    let loaded = match amiga_project::load(&root) {
        Ok(loaded) => loaded,
        Err(error) => {
            return outcome(
                Status::Error,
                refuse(
                    DiagnosticCode::ProjectUnreadable,
                    error.to_string(),
                    diagnostics,
                ),
                None,
            );
        }
    };
    let project = &loaded.project;

    let Some(resource) = project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .find(|candidate| candidate.id() == &request.resource)
    else {
        return outcome(
            Status::Error,
            refuse(
                DiagnosticCode::ProjectContradicted,
                format!("no resource {} in this project", request.resource),
                diagnostics,
            ),
            None,
        );
    };

    // The key first: it decides the destination, so a resource whose recipe
    // cannot be resolved is refused before anything is decoded.
    let recipe_key = match amiga_project::artifact_key(project, resource, TOOL, TOOL_VERSION) {
        Ok(key) => key,
        Err(error) => {
            return outcome(
                Status::Error,
                refuse(
                    DiagnosticCode::ProjectContradicted,
                    error.to_string(),
                    diagnostics,
                ),
                None,
            );
        }
    };

    let (bindings, binding_diagnostics) = crate::local::load_bindings(&root);
    diagnostics.extend(binding_diagnostics);

    let recovery = crate::recovery::ContainerRecovery::from_limits(context.limits());
    let target = match resolve_target(project, &bindings, resource, &recovery) {
        Ok(target) => target,
        Err((code, message)) => {
            return outcome(Status::Error, refuse(code, message, diagnostics), None);
        }
    };
    let bytes = match target.bytes() {
        Ok(bytes) => bytes,
        Err((code, message)) => {
            return outcome(Status::Error, refuse(code, message, diagnostics), None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "recover_object",
        completed: bytes.len() as u64,
        total: Some(bytes.len() as u64),
    });

    let profile = resource.export_profile();
    let encoded = match encode(
        project,
        &bindings,
        resource,
        &target,
        &bytes,
        &profile.media_type,
        &Located {
            root: context.resolver().root(),
            project: request.project.path.as_str(),
            recovery: &recovery,
        },
    ) {
        Ok(encoded) => encoded,
        Err((code, message)) => {
            return outcome(Status::Error, refuse(code, message, diagnostics), None);
        }
    };
    events.emit(OperationEvent::Progress {
        phase: "encode_artifact",
        completed: encoded.len() as u64,
        total: Some(encoded.len() as u64),
    });

    let path = amiga_project::artifact_path(resource, &recipe_key);
    let artifact_id = format!(
        "artifact:{}-{}",
        amiga_project::safe_component(resource.id()),
        recipe_key.get(..8).unwrap_or(recipe_key.as_str())
    );
    // Every record this resource already has. They are superseded rather than
    // overwritten: the new file is at a different path, so the old record still
    // describes bytes that still exist until the document write lands.
    let superseded: Vec<SupersededArtifact> = project
        .resources
        .iter()
        .flat_map(|document| &document.artifacts)
        .filter(|artifact| artifact.resource_id == *resource.id())
        .map(|artifact| SupersededArtifact {
            id: artifact.id.clone(),
            path: artifact.path.clone(),
        })
        .collect();

    let Some(label) = destination_label(request.project.path.as_str()) else {
        return outcome(
            Status::Error,
            refuse(
                DiagnosticCode::RequestSourceNameInvalid,
                format!(
                    "{:?} has no last component a write plan can name",
                    request.project.path.as_str()
                ),
                diagnostics,
            ),
            None,
        );
    };
    let sha256 = amiga_core::sha256(&encoded);
    let plan = WritePlan::new(
        &label,
        DestinationKind::Directory,
        request.policy,
        vec![PlannedOutput {
            path: path.clone(),
            size: encoded.len() as u64,
            sha256: sha256.clone(),
        }],
        Vec::new(),
    );

    let result = |plan: WritePlan, committed| {
        Some(OperationResult::ProjectResourceExport(
            ResourceExportResult {
                resource_id: resource.id().clone(),
                artifact_id: artifact_id.clone(),
                media_type: profile.media_type.clone(),
                recipe_key: recipe_key.clone(),
                path: path.clone(),
                size: encoded.len() as u64,
                sha256: sha256.clone(),
                superseded: superseded.clone(),
                plan,
                committed,
            },
        ))
    };

    let approved = match mode {
        NormalizedMode::Prepare => {
            return outcome(Status::Prepared, diagnostics, result(plan, false));
        }
        NormalizedMode::CommitReviewed {
            approved_plan_sha256,
        } => approved_plan_sha256,
        NormalizedMode::Read => {
            return outcome(
                Status::Error,
                refuse(
                    DiagnosticCode::RequestExecutionModeUnsupported,
                    "`project.resource.export` writes; ask for `prepare` or `commit_reviewed`"
                        .to_owned(),
                    diagnostics,
                ),
                None,
            );
        }
    };
    if !plan.is_approved_by(approved) {
        diagnostics.push(Diagnostic::error(
            DiagnosticCode::OutputPlanChanged,
            format!(
                "the approved plan {approved} is not the plan this request produces ({})",
                plan.plan_sha256
            ),
        ));
        return outcome(Status::Conflict, diagnostics, result(plan, false));
    }

    // The file, then the record that makes it live. A failure between the two
    // leaves an unregistered file at a path no record names — inert, and named
    // in the report so it can be removed.
    let target = root.join(&path);
    if let Err(error) =
        amiga_core::safepath::prepare_output_file(&target, request.policy.permits_replacement())
    {
        return outcome(
            Status::Error,
            refuse(
                DiagnosticCode::OutputDestinationRefused,
                format!("{path}: {error}"),
                diagnostics,
            ),
            None,
        );
    }
    if let Err(error) = std::fs::write(&target, &encoded) {
        return outcome(
            Status::Error,
            refuse(
                DiagnosticCode::OutputDestinationRefused,
                format!("{path}: {error}"),
                diagnostics,
            ),
            None,
        );
    }

    let mut edits: Vec<amiga_project::Edit> = superseded
        .iter()
        .map(|artifact| amiga_project::Edit::RemoveArtifact {
            id: artifact.id.clone(),
        })
        .collect();
    edits.push(amiga_project::Edit::RecordArtifact {
        artifact: Box::new(amiga_project::document::Artifact {
            id: artifact_id.clone(),
            resource_id: resource.id().clone(),
            path: path.clone(),
            media_type: profile.media_type.clone(),
            size: encoded.len() as u64,
            sha256: sha256.clone(),
            recipe_key: recipe_key.clone(),
            produced_by: amiga_project::document::ProducedBy {
                tool: TOOL.to_owned(),
                version: TOOL_VERSION.to_owned(),
            },
            warnings: Vec::new(),
        }),
    });
    let write = amiga_project::EditPlan::prepare(&root, &project.root.documents, edits)
        .and_then(|plan| plan.apply());
    if let Err(error) = write {
        return outcome(
            Status::Error,
            refuse(
                DiagnosticCode::OutputPlanChanged,
                format!(
                    "{path} was written and could not be recorded: {error}; the file is \
                     unreferenced and can be removed"
                ),
                diagnostics,
            ),
            None,
        );
    }

    outcome(Status::Success, diagnostics, result(plan, true))
}

/// Where a resource's bytes are, once its target has been resolved to one frame.
///
/// The object is kept whole beside the range. Three of the encoders need it: a
/// disassembly is of a hunk of a LoadSeg image, and the image is what
/// `analysis.code.disassemble` takes.
struct ResolvedTarget {
    /// The object the target names, recovered as `project.verify` recovers it.
    object: Vec<u8>,
    /// The object that was recovered, for a refusal that can name it.
    object_id: String,
    /// The image the target named, when it named one. What a load map is
    /// looked up against.
    image_id: Option<String>,
    /// The hunk the range lies in, when the target names one. `None` means the
    /// offset is into the object's own bytes.
    hunk: Option<u32>,
    /// The runtime base of `hunk` under the target's load map, when it named
    /// one. What a listing of these bytes is mapped at.
    origin: Option<u32>,
    offset: u64,
    length: u64,
}

impl ResolvedTarget {
    /// The recovered range, in whichever frame the target named it.
    fn bytes(&self) -> Result<Vec<u8>, (DiagnosticCode, String)> {
        let region: &[u8] = match self.hunk {
            None => &self.object,
            Some(hunk) => self.segment(hunk)?,
        };
        let start = usize::try_from(self.offset).unwrap_or(usize::MAX);
        let len = usize::try_from(self.length).unwrap_or(usize::MAX);
        start
            .checked_add(len)
            .and_then(|end| region.get(start..end))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                (
                    DiagnosticCode::ProjectContradicted,
                    format!(
                        "the target names bytes {}..{} of {}, which holds {}",
                        self.offset,
                        self.offset.saturating_add(self.length),
                        match self.hunk {
                            Some(hunk) => format!("hunk {hunk} of {}", self.object_id),
                            None => self.object_id.clone(),
                        },
                        region.len()
                    ),
                )
            })
    }

    /// One hunk's bytes, from the recovered image.
    fn segment(&self, hunk: u32) -> Result<&[u8], (DiagnosticCode, String)> {
        let executable = amiga_hunk::Executable::parse(&self.object).map_err(|error| {
            (
                DiagnosticCode::AnalysisHunkUnreadable,
                format!("{} is not a LoadSeg image: {error}", self.object_id),
            )
        })?;
        executable
            .segment(hunk)
            .map(|segment| segment.bytes)
            .ok_or_else(|| {
                (
                    DiagnosticCode::ProjectContradicted,
                    format!("{} has no hunk {hunk}", self.object_id),
                )
            })
    }

    /// The range as a hunk and a hunk-relative window, which is the frame
    /// `analysis.code.disassemble` reads.
    ///
    /// A `hunk` or `runtime` target already is one. An `object` target into a
    /// LoadSeg image is converted through the segment whose file bytes cover it
    /// — the same conversion the image's own layout defines, so a `code`
    /// resource written against a file offset still exports.
    fn in_hunk(&self) -> Result<(u32, u32, u32), (DiagnosticCode, String)> {
        let narrow = |value: u64, what: &str| {
            u32::try_from(value).map_err(|_| {
                (
                    DiagnosticCode::ProjectResourceUnexportable,
                    format!("a {what} of {value} is more than a hunk offset can name"),
                )
            })
        };
        if let Some(hunk) = self.hunk {
            let start = narrow(self.offset, "hunk offset")?;
            let length = narrow(self.length, "length")?;
            return Ok((hunk, start, start.saturating_add(length)));
        }
        let executable = amiga_hunk::Executable::parse(&self.object).map_err(|error| {
            (
                DiagnosticCode::AnalysisHunkUnreadable,
                format!("{} is not a LoadSeg image: {error}", self.object_id),
            )
        })?;
        let start = usize::try_from(self.offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(self.length).unwrap_or(usize::MAX));
        let segment = executable
            .segments
            .iter()
            .find(|segment| {
                start >= segment.file_offset
                    && end <= segment.file_offset.saturating_add(segment.bytes.len())
            })
            .ok_or_else(|| {
                (
                    DiagnosticCode::ProjectResourceUnexportable,
                    format!(
                        "bytes {start}..{end} of {} lie in no single hunk, so there is no \
                         listing to produce",
                        self.object_id
                    ),
                )
            })?;
        let relative = narrow((start - segment.file_offset) as u64, "hunk offset")?;
        let length = narrow(self.length, "length")?;
        Ok((segment.index, relative, relative.saturating_add(length)))
    }
}

/// The bytes a resource's target names, recovered the way a verify recovers
/// them.
fn resource_bytes(
    project: &amiga_project::document::Project,
    bindings: &amiga_project::Bindings,
    resource: &Resource,
    recovery: &crate::recovery::ContainerRecovery,
) -> Result<Vec<u8>, (DiagnosticCode, String)> {
    resolve_target(project, bindings, resource, recovery)?.bytes()
}

/// Resolve a resource's target into one object and one range within it.
///
/// Every target space that names bytes is resolved here. A `hunk` offset is
/// relative to a segment of the named image, and a `runtime` address is undone
/// through the load map the target itself names — never through some default,
/// because the same executable loaded high and loaded low are both true and the
/// document says which one it meant.
fn resolve_target(
    project: &amiga_project::document::Project,
    bindings: &amiga_project::Bindings,
    resource: &Resource,
    recovery: &crate::recovery::ContainerRecovery,
) -> Result<ResolvedTarget, (DiagnosticCode, String)> {
    use amiga_project::document::Target;

    let recover = |object_id: &str| {
        amiga_project::verify::recover_object_with_limits(
            project,
            bindings,
            recovery,
            object_id,
            recovery.verification_limits(),
        )
        .map_err(|reason| (DiagnosticCode::ProjectContradicted, reason))
    };

    match resource.target() {
        Target::Object {
            object_id,
            offset,
            length,
            ..
        } => Ok(ResolvedTarget {
            object: recover(object_id)?,
            object_id: object_id.clone(),
            image_id: None,
            hunk: None,
            origin: None,
            offset: *offset,
            length: *length,
        }),
        Target::Hunk {
            image_id,
            hunk,
            offset,
            length,
            ..
        } => {
            let object_id = image_object(project, image_id)?;
            Ok(ResolvedTarget {
                object: recover(&object_id)?,
                object_id,
                image_id: Some(image_id.clone()),
                hunk: Some(*hunk),
                origin: None,
                offset: *offset,
                length: *length,
            })
        }
        Target::Runtime {
            image_id,
            load_map_id,
            address,
            length,
            ..
        } => {
            let index = amiga_project::Index::build(project);
            let (hunk, offset) = index
                .to_hunk_offset(image_id, load_map_id, address)
                .ok_or_else(|| {
                    (
                        DiagnosticCode::ProjectContradicted,
                        format!(
                            "{address} is not in any segment of load map {load_map_id} of \
                             {image_id}"
                        ),
                    )
                })?;
            let object_id = image_object(project, image_id)?;
            Ok(ResolvedTarget {
                object: recover(&object_id)?,
                object_id,
                image_id: Some(image_id.clone()),
                hunk: Some(hunk),
                origin: hunk_base(project, image_id, load_map_id, hunk),
                offset,
                length: *length,
            })
        }
        // A base-register global is a location in the *loaded* program at a
        // register value nothing here knows, and an entity target names another
        // record rather than bytes. Neither is a byte range this could export
        // without inventing the part that is missing.
        other => Err((
            DiagnosticCode::ProjectResourceUnexportable,
            format!(
                "{} names a {} target, which names no byte range to export",
                resource.id(),
                other.space()
            ),
        )),
    }
}

/// The object one image is of.
fn image_object(
    project: &amiga_project::document::Project,
    image_id: &str,
) -> Result<String, (DiagnosticCode, String)> {
    project
        .programs
        .iter()
        .flat_map(|program| &program.images)
        .find(|image| image.id == image_id)
        .map(|image| image.object_id.clone())
        .ok_or_else(|| {
            (
                DiagnosticCode::ProjectContradicted,
                format!("no image {image_id} in this project"),
            )
        })
}

/// Where one hunk sits under one named load map, when the document says.
fn hunk_base(
    project: &amiga_project::document::Project,
    image_id: &str,
    load_map_id: &str,
    hunk: u32,
) -> Option<u32> {
    let base = project
        .programs
        .iter()
        .flat_map(|program| &program.images)
        .find(|image| image.id == image_id)?
        .load_maps
        .iter()
        .find(|map| map.id == load_map_id)?
        .segments
        .iter()
        .find(|segment| segment.hunk == hunk)?;
    let text = base.runtime_base.trim_start_matches("0x");
    u32::from_str_radix(text, 16).ok()
}

/// Turn recovered bytes into the file the export profile asks for.
///
/// The pair — the resource's kind and its media type — decides the encoder,
/// because a resource says how to read source bytes and the profile says what
/// comes out. A pair this build cannot produce is refused by name rather than
/// approximated.
fn encode(
    project: &amiga_project::document::Project,
    bindings: &amiga_project::Bindings,
    resource: &Resource,
    target: &ResolvedTarget,
    bytes: &[u8],
    media_type: &str,
    located: &Located<'_>,
) -> Result<Vec<u8>, (DiagnosticCode, String)> {
    match (resource, media_type) {
        // The three listings. Each is routed to the operation that owns the
        // decode rather than decoded again here: an export must be the answer
        // that operation gives from the same bytes, not a second decoder that
        // agrees with it today. What is this operation's own is the *rendering*
        // — the columns and the header — exactly as a frontend's listing is.
        (Resource::Code { load_map_id, .. }, "text/plain") => {
            code_listing(project, resource, target, load_map_id.as_deref(), located)
        }
        (
            Resource::Table {
                type_id,
                row_count,
                row_stride,
                ..
            },
            "text/plain",
        ) => table_listing(
            resource,
            bytes,
            type_id.as_deref(),
            *row_count,
            *row_stride,
            located,
        ),
        (
            Resource::Copper {
                initial_address, ..
            },
            "text/plain",
        ) => copper_listing(resource, bytes, initial_address.as_deref(), located),
        (
            Resource::Image {
                format,
                width,
                height,
                planes,
                plane_order,
                palette_resource_id,
                ..
            },
            "image/png",
        ) => {
            // Every layout by name, and an unknown name refused rather than
            // read as the default: the three disagree about which byte holds
            // which pixel, so guessing produces a plausible wrong image.
            let order = match plane_order.as_deref() {
                None | Some("contiguous") => amiga_hw::PlaneOrder::Contiguous,
                Some("interleaved") => amiga_hw::PlaneOrder::Interleaved,
                Some("byte_interleaved") => {
                    amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Byte)
                }
                Some("word_interleaved") => {
                    amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Word)
                }
                Some("longword_interleaved") => {
                    amiga_hw::PlaneOrder::ChunkInterleaved(amiga_hw::Chunk::Longword)
                }
                Some(other) => {
                    return Err((
                        DiagnosticCode::ProjectResourceUnexportable,
                        format!("{other:?} is not a plane order this build can read"),
                    ));
                }
            };
            let image = if format == "chunky" {
                // Already one byte per pixel: the indices are the bytes.
                let (width, height) = (*width as usize, *height as usize);
                let needed = width.saturating_mul(height);
                let pixels = bytes.get(..needed).ok_or_else(|| {
                    (
                        DiagnosticCode::GraphicsPlanarUndecodable,
                        format!(
                            "{width}x{height} needs {needed} byte(s), and {} are there",
                            bytes.len()
                        ),
                    )
                })?;
                amiga_hw::IndexedImage {
                    width,
                    height,
                    planes: *planes,
                    pixels: pixels.to_vec(),
                }
            } else {
                amiga_hw::deinterleave(bytes, *width as usize, *height as usize, *planes, order)
                    .map_err(|error| {
                        (DiagnosticCode::GraphicsPlanarUndecodable, error.to_string())
                    })?
            };
            let colors = 1_usize << u32::from(*planes);
            let rgb = match palette_resource_id {
                Some(id) => palette_rgb(project, bindings, id, colors, located.recovery)?,
                None => grayscale(colors),
            };
            amiga_hw::encode_indexed_png(&image, &rgb, None)
                .map_err(|error| (DiagnosticCode::GraphicsEncodeFailed, error.to_string()))
        }
        (Resource::Palette { format, count, .. }, "image/png") => {
            let colors = decode_palette(bytes, format, *count)?;
            let image = amiga_hw::palette::swatches(colors.len(), 16, 8).ok_or_else(|| {
                (
                    DiagnosticCode::GraphicsOutputTooLarge,
                    "the swatch geometry does not describe a drawable sheet".to_owned(),
                )
            })?;
            let rgb: Vec<u8> = colors
                .iter()
                .flat_map(|word| amiga_hw::rgb4_to_rgb8(*word))
                .collect();
            amiga_hw::encode_indexed_png(&image, &rgb, None)
                .map_err(|error| (DiagnosticCode::GraphicsEncodeFailed, error.to_string()))
        }
        (
            Resource::Audio {
                encoding,
                sample_rate,
                ..
            },
            "audio/wav",
        ) => match encoding.as_str() {
            "8svx" => {
                let sample = amiga_iff::parse_8svx(bytes)
                    .map_err(|error| (DiagnosticCode::AudioSampleUnreadable, error.to_string()))?;
                amiga_iff::encode_pcm(sample.pcm(), sample.sample_rate().get())
                    .map_err(|error| (DiagnosticCode::AudioEncodeFailed, error.to_string()))
            }
            "raw_pcm8" => {
                // Raw Paula bytes carry no rate, so the resource has to have
                // recorded one; guessing would produce a file that plays at the
                // wrong speed and says nothing about it.
                let rate = sample_rate.ok_or_else(|| {
                    (
                        DiagnosticCode::ProjectResourceUnexportable,
                        format!(
                            "{} is raw PCM, which carries no sample rate; record one on the \
                             resource",
                            resource.id()
                        ),
                    )
                })?;
                let rate = u16::try_from(rate).map_err(|_| {
                    (
                        DiagnosticCode::AudioEncodeFailed,
                        format!("a rate of {rate} does not fit a WAV header"),
                    )
                })?;
                // Paula samples are signed bytes; the recovered bytes are the
                // same bits read unsigned.
                let pcm: Vec<i8> = bytes.iter().map(|byte| *byte as i8).collect();
                amiga_iff::encode_pcm(&pcm, rate)
                    .map_err(|error| (DiagnosticCode::AudioEncodeFailed, error.to_string()))
            }
            other => Err((
                DiagnosticCode::ProjectResourceUnexportable,
                format!("this build cannot export a {other} sample as a WAV"),
            )),
        },
        (
            Resource::Text {
                encoding,
                termination,
                ..
            },
            "text/plain",
        ) => {
            // Latin-1 and ASCII both map byte-for-byte into the Basic Latin and
            // Latin-1 Supplement blocks, so a decode is a `char` cast; a
            // NUL-terminated string stops where it says it does.
            let end = if termination == "nul" {
                bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len())
            } else {
                bytes.len()
            };
            let text: String = bytes[..end]
                .iter()
                .map(|byte| {
                    if encoding == "ascii" && *byte > 0x7f {
                        char::REPLACEMENT_CHARACTER
                    } else {
                        char::from(*byte)
                    }
                })
                .collect();
            Ok(text.into_bytes())
        }
        // Bytes nothing has interpreted, written as they were recovered. Not a
        // fallback for every kind: only the kinds whose recipe says nothing more
        // than "these bytes" get one.
        (Resource::Data { .. } | Resource::Opaque { .. }, "application/octet-stream")
        | (Resource::Image { .. }, "application/octet-stream")
        | (Resource::Audio { .. }, "application/octet-stream") => Ok(bytes.to_vec()),
        (resource, media_type) => Err((
            DiagnosticCode::ProjectResourceUnexportable,
            format!(
                "this build cannot produce {media_type} from a {} resource",
                resource.kind()
            ),
        )),
    }
}

/// Where the project is, for the nested requests that need to name it.
///
/// Only `analysis.table.decode` does — it resolves a record through the
/// project's `types` document — but it is carried for all three so the routing
/// helper has one shape.
struct Located<'a> {
    root: Option<&'a std::path::Path>,
    project: &'a str,
    recovery: &'a crate::recovery::ContainerRecovery,
}

/// Run one read-only operation over bytes this export already recovered.
///
/// The bytes are served in memory: they came out of the project's own recovery
/// and re-reading them from disk would be a second answer to a question already
/// answered. The project *directory* is served beside them for the operations
/// that resolve a record type through it.
fn route(
    document: crate::request::OperationRequestDocument,
    bytes: &[u8],
    located: &Located<'_>,
) -> Result<crate::response::OperationResult, (DiagnosticCode, String)> {
    let name = crate::source::SourceName::parse("resource")
        .map_err(|error| (DiagnosticCode::RequestSourceNameInvalid, error.to_string()))?;
    let mut resolver = crate::source::InMemorySourceResolver::new(
        crate::source::ResolvedSource::new(name, bytes.into()),
    );
    if let Some(root) = located.root {
        resolver = resolver.rooted_at(root);
    }
    // An export renders everything the resource declares, so the caps are the
    // resource's own counts rather than the interactive defaults: a listing
    // silently stopping at 65,536 rows would be a file that looks complete.
    let limits = crate::limits::OperationLimits::default()
        .with_maximum_input_bytes((bytes.len() as u64).max(1))
        .with_maximum_entries(MAX_LISTING_ENTRIES);
    let context = ExecutionContext::new(&resolver).with_limits(limits);
    // Only the operation that resolves a record through the project's `types`
    // document takes a locator; the others refuse one, and rightly — a request
    // naming a project it does not read would be claiming a dependency it has
    // not got.
    let needs_project = matches!(
        document,
        crate::request::OperationRequestDocument::AnalysisTableDecode(_)
    );
    let mut envelope = crate::protocol::RequestEnvelope::read(document);
    if needs_project {
        envelope.project = Some(crate::protocol::ProjectLocator::Path {
            path: located.project.to_owned(),
        });
    }
    let outcome = crate::router::Router::execute(&envelope, &context);
    let errors: Vec<&str> = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.is_error())
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    if !errors.is_empty() {
        return Err((
            DiagnosticCode::ProjectResourceUnexportable,
            errors.join("; "),
        ));
    }
    outcome.result.ok_or((
        DiagnosticCode::ProjectResourceUnexportable,
        "the decode this export renders produced no result".to_owned(),
    ))
}

/// The most rows or instructions one exported listing may hold.
///
/// A ceiling rather than a page: a listing that stopped early would be a file
/// that looks complete, which is the failure this whole layer exists to avoid.
/// Beyond it the export is refused by the operation's own truncation report.
const MAX_LISTING_ENTRIES: usize = 4_000_000;

/// A `code` resource as an MC68000 listing.
///
/// Routed to `analysis.code.disassemble` over the resource's range in its hunk,
/// mapped at the origin its load map gives — which is why a `code` resource
/// carries a `load_map_id`: the addresses in the listing are only true under
/// one mapping, and the document says which.
fn code_listing(
    project: &amiga_project::document::Project,
    resource: &Resource,
    target: &ResolvedTarget,
    load_map_id: Option<&str>,
    located: &Located<'_>,
) -> Result<Vec<u8>, (DiagnosticCode, String)> {
    use std::fmt::Write as _;

    let (hunk, start, end) = target.in_hunk()?;
    let mut arguments = crate::request::CodeDisassembleArguments::new("resource")
        .in_hunk(hunk)
        .over_range(start, Some(end))
        .with_maximum_instructions(MAX_LISTING_ENTRIES);
    // The resource's own load map wins: it is the mapping the resource says its
    // addresses are in. A `runtime` target resolved one on the way here, which
    // is the fallback, and without either the listing is at hunk offsets — true
    // in the one frame it has, rather than guessed at in another.
    let origin = load_map_id
        .zip(target.image_id.as_deref())
        .and_then(|(map, image)| hunk_base(project, image, map, hunk))
        .or(target.origin);
    if let Some(origin) = origin {
        arguments = arguments.mapped_at(origin);
    }
    let result = route(
        crate::request::OperationRequestDocument::AnalysisCodeDisassemble(arguments),
        &target.object,
        located,
    )?;
    let crate::response::OperationResult::AnalysisCodeDisassemble(listing) = result else {
        return Err((
            DiagnosticCode::ProjectResourceUnexportable,
            "the disassembly returned the wrong result".to_owned(),
        ));
    };

    let mut text = String::new();
    let _ = writeln!(text, "; {} — {}", resource.id(), resource_name(resource));
    let _ = writeln!(
        text,
        "; hunk {hunk}, offset {start:#x}..{end:#x} of {}",
        target.object_id
    );
    if let Some(origin) = listing.origin {
        let _ = writeln!(text, "; mapped at {origin:#x}");
    }
    for instruction in &listing.instructions {
        match instruction.address {
            Some(address) => {
                let _ = writeln!(
                    text,
                    "{address:08x}  {:<28} ; {}",
                    instruction.text, instruction.bytes
                );
            }
            None => {
                let _ = writeln!(
                    text,
                    "{:08x}  {:<28} ; {}",
                    instruction.offset, instruction.text, instruction.bytes
                );
            }
        }
    }
    Ok(text.into_bytes())
}

/// A `table` resource as its decoded rows.
///
/// Routed to `analysis.table.decode` through the resource's `type_id`, which is
/// what that field has always meant. A table with no type names no record, and
/// is refused rather than written out as undifferentiated bytes: the resource
/// claims to be a table, and a file of bytes would not be one.
fn table_listing(
    resource: &Resource,
    bytes: &[u8],
    type_id: Option<&str>,
    row_count: u32,
    row_stride: u32,
    located: &Located<'_>,
) -> Result<Vec<u8>, (DiagnosticCode, String)> {
    use std::fmt::Write as _;

    let Some(type_id) = type_id else {
        return Err((
            DiagnosticCode::ProjectResourceUnexportable,
            format!(
                "{} declares no `type_id`, so there is no record to decode its rows through",
                resource.id()
            ),
        ));
    };
    let rows = usize::try_from(row_count).unwrap_or(usize::MAX).max(1);
    let result = route(
        crate::request::OperationRequestDocument::AnalysisTableDecode(
            crate::request::TableDecodeArguments::through_type("resource", type_id, rows)
                .with_maximum_rows(MAX_LISTING_ENTRIES),
        ),
        bytes,
        located,
    )?;
    let crate::response::OperationResult::AnalysisTableDecode(table) = result else {
        return Err((
            DiagnosticCode::ProjectResourceUnexportable,
            "the table decode returned the wrong result".to_owned(),
        ));
    };
    // The stride the resource declares and the width the type describes are two
    // records of one fact. When they disagree one of them is wrong about these
    // bytes, and a file produced from either would be confidently wrong.
    if u64::from(row_stride) != table.record_size {
        return Err((
            DiagnosticCode::ProjectContradicted,
            format!(
                "{} declares a stride of {row_stride} and {type_id} describes {} byte(s)",
                resource.id(),
                table.record_size
            ),
        ));
    }

    let mut text = String::new();
    let _ = writeln!(text, "# {} — {}", resource.id(), resource_name(resource));
    let _ = writeln!(
        text,
        "# {} row(s) of {} byte(s), through {type_id}",
        table.rows.len(),
        table.record_size
    );
    for row in &table.rows {
        let fields: Vec<String> = row.fields.iter().map(render_field).collect();
        let _ = writeln!(text, "{:08x}  {}", row.offset, fields.join("  "));
    }
    Ok(text.into_bytes())
}

/// One decoded table field, in the spelling the export writes.
fn render_field(field: &crate::response::TableField) -> String {
    use crate::response::TableField;
    match field {
        TableField::Unsigned(value) => format!("{value}"),
        TableField::Signed(value) => format!("{value}"),
        TableField::Pointer(value) => format!("{value:#010x}"),
        TableField::Text(text) => format!("{text:?}"),
        TableField::Bytes(bytes) => bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    }
}

/// A `copper` resource as a decoded Copper list.
///
/// Routed to `hardware.copper.decode`, which is the one decoder of a Copper
/// stream in this build. `initial_address` is the address the list is loaded at
/// when the document recorded one; it shifts the addresses in the listing and
/// nothing else, so a list without one still exports at its offsets.
fn copper_listing(
    resource: &Resource,
    bytes: &[u8],
    initial_address: Option<&str>,
    located: &Located<'_>,
) -> Result<Vec<u8>, (DiagnosticCode, String)> {
    use std::fmt::Write as _;

    let result = route(
        crate::request::OperationRequestDocument::HardwareCopperDecode(
            crate::request::CopperDecodeArguments::new("resource"),
        ),
        bytes,
        located,
    )?;
    let crate::response::OperationResult::HardwareCopperDecode(copper) = result else {
        return Err((
            DiagnosticCode::ProjectResourceUnexportable,
            "the Copper decode returned the wrong result".to_owned(),
        ));
    };

    let base = initial_address
        .map(|address| {
            u32::from_str_radix(address.trim_start_matches("0x"), 16).map_err(|error| {
                (
                    DiagnosticCode::ProjectContradicted,
                    format!("{address:?} is not a hexadecimal address: {error}"),
                )
            })
        })
        .transpose()?;

    let mut text = String::new();
    let _ = writeln!(text, "; {} — {}", resource.id(), resource_name(resource));
    if let Some(base) = base {
        let _ = writeln!(text, "; loaded at {base:#x}");
    }
    let _ = writeln!(text, "; {} instruction(s)", copper.instructions.len());
    for instruction in &copper.instructions {
        let at = base.map_or(instruction.offset, |base| {
            base.saturating_add(instruction.offset)
        });
        let _ = writeln!(text, "{at:08x}  {}", render_copper(&instruction.op));
    }
    Ok(text.into_bytes())
}

/// One Copper instruction, in the spelling the export writes.
fn render_copper(op: &crate::response::CopperOp) -> String {
    use crate::response::CopperOp;
    match op {
        CopperOp::Move {
            register,
            value,
            name,
            rgb8,
        } => {
            let register = name
                .as_deref()
                .map_or_else(|| format!("${register:03x}"), str::to_owned);
            let colour = rgb8.map_or_else(String::new, |[red, green, blue]| {
                format!("  ; #{red:02x}{green:02x}{blue:02x}")
            });
            format!("MOVE #${value:04x},{register}{colour}")
        }
        CopperOp::Wait {
            vpos,
            hpos,
            vmask,
            hmask,
            blitter_finish_disable,
            terminator,
        } => {
            let blitter = if *blitter_finish_disable { ",BFD" } else { "" };
            let end = if *terminator { "  ; end of list" } else { "" };
            format!(
                "WAIT  v={vpos:#04x},h={hpos:#04x} mask v={vmask:#04x},h={hmask:#04x}{blitter}{end}"
            )
        }
        CopperOp::Skip {
            vpos,
            hpos,
            vmask,
            hmask,
            blitter_finish_disable,
        } => {
            let blitter = if *blitter_finish_disable { ",BFD" } else { "" };
            format!("SKIP  v={vpos:#04x},h={hpos:#04x} mask v={vmask:#04x},h={hmask:#04x}{blitter}")
        }
    }
}

/// The name a resource carries, for the header a listing prints.
fn resource_name(resource: &Resource) -> &str {
    match resource {
        Resource::Image { name, .. }
        | Resource::Palette { name, .. }
        | Resource::Audio { name, .. }
        | Resource::Table { name, .. }
        | Resource::Text { name, .. }
        | Resource::Code { name, .. }
        | Resource::Copper { name, .. }
        | Resource::Data { name, .. }
        | Resource::Opaque { name, .. } => name,
    }
}

/// The RGB triples a palette resource decodes to, padded for the planes that
/// address them.
fn palette_rgb(
    project: &amiga_project::document::Project,
    bindings: &amiga_project::Bindings,
    id: &str,
    colors: usize,
    recovery: &crate::recovery::ContainerRecovery,
) -> Result<Vec<u8>, (DiagnosticCode, String)> {
    let palette = project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .find(|candidate| candidate.id() == id)
        .ok_or_else(|| {
            (
                DiagnosticCode::ProjectContradicted,
                format!("no resource {id} in this project"),
            )
        })?;
    let Resource::Palette { format, count, .. } = palette else {
        return Err((
            DiagnosticCode::ProjectContradicted,
            format!("{id} is a {} where a palette is needed", palette.kind()),
        ));
    };
    let bytes = resource_bytes(project, bindings, palette, recovery)?;
    let words = decode_palette(&bytes, format, *count)?;
    let mut rgb: Vec<u8> = words
        .iter()
        .flat_map(|word| amiga_hw::rgb4_to_rgb8(*word))
        .collect();
    // Fewer colors than the planes address is not a refusal: an image may
    // legitimately use the low entries of a wider register set. The rest stay
    // black rather than reading past the palette.
    rgb.resize(colors.saturating_mul(3), 0);
    Ok(rgb)
}

/// A palette's stored words, as RGB4.
fn decode_palette(
    bytes: &[u8],
    format: &str,
    count: u16,
) -> Result<Vec<u16>, (DiagnosticCode, String)> {
    let count = usize::from(count);
    match format {
        "rgb4" => {
            let needed = count.saturating_mul(2);
            let words = bytes.get(..needed).ok_or_else(|| {
                (
                    DiagnosticCode::GraphicsPaletteWordInvalid,
                    format!(
                        "{count} RGB4 entries need {needed} byte(s), and {} are there",
                        bytes.len()
                    ),
                )
            })?;
            Ok(words
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect())
        }
        // Stored as three bytes per entry and narrowed back to the RGB4 the
        // encoder takes. The narrowing is the format's, not this operation's:
        // an RGB8 palette in an Amiga project is an OCS palette written wide.
        "rgb8" => {
            let needed = count.saturating_mul(3);
            let triples = bytes.get(..needed).ok_or_else(|| {
                (
                    DiagnosticCode::GraphicsPaletteWordInvalid,
                    format!(
                        "{count} RGB8 entries need {needed} byte(s), and {} are there",
                        bytes.len()
                    ),
                )
            })?;
            Ok(triples
                .as_chunks::<3>()
                .0
                .iter()
                .map(|rgb| {
                    let nibble = |value: u8| u16::from(value >> 4);
                    (nibble(rgb[0]) << 8) | (nibble(rgb[1]) << 4) | nibble(rgb[2])
                })
                .collect())
        }
        other => Err((
            DiagnosticCode::ProjectResourceUnexportable,
            format!("this build cannot read a {other} palette"),
        )),
    }
}

/// The documented ramp an image with no palette is drawn with.
fn grayscale(colors: usize) -> Vec<u8> {
    (0..colors)
        .flat_map(|index| {
            let level = if colors > 1 {
                u8::try_from(index * 255 / (colors - 1)).unwrap_or(u8::MAX)
            } else {
                0
            };
            [level, level, level]
        })
        .collect()
}

/// The project path as a destination name, for the plan's own record.
fn destination_label(path: &str) -> Option<crate::output::DestinationName> {
    let last = path.rsplit('/').find(|part| !part.is_empty())?;
    crate::output::DestinationName::parse(last).ok()
}
