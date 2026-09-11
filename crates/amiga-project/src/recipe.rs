//! Normalized decode recipes, and the artifact key derived from one.
//!
//! A resource says what bytes are and how to read them. This turns that into a
//! digest — the **artifact key** — that answers one question: *would decoding
//! this again produce the same output?*
//!
//! The key covers four things and deliberately nothing else:
//!
//! 1. the object's content digest, so changed source bytes invalidate the
//!    artifact;
//! 2. the normalized recipe **with every reference resolved**, so changing a
//!    width, a palette's own format, or a sample rate invalidates it;
//! 3. what the export produces, so a PNG and a raw dump of one image are two
//!    recipes rather than one;
//! 4. the producing tool's version, so a decoder fix invalidates it.
//!
//! Resolving the references is the part that is easy to get wrong and was.
//! Folding in `palette_resource_id` as a bare **ID** meant editing the palette
//! resource's target, format or count left the image's key unchanged, so a PNG
//! decoded with the old palette stayed "current" while the project said
//! something else. A key is only worth having if editing anything the decode
//! reads invalidates it, which means the key is computed over the *project*,
//! not over one resource. A reference that does not resolve, resolves to the
//! wrong kind, or closes a cycle is refused rather than silently keyed around.
//!
//! It does **not** cover the resource's display name, its notes, or where the
//! output happens to be written. Renaming a resource must not invalidate an
//! artifact that is byte-identical, or a cache would be worthless the moment
//! anyone improved a label.
//!
//! Invalidation is a *comparison*, never a deletion. `is_current` answers
//! whether a recorded artifact still matches; deciding what to do about one
//! that does not is the caller's, and the reviewed-write rails in
//! `amiga-operations` are where that decision gets made.

use serde_json::{Value, json};
use thiserror::Error;

use crate::document::{
    Artifact, ExportProfile, LoadMap, Project, Resource, Target, TypeDefinition,
};

/// Why a recipe could not be normalized into a key.
///
/// Every variant is a decode that cannot run. Producing a key anyway would
/// produce one that compares equal to nothing meaningful, which is worse than
/// saying so.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RecipeError {
    #[error("{referrer} references {reference}, which this project does not define")]
    UnknownReference { referrer: String, reference: String },
    #[error("{referrer} references {reference}, whose kind is {found} where {expected} is needed")]
    WrongKind {
        referrer: String,
        reference: String,
        expected: &'static str,
        found: String,
    },
    #[error("{id} is reached from itself through references, so its recipe has no fixed point")]
    Cycle { id: String },
}

/// The digest that decides whether a recorded artifact is still current.
///
/// # Errors
/// Returns [`RecipeError`] when a reference this recipe depends on is missing,
/// of the wrong kind, or part of a cycle.
pub fn artifact_key(
    project: &Project,
    resource: &Resource,
    tool: &str,
    version: &str,
) -> Result<String, RecipeError> {
    let canonical = json!({
        // The bytes, by content rather than by location.
        "object": target_key(resource.target()),
        // What would be done to them, and what would come out.
        "recipe": normalized_recipe(project, resource)?,
        // Who would do it. A decoder fix must invalidate what the old one made.
        "tool": tool,
        "version": version,
    });
    Ok(amiga_core_sha256(canonical.to_string().as_bytes()))
}

/// Whether `artifact` was produced by the current recipe for `resource`.
///
/// A `false` here means "this output no longer follows from the project" — not
/// "delete it". Nothing in this crate removes an artifact.
///
/// Compares `recipe_key`, never `sha256`: the latter is the digest of the
/// output file, which is what a verify checks against the bytes on disk. One
/// field carrying both meanings is exactly what made this unreliable.
///
/// A recipe that cannot be normalized is not current. It cannot be re-derived
/// either, so the honest answer is the one that sends a caller to re-export and
/// meet the real refusal.
#[must_use]
pub fn is_current(project: &Project, resource: &Resource, artifact: &Artifact) -> bool {
    artifact_key(
        project,
        resource,
        &artifact.produced_by.tool,
        &artifact.produced_by.version,
    )
    .is_ok_and(|key| key == artifact.recipe_key)
}

/// The part of a target that decides the bytes: the object digest and the
/// range, never which image or load map spelled it.
fn target_key(target: &Target) -> Value {
    match target {
        Target::Object {
            offset,
            length,
            object_sha256,
            ..
        }
        | Target::Hunk {
            offset,
            length,
            object_sha256,
            ..
        } => json!({ "sha256": object_sha256, "offset": offset, "length": length }),
        Target::Runtime {
            address,
            length,
            object_sha256,
            ..
        } => json!({ "sha256": object_sha256, "address": address, "length": length }),
        // A base-register slot has no offset or length: the displacement and the
        // width *are* the range, and the register they are taken from decides
        // which bytes as much as either.
        Target::BaseRegister {
            base_register,
            displacement,
            width,
            object_sha256,
            ..
        } => json!({
            "sha256": object_sha256,
            "base_register": base_register,
            "displacement": displacement,
            "width": width,
        }),
        Target::Entity { entity_id } => json!({ "entity": entity_id }),
    }
}

/// One resource's interpretation, with everything that does not change the
/// output removed and everything it depends on resolved.
///
/// Public so a manifest can record the same normalized form the key was
/// computed from: a provenance record that showed a *different* recipe than the
/// one that produced it would be worse than showing none.
///
/// # Errors
/// Returns [`RecipeError`] when a reference is missing, of the wrong kind, or
/// part of a cycle.
pub fn normalized_recipe(project: &Project, resource: &Resource) -> Result<Value, RecipeError> {
    resolve_recipe(project, resource, &mut Vec::new())
}

/// The recursive half, carrying the chain of IDs currently being resolved so a
/// cycle is a refusal rather than a stack overflow.
fn resolve_recipe(
    project: &Project,
    resource: &Resource,
    visiting: &mut Vec<String>,
) -> Result<Value, RecipeError> {
    if visiting.iter().any(|seen| seen == resource.id()) {
        return Err(RecipeError::Cycle {
            id: resource.id().clone(),
        });
    }
    visiting.push(resource.id().clone());
    let mut recipe = match resource {
        Resource::Image {
            id,
            format,
            width,
            height,
            planes,
            plane_order,
            palette_resource_id,
            ..
        } => json!({
            "kind": "image", "format": format, "width": width, "height": height,
            "planes": planes,
            // Defaults are materialized, so a request that spelled one out and
            // one that omitted it share a key.
            "plane_order": plane_order.as_deref().unwrap_or("contiguous"),
            // The palette's own recipe, not its name: editing the palette
            // changes what this image decodes to, and a key that folded in an
            // ID alone would not notice.
            "palette": optional(palette_resource_id, |reference| {
                let palette = palette(project, id, reference)?;
                let recipe = resolve_recipe(project, palette, visiting)?;
                Ok(json!({ "object": target_key(palette.target()), "recipe": recipe }))
            })?,
        }),
        Resource::Palette { format, count, .. } => {
            json!({ "kind": "palette", "format": format, "count": count })
        }
        Resource::Audio {
            encoding,
            channels,
            sample_rate,
            ..
        } => json!({
            "kind": "audio", "encoding": encoding,
            "channels": channels.unwrap_or(1), "sample_rate": sample_rate,
        }),
        Resource::Table {
            id,
            row_count,
            row_stride,
            type_id,
            ..
        } => json!({
            "kind": "table", "row_count": row_count, "row_stride": row_stride,
            "type": optional(type_id, |reference| type_key(project, id, reference, visiting))?,
        }),
        Resource::Text {
            encoding,
            termination,
            ..
        } => json!({ "kind": "text", "encoding": encoding, "termination": termination }),
        Resource::Code {
            id,
            architecture,
            load_map_id,
            ..
        } => json!({
            "kind": "code", "architecture": architecture,
            "load_map": optional(load_map_id, |reference| load_map_key(project, id, reference))?,
        }),
        Resource::Copper {
            initial_address, ..
        } => json!({ "kind": "copper", "initial_address": initial_address }),
        Resource::Data { id, type_id, .. } => json!({
            "kind": "data",
            "type": optional(type_id, |reference| type_key(project, id, reference, visiting))?,
        }),
        Resource::Opaque { .. } => json!({ "kind": "opaque" }),
    };
    // What comes out is part of what would be produced again, so it is part of
    // the key. Without it a PNG and a raw dump of one image share a key.
    if let Some(map) = recipe.as_object_mut() {
        map.insert("export".to_owned(), export_key(&resource.export_profile()));
    }
    visiting.pop();
    Ok(recipe)
}

/// Resolve an optional reference, keeping `null` for one that is absent.
fn optional<F>(reference: &Option<String>, resolve: F) -> Result<Value, RecipeError>
where
    F: FnOnce(&str) -> Result<Value, RecipeError>,
{
    reference
        .as_deref()
        .map_or_else(|| Ok(Value::Null), resolve)
}

fn export_key(profile: &ExportProfile) -> Value {
    json!({ "media_type": profile.media_type })
}

/// The palette an image names, checked by kind.
///
/// An ID proves only that *some* resource is there; an image whose palette
/// points at an audio resource is a decode that cannot run, and it should be
/// refused where the key is computed rather than discovered at export.
fn palette<'a>(
    project: &'a Project,
    referrer: &str,
    reference: &str,
) -> Result<&'a Resource, RecipeError> {
    let found = project
        .resources
        .iter()
        .flat_map(|document| &document.resources)
        .find(|candidate| candidate.id() == reference)
        .ok_or_else(|| RecipeError::UnknownReference {
            referrer: referrer.to_owned(),
            reference: reference.to_owned(),
        })?;
    if found.kind() != "palette" {
        return Err(RecipeError::WrongKind {
            referrer: referrer.to_owned(),
            reference: reference.to_owned(),
            expected: "palette",
            found: found.kind().to_owned(),
        });
    }
    Ok(found)
}

/// A type definition's own contribution, resolved through every type it names.
///
/// A struct field's type, an array's element and a pointer's pointee all decide
/// what a decode produces, and types may legitimately reference each other, so
/// this shares the cycle guard with the resource walk.
fn type_key(
    project: &Project,
    referrer: &str,
    reference: &str,
    visiting: &mut Vec<String>,
) -> Result<Value, RecipeError> {
    let found = project
        .types
        .iter()
        .flat_map(|document| &document.types)
        .find(|candidate| candidate.id() == reference)
        .ok_or_else(|| RecipeError::UnknownReference {
            referrer: referrer.to_owned(),
            reference: reference.to_owned(),
        })?;
    if visiting.iter().any(|seen| seen == reference) {
        return Err(RecipeError::Cycle {
            id: reference.to_owned(),
        });
    }
    visiting.push(reference.to_owned());
    let key = match found {
        TypeDefinition::Integer {
            size,
            signed,
            byte_order,
            ..
        } => json!({
            "kind": "integer", "size": size, "signed": signed, "byte_order": byte_order,
        }),
        TypeDefinition::Pointer {
            pointee_id,
            address_space,
            ..
        } => json!({
            "kind": "pointer", "address_space": address_space,
            "pointee": type_key(project, reference, pointee_id, visiting)?,
        }),
        TypeDefinition::Array {
            element_id, count, ..
        } => json!({
            "kind": "array", "count": count,
            "element": type_key(project, reference, element_id, visiting)?,
        }),
        TypeDefinition::Struct { size, fields, .. } => {
            let mut resolved = Vec::with_capacity(fields.len());
            for field in fields {
                resolved.push(json!({
                    "name": field.name,
                    "offset": field.offset,
                    "type": type_key(project, reference, &field.type_id, visiting)?,
                }));
            }
            json!({ "kind": "struct", "size": size, "fields": resolved })
        }
        TypeDefinition::Enum {
            base_id, members, ..
        } => json!({
            "kind": "enum",
            "base": type_key(project, reference, base_id, visiting)?,
            "members": members
                .iter()
                .map(|member| json!({ "name": member.name, "value": member.value }))
                .collect::<Vec<_>>(),
        }),
        TypeDefinition::Alias { aliased_id, .. } => json!({
            "kind": "alias",
            "aliased": type_key(project, reference, aliased_id, visiting)?,
        }),
        // A signature decodes nothing, so no resource should reach here — and
        // `validate` refuses the one that would. The key is still stated in
        // full rather than shortened to its kind, because that is what a
        // fingerprint is for: if this arm ever does become reachable, a changed
        // parameter must change the key rather than hash the same as the
        // signature it replaced.
        TypeDefinition::Function {
            parameters,
            results,
            clobbers,
            preserves,
            ..
        } => {
            let mut sides = Vec::with_capacity(2);
            for side in [parameters, results] {
                let mut resolved = Vec::with_capacity(side.len());
                for parameter in side {
                    resolved.push(json!({
                        "name": parameter.name,
                        "location": parameter.location,
                        "type": type_key(project, reference, &parameter.type_id, visiting)?,
                    }));
                }
                sides.push(resolved);
            }
            let results = sides.pop().unwrap_or_default();
            let parameters = sides.pop().unwrap_or_default();
            json!({
                "kind": "function",
                "parameters": parameters,
                "results": results,
                "clobbers": clobbers,
                "preserves": preserves,
            })
        }
    };
    visiting.pop();
    Ok(key)
}

/// The load map a code resource names, by its segments rather than its ID.
///
/// Rebasing a hunk changes every address a listing prints, which is exactly the
/// kind of edit an ID-only key stayed current across.
fn load_map_key(project: &Project, referrer: &str, reference: &str) -> Result<Value, RecipeError> {
    let found: &LoadMap = project
        .programs
        .iter()
        .flat_map(|document| &document.images)
        .flat_map(|image| &image.load_maps)
        .find(|candidate| candidate.id == reference)
        .ok_or_else(|| RecipeError::UnknownReference {
            referrer: referrer.to_owned(),
            reference: reference.to_owned(),
        })?;
    Ok(json!({
        "segments": found
            .segments
            .iter()
            .map(|segment| json!({ "hunk": segment.hunk, "runtime_base": segment.runtime_base }))
            .collect::<Vec<_>>(),
    }))
}

/// The predictable output path for one resource's artifact, under its key.
///
/// The extension comes from the resource's own export profile rather than from
/// an argument: a caller that could choose it would decide the file name
/// outside the record that claims to reproduce the file.
///
/// **The key is in the path, and that is what makes re-export safe.** A write
/// path that produced the file before the document is fine the first time — a
/// document failure leaves an unregistered file, and re-exporting fixes it. On
/// a *re*-export the same ordering would overwrite the previous output first,
/// leaving the old `Artifact` record pointing at new bytes with the old digest
/// and the old key: a record that is confidently wrong, which is worse than one
/// that is missing. A new export therefore never occupies the old one's path,
/// and recording the new artifact is what makes it live.
///
/// IDs go through [`path_component`] rather than being copied into a path: an ID
/// may contain `/`, which is readable in an identity and a directory traversal
/// in a path.
#[must_use]
pub fn artifact_path(resource: &Resource, recipe_key: &str) -> String {
    let (directory, id) = match resource {
        Resource::Image { id, .. } | Resource::Palette { id, .. } => ("images", id),
        Resource::Audio { id, .. } => ("audio", id),
        Resource::Code { id, .. } => ("code", id),
        other => ("data", other.id()),
    };
    let extension = extension_for(&resource.export_profile().media_type);
    // The key shortened the way every other digest in a path is: the whole
    // digest is a correct suffix, so a slice that does not fit is a longer name
    // rather than a panic.
    let short = recipe_key.get(..FINGERPRINT_HEX).unwrap_or(recipe_key);
    format!(
        "decoded/{directory}/{}-{short}.{extension}",
        path_component(id)
    )
}

/// The file extension a media type is written with.
///
/// An unknown type gets `bin` rather than a guess derived from its subtype:
/// the schema's media types are a closed set, and inventing an extension for a
/// type this build cannot encode would name a file nothing produced.
#[must_use]
pub fn extension_for(media_type: &str) -> &'static str {
    match media_type {
        "image/png" => "png",
        "audio/wav" => "wav",
        "text/plain" => "txt",
        _ => "bin",
    }
}

/// Turn an ID or a display name into one safe component.
///
/// The one central conversion section 10 requires. ASCII letters are lowercased,
/// because the ID grammar is lowercase and mangling `Demo` into `-emo` would
/// produce an ID the validator then refuses. Everything outside `[a-z0-9._-]`
/// becomes `-`, so `resource:disk-1/title` cannot become two directories.
///
/// The result always starts with a letter or digit: the grammar requires it,
/// and a leading `-` or `.` would be both invalid and, as a path, a traversal
/// or a hidden file.
///
/// **This conversion is lossy and therefore not injective**: `resource:a/b` and
/// `resource:a-b` both produce `a-b`. That is acceptable when deriving an *ID*
/// from a display name, because the result is then validated for uniqueness
/// across the project and a clash is refused. It is not acceptable when deriving
/// a *path*, where a clash silently overwrites — use [`path_component`] there.
#[must_use]
pub fn safe_component(id: &str) -> String {
    let name = id.split_once(':').map_or(id, |(_, rest)| rest);
    let converted: String = name
        .chars()
        .map(|character| match character {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => character,
            'A'..='Z' => character.to_ascii_lowercase(),
            _ => '-',
        })
        .collect();
    let trimmed = converted.trim_start_matches(['-', '.', '_']);
    if trimmed.is_empty() {
        return "unnamed".to_owned();
    }
    trimmed.to_owned()
}

/// Bytes of the ID digest kept in a path component, as hex characters.
///
/// Thirty-two bits. A project holds tens of resources rather than millions, and
/// the suffix exists to make an accidental clash improbable, not to be a
/// cryptographic identity — the caller's duplicate check over its whole planned
/// path set is what actually guarantees no two outputs collide.
const FINGERPRINT_HEX: usize = 8;

/// Turn an ID into one safe path component that no other ID can claim.
///
/// [`safe_component`] alone is lossy: `resource:a/b` and `resource:a-b` both
/// convert to `a-b`, so using it directly for an output path lets two distinct
/// resources write the same file, and the second export overwrites the first
/// with no diagnostic. Appending a digest of the **whole** ID — prefix included,
/// so `image:title` and `palette:title` differ too — keeps the readable stem and
/// makes the result injective in practice.
#[must_use]
pub fn path_component(id: &str) -> String {
    let fingerprint = amiga_core_sha256(id.as_bytes());
    // Shortened without assuming a length, as every other digest-shortening in
    // this workspace is: the whole digest is a correct suffix, so a slice that
    // does not fit is a longer name rather than a panic.
    let short = fingerprint.get(..FINGERPRINT_HEX).unwrap_or(&fingerprint);
    format!("{}-{}", safe_component(id), short)
}

fn amiga_core_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{ResourcesDocument, Target, TypesDocument};

    /// A project holding exactly the resources and types a test names.
    ///
    /// Assembled rather than loaded: the key's contract is about what the
    /// documents say, and reading them off a disk would test the loader.
    fn project(resources: Vec<Resource>, types: Vec<TypeDefinition>) -> Project {
        Project {
            root: serde_json::from_value(json!({
                "document_kind": "project",
                "format_version": 1,
                "project": { "id": "project:demo", "name": "Demo" },
                "documents": { "sources": "analysis/sources.json" },
            }))
            .expect("a root document"),
            sources: serde_json::from_value(json!({
                "document_kind": "sources",
                "format_version": 1,
                "sources": [],
            }))
            .expect("a sources document"),
            inventories: std::collections::BTreeMap::new(),
            programs: Vec::new(),
            annotations: Vec::new(),
            resources: vec![ResourcesDocument {
                schema: None,
                document_kind: "resources".to_owned(),
                format_version: 1,
                resources,
                artifacts: Vec::new(),
                extensions: None,
            }],
            types: vec![TypesDocument {
                schema: None,
                document_kind: "types".to_owned(),
                format_version: 1,
                types,
                extensions: None,
            }],
        }
    }

    fn image(width: u32, name: &str) -> Resource {
        Resource::Image {
            id: "resource:title".to_owned(),
            name: name.to_owned(),
            target: Target::Object {
                object_id: "object:x".to_owned(),
                offset: 0,
                length: 16,
                object_sha256: "a".repeat(64),
            },
            format: "planar".to_owned(),
            width,
            height: 8,
            planes: 2,
            plane_order: None,
            palette_resource_id: None,
            export: None,
            notes: None,
        }
    }

    fn palette_resource(count: u16, offset: u64) -> Resource {
        Resource::Palette {
            id: "resource:title-palette".to_owned(),
            name: "Title palette".to_owned(),
            target: Target::Object {
                object_id: "object:x".to_owned(),
                offset,
                length: 32,
                object_sha256: "a".repeat(64),
            },
            format: "rgb4".to_owned(),
            count,
            export: None,
            notes: None,
        }
    }

    fn key(project: &Project, resource: &Resource) -> String {
        artifact_key(project, resource, "amiga-re", "0.1.0").expect("a resolvable recipe")
    }

    #[test]
    fn changing_the_recipe_changes_the_key() {
        let narrow = project(vec![image(8, "Title")], Vec::new());
        let wide = project(vec![image(16, "Title")], Vec::new());
        assert_ne!(
            key(&narrow, &image(8, "Title")),
            key(&wide, &image(16, "Title")),
        );
    }

    #[test]
    fn renaming_a_resource_does_not_change_the_key() {
        // A cache that a rename invalidated would be worthless the moment
        // anyone improved a label.
        let project = project(vec![image(8, "Title")], Vec::new());
        assert_eq!(
            key(&project, &image(8, "Title")),
            key(&project, &image(8, "Title screen logo")),
        );
    }

    #[test]
    fn a_new_tool_version_changes_the_key() {
        // A decoder fix must invalidate what the old one produced.
        let project = project(vec![image(8, "Title")], Vec::new());
        let resource = image(8, "Title");
        assert_ne!(
            artifact_key(&project, &resource, "amiga-re", "0.1.0"),
            artifact_key(&project, &resource, "amiga-re", "0.2.0"),
        );
    }

    #[test]
    fn changed_source_bytes_change_the_key() {
        let mut moved = image(8, "Title");
        if let Resource::Image { target, .. } = &mut moved {
            *target = Target::Object {
                object_id: "object:x".to_owned(),
                offset: 0,
                length: 16,
                object_sha256: "b".repeat(64),
            };
        }
        let project = project(vec![image(8, "Title")], Vec::new());
        assert_ne!(key(&project, &image(8, "Title")), key(&project, &moved));
    }

    #[test]
    fn spelling_a_default_out_gives_the_same_key_as_omitting_it() {
        let mut explicit = image(8, "Title");
        if let Resource::Image { plane_order, .. } = &mut explicit {
            *plane_order = Some("contiguous".to_owned());
        }
        let project = project(vec![image(8, "Title")], Vec::new());
        assert_eq!(key(&project, &image(8, "Title")), key(&project, &explicit));
    }

    /// An image that decodes through a palette resource.
    fn image_with_palette() -> Resource {
        let mut resource = image(8, "Title");
        if let Resource::Image {
            palette_resource_id,
            ..
        } = &mut resource
        {
            *palette_resource_id = Some("resource:title-palette".to_owned());
        }
        resource
    }

    #[test]
    fn editing_the_palette_a_resource_reads_invalidates_it() {
        // The defect this milestone exists for. The key folded in the palette's
        // *ID*, so changing the palette's own count or target left the image's
        // key unchanged — a PNG decoded with the old palette stayed "current"
        // while the project said something else.
        let image = image_with_palette();
        let before = project(vec![image.clone(), palette_resource(16, 64)], Vec::new());
        let recounted = project(vec![image.clone(), palette_resource(32, 64)], Vec::new());
        let moved = project(vec![image.clone(), palette_resource(16, 128)], Vec::new());
        assert_ne!(key(&before, &image), key(&recounted, &image));
        assert_ne!(key(&before, &image), key(&moved, &image));
    }

    #[test]
    fn renaming_the_palette_a_resource_reads_invalidates_nothing() {
        let image = image_with_palette();
        let before = project(vec![image.clone(), palette_resource(16, 64)], Vec::new());
        let mut renamed = palette_resource(16, 64);
        if let Resource::Palette { name, .. } = &mut renamed {
            *name = "The title screen's palette".to_owned();
        }
        let after = project(vec![image.clone(), renamed], Vec::new());
        assert_eq!(key(&before, &image), key(&after, &image));
    }

    #[test]
    fn a_reference_to_the_wrong_kind_is_refused_where_it_is_read() {
        // An ID proves only that *some* resource is there. An image whose
        // palette points at audio is a decode that cannot run.
        let image = image_with_palette();
        let audio = Resource::Audio {
            id: "resource:title-palette".to_owned(),
            name: "Not a palette".to_owned(),
            target: Target::Object {
                object_id: "object:x".to_owned(),
                offset: 0,
                length: 8,
                object_sha256: "a".repeat(64),
            },
            encoding: "8svx".to_owned(),
            channels: None,
            sample_rate: None,
            export: None,
            notes: None,
        };
        let project = project(vec![image.clone(), audio], Vec::new());
        assert!(matches!(
            artifact_key(&project, &image, "amiga-re", "0.1.0"),
            Err(RecipeError::WrongKind {
                expected: "palette",
                ..
            })
        ));
    }

    #[test]
    fn a_dangling_reference_is_refused_rather_than_keyed_around() {
        let image = image_with_palette();
        let project = project(vec![image.clone()], Vec::new());
        assert!(matches!(
            artifact_key(&project, &image, "amiga-re", "0.1.0"),
            Err(RecipeError::UnknownReference { .. })
        ));
    }

    #[test]
    fn a_type_cycle_is_refused_rather_than_recursed() {
        // Types may legitimately reference each other, so a struct that reaches
        // itself is a real document and must produce a refusal rather than a
        // stack overflow.
        let table = Resource::Table {
            id: "resource:records".to_owned(),
            name: "Records".to_owned(),
            target: Target::Object {
                object_id: "object:x".to_owned(),
                offset: 0,
                length: 64,
                object_sha256: "a".repeat(64),
            },
            row_count: 4,
            row_stride: 16,
            type_id: Some("type:node".to_owned()),
            export: None,
            notes: None,
        };
        let node: TypeDefinition = serde_json::from_value(json!({
            "kind": "struct",
            "id": "type:node",
            "name": "Node",
            "size": 4,
            "fields": [{ "name": "next", "offset": 0, "type_id": "type:node-pointer" }],
        }))
        .expect("a struct type");
        let pointer: TypeDefinition = serde_json::from_value(json!({
            "kind": "pointer",
            "id": "type:node-pointer",
            "name": "Node *",
            "pointee_id": "type:node",
            "address_space": "runtime",
        }))
        .expect("a pointer type");
        let project = project(vec![table.clone()], vec![node, pointer]);
        assert!(matches!(
            artifact_key(&project, &table, "amiga-re", "0.1.0"),
            Err(RecipeError::Cycle { .. })
        ));
    }

    #[test]
    fn the_export_profile_is_part_of_the_key_and_of_the_path() {
        // PNG and a raw dump of one image are two recipes: the resource says
        // how to read *source* bytes and said nothing about what comes out.
        let png = image(8, "Title");
        let mut raw = image(8, "Title");
        if let Resource::Image { export, .. } = &mut raw {
            *export = Some(ExportProfile {
                media_type: "application/octet-stream".to_owned(),
            });
        }
        let project = project(vec![png.clone()], Vec::new());
        assert_ne!(key(&project, &png), key(&project, &raw));
        assert!(artifact_path(&png, &key(&project, &png)).ends_with(".png"));
        assert!(artifact_path(&raw, &key(&project, &raw)).ends_with(".bin"));

        // Storing the default explicitly is the same recipe as omitting it.
        let mut explicit = image(8, "Title");
        if let Resource::Image { export, .. } = &mut explicit {
            *export = Some(ExportProfile {
                media_type: "image/png".to_owned(),
            });
        }
        assert_eq!(key(&project, &png), key(&project, &explicit));
    }

    #[test]
    fn an_id_cannot_become_a_path_traversal() {
        assert_eq!(safe_component("resource:disk-1/title"), "disk-1-title");
        assert_eq!(safe_component("resource:.."), "unnamed");
        assert_eq!(safe_component("resource:a/../b"), "a-..-b");
        // A display name becomes a valid ID name, not a mangled one: the ID
        // grammar is lowercase and must start with a letter or digit.
        assert_eq!(safe_component("Demo"), "demo");
        assert_eq!(safe_component("Sample Project"), "sample-project");
        assert_eq!(safe_component("  leading"), "leading");
        // And the rendered path stays under `decoded/`, with the readable stem
        // still leading it.
        let path = artifact_path(&image(8, "Title"), &"c".repeat(64));
        assert!(
            path.starts_with("decoded/images/title-") && path.ends_with(".png"),
            "unexpected artifact path {path}"
        );
        assert!(!path.contains(".."));
    }

    #[test]
    fn ids_that_collide_under_the_lossy_conversion_still_get_distinct_paths() {
        // The two that matter: distinct IDs whose *converted* stems are equal.
        // A test using two different stems would pass without the fingerprint
        // and prove nothing.
        assert_eq!(
            safe_component("resource:a/b"),
            safe_component("resource:a-b")
        );
        assert_ne!(
            path_component("resource:a/b"),
            path_component("resource:a-b")
        );

        // The prefix is part of the identity, so it is part of the digest.
        assert_eq!(
            safe_component("image:title"),
            safe_component("palette:title")
        );
        assert_ne!(
            path_component("image:title"),
            path_component("palette:title")
        );

        // The readable stem survives, so a path is still something a person can
        // find, and the suffix cannot reintroduce a traversal or a separator.
        let component = path_component("resource:a/b");
        assert!(
            component.starts_with("a-b-"),
            "unexpected component {component}"
        );
        assert!(!component.contains('/') && !component.contains(".."));

        // Same ID, same path: an artifact must land where its record says.
        assert_eq!(
            path_component("resource:a/b"),
            path_component("resource:a/b")
        );
    }
}
