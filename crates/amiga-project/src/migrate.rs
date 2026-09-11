//! Importing a legacy `amiga-re.toml` into the versioned project format.
//!
//! The import is deliberately **lossy in one direction only**: everything the
//! TOML can express gets a reviewed destination, and anything the importer
//! cannot place with confidence becomes a diagnostic rather than a guess.
//!
//! The ambiguity that matters is `[base]`. The old config carries one origin
//! and one entry, which silently assumed a single module with a single mapping.
//! A project has several images and several *named* load maps. Which image a
//! bare `[base]` belongs to is not recoverable from the file — so the importer
//! attaches it to the image the user names and refuses otherwise. Guessing
//! would produce a load map that looks authoritative and is wrong for every
//! module but one.
//!
//! Nothing here writes. The importer produces documents; committing them is the
//! caller's, through the same reviewed-write path everything else uses.

use std::path::Path;

use serde_json::{Value, json};

use crate::FORMAT_VERSION;

/// Why part of a legacy config could not be imported without a decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ambiguity {
    /// The config field, as the TOML spells it.
    pub field: String,
    pub message: String,
}

/// What an import produced.
#[derive(Clone, Debug, Default)]
pub struct Imported {
    /// Document path -> its content, ready to be formatted and written.
    pub documents: Vec<(String, Value)>,
    /// Decisions the importer refused to make.
    pub ambiguities: Vec<Ambiguity>,
}

/// The image a bare `[base]` maps, and the media whose bytes it is.
///
/// Both halves are decisions the config cannot make. `[base]` carries one origin
/// with no image, and a program image needs an object — which a legacy config
/// has no vocabulary for at all. Naming the media entry is what turns the second
/// into a recorded whole-file object instead of a reference to something that
/// does not exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedImage<'a> {
    /// The image ID the imported load map attaches to.
    pub id: &'a str,
    /// The `[[media]]` name whose whole file is that image's bytes.
    pub media: &'a str,
}

/// Import one parsed `amiga-re.toml`.
///
/// `image` is the image a bare `[base]` belongs to and the media it is; `None`
/// means the caller has not decided, and the base becomes an ambiguity rather
/// than a load map.
///
/// `media_root` is the directory a `[[media]]` path is relative to — the
/// config's own directory. Each pinned file is stat'ed there, because the format
/// requires a size the config does not carry and a fabricated one would satisfy
/// the schema and fail every later `project verify`.
#[must_use]
pub fn import(
    config: &amiga_core::Config,
    project_name: &str,
    image: Option<ImportedImage<'_>>,
    media_root: &Path,
) -> Imported {
    let mut imported = Imported::default();

    let mut sources = Vec::new();
    let mut objects = Vec::new();
    // Media name -> the source it became, its size, and its digest, so an image
    // can be recorded as the whole of a file this import actually measured.
    let mut imported_media: std::collections::BTreeMap<&str, (String, u64, &str)> =
        std::collections::BTreeMap::new();
    for (index, media) in config.media.iter().enumerate() {
        let field = format!("[[media]] #{index} ({})", media.path.display());
        // A media entry names a path and may pin a digest. Without one the
        // source has no identity, and the format requires one — so the import
        // records what it knows and says what it needs.
        let Some(sha256) = media.sha256.as_ref() else {
            imported.ambiguities.push(Ambiguity {
                field,
                message: "this entry pins no SHA-256, and a source's identity is its digest; \
                          run `config check` to pin it before importing"
                    .to_owned(),
            });
            continue;
        };
        // The legacy config pins a digest and no size, and the format requires
        // both. The size is read from the file rather than invented: a zero
        // satisfies the schema, passes `project check`, and then fails
        // `project verify` on every source — which is the first thing anyone
        // does after migrating.
        let path = media_root.join(&media.path);
        let size = match std::fs::metadata(&path) {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                imported.ambiguities.push(Ambiguity {
                    field,
                    message: format!(
                        "a source needs its size and this import cannot read {}: {error}; \
                         bind the media where this machine keeps it and re-run",
                        path.display()
                    ),
                });
                continue;
            }
        };
        let id = format!("source:{}", crate::recipe::safe_component(&media.name));
        imported_media.insert(media.name.as_str(), (id.clone(), size, sha256.as_str()));
        sources.push(json!({
            "id": id,
            "kind": "file",
            "display_name": media.name,
            "sha256": sha256,
            "size": size,
            "locations": [{ "kind": "project_relative", "path": normalize(&media.path) }],
        }));
    }

    let symbols: Vec<Value> = config
        .symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| {
            json!({
                "id": format!("symbol:{}", crate::recipe::safe_component(&symbol.name)),
                "kind": "symbol",
                "origin": "imported",
                "name": symbol.name,
                // A config symbol is an absolute address with no image and no
                // load map, which the format cannot express as a target. It is
                // carried as a note so the knowledge survives the import, and
                // rebasing it onto a real image is an explicit later step.
                "notes": format!(
                    "imported from amiga-re.toml [[symbols]] #{index} at absolute {:#010x}; \
                     rebase onto an image before it resolves",
                    symbol.addr
                ),
                "target": { "space": "entity", "entity_id": "project:imported" },
            })
        })
        .collect();

    if let Some(base) = config.base {
        // An image needs an object, and an object that nothing declares is an
        // unresolved reference the loader refuses — so the program document is
        // written only once both halves are known, and the object it names is
        // recorded here with the size and digest this import measured.
        let resolved = image.and_then(|image| {
            imported_media
                .get(image.media)
                .map(|entry| (image, entry.clone()))
        });
        match (image, resolved) {
            (_, Some((image, (parent_id, size, sha256)))) => {
                let object_id = format!(
                    "object:{}/image",
                    crate::recipe::safe_component(image.media)
                );
                objects.push(json!({
                    "id": object_id,
                    "kind": "whole_source",
                    "parent_id": parent_id,
                    "selector": { "container": "range", "offset": 0, "length": size },
                    "size": size,
                    "sha256": sha256,
                    "notes": "The whole of the imported media, named so the imported load map \
                              has an image to attach to.",
                }));
                imported.documents.push((
                    "analysis/programs/imported.json".to_owned(),
                    json!({
                        "document_kind": "program",
                        "format_version": FORMAT_VERSION,
                        "id": "program:imported",
                        "name": project_name,
                        "images": [{
                            "id": image.id,
                            "object_id": object_id,
                            "format": "hunk",
                            "architecture": "mc68000",
                            "load_maps": [{
                                "id": "loadmap:imported/default",
                                "name": "Imported from [base]",
                                "segments": [{ "hunk": 0, "runtime_base": hex(base.origin) }],
                                "entry_points": base.entry.map_or_else(Vec::new, |entry| {
                                    vec![json!({ "address": hex(entry), "role": "program_entry" })]
                                }),
                            }],
                        }],
                    }),
                ));
            }
            (Some(image), None) => imported.ambiguities.push(Ambiguity {
                field: "[base]".to_owned(),
                message: format!(
                    "no imported [[media]] is named {:?}, so image {:?} has no bytes to be; \
                     name a media entry this import could pin and measure",
                    image.media, image.id
                ),
            }),
            (None, _) => imported.ambiguities.push(Ambiguity {
                field: "[base]".to_owned(),
                message: format!(
                    "origin {:#010x} belongs to one image, and the config does not say which; \
                     re-run naming the image it maps and the media it is",
                    base.origin
                ),
            }),
        }
    }

    if let Some(bitmap) = &config.bitmap {
        // Geometry is not a resource. A resource names *where* the pixels are —
        // an object, an offset, a length, and the digest they were established
        // against — and `[bitmap]` carries none of that: it is the default
        // geometry for `bitmap render`, not a record of any particular image.
        // Dropping it silently lost the knowledge; inventing a target would put
        // a made-up offset in a field other tools resolve.
        imported.ambiguities.push(Ambiguity {
            field: "[bitmap]".to_owned(),
            message: format!(
                "{}x{} at {} plane(s){} is default geometry with no bytes behind it; \
                 record it as an `image` resource once the object and offset its pixels \
                 live at are known",
                bitmap.width,
                bitmap.height,
                bitmap.planes,
                if bitmap.palette.is_empty() {
                    String::new()
                } else {
                    format!(" and a {}-entry palette", bitmap.palette.len())
                },
            ),
        });
    }

    if !config.fd.is_empty() {
        imported.ambiguities.push(Ambiguity {
            field: "[[fd]]".to_owned(),
            message: "fd tables describe an ABI, not project knowledge; they stay in \
                      amiga-re.toml and are read alongside the project"
                .to_owned(),
        });
    }

    imported.documents.push((
        "analysis/sources.json".to_owned(),
        json!({
            "document_kind": "sources",
            "format_version": FORMAT_VERSION,
            "sources": sources,
            "objects": objects,
        }),
    ));
    if !symbols.is_empty() {
        imported.documents.push((
            "analysis/annotations/imported.json".to_owned(),
            json!({
                "document_kind": "annotations",
                "format_version": FORMAT_VERSION,
                "annotations": symbols,
            }),
        ));
    }

    let mut index = json!({ "sources": "analysis/sources.json" });
    if imported
        .documents
        .iter()
        .any(|(path, _)| path.contains("programs/"))
    {
        index["programs"] = json!(["analysis/programs/imported.json"]);
    }
    if !config.symbols.is_empty() {
        index["annotations"] = json!(["analysis/annotations/imported.json"]);
    }
    imported.documents.push((
        "amiga-re.project.json".to_owned(),
        json!({
            "document_kind": "project",
            "format_version": FORMAT_VERSION,
            "project": {
                "id": format!("project:{}", crate::recipe::safe_component(project_name)),
                "name": project_name,
                "notes": "Imported from amiga-re.toml. Every ambiguity the importer \
                          refused to guess is listed in the import report.",
            },
            "documents": index,
        }),
    ));
    imported
}

/// A config path as the project spells it: `/`-separated and relative.
fn normalize(path: &std::path::Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn hex(value: u32) -> String {
    format!("0x{value:08x}")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn config() -> amiga_core::Config {
        amiga_core::Config::default()
    }

    /// A directory holding one media file, and the config entry that pins it.
    ///
    /// The import stats what the config names, so a test about sizes has to put
    /// real bytes somewhere.
    fn media_root(tag: &str, bytes: &[u8]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("amiga-migrate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("original")).unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(root.join("original/disk1.adf"), bytes)
            .unwrap_or_else(|error| panic!("{error}"));
        root
    }

    fn pinned_media() -> amiga_core::config::Media {
        amiga_core::config::Media {
            name: "disk1".to_owned(),
            path: PathBuf::from("original/disk1.adf"),
            sha256: Some("a".repeat(64)),
        }
    }

    fn sources_of(imported: &Imported) -> &Value {
        let (_, sources) = imported
            .documents
            .iter()
            .find(|(path, _)| path.ends_with("sources.json"))
            .expect("a sources document");
        sources
    }

    #[test]
    fn a_bare_base_is_an_ambiguity_rather_than_a_guessed_load_map() {
        let mut config = config();
        config.base = Some(amiga_core::config::Base {
            origin: 0x0000_e63e,
            entry: None,
        });
        let imported = import(&config, "Demo", None, Path::new("."));
        assert_eq!(imported.ambiguities.len(), 1);
        assert_eq!(imported.ambiguities[0].field, "[base]");
        assert!(
            !imported
                .documents
                .iter()
                .any(|(path, _)| path.contains("programs/")),
            "a load map was invented for an image nobody named"
        );
    }

    #[test]
    fn a_base_with_a_named_image_becomes_a_load_map_over_an_object_that_exists() {
        let root = media_root("load-map", b"0123456789");
        let mut config = config();
        config.media.push(pinned_media());
        config.base = Some(amiga_core::config::Base {
            origin: 0x0000_e63e,
            entry: Some(0x0000_e700),
        });
        let imported = import(
            &config,
            "Demo",
            Some(ImportedImage {
                id: "image:main",
                media: "disk1",
            }),
            &root,
        );
        assert!(
            imported.ambiguities.is_empty(),
            "{:?}",
            imported.ambiguities
        );
        let (_, program) = imported
            .documents
            .iter()
            .find(|(path, _)| path.contains("programs/"))
            .expect("a program document");
        let map = &program["images"][0]["load_maps"][0];
        assert_eq!(map["segments"][0]["runtime_base"], "0x0000e63e");
        assert_eq!(map["entry_points"][0]["address"], "0x0000e700");

        // The image's object is declared, not merely referenced: an image
        // naming an object nothing declares is an unresolved reference, and the
        // loader refuses the whole project over it.
        let object_id = program["images"][0]["object_id"]
            .as_str()
            .expect("an object id");
        let sources = sources_of(&imported);
        let object = sources["objects"]
            .as_array()
            .expect("objects")
            .iter()
            .find(|object| object["id"] == object_id)
            .expect("the image's object is declared");
        assert_eq!(object["parent_id"], "source:disk1");
        assert_eq!(object["size"], 10);
        assert_eq!(object["selector"]["length"], 10);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_image_naming_media_that_was_not_imported_is_refused_rather_than_dangling() {
        let root = media_root("no-such-media", b"0123456789");
        let mut config = config();
        config.media.push(pinned_media());
        config.base = Some(amiga_core::config::Base {
            origin: 0x0000_e63e,
            entry: None,
        });
        let imported = import(
            &config,
            "Demo",
            Some(ImportedImage {
                id: "image:main",
                media: "disk9",
            }),
            &root,
        );
        assert_eq!(imported.ambiguities.len(), 1);
        assert!(imported.ambiguities[0].message.contains("disk9"));
        assert!(
            !imported
                .documents
                .iter()
                .any(|(path, _)| path.contains("programs/")),
            "an image was written over bytes nothing pinned"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_pinned_media_entry_records_the_size_the_file_actually_has() {
        // A zero satisfies the schema, passes `project check`, and fails
        // `project verify` on every source — the first thing a migrating user
        // does is the thing that could not succeed.
        let root = media_root("real-size", b"0123456789ABCDEF");
        let mut config = config();
        config.media.push(pinned_media());
        let imported = import(&config, "Demo", None, &root);
        assert!(
            imported.ambiguities.is_empty(),
            "{:?}",
            imported.ambiguities
        );
        assert_eq!(sources_of(&imported)["sources"][0]["size"], 16);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn media_this_machine_cannot_read_is_an_ambiguity_rather_than_a_size_of_zero() {
        let root = media_root("absent", b"");
        std::fs::remove_file(root.join("original/disk1.adf"))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut config = config();
        config.media.push(pinned_media());
        let imported = import(&config, "Demo", None, &root);
        assert_eq!(imported.ambiguities.len(), 1);
        assert!(
            imported.ambiguities[0].message.contains("disk1.adf"),
            "{:?}",
            imported.ambiguities[0]
        );
        assert!(
            sources_of(&imported)["sources"]
                .as_array()
                .unwrap()
                .is_empty(),
            "a source was imported with a size nobody measured"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bitmap_table_is_reported_rather_than_silently_dropped() {
        // It cannot become a resource: a resource says where the pixels are, and
        // `[bitmap]` is default geometry with no object, offset, or digest.
        let mut config = config();
        config.bitmap = Some(amiga_core::config::Bitmap {
            width: 320,
            height: 256,
            planes: 4,
            palette: vec![0x000, 0xfff],
        });
        let imported = import(&config, "Demo", None, Path::new("."));
        let bitmap = imported
            .ambiguities
            .iter()
            .find(|ambiguity| ambiguity.field == "[bitmap]")
            .expect("the geometry is reported");
        assert!(bitmap.message.contains("320x256"), "{bitmap:?}");
        assert!(bitmap.message.contains("2-entry palette"), "{bitmap:?}");
    }

    #[test]
    fn an_unpinned_media_entry_is_reported_rather_than_imported_without_identity() {
        let mut config = config();
        config.media.push(amiga_core::config::Media {
            name: "disk1".to_owned(),
            path: PathBuf::from("original/disk1.adf"),
            sha256: None,
        });
        let imported = import(&config, "Demo", None, Path::new("."));
        assert_eq!(imported.ambiguities.len(), 1);
        assert!(imported.ambiguities[0].message.contains("SHA-256"));
        assert!(
            sources_of(&imported)["sources"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_import_always_produces_a_root_that_lists_what_it_wrote() {
        let imported = import(&config(), "Demo", None, Path::new("."));
        let (_, root) = imported
            .documents
            .iter()
            .find(|(path, _)| path == "amiga-re.project.json")
            .expect("a root document");
        assert_eq!(root["document_kind"], "project");
        assert_eq!(root["documents"]["sources"], "analysis/sources.json");
        assert_eq!(root["project"]["id"], "project:demo");
    }
}
