//! The Milestone 0 contract: the fixture is valid, and it is *complete enough*
//! that an independent reader can locate every annotated byte and reproduce
//! every object from the metadata and the synthetic sources.
//!
//! Half of this is JSON Schema. The other half is what JSON Schema cannot say:
//! IDs are unique, references resolve to the right kind of thing, the object
//! graph is acyclic, and every annotated range actually lies inside the object
//! it names. Those are the rules Milestone 1's validator will implement, and
//! writing them against the fixture first is how Milestone 0 proves they are
//! the right rules.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use amiga_project::schemas;
use jsonschema::{Registry, Validator};
use serde_json::{Value, json};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/contract")
}

fn read(relative: &str) -> Value {
    let path = fixture_root().join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is valid JSON: {error}", path.display()))
}

fn parse(schema: &str) -> Value {
    serde_json::from_str(schema).expect("a bundled schema is valid JSON")
}

fn schema_id(schema: &Value) -> String {
    schema["$id"]
        .as_str()
        .unwrap_or_else(|| panic!("every bundled schema declares an $id: {schema}"))
        .to_owned()
}

fn registry() -> Registry<'static> {
    let documents: Vec<(String, Value)> = schemas::ALL
        .iter()
        .map(|(_, schema)| {
            let value = parse(schema);
            (schema_id(&value), value)
        })
        .collect();
    Registry::new()
        .extend(documents)
        .expect("every bundled schema has a usable $id")
        .prepare()
        .expect("the bundled schemas form a resolvable offline set")
}

fn validator_for(schema: &str, registry: &Registry<'_>) -> Validator {
    let value = parse(schema);
    jsonschema::options()
        .with_registry(registry)
        .build(&json!({ "$ref": schema_id(&value) }))
        .expect("the bundled schema compiles as Draft 2020-12")
}

/// Every document the root lists, plus the root and the inventory it references.
fn all_documents() -> Vec<(String, Value)> {
    let root = read("amiga-re.project.json");
    let mut documents = vec![("amiga-re.project.json".to_owned(), root.clone())];
    let listed = &root["documents"];
    let mut paths = vec![
        listed["sources"]
            .as_str()
            .expect("a sources path")
            .to_owned(),
    ];
    for key in ["programs", "annotations", "resources", "types"] {
        for path in listed[key].as_array().into_iter().flatten() {
            paths.push(path.as_str().expect("a document path").to_owned());
        }
    }
    // The inventory is referenced by the sources document, not by the root:
    // the root lists document *kinds*, and an inventory belongs to its source.
    let sources = read(&paths[0]);
    for source in sources["sources"].as_array().into_iter().flatten() {
        if let Some(inventory) = source["inventory"].as_str() {
            paths.push(inventory.to_owned());
        }
    }
    for path in paths {
        documents.push((path.clone(), read(&path)));
    }
    documents
}

#[test]
fn the_bundled_schemas_form_a_resolvable_offline_set() {
    // If this fails, nothing else in this file means anything: a `$ref` that
    // cannot resolve would make every validation vacuous.
    let _ = registry();
    // Eight documents the project format defines, plus `local`, which is not
    // one of them: nothing indexes it and no digest covers it, but this build
    // reads it, so it is described on the same terms as everything else.
    assert_eq!(schemas::ALL.len(), 9);
}

#[test]
fn every_fixture_document_satisfies_the_schema_for_its_kind() {
    let registry = registry();
    for (path, document) in all_documents() {
        let kind = document["document_kind"]
            .as_str()
            .unwrap_or_else(|| panic!("{path} declares no document_kind"));
        let schema = schemas::for_document_kind(kind)
            .unwrap_or_else(|| panic!("{path} has document_kind {kind:?}, which has no schema"));
        let validator = validator_for(schema, &registry);
        if let Err(error) = validator.validate(&document) {
            panic!("{path} does not satisfy the {kind} schema: {error}");
        }
        assert_eq!(
            document["format_version"], 1,
            "{path} mixes format versions"
        );
    }
}

#[test]
fn the_schemas_refuse_what_the_format_forbids() {
    // The load-bearing half. "Every fixture validates" passes against a schema
    // that accepts anything; these are the shapes that must be refused.
    let registry = registry();
    let sources = validator_for(schemas::SOURCES, &registry);
    let annotations = validator_for(schemas::ANNOTATIONS, &registry);
    let types = validator_for(schemas::TYPES, &registry);

    let base = |extra: Value| {
        let mut document = json!({
            "document_kind": "sources", "format_version": 1, "sources": []
        });
        for (key, value) in extra.as_object().expect("an object") {
            document[key] = value.clone();
        }
        document
    };

    // An unknown field anywhere outside `extensions`.
    assert!(
        sources
            .validate(&base(json!({ "invented": true })))
            .is_err()
    );

    // A file source with no content pin: the identity *is* the digest.
    assert!(
        sources
            .validate(&base(json!({ "sources": [{
                "id": "source:x", "kind": "file", "display_name": "X"
            }] })))
            .is_err(),
        "a file source without size and sha256 was accepted"
    );
    // A directory source with a file's pin instead of an inventory.
    assert!(
        sources
            .validate(&base(json!({ "sources": [{
                "id": "source:x", "kind": "directory", "display_name": "X",
                "size": 1, "sha256": "0".repeat(64)
            }] })))
            .is_err(),
        "a directory source without an inventory was accepted"
    );

    // An ID with no kind prefix, and one with a path in it.
    for bad in ["nokind", "Source:Upper", "source:", "../escape"] {
        assert!(
            sources
                .validate(&base(json!({ "sources": [{
                    "id": bad, "kind": "file", "display_name": "X",
                    "size": 1, "sha256": "0".repeat(64)
                }] })))
                .is_err(),
            "{bad:?} was accepted as an ID"
        );
    }

    // A location that escapes the project root.
    for bad in ["/absolute", "../escape", "a/../../escape"] {
        assert!(
            sources
                .validate(&base(json!({ "sources": [{
                    "id": "source:x", "kind": "file", "display_name": "X",
                    "size": 1, "sha256": "0".repeat(64),
                    "locations": [{ "kind": "project_relative", "path": bad }]
                }] })))
                .is_err(),
            "{bad:?} was accepted as a project-relative path"
        );
    }

    // An annotation target with no object digest: the whole staleness
    // mechanism depends on every byte target carrying one.
    let annotation = |target: Value| {
        json!({
            "document_kind": "annotations", "format_version": 1,
            "annotations": [{
                "id": "symbol:x", "kind": "symbol", "origin": "user",
                "name": "x", "target": target
            }]
        })
    };
    assert!(
        annotations
            .validate(&annotation(json!({
                "space": "hunk", "image_id": "image:x", "hunk": 0,
                "offset": 0, "length": 1
            })))
            .is_err(),
        "a target without an object digest was accepted"
    );
    // A runtime target with no load map: an address means nothing without one.
    assert!(
        annotations
            .validate(&annotation(json!({
                "space": "runtime", "image_id": "image:x",
                "address": "0x00000000", "length": 1, "object_sha256": "0".repeat(64)
            })))
            .is_err(),
        "a runtime target without a load map was accepted"
    );
    // An address that is not fixed-form lowercase hex.
    for bad in ["0xE63E", "0x1234", "57406", "0x0000E63E"] {
        assert!(
            annotations
                .validate(&annotation(json!({
                    "space": "runtime", "image_id": "image:x",
                    "load_map_id": "loadmap:x", "address": bad,
                    "length": 1, "object_sha256": "0".repeat(64)
                })))
                .is_err(),
            "{bad:?} was accepted as an address"
        );
    }

    // An integer type with no byte order. Amiga data is big-endian, but a
    // format that let it be omitted would resolve it from the host.
    assert!(
        types
            .validate(&json!({
                "document_kind": "types", "format_version": 1,
                "types": [{ "id": "type:x", "kind": "integer", "name": "x",
                            "size": 2, "signed": false }]
            }))
            .is_err(),
        "an integer type without a byte order was accepted"
    );
}

/// One object of `kind`, with `selector`, in an otherwise minimal document.
fn object_document(kind: &str, selector: Value) -> Value {
    json!({
        "document_kind": "sources", "format_version": 1, "sources": [],
        "objects": [{
            "id": "object:x", "kind": kind, "parent_id": "source:y",
            "size": 8, "sha256": "0".repeat(64), "selector": selector
        }]
    })
}

#[test]
fn a_decompressed_object_states_the_recipe_that_produced_it() {
    // The capability itself: an object may say *how* it was decompressed, and
    // the codec vocabulary is closed, so an unknown codec cannot slip through as
    // a digest with no derivation behind it.
    let registry = registry();
    let sources = validator_for(schemas::SOURCES, &registry);

    for codec in [
        json!({ "name": "powerpacker", "mode_bits": [9, 10, 12, 13] }),
        json!({ "name": "byte_run1" }),
        json!({ "name": "rle_xor", "marker": 144, "xor": true, "inline_marker": false, "size_bytes": 4, "size_includes_field": false }),
        // The two observed inline layouts: a marker with no size field, and a
        // marker followed by a size that counts its own bytes.
        json!({ "name": "rle_xor", "marker": 144, "xor": false, "inline_marker": true, "size_bytes": 0, "size_includes_field": false }),
        json!({ "name": "rle_xor", "marker": 144, "xor": false, "inline_marker": true, "size_bytes": 4, "size_includes_field": true }),
    ] {
        let document = object_document(
            "decompressed",
            json!({ "container": "decompressed", "codec": codec.clone() }),
        );
        if let Err(error) = sources.validate(&document) {
            panic!("{codec} was refused as a recipe: {error}");
        }
    }

    // A declared output size, where the stream carries one.
    assert!(
        sources
            .validate(&object_document(
                "decompressed",
                json!({
                    "container": "decompressed",
                    "codec": { "name": "rle_xor", "marker": 144, "xor": true, "inline_marker": false, "size_bytes": 4, "size_includes_field": false },
                    "declared_size": 6144
                })
            ))
            .is_ok()
    );
}

#[test]
fn the_schemas_refuse_a_recipe_no_decoder_could_run() {
    // The load-bearing half again. An incomplete or impossible recipe is worse
    // than none: it looks like provenance and reproduces nothing.
    let registry = registry();
    let sources = validator_for(schemas::SOURCES, &registry);
    let refused = |what: &str, codec: Value| {
        assert!(
            sources
                .validate(&object_document(
                    "decompressed",
                    json!({ "container": "decompressed", "codec": codec })
                ))
                .is_err(),
            "{what} was accepted"
        );
    };

    refused("an unknown codec", json!({ "name": "invented" }));
    refused("a codec with no name", json!({ "marker": 144 }));
    // Every rle_xor parameter is title-specific, so each is required: a recipe
    // that omitted one would decode to different bytes on a build whose default
    // differed.
    refused(
        "rle_xor without its marker",
        json!({ "name": "rle_xor", "xor": true, "inline_marker": false, "size_bytes": 4, "size_includes_field": false }),
    );
    refused(
        "rle_xor without its xor layer stated",
        json!({ "name": "rle_xor", "marker": 144, "inline_marker": false, "size_bytes": 4, "size_includes_field": false }),
    );
    refused(
        "a size field of an unsupported width",
        json!({ "name": "rle_xor", "marker": 144, "xor": true, "inline_marker": false, "size_bytes": 3, "size_includes_field": false }),
    );
    refused(
        "a marker outside a byte",
        json!({ "name": "rle_xor", "marker": 256, "xor": true, "inline_marker": false, "size_bytes": 4, "size_includes_field": false }),
    );
    // The layout is a parameter like any other: a stream carrying its marker
    // inline decodes without error under the out-of-band layout and produces
    // bytes that were never in the original, so it cannot be left unstated.
    refused(
        "rle_xor without its marker layout stated",
        json!({ "name": "rle_xor", "marker": 144, "xor": true, "size_bytes": 4, "size_includes_field": false }),
    );
    refused(
        "rle_xor without saying whether the size field counts itself",
        json!({ "name": "rle_xor", "marker": 144, "xor": true, "inline_marker": true, "size_bytes": 4 }),
    );
    refused(
        "a partial PowerPacker mode table",
        json!({ "name": "powerpacker", "mode_bits": [9, 10, 12] }),
    );
    refused(
        "a mode width no decoder accepts",
        json!({ "name": "powerpacker", "mode_bits": [0, 10, 12, 13] }),
    );
    refused(
        "a parameter on a codec that takes none",
        json!({ "name": "byte_run1", "marker": 144 }),
    );

    // And the kind and the selector must agree, in both directions: nothing can
    // slice a decompressed object out of its packed parent, so a document where
    // they disagree describes bytes nothing can reproduce.
    assert!(
        sources
            .validate(&object_document(
                "decompressed",
                json!({ "container": "range", "offset": 0, "length": 8 })
            ))
            .is_err(),
        "a decompressed object with a range selector was accepted"
    );
    assert!(
        sources
            .validate(&object_document(
                "byte_range",
                json!({ "container": "decompressed", "codec": { "name": "byte_run1" } })
            ))
            .is_err(),
        "a byte range with a decompression recipe was accepted"
    );
    // A decompressed object with no selector at all is the same failure: the
    // kind claims a derivation the document does not record.
    assert!(
        sources
            .validate(&json!({
                "document_kind": "sources", "format_version": 1, "sources": [],
                "objects": [{
                    "id": "object:x", "kind": "decompressed", "parent_id": "source:y",
                    "size": 8, "sha256": "0".repeat(64)
                }]
            }))
            .is_err(),
        "a decompressed object without a recipe was accepted"
    );
}

/// Index every declared ID with the document it came from.
fn declared_ids() -> BTreeMap<String, String> {
    let mut ids = BTreeMap::new();
    let mut declare = |id: &str, path: &str| {
        assert!(
            ids.insert(id.to_owned(), path.to_owned()).is_none(),
            "{id} is declared twice; the second is in {path}"
        );
    };
    for (path, document) in all_documents() {
        match document["document_kind"].as_str().unwrap_or_default() {
            "project" => declare(document["project"]["id"].as_str().expect("an id"), &path),
            "program" => {
                declare(document["id"].as_str().expect("an id"), &path);
                for image in document["images"].as_array().into_iter().flatten() {
                    declare(image["id"].as_str().expect("an id"), &path);
                    for map in image["load_maps"].as_array().into_iter().flatten() {
                        declare(map["id"].as_str().expect("an id"), &path);
                    }
                }
            }
            "sources" => {
                for key in ["sources", "source_sets", "objects"] {
                    for item in document[key].as_array().into_iter().flatten() {
                        declare(item["id"].as_str().expect("an id"), &path);
                    }
                }
            }
            kind @ ("annotations" | "resources" | "types") => {
                let key = if kind == "types" { "types" } else { kind };
                for item in document[key].as_array().into_iter().flatten() {
                    declare(item["id"].as_str().expect("an id"), &path);
                }
                for artifact in document["artifacts"].as_array().into_iter().flatten() {
                    declare(artifact["id"].as_str().expect("an id"), &path);
                }
            }
            _ => {}
        }
    }
    ids
}

#[test]
fn every_id_is_unique_and_every_reference_resolves_to_the_right_kind() {
    let ids = declared_ids();
    assert!(ids.len() > 20, "the fixture is too small to prove anything");

    // Walk every `*_id` field in every document and check it resolves, and that
    // the field name's prefix matches the ID's kind. `source_id` must name a
    // `source:`, `type_id` a `type:`, and so on — the typed-reference rule.
    fn walk(value: &Value, ids: &BTreeMap<String, String>, path: &str) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if let (Some(expected), Some(id)) = (expected_kind(key), child.as_str()) {
                        assert!(
                            ids.contains_key(id),
                            "{path}: {key} = {id} resolves to nothing"
                        );
                        assert!(
                            id.starts_with(&format!("{expected}:")),
                            "{path}: {key} = {id} is not a {expected}"
                        );
                    }
                    walk(child, ids, path);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, ids, path);
                }
            }
            _ => {}
        }
    }

    fn expected_kind(field: &str) -> Option<&'static str> {
        match field {
            "source_id" => Some("source"),
            "object_id" => Some("object"),
            "image_id" => Some("image"),
            "load_map_id" => Some("loadmap"),
            "program_id" => Some("program"),
            "type_id" | "element_id" | "pointee_id" | "base_id" | "aliased_id" => Some("type"),
            "function_id" => Some("function"),
            "resource_id" | "palette_resource_id" => Some("resource"),
            "source_set_id" => Some("set"),
            _ => None,
        }
    }

    for (path, document) in all_documents() {
        walk(&document, &ids, &path);
    }
}

#[test]
fn the_object_derivation_graph_is_acyclic_and_rooted_in_sources() {
    let sources = read("analysis/sources.json");
    let source_ids: BTreeSet<&str> = sources["sources"]
        .as_array()
        .expect("sources")
        .iter()
        .map(|source| source["id"].as_str().expect("an id"))
        .collect();
    let parents: BTreeMap<&str, &str> = sources["objects"]
        .as_array()
        .expect("objects")
        .iter()
        .map(|object| {
            (
                object["id"].as_str().expect("an id"),
                object["parent_id"].as_str().expect("a parent"),
            )
        })
        .collect();

    for object in parents.keys() {
        // Every chain must reach a source in a bounded number of steps. The
        // bound is what makes a cycle a failure rather than a hang.
        let mut current = *object;
        for _ in 0..=parents.len() {
            match parents.get(current) {
                Some(parent) if source_ids.contains(parent) => break,
                Some(parent) => current = parent,
                None => panic!("{object}: the chain leaves the graph at {current}"),
            }
        }
        assert!(
            parents
                .get(current)
                .is_some_and(|parent| source_ids.contains(parent)),
            "{object}: the derivation chain does not terminate in a source"
        );
    }
}

/// The Milestone 0 acceptance criterion, mechanized: every object can be
/// reproduced from its pinned source and its selector, and every annotated
/// byte range lies inside the object it names.
#[test]
fn every_object_reproduces_and_every_annotated_range_lies_inside_its_object() {
    use sha2::{Digest as _, Sha256};

    let sources_doc = read("analysis/sources.json");
    let root = fixture_root();

    // Read each file source and check it against its pin.
    let mut bytes_of: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for source in sources_doc["sources"].as_array().expect("sources") {
        let Some(location) = source["locations"][0]["path"].as_str() else {
            continue;
        };
        if source["kind"] != "file" {
            continue;
        }
        let path = root.join(location);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
        let id = source["id"].as_str().expect("an id").to_owned();
        assert_eq!(
            bytes.len() as u64,
            source["size"].as_u64().expect("a size"),
            "{id} has a different size than the project pins"
        );
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            source["sha256"].as_str().expect("a digest"),
            "{id} has different bytes than the project pins"
        );
        bytes_of.insert(id, bytes);
    }
    assert_eq!(bytes_of.len(), 4, "four file sources were expected");

    // Recover each object from its parent and check it against *its* pin. This
    // is the acceptance criterion: the metadata alone locates the bytes.
    let mut object_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for object in sources_doc["objects"].as_array().expect("objects") {
        let id = object["id"].as_str().expect("an id");
        let parent = object["parent_id"].as_str().expect("a parent");
        let Some(source) = bytes_of.get(parent) else {
            // A directory-source member; the inventory pins it instead, and
            // Milestone 2 is where directory recovery lands.
            continue;
        };
        let offset = object["selector"]["offset"].as_u64().expect("an offset") as usize;
        let length = object["selector"]["length"].as_u64().expect("a length") as usize;
        let recovered = source
            .get(offset..offset + length)
            .unwrap_or_else(|| panic!("{id}: the selector runs past its source"));
        let digest: String = Sha256::digest(recovered)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            object["sha256"].as_str().expect("a digest"),
            "{id} does not reproduce from its source and selector"
        );
        assert_eq!(
            recovered.len() as u64,
            object["size"].as_u64().expect("a size")
        );
        object_bytes.insert(id.to_owned(), recovered.to_vec());
    }
    assert!(
        object_bytes.len() >= 5,
        "too few objects were reproduced to prove the criterion"
    );

    // Every image names an object; every annotated hunk range must lie inside
    // the object that image is built from, and carry its digest — unless the
    // annotation is explicitly marked stale, which is the one case where a
    // mismatch is the point.
    let program = read("analysis/programs/main.json");
    let image_object: BTreeMap<&str, &str> = program["images"]
        .as_array()
        .expect("images")
        .iter()
        .map(|image| {
            (
                image["id"].as_str().expect("an id"),
                image["object_id"].as_str().expect("an object"),
            )
        })
        .collect();

    let mut stale_seen = 0;
    let mut checked = 0;
    for path in [
        "analysis/annotations/main-code.json",
        "analysis/annotations/loader-code.json",
    ] {
        let document = read(path);
        for annotation in document["annotations"].as_array().expect("annotations") {
            let target = &annotation["target"];
            if target["space"] != "hunk" && target["space"] != "runtime" {
                continue;
            }
            let image = target["image_id"].as_str().expect("an image");
            let object = image_object[image];
            let expected = object_bytes[object].len();
            let recorded = target["object_sha256"].as_str().expect("a digest");
            let actual: String = Sha256::digest(&object_bytes[object])
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            if annotation["stale"] == serde_json::Value::Bool(true) {
                assert_ne!(
                    recorded, actual,
                    "{}: marked stale but its digest still matches",
                    annotation["id"]
                );
                stale_seen += 1;
                continue;
            }
            assert_eq!(
                recorded, actual,
                "{}: its object digest does not match, so it is stale and unmarked",
                annotation["id"]
            );
            if target["space"] == "hunk" {
                let offset = target["offset"].as_u64().expect("an offset");
                let length = target["length"].as_u64().expect("a length");
                assert!(
                    offset + length <= expected as u64,
                    "{}: the range runs past its object",
                    annotation["id"]
                );
            }
            checked += 1;
        }
    }
    assert_eq!(
        stale_seen, 1,
        "the fixture must carry exactly one deliberately stale annotation"
    );
    assert!(checked >= 5, "too few annotated ranges were checked");
}

#[test]
fn the_two_images_use_the_same_numeric_offsets_for_different_things() {
    // The multi-module case the format exists for. If the fixture did not have
    // overlapping numeric addresses, nothing here would prove that a target
    // needs its image.
    let main = read("analysis/annotations/main-code.json");
    let loader = read("analysis/annotations/loader-code.json");
    let offsets = |document: &Value| -> BTreeSet<(u64, u64)> {
        document["annotations"]
            .as_array()
            .expect("annotations")
            .iter()
            .filter(|annotation| annotation["target"]["space"] == "hunk")
            .map(|annotation| {
                (
                    annotation["target"]["hunk"].as_u64().expect("a hunk"),
                    annotation["target"]["offset"].as_u64().expect("an offset"),
                )
            })
            .collect()
    };
    let shared: Vec<_> = offsets(&main)
        .intersection(&offsets(&loader))
        .copied()
        .collect();
    assert!(
        !shared.is_empty(),
        "the two images share no numeric offsets, so the fixture does not \
         exercise the ambiguity the format exists to remove"
    );
}

#[test]
fn the_tree_hash_in_the_fixture_is_the_one_the_library_computes() {
    let sources = read("analysis/sources.json");
    let inventory = read("analysis/source-inventories/installed-tree.json");
    let files: Vec<(String, u64, String)> = inventory["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|file| {
            (
                file["path"].as_str().expect("a path").to_owned(),
                file["size"].as_u64().expect("a size"),
                file["sha256"].as_str().expect("a digest").to_owned(),
            )
        })
        .collect();
    let computed = amiga_project::tree_sha256(&files);
    assert_eq!(computed, inventory["tree_sha256"].as_str().expect("a hash"));

    let directory = sources["sources"]
        .as_array()
        .expect("sources")
        .iter()
        .find(|source| source["kind"] == "directory")
        .expect("a directory source");
    assert_eq!(
        computed,
        directory["tree_sha256"].as_str().expect("a hash"),
        "the source and its inventory disagree about the tree hash"
    );
}

/// One annotations document carrying a single annotation.
fn annotation_document(annotation: Value) -> Value {
    json!({
        "document_kind": "annotations",
        "format_version": 1,
        "annotations": [annotation]
    })
}

#[test]
fn a_variable_may_be_a_base_register_global_with_no_function_scope() {
    // The shape `disasm globals` reports and nothing could name. A global has
    // no function to be scoped to, and requiring one would mean inventing an ID
    // that other tools resolve.
    let registry = registry();
    let annotations = validator_for(schemas::ANNOTATIONS, &registry);

    let global = json!({
        "id": "variable:map-seed",
        "kind": "variable",
        "origin": "user",
        "name": "map_seed",
        "target": {
            "space": "base_register",
            "image_id": "image:main",
            "base_register": "a5",
            "displacement": -8,
            "width": 4,
            "object_sha256": "0".repeat(64)
        }
    });
    if let Err(error) = annotations.validate(&annotation_document(global.clone())) {
        panic!("a base-register global was refused: {error}");
    }

    // The digest is not optional: without it the name could be reapplied to
    // whatever the displacement holds in a later build.
    let mut no_digest = global.clone();
    no_digest["target"]
        .as_object_mut()
        .expect("a target")
        .remove("object_sha256");
    assert!(
        annotations
            .validate(&annotation_document(no_digest))
            .is_err(),
        "a global with no object digest was accepted"
    );

    // Neither is the width: a byte slot and a longword slot at the same
    // displacement are different globals.
    let mut no_width = global.clone();
    no_width["target"]
        .as_object_mut()
        .expect("a target")
        .remove("width");
    assert!(
        annotations
            .validate(&annotation_document(no_width))
            .is_err(),
        "a global with no access width was accepted"
    );

    // And the two shapes do not mix: a global with a function scope is neither
    // one thing nor the other.
    let mut both = global;
    both["scope"] = json!({ "function_id": "function:init" });
    both["storage"] = json!({ "kind": "register", "register": "d0" });
    assert!(
        annotations.validate(&annotation_document(both)).is_err(),
        "a variable claiming both shapes was accepted"
    );

    // A local still needs its scope and storage, which is the rule the second
    // shape must not have weakened.
    assert!(
        annotations
            .validate(&annotation_document(json!({
                "id": "variable:local",
                "kind": "variable",
                "origin": "user",
                "name": "counter",
                "storage": { "kind": "register", "register": "d0" }
            })))
            .is_err(),
        "a local with no function scope was accepted"
    );
}

/// Every file the fixture's sources name is present in this checkout.
///
/// The fixture used to be excluded by a blanket `*.adf` ignore rule, so a fresh
/// clone or a new worktree had no disks and every media-dependent assertion
/// failed somewhere deep in a decode. They are committed now — they are
/// synthetic and hold no third-party bytes — and this says so in one place, so
/// the next time one goes missing the suite names the file instead of reporting
/// a digest that does not match bytes that are not there.
#[test]
fn every_source_the_fixture_names_is_present_in_this_checkout() {
    let sources = read("analysis/sources.json");
    let listed = sources["sources"]
        .as_array()
        .expect("the fixture lists its sources");
    assert!(!listed.is_empty(), "the fixture named no sources at all");

    for source in listed {
        for location in source["locations"]
            .as_array()
            .expect("every source records where it lives")
        {
            let relative = location["path"]
                .as_str()
                .expect("every location names a path");
            let path = fixture_root().join(relative);
            assert!(
                path.exists(),
                "{} is missing. It is committed test data, not private media, \
                 so this checkout is incomplete rather than merely unprepared.",
                path.display()
            );
        }
    }
}
