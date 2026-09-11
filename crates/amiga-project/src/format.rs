//! The deterministic formatter.
//!
//! Milestone 0's review found this and deliberately left it open: nothing
//! required arrays to be sorted, so two writers could produce semantically
//! identical documents that differed textually. In a format whose whole point
//! is being diffable and mergeable, that is not a cosmetic problem — it turns
//! every save into a spurious diff and every merge into a conflict.
//!
//! ## The sort key
//!
//! Every array of entities sorts by the entity's **ID**. Not by name, which
//! changes when someone improves a label; not by address, which changes when an
//! annotation is rebased; not by insertion order, which is whatever the writer
//! happened to do. The ID is the one field the format promises is stable, which
//! makes it the only defensible key.
//!
//! Arrays whose order is *meaningful* keep it: a struct's fields, an enum's
//! members, a load map's segments, and a source set's members are ordered by
//! offset, value, hunk, and slot respectively, and reordering them would change
//! what the document says. Those are sorted by that meaning, not by ID.
//!
//! ## Key order
//!
//! Object keys are emitted in sorted order. JSON objects are unordered by
//! definition, so any stable choice works; sorted is the one a reader can
//! predict without consulting a schema.

use serde_json::{Map, Value};

/// Format one project document canonically.
///
/// Takes and returns JSON rather than typed documents so that a document this
/// build does not fully understand — a newer minor addition, an `extensions`
/// blob — still formats correctly instead of being silently dropped.
#[must_use]
pub fn format_document(document: &Value) -> String {
    let canonical = canonicalize(document);
    // Two-space indent and a trailing newline: the shape every other checked-in
    // JSON file in this repository already uses.
    format!(
        "{}\n",
        serde_json::to_string_pretty(&canonical).unwrap_or_else(|_| String::new())
    )
}

/// Sort what may be sorted, recursively.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let child = &map[key];
                sorted.insert(key.clone(), canonicalize_array(key, child));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Canonicalize one field, sorting it if its array has a defined order.
fn canonicalize_array(key: &str, value: &Value) -> Value {
    let Value::Array(items) = value else {
        return canonicalize(value);
    };
    let mut items: Vec<Value> = items.iter().map(canonicalize).collect();
    match key {
        // Entity arrays: sorted by the one field the format promises is stable.
        "sources" | "source_sets" | "objects" | "images" | "load_maps" | "annotations"
        | "resources" | "artifacts" | "types" => {
            items.sort_by_cached_key(|item| sort_key(item, "id"));
        }
        // Ordered by meaning, not identity: reordering these would change what
        // the document says.
        "fields" => items.sort_by_key(|item| item["offset"].as_u64().unwrap_or(0)),
        "members" => items.sort_by(|left, right| {
            // A source set's members order by slot; an enum's by value. Both
            // fall back to the name so the order is total either way.
            let key = |item: &Value| {
                (
                    item["slot"]
                        .as_u64()
                        .or_else(|| item["value"].as_i64().map(|v| v as u64)),
                    sort_key(item, "source_id"),
                    sort_key(item, "name"),
                )
            };
            key(left).cmp(&key(right))
        }),
        "segments" => items.sort_by_key(|item| item["hunk"].as_u64().unwrap_or(0)),
        "entry_points" => items.sort_by_cached_key(|item| sort_key(item, "address")),
        // Path-keyed arrays sort by path, which is what makes an inventory's
        // tree hash reproducible.
        "files" | "omitted" => items.sort_by_cached_key(|item| sort_key(item, "path")),
        // Anything else keeps its order: a document reference list, a warning
        // list, and a palette are all sequences whose order the author chose.
        _ => {}
    }
    Value::Array(items)
}

fn sort_key(value: &Value, field: &str) -> String {
    value[field].as_str().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entity_arrays_sort_by_id_whatever_order_they_arrive_in() {
        let forward = json!({
            "sources": [{ "id": "source:a" }, { "id": "source:b" }]
        });
        let backward = json!({
            "sources": [{ "id": "source:b" }, { "id": "source:a" }]
        });
        assert_eq!(format_document(&forward), format_document(&backward));
        assert!(
            format_document(&backward).find("source:a")
                < format_document(&backward).find("source:b")
        );
    }

    #[test]
    fn arrays_whose_order_carries_meaning_sort_by_that_meaning() {
        // A struct's fields are ordered by offset, not by name: sorting them
        // alphabetically would make the document say something different.
        let document = json!({
            "fields": [
                { "name": "zeta", "offset": 0 },
                { "name": "alpha", "offset": 4 }
            ]
        });
        let text = format_document(&document);
        assert!(
            text.find("zeta") < text.find("alpha"),
            "fields were sorted by name rather than offset:\n{text}"
        );
    }

    #[test]
    fn a_load_maps_segments_stay_in_hunk_order() {
        let document = json!({
            "segments": [
                { "hunk": 1, "runtime_base": "0x00022000" },
                { "hunk": 0, "runtime_base": "0x0000e63e" }
            ]
        });
        let text = format_document(&document);
        assert!(text.find("0x0000e63e") < text.find("0x00022000"));
    }

    #[test]
    fn an_arrays_order_is_kept_when_the_format_does_not_define_one() {
        // A document reference list is a sequence the author chose. Sorting it
        // would be inventing a rule the format does not have.
        let document = json!({ "programs": ["b.json", "a.json"] });
        let text = format_document(&document);
        assert!(text.find("b.json") < text.find("a.json"));
    }

    #[test]
    fn keys_are_emitted_in_a_predictable_order() {
        let document = json!({ "zeta": 1, "alpha": 2 });
        let text = format_document(&document);
        assert!(text.find("alpha") < text.find("zeta"));
    }

    #[test]
    fn formatting_is_idempotent() {
        // The property that makes a formatter usable in a pre-commit hook: a
        // second run must never produce a third form.
        let document = json!({
            "sources": [{ "id": "source:b", "notes": "x" }, { "id": "source:a" }],
            "format_version": 1
        });
        let once = format_document(&document);
        let reparsed: Value = serde_json::from_str(&once).expect("formatted output is JSON");
        assert_eq!(format_document(&reparsed), once);
    }

    #[test]
    fn formatting_preserves_content_it_does_not_understand() {
        // A newer field, or an `extensions` blob, must survive a format pass. A
        // formatter that dropped what it could not classify would silently
        // delete a downstream project's data.
        let document = json!({
            "extensions": { "downstream": { "anything": [1, 2, 3] } },
            "invented_field": true
        });
        let text = format_document(&document);
        let reparsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(reparsed["invented_field"], json!(true));
        assert_eq!(
            reparsed["extensions"]["downstream"]["anything"],
            json!([1, 2, 3])
        );
    }
}
