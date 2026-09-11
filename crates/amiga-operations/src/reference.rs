//! The operation reference, generated from the catalog and the bundled schemas.
//!
//! Documentation that restates the contract by hand goes stale silently. This
//! renders it from the same descriptors the router dispatches on and the same
//! schemas the tests validate against. The reference covers current workflows;
//! the configuration importer is excluded. The repository keeps a checked-in
//! copy and a test that regenerates it.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::descriptor::{catalog, schemas};
use crate::protocol::PROTOCOL_VERSION;

/// Render the operation reference for current workflows as Markdown.
#[must_use]
pub fn markdown() -> String {
    let documents = bundled_documents();
    let mut text = String::new();
    // Writing to a String cannot fail.
    let _ = writeln!(text, "# Operation reference");
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "Generated from the operation catalog and the bundled Draft 2020-12 schemas by\n\
         `amiga_operations::reference::markdown`. Edit the generator or schemas, then update\n\
         this file with:\n\n\
         ```bash\n\
         UPDATE_GOLDEN=1 cargo test -p amiga-operations --test catalog the_checked_in_operation_reference_matches_the_catalog\n\
         ```\n\n\
         Review the resulting diff. Without `UPDATE_GOLDEN`, the test checks for drift\n\
         and leaves the file unchanged."
    );
    let _ = writeln!(text);
    let _ = writeln!(text, "Protocol version: `{PROTOCOL_VERSION}`");
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "The argument tables describe operation payloads. Requests wrap them in an\n\
         envelope with `protocol_version` and `request`; `request` contains `operation` and\n\
         `arguments`. Inspect the catalog and bundled schemas through the CLI:\n\n\
         ```bash\n\
         amiga-re operations list --response json\n\
         amiga-re schema\n\
         amiga-re schema source.survey --kind request\n\
         amiga-re schema source.survey --kind response\n\
         ```\n\n\
         Schema identifiers below are offline identities, not downloadable URLs. Use\n\
         `amiga-re schema --output schemas` to export the complete bundled set. Nested\n\
         object fields and validation constraints are described in those schemas.\n\n\
         Defaults apply when an argument is omitted; they are not host ceilings.\n\
         `ExecutionContext` supplies `OperationLimits`, including aggregate recovery\n\
         and object budgets that are not request arguments. Requests cannot raise\n\
         those host limits. Limit reductions are reported in diagnostics.\n\n\
         `read_only` operations return results without writing output files.\n\
         `prepared_output` operations require a destination resolver and produce a\n\
         plan for review before commit. `amiga-re operations run --request request.json`\n\
         uses the current directory for source resolution and supplies no destination\n\
         resolver; use the corresponding export/extraction command or a library host\n\
         with destinations configured for prepared output.\n"
    );
    let _ = writeln!(text, "| Operation | Access | Summary |");
    let _ = writeln!(text, "|---|---|---|");
    for descriptor in catalog()
        .iter()
        .filter(|descriptor| descriptor.name != crate::OperationName::ProjectMigrate)
    {
        let _ = writeln!(
            text,
            "| [`{}`](#{}) | `{}` | {} |",
            descriptor.name.as_str(),
            anchor(descriptor.name.as_str()),
            descriptor.access.as_str(),
            descriptor.summary
        );
    }

    for descriptor in catalog()
        .iter()
        .filter(|descriptor| descriptor.name != crate::OperationName::ProjectMigrate)
    {
        let _ = writeln!(text);
        let _ = writeln!(text, "<a id=\"{}\"></a>", anchor(descriptor.name.as_str()));
        let _ = writeln!(text);
        let _ = writeln!(text, "## `{}`", descriptor.name.as_str());
        let _ = writeln!(text);
        let _ = writeln!(text, "{}", descriptor.summary);
        let _ = writeln!(text);
        let _ = writeln!(text, "- Access class: `{}`", descriptor.access.as_str());
        let _ = writeln!(
            text,
            "- Request schema: `{}`",
            schema_id(descriptor.request_schema)
        );
        let _ = writeln!(
            text,
            "- Response schema: `{}`",
            schema_id(descriptor.response_schema)
        );
        let _ = writeln!(text);
        let _ = writeln!(text, "### Arguments");
        let _ = writeln!(text);
        let _ = write!(
            text,
            "{}",
            arguments_table(descriptor.request_schema, &documents)
        );
    }
    text
}

/// The explicit HTML anchor used by an operation's catalog link.
fn anchor(name: &str) -> String {
    name.chars()
        .filter_map(|character| match character {
            'a'..='z' | '0'..='9' | '-' => Some(character),
            'A'..='Z' => Some(character.to_ascii_lowercase()),
            '.' | ' ' => Some('-'),
            _ => None,
        })
        .collect()
}

/// The `$id` a bundled schema declares, or a placeholder when it has none.
///
/// Read from the document rather than reconstructed from the operation name, so
/// the reference cites the identity a consumer would actually resolve.
fn schema_id(schema: &str) -> String {
    serde_json::from_str::<Value>(schema)
        .ok()
        .and_then(|document| {
            document
                .get("$id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "(no $id)".to_owned())
}

/// Every bundled schema, keyed by the `$id` a `$ref` names it with.
///
/// The shared documents and every operation's own pair, because a `$ref` may
/// name any of them. `the_bundled_schemas_form_a_resolvable_offline_set` proves
/// the set is closed, so a `$ref` that misses this map is a schema fault rather
/// than a missing entry here.
fn bundled_documents() -> BTreeMap<String, Value> {
    let mut documents = BTreeMap::new();
    let mut insert = |schema: &str| {
        if let Ok(document) = serde_json::from_str::<Value>(schema)
            && let Some(id) = document.get("$id").and_then(Value::as_str)
        {
            documents.insert(id.to_owned(), document);
        }
    };
    for (_, schema) in schemas::ALL {
        insert(schema);
    }
    for descriptor in catalog() {
        insert(descriptor.request_schema);
        insert(descriptor.response_schema);
    }
    documents
}

/// The schema a `$ref` names, from the operation's own document or the set.
///
/// A `$ref` here is either local (`#/$defs/name`) or a bundled `$id` with a
/// JSON Pointer fragment. Anything else resolves to nothing, which the caller
/// renders as an undescribed argument rather than as a URL.
fn follow<'a>(
    reference: &str,
    root: &'a Value,
    documents: &'a BTreeMap<String, Value>,
) -> Option<&'a Value> {
    let (document, pointer) = match reference.split_once('#') {
        Some(("", pointer)) => (root, pointer),
        Some((id, pointer)) => (documents.get(id)?, pointer),
        None => (documents.get(reference)?, ""),
    };
    if pointer.is_empty() {
        return Some(document);
    }
    document.pointer(pointer)
}

/// One argument's schema with every `$ref` into the bundled set followed.
///
/// Keys written beside a `$ref` win over the definition's, which is what a
/// schema processor does with them and how an operation overrides a shared
/// cap's `default`. The chain is bounded so a schema that referenced itself
/// would render oddly rather than hang.
fn effective(
    property: &Value,
    root: &Value,
    documents: &BTreeMap<String, Value>,
) -> Map<String, Value> {
    let mut merged = property.as_object().cloned().unwrap_or_default();
    let mut current = property;
    for _ in 0..8 {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            break;
        };
        let Some(target) = follow(reference, root, documents) else {
            break;
        };
        if let Some(fields) = target.as_object() {
            for (key, value) in fields {
                merged.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        current = target;
    }
    // The reader wants the constraint, not the definition's URL; a caller who
    // wants the definition reads the schema.
    merged.remove("$ref");
    merged
}

/// The type cell: the enumerated values when there are any, else the JSON type.
fn type_cell(schema: &Map<String, Value>) -> String {
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values
            .iter()
            .map(|value| format!("`{}`", escape(&render(value))))
            .collect::<Vec<_>>()
            .join(" \\| ");
    }
    match schema.get("type") {
        Some(Value::String(name)) => format!("`{name}`"),
        Some(Value::Array(names)) => names
            .iter()
            .filter_map(Value::as_str)
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(" \\| "),
        _ => "—".to_owned(),
    }
}

/// A JSON value as it reads in prose: a string unquoted, anything else as JSON.
fn render(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A cell's text with the characters that would end it early neutralized.
fn escape(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// One Markdown table of an operation's arguments, read from its request schema.
///
/// Reads `properties.arguments`, which is where every operation's arguments
/// live: the outer object is the tagged request document, not the payload.
fn arguments_table(schema: &str, documents: &BTreeMap<String, Value>) -> String {
    let Ok(root) = serde_json::from_str::<Value>(schema) else {
        return "_This operation takes no arguments._\n".to_owned();
    };
    let Some(arguments) = root
        .get("properties")
        .and_then(|properties| properties.get("arguments"))
    else {
        return "_This operation takes no arguments._\n".to_owned();
    };
    let required: Vec<&str> = arguments
        .get("required")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(properties) = arguments.get("properties").and_then(Value::as_object) else {
        return "_This operation takes no arguments._\n".to_owned();
    };

    let mut text = String::new();
    let _ = writeln!(
        text,
        "| Argument | Type | Required | Default | Description |"
    );
    let _ = writeln!(text, "|---|---|---|---|---|");
    for (name, property) in properties {
        let schema = effective(property, &root, documents);
        let _ = writeln!(
            text,
            "| `{name}` | {} | {} | {} | {} |",
            type_cell(&schema),
            if required.contains(&name.as_str()) {
                "yes"
            } else {
                "no"
            },
            schema.get("default").map_or_else(
                || "—".to_owned(),
                |value| format!("`{}`", escape(&value.to_string()))
            ),
            schema
                .get("description")
                .and_then(Value::as_str)
                .map_or_else(|| "—".to_owned(), escape)
        );
    }
    text
}
