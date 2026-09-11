//! The catalog and the bundled schemas.
//!
//! Hand-written schemas are the published contract, and hand-written semantic
//! validation is what actually refuses a bad request. Those are two artifacts
//! describing one thing, so they can drift. These tests are what stops them:
//! every fixture the code produces is validated against the schema the crate
//! ships, and every shape the schema forbids is proven to be refused.

use std::path::{Path, PathBuf};

use amiga_operations::{
    AccessClass, ExecutionContext, FilesystemSourceResolver, OperationName, PROTOCOL_VERSION,
    RequestEnvelope, ResponseEnvelope, Router, catalog, descriptor,
};
use jsonschema::{Registry, Validator};
use serde_json::{Value, json};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn read_fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(fixture_dir().join(name))
        .unwrap_or_else(|error| panic!("fixture {name} is readable: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("fixture {name} is JSON: {error}"))
}

fn parse(schema: &str) -> Value {
    serde_json::from_str(schema).unwrap_or_else(|error| panic!("bundled schema is JSON: {error}"))
}

/// Every bundled document, registered under its own `$id`.
///
/// Nothing is fetched: the identifiers use the reserved `.invalid` domain
/// precisely so a resolution attempt would fail loudly rather than reach the
/// network.
fn registry() -> Registry<'static> {
    use amiga_operations::descriptor::schemas;

    let mut documents: Vec<(String, Value)> = vec![
        schemas::COMMON,
        schemas::REQUEST,
        schemas::RESPONSE,
        schemas::DIAGNOSTIC,
        schemas::EVENT,
    ]
    .into_iter()
    .map(|schema| {
        let value = parse(schema);
        (schema_id(&value), value)
    })
    .collect();

    for described in catalog() {
        for schema in [described.request_schema, described.response_schema] {
            let value = parse(schema);
            documents.push((schema_id(&value), value));
        }
    }

    Registry::new()
        .extend(documents)
        .expect("every bundled schema has a usable $id")
        .prepare()
        .expect("the bundled schemas form a resolvable set")
}

fn schema_id(schema: &Value) -> String {
    schema["$id"]
        .as_str()
        .unwrap_or_else(|| panic!("every bundled schema declares an $id: {schema}"))
        .to_owned()
}

fn validator_for(schema: &str, registry: &Registry<'_>) -> Validator {
    let value = parse(schema);
    jsonschema::options()
        .with_registry(registry)
        .build(&json!({ "$ref": schema_id(&value) }))
        .expect("the bundled schema compiles as Draft 2020-12")
}

fn assert_valid(validator: &Validator, document: &Value, what: &str) {
    if let Err(error) = validator.validate(document) {
        panic!("{what} does not satisfy its bundled schema: {error}");
    }
}

#[test]
fn every_operation_has_a_descriptor_and_appears_once_in_the_catalog() {
    // Exhaustive by construction: a new variant cannot be added without
    // deciding where it sits, which is what keeps `ALL` honest.
    const fn position(name: OperationName) -> usize {
        match name {
            OperationName::SourceSurvey => 0,
            OperationName::ContainerAdfList => 1,
            OperationName::GraphicsBitmapDecode => 2,
            OperationName::ContainerAdfExtract => 3,
            OperationName::ContainerLhaExtract => 4,
            OperationName::GraphicsBitmapExport => 5,
            OperationName::ProjectCheck => 6,
            OperationName::ProjectVerify => 7,
            OperationName::AnalysisHunkDiff => 8,
            OperationName::AnalysisHunkDiffExport => 9,
            OperationName::SourceCarve => 10,
            OperationName::AnalysisTableDecode => 11,
            OperationName::AnalysisTableSummarize => 12,
            OperationName::AudioSampleDecode => 13,
            OperationName::AudioSampleExport => 14,
            OperationName::CompressPowerpackerDecode => 15,
            OperationName::CompressPowerpackerExport => 16,
            OperationName::CompressRleXorDecode => 17,
            OperationName::CompressRleXorExport => 18,
            OperationName::AudioPcmDecode => 19,
            OperationName::AudioPcmExport => 20,
            OperationName::AudioModuleDecode => 21,
            OperationName::AudioModuleExport => 22,
            OperationName::AnalysisHunkNormalize => 23,
            OperationName::AnalysisHunkNormalizeExport => 24,
            OperationName::ProvenanceManifest => 25,
            OperationName::ProvenanceManifestExport => 26,
            OperationName::GraphicsPaletteDecode => 27,
            OperationName::GraphicsPaletteExport => 28,
            OperationName::EnvSandboxRun => 29,
            OperationName::EnvBootInfo => 30,
            OperationName::EnvSandboxCall => 31,
            OperationName::EnvSandboxCallExport => 32,
            OperationName::EnvBootTrace => 33,
            OperationName::EnvBootTraceExport => 34,
            OperationName::AnalysisHunkList => 35,
            OperationName::AnalysisStringsScan => 36,
            OperationName::AnalysisAddressResolve => 37,
            OperationName::AnalysisPointersScan => 38,
            OperationName::AnalysisCodeDisassemble => 39,
            OperationName::AnalysisAddressReferences => 40,
            OperationName::AnalysisCodeCallgraph => 41,
            OperationName::AnalysisCodeGlobals => 42,
            OperationName::AnalysisCodeFixedPoint => 43,
            OperationName::ContainerLhaList => 44,
            OperationName::HardwareRegisterList => 45,
            OperationName::AudioPcmScan => 46,
            OperationName::AudioModuleScan => 47,
            OperationName::GraphicsPaletteScan => 48,
            OperationName::HardwareCopperScan => 49,
            OperationName::HardwareCopperDecode => 50,
            OperationName::GraphicsIlbmDecode => 51,
            OperationName::GraphicsBitmapDetect => 52,
            OperationName::HardwareRegisterReferences => 53,
            OperationName::HardwareCopperReferences => 54,
            OperationName::ProjectDescribe => 55,
            OperationName::ProjectAnnotations => 56,
            OperationName::ProjectInventory => 57,
            OperationName::ProjectEdit => 58,
            OperationName::ProjectFormat => 59,
            OperationName::ProjectMigrate => 60,
            OperationName::AnalysisCodeFacts => 61,
            OperationName::SourceRead => 62,
            OperationName::ProjectInit => 63,
            OperationName::ProjectExtract => 64,
            OperationName::ProjectResourceExport => 65,
            OperationName::EnvSandboxMatrix => 66,
            OperationName::EnvSandboxCompare => 67,
            OperationName::EnvSandboxMatrixExport => 68,
            OperationName::EnvSandboxTimeline => 69,
            OperationName::AnalysisStateSnapshot => 70,
            OperationName::AnalysisStateCompare => 71,
            OperationName::EnvFrameCapture => 72,
            OperationName::EnvFrameCaptureExport => 73,
            OperationName::GraphicsBitmapCompare => 74,
            OperationName::GraphicsBitmapCompareExport => 75,
            OperationName::EnvSandboxSlice => 76,
            OperationName::EnvSandboxTimelineExport => 77,
        }
    }

    assert_eq!(OperationName::ALL.len(), 78);
    for (index, name) in OperationName::ALL.iter().enumerate() {
        assert_eq!(position(*name), index, "{name} is out of catalog order");
    }

    let described = catalog();
    assert_eq!(described.len(), OperationName::ALL.len());
    for (entry, name) in described.iter().zip(OperationName::ALL) {
        assert_eq!(entry.name, *name);
        assert_eq!(descriptor(*name).name, *name);
        assert!(!entry.summary.is_empty());
        assert!(
            entry.summary.ends_with('.'),
            "{name}: a summary is one sentence"
        );
        // The access class is what decides which execution modes an operation
        // accepts, so it must be the one its handler actually implements —
        // a read-only operation that could write would be the worst kind of
        // metadata error.
        let expected = match name {
            OperationName::SourceSurvey
            | OperationName::ContainerAdfList
            | OperationName::GraphicsBitmapDecode
            | OperationName::ProjectCheck
            | OperationName::ProjectVerify
            | OperationName::AnalysisHunkDiff
            | OperationName::AnalysisTableDecode
            | OperationName::AnalysisTableSummarize
            | OperationName::AudioSampleDecode
            | OperationName::CompressPowerpackerDecode
            | OperationName::CompressRleXorDecode
            | OperationName::AudioPcmDecode
            | OperationName::AudioModuleDecode
            | OperationName::AnalysisHunkNormalize
            | OperationName::ProvenanceManifest
            | OperationName::GraphicsPaletteDecode
            | OperationName::EnvSandboxRun
            | OperationName::EnvBootInfo
            | OperationName::EnvSandboxCall
            | OperationName::EnvSandboxMatrix
            | OperationName::EnvSandboxTimeline
            | OperationName::EnvSandboxSlice
            | OperationName::EnvSandboxCompare
            | OperationName::EnvBootTrace
            | OperationName::AnalysisHunkList
            | OperationName::AnalysisStringsScan
            | OperationName::AnalysisAddressResolve
            | OperationName::AnalysisPointersScan
            | OperationName::AnalysisCodeDisassemble
            | OperationName::AnalysisAddressReferences
            | OperationName::AnalysisCodeCallgraph
            | OperationName::AnalysisCodeGlobals
            | OperationName::AnalysisCodeFixedPoint
            | OperationName::AnalysisStateSnapshot
            | OperationName::AnalysisStateCompare
            | OperationName::EnvFrameCapture
            | OperationName::GraphicsBitmapCompare
            | OperationName::ContainerLhaList
            | OperationName::HardwareRegisterList
            | OperationName::AudioPcmScan
            | OperationName::AudioModuleScan
            | OperationName::GraphicsPaletteScan
            | OperationName::HardwareCopperScan
            | OperationName::HardwareCopperDecode
            | OperationName::GraphicsIlbmDecode
            | OperationName::GraphicsBitmapDetect
            | OperationName::HardwareRegisterReferences
            | OperationName::HardwareCopperReferences
            | OperationName::ProjectDescribe
            | OperationName::ProjectAnnotations
            | OperationName::ProjectInventory
            | OperationName::AnalysisCodeFacts
            | OperationName::SourceRead => AccessClass::ReadOnly,
            OperationName::ContainerAdfExtract
            | OperationName::ContainerLhaExtract
            | OperationName::GraphicsBitmapExport
            | OperationName::AnalysisHunkDiffExport
            | OperationName::SourceCarve
            | OperationName::AudioSampleExport
            | OperationName::CompressPowerpackerExport
            | OperationName::CompressRleXorExport
            | OperationName::AudioPcmExport
            | OperationName::AudioModuleExport
            | OperationName::AnalysisHunkNormalizeExport
            | OperationName::ProvenanceManifestExport
            | OperationName::GraphicsPaletteExport
            | OperationName::EnvSandboxCallExport
            | OperationName::EnvSandboxMatrixExport
            | OperationName::EnvSandboxTimelineExport
            | OperationName::EnvFrameCaptureExport
            | OperationName::GraphicsBitmapCompareExport
            | OperationName::EnvBootTraceExport
            | OperationName::ProjectEdit
            | OperationName::ProjectFormat
            | OperationName::ProjectMigrate
            | OperationName::ProjectInit
            | OperationName::ProjectExtract
            | OperationName::ProjectResourceExport => AccessClass::PreparedOutput,
        };
        assert_eq!(entry.access, expected, "{name}");
    }
}

#[test]
fn every_operation_schema_names_the_operation_it_describes() {
    for described in catalog() {
        let request = parse(described.request_schema);
        assert_eq!(
            request["properties"]["operation"]["const"].as_str(),
            Some(described.name.as_str()),
            "{}: the request schema must pin its own operation tag",
            described.name
        );
        // A response payload carries no second operation tag: the envelope's
        // `operation` field already names it.
        let response = parse(described.response_schema);
        assert!(response["properties"]["operation"].is_null());
        assert_eq!(response["type"].as_str(), Some("object"));
    }
}

#[test]
fn the_bundled_schemas_form_a_resolvable_offline_set() {
    let registry = registry();
    // Building each envelope validator resolves every cross-document `$ref`.
    let _ = validator_for(amiga_operations::descriptor::schemas::REQUEST, &registry);
    let _ = validator_for(amiga_operations::descriptor::schemas::RESPONSE, &registry);
    let _ = validator_for(amiga_operations::descriptor::schemas::DIAGNOSTIC, &registry);
}

#[test]
fn every_request_fixture_satisfies_the_bundled_request_schema() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::REQUEST, &registry);

    for name in [
        "source.survey.request.json",
        "container.adf.list.request.json",
    ] {
        assert_valid(&validator, &read_fixture(name), name);
    }
}

#[test]
fn every_response_the_router_produces_satisfies_the_bundled_response_schema() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::RESPONSE, &registry);
    let resolver = FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"));
    let context = ExecutionContext::new(&resolver);

    // The recorded fixtures, and the live responses they were recorded from.
    for name in [
        "source.survey.response.json",
        "container.adf.list.response.json",
    ] {
        assert_valid(&validator, &read_fixture(name), name);
    }

    for name in [
        "source.survey.request.json",
        "container.adf.list.request.json",
    ] {
        let request: RequestEnvelope = serde_json::from_value(read_fixture(name))
            .unwrap_or_else(|error| panic!("{name} parses: {error}"));
        let outcome = Router::execute(&request, &context);
        let response = ResponseEnvelope::from_outcome(&outcome, request.request_id.as_deref());
        let document = serde_json::to_value(&response).expect("the response serializes");
        assert_valid(&validator, &document, &format!("the response to {name}"));
    }
}

#[test]
fn an_error_response_without_a_result_satisfies_the_schema() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::RESPONSE, &registry);
    let resolver = FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"));
    let context = ExecutionContext::new(&resolver);

    let outcome = Router::execute(
        &RequestEnvelope::read(amiga_operations::OperationRequestDocument::SourceSurvey(
            amiga_operations::SourceSurveyArguments::new("fixtures/absent.bin"),
        )),
        &context,
    );
    let document =
        serde_json::to_value(ResponseEnvelope::from_outcome(&outcome, None)).expect("serializes");

    assert_valid(&validator, &document, "an error response");
    assert!(document.get("result").is_none());
}

#[test]
fn the_response_schema_binds_status_to_what_the_response_carries() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::RESPONSE, &registry);

    // Guards the conditional itself: without these, `allOf`/`if` could be a
    // no-op and every "valid" assertion above would still pass.
    let success_without_result = json!({
        "protocol_version": PROTOCOL_VERSION,
        "operation": "source.survey",
        "status": "success",
        "diagnostics": []
    });
    assert!(
        validator.validate(&success_without_result).is_err(),
        "a success must carry the result it claims to have produced"
    );

    let error_with_invalid_result = json!({
        "protocol_version": PROTOCOL_VERSION,
        "operation": "container.adf.list",
        "status": "error",
        "diagnostics": [
            { "code": "SOURCE_MISSING", "severity": "error", "message": "gone" }
        ],
        "result": { "unexpected": true }
    });
    assert!(
        validator.validate(&error_with_invalid_result).is_err(),
        "an error's retained result must still match its operation"
    );

    let error_without_an_error_diagnostic = json!({
        "protocol_version": PROTOCOL_VERSION,
        "operation": "source.survey",
        "status": "error",
        "diagnostics": [
            { "code": "LIMIT_REDUCED", "severity": "warning", "message": "reduced" }
        ]
    });
    assert!(
        validator
            .validate(&error_without_an_error_diagnostic)
            .is_err(),
        "a failure must say why it failed"
    );
}

#[test]
fn the_schema_refuses_what_the_code_refuses() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::REQUEST, &registry);

    let cases: Vec<(&str, Value)> = vec![
        (
            "an unknown argument",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "request": {
                    "operation": "source.survey",
                    "arguments": {
                        "source": { "kind": "file", "path": "sample.bin" },
                        "min_string": 6
                    }
                }
            }),
        ),
        (
            "an unknown operation",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "request": { "operation": "source.divine", "arguments": {} }
            }),
        ),
        (
            "an absolute source path",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "request": {
                    "operation": "source.survey",
                    "arguments": { "source": { "kind": "file", "path": "/etc/passwd" } }
                }
            }),
        ),
        (
            "a zero result cap",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "request": {
                    "operation": "source.survey",
                    "arguments": {
                        "source": { "kind": "file", "path": "sample.bin" },
                        "maximum_regions": 0
                    }
                }
            }),
        ),
        (
            "a future protocol version",
            json!({
                "protocol_version": PROTOCOL_VERSION + 1,
                "request": {
                    "operation": "source.survey",
                    "arguments": { "source": { "kind": "file", "path": "sample.bin" } }
                }
            }),
        ),
        (
            "a commit without the plan digest it was authorized against",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "execution": { "mode": { "kind": "commit_reviewed" } },
                "request": {
                    "operation": "container.adf.list",
                    "arguments": { "source": { "kind": "file", "path": "volume.adf" } }
                }
            }),
        ),
    ];

    for (what, document) in cases {
        assert!(
            validator.validate(&document).is_err(),
            "the schema accepts {what}, which the code refuses"
        );
        // And the Rust types refuse it too, or refuse it at normalization.
        let parsed = serde_json::from_value::<RequestEnvelope>(document);
        if let Ok(envelope) = parsed {
            let resolver = FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"));
            let context = ExecutionContext::new(&resolver);
            let outcome = Router::execute(&envelope, &context);
            assert_eq!(
                outcome.exit_code(),
                2,
                "{what} parsed, so normalization must refuse it as an invalid request"
            );
        }
    }
}

#[test]
fn a_source_name_the_schema_accepts_may_still_be_refused_by_the_resolver() {
    // The schema bounds the shape; the code enforces the semantics. A `..`
    // component is well-shaped and still refused, which is exactly the split
    // the schema documentation claims.
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::REQUEST, &registry);

    let document = json!({
        "protocol_version": PROTOCOL_VERSION,
        "request": {
            "operation": "source.survey",
            "arguments": { "source": { "kind": "file", "path": "../secret.bin" } }
        }
    });
    assert!(validator.validate(&document).is_ok());

    let envelope: RequestEnvelope = serde_json::from_value(document).expect("it parses");
    let resolver = FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"));
    let outcome = Router::execute(&envelope, &ExecutionContext::new(&resolver));
    assert_eq!(outcome.exit_code(), 2);
}

/// The generated operation reference, checked in so a reader outside the build
/// can consult it and so a drift is a failing test rather than a stale file.
///
/// This is not documentation *about* the catalog; it is rendered from it. The
/// test therefore proves only one thing, which is the thing worth proving: the
/// file on disk is what the current catalog and schemas produce.
#[test]
fn the_checked_in_operation_reference_matches_the_catalog() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/operations.md")
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!("docs/operations.md is missing (run with UPDATE_GOLDEN=1 to create it): {error}")
        });
    let actual = amiga_operations::reference::markdown();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &actual).expect("the reference is writable");
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("the reference is readable");
    assert_eq!(
        actual, expected,
        "docs/operations.md is stale (run with UPDATE_GOLDEN=1 after auditing the change)"
    );
}

/// No argument row sends the reader to a schema URL instead of describing the
/// argument.
///
/// Deduplicating the schemas replaced real prose with a `$ref`, and the
/// renderer used to print the reference itself — a URL that is published
/// nowhere. Resolving it is what makes deduplication free for a reader. The
/// `$id` bullets above each table are deliberately not covered: those cite the
/// identity a consumer would resolve, which is the one place the URL belongs.
#[test]
fn no_argument_row_of_the_reference_cites_a_schema_url() {
    let reference = amiga_operations::reference::markdown();
    for line in reference.lines().filter(|line| line.starts_with('|')) {
        assert!(
            !line.contains("amiga-re.invalid"),
            "an argument row cites a schema URL instead of the constraint: {line}"
        );
    }
}

/// Every argument the catalog serves is described somewhere.
///
/// A resolved `$ref` covers the shared definitions; this covers the rest. A
/// blank description cell reads as "nothing to say about this argument" rather
/// than "nobody wrote one", and a reference generated from the schemas can only
/// be as complete as they are.
#[test]
fn every_argument_of_every_operation_is_described() {
    let reference = amiga_operations::reference::markdown();
    for line in reference.lines().filter(|line| line.starts_with("| `")) {
        assert!(
            !line.ends_with("| — |"),
            "an argument is documented nowhere: {line}"
        );
    }
}

/// A `$ref`'d argument reads exactly as the definition it points at, including
/// the enumerated values, and a `default` written beside the `$ref` still wins.
#[test]
fn a_shared_definition_renders_as_if_it_had_been_written_inline() {
    let reference = amiga_operations::reference::markdown();
    assert!(
        reference.contains(
            "| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright"
        ),
        "the shared cap's description and the operation's own default should both appear"
    );
    assert!(
        reference.contains(
            "| `policy` | `create_only` \\| `replace_matching_provenance` \
             \\| `replace_explicit_generated` |"
        ),
        "an enumerated argument should list the values it accepts"
    );
}

/// No request schema spells out a shared sandbox argument shape of its own.
///
/// The seven shapes below appeared inline in eleven request schemas — the seed
/// alone was about a hundred lines and appeared eight times, twice within
/// `matrix` because a case repeats it. A rule added to one copy and not the
/// others is invisible in review, and these are the published contract: the
/// catalog tests catch drift between a schema and the code, and can catch none
/// between two schemas. So the shapes live in `common.schema.json` and every
/// site `$ref`s one, and this is what stops the eleventh copy coming back.
///
/// The property may keep its own `description`, `type` and caps — an operation
/// says what *its* list of seeds is for — but the item shape must be a bare
/// `$ref`, since that is where the hundred lines were.
#[test]
fn no_request_schema_carries_its_own_copy_of_a_shared_sandbox_shape() {
    /// The property name, whether the shared part is the array's `items` or the
    /// whole property, and the definition it must name.
    const SHARED: [(&str, bool, &str); 7] = [
        ("memory_seeds", true, "memorySeed"),
        ("memory_exports", true, "memoryExport"),
        ("interrupts", true, "scheduledInterrupt"),
        ("watch", true, "watchRange"),
        ("hunk_bases", true, "hunkBase"),
        ("custom_chips", false, "customChips"),
        ("stack", false, "stackRegion"),
    ];

    fn visit(node: &Value, schema: &str, seen: &mut usize) {
        match node {
            Value::Object(fields) => {
                if let Some(Value::Object(properties)) = fields.get("properties") {
                    for (name, is_items, definition) in SHARED {
                        let Some(property) = properties.get(name) else {
                            continue;
                        };
                        let shared = if is_items {
                            property.get("items")
                        } else {
                            Some(property)
                        };
                        *seen += 1;
                        assert_eq!(
                            shared.and_then(|value| value.get("$ref")),
                            Some(&json!(format!(
                                "https://amiga-re.invalid/schemas/operations/v1/\
                                 common.schema.json#/$defs/{definition}"
                            ))),
                            "{schema} spells {name:?} out instead of naming {definition}"
                        );
                    }
                }
                for value in fields.values() {
                    visit(value, schema, seen);
                }
            }
            Value::Array(items) => {
                for value in items {
                    visit(value, schema, seen);
                }
            }
            _ => {}
        }
    }

    let common = parse(amiga_operations::descriptor::schemas::COMMON);
    for (_, _, definition) in SHARED {
        assert!(
            common["$defs"][definition].is_object(),
            "common.schema.json defines {definition}"
        );
    }

    let mut seen = 0;
    for described in catalog() {
        let schema = parse(described.request_schema);
        visit(&schema, described.name.as_str(), &mut seen);
    }
    // Stated so that a refactor which stopped *finding* the sites would fail
    // here rather than pass by walking nothing.
    assert_eq!(seen, 73, "the shared shapes are used this many times");
}

/// Current workflows are documented; the configuration importer is omitted.
/// Every other catalog operation must retain its reference section.
#[test]
fn the_reference_documents_current_workflows() {
    let reference = amiga_operations::reference::markdown();
    for descriptor in amiga_operations::catalog() {
        assert!(
            reference.contains(&format!("## `{}`", descriptor.name.as_str()))
                == (descriptor.name != OperationName::ProjectMigrate),
            "{} has incorrect reference visibility",
            descriptor.name.as_str()
        );
    }
    let sections = reference.matches("\n## `").count();
    assert_eq!(sections, amiga_operations::catalog().len() - 1);
    assert!(!reference.to_ascii_lowercase().contains("migrat"));
}

#[test]
fn every_reference_catalog_link_has_one_explicit_target() {
    let reference = amiga_operations::reference::markdown();
    let mut links = 0;
    for line in reference.lines().filter(|line| line.starts_with("| [`")) {
        let target = line.split("](#").nth(1).unwrap().split(')').next().unwrap();
        assert_eq!(
            reference
                .matches(&format!("<a id=\"{target}\"></a>"))
                .count(),
            1,
            "catalog link {target} must resolve to exactly one explicit anchor"
        );
        links += 1;
    }
    assert_eq!(links, catalog().len() - 1);
}

#[test]
fn sandbox_step_descriptions_match_the_host_limits() {
    use amiga_operations::limits::{DEFAULT_MAXIMUM_SANDBOX_STEPS, MAXIMUM_SANDBOX_STEPS_CEILING};

    let mut checked = 0;
    for descriptor in catalog() {
        let schema = parse(descriptor.request_schema);
        let Some(property) = schema.pointer("/properties/arguments/properties/maximum_steps")
        else {
            continue;
        };
        let description = property["description"].as_str().unwrap();
        assert!(
            description.contains(&format!("{DEFAULT_MAXIMUM_SANDBOX_STEPS} by default"))
                && description.contains(&format!("at most {MAXIMUM_SANDBOX_STEPS_CEILING} ")),
            "{} must describe the current host step limits",
            descriptor.name.as_str()
        );
        checked += 1;
    }
    assert!(checked > 0);
}

/// Every event the router actually produces satisfies the bundled event schema.
///
/// The negative half matters more than the positive one: a schema that accepted
/// anything would pass the first assertion, so this also proves the schema
/// refuses an event with no `event` tag and one whose tag it does not know.
#[test]
fn every_event_the_router_produces_satisfies_the_bundled_event_schema() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::EVENT, &registry);

    let resolver = amiga_operations::FilesystemSourceResolver::new(env!("CARGO_MANIFEST_DIR"));
    let context = amiga_operations::ExecutionContext::new(&resolver);
    let mut sink = amiga_operations::CollectingSink::default();
    let _ = amiga_operations::Router::execute_with_events(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::ContainerAdfList(
                amiga_operations::AdfListArguments::new("fixtures/volume.adf"),
            ),
        ),
        &context,
        &mut sink,
    );
    assert!(!sink.events().is_empty());
    for event in sink.events() {
        let document = serde_json::to_value(event).expect("an event serializes");
        assert_valid(&validator, &document, "an event");
    }

    // A record with no kind, and one with a kind this build does not define.
    for rejected in [
        json!({ "phase": "scan", "completed": 1 }),
        json!({ "event": "invented", "phase": "scan" }),
        // Right kind, missing the field that kind requires.
        json!({ "event": "progress", "completed": 1 }),
    ] {
        assert!(
            validator.validate(&rejected).is_err(),
            "the event schema accepted {rejected}"
        );
    }
}

/// The truncation notice is part of the contract, not an implementation detail:
/// a consumer must be able to recognize a capped stream.
#[test]
fn the_event_schema_describes_the_truncation_notice() {
    let registry = registry();
    let validator = validator_for(amiga_operations::descriptor::schemas::EVENT, &registry);
    assert_valid(
        &validator,
        &json!({ "event": "truncated", "emitted": amiga_operations::MAX_EVENTS }),
        "a truncation notice",
    );
}

#[test]
fn response_envelope_discriminators_and_schemas_match_the_complete_catalog() {
    let schema = parse(amiga_operations::descriptor::schemas::RESPONSE);
    for item in catalog() {
        assert_eq!(
            serde_json::to_value(item.name).unwrap(),
            json!(item.name.as_str())
        );
    }
    let names: Vec<_> = catalog().iter().map(|item| item.name.as_str()).collect();
    assert_eq!(schema["properties"]["operation"]["enum"], json!(names));
    let expected: Vec<_> = catalog()
        .iter()
        .map(|item| {
            json!({
                "properties": {
                    "operation": { "const": item.name.as_str() },
                    "result": { "$ref": schema_id(&parse(item.response_schema)) }
                }
            })
        })
        .collect();
    assert_eq!(
        schema["oneOf"],
        json!(expected),
        "every result must be selected by the operation discriminator"
    );
}
