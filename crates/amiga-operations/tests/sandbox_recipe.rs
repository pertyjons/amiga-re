//! Project sandbox derivations recover named bytes from pinned inputs.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use amiga_operations::sandbox_recipe::SandboxRecipe;
use amiga_operations::{ContainerRecovery, OperationLimits, RequestEnvelope, Selector};
use amiga_project::Recover;
use serde_json::{Value, json};

fn image() -> Vec<u8> {
    // MOVE.L (A0),D0; ADDQ.L #1,D0; MOVE.L D0,(A1); RTS.
    let code = [0x20, 0x10, 0x52, 0x80, 0x22, 0x80, 0x4e, 0x75];
    let mut bytes = Vec::new();
    for word in [1011_u32, 0, 1, 0, 0, 2, 1001, 2] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&1010_u32.to_be_bytes());
    bytes
}

fn request(origin: u32, ram: u32) -> RequestEnvelope {
    serde_json::from_value(json!({
        "protocol_version": 1,
        "request": { "operation": "env.sandbox.call", "arguments": {
            "source": { "kind": "file", "path": "program" },
            "hunk": 0, "load_origin": origin, "entry_offset": 0,
            "stack": { "base": 0x100000, "size": 4096 }, "maximum_steps": 100,
            "address_registers": [ram, ram + 4, 0, 0, 0, 0, 0],
            "mapped_regions": [{ "address": ram, "size": 8 }],
            "memory_seeds": [{ "address": ram, "from": {
                "source": { "kind": "file", "path": "seed" }, "offset": 0, "length": 4
            }}],
            "memory_exports": [
                { "name": "result.bin", "address": ram + 4, "length": 4 },
                { "name": "input.bin", "address": ram, "length": 4 }
            ]
        }}
    }))
    .unwrap()
}

fn recipe(origin: u32, ram: u32) -> Vec<u8> {
    serde_json::to_vec(
        &SandboxRecipe::new(request(origin, ram), OperationLimits::default()).unwrap(),
    )
    .unwrap()
}

fn selector(export: &str) -> Selector {
    Selector::Sandbox {
        export: export.to_owned(),
        inputs: BTreeMap::from([
            ("program".to_owned(), "source:program".to_owned()),
            ("seed".to_owned(), "object:seed".to_owned()),
        ]),
    }
}

fn recover(bytes: &[u8], export: &str) -> Result<Vec<u8>, String> {
    ContainerRecovery::default().recover_with_inputs(
        &selector(export),
        bytes,
        &BTreeMap::from([
            ("program", image().as_slice()),
            ("seed", [0, 0, 0, 41].as_slice()),
        ]),
    )
}

#[test]
fn export_identity_survives_relocation_and_repeated_runs() {
    for (origin, ram) in [(0x20000, 0x30000), (0x40000, 0x50000)] {
        let recipe = recipe(origin, ram);
        assert_eq!(recover(&recipe, "result.bin").unwrap(), [0, 0, 0, 42]);
        assert_eq!(recover(&recipe, "result.bin").unwrap(), [0, 0, 0, 42]);
        assert_eq!(recover(&recipe, "input.bin").unwrap(), [0, 0, 0, 41]);
        assert!(
            recover(&recipe, "absent.bin")
                .unwrap_err()
                .contains("no export")
        );
    }
}

#[test]
fn malformed_and_reinterpreted_recipes_are_refused() {
    let original: Value = serde_json::from_slice(&recipe(0x20000, 0x30000)).unwrap();
    for (pointer, value, reason) in [
        ("/recipe_version", json!(2), "unsupported"),
        ("/execution_version", json!(2), "unsupported"),
        (
            "/normalized_request_sha256",
            json!("0".repeat(64)),
            "digest changed",
        ),
        (
            "/request/request/arguments/maximum_steps",
            json!(101),
            "digest changed",
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            recover(&serde_json::to_vec(&changed).unwrap(), "result.bin")
                .unwrap_err()
                .contains(reason)
        );
    }
    let mut unknown = original;
    unknown["request"]["request"]["arguments"]["future_cpu"] = json!("68020");
    assert!(recover(&serde_json::to_vec(&unknown).unwrap(), "result.bin").is_err());
    assert!(recover(b"{}", "result.bin").is_err());
    assert!(
        recover(&vec![b' '; 1024 * 1024 + 1], "result.bin")
            .unwrap_err()
            .contains("1 MiB")
    );
}

#[test]
fn budgets_apply_before_execution_and_cache_reuses_all_named_exports() {
    let program = image();
    let inputs = BTreeMap::from([
        ("program", program.as_slice()),
        ("seed", [0, 0, 0, 41].as_slice()),
    ]);
    let bytes = recipe(0x20000, 0x30000);
    // Changing the context's instruction ceiling does not silently clip a frozen recipe.
    let small =
        ContainerRecovery::from_limits(OperationLimits::default().with_maximum_sandbox_steps(99));
    assert!(
        small
            .recover_with_inputs(&selector("result.bin"), &bytes, &inputs)
            .is_err()
    );
    let one_call =
        ContainerRecovery::from_limits(OperationLimits::default().with_maximum_sandbox_steps(100));
    assert_eq!(
        one_call
            .recover_with_inputs(&selector("result.bin"), &bytes, &inputs)
            .unwrap(),
        [0, 0, 0, 42]
    );
    assert_eq!(
        one_call
            .recover_with_inputs(&selector("input.bin"), &bytes, &inputs)
            .unwrap(),
        [0, 0, 0, 41]
    );
    assert!(
        one_call
            .recover_with_inputs(&selector("result.bin"), &recipe(0x40000, 0x30000), &inputs)
            .unwrap_err()
            .contains("shared instruction budget")
    );
    let small_output = ContainerRecovery::new(7);
    assert!(
        small_output
            .recover_with_inputs(&selector("result.bin"), &bytes, &inputs)
            .unwrap_err()
            .contains("output byte budget")
    );
    let mut oversized = request(0x20000, 0x30000);
    let amiga_operations::OperationRequestDocument::EnvSandboxCall(call) = &mut oversized.request
    else {
        unreachable!()
    };
    call.mapped_regions[0].size = 65 * 1024 * 1024;
    let oversized =
        serde_json::to_vec(&SandboxRecipe::new(oversized, OperationLimits::default()).unwrap())
            .unwrap();
    assert!(
        recover(&oversized, "result.bin")
            .unwrap_err()
            .contains("before allocation")
    );
}

fn scratch() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "amiga-sandbox-project-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    root
}

fn write_project(root: &Path) -> Value {
    let mut sources = Vec::new();
    for (name, bytes) in [
        ("program", image()),
        ("seed", vec![0, 0, 0, 41]),
        ("recipe", recipe(0x20000, 0x30000)),
    ] {
        std::fs::write(root.join(name), &bytes).unwrap();
        sources.push(
            json!({"id": format!("source:{name}"), "kind":"file", "display_name":name,
            "size":bytes.len(), "sha256":amiga_core::sha256(&bytes),
            "locations":[{"kind":"project_relative", "path":name}]}),
        );
    }
    std::fs::write(
        root.join("amiga-re.project.json"),
        serde_json::to_vec(&json!({
            "document_kind":"project", "format_version":1,
            "project":{"id":"project:sandbox", "name":"Sandbox derivation"},
            "documents":{"sources":"sources.json"}
        }))
        .unwrap(),
    )
    .unwrap();
    let sources = json!({"document_kind":"sources", "format_version":1, "sources":sources,
    "objects":[
        {"id":"object:result", "kind":"sandbox_export", "parent_id":"source:recipe",
         "selector":selector("result.bin"), "size":4, "sha256":amiga_core::sha256(&[0,0,0,42])},
        {"id":"object:seed", "kind":"byte_range", "parent_id":"source:seed",
         "selector":{"container":"range", "offset":0, "length":4}, "size":4,
         "sha256":amiga_core::sha256(&[0,0,0,41])}
    ]});
    write_sources(root, &sources);
    sources
}

fn write_sources(root: &Path, sources: &Value) {
    std::fs::write(
        root.join("sources.json"),
        serde_json::to_vec_pretty(sources).unwrap(),
    )
    .unwrap();
}

#[test]
fn project_verification_resolves_dependencies_checks_content_and_refuses_corrupt_inputs() {
    let root = scratch();
    write_project(&root);
    let loaded = amiga_project::load(&root).unwrap();
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    let bindings = amiga_project::Bindings::new(&root);
    let bytes = amiga_project::verify::recover_object(
        &loaded.project,
        &bindings,
        &ContainerRecovery::default(),
        "object:result",
    )
    .unwrap();
    assert_eq!(bytes, [0, 0, 0, 42]);
    std::fs::write(root.join("seed"), [0, 0, 0, 99]).unwrap();
    let report = amiga_project::verify(&loaded.project, &bindings, &ContainerRecovery::default());
    assert!(report.contradicted());
    assert_eq!(
        report.objects["object:result"],
        amiga_project::verify::ObjectStatus::ParentUnavailable
    );
}

#[test]
fn graph_validation_rejects_missing_inputs_cycles_and_unsafe_names() {
    for (key, value, expected) in [
        (
            "seed",
            "object:absent",
            amiga_project::ProblemCode::UnresolvedReference,
        ),
        (
            "seed",
            "object:result",
            amiga_project::ProblemCode::DerivationCycle,
        ),
    ] {
        let root = scratch();
        let mut sources = write_project(&root);
        sources["objects"][0]["selector"]["inputs"][key] = json!(value);
        write_sources(&root, &sources);
        let amiga_project::LoadError::Invalid(problems) = amiga_project::load(&root).unwrap_err()
        else {
            panic!("expected invalid graph")
        };
        assert!(problems.iter().any(|p| p.code == expected), "{problems:?}");
    }
    let root = scratch();
    let mut sources = write_project(&root);
    sources["objects"][0]["selector"]["export"] = json!("../outside");
    write_sources(&root, &sources);
    assert!(amiga_project::load(&root).is_err());
}

#[test]
fn private_project_recipes_verify_when_explicitly_configured() {
    let Some(root) = std::env::var_os("AMIGA_RE_SANDBOX_PROJECT") else {
        eprintln!("skipping private sandbox project: AMIGA_RE_SANDBOX_PROJECT is unset");
        return;
    };
    let root = PathBuf::from(root);
    let loaded = amiga_project::load(&root).unwrap();
    assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
    assert!(
        loaded
            .project
            .sources
            .objects
            .iter()
            .any(|o| matches!(o.selector, Some(Selector::Sandbox { .. })))
    );
    let report = amiga_project::verify(
        &loaded.project,
        &amiga_project::Bindings::new(&root),
        &ContainerRecovery::default(),
    );
    assert!(
        report
            .sources
            .values()
            .all(amiga_project::verify::SourceStatus::is_verified),
        "{:?}",
        report.sources
    );
    assert!(
        report
            .objects
            .values()
            .all(amiga_project::verify::ObjectStatus::is_verified),
        "{:?}",
        report.objects
    );
}

#[test]
fn missing_external_seeds_and_nonreturning_calls_cannot_verify() {
    let program = image();
    let recipe = recipe(0x20000, 0x30000);
    let mut only_program = selector("result.bin");
    let Selector::Sandbox { inputs, .. } = &mut only_program else {
        unreachable!()
    };
    inputs.remove("seed");
    assert!(
        ContainerRecovery::default()
            .recover_with_inputs(
                &only_program,
                &recipe,
                &BTreeMap::from([("program", program.as_slice())])
            )
            .is_err()
    );
    let mut loop_program = program;
    loop_program[32..34].copy_from_slice(&[0x60, 0xfe]); // BRA to itself.
    let inputs = BTreeMap::from([
        ("program", loop_program.as_slice()),
        ("seed", [0, 0, 0, 41].as_slice()),
    ]);
    assert!(
        ContainerRecovery::default()
            .recover_with_inputs(&selector("result.bin"), &recipe, &inputs)
            .unwrap_err()
            .contains("did not return")
    );
}

#[test]
fn project_output_size_and_digest_are_checked_after_execution() {
    for (field, value) in [("size", json!(5)), ("sha256", json!("0".repeat(64)))] {
        let root = scratch();
        let mut sources = write_project(&root);
        sources["objects"][0][field] = value;
        write_sources(&root, &sources);
        let loaded = amiga_project::load(&root).unwrap();
        let report = amiga_project::verify(
            &loaded.project,
            &amiga_project::Bindings::new(&root),
            &ContainerRecovery::default(),
        );
        assert!(!report.objects["object:result"].is_verified());
        assert!(report.objects["object:result"].contradicts());
    }
}

#[test]
fn recipe_schema_resolves_offline_and_reuses_the_call_vocabulary() {
    let mut documents = Vec::new();
    for (_, text) in amiga_operations::descriptor::schemas::ALL {
        let schema: Value = serde_json::from_str(text).unwrap();
        documents.push((schema["$id"].as_str().unwrap().to_owned(), schema));
    }
    for operation in amiga_operations::catalog() {
        for text in [operation.request_schema, operation.response_schema] {
            let schema: Value = serde_json::from_str(text).unwrap();
            documents.push((schema["$id"].as_str().unwrap().to_owned(), schema));
        }
    }
    let registry = jsonschema::Registry::new()
        .extend(documents)
        .unwrap()
        .prepare()
        .unwrap();
    let schema: Value =
        serde_json::from_str(amiga_operations::descriptor::schemas::SANDBOX_RECIPE).unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    let mut value: Value = serde_json::from_slice(&recipe(0x20000, 0x30000)).unwrap();
    assert!(
        validator.is_valid(&value),
        "{:?}\n{}",
        validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect::<Vec<_>>(),
        value
    );
    value["request"]["request"]["arguments"]["future_cpu"] = json!("68020");
    assert!(!validator.is_valid(&value));
}

#[test]
fn freezing_json_refuses_unknown_execution_inputs() {
    let mut value = serde_json::to_value(request(0x20000, 0x30000)).unwrap();
    let freeze = |v: &Value| {
        SandboxRecipe::from_request_json(
            &serde_json::to_vec(v).unwrap(),
            OperationLimits::default(),
        )
    };
    assert!(freeze(&value).is_ok());
    value["request"]["arguments"]["future_cpu"] = json!("68020");
    assert!(freeze(&value).is_err());
}

#[test]
fn request_envelope_names_every_catalog_operation_exactly_once() {
    let schema: Value =
        serde_json::from_str(amiga_operations::descriptor::schemas::REQUEST).unwrap();
    let actual: std::collections::BTreeSet<_> = schema["properties"]["request"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["$ref"].as_str().unwrap().to_owned())
        .collect();
    let expected: std::collections::BTreeSet<_> = amiga_operations::catalog()
        .iter()
        .map(|operation| {
            let schema: Value = serde_json::from_str(operation.request_schema).unwrap();
            schema["$id"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        actual.len(),
        schema["properties"]["request"]["oneOf"]
            .as_array()
            .unwrap()
            .len()
    );
}

#[test]
fn project_recipe_replay_uses_the_shared_context_ram_limit() {
    let recipe = recipe(0x20000, 0x30000);
    let program = image();
    let inputs = BTreeMap::from([
        ("program", program.as_slice()),
        ("seed", [0, 0, 0, 41].as_slice()),
    ]);
    let recovery = ContainerRecovery::from_limits(
        OperationLimits::default().with_maximum_sandbox_memory_bytes(4096),
    );
    let error = recovery
        .recover_with_inputs(&selector("result.bin"), &recipe, &inputs)
        .unwrap_err();
    assert!(error.contains("before allocation"), "{error}");
}

#[test]
fn bounded_recovery_refuses_actual_decoder_output_and_cached_exports() {
    let recovery = ContainerRecovery::default();
    let packed = [0x81, 42]; // ByteRun1: 128 identical bytes.
    let compressed_selector = Selector::Decompressed {
        codec: amiga_project::document::Codec::ByteRun1 {},
        declared_size: None,
    };
    assert!(
        recovery
            .recover_bounded(&compressed_selector, &packed, &BTreeMap::new(), 8)
            .is_err()
    );
    assert_eq!(
        recovery
            .recover_bounded(&compressed_selector, &packed, &BTreeMap::new(), 128)
            .unwrap(),
        vec![42; 128]
    );
    let program = image();
    let inputs = BTreeMap::from([
        ("program", program.as_slice()),
        ("seed", [0, 0, 0, 41].as_slice()),
    ]);
    let recipe = recipe(0x20000, 0x30000);
    assert_eq!(
        recovery
            .recover_bounded(&selector("result.bin"), &recipe, &inputs, 8)
            .unwrap(),
        [0, 0, 0, 42]
    );
    assert!(
        recovery
            .recover_bounded(&selector("result.bin"), &recipe, &inputs, 7)
            .unwrap_err()
            .contains("cached sandbox exports")
    );
}
