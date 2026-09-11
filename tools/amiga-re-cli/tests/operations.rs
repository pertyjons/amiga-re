//! The structured operation boundary: `operations`, `operations run`, `schema`.
//!
//! These tests are about *framing*, not about what the operations compute —
//! `crates/amiga-operations` owns that. What matters here is that automation
//! can rely on the shape: one document on standard output in `json` mode, one
//! self-describing record per line in `jsonl` mode, exit codes that separate a
//! bad request from a failed operation, and convenience wrappers that reach the
//! same handler with the same defaults.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn amiga_re() -> Command {
    Command::new(env!("CARGO_BIN_EXE_amiga-re"))
}

/// The operations crate root. Its `fixtures/` are live test data rather than
/// copies — a request document there and one here would drift — and the
/// checked-in requests name their sources as `fixtures/...`, so this, not the
/// fixtures directory, is the root those identities resolve against.
fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the operations crate is readable: {error}"))
}

/// Run a command from that root, since a request names its source by identity
/// and the adapter resolves those against the working directory.
fn run(args: &[&str]) -> std::process::Output {
    amiga_re()
        .args(args)
        .current_dir(crate_root())
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"))
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone())
        .unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

#[test]
fn the_catalog_listing_names_every_operation_in_both_framings() {
    let text = run(&["operations"]);
    assert!(text.status.success());
    let listing = stdout_of(&text);
    for operation in ["source.survey", "container.adf.list"] {
        assert!(
            listing.contains(operation),
            "{operation} is not listed:\n{listing}"
        );
    }

    let json = run(&["operations", "--response", "json"]);
    assert!(json.status.success());
    let document: serde_json::Value = serde_json::from_str(&stdout_of(&json))
        .unwrap_or_else(|error| panic!("the listing is not valid JSON: {error}"));
    let names: Vec<&str> = document["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["operation"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "source.survey",
            "container.adf.list",
            "graphics.bitmap.decode",
            "container.adf.extract",
            "container.lha.extract",
            "graphics.bitmap.export",
            "project.check",
            "project.verify",
            "analysis.hunk.diff",
            "analysis.hunk.diff.export",
            "source.carve",
            "analysis.table.decode",
            "analysis.table.summarize",
            "audio.sample.decode",
            "audio.sample.export",
            "compress.powerpacker.decode",
            "compress.powerpacker.export",
            "compress.rle-xor.decode",
            "compress.rle-xor.export",
            "audio.pcm.decode",
            "audio.pcm.export",
            "audio.module.decode",
            "audio.module.export",
            "analysis.hunk.normalize",
            "analysis.hunk.normalize.export",
            "provenance.manifest",
            "provenance.manifest.export",
            "graphics.palette.decode",
            "graphics.palette.export",
            "env.sandbox.run",
            "env.boot.info",
            "env.sandbox.call",
            "env.sandbox.call.export",
            "env.boot.trace",
            "env.boot.trace.export",
            "analysis.hunk.list",
            "analysis.strings.scan",
            "analysis.address.resolve",
            "analysis.pointers.scan",
            "analysis.code.disassemble",
            "analysis.address.references",
            "analysis.code.callgraph",
            "analysis.code.globals",
            "analysis.code.fixed-point",
            "container.lha.list",
            "hardware.register.list",
            "audio.pcm.scan",
            "audio.module.scan",
            "graphics.palette.scan",
            "hardware.copper.scan",
            "hardware.copper.decode",
            "graphics.ilbm.decode",
            "graphics.bitmap.detect",
            "hardware.register.references",
            "hardware.copper.references",
            "project.describe",
            "project.annotations",
            "project.inventory",
            "project.edit",
            "project.format",
            "project.migrate",
            "analysis.code.facts",
            "source.read",
            "project.init",
            "project.extract",
            "project.resource.export",
            "env.sandbox.matrix",
            "env.sandbox.compare",
            "env.sandbox.matrix.export",
            "env.sandbox.timeline",
            "analysis.state.snapshot",
            "analysis.state.compare",
            "env.frame.capture",
            "env.frame.capture.export",
            "graphics.bitmap.compare",
            "graphics.bitmap.compare.export",
            "env.sandbox.slice",
            "env.sandbox.timeline.export"
        ]
    );
    // Access class travels with the name: a caller deciding whether an
    // operation may write must not have to look it up elsewhere.
    assert_eq!(document["operations"][0]["access"], "read_only");

    // The subcommand form is the same command, so it must not answer
    // differently.
    let via_subcommand = run(&["operations", "list", "--response", "json"]);
    assert_eq!(stdout_of(&via_subcommand), stdout_of(&json));
}

#[test]
fn every_bundled_schema_is_printable_and_is_valid_json() {
    // With no operation named, the envelope is what a caller writes.
    for kind in ["request", "response"] {
        let output = run(&["schema", "--kind", kind]);
        assert!(output.status.success(), "schema --kind {kind} failed");
        let document: serde_json::Value = serde_json::from_str(&stdout_of(&output))
            .unwrap_or_else(|error| panic!("the {kind} envelope schema is not JSON: {error}"));
        assert!(document["$id"].is_string());
    }

    for operation in [
        "source.survey",
        "container.adf.list",
        "graphics.bitmap.decode",
        "container.adf.extract",
        "container.lha.extract",
        "graphics.bitmap.export",
        "project.check",
        "project.verify",
    ] {
        for kind in ["request", "response"] {
            let output = run(&["schema", operation, "--kind", kind]);
            assert!(
                output.status.success(),
                "schema {operation} --kind {kind} failed"
            );
            let document: serde_json::Value = serde_json::from_str(&stdout_of(&output))
                .unwrap_or_else(|error| panic!("{operation} {kind} schema is not JSON: {error}"));
            assert!(
                document["$id"]
                    .as_str()
                    .unwrap_or_default()
                    .contains(operation),
                "{operation} {kind} schema has the wrong identity: {document}"
            );
        }
    }
}

#[test]
fn an_unknown_operation_is_refused_and_the_catalog_is_offered() {
    let output = run(&["schema", "container.adf.nope"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown operation"), "{stderr}");
    assert!(
        stderr.contains("container.adf.list"),
        "the error does not say what this build does serve: {stderr}"
    );
}

#[test]
fn json_mode_writes_exactly_one_document_on_standard_output() {
    let output = run(&[
        "operations",
        "run",
        "--request",
        "fixtures/container.adf.list.request.json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let document: serde_json::Value = serde_json::from_str(&stdout_of(&output))
        .unwrap_or_else(|error| panic!("standard output is not one JSON document: {error}"));
    assert_eq!(document["status"], "success");
    assert_eq!(document["operation"], "container.adf.list");
    assert_eq!(document["request_id"], "request:list-volume");
    assert!(document["normalized_request_sha256"].is_string());
    assert_eq!(document["result"]["volume"]["name"], "AmigaRe");
}

#[test]
fn jsonl_mode_tags_every_line_and_ends_with_the_response() {
    let output = run(&[
        "operations",
        "run",
        "--request",
        "fixtures/container.adf.list.request.json",
        "--response",
        "jsonl",
    ]);
    assert!(output.status.success());
    let lines: Vec<serde_json::Value> = stdout_of(&output)
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("a stream line is not JSON: {error}\n{line}"))
        })
        .collect();
    assert!(lines.len() >= 2, "expected at least accepted + response");

    // Every record says what it is; a consumer never guesses from field
    // accidents, which is what lets later milestones add message kinds.
    for line in &lines {
        assert!(
            line["message_type"].is_string(),
            "a line has no message_type: {line}"
        );
    }
    assert_eq!(lines[0]["message_type"], "accepted");
    assert_eq!(lines[lines.len() - 1]["message_type"], "response");

    // Events arrive strictly between the two, in the order the handler reached
    // its phases, so a consumer may treat the response as the end.
    let events: Vec<&serde_json::Value> = lines[1..lines.len() - 1].iter().collect();
    assert!(!events.is_empty(), "the stream carried no events");
    assert!(
        events.iter().all(|line| line["message_type"] == "event"),
        "something other than an event appeared mid-stream: {events:?}"
    );
    assert_eq!(events[0]["event"], "started");
    let phases: Vec<&str> = events
        .iter()
        .filter(|line| line["event"] == "progress")
        .map(|line| line["phase"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(phases, ["open_volume", "walk_directories"]);
    // Correlation travels with every line, not only with the response.
    assert!(
        events
            .iter()
            .all(|line| line["request_id"] == "request:list-volume"),
        "an event lost the caller's correlation id"
    );
    // The digest is known before the operation runs, and the two agree.
    assert_eq!(
        lines[0]["normalized_request_sha256"],
        lines[lines.len() - 1]["normalized_request_sha256"]
    );
}

#[test]
fn the_two_framings_carry_the_same_final_result() {
    let json = run(&[
        "operations",
        "run",
        "--request",
        "fixtures/container.adf.list.request.json",
    ]);
    let jsonl = run(&[
        "operations",
        "run",
        "--request",
        "fixtures/container.adf.list.request.json",
        "--response",
        "jsonl",
    ]);
    let one: serde_json::Value = serde_json::from_str(&stdout_of(&json)).unwrap();
    let last = stdout_of(&jsonl).lines().last().unwrap().to_owned();
    let mut streamed: serde_json::Value = serde_json::from_str(&last).unwrap();
    // The only difference is the framing tag the stream adds. Events are
    // extra, never a substitute: the final result must be identical.
    assert_eq!(streamed["message_type"], "response");
    streamed
        .as_object_mut()
        .unwrap()
        .remove("message_type")
        .unwrap();
    assert_eq!(one, streamed, "the framings disagree about what happened");
}

#[test]
fn a_request_arrives_the_same_way_through_standard_input() {
    let document = std::fs::read(crate_root().join("fixtures/container.adf.list.request.json"))
        .unwrap_or_else(|error| panic!("the request fixture is readable: {error}"));
    let mut child = amiga_re()
        .args(["operations", "run", "--request", "-"])
        .current_dir(crate_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn amiga-re: {error}"));
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(&document)
        .unwrap_or_else(|error| panic!("failed to write the request: {error}"));
    let piped = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("failed to wait for amiga-re: {error}"));
    assert!(piped.status.success());

    let from_file = run(&[
        "operations",
        "run",
        "--request",
        "fixtures/container.adf.list.request.json",
    ]);
    assert_eq!(stdout_of(&piped), stdout_of(&from_file));
}

#[test]
fn exit_codes_separate_a_bad_request_from_a_failed_operation() {
    let directory = std::env::temp_dir().join(format!("amiga-re-ops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap_or_else(|error| panic!("{error}"));

    let write = |name: &str, body: &str| -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, body).unwrap_or_else(|error| panic!("{error}"));
        path
    };

    // A source that exists but is not a volume: the operation ran and failed.
    let failing = write(
        "failing.json",
        r#"{"protocol_version":1,"request":{"operation":"container.adf.list",
            "arguments":{"source":{"kind":"file","path":"fixtures/sample.bin"}}}}"#,
    );
    let output = run(&[
        "operations",
        "run",
        "--request",
        failing.to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout_of(&output));
    let document: serde_json::Value = serde_json::from_str(&stdout_of(&output)).unwrap();
    assert_eq!(document["status"], "error");
    assert!(document["result"].is_null(), "a failure carried a result");

    // A request the validator refuses before any source is opened.
    let invalid = write(
        "invalid.json",
        r#"{"protocol_version":1,"request":{"operation":"container.adf.list",
            "arguments":{"source":{"kind":"file","path":"../escape.adf"}}}}"#,
    );
    let output = run(&[
        "operations",
        "run",
        "--request",
        invalid.to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an invalid request must be distinguishable from a failed operation: {}",
        stdout_of(&output)
    );

    // A document that is not a request at all is an adapter error, not an
    // operation outcome: there is nothing to report a status about.
    let garbage = write("garbage.json", "not json");
    let output = run(&["operations", "run", "--request", garbage.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(
        stdout_of(&output).is_empty(),
        "a malformed request still wrote to standard output"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn the_convenience_wrapper_and_the_request_reach_the_same_handler() {
    // `adf list` with no flags must behave exactly as a request with no
    // optional arguments: same defaults, same handler, same answer.
    let wrapper = run(&["adf", "list", "fixtures/volume.adf"]);
    assert!(
        wrapper.status.success(),
        "{}",
        String::from_utf8_lossy(&wrapper.stderr)
    );
    let rendered = stdout_of(&wrapper);

    let structured = run(&[
        "operations",
        "run",
        "--request",
        "fixtures/container.adf.list.request.json",
    ]);
    let document: serde_json::Value = serde_json::from_str(&stdout_of(&structured)).unwrap();

    assert!(
        rendered.contains(document["result"]["volume"]["name"].as_str().unwrap()),
        "the wrapper named a different volume:\n{rendered}"
    );
    for entry in document["result"]["entries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        assert!(
            rendered.contains(path),
            "the wrapper omitted {path}, so it is not the same listing:\n{rendered}"
        );
    }
    // The wrapper's tolerated inconsistencies are the response's diagnostics.
    assert_eq!(document["diagnostics"].as_array().unwrap().len(), 2);
    let warnings = String::from_utf8_lossy(&wrapper.stderr);
    assert!(
        warnings.contains("boot block checksum"),
        "the wrapper dropped a diagnostic the response carries: {warnings}"
    );
}

#[test]
fn emitted_schemas_keep_the_layout_their_references_resolve_against() {
    let directory = std::env::temp_dir().join(format!("amiga-re-schemas-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    let output = run(&["schema", "--output", directory.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    for name in [
        "common.schema.json",
        "request.schema.json",
        "response.schema.json",
        "diagnostic.schema.json",
        "operations/source.survey.request.schema.json",
        "operations/container.adf.list.response.schema.json",
    ] {
        let path = directory.join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{name} was not emitted: {error}"));
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"));
    }

    // Emitting into a populated directory needs the same explicit consent
    // every other generated output in this toolkit needs.
    let again = run(&["schema", "--output", directory.to_str().unwrap()]);
    assert!(
        !again.status.success(),
        "an existing set was overwritten silently"
    );
    let forced = run(&["schema", "--output", directory.to_str().unwrap(), "--force"]);
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );

    let _ = std::fs::remove_dir_all(&directory);
}
