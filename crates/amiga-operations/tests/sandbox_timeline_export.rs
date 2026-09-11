//! `env.sandbox.timeline.export`: a timeline's checkpoints, written per step.
//!
//! This is the reconstruction problem one level above `env.sandbox.call.export`.
//! The read-only timeline reports a digest per checkpoint and no bytes — right
//! for a response, since sixty ticks each checkpointing a framebuffer is one
//! nobody can read — and left no way to *get* them: re-running the interesting
//! step through `env.sandbox.call` with an export only works when the step can
//! be reproduced as a standalone call, and a step deep in an evolving timeline
//! cannot, because its inputs are the machine every step before it produced.
//!
//! Two properties make it more than a loop, and both are here. **Nothing is
//! written until every step has run** — which the timeline satisfies more
//! strongly than the sweep does, since the whole request is validated against
//! the map before the first instruction executes. And the manifest records each
//! file's **step and the timeline's own recipe digest**, so a later run can tell
//! its outputs from another's that reused the step names.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, ExecutionMode, FilesystemDestinationResolver, InMemorySourceResolver,
    MemoryExport, OperationRequestDocument, RequestEnvelope, ResolvedSource, Router,
    SandboxCallArguments, SandboxRunArguments, SandboxTimelineArguments,
    SandboxTimelineExportArguments, SourceName, Status, TimelineStep,
};

fn envelope(arguments: SandboxTimelineExportArguments, mode: ExecutionMode) -> RequestEnvelope {
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::EnvSandboxTimelineExport(
        arguments,
    ));
    envelope.execution.mode = mode;
    envelope
}

/// A one-hunk LoadSeg image whose CODE hunk holds `code`.
fn image(code: &[u8], allocation_longwords: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, allocation_longwords] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    let longwords = code.len().div_ceil(4) as u32;
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(code);
    bytes.resize(bytes.len() + (longwords as usize * 4 - code.len()), 0);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

const BUFFER: u32 = 0x10_0000;

/// `ADDQ.W #1,(A0) ; RTS` — increments a word of the shared buffer.
///
/// The whole point of a timeline in one instruction: the second step's
/// checkpoint depends on what the first step left, so a per-step export that
/// re-ran the step in isolation would write the wrong bytes.
fn incrementer() -> InMemorySourceResolver {
    let name = SourceName::parse("game").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(
        name,
        Arc::from(image(&[0x52, 0x50, 0x4e, 0x75], 64)),
    ))
}

fn workspace(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "amiga-timeline-export-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    base
}

fn base() -> SandboxCallArguments {
    let mut run = SandboxRunArguments::new("game")
        .at_origin(0x2_0000)
        .with_maximum_steps(64);
    // Every step that enters inherits this, so each of them finds the buffer
    // where the one before it left off.
    run.address_registers = Some([BUFFER, 0, 0, 0, 0, 0, 0]);
    SandboxCallArguments::new(run).with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: BUFFER,
        size: 64,
    }])
}

fn step(name: &str) -> TimelineStep {
    TimelineStep::call(name, 0).with_checkpoints(vec![MemoryExport {
        address: BUFFER,
        length: 2,
        name: "cell".to_owned(),
    }])
}

fn timeline(steps: Vec<TimelineStep>) -> SandboxTimelineArguments {
    SandboxTimelineArguments::new(base(), steps).with_maximum_total_steps(512)
}

/// Prepare, then commit the plan just prepared.
fn export(
    base_directory: &Path,
    arguments: SandboxTimelineExportArguments,
) -> amiga_operations::OperationOutcome {
    let resolver = incrementer();
    let destinations = FilesystemDestinationResolver::new(base_directory.to_path_buf());
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let prepared = Router::execute(
        &envelope(arguments.clone(), ExecutionMode::Prepare),
        &context,
    );
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let plan = prepared
        .env_sandbox_timeline_export()
        .expect("a prepared plan")
        .plan
        .plan_sha256
        .clone();

    Router::execute(
        &envelope(
            arguments,
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: plan,
            },
        ),
        &context,
    )
}

/// Each step's checkpoint lands under the step's own name, holding the machine
/// as that step left it.
///
/// The two files differ, which is the assertion that matters: it is what says
/// the bytes were taken at each step rather than once at the end, and what a
/// per-step export built by re-running steps in isolation could not produce.
#[test]
fn each_step_writes_its_checkpoints_under_its_own_name() {
    let base_directory = workspace("per-step");
    let outcome = export(
        &base_directory,
        SandboxTimelineExportArguments::new(
            timeline(vec![step("first"), step("second"), step("third")]),
            "timeline",
        ),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let export = outcome
        .env_sandbox_timeline_export()
        .expect("an export result");
    assert!(export.committed);

    let root = base_directory.join("timeline");
    for (step, expected) in [("first", 1_u16), ("second", 2), ("third", 3)] {
        let path = root.join(step).join("cell");
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
        assert_eq!(
            bytes,
            expected.to_be_bytes(),
            "{step} wrote the wrong bytes"
        );
    }
    assert!(root.join("timeline.json").is_file());

    // And the bytes on disk are the bytes the response's digests are over, so a
    // reader can check one against the other without re-running anything.
    for step in &export.result.steps {
        let checkpoint = &step.checkpoints[0];
        let bytes = std::fs::read(root.join(&step.name).join(&checkpoint.name))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            checkpoint.sha256,
            amiga_core::sha256(&bytes),
            "{}",
            step.name
        );
    }
}

/// The manifest names each file's step and the timeline's own recipe digest.
///
/// Without the digest, two runs that reused the step names would write
/// indistinguishable trees: the paths alone say which step produced a file and
/// not which experiment did.
#[test]
fn the_manifest_records_each_file_s_step_and_the_timeline_s_recipe() {
    let base_directory = workspace("manifest");
    let outcome = export(
        &base_directory,
        SandboxTimelineExportArguments::new(
            timeline(vec![step("first"), step("second")]),
            "timeline",
        ),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = &outcome
        .env_sandbox_timeline_export()
        .expect("an export result")
        .result;

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(base_directory.join("timeline/timeline.json.manifest.json"))
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(manifest["base_recipe_sha256"], result.base_recipe_sha256);
    assert_eq!(manifest["steps_ran"], 2);
    let files = manifest["files"].as_array().expect("a file list");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["path"], "first/cell");
    assert_eq!(files[0]["step"], "first");
    assert_eq!(files[0]["checkpoint"], "cell");
    assert_eq!(files[1]["path"], "second/cell");
}

/// Nothing is written when a step could never record its checkpoint, and the
/// refusal is of the *request* rather than of a run that stopped part-way.
///
/// The timeline satisfies this more strongly than a sweep does: the checkpoint
/// range of the *last* step is validated against the map before the first
/// instruction of the first step executes, so there is no window in which some
/// steps have run and a later one turns out to be unrunnable.
#[test]
fn a_checkpoint_outside_the_map_writes_nothing_at_all() {
    let base_directory = workspace("unmapped");
    let resolver = incrementer();
    let destinations = FilesystemDestinationResolver::new(base_directory.clone());
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let unmapped = TimelineStep::call("last", 0).with_checkpoints(vec![MemoryExport {
        address: 0x0f00_0000,
        length: 2,
        name: "nowhere".to_owned(),
    }]);
    let outcome = Router::execute(
        &envelope(
            SandboxTimelineExportArguments::new(
                timeline(vec![step("first"), unmapped]),
                "timeline",
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    let message = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(message.contains("\"last\""), "{message}");
    assert!(message.contains("mapped_regions"), "{message}");
    assert!(
        !base_directory.join("timeline").exists(),
        "a refused request must leave no directory behind"
    );
}
