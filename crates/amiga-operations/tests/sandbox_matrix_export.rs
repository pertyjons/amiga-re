//! `env.sandbox.matrix.export`: a sweep's exported ranges, written per case.
//!
//! Two properties separate this from a loop of `env.sandbox.call.export`, and
//! both are here. **Nothing is written until every case has run** — including
//! when the *last* case is the malformed one, which is the case a loop gets
//! wrong. And the manifest records each file's **case and that case's recipe
//! digest**, so a later sweep can tell its own outputs from another sweep's that
//! happened to reuse the case names.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, ExecutionMode, FilesystemDestinationResolver, InMemorySourceResolver,
    MemoryExport, OperationRequestDocument, RequestEnvelope, ResolvedSource, Router,
    SandboxCallArguments, SandboxMatrixArguments, SandboxMatrixCase, SandboxMatrixExportArguments,
    SandboxRunArguments, SourceName, Status,
};

/// One export request under one execution mode.
fn envelope(arguments: SandboxMatrixExportArguments, mode: ExecutionMode) -> RequestEnvelope {
    let mut envelope =
        RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrixExport(arguments));
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

/// `MOVE.W D0,(A0) ; RTS` — writes its input into a mapped buffer.
fn writer() -> InMemorySourceResolver {
    let name = SourceName::parse("game").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(
        name,
        Arc::from(image(&[0x30, 0x80, 0x4e, 0x75], 64)),
    ))
}

fn workspace(tag: &str) -> PathBuf {
    let base =
        std::env::temp_dir().join(format!("amiga-matrix-export-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    base
}

const BUFFER: u32 = 0x10_0000;

fn base() -> SandboxCallArguments {
    SandboxCallArguments::new(
        SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64),
    )
    .with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: BUFFER,
        size: 64,
    }])
    .with_memory_exports(vec![MemoryExport {
        address: BUFFER,
        length: 2,
        name: "cell".to_owned(),
    }])
}

fn case(name: &str, value: u32) -> SandboxMatrixCase {
    SandboxMatrixCase::new(name)
        .with_data_registers([value, 0, 0, 0, 0, 0, 0, 0])
        .with_address_registers([BUFFER, 0, 0, 0, 0, 0, 0])
}

/// Prepare, then commit the plan just prepared — the two-step every
/// `prepared_output` operation goes through.
fn export(
    base_directory: &Path,
    arguments: SandboxMatrixExportArguments,
) -> amiga_operations::OperationOutcome {
    let resolver = writer();
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
        .env_sandbox_matrix_export()
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

/// Each case's range lands under the case's own name, which is why a case name
/// is validated as one path component.
#[test]
fn each_case_writes_its_ranges_under_its_own_name() {
    let base_directory = workspace("per-case");
    let outcome = export(
        &base_directory,
        SandboxMatrixExportArguments::new(
            SandboxMatrixArguments::new(base(), vec![case("low", 0x1111), case("high", 0x2222)]),
            "sweep",
        ),
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let export = outcome
        .env_sandbox_matrix_export()
        .expect("an export result");
    assert!(export.committed);

    let root = base_directory.join("sweep");
    for (case, expected) in [("low", [0x11_u8, 0x11]), ("high", [0x22, 0x22])] {
        let path = root.join(case).join("cell");
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
        assert_eq!(bytes, expected, "{case} wrote the wrong bytes");
    }
    // And the aggregate beside them, under its default name.
    assert!(root.join("matrix.json").is_file());

    // The manifest names each file's case *and* that case's recipe digest. A
    // manifest listing only the paths would not let a later sweep tell its own
    // outputs from another's that reused the case names.
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("matrix.json.manifest.json"))
            .unwrap_or_else(|error| panic!("the manifest is readable: {error}")),
    )
    .unwrap_or_else(|error| panic!("the manifest is JSON: {error}"));
    let files = manifest["files"].as_array().expect("a file list");
    assert_eq!(files.len(), 2, "{files:?}");
    for entry in files {
        let case = entry["case"].as_str().expect("a case name");
        let digest = entry["recipe_sha256"].as_str().expect("a recipe digest");
        assert_eq!(entry["path"], format!("{case}/cell"));
        assert_eq!(digest.len(), 64, "{entry:?}");
        // The digest is the one the sweep reports for that case, not the
        // matrix's — so a file can be traced to the exact call that made it.
        let reported = export
            .result
            .cases
            .iter()
            .find(|reported| reported.name == case)
            .expect("the case is in the result");
        assert_eq!(digest, reported.recipe_sha256);
        assert_ne!(digest, export.result.base_recipe_sha256);
    }
    let _ = std::fs::remove_dir_all(&base_directory);
}

/// A malformed **last** case writes nothing at all.
///
/// This is the case a shell loop over `env.sandbox.call.export` gets wrong: it
/// would have written every earlier case before reaching the bad one. Expansion
/// happens at normalization, so the matrix is refused before a destination is
/// even resolved.
#[test]
fn a_malformed_last_case_writes_nothing() {
    let base_directory = workspace("bad-last");
    let resolver = writer();
    let destinations = FilesystemDestinationResolver::new(base_directory.clone());
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let outcome = Router::execute(
        &envelope(
            SandboxMatrixExportArguments::new(
                SandboxMatrixArguments::new(
                    base(),
                    vec![
                        case("first", 0x1111),
                        case("second", 0x2222),
                        // Not hex, so normalization refuses the whole matrix.
                        SandboxMatrixCase::new("broken").with_memory_seeds(vec![
                            amiga_operations::MemorySeed::hex(BUFFER, "zz"),
                        ]),
                    ],
                ),
                "sweep",
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome.result.is_none(),
        "a refused sweep planned something"
    );
    assert!(
        !base_directory.join("sweep").exists(),
        "a refused sweep created its destination"
    );
    let _ = std::fs::remove_dir_all(&base_directory);
}

/// Preparing writes nothing, which is what makes the plan reviewable.
#[test]
fn preparing_the_export_writes_nothing() {
    let base_directory = workspace("prepare-only");
    let resolver = writer();
    let destinations = FilesystemDestinationResolver::new(base_directory.clone());
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let outcome = Router::execute(
        &envelope(
            SandboxMatrixExportArguments::new(
                SandboxMatrixArguments::new(base(), vec![case("only", 0x1234)]),
                "sweep",
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Prepared);
    let export = outcome.env_sandbox_matrix_export().expect("a plan");
    assert!(!export.committed);
    // The aggregate and the one range, planned and not written.
    assert_eq!(export.plan.files.len(), 2, "{:?}", export.plan.files);
    assert!(!base_directory.join("sweep").exists());
    let _ = std::fs::remove_dir_all(&base_directory);
}

/// A plan approved for one sweep does not commit a different one.
///
/// The recipe is part of the plan's digest, so a sweep whose cases changed
/// between the review and the commit is refused rather than written under the
/// reviewer's approval of something else.
#[test]
fn a_plan_reviewed_for_one_sweep_will_not_commit_another() {
    let base_directory = workspace("plan-changed");
    let resolver = writer();
    let destinations = FilesystemDestinationResolver::new(base_directory.clone());
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let prepared = Router::execute(
        &envelope(
            SandboxMatrixExportArguments::new(
                SandboxMatrixArguments::new(base(), vec![case("one", 0x1111)]),
                "sweep",
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    let approved = prepared
        .env_sandbox_matrix_export()
        .expect("a plan")
        .plan
        .plan_sha256
        .clone();

    // A different input, so different bytes, so a different plan.
    let outcome = Router::execute(
        &envelope(
            SandboxMatrixExportArguments::new(
                SandboxMatrixArguments::new(base(), vec![case("one", 0x9999)]),
                "sweep",
            ),
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: approved,
            },
        ),
        &context,
    );
    assert_eq!(
        outcome.status,
        Status::Conflict,
        "{:?}",
        outcome.diagnostics
    );
    assert!(!base_directory.join("sweep").exists());
    let _ = std::fs::remove_dir_all(&base_directory);
}

/// A sweep in which nothing ran writes nothing and says why.
#[test]
fn a_sweep_where_nothing_ran_writes_nothing() {
    let base_directory = workspace("nothing-ran");
    let resolver = writer();
    let destinations = FilesystemDestinationResolver::new(base_directory.clone());
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    // The mapped region collides with the derived stack, so every case is
    // refused at run time rather than at normalization.
    let colliding = SandboxCallArguments::new(
        SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64),
    )
    .with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: 0x2_0000,
        size: 64,
    }]);
    let outcome = Router::execute(
        &envelope(
            SandboxMatrixExportArguments::new(
                SandboxMatrixArguments::new(colliding, vec![case("a", 1), case("b", 2)]),
                "sweep",
            ),
            ExecutionMode::Prepare,
        ),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(!base_directory.join("sweep").exists());
    let _ = std::fs::remove_dir_all(&base_directory);
}
