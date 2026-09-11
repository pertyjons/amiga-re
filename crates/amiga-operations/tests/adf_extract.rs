//! `container.adf.extract`: prepare writes nothing, commit needs the digest it
//! was approved with, and anything that changed in between is a conflict.

use std::path::{Path, PathBuf};

use amiga_operations::{
    ContainerExtractArguments, DiagnosticCode, ExecutionContext, ExecutionMode,
    FilesystemDestinationResolver, FilesystemSourceResolver, OperationRequestDocument,
    OutputPolicy, RequestEnvelope, Router, Status,
};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A fresh output root nobody else is using.
fn output_root(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("amiga-re-extract-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
    path
}

fn request(mode: ExecutionMode, policy: OutputPolicy) -> RequestEnvelope {
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ContainerAdfExtract(
        ContainerExtractArguments::new("fixtures/volume.adf", "recovered").with_policy(policy),
    ));
    envelope.execution.mode = mode;
    envelope
}

fn run(
    root: &Path,
    mode: ExecutionMode,
    policy: OutputPolicy,
) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(crate_root());
    let destinations = FilesystemDestinationResolver::new(root);
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    Router::execute(&request(mode, policy), &context)
}

#[test]
fn prepare_reports_a_complete_plan_and_writes_nothing() {
    let root = output_root("prepare");
    let outcome = run(&root, ExecutionMode::Prepare, OutputPolicy::CreateOnly);

    assert_eq!(outcome.status, Status::Prepared);
    assert_eq!(outcome.exit_code(), 0, "a prepared plan is not a failure");
    let result = outcome.container_extract().expect("the plan was built");
    assert!(!result.committed);

    // The plan describes every file the volume holds, with its content hash,
    // so a reviewer can decide without running anything.
    let paths: Vec<&str> = result
        .plan
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["S/stale", "S/startup-sequence", "readme.txt"],
        "{:?}",
        result.plan.files
    );
    assert!(result.plan.files.iter().all(|file| file.sha256.len() == 64));
    assert_eq!(result.plan.plan_sha256.len(), 64);

    // Nothing on disk. This is the whole promise of `prepare`.
    assert_eq!(
        std::fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("{error}"))
            .count(),
        0,
        "prepare wrote to the destination"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_commit_naming_the_approved_plan_writes_exactly_that_plan() {
    let root = output_root("commit");
    let prepared = run(&root, ExecutionMode::Prepare, OutputPolicy::CreateOnly);
    let plan = prepared
        .container_extract()
        .expect("the plan was built")
        .plan
        .clone();

    let committed = run(
        &root,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan.plan_sha256.clone(),
        },
        OutputPolicy::CreateOnly,
    );
    assert_eq!(committed.status, Status::Success);
    let result = committed.container_extract().expect("it committed");
    assert!(result.committed);
    // The response documents what is now on disk, and it is the same plan the
    // reviewer approved — not a re-derived one that happens to look similar.
    assert_eq!(result.plan.plan_sha256, plan.plan_sha256);

    for file in &plan.files {
        // The plan spells paths `/`-separated on every host; joining component
        // by component is what turns one back into a host path.
        let path = file
            .path
            .split('/')
            .fold(root.join("recovered"), |path, part| path.join(part));
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{} was not written: {error}", file.path));
        assert_eq!(bytes.len() as u64, file.size);
        assert_eq!(amiga_core::sha256(&bytes), file.sha256);
    }
    assert!(root.join("recovered/manifest.json").is_file());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_commit_naming_a_stale_plan_is_a_conflict_and_writes_nothing() {
    let root = output_root("stale");
    let outcome = run(
        &root,
        ExecutionMode::CommitReviewed {
            // A well-formed digest that is not this plan's: what a caller would
            // send after the source changed under an approved review.
            approved_plan_sha256: "0".repeat(64),
        },
        OutputPolicy::CreateOnly,
    );

    assert_eq!(outcome.status, Status::Conflict);
    assert_eq!(outcome.exit_code(), 4);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::OutputPlanChanged)
    );
    // The current plan comes back, so the caller can review the new one rather
    // than having to ask again.
    let result = outcome.container_extract().expect("the plan came back");
    assert!(!result.committed);
    assert_ne!(result.plan.plan_sha256, "0".repeat(64));
    assert_eq!(
        std::fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("{error}"))
            .count(),
        0,
        "a refused commit wrote to the destination"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_malformed_approval_is_a_bad_request_not_a_conflict() {
    // Refused in normalization, before a source is opened: a caller that sent
    // a truncated digest has a bug, not a stale review.
    let root = output_root("malformed");
    for approved in ["", "abc", &"0".repeat(63), &"A".repeat(64)] {
        let outcome = run(
            &root,
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: approved.to_owned(),
            },
            OutputPolicy::CreateOnly,
        );
        assert_eq!(outcome.status, Status::Error, "{approved:?}");
        assert_eq!(outcome.exit_code(), 2, "{approved:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_only_refuses_a_destination_that_already_exists() {
    let root = output_root("exists");
    let plan_of = |outcome: &amiga_operations::OperationOutcome| {
        outcome
            .container_extract()
            .expect("a plan")
            .plan
            .plan_sha256
            .clone()
    };

    let first = run(&root, ExecutionMode::Prepare, OutputPolicy::CreateOnly);
    let digest = plan_of(&first);
    let committed = run(
        &root,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest.clone(),
        },
        OutputPolicy::CreateOnly,
    );
    assert_eq!(committed.status, Status::Success);

    // The same commit again. The plan is identical, so the digest still
    // matches; what refuses it is the destination, and that is a conflict too.
    let again = run(
        &root,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest.clone(),
        },
        OutputPolicy::CreateOnly,
    );
    assert_eq!(again.status, Status::Conflict);
    assert!(
        again
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::OutputDestinationRefused)
    );

    // With a replacing policy the same bytes go back, but the plan digest
    // differs because the policy is part of what was approved — a reviewer who
    // approved `create_only` did not approve a replacement.
    let replacing = run(
        &root,
        ExecutionMode::Prepare,
        OutputPolicy::ReplaceMatchingProvenance,
    );
    assert_ne!(plan_of(&replacing), digest);
    let replaced = run(
        &root,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan_of(&replacing),
        },
        OutputPolicy::ReplaceMatchingProvenance,
    );
    assert_eq!(
        replaced.status,
        Status::Success,
        "{:?}",
        replaced.diagnostics
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_context_with_no_output_root_cannot_be_made_to_write() {
    // The default context serves no destinations, so even a correctly approved
    // commit is refused — an adapter that never named an output root has
    // authorized nothing.
    let sources = FilesystemSourceResolver::new(crate_root());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &request(
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: "0".repeat(64),
            },
            OutputPolicy::ReplaceExplicitGenerated,
        ),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::OutputDestinationUnavailable
    );
}

#[test]
fn a_read_mode_request_is_refused_because_there_is_nothing_to_report() {
    let root = output_root("read");
    let outcome = run(&root, ExecutionMode::Read, OutputPolicy::CreateOnly);
    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::RequestExecutionModeUnsupported
    );
    assert_eq!(outcome.exit_code(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_destination_cannot_escape_the_root_the_adapter_chose() {
    let root = output_root("escape");
    let sources = FilesystemSourceResolver::new(crate_root());
    let destinations = FilesystemDestinationResolver::new(&root);
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);

    for destination in ["../escape", "/absolute", "recovered/../../escape"] {
        let mut envelope = RequestEnvelope::read(OperationRequestDocument::ContainerAdfExtract(
            ContainerExtractArguments::new("fixtures/volume.adf", destination),
        ));
        envelope.execution.mode = ExecutionMode::Prepare;
        let outcome = Router::execute(&envelope, &context);
        assert_eq!(outcome.status, Status::Error, "{destination}");
        assert_eq!(
            outcome.diagnostics[0].code,
            DiagnosticCode::RequestSourceNameInvalid,
            "{destination}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn prepare_and_commit_share_one_request_digest() {
    // The approved plan digest authorizes a write; it does not change what
    // would be written. If it entered the request digest, prepare and commit
    // would identify themselves as different requests for the same work.
    let root = output_root("digest");
    let prepared = run(&root, ExecutionMode::Prepare, OutputPolicy::CreateOnly);
    let committing = run(
        &root,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: "0".repeat(64),
        },
        OutputPolicy::CreateOnly,
    );
    assert_eq!(
        prepared.normalized_request_sha256,
        committing.normalized_request_sha256
    );
    let _ = std::fs::remove_dir_all(&root);
}

// --- graphics.bitmap.export --------------------------------------------------

/// The second `prepared_output` operation, on the same rails. These assert the
/// two things that are *its* own: that it decodes the same way the decode
/// operation does, and that the palette it committed to is visible.
mod bitmap_export {
    use super::{crate_root, output_root};
    use amiga_operations::{
        BitmapDecodeArguments, BitmapExportArguments, DiagnosticCode, ExecutionContext,
        ExecutionMode, FilesystemDestinationResolver, FilesystemSourceResolver,
        OperationRequestDocument, OutputPolicy, RequestEnvelope, Router, Status,
    };

    fn export(
        root: &std::path::Path,
        mode: ExecutionMode,
        arguments: BitmapExportArguments,
    ) -> amiga_operations::OperationOutcome {
        let sources = FilesystemSourceResolver::new(crate_root());
        let destinations = FilesystemDestinationResolver::new(root);
        let context = ExecutionContext::new(&sources).with_destinations(&destinations);
        let mut envelope =
            RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapExport(arguments));
        envelope.execution.mode = mode;
        Router::execute(&envelope, &context)
    }

    fn arguments() -> BitmapExportArguments {
        BitmapExportArguments::new(
            BitmapDecodeArguments::new("fixtures/sample.bin", 8, 4, 1),
            "exports",
        )
        .with_file_name("title.png")
    }

    #[test]
    fn prepare_reports_the_png_it_would_write_and_writes_nothing() {
        let root = output_root("export-prepare");
        let outcome = export(&root, ExecutionMode::Prepare, arguments());

        assert_eq!(
            outcome.status,
            Status::Prepared,
            "{:?}",
            outcome.diagnostics
        );
        let result = outcome.graphics_bitmap_export().expect("a plan");
        assert!(!result.committed);
        assert_eq!(result.plan.files.len(), 1);
        assert_eq!(result.plan.files[0].path, "title.png");
        assert!(result.plan.files[0].size > 0);
        // One plane addresses two colors, and the export says which two it
        // chose even though the request named none.
        assert_eq!(result.palette.len(), 2);
        assert_eq!(result.palette, [0x000, 0xfff]);
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap_or_else(|error| panic!("{error}"))
                .count(),
            0
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_committed_export_writes_the_png_the_plan_promised() {
        let root = output_root("export-commit");
        let prepared = export(&root, ExecutionMode::Prepare, arguments());
        let plan = prepared
            .graphics_bitmap_export()
            .expect("a plan")
            .plan
            .clone();

        let committed = export(
            &root,
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: plan.plan_sha256.clone(),
            },
            arguments(),
        );
        assert_eq!(
            committed.status,
            Status::Success,
            "{:?}",
            committed.diagnostics
        );

        let png = std::fs::read(root.join("exports/title.png"))
            .unwrap_or_else(|error| panic!("the PNG was not written: {error}"));
        assert_eq!(amiga_core::sha256(&png), plan.files[0].sha256);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
        // Provenance sits beside the file it describes, not at the top of a
        // directory this export does not own: `exports/` may hold other people's
        // work, and one `manifest.json` there could only describe one of them.
        assert!(root.join("exports/title.png.manifest.json").is_file());
        assert!(
            !root.join("exports/manifest.json").exists(),
            "a single-file export claimed the whole directory's manifest"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_different_palette_is_a_different_plan() {
        // The palette is part of what a reviewer approved: the same pixels with
        // different colors are a different image, and must not commit under the
        // old digest.
        let root = output_root("export-palette");
        let plain = export(&root, ExecutionMode::Prepare, arguments());
        let colored = export(
            &root,
            ExecutionMode::Prepare,
            arguments().with_palette(vec![0xf00, 0x00f]),
        );

        let left = plain.graphics_bitmap_export().expect("a plan");
        let right = colored.graphics_bitmap_export().expect("a plan");
        assert_ne!(left.plan.plan_sha256, right.plan.plan_sha256);
        assert_eq!(right.palette, [0xf00, 0x00f]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_palette_too_short_for_the_planes_is_refused() {
        let root = output_root("export-short");
        let outcome = export(
            &root,
            ExecutionMode::Prepare,
            BitmapExportArguments::new(
                BitmapDecodeArguments::new("fixtures/sample.bin", 8, 4, 2),
                "exports",
            )
            .with_palette(vec![0x000, 0xfff]),
        );
        assert_eq!(outcome.status, Status::Error);
        assert_eq!(
            outcome.diagnostics.last().expect("a diagnostic").code,
            DiagnosticCode::RequestArgumentOutOfRange
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_decode_failure_is_reported_as_the_decode_reports_it() {
        // The export runs the decode operation's handler, so a geometry the
        // decode refuses must fail the same way here — one story about the
        // same bytes, not two.
        let root = output_root("export-undecodable");
        let outcome = export(
            &root,
            ExecutionMode::Prepare,
            BitmapExportArguments::new(
                BitmapDecodeArguments::new("fixtures/sample.bin", 8, 4096, 1),
                "exports",
            ),
        );
        assert_eq!(outcome.status, Status::Error);
        assert_eq!(
            outcome.diagnostics.last().expect("a diagnostic").code,
            DiagnosticCode::GraphicsPlanarUndecodable
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_name_with_a_path_separator_is_refused() {
        let root = output_root("export-escape");
        for name in ["../escape.png", "nested/title.png", "/absolute.png"] {
            let outcome = export(
                &root,
                ExecutionMode::Prepare,
                arguments().with_file_name(name),
            );
            assert_eq!(outcome.status, Status::Error, "{name}");
            assert_eq!(
                outcome.diagnostics[0].code,
                DiagnosticCode::RequestSourceNameInvalid,
                "{name}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_export_cannot_write_without_an_output_root() {
        let sources = FilesystemSourceResolver::new(crate_root());
        let context = ExecutionContext::new(&sources);
        let mut envelope = RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapExport(
            arguments().with_policy(OutputPolicy::ReplaceExplicitGenerated),
        ));
        envelope.execution.mode = ExecutionMode::Prepare;
        let outcome = Router::execute(&envelope, &context);
        assert_eq!(outcome.status, Status::Error);
        assert_eq!(
            outcome.diagnostics[0].code,
            DiagnosticCode::OutputDestinationUnavailable
        );
    }
}

/// A volume whose *every* file is damaged is refused rather than committed as
/// an empty directory.
///
/// The counterpart to "one damaged file does not refuse the volume": there is
/// no extraction here, only a directory holding a manifest that says so — and
/// committing it would consume the destination, since `create_only` refuses a
/// second attempt at a path that already exists. A user who then repaired the
/// image would find the toolkit refusing to write the files it can now recover.
///
/// An *empty* volume is deliberately a different case and still extracts to an
/// empty directory, which is why the refusal tests the refusals rather than the
/// file count alone.
#[test]
fn a_volume_whose_every_file_is_damaged_is_refused_rather_than_written_empty() {
    const TYPE_HEADER: u32 = 2;
    const TYPE_DATA: u32 = 8;
    const ST_ROOT: u32 = 1;
    const ST_FILE: i32 = -3;
    const ROOT: usize = 3;
    const HEADER: usize = 1;
    const DATA: usize = 2;
    const BLOCK: usize = 512;

    fn write_u32(block: &mut [u8], offset: usize, value: u32) {
        block[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    fn seal(block: &mut [u8]) {
        write_u32(block, 20, 0);
        let sum = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .fold(0_u32, u32::wrapping_add);
        write_u32(block, 20, 0_u32.wrapping_sub(sum));
    }
    fn name(block: &mut [u8], text: &str) {
        block[432] = text.len() as u8;
        block[433..433 + text.len()].copy_from_slice(text.as_bytes());
    }

    let mut image = vec![0_u8; 6 * BLOCK];
    {
        let root = &mut image[ROOT * BLOCK..(ROOT + 1) * BLOCK];
        write_u32(root, 0, TYPE_HEADER);
        write_u32(root, 24, HEADER as u32);
        name(root, "ONLYBAD");
        write_u32(root, 508, ST_ROOT);
        seal(root);
    }
    {
        let header = &mut image[HEADER * BLOCK..(HEADER + 1) * BLOCK];
        write_u32(header, 0, TYPE_HEADER);
        write_u32(header, 4, HEADER as u32);
        write_u32(header, 16, DATA as u32);
        write_u32(header, 324, 4);
        name(header, "only");
        write_u32(header, 508, ST_FILE as u32);
        seal(header);
    }
    {
        let data = &mut image[DATA * BLOCK..(DATA + 1) * BLOCK];
        write_u32(data, 0, TYPE_DATA);
        write_u32(data, 4, HEADER as u32);
        write_u32(data, 8, 1);
        write_u32(data, 12, 4);
        data[24..28].copy_from_slice(b"data");
        seal(data);
        // Sealed and then damaged, so the block is corrupt rather than never
        // checksummed — the shape a bad sector leaves.
        data[24] ^= 0xff;
    }

    let source_root = output_root("all-damaged-source");
    std::fs::write(source_root.join("broken.adf"), &image)
        .unwrap_or_else(|error| panic!("{error}"));
    let root = output_root("all-damaged");

    let sources = FilesystemSourceResolver::new(source_root);
    let destinations = FilesystemDestinationResolver::new(&root);
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let mut envelope = RequestEnvelope::read(OperationRequestDocument::ContainerAdfExtract(
        ContainerExtractArguments::new("broken.adf", "recovered")
            .with_policy(OutputPolicy::CreateOnly),
    ));
    envelope.execution.mode = ExecutionMode::Prepare;
    let outcome = Router::execute(&envelope, &context);

    assert_eq!(outcome.status, Status::Error, "{:?}", outcome.diagnostics);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ContainerMemberUnreadable),
        "{:?}",
        outcome.diagnostics
    );
    assert!(
        !root.join("recovered").exists(),
        "a refused extraction leaves no directory behind"
    );
}

#[test]
fn recovery_budgets_apply_before_any_adf_output_is_written() {
    use amiga_operations::OperationLimits;
    let root = output_root("recovery-budgets");
    let sources = FilesystemSourceResolver::new(crate_root());
    let destinations = FilesystemDestinationResolver::new(&root);
    let expected: [(&str, &[u8]); 3] = [
        ("S/stale", b""),
        ("S/startup-sequence", b"echo AmigaRe fixture volume\n"),
        (
            "readme.txt",
            b"Synthetic OFS volume for amiga-operations tests.\n",
        ),
    ];
    let total: u64 = expected.iter().map(|(_, bytes)| bytes.len() as u64).sum();
    // Three files plus their directory. Empty files still consume a member slot.
    let exact = OperationLimits::default()
        .with_maximum_total_recovered_bytes(total)
        .with_maximum_objects(4);
    let run = |limits, mode| {
        let context = ExecutionContext::new(&sources)
            .with_destinations(&destinations)
            .with_limits(limits);
        Router::execute(&request(mode, OutputPolicy::CreateOnly), &context)
    };
    let prepared = run(exact, ExecutionMode::Prepare);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let digest = prepared
        .container_extract()
        .unwrap()
        .plan
        .plan_sha256
        .clone();
    let below = [
        exact.with_maximum_total_recovered_bytes(0),
        exact.with_maximum_total_recovered_bytes(total - 1),
        exact.with_maximum_objects(0),
        exact.with_maximum_objects(3),
    ];
    for limits in below {
        for mode in [
            ExecutionMode::Prepare,
            ExecutionMode::CommitReviewed {
                approved_plan_sha256: digest.clone(),
            },
        ] {
            let outcome = run(limits, mode);
            assert_eq!(outcome.status, Status::Error, "{:?}", outcome.diagnostics);
            assert!(outcome.result.is_none());
            assert!(
                outcome
                    .diagnostics
                    .iter()
                    .any(|d| d.code == DiagnosticCode::LimitExceeded)
            );
            assert!(
                !outcome
                    .diagnostics
                    .iter()
                    .any(|d| d.code == DiagnosticCode::ContainerMemberUnreadable)
            );
            assert!(!root.join("recovered").exists());
        }
    }
    let committed = run(
        exact,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest.clone(),
        },
    );
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );
    let manifest = std::fs::read(root.join("recovered/manifest.json")).unwrap();
    // Exhaustion also preserves an existing destination, including its manifest.
    let outcome = run(
        below[1],
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest,
        },
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::LimitExceeded)
    );
    assert_eq!(
        std::fs::read(root.join("recovered/manifest.json")).unwrap(),
        manifest
    );
    for (path, bytes) in expected {
        assert_eq!(
            std::fs::read(root.join("recovered").join(path)).unwrap(),
            bytes
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
