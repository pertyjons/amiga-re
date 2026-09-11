//! `analysis.state.snapshot` and `analysis.state.compare`: a machine's state in
//! the project's own words.
//!
//! Every test here runs against the project format's own contract fixture, which
//! carries the three global shapes the format can express — an aggregate at a
//! hunk offset, a small-data slot behind a base register, and a scalar at a
//! runtime address — plus a function-scoped local that is deliberately *not*
//! machine state. Using the format's fixture rather than an invented project is
//! what keeps this honest about the format rather than about this test.

use std::path::{Path, PathBuf};

use amiga_operations::{
    ExecutionContext, FilesystemSourceResolver, OperationRequestDocument, ProjectLocator,
    RequestEnvelope, Router, SandboxRegisters, StateCompareArguments, StateCompareResult,
    StateRegion, StateSnapshotArguments, StateSnapshotResult, StateValue, Status,
};

/// A workspace holding the contract project and the ranges of machine memory
/// its globals live in.
fn workspace(name: &str, lives: [u8; 2]) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "amiga-operations-state-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../amiga-project/fixtures/contract"),
        &base.join("contract"),
    );

    // Four level headers: id, width, height, flags. The last one's flags are 9,
    // which the project enumerates nothing for — a finding the snapshot reports
    // rather than an error.
    let mut table = Vec::new();
    for (id, flags) in [(1_u16, 0_u16), (2, 1), (3, 2), (4, 9)] {
        table.extend_from_slice(&id.to_be_bytes());
        table.extend_from_slice(&320_u16.to_be_bytes());
        table.extend_from_slice(&200_u16.to_be_bytes());
        table.extend_from_slice(&flags.to_be_bytes());
    }
    std::fs::write(base.join("mem-table.bin"), table).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("mem-seed.bin"), [0x12, 0x34, 0x56, 0x78])
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("mem-lives.bin"), lives).unwrap_or_else(|error| panic!("{error}"));
    base
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|error| panic!("{error}"));
    for entry in std::fs::read_dir(from).unwrap_or_else(|error| panic!("{error}")) {
        let entry = entry.unwrap_or_else(|error| panic!("{error}"));
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap_or_else(|error| panic!("{error}"));
        }
    }
}

/// The machine, with hunk 1 placed where the caller says rather than where the
/// project's default load map does.
fn arguments(hunk1: u32) -> StateSnapshotArguments {
    let mut registers = SandboxRegisters {
        d: [0; 8],
        a: [0; 7],
        usp: 0,
        ssp: 0,
        pc: 0,
        sr: 0x2700,
    };
    // `map_seed` is at A5-8, so A5 is eight bytes above where its bytes sit.
    registers.a[5] = 0x0004_0008;
    StateSnapshotArguments::new(vec![
        StateRegion::new(hunk1, "mem-table.bin"),
        StateRegion::new(0x0004_0000, "mem-seed.bin"),
        StateRegion::new(0x0002_2010, "mem-lives.bin"),
    ])
    .of_image("image:main-executable")
    .with_registers(registers)
    .with_hunk_base(1, hunk1)
}

fn execute(base: &Path, arguments: StateSnapshotArguments) -> amiga_operations::OperationOutcome {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let mut envelope =
        RequestEnvelope::read(OperationRequestDocument::AnalysisStateSnapshot(arguments));
    envelope.project = Some(ProjectLocator::Path {
        path: "contract".to_owned(),
    });
    Router::execute(&envelope, &context)
}

fn snapshot(base: &Path, arguments: StateSnapshotArguments) -> StateSnapshotResult {
    let outcome = execute(base, arguments);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome
        .analysis_state_snapshot()
        .expect("a snapshot result")
        .clone()
}

fn refusal(base: &Path, arguments: StateSnapshotArguments) -> String {
    let outcome = execute(base, arguments);
    assert_eq!(outcome.status, Status::Error, "expected a refusal");
    outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.is_error())
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn field<'a>(snapshot: &'a StateSnapshotResult, path: &str) -> &'a StateValue {
    &snapshot
        .fields
        .iter()
        .find(|field| field.path == path)
        .unwrap_or_else(|| panic!("no field {path:?} in {:?}", paths(snapshot)))
        .value
}

fn paths(snapshot: &StateSnapshotResult) -> Vec<&str> {
    snapshot
        .fields
        .iter()
        .map(|field| field.path.as_str())
        .collect()
}

/// Mark one annotation of the copied contract project stale, as a reviewer who
/// had found that the global moved would.
fn mark_stale(base: &Path, annotation_id: &str) {
    let path = base.join("contract/analysis/annotations/main-code.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}"));
    let mut document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    let annotations = document["annotations"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("the document's annotation list"));
    let annotation = annotations
        .iter_mut()
        .find(|annotation| annotation["id"] == annotation_id)
        .unwrap_or_else(|| panic!("no annotation {annotation_id:?}"));
    annotation["stale"] = serde_json::Value::Bool(true);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&document).unwrap_or_default(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

/// The three global shapes decode, and the local does not.
///
/// An aggregate contributes its leaves and no row of its own, so a four-element
/// array of four-field structs is sixteen fields — which is the whole point of
/// addressing by path: `level_table[2].height` is a name a person and a port can
/// both use, and `0x30014` is not.
#[test]
fn every_global_shape_decodes_and_a_function_local_is_not_machine_state() {
    let base = workspace("shapes", [0xff, 0xfe]);
    let snapshot = snapshot(&base, arguments(0x0003_0000));

    assert_eq!(snapshot.image_id, "image:main-executable");
    // 16 from the table, one seed, one lives.
    assert_eq!(snapshot.fields_total, 18);
    assert!(!snapshot.fields_truncated);
    assert!(
        !paths(&snapshot).contains(&"library_base"),
        "a register local belongs to a frame, not to the machine's shared state"
    );

    // A hunk target, placed by the caller's own layout.
    assert_eq!(
        field(&snapshot, "level_table[1].id"),
        &StateValue::Integer {
            value: 2,
            signed: false,
            byte_order: "big".to_owned(),
        }
    );
    // An enum inside a struct inside an array, named where the project names it.
    assert_eq!(
        field(&snapshot, "level_table[2].flags"),
        &StateValue::Enum {
            value: 2,
            member: Some("Boss".to_owned()),
        }
    );
    // And unnamed where it does not. A finding, not an error: the machine held
    // a value the review has not accounted for, and saying so is the point.
    assert_eq!(
        field(&snapshot, "level_table[3].flags"),
        &StateValue::Enum {
            value: 9,
            member: None,
        }
    );
    // A small-data slot behind a base register, read at A5-8.
    assert_eq!(
        field(&snapshot, "map_seed"),
        &StateValue::Integer {
            value: 0x1234_5678,
            signed: false,
            byte_order: "big".to_owned(),
        }
    );
    // A runtime address, and a signed one: 0xfffe is -2 and not 65534.
    assert_eq!(
        field(&snapshot, "player_lives"),
        &StateValue::Integer {
            value: -2,
            signed: true,
            byte_order: "big".to_owned(),
        }
    );

    // Every field carries the digest its annotation was established against, so
    // a consumer can tell a snapshot of a rebased image from one of this image.
    for reported in &snapshot.fields {
        assert_eq!(reported.object_sha256.len(), 64, "{}", reported.path);
    }
}

/// Two variables over one set of bytes is refused, and the fixture's own default
/// load map is what produces it.
///
/// The contract project puts hunk 1 at `0x22000` and `player_lives` at
/// `0x22010`, which is inside the level table. That is a real disagreement in a
/// real project, and a snapshot cannot paper over it: whichever variable it
/// decoded second would name the same memory a second way, and a comparison
/// would then report one machine as two.
#[test]
fn two_variables_over_one_set_of_bytes_refuse_the_snapshot() {
    let base = workspace("overlap", [0xff, 0xfe]);
    let message = refusal(&base, arguments(0x0002_2000));
    assert!(message.contains("both cover"), "{message}");
    assert!(message.contains("player_lives"), "{message}");
}

/// A variable no region covers is a refusal naming it.
///
/// The alternative is the failure the whole operation exists to avoid: a
/// snapshot missing a field compares cleanly against one that has it, and reads
/// as agreement about a machine nobody looked at.
#[test]
fn a_variable_no_region_covers_refuses_the_snapshot_by_name() {
    let base = workspace("uncovered", [0xff, 0xfe]);
    let mut incomplete = arguments(0x0003_0000);
    incomplete
        .regions
        .retain(|region| region.address != 0x0002_2010);
    let message = refusal(&base, incomplete);
    assert!(message.contains("player_lives"), "{message}");
    assert!(message.contains("no region"), "{message}");
}

/// A base-register global with no register file is refused rather than read at
/// whatever zero points at.
#[test]
fn a_base_register_global_without_a_register_file_is_refused() {
    let base = workspace("blind", [0xff, 0xfe]);
    let mut blind = arguments(0x0003_0000);
    blind.registers = None;
    let message = refusal(&base, blind);
    assert!(message.contains("map_seed"), "{message}");
    assert!(message.contains("register file"), "{message}");
}

/// A project with more than one image is refused rather than having one picked.
#[test]
fn a_project_with_several_images_refuses_to_choose_one() {
    let base = workspace("unnamed", [0xff, 0xfe]);
    let mut unnamed = arguments(0x0003_0000);
    unnamed.image = None;
    let message = refusal(&base, unnamed);
    assert!(
        message.contains("name the one this snapshot is of"),
        "{message}"
    );
}

/// A global a reviewer has marked stale is refused rather than decoded at an
/// address the project no longer claims it lives at.
///
/// The refusal existed before the flag did and was unreachable: `variable` had
/// no way to be marked stale, so a reviewer who had found that a global moved
/// could only delete the annotation. What a consumer had instead was the
/// target's `object_sha256`, which says the *bytes* changed — a different claim
/// from a person having looked and agreed the annotation is now wrong.
#[test]
fn a_stale_global_is_refused_rather_than_read_where_it_no_longer_lives() {
    let base = workspace("stale", [0xff, 0xfe]);
    mark_stale(&base, "variable:main/player-lives");
    let message = refusal(&base, arguments(0x0003_0000));
    assert!(message.contains("player_lives"), "{message}");
    assert!(message.contains("stale"), "{message}");
    assert!(message.contains("rebase"), "the remedy is named: {message}");
}

/// And the same project without the flag decodes it, so the refusal above is
/// the flag's doing rather than the fixture's.
#[test]
fn the_same_global_decodes_when_it_is_not_marked_stale() {
    let base = workspace("stale-control", [0xff, 0xfe]);
    let snapshot = snapshot(&base, arguments(0x0003_0000));
    assert!(
        paths(&snapshot).contains(&"player_lives"),
        "{:?}",
        paths(&snapshot)
    );
}

/// A hunk-targeted variable with no base is refused, naming the hunk.
#[test]
fn a_hunk_target_this_request_does_not_place_is_refused() {
    let base = workspace("unplaced", [0xff, 0xfe]);
    let mut unplaced = arguments(0x0003_0000);
    unplaced.hunk_bases.clear();
    let message = refusal(&base, unplaced);
    assert!(message.contains("level_table"), "{message}");
    assert!(message.contains("hunk_bases"), "{message}");
}

/// Two snapshots are compared by path, and one changed field is one difference.
#[test]
fn two_snapshots_differ_in_exactly_the_field_that_changed() {
    let first = workspace("compare-a", [0xff, 0xfe]);
    let second = workspace("compare-b", [0x00, 0x03]);
    let a = snapshot(&first, arguments(0x0003_0000));
    let b = snapshot(&second, arguments(0x0003_0000));

    let base = workspace("compare", [0xff, 0xfe]);
    for (name, document) in [("a.json", &a), ("b.json", &b)] {
        std::fs::write(
            base.join(name),
            serde_json::to_vec_pretty(document).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    let result = compare(&base, StateCompareArguments::of(["a.json", "b.json"]));
    assert!(!result.identical);
    assert_eq!(result.paths_total, 18);
    assert_eq!(result.differences_total, 1);
    assert_eq!(result.differences[0].path, "player_lives");
    assert_eq!(
        result.differences[0].values,
        vec![
            Some(StateValue::Integer {
                value: -2,
                signed: true,
                byte_order: "big".to_owned(),
            }),
            Some(StateValue::Integer {
                value: 3,
                signed: true,
                byte_order: "big".to_owned(),
            }),
        ]
    );

    // And a snapshot compared against itself is identical, which is the half a
    // comparison that always found something would quietly fail.
    let same = compare(&base, StateCompareArguments::of(["a.json", "a.json"]));
    assert!(same.identical);
    assert_eq!(same.differences_total, 0);
}

/// A document this build does not fully understand is refused rather than
/// diffed.
///
/// A snapshot is meant to be written by other programs — that is what makes a
/// clean-room check possible — so the one thing the comparison must not do is
/// produce a plausible answer about a document neither side understood.
#[test]
fn a_snapshot_document_with_a_field_this_build_does_not_know_is_refused() {
    let base = workspace("invented", [0xff, 0xfe]);
    let a = snapshot(&base, arguments(0x0003_0000));
    let mut invented =
        serde_json::to_value(&a).unwrap_or_else(|error| panic!("a snapshot serializes: {error}"));
    invented["tick"] = serde_json::Value::from(7);
    std::fs::write(
        base.join("a.json"),
        serde_json::to_vec_pretty(&a).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(
        base.join("invented.json"),
        serde_json::to_vec_pretty(&invented).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let sources = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisStateCompare(
            StateCompareArguments::of(["a.json", "invented.json"]),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("this build understands")),
        "{:?}",
        outcome.diagnostics
    );
}

fn compare(base: &Path, arguments: StateCompareArguments) -> StateCompareResult {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisStateCompare(arguments)),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome
        .analysis_state_compare()
        .expect("a comparison result")
        .clone()
}
