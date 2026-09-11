//! `env.sandbox.compare`: what a textual diff of two golden records cannot say.
//!
//! Three things, and each is a test here. A diff does not know which fields are
//! *inputs*, so it reports the question and the answer as the same kind of
//! finding. It compares changed memory positionally, so one extra region early
//! makes every later one line up against the wrong one. And it aligns traces by
//! row number, so it cannot say which pass through a loop diverged.

use std::path::{Path, PathBuf};

use amiga_operations::{
    ExecutionContext, FilesystemSourceResolver, OperationRequestDocument, RequestEnvelope, Router,
    SandboxCallArguments, SandboxCompareArguments, SandboxCompareResult, SandboxRunArguments,
    Status, TraceComparison,
};

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

fn workspace(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("amiga-compare-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    base
}

/// Run a call and write its record, exactly as `env.sandbox.call.export` would.
///
/// The records under test are *produced* rather than hand-written, for the same
/// reason the schema sweep produces its two: a hand-written record would be this
/// test's idea of the format, and what the comparison must refuse is a record the
/// format itself would not have written.
fn record(base: &Path, name: &str, call: SandboxCallArguments) {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(call)),
        &context,
    );
    let result = outcome
        .env_sandbox_call()
        .unwrap_or_else(|| panic!("{name}: {:?}", outcome.diagnostics));
    std::fs::write(
        base.join(name),
        serde_json::to_vec_pretty(result).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

fn compare(base: &Path, records: &[&str]) -> SandboxCompareResult {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCompare(
            SandboxCompareArguments::of(records.iter().copied()),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome.env_sandbox_compare().expect("a comparison").clone()
}

fn fields(differences: &[amiga_operations::CompareDifference]) -> Vec<&str> {
    differences
        .iter()
        .map(|difference| difference.field.as_str())
        .collect()
}

fn call(source: &str, d0: u32) -> SandboxCallArguments {
    let mut run = SandboxRunArguments::new(source)
        .at_origin(0x2_0000)
        .with_maximum_steps(64);
    run.data_registers = Some([d0, 0, 0, 0, 0, 0, 0, 0]);
    SandboxCallArguments::new(run)
}

/// The split is the point: a changed input register and a changed output
/// register are not the same kind of finding, and a textual diff calls them one.
#[test]
fn a_changed_input_and_a_changed_output_are_reported_separately() {
    let base = workspace("split");
    // MOVEQ #1,D1 ; ADD.W D1,D0 ; RTS — D0 in, D0+1 out.
    std::fs::write(
        base.join("game"),
        image(&[0x72, 0x01, 0xd0, 0x41, 0x4e, 0x75], 64),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    record(&base, "a.json", call("game", 1));
    record(&base, "b.json", call("game", 5));

    let result = compare(&base, &["a.json", "b.json"]);

    // The input that was changed, and only it.
    assert_eq!(fields(&result.input_differences), ["inputs.d0"]);
    assert_eq!(result.input_differences_total, 1);
    // The output that followed from it. `d1` also differs at entry? No — d1 is
    // seeded to 0 in both and written by the routine, so it is behavior.
    let behavior = fields(&result.behavioral_differences);
    assert!(behavior.contains(&"outputs.d0"), "{behavior:?}");

    assert!(!result.identical);
    assert!(!result.same_behavior);
    assert!(result.same_source);
}

/// Two runs given different things that nevertheless did the same thing is a
/// finding, and `same_behavior` is what states it.
#[test]
fn different_inputs_with_identical_behavior_are_reported_as_such() {
    let base = workspace("same-behavior");
    // MOVEQ #7,D0 ; RTS — ignores what it was handed.
    std::fs::write(base.join("game"), image(&[0x70, 0x07, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    // The differing input is a seed into a buffer the routine never reads. A
    // register would not do: an untouched register is still in the output file,
    // so it would be a behavioral difference too — correctly, because the final
    // register file really did differ.
    let seeded = |hex: &str| {
        call("game", 0)
            .with_mapped_regions(vec![amiga_operations::MappedRegion {
                address: 0x10_0000,
                size: 64,
            }])
            .with_memory_seeds(vec![amiga_operations::MemorySeed::hex(0x10_0000, hex)])
    };
    record(&base, "a.json", seeded("1111"));
    record(&base, "b.json", seeded("2222"));

    let result = compare(&base, &["a.json", "b.json"]);
    assert_eq!(fields(&result.input_differences), ["memory_seeds"]);
    assert!(!result.identical, "the inputs differ");
    assert!(result.same_behavior, "{:?}", result.behavioral_differences);
}

/// Two records of the same run are identical, and nothing about *how* they were
/// written shows up as a difference.
#[test]
fn two_records_of_one_run_are_identical() {
    let base = workspace("identical");
    std::fs::write(base.join("game"), image(&[0x70, 0x07, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    record(&base, "a.json", call("game", 3));
    record(&base, "b.json", call("game", 3));

    let result = compare(&base, &["a.json", "b.json"]);
    assert!(result.identical, "{result:?}");
    assert!(result.same_behavior);
    assert_eq!(result.input_differences_total, 0);
    assert_eq!(result.behavioral_differences_total, 0);
    // The file names and their digests are reported, and are not differences:
    // where a record was written says nothing about the run it records.
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].name, "a.json");
    assert_ne!(result.records[0].sha256, "");
}

/// Changed memory is compared by address, so a region present in one record and
/// absent from the other is named rather than shifting everything after it.
#[test]
fn changed_memory_is_compared_by_address_rather_than_by_position() {
    let base = workspace("regions");
    // MOVE.W D0,(A0) ; RTS — writes into a mapped buffer at whatever A0 holds.
    std::fs::write(base.join("game"), image(&[0x30, 0x80, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    let write_at = |address: u32| {
        let mut run = SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64);
        run.data_registers = Some([0x1234, 0, 0, 0, 0, 0, 0, 0]);
        run.address_registers = Some([address, 0, 0, 0, 0, 0, 0]);
        SandboxCallArguments::new(run).with_mapped_regions(vec![amiga_operations::MappedRegion {
            address: 0x10_0000,
            size: 64,
        }])
    };
    record(&base, "a.json", write_at(0x10_0000));
    record(&base, "b.json", write_at(0x10_0010));

    let result = compare(&base, &["a.json", "b.json"]);
    let behavior = fields(&result.behavioral_differences);
    // Both addresses are named. A positional comparison would have reported one
    // difference between two unrelated regions instead of two absences.
    assert!(
        behavior.contains(&"changed_memory[0x00100000]"),
        "{behavior:?}"
    );
    assert!(
        behavior.contains(&"changed_memory[0x00100010]"),
        "{behavior:?}"
    );
    // And the record that did not touch an address says so rather than showing
    // a digest of nothing.
    let absent = result
        .behavioral_differences
        .iter()
        .find(|difference| difference.field == "changed_memory[0x00100000]")
        .expect("the first address");
    assert!(absent.values[1].contains("unchanged"), "{absent:?}");
}

/// The digest the comparison reports for a changed region is the one the matrix
/// reports for the same memory.
///
/// They are computed in two modules and printed side by side by anyone reading a
/// sweep and then diffing two of its cases. Hashing the hex *text* would compare
/// just as correctly and print a different number, which is a defect a reader
/// discovers by trusting the toolkit.
#[test]
fn the_comparison_and_the_matrix_digest_a_region_the_same_way() {
    let base = workspace("digest-agreement");
    // MOVE.W D0,(A0) ; RTS
    std::fs::write(base.join("game"), image(&[0x30, 0x80, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    let buffer = vec![amiga_operations::MappedRegion {
        address: 0x10_0000,
        size: 64,
    }];
    let writing = |value: u32| {
        let mut run = SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64);
        run.data_registers = Some([value, 0, 0, 0, 0, 0, 0, 0]);
        run.address_registers = Some([0x10_0000, 0, 0, 0, 0, 0, 0]);
        SandboxCallArguments::new(run).with_mapped_regions(buffer.clone())
    };
    record(&base, "a.json", writing(0x1111));
    record(&base, "b.json", writing(0x2222));

    // What the matrix says about the same two runs.
    let sources = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
            amiga_operations::SandboxMatrixArguments::new(
                writing(0),
                vec![
                    amiga_operations::SandboxMatrixCase::new("a")
                        .with_data_registers([0x1111, 0, 0, 0, 0, 0, 0, 0])
                        .with_address_registers([0x10_0000, 0, 0, 0, 0, 0, 0]),
                ],
            ),
        )),
        &context,
    );
    let matrix = outcome.env_sandbox_matrix().expect("a matrix");
    let from_matrix = &matrix.cases[0].changed_regions[0].sha256;

    // And what the comparison says about the record of that same run.
    let result = compare(&base, &["a.json", "b.json"]);
    let difference = result
        .behavioral_differences
        .iter()
        .find(|difference| difference.field == "changed_memory[0x00100000]")
        .expect("the written region");
    assert!(
        difference.values[0].contains(from_matrix.as_str()),
        "the matrix reported {from_matrix} and the comparison reported {:?}",
        difference.values[0]
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// The traces are aligned by execution address, and the divergence says which
/// pass through the code each record was on.
#[test]
fn the_first_divergence_names_the_address_and_the_pass() {
    let base = workspace("divergence");
    // Count D0 down to zero, then return:
    //   0000 SUBQ.W #1,D0
    //   0002 BNE.S  $0000
    //   0004 RTS
    std::fs::write(
        base.join("game"),
        image(&[0x53, 0x40, 0x66, 0xfc, 0x4e, 0x75], 64),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let looping = |count: u32| {
        let mut run = SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64);
        run.data_registers = Some([count, 0, 0, 0, 0, 0, 0, 0]);
        run.trace = true;
        SandboxCallArguments::new(run)
    };
    record(&base, "short.json", looping(2));
    record(&base, "long.json", looping(4));

    let result = compare(&base, &["short.json", "long.json"]);
    let TraceComparison::Compared { steps, truncated } = result.trace_comparison else {
        panic!("both records carry traces: {:?}", result.trace_comparison);
    };
    assert!(steps > 0);
    assert!(!truncated);

    let divergence = result
        .first_divergence
        .as_ref()
        .expect("two loops of different lengths diverge");
    // They diverge where the shorter one falls out of the loop and the longer
    // one goes round again.
    assert_ne!(
        divergence.records[0].address, divergence.records[1].address,
        "{divergence:?}"
    );
    // And the occurrence is what makes it readable: this is a loop, so knowing
    // *which pass* is the whole content of the finding.
    assert!(
        divergence.records.iter().any(|step| step.occurrence > 0),
        "a divergence inside a loop reported no pass count: {divergence:?}"
    );
}

/// A record with no trace makes the comparison say so, rather than reporting
/// "no divergence" — which would read as agreement.
#[test]
fn an_absent_trace_is_not_agreement() {
    let base = workspace("no-trace");
    std::fs::write(base.join("game"), image(&[0x70, 0x07, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut traced = call("game", 1);
    traced.run.trace = true;
    record(&base, "traced.json", traced);
    record(&base, "bare.json", call("game", 1));

    let result = compare(&base, &["traced.json", "bare.json"]);
    assert_eq!(result.trace_comparison, TraceComparison::Absent);
    assert!(result.first_divergence.is_none());
    // The records are still compared on everything else.
    assert!(result.same_behavior, "{:?}", result.behavioral_differences);
}

/// A file that is not a record this build can read is refused rather than
/// diffed. A comparison of two documents nothing understood would still produce
/// a plausible-looking answer, which is the failure mode being prevented.
#[test]
fn a_file_that_is_not_a_readable_record_is_refused() {
    let base = workspace("unreadable");
    std::fs::write(base.join("game"), image(&[0x70, 0x07, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    record(&base, "good.json", call("game", 1));

    for (name, bytes) in [
        ("not-json.json", b"not json at all".to_vec()),
        // Valid JSON, and not a record.
        ("wrong-shape.json", br#"{"hello":"world"}"#.to_vec()),
        // A record with a field this build does not know, which is what a
        // record from a later build looks like.
        ("from-the-future.json", {
            let text = std::fs::read_to_string(base.join("good.json")).expect("the good record");
            let mut value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            value["invented_field"] = serde_json::json!(1);
            serde_json::to_vec(&value).expect("serializes")
        }),
    ] {
        std::fs::write(base.join(name), bytes).unwrap_or_else(|error| panic!("{error}"));
        let sources = FilesystemSourceResolver::new(base.clone());
        let context = ExecutionContext::new(&sources);
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCompare(
                SandboxCompareArguments::of(["good.json", name]),
            )),
            &context,
        );
        assert_eq!(outcome.status, Status::Error, "{name} was compared");
        assert!(outcome.result.is_none(), "{name} produced a comparison");
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// One record compared against nothing has no answer, and is refused rather
/// than reported as identical to itself.
#[test]
fn a_comparison_needs_at_least_two_records() {
    let base = workspace("one");
    std::fs::write(base.join("game"), image(&[0x70, 0x07, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    record(&base, "a.json", call("game", 1));

    let sources = FilesystemSourceResolver::new(base.clone());
    let context = ExecutionContext::new(&sources);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCompare(
            SandboxCompareArguments::of(["a.json"]),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    let _ = std::fs::remove_dir_all(&base);
}

/// More than two records compare in one pass, and every difference carries one
/// value per record in the order the request named them.
#[test]
fn three_records_compare_in_one_pass() {
    let base = workspace("three");
    // MOVEQ #1,D1 ; ADD.W D1,D0 ; RTS
    std::fs::write(
        base.join("game"),
        image(&[0x72, 0x01, 0xd0, 0x41, 0x4e, 0x75], 64),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    record(&base, "a.json", call("game", 1));
    record(&base, "b.json", call("game", 2));
    record(&base, "c.json", call("game", 3));

    let result = compare(&base, &["a.json", "b.json", "c.json"]);
    assert_eq!(result.records.len(), 3);
    let difference = result
        .input_differences
        .iter()
        .find(|difference| difference.field == "inputs.d0")
        .expect("the seeded register");
    assert_eq!(difference.values, ["1", "2", "3"]);
    let _ = std::fs::remove_dir_all(&base);
}

/// Records of two different images are compared, and the result says so — a
/// behavioral difference between two programs is not a behavioral difference.
#[test]
fn records_of_different_images_are_flagged() {
    let base = workspace("two-images");
    std::fs::write(base.join("one"), image(&[0x70, 0x07, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("two"), image(&[0x70, 0x09, 0x4e, 0x75], 64))
        .unwrap_or_else(|error| panic!("{error}"));
    record(&base, "a.json", call("one", 0));
    record(&base, "b.json", call("two", 0));

    let result = compare(&base, &["a.json", "b.json"]);
    assert!(!result.same_source);
    assert!(
        fields(&result.input_differences).contains(&"source.sha256"),
        "{:?}",
        result.input_differences
    );
    let _ = std::fs::remove_dir_all(&base);
}
