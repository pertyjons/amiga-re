//! `env.sandbox.matrix`: one recipe, many inputs, and one aggregate to read.
//!
//! The properties under test are the ones that make a matrix different from a
//! shell loop over `env.sandbox.call`. A loop expands as it goes, so a bad case
//! halfway through leaves half a sweep; it has no aggregate, so a reader counts
//! by hand; and it has nothing to say about a case that never ran. Each of those
//! is a test here.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, InMemorySourceResolver, MatrixCaseOutcome, OperationRequestDocument,
    RequestEnvelope, ResolvedSource, Router, SandboxCallArguments, SandboxMatrixArguments,
    SandboxMatrixCase, SandboxMatrixResult, SandboxRunArguments, SourceName, Status,
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

fn resolver(bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse("game").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

/// `ADD.W D1,D0 ; RTS` — an output that depends on two inputs, which is the
/// smallest routine a sweep can say anything about.
fn adder() -> InMemorySourceResolver {
    resolver(image(&[0xd0, 0x41, 0x4e, 0x75], 64))
}

fn base() -> SandboxCallArguments {
    SandboxCallArguments::new(
        SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64),
    )
}

fn case(name: &str, d0: u32, d1: u32) -> SandboxMatrixCase {
    SandboxMatrixCase::new(name).with_data_registers([d0, d1, 0, 0, 0, 0, 0, 0])
}

fn run(matrix: SandboxMatrixArguments, context: &ExecutionContext<'_>) -> SandboxMatrixResult {
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(matrix)),
        context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome
        .env_sandbox_matrix()
        .expect("a matrix result")
        .clone()
}

#[test]
fn every_case_runs_with_its_own_inputs_and_reports_its_own_outputs() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxMatrixArguments::new(
            base(),
            vec![
                case("zero", 0, 0),
                case("small", 2, 3),
                case("wrap", 0xffff, 1),
            ],
        ),
        &context,
    );

    assert_eq!(result.cases_total, 3);
    assert_eq!(result.cases_ran, 3);
    assert_eq!(result.cases_returned, 3);
    assert_eq!(result.cases_refused, 0);
    assert_eq!(result.cases_not_run, 0);
    assert!(!result.budget_exhausted);

    // The order is the request's, so a result can be read against the list that
    // produced it without matching on anything.
    let names: Vec<&str> = result.cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names, ["zero", "small", "wrap"]);

    let d0 = |index: usize| {
        result.cases[index]
            .outputs
            .as_ref()
            .expect("a case that ran has outputs")
            .d[0]
    };
    assert_eq!(d0(0), 0);
    assert_eq!(d0(1), 5);
    // ADD.W is a word operation: the low word wraps and the high word is the
    // input's. Asserted because it is the kind of thing a sweep exists to find.
    assert_eq!(d0(2) & 0xffff, 0);
}

/// Each case carries the digest of *its own* request, and no two differ by
/// nothing.
///
/// This is what makes a matrix a set of ordinary calls: a case can be cited,
/// re-run through `env.sandbox.call`, and shown to be the same recipe. A shared
/// digest would make every case of a sweep indistinguishable in a record.
#[test]
fn each_case_is_digested_on_its_own_and_none_shares_the_recipe_s() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxMatrixArguments::new(base(), vec![case("a", 1, 1), case("b", 2, 2)]),
        &context,
    );

    let first = &result.cases[0].recipe_sha256;
    let second = &result.cases[1].recipe_sha256;
    assert_ne!(first, second, "two different inputs digested the same");
    assert_ne!(first, &result.base_recipe_sha256);
    assert_ne!(second, &result.base_recipe_sha256);
    assert_eq!(first.len(), 64);
}

/// A case whose *inputs* are identical to the shared recipe's still gets the
/// shared recipe's digest, because it is the same call.
///
/// The complement of the test above, and the one that would catch a digest that
/// mixed the case's name in: a name is how a result is read back, not part of
/// what was executed.
#[test]
fn a_case_that_overrides_nothing_digests_as_the_shared_recipe() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxMatrixArguments::new(base(), vec![SandboxMatrixCase::new("as-is")]),
        &context,
    );
    assert_eq!(result.cases[0].recipe_sha256, result.base_recipe_sha256);
}

/// One malformed case refuses the whole matrix, before anything runs.
///
/// The alternative — expanding as you go — is what a shell loop does, and it
/// leaves a partial sweep whose coverage nobody can state. This is the same
/// recover-then-commit rule the extraction path follows, applied to execution.
#[test]
fn a_malformed_case_refuses_the_matrix_rather_than_half_of_it() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
            SandboxMatrixArguments::new(
                base(),
                vec![
                    case("fine", 1, 1),
                    // Not hex, so normalization refuses it.
                    SandboxMatrixCase::new("broken")
                        .with_memory_seeds(vec![amiga_operations::MemorySeed::hex(0x2_0000, "zz")]),
                    case("also-fine", 2, 2),
                ],
            ),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none(), "a refused matrix ran something");

    // And the path names the case, with the seed index the caller wrote rather
    // than the one it had after expansion. A path that resolved to a different
    // seed would be worse than none, because a reader would act on it.
    let paths: Vec<&str> = outcome
        .diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.json_path.as_deref())
        .collect();
    assert!(
        paths.contains(&"$.request.arguments.cases[1].memory_seeds[0].hex"),
        "{paths:?}"
    );
}

/// Two cases under one name are refused: a name is how a result is matched back
/// to the case that produced it, and two candidates is no answer.
#[test]
fn two_cases_may_not_share_a_name() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
            SandboxMatrixArguments::new(base(), vec![case("same", 1, 1), case("same", 2, 2)]),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);

    // A name that is not one path component goes the same way, because a case
    // names an artifact.
    for bad in ["", "a/b", "..", "."] {
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
                SandboxMatrixArguments::new(base(), vec![SandboxMatrixCase::new(bad)]),
            )),
            &context,
        );
        assert_eq!(outcome.status, Status::Error, "{bad:?} was accepted");
    }
}

/// A matrix with no cases is refused rather than reported as a sweep that
/// passed, which is what a zero-of-zero success would read as.
#[test]
fn a_matrix_needs_at_least_one_case() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
            SandboxMatrixArguments::new(base(), Vec::new()),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
}

/// The aggregate budget stops the sweep, and the cases it stopped are reported
/// as not run rather than dropped.
///
/// A case is never clipped to what is left: one stopped by the *matrix's* budget
/// would carry a stop reason that says nothing about the routine and would read
/// exactly like one that ran out on its own.
#[test]
fn cases_past_the_aggregate_budget_are_reported_rather_than_dropped() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    // Each case may run 64 instructions, so a budget of 64 admits exactly one.
    let result = run(
        SandboxMatrixArguments::new(
            base(),
            vec![
                case("first", 1, 1),
                case("second", 2, 2),
                case("third", 3, 3),
            ],
        )
        .with_maximum_total_steps(64),
        &context,
    );

    assert_eq!(result.cases_total, 3);
    assert_eq!(result.cases_ran, 1);
    assert_eq!(result.cases_not_run, 2);
    assert!(result.budget_exhausted);

    // Every case is still present, and the two that did not run say so.
    assert_eq!(result.cases.len(), 3);
    assert_eq!(result.cases[0].outcome, MatrixCaseOutcome::Ran);
    assert_eq!(result.cases[1].outcome, MatrixCaseOutcome::NotRun);
    assert_eq!(result.cases[2].outcome, MatrixCaseOutcome::NotRun);
    // A case that did not run reports no outputs at all rather than zeroes,
    // which a reader could mistake for a routine that returned zero.
    assert!(result.cases[1].outputs.is_none());
    assert!(result.cases[1].stop.is_none());
    // And it still carries its identity, so the sweep can be resumed by name.
    assert_eq!(result.cases[1].name, "second");
    assert_eq!(result.cases[1].recipe_sha256.len(), 64);
}

/// A case that faults does not end the matrix. The sweep exists to find out
/// which inputs behave differently, and one that faulted is a finding.
#[test]
fn a_faulting_case_is_a_result_rather_than_the_end_of_the_sweep() {
    // MOVEA.L D0,A0 ; MOVE.W (A0),D1 ; RTS — reads through whatever D0 holds.
    let resolver = resolver(image(&[0x20, 0x40, 0x32, 0x10, 0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let result = run(
        SandboxMatrixArguments::new(
            base(),
            vec![
                // Inside the mapped hunk.
                case("mapped", 0x2_0000, 0),
                // Nowhere at all.
                case("unmapped", 0x7fff_0000, 0),
                case("mapped-again", 0x2_0004, 0),
            ],
        ),
        &context,
    );

    assert_eq!(result.cases_total, 3);
    // The two good cases ran either side of the bad one, which is the property:
    // a fault in the middle did not cost the cases after it.
    assert_eq!(result.cases[0].outcome, MatrixCaseOutcome::Ran);
    assert_eq!(result.cases[2].outcome, MatrixCaseOutcome::Ran);
    // The faulting case ran too — an unmapped read is a stop reason, not a
    // refusal — so what it reports is a stop rather than a diagnostic.
    assert_eq!(result.cases[1].outcome, MatrixCaseOutcome::Ran);
    assert!(!result.cases[1].returned);
    assert_eq!(result.cases_returned, 2);
    assert_eq!(result.cases_ran, 3);
}

/// A case's changed memory is reported as a digest per run, not as bytes — and
/// two cases that changed memory differently have different digests.
#[test]
fn changed_memory_is_reported_as_a_digest_a_reader_can_compare() {
    // MOVE.W D0,(A0) ; RTS — writes its input into a mapped buffer.
    let resolver = resolver(image(&[0x30, 0x80, 0x4e, 0x75], 64));
    let context = ExecutionContext::new(&resolver);
    let base = SandboxCallArguments::new(
        SandboxRunArguments::new("game")
            .at_origin(0x2_0000)
            .with_maximum_steps(64),
    )
    .with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: 0x10_0000,
        size: 64,
    }]);
    let with_a0 = |name: &str, value: u32| {
        SandboxMatrixCase::new(name)
            .with_data_registers([value, 0, 0, 0, 0, 0, 0, 0])
            .with_address_registers([0x10_0000, 0, 0, 0, 0, 0, 0])
    };
    let result = run(
        SandboxMatrixArguments::new(
            base,
            vec![with_a0("wrote-one", 0x1111), with_a0("wrote-two", 0x2222)],
        ),
        &context,
    );

    for case in &result.cases {
        assert_eq!(case.outcome, MatrixCaseOutcome::Ran);
        assert_eq!(case.changed_regions.len(), 1, "{}", case.name);
        assert_eq!(case.changed_regions[0].address, 0x10_0000);
        assert_eq!(case.changed_regions[0].length, 2);
        assert_eq!(case.changed_regions[0].sha256.len(), 64);
        assert!(!case.changed_regions_truncated);
        assert_eq!(case.changed_regions_total, 1);
    }
    assert_ne!(
        result.cases[0].changed_regions[0].sha256, result.cases[1].changed_regions[0].sha256,
        "two cases that wrote different bytes digested the same"
    );
}

/// A matrix in which every case is refused still returns a result, and that
/// result still says why each one was.
///
/// The tempting shape is to answer with nothing when nothing succeeded. It is
/// wrong: the per-case diagnostics are the only thing a failed sweep is for, and
/// an empty answer would send the caller back to run the cases one at a time to
/// learn what the matrix already knew. Found by writing a test whose cases all
/// failed for a reason the test could not see.
#[test]
fn a_matrix_where_nothing_ran_still_reports_why_each_case_did_not() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    // Both cases map a region over the derived stack, which `call` refuses.
    let base = base().with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: 0x2_0000,
        size: 64,
    }]);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
            SandboxMatrixArguments::new(base, vec![case("a", 1, 1), case("b", 2, 2)]),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    let result = outcome
        .env_sandbox_matrix()
        .expect("a matrix that refused every case still answers");
    assert_eq!(result.cases_ran, 0);
    assert_eq!(result.cases_refused, 2);
    assert!(
        result.source.is_none(),
        "nothing ran, so nothing read the image"
    );
    for case in &result.cases {
        assert_eq!(case.outcome, MatrixCaseOutcome::Refused);
        assert!(
            !case.diagnostics.is_empty(),
            "{} was refused without saying why",
            case.name
        );
    }
}

/// The shared recipe's own faults are reported where the caller wrote them, not
/// blamed on the first case that inherits one.
///
/// This is the ordering the normalizer depends on: the base is validated first,
/// so anything a case's expansion then fails on came from that case — which is
/// what makes the path rewriting truthful rather than a guess.
#[test]
fn a_fault_in_the_shared_recipe_is_reported_against_the_recipe() {
    let resolver = adder();
    let context = ExecutionContext::new(&resolver);
    let base = base().with_memory_seeds(vec![amiga_operations::MemorySeed::hex(0x2_0000, "zz")]);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxMatrix(
            SandboxMatrixArguments::new(base, vec![case("fine", 1, 1)]),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Error);
    let paths: Vec<&str> = outcome
        .diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.json_path.as_deref())
        .collect();
    assert!(
        paths.contains(&"$.request.arguments.memory_seeds[0].hex"),
        "the recipe's own fault was reported at {paths:?}"
    );
}
