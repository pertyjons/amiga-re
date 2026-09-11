//! `compress.*.decode` / `compress.*.export`: what a packed stream says about
//! itself, and what gets written when it is unpacked.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, FilesystemDestinationResolver, InMemorySourceResolver, OperationLimits,
    OperationRequestDocument, PowerpackerArguments, PowerpackerExportArguments, RequestEnvelope,
    ResolvedSource, RleXorArguments, RleXorExportArguments, Router, SourceName, Status,
};

const MARKER: u8 = 0x90;

/// A position-XOR RLE stream for `payload`, encoded literally.
///
/// No run escapes: the point of most tests here is the layout around the body,
/// and a literal body keeps the expected output obvious.
fn literal_stream(payload: &[u8], size_bytes: u8, inline_marker: bool, xor: bool) -> Vec<u8> {
    let mut stream = Vec::new();
    if inline_marker {
        stream.push(MARKER);
    }
    match size_bytes {
        2 => stream.extend_from_slice(&(payload.len() as u16).to_be_bytes()),
        4 => stream.extend_from_slice(&(payload.len() as u32).to_be_bytes()),
        _ => {}
    }
    stream.extend_from_slice(payload);
    if xor {
        stream
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ (index as u8))
            .collect()
    } else {
        stream
    }
}

/// A headerless PowerPacker stream decoding to `ABC`.
fn powerpacker_stream() -> Vec<u8> {
    let fields: &[(u32, u32)] = &[
        (0, 1),
        (2, 2),
        (u32::from(b'C'), 8),
        (u32::from(b'B'), 8),
        (u32::from(b'A'), 8),
    ];
    let mut bits = Vec::new();
    for &(value, count) in fields {
        for shift in (0..count).rev() {
            bits.push((value >> shift) & 1);
        }
    }
    bits.resize(bits.len().next_multiple_of(32), 0);
    let mut words = Vec::new();
    for chunk in bits.as_chunks::<32>().0.iter() {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |word, (index, bit)| word | (bit << index));
        words.push(word.to_be_bytes());
    }
    let mut packed = Vec::new();
    for word in words.into_iter().rev() {
        packed.extend_from_slice(&word);
    }
    packed.extend_from_slice(&(3_u32 << 8).to_be_bytes());
    packed
}

fn resolver(bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse("packed.bin").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

fn rle(marker: u8) -> RleXorArguments {
    RleXorArguments::new("packed.bin", marker)
}

#[test]
fn a_powerpacker_stream_reports_its_shape_without_returning_its_bytes() {
    let resolver = resolver(powerpacker_stream());
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::CompressPowerpackerDecode(
        PowerpackerArguments::new("packed.bin", [9, 10, 12, 13]).with_maximum_output_bytes(3),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let decoded = outcome.compress_decode().expect("a decode");
    assert_eq!(decoded.decoded_bytes, 3);
    assert_eq!(decoded.decoded_sha256, amiga_core::sha256(b"ABC"));
    // PowerPacker carries no declared size the caller can cross-check, so the
    // field is absent rather than invented.
    assert_eq!(decoded.declared_size, None);
}

#[test]
fn the_context_reduces_a_powerpacker_output_limit_before_allocation() {
    let resolver = resolver(powerpacker_stream());
    let context = ExecutionContext::new(&resolver)
        .with_limits(OperationLimits::default().with_maximum_output_bytes(2));
    let request = RequestEnvelope::read(OperationRequestDocument::CompressPowerpackerDecode(
        PowerpackerArguments::new("packed.bin", [9, 10, 12, 13]).with_maximum_output_bytes(4),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::LimitReduced),
        "{:?}",
        outcome.diagnostics
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::LimitExceeded),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn a_wrong_mode_table_fails_rather_than_producing_plausible_bytes() {
    // The whole reason `modes` is required: a headerless stream stores the
    // offset widths outside itself, so nothing in the data can catch a wrong
    // table. It must fail loudly where it can.
    let resolver = resolver(powerpacker_stream());
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::CompressPowerpackerDecode(
        PowerpackerArguments::new("packed.bin", [0, 0, 0, 0]),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::CompressStreamUnreadable),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_rle_stream_reports_the_size_its_field_declares() {
    let resolver = resolver(literal_stream(b"HELLO", 4, false, true));
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(
        rle(MARKER).with_size_field(4, false),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let decoded = outcome.compress_decode().expect("a decode");
    assert_eq!(decoded.decoded_bytes, 5);
    assert_eq!(decoded.declared_size, Some(5));
    assert_eq!(decoded.decoded_sha256, amiga_core::sha256(b"HELLO"));
}

#[test]
fn a_size_field_that_disagrees_is_a_warning_and_not_a_refusal() {
    // The field is a claim about the bytes, not their definition: the decode is
    // still the decode, and swallowing the disagreement would hide the one
    // signal that the recipe is wrong.
    let mut stream = Vec::new();
    stream.extend_from_slice(&99_u32.to_be_bytes());
    stream.extend_from_slice(b"HELLO");
    let stream: Vec<u8> = stream
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ (index as u8))
        .collect();

    let resolver = resolver(stream);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(
            rle(MARKER).with_size_field(4, false),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let decoded = outcome.compress_decode().expect("a decode");
    assert_eq!(decoded.decoded_bytes, 5);
    assert_eq!(decoded.declared_size, Some(99));
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == amiga_operations::DiagnosticCode::CompressDeclaredSizeMismatch
            && diagnostic.severity == amiga_operations::Severity::Warning),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_rle_run_is_refused_before_it_exceeds_the_requested_output_limit() {
    let resolver = resolver(vec![MARKER, u8::MAX, b'A']);
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(
        rle(MARKER).with_xor(false).with_maximum_output_bytes(255),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::LimitExceeded),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn the_context_reduces_a_requested_output_limit_and_enforces_it() {
    let resolver = resolver(vec![MARKER, 4, b'A']);
    let context = ExecutionContext::new(&resolver)
        .with_limits(OperationLimits::default().with_maximum_output_bytes(4));
    let request = RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(
        rle(MARKER).with_xor(false).with_maximum_output_bytes(8),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::LimitReduced),
        "{:?}",
        outcome.diagnostics
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::LimitExceeded),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn two_layouts_over_the_same_bytes_are_two_different_requests() {
    // A stream that carries its marker inline and one that does not decode to
    // different output without either failing. The digest must tell them apart,
    // or a cached artifact from one recipe would satisfy the other.
    let bytes = literal_stream(b"DATA", 0, true, false);
    let resolver = resolver(bytes);
    let context = ExecutionContext::new(&resolver);

    let inline = RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(
        rle(MARKER).with_xor(false).with_inline_marker(true),
    ));
    let plain = RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(
        rle(MARKER).with_xor(false),
    ));

    let from_inline = Router::execute(&inline, &context);
    let from_plain = Router::execute(&plain, &context);
    assert_eq!(from_inline.status, Status::Success);
    assert_eq!(from_plain.status, Status::Success);
    assert_ne!(
        from_inline.normalized_request_sha256, from_plain.normalized_request_sha256,
        "two layouts digested identically"
    );
    assert_ne!(
        from_inline
            .compress_decode()
            .expect("a decode")
            .decoded_sha256,
        from_plain
            .compress_decode()
            .expect("a decode")
            .decoded_sha256,
        "the fixture does not distinguish the two layouts"
    );
}

#[test]
fn a_size_width_the_format_does_not_use_is_refused_before_the_source_is_read() {
    let resolver = resolver(Vec::new());
    let context = ExecutionContext::new(&resolver);
    let mut arguments = rle(MARKER);
    arguments.size_bytes = 3;
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::CompressRleXorDecode(arguments)),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.exit_code(),
        2,
        "a bad request has its own exit code"
    );
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::RequestArgumentOutOfRange
    );
}

#[test]
fn an_export_prepares_a_plan_and_writes_nothing() {
    let directory = std::env::temp_dir().join(format!("amiga-re-compress-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver(literal_stream(b"HELLO", 4, false, true));
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments = RleXorExportArguments::new(rle(MARKER).with_size_field(4, false), "unpacked")
        .with_file_name("map.bin");
    let mut prepare = RequestEnvelope::read(OperationRequestDocument::CompressRleXorExport(
        arguments.clone(),
    ));
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = Router::execute(&prepare, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let plan = prepared.compress_export().expect("a plan").plan.clone();
    assert_eq!(plan.files[0].path, "map.bin");
    assert_eq!(plan.files[0].size, 5);
    assert!(!directory.exists(), "preparing wrote something");

    let mut commit =
        RequestEnvelope::read(OperationRequestDocument::CompressRleXorExport(arguments));
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256.clone(),
    };
    let committed = Router::execute(&commit, &context);
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );
    assert_eq!(
        std::fs::read(directory.join("unpacked/map.bin")).expect("the file was written"),
        b"HELLO"
    );
    // Beside the file, under a name derivable from it: the directory is not this
    // export's to own.
    assert!(directory.join("unpacked/map.bin.manifest.json").exists());

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_commit_naming_a_stale_plan_is_a_conflict_rather_than_a_write() {
    let directory =
        std::env::temp_dir().join(format!("amiga-re-compress-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver(powerpacker_stream());
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments = PowerpackerExportArguments::new(
        PowerpackerArguments::new("packed.bin", [9, 10, 12, 13]),
        "unpacked",
    );
    let mut commit = RequestEnvelope::read(OperationRequestDocument::CompressPowerpackerExport(
        arguments,
    ));
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: "0".repeat(64),
    };
    let outcome = Router::execute(&commit, &context);

    assert_eq!(outcome.status, Status::Conflict);
    assert!(!directory.exists(), "a conflict wrote something");
    assert!(
        outcome.diagnostics.iter().any(
            |diagnostic| diagnostic.code == amiga_operations::DiagnosticCode::OutputPlanChanged
        ),
        "{:?}",
        outcome.diagnostics
    );

    let _ = std::fs::remove_dir_all(&directory);
}
