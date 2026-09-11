//! `analysis.hunk.normalize.*` / `provenance.manifest.*`: the two writes whose
//! subject is a derived file rather than a decoded one.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, FilesystemDestinationResolver, HunkNormalizeArguments,
    HunkNormalizeExportArguments, InMemorySourceResolver, ManifestArguments,
    ManifestExportArguments, OperationRequestDocument, RequestEnvelope, ResolvedSource, Router,
    SourceName, Status,
};

fn resolver(name: &str, bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse(name).expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

/// A one-file loader image whose relocations use the compact encoding: one
/// four-longword CODE hunk with relocations at 0, 4, and 8.
fn compact_image() -> Vec<u8> {
    let mut image = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 4] {
        image.extend_from_slice(&value.to_be_bytes());
    }
    image.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    image.extend_from_slice(&4_u32.to_be_bytes());
    image.extend_from_slice(&[0; 16]);
    image.extend_from_slice(&0x0000_03ec_u32.to_be_bytes()); // HUNK_RELOC32
    image.extend_from_slice(&3_u16.to_be_bytes()); // count
    image.extend_from_slice(&0_u16.to_be_bytes()); // target hunk
    image.extend_from_slice(&0_u32.to_be_bytes()); // first offset
    image.push(2); // short delta: +4
    image.extend_from_slice(&[0, 0, 0, 2]); // escaped delta: +4
    image.push(0xa5); // alignment byte, deliberately not zero
    image.extend_from_slice(&0_u16.to_be_bytes()); // end of groups
    image.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    image
}

/// The same image with ordinary relocation records: what normalizing produces.
fn ordinary_image() -> Vec<u8> {
    let mut image = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 4] {
        image.extend_from_slice(&value.to_be_bytes());
    }
    image.extend_from_slice(&0x0000_03e9_u32.to_be_bytes());
    image.extend_from_slice(&4_u32.to_be_bytes());
    image.extend_from_slice(&[0; 16]);
    image.extend_from_slice(&0x0000_03ec_u32.to_be_bytes());
    for value in [3_u32, 0, 0, 4, 8, 0] {
        image.extend_from_slice(&value.to_be_bytes());
    }
    image.extend_from_slice(&0x0000_03f2_u32.to_be_bytes());
    image
}

#[test]
fn normalizing_reports_the_counts_its_own_re_parse_found() {
    let resolver = resolver("loader", compact_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisHunkNormalize(
            HunkNormalizeArguments::new("loader"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let normalized = outcome.analysis_hunk_normalize().expect("a result");
    assert_eq!(normalized.segments, 1);
    assert_eq!(normalized.relocations, 3);
    // The read half reports the digest of what the write half would produce, so
    // a caller can compare two runs without writing either.
    assert_eq!(
        normalized.normalized_sha256,
        amiga_core::sha256(&ordinary_image())
    );
}

#[test]
fn an_image_that_already_parses_is_refused_rather_than_rewritten() {
    // Nothing in the file says which relocation encoding it uses. Reading an
    // ordinary image as compact takes a 16-bit count where a 32-bit one sits and
    // shifts every record after it, producing a file that looks finished and is
    // not — so this must be a refusal, never a rewrite.
    let resolver = resolver("loader", ordinary_image());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AnalysisHunkNormalize(
            HunkNormalizeArguments::new("loader"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::AnalysisHunkAlreadyNormal
    );
}

#[test]
fn a_normalize_export_writes_the_ordinary_image_byte_for_byte() {
    let directory = std::env::temp_dir().join(format!("amiga-re-normalize-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver("loader", compact_image());
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments =
        HunkNormalizeExportArguments::new(HunkNormalizeArguments::new("loader"), "normalized")
            .with_file_name("loader.exe");
    let mut prepare = RequestEnvelope::read(OperationRequestDocument::AnalysisHunkNormalizeExport(
        arguments.clone(),
    ));
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = Router::execute(&prepare, &context);
    assert_eq!(prepared.status, Status::Prepared);
    let plan = prepared
        .analysis_hunk_normalize_export()
        .expect("a plan")
        .plan
        .clone();
    assert!(!directory.exists(), "preparing wrote something");

    let mut commit = RequestEnvelope::read(OperationRequestDocument::AnalysisHunkNormalizeExport(
        arguments,
    ));
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256,
    };
    let committed = Router::execute(&commit, &context);
    assert_eq!(
        committed.status,
        Status::Success,
        "{:?}",
        committed.diagnostics
    );
    assert_eq!(
        std::fs::read(directory.join("normalized/loader.exe")).expect("the image was written"),
        ordinary_image(),
        "byte-for-byte"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_manifest_pins_the_source_it_names() {
    let bytes = b"contents".to_vec();
    let resolver = resolver("disk1.adf", bytes.clone());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::ProvenanceManifest(
            ManifestArguments::new("disk1.adf"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let manifest = outcome.provenance_manifest().expect("a manifest");
    // The resolver's identity, not a host path: a manifest that named a host
    // path would mean something different on another machine.
    assert_eq!(manifest.name, "disk1.adf");
    assert_eq!(manifest.source.size, bytes.len() as u64);
    assert_eq!(manifest.source.sha256, amiga_core::sha256(&bytes));
}

#[test]
fn the_manifest_written_is_the_one_the_plan_described() {
    // The manifest *is* the file, so the plan's digest and the bytes written
    // must come from one serialization. Two would be how a plan ends up
    // describing something other than what lands.
    let directory = std::env::temp_dir().join(format!("amiga-re-manifest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver("disk1.adf", b"contents".to_vec());
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments = ManifestExportArguments::new(ManifestArguments::new("disk1.adf"), "reports")
        .with_file_name("disk1.manifest.json");
    let mut prepare = RequestEnvelope::read(OperationRequestDocument::ProvenanceManifestExport(
        arguments.clone(),
    ));
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let plan = Router::execute(&prepare, &context)
        .provenance_manifest_export()
        .expect("a plan")
        .plan
        .clone();

    let mut commit = RequestEnvelope::read(OperationRequestDocument::ProvenanceManifestExport(
        arguments,
    ));
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

    let written =
        std::fs::read(directory.join("reports/disk1.manifest.json")).expect("it was written");
    assert_eq!(amiga_core::sha256(&written), plan.files[0].sha256);
    let document: serde_json::Value = serde_json::from_slice(&written).expect("valid JSON");
    assert_eq!(document["sha256"], amiga_core::sha256(b"contents"));

    let _ = std::fs::remove_dir_all(&directory);
}
