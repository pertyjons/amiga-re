//! `audio.pcm.*` / `audio.module.*`: the two audio formats with no IFF wrapper.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, FilesystemDestinationResolver, InMemorySourceResolver, ModuleArguments,
    ModuleExportArguments, OperationRequestDocument, PcmArguments, PcmExportArguments,
    RequestEnvelope, ResolvedSource, Router, SourceName, Status,
};

fn resolver(name: &str, bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse(name).expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

/// A minimal four-channel ProTracker module: one pattern, no sample data.
///
/// Every sample slot is left at zero length, which a real module does and which
/// the decode must still report rather than drop.
fn module_bytes(title: &[u8]) -> Vec<u8> {
    let mut module = vec![0_u8; 1084];
    module[..title.len()].copy_from_slice(title);
    module[950] = 1; // song length, which the parser requires to be 1..=128
    module[1080..1084].copy_from_slice(b"M.K.");
    module.extend(std::iter::repeat_n(0_u8, 64 * 4 * 4));
    module
}

#[test]
fn a_pcm_region_reports_the_rate_it_was_told_beside_the_bytes_it_read() {
    // Raw PCM carries nothing: the rate and the bounds are the request's claim.
    // Echoing them back beside a digest of exactly those bytes is what makes the
    // claim checkable rather than merely plausible.
    let bytes: Vec<u8> = (0..=255_u8).collect();
    let resolver = resolver("game.bin", bytes.clone());
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AudioPcmDecode(
            PcmArguments::new("game.bin", 16, 32, 8287).with_maximum_buckets(8),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let pcm = outcome.audio_pcm_decode().expect("a decode");
    assert_eq!(pcm.offset, 16);
    assert_eq!(pcm.frames, 32);
    assert_eq!(pcm.sample_rate, 8287);
    assert_eq!(pcm.region_sha256, amiga_core::sha256(&bytes[16..48]));
    assert!((1..=8).contains(&pcm.envelope.len()));
}

#[test]
fn a_region_outside_the_source_is_refused_rather_than_truncated() {
    let resolver = resolver("game.bin", vec![0; 16]);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AudioPcmDecode(PcmArguments::new(
            "game.bin", 8, 32, 8287,
        ))),
        &context,
    );

    // A prefix of what was asked for would be a different sample reported under
    // the request's name.
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::SourceRangeOutsideSource
    );
}

#[test]
fn a_rate_of_zero_is_refused_before_the_source_is_opened() {
    // Every consumer divides by the rate, and nothing in raw PCM could supply a
    // better one. This is a bad request, not a failed read.
    let resolver = resolver("game.bin", vec![0; 64]);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AudioPcmDecode(PcmArguments::new(
            "game.bin", 0, 32, 0,
        ))),
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
fn the_same_bytes_at_two_rates_are_two_different_requests() {
    // The rate reaches the WAV header, so it changes what gets written. Two
    // exports that differ only in rate must not share a digest.
    let resolver = resolver("game.bin", (0..=255_u8).collect());
    let context = ExecutionContext::new(&resolver);
    let at = |rate| {
        Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::AudioPcmDecode(PcmArguments::new(
                "game.bin", 0, 32, rate,
            ))),
            &context,
        )
        .normalized_request_sha256
    };
    assert_ne!(at(8287), at(11025));
}

#[test]
fn a_module_reports_every_slot_including_the_empty_ones() {
    let resolver = resolver("song.mod", module_bytes(b"TITLE"));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AudioModuleDecode(
            ModuleArguments::new("song.mod"),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let module = outcome.audio_module_decode().expect("a module");
    assert_eq!(module.title, "TITLE");
    assert_eq!(module.signature, "M.K.");
    assert_eq!(module.channels, 4);
    // A tracker addresses samples by slot number, so all 31 are reported and
    // the numbering is the tracker's own.
    assert_eq!(module.samples.len(), 31);
    assert_eq!(module.samples[0].slot, 1);
    assert_eq!(module.samples[30].slot, 31);
    assert!(module.samples.iter().all(|sample| sample.length == 0));
}

#[test]
fn an_offset_holding_no_module_is_an_error_naming_the_offset() {
    let resolver = resolver("song.mod", module_bytes(b"TITLE"));
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::AudioModuleDecode(
            ModuleArguments::new("song.mod").with_offset(4),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(
        outcome.diagnostics[0].code,
        amiga_operations::DiagnosticCode::AudioModuleUnreadable
    );
    assert_eq!(
        outcome.diagnostics[0].json_path.as_deref(),
        Some("$.request.arguments.offset")
    );
}

#[test]
fn a_module_export_writes_exactly_the_bytes_the_decode_pinned() {
    let directory =
        std::env::temp_dir().join(format!("amiga-re-module-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let bytes = module_bytes(b"TITLE");
    let resolver = resolver("song.mod", bytes.clone());
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments = ModuleExportArguments::new(ModuleArguments::new("song.mod"), "music")
        .with_file_name("title.mod");
    let mut prepare = RequestEnvelope::read(OperationRequestDocument::AudioModuleExport(
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
    let export = prepared.audio_module_export().expect("a plan");
    let plan = export.plan.clone();
    // The plan's digest for the file is the module digest the decode reported:
    // one number, so a reviewer cannot be shown one thing and given another.
    assert_eq!(plan.files[0].sha256, export.module.module_sha256);
    assert!(!directory.exists(), "preparing wrote something");

    let mut commit = RequestEnvelope::read(OperationRequestDocument::AudioModuleExport(arguments));
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
    let written = std::fs::read(directory.join("music/title.mod")).expect("the module was written");
    assert_eq!(written, bytes);
    assert!(directory.join("music/title.mod.manifest.json").exists());

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_pcm_export_writes_a_wav_and_refuses_a_stale_plan() {
    let directory =
        std::env::temp_dir().join(format!("amiga-re-pcm-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver("game.bin", (0..=255_u8).collect());
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments = PcmExportArguments::new(PcmArguments::new("game.bin", 0, 32, 8287), "audio")
        .with_file_name("shot.wav");

    let mut stale =
        RequestEnvelope::read(OperationRequestDocument::AudioPcmExport(arguments.clone()));
    stale.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: "0".repeat(64),
    };
    let refused = Router::execute(&stale, &context);
    assert_eq!(refused.status, Status::Conflict);
    assert!(!directory.exists(), "a conflict wrote something");

    let mut prepare =
        RequestEnvelope::read(OperationRequestDocument::AudioPcmExport(arguments.clone()));
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let plan = Router::execute(&prepare, &context)
        .audio_pcm_export()
        .expect("a plan")
        .plan
        .clone();
    let mut commit = RequestEnvelope::read(OperationRequestDocument::AudioPcmExport(arguments));
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
    let wav = std::fs::read(directory.join("audio/shot.wav")).expect("the WAV was written");
    assert_eq!(&wav[..4], b"RIFF");
    // 44 bytes of header plus the 32 sample bytes.
    assert_eq!(wav.len(), 44 + 32);

    let _ = std::fs::remove_dir_all(&directory);
}
