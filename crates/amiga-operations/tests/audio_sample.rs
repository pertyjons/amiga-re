//! `audio.sample.decode` / `audio.sample.export`: what a sample says about
//! itself, and what gets written when it is converted.

use std::sync::Arc;

use amiga_operations::{
    AudioSampleArguments, AudioSampleExportArguments, ExecutionContext,
    FilesystemDestinationResolver, InMemorySourceResolver, OperationRequestDocument,
    RequestEnvelope, ResolvedSource, Router, SourceName, Status,
};

/// A minimal 8SVX: `VHDR` with `one_shot` frames, then `NAME` and `BODY`.
fn svx(pcm: &[i8], sample_rate: u16) -> Vec<u8> {
    svx_named(pcm, sample_rate, Some(b"beep"))
}

/// The same form with the optional `NAME` under the caller's control.
fn svx_named(pcm: &[i8], sample_rate: u16, name: Option<&[u8]>) -> Vec<u8> {
    let mut vhdr = Vec::new();
    vhdr.extend_from_slice(&(pcm.len() as u32).to_be_bytes()); // one-shot
    vhdr.extend_from_slice(&0_u32.to_be_bytes()); // repeat
    vhdr.extend_from_slice(&0_u32.to_be_bytes()); // samples per cycle
    vhdr.extend_from_slice(&sample_rate.to_be_bytes());
    vhdr.push(1); // octaves
    vhdr.push(0); // compression
    vhdr.extend_from_slice(&0x0001_0000_u32.to_be_bytes()); // volume

    let mut chunks: Vec<(&[u8; 4], Vec<u8>)> = vec![(b"VHDR", vhdr.clone())];
    if let Some(name) = name {
        chunks.push((b"NAME", name.to_vec()));
    }
    chunks.push((b"BODY", pcm.iter().map(|value| *value as u8).collect()));

    let mut body = Vec::new();
    for chunk in chunks {
        let (id, data) = chunk;
        body.extend_from_slice(id);
        body.extend_from_slice(&(data.len() as u32).to_be_bytes());
        body.extend_from_slice(&data);
        if !data.len().is_multiple_of(2) {
            body.push(0);
        }
    }

    let mut form = Vec::new();
    form.extend_from_slice(b"FORM");
    form.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    form.extend_from_slice(b"8SVX");
    form.extend_from_slice(&body);
    form
}

fn resolver(bytes: Vec<u8>) -> InMemorySourceResolver {
    let name = SourceName::parse("beep.8svx").expect("a valid name");
    InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)))
}

#[test]
fn a_sample_reports_what_it_declares_and_a_bounded_envelope() {
    let pcm: Vec<i8> = (0..1000)
        .map(|index| if index % 2 == 0 { 120 } else { -120 })
        .collect();
    let resolver = resolver(svx(&pcm, 8363));
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::AudioSampleDecode(
        AudioSampleArguments::new("beep.8svx").with_maximum_buckets(64),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let sample = outcome.audio_sample_decode().expect("a sample");
    assert_eq!(sample.name, "beep");
    assert_eq!(sample.sample_rate, 8363);
    assert_eq!(sample.frames, 1000);
    // Bounded, and both extremes kept: an averaged envelope of this sample
    // would be a flat line at zero.
    assert!(
        (1..=64).contains(&sample.envelope.len()),
        "the envelope is not bounded: {}",
        sample.envelope.len()
    );
    assert!(sample.envelope.iter().all(|bucket| bucket.maximum == 120));
    assert!(sample.envelope.iter().all(|bucket| bucket.minimum == -120));
}

#[test]
fn a_sample_that_declares_no_rate_is_refused_by_the_parser() {
    let resolver = resolver(svx(&[1, 2, 3, 4], 0));
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::AudioSampleDecode(
        AudioSampleArguments::new("beep.8svx"),
    ));

    // A rate of zero is what a malformed VHDR looks like, and every consumer
    // would divide by it. The parser refuses it, so no operation has to decide
    // what a sample with no rate means.
    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == amiga_operations::DiagnosticCode::AudioSampleUnreadable),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn a_sample_that_carries_no_name_decodes_and_exports() {
    // Only `VHDR` and `BODY` are required by the format, and a sample ripped
    // from a game usually carries nothing else. The response schema has always
    // said `name` is "empty when the file carries none"; this is the sample that
    // makes that true rather than unreachable.
    let directory =
        std::env::temp_dir().join(format!("amiga-re-audio-unnamed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver(svx_named(&[10, -10, 20, -20], 8000, None));
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let request = RequestEnvelope::read(OperationRequestDocument::AudioSampleDecode(
        AudioSampleArguments::new("beep.8svx"),
    ));
    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let sample = outcome.audio_sample_decode().expect("a sample");
    assert_eq!(sample.name, "");
    assert_eq!(sample.frames, 4);

    // And the export still names its own file, because the file name comes from
    // the request rather than from the sample.
    let arguments =
        AudioSampleExportArguments::new(AudioSampleArguments::new("beep.8svx"), "exported")
            .with_file_name("unnamed.wav");
    let mut prepare = RequestEnvelope::read(OperationRequestDocument::AudioSampleExport(
        arguments.clone(),
    ));
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = Router::execute(&prepare, &context);
    let plan = prepared.audio_sample_export().expect("a plan").plan.clone();

    let mut commit = RequestEnvelope::read(OperationRequestDocument::AudioSampleExport(arguments));
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
    let wav = std::fs::read(directory.join("exported/unnamed.wav")).expect("the WAV was written");
    assert_eq!(&wav[..4], b"RIFF");

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_source_that_is_not_a_sample_fails_without_a_result() {
    let resolver = resolver(b"not an IFF file at all".to_vec());
    let context = ExecutionContext::new(&resolver);
    let request = RequestEnvelope::read(OperationRequestDocument::AudioSampleDecode(
        AudioSampleArguments::new("beep.8svx"),
    ));

    let outcome = Router::execute(&request, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == amiga_operations::DiagnosticCode::AudioSampleUnreadable),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_export_prepares_a_plan_and_writes_nothing() {
    let directory = std::env::temp_dir().join(format!("amiga-re-audio-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver(svx(&[10, -10, 20, -20], 8000));
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let arguments =
        AudioSampleExportArguments::new(AudioSampleArguments::new("beep.8svx"), "exported")
            .with_file_name("beep.wav");
    let mut prepare = RequestEnvelope::read(OperationRequestDocument::AudioSampleExport(
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
    let plan = prepared.audio_sample_export().expect("a plan").plan.clone();
    assert_eq!(plan.files[0].path, "beep.wav");
    assert!(!directory.exists(), "preparing wrote something");

    let mut commit = RequestEnvelope::read(OperationRequestDocument::AudioSampleExport(arguments));
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
    let wav = std::fs::read(directory.join("exported/beep.wav")).expect("the WAV was written");
    assert_eq!(&wav[..4], b"RIFF");
    // Beside the WAV, under the name a reader can derive from it: the directory
    // is not this export's to own, so one manifest at its top could not describe
    // whatever else lands there.
    assert!(directory.join("exported/beep.wav.manifest.json").exists());

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn an_export_of_a_sample_with_no_usable_rate_is_refused() {
    // A WAV header has to state a rate, and the parser refuses a sample that
    // declares none, so the export refuses before it plans anything.
    let directory =
        std::env::temp_dir().join(format!("amiga-re-audio-rate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let resolver = resolver(svx(&[1, 2, 3, 4], 0));
    let destinations = FilesystemDestinationResolver::new(&directory);
    let context = ExecutionContext::new(&resolver).with_destinations(&destinations);

    let mut prepare = RequestEnvelope::read(OperationRequestDocument::AudioSampleExport(
        AudioSampleExportArguments::new(AudioSampleArguments::new("beep.8svx"), "exported"),
    ));
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let outcome = Router::execute(&prepare, &context);
    assert_eq!(outcome.status, Status::Error);
    assert!(!directory.exists());
}
