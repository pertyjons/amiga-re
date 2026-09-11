//! Compressed LHA members reach extraction and HUNK discovery, not just listing.
//!
//! Compressed payloads are fixed synthetic fixtures. Their construction and
//! checksums are recorded in `amiga-lha/fixtures/synthetic/README.md`.

/// A level-0 LHA header followed by `payload`.
fn entry(method: &[u8; 5], name: &str, payload: &[u8], original: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(method);
    body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&u32::try_from(original.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&[0; 4]); // timestamp
    body.push(0x20); // attribute
    body.push(0); // header level
    body.push(u8::try_from(name.len()).unwrap());
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&amiga_lha::crc16(original).to_le_bytes());

    let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    let mut out = vec![u8::try_from(body.len()).unwrap(), checksum];
    out.extend_from_slice(&body);
    out.extend_from_slice(payload);
    out
}

fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes: Vec<u8> = entries.iter().flatten().copied().collect();
    bytes.push(0); // terminator
    bytes
}

/// A tiny but structurally valid HUNK executable, so discovery has something
/// real to find inside the compressed member.
fn hunk_executable() -> Vec<u8> {
    let code: [u8; 4] = [0x4e, 0x71, 0x4e, 0x75]; // NOP ; RTS
    let mut bytes = Vec::new();
    for word in [0x03f3_u32, 0, 1, 0, 0, 1] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    for word in [0x03e9_u32, 1] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&0x03f2_u32.to_be_bytes());
    bytes
}

#[test]
fn a_compressed_member_extracts_to_the_same_bytes_a_stored_one_would() {
    let payload = b"SYNTHETIC ARCHIVE TEST PAYLOAD -- a member worth compressing";
    let bytes = archive(&[
        entry(b"-lh0-", "stored.txt", payload, payload),
        entry(
            b"-lh5-",
            "packed.txt",
            include_bytes!("../fixtures/lha/lh45-literals.bin"),
            payload,
        ),
    ]);

    let prepared = amiga_analysis::prepare_lha_extraction(
        "archive.lha".to_owned(),
        &bytes,
        amiga_lha::OutputLimit::new(1024 * 1024),
    )
    .unwrap_or_else(|error| panic!("preparation failed: {error}"));

    // Both members are recovered, and neither is reported as skipped.
    assert_eq!(prepared.plan.file_count(), 2, "{:?}", prepared.warnings);
    assert!(
        prepared.warnings.is_empty(),
        "a decodable member was skipped: {:?}",
        prepared.warnings
    );

    // The manifest records the same content hash for both, which is the real
    // claim: the decoder recovered the bytes, not merely something of the
    // right length.
    let manifest: serde_json::Value = serde_json::from_slice(&prepared.manifest).unwrap();
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["method"], "-lh0-");
    assert_eq!(files[1]["method"], "-lh5-");
    assert_eq!(
        files[0]["sha256"], files[1]["sha256"],
        "the compressed member did not decode to the stored member's bytes"
    );
    assert_eq!(files[1]["original_size"], payload.len());
}

#[test]
fn a_compressed_hunk_member_becomes_inventoried() {
    let executable = hunk_executable();
    let bytes = archive(&[entry(
        b"-lh5-",
        "game.exe",
        include_bytes!("../fixtures/lha/lh45-hunk.bin"),
        &executable,
    )]);

    let discovery = amiga_analysis::discover_hunk_sources(
        amiga_analysis::HunkDiscoveryKind::Lha,
        &bytes,
        amiga_lha::OutputLimit::new(1024 * 1024),
    )
    .unwrap_or_else(|error| panic!("discovery failed: {error}"));

    assert!(
        discovery.warnings.is_empty(),
        "a decodable member was reported as unscannable: {:?}",
        discovery.warnings
    );
    assert_eq!(
        discovery.sources.len(),
        1,
        "the HUNK inside the compressed member was not found: {discovery:?}"
    );
}

#[test]
fn an_undecodable_method_is_still_reported_rather_than_silently_dropped() {
    // `-lh2-` is not implemented. Extraction must say so instead of pretending
    // the archive held one fewer file.
    let payload = b"whatever bytes";
    let bytes = archive(&[entry(b"-lh2-", "old.txt", payload, payload)]);

    let prepared = amiga_analysis::prepare_lha_extraction(
        "archive.lha".to_owned(),
        &bytes,
        amiga_lha::OutputLimit::new(1024 * 1024),
    )
    .unwrap_or_else(|error| panic!("preparation failed: {error}"));
    assert_eq!(prepared.plan.file_count(), 0);
    assert_eq!(prepared.warnings.len(), 1);
    assert!(
        prepared.warnings[0].contains("-lh2-"),
        "the warning does not name the method: {:?}",
        prepared.warnings
    );
}

#[test]
fn cumulative_output_limits_refuse_extraction_and_discovery() {
    let original = b"SYNTHETIC ARCHIVE TEST PAYLOAD -- a member worth compressing";
    let compressed = include_bytes!("../fixtures/lha/lh45-literals.bin");
    let bytes = archive(&[
        entry(b"-lh5-", "first", compressed, original),
        entry(b"-lh5-", "second", compressed, original),
    ]);
    let exact = 2 * original.len() as u64;
    for limit in [0, original.len() as u64, exact - 1] {
        let limit = amiga_lha::OutputLimit::new(limit);
        assert!(matches!(
            amiga_analysis::prepare_lha_extraction("two.lha", &bytes, limit),
            Err(amiga_analysis::ExtractionPreparationError::Lha(
                amiga_lha::LhaError::OutputLimitExceeded { .. }
            ))
        ));
        assert!(matches!(
            amiga_analysis::discover_hunk_sources(
                amiga_analysis::HunkDiscoveryKind::Lha,
                &bytes,
                limit
            ),
            Err(amiga_analysis::HunkDiscoveryError::Lha(
                amiga_lha::LhaError::OutputLimitExceeded { .. }
            ))
        ));
    }
    let prepared = amiga_analysis::prepare_lha_extraction(
        "two.lha",
        &bytes,
        amiga_lha::OutputLimit::new(exact),
    )
    .unwrap();
    assert_eq!(prepared.plan.file_count(), 2);
    for file in prepared.plan.files() {
        assert_eq!(file.bytes, original);
    }
}
