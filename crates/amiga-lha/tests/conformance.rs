//! Fixed external encoder outputs; no encoder or external executable at test time.
//! Source, licenses, commands, and independent checks: fixtures/conformance/README.md.
use amiga_lha::{Archive, LhaError, OutputLimit};

const INPUT_SHA256: &str = "0c2b8a1b2a2bfc561ca8a83e05190c3753675978729a95a9bd6c20df65fa8b5b";
const FIXTURES: [(u8, &[u8], &str); 5] = [
    (
        1,
        include_bytes!("../fixtures/conformance/lh1.bin"),
        "b3d46520a5c971959b543330b22ed66bbcd0dbdfee4ba18ff352a8d542e7c9f5",
    ),
    (
        4,
        include_bytes!("../fixtures/conformance/lh4.bin"),
        "a480e2115c9596e93c855ad955004e9875bc01befd24297ba3990bb17e512437",
    ),
    (
        5,
        include_bytes!("../fixtures/conformance/lh5.bin"),
        "48891dcdb4a9d12b5873072ae60570e55f6f4325f2d1d0c4cfbfbbda5b48a7e5",
    ),
    (
        6,
        include_bytes!("../fixtures/conformance/lh6.bin"),
        "dd7663f706bee810d76dd755b56552261733a4adf70c870002eeb9a6ec648a15",
    ),
    (
        7,
        include_bytes!("../fixtures/conformance/lh7.bin"),
        "92a801e820e6409e35dc05c571f9668b6982011cfdf1c739af346946012a5792",
    ),
];

/// Construct only the expected uncompressed bytes, independent of all codecs.
fn expected_input() -> Vec<u8> {
    let block: Vec<u8> = (0..4096)
        .map(|i| ((i * i + 17 * i + i / 7) % 256) as u8)
        .collect();
    let mut input = Vec::new();
    for n in 0..64 {
        input.extend(std::iter::repeat_n(n as u8, n % 31 + 1));
        input.extend_from_slice(&block[n..n + 2048]);
        input.extend_from_slice(&block);
    }
    input
}

#[test]
fn external_lh1_and_lh4_through_lh7_archives_recover_exact_pinned_input() {
    let expected = expected_input();
    assert_eq!(expected.len(), 394_211);
    assert_eq!(amiga_core::sha256(&expected), INPUT_SHA256);
    for (method, bytes, sha256) in FIXTURES {
        assert_eq!(
            amiga_core::sha256(bytes),
            sha256,
            "LH{method} fixture changed"
        );
        let archive = Archive::parse(bytes).unwrap();
        assert_eq!(archive.entries().len(), 1);
        let entry = &archive.entries()[0];
        assert_eq!(entry.method_str(), format!("-lh{method}-"));
        assert_eq!(entry.header_level(), 0);
        assert_eq!(entry.name(), "pattern.bin");
        assert_eq!(entry.original_size() as usize, expected.len());
        let limit = OutputLimit::new(expected.len() as u64);
        let recovered = archive.read(entry, limit).unwrap();
        assert_eq!(recovered, expected, "LH{method}");
        assert_eq!(amiga_core::sha256(&recovered), INPUT_SHA256);
        assert!(matches!(
            archive.read(entry, OutputLimit::new(limit.bytes() - 1)),
            Err(LhaError::OutputLimitExceeded { .. })
        ));
    }
}

#[test]
fn external_static_streams_exercise_explicit_non_singleton_tables() {
    for (method, bytes, _) in FIXTURES.into_iter().filter(|(method, _, _)| *method >= 4) {
        let archive = Archive::parse(bytes).unwrap();
        let payload = archive.compressed_bytes(&archive.entries()[0]).unwrap();
        // The first 16 stream bits are the token count, followed by the five-bit
        // code-length alphabet count. Zero would signal a singleton tree.
        assert_eq!(
            u16::from_be_bytes([payload[0], payload[1]]),
            2555,
            "LH{method}"
        );
        assert_eq!(
            payload[2] >> 3,
            14,
            "LH{method} must have explicit code lengths"
        );
    }
}
