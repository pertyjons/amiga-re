//! Fixed synthetic inputs, without a test encoder. See fixtures/synthetic/README.md.
use amiga_lha::{Archive, LhaError, crc16};

const TEXT: &[u8] = b"SYNTHETIC ARCHIVE TEST PAYLOAD -- a member worth compressing";

struct Fixture {
    method: &'static [u8; 5],
    compressed: &'static [u8],
    expected: Vec<u8>,
}

fn fixtures() -> Vec<Fixture> {
    let mut fixtures = Vec::new();
    let wide: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
    let mut wide_expected = wide.clone();
    wide_expected.extend_from_slice(&wide[..20]);
    let mut ring: Vec<u8> = (0..=255).flat_map(|i| [i; 300]).collect();
    ring.extend_from_slice(&[255; 20]);
    macro_rules! static_fixtures {
        ($prefix:literal, $method:literal) => {
            for (compressed, expected) in [
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-literals.bin"))
                        .as_slice(),
                    TEXT.to_vec(),
                ),
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-overlap.bin"))
                        .as_slice(),
                    b"ABCABCABC".to_vec(),
                ),
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-repeat.bin"))
                        .as_slice(),
                    vec![b'Z'; 17],
                ),
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-boundary.bin"))
                        .as_slice(),
                    vec![b'Z'; 8206],
                ),
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-spaces.bin"))
                        .as_slice(),
                    b"A    ".to_vec(),
                ),
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-wide.bin"))
                        .as_slice(),
                    wide_expected.clone(),
                ),
                (
                    include_bytes!(concat!("../fixtures/synthetic/", $prefix, "-ring.bin"))
                        .as_slice(),
                    ring.clone(),
                ),
            ] {
                fixtures.push(Fixture {
                    method: $method,
                    compressed,
                    expected,
                });
            }
        };
    }
    static_fixtures!("lh45", b"-lh4-");
    static_fixtures!("lh45", b"-lh5-");
    static_fixtures!("lh67", b"-lh6-");
    static_fixtures!("lh67", b"-lh7-");
    for (compressed, expected) in [
        (
            include_bytes!("../fixtures/synthetic/lh1-literals.bin").as_slice(),
            (0..300).map(|i| (i % 251) as u8).collect(),
        ),
        (
            include_bytes!("../fixtures/synthetic/lh1-overlap.bin").as_slice(),
            b"abcabcabc".to_vec(),
        ),
        (
            include_bytes!("../fixtures/synthetic/lh1-spaces.bin").as_slice(),
            b"    ".to_vec(),
        ),
        (
            include_bytes!("../fixtures/synthetic/lh1-rebuild.bin").as_slice(),
            (0..200_000).map(|i| (i % 7) as u8).collect(),
        ),
    ] {
        fixtures.push(Fixture {
            method: b"-lh1-",
            compressed,
            expected,
        });
    }
    fixtures
}

fn member(method: &[u8; 5], compressed: &[u8], original: &[u8]) -> Vec<u8> {
    let mut header = method.to_vec();
    header.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_le_bytes());
    header.extend_from_slice(&u32::try_from(original.len()).unwrap().to_le_bytes());
    header.extend_from_slice(&[0; 4]);
    header.extend_from_slice(&[0x20, 0, 1, b'x']);
    header.extend_from_slice(&crc16(original).to_le_bytes());
    let mut bytes = vec![
        header.len() as u8,
        header.iter().fold(0u8, |a, b| a.wrapping_add(*b)),
    ];
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(compressed);
    bytes
}

#[test]
fn all_supported_methods_recover_exact_bytes_and_check_crc() {
    for fixture in fixtures() {
        let bytes = member(fixture.method, fixture.compressed, &fixture.expected);
        let archive = Archive::parse(&bytes).unwrap();
        let entry = &archive.entries()[0];
        assert!(entry.is_readable());
        assert_eq!(
            archive
                .read(entry, amiga_lha::OutputLimit::new(64 * 1024 * 1024))
                .unwrap(),
            fixture.expected,
            "{}",
            entry.method_str()
        );
        let mut bytes = bytes.clone();
        bytes[23] ^= 1;
        fix_header_checksum(&mut bytes);
        let bad_archive = Archive::parse(&bytes).unwrap();
        assert!(matches!(
            bad_archive.read(
                &bad_archive.entries()[0],
                amiga_lha::OutputLimit::new(64 * 1024 * 1024)
            ),
            Err(LhaError::CrcMismatch { .. })
        ));
    }
}

#[test]
fn truncated_payloads_cannot_read_a_following_member() {
    for fixture in fixtures() {
        for keep in [
            0,
            1,
            fixture.compressed.len() / 2,
            fixture.compressed.len() - 1,
        ] {
            let mut bytes = member(
                fixture.method,
                &fixture.compressed[..keep],
                &fixture.expected,
            );
            bytes.extend_from_slice(&member(b"-lh0-", b"next", b"next"));
            let archive = Archive::parse(&bytes).unwrap();
            assert!(
                matches!(
                    archive.read(
                        &archive.entries()[0],
                        amiga_lha::OutputLimit::new(64 * 1024 * 1024)
                    ),
                    Err(LhaError::MalformedStream { .. })
                ),
                "{} accepted {keep} of {} compressed bytes",
                String::from_utf8_lossy(fixture.method),
                fixture.compressed.len()
            );
            assert_eq!(
                archive
                    .read(
                        &archive.entries()[1],
                        amiga_lha::OutputLimit::new(64 * 1024 * 1024)
                    )
                    .unwrap(),
                b"next"
            );
        }
    }
}

#[test]
fn output_stops_at_declared_length_even_during_a_match_or_buffer_boundary() {
    for (method, compressed, full) in [
        (
            b"-lh1-",
            include_bytes!("../fixtures/synthetic/lh1-overlap.bin").as_slice(),
            b"abcabcabc".to_vec(),
        ),
        (
            b"-lh5-",
            include_bytes!("../fixtures/synthetic/lh45-boundary.bin").as_slice(),
            vec![b'Z'; 8206],
        ),
        (
            b"-lh7-",
            include_bytes!("../fixtures/synthetic/lh67-boundary.bin").as_slice(),
            vec![b'Z'; 8206],
        ),
    ] {
        for length in [0, 5, full.len() - 1] {
            let bytes = member(method, compressed, &full[..length]);
            let archive = Archive::parse(&bytes).unwrap();
            assert_eq!(
                archive
                    .read(
                        &archive.entries()[0],
                        amiga_lha::OutputLimit::new(64 * 1024 * 1024)
                    )
                    .unwrap(),
                full[..length]
            );
        }
    }
}

#[test]
fn incomplete_huffman_tables_from_the_removed_encoder_are_rejected() {
    let compressed = include_bytes!("../fixtures/synthetic/incomplete-legacy-lh5.bin");
    let bytes = member(b"-lh5-", compressed, b"A");
    let archive = Archive::parse(&bytes).unwrap();
    assert!(matches!(
        archive.read(
            &archive.entries()[0],
            amiga_lha::OutputLimit::new(64 * 1024 * 1024)
        ),
        Err(LhaError::MalformedStream { .. })
    ));
}

#[test]
fn oversized_declarations_fail_before_decoding() {
    for method in [b"-lh1-", b"-lh4-", b"-lh5-", b"-lh6-", b"-lh7-"] {
        for payload in [&[][..], &[0; 64][..]] {
            let mut bytes = member(method, payload, &[]);
            bytes[11..15].copy_from_slice(&u32::MAX.to_le_bytes());
            fix_header_checksum(&mut bytes);
            let archive = Archive::parse(&bytes).unwrap();
            let entry = &archive.entries()[0];
            assert!(matches!(
                archive.read(entry, amiga_lha::OutputLimit::new(64 * 1024 * 1024)),
                Err(LhaError::OutputLimitExceeded { .. })
            ));
        }
    }
}

fn fix_header_checksum(bytes: &mut [u8]) {
    bytes[1] = bytes[2..2 + usize::from(bytes[0])]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
}

#[test]
fn valid_expansion_requires_the_full_output_budget() {
    for fixture in fixtures() {
        let bytes = member(fixture.method, fixture.compressed, &fixture.expected);
        let archive = Archive::parse(&bytes).unwrap();
        let size = fixture.expected.len() as u64;
        let entry = &archive.entries()[0];
        for limit in [0, size - 1] {
            assert!(matches!(
                archive.read(entry, amiga_lha::OutputLimit::new(limit)),
                Err(LhaError::OutputLimitExceeded { .. })
            ));
        }
        assert_eq!(
            archive
                .read(entry, amiga_lha::OutputLimit::new(size))
                .unwrap(),
            fixture.expected
        );
    }
}

#[test]
fn exhausted_empty_blocks_cannot_supply_nonempty_output() {
    for method in [b"-lh1-", b"-lh4-", b"-lh5-", b"-lh6-", b"-lh7-"] {
        for payload in [&[][..], &[0; 64][..]] {
            let bytes = member(method, payload, &vec![0; 1024 * 1024]);
            let archive = Archive::parse(&bytes).unwrap();
            assert!(matches!(
                archive.read(
                    &archive.entries()[0],
                    amiga_lha::OutputLimit::new(1024 * 1024)
                ),
                Err(LhaError::MalformedStream { .. })
            ));
        }
    }
}
