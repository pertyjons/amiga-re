use super::*;

const MODES: [u8; 4] = [9, 10, 12, 13];

#[test]
fn decodes_a_literal_run() {
    let packed = synthetic_stream(
        &[
            (0, 1),
            (2, 2),
            (u32::from(b'C'), 8),
            (u32::from(b'B'), 8),
            (u32::from(b'A'), 8),
        ],
        3,
    );
    assert_eq!(
        decode_embedded_powerpacker(&packed, MODES),
        Ok(b"ABC".to_vec())
    );
}

#[test]
fn bounded_decode_accepts_output_at_the_limit() {
    let packed = synthetic_stream(
        &[
            (0, 1),
            (2, 2),
            (u32::from(b'C'), 8),
            (u32::from(b'B'), 8),
            (u32::from(b'A'), 8),
        ],
        3,
    );
    assert_eq!(
        decode_embedded_powerpacker_bounded(&packed, MODES, 3),
        Ok(b"ABC".to_vec())
    );
}

#[test]
fn bounded_decode_refuses_the_trailer_before_allocating_its_output() {
    let packed = synthetic_stream(&[(0, 1)], 4);
    assert_eq!(
        decode_embedded_powerpacker_bounded(&packed, MODES, 3),
        Err(PowerPackerError::OutputLimitExceeded { size: 4, limit: 3 })
    );
}

#[test]
fn decodes_an_overlapping_match() {
    let packed = synthetic_stream(&[(0, 1), (0, 2), (u32::from(b'A'), 8), (0, 2), (0, 9)], 3);
    assert_eq!(
        decode_embedded_powerpacker(&packed, MODES),
        Ok(b"AAA".to_vec())
    );
}

#[test]
fn rejects_a_match_outside_the_output() {
    let packed = synthetic_stream(&[(1, 1), (0, 2), (1, 9)], 2);
    assert!(matches!(
        decode_embedded_powerpacker(&packed, MODES),
        Err(PowerPackerError::InvalidDistance { .. })
    ));
}

fn synthetic_stream(fields: &[(u32, u32)], output_size: u32) -> Vec<u8> {
    stream_with_skip(fields, output_size, 0)
}

fn stream_with_skip(fields: &[(u32, u32)], output_size: u32, skip: u8) -> Vec<u8> {
    let mut consumed_bits = vec![1; usize::from(skip)];
    for &(value, count) in fields {
        for shift in (0..count).rev() {
            consumed_bits.push((value >> shift) & 1);
        }
    }
    consumed_bits.resize(consumed_bits.len().next_multiple_of(32), 0);
    let mut words = Vec::new();
    for chunk in consumed_bits.as_chunks::<32>().0 {
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
    packed.extend_from_slice(&((output_size << 8) | u32::from(skip)).to_be_bytes());
    packed
}

const STANDARD_MODES: [[u8; 4]; 5] = [
    [9, 9, 9, 9],
    [9, 10, 10, 10],
    [9, 10, 11, 11],
    [9, 10, 12, 12],
    [9, 10, 12, 13],
];

struct Case {
    fields: Vec<(u32, u32)>,
    expected: Vec<u8>,
}

// Serialize explicit token descriptions, not a compressor: no match search or
// compression decisions are made here. Expected bytes are specified separately.
fn literals(bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut fields = vec![(0, 1)];
    let mut extension = bytes.len() - 1;
    while extension >= 3 {
        fields.push((3, 2));
        extension -= 3;
    }
    fields.push((extension as u32, 2));
    fields.extend(bytes.iter().rev().map(|byte| (u32::from(*byte), 8)));
    fields
}

fn cases(modes: [u8; 4]) -> Vec<Case> {
    let literal: Vec<u8> = (0..512).map(|n| n as u8).collect();
    let mut cases = vec![Case {
        fields: literals(&literal),
        expected: literal,
    }];
    for (mode, distance, expected) in [
        (0, 1, b"AAABCD".as_slice()),
        (1, 2, b"BABABCD".as_slice()),
        (2, 4, b"ABCDABCD".as_slice()),
    ] {
        let mut fields = literals(b"ABCD");
        fields.extend([(mode as u32, 2), (distance - 1, u32::from(modes[mode]))]);
        cases.push(Case {
            fields,
            expected: expected.to_vec(),
        });
    }
    let mut fields = literals(b"AB");
    // Long match: seven-bit distance 2; count 5 + 7 + 7 + 7 + 4 = 30.
    fields.extend([(3, 2), (0, 1), (1, 7), (7, 3), (7, 3), (7, 3), (4, 3)]);
    cases.push(Case {
        fields,
        expected: b"AB".repeat(16),
    });
    let seed: Vec<u8> = (0..129).collect();
    let mut fields = literals(&seed);
    fields.extend([(3, 2), (1, 1), (128, u32::from(modes[3])), (7, 3), (0, 3)]);
    let mut expected = seed[117..].to_vec();
    expected.extend_from_slice(&seed);
    cases.push(Case { fields, expected });
    let mut fields = literals(b"A");
    fields.extend([
        (0, 2),
        (0, u32::from(modes[0])),
        (1, 1),
        (1, 2),
        (0, u32::from(modes[1])),
    ]);
    fields.extend(literals(b"BC"));
    cases.push(Case {
        fields,
        expected: b"BCAAAAAA".to_vec(),
    });
    cases
}

#[test]
fn all_standard_modes_and_initial_skips_decode_exact_bytes() {
    for modes in STANDARD_MODES {
        for case in cases(modes) {
            for skip in 0..32 {
                let packed = stream_with_skip(&case.fields, case.expected.len() as u32, skip);
                assert_eq!(
                    decode_embedded_powerpacker(&packed, modes).unwrap(),
                    case.expected,
                    "modes={modes:?}, skip={skip}"
                );
                assert!(matches!(
                    decode_embedded_powerpacker_bounded(&packed, modes, case.expected.len() - 1),
                    Err(PowerPackerError::OutputLimitExceeded { .. })
                ));
            }
        }
    }
}

#[test]
fn impossible_length_extensions_are_refused_before_they_terminate() {
    let literals = synthetic_stream(&[(0, 1), (3, 2)], 1);
    assert_eq!(
        decode_embedded_powerpacker(&literals, MODES),
        Err(PowerPackerError::LiteralExceedsOutput {
            count: 4,
            remaining: 1
        })
    );
    let mut fields = self::literals(b"A");
    fields.extend([(3, 2), (0, 1), (0, 7), (7, 3)]);
    let matches = synthetic_stream(&fields, 7);
    assert_eq!(
        decode_embedded_powerpacker(&matches, MODES),
        Err(PowerPackerError::MatchExceedsOutput {
            count: 12,
            remaining: 6
        })
    );
    let minimum = synthetic_stream(&[(1, 1), (3, 2)], 4);
    assert_eq!(
        decode_embedded_powerpacker(&minimum, MODES),
        Err(PowerPackerError::MatchExceedsOutput {
            count: 5,
            remaining: 4
        })
    );
}

#[test]
fn truncated_words_and_invalid_headers_are_refused() {
    for size in [0, 1, 4, 7, 9, 10, 11] {
        assert!(matches!(
            decode_embedded_powerpacker(&vec![0; size], MODES),
            Err(PowerPackerError::InvalidPackedSize { .. })
        ));
    }
    let packed = synthetic_stream(&literals(b"ABC"), 3);
    for width in [0, 32, 255] {
        for index in 0..4 {
            let mut modes = MODES;
            modes[index] = width;
            assert_eq!(
                decode_embedded_powerpacker(&packed, modes),
                Err(PowerPackerError::InvalidModeBits { mode_bits: modes })
            );
        }
    }
    for skip in [32, 255] {
        let mut invalid = packed.clone();
        *invalid.last_mut().unwrap() = skip;
        assert_eq!(
            decode_embedded_powerpacker(&invalid, MODES),
            Err(PowerPackerError::InvalidInitialSkip { bits: skip })
        );
    }
    let empty = synthetic_stream(&[(0, 1)], 0);
    assert_eq!(
        decode_embedded_powerpacker(&empty, MODES),
        Err(PowerPackerError::OutputTooLarge { size: 0 })
    );
    for case in cases(MODES) {
        let packed = synthetic_stream(&case.fields, case.expected.len() as u32);
        for start in (4..packed.len() - 4).step_by(4) {
            assert!(decode_embedded_powerpacker(&packed[start..], MODES).is_err());
        }
    }
}

#[test]
fn custom_loader_mode_widths_remain_supported() {
    for width in [1, 7, 16, 31] {
        let mut fields = literals(b"A");
        fields.extend([(0, 2), (0, u32::from(width))]);
        let packed = stream_with_skip(&fields, 3, 31);
        assert_eq!(
            decode_embedded_powerpacker(&packed, [width; 4]).unwrap(),
            b"AAA"
        );
    }
    assert!(matches!(
        read_u32(&[], usize::MAX),
        Err(PowerPackerError::TruncatedBitstream)
    ));
}

#[test]
fn bit_reader_crosses_word_boundaries_without_reordering_bits() {
    let bytes = [0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67];
    let consumed: Vec<u32> = [0x0123_4567_u32, 0x89ab_cdef]
        .into_iter()
        .flat_map(|word| (0..32).map(move |bit| (word >> bit) & 1))
        .collect();
    for skip in 0..32 {
        for width in 0..=32 {
            let mut bits = BackwardBits::new(&bytes);
            bits.read(skip).unwrap();
            let expected = consumed[skip as usize..(skip + width) as usize]
                .iter()
                .fold(0, |value, bit| (value << 1) | bit);
            assert_eq!(bits.read(width).unwrap(), expected);
        }
    }
    let mut bits = BackwardBits::new(&bytes);
    assert_eq!(
        bits.read(33),
        Err(PowerPackerError::InvalidBitCount { count: 33 })
    );
    bits.read(32).unwrap();
    bits.read(32).unwrap();
    assert_eq!(bits.read(1), Err(PowerPackerError::TruncatedBitstream));
}

#[test]
fn compare_with_ancient_when_available() {
    compare_reference("AMIGA_RE_ANCIENT", true);
}

#[test]
fn compare_with_c_reference_when_available() {
    compare_reference("AMIGA_RE_PP_C_REFERENCE", false);
}

fn compare_reference(variable: &str, end_with_literal: bool) {
    let Some(reference) = std::env::var_os(variable) else {
        eprintln!(
            "skipping external PowerPacker comparison: set {variable} to the reference executable"
        );
        return;
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("amiga-pp-reference-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let input = root.join("input.pp20");
    let expected_file = root.join("expected.bin");
    if end_with_literal {
        // This pinned Ancient revision consults another flag after a terminal
        // match. Its verdict changes with an otherwise unused padding bit.
        for trailing_flag in [0, 1] {
            let packed = synthetic_stream(
                &[
                    (0, 1),
                    (0, 2),
                    (u32::from(b'A'), 8),
                    (0, 2),
                    (0, 9),
                    (trailing_flag, 1),
                ],
                3,
            );
            assert_eq!(decode_embedded_powerpacker(&packed, MODES).unwrap(), b"AAA");
            let framed: Vec<u8> = b"PP20"
                .iter()
                .chain(MODES.iter())
                .chain(packed.iter())
                .copied()
                .collect();
            std::fs::write(&input, framed).unwrap();
            std::fs::write(&expected_file, b"AAA").unwrap();
            let result = std::process::Command::new(&reference)
                .arg("verify")
                .arg(&input)
                .arg(&expected_file)
                .output()
                .unwrap();
            assert_eq!(
                result.status.success(),
                trailing_flag == 1,
                "pinned Ancient terminal-match behavior changed"
            );
        }
    }
    let mut compared = 0;
    for modes in STANDARD_MODES {
        for (index, mut case) in cases(modes).into_iter().enumerate() {
            // Ancient tests EOF after the optional literal run, not immediately
            // after a match. End these shared cases with an explicit literal.
            if end_with_literal && (1..=5).contains(&index) {
                case.fields.extend(literals(b"!"));
                case.expected.insert(0, b'!');
            }
            std::fs::write(&expected_file, &case.expected).unwrap();
            for skip in 0..32 {
                let packed = stream_with_skip(&case.fields, case.expected.len() as u32, skip);
                assert_eq!(
                    decode_embedded_powerpacker(&packed, modes).unwrap(),
                    case.expected
                );
                let framed: Vec<u8> = b"PP20"
                    .iter()
                    .chain(modes.iter())
                    .chain(packed.iter())
                    .copied()
                    .collect();
                std::fs::write(&input, framed).unwrap();
                let result = std::process::Command::new(&reference)
                    .arg("verify")
                    .arg(&input)
                    .arg(&expected_file)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{variable} rejected modes={modes:?} skip={skip}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                compared += 1;
            }
        }
    }
    std::fs::remove_dir_all(&root).unwrap();
    eprintln!("{variable} and Rust matched all bytes for {compared} synthetic streams");
}
