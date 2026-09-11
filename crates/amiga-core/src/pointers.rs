//! Discovery of plausible pointer and jump tables in big-endian data.

/// How table entries encode their target address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerEncoding {
    /// A big-endian absolute 32-bit address.
    Long,
    /// A big-endian unsigned word, scaled and added to `origin`.
    ScaledWord(u32),
}

impl PointerEncoding {
    fn width(self) -> usize {
        match self {
            Self::Long => 4,
            Self::ScaledWord(_) => 2,
        }
    }
}

/// A consecutive run of plausible pointer entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointerTable {
    /// Byte offset of the first entry in the scanned slice.
    pub offset: u32,
    pub encoding: PointerEncoding,
    /// Decoded targets in table order.
    pub targets: Vec<u32>,
}

/// Find runs whose decoded targets all lie inside `[target_start, target_end)`.
///
/// Longword tables are considered at both legal MC68000 alignments (offsets 0
/// and 2 modulo 4). Scaled-word targets are `origin + raw * scale`.
#[must_use]
pub fn scan(
    bytes: &[u8],
    target_start: u32,
    target_end: u32,
    origin: u32,
    encoding: PointerEncoding,
    minimum: usize,
) -> Vec<PointerTable> {
    if target_start >= target_end || minimum == 0 {
        return Vec::new();
    }
    let width = encoding.width();
    let alignments: &[usize] = if width == 4 { &[0, 2] } else { &[0] };
    let mut tables = Vec::new();
    for &alignment in alignments {
        let mut offset = alignment;
        let mut run_start = offset;
        let mut targets = Vec::new();
        while offset
            .checked_add(width)
            .is_some_and(|end| end <= bytes.len())
        {
            let target = decode(bytes, offset, origin, encoding)
                .filter(|target| *target != 0 && (target_start..target_end).contains(target));
            if let Some(target) = target {
                if targets.is_empty() {
                    run_start = offset;
                }
                targets.push(target);
            } else {
                finish_run(&mut tables, run_start, encoding, &mut targets, minimum);
            }
            offset += width;
        }
        finish_run(&mut tables, run_start, encoding, &mut targets, minimum);
    }
    tables.sort_by_key(|table| table.offset);
    tables
}

fn decode(bytes: &[u8], offset: usize, origin: u32, encoding: PointerEncoding) -> Option<u32> {
    match encoding {
        PointerEncoding::Long => Some(u32::from_be_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        )),
        PointerEncoding::ScaledWord(scale) => {
            let raw = u32::from(u16::from_be_bytes(
                bytes.get(offset..offset + 2)?.try_into().ok()?,
            ));
            origin.checked_add(raw.checked_mul(scale)?)
        }
    }
}

fn finish_run(
    tables: &mut Vec<PointerTable>,
    start: usize,
    encoding: PointerEncoding,
    targets: &mut Vec<u32>,
    minimum: usize,
) {
    if targets.len() >= minimum
        && let Ok(offset) = u32::try_from(start)
    {
        tables.push(PointerTable {
            offset,
            encoding,
            targets: std::mem::take(targets),
        });
    } else {
        targets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_even_aligned_longword_runs() {
        let bytes = [
            0xff, 0xff, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x10, 0x08, 0xff, 0xff,
        ];
        let tables = scan(&bytes, 0x1000, 0x1100, 0, PointerEncoding::Long, 2);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].offset, 2);
        assert_eq!(tables[0].targets, [0x1002, 0x1008]);
    }

    #[test]
    fn decodes_scaled_word_offsets() {
        let bytes = [0, 1, 0, 3, 0xff, 0xff];
        let tables = scan(
            &bytes,
            0x1000,
            0x1100,
            0x1000,
            PointerEncoding::ScaledWord(2),
            2,
        );
        assert_eq!(tables[0].targets, [0x1002, 0x1006]);
    }

    #[test]
    fn rejects_zero_minimum_and_wrapping_scaled_targets() {
        assert!(scan(&[0; 8], 0, 10, 0, PointerEncoding::Long, 0).is_empty());
        assert!(
            scan(
                &[0xff, 0xff],
                0,
                u32::MAX,
                u32::MAX,
                PointerEncoding::ScaledWord(u32::MAX),
                1,
            )
            .is_empty()
        );
    }
}
