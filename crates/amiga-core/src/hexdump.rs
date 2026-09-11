//! Canonical hex + ASCII ("xxd-style") dump rendering.
//!
//! Eyeballing raw bytes is the simplest recon operation, but doing it with an
//! external `xxd -s <whole-file-offset>` forces a hand conversion between the
//! address frames the rest of the toolkit speaks (absolute, hunk-relative,
//! whole-file) — a known source of arithmetic slips. This renderer takes the
//! address to show for the first byte, so the caller keeps the region in
//! whichever frame it resolved, and annotates relocation sites so a data
//! table's pointer structure is visible at a glance. The ASCII gutter makes
//! printable runs stand out inline.

use std::fmt::Write as _;

/// Bytes shown per row.
const ROW: usize = 16;

/// Render `data` as a hex + ASCII dump. The address column starts at
/// `display_start` and increments by one per byte, so the caller decides whether
/// it reads as an absolute, hunk-relative, or whole-file address.
///
/// Each entry in `reloc_sites` is a byte index into `data` at which a 4-byte
/// relocation pointer is stored; every row covering one is annotated with the
/// display-frame address of each site it holds. Indices outside `data` are
/// ignored.
#[must_use]
pub fn render(data: &[u8], display_start: u64, reloc_sites: &[usize]) -> String {
    let mut out = String::new();
    for (row_index, chunk) in data.chunks(ROW).enumerate() {
        let row_start = row_index * ROW;
        let address = display_start.wrapping_add(row_start as u64);
        let mut line = format!("{address:08x}  ");
        // Hex columns, with a gap after the first half so long rows stay legible.
        for column in 0..ROW {
            if column == ROW / 2 {
                line.push(' ');
            }
            match chunk.get(column) {
                Some(byte) => {
                    let _ = write!(line, "{byte:02x} ");
                }
                None => line.push_str("   "),
            }
        }
        // ASCII gutter: printable bytes as themselves, the rest as '.'.
        line.push('|');
        for &byte in chunk {
            line.push(printable(byte));
        }
        line.push('|');
        // Relocation annotations for any sites that start in this row.
        let row_end = row_start + chunk.len();
        let mut annotated = false;
        for &site in reloc_sites {
            if (row_start..row_end).contains(&site) {
                if !annotated {
                    line.push_str("  reloc");
                    annotated = true;
                }
                let _ = write!(line, " {:#x}", display_start.wrapping_add(site as u64));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// A byte shown in the ASCII gutter: printable ASCII as itself, else `.`.
fn printable(byte: u8) -> char {
    if (0x20..=0x7e).contains(&byte) {
        char::from(byte)
    } else {
        '.'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_full_row_with_address_hex_and_ascii() {
        let data = b"ABCDEFGHIJKLMNOP";
        let dump = render(data, 0x1000, &[]);
        assert_eq!(
            dump,
            "00001000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50 |ABCDEFGHIJKLMNOP|\n"
        );
    }

    #[test]
    fn pads_a_short_final_row_and_keeps_columns_aligned() {
        let data = b"\x00\x01\xffhi";
        let dump = render(data, 0, &[]);
        // Five bytes: three hex columns filled, the rest padded, gutter shows the
        // two printable bytes.
        assert_eq!(
            dump,
            "00000000  00 01 ff 68 69                                   |...hi|\n"
        );
    }

    #[test]
    fn address_column_follows_the_display_start() {
        let data = [0_u8; 17];
        let dump = render(&data, 0xe700, &[]);
        let second_row = dump.lines().nth(1).unwrap_or("");
        assert!(
            second_row.starts_with("0000e710  "),
            "second row was {second_row:?}"
        );
    }

    #[test]
    fn annotates_rows_that_hold_relocation_sites() {
        let data = [0_u8; 32];
        // Sites at data-relative 4 (row 0) and 20 (row 1).
        let dump = render(&data, 0x2000, &[4, 20]);
        let rows: Vec<&str> = dump.lines().collect();
        assert!(
            rows[0].ends_with("  reloc 0x2004"),
            "row 0 was {:?}",
            rows[0]
        );
        assert!(
            rows[1].ends_with("  reloc 0x2014"),
            "row 1 was {:?}",
            rows[1]
        );
    }

    #[test]
    fn groups_multiple_sites_in_one_row() {
        let data = [0_u8; 16];
        let dump = render(&data, 0, &[0, 8]);
        assert!(dump.trim_end().ends_with("  reloc 0x0 0x8"), "{dump:?}");
    }

    #[test]
    fn empty_input_renders_nothing() {
        assert_eq!(render(&[], 0x100, &[]), "");
    }
}
