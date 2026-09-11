//! Conservative Copper-list discovery in a raw binary.
//!
//! Scans for longword-aligned, `$FFFF_FFFE`-terminated Copper lists that program
//! at least a few real display registers, then extracts their palettes and
//! bitplane pointers. The heuristics deliberately reject bitmap data that
//! happens to resemble a list.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::color::rgb4_to_rgb8;

const COPPER_END: [u8; 4] = [0xff, 0xff, 0xff, 0xfe];
const MAX_INSTRUCTIONS: usize = 4096;

/// A Copper list located by [`scan`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CopperList {
    pub start: u32,
    pub end: u32,
    pub instruction_count: usize,
    pub moves: Vec<CopperMove>,
    pub palettes: Vec<CopperPalette>,
    pub bitplane_pointers: Vec<BitplanePointer>,
}

/// One Copper `MOVE #value, register` instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CopperMove {
    pub offset: u32,
    pub register: u16,
    pub value: u16,
}

/// A run of consecutive color registers, decoded as a palette.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CopperPalette {
    pub start_offset: u32,
    pub first_color: u8,
    pub rgb12: Vec<u16>,
    pub rgb8: Vec<[u8; 3]>,
}

/// A bitplane pointer reconstructed from a `BPLxPTH`/`BPLxPTL` pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BitplanePointer {
    pub plane: u8,
    pub high_offset: u32,
    pub low_offset: u32,
    pub address: u32,
    pub points_inside_image: bool,
}

/// Find every plausible Copper list in `image`, keeping the earliest start for
/// each distinct end.
#[must_use]
pub fn scan(image: &[u8]) -> Vec<CopperList> {
    // One implementation, run with a signal that never fires, so the plain and
    // cancellable scans cannot disagree about what a Copper list is.
    scan_cancellable(image, &amiga_core::Never).unwrap_or_default()
}

/// [`scan`], stopping between candidates when `cancel` fires.
///
/// A candidate is one aligned longword position and can walk up to
/// `MAX_INSTRUCTIONS` words, so the checkpoint counts candidates rather than
/// bytes: an item here is far more expensive than a byte.
///
/// # Errors
/// Returns [`amiga_core::Cancelled`] rather than the lists found so far, so a
/// stopped scan can never be mistaken for a complete one.
pub fn scan_cancellable(
    image: &[u8],
    cancel: &impl amiga_core::Cancel,
) -> amiga_core::Cancellable<Vec<CopperList>> {
    let mut by_end = BTreeMap::<u32, CopperList>::new();
    for (index, start) in (0..image.len().saturating_sub(3)).step_by(4).enumerate() {
        if index.is_multiple_of(amiga_core::ITEMS_PER_CHECKPOINT) {
            amiga_core::checkpoint!(cancel);
        }
        if let Some(candidate) = parse_candidate(image, start) {
            by_end
                .entry(candidate.end)
                .and_modify(|existing| {
                    if candidate.start < existing.start {
                        *existing = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }
    Ok(by_end.into_values().collect())
}

fn parse_candidate(image: &[u8], start: usize) -> Option<CopperList> {
    let mut cursor = start;
    let mut moves = Vec::<CopperMove>::new();
    for instruction_count in 1..=MAX_INSTRUCTIONS {
        let bytes = image.get(cursor..cursor.checked_add(4)?)?;
        if bytes == COPPER_END {
            if moves.len() < 3
                || !moves
                    .iter()
                    .any(|entry| is_display_register(entry.register))
            {
                return None;
            }
            let end = cursor.checked_add(4)?;
            return Some(CopperList {
                start: u32::try_from(start).ok()?,
                end: u32::try_from(end).ok()?,
                instruction_count,
                palettes: palettes(&moves),
                bitplane_pointers: bitplane_pointers(&moves, image.len()),
                moves,
            });
        }
        let first = u16::from_be_bytes([bytes[0], bytes[1]]);
        let second = u16::from_be_bytes([bytes[2], bytes[3]]);
        if first & 1 == 0 {
            if !(0x0080..=0x01fe).contains(&first) {
                return None;
            }
            moves.push(CopperMove {
                offset: u32::try_from(cursor).ok()?,
                register: first,
                value: second,
            });
        }
        cursor = cursor.checked_add(4)?;
    }
    None
}

/// Whether `register` is one this scanner treats as a display register: the
/// display-control, bitplane- and sprite-pointer, and color ranges.
#[must_use]
pub fn is_display_register(register: u16) -> bool {
    matches!(register, 0x0080..=0x0096 | 0x00e0..=0x013e | 0x0180..=0x01be)
}

fn palettes(moves: &[CopperMove]) -> Vec<CopperPalette> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while cursor < moves.len() {
        let first = moves[cursor];
        if !(0x0180..=0x01be).contains(&first.register) || first.value > 0x0fff {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < moves.len()
            && moves[cursor].register == moves[cursor - 1].register + 2
            && moves[cursor].register <= 0x01be
            && moves[cursor].value <= 0x0fff
        {
            cursor += 1;
        }
        if cursor - start >= 2 {
            let rgb12 = moves[start..cursor]
                .iter()
                .map(|entry| entry.value)
                .collect::<Vec<_>>();
            result.push(CopperPalette {
                start_offset: first.offset,
                first_color: u8::try_from((first.register - 0x0180) / 2).unwrap_or_default(),
                rgb8: rgb12.iter().copied().map(rgb4_to_rgb8).collect(),
                rgb12,
            });
        }
    }
    result
}

fn bitplane_pointers(moves: &[CopperMove], image_size: usize) -> Vec<BitplanePointer> {
    let image_size = u32::try_from(image_size).unwrap_or(u32::MAX);
    let mut result = Vec::new();
    for plane in 0_u8..8 {
        let high_register = 0x00e0 + u16::from(plane) * 4;
        let low_register = high_register + 2;
        for pair in moves.windows(2) {
            if pair[0].register == high_register && pair[1].register == low_register {
                let address = u32::from(pair[0].value) << 16 | u32::from(pair[1].value);
                result.push(BitplanePointer {
                    plane: plane + 1,
                    high_offset: pair[0].offset,
                    low_offset: pair[1].offset,
                    address,
                    points_inside_image: address < image_size,
                });
            }
        }
    }
    result
}

/// The display configuration a Copper list programs: plane count, palette, and
/// resolved bitplane pointers. Extracted by [`display_spec`] so a render can pull
/// its geometry and colors straight from the list instead of by hand.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DisplaySpec {
    /// Bitplane count from `BPLCON0` (BPU field), if the register was written.
    pub planes: Option<u8>,
    /// Palette color words in color-register order (index = color number).
    pub palette: Vec<u16>,
    /// Bitplane runtime addresses in plane order, from each `BPLxPTH`/`PTL` pair.
    pub bitplane_addresses: Vec<u32>,
}

/// Extract the display configuration a decoded Copper instruction stream
/// programs: the `BPLCON0` plane count, the `COLORxx` palette, and the resolved
/// `BPLxPTH`/`BPLxPTL` bitplane pointers.
#[must_use]
pub fn display_spec(instructions: &[CopperInstruction]) -> DisplaySpec {
    let mut planes = None;
    let mut palette = vec![0_u16; 32];
    let mut highest_color: Option<usize> = None;
    let mut high = [None; 8];
    let mut low = [None; 8];

    for instruction in instructions {
        let CopperOp::Move { register, value } = instruction.op else {
            continue;
        };
        match register {
            // BPLCON0: the BPU field (bits 14..12) is the bitplane count.
            0x0100 => planes = Some(((value >> 12) & 0x7) as u8),
            // BPL1PTH..BPL8PTL, two words per plane.
            0x00e0..=0x00fe => {
                let plane = usize::from((register - 0x00e0) / 4);
                if (register - 0x00e0).is_multiple_of(4) {
                    high[plane] = Some(value);
                } else {
                    low[plane] = Some(value);
                }
            }
            // COLOR00..COLOR31.
            _ if crate::registers::is_color_register(register) => {
                let index = usize::from((register - 0x0180) / 2);
                palette[index] = value & 0x0fff;
                highest_color = Some(highest_color.map_or(index, |seen| seen.max(index)));
            }
            _ => {}
        }
    }

    palette.truncate(highest_color.map_or(0, |index| index + 1));
    let bitplane_addresses = high
        .iter()
        .zip(low.iter())
        .filter_map(|(high, low)| Some((u32::from((*high)?) << 16) | u32::from((*low)?)))
        .collect();

    DisplaySpec {
        planes,
        palette,
        bitplane_addresses,
    }
}

/// One decoded Copper instruction's operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CopperOp {
    /// `MOVE #value, register` (register is the `$DFF000` offset).
    Move { register: u16, value: u16 },
    /// `WAIT` for a beam position.
    Wait {
        vpos: u8,
        hpos: u8,
        vmask: u8,
        hmask: u8,
        blitter_finish_disable: bool,
    },
    /// `SKIP` the next instruction if the beam is at/after a position.
    Skip {
        vpos: u8,
        hpos: u8,
        vmask: u8,
        hmask: u8,
        blitter_finish_disable: bool,
    },
}

/// A decoded Copper instruction with its byte offset in the image.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CopperInstruction {
    pub offset: u32,
    pub op: CopperOp,
}

impl CopperInstruction {
    /// Whether this is the `FFFF FFFE` end-of-list `WAIT`.
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        matches!(
            self.op,
            CopperOp::Wait {
                vpos: 0xff,
                hpos: 0xfe,
                ..
            }
        )
    }
}

/// Which 16-bit half of a 4-byte Copper instruction a write lands in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CopperWord {
    /// The first word: a `MOVE`'s register selector, or a `WAIT`/`SKIP` position.
    Control,
    /// The second word: a `MOVE`'s value, or a `WAIT`/`SKIP` mask.
    Data,
}

/// A Copper instruction word a CPU write patches, described in Copper terms.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CopperPatchSite {
    /// List-relative byte offset of the instruction the write lands in.
    pub instruction_offset: u32,
    /// Which half of the instruction the write targets.
    pub word: CopperWord,
    /// A Copper-relative description, e.g. `COLOR02 value` or `WAIT position`.
    pub description: String,
}

/// Map a list-relative byte `offset` to the decoded Copper instruction word it
/// lands in, describing the field in Copper terms. `instructions` come from
/// [`decode`] over the list's own bytes (so their offsets are list-relative).
/// Returns `None` when `offset` is past the decoded list.
#[must_use]
pub fn patch_site(instructions: &[CopperInstruction], offset: u32) -> Option<CopperPatchSite> {
    for instruction in instructions {
        let start = instruction.offset;
        let end = start.checked_add(4)?;
        if !(start..end).contains(&offset) {
            continue;
        }
        let word = if offset < start.checked_add(2)? {
            CopperWord::Control
        } else {
            CopperWord::Data
        };
        return Some(CopperPatchSite {
            instruction_offset: start,
            word,
            description: describe_field(instruction.op, word),
        });
    }
    None
}

/// A Copper-relative name for the `word` of `op`.
fn describe_field(op: CopperOp, word: CopperWord) -> String {
    match op {
        CopperOp::Move { register, .. } => {
            let name = crate::registers::register_name(register)
                .unwrap_or_else(|| format!("${register:03x}"));
            match word {
                CopperWord::Control => format!("{name} register-select"),
                CopperWord::Data => format!("{name} value"),
            }
        }
        CopperOp::Wait { .. } => match word {
            CopperWord::Control => "WAIT position".to_owned(),
            CopperWord::Data => "WAIT mask".to_owned(),
        },
        CopperOp::Skip { .. } => match word {
            CopperWord::Control => "SKIP position".to_owned(),
            CopperWord::Data => "SKIP mask".to_owned(),
        },
    }
}

/// Decode the Copper instruction stream at `start`, up to and including the
/// `FFFF FFFE` terminator (or the end of `image`, or a safety cap).
#[must_use]
pub fn decode(image: &[u8], start: usize) -> Vec<CopperInstruction> {
    let mut result = Vec::new();
    let mut cursor = start;
    for _ in 0..MAX_INSTRUCTIONS {
        let Some(end) = cursor.checked_add(4) else {
            break;
        };
        let Some(bytes) = image.get(cursor..end) else {
            break;
        };
        let Ok(offset) = u32::try_from(cursor) else {
            break;
        };
        let first = u16::from_be_bytes([bytes[0], bytes[1]]);
        let second = u16::from_be_bytes([bytes[2], bytes[3]]);
        let op = if first & 1 == 0 {
            CopperOp::Move {
                register: first & 0x01fe,
                value: second,
            }
        } else {
            let vpos = (first >> 8) as u8;
            let hpos = (first & 0x00fe) as u8;
            let vmask = ((second >> 8) & 0x7f) as u8;
            let hmask = (second & 0x00fe) as u8;
            let blitter_finish_disable = second & 0x8000 != 0;
            if second & 1 == 0 {
                CopperOp::Wait {
                    vpos,
                    hpos,
                    vmask,
                    hmask,
                    blitter_finish_disable,
                }
            } else {
                CopperOp::Skip {
                    vpos,
                    hpos,
                    vmask,
                    hmask,
                    blitter_finish_disable,
                }
            }
        };
        result.push(CopperInstruction { offset, op });
        cursor = end;
        if first == 0xffff && second == 0xfffe {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_move_wait_and_terminator() {
        // MOVE #$0F00, COLOR00 ; WAIT (mid-screen) ; end WAIT $FFFF,$FFFE
        let image = [
            0x01, 0x80, 0x0f, 0x00, // MOVE COLOR00, $0F00
            0x2c, 0x01, 0xff, 0x00, // WAIT vpos=$2C
            0xff, 0xff, 0xff, 0xfe, // end
        ];
        let decoded = decode(&image, 0);
        assert_eq!(decoded.len(), 3);
        assert_eq!(
            decoded[0].op,
            CopperOp::Move {
                register: 0x180,
                value: 0x0f00
            }
        );
        assert!(matches!(decoded[1].op, CopperOp::Wait { vpos: 0x2c, .. }));
        assert!(decoded[2].is_terminator());
    }

    #[test]
    fn display_spec_reads_planes_palette_and_pointers() {
        let image = [
            0x01, 0x00, 0x40, 0x00, // BPLCON0 = $4000 -> 4 planes
            0x01, 0x80, 0x00, 0x00, // COLOR00 = $000
            0x01, 0x82, 0x0f, 0xff, // COLOR01 = $FFF
            0x00, 0xe0, 0x00, 0x07, // BPL1PTH = $0007
            0x00, 0xe2, 0x80, 0x00, // BPL1PTL = $8000 -> $78000
            0xff, 0xff, 0xff, 0xfe, // end
        ];
        let spec = display_spec(&decode(&image, 0));
        assert_eq!(spec.planes, Some(4));
        assert_eq!(spec.palette, [0x000, 0xfff]);
        assert_eq!(spec.bitplane_addresses, [0x0007_8000]);
    }

    #[test]
    fn finds_palette_and_bitplane_pointer_in_terminated_list() {
        let image = [
            0x00, 0xe0, 0x00, 0x00, 0x00, 0xe2, 0x00, 0x20, 0x01, 0x80, 0x00, 0x00, 0x01, 0x82,
            0x0f, 0xff, 0xff, 0xff, 0xff, 0xfe,
        ];
        let lists = scan(&image);
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].start, 0);
        assert_eq!(lists[0].palettes[0].rgb12, [0x000, 0xfff]);
        assert_eq!(lists[0].palettes[0].rgb8, [[0, 0, 0], [255, 255, 255]]);
        assert_eq!(lists[0].bitplane_pointers[0].address, 0x20);
        assert!(!lists[0].bitplane_pointers[0].points_inside_image);
    }

    #[test]
    fn rejects_unterminated_and_unaligned_sequences() {
        let unterminated = [0x01, 0x80, 0, 0, 0x01, 0x82, 0, 1, 0x01, 0x84, 0, 2];
        assert!(scan(&unterminated).is_empty());
        let unaligned = [
            0, 0, 0x01, 0x80, 0, 0, 0x01, 0x82, 0, 1, 0x01, 0x84, 0, 2, 0xff, 0xff, 0xff, 0xfe,
        ];
        assert!(scan(&unaligned).is_empty());
    }

    #[test]
    fn patch_site_names_the_move_value_and_register_words() {
        // MOVE COLOR01, $0000 ; end
        let image = [0x01, 0x82, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe];
        let instructions = decode(&image, 0);
        // The value word (offset 2) of the MOVE.
        let value = patch_site(&instructions, 2).unwrap_or_else(|| panic!("no site at 2"));
        assert_eq!(value.instruction_offset, 0);
        assert_eq!(value.word, CopperWord::Data);
        assert_eq!(value.description, "COLOR01 value");
        // The control word (offset 0) selects the register.
        let control = patch_site(&instructions, 0).unwrap_or_else(|| panic!("no site at 0"));
        assert_eq!(control.word, CopperWord::Control);
        assert_eq!(control.description, "COLOR01 register-select");
    }

    #[test]
    fn patch_site_past_the_list_is_none() {
        let image = [0x01, 0x82, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe];
        assert!(patch_site(&decode(&image, 0), 0x40).is_none());
    }

    #[test]
    fn rejects_low_register_moves_that_mimic_a_list_in_bitmap_data() {
        let image = [
            0x00, 0x40, 0, 0, 0x01, 0x80, 0, 0, 0x01, 0x82, 0, 1, 0x01, 0x84, 0, 2, 0xff, 0xff,
            0xff, 0xfe,
        ];
        assert!(parse_candidate(&image, 0).is_none());
    }
}
