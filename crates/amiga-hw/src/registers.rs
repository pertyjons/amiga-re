//! A map from custom-chip register offset to name.
//!
//! Offsets are relative to the custom-chip base `$DFF000`, the same values that
//! appear in Copper `MOVE` instructions and in `$DFFxxx` operands in
//! disassembled code. Only even offsets name a register.
//!
//! Names and offsets were checked against the
//! [Hardware Reference Manual, Appendix B](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0060.html).
//! The later bitplane 7/8 and FMODE entries use NDK 3.2 R4 `hardware/custom.h`
//! and `hardware/custom.i`. Source hashes and comparison details are recorded
//! in `docs/hardware-and-abi-references.md` in the repository.

/// The custom-chip base address the offsets are relative to.
pub const CUSTOM_BASE: u32 = 0x00df_f000;

/// Name the custom-chip register at `offset` from `$DFF000`, if known.
///
/// Handles the register families (audio, bitplane, sprite, color) by range and
/// the remaining singletons by table. Odd offsets and offsets at or beyond
/// `$200` return `None`.
#[must_use]
pub fn register_name(offset: u16) -> Option<String> {
    if !offset.is_multiple_of(2) || offset >= 0x0200 {
        return None;
    }

    // Audio: four channels of 16 bytes from $0A0.
    if (0x00a0..0x00e0).contains(&offset) {
        let channel = (offset - 0x00a0) / 0x10;
        let field = match (offset - 0x00a0) % 0x10 {
            0x0 => "LCH",
            0x2 => "LCL",
            0x4 => "LEN",
            0x6 => "PER",
            0x8 => "VOL",
            0xa => "DAT",
            _ => return None,
        };
        return Some(format!("AUD{channel}{field}"));
    }
    // Bitplane pointers: eight planes of two words from $0E0.
    if (0x00e0..0x0100).contains(&offset) {
        let plane = (offset - 0x00e0) / 4 + 1;
        let half = ptr_half(offset);
        return Some(format!("BPL{plane}{half}"));
    }
    // Bitplane data: $110..$11E.
    if (0x0110..0x0120).contains(&offset) {
        let plane = (offset - 0x0110) / 2 + 1;
        return Some(format!("BPL{plane}DAT"));
    }
    // Sprite pointers: eight sprites of two words from $120.
    if (0x0120..0x0140).contains(&offset) {
        let sprite = (offset - 0x0120) / 4;
        let half = ptr_half(offset);
        return Some(format!("SPR{sprite}{half}"));
    }
    // Sprite control/data: eight sprites of four words from $140.
    if (0x0140..0x0180).contains(&offset) {
        let sprite = (offset - 0x0140) / 8;
        let field = match (offset - 0x0140) % 8 {
            0 => "POS",
            2 => "CTL",
            4 => "DATA",
            _ => "DATB",
        };
        return Some(format!("SPR{sprite}{field}"));
    }
    // Color palette: 32 entries from $180.
    if (0x0180..0x01c0).contains(&offset) {
        let index = (offset - 0x0180) / 2;
        return Some(format!("COLOR{index:02}"));
    }

    singleton(offset).map(str::to_owned)
}

/// `"PTH"` for a pointer register's high word (4-byte aligned), else `"PTL"`.
fn ptr_half(offset: u16) -> &'static str {
    if offset.is_multiple_of(4) {
        "PTH"
    } else {
        "PTL"
    }
}

fn singleton(offset: u16) -> Option<&'static str> {
    let name = match offset {
        0x002 => "DMACONR",
        0x004 => "VPOSR",
        0x006 => "VHPOSR",
        0x00a => "JOY0DAT",
        0x00c => "JOY1DAT",
        0x00e => "CLXDAT",
        0x010 => "ADKCONR",
        0x016 => "POTGOR",
        0x01a => "DSKBYTR",
        0x01c => "INTENAR",
        0x01e => "INTREQR",
        0x020 => "DSKPTH",
        0x022 => "DSKPTL",
        0x024 => "DSKLEN",
        0x02a => "VPOSW",
        0x02c => "VHPOSW",
        0x02e => "COPCON",
        0x030 => "SERDAT",
        0x032 => "SERPER",
        0x034 => "POTGO",
        0x040 => "BLTCON0",
        0x042 => "BLTCON1",
        0x044 => "BLTAFWM",
        0x046 => "BLTALWM",
        0x048 => "BLTCPTH",
        0x04a => "BLTCPTL",
        0x04c => "BLTBPTH",
        0x04e => "BLTBPTL",
        0x050 => "BLTAPTH",
        0x052 => "BLTAPTL",
        0x054 => "BLTDPTH",
        0x056 => "BLTDPTL",
        0x058 => "BLTSIZE",
        // ECS-only. Named because a write to one is a fact worth reporting even
        // on an OCS chipset, where it changes nothing.
        0x05a => "BLTCON0L",
        0x05c => "BLTSIZV",
        0x05e => "BLTSIZH",
        0x060 => "BLTCMOD",
        0x062 => "BLTBMOD",
        0x064 => "BLTAMOD",
        0x066 => "BLTDMOD",
        0x070 => "BLTCDAT",
        0x072 => "BLTBDAT",
        0x074 => "BLTADAT",
        0x07e => "DSKSYNC",
        0x080 => "COP1LCH",
        0x082 => "COP1LCL",
        0x084 => "COP2LCH",
        0x086 => "COP2LCL",
        0x088 => "COPJMP1",
        0x08a => "COPJMP2",
        0x08c => "COPINS",
        0x08e => "DIWSTRT",
        0x090 => "DIWSTOP",
        0x092 => "DDFSTRT",
        0x094 => "DDFSTOP",
        0x096 => "DMACON",
        0x098 => "CLXCON",
        0x09a => "INTENA",
        0x09c => "INTREQ",
        0x09e => "ADKCON",
        0x100 => "BPLCON0",
        0x102 => "BPLCON1",
        0x104 => "BPLCON2",
        0x106 => "BPLCON3",
        0x108 => "BPL1MOD",
        0x10a => "BPL2MOD",
        0x1dc => "BEAMCON0",
        0x1e4 => "DIWHIGH",
        0x1fc => "FMODE",
        _ => return None,
    };
    Some(name)
}

/// Every known register offset paired with its name, in ascending order.
#[must_use]
pub fn known_registers() -> Vec<(u16, String)> {
    (0..0x0200_u16)
        .step_by(2)
        .filter_map(|offset| register_name(offset).map(|name| (offset, name)))
        .collect()
}

/// Classify a register `offset` into a coarse custom-chip subsystem, for
/// grouping register accesses. Offsets outside the known ranges return `"other"`.
#[must_use]
pub fn subsystem(offset: u16) -> &'static str {
    match offset {
        0x002 | 0x096 => "dma",
        0x018 | 0x01c | 0x01e | 0x09a | 0x09c => "interrupt",
        0x01a | 0x020..=0x024 | 0x07e => "disk",
        0x030 | 0x032 => "serial",
        0x040..=0x074 => "blitter",
        0x080..=0x08c => "copper",
        0x08e..=0x094 | 0x098 => "display",
        0x09e | 0x0a0..=0x0df => "audio",
        0x0e0..=0x0fe | 0x110..=0x11e => "bitplane",
        0x100..=0x10e => "display",
        0x120..=0x17e => "sprite",
        0x180..=0x1be => "color",
        _ => "other",
    }
}

/// Whether `offset` names a color register (`COLOR00`..`COLOR31`, `$180..=$1BE`).
#[must_use]
pub fn is_color_register(offset: u16) -> bool {
    (0x0180..=0x01be).contains(&offset)
}

/// Whether `offset` is the low word of a bitplane or sprite pointer pair (its
/// high word is at `offset - 2`).
#[must_use]
pub fn is_pointer_low(offset: u16) -> bool {
    let pointer = (0x00e0..0x0100).contains(&offset) || (0x0120..0x0140).contains(&offset);
    pointer && offset % 4 == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_register_families() {
        assert_eq!(register_name(0x0a6).as_deref(), Some("AUD0PER"));
        assert_eq!(register_name(0x0d8).as_deref(), Some("AUD3VOL"));
        assert_eq!(register_name(0x0e0).as_deref(), Some("BPL1PTH"));
        assert_eq!(register_name(0x0e2).as_deref(), Some("BPL1PTL"));
        assert_eq!(register_name(0x120).as_deref(), Some("SPR0PTH"));
        assert_eq!(register_name(0x144).as_deref(), Some("SPR0DATA"));
        assert_eq!(register_name(0x180).as_deref(), Some("COLOR00"));
        assert_eq!(register_name(0x1be).as_deref(), Some("COLOR31"));
    }

    #[test]
    fn names_singletons() {
        assert_eq!(register_name(0x096).as_deref(), Some("DMACON"));
        assert_eq!(register_name(0x100).as_deref(), Some("BPLCON0"));
        assert_eq!(register_name(0x088).as_deref(), Some("COPJMP1"));
    }

    #[test]
    fn rejects_odd_and_unknown_offsets() {
        assert_eq!(register_name(0x097), None);
        assert_eq!(register_name(0x200), None);
        assert_eq!(register_name(0x0de), None); // gap in the audio block
    }

    #[test]
    fn lists_a_reasonable_number_of_registers() {
        let registers = known_registers();
        assert!(registers.iter().any(|(offset, _)| *offset == 0x096));
        assert!(registers.len() > 100);
    }

    #[test]
    fn classifies_subsystems() {
        assert_eq!(subsystem(0x096), "dma"); // DMACON
        assert_eq!(subsystem(0x09c), "interrupt"); // INTREQ
        assert_eq!(subsystem(0x058), "blitter"); // BLTSIZE
        assert_eq!(subsystem(0x0a8), "audio"); // AUD0VOL
        assert_eq!(subsystem(0x0e0), "bitplane"); // BPL1PTH
        assert_eq!(subsystem(0x180), "color"); // COLOR00
        assert_eq!(subsystem(0x120), "sprite"); // SPR0PTH
        assert_eq!(subsystem(0x1fc), "other"); // FMODE
    }
}
