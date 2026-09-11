//! Reconstructing the frame the OCS display hardware would have shown.
//!
//! A raw framebuffer range is not a frame. Which bytes reach the screen is
//! decided by the bitplane pointers, the plane count and mode in `BPLCON0`, the
//! display window (`DIWSTRT`/`DIWSTOP`), the data fetch (`DDFSTRT`/`DDFSTOP`),
//! the two modulos, the colour registers — and by whatever the Copper changes
//! part-way down the frame. A program that double-buffers is showing one of two
//! buffers and the range says nothing about which; a program that swaps a
//! palette at line 100 is showing two palettes.
//!
//! So this takes the register state a run left, the memory it left, and the
//! Copper list the chipset was pointed at, and produces the picture together
//! with **which raster interval and which pointers supplied every band of it**.
//!
//! ## What is refused rather than approximated
//!
//! A wrong shift or a wrong mode produces a picture that looks nearly right,
//! which is exactly the silent failure this toolkit refuses elsewhere. Every
//! mode this build does not model is therefore named and refused rather than
//! rendered as if it were plain lores planar: HAM, dual playfield, extra
//! half-brite, hires and interlace each change what a pixel *means*, and
//! reconstructing one as the other is not a partial answer but a different
//! picture.

use std::collections::BTreeMap;

use crate::color::rgb4_to_rgb8;
use crate::copper::{CopperInstruction, CopperOp};

/// `$DFF000` register offsets this model reads. Named rather than spelled at
/// each use, because a display is decided by exactly these and a reader should
/// be able to see the whole list.
mod offsets {
    pub const BPLCON0: u16 = 0x100;
    pub const BPLCON1: u16 = 0x102;
    pub const BPLCON2: u16 = 0x104;
    pub const BPL1MOD: u16 = 0x108;
    pub const BPL2MOD: u16 = 0x10a;
    pub const DIWSTRT: u16 = 0x08e;
    pub const DIWSTOP: u16 = 0x090;
    pub const DDFSTRT: u16 = 0x092;
    pub const DDFSTOP: u16 = 0x094;
    pub const BPL1PTH: u16 = 0x0e0;
    pub const SPR0PTH: u16 = 0x120;
    pub const COLOR00: u16 = 0x180;
}

/// `DMACON` bits that decide whether the display fetches at all.
const DMAEN: u16 = 1 << 9;
const BPLEN: u16 = 1 << 8;
const COPEN: u16 = 1 << 7;
const SPREN: u16 = 1 << 5;

/// `BPLCON0` bits that change what a pixel means.
const HIRES: u16 = 1 << 15;
const HAM: u16 = 1 << 11;
const DUAL_PLAYFIELD: u16 = 1 << 10;
const INTERLACE: u16 = 1 << 2;

/// The `BPU` value that means extra half-brite on OCS.
///
/// **Extra half-brite is not a `BPLCON0` bit.** It is what six bitplanes *mean*
/// when neither hold-and-modify nor dual playfield is selected: colours 32–63
/// are the low-intensity halves of 0–31. Bit 9, which this once tested for, is
/// `COLOR` — the composite colour-burst enable that essentially every real
/// program sets, so a one-plane lores screen's canonical `BPLCON0` is `$1200`.
/// Reading bit 9 as the mode therefore refused almost every genuine frame while
/// naming a mode it was not in, and let a real half-brite screen with the burst
/// off through to be rendered as a plain six-plane playfield — the confidently
/// wrong picture this check exists to prevent.
const EXTRA_HALF_BRITE_PLANES: u8 = 6;

/// The most bitplanes an OCS display fetches.
const MAXIMUM_PLANES: usize = 6;

/// The eight sprite DMA channels in OCS.
const MAXIMUM_SPRITES: usize = 8;

/// The most raster rows retained from one sprite DMA chain.
///
/// A normal chain is a few hundred rows. The cap makes a missing terminator in
/// hostile memory a refusal with bounded allocation rather than a walk through
/// the rest of chip RAM.
const MAXIMUM_SPRITE_ROWS: usize = 64 * 1024;

/// The most distinct objects one sprite DMA chain may describe.
const MAXIMUM_SPRITE_OBJECTS: usize = 4096;

/// The custom-chip registers as one run left them.
///
/// A plain snapshot rather than a live page: reconstruction is a question about
/// state, and threading the emulator's own page through here would make this
/// untestable without a sandbox — which is the property the blitter's own model
/// was built for and this one keeps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DisplayRegisters {
    pub bplcon0: u16,
    pub bplcon1: u16,
    pub bplcon2: u16,
    pub diwstrt: u16,
    pub diwstop: u16,
    pub ddfstrt: u16,
    pub ddfstop: u16,
    pub bpl1mod: i16,
    pub bpl2mod: i16,
    /// `BPL1PT`–`BPL6PT`, already assembled from their high and low words.
    pub bitplanes: [u32; MAXIMUM_PLANES],
    /// `SPR0PT`–`SPR7PT`, already assembled from their high and low words.
    pub sprites: [u32; MAXIMUM_SPRITES],
    pub palette: [u16; 32],
    pub dmacon: u16,
}

impl DisplayRegisters {
    /// Read the registers out of a page's final values, where each is `None`
    /// until something has written it.
    ///
    /// An unwritten register reads as zero, which is what the hardware would
    /// hold after a reset — but the *fact* that it was never written is what
    /// [`reconstruct`] reports as a display nobody configured, rather than
    /// rendering a zero-sized window as an empty picture.
    #[must_use]
    pub fn from_page(value: impl Fn(u16) -> Option<u16>) -> (Self, bool) {
        let read = |offset: u16| value(offset).unwrap_or(0);
        let mut bitplanes = [0_u32; MAXIMUM_PLANES];
        for (plane, pointer) in bitplanes.iter_mut().enumerate() {
            let high = read(offsets::BPL1PTH + (plane as u16) * 4);
            let low = read(offsets::BPL1PTH + (plane as u16) * 4 + 2);
            *pointer = (u32::from(high) << 16) | u32::from(low);
        }
        let mut sprites = [0_u32; MAXIMUM_SPRITES];
        for (sprite, pointer) in sprites.iter_mut().enumerate() {
            let high = read(offsets::SPR0PTH + (sprite as u16) * 4);
            let low = read(offsets::SPR0PTH + (sprite as u16) * 4 + 2);
            *pointer = (u32::from(high) << 16) | u32::from(low);
        }
        let mut palette = [0_u16; 32];
        for (index, colour) in palette.iter_mut().enumerate() {
            *colour = read(offsets::COLOR00 + (index as u16) * 2) & 0x0fff;
        }
        let configured = value(offsets::BPLCON0).is_some() && value(offsets::BPL1PTH).is_some();
        (
            Self {
                bplcon0: read(offsets::BPLCON0),
                bplcon1: read(offsets::BPLCON1),
                bplcon2: read(offsets::BPLCON2),
                diwstrt: read(offsets::DIWSTRT),
                diwstop: read(offsets::DIWSTOP),
                ddfstrt: read(offsets::DDFSTRT),
                ddfstop: read(offsets::DDFSTOP),
                bpl1mod: read(offsets::BPL1MOD) as i16,
                bpl2mod: read(offsets::BPL2MOD) as i16,
                bitplanes,
                sprites,
                palette,
                dmacon: read(0x096),
            },
            configured,
        )
    }

    /// How many bitplanes `BPLCON0` fetches.
    #[must_use]
    pub const fn planes(&self) -> u8 {
        ((self.bplcon0 >> 12) & 0x7) as u8
    }
}

/// Why a frame could not be reconstructed, or could only be reconstructed as
/// something other than what the hardware would show.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DisplayError {
    #[error(
        "nothing configured the display: BPLCON0 and the bitplane pointers were never written, \
         so there is no frame to reconstruct rather than an empty one"
    )]
    Unconfigured,
    #[error(
        "BPLCON0 selects {0}, which this build does not model; reconstructing it as plain \
             lores planar would produce a different picture rather than a partial one"
    )]
    UnsupportedMode(&'static str),
    #[error("BPLCON0 fetches {planes} bitplanes; OCS fetches at most {MAXIMUM_PLANES}")]
    TooManyPlanes { planes: u8 },
    #[error(
        "BPLCON1 = {bplcon1:#06x} delays the odd planes by {odd} pixels and the even ones by \
         {even}; outside dual playfield the two halves are one playfield, and shifting them \
         apart would produce a picture no single-playfield display shows"
    )]
    SplitScroll { bplcon1: u16, odd: u8, even: u8 },
    #[error(
        "BPLCON0 fetches no bitplanes, so the display shows the background colour and nothing \
         a reconstruction could be about"
    )]
    NoPlanes,
    #[error(
        "the display window is empty ({width}x{height}): DIWSTRT/DIWSTOP and DDFSTRT/DDFSTOP \
         describe no visible pixels"
    )]
    EmptyWindow { width: usize, height: usize },
    #[error("the frame would be {pixels} pixels, past the {maximum} this call allows")]
    TooLarge { pixels: u64, maximum: u64 },
    #[error(
        "plane {plane} of raster lines {first}..={last} reads [{address:#010x}..+{length:#x}), \
             which the captured memory does not cover"
    )]
    Unmapped {
        plane: usize,
        first: usize,
        last: usize,
        address: u32,
        length: usize,
    },
    #[error(
        "sprite {sprite} DMA reads [{address:#010x}..+{length:#x}), which the captured memory \
         does not cover"
    )]
    SpriteUnmapped {
        sprite: usize,
        address: u32,
        length: usize,
    },
    #[error(
        "sprite {sprite} DMA describes more than {maximum} raster rows; the chain is missing \
         its terminator or is too large to retain safely"
    )]
    SpriteDataTooLong { sprite: usize, maximum: usize },
    #[error(
        "sprite {sprite} DMA describes more than {maximum} objects; the chain is missing its \
         terminator or is too large to retain safely"
    )]
    SpriteChainTooLong { sprite: usize, maximum: usize },
    #[error("sprite {sprite} DMA address arithmetic overflows after {address:#010x}")]
    SpriteAddressOverflow { sprite: usize, address: u32 },
    #[error(
        "sprite {sprite} starts at raster line {vstart} and stops at {vstop}; a sprite that \
         wraps into another frame cannot be reconstructed from one frame's final pointers"
    )]
    SpriteVerticalWrap {
        sprite: usize,
        vstart: usize,
        vstop: usize,
    },
}

/// Something true about the frame that a reader must know and that does not
/// stop it being reconstructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayWarning {
    /// `DMACON` says bitplane or master DMA is off, so the hardware would have
    /// shown nothing. The frame is reconstructed anyway, because a capture
    /// taken mid-initialization is the ordinary case — but what it shows is
    /// what the *pointers* select, not what a screen held.
    DmaOff { dmacon: u16 },
    /// The Copper changed a display register part-way down the frame, so the
    /// picture is several bands. Each is reported in [`Frame::intervals`].
    CopperChangedDisplay { changes: usize },
    /// A Copper instruction this model does not follow was met, so the register
    /// state below it is the state before it. `SKIP` needs a comparison against
    /// the live beam, which a still frame does not have.
    CopperSkipped { at: usize },
    /// `BPLCON1` asks for a horizontal scroll, so every row's leftmost pixels
    /// were taken from the word *before* it. The picture is complete; this says
    /// the reconstruction read memory the display window does not name, which a
    /// reader comparing it against a `--map` needs to know.
    ScrollFetchedExtraWord { pixels: u8 },
    /// Sprite pointers are configured while sprite or master DMA is disabled.
    /// The hardware therefore displays no sprites, and the reconstruction
    /// leaves them out rather than treating stale pointers as live DMA.
    SpriteDmaOff { dmacon: u16 },
}

/// One band of raster lines and the registers that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RasterInterval {
    /// First and last display line this band covers, counted from the top of
    /// the display window rather than from the top of the raster: a consumer
    /// indexes the image, not the beam.
    pub first_line: usize,
    pub last_line: usize,
    /// The raster line the band starts at, so it can be read against a Copper
    /// listing, which counts in raster lines.
    pub first_raster_line: usize,
    /// The bitplane pointers this band was fetched through — the field that
    /// says *which buffer* a double-buffered program was showing.
    pub bitplanes: [u32; MAXIMUM_PLANES],
    /// The sprite DMA pointers in force across this band.
    pub sprites: [u32; MAXIMUM_SPRITES],
    /// Sprite/playfield priority in force across this band.
    pub bplcon2: u16,
    /// The palette in force across this band.
    pub palette: [u16; 32],
}

/// One reconstructed frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub planes: u8,
    /// One palette index per pixel, row-major. Preserved beside the RGBA
    /// because an index is what the program wrote and a colour is only what one
    /// palette made of it — a comparison that had lost the indices could not
    /// tell a palette change from a geometry change.
    pub indices: Vec<u8>,
    /// One origin code per pixel, row-major: zero is the playfield and 1–8
    /// identify the sprite DMA channel whose pixel won priority. An attached
    /// pair uses its lower-numbered channel.
    pub pixel_sources: Vec<PixelSource>,
    /// Four bytes per pixel, resolved through whichever palette was in force on
    /// that line.
    pub rgba: Vec<u8>,
    pub intervals: Vec<RasterInterval>,
    pub warnings: Vec<DisplayWarning>,
}

/// Which display source supplied one visible pixel.
///
/// Kept separately from [`Frame::indices`]: a sprite colour register and a
/// playfield index can have the same number while representing different
/// objects, and collapsing them would make a moved sprite look like changed
/// playfield data in an index-space comparison.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelSource(u8);

impl PixelSource {
    pub const PLAYFIELD: Self = Self(0);

    /// The source code for `channel`, when it is an OCS sprite channel.
    pub const fn sprite(channel: u8) -> Option<Self> {
        if channel < MAXIMUM_SPRITES as u8 {
            Some(Self(channel + 1))
        } else {
            None
        }
    }

    /// The stable byte representation used by operation responses and raw
    /// pixel-source planes.
    pub const fn code(self) -> u8 {
        self.0
    }

    /// The sprite channel, or `None` for a playfield pixel.
    pub const fn sprite_channel(self) -> Option<u8> {
        if self.0 == 0 { None } else { Some(self.0 - 1) }
    }
}

/// Reconstruct the frame `registers` selects out of `memory`.
///
/// `memory` answers with the bytes at an absolute address, or `None` when the
/// capture does not cover them — which is a refusal rather than a black band,
/// because a band of zeros in a reconstructed frame is indistinguishable from a
/// band the program cleared.
///
/// `copper` is the Copper list the chipset was pointed at, already decoded. It
/// is what turns a still register file into a frame: a `WAIT` sets the raster
/// line from which the `MOVE`s below it apply, so a pointer swapped at line 100
/// or a palette changed at line 200 shows up as a band rather than being applied
/// to the whole picture or to none of it.
///
/// # Errors
/// Returns [`DisplayError`] when the display is unconfigured, in a mode this
/// build does not model, empty, larger than `maximum_pixels`, or fetched from
/// memory the capture does not hold.
pub fn reconstruct(
    registers: &DisplayRegisters,
    configured: bool,
    copper: &[CopperInstruction],
    memory: &impl Fn(u32, usize) -> Option<Vec<u8>>,
    maximum_pixels: u64,
) -> Result<Frame, DisplayError> {
    if !configured {
        return Err(DisplayError::Unconfigured);
    }
    let mut warnings = Vec::new();
    check_mode(registers.bplcon0)?;
    let planes = registers.planes();
    if planes == 0 {
        return Err(DisplayError::NoPlanes);
    }
    if planes as usize > MAXIMUM_PLANES {
        return Err(DisplayError::TooManyPlanes { planes });
    }
    // Checked before anything is fetched, because a split delay is a property
    // of the request rather than of the memory. The Copper may set BPLCON1 too,
    // and `ScheduledChange::apply` runs the same check per band.
    let mut scroll = single_playfield_scroll(registers.bplcon1)?;
    if scroll != 0 {
        warnings.push(DisplayWarning::ScrollFetchedExtraWord { pixels: scroll });
    }
    if registers.dmacon & (DMAEN | BPLEN) != (DMAEN | BPLEN) {
        warnings.push(DisplayWarning::DmaOff {
            dmacon: registers.dmacon,
        });
    }
    let sprites_enabled = registers.dmacon & (DMAEN | SPREN) == (DMAEN | SPREN);
    if !sprites_enabled && registers.sprites.iter().any(|pointer| *pointer != 0) {
        warnings.push(DisplayWarning::SpriteDmaOff {
            dmacon: registers.dmacon,
        });
    }

    let (width, height, first_raster_line) = geometry(registers)?;
    let pixels = width as u64 * height as u64;
    if pixels > maximum_pixels {
        return Err(DisplayError::TooLarge {
            pixels,
            maximum: maximum_pixels,
        });
    }

    // The Copper's effect on the display registers, as a schedule of raster
    // lines. Only consulted when the Copper is actually fetching: a list the
    // chipset was never pointed at describes a display that did not happen.
    let mut schedule = if registers.dmacon & (DMAEN | COPEN) == (DMAEN | COPEN) {
        copper_schedule(copper, &mut warnings)
    } else {
        Vec::new()
    };
    // Stable, so the `MOVE`s under one `WAIT` keep the order the program wrote
    // them in while a single cursor can walk the whole list once.
    schedule.sort_by_key(|change| change.line);

    let row_bytes = width / 8;
    let mut indices = vec![0_u8; width * height];
    let mut pixel_sources = vec![PixelSource::PLAYFIELD; width * height];
    let mut rgba = vec![0_u8; width * height * 4];
    let mut intervals: Vec<RasterInterval> = Vec::new();
    let mut sprite_cache: BTreeMap<(usize, u32), Vec<SpriteSpan>> = BTreeMap::new();

    // The state the frame starts in, then each band as the schedule changes it.
    let mut pointers = registers.bitplanes;
    let mut sprite_pointers = registers.sprites;
    let mut palette = registers.palette;
    let mut modulos = (registers.bpl1mod, registers.bpl2mod);
    let mut bplcon2 = registers.bplcon2;
    let mut current = RasterInterval {
        first_line: 0,
        last_line: 0,
        first_raster_line,
        bitplanes: pointers,
        sprites: sprite_pointers,
        bplcon2,
        palette,
    };

    // How much of the schedule has been applied. A cursor rather than a filter
    // on the raster line, because the display window starts far below the top of
    // the raster: the `MOVE`s above the first `WAIT` are scheduled at line zero,
    // and every change the Copper makes before the window opens is part of the
    // state the first visible row is fetched with. Matching the line exactly
    // would drop all of them and reconstruct the frame from whatever the
    // register file happened to hold instead.
    let mut applied = 0_usize;
    for line in 0..height {
        let raster = first_raster_line + line;
        // Apply everything the Copper does at or before this line and after the
        // previous one. A change starts a new band, because the band is what
        // says which pointers a row was fetched through.
        let mut changed = false;
        while let Some(change) = schedule.get(applied) {
            if change.line > raster {
                break;
            }
            change.apply(
                &mut pointers,
                &mut sprite_pointers,
                &mut palette,
                &mut modulos,
                &mut scroll,
                &mut bplcon2,
            )?;
            applied += 1;
            changed = true;
        }
        if changed && line > 0 {
            current.last_line = line - 1;
            intervals.push(current.clone());
            current = RasterInterval {
                first_line: line,
                last_line: line,
                first_raster_line: raster,
                bitplanes: pointers,
                sprites: sprite_pointers,
                bplcon2,
                palette,
            };
        } else if changed {
            current.bitplanes = pointers;
            current.sprites = sprite_pointers;
            current.bplcon2 = bplcon2;
            current.palette = palette;
        }

        // `BPLCON1` delays the playfield by up to fifteen pixels, so the pixel
        // at display column x is the bit the DMA fetched for column x - scroll,
        // and the leftmost `scroll` columns come from the word *before* the row.
        // Fetching that word is why this is not a post-pass over the row: the
        // pixels the shift brings in have to come from somewhere real, and a
        // shift that left them zero would draw a black bar down the left edge
        // of every scrolling playfield.
        let lead_bytes = if scroll == 0 { 0 } else { 2 };
        let fetch_bytes = row_bytes + lead_bytes;
        for (plane, pointer) in pointers.iter_mut().enumerate().take(usize::from(planes)) {
            let address = *pointer;
            let fetch_from = address.wrapping_sub(lead_bytes as u32);
            let bytes = memory(fetch_from, fetch_bytes).ok_or(DisplayError::Unmapped {
                plane,
                first: current.first_line,
                last: line,
                address: fetch_from,
                length: fetch_bytes,
            })?;
            // Capped at what was asked for rather than trusted: `memory` is the
            // caller's, and a closure answering with more would index past the
            // end of the row and panic.
            let lead_bits = lead_bytes * 8;
            for (byte_index, byte) in bytes.iter().take(fetch_bytes).enumerate() {
                for bit in 0..8_usize {
                    // Where this fetched bit is emitted: the shifter's own
                    // arithmetic, with the extra word occupying the columns
                    // below zero that the delay pulls into view.
                    let Some(x) =
                        (byte_index * 8 + bit + usize::from(scroll)).checked_sub(lead_bits)
                    else {
                        continue;
                    };
                    if x >= width {
                        continue;
                    }
                    if (byte >> (7 - bit)) & 1 == 1 {
                        indices[line * width + x] |= 1 << plane;
                    }
                }
            }
            // Odd-numbered bitplanes (1, 3, 5) take BPL1MOD; even ones take
            // BPL2MOD. Counted from one as the hardware names them, which is
            // why plane 0 here is bitplane 1.
            let modulo = if plane.is_multiple_of(2) {
                modulos.0
            } else {
                modulos.1
            };
            *pointer = address
                .wrapping_add(row_bytes as u32)
                .wrapping_add(modulo as u32);
        }

        let mut sprite_lines = [None; MAXIMUM_SPRITES];
        if sprites_enabled {
            for (sprite, pointer) in sprite_pointers.iter().copied().enumerate() {
                if pointer == 0 {
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    sprite_cache.entry((sprite, pointer))
                {
                    entry.insert(sprite_chain(sprite, pointer, memory)?);
                }
                sprite_lines[sprite] = sprite_cache
                    .get(&(sprite, pointer))
                    .and_then(|spans| sprite_line(spans, raster));
            }
        }

        let first_fetched_pixel = i32::from(registers.ddfstrt) * 2 + 17;
        for x in 0..width {
            let index = indices[line * width + x];
            let raster_x = first_fetched_pixel + i32::try_from(x).unwrap_or(i32::MAX);
            let sprite =
                visible_sprite_pixel(&sprite_lines, raster_x, index != 0, (bplcon2 & 0x7) as u8);
            let colour_index = sprite.map_or(index, |(_, colour)| colour);
            if let Some((channel, _)) = sprite
                && let Some(source) = PixelSource::sprite(channel)
            {
                pixel_sources[line * width + x] = source;
            }
            let colour = palette
                .get(usize::from(colour_index))
                .copied()
                .unwrap_or_default();
            let [red, green, blue] = rgb4_to_rgb8(colour);
            let at = (line * width + x) * 4;
            rgba[at] = red;
            rgba[at + 1] = green;
            rgba[at + 2] = blue;
            rgba[at + 3] = 0xff;
        }
    }
    current.last_line = height.saturating_sub(1);
    intervals.push(current);
    if intervals.len() > 1 {
        warnings.push(DisplayWarning::CopperChangedDisplay {
            changes: intervals.len() - 1,
        });
    }

    Ok(Frame {
        width,
        height,
        planes,
        indices,
        pixel_sources,
        rgba,
        intervals,
        warnings,
    })
}

/// One object in a sprite DMA channel's sequential data structure.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SpriteSpan {
    vstart: usize,
    vstop: usize,
    hstart: i32,
    attached: bool,
    /// `SPRxDATA`, then `SPRxDATB`, for each raster row.
    rows: Vec<(u16, u16)>,
}

/// The data one sprite channel presents on one raster line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpriteLine {
    hstart: i32,
    attached: bool,
    data: u16,
    data_b: u16,
}

/// Decode the sequential objects one sprite DMA pointer names.
///
/// Every object begins with `SPRxPOS`/`SPRxCTL`, carries two words per raster
/// row, and is followed immediately by either another control pair or the zero
/// pair that disarms the channel. The whole chain is decoded before rendering
/// any of it, so an unmapped later object cannot leave a plausible partial
/// sprite in the frame.
fn sprite_chain(
    sprite: usize,
    pointer: u32,
    memory: &impl Fn(u32, usize) -> Option<Vec<u8>>,
) -> Result<Vec<SpriteSpan>, DisplayError> {
    let mut at = pointer;
    let mut spans = Vec::new();
    let mut retained_rows = 0_usize;
    let mut previous_stop = None;

    for _ in 0..MAXIMUM_SPRITE_OBJECTS {
        let control = exact_sprite_bytes(sprite, at, 4, memory)?;
        let pos = u16::from_be_bytes([control[0], control[1]]);
        let ctl = u16::from_be_bytes([control[2], control[3]]);
        at = at
            .checked_add(4)
            .ok_or(DisplayError::SpriteAddressOverflow {
                sprite,
                address: at,
            })?;
        if pos == 0 && ctl == 0 {
            return Ok(spans);
        }

        let vstart = usize::from(pos >> 8) | (usize::from(ctl & 0x0004) << 6);
        let vstop = usize::from(ctl >> 8) | (usize::from(ctl & 0x0002) << 7);
        if vstop < vstart {
            return Err(DisplayError::SpriteVerticalWrap {
                sprite,
                vstart,
                vstop,
            });
        }
        // Once a chain names a start the beam has already passed, that object
        // belongs to the next frame. Stop before fetching its data rather than
        // requiring bytes this frame's DMA would not read.
        if previous_stop.is_some_and(|stop| vstart < stop) {
            return Ok(spans);
        }
        let rows = vstop - vstart;
        retained_rows = retained_rows
            .checked_add(rows)
            .filter(|total| *total <= MAXIMUM_SPRITE_ROWS)
            .ok_or(DisplayError::SpriteDataTooLong {
                sprite,
                maximum: MAXIMUM_SPRITE_ROWS,
            })?;
        let length = rows.checked_mul(4).ok_or(DisplayError::SpriteDataTooLong {
            sprite,
            maximum: MAXIMUM_SPRITE_ROWS,
        })?;
        let data = exact_sprite_bytes(sprite, at, length, memory)?;
        at = at
            .checked_add(u32::try_from(length).map_err(|_| {
                DisplayError::SpriteAddressOverflow {
                    sprite,
                    address: at,
                }
            })?)
            .ok_or(DisplayError::SpriteAddressOverflow {
                sprite,
                address: at,
            })?;

        previous_stop = Some(vstop);
        let hstart = i32::from((pos & 0x00ff) << 1 | (ctl & 1));
        let rows = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|words| {
                (
                    u16::from_be_bytes([words[0], words[1]]),
                    u16::from_be_bytes([words[2], words[3]]),
                )
            })
            .collect();
        spans.push(SpriteSpan {
            vstart,
            vstop,
            hstart,
            attached: ctl & 0x0080 != 0,
            rows,
        });
    }

    Err(DisplayError::SpriteChainTooLong {
        sprite,
        maximum: MAXIMUM_SPRITE_OBJECTS,
    })
}

fn exact_sprite_bytes(
    sprite: usize,
    address: u32,
    length: usize,
    memory: &impl Fn(u32, usize) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, DisplayError> {
    let bytes = memory(address, length).ok_or(DisplayError::SpriteUnmapped {
        sprite,
        address,
        length,
    })?;
    if bytes.len() != length {
        return Err(DisplayError::SpriteUnmapped {
            sprite,
            address,
            length,
        });
    }
    Ok(bytes)
}

fn sprite_line(spans: &[SpriteSpan], raster: usize) -> Option<SpriteLine> {
    let span = spans
        .iter()
        .find(|span| (span.vstart..span.vstop).contains(&raster))?;
    let (data, data_b) = span.rows.get(raster - span.vstart).copied()?;
    Some(SpriteLine {
        hstart: span.hstart,
        attached: span.attached,
        data,
        data_b,
    })
}

/// The two-bit value one sprite channel emits at an absolute lores raster x.
fn sprite_value(line: Option<SpriteLine>, raster_x: i32) -> Option<u8> {
    let line = line?;
    let pixel = raster_x.checked_sub(line.hstart)?;
    let pixel = u32::try_from(pixel).ok()?;
    if pixel >= 16 {
        return None;
    }
    let bit = 15 - pixel;
    Some(((line.data >> bit) & 1) as u8 | ((((line.data_b >> bit) & 1) as u8) << 1))
}

/// The sprite and palette register visible at one pixel after fixed sprite
/// priority, attachment and `BPLCON2.PF1P` have been applied.
fn visible_sprite_pixel(
    lines: &[Option<SpriteLine>; MAXIMUM_SPRITES],
    raster_x: i32,
    playfield_opaque: bool,
    pf1p: u8,
) -> Option<(u8, u8)> {
    for group in 0..4_usize {
        let even = group * 2;
        let odd = even + 1;
        let even_value = sprite_value(lines[even], raster_x);
        let odd_value = sprite_value(lines[odd], raster_x);
        let overlap_attached = lines[odd].is_some_and(|line| line.attached)
            && even_value.is_some()
            && odd_value.is_some();

        let candidate = if overlap_attached {
            let value = even_value.unwrap_or(0) | (odd_value.unwrap_or(0) << 2);
            (value != 0).then_some((even as u8, 16 + value))
        } else if even_value.is_some_and(|value| value != 0) {
            let value = even_value.unwrap_or(0);
            Some((even as u8, 16 + (group as u8) * 4 + value))
        } else if odd_value.is_some_and(|value| value != 0) {
            let value = odd_value.unwrap_or(0);
            let colour = if lines[odd].is_some_and(|line| line.attached) {
                // Outside the overlap an attached odd channel supplies the
                // high two bits by itself: registers 20, 24 or 28.
                16 + value * 4
            } else {
                16 + (group as u8) * 4 + value
            };
            Some((odd as u8, colour))
        } else {
            None
        };

        if let Some(candidate) = candidate {
            // PF1P 0 puts the playfield before every group; 4 puts every
            // sprite group before it. A transparent playfield never hides a
            // sprite, whichever position it occupies in the priority chain.
            return (!playfield_opaque || pf1p > group as u8).then_some(candidate);
        }
    }
    None
}

/// Refuse a `BPLCON0` mode this build does not model.
///
/// Half-brite is tested *after* hold-and-modify and dual playfield, and the
/// order is the hardware's rather than a convenience: both of those override
/// what six bitplanes would otherwise mean, so a `BPLCON0` selecting HAM with
/// `BPU` = 6 is a HAM screen and must be named as one.
const fn check_mode(bplcon0: u16) -> Result<(), DisplayError> {
    if bplcon0 & HAM != 0 {
        return Err(DisplayError::UnsupportedMode("hold-and-modify"));
    }
    if bplcon0 & DUAL_PLAYFIELD != 0 {
        return Err(DisplayError::UnsupportedMode("dual playfield"));
    }
    if ((bplcon0 >> 12) & 0x7) as u8 == EXTRA_HALF_BRITE_PLANES {
        return Err(DisplayError::UnsupportedMode("extra half-brite"));
    }
    if bplcon0 & HIRES != 0 {
        return Err(DisplayError::UnsupportedMode("hires"));
    }
    if bplcon0 & INTERLACE != 0 {
        return Err(DisplayError::UnsupportedMode("interlace"));
    }
    Ok(())
}

/// The visible geometry `DIWSTRT`/`DIWSTOP` and `DDFSTRT`/`DDFSTOP` describe.
///
/// The width comes from the *data fetch* rather than from the display window,
/// because the fetch is what decides how many bytes a row consumes — and a
/// reconstruction that read a different number of bytes per row than the
/// hardware did would shear the picture rather than crop it. The height comes
/// from the display window, which is what decides how many rows are fetched at
/// all.
fn geometry(registers: &DisplayRegisters) -> Result<(usize, usize, usize), DisplayError> {
    let words = (u32::from(registers.ddfstop).saturating_sub(u32::from(registers.ddfstrt)) / 8) + 1;
    let width = (words * 16) as usize;

    let vstart = usize::from(registers.diwstrt >> 8);
    // OCS forms the stop line's bit 8 as the complement of bit 7, which is what
    // lets a window end below line 256 with an eight-bit field.
    let raw_stop = usize::from(registers.diwstop >> 8);
    let vstop = if raw_stop & 0x80 == 0 {
        raw_stop | 0x100
    } else {
        raw_stop
    };
    let height = vstop.saturating_sub(vstart);

    if width == 0 || height == 0 || !width.is_multiple_of(8) {
        return Err(DisplayError::EmptyWindow { width, height });
    }
    Ok((width, height, vstart))
}

/// The one horizontal delay a single-playfield display has, in lores pixels.
///
/// `BPLCON1` carries two: bits 3–0 delay the odd bitplanes and bits 7–4 the
/// even ones, which is how dual playfield scrolls its two playfields
/// independently. Outside dual playfield — which [`check_mode`] already refuses
/// — the odd and even planes are one picture, so two different delays would
/// tear it, and every program that scrolls a single playfield writes the same
/// nibble twice. A request that does not is refused rather than served with one
/// of the two numbers picked for it.
const fn single_playfield_scroll(bplcon1: u16) -> Result<u8, DisplayError> {
    let odd = (bplcon1 & 0x0f) as u8;
    let even = ((bplcon1 >> 4) & 0x0f) as u8;
    if odd != even {
        return Err(DisplayError::SplitScroll { bplcon1, odd, even });
    }
    Ok(odd)
}

/// One display-register change the Copper makes, and the raster line it makes
/// it on.
struct ScheduledChange {
    line: usize,
    register: u16,
    value: u16,
}

impl ScheduledChange {
    /// Apply this change to the state the next band is fetched with.
    ///
    /// # Errors
    /// Returns [`DisplayError::SplitScroll`] when the Copper writes a `BPLCON1`
    /// whose two nibbles disagree. Checked here as well as up front, because a
    /// list that scrolls part-way down the frame is the ordinary way a program
    /// scrolls at all — and a band this model cannot describe must refuse where
    /// it appears rather than be reconstructed as the band above it.
    fn apply(
        &self,
        pointers: &mut [u32; MAXIMUM_PLANES],
        sprites: &mut [u32; MAXIMUM_SPRITES],
        palette: &mut [u16; 32],
        modulos: &mut (i16, i16),
        scroll: &mut u8,
        bplcon2: &mut u16,
    ) -> Result<(), DisplayError> {
        match self.register {
            offsets::BPLCON1 => *scroll = single_playfield_scroll(self.value)?,
            offsets::BPLCON2 => *bplcon2 = self.value,
            offsets::BPL1MOD => modulos.0 = self.value as i16,
            offsets::BPL2MOD => modulos.1 = self.value as i16,
            register if (offsets::BPL1PTH..offsets::BPL1PTH + 4 * 8).contains(&register) => {
                let plane = usize::from((register - offsets::BPL1PTH) / 4);
                let Some(pointer) = pointers.get_mut(plane) else {
                    return Ok(());
                };
                if (register - offsets::BPL1PTH).is_multiple_of(4) {
                    *pointer = (*pointer & 0x0000_ffff) | (u32::from(self.value) << 16);
                } else {
                    *pointer = (*pointer & 0xffff_0000) | u32::from(self.value);
                }
            }
            register if (offsets::SPR0PTH..offsets::SPR0PTH + 4 * 8).contains(&register) => {
                let sprite = usize::from((register - offsets::SPR0PTH) / 4);
                let Some(pointer) = sprites.get_mut(sprite) else {
                    return Ok(());
                };
                if (register - offsets::SPR0PTH).is_multiple_of(4) {
                    *pointer = (*pointer & 0x0000_ffff) | (u32::from(self.value) << 16);
                } else {
                    *pointer = (*pointer & 0xffff_0000) | u32::from(self.value);
                }
            }
            register if crate::registers::is_color_register(register) => {
                let index = usize::from((register - offsets::COLOR00) / 2);
                if let Some(colour) = palette.get_mut(index) {
                    *colour = self.value & 0x0fff;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// What the Copper does to the display registers, line by line.
///
/// A `WAIT` sets the line the `MOVE`s under it take effect on; the list before
/// the first `WAIT` is the state the frame starts in and is scheduled at line
/// zero. A `SKIP` is not followed — it needs a comparison against the live beam,
/// which a still frame does not have — and is reported rather than passed over,
/// because the registers below one are then the state before it.
fn copper_schedule(
    instructions: &[CopperInstruction],
    warnings: &mut Vec<DisplayWarning>,
) -> Vec<ScheduledChange> {
    let mut schedule = Vec::new();
    let mut line = 0_usize;
    for (index, instruction) in instructions.iter().enumerate() {
        match instruction.op {
            CopperOp::Move { register, value } => {
                if crate::copper::is_display_register(register)
                    || register == offsets::BPL1MOD
                    || register == offsets::BPL2MOD
                    || (offsets::SPR0PTH..offsets::SPR0PTH + 4 * 8).contains(&register)
                {
                    schedule.push(ScheduledChange {
                        line,
                        register,
                        value,
                    });
                }
            }
            CopperOp::Wait { vpos, .. } => {
                // The end-of-list `WAIT` is a position no beam reaches, so it
                // ends the walk rather than scheduling everything after it at
                // line 255.
                if instruction.is_terminator() {
                    break;
                }
                line = usize::from(vpos);
            }
            CopperOp::Skip { .. } => {
                warnings.push(DisplayWarning::CopperSkipped { at: index });
            }
        }
    }
    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A display of `planes` bitplanes, 16 pixels wide and two lines tall, whose
    /// planes sit consecutively from `base`.
    fn registers(planes: u8, base: u32) -> DisplayRegisters {
        let mut registers = DisplayRegisters {
            bplcon0: u16::from(planes) << 12,
            // 16 pixels: one fetch word.
            ddfstrt: 0x38,
            ddfstop: 0x38,
            // Two lines, from raster line 148. `DIWSTOP` forms its bit 8 as
            // the complement of bit 7, so a stop line is expressible in
            // 128..=255 or 256..=383 and nowhere else — 150 is the first of
            // those, which is why the window is not at the top of the raster.
            diwstrt: 0x9481,
            diwstop: 0x96c1,
            ..DisplayRegisters::default()
        };
        for (plane, pointer) in registers.bitplanes.iter_mut().enumerate() {
            *pointer = base + (plane as u32) * 4;
        }
        registers.palette[1] = 0x0f00;
        registers.palette[2] = 0x00f0;
        registers.palette[3] = 0x000f;
        registers
    }

    /// Memory answering from one flat block at `base`.
    fn block(base: u32, bytes: Vec<u8>) -> impl Fn(u32, usize) -> Option<Vec<u8>> {
        move |address, length| {
            let offset = usize::try_from(address.checked_sub(base)?).ok()?;
            bytes
                .get(offset..offset.checked_add(length)?)
                .map(<[u8]>::to_vec)
        }
    }

    #[test]
    fn two_planes_combine_into_one_index_per_pixel() {
        // Plane 1 is 11110000 and plane 2 is 11001100, so the eight pixels are
        // 3, 3, 1, 1, 2, 2, 0, 0 — the bitwise combination of the two planes
        // rather than either of them alone, which is the whole of what planar
        // means and the thing a per-plane reader gets wrong.
        let memory = block(
            0x2_0000,
            vec![0xf0, 0x00, 0xf0, 0x00, 0xcc, 0x00, 0xcc, 0x00],
        );
        let frame = reconstruct(&registers(2, 0x2_0000), true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(frame.width, 16);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.planes, 2);
        assert_eq!(&frame.indices[0..8], &[3, 3, 1, 1, 2, 2, 0, 0]);
        // And the colours come from the palette rather than from the index.
        assert_eq!(&frame.rgba[0..4], &[0x00, 0x00, 0xff, 0xff]);
    }

    /// The mode bits each change what a pixel means, so each is refused rather
    /// than rendered as plain planar.
    #[test]
    fn a_mode_this_build_does_not_model_is_refused_by_name() {
        let memory = block(0x2_0000, vec![0; 64]);
        for (bit, named) in [
            (HAM, "hold-and-modify"),
            (DUAL_PLAYFIELD, "dual playfield"),
            (HIRES, "hires"),
            (INTERLACE, "interlace"),
        ] {
            let mut modal = registers(2, 0x2_0000);
            modal.bplcon0 |= bit;
            assert_eq!(
                reconstruct(&modal, true, &[], &memory, 1 << 20),
                Err(DisplayError::UnsupportedMode(named))
            );
        }
    }

    /// Half-brite is six bitplanes, not a bit — and the bit it was read from is
    /// one nearly every real program sets.
    ///
    /// Both halves are asserted because they fail in opposite directions. A
    /// `BPLCON0` of `$1200` — one lores plane with the colour burst on, the
    /// canonical value — was refused as half-brite and could not be captured at
    /// all; a genuine half-brite screen with the burst off was accepted and
    /// rendered as a plain six-plane playfield, where colours 32–63 mean half
    /// intensity rather than the palette entries drawn for them.
    #[test]
    fn half_brite_is_six_planes_and_bit_nine_is_the_colour_burst() {
        let memory = block(0x2_0000, vec![0; 256]);

        let mut burst = registers(1, 0x2_0000);
        burst.bplcon0 |= 1 << 9;
        let frame = reconstruct(&burst, true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("an ordinary lores screen was refused: {error}"));
        assert_eq!(frame.planes, 1);

        for bplcon0 in [
            u16::from(EXTRA_HALF_BRITE_PLANES) << 12,
            (u16::from(EXTRA_HALF_BRITE_PLANES) << 12) | (1 << 9),
        ] {
            let mut half_brite = registers(EXTRA_HALF_BRITE_PLANES, 0x2_0000);
            half_brite.bplcon0 = bplcon0;
            assert_eq!(
                reconstruct(&half_brite, true, &[], &memory, 1 << 20),
                Err(DisplayError::UnsupportedMode("extra half-brite")),
                "BPLCON0 {bplcon0:#06x}"
            );
        }

        // And the modes that override what six planes mean are still named as
        // themselves rather than as half-brite.
        for (bit, named) in [(HAM, "hold-and-modify"), (DUAL_PLAYFIELD, "dual playfield")] {
            let mut overridden = registers(EXTRA_HALF_BRITE_PLANES, 0x2_0000);
            overridden.bplcon0 |= bit;
            assert_eq!(
                reconstruct(&overridden, true, &[], &memory, 1 << 20),
                Err(DisplayError::UnsupportedMode(named))
            );
        }
    }

    /// The `MOVE`s above the first `WAIT` set the state the *whole* frame is
    /// fetched with, even though they are scheduled at raster line zero and the
    /// display window opens far below it.
    ///
    /// This is the ordinary shape of a Copper list — pointers and palette at the
    /// top, `WAIT`s below — so a reconstruction that only applied a change whose
    /// line fell inside the window would drop every one of them and rebuild the
    /// frame from whatever the register file happened to hold.
    #[test]
    fn copper_moves_above_the_first_wait_apply_to_the_whole_frame() {
        let memory = block(0x2_0000, {
            let mut bytes = vec![0_u8; 256];
            bytes[0] = 0xff; // what the register file's pointer selects
            bytes[128] = 0x0f; // what the Copper's pointer selects
            bytes
        });
        // No `WAIT` at all: a bare `MOVE`, which is scheduled at line zero while
        // the window starts at raster line 148.
        let copper = vec![CopperInstruction {
            offset: 0,
            op: CopperOp::Move {
                register: 0x0e2,
                value: 0x0080,
            },
        }];
        let mut with_copper = registers(1, 0x2_0000);
        with_copper.dmacon = DMAEN | COPEN | BPLEN;
        let frame = reconstruct(&with_copper, true, &copper, &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        // One band, because the change is in force before the first visible row
        // rather than part-way down.
        assert_eq!(frame.intervals.len(), 1);
        assert_eq!(frame.intervals[0].bitplanes[0], 0x2_0080);
        assert_eq!(&frame.indices[0..8], &[0, 0, 0, 0, 1, 1, 1, 1]);
    }

    /// Sprite pointers are display state too, so a Copper-installed pointer is
    /// the object DMA fetches even when the final register snapshot held zero.
    #[test]
    fn a_copper_sprite_pointer_is_applied_before_dma_fetches_the_object() {
        let base = 0x2_0000;
        let mut bytes = vec![0_u8; 0x120];
        bytes[0x100..0x110].copy_from_slice(&[
            0x94, 0x40, 0x96, 0x01, // raster 148..150, first frame column
            0x80, 0x00, 0x00, 0x00, // one sprite pixel
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // terminator
        ]);
        let memory = block(base, bytes);
        let copper = vec![
            CopperInstruction {
                offset: 0,
                op: CopperOp::Move {
                    register: offsets::SPR0PTH,
                    value: 0x0002,
                },
            },
            CopperInstruction {
                offset: 4,
                op: CopperOp::Move {
                    register: offsets::SPR0PTH + 2,
                    value: 0x0100,
                },
            },
        ];
        let mut display = registers(1, base);
        display.dmacon = DMAEN | BPLEN | SPREN | COPEN;
        display.bplcon2 = 1;

        let frame = reconstruct(&display, true, &copper, &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(frame.intervals[0].sprites[0], base + 0x100);
        assert_eq!(frame.pixel_sources[0].sprite_channel(), Some(0));
    }

    /// A Copper that swaps a bitplane pointer part-way down produces two bands,
    /// and the bands say which pointers each was fetched through.
    ///
    /// This is the double-buffering case the entry exists for: without it the
    /// whole frame would be reconstructed from whichever pointer happened to be
    /// in the register file at the end.
    #[test]
    fn a_copper_pointer_swap_makes_two_bands_that_name_their_own_pointers() {
        let memory = block(0x2_0000, {
            let mut bytes = vec![0_u8; 256];
            bytes[0] = 0xff; // the first buffer's first row
            bytes[128] = 0x0f; // the second buffer's row
            bytes
        });
        let copper = vec![
            CopperInstruction {
                offset: 0,
                op: CopperOp::Wait {
                    vpos: 149,
                    hpos: 0,
                    vmask: 0xff,
                    hmask: 0xfe,
                    blitter_finish_disable: false,
                },
            },
            CopperInstruction {
                offset: 4,
                op: CopperOp::Move {
                    register: 0x0e2,
                    value: 0x0080,
                },
            },
        ];
        let mut with_copper = registers(1, 0x2_0000);
        with_copper.dmacon = DMAEN | COPEN | BPLEN;
        let frame = reconstruct(&with_copper, true, &copper, &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(frame.intervals.len(), 2);
        assert_eq!(frame.intervals[0].bitplanes[0], 0x2_0000);
        assert_eq!(frame.intervals[1].bitplanes[0], 0x2_0080);
        assert_eq!(frame.intervals[1].first_raster_line, 149);
        assert!(
            frame
                .warnings
                .contains(&DisplayWarning::CopperChangedDisplay { changes: 1 })
        );
        // The first row came from the first buffer and the second from the
        // second, which is the whole assertion: eight set pixels then four.
        assert_eq!(&frame.indices[0..8], &[1; 8]);
        assert_eq!(&frame.indices[16..24], &[0, 0, 0, 0, 1, 1, 1, 1]);
    }

    /// A `BPLCON1` scroll moves the playfield right and pulls the pixels it
    /// needs out of the word before the row.
    ///
    /// Hand-computed. The row is `0xf0 0x00` — four set pixels then twelve
    /// clear — and the word before it is `0x00 0x0f`, whose last four bits are
    /// set. A four-pixel delay therefore puts the previous word's four set bits
    /// at columns 0..4 and the row's four at columns 4..8, so the first eight
    /// pixels are all set and the rest are clear. Reconstructing the shift as a
    /// post-pass over the row alone would leave columns 0..4 black, which is a
    /// bar down the left edge of every scrolling playfield.
    #[test]
    fn a_scroll_takes_its_leading_pixels_from_the_word_before_the_row() {
        let mut bytes = vec![0_u8; 256];
        bytes[0] = 0x00; // the word before the first row
        bytes[1] = 0x0f;
        bytes[2] = 0xf0; // the row itself
        bytes[3] = 0x00;
        let memory = block(0x2_0000, bytes);

        let mut scrolled = registers(1, 0x2_0002);
        scrolled.bplcon1 = 0x44;
        let frame = reconstruct(&scrolled, true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(&frame.indices[0..10], &[1, 1, 1, 1, 1, 1, 1, 1, 0, 0]);
        assert!(
            frame
                .warnings
                .contains(&DisplayWarning::ScrollFetchedExtraWord { pixels: 4 }),
            "a reader comparing against a --map needs to know memory outside the \
             window was read: {:?}",
            frame.warnings
        );
    }

    /// And with no scroll the same row is unshifted, so the test above is about
    /// the delay rather than about the fixture.
    #[test]
    fn no_scroll_reads_no_extra_word_and_shifts_nothing() {
        let mut bytes = vec![0_u8; 256];
        bytes[0] = 0x00;
        bytes[1] = 0x0f;
        bytes[2] = 0xf0;
        bytes[3] = 0x00;
        let memory = block(0x2_0000, bytes);

        let frame = reconstruct(&registers(1, 0x2_0002), true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(&frame.indices[0..10], &[1, 1, 1, 1, 0, 0, 0, 0, 0, 0]);
        assert!(
            !frame
                .warnings
                .iter()
                .any(|warning| matches!(warning, DisplayWarning::ScrollFetchedExtraWord { .. })),
            "nothing outside the row was read: {:?}",
            frame.warnings
        );
    }

    /// A sprite is composited through its own colour registers while the raw
    /// playfield index survives beside a separate origin plane.
    #[test]
    fn sprite_dma_composites_without_turning_a_sprite_into_playfield_data() {
        let base = 0x2_0000;
        let mut bytes = vec![0_u8; 0x200];
        // The one-plane playfield is opaque across both rows.
        bytes[0..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        // Sprite 0: raster lines 148..150, x=131. The fetch origin is 129,
        // hence frame columns 2..5 for the four set pixels on its first row.
        let sprite = 0x100;
        bytes[sprite..sprite + 16].copy_from_slice(&[
            0x94, 0x41, 0x96, 0x01, // POS, CTL
            0xf0, 0x00, 0x00, 0x00, // first row: value 1
            0x00, 0x00, 0x00, 0x00, // second row: transparent
            0x00, 0x00, 0x00, 0x00, // terminator
        ]);
        let memory = block(base, bytes);
        let mut display = registers(1, base);
        display.sprites[0] = base + sprite as u32;
        display.palette[1] = 0x0f00;
        display.palette[17] = 0x00f0;
        display.bplcon2 = 1; // sprite group 0 in front of PF1
        display.dmacon = DMAEN | BPLEN | SPREN;

        let frame = reconstruct(&display, true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(&frame.indices[0..8], &[1; 8]);
        assert_eq!(frame.pixel_sources[1], PixelSource::PLAYFIELD);
        assert_eq!(frame.pixel_sources[2].sprite_channel(), Some(0));
        assert_eq!(&frame.rgba[2 * 4..2 * 4 + 4], &[0x00, 0xff, 0x00, 0xff]);
        assert_eq!(&frame.rgba[4..8], &[0xff, 0x00, 0x00, 0xff]);
    }

    /// The odd channel contributes the high two bits in attach mode, and the
    /// source plane keeps the attached object distinct even when its colour
    /// register number equals the playfield's index.
    #[test]
    fn an_attached_pair_uses_sixteen_colours_and_one_explicit_origin() {
        let base = 0x2_0000;
        let mut bytes = vec![0_u8; 0x300];
        // Five playfield planes make index 27 (11011) at the first pixel.
        for (plane, set) in [true, true, false, true, true].into_iter().enumerate() {
            if set {
                bytes[plane * 4] = 0x80;
            }
        }
        for (offset, attached, data, data_b) in [
            (0x100_usize, false, 0x8000_u16, 0x8000_u16), // low bits 3
            (0x180, true, 0x0000, 0x8000),                // high bits 2
        ] {
            let ctl = 0x9601_u16 | if attached { 0x0080 } else { 0 };
            let words = [0x9440_u16, ctl, data, data_b, 0, 0, 0, 0];
            for (index, word) in words.into_iter().enumerate() {
                bytes[offset + index * 2..offset + index * 2 + 2]
                    .copy_from_slice(&word.to_be_bytes());
            }
        }
        let memory = block(base, bytes);
        let mut display = registers(5, base);
        display.sprites[0] = base + 0x100;
        display.sprites[1] = base + 0x180;
        display.palette[27] = 0x00f0;
        display.bplcon2 = 1;
        display.dmacon = DMAEN | BPLEN | SPREN;

        let frame = reconstruct(&display, true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));

        // 3 | (2 << 2) = 11, hence attached colour register 16 + 11 = 27:
        // exactly the playfield index that must remain distinguishable by
        // origin.
        assert_eq!(frame.indices[0], 27);
        assert_eq!(frame.pixel_sources[0].sprite_channel(), Some(0));
    }

    /// `PF1P` places one whole sprite group at a time around the playfield.
    #[test]
    fn bplcon2_places_sprite_groups_on_opposite_sides_of_the_playfield() {
        let base = 0x2_0000;
        let mut bytes = vec![0_u8; 0x300];
        bytes[0..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        for (offset, pos, data) in [
            (0x100_usize, 0x9440_u16, 0x8000_u16), // sprite 0 at column 0
            (0x180, 0x9441, 0x4000),               // sprite 2 at column 2
        ] {
            let ctl = if offset == 0x100 { 0x9601 } else { 0x9600 };
            let words = [pos, ctl, data, 0, 0, 0, 0, 0];
            for (index, word) in words.into_iter().enumerate() {
                bytes[offset + index * 2..offset + index * 2 + 2]
                    .copy_from_slice(&word.to_be_bytes());
            }
        }
        let memory = block(base, bytes);
        let mut display = registers(1, base);
        display.sprites[0] = base + 0x100;
        display.sprites[2] = base + 0x180;
        display.bplcon2 = 1; // SP01, then PF1, then SP23
        display.dmacon = DMAEN | BPLEN | SPREN;

        let frame = reconstruct(&display, true, &[], &memory, 1 << 20)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(frame.pixel_sources[0].sprite_channel(), Some(0));
        assert_eq!(frame.pixel_sources[2], PixelSource::PLAYFIELD);
    }

    /// A vertical wrap needs state from two frames, which this still capture
    /// deliberately does not invent.
    #[test]
    fn a_sprite_wrapping_into_another_frame_is_refused() {
        let base = 0x2_0000;
        let mut bytes = vec![0_u8; 0x120];
        // VSTART 200, VSTOP 100.
        bytes[0x100..0x104].copy_from_slice(&[0xc8, 0x40, 0x64, 0x00]);
        let memory = block(base, bytes);
        let mut display = registers(1, base);
        display.sprites[0] = base + 0x100;
        display.dmacon = DMAEN | BPLEN | SPREN;

        assert_eq!(
            reconstruct(&display, true, &[], &memory, 1 << 20),
            Err(DisplayError::SpriteVerticalWrap {
                sprite: 0,
                vstart: 200,
                vstop: 100,
            })
        );
    }

    /// Two different delays are refused rather than served with one of them.
    ///
    /// Outside dual playfield — which is refused already — the odd and even
    /// bitplanes are one picture, so shifting them apart tears it. Every program
    /// that scrolls a single playfield writes the same nibble twice.
    #[test]
    fn a_split_scroll_is_refused_rather_than_reconstructed_from_one_nibble() {
        let memory = block(0x2_0000, vec![0; 256]);
        let mut split = registers(2, 0x2_0000);
        split.bplcon1 = 0x42;
        assert_eq!(
            reconstruct(&split, true, &[], &memory, 1 << 20),
            Err(DisplayError::SplitScroll {
                bplcon1: 0x42,
                odd: 2,
                even: 4,
            })
        );
    }

    /// A Copper that scrolls part-way down the frame is the ordinary way a
    /// program scrolls, so a split one it writes is refused where it appears.
    #[test]
    fn a_copper_split_scroll_is_refused_at_the_band_it_appears_in() {
        let memory = block(0x2_0000, vec![0; 256]);
        let copper = vec![
            CopperInstruction {
                offset: 0,
                op: CopperOp::Wait {
                    vpos: 149,
                    hpos: 0,
                    vmask: 0xff,
                    hmask: 0xfe,
                    blitter_finish_disable: false,
                },
            },
            CopperInstruction {
                offset: 4,
                op: CopperOp::Move {
                    register: 0x102,
                    value: 0x0031,
                },
            },
        ];
        let mut with_copper = registers(1, 0x2_0000);
        with_copper.dmacon = DMAEN | COPEN | BPLEN;
        assert_eq!(
            reconstruct(&with_copper, true, &copper, &memory, 1 << 20),
            Err(DisplayError::SplitScroll {
                bplcon1: 0x0031,
                odd: 1,
                even: 3,
            })
        );
    }

    /// Memory the capture does not cover is a refusal, not a black band.
    #[test]
    fn a_row_the_capture_does_not_hold_is_refused_rather_than_shown_as_black() {
        let memory = block(0x2_0000, vec![0; 2]);
        assert!(matches!(
            reconstruct(&registers(1, 0x2_0000), true, &[], &memory, 1 << 20),
            Err(DisplayError::Unmapped { .. })
        ));
    }

    #[test]
    fn a_display_nothing_configured_is_refused_rather_than_reported_empty() {
        let memory = block(0x2_0000, vec![0; 64]);
        assert_eq!(
            reconstruct(&registers(1, 0x2_0000), false, &[], &memory, 1 << 20),
            Err(DisplayError::Unconfigured)
        );
    }
}
