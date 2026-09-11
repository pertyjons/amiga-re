//! The custom-chip (`$DFF000`) register page, and optionally a blitter behind
//! it.
//!
//! This is not a display or timing model, and it is still not one — there is no
//! bitplane DMA, no sprites and no Copper. What it covers is the register
//! behaviour a program actually depends on: beam-wait polls make progress, the
//! set/clear control registers read back correctly, and — when the page is built
//! with [`CustomChips::with_blitter`] — a write to `BLTSIZE` performs a blit and
//! **changes memory**. Everything else in the page is a plain shadow cell: a
//! write takes effect and reads back, never silently ignored and never a
//! fabricated value.
//!
//! # One source of truth per register
//!
//! A register the [`Blitter`] models is read back from the blitter; only
//! registers it does not model fall through to the shadow. Most of them are
//! write-only on real hardware, so the read-back is a sandbox convenience rather
//! than a fidelity claim — but a convenience with two answers is worse than
//! either.
//!
//! # The blit happens inside the register write
//!
//! A blit is atomic: the whole thing runs inside the `MOVE.W` that starts it,
//! before the next instruction. It needs no cycle accuracy, it is deterministic
//! and it is reproducible. The visible consequences are that `BBUSY` always
//! reads 0 — correct for an observer that cannot see a blit in progress, so a
//! `WaitBlit` loop exits on its first read — and that `BZERO` and `INTREQ` bit 6
//! are already set by the time anything can look.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use amiga_disasm::{Device, DeviceAccess};
use amiga_hw::blitter::{
    BlitConditions, BlitObservation, BlitRefusal, Blitter, ChannelPointers, Chipset, DmaMemory,
    DmaPolicy, StartRequest, is_blitter_register,
};

use crate::layout;

// Register offsets from `$DFF000` (the values that appear in `$DFFxxx` operands).
const DMACONR: u16 = 0x002;
const VPOSR: u16 = 0x004;
const VHPOSR: u16 = 0x006;
const ADKCONR: u16 = 0x010;
const INTENAR: u16 = 0x01c;
const INTREQR: u16 = 0x01e;
const DMACON: u16 = 0x096;
const INTENA: u16 = 0x09a;
const INTREQ: u16 = 0x09c;
const ADKCON: u16 = 0x09e;

/// `DMACON` bits a *write* may change: 0-10.
///
/// Bit 15 is `SET/CLR` and selects between setting and clearing; bits 13
/// (`BZERO`) and 14 (`BBUSY`) are **read-only status**, and the writable control
/// bits stop at 10 (`BLTPRI`). Letting a write reach 13 and 14 is a defect with
/// a visible symptom: a `MOVE.W #$C000,DMACON` would set `BBUSY`, and every
/// later `WaitBlit` would spin until the step budget ran out.
const DMACON_WRITABLE: u16 = 0x07ff;
/// `DMACON` bit 6: blitter DMA.
const BLTEN: u16 = 1 << 6;
/// `DMACON` bit 9: the master DMA enable, which gates every channel.
const DMAEN: u16 = 1 << 9;
/// `DMACONR` bit 14: read-only, and always 0 here because a blit is atomic.
const BBUSY: u16 = 1 << 14;
/// `DMACONR` bit 13: read-only, set when the last blit's output was all zero.
const BZERO: u16 = 1 << 13;
/// `INTREQ` bit 6: blitter finished.
const INTREQ_BLIT: u16 = 1 << 6;

/// Horizontal positions per scanline (PAL), used to derive the beam counters.
///
/// Public because the beam *is* the instruction counter here: a caller that
/// wants to run until the beam reaches a raster line computes an instruction
/// budget from it rather than asking for a hook the run loop does not have.
/// Deriving that number anywhere else would be a second definition of where the
/// beam is, and the two would drift.
pub const HORIZONTAL: u64 = 227;
/// Scanlines per frame (PAL).
pub const VERTICAL: u64 = 313;

/// How a [`CustomChips`] page is configured.
///
/// Plain numbers and enums: the environment is not told about the operation
/// layer's limits, and the operation layer derives these from them.
#[derive(Clone, Copy, Debug)]
pub struct ChipsOptions {
    /// What to do when a blit starts with blitter DMA disabled.
    pub blitter_dma: DmaPolicy,
    /// Datapath words the whole run may spend on blits, refusals included.
    pub maximum_blit_words: u64,
    /// How many blit rows the telemetry retains. The true total is counted
    /// separately, so a capped list never reads as a short run.
    pub maximum_reported_blits: usize,
    /// Which chipset the blitter models.
    pub chipset: Chipset,
}

impl Default for ChipsOptions {
    fn default() -> Self {
        Self {
            blitter_dma: DmaPolicy::AssumeEnabled,
            maximum_blit_words: 4_194_304,
            maximum_reported_blits: 256,
            chipset: Chipset::Ocs,
        }
    }
}

/// One blit the page performed or refused.
#[derive(Clone, Debug, PartialEq)]
pub struct BlitRow {
    /// Position in the run, counting refused blits.
    pub index: u64,
    pub width: u16,
    pub height: u16,
    pub bltcon0: u16,
    pub bltcon1: u16,
    pub initial_pointers: ChannelPointers,
    pub final_pointers: ChannelPointers,
    /// Datapath words: `width × height`, charged whether or not the blit ran.
    pub datapath_words: u64,
    pub words_written: u64,
    /// `None` when the blit did not run — reporting `false` would be a claim.
    pub zero: Option<bool>,
    /// Whether the blit ran with DMA off under an assuming policy.
    pub dma_assumed: bool,
    pub refused: Option<BlitRefusal>,
    pub observations: Vec<BlitObservation>,
}

/// One kind of refusal this run produced, with a representative example.
///
/// Recorded for **every** refused blit, retained or not: the row cap bounds what
/// a record shows, and it must not bound what a run is told went wrong. The key
/// is `(kind, channel)` — a small closed enum times four channels — so this list
/// is bounded by construction without needing a cap of its own. The address is
/// deliberately not part of the key; a loop touching new addresses would defeat
/// the bound, so the first one goes in `message` as an example instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefusalTally {
    pub kind: &'static str,
    pub channel: Option<&'static str>,
    pub occurrences: u64,
    /// The index of the first blit refused this way.
    pub first_index: u64,
    /// That first refusal, spelled out.
    pub message: String,
}

/// A run-level observation, aggregated rather than accumulated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationTally {
    /// The observation's stable kind name.
    pub kind: &'static str,
    /// The register it is about, when it is about one.
    pub register: Option<u16>,
    pub occurrences: u64,
    /// How many chip-register writes the page had served when this was first
    /// seen, which places it in the run without carrying an address.
    pub first_seen_at: u64,
}

/// One write to a custom-chip register, as the page resolved it.
///
/// Recorded per *register*, not per instruction: a `MOVE.L` into a pointer pair
/// is two of these in order, and a byte write is the mirrored word the 16-bit
/// bus actually presents. That decomposition is the page's own, so a reader is
/// not left to redo it from an instruction's address and width and reach a
/// different answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipRegisterWrite {
    /// Absolute address of the register written.
    pub address: u32,
    /// Its offset from `$DFF000`.
    pub offset: u16,
    pub value: u16,
}

/// Every custom-chip register write a run performed, bounded.
///
/// This exists because the alternative does not survive a long run. The chip
/// writes used to be recovered by scanning the sandbox's whole memory write
/// log afterwards, which forced that log to stay complete — one entry per write
/// executing code performs, growing without bound with the step budget. Writes
/// are collected here as they happen instead, so the log they were read out of
/// is free to be capped.
///
/// Bounded the way every other retained list in this crate is: a cap on what is
/// kept, and a total that keeps counting past it, so a truncated record never
/// reads as a complete one.
#[derive(Clone, Debug)]
pub struct ChipWriteLog {
    writes: Vec<ChipRegisterWrite>,
    total: u64,
    retained: usize,
}

/// Register writes retained by default.
///
/// A boot block sets up DMA, the copper and the bitplane pointers; a few
/// hundred writes covers that with room to spare, and a loader that writes more
/// is writing them in a loop, where the count matters and the thousandth
/// repetition does not.
pub const DEFAULT_RETAINED_CHIP_WRITES: usize = 4096;

impl Default for ChipWriteLog {
    fn default() -> Self {
        Self {
            writes: Vec::new(),
            total: 0,
            retained: DEFAULT_RETAINED_CHIP_WRITES,
        }
    }
}

impl ChipWriteLog {
    /// The retained writes, in order, at most `retained` of them.
    #[must_use]
    pub fn writes(&self) -> &[ChipRegisterWrite] {
        &self.writes
    }

    /// Register writes performed, always the true total.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Whether more writes happened than were retained.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.total > self.writes.len() as u64
    }

    fn record(&mut self, write: ChipRegisterWrite) {
        self.total = self.total.saturating_add(1);
        if self.writes.len() < self.retained {
            self.writes.push(write);
        }
    }
}

/// Every custom-chip register's value, as the run left it.
///
/// Separate from [`ChipWriteLog`], and deliberately not derived from it: that
/// log is a bounded *prefix* of what a run wrote, and a display reconstructed
/// by replaying a prefix would be a display the run never had. This is 256
/// words whatever the run does, so it is complete by construction.
///
/// A register reads as `None` until something writes it, which is a different
/// fact from reading as zero: a display nobody configured and a display
/// configured to zero are two different findings, and only the first is a
/// reason to refuse a frame.
///
/// The value stored is the register's *effective* state rather than the word
/// written to it. `DMACON`, `INTENA`, `INTREQ` and `ADKCON` are set/clear
/// registers, so the word `0x8200` written to `DMACON` means "set two bits" and
/// not "the register now holds 0x8200"; storing what was written would make a
/// reader answer the wrong question about the one register that decides whether
/// the display fetches at all.
#[derive(Clone, Debug)]
pub struct ChipRegisters {
    values: [Option<u16>; 0x100],
}

impl Default for ChipRegisters {
    fn default() -> Self {
        Self {
            values: [None; 0x100],
        }
    }
}

impl ChipRegisters {
    /// The effective value of the register at `offset` from `$DFF000`, or
    /// `None` if nothing has written it.
    #[must_use]
    pub fn value(&self, offset: u16) -> Option<u16> {
        self.values.get(usize::from(offset >> 1)).copied().flatten()
    }

    /// How many distinct registers the run wrote.
    #[must_use]
    pub fn written(&self) -> usize {
        self.values.iter().filter(|value| value.is_some()).count()
    }

    fn record(&mut self, offset: u16, value: u16) {
        if let Some(cell) = self.values.get_mut(usize::from(offset >> 1)) {
            *cell = Some(value);
        }
    }
}

/// What the blitter did over a whole run.
///
/// Every list here is bounded by construction. Blit rows are capped with the
/// true total counted beside them; run-level observations are aggregated by the
/// finite key `(kind, register)`, so a program writing an ECS register in a loop
/// produces one row with a count rather than millions of rows. Milestone 0 of
/// this work exists to stop telemetry scaling with a blit, and it would be an
/// odd thing to reintroduce here.
#[derive(Clone, Debug, Default)]
pub struct BlitterTelemetry {
    blits: Vec<BlitRow>,
    blits_total: u64,
    attempted_blit_words_total: u64,
    executed_blit_words_total: u64,
    observations: BTreeMap<(&'static str, Option<u16>), ObservationTally>,
    refusals: BTreeMap<(&'static str, Option<&'static str>), RefusalTally>,
    /// Run-level, like the refusal tallies and for the same reason: the row cap
    /// bounds what a record shows, and it must not bound what a run is told the
    /// blits were performed under.
    any_dma_assumed: bool,
    register_writes: u64,
    maximum_reported_blits: usize,
}

impl BlitterTelemetry {
    /// The retained blit rows, at most `maximum_reported_blits` of them.
    #[must_use]
    pub fn blits(&self) -> &[BlitRow] {
        &self.blits
    }

    /// Blits triggered, refused ones included. Always the true total.
    #[must_use]
    pub const fn blits_total(&self) -> u64 {
        self.blits_total
    }

    /// Whether more blits happened than were retained.
    #[must_use]
    pub fn blits_truncated(&self) -> bool {
        self.blits_total > self.blits.len() as u64
    }

    /// Datapath words every triggered blit asked for, refused ones included.
    /// This is what the budget was charged.
    #[must_use]
    pub const fn attempted_blit_words_total(&self) -> u64 {
        self.attempted_blit_words_total
    }

    /// Datapath words the blits that actually ran performed. Two named fields
    /// rather than one described as both, so a run that spent its budget on
    /// refusals is legible as exactly that.
    #[must_use]
    pub const fn executed_blit_words_total(&self) -> u64 {
        self.executed_blit_words_total
    }

    /// Run-level observations, aggregated by `(kind, register)`.
    pub fn observations(&self) -> impl Iterator<Item = &ObservationTally> {
        self.observations.values()
    }

    /// Every kind of refusal this run produced, aggregated by `(kind, channel)`
    /// and counted whether or not the blit row survived the retention cap.
    pub fn refusals(&self) -> impl Iterator<Item = &RefusalTally> {
        self.refusals.values()
    }

    /// Whether any blit ran with DMA off under an assuming policy. The
    /// diagnostic this feeds is raised once per run, not once per blit.
    ///
    /// Kept as run-level state rather than derived from [`Self::blits`], which
    /// is capped: the assumption changed memory whether or not the blit that
    /// made it is among the rows a record shows.
    #[must_use]
    pub const fn any_dma_assumed(&self) -> bool {
        self.any_dma_assumed
    }

    fn observe(&mut self, observation: BlitObservation) {
        let key = (observation.kind(), observation.register());
        let seen_at = self.register_writes;
        self.observations
            .entry(key)
            .and_modify(|tally| tally.occurrences = tally.occurrences.saturating_add(1))
            .or_insert(ObservationTally {
                kind: key.0,
                register: key.1,
                occurrences: 1,
                first_seen_at: seen_at,
            });
    }

    fn record(&mut self, row: BlitRow) {
        if let Some(refusal) = row.refused {
            let channel = refusal.channel().map(amiga_hw::blitter::Channel::name);
            self.refusals
                .entry((refusal.kind(), channel))
                .and_modify(|tally| tally.occurrences = tally.occurrences.saturating_add(1))
                .or_insert_with(|| RefusalTally {
                    kind: refusal.kind(),
                    channel,
                    occurrences: 1,
                    first_index: row.index,
                    message: refusal.to_string(),
                });
        }
        self.any_dma_assumed |= row.dma_assumed;
        self.blits_total = self.blits_total.saturating_add(1);
        self.attempted_blit_words_total = self
            .attempted_blit_words_total
            .saturating_add(row.datapath_words);
        if row.refused.is_none() {
            self.executed_blit_words_total = self
                .executed_blit_words_total
                .saturating_add(row.datapath_words);
        }
        if self.blits.len() < self.maximum_reported_blits {
            self.blits.push(row);
        }
    }
}

/// The blitter and the run-level state around it.
struct BlitterState {
    blitter: Blitter,
    dma: DmaPolicy,
    /// Datapath words left in the run's budget. Charged before the preflight and
    /// never refunded, so a loop of refusals costs what it costs.
    words_remaining: u64,
    telemetry: Rc<RefCell<BlitterTelemetry>>,
}

/// The `$DFF000..$DFF200` custom-chip register page.
pub struct CustomChips {
    /// Plain word cells for every register without special semantics.
    shadow: [u16; 0x100],
    /// Set/clear control registers (bit 15 selects set vs clear).
    dmacon: u16,
    intena: u16,
    intreq: u16,
    adkcon: u16,
    /// Instruction counter shared with the host; drives the beam position.
    beam: Rc<Cell<u64>>,
    /// Present only when the page was built with a blitter.
    blitter: Option<BlitterState>,
    /// Present only when the caller asked to record register writes, because a
    /// log nobody holds a handle to is memory spent on nothing.
    log: Option<Rc<RefCell<ChipWriteLog>>>,
    /// Always present, unlike the log: it is 256 words rather than a growing
    /// list, and it is the only complete answer to "what did the chips end up
    /// holding". A caller that wants it takes a handle before the page is boxed
    /// and attached, because a `DeviceBus` owns its devices as `Box<dyn Device>`
    /// and offers no downcast.
    registers: Rc<RefCell<ChipRegisters>>,
}

impl CustomChips {
    /// A fresh register page whose beam is driven by `beam`, with no blitter.
    #[must_use]
    pub fn new(beam: Rc<Cell<u64>>) -> Self {
        Self {
            shadow: [0; 0x100],
            dmacon: 0,
            intena: 0,
            intreq: 0,
            adkcon: 0,
            beam,
            blitter: None,
            log: None,
            registers: Rc::new(RefCell::new(ChipRegisters::default())),
        }
    }

    /// A handle to the register state this page keeps, for a caller that will
    /// need it after the page has been attached to a bus.
    #[must_use]
    pub fn register_handle(&self) -> Rc<RefCell<ChipRegisters>> {
        Rc::clone(&self.registers)
    }

    /// The same page, plus the handle to the register-write log it records into.
    ///
    /// The handle is returned here for the reason [`Self::with_blitter`] gives
    /// for its own: [`amiga_disasm::DeviceBus`] owns its devices as
    /// `Box<dyn Device>` and offers no downcast, so a caller that did not keep a
    /// reference at construction could never read what the page recorded.
    #[must_use]
    pub fn recording(beam: Rc<Cell<u64>>) -> (Self, Rc<RefCell<ChipWriteLog>>) {
        let log = Rc::new(RefCell::new(ChipWriteLog::default()));
        let mut chips = Self::new(beam);
        chips.log = Some(Rc::clone(&log));
        (chips, log)
    }

    /// The same page with a blitter behind it, plus the telemetry handle the
    /// caller keeps.
    ///
    /// The handle is returned here because there is no way to get one later:
    /// [`amiga_disasm::DeviceBus`] owns its devices as `Box<dyn Device>` and
    /// offers no downcast, so a caller that did not keep a reference at
    /// construction could never read what the blitter did.
    #[must_use]
    pub fn with_blitter(
        beam: Rc<Cell<u64>>,
        options: ChipsOptions,
    ) -> (Self, Rc<RefCell<BlitterTelemetry>>) {
        let telemetry = Rc::new(RefCell::new(BlitterTelemetry {
            maximum_reported_blits: options.maximum_reported_blits,
            ..BlitterTelemetry::default()
        }));
        let mut chips = Self::new(beam);
        chips.blitter = Some(BlitterState {
            blitter: Blitter::new(options.chipset),
            dma: options.blitter_dma,
            words_remaining: options.maximum_blit_words,
            telemetry: Rc::clone(&telemetry),
        });
        (chips, telemetry)
    }

    /// The current raster position `(vpos, hpos)` derived from the beam counter.
    fn beam_position(&self) -> (u16, u16) {
        let position = self.beam.get();
        let hpos = (position % HORIZONTAL) as u16;
        let vpos = ((position / HORIZONTAL) % VERTICAL) as u16;
        (vpos, hpos)
    }

    /// Read the register at `offset` (relative to `$DFF000`, even), applying the
    /// read aliases, the beam counters, and the blitter's own registers.
    fn read_word(&self, offset: u16) -> u16 {
        match offset {
            DMACONR => {
                // The writable control bits as written, plus the two read-only
                // status bits synthesized from the blitter rather than stored.
                // BBUSY is always clear: a blit is atomic, so an observer that
                // cannot see one in progress is telling the truth, and that is
                // what lets a `WaitBlit` loop exit on its first read.
                let mut value = self.dmacon & DMACON_WRITABLE;
                value &= !BBUSY;
                if self.blitter_zero() == Some(true) {
                    value |= BZERO;
                }
                value
            }
            INTENAR => self.intena,
            INTREQR => self.intreq,
            ADKCONR => self.adkcon,
            VPOSR => {
                // OCS Agnus: identification bits are 0. LOF (bit 15) is held at
                // 1 for a non-interlaced long frame; carry the V8 bit in bit 0.
                let (vpos, _) = self.beam_position();
                0x8000 | ((vpos >> 8) & 1)
            }
            VHPOSR => {
                let (vpos, hpos) = self.beam_position();
                ((vpos & 0xff) << 8) | (hpos & 0xff)
            }
            // A register the blitter models answers from the blitter; one it
            // does not — the ECS three on OCS — falls through to the shadow, so
            // the page keeps its promise that a write reads back.
            offset if is_blitter_register(offset) => self
                .blitter
                .as_ref()
                .and_then(|state| state.blitter.read_register(offset))
                .unwrap_or(self.shadow[usize::from(offset >> 1)]),
            _ => self.shadow[usize::from(offset >> 1)],
        }
    }

    /// `BZERO` from the last blit that ran, or `None` if none has.
    fn blitter_zero(&self) -> Option<bool> {
        self.blitter.as_ref().and_then(|state| state.blitter.zero())
    }

    /// Write the register at `offset`, applying set/clear on the control
    /// registers, routing the blitter's range to the blitter, and shadowing
    /// everything else.
    fn write_word(&mut self, offset: u16, value: u16, memory: &mut dyn DmaMemory) {
        if let Some(log) = self.log.as_ref() {
            log.borrow_mut().record(ChipRegisterWrite {
                address: layout::CUSTOM_BASE + u32::from(offset),
                offset,
                value,
            });
        }
        match offset {
            // Masked to the writable bits, so a write cannot fabricate the
            // read-only status the blitter owns.
            DMACON => self.dmacon = set_or_clear(self.dmacon, value) & DMACON_WRITABLE,
            INTENA => self.intena = set_or_clear(self.intena, value),
            INTREQ => self.intreq = set_or_clear(self.intreq, value),
            ADKCON => self.adkcon = set_or_clear(self.adkcon, value),
            offset if is_blitter_register(offset) => {
                // Shadowed as well as routed: what the blitter does not model
                // still has to read back from somewhere.
                self.shadow[usize::from(offset >> 1)] = value;
                self.write_blitter_register(offset, value, memory);
            }
            _ => self.shadow[usize::from(offset >> 1)] = value,
        }
        // After the match, so what is recorded is the register's resulting
        // state rather than the word written at it — the two differ for every
        // set/clear register, and `DMACON` is one of them.
        self.registers
            .borrow_mut()
            .record(offset, self.effective(offset));
    }

    /// The state the register at `offset` now holds.
    fn effective(&self, offset: u16) -> u16 {
        match offset {
            DMACON => self.dmacon,
            INTENA => self.intena,
            INTREQ => self.intreq,
            ADKCON => self.adkcon,
            _ => self.shadow[usize::from(offset >> 1)],
        }
    }

    /// Hand a blitter register to the blitter, and perform the blit if that
    /// write was a start trigger.
    fn write_blitter_register(&mut self, offset: u16, value: u16, memory: &mut dyn DmaMemory) {
        // `DMACON` is read before the blitter is borrowed, and it is the state
        // the blit runs under either way.
        let dma_enabled = self.dmacon & (BLTEN | DMAEN) == (BLTEN | DMAEN);
        let Some(state) = self.blitter.as_mut() else {
            return;
        };
        let outcome = state.blitter.write_register(offset, value);
        {
            let mut telemetry = state.telemetry.borrow_mut();
            telemetry.register_writes = telemetry.register_writes.saturating_add(1);
            for observation in outcome.observations {
                telemetry.observe(observation);
            }
        }
        let Some(start) = outcome.start else {
            return;
        };
        // A blit that ran raises the completion interrupt, so code waiting on
        // the flag rather than on BBUSY also makes progress. A refusal raises
        // nothing: a blit that did not happen cannot have finished. The answer
        // comes from the blit itself rather than from the last retained
        // telemetry row, which past the row cap is a different blit entirely.
        if Self::perform(state, start, dma_enabled, memory) {
            self.intreq |= INTREQ_BLIT;
        }
    }

    /// Run one blit and record it. Returns whether it was performed.
    fn perform(
        state: &mut BlitterState,
        start: StartRequest,
        dma_enabled: bool,
        memory: &mut dyn DmaMemory,
    ) -> bool {
        let conditions = BlitConditions {
            dma_enabled,
            dma: state.dma,
            word_budget: state.words_remaining,
        };
        let outcome = state.blitter.execute(start, memory, conditions);
        // Charged whatever happened, and not refunded: the preflight is itself
        // proportional to the blit, so a refusal loop that cost nothing would
        // leave the expensive half unbounded.
        state.words_remaining = state.words_remaining.saturating_sub(outcome.datapath_words);

        let performed = outcome.refused.is_none();
        let mut telemetry = state.telemetry.borrow_mut();
        let index = telemetry.blits_total();
        telemetry.record(BlitRow {
            index,
            width: outcome.size.width(),
            height: outcome.size.height(),
            bltcon0: state.blitter.read_register(0x040).unwrap_or_default(),
            bltcon1: state.blitter.read_register(0x042).unwrap_or_default(),
            initial_pointers: outcome.initial_pointers,
            final_pointers: outcome.final_pointers,
            datapath_words: outcome.datapath_words,
            words_written: outcome.words_written,
            zero: outcome.zero,
            dma_assumed: outcome.dma_assumed,
            refused: outcome.refused,
            observations: outcome.observations,
        });
        performed
    }
}

/// Apply a set/clear write: bit 15 set means OR in the low 15 bits, else clear.
fn set_or_clear(current: u16, value: u16) -> u16 {
    if value & 0x8000 != 0 {
        current | (value & 0x7fff)
    } else {
        current & !(value & 0x7fff)
    }
}

impl Device for CustomChips {
    fn range(&self) -> std::ops::Range<u32> {
        layout::CUSTOM_BASE..layout::CUSTOM_BASE + layout::CUSTOM_SIZE as u32
    }

    fn read(&mut self, addr: u32, size: u8, _memory: &mut dyn DmaMemory) -> DeviceAccess {
        let Some(offset) = in_page(addr, size) else {
            return DeviceAccess::Fault;
        };
        let value = match size {
            1 => {
                let word = self.read_word(offset & !1);
                u32::from(if offset & 1 == 0 {
                    (word >> 8) as u8
                } else {
                    word as u8
                })
            }
            2 => u32::from(self.read_word(offset)),
            _ => {
                let high = self.read_word(offset);
                let low = self.read_word(offset + 2);
                (u32::from(high) << 16) | u32::from(low)
            }
        };
        DeviceAccess::Value(value)
    }

    fn write(
        &mut self,
        addr: u32,
        size: u8,
        value: u32,
        memory: &mut dyn DmaMemory,
    ) -> DeviceAccess {
        let Some(offset) = in_page(addr, size) else {
            return DeviceAccess::Fault;
        };
        // Every width resolves to the same word writes, in order, so a `MOVE.L`
        // into a pointer pair is two register writes and a `MOVE.L` into
        // `BLTSIZE` starts the blit on its second half — as on the hardware.
        match size {
            1 => {
                // Custom registers are word-oriented; a byte access drives the
                // byte on both halves of the 16-bit bus, so mirror it. This makes
                // a byte write to a set/clear register apply the mask correctly
                // (a stale shadow half would corrupt it).
                let byte = u16::from(value as u8);
                self.write_word(offset & !1, (byte << 8) | byte, memory);
            }
            2 => self.write_word(offset, value as u16, memory),
            _ => {
                self.write_word(offset, (value >> 16) as u16, memory);
                self.write_word(offset + 2, value as u16, memory);
            }
        }
        DeviceAccess::Wrote
    }
}

/// The page-relative offset of `[addr, addr + size)`, or `None` if it is not
/// wholly inside `$DFF000..$DFF200`. A self-guard so the register indexing stays
/// in bounds even if a caller bypasses the bus's straddle check.
fn in_page(addr: u32, size: u8) -> Option<u16> {
    let relative = addr.checked_sub(layout::CUSTOM_BASE)?;
    let end = relative.checked_add(u32::from(size))?;
    (end <= layout::CUSTOM_SIZE as u32).then_some(relative as u16)
}

#[cfg(test)]
mod tests {
    use amiga_disasm::Memory;

    use super::*;

    /// A DMA handle with nothing mapped, for the register behaviour that has no
    /// business reaching memory at all.
    struct NoRam;

    impl DmaMemory for NoRam {
        fn contains_word(&self, _address: u32) -> bool {
            false
        }
        fn read_dma_word(&mut self, _address: u32) -> Option<u16> {
            None
        }
        fn write_dma_word(&mut self, _address: u32, _value: u16) -> Option<()> {
            None
        }
    }

    fn chips() -> CustomChips {
        CustomChips::new(Rc::new(Cell::new(0)))
    }

    /// A page with a blitter, its telemetry handle, and RAM to blit into.
    fn blitting(options: ChipsOptions) -> (CustomChips, Rc<RefCell<BlitterTelemetry>>, Memory) {
        let (chips, telemetry) = CustomChips::with_blitter(Rc::new(Cell::new(0)), options);
        let mut memory = Memory::new();
        memory
            .map(0x2_0000, 0x1000)
            .unwrap_or_else(|error| panic!("{error}"));
        (chips, telemetry, memory)
    }

    fn poke(chips: &mut CustomChips, memory: &mut Memory, offset: u16, value: u16) {
        chips.write(
            layout::CUSTOM_BASE + u32::from(offset),
            2,
            u32::from(value),
            memory,
        );
    }

    fn peek(chips: &mut CustomChips, memory: &mut Memory, offset: u16) -> u16 {
        match chips.read(layout::CUSTOM_BASE + u32::from(offset), 2, memory) {
            DeviceAccess::Value(value) => value as u16,
            other => panic!("expected a value, got {other:?}"),
        }
    }

    #[test]
    fn a_cpu_write_cannot_fabricate_the_blitter_status_bits() {
        // A live defect before the blitter existed: `MOVE.W #$C000,DMACON` set
        // BBUSY, and every later WaitBlit spun until the step budget. The bits
        // are read-only status and are synthesized on read, never stored.
        let mut chips = chips();
        let dmacon = layout::CUSTOM_BASE + u32::from(DMACON);
        let dmaconr = layout::CUSTOM_BASE + u32::from(DMACONR);
        chips.write(dmacon, 2, 0xc000, &mut NoRam);
        assert_eq!(
            chips.read(dmaconr, 2, &mut NoRam),
            DeviceAccess::Value(0x0000),
            "bits 13 and 14 cannot be set by a write"
        );
        // The writable bits still work, and BBUSY still reads 0 beside them.
        chips.write(dmacon, 2, 0x8240, &mut NoRam);
        assert_eq!(
            chips.read(dmaconr, 2, &mut NoRam),
            DeviceAccess::Value(0x0240)
        );
    }

    #[test]
    fn bzero_is_synthesized_from_the_blit_that_just_finished() {
        let (mut chips, _telemetry, mut memory) = blitting(ChipsOptions::default());
        // Clear a word: BLTCON0 = USED with the zero minterm.
        poke(&mut chips, &mut memory, 0x040, 0x0100);
        poke(&mut chips, &mut memory, 0x042, 0x0000);
        poke(&mut chips, &mut memory, 0x044, 0xffff);
        poke(&mut chips, &mut memory, 0x046, 0xffff);
        poke(&mut chips, &mut memory, 0x054, 0x0002);
        poke(&mut chips, &mut memory, 0x056, 0x0000);
        assert_eq!(peek(&mut chips, &mut memory, DMACONR) & 0x6000, 0);

        poke(&mut chips, &mut memory, 0x058, 0x0041); // one word, one line
        let status = peek(&mut chips, &mut memory, DMACONR);
        assert_eq!(status & BZERO, BZERO, "the blit's output was all zero");
        assert_eq!(status & BBUSY, 0, "a blit is atomic, so it is never busy");
        assert_eq!(
            peek(&mut chips, &mut memory, INTREQR) & INTREQ_BLIT,
            INTREQ_BLIT,
            "and the completion interrupt is raised"
        );
    }

    #[test]
    fn a_blit_started_through_the_register_page_changes_memory() {
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions::default());
        memory
            .load(0x2_0000, &[0x12, 0x34, 0x56, 0x78])
            .unwrap_or_else(|error| panic!("{error}"));
        // Copy A, two words, from $20000 to $20100.
        poke(&mut chips, &mut memory, 0x040, 0x09f0);
        poke(&mut chips, &mut memory, 0x042, 0x0000);
        poke(&mut chips, &mut memory, 0x044, 0xffff);
        poke(&mut chips, &mut memory, 0x046, 0xffff);
        poke(&mut chips, &mut memory, 0x050, 0x0002);
        poke(&mut chips, &mut memory, 0x052, 0x0000);
        poke(&mut chips, &mut memory, 0x054, 0x0002);
        poke(&mut chips, &mut memory, 0x056, 0x0100);
        poke(&mut chips, &mut memory, 0x058, 0x0042); // two words, one line

        assert_eq!(
            memory.slice(0x2_0100, 4),
            Some(&[0x12, 0x34, 0x56, 0x78][..])
        );
        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.blits_total(), 1);
        assert_eq!(telemetry.attempted_blit_words_total(), 2);
        assert_eq!(telemetry.executed_blit_words_total(), 2);
        let row = &telemetry.blits()[0];
        assert_eq!((row.width, row.height), (2, 1));
        assert_eq!(row.words_written, 2);
        assert_eq!(row.initial_pointers.a, 0x2_0000);
        assert_eq!(row.final_pointers.a, 0x2_0004);
        assert_eq!(row.refused, None);
    }

    #[test]
    fn a_pointer_reads_back_advanced_after_the_blit() {
        let (mut chips, _telemetry, mut memory) = blitting(ChipsOptions::default());
        poke(&mut chips, &mut memory, 0x040, 0x09f0);
        poke(&mut chips, &mut memory, 0x042, 0x0000);
        poke(&mut chips, &mut memory, 0x044, 0xffff);
        poke(&mut chips, &mut memory, 0x046, 0xffff);
        poke(&mut chips, &mut memory, 0x050, 0x0002);
        poke(&mut chips, &mut memory, 0x052, 0x0000);
        poke(&mut chips, &mut memory, 0x054, 0x0002);
        poke(&mut chips, &mut memory, 0x056, 0x0100);
        poke(&mut chips, &mut memory, 0x058, 0x0042);

        // Read back from the blitter, not from the shadow the write also filled.
        assert_eq!(peek(&mut chips, &mut memory, 0x052), 0x0004);
    }

    #[test]
    fn a_longword_write_to_a_pointer_pair_is_two_register_writes_in_order() {
        let (mut chips, _telemetry, mut memory) = blitting(ChipsOptions::default());
        chips.write(layout::CUSTOM_BASE + 0x050, 4, 0x0002_0040, &mut memory);
        assert_eq!(peek(&mut chips, &mut memory, 0x050), 0x0002);
        assert_eq!(peek(&mut chips, &mut memory, 0x052), 0x0040);
    }

    #[test]
    fn dma_off_is_assumed_by_default_and_refused_when_the_recipe_requires_it() {
        for (policy, expected) in [
            (DmaPolicy::AssumeEnabled, None),
            (DmaPolicy::RequireEnabled, Some(BlitRefusal::DmaDisabled)),
        ] {
            let (mut chips, telemetry, mut memory) = blitting(ChipsOptions {
                blitter_dma: policy,
                ..ChipsOptions::default()
            });
            // DMACON is left at zero: no BLTEN, no DMAEN.
            poke(&mut chips, &mut memory, 0x040, 0x0100);
            poke(&mut chips, &mut memory, 0x042, 0x0000);
            poke(&mut chips, &mut memory, 0x054, 0x0002);
            poke(&mut chips, &mut memory, 0x056, 0x0000);
            poke(&mut chips, &mut memory, 0x058, 0x0041);

            let telemetry = telemetry.borrow();
            let row = &telemetry.blits()[0];
            assert_eq!(row.refused, expected, "{policy:?}");
            assert_eq!(row.dma_assumed, expected.is_none(), "{policy:?}");
            assert_eq!(telemetry.any_dma_assumed(), expected.is_none());
        }
    }

    #[test]
    fn line_mode_is_refused_and_the_record_says_so() {
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions::default());
        poke(&mut chips, &mut memory, 0x040, 0x09f0);
        poke(&mut chips, &mut memory, 0x042, 0x0001); // LINE
        poke(&mut chips, &mut memory, 0x050, 0x0002);
        poke(&mut chips, &mut memory, 0x052, 0x0000);
        poke(&mut chips, &mut memory, 0x054, 0x0002);
        poke(&mut chips, &mut memory, 0x056, 0x0100);
        poke(&mut chips, &mut memory, 0x058, 0x0042);

        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.blits()[0].refused, Some(BlitRefusal::LineMode));
        assert_eq!(telemetry.executed_blit_words_total(), 0);
        assert_eq!(
            telemetry.attempted_blit_words_total(),
            2,
            "a refusal still costs the budget it was charged"
        );
        assert_eq!(
            peek(&mut chips, &mut memory, INTREQR) & INTREQ_BLIT,
            0,
            "a blit that did not happen cannot have finished"
        );
    }

    #[test]
    fn bltsizv_is_observed_quietly_and_bltsizh_is_the_one_that_matters() {
        // On ECS a BLTSIZH write starts a blit. On OCS it does nothing, so a
        // program doing it would produce no image and no explanation — which is
        // why only that one is escalated later, and both are observed here.
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions::default());
        poke(&mut chips, &mut memory, 0x040, 0x09f0);
        for _ in 0..3 {
            poke(&mut chips, &mut memory, 0x05c, 0x0010); // BLTSIZV
        }
        poke(&mut chips, &mut memory, 0x05e, 0x0020); // BLTSIZH

        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.blits_total(), 0, "neither starts a blit on OCS");
        let tallies: Vec<_> = telemetry.observations().collect();
        assert_eq!(
            tallies.len(),
            2,
            "one row per (kind, register), not per write"
        );
        let sizv = tallies
            .iter()
            .find(|tally| tally.register == Some(0x05c))
            .unwrap_or_else(|| panic!("BLTSIZV observed"));
        assert_eq!(sizv.kind, "ecs_register_written");
        assert_eq!(sizv.occurrences, 3, "aggregated, not accumulated");
        assert_eq!(peek(&mut chips, &mut memory, 0x040), 0x09f0);
    }

    #[test]
    fn a_refusal_past_the_row_cap_is_still_counted_and_still_has_an_example() {
        // The row cap bounds what a record shows. It must not bound what a run
        // is told went wrong: a refusal that fell off the end of the list would
        // otherwise leave a clean-looking record.
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions {
            maximum_reported_blits: 2,
            ..ChipsOptions::default()
        });
        poke(&mut chips, &mut memory, 0x040, 0x0100);
        poke(&mut chips, &mut memory, 0x054, 0x0009); // a destination off the map
        poke(&mut chips, &mut memory, 0x056, 0x0000);
        for _ in 0..5 {
            poke(&mut chips, &mut memory, 0x058, 0x0041);
        }

        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.blits().len(), 2, "rows are capped");
        assert_eq!(telemetry.blits_total(), 5);
        let tallies: Vec<_> = telemetry.refusals().collect();
        assert_eq!(tallies.len(), 1, "one row per (kind, channel)");
        assert_eq!(tallies[0].kind, "unmapped");
        assert_eq!(tallies[0].channel, Some("d"));
        assert_eq!(
            tallies[0].occurrences, 5,
            "every refusal, not just the kept ones"
        );
        assert_eq!(tallies[0].first_index, 0);
        assert!(
            tallies[0].message.contains("0x00090000"),
            "the first occurrence's address is the representative example: {}",
            tallies[0].message
        );
    }

    #[test]
    fn an_assumed_blit_past_the_row_cap_is_still_an_assumed_run() {
        // Same rule as the refusal tallies: the row cap bounds what a record
        // shows, not what the run is told its blits were performed under. A
        // program that enables DMA, blits a while, then disables it changed
        // memory under the assumption whether or not that row survived.
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions {
            maximum_reported_blits: 1,
            ..ChipsOptions::default()
        });
        poke(&mut chips, &mut memory, DMACON, 0x8000 | DMAEN | BLTEN);
        poke(&mut chips, &mut memory, 0x040, 0x0100); // clear one word
        poke(&mut chips, &mut memory, 0x054, 0x0002);
        poke(&mut chips, &mut memory, 0x056, 0x0000);
        poke(&mut chips, &mut memory, 0x058, 0x0041); // blit 0: DMA was on
        assert!(!telemetry.borrow().any_dma_assumed());

        poke(&mut chips, &mut memory, DMACON, BLTEN); // clear: no bit 15
        poke(&mut chips, &mut memory, 0x058, 0x0041); // blit 1: assumed, dropped

        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.blits().len(), 1, "rows are capped");
        assert_eq!(telemetry.blits_total(), 2);
        assert!(
            !telemetry.blits()[0].dma_assumed,
            "the retained row is the one that ran with DMA on"
        );
        assert!(telemetry.any_dma_assumed());
    }

    #[test]
    fn the_completion_interrupt_follows_the_blit_and_not_the_last_retained_row() {
        // Past the row cap, the last retained row is a different blit entirely.
        // Deciding the interrupt from it would raise it for a blit that was
        // refused, or leave it clear for one that ran.
        let (mut chips, _telemetry, mut memory) = blitting(ChipsOptions {
            maximum_reported_blits: 1,
            ..ChipsOptions::default()
        });
        poke(&mut chips, &mut memory, 0x040, 0x0100); // clear one word
        poke(&mut chips, &mut memory, 0x054, 0x0002);
        poke(&mut chips, &mut memory, 0x056, 0x0000);
        poke(&mut chips, &mut memory, 0x058, 0x0041); // blit 0: performed
        assert_eq!(
            peek(&mut chips, &mut memory, INTREQR) & INTREQ_BLIT,
            INTREQ_BLIT
        );

        // Clear the flag, then refuse a blit whose row will not be retained.
        poke(&mut chips, &mut memory, INTREQ, INTREQ_BLIT);
        poke(&mut chips, &mut memory, 0x042, 0x0001); // LINE
        poke(&mut chips, &mut memory, 0x058, 0x0041);
        assert_eq!(
            peek(&mut chips, &mut memory, INTREQR) & INTREQ_BLIT,
            0,
            "a blit that did not happen cannot have finished"
        );
    }

    #[test]
    fn a_loop_of_ecs_writes_stays_one_row_however_long_it_runs() {
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions::default());
        for _ in 0..10_000 {
            poke(&mut chips, &mut memory, 0x05a, 0xffff);
        }
        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.observations().count(), 1);
        assert_eq!(
            telemetry
                .observations()
                .next()
                .map(|tally| tally.occurrences),
            Some(10_000)
        );
    }

    #[test]
    fn a_loop_of_refused_blits_runs_out_of_budget_rather_than_time() {
        let (mut chips, telemetry, mut memory) = blitting(ChipsOptions {
            // Three two-word blits' worth, so the fourth is the one the budget
            // stops and the transition is inside the retained rows.
            maximum_blit_words: 6,
            maximum_reported_blits: 4,
            ..ChipsOptions::default()
        });
        // A destination outside the map: every one of these is refused by the
        // preflight, and the budget is charged anyway.
        poke(&mut chips, &mut memory, 0x040, 0x0100);
        poke(&mut chips, &mut memory, 0x054, 0x0009);
        poke(&mut chips, &mut memory, 0x056, 0x0000);
        for _ in 0..6 {
            poke(&mut chips, &mut memory, 0x058, 0x0042); // two words each
        }

        let telemetry = telemetry.borrow();
        assert_eq!(telemetry.blits_total(), 6);
        assert_eq!(telemetry.blits().len(), 4, "rows are capped");
        assert!(telemetry.blits_truncated());
        assert_eq!(telemetry.attempted_blit_words_total(), 12);
        assert_eq!(telemetry.executed_blit_words_total(), 0);
        // The first four are unmapped; once the budget is gone the refusal
        // changes, which is what proves it was charged for refusals too.
        assert!(matches!(
            telemetry.blits()[0].refused,
            Some(BlitRefusal::Unmapped { .. })
        ));
        assert!(matches!(
            telemetry.blits()[3].refused,
            Some(BlitRefusal::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn dmacon_set_and_clear_read_back_via_dmaconr() {
        let mut chips = chips();
        let dmacon = layout::CUSTOM_BASE + u32::from(DMACON);
        let dmaconr = layout::CUSTOM_BASE + u32::from(DMACONR);
        // Set BLTEN (0x0040) and DMAEN (0x0200): value 0x8240.
        chips.write(dmacon, 2, 0x8240, &mut NoRam);
        assert_eq!(
            chips.read(dmaconr, 2, &mut NoRam),
            DeviceAccess::Value(0x0240)
        );
        // Clear BLTEN (0x0040): value 0x0040.
        chips.write(dmacon, 2, 0x0040, &mut NoRam);
        assert_eq!(
            chips.read(dmaconr, 2, &mut NoRam),
            DeviceAccess::Value(0x0200)
        );
    }

    #[test]
    fn a_byte_write_to_a_control_register_mirrors_the_byte() {
        let mut chips = chips();
        let dmacon = layout::CUSTOM_BASE + u32::from(DMACON);
        let dmaconr = layout::CUSTOM_BASE + u32::from(DMACONR);
        // MOVE.B #$82,DMACON drives $82 on both bus halves -> set-mask $0282.
        chips.write(dmacon, 1, 0x82, &mut NoRam);
        assert_eq!(
            chips.read(dmaconr, 2, &mut NoRam),
            DeviceAccess::Value(0x0282)
        );
    }

    #[test]
    fn vposr_reports_a_long_frame() {
        let mut chips = chips();
        let vposr = layout::CUSTOM_BASE + u32::from(VPOSR);
        // LOF (bit 15) is set; the V8 bit is 0 at beam position 0.
        assert_eq!(
            chips.read(vposr, 2, &mut NoRam),
            DeviceAccess::Value(0x8000)
        );
    }

    #[test]
    fn an_out_of_range_access_faults() {
        let mut chips = chips();
        assert_eq!(
            chips.read(layout::CUSTOM_BASE + 0x1fe, 4, &mut NoRam),
            DeviceAccess::Fault
        );
        assert_eq!(in_page(layout::CUSTOM_BASE + 0x1fe, 4), None);
        assert_eq!(in_page(layout::CUSTOM_BASE + 0x1fc, 4), Some(0x1fc));
    }

    #[test]
    fn an_unmodelled_register_round_trips() {
        let mut chips = chips();
        // BLTCON0 ($040) has no special semantics: it must shadow, not fault.
        let bltcon0 = layout::CUSTOM_BASE + 0x040;
        chips.write(bltcon0, 2, 0x09f0, &mut NoRam);
        assert_eq!(
            chips.read(bltcon0, 2, &mut NoRam),
            DeviceAccess::Value(0x09f0)
        );
    }

    #[test]
    fn the_beam_advances_with_the_counter() {
        let beam = Rc::new(Cell::new(0));
        let mut chips = CustomChips::new(beam.clone());
        let vhposr = layout::CUSTOM_BASE + u32::from(VHPOSR);
        let before = chips.read(vhposr, 2, &mut NoRam);
        beam.set(HORIZONTAL); // advance one scanline
        let after = chips.read(vhposr, 2, &mut NoRam);
        assert_ne!(before, after);
        // vpos is now 1 (high byte of VHPOSR).
        assert_eq!(after, DeviceAccess::Value(0x0100));
    }
}
