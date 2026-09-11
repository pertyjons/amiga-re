//! The blitter's effect on memory: an OCS Agnus area-mode blit.
//!
//! This is chip behaviour, not a sandbox: the blitter reaches memory only
//! through [`DmaMemory`], so it can be driven with a `Vec<u16>` and no CPU at
//! all. What it models is what a blit *does to memory* — four DMA channels, all
//! 256 minterms, the first/last-word masks, the barrel shifters, signed modulos,
//! descending mode, both fill modes, and the pipeline register. What it does not
//! model is timing: a blit here happens entirely inside the `BLTSIZE` write
//! that starts it, which is deterministic and reproducible and is why `BBUSY`
//! can honestly read 0.
//!
//! The behavioral reference is Commodore's
//! [Hardware Reference Manual, Chapter 6](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0118.html),
//! particularly Function Generator, Shifts and Masks, Descending Mode, Area
//! Fill Mode, and Pipeline Register. The inspected edition, section links and
//! source hashes are recorded in `docs/hardware-and-abi-references.md`.
//!
//! # The A and B channels are different datapaths
//!
//! This is the rule most easily got backwards, and getting it backwards
//! corrupts every blit that preloads `BLTBDAT` — an ordinary shape — while
//! still producing a plausible picture.
//!
//! **A is recomputed every datapath word.** Fetched or not, the A value is
//! taken from the register, masked by `BLTAFWM`/`BLTALWM`, and shifted, once per
//! word. It has to be: the masks differ between the first, middle and last word
//! of a row, so the stage is clocked per word and a channel-enable bit cannot
//! short-circuit it. Disabling DMA stops the fetch; masks and shifts still
//! operate on the channel's stored data.
//!
//! **B is a latch, shifted when it is written.** Writing `BLTBDAT` draws the
//! data through the shifter *at that moment*, using whatever `BSH` and `DESC`
//! held then, and the result is reused unchanged for every datapath word until B
//! DMA fetches something new. Changing the shift control after loading B data
//! does not retroactively change the latched value.
//!
//! These rules describe separate A and B
//! channels. [`Blitter::write_register`] records the shift and direction in
//! force at each `BLTBDAT` write, so a program that later changes them is
//! reported through [`BlitObservation::ImmediateDataShiftChanged`] — a fact
//! about the program, not a hedge about this model.
//!
//! `BLTADAT` has no load-time capture at all, so there is no A-side hazard.
//!
//! # What is refused
//!
//! A blit that this build will not perform is **refused by name** and the
//! refusal is part of the outcome. That is the whole point: the failure mode
//! worth removing is an incomplete picture that nothing reported. See
//! [`BlitRefusal`].

use serde::Serialize;

/// Register offsets, relative to `$DFF000`.
mod offsets {
    pub(super) const BLTCON0: u16 = 0x040;
    pub(super) const BLTCON1: u16 = 0x042;
    pub(super) const BLTAFWM: u16 = 0x044;
    pub(super) const BLTALWM: u16 = 0x046;
    pub(super) const BLTCPTH: u16 = 0x048;
    pub(super) const BLTCPTL: u16 = 0x04a;
    pub(super) const BLTBPTH: u16 = 0x04c;
    pub(super) const BLTBPTL: u16 = 0x04e;
    pub(super) const BLTAPTH: u16 = 0x050;
    pub(super) const BLTAPTL: u16 = 0x052;
    pub(super) const BLTDPTH: u16 = 0x054;
    pub(super) const BLTDPTL: u16 = 0x056;
    pub(super) const BLTSIZE: u16 = 0x058;
    pub(super) const BLTCON0L: u16 = 0x05a;
    pub(super) const BLTSIZV: u16 = 0x05c;
    pub(super) const BLTSIZH: u16 = 0x05e;
    pub(super) const BLTCMOD: u16 = 0x060;
    pub(super) const BLTBMOD: u16 = 0x062;
    pub(super) const BLTAMOD: u16 = 0x064;
    pub(super) const BLTDMOD: u16 = 0x066;
    pub(super) const BLTCDAT: u16 = 0x070;
    pub(super) const BLTBDAT: u16 = 0x072;
    pub(super) const BLTADAT: u16 = 0x074;

    /// The first and last offsets the blitter claims.
    pub(super) const FIRST: u16 = BLTCON0;
    pub(super) const LAST: u16 = BLTADAT;
}

/// Whether `offset` (relative to `$DFF000`) belongs to the blitter.
///
/// The whole span `$040`–`$074` is claimed, including the three ECS offsets
/// inside it, because on an OCS chipset a write to one of those must still be
/// *seen* in order to be reported — see [`BlitObservation::EcsRegisterWritten`].
#[must_use]
pub const fn is_blitter_register(offset: u16) -> bool {
    offset >= offsets::FIRST && offset <= offsets::LAST && offset.is_multiple_of(2)
}

/// Whether a write to `offset` would start a blit on a chipset this build does
/// not model, so that observing it is not enough.
///
/// `BLTSIZH` is ECS's second start trigger: on the OCS blitter modelled here the
/// write changes no state and no blit happens, which shows up as a missing image
/// with nothing to explain it. `BLTCON0L` and `BLTSIZV` start nothing on either
/// chipset, so they stay observations — which is why this asks about a start
/// trigger rather than about ECS registers in general.
#[must_use]
pub const fn is_unmodelled_start_trigger(offset: u16) -> bool {
    offset == offsets::BLTSIZH
}

/// Which chipset's blitter is being modelled.
///
/// A chipset rather than a feature flag, because "OCS with some ECS registers
/// observed but ignored" is not a coherent machine: `BLTCON0L` would leave a
/// stale minterm and `DOFF` would write memory the program said not to write.
/// ECS support is a second variant and a second start trigger, added when a
/// title needs it, rather than a hole in the middle of this one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Chipset {
    /// An OCS Agnus. `$05A`, `$05C` and `$05E` are not registers, and `BLTCON1`
    /// bit 7 (`DOFF`) is a reserved bit with no meaning.
    #[default]
    Ocs,
}

/// One of the blitter's four DMA channels.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    A,
    B,
    C,
    D,
}

impl Channel {
    /// Every channel, in the order the datapath uses them.
    pub const ALL: [Self; 4] = [Self::A, Self::B, Self::C, Self::D];

    /// The channel's index into the pointer and modulo files.
    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
            Self::C => 2,
            Self::D => 3,
        }
    }

    /// The channel's name, as the hardware documentation spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::C => "c",
            Self::D => "d",
        }
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// A decoded `BLTSIZE`: bits 5–0 are the width in words and bits 15–6 the height
/// in lines, with **zero meaning the maximum** in both fields.
///
/// The zero encoding is the reason this is a type rather than two `u16`s: a
/// width field of 0 means 64 words and a height field of 0 means 1024 lines, so
/// a caller that treated the raw fields as counts would silently do nothing at
/// all for the largest blit the hardware can perform.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OcsBlitSize {
    width: u16,
    height: u16,
}

impl OcsBlitSize {
    /// Decode a `BLTSIZE` word.
    pub const fn decode(word: u16) -> Self {
        let width = word & 0x3f;
        let height = word >> 6;
        Self {
            width: if width == 0 { 64 } else { width },
            height: if height == 0 { 1024 } else { height },
        }
    }

    /// Words per row, 1..=64.
    #[must_use]
    pub const fn width(self) -> u16 {
        self.width
    }

    /// Rows, 1..=1024.
    #[must_use]
    pub const fn height(self) -> u16 {
        self.height
    }

    /// Iterations of the datapath: `width × height`, at most 65,536.
    ///
    /// This is the unit the budget is charged in, because it is the work the
    /// blit does regardless of how many channels are enabled.
    #[must_use]
    pub const fn datapath_words(self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

/// The four channel pointers at one instant.
#[must_use]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ChannelPointers {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

impl ChannelPointers {
    /// One channel's pointer.
    #[must_use]
    pub const fn get(self, channel: Channel) -> u32 {
        match channel {
            Channel::A => self.a,
            Channel::B => self.b,
            Channel::C => self.c,
            Channel::D => self.d,
        }
    }
}

/// The memory a blit reaches, as a DMA contract rather than a read/write pair.
///
/// The separation matters. To check a destination the blitter must be able to
/// ask whether an address is there *without* reading it — inventing a DMA read
/// that never happened would put a fabricated event in front of every
/// watchpoint. And a DMA write is not a CPU write: it changes memory and a
/// watchpoint should see it, but it is not something the executing code did, and
/// putting tens of thousands of them into a write log alongside the one
/// instruction that started them would bury the instruction.
///
/// # Contract
///
/// 1. [`DmaMemory::contains_word`] has no observable effect of any kind: no
///    access event, no write, no dirty bit, no pending fault.
/// 2. A word `contains_word` accepted must not then fail to read or write. A
///    blit is atomic, so nothing can change the mapping underneath it; an
///    implementation that breaks this anyway gets a
///    [`BlitRefusal::Unmapped`] outcome *after* memory has been partly
///    written, which is the one case where a refusal is not clean.
/// 3. Both accessors take whole big-endian words at even addresses.
pub trait DmaMemory {
    /// Whether the word at `address` is inside mapped memory. Records nothing.
    fn contains_word(&self, address: u32) -> bool;
    /// Read a word by DMA. Observable to a watchpoint; never a CPU access.
    fn read_dma_word(&mut self, address: u32) -> Option<u16>;
    /// Write a word by DMA. Changes memory and is observable to a watchpoint;
    /// never appended to a CPU write log.
    fn write_dma_word(&mut self, address: u32, value: u16) -> Option<()>;
}

/// Why a triggered blit did not run.
///
/// A refusal means the record says a blit did not happen, which is the whole
/// value: an incomplete picture that nothing reported is the failure this type
/// exists to remove.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BlitRefusal {
    /// `BLTCON1` bit 0 was set. Line mode is not implemented.
    LineMode,
    /// A channel would have touched an address outside mapped memory.
    Unmapped { channel: Channel, address: u32 },
    /// Advancing a channel pointer by a step or a modulo left the 32-bit
    /// address space. Distinct from `Unmapped`, which is about the map rather
    /// than about the arithmetic.
    AddressOverflow { channel: Channel, at: u32 },
    /// `DMACON` did not have both `BLTEN` and `DMAEN` set, under a policy that
    /// requires them.
    DmaDisabled,
    /// The blit's datapath words exceeded the budget left for the run.
    BudgetExceeded { requested: u64, remaining: u64 },
}

impl BlitRefusal {
    /// A short, stable name for the kind of refusal, for grouping and dedup.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::LineMode => "line_mode",
            Self::Unmapped { .. } => "unmapped",
            Self::AddressOverflow { .. } => "address_overflow",
            Self::DmaDisabled => "dma_disabled",
            Self::BudgetExceeded { .. } => "budget_exceeded",
        }
    }

    /// The channel the refusal is about, when it is about one.
    #[must_use]
    pub const fn channel(self) -> Option<Channel> {
        match self {
            Self::Unmapped { channel, .. } | Self::AddressOverflow { channel, .. } => Some(channel),
            _ => None,
        }
    }
}

impl std::fmt::Display for BlitRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LineMode => formatter.write_str("line mode is not implemented"),
            Self::Unmapped { channel, address } => write!(
                formatter,
                "channel {channel} would reach {address:#010x}, which is not mapped"
            ),
            Self::AddressOverflow { channel, at } => write!(
                formatter,
                "channel {channel} left the address space advancing from {at:#010x}"
            ),
            Self::DmaDisabled => {
                formatter.write_str("blitter DMA is disabled and the recipe requires it")
            }
            Self::BudgetExceeded {
                requested,
                remaining,
            } => write!(
                formatter,
                "the blit needs {requested} datapath words and {remaining} remain in the budget"
            ),
        }
    }
}

/// Something true about a blit that a reader needs in order to distrust the
/// right pixel — or about a register write that changed nothing.
///
/// None of these refuse anything. Each marks either a place where this model's
/// fidelity is least certain, or a fact about the program worth reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BlitObservation {
    /// A write to a register this chipset does not have. It changed no state,
    /// which is what the chipset does.
    EcsRegisterWritten { register: u16, chipset: Chipset },
    /// A control bit that is reserved on this chipset was set — `BLTCON1` bit 7
    /// (`DOFF`) on OCS. It has no meaning and was ignored.
    ReservedControlBit { register: u16, bit: u8 },
    /// Both `EFE` and `IFE` were set. The manual does not say what the hardware
    /// does; this model lets exclusive fill win, and says so rather than
    /// choosing quietly.
    BothFillModes,
    /// A fill was requested without `DESC`. "Area fill only works correctly in
    /// descending mode" — but the hardware still runs it, so this does too, and
    /// the carry simply travels the wrong way. Refusing would reject a blit real
    /// hardware performs; silence would hide the one fact that explains the
    /// output.
    FillWithoutDescending,
    /// The destination's address extent overlaps an enabled source's.
    ///
    /// Not a refusal: exact `C == D` is the cookie-cut idiom and must work. It
    /// marks where the one-word pipeline's fidelity is least certain, since the
    /// real queue depth varies with which channels are active. Extents are
    /// compared, not exact word sets, so this can report an overlap where none
    /// of the individual words collide — over-reporting is the safe direction
    /// for a fidelity note.
    DestinationOverlapsSource { channel: Channel },
    /// `BSH` or `DESC` changed after `BLTBDAT` had already been shifted through
    /// the barrel shifter at load time, so the B constant in use is not the one
    /// the current shift would produce.
    ///
    /// With B DMA enabled the loaded hold is overwritten by the first fetch, so
    /// there the observation is informational rather than consequential.
    ImmediateDataShiftChanged {
        loaded_shift: u8,
        loaded_descending: bool,
        shift: u8,
        descending: bool,
    },
}

impl BlitObservation {
    /// A short, stable name for the kind of observation, for grouping and dedup.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::EcsRegisterWritten { .. } => "ecs_register_written",
            Self::ReservedControlBit { .. } => "reserved_control_bit",
            Self::BothFillModes => "both_fill_modes",
            Self::FillWithoutDescending => "fill_without_descending",
            Self::DestinationOverlapsSource { .. } => "destination_overlaps_source",
            Self::ImmediateDataShiftChanged { .. } => "immediate_data_shift_changed",
        }
    }

    /// The register the observation is about, when it is about one. Part of the
    /// finite key run-level observations are aggregated by, so a program writing
    /// one in a loop produces one row with a count rather than a million rows.
    #[must_use]
    pub const fn register(self) -> Option<u16> {
        match self {
            Self::EcsRegisterWritten { register, .. }
            | Self::ReservedControlBit { register, .. } => Some(register),
            _ => None,
        }
    }

    /// The channel the observation is about, when it is about one.
    #[must_use]
    pub const fn channel(self) -> Option<Channel> {
        match self {
            Self::DestinationOverlapsSource { channel } => Some(channel),
            _ => None,
        }
    }
}

/// What a register write asks for.
///
/// A `RegisterWriteOutcome` rather than an `Option<StartRequest>`, because a
/// write that starts nothing can still have something to report — which is
/// exactly the case a write to an ECS register on OCS is.
#[must_use]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegisterWriteOutcome {
    /// Present when the write was to a start trigger.
    pub start: Option<StartRequest>,
    pub observations: Vec<BlitObservation>,
}

/// A blit the register file has been told to perform.
///
/// Carrying the decoded size lets a caller charge its budget before handing the
/// request back to [`Blitter::execute`], which is what keeps a refused blit from
/// being cheaper than the budget says it was.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartRequest {
    size: OcsBlitSize,
}

impl StartRequest {
    /// The decoded `BLTSIZE`.
    pub const fn size(self) -> OcsBlitSize {
        self.size
    }
}

/// What to do when `DMACON` does not have blitter DMA enabled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DmaPolicy {
    /// Perform the blit anyway and say that the assumption was made.
    ///
    /// The default, because a call starts in the middle of a program, after an
    /// initialization the sandbox never ran: `DMACON` holding 0 says nothing
    /// about what the program intended.
    #[default]
    AssumeEnabled,
    /// Refuse the blit with [`BlitRefusal::DmaDisabled`]. For a recipe that did
    /// run the initialization, and where a blit with DMA off is a real finding.
    RequireEnabled,
}

/// The run-level state a blit happens under, supplied by whatever owns the
/// chipset rather than tracked here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlitConditions {
    /// Whether `DMACON` has both `BLTEN` and `DMAEN` set.
    pub dma_enabled: bool,
    /// What to do when it does not.
    pub dma: DmaPolicy,
    /// Datapath words still available to the run.
    ///
    /// The blit's whole cost is measured against this **before any address is
    /// generated**, because the preflight is itself proportional to the blit:
    /// charging only for blits that ran would leave the expensive half of a
    /// refusal loop unbounded. The caller subtracts
    /// [`BlitOutcome::datapath_words`] whatever the outcome — a refusal is not
    /// refunded.
    pub word_budget: u64,
}

/// What one triggered blit did.
#[must_use]
#[derive(Clone, Debug, PartialEq)]
pub struct BlitOutcome {
    /// The decoded `BLTSIZE`.
    pub size: OcsBlitSize,
    /// `width × height`: what the blit costs, whether or not it ran. This is
    /// what the caller charges its budget.
    pub datapath_words: u64,
    /// Words the D channel wrote. Zero when `USED` was clear or the blit was
    /// refused.
    pub words_written: u64,
    /// `BZERO`: whether every word the datapath produced was zero. `None` when
    /// no blit ran — reporting `false` there would be a claim.
    pub zero: Option<bool>,
    /// The channel pointers as they stood when the blit was triggered.
    pub initial_pointers: ChannelPointers,
    /// The channel pointers afterwards. Equal to `initial_pointers` when the
    /// blit was refused: a blit that did not happen cannot have advanced a
    /// pointer.
    pub final_pointers: ChannelPointers,
    /// Whether the blit ran under [`DmaPolicy::AssumeEnabled`] with DMA off.
    pub dma_assumed: bool,
    pub observations: Vec<BlitObservation>,
    /// `None` when the blit ran.
    ///
    /// A refusal decided before the datapath started — every one this build can
    /// reach through a well-behaved [`DmaMemory`] — wrote nothing and left every
    /// pointer where it was. The single exception is a `DmaMemory` that broke
    /// its own contract by failing an access its `contains_word` had accepted:
    /// there the refusal arrives mid-blit, `words_written` is non-zero, and
    /// `final_pointers` are wherever the datapath had reached.
    pub refused: Option<BlitRefusal>,
}

/// `BLTCON0` bit assignments.
const USEA: u16 = 1 << 11;
const USEB: u16 = 1 << 10;
const USEC: u16 = 1 << 9;
const USED: u16 = 1 << 8;

/// `BLTCON1` bit assignments, area mode.
const DOFF: u16 = 1 << 7;
const EFE: u16 = 1 << 4;
const IFE: u16 = 1 << 3;
const FCI: u16 = 1 << 2;
const DESC: u16 = 1 << 1;
const LINE: u16 = 1 << 0;

/// The blitter's register file and the state a blit leaves behind.
///
/// Stateful because the hardware is: the *order* of register writes is
/// observable, so a field bag read at `BLTSIZE` time could not be correct. See
/// the module documentation for the A/B asymmetry that makes this true.
#[derive(Clone, Debug)]
pub struct Blitter {
    chipset: Chipset,
    con0: u16,
    con1: u16,
    first_word_mask: u16,
    last_word_mask: u16,
    /// Indexed by [`Channel::index`].
    pointers: [u32; 4],
    /// Indexed by [`Channel::index`]; sign-extended from 16 bits, bit 0 cleared.
    modulos: [i32; 4],
    adat: u16,
    bdat: u16,
    cdat: u16,
    /// The B hold, computed when `BLTBDAT` was written and reused until B DMA
    /// fetches something new. Deliberately **not** reset at blit start, so a
    /// preloaded constant survives into the blit.
    b_hold: u16,
    /// The previous A word, masked. Reset at blit start.
    a_old: u16,
    /// The previous B word: what the next shift shifts against, whether that
    /// shift comes from a DMA fetch or from another `BLTBDAT` write. Reset at
    /// blit start.
    b_old: u16,
    /// `(BSH, DESC)` in force at the last `BLTBDAT` write, if there was one.
    b_loaded_with: Option<(u8, bool)>,
    /// The raw last `BLTSIZE` word, for read-back only.
    size_word: u16,
    /// `BZERO` from the last blit that ran.
    zero: Option<bool>,
}

impl Default for Blitter {
    fn default() -> Self {
        Self::new(Chipset::Ocs)
    }
}

impl Blitter {
    /// A blitter with every register clear, modelling `chipset`.
    #[must_use]
    pub const fn new(chipset: Chipset) -> Self {
        Self {
            chipset,
            con0: 0,
            con1: 0,
            first_word_mask: 0,
            last_word_mask: 0,
            pointers: [0; 4],
            modulos: [0; 4],
            adat: 0,
            bdat: 0,
            cdat: 0,
            b_hold: 0,
            a_old: 0,
            b_old: 0,
            b_loaded_with: None,
            size_word: 0,
            zero: None,
        }
    }

    /// The chipset being modelled.
    #[must_use]
    pub const fn chipset(&self) -> Chipset {
        self.chipset
    }

    /// `BZERO`: whether the last blit that ran produced only zero words. `None`
    /// until one has.
    #[must_use]
    pub const fn zero(&self) -> Option<bool> {
        self.zero
    }

    /// The current channel pointers.
    pub const fn pointers(&self) -> ChannelPointers {
        ChannelPointers {
            a: self.pointers[0],
            b: self.pointers[1],
            c: self.pointers[2],
            d: self.pointers[3],
        }
    }

    /// Read a register back, or `None` if this chipset does not model it.
    ///
    /// Most of these are write-only on real hardware, so a read-back is a
    /// sandbox convenience rather than a fidelity claim — but a convenience with
    /// two answers is worse than either, so whatever the blitter models it is
    /// the one that answers.
    #[must_use]
    pub fn read_register(&self, offset: u16) -> Option<u16> {
        use offsets as reg;
        let value = match offset {
            reg::BLTCON0 => self.con0,
            reg::BLTCON1 => self.con1,
            reg::BLTAFWM => self.first_word_mask,
            reg::BLTALWM => self.last_word_mask,
            reg::BLTCPTH => (self.pointers[Channel::C.index()] >> 16) as u16,
            reg::BLTCPTL => self.pointers[Channel::C.index()] as u16,
            reg::BLTBPTH => (self.pointers[Channel::B.index()] >> 16) as u16,
            reg::BLTBPTL => self.pointers[Channel::B.index()] as u16,
            reg::BLTAPTH => (self.pointers[Channel::A.index()] >> 16) as u16,
            reg::BLTAPTL => self.pointers[Channel::A.index()] as u16,
            reg::BLTDPTH => (self.pointers[Channel::D.index()] >> 16) as u16,
            reg::BLTDPTL => self.pointers[Channel::D.index()] as u16,
            reg::BLTSIZE => self.size_word,
            reg::BLTCMOD => self.modulos[Channel::C.index()] as u16,
            reg::BLTBMOD => self.modulos[Channel::B.index()] as u16,
            reg::BLTAMOD => self.modulos[Channel::A.index()] as u16,
            reg::BLTDMOD => self.modulos[Channel::D.index()] as u16,
            reg::BLTCDAT => self.cdat,
            reg::BLTBDAT => self.bdat,
            reg::BLTADAT => self.adat,
            // `$05A`/`$05C`/`$05E` are not registers on OCS, and `$068`–`$06E`
            // are not registers on anything. Neither is modelled, so neither
            // answers; a caller's own shadow does.
            _ => return None,
        };
        Some(value)
    }

    /// Write a register, and say whether that started a blit.
    ///
    /// A pointer write clears bit 0 — "because the blitter works only on words,
    /// the least significant bit of the address is ignored". A modulo write does
    /// the same and sign-extends: "the modulo values are in bytes, not words …
    /// the value is sign-extended to the full width of the address pointer
    /// registers. Negative modulos can be useful in a variety of ways."
    pub fn write_register(&mut self, offset: u16, value: u16) -> RegisterWriteOutcome {
        use offsets as reg;
        let mut outcome = RegisterWriteOutcome::default();
        match offset {
            reg::BLTCON0 => self.con0 = value,
            reg::BLTCON1 => self.con1 = value,
            reg::BLTAFWM => self.first_word_mask = value,
            reg::BLTALWM => self.last_word_mask = value,
            reg::BLTCPTH => self.set_pointer_high(Channel::C, value),
            reg::BLTCPTL => self.set_pointer_low(Channel::C, value),
            reg::BLTBPTH => self.set_pointer_high(Channel::B, value),
            reg::BLTBPTL => self.set_pointer_low(Channel::B, value),
            reg::BLTAPTH => self.set_pointer_high(Channel::A, value),
            reg::BLTAPTL => self.set_pointer_low(Channel::A, value),
            reg::BLTDPTH => self.set_pointer_high(Channel::D, value),
            reg::BLTDPTL => self.set_pointer_low(Channel::D, value),
            reg::BLTCMOD => self.set_modulo(Channel::C, value),
            reg::BLTBMOD => self.set_modulo(Channel::B, value),
            reg::BLTAMOD => self.set_modulo(Channel::A, value),
            reg::BLTDMOD => self.set_modulo(Channel::D, value),
            // Raw. It is re-masked and re-shifted every datapath word, so there
            // is nothing to capture here and no A-side hazard to detect.
            reg::BLTADAT => self.adat = value,
            // The load-time shift: writing BLTBDAT draws the data through the
            // barrel shifter now, with whatever BSH and DESC hold now.
            reg::BLTBDAT => self.load_b(value),
            // No shifter in the C path, and no mask.
            reg::BLTCDAT => self.cdat = value,
            reg::BLTSIZE => {
                self.size_word = value;
                outcome.start = Some(StartRequest {
                    size: OcsBlitSize::decode(value),
                });
            }
            reg::BLTCON0L | reg::BLTSIZV | reg::BLTSIZH => {
                // Not registers on this chipset. The write changes no state,
                // which is what the chipset does, and is reported so that a
                // program relying on one is not silently doing nothing.
                outcome
                    .observations
                    .push(BlitObservation::EcsRegisterWritten {
                        register: offset,
                        chipset: self.chipset,
                    });
            }
            _ => {}
        }
        outcome
    }

    fn set_pointer_high(&mut self, channel: Channel, value: u16) {
        let pointer = &mut self.pointers[channel.index()];
        *pointer = (u32::from(value) << 16) | (*pointer & 0xffff);
        *pointer &= !1;
    }

    fn set_pointer_low(&mut self, channel: Channel, value: u16) {
        let pointer = &mut self.pointers[channel.index()];
        *pointer = (*pointer & 0xffff_0000) | u32::from(value & !1);
    }

    fn set_modulo(&mut self, channel: Channel, value: u16) {
        self.modulos[channel.index()] = i32::from(value as i16) & !1;
    }

    /// Apply a `BLTBDAT` write: shift now, with the shift and direction now.
    fn load_b(&mut self, value: u16) {
        let shift = self.b_shift();
        let descending = self.descending();
        self.b_hold = shift_word(self.b_old, value, shift, descending);
        self.b_old = value;
        self.bdat = value;
        self.b_loaded_with = Some((shift, descending));
    }

    const fn a_shift(&self) -> u8 {
        (self.con0 >> 12) as u8
    }

    const fn b_shift(&self) -> u8 {
        (self.con1 >> 12) as u8
    }

    const fn descending(&self) -> bool {
        self.con1 & DESC != 0
    }

    const fn uses(&self, channel: Channel) -> bool {
        let bit = match channel {
            Channel::A => USEA,
            Channel::B => USEB,
            Channel::C => USEC,
            Channel::D => USED,
        };
        self.con0 & bit != 0
    }

    /// Perform the blit `start` asked for.
    ///
    /// The refusal order is deliberate and is part of the contract:
    ///
    /// 1. [`BlitRefusal::LineMode`] — nothing else about the blit is meaningful
    ///    under a mode this build does not implement.
    /// 2. [`BlitRefusal::DmaDisabled`] — a stated policy, decided before any
    ///    work.
    /// 3. [`BlitRefusal::BudgetExceeded`] — checked **before any address is
    ///    generated**, because generating them is what costs.
    /// 4. [`BlitRefusal::Unmapped`] / [`BlitRefusal::AddressOverflow`] — the
    ///    preflight, which reaches every address every enabled channel would
    ///    touch before a single word is written.
    ///
    /// A refusal freezes every piece of blitter state: the four pointers, the
    /// latches and holds, the data registers, the control words, the masks, the
    /// modulos and the last decoded size are all exactly as they were. No memory
    /// is written, `zero` stays as it was, and the only things that change are
    /// the caller's budget and its telemetry. This is the only contract
    /// consistent with the blit being atomic — a blit that did not happen cannot
    /// have advanced a pointer.
    pub fn execute(
        &mut self,
        start: StartRequest,
        memory: &mut dyn DmaMemory,
        conditions: BlitConditions,
    ) -> BlitOutcome {
        let size = start.size;
        let initial = self.pointers();
        let refuse = |refusal, observations| BlitOutcome {
            size,
            datapath_words: size.datapath_words(),
            words_written: 0,
            zero: None,
            initial_pointers: initial,
            final_pointers: initial,
            dma_assumed: false,
            observations,
            refused: Some(refusal),
        };

        if self.con1 & LINE != 0 {
            return refuse(BlitRefusal::LineMode, Vec::new());
        }
        let dma_assumed = match (conditions.dma_enabled, conditions.dma) {
            (true, _) => false,
            (false, DmaPolicy::AssumeEnabled) => true,
            (false, DmaPolicy::RequireEnabled) => {
                return refuse(BlitRefusal::DmaDisabled, Vec::new());
            }
        };
        let words = size.datapath_words();
        if words > conditions.word_budget {
            return refuse(
                BlitRefusal::BudgetExceeded {
                    requested: words,
                    remaining: conditions.word_budget,
                },
                Vec::new(),
            );
        }

        let extents = match self.preflight(size, memory) {
            Ok(extents) => extents,
            Err(refusal) => return refuse(refusal, Vec::new()),
        };

        let mut observations = self.observations_for_run(&extents);
        let mut outcome = self.run(size, initial, memory, &mut observations);
        outcome.dma_assumed = dma_assumed;
        outcome
    }

    /// Everything worth saying about a blit that is about to run.
    fn observations_for_run(&self, extents: &ChannelExtents) -> Vec<BlitObservation> {
        let mut observations = Vec::new();
        if self.con1 & DOFF != 0 {
            observations.push(BlitObservation::ReservedControlBit {
                register: offsets::BLTCON1,
                bit: 7,
            });
        }
        if self.con1 & EFE != 0 && self.con1 & IFE != 0 {
            observations.push(BlitObservation::BothFillModes);
        }
        if self.con1 & (EFE | IFE) != 0 && !self.descending() {
            observations.push(BlitObservation::FillWithoutDescending);
        }
        if let Some((loaded_shift, loaded_descending)) = self.b_loaded_with {
            let shift = self.b_shift();
            let descending = self.descending();
            if (loaded_shift, loaded_descending) != (shift, descending) {
                observations.push(BlitObservation::ImmediateDataShiftChanged {
                    loaded_shift,
                    loaded_descending,
                    shift,
                    descending,
                });
            }
        }
        observations.extend(extents.overlaps_with_destination());
        observations
    }

    /// Reach every address every enabled channel would touch, before anything
    /// is written, and report the extent each one covers.
    ///
    /// A **disabled** channel's pointer is never dereferenced and never checked:
    /// a recipe with a stale `BLTBPT` and `USEB` clear must not be refused. That
    /// is consistent with the datapath, where a disabled channel still
    /// contributes data and that data comes from a register.
    fn preflight(
        &self,
        size: OcsBlitSize,
        memory: &dyn DmaMemory,
    ) -> Result<ChannelExtents, BlitRefusal> {
        let descending = self.descending();
        let mut extents = ChannelExtents::default();
        for channel in Channel::ALL {
            if !self.uses(channel) {
                continue;
            }
            let mut pointer = self.pointers[channel.index()];
            let mut extent: Option<(u32, u32)> = None;
            for _ in 0..size.height() {
                for _ in 0..size.width() {
                    if !memory.contains_word(pointer) {
                        return Err(BlitRefusal::Unmapped {
                            channel,
                            address: pointer,
                        });
                    }
                    extent = Some(match extent {
                        None => (pointer, pointer),
                        Some((low, high)) => (low.min(pointer), high.max(pointer)),
                    });
                    pointer = step(pointer, descending).ok_or(BlitRefusal::AddressOverflow {
                        channel,
                        at: pointer,
                    })?;
                }
                pointer = apply_modulo(pointer, self.modulos[channel.index()], descending).ok_or(
                    BlitRefusal::AddressOverflow {
                        channel,
                        at: pointer,
                    },
                )?;
            }
            extents.set(channel, extent);
        }
        Ok(extents)
    }

    /// The datapath. One pass, per word, per row, with one pending destination
    /// word — "the first two sets of sources are fetched before the first
    /// destination is written", which is a queue holding exactly one word.
    fn run(
        &mut self,
        size: OcsBlitSize,
        initial: ChannelPointers,
        memory: &mut dyn DmaMemory,
        observations: &mut Vec<BlitObservation>,
    ) -> BlitOutcome {
        let descending = self.descending();
        let a_shift = self.a_shift();
        let b_shift = self.b_shift();
        let minterm_bits = self.con0 as u8;
        let filling = self.con1 & (EFE | IFE) != 0;
        // Exclusive wins when both are set: the manual does not say, and a
        // stated choice with an observation beats a quiet one.
        let exclusive = self.con1 & EFE != 0;
        let use_a = self.uses(Channel::A);
        let use_b = self.uses(Channel::B);
        let use_c = self.uses(Channel::C);
        let use_d = self.uses(Channel::D);

        // Source latches reset; `b_hold` deliberately does not, so a preloaded
        // BLTBDAT constant survives into the blit.
        self.a_old = 0;
        self.b_old = 0;

        let mut pending: Option<(u32, u16)> = None;
        let mut words_written = 0_u64;
        let mut zero = true;
        let mut refused = None;
        let last = size.width() - 1;

        'rows: for _ in 0..size.height() {
            let mut carry = self.con1 & FCI != 0;
            for x in 0..size.width() {
                // A is recomputed every word, fetched or not. `USEA` gates the
                // fetch and nothing else, so the masks act either way.
                let a_raw = if use_a {
                    match memory.read_dma_word(self.pointers[Channel::A.index()]) {
                        Some(word) => {
                            self.adat = word;
                            word
                        }
                        None => {
                            refused = Some(BlitRefusal::Unmapped {
                                channel: Channel::A,
                                address: self.pointers[Channel::A.index()],
                            });
                            break 'rows;
                        }
                    }
                } else {
                    self.adat
                };
                let mut a_masked = a_raw;
                if x == 0 {
                    a_masked &= self.first_word_mask;
                }
                if x == last {
                    a_masked &= self.last_word_mask;
                }
                let a = shift_word(self.a_old, a_masked, a_shift, descending);
                self.a_old = a_masked;

                // B is a latch. Only a fetch disturbs it.
                if use_b {
                    match memory.read_dma_word(self.pointers[Channel::B.index()]) {
                        Some(word) => {
                            self.b_hold = shift_word(self.b_old, word, b_shift, descending);
                            self.b_old = word;
                            self.bdat = word;
                        }
                        None => {
                            refused = Some(BlitRefusal::Unmapped {
                                channel: Channel::B,
                                address: self.pointers[Channel::B.index()],
                            });
                            break 'rows;
                        }
                    }
                }
                let b = self.b_hold;

                // C has no mask and no shifter.
                let c = if use_c {
                    match memory.read_dma_word(self.pointers[Channel::C.index()]) {
                        Some(word) => {
                            self.cdat = word;
                            word
                        }
                        None => {
                            refused = Some(BlitRefusal::Unmapped {
                                channel: Channel::C,
                                address: self.pointers[Channel::C.index()],
                            });
                            break 'rows;
                        }
                    }
                } else {
                    self.cdat
                };

                let mut d = minterm(minterm_bits, a, b, c);
                if filling {
                    (d, carry) = fill(d, carry, exclusive);
                }
                // Computed whether or not D writes: BZERO is about the
                // datapath's output, not about the traffic.
                zero &= d == 0;

                // The queue holds exactly one word: pushing d(n) pops d(n-1),
                // which is written only now — after the sources of this slot
                // were read. That one-slot delay is what makes an in-place
                // scroll behave as the hardware's does rather than smearing.
                if use_d
                    && let Some((address, word)) =
                        pending.replace((self.pointers[Channel::D.index()], d))
                {
                    if memory.write_dma_word(address, word).is_none() {
                        refused = Some(BlitRefusal::Unmapped {
                            channel: Channel::D,
                            address,
                        });
                        break 'rows;
                    }
                    words_written += 1;
                }

                // Advance every enabled channel by one word.
                for channel in Channel::ALL {
                    if !self.uses(channel) {
                        continue;
                    }
                    match step(self.pointers[channel.index()], descending) {
                        Some(next) => self.pointers[channel.index()] = next,
                        None => {
                            refused = Some(BlitRefusal::AddressOverflow {
                                channel,
                                at: self.pointers[channel.index()],
                            });
                            break 'rows;
                        }
                    }
                }
            }

            for channel in Channel::ALL {
                if !self.uses(channel) {
                    continue;
                }
                match apply_modulo(
                    self.pointers[channel.index()],
                    self.modulos[channel.index()],
                    descending,
                ) {
                    Some(next) => self.pointers[channel.index()] = next,
                    None => {
                        refused = Some(BlitRefusal::AddressOverflow {
                            channel,
                            at: self.pointers[channel.index()],
                        });
                        break 'rows;
                    }
                }
            }
        }

        // Exactly one word remains in the queue.
        if refused.is_none()
            && let Some((address, word)) = pending.take()
        {
            if memory.write_dma_word(address, word).is_some() {
                words_written += 1;
            } else {
                refused = Some(BlitRefusal::Unmapped {
                    channel: Channel::D,
                    address,
                });
            }
        }

        let zero = refused.is_none().then_some(zero);
        if let Some(zero) = zero {
            self.zero = Some(zero);
        }
        BlitOutcome {
            size,
            datapath_words: size.datapath_words(),
            words_written,
            zero,
            initial_pointers: initial,
            final_pointers: self.pointers(),
            dma_assumed: false,
            observations: std::mem::take(observations),
            refused,
        }
    }
}

/// The address span each channel covered, for the overlap observation.
#[derive(Clone, Copy, Debug, Default)]
struct ChannelExtents {
    spans: [Option<(u32, u32)>; 4],
}

impl ChannelExtents {
    fn set(&mut self, channel: Channel, span: Option<(u32, u32)>) {
        self.spans[channel.index()] = span;
    }

    /// Every enabled source whose extent meets the destination's.
    fn overlaps_with_destination(self) -> Vec<BlitObservation> {
        let Some((low, high)) = self.spans[Channel::D.index()] else {
            return Vec::new();
        };
        [Channel::A, Channel::B, Channel::C]
            .into_iter()
            .filter(|channel| {
                self.spans[channel.index()].is_some_and(|(start, end)| start <= high && low <= end)
            })
            .map(|channel| BlitObservation::DestinationOverlapsSource { channel })
            .collect()
    }
}

/// One word forward (ascending) or backward (descending).
const fn step(pointer: u32, descending: bool) -> Option<u32> {
    if descending {
        pointer.checked_sub(2)
    } else {
        pointer.checked_add(2)
    }
}

/// The row modulo: added ascending, subtracted descending.
///
/// An overflow here is refused rather than wrapped. OCS ignores the top address
/// bits, but the sandbox is not a 512 KB machine and its map is wherever the
/// recipe put it, so wrapping would silently redirect a pointer into a region
/// the recipe never named.
const fn apply_modulo(pointer: u32, modulo: i32, descending: bool) -> Option<u32> {
    if descending {
        match modulo.checked_neg() {
            Some(negated) => pointer.checked_add_signed(negated),
            None => None,
        }
    } else {
        pointer.checked_add_signed(modulo)
    }
}

/// The barrel shifter, serving the per-word A path, the per-fetch B path and the
/// `BLTBDAT` write path — one implementation, so the three cannot disagree.
///
/// Ascending is a right shift pulling in the previous word's low bits.
/// Descending is a left shift pulling in the previously *processed* — that is,
/// the right-hand — word's high bits, which at shift 0 correctly reduces to the
/// current word.
#[must_use]
const fn shift_word(previous: u16, current: u16, shift: u8, descending: bool) -> u16 {
    let shift = (shift & 0x0f) as u32;
    let pair = if descending {
        ((current as u32) << 16) | previous as u32
    } else {
        ((previous as u32) << 16) | current as u32
    };
    let amount = if descending { 16 - shift } else { shift };
    (pair >> amount) as u16
}

/// The logic function, bitwise over 16 bits.
///
/// The eight minterms are indexed `(A << 2) | (B << 1) | C`, so `LF7` is the
/// `A·B·C` term and `LF0` the `Ā·B̄·C̄` term. `$f0` is "copy A", `$ca` is
/// `AB + ĀC` — the cookie-cut — and `$00` clears.
#[must_use]
const fn minterm(function: u8, a: u16, b: u16, c: u16) -> u16 {
    let mut out = 0_u16;
    let mut index = 0_u8;
    while index < 8 {
        if function & (1 << index) != 0 {
            let a_term = if index & 4 != 0 { a } else { !a };
            let b_term = if index & 2 != 0 { b } else { !b };
            let c_term = if index & 1 != 0 { c } else { !c };
            out |= a_term & b_term & c_term;
        }
        index += 1;
    }
    out
}

/// Area fill, LSB to MSB within the word — bit 0 is the rightmost pixel, and
/// descending mode is what makes the carry travel the right way across words.
///
/// Inclusive fill leaves both border lines; exclusive fill keeps the right
/// border and deletes the left, so a row `…10001` becomes `…11111` inclusive and
/// `…01111` exclusive.
#[must_use]
const fn fill(word: u16, carry_in: bool, exclusive: bool) -> (u16, bool) {
    let mut out = 0_u16;
    let mut carry = carry_in;
    let mut bit = 0_u32;
    while bit < 16 {
        let value = (word >> bit) & 1 == 1;
        carry ^= value;
        if if exclusive { carry } else { carry || value } {
            out |= 1 << bit;
        }
        bit += 1;
    }
    (out, carry)
}

#[cfg(test)]
mod tests {
    use super::offsets as reg;
    use super::*;

    /// Where the test RAM starts, and how many words it holds.
    const RAM_BASE: u32 = 0x1000;
    const RAM_WORDS: usize = 0x400;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Touch {
        Read(u32),
        Write(u32, u16),
    }

    /// A `Vec<u16>` with a DMA contract over it. The access log is what lets the
    /// pipeline's ordering be asserted rather than inferred from the result.
    struct TestRam {
        words: Vec<u16>,
        log: Vec<Touch>,
    }

    impl TestRam {
        fn new() -> Self {
            Self {
                words: vec![0; RAM_WORDS],
                log: Vec::new(),
            }
        }

        fn index(&self, address: u32) -> Option<usize> {
            if !address.is_multiple_of(2) {
                return None;
            }
            let offset = usize::try_from(address.checked_sub(RAM_BASE)?).ok()? / 2;
            (offset < self.words.len()).then_some(offset)
        }

        fn poke(&mut self, address: u32, words: &[u16]) {
            for (step, word) in words.iter().enumerate() {
                let index = self
                    .index(address + step as u32 * 2)
                    .unwrap_or_else(|| panic!("{address:#x} + {step} is outside the test RAM"));
                self.words[index] = *word;
            }
        }

        fn peek(&self, address: u32, count: usize) -> Vec<u16> {
            (0..count)
                .map(|step| {
                    let index = self
                        .index(address + step as u32 * 2)
                        .unwrap_or_else(|| panic!("{address:#x} + {step} is outside the test RAM"));
                    self.words[index]
                })
                .collect()
        }
    }

    impl DmaMemory for TestRam {
        fn contains_word(&self, address: u32) -> bool {
            self.index(address).is_some()
        }

        fn read_dma_word(&mut self, address: u32) -> Option<u16> {
            let index = self.index(address)?;
            self.log.push(Touch::Read(address));
            Some(self.words[index])
        }

        fn write_dma_word(&mut self, address: u32, value: u16) -> Option<()> {
            let index = self.index(address)?;
            self.words[index] = value;
            self.log.push(Touch::Write(address, value));
            Some(())
        }
    }

    /// Every even address is mapped, so a blit can be driven off the end of the
    /// address space and the arithmetic refusal is what stops it.
    struct BoundlessRam;

    impl DmaMemory for BoundlessRam {
        fn contains_word(&self, address: u32) -> bool {
            address.is_multiple_of(2)
        }
        fn read_dma_word(&mut self, _address: u32) -> Option<u16> {
            Some(0)
        }
        fn write_dma_word(&mut self, _address: u32, _value: u16) -> Option<()> {
            Some(())
        }
    }

    fn conditions() -> BlitConditions {
        BlitConditions {
            dma_enabled: true,
            dma: DmaPolicy::AssumeEnabled,
            word_budget: u64::MAX,
        }
    }

    struct Fixture {
        blitter: Blitter,
        ram: TestRam,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                blitter: Blitter::new(Chipset::Ocs),
                ram: TestRam::new(),
            }
        }

        fn set(&mut self, offset: u16, value: u16) -> &mut Self {
            let outcome = self.blitter.write_register(offset, value);
            assert!(
                outcome.start.is_none(),
                "{offset:#05x} is a start trigger; use blit()"
            );
            self
        }

        /// Set a channel pointer through both halves, as a `MOVE.L` would.
        fn point(&mut self, high: u16, address: u32) -> &mut Self {
            self.set(high, (address >> 16) as u16);
            self.set(high + 2, address as u16)
        }

        /// Both word masks wide open, which is what most tests want.
        fn open_masks(&mut self) -> &mut Self {
            self.set(reg::BLTAFWM, 0xffff);
            self.set(reg::BLTALWM, 0xffff)
        }

        fn blit(&mut self, size_word: u16) -> BlitOutcome {
            self.blit_under(size_word, conditions())
        }

        /// Run a blit that is meant to be performed, and say so. Most tests
        /// assert on the resulting bytes; asserting the blit happened at all
        /// keeps a refusal from reading as a wrong result.
        fn blit_ok(&mut self, size_word: u16) {
            let outcome = self.blit(size_word);
            assert_eq!(outcome.refused, None, "the blit was refused");
        }

        fn blit_under(&mut self, size_word: u16, conditions: BlitConditions) -> BlitOutcome {
            self.ram.log.clear();
            let start = self
                .blitter
                .write_register(reg::BLTSIZE, size_word)
                .start
                .expect("BLTSIZE starts a blit");
            self.blitter.execute(start, &mut self.ram, conditions)
        }
    }

    /// Write a register that is not a start trigger, for the tests that drive a
    /// bare [`Blitter`] rather than a [`Fixture`].
    fn plain(blitter: &mut Blitter, offset: u16, value: u16) {
        let outcome = blitter.write_register(offset, value);
        assert!(outcome.start.is_none(), "{offset:#05x} is a start trigger");
    }

    /// `BLTSIZE` for a width in words and a height in lines, as a caller writes
    /// it rather than as the register encodes it.
    fn size_of(width: u16, height: u16) -> u16 {
        assert!((1..=64).contains(&width) && (1..=1024).contains(&height));
        ((height % 1024) << 6) | (width % 64)
    }

    /// `USEA | USED` with the "copy A" minterm and no shift.
    const COPY_A: u16 = USEA | USED | 0xf0;
    /// `USEB | USED` with the "copy B" minterm: indices 2, 3, 6 and 7.
    const COPY_B: u16 = USEB | USED | 0xcc;
    /// The same, with B DMA **off**, so the B value comes from the latch a
    /// `BLTBDAT` write left — the shape §3.7 is about.
    const B_CONSTANT: u16 = USED | 0xcc;

    // ---------------------------------------------------------------- minterm

    #[test]
    fn every_minterm_matches_its_truth_table() {
        // Logically exhaustive: the function is bitwise, so all-zero and all-one
        // inputs cover every bit position's behaviour for every one of the 256
        // functions.
        for function in 0..=u8::MAX {
            for combination in 0..8_u8 {
                let a = if combination & 4 != 0 { 0xffff } else { 0 };
                let b = if combination & 2 != 0 { 0xffff } else { 0 };
                let c = if combination & 1 != 0 { 0xffff } else { 0 };
                let expected = if function & (1 << combination) != 0 {
                    0xffff
                } else {
                    0
                };
                assert_eq!(
                    minterm(function, a, b, c),
                    expected,
                    "LF={function:#04x} for (a,b,c)={combination:03b}"
                );
            }
        }
    }

    #[test]
    fn the_named_minterms_are_what_they_are_named() {
        let (a, b, c) = (0xff00, 0x1234, 0xabcd);
        assert_eq!(minterm(0xf0, a, b, c), a, "$f0 copies A");
        assert_eq!(minterm(0xcc, a, b, c), b, "$cc copies B");
        assert_eq!(minterm(0xaa, a, b, c), c, "$aa copies C");
        assert_eq!(minterm(0x00, a, b, c), 0, "$00 clears");
        assert_eq!(minterm(0xff, a, b, c), 0xffff, "$ff sets");
        // The cookie cut: AB + not-A C.
        assert_eq!(minterm(0xca, a, b, c), (a & b) | (!a & c));
        assert_eq!(minterm(0xca, a, b, c), 0x12cd);
    }

    // --------------------------------------------------------- copy and masks

    #[test]
    fn a_straight_copy_moves_the_words_unchanged() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1234, 0x5678]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(2, 1));
        assert_eq!(outcome.refused, None);
        assert_eq!(outcome.words_written, 2);
        assert_eq!(outcome.datapath_words, 2);
        assert_eq!(fixture.ram.peek(0x1100, 2), vec![0x1234, 0x5678]);
    }

    #[test]
    fn the_first_and_last_word_masks_clip_the_edges_of_a_row() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0xffff, 0xffff, 0xffff]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.set(reg::BLTAFWM, 0x07ff);
        fixture.set(reg::BLTALWM, 0xfff0);
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(3, 1));
        assert_eq!(fixture.ram.peek(0x1100, 3), vec![0x07ff, 0xffff, 0xfff0]);
    }

    #[test]
    fn a_one_word_row_gets_both_masks() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0xffff]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.set(reg::BLTAFWM, 0x0fff);
        fixture.set(reg::BLTALWM, 0xfff0);
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x0ff0]);
    }

    // ------------------------------------------------------------- disabled A

    #[test]
    fn a_disabled_a_channel_still_gets_its_masks() {
        // The manual's own case: "even though the A channel is disabled, we use
        // it in our logic function and preload the data register". Skipping the
        // masks here is not an edge case — it is how a masked, non-word-aligned
        // rectangle is clipped, and skipping them makes the clipped edges come
        // out solid with nothing reported.
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, USED | 0xf0); // USEA deliberately clear
        fixture.set(reg::BLTCON1, 0);
        fixture.set(reg::BLTADAT, 0xffff);
        fixture.set(reg::BLTAFWM, 0x07ff);
        fixture.set(reg::BLTALWM, 0xfff0);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(3, 1));
        assert_eq!(outcome.refused, None);
        assert_eq!(fixture.ram.peek(0x1100, 3), vec![0x07ff, 0xffff, 0xfff0]);
        assert!(
            fixture
                .ram
                .log
                .iter()
                .all(|touch| !matches!(touch, Touch::Read(_))),
            "a disabled channel fetches nothing"
        );
    }

    #[test]
    fn shifting_a_full_mask_reaches_the_same_edge_as_masking_the_shift() {
        // The manual's second form of the same clip: ASH=5 with a wide first
        // mask lands on exactly the bytes the narrow mask selected above.
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, USED | (5 << 12) | 0xf0);
        fixture.set(reg::BLTCON1, 0);
        fixture.set(reg::BLTADAT, 0xffff);
        fixture.set(reg::BLTAFWM, 0xffff);
        fixture.set(reg::BLTALWM, 0xfe00);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(3, 1));
        assert_eq!(fixture.ram.peek(0x1100, 3), vec![0x07ff, 0xffff, 0xfff0]);
    }

    // ----------------------------------------------------------------- shifts

    #[test]
    fn a_shift_pulls_in_the_previous_words_low_bits() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1234, 0x5678]);
        fixture.set(reg::BLTCON0, COPY_A | (4 << 12));
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(2, 1));
        // (0x0000_1234 >> 4) and (0x1234_5678 >> 4).
        assert_eq!(fixture.ram.peek(0x1100, 2), vec![0x0123, 0x4567]);
    }

    #[test]
    fn a_shift_of_zero_and_of_fifteen_are_both_exact() {
        for (shift, expected) in [(0_u16, vec![0x1234, 0x5678]), (15, vec![0x0000, 0x2468])] {
            let mut fixture = Fixture::new();
            fixture.ram.poke(0x1000, &[0x1234, 0x5678]);
            fixture.set(reg::BLTCON0, COPY_A | (shift << 12));
            fixture.set(reg::BLTCON1, 0);
            fixture.open_masks();
            fixture.point(reg::BLTAPTH, 0x1000);
            fixture.point(reg::BLTDPTH, 0x1100);

            fixture.blit_ok(size_of(2, 1));
            assert_eq!(fixture.ram.peek(0x1100, 2), expected, "ASH={shift}");
        }
    }

    #[test]
    fn the_a_latch_carries_across_a_row_boundary() {
        // A pinned choice: the latch is reset once per blit, not once per row,
        // so the first word of row 1 shifts against the last word of row 0.
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0xaaaa, 0xbbbb]);
        fixture.set(reg::BLTCON0, COPY_A | (4 << 12));
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(1, 2));
        // Row 0 shifts against the reset latch, row 1 against 0xaaaa.
        assert_eq!(fixture.ram.peek(0x1100, 2), vec![0x0aaa, 0xabbb]);
    }

    #[test]
    fn descending_shifts_the_other_way_and_walks_backwards() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1234, 0x5678]);
        fixture.set(reg::BLTCON0, COPY_A | (4 << 12));
        fixture.set(reg::BLTCON1, DESC);
        fixture.open_masks();
        // Descending starts at the last word of the block.
        fixture.point(reg::BLTAPTH, 0x1002);
        fixture.point(reg::BLTDPTH, 0x1102);

        fixture.blit_ok(size_of(2, 1));
        // The rightmost word is processed first: (0x5678_0000 >> 12) lands at
        // 0x1102, then (0x1234_5678 >> 12) at 0x1100.
        assert_eq!(fixture.ram.peek(0x1100, 2), vec![0x2345, 0x6780]);
    }

    // -------------------------------------------------------- the B latch

    #[test]
    fn a_preloaded_b_constant_is_shifted_at_load_time_not_per_word() {
        // The manual's warning, exactly: "if the last person left BSHIFT to be
        // '4', and I load BDATA with '1' and then change BSHIFT to '2', the
        // resulting BDATA that is used is '1<<4', not '1<<2'." Applying A's
        // rule to B here would produce 1<<2 and quietly corrupt every blit that
        // preloads BLTBDAT.
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, B_CONSTANT);
        fixture.set(reg::BLTCON1, (4 << 12) | DESC);
        fixture.set(reg::BLTBDAT, 1);
        fixture.set(reg::BLTCON1, (2 << 12) | DESC);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![1 << 4]);
        assert_ne!(fixture.ram.peek(0x1100, 1), vec![1 << 2]);
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            BlitObservation::ImmediateDataShiftChanged {
                loaded_shift: 4,
                shift: 2,
                ..
            }
        )));
    }

    #[test]
    fn a_second_bltbdat_write_shifts_against_the_first() {
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, B_CONSTANT);
        fixture.set(reg::BLTCON1, 8 << 12);
        fixture.set(reg::BLTBDAT, 0xaaaa);
        fixture.set(reg::BLTBDAT, 0xbbbb);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(1, 1));
        // (0xaaaa_bbbb >> 8), because the previous *written* word is what the
        // second load shifts against.
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0xaabb]);
    }

    #[test]
    fn an_unchanged_shift_after_a_bltbdat_write_raises_nothing() {
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, B_CONSTANT);
        fixture.set(reg::BLTCON1, 4 << 12);
        fixture.set(reg::BLTBDAT, 0xf000);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x0f00]);
        assert!(!outcome.observations.iter().any(|observation| matches!(
            observation,
            BlitObservation::ImmediateDataShiftChanged { .. }
        )));
    }

    #[test]
    fn changing_only_the_direction_after_a_load_is_reported_too() {
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, B_CONSTANT);
        fixture.set(reg::BLTCON1, 4 << 12);
        fixture.set(reg::BLTBDAT, 0xf000);
        fixture.set(reg::BLTCON1, (4 << 12) | DESC);
        fixture.point(reg::BLTDPTH, 0x1102);

        let outcome = fixture.blit(size_of(1, 1));
        // The hold was computed ascending and is used unchanged.
        assert_eq!(fixture.ram.peek(0x1102, 1), vec![0x0f00]);
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            BlitObservation::ImmediateDataShiftChanged {
                loaded_descending: false,
                descending: true,
                ..
            }
        )));
    }

    #[test]
    fn the_b_hold_survives_into_a_second_blit_while_the_latches_reset() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0xaaaa, 0xbbbb]);
        fixture.set(reg::BLTCON0, B_CONSTANT);
        fixture.set(reg::BLTCON1, 8 << 12);
        fixture.set(reg::BLTBDAT, 0x1234);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x0012]);

        // A second blit with nothing reloaded reuses the same hold, because
        // b_hold is deliberately not reset at blit start.
        fixture.point(reg::BLTDPTH, 0x1110);
        fixture.blit_ok(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1110, 1), vec![0x0012]);
    }

    #[test]
    fn the_a_latch_does_reset_between_blits() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0xaaaa]);
        fixture.ram.poke(0x1010, &[0xbbbb]);
        fixture.set(reg::BLTCON0, COPY_A | (4 << 12));
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.blit_ok(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x0aaa]);

        fixture.point(reg::BLTAPTH, 0x1010);
        fixture.point(reg::BLTDPTH, 0x1110);
        fixture.blit_ok(size_of(1, 1));
        // Against the reset latch, not against 0xaaaa: 0x0bbb, not 0xabbb.
        assert_eq!(fixture.ram.peek(0x1110, 1), vec![0x0bbb]);
    }

    #[test]
    fn an_enabled_b_channel_recomputes_its_hold_on_every_fetch() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1111, 0x2222]);
        fixture.set(reg::BLTCON0, COPY_B);
        fixture.set(reg::BLTCON1, 4 << 12);
        fixture.point(reg::BLTBPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(2, 1));
        assert_eq!(fixture.ram.peek(0x1100, 2), vec![0x0111, 0x1222]);
    }

    // ---------------------------------------------------------------- modulos

    #[test]
    fn each_channels_modulo_is_applied_independently_after_every_row() {
        let mut fixture = Fixture::new();
        fixture
            .ram
            .poke(0x1000, &[0x0001, 0x0002, 0xdead, 0xbeef, 0x0003, 0x0004]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.set(reg::BLTAMOD, 4); // skip two words between rows
        fixture.set(reg::BLTDMOD, 0);

        fixture.blit_ok(size_of(2, 2));
        assert_eq!(
            fixture.ram.peek(0x1100, 4),
            vec![0x0001, 0x0002, 0x0003, 0x0004]
        );
    }

    #[test]
    fn a_negative_modulo_walks_the_source_backwards_a_row_at_a_time() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0003, 0x0004, 0x0001, 0x0002]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1004);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.set(reg::BLTAMOD, 0xfff8_u32 as u16); // -8
        fixture.set(reg::BLTDMOD, 0);

        fixture.blit_ok(size_of(2, 2));
        assert_eq!(
            fixture.ram.peek(0x1100, 4),
            vec![0x0001, 0x0002, 0x0003, 0x0004]
        );
        assert_eq!(fixture.blitter.read_register(reg::BLTAMOD), Some(0xfff8));
    }

    #[test]
    fn the_low_bit_of_a_modulo_and_of_a_pointer_is_ignored() {
        let mut fixture = Fixture::new();
        fixture
            .ram
            .poke(0x1000, &[0x0001, 0x0002, 0xdead, 0xbeef, 0x0003, 0x0004]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        // An odd pointer and an odd modulo: both low bits are dropped, so this
        // is the same blit as the even-valued one above.
        fixture.set(reg::BLTAPTH, 0x0000);
        fixture.set(reg::BLTAPTL, 0x1001);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.set(reg::BLTAMOD, 5);
        fixture.set(reg::BLTDMOD, 0);

        fixture.blit_ok(size_of(2, 2));
        assert_eq!(
            fixture.ram.peek(0x1100, 4),
            vec![0x0001, 0x0002, 0x0003, 0x0004]
        );
        // Four words read, plus the modulo after each of the two rows — the
        // last row's included, which is what leaves the pointer ready for the
        // next blit.
        assert_eq!(fixture.blitter.read_register(reg::BLTAPTL), Some(0x1010));
        assert_eq!(fixture.blitter.read_register(reg::BLTAMOD), Some(4));
    }

    // -------------------------------------------------------- arithmetic edges

    #[test]
    fn a_pointer_that_leaves_the_address_space_is_its_own_refusal() {
        for (descending, pointer) in [(false, 0xffff_fffe_u32), (true, 0x0000_0000)] {
            let mut blitter = Blitter::new(Chipset::Ocs);
            plain(&mut blitter, reg::BLTCON0, COPY_A);
            plain(
                &mut blitter,
                reg::BLTCON1,
                if descending { DESC } else { 0 },
            );
            plain(&mut blitter, reg::BLTAPTH, (pointer >> 16) as u16);
            plain(&mut blitter, reg::BLTAPTL, pointer as u16);
            plain(&mut blitter, reg::BLTDPTH, 0);
            plain(&mut blitter, reg::BLTDPTL, 0x100);
            let start = blitter
                .write_register(reg::BLTSIZE, size_of(2, 1))
                .start
                .expect("a blit");

            let outcome = blitter.execute(start, &mut BoundlessRam, conditions());
            assert_eq!(
                outcome.refused,
                Some(BlitRefusal::AddressOverflow {
                    channel: Channel::A,
                    at: pointer,
                }),
                "descending={descending}"
            );
        }
    }

    #[test]
    fn a_modulo_that_leaves_the_address_space_is_refused_too() {
        let mut blitter = Blitter::new(Chipset::Ocs);
        plain(&mut blitter, reg::BLTCON0, COPY_A);
        plain(&mut blitter, reg::BLTCON1, 0);
        plain(&mut blitter, reg::BLTAPTH, 0xffff);
        plain(&mut blitter, reg::BLTAPTL, 0xfffc);
        plain(&mut blitter, reg::BLTAMOD, 2);
        plain(&mut blitter, reg::BLTDPTH, 0);
        plain(&mut blitter, reg::BLTDPTL, 0x100);
        let start = blitter
            .write_register(reg::BLTSIZE, size_of(1, 2))
            .start
            .expect("a blit");

        let outcome = blitter.execute(start, &mut BoundlessRam, conditions());
        assert_eq!(
            outcome.refused,
            Some(BlitRefusal::AddressOverflow {
                channel: Channel::A,
                at: 0xffff_fffe,
            })
        );
    }

    // ------------------------------------------------------------------- fill

    #[test]
    fn inclusive_fill_keeps_both_borders_and_exclusive_deletes_the_left() {
        for (control, expected) in [(IFE, 0x001f_u16), (EFE, 0x000f)] {
            let mut fixture = Fixture::new();
            fixture.ram.poke(0x1000, &[0x0011]);
            fixture.set(reg::BLTCON0, COPY_A);
            fixture.set(reg::BLTCON1, control | DESC);
            fixture.open_masks();
            fixture.point(reg::BLTAPTH, 0x1000);
            fixture.point(reg::BLTDPTH, 0x1100);

            fixture.blit_ok(size_of(1, 1));
            assert_eq!(fixture.ram.peek(0x1100, 1), vec![expected]);
        }
    }

    #[test]
    fn the_fill_carry_starts_from_fci_and_resets_every_row() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0011]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, IFE | FCI | DESC);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.blit_ok(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0xfff1]);

        // A carry that leaked between rows would fill row 1 solid. Descending,
        // so the rows walk downwards: row 0 reads 0x1010, row 1 reads 0x100e.
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x100e, &[0x0000, 0x0001]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, IFE | DESC);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1010);
        fixture.point(reg::BLTDPTH, 0x1110);
        fixture.blit_ok(size_of(1, 2));
        // Row 0's odd bit count leaves the carry set; row 1 must start from FCI
        // again, so it stays empty instead of filling solid.
        assert_eq!(fixture.ram.peek(0x110e, 2), vec![0x0000, 0xffff]);
    }

    #[test]
    fn both_fill_modes_let_exclusive_win_and_say_so() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0011]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, IFE | EFE | DESC);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x000f], "exclusive wins");
        assert!(
            outcome
                .observations
                .contains(&BlitObservation::BothFillModes)
        );
    }

    #[test]
    fn a_fill_without_descending_is_performed_and_observed() {
        // The manual says area fill only works correctly descending. The
        // hardware still runs it, so this does too: refusing would reject a blit
        // real hardware performs, and silence would hide the one fact that
        // explains the output.
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0011]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, IFE);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(outcome.refused, None);
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x001f]);
        assert!(
            outcome
                .observations
                .contains(&BlitObservation::FillWithoutDescending)
        );
    }

    // ------------------------------------------------------------------ sizes

    #[test]
    fn a_zero_size_field_means_the_maximum() {
        assert_eq!(OcsBlitSize::decode(0x0040).width(), 64, "width 0 means 64");
        assert_eq!(OcsBlitSize::decode(0x0040).height(), 1);
        assert_eq!(
            OcsBlitSize::decode(0x0001).height(),
            1024,
            "height 0 means 1024"
        );
        assert_eq!(OcsBlitSize::decode(0x0001).width(), 1);
        assert_eq!(
            OcsBlitSize::decode(0x0000).datapath_words(),
            65_536,
            "the largest blit the hardware can perform"
        );
    }

    // ------------------------------------------------------------------- zero

    #[test]
    fn bzero_is_set_only_when_every_word_was_zero() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0000, 0x0001]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        assert_eq!(fixture.blit(size_of(2, 1)).zero, Some(false));

        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        assert_eq!(fixture.blit(size_of(1, 1)).zero, Some(true));
    }

    #[test]
    fn bzero_is_computed_even_with_the_destination_off() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0000, 0x0000]);
        fixture.set(reg::BLTCON0, USEA | 0xf0); // no USED
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);

        let outcome = fixture.blit(size_of(2, 1));
        assert_eq!(outcome.words_written, 0);
        assert_eq!(outcome.zero, Some(true));
        assert_eq!(fixture.blitter.zero(), Some(true));
    }

    // -------------------------------------------------------------- preflight

    #[test]
    fn each_channel_that_would_leave_the_map_is_refused_by_name() {
        for (channel, pointer_register) in [
            (Channel::A, reg::BLTAPTH),
            (Channel::B, reg::BLTBPTH),
            (Channel::C, reg::BLTCPTH),
            (Channel::D, reg::BLTDPTH),
        ] {
            let mut fixture = Fixture::new();
            fixture.set(reg::BLTCON0, USEA | USEB | USEC | USED | 0xf0);
            fixture.set(reg::BLTCON1, 0);
            fixture.open_masks();
            for register in [reg::BLTAPTH, reg::BLTBPTH, reg::BLTCPTH, reg::BLTDPTH] {
                fixture.point(register, 0x1000);
            }
            fixture.point(pointer_register, 0x9000);

            let outcome = fixture.blit(size_of(1, 1));
            assert_eq!(
                outcome.refused,
                Some(BlitRefusal::Unmapped {
                    channel,
                    address: 0x9000,
                })
            );
            assert!(
                fixture.ram.log.is_empty(),
                "a refused blit touches no memory"
            );
        }
    }

    #[test]
    fn a_disabled_channels_stale_pointer_does_not_refuse_the_blit() {
        // A recipe with a stale BLTBPT and USEB clear is an ordinary recipe. A
        // disabled channel's pointer is never dereferenced, so it is never
        // checked either.
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x4321]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.point(reg::BLTBPTH, 0xdead_0000);
        fixture.point(reg::BLTCPTH, 0xbeef_0000);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(outcome.refused, None);
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x4321]);
    }

    // -------------------------------------------------------- refusal freezes

    #[test]
    fn a_refused_blit_leaves_the_next_one_exactly_as_it_would_have_been() {
        // A refusal is a blit that did not happen, and a blit that did not
        // happen cannot have advanced a pointer or disturbed a latch.
        let run_alone = || {
            let mut fixture = Fixture::new();
            fixture.ram.poke(0x1000, &[0x1111, 0x2222]);
            fixture.set(reg::BLTCON0, COPY_A | (4 << 12));
            fixture.set(reg::BLTCON1, 0);
            fixture.open_masks();
            fixture.set(reg::BLTBDAT, 0x00f0);
            fixture.point(reg::BLTAPTH, 0x1000);
            fixture.point(reg::BLTDPTH, 0x1100);
            let outcome = fixture.blit(size_of(2, 1));
            (
                fixture.ram.peek(0x1100, 2),
                outcome,
                fixture.blitter.pointers(),
            )
        };

        let (expected_bytes, expected_outcome, expected_pointers) = run_alone();

        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1111, 0x2222]);
        fixture.set(reg::BLTCON0, COPY_A | (4 << 12));
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.set(reg::BLTBDAT, 0x00f0);
        fixture.point(reg::BLTAPTH, 0x1000);
        // A destination off the map: refused before anything is written.
        fixture.point(reg::BLTDPTH, 0x9000);
        let before = fixture.blitter.pointers();
        let refused = fixture.blit(size_of(2, 1));
        assert!(refused.refused.is_some());
        assert_eq!(
            fixture.blitter.pointers(),
            before,
            "a refusal freezes the pointers"
        );
        assert_eq!(refused.final_pointers, refused.initial_pointers);
        assert_eq!(fixture.blitter.zero(), None, "and leaves BZERO alone");

        // Now the blit that should behave as if the first had never happened.
        fixture.point(reg::BLTDPTH, 0x1100);
        let outcome = fixture.blit(size_of(2, 1));
        assert_eq!(fixture.ram.peek(0x1100, 2), expected_bytes);
        assert_eq!(outcome.words_written, expected_outcome.words_written);
        assert_eq!(outcome.zero, expected_outcome.zero);
        assert_eq!(fixture.blitter.pointers(), expected_pointers);
    }

    // --------------------------------------------------------------- pointers

    #[test]
    fn the_final_pointers_are_reported_and_a_second_blit_continues_from_them() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x0001, 0x0002, 0x0003, 0x0004]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        fixture.set(reg::BLTAMOD, 0);
        fixture.set(reg::BLTDMOD, 0);

        let first = fixture.blit(size_of(2, 1));
        assert_eq!(first.initial_pointers.a, 0x1000);
        assert_eq!(first.final_pointers.a, 0x1004);
        assert_eq!(first.final_pointers.d, 0x1104);
        assert_eq!(
            fixture.blitter.read_register(reg::BLTAPTL),
            Some(0x1004),
            "the CPU reads back the advanced pointer"
        );

        let second = fixture.blit(size_of(2, 1));
        assert_eq!(second.initial_pointers.a, 0x1004);
        assert_eq!(
            fixture.ram.peek(0x1100, 4),
            vec![0x0001, 0x0002, 0x0003, 0x0004]
        );
    }

    // --------------------------------------------------------------- pipeline

    #[test]
    fn two_sets_of_sources_are_fetched_before_the_first_destination_is_written() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1111, 0x2222, 0x3333]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        fixture.blit_ok(size_of(3, 1));
        assert_eq!(
            fixture.ram.log,
            vec![
                Touch::Read(0x1000),
                Touch::Read(0x1002),
                Touch::Write(0x1100, 0x1111),
                Touch::Read(0x1004),
                Touch::Write(0x1102, 0x2222),
                // The one word the queue still holds, drained after the loop.
                Touch::Write(0x1104, 0x3333),
            ]
        );
    }

    #[test]
    fn an_in_place_scroll_does_not_smear_because_the_queue_delays_the_write() {
        // The shape the pipeline exists for. Writing each word immediately would
        // make every source read after the first see a word this blit had
        // already overwritten, and the row would come out solid.
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x1111, 0x2222, 0x3333, 0x4444]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1002); // one word ahead of A

        let outcome = fixture.blit(size_of(3, 1));
        assert_eq!(
            fixture.ram.peek(0x1000, 4),
            vec![0x1111, 0x1111, 0x2222, 0x3333]
        );
        assert_ne!(
            fixture.ram.peek(0x1000, 4),
            vec![0x1111, 0x1111, 0x1111, 0x1111],
            "an immediate write would smear the first word across the row"
        );
        assert!(
            outcome
                .observations
                .contains(&BlitObservation::DestinationOverlapsSource {
                    channel: Channel::A
                })
        );
    }

    #[test]
    fn an_exact_cookie_cut_overlap_works_and_is_still_observed() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0xff00]); // A: the mask
        fixture.ram.poke(0x1010, &[0x1234]); // B: the new pixels
        fixture.ram.poke(0x1020, &[0xabcd]); // C and D: the background
        fixture.set(reg::BLTCON0, USEA | USEB | USEC | USED | 0xca);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTBPTH, 0x1010);
        fixture.point(reg::BLTCPTH, 0x1020);
        fixture.point(reg::BLTDPTH, 0x1020);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(outcome.refused, None, "C == D is the cookie-cut idiom");
        assert_eq!(fixture.ram.peek(0x1020, 1), vec![0x12cd]);
        assert!(
            outcome
                .observations
                .contains(&BlitObservation::DestinationOverlapsSource {
                    channel: Channel::C
                })
        );
    }

    // ---------------------------------------------------------------- chipset

    #[test]
    fn an_ecs_register_write_changes_no_state_and_is_reported() {
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, 0x09f0);

        for register in [reg::BLTCON0L, reg::BLTSIZV, reg::BLTSIZH] {
            let outcome = fixture.blitter.write_register(register, 0xffff);
            assert!(
                outcome.start.is_none(),
                "{register:#05x} starts nothing on OCS"
            );
            assert_eq!(
                outcome.observations,
                vec![BlitObservation::EcsRegisterWritten {
                    register,
                    chipset: Chipset::Ocs,
                }]
            );
            assert_eq!(
                fixture.blitter.read_register(register),
                None,
                "{register:#05x} is not a register on OCS"
            );
        }
        assert_eq!(
            fixture.blitter.read_register(reg::BLTCON0),
            Some(0x09f0),
            "BLTCON0L must not have patched the minterm"
        );
    }

    #[test]
    fn doff_is_a_reserved_bit_on_ocs_and_the_destination_is_still_written() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x4321]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, DOFF);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x4321]);
        assert!(
            outcome
                .observations
                .contains(&BlitObservation::ReservedControlBit {
                    register: reg::BLTCON1,
                    bit: 7,
                })
        );
    }

    #[test]
    fn the_blitter_claims_its_whole_register_span() {
        assert!(is_blitter_register(0x040));
        assert!(is_blitter_register(0x05a), "observed, though not modelled");
        assert!(is_blitter_register(0x074));
        assert!(!is_blitter_register(0x03e));
        assert!(!is_blitter_register(0x076));
        assert!(!is_blitter_register(0x041), "registers are word-aligned");
    }

    // --------------------------------------------------------------- refusals

    #[test]
    fn line_mode_refuses_writes_nothing_and_names_itself() {
        let mut fixture = Fixture::new();
        fixture.ram.poke(0x1000, &[0x4321]);
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, LINE);
        fixture.open_masks();
        fixture.point(reg::BLTAPTH, 0x1000);
        fixture.point(reg::BLTDPTH, 0x1100);
        let before = fixture.blitter.pointers();

        let outcome = fixture.blit(size_of(1, 1));
        assert_eq!(outcome.refused, Some(BlitRefusal::LineMode));
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x0000]);
        assert!(fixture.ram.log.is_empty());
        assert_eq!(fixture.blitter.pointers(), before);
    }

    #[test]
    fn dma_off_is_assumed_by_default_and_required_on_request() {
        let build = || {
            let mut fixture = Fixture::new();
            fixture.ram.poke(0x1000, &[0x4321]);
            fixture.set(reg::BLTCON0, COPY_A);
            fixture.set(reg::BLTCON1, 0);
            fixture.open_masks();
            fixture.point(reg::BLTAPTH, 0x1000);
            fixture.point(reg::BLTDPTH, 0x1100);
            fixture
        };

        let mut fixture = build();
        let outcome = fixture.blit_under(
            size_of(1, 1),
            BlitConditions {
                dma_enabled: false,
                dma: DmaPolicy::AssumeEnabled,
                word_budget: u64::MAX,
            },
        );
        assert_eq!(outcome.refused, None);
        assert!(outcome.dma_assumed);
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x4321]);

        let mut fixture = build();
        let outcome = fixture.blit_under(
            size_of(1, 1),
            BlitConditions {
                dma_enabled: false,
                dma: DmaPolicy::RequireEnabled,
                word_budget: u64::MAX,
            },
        );
        assert_eq!(outcome.refused, Some(BlitRefusal::DmaDisabled));
        assert!(!outcome.dma_assumed);
        assert_eq!(fixture.ram.peek(0x1100, 1), vec![0x0000]);
    }

    #[test]
    fn a_blit_over_budget_is_refused_before_any_address_is_generated() {
        let mut fixture = Fixture::new();
        fixture.set(reg::BLTCON0, COPY_A);
        fixture.set(reg::BLTCON1, 0);
        fixture.open_masks();
        // Pointers nowhere near the map: if the preflight had run, it would have
        // refused with Unmapped instead, which is how this asserts the order.
        fixture.point(reg::BLTAPTH, 0x9000);
        fixture.point(reg::BLTDPTH, 0x9100);

        let outcome = fixture.blit_under(
            size_of(4, 4),
            BlitConditions {
                dma_enabled: true,
                dma: DmaPolicy::AssumeEnabled,
                word_budget: 15,
            },
        );
        assert_eq!(
            outcome.refused,
            Some(BlitRefusal::BudgetExceeded {
                requested: 16,
                remaining: 15,
            })
        );
        assert_eq!(
            outcome.datapath_words, 16,
            "the caller charges what the blit would have cost, refused or not"
        );
    }

    // ------------------------------------------------------------- primitives

    #[test]
    fn the_shifter_reduces_to_the_current_word_at_shift_zero_either_way() {
        assert_eq!(shift_word(0xaaaa, 0x1234, 0, false), 0x1234);
        assert_eq!(shift_word(0xaaaa, 0x1234, 0, true), 0x1234);
    }

    #[test]
    fn fill_is_what_the_manual_describes() {
        assert_eq!(fill(0x0011, false, false), (0x001f, false));
        assert_eq!(fill(0x0011, false, true), (0x000f, false));
        // An odd number of set bits leaves the carry set for the next word.
        assert_eq!(fill(0x0001, false, false), (0xffff, true));
    }
}
