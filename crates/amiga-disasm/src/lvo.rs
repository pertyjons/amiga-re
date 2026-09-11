//! AmigaOS library-call (LVO) recognition for annotating disassembly.
//!
//! AmigaOS library functions are called as `JSR (offset, A6)` where `A6` holds
//! the library base and `offset` is a negative library-vector offset (LVO).
//! This detects that call form and names common vectors from a curated,
//! high-confidence subset of the exec, dos, graphics, and intuition tables,
//! checked against the Exec, DOS, Graphics and Intuition FD files in
//! [NDK 3.2 R4](https://aminet.net/package/dev/misc/NDK3.2).
//! These are classic m68k vector assignments; some entries require later OS
//! versions (for example, `ZipWindow` requires V36). The table does not assert
//! availability on a particular ROM. See `docs/hardware-and-abi-references.md`
//! for the exact source hashes and comparison results.
//! [`infer_libraries`] additionally follows the conventional ExecBase-at-4 and
//! `OpenLibrary` result flow through address registers and memory slots.

use std::collections::{BTreeMap, BTreeSet};

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Operands, Size};
use m68000::isa::Isa;

use crate::control_flow::{
    ControlFlowAnalysis, DecodedInstruction, FlowKind, FlowOptions, Rebase, UnresolvedFlow,
    analyze_entries_with,
};
use crate::globals::sign_extend_word;

/// The longest open-name accepted for an [`Library::Other`] identity.
const MAX_LIBRARY_NAME: usize = 64;

/// A library identity: one of the four with built-in curated LVO tables, or
/// any other library/device known by its open-name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Library {
    Exec,
    Dos,
    Graphics,
    Intuition,
    /// Any other library or device, identified by the open-name a program
    /// passes to `OpenLibrary`/`OpenDevice` (e.g. `mathffp.library`). Named
    /// only through config-supplied fd tables.
    Other(String),
}

impl Library {
    /// Parse a library name such as `"exec"`, `"dos.library"`, or — for any
    /// other identity — a plausible open-name ending in `.library` or
    /// `.device` (printable ASCII, non-empty stem, at most 64 bytes).
    ///
    /// Names are normalized to ASCII lowercase, so a config-supplied identity
    /// always matches the same name found in a binary regardless of case.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let normalized = name.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "exec" | "exec.library" => Some(Self::Exec),
            "dos" | "dos.library" => Some(Self::Dos),
            "graphics" | "graphics.library" => Some(Self::Graphics),
            "intuition" | "intuition.library" => Some(Self::Intuition),
            _ => {
                let stem = normalized
                    .strip_suffix(".library")
                    .or_else(|| normalized.strip_suffix(".device"))?;
                let valid = !stem.is_empty()
                    && normalized.len() <= MAX_LIBRARY_NAME
                    && normalized
                        .chars()
                        .all(|character| character.is_ascii_graphic());
                valid.then(|| Self::Other(normalized.clone()))
            }
        }
    }

    /// The full library name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Exec => "exec.library",
            Self::Dos => "dos.library",
            Self::Graphics => "graphics.library",
            Self::Intuition => "intuition.library",
            Self::Other(name) => name,
        }
    }
}

/// A detected library call: `JSR`/`JMP (offset, An)` with a negative offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibraryCall {
    /// The base register (6 for the usual `A6`).
    pub register: u8,
    /// The negative library-vector offset.
    pub offset: i16,
}

/// The AmigaOS library-call operand form: `(d16,A6)` with a negative
/// displacement. The ABI requires the library base in A6 at the call, so a
/// negative displacement off any other address register (a jump table, a
/// stack trampoline) is not convention-explained.
#[must_use]
pub fn is_library_call_mode(mode: AddressingMode) -> bool {
    matches!(mode, AddressingMode::Ariwd(6, displacement) if displacement < 0)
}

/// Recognize an instruction as an AmigaOS library call.
#[must_use]
pub fn library_call(decoded: &DecodedInstruction) -> Option<LibraryCall> {
    if !matches!(Isa::from(decoded.instruction.opcode), Isa::Jsr | Isa::Jmp) {
        return None;
    }
    match decoded.instruction.operands {
        Operands::EffectiveAddress(mode @ AddressingMode::Ariwd(register, offset))
            if is_library_call_mode(mode) =>
        {
            Some(LibraryCall { register, offset })
        }
        _ => None,
    }
}

/// Name the LVO at `offset` in `library` from the curated built-in tables,
/// if known. [`Library::Other`] identities have no built-in table.
#[must_use]
pub fn lvo_name(library: &Library, offset: i16) -> Option<&'static str> {
    match library {
        Library::Exec => exec_lvo(offset),
        Library::Dos => dos_lvo(offset),
        Library::Graphics => graphics_lvo(offset),
        Library::Intuition => intuition_lvo(offset),
        Library::Other(_) => None,
    }
}

fn graphics_lvo(offset: i16) -> Option<&'static str> {
    let name = match offset {
        -30 => "BltBitMap",
        -36 => "BltTemplate",
        -42 => "ClearEOL",
        -48 => "ClearScreen",
        -54 => "TextLength",
        -60 => "Text",
        -66 => "SetFont",
        -72 => "OpenFont",
        -78 => "CloseFont",
        -84 => "AskSoftStyle",
        -90 => "SetSoftStyle",
        -96 => "AddBob",
        -102 => "AddVSprite",
        -192 => "LoadRGB4",
        -198 => "InitRastPort",
        -204 => "InitVPort",
        -210 => "MrgCop",
        -216 => "MakeVPort",
        -222 => "LoadView",
        -228 => "WaitBlit",
        -234 => "SetRast",
        -240 => "Move",
        -246 => "Draw",
        -252 => "AreaMove",
        -258 => "AreaDraw",
        -264 => "AreaEnd",
        -270 => "WaitTOF",
        -276 => "QBlit",
        -282 => "InitArea",
        -288 => "SetRGB4",
        -294 => "QBSBlit",
        -300 => "BltClear",
        -306 => "RectFill",
        -312 => "BltPattern",
        -318 => "ReadPixel",
        -324 => "WritePixel",
        -330 => "Flood",
        -336 => "PolyDraw",
        -342 => "SetAPen",
        -348 => "SetBPen",
        -354 => "SetDrMd",
        -360 => "InitView",
        -366 => "CBump",
        -372 => "CMove",
        -378 => "CWait",
        -384 => "VBeamPos",
        -390 => "InitBitMap",
        -396 => "ScrollRaster",
        -402 => "WaitBOVP",
        -408 => "GetSprite",
        -414 => "FreeSprite",
        -420 => "ChangeSprite",
        -426 => "MoveSprite",
        -456 => "OwnBlitter",
        -462 => "DisownBlitter",
        -492 => "AllocRaster",
        -498 => "FreeRaster",
        -552 => "ClipBlit",
        -570 => "GetColorMap",
        -576 => "FreeColorMap",
        -582 => "GetRGB4",
        _ => return None,
    };
    Some(name)
}

fn intuition_lvo(offset: i16) -> Option<&'static str> {
    let name = match offset {
        -30 => "OpenIntuition",
        -42 => "AddGadget",
        -54 => "ClearMenuStrip",
        -60 => "ClearPointer",
        -66 => "CloseScreen",
        -72 => "CloseWindow",
        -78 => "CloseWorkBench",
        -84 => "CurrentTime",
        -90 => "DisplayAlert",
        -96 => "DisplayBeep",
        -102 => "DoubleClick",
        -108 => "DrawBorder",
        -114 => "DrawImage",
        -120 => "EndRequest",
        -126 => "GetDefPrefs",
        -132 => "GetPrefs",
        -138 => "InitRequester",
        -144 => "ItemAddress",
        -150 => "ModifyIDCMP",
        -156 => "ModifyProp",
        -162 => "MoveScreen",
        -168 => "MoveWindow",
        -174 => "OffGadget",
        -180 => "OffMenu",
        -186 => "OnGadget",
        -192 => "OnMenu",
        -198 => "OpenScreen",
        -204 => "OpenWindow",
        -210 => "OpenWorkBench",
        -216 => "PrintIText",
        -222 => "RefreshGadgets",
        -228 => "RemoveGadget",
        -234 => "ReportMouse",
        -240 => "Request",
        -246 => "ScreenToBack",
        -252 => "ScreenToFront",
        -258 => "SetDMRequest",
        -264 => "SetMenuStrip",
        -270 => "SetPointer",
        -276 => "SetWindowTitles",
        -282 => "ShowTitle",
        -288 => "SizeWindow",
        -294 => "ViewAddress",
        -300 => "ViewPortAddress",
        -306 => "WindowToBack",
        -312 => "WindowToFront",
        -318 => "WindowLimits",
        -324 => "SetPrefs",
        -330 => "IntuiTextLength",
        -336 => "WBenchToBack",
        -342 => "WBenchToFront",
        -348 => "AutoRequest",
        -354 => "BeginRefresh",
        -366 => "EndRefresh",
        -378 => "MakeScreen",
        -384 => "RemakeDisplay",
        -390 => "RethinkDisplay",
        -396 => "AllocRemember",
        -408 => "FreeRemember",
        -414 => "LockIBase",
        -420 => "UnlockIBase",
        -426 => "GetScreenData",
        -432 => "RefreshGList",
        -438 => "AddGList",
        -444 => "RemoveGList",
        -450 => "ActivateWindow",
        -462 => "ActivateGadget",
        -504 => "ZipWindow",
        _ => return None,
    };
    Some(name)
}

/// How many establishing sites a tracked base keeps. Once the cap is reached
/// the earliest sites are kept — they contain the base's origin.
const MAX_CHAIN: usize = 8;

/// A tracked library value and the instruction sites that established it, in
/// dataflow order.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Tracked {
    library: Library,
    chain: Vec<u32>,
}

impl Tracked {
    fn new(library: Library, site: u32) -> Self {
        Self {
            library,
            chain: vec![site],
        }
    }

    /// The value after flowing through another instruction: same library,
    /// chain extended by that site (bounded by [`MAX_CHAIN`]).
    fn through(&self, site: u32) -> Self {
        let mut chain = self.chain.clone();
        if chain.len() < MAX_CHAIN {
            chain.push(site);
        }
        Self {
            library: self.library.clone(),
            chain,
        }
    }
}

/// A memory slot whose address does not depend on where control came from.
///
/// The two shapes a program keeps a library base in: an absolute address, and a
/// displacement off a small-data base register. Both are recorded so a base a
/// program establishes once at startup can be recognized at a call site in a
/// function the startup never reaches — which is where nearly every "unknown
/// base" came from, since the per-function pass starts each function knowing
/// nothing.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GlobalSlot {
    Absolute(u32),
    BaseRelative(u8, i16),
}

impl GlobalSlot {
    /// The slot `mode` names, or `None` when it is not one address for the whole
    /// program.
    ///
    /// Only A2 through A5 qualify as a base, and each of them only while the
    /// program never re-points it. The excluded three are excluded for three
    /// different reasons, and each of them would otherwise be a way to be
    /// confidently wrong:
    ///
    /// - **A0 and A1** are ABI scratch. A callee may return with anything in
    ///   them, so `(20,A1)` names a different structure after every call — the
    ///   IORequest field `OpenDevice` writes is exactly this shape, and it is a
    ///   fact about one call rather than about the program.
    /// - **A6** is the library base register itself; a displacement off it is a
    ///   library vector, and it changes at every call site that uses another
    ///   library.
    /// - **A7** is the stack. A displacement off it names a different byte in
    ///   every frame.
    fn of(mode: AddressingMode) -> Option<Self> {
        match mode {
            // Absolute short is sign-extended by the 68000, so the two
            // spellings of one address normalize to the same slot rather than
            // to two that never meet.
            AddressingMode::AbsShort(address) => Some(Self::Absolute(sign_extend_word(address))),
            AddressingMode::AbsLong(address) => Some(Self::Absolute(address)),
            AddressingMode::Ariwd(register, displacement) if (2..=5).contains(&register) => {
                Some(Self::BaseRelative(register, displacement))
            }
            _ => None,
        }
    }

    /// The addressing mode that reads this slot, for seeding a walk.
    const fn mode(self) -> AddressingMode {
        match self {
            Self::Absolute(address) => AddressingMode::AbsLong(address),
            Self::BaseRelative(register, displacement) => {
                AddressingMode::Ariwd(register, displacement)
            }
        }
    }
}

/// What a caller is known to hold in an address register when it calls into a
/// function.
///
/// The program-wide question — "was this register ever re-pointed anywhere" —
/// is the wrong one, and refuses a base every real program re-points: `A5` is
/// `exec.library/Supervisor`'s `userFunction` argument register, so a program
/// that calls `Supervisor` writes an address into `A5` that is not its base and
/// re-establishes the base afterwards. The question a slot actually poses is
/// whether a re-pointing write reaches *this* read, and a call site answers it:
/// what the caller holds is what the callee is entered with.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum EntryBase {
    /// No resolved call site reaches this owner, so nothing is claimed. An
    /// entry point is this, and so is a function reached only through flow the
    /// traversal could not follow.
    #[default]
    Unseen,
    /// Every resolved call site reaching this owner holds this address.
    At(u32),
    /// The call sites disagree, or one of them arrived with a value the walk
    /// could not name. Either way a displacement off the register names
    /// whichever memory the path decided, which is not a fact about the program.
    Conflicting,
}

impl EntryBase {
    /// Fold in one more call site, which held `incoming` — `None` where the
    /// walk could not say, which is a disagreement rather than an absence.
    fn meet(self, incoming: Option<u32>) -> Self {
        match (self, incoming) {
            (Self::Conflicting, _) | (_, None) => Self::Conflicting,
            (Self::Unseen, Some(address)) => Self::At(address),
            (Self::At(held), Some(address)) if held == address => Self::At(held),
            (Self::At(_), Some(_)) => Self::Conflicting,
        }
    }

    const fn address(self) -> Option<u32> {
        match self {
            Self::At(address) => Some(address),
            Self::Unseen | Self::Conflicting => None,
        }
    }
}

/// The address registers something may leave holding a different value, as a
/// bitmask over A0–A7. `!0` is "anything might have changed".
type RegisterSet = u8;

/// Every address register, which is what a call the walk cannot follow leaves
/// unknown.
const ALL_ADDRESS_REGISTERS: RegisterSet = u8::MAX;

/// Where the program's writes leave one address register pointing.
///
/// The question a small-data base has to answer is whether a displacement off
/// the register names one piece of memory program-wide. That is decided by the
/// set of addresses it is pointed at, not by how many instructions point it:
/// a program whose second entry point re-runs the same `LEA (d16,PC),A5` has
/// not moved its base, and refusing every slot behind `A5` for that costs the
/// attribution of every call reached through it.
///
/// This stays the *fallback*. A register that names one address program-wide
/// needs no call site to vouch for it, and seeding its slots everywhere is what
/// carries a base down a call chain of any depth. [`EntryBase`] is what answers
/// for the registers this rule refuses.
#[derive(Default)]
struct BaseWrites {
    /// The distinct addresses the walk could resolve this register to.
    destinations: BTreeSet<u32>,
    /// A write whose destination the walk could not follow. One is enough to
    /// give up on the register: the same principle the sibling rule for a
    /// slot's *contents* already applies, and for the same reason — an
    /// unfollowable write may have re-pointed it anywhere.
    unfollowable: bool,
}

impl BaseWrites {
    /// Whether a displacement off this register names one piece of memory.
    fn names_one_address(&self) -> bool {
        !self.unfollowable && self.destinations.len() <= 1
    }
}

/// Each address register an instruction may leave holding something new, with
/// the address it was pointed at where the walk can say.
///
/// Only a base established from a constant is resolvable: `LEA (d16,PC),An` is
/// how a small-data base is normally set up and `MOVEA.L #addr,An` is the other
/// spelling. Everything else — including the pre/postdecrement side effects
/// [`address_registers_written`] reports — is an unfollowable write.
fn address_register_destinations(
    decoded: &DecodedInstruction,
    image_origin: Option<u32>,
) -> Vec<(u8, Option<u32>)> {
    let resolved = match decoded.instruction.operands {
        Operands::RegisterEffectiveAddress(register, source)
            if Isa::from(decoded.instruction.opcode) == Isa::Lea =>
        {
            Some((register, effective_address(source, image_origin)))
        }
        // `MOVEA.L #addr,An` only. Every other source *dereferences* — `MOVEA.L
        // $1000.L,A5` loads the longword stored at `$1000`, not `$1000` — so
        // resolving it the way `LEA` is resolved would read a runtime pointer
        // as a fixed base and accept a register the program really does
        // re-point. A word-sized MOVEA is excluded separately: it
        // sign-extends, so its immediate is not the address either.
        Operands::SizeRegisterEffectiveAddress(
            Size::Long,
            register,
            AddressingMode::Immediate(value),
        ) => Some((
            register,
            effective_address(AddressingMode::Immediate(value), image_origin),
        )),
        _ => None,
    };
    address_registers_written(decoded)
        .into_iter()
        .map(|written| match resolved {
            Some((register, address)) if register == written => (written, address),
            _ => (written, None),
        })
        .collect()
}

/// An address register changed as a side effect of evaluating an effective
/// address.
///
/// Direct `An` is only a read when it is a source. Pre-decrement and
/// post-increment change the register regardless of whether the effective
/// address supplies or receives the value.
fn effective_address_side_effect(mode: AddressingMode) -> Option<u8> {
    match mode {
        AddressingMode::Ariwpo(register) | AddressingMode::Ariwpr(register) => Some(register),
        _ => None,
    }
}

/// An address register changed by writing an effective-address destination.
fn effective_address_destination(mode: AddressingMode) -> Option<u8> {
    match mode {
        AddressingMode::Ard(register)
        | AddressingMode::Ariwpo(register)
        | AddressingMode::Ariwpr(register) => Some(register),
        _ => None,
    }
}

fn record_effective_address_side_effect(written: &mut BTreeSet<u8>, mode: AddressingMode) {
    written.extend(effective_address_side_effect(mode));
}

fn record_effective_address_destination(written: &mut BTreeSet<u8>, mode: AddressingMode) {
    written.extend(effective_address_destination(mode));
}

/// The address registers an instruction may leave holding something new.
///
/// The operand enum reuses bare `u8` fields for data and address registers and
/// [`AddressingMode`] for both sources and destinations. This match therefore
/// stays exhaustive over [`Operands`] but also consults the instruction and
/// operand direction: treating every numbered register or direct `An` as a
/// write makes `SWAP D5` and `MOVE.L A5,(addr).L` falsely clobber A5.
fn address_registers_written(decoded: &DecodedInstruction) -> Vec<u8> {
    if decoded.is_opaque_fallthrough() {
        return decoded
            .movec_destination()
            .and_then(|(address, register)| address.then_some(register))
            .into_iter()
            .collect();
    }
    let isa = Isa::from(decoded.instruction.opcode);
    let mut written = BTreeSet::new();
    match decoded.instruction.operands {
        Operands::SizeEffectiveAddressImmediate(_, mode, _) => {
            if isa == Isa::Cmpi {
                record_effective_address_side_effect(&mut written, mode);
            } else {
                record_effective_address_destination(&mut written, mode);
            }
        }
        Operands::EffectiveAddressCount(mode, _) => {
            if isa == Isa::Btst {
                record_effective_address_side_effect(&mut written, mode);
            } else {
                record_effective_address_destination(&mut written, mode);
            }
        }
        Operands::EffectiveAddress(mode) => match isa {
            Isa::Movefsr | Isa::Nbcd | Isa::Tas => {
                record_effective_address_destination(&mut written, mode);
            }
            _ => record_effective_address_side_effect(&mut written, mode),
        },
        Operands::SizeEffectiveAddress(_, mode) => {
            if isa == Isa::Tst {
                record_effective_address_side_effect(&mut written, mode);
            } else {
                record_effective_address_destination(&mut written, mode);
            }
        }
        // CHK/DIV/MUL name a data register; LEA alone names an address
        // destination. Their effective address is a source in every case.
        Operands::RegisterEffectiveAddress(register, mode) => {
            record_effective_address_side_effect(&mut written, mode);
            if isa == Isa::Lea {
                written.insert(register);
            }
        }
        Operands::SizeRegisterEffectiveAddress(_, register, mode) => {
            record_effective_address_side_effect(&mut written, mode);
            written.insert(register);
        }
        Operands::SizeEffectiveAddressEffectiveAddress(_, destination_mode, source_mode) => {
            record_effective_address_side_effect(&mut written, source_mode);
            record_effective_address_destination(&mut written, destination_mode);
        }
        Operands::RegisterOpmodeRegister(left, direction, right) => match direction {
            Direction::ExchangeAddress => {
                written.extend([left, right]);
            }
            Direction::ExchangeDataAddress => {
                written.insert(right);
            }
            _ => {}
        },
        Operands::RegisterDisplacement(register, _) => {
            written.insert(register);
        }
        Operands::Register(register) => {
            if isa == Isa::Unlk {
                written.insert(register);
            }
        }
        Operands::DirectionRegister(direction, register) => {
            if direction == Direction::UspToRegister {
                written.insert(register);
            }
        }
        // MOVEM memory-to-register restores whatever the list names; bit 8+n is
        // An in that direction. Its memory operand may also pre-decrement or
        // post-increment its own address register in either direction.
        Operands::DirectionSizeEffectiveAddressList(direction, _, mode, list) => {
            record_effective_address_side_effect(&mut written, mode);
            if matches!(direction, Direction::MemoryToRegister) {
                written.extend(
                    (0..8u8).filter(|register| list & (1 << (8 + u16::from(*register))) != 0),
                );
            }
        }
        Operands::DataSizeEffectiveAddress(_, _, mode)
        | Operands::ConditionEffectiveAddress(_, mode)
        | Operands::DirectionEffectiveAddress(_, mode) => {
            record_effective_address_destination(&mut written, mode);
        }
        Operands::RegisterDirectionSizeEffectiveAddress(_, direction, _, mode) => {
            if direction == Direction::DstEa {
                record_effective_address_destination(&mut written, mode);
            } else {
                record_effective_address_side_effect(&mut written, mode);
            }
        }
        // ADDA/SUBA write their named An; CMPA only reads it. The effective
        // address is the source for all three.
        Operands::RegisterSizeEffectiveAddress(register, _, mode) => {
            record_effective_address_side_effect(&mut written, mode);
            if isa != Isa::Cmpa {
                written.insert(register);
            }
        }
        // The memory-to-memory forms of ABCD/ADDX/SBCD/SUBX pre-decrement two
        // address registers. Their register-to-register forms use Dn only.
        Operands::RegisterSizeModeRegister(left, _, direction, right) => {
            if direction == Direction::MemoryToMemory {
                written.extend([left, right]);
            }
        }
        // CMPM reads through and post-increments both address registers.
        Operands::RegisterSizeRegister(left, _, right) => {
            written.extend([left, right]);
        }
        // None of these can name an address register as a destination or use
        // an addressing mode with a register side effect.
        Operands::NoOperands
        | Operands::Immediate(_)
        | Operands::RegisterDirectionSizeRegisterDisplacement(..)
        | Operands::OpmodeRegister(..)
        | Operands::Vector(_)
        | Operands::ConditionRegisterDisplacement(..)
        | Operands::Displacement(_)
        | Operands::ConditionDisplacement(..)
        | Operands::RegisterData(..)
        | Operands::RotationDirectionSizeModeRegister(..) => {}
    };
    written.into_iter().collect()
}

/// Every write one walk saw into one slot.
#[derive(Default)]
struct SlotStores {
    /// Every value written to it. `None` is a write the tracker could not
    /// follow, and one of those is enough to disqualify the slot: a global that
    /// also holds something else is not a library base.
    libraries: BTreeSet<Option<Library>>,
    /// For a base-relative slot, the address the base register held at each
    /// store — `None` where the walk could not say. Empty for an absolute slot,
    /// whose address does not depend on a register.
    anchors: BTreeSet<Option<u32>>,
}

/// What one walk found: the call sites it could attribute, every write it saw
/// into a slot that names one address program-wide, and what each function was
/// entered holding.
#[derive(Default)]
struct Findings {
    candidates: BTreeMap<u32, BTreeMap<Library, Vec<u32>>>,
    stores: BTreeMap<GlobalSlot, SlotStores>,
    /// Per callee, what the resolved call sites reaching it held in each
    /// address register.
    entry_bases: BTreeMap<u32, [EntryBase; 8]>,
    /// Per function, the address bases shared by every reachable ordinary
    /// return. These are consumed by the next discovery round, never the round
    /// that produced them.
    return_bases: BTreeMap<u32, [Option<u32>; 8]>,
}

impl Findings {
    /// Note a write into `destination`, whatever it wrote, against the base
    /// addresses the walk currently knows.
    fn note(
        &mut self,
        destination: AddressingMode,
        library: Option<&Library>,
        bases: &[Option<u32>; 8],
    ) {
        let Some(slot) = GlobalSlot::of(destination) else {
            return;
        };
        let stores = self.stores.entry(slot).or_default();
        stores.libraries.insert(library.cloned());
        if let GlobalSlot::BaseRelative(register, _) = slot {
            stores.anchors.insert(bases[usize::from(register)]);
        }
    }

    /// Record what one resolved call site handed a callee.
    fn note_call(&mut self, callee: u32, bases: &[Option<u32>; 8]) {
        let entry = self.entry_bases.entry(callee).or_default();
        for (register, base) in entry.iter_mut().zip(bases) {
            *register = register.meet(*base);
        }
    }
}

#[derive(Clone, Default, PartialEq)]
struct LibraryState {
    address: [Option<Tracked>; 8],
    /// The address each address register is known to hold, where the walk could
    /// resolve it. This is not the library tracking above: it answers *which
    /// memory* a displacement off the register names, not what that memory
    /// holds.
    bases: [Option<u32>; 8],
    slots: Vec<(AddressingMode, Tracked)>,
    /// A name loaded into A1: the `OpenLibrary` argument.
    argument_name: Option<Tracked>,
    /// A name loaded into A0: the `OpenDevice` argument. A separate field
    /// because the two calls read different registers, and letting one
    /// overwrite the other would attribute a device's name to a library open.
    device_name: Option<Tracked>,
    d0_result: Option<Tracked>,
}

impl LibraryState {
    /// Merge `other` into `self` at a control-flow join, keeping only what both
    /// paths agree on. Reports whether anything changed.
    ///
    /// This is the whole point of the flow-sensitive pass: a base that only one
    /// predecessor establishes must not survive into code both reach, because
    /// the other predecessor arrives there with the register holding something
    /// else — or nothing.
    fn meet(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (slot, incoming) in self.address.iter_mut().zip(&other.address) {
            changed |= meet_tracked(slot, incoming.as_ref());
        }
        // Two paths that point a base register at different addresses leave it
        // naming neither, exactly as they leave a library base tracked by
        // neither.
        for (base, incoming) in self.bases.iter_mut().zip(&other.bases) {
            if *base != *incoming && base.is_some() {
                *base = None;
                changed = true;
            }
        }
        changed |= meet_tracked(&mut self.argument_name, other.argument_name.as_ref());
        changed |= meet_tracked(&mut self.device_name, other.device_name.as_ref());
        changed |= meet_tracked(&mut self.d0_result, other.d0_result.as_ref());

        let before = self.slots.len();
        let mut merged = Vec::with_capacity(before);
        for (mode, tracked) in std::mem::take(&mut self.slots) {
            let Some(incoming) = slot_library(&other.slots, mode) else {
                changed = true;
                continue;
            };
            let mut kept = Some(tracked);
            changed |= meet_tracked(&mut kept, Some(incoming));
            if let Some(kept) = kept {
                merged.push((mode, kept));
            }
        }
        self.slots = merged;
        changed
    }
}

/// Keep `slot` only if `incoming` agrees on the library. Reports whether the
/// stored value changed.
///
/// When both agree, the evidence chain is the lesser of the two by length then
/// contents — an arbitrary but total rule, so a join is idempotent and the
/// worklist converges instead of alternating between two equally good chains.
fn meet_tracked(slot: &mut Option<Tracked>, incoming: Option<&Tracked>) -> bool {
    let Some(current) = slot.as_ref() else {
        return false;
    };
    let Some(incoming) = incoming else {
        *slot = None;
        return true;
    };
    if current.library != incoming.library {
        *slot = None;
        return true;
    }
    let take_incoming =
        (incoming.chain.len(), &incoming.chain) < (current.chain.len(), &current.chain);
    if take_incoming {
        *slot = Some(incoming.clone());
        return true;
    }
    false
}

/// Infer the library base used at each LVO call site.
///
/// The pass is deliberately conservative: within each discovered function it
/// follows ExecBase loaded from address 4, library-name pointers loaded into
/// A1, `exec.library/OpenLibrary`, its D0 result, and copies through address
/// registers or fixed memory operands. Conflicting results from overlapping
/// function ownership are omitted; use [`infer_library_candidates`] to see
/// them. `default_a6` seeds A6 for entry conventions known by the caller (for
/// example, boot code starts with ExecBase in A6).
#[must_use]
pub fn infer_libraries(
    analysis: &ControlFlowAnalysis,
    code: &[u8],
    image_origin: Option<u32>,
    default_a6: Option<Library>,
) -> BTreeMap<u32, Library> {
    infer_library_candidates(analysis, code, image_origin, default_a6)
        .into_iter()
        .filter_map(|(site, libraries)| {
            if libraries.len() != 1 {
                return None;
            }
            Some((site, libraries.into_iter().next()?.0))
        })
        .collect()
}

/// Collect every library base inferred for each LVO call site, preserving
/// conflicts, with the instruction sites whose dataflow established each
/// candidate (in flow order; a `default_a6` seed has an empty chain).
///
/// A call site reached from several function owners can be inferred with a
/// different base per owner; unlike [`infer_libraries`], which drops such
/// sites, every candidate is reported so a caller can surface the conflict as
/// an explicit ambiguity instead of an arbitrary winner.
///
/// The pass is flow-sensitive: each owner's instructions are visited in
/// control-flow order through a bounded worklist, and a value survives a join
/// only when every predecessor reaching it agrees. A base established on a
/// path a branch skips is therefore not attributed to the site the branch
/// reaches — `TST.W D1; BEQ.S skip; <OpenLibrary into A6>; skip: JSR (-30,A6)`
/// yields no candidate for the call, not a confident wrong one.
///
/// Only intra-procedural flow is followed: a call edge is not traversed,
/// because the callee is analyzed as its own owner. A call's fall-through is,
/// and the pass makes no assumption about what the callee preserved beyond
/// what the call instruction itself clobbers.
#[must_use]
pub fn infer_library_candidates(
    analysis: &ControlFlowAnalysis,
    code: &[u8],
    image_origin: Option<u32>,
    default_a6: Option<Library>,
) -> BTreeMap<u32, BTreeMap<Library, Vec<u32>>> {
    // Bucket per owner in one pass; rescanning all instructions for every
    // function would be O(functions x instructions) on the hot path.
    let mut owners = BTreeMap::<u32, BTreeSet<u32>>::new();
    for decoded in analysis.instructions.values() {
        for &owner in &decoded.owners {
            owners.entry(owner).or_default().insert(decoded.address);
        }
    }
    // Successor edges, likewise indexed once rather than rescanned per owner.
    let mut edges = BTreeMap::<(u32, u32), BTreeSet<u32>>::new();
    for flow in &analysis.flows {
        // A call leaves this function; its fall-through edge is recorded
        // separately and is the one that continues the owner's flow.
        if flow.kind != FlowKind::Call {
            edges
                .entry((flow.owner, flow.site))
                .or_default()
                .insert(flow.target);
        }
    }

    // The address registers a displacement may safely be taken off. A
    // small-data base is established once and never moved; a register the code
    // re-points is a pointer, and a displacement off it names different memory
    // each time it is loaded.
    //
    // What decides that is *where* the writes point, not how many there are.
    // Re-establishing the same base a second time — a second entry point
    // running the same `LEA (d16,PC),A5` — is an ordinary shape, and counting
    // writes refused every slot behind that register for it.
    let mut writes: [BaseWrites; 8] = Default::default();
    for decoded in analysis.instructions.values() {
        for (register, destination) in address_register_destinations(decoded, image_origin) {
            let Some(slot) = writes.get_mut(usize::from(register)) else {
                continue;
            };
            match destination {
                Some(address) => {
                    slot.destinations.insert(address);
                }
                None => slot.unfollowable = true,
            }
        }
    }

    let callees = callees_by_site(analysis);
    let clobbered = call_clobbers(analysis, &owners, &callees);
    let walk = |globals: &[Global],
                entry_bases: &BTreeMap<u32, [EntryBase; 8]>,
                return_bases: &BTreeMap<u32, [Option<u32>; 8]>| {
        let index = WalkIndex {
            analysis,
            code,
            image_origin,
            edges: &edges,
            callees: &callees,
            clobbered: &clobbered,
            return_bases,
        };
        let mut findings = Findings::default();
        for (owner, owned) in &owners {
            let entry = entry_bases.get(owner).copied().unwrap_or_default();
            let mut seed = LibraryState {
                slots: seed_slots(globals, &entry, &writes),
                bases: entry.map(EntryBase::address),
                ..LibraryState::default()
            };
            seed.address[6] = default_a6.as_ref().map(|library| Tracked {
                library: library.clone(),
                chain: Vec::new(),
            });
            walk_owner(&index, *owner, owned, seed, &mut findings);
        }
        findings
    };

    // Discovery establishes two things a per-function pass cannot see: what the
    // program keeps in which slot, and what each function is entered holding.
    // Nothing it finds is reported — the candidates it produces are the ones a
    // per-function pass could already reach, and the reporting walk produces
    // them again from a state that knows about the globals.
    //
    // A round learns both what a caller handed a callee and what fixed bases a
    // callee established before every return. Neither result is consumed until
    // the next round: a caller cannot use a return summary that the same pass
    // has not finished computing. Iterate until both maps agree with the inputs
    // that produced them, with a hard pass bound. If a pathological call graph
    // does not converge, discard the interprocedural facts and rerun discovery
    // without them; incomplete attribution is safer than a stale summary.
    let mut entry_bases = BTreeMap::new();
    let mut return_bases = BTreeMap::new();
    let mut discovery = Findings::default();
    let mut converged = false;
    for _ in 0..MAX_DISCOVERY_ROUNDS {
        let mut next = walk(&[], &entry_bases, &return_bases);
        let next_entries = std::mem::take(&mut next.entry_bases);
        let next_returns = std::mem::take(&mut next.return_bases);
        converged = next_entries == entry_bases && next_returns == return_bases;
        entry_bases = next_entries;
        return_bases = next_returns;
        discovery = next;
        if converged {
            break;
        }
    }
    if !converged {
        entry_bases.clear();
        return_bases.clear();
        discovery = walk(&[], &entry_bases, &return_bases);
    }

    let globals: Vec<Global> = discovery
        .stores
        .into_iter()
        .filter_map(|(slot, stored)| {
            // One library, written by every store the tracker saw, and never a
            // value it could not follow. A slot the program also uses for
            // something else is not a library base, and a slot two libraries
            // share names whichever was stored last — which is a fact about the
            // path taken, not about the program.
            let written: Vec<_> = stored.libraries.into_iter().collect();
            let [Some(library)] = written.as_slice() else {
                return None;
            };
            // A base-relative slot names one piece of memory only through the
            // address its register held; stores made through two different
            // addresses are two slots that this key merged, so the merge is
            // withdrawn rather than resolved in favour of one of them.
            let anchors: Vec<_> = stored.anchors.into_iter().collect();
            let anchor = match anchors.as_slice() {
                [Some(anchor)] => Some(*anchor),
                _ => None,
            };
            Some(Global {
                slot,
                anchor,
                tracked: Tracked {
                    library: library.clone(),
                    chain: Vec::new(),
                },
            })
        })
        .collect();

    walk(&globals, &entry_bases, &return_bases).candidates
}

/// Maximum interprocedural discovery passes before conservative fallback.
const MAX_DISCOVERY_ROUNDS: usize = 8;

/// A slot the program keeps a library base in, with the base address its
/// register held when it was written.
struct Global {
    slot: GlobalSlot,
    /// For a base-relative slot, the one address its register held at every
    /// store; `None` for an absolute slot and for stores the walk could not
    /// anchor.
    anchor: Option<u32>,
    tracked: Tracked,
}

/// The slots one owner may be seeded with.
///
/// An absolute slot names the same memory everywhere. A base-relative one needs
/// the register to name the memory the store was made through, and there are two
/// ways to know it does: the register names one address program-wide, or every
/// resolved call site reaching this function held the store's own base. The
/// first carries a base down a call chain of any depth and is what programs with
/// an ordinary small-data base rely on; the second is what answers for a
/// register the program also uses for something else.
fn seed_slots(
    globals: &[Global],
    entry: &[EntryBase; 8],
    writes: &[BaseWrites; 8],
) -> Vec<(AddressingMode, Tracked)> {
    globals
        .iter()
        .filter(|global| match global.slot {
            GlobalSlot::Absolute(_) => true,
            GlobalSlot::BaseRelative(register, _) => {
                let register = usize::from(register);
                writes
                    .get(register)
                    .is_some_and(BaseWrites::names_one_address)
                    || (global.anchor.is_some()
                        && entry.get(register).and_then(|base| base.address()) == global.anchor)
            }
        })
        .map(|global| (global.slot.mode(), global.tracked.clone()))
        .collect()
}

/// Every resolved callee of each call site, indexed once.
fn callees_by_site(analysis: &ControlFlowAnalysis) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut sites = BTreeMap::<u32, BTreeSet<u32>>::new();
    for call in &analysis.calls {
        sites.entry(call.call_site).or_default().insert(call.callee);
    }
    sites
}

/// Which address registers a call to each function may leave holding something
/// else, transitively.
///
/// This is what makes a call site's answer trustworthy. The pass is
/// intra-procedural, so a caller's own dataflow says nothing about what the
/// callee did to A5 — and a program whose helper re-establishes the base is
/// exactly the shape where assuming "nothing" is confidently wrong. A callee
/// that reaches a call the walk cannot follow may have left anything anywhere.
fn call_clobbers(
    analysis: &ControlFlowAnalysis,
    owners: &BTreeMap<u32, BTreeSet<u32>>,
    callees: &BTreeMap<u32, BTreeSet<u32>>,
) -> BTreeMap<u32, RegisterSet> {
    let mut clobbers = BTreeMap::<u32, RegisterSet>::new();
    for (owner, owned) in owners {
        let mut written: RegisterSet = 0;
        for address in owned {
            let Some(decoded) = analysis.instructions.get(address) else {
                continue;
            };
            for register in address_registers_written(decoded) {
                written |= 1 << register;
            }
            if matches!(
                call_effect(analysis, callees, decoded),
                Some(CallEffect::Opaque)
            ) {
                written = ALL_ADDRESS_REGISTERS;
            }
        }
        clobbers.insert(*owner, written);
    }

    // Union what each callee may clobber into its callers, to a fixpoint. The
    // sets only grow and there are eight bits, so it converges; the step bound
    // exists so a pathological call graph degrades into *more* clobbering —
    // fewer attributions — rather than into a hang.
    let mut budget = owners.len().saturating_mul(8).saturating_add(1);
    let mut changed = true;
    while changed && budget > 0 {
        changed = false;
        budget -= 1;
        for (owner, owned) in owners {
            let mut written = clobbers
                .get(owner)
                .copied()
                .unwrap_or(ALL_ADDRESS_REGISTERS);
            for address in owned {
                for callee in callees.get(address).into_iter().flatten() {
                    written |= clobbers
                        .get(callee)
                        .copied()
                        .unwrap_or(ALL_ADDRESS_REGISTERS);
                }
            }
            if clobbers.insert(*owner, written) != Some(written) {
                changed = true;
            }
        }
    }
    clobbers
}

/// What a call at one site does to the caller's base registers.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CallEffect {
    /// `JSR (d16,A6)`. The AmigaOS ABI preserves everything but D0/D1/A0/A1, so
    /// a base register survives — which is the same assumption that lets a
    /// tracked library base survive a library call.
    Library,
    /// A call the traversal resolved inside this image.
    Resolved,
    /// A call the walk cannot follow: an indirect call with no resolved target,
    /// one a relocation proves leaves the hunk, or a word the decoder cannot
    /// name. Nothing may be assumed about what it left behind.
    Opaque,
}

fn call_effect(
    analysis: &ControlFlowAnalysis,
    callees: &BTreeMap<u32, BTreeSet<u32>>,
    decoded: &DecodedInstruction,
) -> Option<CallEffect> {
    if analysis.library_calls.contains(&decoded.address) {
        return Some(CallEffect::Library);
    }
    if !is_subroutine_call(decoded) {
        return None;
    }
    Some(if callees.contains_key(&decoded.address) {
        CallEffect::Resolved
    } else {
        CallEffect::Opaque
    })
}

/// How many times the worklist may pop before it gives up.
///
/// The lattice only ever loses information at a join, so the fixpoint is
/// reached in a small multiple of the instruction count. The bound exists so a
/// pathological input degrades into *fewer* inferences rather than into a hang;
/// exhausting it can only leave candidates unrecorded, never invent one.
const MAX_WORKLIST_STEPS_PER_INSTRUCTION: usize = 8;

/// The whole-program inputs every owner's walk reads, indexed once.
struct WalkIndex<'a> {
    analysis: &'a ControlFlowAnalysis,
    code: &'a [u8],
    image_origin: Option<u32>,
    edges: &'a BTreeMap<(u32, u32), BTreeSet<u32>>,
    callees: &'a BTreeMap<u32, BTreeSet<u32>>,
    clobbered: &'a BTreeMap<u32, RegisterSet>,
    return_bases: &'a BTreeMap<u32, [Option<u32>; 8]>,
}

#[derive(Clone, Copy)]
enum ReturnConvention {
    Ordinary,
    Exception,
}

impl ReturnConvention {
    const fn accepts(self, isa: Isa) -> bool {
        match self {
            Self::Ordinary => matches!(isa, Isa::Rts | Isa::Rtr),
            Self::Exception => matches!(isa, Isa::Rte),
        }
    }
}

/// Run the dataflow for one function owner and record its call-site candidates.
fn walk_owner(
    index: &WalkIndex<'_>,
    owner: u32,
    owned: &BTreeSet<u32>,
    seed: LibraryState,
    findings: &mut Findings,
) {
    let returned = walk_owner_state(
        index,
        owner,
        owned,
        seed,
        findings,
        true,
        ReturnConvention::Ordinary,
    );
    let has_unresolved_exit = index
        .analysis
        .unresolved
        .iter()
        .any(|flow| flow.owner == owner);
    if !has_unresolved_exit && let Some(returned) = returned {
        findings.return_bases.insert(owner, returned.bases);
    }
}

/// Run one owner's dataflow and return the state shared by every reachable
/// return accepted by `returns`.
fn walk_owner_state(
    index: &WalkIndex<'_>,
    owner: u32,
    owned: &BTreeSet<u32>,
    seed: LibraryState,
    findings: &mut Findings,
    follow_supervisor: bool,
    returns: ReturnConvention,
) -> Option<LibraryState> {
    let analysis = index.analysis;
    let mut incoming = BTreeMap::<u32, LibraryState>::new();
    incoming.insert(owner, seed);
    // A BTreeSet worklist keeps the visit order ascending and deterministic,
    // which matters because the recorded evidence chain depends on it.
    let mut pending = BTreeSet::from([owner]);
    let budget = owned
        .len()
        .saturating_mul(MAX_WORKLIST_STEPS_PER_INSTRUCTION);
    let mut steps = 0_usize;
    let mut returned: Option<LibraryState> = None;

    while let Some(address) = pending.pop_first() {
        steps += 1;
        if steps > budget {
            return None;
        }
        let Some(decoded) = analysis.instructions.get(&address) else {
            continue;
        };
        let Some(state) = incoming.get(&address).cloned() else {
            continue;
        };
        let entering = state.bases;
        let mut out = transfer(state, decoded, index.code, index.image_origin, findings);
        apply_call_effect(
            index,
            decoded,
            &entering,
            &mut out,
            findings,
            follow_supervisor,
        );

        if returns.accepts(Isa::from(decoded.instruction.opcode)) {
            match returned.as_mut() {
                Some(existing) => {
                    existing.meet(&out);
                }
                None => returned = Some(out),
            }
            continue;
        }

        for successor in successors(analysis, decoded, owner, index.edges) {
            if !owned.contains(&successor) {
                continue;
            }
            match incoming.get_mut(&successor) {
                Some(existing) => {
                    if existing.meet(&out) {
                        pending.insert(successor);
                    }
                }
                None => {
                    incoming.insert(successor, out.clone());
                    pending.insert(successor);
                }
            }
        }
    }
    returned
}

/// Record what a call handed its callees, and forget what it may have changed.
///
/// The two halves are one instruction apart and must not be reordered: a callee
/// is entered with what the caller holds *at* the call, while the caller
/// continues with only what the callee cannot have touched.
fn apply_call_effect(
    index: &WalkIndex<'_>,
    decoded: &DecodedInstruction,
    entering: &[Option<u32>; 8],
    out: &mut LibraryState,
    findings: &mut Findings,
    follow_supervisor: bool,
) {
    match call_effect(index.analysis, index.callees, decoded) {
        None => {}
        Some(CallEffect::Library) => {
            if follow_supervisor && is_exec_supervisor(out, decoded) {
                let returned = out.bases[5]
                    .and_then(|target| supervisor_callback_exit(index, target, out.clone()));
                if let Some(returned) = returned {
                    *out = returned;
                } else {
                    forget_callback_effects(out);
                }
            }
        }
        Some(CallEffect::Opaque) => out.bases = [None; 8],
        Some(CallEffect::Resolved) => {
            let callees = index.callees.get(&decoded.address);
            for callee in callees.into_iter().flatten() {
                findings.note_call(*callee, entering);
            }
            for (register, base) in out.bases.iter_mut().enumerate() {
                let mut returned = None;
                for callee in callees.into_iter().flatten() {
                    let clobbered = index
                        .clobbered
                        .get(callee)
                        .copied()
                        .unwrap_or(ALL_ADDRESS_REGISTERS);
                    let candidate = if clobbered & (1 << register) == 0 {
                        *base
                    } else {
                        index
                            .return_bases
                            .get(callee)
                            .and_then(|bases| bases[register])
                    };
                    returned = match returned {
                        None => Some(candidate),
                        Some(current) if current == candidate => Some(current),
                        Some(_) => Some(None),
                    };
                }
                *base = returned.flatten();
            }
        }
    }
}

/// `exec.library/Supervisor`, whose `A5` argument is an in-image callback.
const SUPERVISOR_LVO: i16 = -30;

fn is_exec_supervisor(state: &LibraryState, decoded: &DecodedInstruction) -> bool {
    library_call(decoded).is_some_and(|call| call.offset == SUPERVISOR_LVO)
        && state.address[6]
            .as_ref()
            .is_some_and(|base| base.library == Library::Exec)
}

/// Analyze one statically known Supervisor callback and carry its return state
/// back to the instruction after the library call.
///
/// The callback is deliberately a nested, bounded control-flow analysis. It is
/// not added to the caller's ordinary call graph: `Supervisor` reaches it
/// through an ABI argument rather than a machine-code `JSR`, and pretending
/// otherwise would give the callback an ordinary `RTS` calling convention.
fn supervisor_callback_exit(
    parent: &WalkIndex<'_>,
    target: u32,
    seed: LibraryState,
) -> Option<LibraryState> {
    let options = FlowOptions {
        rebase: parent.image_origin.map(Rebase::new),
        relocations: None,
    };
    let analysis = analyze_entries_with(parent.code, &[target], &options);
    let owned = analysis
        .instructions
        .values()
        .filter(|decoded| decoded.owners.contains(&target))
        .map(|decoded| decoded.address)
        .collect::<BTreeSet<_>>();
    // This API receives no relocation map. Refuse ordinary direct calls rather
    // than risk following an unpatched HUNK addend as an in-image callee; the
    // callback shape needed here is self-contained.
    if owned.is_empty()
        || !analysis.calls.is_empty()
        || analysis.unresolved.iter().any(|flow| flow.owner == target)
        || owned.iter().any(|address| {
            analysis.instructions.get(address).is_some_and(|decoded| {
                let isa = Isa::from(decoded.instruction.opcode);
                crate::control_flow::is_return(isa) && isa != Isa::Rte
            })
        })
    {
        return None;
    }

    let owners = analysis
        .instructions
        .values()
        .flat_map(|decoded| {
            decoded
                .owners
                .iter()
                .map(move |owner| (*owner, decoded.address))
        })
        .fold(
            BTreeMap::<u32, BTreeSet<u32>>::new(),
            |mut owners, (owner, address)| {
                owners.entry(owner).or_default().insert(address);
                owners
            },
        );
    let mut edges = BTreeMap::<(u32, u32), BTreeSet<u32>>::new();
    for flow in &analysis.flows {
        if flow.kind != FlowKind::Call {
            edges
                .entry((flow.owner, flow.site))
                .or_default()
                .insert(flow.target);
        }
    }
    let callees = callees_by_site(&analysis);
    let clobbered = call_clobbers(&analysis, &owners, &callees);
    let return_bases = BTreeMap::new();
    let index = WalkIndex {
        analysis: &analysis,
        code: parent.code,
        image_origin: parent.image_origin,
        edges: &edges,
        callees: &callees,
        clobbered: &clobbered,
        return_bases: &return_bases,
    };
    // Callback-local calls and stores are needed to evaluate its state, but
    // they do not belong to the caller's ordinary control-flow report.
    let mut callback_findings = Findings::default();
    walk_owner_state(
        &index,
        target,
        &owned,
        seed,
        &mut callback_findings,
        false,
        ReturnConvention::Exception,
    )
}

fn forget_callback_effects(state: &mut LibraryState) {
    state.address = Default::default();
    state.bases = Default::default();
    state.slots.clear();
    state.argument_name = None;
    state.device_name = None;
    state.d0_result = None;
}

/// The instructions control can reach from `decoded` without leaving `owner`.
fn successors(
    analysis: &ControlFlowAnalysis,
    decoded: &DecodedInstruction,
    owner: u32,
    edges: &BTreeMap<(u32, u32), BTreeSet<u32>>,
) -> Vec<u32> {
    if let Some(targets) = edges.get(&(owner, decoded.address)) {
        return targets.iter().copied().collect();
    }
    // No recorded edge means the traversal did not treat this as a transfer:
    // either it fell through to the next instruction, or it stopped here. A
    // return stops; so does control flow the traversal could not resolve,
    // which must not be assumed to continue in a straight line.
    if crate::control_flow::is_return(Isa::from(decoded.instruction.opcode))
        || analysis.unresolved.contains(&UnresolvedFlow {
            owner,
            address: decoded.address,
        })
    {
        return Vec::new();
    }
    vec![decoded.end]
}

/// `exec.library/OpenLibrary`, which returns the base in D0.
const OPEN_LIBRARY_LVO: i16 = -552;
/// `exec.library/OpenDevice`, which returns an error code in D0 and writes the
/// device base into the caller's IORequest.
const OPEN_DEVICE_LVO: i16 = -444;
/// Offset of `io_Device` in `struct IORequest`: `struct Message` is 20 bytes
/// (a 14-byte `Node`, a reply port, and a length), and the device pointer is
/// the first field after it.
const IO_DEVICE_OFFSET: i16 = 20;

/// Record what `OpenDevice` established: the device base now lives in the
/// IORequest that A1 pointed at.
///
/// This is the whole difference from `OpenLibrary`. There is no value in a
/// register to follow — the base is in memory the call wrote — so what gets
/// tracked is the *slot* `io_Device(A1)`, which is exactly what the caller
/// reads back with `MOVEA.L (20,A1),A6`. Nothing else about the IORequest is
/// modelled, and the slot dies as soon as A1 changes, because after that the
/// displacement names different memory.
fn open_device(state: &mut LibraryState, site: u32, findings: &mut Findings) {
    let Some(name) = state.device_name.as_ref().map(|name| name.through(site)) else {
        return;
    };
    let destination = AddressingMode::Ariwd(1, IO_DEVICE_OFFSET);
    findings.note(destination, Some(&name.library), &state.bases);
    set_slot(&mut state.slots, destination, Some(name));
}

/// Record an open-name loaded into A0 or A1, keeping the two apart.
fn set_open_name(state: &mut LibraryState, register: u8, name: Option<Tracked>) {
    if register == 0 {
        state.device_name = name;
    } else {
        state.argument_name = name;
    }
}

/// Forget every slot read through `register`.
///
/// A slot keyed `(20,A1)` is only meaningful while A1 still points at the same
/// structure. Without this, a reloaded pointer would keep serving the previous
/// structure's contents — the one way a register-relative slot can turn a
/// conservative tracker into a confidently wrong one.
fn drop_relative_slots(slots: &mut Vec<(AddressingMode, Tracked)>, register: u8) {
    slots.retain(|(slot, _)| !reads_through(*slot, register));
}

/// Whether `mode` reaches memory through `register`.
const fn reads_through(mode: AddressingMode, register: u8) -> bool {
    match mode {
        AddressingMode::Ari(base)
        | AddressingMode::Ariwpo(base)
        | AddressingMode::Ariwpr(base)
        | AddressingMode::Ariwd(base, _)
        | AddressingMode::Ariwi8(base, _) => base == register,
        _ => false,
    }
}

/// Apply one instruction to the state, recording a candidate when it is an LVO
/// call whose base register is tracked.
fn transfer(
    mut state: LibraryState,
    decoded: &DecodedInstruction,
    code: &[u8],
    image_origin: Option<u32>,
    findings: &mut Findings,
) -> LibraryState {
    if let Some(call) = library_call(decoded) {
        if let Some(tracked) = state.address[usize::from(call.register)].clone() {
            let is_exec = tracked.library == Library::Exec;
            let is_open_library = is_exec && call.offset == OPEN_LIBRARY_LVO;
            let is_open_device = is_exec && call.offset == OPEN_DEVICE_LVO;
            findings
                .candidates
                .entry(decoded.address)
                .or_default()
                .entry(tracked.library)
                .or_insert(tracked.chain);
            // `OpenLibrary` returns the base in D0. `OpenDevice` returns an
            // error code there and writes the base into the IORequest it was
            // handed, so the two results land in entirely different places.
            state.d0_result = if is_open_library {
                state
                    .argument_name
                    .as_ref()
                    .map(|name| name.through(decoded.address))
            } else {
                None
            };
            if is_open_device {
                open_device(&mut state, decoded.address, findings);
            }
        } else {
            state.d0_result = None;
        }
        return state;
    }
    if is_subroutine_call(decoded) {
        // The AmigaOS ABI makes D0/D1/A0/A1 scratch: a callee may return with
        // anything in them, and anything read through A0/A1 afterwards is
        // other memory. A6 is preserved by convention, which is why a tracked
        // base survives a call and these do not.
        for register in [0, 1] {
            state.address[register] = None;
            set_open_name(&mut state, register as u8, None);
            drop_relative_slots(&mut state.slots, register as u8);
        }
        state.d0_result = None;
        return state;
    }
    update_library_state(&mut state, decoded, code, image_origin, findings);
    state
}

/// Whether this instruction calls a subroutine (`JSR`/`BSR`), or is a word the
/// decoder cannot name — which must invalidate the same scratch registers,
/// since nothing here can say it did not write them.
fn is_subroutine_call(decoded: &DecodedInstruction) -> bool {
    if decoded.is_opaque_fallthrough() {
        return false;
    }
    matches!(
        Isa::from(decoded.instruction.opcode),
        Isa::Jsr | Isa::Bsr | Isa::Unknown
    )
}

fn update_library_state(
    state: &mut LibraryState,
    decoded: &DecodedInstruction,
    code: &[u8],
    image_origin: Option<u32>,
    findings: &mut Findings,
) {
    let site = decoded.address;
    let isa = Isa::from(decoded.instruction.opcode);
    let operands = decoded.instruction.operands;
    // Where this instruction leaves each address register pointing, before
    // anything else is decided: a store recorded below is a store into the
    // memory the register names *now*.
    for (register, destination) in address_register_destinations(decoded, image_origin) {
        if let Some(base) = state.bases.get_mut(usize::from(register)) {
            *base = destination;
        }
    }
    match operands {
        // MOVEA <ea>,An, including the conventional MOVEA.L 4.W,A6 ExecBase load.
        Operands::SizeRegisterEffectiveAddress(_, register, source) => {
            state.address[usize::from(register)] = source_library(state, source, site);
            if register == 0 || register == 1 {
                let name = match source {
                    AddressingMode::Immediate(address) => {
                        library_name_at(code, address, image_origin)
                            .map(|library| Tracked::new(library, site))
                    }
                    _ => None,
                };
                set_open_name(state, register, name);
            }
            // A pointer register changed, so anything read through it is no
            // longer the same memory.
            drop_relative_slots(&mut state.slots, register);
        }
        // LEA name,A1 is the usual OpenLibrary argument setup.
        Operands::RegisterEffectiveAddress(register, source) if isa == Isa::Lea => {
            state.address[usize::from(register)] = None;
            if register == 0 || register == 1 {
                let name = effective_address(source, image_origin)
                    .and_then(|offset| library_name_at_offset(code, offset))
                    .map(|library| Tracked::new(library, site));
                set_open_name(state, register, name);
            }
            drop_relative_slots(&mut state.slots, register);
        }
        // MULS/MULU/DIVS/DIVU/CHK (the non-LEA RegisterEffectiveAddress
        // forms) overwrite or consume a data register.
        Operands::RegisterEffectiveAddress(register, _) => {
            invalidate_destination(state, findings, AddressingMode::Drd(register));
        }
        // A longword move preserves whatever the source was: an OpenLibrary
        // result in D0, a base already in an address register, a base already
        // in another slot — or `(4).L`, which is AbsExecBase and is how
        // essentially every Amiga program obtains exec. Anything narrower than
        // a longword cannot carry a pointer, and anything else overwrites its
        // destination.
        //
        // Conservative over-invalidation (CMP/CMPI/TST read-only forms are
        // excluded where the encoding distinguishes them) only loses tracking,
        // never invents it.
        Operands::SizeEffectiveAddressEffectiveAddress(size, destination, source) => {
            let stored = match size {
                Size::Long => source_library(state, source, site),
                _ => None,
            };
            match stored {
                Some(tracked) => {
                    findings.note(destination, Some(&tracked.library), &state.bases);
                    set_slot(&mut state.slots, destination, Some(tracked));
                }
                None => invalidate_destination(state, findings, destination),
            }
        }
        // MOVEQ overwrites a data register.
        Operands::RegisterData(register, _) => {
            invalidate_destination(state, findings, AddressingMode::Drd(register));
        }
        // CLR/NEG/NOT overwrite their operand; TST only reads it.
        Operands::SizeEffectiveAddress(_, destination) if isa != Isa::Tst => {
            invalidate_destination(state, findings, destination);
        }
        // Immediate arithmetic (ADDI/SUBI/ANDI/ORI/EORI); CMPI only reads.
        Operands::SizeEffectiveAddressImmediate(_, destination, _) if isa != Isa::Cmpi => {
            invalidate_destination(state, findings, destination);
        }
        // Quick arithmetic overwrites its destination, including an address
        // register (`ADDQ #n,A6` shifts a tracked base away).
        Operands::DataSizeEffectiveAddress(_, _, destination) => {
            invalidate_destination(state, findings, destination);
        }
        // Register arithmetic: the destination side is overwritten. The
        // register side of a read (DstEa) stays intact, but CMP's DstReg
        // encoding is conservatively invalidated along with real writes.
        Operands::RegisterDirectionSizeEffectiveAddress(register, direction, _, destination) => {
            match direction {
                Direction::DstEa => invalidate_destination(state, findings, destination),
                _ => invalidate_destination(state, findings, AddressingMode::Drd(register)),
            }
        }
        // Register shifts overwrite a data register; memory shifts their word.
        Operands::RotationDirectionSizeModeRegister(_, _, _, _, register) => {
            invalidate_destination(state, findings, AddressingMode::Drd(register));
        }
        Operands::DirectionEffectiveAddress(_, destination) => {
            invalidate_destination(state, findings, destination);
        }
        // MOVEM memory-to-register overwrites every listed register with
        // values the tracker does not model (bit 0 = D0 .. bit 15 = A7 in
        // this direction).
        Operands::DirectionSizeEffectiveAddressList(direction, _, _, list) => {
            if matches!(direction, Direction::MemoryToRegister) {
                for register in 0..8u8 {
                    if list & (1 << (8 + u16::from(register))) != 0 {
                        state.address[usize::from(register)] = None;
                        if register == 0 || register == 1 {
                            set_open_name(state, register, None);
                        }
                        // Restoring a pointer from the stack is the usual way
                        // real code reloads A1, and it names other memory
                        // afterwards.
                        drop_relative_slots(&mut state.slots, register);
                    }
                    if list & (1 << u16::from(register)) != 0 {
                        invalidate_destination(state, findings, AddressingMode::Drd(register));
                    }
                }
            }
        }
        // Address arithmetic destroys a tracked library base — and moves the
        // pointer, so anything read through it named different memory.
        Operands::RegisterSizeEffectiveAddress(register, _, _)
        | Operands::RegisterDisplacement(register, _) => {
            state.address[usize::from(register)] = None;
            if register == 0 || register == 1 {
                set_open_name(state, register, None);
            }
            drop_relative_slots(&mut state.slots, register);
        }
        _ => {}
    }
}

/// Invalidate whatever the tracker knows about a written `destination`: a
/// pending OpenLibrary result in D0, a tracked address-register base, or a
/// tracked slot (memory operand or data-register copy).
fn invalidate_destination(
    state: &mut LibraryState,
    findings: &mut Findings,
    destination: AddressingMode,
) {
    findings.note(destination, None, &state.bases);
    match destination {
        AddressingMode::Drd(0) => state.d0_result = None,
        AddressingMode::Ard(register) => {
            state.address[usize::from(register)] = None;
            if register == 0 || register == 1 {
                set_open_name(state, register, None);
            }
            drop_relative_slots(&mut state.slots, register);
        }
        _ => {}
    }
    set_slot(&mut state.slots, destination, None);
}

/// The library a value read through `source` carries, if the tracker knows one.
///
/// One table for every read, so a `MOVEA` and a `MOVE` into a slot cannot come
/// to disagree about what `(4).L` is.
fn source_library(state: &LibraryState, source: AddressingMode, site: u32) -> Option<Tracked> {
    match source {
        // AbsExecBase. Unambiguous, and how essentially every Amiga program
        // obtains exec — including the programs that then store it in a global
        // and never load it from address 4 again.
        AddressingMode::AbsShort(4) | AddressingMode::AbsLong(4) => {
            Some(Tracked::new(Library::Exec, site))
        }
        AddressingMode::Ard(register) => state.address[usize::from(register)]
            .as_ref()
            .map(|tracked| tracked.through(site)),
        AddressingMode::Drd(0) => state
            .d0_result
            .as_ref()
            .map(|tracked| tracked.through(site)),
        _ => slot_library(&state.slots, source).map(|tracked| tracked.through(site)),
    }
}

fn slot_library(slots: &[(AddressingMode, Tracked)], source: AddressingMode) -> Option<&Tracked> {
    slots
        .iter()
        .rev()
        .find_map(|(slot, tracked)| (*slot == source).then_some(tracked))
}

fn set_slot(
    slots: &mut Vec<(AddressingMode, Tracked)>,
    destination: AddressingMode,
    tracked: Option<Tracked>,
) {
    slots.retain(|(slot, _)| *slot != destination);
    if let Some(tracked) = tracked {
        slots.push((destination, tracked));
    }
}

fn effective_address(mode: AddressingMode, image_origin: Option<u32>) -> Option<u32> {
    match mode {
        AddressingMode::Pciwd(pc, displacement) => {
            Some(pc.wrapping_add_signed(i32::from(displacement)))
        }
        AddressingMode::AbsLong(address) | AddressingMode::Immediate(address) => match image_origin
        {
            Some(origin) => address.checked_sub(origin),
            None => Some(address),
        },
        // Sign-extended, as the 68000 extends it, and then read in the absolute
        // frame like the long form — the same address under a shorter encoding.
        // Taking the sixteen bits as they stand would make `($FFF8).W` resolve
        // to `0xFFF8`, which is a plausible position inside a real hunk and
        // would establish a base the program never pointed anywhere near.
        AddressingMode::AbsShort(address) => effective_address(
            AddressingMode::AbsLong(sign_extend_word(address)),
            image_origin,
        ),
        _ => None,
    }
}

fn library_name_at(code: &[u8], address: u32, image_origin: Option<u32>) -> Option<Library> {
    let offset = match image_origin {
        Some(origin) => address.checked_sub(origin)?,
        None => address,
    };
    library_name_at_offset(code, offset)
}

fn library_name_at_offset(code: &[u8], offset: u32) -> Option<Library> {
    let start = usize::try_from(offset).ok()?;
    let tail = code.get(start..)?;
    // Scan one byte past the longest accepted name so a name of exactly
    // MAX_LIBRARY_NAME bytes still finds its terminator.
    let end = tail
        .iter()
        .take(MAX_LIBRARY_NAME + 1)
        .position(|byte| *byte == 0)?;
    let name = std::str::from_utf8(tail.get(..end)?).ok()?;
    Library::from_name(name)
}

fn exec_lvo(offset: i16) -> Option<&'static str> {
    let name = match offset {
        -30 => "Supervisor",
        -72 => "InitCode",
        -78 => "InitStruct",
        -84 => "MakeLibrary",
        -90 => "MakeFunctions",
        -96 => "FindResident",
        -102 => "InitResident",
        -108 => "Alert",
        -114 => "Debug",
        -120 => "Disable",
        -126 => "Enable",
        -132 => "Forbid",
        -138 => "Permit",
        -144 => "SetSR",
        -150 => "SuperState",
        -156 => "UserState",
        -162 => "SetIntVector",
        -168 => "AddIntServer",
        -174 => "RemIntServer",
        -180 => "Cause",
        -186 => "Allocate",
        -192 => "Deallocate",
        -198 => "AllocMem",
        -204 => "AllocAbs",
        -210 => "FreeMem",
        -216 => "AvailMem",
        -222 => "AllocEntry",
        -228 => "FreeEntry",
        -234 => "Insert",
        -240 => "AddHead",
        -246 => "AddTail",
        -252 => "Remove",
        -258 => "RemHead",
        -264 => "RemTail",
        -270 => "Enqueue",
        -276 => "FindName",
        -282 => "AddTask",
        -288 => "RemTask",
        -294 => "FindTask",
        -300 => "SetTaskPri",
        -306 => "SetSignal",
        -312 => "SetExcept",
        -318 => "Wait",
        -324 => "Signal",
        -330 => "AllocSignal",
        -336 => "FreeSignal",
        -342 => "AllocTrap",
        -348 => "FreeTrap",
        -354 => "AddPort",
        -360 => "RemPort",
        -366 => "PutMsg",
        -372 => "GetMsg",
        -378 => "ReplyMsg",
        -384 => "WaitPort",
        -390 => "FindPort",
        -396 => "AddLibrary",
        -402 => "RemLibrary",
        -408 => "OldOpenLibrary",
        -414 => "CloseLibrary",
        -420 => "SetFunction",
        -426 => "SumLibrary",
        -432 => "AddDevice",
        -438 => "RemDevice",
        -444 => "OpenDevice",
        -450 => "CloseDevice",
        -456 => "DoIO",
        -462 => "SendIO",
        -468 => "CheckIO",
        -474 => "WaitIO",
        -480 => "AbortIO",
        -486 => "AddResource",
        -492 => "RemResource",
        -498 => "OpenResource",
        -522 => "RawDoFmt",
        -528 => "GetCC",
        -534 => "TypeOfMem",
        -540 => "Procure",
        -546 => "Vacate",
        -552 => "OpenLibrary",
        -558 => "InitSemaphore",
        -564 => "ObtainSemaphore",
        -570 => "ReleaseSemaphore",
        -576 => "AttemptSemaphore",
        -624 => "CopyMem",
        -630 => "CopyMemQuick",
        _ => return None,
    };
    Some(name)
}

fn dos_lvo(offset: i16) -> Option<&'static str> {
    let name = match offset {
        -30 => "Open",
        -36 => "Close",
        -42 => "Read",
        -48 => "Write",
        -54 => "Input",
        -60 => "Output",
        -66 => "Seek",
        -72 => "DeleteFile",
        -78 => "Rename",
        -84 => "Lock",
        -90 => "UnLock",
        -96 => "DupLock",
        -102 => "Examine",
        -108 => "ExNext",
        -114 => "Info",
        -120 => "CreateDir",
        -126 => "CurrentDir",
        -132 => "IoErr",
        -138 => "CreateProc",
        -144 => "Exit",
        -150 => "LoadSeg",
        -156 => "UnLoadSeg",
        -174 => "DeviceProc",
        -180 => "SetComment",
        -186 => "SetProtection",
        -192 => "DateStamp",
        -198 => "Delay",
        -204 => "WaitForChar",
        -210 => "ParentDir",
        -216 => "IsInteractive",
        -222 => "Execute",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {

    /// Every way real code loses the IORequest pointer, and one that keeps it.
    #[test]
    fn the_io_device_slot_dies_with_the_pointer_it_was_read_through() {
        // The shared prologue: open trackdisk.device with the IORequest in A1.
        // `disturbance` runs between the open and the field read.
        let attribute = |disturbance: &[u8]| {
            let mut code = vec![
                0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
                0x41, 0xfa, 0x00, 0x3a, // 0x04 LEA (0x3a,PC),A0 -> name at 0x40
                0x43, 0xfa, 0x00, 0x46, // 0x08 LEA (0x46,PC),A1 -> ioreq at 0x52
                0x4e, 0xae, 0xfe, 0x44, // 0x0c JSR (-444,A6) = OpenDevice
            ];
            code.extend_from_slice(disturbance);
            let read = code.len() as u32;
            code.extend_from_slice(&[0x2c, 0x69, 0x00, 0x14]); // MOVEA.L (20,A1),A6
            let call = code.len() as u32;
            code.extend_from_slice(&[0x4e, 0xae, 0xff, 0xe2]); // JSR (-30,A6)
            code.extend_from_slice(&[0x4e, 0x75]); // RTS
            assert!(read < 0x40 && call < 0x40, "the fixture outgrew its layout");
            code.resize(0x40, 0);
            code.extend_from_slice(b"trackdisk.device\0"); // 0x40..0x51
            code.resize(0x52, 0);
            code.resize(0x72, 0); // the IORequest
            let analysis = analyze(&code, 0);
            infer_libraries(&analysis, &code, None, None)
                .get(&call)
                .cloned()
        };

        let device = Some(Library::Other("trackdisk.device".to_owned()));
        assert_eq!(attribute(&[]), device, "the baseline flow stopped working");

        for (name, disturbance) in [
            ("ADDQ.L #4,A1", vec![0x52, 0x89]),
            ("ADDA.W #4,A1", vec![0xd2, 0xfc, 0x00, 0x04]),
            ("LINK A1,#-8", vec![0x4e, 0x51, 0xff, 0xf8]),
            ("MOVEA.L (A2),A1", vec![0x22, 0x52]),
            ("MOVEM.L (A2)+,A1", vec![0x4c, 0xda, 0x02, 0x00]),
            (
                "BSR.S past",
                vec![0x61, 0x02, 0x60, 0x00, 0x00, 0x02, 0x4e, 0x75],
            ),
        ] {
            assert_eq!(
                attribute(&disturbance),
                None,
                "{name}: the device slot outlived the pointer it was read through"
            );
        }
    }

    #[test]
    fn address_arithmetic_on_a0_forgets_the_device_name() {
        // A0 no longer points at the string, so the name it carried is not
        // this call's argument.
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x41, 0xfa, 0x00, 0x1a, // 0x04 LEA (0x1a,PC),A0 -> name at 0x20
            0x50, 0x88, // 0x08 ADDQ.L #8,A0
            0x43, 0xfa, 0x00, 0x2a, // 0x0a LEA (0x2a,PC),A1 -> ioreq at 0x38
            0x4e, 0xae, 0xfe, 0x44, // 0x0e JSR (-444,A6) = OpenDevice
            0x2c, 0x69, 0x00, 0x14, // 0x12 MOVEA.L (20,A1),A6
            0x4e, 0xae, 0xff, 0xe2, // 0x16 JSR (-30,A6)
            0x4e, 0x75, // 0x1a RTS
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"trackdisk.device\0");
        code.resize(0x38, 0);
        code.resize(0x58, 0);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x16),
            None,
            "a device name survived arithmetic that moved A0 off it"
        );
    }

    /// `OpenDevice` binds a device base through the IORequest it is handed,
    /// not through D0 — the pattern the roadmap's second Stage 4 gap names.
    #[test]
    fn open_device_binds_the_base_through_the_io_request() {
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6 (ExecBase)
            0x41, 0xfa, 0x00, 0x14, // 0x04 LEA (0x14,PC),A0 -> name at 0x1a
            0x43, 0xfa, 0x00, 0x22, // 0x08 LEA (0x22,PC),A1 -> ioreq at 0x2c
            0x4e, 0xae, 0xfe, 0x44, // 0x0c JSR (-444,A6) = OpenDevice
            0x2c, 0x69, 0x00, 0x14, // 0x10 MOVEA.L (20,A1),A6 = io_Device
            0x4e, 0xae, 0xff, 0xe2, // 0x14 JSR (-30,A6) = a device vector
            0x4e, 0x75, // 0x18 RTS
        ];
        code.extend_from_slice(b"trackdisk.device\0"); // 0x1a..0x2b
        code.push(0); // 0x2b pad
        code.resize(0x4c, 0); // the IORequest itself, at 0x2c

        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(
            libraries.get(&0x14),
            Some(&Library::Other("trackdisk.device".to_owned())),
            "the device call was not attributed through the IORequest"
        );
    }

    #[test]
    fn a_reloaded_io_request_pointer_drops_the_field_it_used_to_name() {
        // The same flow, but A1 is reloaded from somewhere unknown before the
        // field is read. After that the displacement names different memory,
        // and claiming the old device would be confidently wrong.
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x41, 0xfa, 0x00, 0x18, // 0x04 LEA (0x18,PC),A0 -> name at 0x1e
            0x43, 0xfa, 0x00, 0x26, // 0x08 LEA (0x26,PC),A1 -> ioreq at 0x30
            0x4e, 0xae, 0xfe, 0x44, // 0x0c JSR (-444,A6) = OpenDevice
            0x22, 0x52, // 0x10 MOVEA.L (A2),A1  (A1 now points elsewhere)
            0x2c, 0x69, 0x00, 0x14, // 0x12 MOVEA.L (20,A1),A6
            0x4e, 0xae, 0xff, 0xe2, // 0x16 JSR (-30,A6)
            0x4e, 0x75, // 0x1a RTS
            0x4e, 0x71, // 0x1c filler
        ];
        code.extend_from_slice(b"trackdisk.device\0"); // 0x1e..0x2f
        code.push(0); // 0x2f pad
        code.resize(0x50, 0);

        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(
            libraries.get(&0x16),
            None,
            "a stale IORequest field was still trusted after its pointer changed"
        );
    }

    #[test]
    fn an_open_device_name_does_not_leak_into_an_open_library_result() {
        // A0 and A1 carry different arguments. If one name overwrote the
        // other, this OpenLibrary would come back as the device.
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x41, 0xfa, 0x00, 0x1a, // 0x04 LEA (0x1a,PC),A0 -> device name at 0x20
            0x43, 0xfa, 0x00, 0x28, // 0x08 LEA (0x28,PC),A1 -> library name at 0x32
            0x4e, 0xae, 0xfd, 0xd8, // 0x0c JSR (-552,A6) = OpenLibrary
            0x2c, 0x40, // 0x10 MOVEA.L D0,A6
            0x4e, 0xae, 0xff, 0xe2, // 0x12 JSR (-30,A6)
            0x4e, 0x75, // 0x16 RTS
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"trackdisk.device\0"); // 0x20..0x31
        code.resize(0x32, 0);
        code.extend_from_slice(b"mathffp.library\0"); // 0x32..0x41
        code.resize(0x48, 0);

        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(
            libraries.get(&0x12),
            Some(&Library::Other("mathffp.library".to_owned())),
            "the A0 device name displaced the A1 library name"
        );
    }

    use super::*;
    use crate::control_flow::analyze;

    fn address_register_writes(code: &[u8]) -> Vec<u8> {
        let analysis = analyze(code, 0);
        let decoded = analysis
            .instructions
            .get(&0)
            .unwrap_or_else(|| panic!("the fixture's first instruction was not decoded"));
        address_registers_written(decoded)
    }

    #[test]
    fn reading_an_address_register_as_a_move_source_does_not_write_it() {
        // MOVE.L A5,(0x1cc2).L ; RTS. A5 supplies the value; the absolute
        // destination leaves every address register unchanged.
        let code = [0x23, 0xcd, 0x00, 0x00, 0x1c, 0xc2, 0x4e, 0x75];
        assert_eq!(address_register_writes(&code), Vec::<u8>::new());
    }

    #[test]
    fn data_register_operations_do_not_alias_the_same_numbered_address_register() {
        for (name, code) in [
            ("SWAP D5", [0x48, 0x45, 0x4e, 0x75]),
            ("EXG D2,D5", [0xc5, 0x45, 0x4e, 0x75]),
        ] {
            assert_eq!(
                address_register_writes(&code),
                Vec::<u8>::new(),
                "{name} was misclassified as an address-register write"
            );
        }
    }

    #[test]
    fn address_register_exchanges_and_movem_restores_remain_real_writes() {
        assert_eq!(
            address_register_writes(&[0xc5, 0x4d, 0x4e, 0x75]),
            vec![2, 5],
            "EXG A2,A5 must write both address registers"
        );
        assert_eq!(
            address_register_writes(&[0xc5, 0x8d, 0x4e, 0x75]),
            vec![5],
            "EXG D2,A5 must write only its address-register operand"
        );
        assert_eq!(
            address_register_writes(&[0x4c, 0xdf, 0x40, 0x00, 0x4e, 0x75]),
            vec![6, 7],
            "MOVEM.L (A7)+,A6 writes restored A6 and post-incremented A7"
        );
        assert_eq!(
            address_register_writes(&[0x4e, 0x7a, 0xd8, 0x01, 0x4e, 0x75]),
            vec![5],
            "MOVEC VBR,A5 writes its general-register destination"
        );
        assert_eq!(
            address_register_writes(&[0x4e, 0x7b, 0xd8, 0x01, 0x4e, 0x75]),
            Vec::<u8>::new(),
            "MOVEC A5,VBR only reads A5"
        );
    }

    #[test]
    fn a_move_source_addressing_side_effect_is_still_a_write() {
        // MOVE.L (A5)+,D0 ; RTS. Reading memory changes A5 because the source
        // mode is post-increment, even though an ordinary A5 source does not.
        let code = [0x20, 0x1d, 0x4e, 0x75];
        assert_eq!(address_register_writes(&code), vec![5]);
    }

    #[test]
    fn unrelated_register_reads_and_data_operations_keep_a_base_global_anchored() {
        // LEA data,A5 ; MOVE.L A5,(0x100).L ; SWAP D5 ; EXG D2,D5 ;
        // MOVE.L (4).L,(0xe4,A5) ; BSR helper ; RTS
        // helper: MOVEA.L (0xe4,A5),A6 ; JSR (-132,A6) ; RTS
        //
        // The middle three instructions were all reported as A5 writes by the
        // old operand-shape-only classifier. That lost the anchor on the
        // ExecBase slot before the helper could read it.
        let mut code = vec![
            0x4b, 0xfa, 0x00, 0x3e, // 0x00 LEA (0x3e,PC),A5 -> 0x40
            0x23, 0xcd, 0x00, 0x00, 0x01, 0x00, // 0x04 MOVE.L A5,(0x100).L
            0x48, 0x45, // 0x0a SWAP D5
            0xc5, 0x45, // 0x0c EXG D2,D5
            0x2b, 0x79, 0x00, 0x00, 0x00, 0x04, 0x00, 0xe4, // 0x0e store ExecBase
            0x61, 0x02, // 0x16 BSR.S helper
            0x4e, 0x75, // 0x18 RTS
            0x2c, 0x6d, 0x00, 0xe4, // 0x1a MOVEA.L (0xe4,A5),A6
            0x4e, 0xae, 0xff, 0x7c, // 0x1e JSR (-132,A6)
            0x4e, 0x75, // 0x22 RTS
        ];
        code.resize(0x60, 0);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x1e),
            Some(&Library::Exec),
            "a read of A5 or an operation on D5 discarded the A5-relative slot"
        );
    }

    #[test]
    fn a_base_stored_in_a_global_is_known_in_the_function_that_loads_it() {
        // The shape essentially every Amiga program has, and the one the
        // per-function pass could never see: the entry function establishes the
        // bases in the first few hundred bytes and every later function loads
        // A6 from a slot. Nothing about the *call site* says which library it
        // is; the store, in another function entirely, is what says.
        //
        //   entry:  LEA (data,PC),A5          ; the small-data base, set once
        //           MOVE.L (4).L,(0xe4,A5)    ; AbsExecBase into a global
        //           BSR.S helper
        //           RTS
        //   helper: MOVEA.L (0xe4,A5),A6
        //           JSR (-132,A6)             ; exec.library/Forbid
        //           RTS
        let mut code = vec![
            0x4b, 0xfa, 0x00, 0x1e, // 0x00 LEA (0x1e,PC),A5 -> 0x20
            0x2b, 0x79, 0x00, 0x00, 0x00, 0x04, 0x00, 0xe4, // 0x04 MOVE.L (4).L,(0xe4,A5)
            0x61, 0x02, // 0x0c BSR.S helper
            0x4e, 0x75, // 0x0e RTS
            0x2c, 0x6d, 0x00, 0xe4, // 0x10 MOVEA.L (0xe4,A5),A6
            0x4e, 0xae, 0xff, 0x7c, // 0x14 JSR (-132,A6)
            0x4e, 0x75, // 0x18 RTS
        ];
        code.resize(0x40, 0);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x14),
            Some(&Library::Exec),
            "the base did not survive the store and the later load"
        );
    }

    #[test]
    fn a_base_stored_at_an_absolute_address_is_known_where_it_is_loaded() {
        //   MOVE.L (4).L,(0x84a).L
        //   BSR.S helper ; RTS
        //   helper: MOVEA.L (0x84a).L,A6 ; JSR (-132,A6) ; RTS
        let mut code = vec![
            0x23, 0xf9, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x08, 0x4a, // 0x00
            0x61, 0x02, // 0x0a BSR.S helper
            0x4e, 0x75, // 0x0c RTS
            0x2c, 0x79, 0x00, 0x00, 0x08, 0x4a, // 0x0e MOVEA.L (0x84a).L,A6
            0x4e, 0xae, 0xff, 0x7c, // 0x14 JSR (-132,A6)
            0x4e, 0x75, // 0x18 RTS
        ];
        code.resize(0x40, 0);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x14),
            Some(&Library::Exec)
        );
    }

    #[test]
    fn a_displacement_off_a_repointed_register_is_not_a_global() {
        // The same program, except the helper re-points A5 before reading the
        // slot. Two writes to a base register mean it is a pointer, not a
        // small-data base, and a displacement off it names different memory
        // each time — so the store says nothing about what the load reads.
        let mut code = vec![
            0x4b, 0xfa, 0x00, 0x1e, // 0x00 LEA (0x1e,PC),A5
            0x2b, 0x79, 0x00, 0x00, 0x00, 0x04, 0x00, 0xe4, // 0x04 MOVE.L (4).L,(0xe4,A5)
            0x61, 0x02, // 0x0c BSR.S helper
            0x4e, 0x75, // 0x0e RTS
            0x2a, 0x52, // 0x10 MOVEA.L (A2),A5 — a second write to A5
            0x2c, 0x6d, 0x00, 0xe4, // 0x12 MOVEA.L (0xe4,A5),A6
            0x4e, 0xae, 0xff, 0x7c, // 0x16 JSR (-132,A6)
            0x4e, 0x75, // 0x1a RTS
        ];
        code.resize(0x40, 0);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x16),
            None,
            "a re-pointed base register was read as a small-data base"
        );
    }

    /// The shape a base register is re-pointed by before a later ordinary
    /// call: `A5` first holds a callback address rather than its base, then is
    /// explicitly re-established.
    ///
    /// Program-wide the register therefore points at two addresses and every
    /// slot behind it used to be refused — which is a fact about the argument
    /// write, not about the read. The read is reached only through a call made
    /// while the base is established, and that is what says so.
    ///
    /// `re_establish` decides whether the base is put back before the call.
    fn supervisor_argument_shape(re_establish: bool) -> Vec<u8> {
        // 0x00 LEA (0x3e,PC),A5   — PC is 0x02, so A5 = 0x40, the base.
        let mut code = vec![0x4b, 0xfa, 0x00, 0x3e];
        // 0x04 MOVE.L (4).L,(0xe4,A5) — AbsExecBase into the global.
        code.extend_from_slice(&[0x2b, 0x79, 0x00, 0x00, 0x00, 0x04, 0x00, 0xe4]);
        // 0x0c MOVEA.L #0x112,A5 — a callback-argument-shaped write.
        code.extend_from_slice(&[0x2a, 0x7c, 0x00, 0x00, 0x01, 0x12]);
        code.extend_from_slice(&if re_establish {
            // 0x12 LEA (0x2c,PC),A5 — PC is 0x14, so A5 = 0x40 again.
            [0x4b, 0xfa, 0x00, 0x2c]
        } else {
            [0x4e, 0x71, 0x4e, 0x71] // NOP ; NOP
        });
        code.extend_from_slice(&[
            0x61, 0x02, // 0x16 BSR.S 0x1a
            0x4e, 0x75, // 0x18 RTS
            0x2c, 0x6d, 0x00, 0xe4, // 0x1a MOVEA.L (0xe4,A5),A6
            0x4e, 0xae, 0xff, 0x7c, // 0x1e JSR (-132,A6) = exec.library/Forbid
            0x4e, 0x75, // 0x22 RTS
        ]);
        code.resize(0x60, 0);
        code
    }

    #[test]
    fn a_base_re_established_before_the_call_reaches_the_read() {
        let code = supervisor_argument_shape(true);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x1e),
            Some(&Library::Exec),
            "a register re-pointed on a path the read is not reached through \
             disqualified every slot behind it"
        );
    }

    #[test]
    fn a_base_still_re_pointed_at_the_call_does_not_reach_the_read() {
        // The same program without the re-establishment: the callee really is
        // entered with A5 holding the argument, so `(0xe4,A5)` names memory
        // 0xd2 bytes past it and nothing about the store applies.
        let code = supervisor_argument_shape(false);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x1e),
            None,
            "a slot was read through a base the caller had replaced"
        );
    }

    fn supervisor_callback_shape(restores_base: bool) -> Vec<u8> {
        let mut code = vec![
            0x4b, 0xfa, 0x00, 0x3e, // 0x00 LEA (0x3e,PC),A5 -> 0x40
            0x2b, 0x79, 0x00, 0x00, 0x00, 0x04, 0x00, 0xe4, // 0x04 ExecBase -> (0xe4,A5)
            0x2c, 0x6d, 0x00, 0xe4, // 0x0c MOVEA.L (0xe4,A5),A6
            0x2a, 0x7c, 0x00, 0x00, 0x00, 0x30, // 0x10 MOVEA.L #0x30,A5
            0x4e, 0xae, 0xff, 0xe2, // 0x16 JSR (-30,A6) = Supervisor
            0x4e, 0xb9, 0x00, 0x00, 0x00, 0x24, // 0x1a JSR helper
            0x4e, 0x75, // 0x20 RTS
            0x4e, 0x71, // 0x22 padding
            0x2c, 0x6d, 0x00, 0xe4, // 0x24 MOVEA.L (0xe4,A5),A6
            0x4e, 0xae, 0xff, 0x7c, // 0x28 JSR (-132,A6) = Forbid
            0x4e, 0x75, // 0x2c RTS
            0x4e, 0x71, // 0x2e padding
            0x4e, 0x7a, 0x08, 0x01, // 0x30 MOVEC VBR,D0 (MC68010+)
        ];
        code.extend_from_slice(&if restores_base {
            [
                0x4b, 0xfa, 0x00, 0x0a, // 0x34 LEA (0x0a,PC),A5 -> 0x40
                0x4e, 0x73, // 0x38 RTE
            ]
        } else {
            [
                0x4e, 0x71, 0x4e, 0x71, // 0x34 NOP ; NOP
                0x4e, 0x73, // 0x38 RTE
            ]
        });
        code.resize(0x60, 0);
        code
    }

    #[test]
    fn supervisor_callback_return_restores_the_callers_base_state() {
        let code = supervisor_callback_shape(true);
        let analysis = analyze(&code, 0);
        assert!(
            !analysis.instructions.contains_key(&0x30),
            "an ABI callback must not masquerade as an ordinary call edge"
        );
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x28),
            Some(&Library::Exec)
        );
    }

    #[test]
    fn supervisor_callback_that_does_not_restore_the_base_stays_unknown() {
        let code = supervisor_callback_shape(false);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x28),
            None,
            "Supervisor itself must not be assumed to restore its A5 argument"
        );
    }

    fn returned_base_through_two_calls_shape(restored_base: u32) -> Vec<u8> {
        let mut code = vec![
            0x4b, 0xfa, 0x00, 0x7e, // 0x00 LEA (0x7e,PC),A5 -> 0x80
            0x2b, 0x79, 0x00, 0x00, 0x00, 0x04, 0x00, 0xe0, // 0x04 ExecBase -> (0xe0,A5)
            0x2a, 0x7c, 0x00, 0x00, 0x00, 0x70, // 0x0c MOVEA.L #0x70,A5
            0x4e, 0xb9, 0x00, 0x00, 0x00, 0x30, // 0x12 JSR restore
            0x4e, 0xb9, 0x00, 0x00, 0x00, 0x40, // 0x18 JSR bridge
            0x4e, 0x75, // 0x1e RTS
        ];
        code.resize(0x30, 0);
        // 0x30 LEA (d16,PC),A5 ; RTS. The PC base is 0x32.
        let displacement = restored_base.wrapping_sub(0x32) as u16;
        code.extend_from_slice(&[
            0x4b,
            0xfa,
            (displacement >> 8) as u8,
            displacement as u8,
            0x4e,
            0x75,
        ]);
        code.resize(0x40, 0);
        code.extend_from_slice(&[
            0x4e, 0xb9, 0x00, 0x00, 0x00, 0x50, // 0x40 JSR consumer
            0x4e, 0x75, // 0x46 RTS
        ]);
        code.resize(0x50, 0);
        code.extend_from_slice(&[
            0x2c, 0x6d, 0x00, 0xe0, // 0x50 MOVEA.L (0xe0,A5),A6
            0x4e, 0xae, 0xff, 0x7c, // 0x54 JSR (-132,A6) = Forbid
            0x4e, 0x75, // 0x58 RTS
        ]);
        code.resize(0x90, 0);
        code
    }

    #[test]
    fn a_callee_returning_the_base_carries_it_through_two_more_calls() {
        let code = returned_base_through_two_calls_shape(0x80);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x54),
            Some(&Library::Exec)
        );
    }

    #[test]
    fn a_callee_returning_a_different_base_does_not_seed_the_slot() {
        let code = returned_base_through_two_calls_shape(0x84);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x54),
            None,
            "a precise return summary must still match the slot's store anchor"
        );
    }

    #[test]
    fn disagreeing_callee_returns_do_not_claim_either_base() {
        let mut code = returned_base_through_two_calls_shape(0x80);
        code[0x30..0x40].copy_from_slice(&[
            0x4a, 0x40, // 0x30 TST.W D0
            0x67, 0x06, // 0x32 BEQ.S 0x3a
            0x4b, 0xfa, 0x00, 0x4a, // 0x34 LEA (0x4a,PC),A5 -> 0x80
            0x4e, 0x75, // 0x38 RTS
            0x4b, 0xfa, 0x00, 0x48, // 0x3a LEA (0x48,PC),A5 -> 0x84
            0x4e, 0x75, // 0x3e RTS
        ]);
        let analysis = analyze(&code, 0);
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x54),
            None,
            "a return summary used one of two conflicting exit bases"
        );
    }

    #[test]
    fn a_global_two_libraries_share_names_neither() {
        // Whichever was stored last is a fact about the path taken, not about
        // the program, so the slot establishes nothing.
        //
        //   MOVE.L (4).L,(0x84a).L      ; exec here …
        //   LEA (name,PC),A1 ; MOVEA.L 4.W,A6 ; JSR (-552,A6) ; MOVE.L D0,(0x84a).L
        //   BSR.S helper ; RTS
        //   helper: MOVEA.L (0x84a).L,A6 ; JSR (-132,A6) ; RTS
        let mut code = vec![
            0x23, 0xf9, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x08, 0x4a, // 0x00
            0x43, 0xfa, 0x00, 0x2a, // 0x0a LEA (0x2a,PC),A1 -> 0x38
            0x2c, 0x78, 0x00, 0x04, // 0x0e MOVEA.L 4.W,A6
            0x4e, 0xae, 0xfd, 0xd8, // 0x12 JSR (-552,A6) = OpenLibrary
            0x23, 0xc0, 0x00, 0x00, 0x08, 0x4a, // 0x16 MOVE.L D0,(0x84a).L
            0x61, 0x02, // 0x1c BSR.S helper
            0x4e, 0x75, // 0x1e RTS
            0x2c, 0x79, 0x00, 0x00, 0x08, 0x4a, // 0x20 MOVEA.L (0x84a).L,A6
            0x4e, 0xae, 0xff, 0x7c, // 0x26 JSR (-132,A6)
            0x4e, 0x75, // 0x2a RTS
        ];
        code.resize(0x38, 0);
        code.extend_from_slice(b"dos.library\0");
        code.resize(0x60, 0);
        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(
            libraries.get(&0x12),
            Some(&Library::Exec),
            "the OpenLibrary call itself lost its base"
        );
        assert_eq!(
            libraries.get(&0x26),
            None,
            "a slot two libraries share named one of them"
        );
    }

    #[test]
    fn names_common_lvos_per_library() {
        assert_eq!(lvo_name(&Library::Dos, -30), Some("Open"));
        assert_eq!(lvo_name(&Library::Dos, -66), Some("Seek"));
        assert_eq!(lvo_name(&Library::Exec, -456), Some("DoIO"));
        assert_eq!(lvo_name(&Library::Exec, -552), Some("OpenLibrary"));
        assert_eq!(lvo_name(&Library::Graphics, -228), Some("WaitBlit"));
        assert_eq!(lvo_name(&Library::Intuition, -204), Some("OpenWindow"));
        // Same offset, different library, different meaning.
        assert_eq!(lvo_name(&Library::Dos, -132), Some("IoErr"));
        assert_eq!(lvo_name(&Library::Exec, -132), Some("Forbid"));
        assert_eq!(lvo_name(&Library::Dos, -1000), None);
    }

    #[test]
    fn names_expanded_lvos_per_library() {
        // exec: interrupt gates, list/task primitives, async device IO,
        // formatting, and memory copies.
        assert_eq!(lvo_name(&Library::Exec, -120), Some("Disable"));
        assert_eq!(lvo_name(&Library::Exec, -126), Some("Enable"));
        assert_eq!(lvo_name(&Library::Exec, -276), Some("FindName"));
        assert_eq!(lvo_name(&Library::Exec, -330), Some("AllocSignal"));
        assert_eq!(lvo_name(&Library::Exec, -408), Some("OldOpenLibrary"));
        assert_eq!(lvo_name(&Library::Exec, -462), Some("SendIO"));
        assert_eq!(lvo_name(&Library::Exec, -474), Some("WaitIO"));
        assert_eq!(lvo_name(&Library::Exec, -522), Some("RawDoFmt"));
        assert_eq!(lvo_name(&Library::Exec, -624), Some("CopyMem"));
        // dos: the 1.x tail after UnLoadSeg.
        assert_eq!(lvo_name(&Library::Dos, -192), Some("DateStamp"));
        assert_eq!(lvo_name(&Library::Dos, -198), Some("Delay"));
        assert_eq!(lvo_name(&Library::Dos, -222), Some("Execute"));
        // dos -162/-168 are private packet vectors and stay unnamed.
        assert_eq!(lvo_name(&Library::Dos, -162), None);
        // graphics: text, area, Copper, beam, and sprite vectors.
        assert_eq!(lvo_name(&Library::Graphics, -42), Some("ClearEOL"));
        assert_eq!(lvo_name(&Library::Graphics, -252), Some("AreaMove"));
        assert_eq!(lvo_name(&Library::Graphics, -378), Some("CWait"));
        assert_eq!(lvo_name(&Library::Graphics, -384), Some("VBeamPos"));
        assert_eq!(lvo_name(&Library::Graphics, -408), Some("GetSprite"));
        // intuition: workbench, prefs, and view vectors.
        assert_eq!(lvo_name(&Library::Intuition, -84), Some("CurrentTime"));
        assert_eq!(lvo_name(&Library::Intuition, -102), Some("DoubleClick"));
        assert_eq!(lvo_name(&Library::Intuition, -210), Some("OpenWorkBench"));
        assert_eq!(lvo_name(&Library::Intuition, -300), Some("ViewPortAddress"));
        assert_eq!(lvo_name(&Library::Intuition, -408), Some("FreeRemember"));
    }

    #[test]
    fn parses_library_names() {
        assert_eq!(Library::from_name("dos.library"), Some(Library::Dos));
        assert_eq!(Library::from_name("EXEC"), Some(Library::Exec));
        assert_eq!(Library::from_name("graphics"), Some(Library::Graphics));
        assert_eq!(
            Library::from_name("intuition.library"),
            Some(Library::Intuition)
        );
    }

    #[test]
    fn accepts_other_library_and_device_open_names() {
        assert_eq!(
            Library::from_name("mathffp.library"),
            Some(Library::Other("mathffp.library".to_owned()))
        );
        // Case is normalized, so a config identity matches the binary's
        // string regardless of spelling.
        assert_eq!(
            Library::from_name("MathFFP.Library"),
            Some(Library::Other("mathffp.library".to_owned()))
        );
        assert_eq!(
            Library::from_name("trackdisk.device"),
            Some(Library::Other("trackdisk.device".to_owned()))
        );
        assert_eq!(
            Library::from_name("mathffp.library")
                .as_ref()
                .map(Library::as_str),
            Some("mathffp.library")
        );
        // No suffix, an empty stem, control characters, or oversized names
        // are not plausible open-names.
        assert_eq!(Library::from_name("mathffp"), None);
        assert_eq!(Library::from_name(".library"), None);
        assert_eq!(Library::from_name("bad\nname.library"), None);
        let oversized = format!("{}.library", "x".repeat(64));
        assert_eq!(Library::from_name(&oversized), None);
        // Other identities have no curated table.
        assert_eq!(
            lvo_name(&Library::Other("mathffp.library".to_owned()), -30),
            None
        );
    }

    #[test]
    fn infers_an_other_library_through_the_openlibrary_flow() {
        // MOVEA.L 4.W,A6 ; LEA $20,A1 ; JSR (-552,A6) ; MOVEA.L D0,A6 ;
        // JSR (-30,A6) ; RTS ; ... ; "mathffp.library\0"
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, 0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x4e, 0xae, 0xfd, 0xd8,
            0x2c, 0x40, 0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75,
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"mathffp.library\0");
        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(libraries.get(&10), Some(&Library::Exec));
        assert_eq!(
            libraries.get(&16),
            Some(&Library::Other("mathffp.library".to_owned()))
        );
    }

    #[test]
    fn detects_a_library_call() {
        // JSR (-30,A6) ; RTS
        let code = [0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let call = library_call(&analysis.instructions[&0])
            .unwrap_or_else(|| panic!("expected a library call"));
        assert_eq!(
            call,
            LibraryCall {
                register: 6,
                offset: -30
            }
        );
        assert_eq!(lvo_name(&Library::Dos, call.offset), Some("Open"));
        // A plain RTS is not a library call.
        assert_eq!(library_call(&analysis.instructions[&4]), None);
    }

    #[test]
    fn follows_openlibrary_result_into_a6() {
        // MOVEA.L 4.W,A6 ; LEA $20,A1 ; JSR (-552,A6) ; MOVEA.L D0,A6 ;
        // JSR (-228,A6) ; RTS ; ... ; "graphics.library\0"
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, 0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x4e, 0xae, 0xfd, 0xd8,
            0x2c, 0x40, 0x4e, 0xae, 0xff, 0x1c, 0x4e, 0x75,
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"graphics.library\0");
        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(libraries.get(&10), Some(&Library::Exec));
        assert_eq!(libraries.get(&16), Some(&Library::Graphics));
    }

    #[test]
    fn candidate_chains_cite_the_establishing_sites() {
        // MOVEA.L 4.W,A6 ; LEA $20,A1 ; JSR (-552,A6) ; MOVEA.L D0,A6 ;
        // JSR (-228,A6) ; RTS ; ... ; "graphics.library\0"
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, 0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x4e, 0xae, 0xfd, 0xd8,
            0x2c, 0x40, 0x4e, 0xae, 0xff, 0x1c, 0x4e, 0x75,
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"graphics.library\0");
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, None);
        // The OpenLibrary call cites the ExecBase load that set up A6.
        assert_eq!(candidates[&10][&Library::Exec], vec![0]);
        // The WaitBlit call cites the name setup, the OpenLibrary call, and
        // the D0 copy into A6, in flow order.
        assert_eq!(candidates[&16][&Library::Graphics], vec![4, 10, 14]);
    }

    #[test]
    fn a_base_the_taken_branch_never_set_is_not_attributed() {
        // TST.W D1 ; BEQ.S skip ; MOVEA.L 4.W,A6 ; skip: JSR (-30,A6) ; RTS
        //
        // The branch reaches the call without ever loading ExecBase, so one of
        // the two paths into the call leaves A6 holding whatever the caller
        // had. An address-order walk sees the `MOVEA` before the call and
        // reports a confident `exec.library`; only control-flow order can see
        // that the two predecessors disagree.
        let code = [
            0x4a, 0x41, // 0x00 TST.W D1
            0x67, 0x04, // 0x02 BEQ.S 0x08
            0x2c, 0x78, 0x00, 0x04, // 0x04 MOVEA.L 4.W,A6
            0x4e, 0xae, 0xff, 0xe2, // 0x08 JSR (-30,A6)
            0x4e, 0x75, // 0x0c RTS
        ];
        let analysis = analyze(&code, 0);

        let candidates = infer_library_candidates(&analysis, &code, None, None);
        assert!(
            !candidates.contains_key(&0x08),
            "a base only one predecessor establishes survived a join: {:?}",
            candidates.get(&0x08)
        );
        // And nothing downstream turns the absence into a confident answer.
        assert!(infer_libraries(&analysis, &code, None, None).is_empty());
    }

    #[test]
    fn a_base_both_predecessors_agree_on_survives_the_join() {
        // MOVEA.L 4.W,A6 ; TST.W D1 ; BEQ.S skip ; NOP ; skip: JSR (-30,A6)
        //
        // The mirror of the case above: the join must lose only what the paths
        // disagree about. A conservative pass that dropped every joined value
        // would pass the previous test and be useless.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x4a, 0x41, // 0x04 TST.W D1
            0x67, 0x02, // 0x06 BEQ.S 0x0a
            0x4e, 0x71, // 0x08 NOP
            0x4e, 0xae, 0xff, 0xe2, // 0x0a JSR (-30,A6)
            0x4e, 0x75, // 0x0e RTS
        ];
        let analysis = analyze(&code, 0);

        let candidates = infer_library_candidates(&analysis, &code, None, None);
        assert_eq!(
            candidates[&0x0a][&Library::Exec],
            vec![0],
            "the agreed base lost its evidence chain: {candidates:?}"
        );
        assert_eq!(
            infer_libraries(&analysis, &code, None, None).get(&0x0a),
            Some(&Library::Exec)
        );
    }

    #[test]
    fn a_backward_branch_reaches_a_fixpoint_rather_than_looping() {
        // MOVEA.L 4.W,A6 ; loop: JSR (-30,A6) ; DBRA D1,loop ; RTS
        //
        // The call is inside a loop, so its in-state is joined with its own
        // downstream out-state. The worklist must converge on "A6 is still
        // ExecBase" instead of re-queueing forever.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x4e, 0xae, 0xff, 0xe2, // 0x04 JSR (-30,A6)
            0x51, 0xc9, 0xff, 0xfa, // 0x08 DBRA D1,0x04
            0x4e, 0x75, // 0x0c RTS
        ];
        let analysis = analyze(&code, 0);

        let candidates = infer_library_candidates(&analysis, &code, None, None);
        assert_eq!(candidates[&0x04][&Library::Exec], vec![0]);
    }

    #[test]
    fn a_default_a6_seed_has_an_empty_chain() {
        // JSR (-456,A6) ; RTS with ExecBase seeded by the entry convention.
        let code = [0x4e, 0xae, 0xfe, 0x38, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
        assert_eq!(candidates[&0][&Library::Exec], Vec::<u32>::new());
    }

    #[test]
    fn non_a6_negative_displacement_is_not_a_library_call() {
        // JSR (-8,A7) ; JSR (-4,A5) ; RTS — computed jumps, not LVO calls.
        let code = [0x4e, 0xaf, 0xff, 0xf8, 0x4e, 0xad, 0xff, 0xfc, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        assert_eq!(library_call(&analysis.instructions[&0]), None);
        assert_eq!(library_call(&analysis.instructions[&4]), None);
    }

    #[test]
    fn movem_restore_invalidates_tracked_bases() {
        // MOVEA.L 4.W,A6 ; MOVEM.L (SP)+,A6 ; JSR (-132,A6) ; RTS — the
        // restore overwrites A6 with an unknown caller value.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // MOVEA.L 4.W,A6
            0x4c, 0xdf, 0x40, 0x00, // MOVEM.L (SP)+,A6
            0x4e, 0xae, 0xff, 0x7c, // JSR (-132,A6)
            0x4e, 0x75, // RTS
        ];
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, None);
        assert!(!candidates.contains_key(&8));
    }

    #[test]
    fn a_non_d0_store_clobbers_a_tracked_slot() {
        // A6 = ExecBase (seeded). LEA name,A1 ; JSR OpenLibrary ;
        // MOVE.L D0,(8,A5) ; MOVE.L D1,(8,A5) ; MOVEA.L (8,A5),A6 ;
        // JSR (-30,A6) ; RTS — the second store overwrote the slot.
        let mut code = vec![
            0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, // 0x00 LEA $20,A1
            0x4e, 0xae, 0xfd, 0xd8, // 0x06 JSR (-552,A6)
            0x2b, 0x40, 0x00, 0x08, // 0x0a MOVE.L D0,(8,A5)
            0x2b, 0x41, 0x00, 0x08, // 0x0e MOVE.L D1,(8,A5)
            0x2c, 0x6d, 0x00, 0x08, // 0x12 MOVEA.L (8,A5),A6
            0x4e, 0xae, 0xff, 0xe2, // 0x16 JSR (-30,A6)
            0x4e, 0x75, // 0x1a RTS
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"graphics.library\0");
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
        assert!(!candidates.contains_key(&0x16));
    }

    #[test]
    fn arithmetic_on_d0_invalidates_the_openlibrary_result() {
        // A6 = ExecBase (seeded). LEA name,A1 ; JSR OpenLibrary ;
        // ADDI.L #4,D0 ; MOVEA.L D0,A6 ; JSR (-30,A6) ; RTS — D0 no longer
        // holds the OpenLibrary result.
        let mut code = vec![
            0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, // 0x00 LEA $20,A1
            0x4e, 0xae, 0xfd, 0xd8, // 0x06 JSR (-552,A6)
            0x06, 0x80, 0x00, 0x00, 0x00, 0x04, // 0x0a ADDI.L #4,D0
            0x2c, 0x40, // 0x10 MOVEA.L D0,A6
            0x4e, 0xae, 0xff, 0xe2, // 0x12 JSR (-30,A6)
            0x4e, 0x75, // 0x16 RTS
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"graphics.library\0");
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
        assert!(!candidates.contains_key(&0x12));
    }

    #[test]
    fn a_max_length_open_name_is_still_inferred() {
        // MOVEA.L 4.W,A6 ; LEA $20,A1 ; JSR OpenLibrary ; MOVEA.L D0,A6 ;
        // JSR (-30,A6) ; RTS with a 64-byte open-name (the accepted maximum).
        let name = format!(
            "{}.library",
            "x".repeat(MAX_LIBRARY_NAME - ".library".len())
        );
        assert_eq!(name.len(), MAX_LIBRARY_NAME);
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, 0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x4e, 0xae, 0xfd, 0xd8,
            0x2c, 0x40, 0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75,
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(name.as_bytes());
        code.push(0);
        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, None);
        assert_eq!(libraries.get(&16), Some(&Library::Other(name)));
    }

    #[test]
    fn follows_openlibrary_result_through_a_global_slot() {
        // A6 starts as ExecBase. LEA $20,A1 ; JSR OpenLibrary ;
        // MOVE.L D0,(8,A5) ; MOVEA.L (8,A5),A6 ; JSR intuition/OpenWindow ; RTS
        let mut code = vec![
            0x43, 0xf9, 0x00, 0x00, 0x00, 0x20, 0x4e, 0xae, 0xfd, 0xd8, 0x2b, 0x40, 0x00, 0x08,
            0x2c, 0x6d, 0x00, 0x08, 0x4e, 0xae, 0xff, 0x34, 0x4e, 0x75,
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"intuition.library\0");
        let analysis = analyze(&code, 0);
        let libraries = infer_libraries(&analysis, &code, None, Some(Library::Exec));
        assert_eq!(libraries.get(&6), Some(&Library::Exec));
        assert_eq!(libraries.get(&18), Some(&Library::Intuition));
    }

    /// A program whose base register is established in two places, with
    /// `second_base` the address the second establishment points at.
    ///
    /// Three routines, because the guard only decides anything when they are
    /// separate. Entry opens a library and stores it into `(8,A5)`; a second
    /// routine re-establishes `A5`; a third reads the slot and calls through
    /// it. Within one straight-line routine the tracker follows the value
    /// directly, and a routine that re-points `A5` itself drops the slot for a
    /// different reason — so the read has to live somewhere that does neither.
    fn two_base_establishments(second_base: u16) -> Vec<u8> {
        // The second LEA sits at 0x1c with its extension word at 0x1e, so its
        // displacement is measured from there.
        let displacement = second_base - 0x1e;
        let mut code = vec![
            0x4b,
            0xfa,
            0x00,
            0x5e, // 0x00 LEA (0x5e,PC),A5 -> A5 = 0x60
            0x43,
            0xf9,
            0x00,
            0x00,
            0x00,
            0x40, // 0x04 LEA $40,A1
            0x4e,
            0xae,
            0xfd,
            0xd8, // 0x0a JSR (-552,A6)  OpenLibrary
            0x2b,
            0x40,
            0x00,
            0x08, // 0x0e MOVE.L D0,(8,A5)
            0x61,
            0x08, // 0x12 BSR.S 0x1c  (re-establish)
            0x61,
            0x0c, // 0x14 BSR.S 0x22  (read through the slot)
            0x4e,
            0x75, // 0x16 RTS
            0x4e,
            0x71,
            0x4e,
            0x71, // 0x18 NOP ; NOP
            // 0x1c LEA (d16,PC),A5 — the second establishment.
            0x4b,
            0xfa,
            (displacement >> 8) as u8,
            displacement as u8,
            0x4e,
            0x75, // 0x20 RTS
            0x2c,
            0x6d,
            0x00,
            0x08, // 0x22 MOVEA.L (8,A5),A6
            0x4e,
            0xae,
            0xff,
            0xe2, // 0x26 JSR (-30,A6)
            0x4e,
            0x75, // 0x2a RTS
        ];
        code.resize(0x40, 0);
        code.extend_from_slice(b"graphics.library\0");
        code.resize(0x80, 0);
        code
    }

    #[test]
    fn a_base_established_twice_at_one_address_keeps_its_slots() {
        // Both establishments point A5 at 0x60. The register was never
        // re-pointed, so a displacement off it still names one piece of memory
        // and the call through the slot is attributed.
        let code = two_base_establishments(0x60);
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
        assert_eq!(
            candidates.get(&0x26).and_then(|by| by.keys().next()),
            Some(&Library::Graphics),
            "re-establishing the same base is not a re-point"
        );
    }

    #[test]
    fn a_base_repointed_to_a_second_address_loses_its_slots() {
        // The second establishment points A5 somewhere else, so (8,A5) names
        // different memory depending on which ran last. The slot is refused.
        let code = two_base_establishments(0x70);
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
        assert!(!candidates.contains_key(&0x26));
    }

    #[test]
    fn a_base_loaded_through_an_address_is_not_a_resolved_destination() {
        // `MOVEA.L $0060.W,A5` loads the longword *stored at* 0x60 — a runtime
        // pointer — where `LEA (0x5e,PC),A5` loaded 0x60 itself. Resolving the
        // two the same way would make both "destinations" 0x60, leave the
        // register looking un-re-pointed, and name a call through `(8,A5)` on
        // the strength of a base the program had replaced.
        for source in [
            [0x2a, 0x78, 0x00, 0x60], // MOVEA.L $0060.W,A5
            [0x2a, 0x7b, 0x01, 0x42], // MOVEA.L (0x42,PC,D0.W),A5
            [0x2a, 0x50, 0x4e, 0x71], // MOVEA.L (A0),A5 ; NOP
        ] {
            let mut code = two_base_establishments(0x60);
            code[0x1c..0x20].copy_from_slice(&source);
            let analysis = analyze(&code, 0);
            let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
            assert!(
                !candidates.contains_key(&0x26),
                "a dereferencing load must disqualify the base, not resolve to \
                 the address it read through: {source:02x?}"
            );
        }
    }

    #[test]
    fn a_base_written_by_a_value_the_walk_cannot_follow_loses_its_slots() {
        // Same shape, but the second routine loads A5 through memory instead
        // of from a constant. One unfollowable write and nothing about the
        // register is known — it must be refused even though it is the only
        // write that is not the original establishment.
        let mut code = two_base_establishments(0x60);
        // Replace the second LEA with MOVEA.L (A0),A5 plus a NOP, which is
        // the same length and leaves A5 holding something the walk cannot
        // value.
        code[0x1c..0x20].copy_from_slice(&[0x2a, 0x50, 0x4e, 0x71]);
        let analysis = analyze(&code, 0);
        let candidates = infer_library_candidates(&analysis, &code, None, Some(Library::Exec));
        assert!(!candidates.contains_key(&0x26));
    }
}
