//! A bounded backward dependency slice over one executed trace.
//!
//! Ordinary trace comparison identifies the first instruction two runs disagree
//! at. It does not say *why* — which earlier value made that instruction behave
//! differently, and which input made that one. This walks a recorded trace
//! backwards from a chosen value, through registers, the condition codes and
//! memory, to the instructions that produced it and, in the end, to the state
//! the run started in.
//!
//! ## Dynamic evidence for one run
//!
//! This is not whole-program static taint. It says what the instructions this
//! run *executed* did, at the addresses they read and wrote, which is exactly
//! the claim a person retracing a divergence wants and exactly not a claim about
//! every path the program has. A loop is unambiguous because every row carries
//! the instruction's address **and its occurrence** — the third time through is
//! a different row from the first.
//!
//! ## Where it is precise and where it is not
//!
//! **Definitions are exact.** A register is defined by a step when the trace
//! recorded it changing, or when the instruction writes it as a destination
//! operand — the second half is what catches a store of the value a register
//! already held, which produces no delta and is still a definition. Memory
//! definitions come from the recorded writes, which carry the address and width
//! the bus saw.
//!
//! **Uses are an over-approximation, deliberately.** A step is taken to use
//! every register its operands name and every register an address computation
//! reads. Where the exact semantics of an instruction would use fewer, the slice
//! is a superset: it may include a dependency the run did not really have, and
//! it will not miss one it did. That is the right direction for evidence — a
//! slice that quietly dropped an edge would send a reader looking in the wrong
//! place — and it is reported rather than implied, because a superset presented
//! as a minimum is a different claim.
//!
//! **A step this build cannot decode is a stated stop.** Self-modifying code, or
//! bytes the baseline memory no longer holds, end a chain with
//! [`SliceStop::Undecodable`] rather than silently pruning it.

use std::collections::{BTreeMap, BTreeSet};

use m68000::addressing_modes::AddressingMode;
use m68000::instruction::{Direction, Instruction, Operands, Size};
use m68000::isa::Isa;
use m68000::memory_access::MemoryAccess;

use crate::execute::{RegisterFile, Step};

/// One place a value can live, as the slice tracks it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Location {
    /// `D0`–`D7`.
    Data(u8),
    /// `A0`–`A7`, where `A7` is the stack pointer.
    Address(u8),
    /// The condition codes, tracked as one location: an instruction that sets
    /// any of them sets the reader's view of "the flags", and splitting them
    /// would claim a precision the trace does not record.
    Flags,
    /// One byte of memory. A word or longword access is the two or four bytes
    /// it covers, so a store of a longword and a load of its low word are
    /// related without either side having to model widths.
    Memory(u32),
}

impl std::fmt::Display for Location {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(index) => write!(formatter, "d{index}"),
            Self::Address(index) => write!(formatter, "a{index}"),
            Self::Flags => formatter.write_str("ccr"),
            Self::Memory(address) => write!(formatter, "[{address:#010x}]"),
        }
    }
}

/// What the slice was asked to explain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SliceSeed {
    /// A location as the run left it: the last step that defined it, and
    /// everything behind that.
    Final(Location),
    /// Everything the instruction at `address` read on its `occurrence`-th
    /// execution, counted from one.
    Instruction { address: u32, occurrence: u32 },
}

/// Why a chain stopped.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SliceStop {
    /// The location was never written during the run, so its value is an input:
    /// a seeded register, a memory seed, or a byte of the loaded image.
    Input(Location),
    /// A step this build could not decode, so what it read is unknown. Self
    /// modifying code, or bytes the baseline no longer holds.
    Undecodable { step: usize, address: u32 },
    /// The depth bound stopped the walk. The chain continues past here and this
    /// slice does not say where.
    DepthReached,
    /// The step budget stopped the walk, for the same reason.
    StepsReached,
    /// The seed named an execution the run never performed: the address was
    /// executed `executed` times and the question asked about the
    /// `occurrence`-th.
    ///
    /// This is a fact about an *execution*, which is why it is not
    /// [`SliceStop::Input`] — that one says a byte of memory was never written,
    /// and answering an unreached instruction with it makes a claim about data
    /// for a question that was about control flow. `executed` is carried rather
    /// than left to the reader to recount, because the trace the count comes
    /// from is not part of the answer.
    NotExecuted {
        address: u32,
        occurrence: u32,
        executed: u32,
    },
}

/// One instruction the slice reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceStep {
    /// The trace row's index, which is what makes a loop unambiguous together
    /// with the address.
    pub index: usize,
    pub address: u32,
    /// How many times this address had already been executed when this row ran,
    /// counted from one.
    pub occurrence: u32,
    pub text: String,
    /// How many edges away from the seed this step was first reached.
    pub depth: usize,
    /// The locations this step defined that the slice depends on.
    pub defines: Vec<Location>,
    /// The locations this step read, as far as the model resolves them.
    pub uses: Vec<Location>,
}

/// One bounded backward slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Slice {
    pub steps: Vec<SliceStep>,
    /// Every reason a chain ended, deduplicated and in a stable order.
    pub stops: Vec<SliceStop>,
    /// Defining steps encountered by the bounded walk, including steps refused
    /// by the retention cap. This does not count unexplored dependencies.
    pub steps_total: usize,
    pub steps_truncated: bool,
    /// Whether any step's uses were over-approximated — which is every step this
    /// build decodes, and is stated rather than assumed.
    pub uses_are_a_superset: bool,
}

/// How the slice reads the instructions it walks.
///
/// The bytes are the ones the run *started* with, which is what makes this
/// possible at all: an executed trace records what each instruction did and not
/// what it was. Self-modifying code therefore ends a chain rather than being
/// followed, and it is detected rather than assumed — the re-decoded text is
/// compared against the text the trace recorded.
pub struct SliceInput<'a> {
    pub steps: &'a [Step],
    /// The register file at entry, from which every step's pre-state is
    /// reconstructed by applying the recorded deltas forward.
    pub initial: RegisterFile,
    /// The code as it stood when the run started, and the address it starts at.
    pub code: &'a [u8],
    pub code_origin: u32,
    /// Edges to follow before stopping.
    pub maximum_depth: usize,
    /// Steps to report.
    pub maximum_steps: usize,
}

/// Walk `input`'s trace backwards from `seed`.
///
/// # Errors
/// Never: an input the model cannot follow ends a chain with a stated
/// [`SliceStop`] rather than failing, because a slice that refused on meeting
/// one undecodable instruction would throw away the evidence it had already
/// gathered.
#[must_use]
pub fn slice(input: &SliceInput<'_>, seed: SliceSeed) -> Slice {
    let decoded = decode_steps(input);
    let occurrences = occurrences(input.steps);

    // What is wanted, and from which step backwards. A location is looked up in
    // the steps *before* the one asking, which is what makes the walk a walk.
    let mut wanted: Vec<(usize, Location, usize)> = Vec::new();
    let mut stops: BTreeSet<SliceStop> = BTreeSet::new();
    match seed {
        SliceSeed::Final(location) => wanted.push((input.steps.len(), location, 0)),
        SliceSeed::Instruction {
            address,
            occurrence,
        } => {
            match input
                .steps
                .iter()
                .enumerate()
                .find(|(index, step)| step.address == address && occurrences[*index] == occurrence)
            {
                Some((index, _)) => {
                    for location in decoded[index].as_ref().map_or(&[][..], |row| &row.uses) {
                        wanted.push((index, *location, 0));
                    }
                    if decoded[index].is_none() {
                        stops.insert(SliceStop::Undecodable {
                            step: index,
                            address,
                        });
                    }
                }
                // Asking about an execution that did not happen is not an
                // error: it is the answer, and the caller learns the run never
                // reached there that many times.
                None => {
                    stops.insert(SliceStop::NotExecuted {
                        address,
                        occurrence,
                        executed: input
                            .steps
                            .iter()
                            .filter(|step| step.address == address)
                            .count()
                            .try_into()
                            .unwrap_or(u32::MAX),
                    });
                }
            }
        }
    }

    let mut included: BTreeMap<usize, SliceStep> = BTreeMap::new();
    let mut asked: BTreeSet<(usize, Location)> = BTreeSet::new();
    let mut total = 0_usize;

    while let Some((before, location, depth)) = wanted.pop() {
        if !asked.insert((before, location)) {
            continue;
        }
        if depth > input.maximum_depth {
            stops.insert(SliceStop::DepthReached);
            continue;
        }
        let Some(index) = last_definition(input.steps, &decoded, before, location) else {
            stops.insert(SliceStop::Input(location));
            continue;
        };
        let Some(row) = decoded[index].as_ref() else {
            stops.insert(SliceStop::Undecodable {
                step: index,
                address: input.steps[index].address,
            });
            continue;
        };
        // Counted once per *step*, not once per edge into it. A step that
        // defines two locations the slice wants is one instruction a reader
        // reads, and charging it twice both inflates `steps_total` and spends a
        // budget the report never uses — a slice of four rows could otherwise
        // come back marked truncated with nothing left out.
        if !included.contains_key(&index) {
            total += 1;
            if total > input.maximum_steps {
                stops.insert(SliceStop::StepsReached);
                continue;
            }
        }
        let entry = included.entry(index).or_insert_with(|| SliceStep {
            index,
            address: input.steps[index].address,
            occurrence: occurrences[index],
            text: input.steps[index].text.clone(),
            depth,
            defines: Vec::new(),
            uses: row.uses.clone(),
        });
        if !entry.defines.contains(&location) {
            entry.defines.push(location);
        }
        for used in &row.uses {
            wanted.push((index, *used, depth + 1));
        }
    }

    let mut steps: Vec<SliceStep> = included.into_values().collect();
    // Newest first: a reader retracing a divergence starts at the value they
    // asked about and walks back towards its inputs, which is the order the
    // question was asked in.
    steps.sort_by_key(|step| std::cmp::Reverse(step.index));
    for step in &mut steps {
        step.defines.sort_unstable();
        step.uses.sort_unstable();
        step.uses.dedup();
    }
    let steps_truncated = total > input.maximum_steps;
    steps.truncate(input.maximum_steps);
    Slice {
        uses_are_a_superset: !steps.is_empty(),
        steps,
        stops: stops.into_iter().collect(),
        steps_total: total,
        steps_truncated,
    }
}

/// The last step before `before` that defined `location`.
fn last_definition(
    steps: &[Step],
    decoded: &[Option<Row>],
    before: usize,
    location: Location,
) -> Option<usize> {
    (0..before.min(steps.len())).rev().find(|index| {
        decoded[*index]
            .as_ref()
            .is_some_and(|row| row.defines.contains(&location))
    })
}

/// How many times each step's address had been executed when it ran, counted
/// from one.
fn occurrences(steps: &[Step]) -> Vec<u32> {
    let mut seen: BTreeMap<u32, u32> = BTreeMap::new();
    steps
        .iter()
        .map(|step| {
            let count = seen.entry(step.address).or_insert(0);
            *count += 1;
            *count
        })
        .collect()
}

/// One decoded step: what it defined and what it read.
struct Row {
    defines: Vec<Location>,
    uses: Vec<Location>,
}

/// Decode every step against the code the run started with, reconstructing the
/// register file before each one so an effective address can be resolved.
fn decode_steps(input: &SliceInput<'_>) -> Vec<Option<Row>> {
    // Padded, so an instruction at the very end of the block still has its
    // extension words to read rather than failing to decode for want of them.
    // Built once for the whole trace: a copy per row would recopy the image for
    // every instruction the run executed, which for a long trace is the whole
    // cost of the operation.
    let mut padded = input.code.to_vec();
    padded.resize(padded.len().saturating_add(10), 0);

    let mut registers = input.initial;
    let mut rows = Vec::with_capacity(input.steps.len());
    for step in input.steps {
        let before = registers;
        // The deltas the trace recorded, applied forward. The program counter is
        // taken from the next row's address rather than tracked here, and is
        // not part of any location the slice follows.
        for delta in &step.register_deltas {
            apply(&mut registers, delta);
        }
        rows.push(decode_step(input, &padded, step, &before));
    }
    rows
}

/// Apply one recorded register change.
fn apply(registers: &mut RegisterFile, delta: &crate::execute::RegisterDelta) {
    match delta.register {
        crate::execute::Register::Data(index) => {
            if let Some(cell) = registers.d.get_mut(usize::from(index)) {
                *cell = delta.after;
            }
        }
        crate::execute::Register::Address(index) => {
            if let Some(cell) = registers.a.get_mut(usize::from(index)) {
                *cell = delta.after;
            }
        }
        crate::execute::Register::Usp => registers.usp = delta.after,
        crate::execute::Register::Ssp => registers.ssp = delta.after,
        crate::execute::Register::Status => registers.sr = delta.after as u16,
    }
}

/// Decode one step, or `None` when the bytes are not the ones that ran.
fn decode_step(
    input: &SliceInput<'_>,
    padded: &[u8],
    step: &Step,
    before: &RegisterFile,
) -> Option<Row> {
    // The iterator indexes the block by address, so the block is read at the
    // step's offset within it rather than at its absolute address.
    let offset = step.address.checked_sub(input.code_origin)?;
    if usize::try_from(offset).ok()? >= input.code.len() {
        return None;
    }
    // `iter_u16` borrows its receiver mutably for the iterator's lifetime, so it
    // reads through a separate binding, as the listing's own sweep does.
    let mut memory = padded;
    let mut words = memory.iter_u16(offset);
    let instruction = Instruction::from_memory(&mut words).ok()?;
    // The proof that these are the bytes that ran. A run that rewrote its own
    // code decodes to something else here, and a chain through it ends rather
    // than being followed into a different program.
    if instruction.disassemble() != step.text {
        return None;
    }

    let mut defines = Vec::new();
    let mut uses = Vec::new();
    let isa = Isa::from(instruction.opcode);
    operand_locations(isa, instruction.operands, before, &mut defines, &mut uses);

    // Exact, and the reason the operand walk alone is not enough: a register
    // written with the value it already held produces no delta, and a register
    // the operand model did not name as a destination still changed.
    for delta in &step.register_deltas {
        if let Some(location) = location_of(delta.register)
            && !defines.contains(&location)
        {
            defines.push(location);
        }
    }
    // And the memory the bus actually saw, which is exact in both address and
    // width — unlike an address recomputed from an operand.
    for write in &step.writes {
        for byte in 0..u32::from(write.size) {
            let at = Location::Memory(write.address.wrapping_add(byte));
            if !defines.contains(&at) {
                defines.push(at);
            }
        }
    }
    Some(Row { defines, uses })
}

const fn location_of(register: crate::execute::Register) -> Option<Location> {
    match register {
        crate::execute::Register::Data(index) => Some(Location::Data(index)),
        crate::execute::Register::Address(index) => Some(Location::Address(index)),
        // The stack pointers are `A7` under two names; the slice tracks the one
        // register the program sees.
        crate::execute::Register::Usp | crate::execute::Register::Ssp => Some(Location::Address(7)),
        crate::execute::Register::Status => Some(Location::Flags),
    }
}

/// The locations one instruction's operands define and use.
///
/// Exhaustive over [`Operands`] so a variant cannot be added without deciding
/// what it reads. Uses are an over-approximation where the exact semantics would
/// name fewer; the module documentation says why that is the safe direction.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per operand shape; splitting it would hide which shapes were decided"
)]
fn operand_locations(
    isa: Isa,
    operands: Operands,
    before: &RegisterFile,
    defines: &mut Vec<Location>,
    uses: &mut Vec<Location>,
) {
    // Every instruction that sets condition codes defines the flags, and almost
    // every one does; the few that do not contribute a definition nothing reads,
    // which costs an edge the walk never takes.
    let sets_flags = !matches!(
        isa,
        Isa::Lea | Isa::Pea | Isa::Jmp | Isa::Jsr | Isa::Rts | Isa::Nop | Isa::Movem
    );
    if sets_flags {
        defines.push(Location::Flags);
    }
    match operands {
        Operands::NoOperands | Operands::Immediate(_) | Operands::Vector(_) => {}
        Operands::SizeEffectiveAddressImmediate(size, ea, _) => {
            // A modify reads as well as writes; `CMPI` only reads.
            read_ea(ea, Some(size), before, uses);
            if isa != Isa::Cmpi {
                write_ea(ea, defines);
            }
        }
        Operands::EffectiveAddressCount(ea, _) => {
            read_ea(ea, None, before, uses);
            if isa != Isa::Btst {
                write_ea(ea, defines);
            }
        }
        Operands::EffectiveAddress(ea) => match isa {
            Isa::Pea | Isa::Jmp | Isa::Jsr => address_registers(ea, uses),
            Isa::Movefsr => write_ea(ea, defines),
            _ => {
                read_ea(ea, None, before, uses);
                write_ea(ea, defines);
            }
        },
        Operands::SizeEffectiveAddress(size, ea) => {
            if isa != Isa::Clr {
                read_ea(ea, Some(size), before, uses);
            }
            if isa != Isa::Tst {
                write_ea(ea, defines);
            }
        }
        Operands::RegisterEffectiveAddress(register, ea) => {
            if isa == Isa::Lea {
                // The *address*, not the bytes there.
                address_registers(ea, uses);
                defines.push(Location::Address(register));
            } else {
                read_ea(ea, None, before, uses);
                uses.push(Location::Data(register));
                defines.push(Location::Data(register));
            }
        }
        Operands::RegisterDirectionSizeRegisterDisplacement(data, direction, _, address, _) => {
            uses.push(Location::Address(address));
            match direction {
                Direction::MemoryToRegister => defines.push(Location::Data(data)),
                _ => uses.push(Location::Data(data)),
            }
        }
        Operands::SizeRegisterEffectiveAddress(size, register, ea) => {
            read_ea(ea, Some(size), before, uses);
            defines.push(Location::Address(register));
        }
        Operands::SizeEffectiveAddressEffectiveAddress(size, destination, source) => {
            read_ea(source, Some(size), before, uses);
            write_ea(destination, defines);
        }
        Operands::RegisterOpmodeRegister(left, _, right) => {
            // `EXG` swaps, so both are read and both written. Which file each
            // is in is the opmode's business and the deltas record it exactly.
            uses.push(Location::Data(left));
            uses.push(Location::Data(right));
            uses.push(Location::Address(left));
            uses.push(Location::Address(right));
        }
        Operands::OpmodeRegister(_, register) | Operands::RegisterData(register, _) => {
            if !matches!(operands, Operands::RegisterData(_, _)) {
                uses.push(Location::Data(register));
            }
            defines.push(Location::Data(register));
        }
        Operands::RegisterDisplacement(register, _) => {
            // `LINK` pushes the register and reads the stack pointer.
            uses.push(Location::Address(register));
            uses.push(Location::Address(7));
            defines.push(Location::Address(register));
            defines.push(Location::Address(7));
        }
        Operands::Register(register) => {
            uses.push(Location::Data(register));
            uses.push(Location::Address(register));
            defines.push(Location::Data(register));
            defines.push(Location::Address(register));
        }
        Operands::DirectionRegister(_, register) => {
            uses.push(Location::Address(register));
            defines.push(Location::Address(register));
        }
        Operands::DirectionSizeEffectiveAddressList(direction, size, ea, list) => {
            // Every register the list names, in whichever direction. The bytes
            // are covered by the recorded writes for a store, and by the EA for
            // a load — the exact per-register addresses are not recomputed here,
            // which is the one place the over-approximation is coarse and is
            // recorded in the module documentation.
            address_registers(ea, uses);
            let _ = size;
            for index in 0..8_u8 {
                if list >> index & 1 == 1 || list >> (index + 8) & 1 == 1 {
                    match direction {
                        Direction::MemoryToRegister => {
                            defines.push(Location::Data(index));
                            defines.push(Location::Address(index));
                        }
                        _ => {
                            uses.push(Location::Data(index));
                            uses.push(Location::Address(index));
                        }
                    }
                }
            }
        }
        Operands::DataSizeEffectiveAddress(_, size, ea) => {
            read_ea(ea, Some(size), before, uses);
            write_ea(ea, defines);
        }
        Operands::ConditionEffectiveAddress(_, ea) => {
            uses.push(Location::Flags);
            write_ea(ea, defines);
        }
        Operands::ConditionRegisterDisplacement(_, register, _) => {
            uses.push(Location::Flags);
            uses.push(Location::Data(register));
            defines.push(Location::Data(register));
        }
        Operands::Displacement(_) => {}
        Operands::ConditionDisplacement(_, _) => uses.push(Location::Flags),
        Operands::RegisterDirectionSizeEffectiveAddress(register, direction, size, ea) => {
            uses.push(Location::Data(register));
            read_ea(ea, Some(size), before, uses);
            match direction {
                Direction::RegisterToMemory => write_ea(ea, defines),
                _ => defines.push(Location::Data(register)),
            }
        }
        Operands::RegisterSizeEffectiveAddress(register, size, ea) => {
            uses.push(Location::Address(register));
            read_ea(ea, Some(size), before, uses);
            if isa != Isa::Cmpa {
                defines.push(Location::Address(register));
            }
        }
        Operands::RegisterSizeModeRegister(left, _, direction, right) => {
            // Register-to-register or memory-to-memory with predecrement; the
            // recorded writes carry the memory side exactly.
            match direction {
                Direction::MemoryToRegister => {
                    uses.push(Location::Address(left));
                    uses.push(Location::Address(right));
                }
                _ => {
                    uses.push(Location::Data(left));
                    uses.push(Location::Data(right));
                    defines.push(Location::Data(left));
                }
            }
            uses.push(Location::Flags);
        }
        Operands::RegisterSizeRegister(left, _, right) => {
            uses.push(Location::Address(left));
            uses.push(Location::Address(right));
        }
        Operands::DirectionEffectiveAddress(_, ea) => {
            read_ea(ea, None, before, uses);
            write_ea(ea, defines);
        }
        Operands::RotationDirectionSizeModeRegister(count, _, _, immediate, register) => {
            if !immediate {
                uses.push(Location::Data(count));
            }
            uses.push(Location::Data(register));
            defines.push(Location::Data(register));
        }
    }
}

/// The bytes an effective address reads, plus the registers that compute it.
fn read_ea(
    ea: AddressingMode,
    size: Option<Size>,
    before: &RegisterFile,
    uses: &mut Vec<Location>,
) {
    match ea {
        AddressingMode::Drd(index) => uses.push(Location::Data(index)),
        AddressingMode::Ard(index) => uses.push(Location::Address(index)),
        AddressingMode::Immediate(_) => {}
        _ => {
            address_registers(ea, uses);
            if let Some(address) = effective_address(ea, before, size) {
                for byte in 0..width(size) {
                    uses.push(Location::Memory(address.wrapping_add(byte)));
                }
            }
        }
    }
}

/// The location an effective address writes, for the register cases.
///
/// Memory destinations are deliberately not added here: the recorded writes
/// carry the address and the width the bus saw, which is exact where a
/// recomputed address is a reconstruction.
fn write_ea(ea: AddressingMode, defines: &mut Vec<Location>) {
    match ea {
        AddressingMode::Drd(index) => defines.push(Location::Data(index)),
        AddressingMode::Ard(index) => defines.push(Location::Address(index)),
        _ => {}
    }
}

/// The registers an address computation reads.
fn address_registers(ea: AddressingMode, uses: &mut Vec<Location>) {
    match ea {
        AddressingMode::Ari(index)
        | AddressingMode::Ariwpo(index)
        | AddressingMode::Ariwpr(index)
        | AddressingMode::Ariwd(index, _) => uses.push(Location::Address(index)),
        AddressingMode::Ariwi8(index, brief) => {
            uses.push(Location::Address(index));
            uses.push(index_register(brief));
        }
        AddressingMode::Pciwi8(_, brief) => uses.push(index_register(brief)),
        _ => {}
    }
}

/// The address an operand resolves to, where the model can work it out.
///
/// `None` for a mode whose address depends on state the trace does not record.
/// The post-increment and pre-decrement modes are resolved against the register
/// file *before* the step, which is where the two differ: `(An)+` reads at the
/// old value and the increment follows, while `-(An)` decrements *first* and
/// reads below it. Resolving a pre-decrement at the old value would name bytes
/// the access never touched and lose the store the load actually depended on.
fn effective_address(ea: AddressingMode, before: &RegisterFile, size: Option<Size>) -> Option<u32> {
    match ea {
        AddressingMode::Ari(index) | AddressingMode::Ariwpo(index) => {
            address_register(before, index)
        }
        AddressingMode::Ariwpr(index) => {
            Some(address_register(before, index)?.wrapping_sub(width(size)))
        }
        AddressingMode::Ariwd(index, displacement) => {
            Some(address_register(before, index)?.wrapping_add(displacement as i32 as u32))
        }
        AddressingMode::AbsShort(short) => Some(short as i16 as i32 as u32),
        AddressingMode::AbsLong(long) => Some(long),
        AddressingMode::Pciwd(pc, displacement) => {
            Some(pc.wrapping_add(displacement as i32 as u32))
        }
        // `(d8,An,Xn)` and `(d8,PC,Xn)`: base plus the sign-extended byte
        // displacement plus the index, all in wrapping 32-bit arithmetic. This
        // is the mode a table lookup uses, and a table lookup is what a reverse
        // engineer slices back through.
        AddressingMode::Ariwi8(index, brief) => Some(
            address_register(before, index)?
                .wrapping_add(brief.disp() as u32)
                .wrapping_add(index_value(before, brief)?),
        ),
        AddressingMode::Pciwi8(pc, brief) => Some(
            pc.wrapping_add(brief.disp() as u32)
                .wrapping_add(index_value(before, brief)?),
        ),
        _ => None,
    }
}

/// An address register's value before the step, with A7 read as the supervisor
/// stack pointer — which is the mode the sandbox runs in.
fn address_register(before: &RegisterFile, index: u8) -> Option<u32> {
    if index == 7 {
        Some(before.ssp)
    } else {
        before.a.get(usize::from(index)).copied()
    }
}

/// The value a brief extension word's index register contributes.
///
/// Sign-extended from a word when bit 11 is clear, which is where a missing
/// extension produces a *plausible* wrong address rather than a failure: a
/// negative word index would otherwise land 64 KiB above the table instead of
/// below it. There is no scale field to apply — that is a 68020 addition, and
/// the 68000 ignores those bits.
fn index_value(
    before: &RegisterFile,
    brief: m68000::addressing_modes::BriefExtensionWord,
) -> Option<u32> {
    // Which register it is, decoded once: `index_register` is what reports it
    // as used, and a second decoding here could name a different one.
    let value = match index_register(brief) {
        Location::Data(number) => before.d.get(usize::from(number)).copied()?,
        Location::Address(number) => address_register(before, number)?,
        // One bit selects one of the two register families, so neither of the
        // remaining locations can come out of it.
        Location::Flags | Location::Memory(_) => return None,
    };
    Some(if brief.0 & 0x0800 == 0 {
        value as u16 as i16 as i32 as u32
    } else {
        value
    })
}

/// The register a brief extension word indexes with.
fn index_register(brief: m68000::addressing_modes::BriefExtensionWord) -> Location {
    let word = brief.0;
    let index = ((word >> 12) & 0x7) as u8;
    if word & 0x8000 == 0 {
        Location::Data(index)
    } else {
        Location::Address(index)
    }
}

/// How many bytes an access of this size covers.
const fn width(size: Option<Size>) -> u32 {
    match size {
        Some(Size::Byte) => 1,
        Some(Size::Word) | None => 2,
        Some(Size::Long) => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute::{Memory, RunOptions, run};

    const LOAD: u32 = 0x1000;
    const MARKER: u32 = 0x00f0_0000;

    /// Run `code` at [`LOAD`] with a full trace, and slice it.
    fn traced(code: &[u8], seed: SliceSeed, data: [u32; 8]) -> (Slice, Vec<u8>) {
        let mut memory = Memory::new();
        memory
            .map(0, 0x3000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(LOAD, code)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut options = RunOptions::new(0x2ffc, MARKER);
        options.data = data;
        options.record_steps = true;
        options.retained_steps = None;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, crate::StopReason::Returned);

        // The code as it stood when the run started, which is what the slice
        // decodes against.
        let mut baseline = vec![0_u8; 0x3000];
        baseline[LOAD as usize..LOAD as usize + code.len()].copy_from_slice(code);
        let initial = RegisterFile {
            d: data,
            a: [0; 7],
            usp: 0,
            ssp: 0x2ff8,
            pc: LOAD,
            sr: 0x2700,
        };
        let input = SliceInput {
            steps: &execution.steps,
            initial,
            code: &baseline,
            code_origin: 0,
            maximum_depth: 64,
            maximum_steps: 64,
        };
        (
            slice(&input, seed),
            execution.steps.iter().map(|_| 0).collect(),
        )
    }

    /// A value's chain reaches back through the registers that made it, and
    /// stops at the input that was never written.
    #[test]
    fn a_register_s_chain_reaches_the_input_that_was_never_written() {
        // MOVEQ #5,D1 ; MOVE.L D1,D2 ; ADD.L D0,D2 ; RTS
        // D2 depends on D1 (the MOVEQ) and on D0, which nothing wrote: D0 is an
        // input, which is exactly what the slice exists to find.
        let code = [
            0x72, 0x05, // MOVEQ #5,D1
            0x24, 0x01, // MOVE.L D1,D2
            0xd4, 0x80, // ADD.L D0,D2
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(
            &code,
            SliceSeed::Final(Location::Data(2)),
            [7, 0, 0, 0, 0, 0, 0, 0],
        );

        let addresses: Vec<u32> = slice.steps.iter().map(|step| step.address).collect();
        assert_eq!(
            addresses,
            vec![LOAD + 4, LOAD + 2, LOAD],
            "newest first: the ADD, the MOVE it read D1 from, and the MOVEQ that set D1"
        );
        assert!(
            slice.stops.contains(&SliceStop::Input(Location::Data(0))),
            "D0 was never written, so it is an input: {:?}",
            slice.stops
        );
        assert!(slice.uses_are_a_superset);
    }

    /// A seed naming an execution past the loop's trip count says so, rather
    /// than borrowing the stop that means "no step ever wrote this byte".
    #[test]
    fn a_seed_past_the_trip_count_reports_the_executions_that_did_happen() {
        // MOVEQ #2,D0 ; SUBQ.L #1,D0 ; BNE.S -4 ; RTS — the SUBQ runs twice.
        let code = [
            0x70, 0x02, // MOVEQ #2,D0
            0x53, 0x80, // SUBQ.L #1,D0
            0x66, 0xfc, // BNE.S -4
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(
            &code,
            SliceSeed::Instruction {
                address: LOAD + 2,
                occurrence: 3,
            },
            [0; 8],
        );

        assert_eq!(
            slice.stops,
            vec![SliceStop::NotExecuted {
                address: LOAD + 2,
                occurrence: 3,
                executed: 2,
            }],
            "the one stop is about the execution, and no chain claims an unwritten byte"
        );
        assert!(
            slice.steps.is_empty(),
            "nothing influenced an execution that did not happen: {:?}",
            slice.steps
        );
    }

    /// The occurrence the run did reach is still sliced, so the stop above is
    /// the seed's answer rather than the seed's shape being unsupported.
    #[test]
    fn a_seed_within_the_trip_count_is_sliced() {
        let code = [
            0x70, 0x02, // MOVEQ #2,D0
            0x53, 0x80, // SUBQ.L #1,D0
            0x66, 0xfc, // BNE.S -4
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(
            &code,
            SliceSeed::Instruction {
                address: LOAD + 2,
                occurrence: 2,
            },
            [0; 8],
        );

        assert!(
            !slice
                .stops
                .iter()
                .any(|stop| matches!(stop, SliceStop::NotExecuted { .. })),
            "the run executed it twice: {:?}",
            slice.stops
        );
        let addresses: Vec<u32> = slice.steps.iter().map(|step| step.address).collect();
        assert!(
            addresses.contains(&(LOAD + 2)),
            "the second SUBQ read what the first one wrote: {addresses:?}"
        );
    }

    /// A table lookup reaches the instruction that wrote the entry, not just
    /// the two registers that named it.
    ///
    /// `(d8,An,Xn)` is the mode a table lookup uses, and a table lookup is what
    /// a reverse engineer slices back through. Before the index was resolved
    /// this chain stopped at A0 and D1 and never reached the store.
    #[test]
    fn a_table_read_through_an_indexed_mode_reaches_the_store_that_filled_it() {
        let code = [
            0x20, 0x7c, 0x00, 0x00, 0x20, 0x00, // MOVEA.L #$00002000,A0
            0x72, 0x01, // MOVEQ #1,D1
            0x74, 0x2a, // MOVEQ #42,D2
            0x13, 0xc2, 0x00, 0x00, 0x20, 0x01, // MOVE.B D2,($00002001).L
            0x10, 0x30, 0x10, 0x00, // MOVE.B (0,A0,D1.W),D0
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(&code, SliceSeed::Final(Location::Data(0)), [0; 8]);

        let load = slice
            .steps
            .iter()
            .find(|step| step.address == LOAD + 16)
            .expect("the indexed load");
        assert!(
            load.uses.contains(&Location::Memory(0x2001)),
            "A0 + 0 + D1.W is the table entry, and it is claimed: {:?}",
            load.uses
        );
        let addresses: Vec<u32> = slice.steps.iter().map(|step| step.address).collect();
        assert!(
            addresses.contains(&(LOAD + 10)) && addresses.contains(&(LOAD + 8)),
            "the chain reaches the store and the MOVEQ whose value it wrote: {addresses:?}"
        );
    }

    /// A negative word index is sign-extended, which is where a missing
    /// extension produces a plausible wrong address rather than a failure.
    ///
    /// D1 holds `0x0001ffff`, so the three readings are three different
    /// addresses: word and signed reaches the entry below the base, word and
    /// unsigned lands 64 KiB above it, and the whole longword further still.
    #[test]
    fn a_negative_word_index_is_sign_extended_rather_than_zero_extended() {
        let code = [
            0x20, 0x7c, 0x00, 0x00, 0x20, 0x02, // MOVEA.L #$00002002,A0
            0x22, 0x3c, 0x00, 0x01, 0xff, 0xff, // MOVE.L #$0001ffff,D1
            0x74, 0x37, // MOVEQ #55,D2
            0x13, 0xc2, 0x00, 0x00, 0x20, 0x01, // MOVE.B D2,($00002001).L
            0x10, 0x30, 0x10, 0x00, // MOVE.B (0,A0,D1.W),D0
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(&code, SliceSeed::Final(Location::Data(0)), [0; 8]);

        let load = slice
            .steps
            .iter()
            .find(|step| step.address == LOAD + 20)
            .expect("the indexed load");
        assert!(
            load.uses.contains(&Location::Memory(0x2001)),
            "0x2002 + (-1) is 0x2001: {:?}",
            load.uses
        );
        let addresses: Vec<u32> = slice.steps.iter().map(|step| step.address).collect();
        assert!(
            addresses.contains(&(LOAD + 14)),
            "and the chain reaches the store that filled it: {addresses:?}"
        );
    }

    /// A chain follows a value through memory: the load's dependency is the
    /// store, not merely the register that held the address.
    #[test]
    fn a_chain_follows_a_value_through_a_store_and_a_load() {
        // MOVEQ #9,D0 ; MOVE.W D0,($2000).L ; MOVE.W ($2000).L,D3 ; RTS
        let code = [
            0x70, 0x09, // MOVEQ #9,D0
            0x33, 0xc0, 0x00, 0x00, 0x20, 0x00, // MOVE.W D0,($00002000).L
            0x36, 0x38, 0x20, 0x00, // MOVE.W ($2000).W,D3
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(&code, SliceSeed::Final(Location::Data(3)), [0; 8]);

        let addresses: Vec<u32> = slice.steps.iter().map(|step| step.address).collect();
        assert!(
            addresses.contains(&LOAD) && addresses.contains(&(LOAD + 2)),
            "the load's chain reaches the store and the MOVEQ behind it: {addresses:?}"
        );
        // And the store is there because the load *used* the bytes it wrote,
        // which is the edge a register-only slice would not have.
        let load = slice
            .steps
            .iter()
            .find(|step| step.address == LOAD + 8)
            .expect("the load is in the slice");
        assert!(load.uses.contains(&Location::Memory(0x2000)));
    }

    /// A pre-decrement load reads *below* the register it names, and the chain
    /// finds the store that wrote those bytes.
    ///
    /// Resolving `-(A0)` at the register's value before the step would name
    /// `[0x2002]`, which nothing wrote — so the load would read as an input and
    /// the store it actually depended on would drop out of the slice entirely.
    #[test]
    fn a_pre_decrement_load_reaches_the_store_below_the_register() {
        let code = [
            0x70, 0x09, // MOVEQ #9,D0
            0x31, 0xc0, 0x20, 0x00, // MOVE.W D0,($2000).W
            0x41, 0xf8, 0x20, 0x02, // LEA ($2002).W,A0
            0x36, 0x20, // MOVE.W -(A0),D3
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(&code, SliceSeed::Final(Location::Data(3)), [0; 8]);

        let load = slice
            .steps
            .iter()
            .find(|step| step.address == LOAD + 10)
            .expect("the load is in the slice");
        assert!(
            load.uses.contains(&Location::Memory(0x2000)),
            "the access is at A0 - 2, not at A0: {:?}",
            load.uses
        );
        let addresses: Vec<u32> = slice.steps.iter().map(|step| step.address).collect();
        assert!(
            addresses.contains(&(LOAD + 2)),
            "and so the chain reaches the store: {addresses:?}"
        );
    }

    /// Every row names the occurrence as well as the address, so a loop is
    /// unambiguous.
    #[test]
    fn a_loop_s_rows_are_distinguished_by_occurrence() {
        // MOVEQ #3,D0 ; loop: SUBQ.L #1,D0 ; BNE.S loop ; RTS
        let code = [
            0x70, 0x03, // MOVEQ #3,D0
            0x53, 0x80, // SUBQ.L #1,D0
            0x66, 0xfc, // BNE.S -4
            0x4e, 0x75, // RTS
        ];
        let (slice, _) = traced(&code, SliceSeed::Final(Location::Data(0)), [0; 8]);

        let subtractions: Vec<u32> = slice
            .steps
            .iter()
            .filter(|step| step.address == LOAD + 2)
            .map(|step| step.occurrence)
            .collect();
        assert_eq!(
            subtractions,
            vec![3, 2, 1],
            "each lap is its own row, newest first"
        );
    }

    /// The depth bound is a stated stop rather than a shorter answer.
    #[test]
    fn the_depth_bound_ends_a_chain_and_says_so() {
        let code = [
            0x70, 0x01, // MOVEQ #1,D0
            0x52, 0x80, // ADDQ.L #1,D0
            0x52, 0x80, // ADDQ.L #1,D0
            0x52, 0x80, // ADDQ.L #1,D0
            0x4e, 0x75, // RTS
        ];
        let mut memory = Memory::new();
        memory
            .map(0, 0x3000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(LOAD, &code)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut options = RunOptions::new(0x2ffc, MARKER);
        options.record_steps = true;
        options.retained_steps = None;
        let execution = run(&mut memory, LOAD, &options);
        let mut baseline = vec![0_u8; 0x3000];
        baseline[LOAD as usize..LOAD as usize + code.len()].copy_from_slice(&code);
        let input = SliceInput {
            steps: &execution.steps,
            initial: RegisterFile {
                d: [0; 8],
                a: [0; 7],
                usp: 0,
                ssp: 0x2ff8,
                pc: LOAD,
                sr: 0x2700,
            },
            code: &baseline,
            code_origin: 0,
            maximum_depth: 1,
            maximum_steps: 64,
        };
        let sliced = slice(&input, SliceSeed::Final(Location::Data(0)));
        assert!(
            sliced.stops.contains(&SliceStop::DepthReached),
            "{:?}",
            sliced.stops
        );
    }
}
