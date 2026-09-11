//! Instrumented, sandboxed offline execution of MC68000 code.
//!
//! Static analysis ([`crate::control_flow`]) decodes instructions without running
//! them; this module *runs* them, over the external `m68000` interpreter, so a
//! routine's actual behaviour can be observed. Execution happens in a bounded
//! [`Memory`] sandbox with no real operating system or hardware: any access
//! outside the mapped regions traps (a [`Fault`]) instead of touching anything,
//! which keeps it a safe offline analysis tool rather than an emulator.
//!
//! [`run`] seeds registers and a stack, executes from an entry address for a
//! bounded number of steps or until the top-level routine returns, and captures a
//! step trace: for each instruction its address, disassembly, cycle count,
//! register/flag deltas, and the memory writes it performed. Each image (code
//! hunk, data hunk, stack) is mapped at its real load address and executed there,
//! so absolute operands resolve naturally — the opposite of the [`crate::Rebase`]
//! used for static traversal.

use std::num::Wrapping;
use std::ops::Range;

use amiga_hw::blitter::DmaMemory;

use m68000::cpu_details::Mc68000;
use m68000::memory_access::MemoryAccess;
use m68000::{CpuDetails, M68000, Registers};
use serde::Serialize;
use thiserror::Error;

/// Default cap on the number of instructions [`run`] executes before stopping
/// with [`StopReason::StepLimit`]. Bounds runaway loops in offline analysis.
pub const DEFAULT_MAX_STEPS: usize = 100_000;

/// Default cap on how many watchpoint-matching accesses [`run`] retains.
///
/// Three times the trace's own default row count, so a watched range can outlive
/// the trace that displays it. It is a separate budget from the step count
/// because it is not bounded by one: a device that writes memory can make one
/// instruction produce more matching accesses than a whole run makes steps.
pub const DEFAULT_RETAINED_WATCH_EVENTS: usize = 65_536;

/// Default cap on how many writes [`Memory`] retains in its log.
///
/// The log used to be complete, one entry per write executing code performs,
/// and that made a run's peak memory grow linearly with its step budget — about
/// sixty megabytes at five million steps, and more with any raise. It was the
/// last unbounded structure in a run.
///
/// It could be capped because neither reader needs it whole. A summary wants
/// the first N writes and the true count, which is what this leaves. The other
/// reader wanted every write to one page, and now collects those as they
/// happen — `amiga_env::ChipWriteLog` does exactly that — instead of asking the
/// log to have kept everything on its behalf.
///
/// Matched to the watch-event budget rather than to the trace's, because like
/// that one it bounds a list the caller did not choose the length of.
pub const DEFAULT_RETAINED_WRITES: usize = 65_536;

/// Default cap on how many trace rows a run retains.
///
/// A [`Step`] carries the instruction's text, its register deltas and its
/// writes, so the trace is the largest thing a run builds per instruction — it
/// dominated a long run's memory even after the write log was capped. The
/// default used to be `None`, meaning *keep every row*, which made an unbounded
/// structure the thing a caller got by saying nothing; every bound in this
/// module exists because the caller does not choose how long unknown code runs.
///
/// A caller that wants a different number sets [`RunOptions::retained_steps`],
/// and [`Execution::steps_traced`] counts past it either way.
pub const DEFAULT_RETAINED_STEPS: usize = 65_536;

/// A failure mapping or seeding a [`Memory`] sandbox.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MemoryError {
    /// Zero-length mappings have no addressable bytes and are rejected.
    #[error("cannot map an empty memory region at {origin:#x}")]
    Empty { origin: u32 },
    /// The inclusive bytes of a region would extend beyond address `0xffffffff`.
    #[error("mapped region [{origin:#x}..+{length:#x}] exceeds the 32-bit address space")]
    AddressOverflow { origin: u32, length: usize },
    /// A new region overlaps one already mapped.
    #[error("mapped region [{origin:#x}..+{length:#x}] overlaps an existing region")]
    Overlap { origin: u32, length: usize },
    /// A region `[address, address + length)` was not fully within one mapped region.
    #[error("region [{address:#x}..+{length:#x}] is not fully mapped")]
    OutOfRange { address: u32, length: usize },
    /// Reserving host memory for a mapped region failed.
    #[error("failed to allocate {length:#x} bytes for mapped region at {origin:#x}")]
    Allocation { origin: u32, length: usize },
}

/// The direction of a memory access.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Access {
    Read,
    Write,
}

/// Which direction(s) a watchpoint observes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum WatchAccess {
    Read,
    Write,
    Both,
}

/// An absolute half-open address range watched during execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Watchpoint {
    pub start: u32,
    pub end: u32,
    pub access: WatchAccess,
}

impl Watchpoint {
    /// Construct a non-empty, non-wrapping watchpoint.
    #[must_use]
    pub fn new(start: u32, length: u32, access: WatchAccess) -> Option<Self> {
        let end = start.checked_add(length)?;
        (start < end).then_some(Self { start, end, access })
    }

    fn matches(self, event: &MemoryAccessEvent) -> bool {
        let event_end = u64::from(event.address) + u64::from(event.size);
        let overlaps =
            u64::from(event.address) < u64::from(self.end) && u64::from(self.start) < event_end;
        let direction = matches!(
            (self.access, event.access),
            (WatchAccess::Both, _)
                | (WatchAccess::Read, Access::Read)
                | (WatchAccess::Write, Access::Write)
        );
        overlaps && direction
    }
}

/// Who performed a memory access.
///
/// Without this a consumer cannot tell a blitter fetch from the CPU read of the
/// same address, and the two mean entirely different things: one is the chipset
/// working on the program's behalf, the other is an instruction the program
/// executed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessSource {
    /// An executing instruction, or a device serving one at the CPU's request.
    #[default]
    Cpu,
    /// DMA an attached device performed itself.
    DeviceDma,
}

/// One observed memory access. For reads, `before == after`; for writes they
/// are the old and new big-endian values of the accessed width.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MemoryAccessEvent {
    pub address: u32,
    pub access: Access,
    pub size: u8,
    pub before: u32,
    pub after: u32,
    pub source: AccessSource,
}

/// An out-of-range memory access that trapped execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Fault {
    /// The absolute address the instruction tried to touch.
    pub address: u32,
    pub access: Access,
    /// Access width in bytes (1, 2, or 4).
    pub size: u8,
}

/// One memory write performed while executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MemoryWrite {
    pub address: u32,
    /// Write width in bytes (1, 2, or 4).
    pub size: u8,
    /// The stored value; only the low `size` bytes are meaningful.
    pub value: u32,
}

/// How many dirty flags one word of a [`DirtyBits`] bitmap holds.
const DIRTY_BITS_PER_WORD: usize = u64::BITS as usize;

/// One bit per byte of a [`Region`], marking the bytes something changed.
///
/// This is what [`changed_regions`] walks. Replaying the write log instead would
/// make the diff's cost scale with the *number of writes*, and a single blitter
/// operation performs tens of thousands of them from one instruction; the bitmap
/// makes the cost scale with the mapped RAM, which the recipe fixes in advance.
///
/// `len` is always the byte length of the region the bitmap belongs to, so no
/// offset [`DirtyBits::iter_set`] yields can be out of bounds for its `ram`.
#[derive(Clone, Default)]
struct DirtyBits {
    words: Vec<u64>,
    /// The number of bytes covered, so `mark` cannot set a bit past the region.
    len: usize,
}

impl DirtyBits {
    /// Room for `len` clean bytes, or `None` if the storage cannot be reserved.
    fn with_len(len: usize) -> Option<Self> {
        let words_needed = len.div_ceil(DIRTY_BITS_PER_WORD);
        let mut words = Vec::new();
        words.try_reserve_exact(words_needed).ok()?;
        words.resize(words_needed, 0);
        Some(Self { words, len })
    }

    /// Mark `length` bytes from in-region offset `start`, clamped to the region.
    fn mark(&mut self, start: usize, length: usize) {
        let end = start.saturating_add(length).min(self.len);
        for index in start.min(end)..end {
            self.words[index / DIRTY_BITS_PER_WORD] |= 1 << (index % DIRTY_BITS_PER_WORD);
        }
    }

    /// Copy every set bit into `target`, shifted up by `at` bytes. Used when
    /// [`Memory::map`] joins touching regions, so a merge preserves what was
    /// already changed.
    fn copy_into(&self, target: &mut Self, at: usize) {
        for index in self.iter_set() {
            target.mark(index.saturating_add(at), 1);
        }
    }

    /// The in-region offsets that are marked, ascending. Whole clean words are
    /// skipped, which is the common case for a region a routine barely touched.
    fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        self.words
            .iter()
            .enumerate()
            .filter(|&(_, &bits)| bits != 0)
            .flat_map(|(word, &bits)| {
                (0..DIRTY_BITS_PER_WORD)
                    .filter(move |bit| bits & (1 << bit) != 0)
                    .map(move |bit| word * DIRTY_BITS_PER_WORD + bit)
            })
    }
}

/// One contiguous span of mapped RAM at a fixed base address.
#[derive(Clone)]
struct Region {
    origin: u32,
    ram: Vec<u8>,
    /// Which of `ram`'s bytes have been changed since the region was mapped.
    dirty: DirtyBits,
}

impl Region {
    /// The index within this region of `[address, address + length)`, if the
    /// whole span lies inside it.
    fn contains(&self, address: u32, length: usize) -> Option<usize> {
        let start = usize::try_from(address.checked_sub(self.origin)?).ok()?;
        let end = start.checked_add(length)?;
        (end <= self.ram.len()).then_some(start)
    }

    /// One past the last mapped address, widened so the sum cannot overflow.
    fn end(&self) -> u64 {
        u64::from(self.origin) + self.ram.len() as u64
    }
}

/// A bounded, sandboxed memory image: a set of non-overlapping RAM regions, each
/// a contiguous span `[origin, origin + len)`.
///
/// Reads and writes inside a region behave as ordinary big-endian RAM; every
/// access not fully covered by one region records a [`Fault`] and is reported to
/// the CPU as a bus (Access) Error, so execution traps on unmapped memory — the
/// gap *between* two mapped hunks faults rather than reading as zero. Writes
/// performed by executing code are logged (see [`Memory::writes`]); seeding
/// writes made by the host ([`Memory::load`], [`Memory::write_long`]) are not.
///
/// ## Two records of a write, for two questions
///
/// A write to RAM does two separate things here. It appends to the **write log**,
/// which answers *what did the executing code do* and is what a trace step and
/// the boot trace read; and it sets a bit in the region's **dirty bitmap**, which
/// answers *which bytes ended up changed* and is what [`changed_regions`] walks.
///
/// They are not the same set. [`Memory::write_dma_word`] — a write an attached
/// device performed on the program's behalf, not an instruction the program
/// executed — marks dirty without logging, because one `MOVE.W` that starts a
/// blit is one thing the code did and tens of thousands of things the chipset did
/// in response, and burying the first under the second would make the log useless.
/// [`Memory::load`] does neither: a seeded image is the starting state, not a
/// change to it.
///
/// The cost of the diff follows the bitmap, so it scales with the **total mapped
/// RAM** rather than with the number of writes. That is a better bound, not a
/// free one: a recipe mapping a megabyte pays for a megabyte of bits to scan
/// however little it wrote.
///
/// ## Touching regions are one region
///
/// Two mappings that meet exactly — `region.end() == next.origin`, with no gap
/// at all — are merged by [`Memory::map`] into a single span. A `MOVE.L` whose
/// four bytes start in a CODE hunk and end in the BSS hunk mapped immediately
/// after it is a legal access to mapped memory, and faulting it would be the
/// sandbox inventing a boundary the machine does not have; a program that
/// clears a buffer spanning that seam had to be patched instruction by
/// instruction to run here.
///
/// The merge is at map time rather than at access time so that everything
/// downstream — [`Memory::slice`], [`Memory::load`], and the fault rule — sees
/// one span and cannot disagree about where it ends. What is *not* merged is
/// anything with a gap, however small: a fault between two mappings a byte
/// apart is the property the derived stack's [`Memory`] gap depends on, and it
/// is untouched.
#[derive(Clone)]
pub struct Memory {
    regions: Vec<Region>,
    /// The retained writes — at most `retained_writes` of them. Capped for the
    /// reason [`DEFAULT_RETAINED_WRITES`] gives.
    writes: Vec<MemoryWrite>,
    /// Every write executing code performed, counted whether or not it was
    /// retained, so a truncated log never reads as a complete one.
    writes_total: u64,
    /// How many writes `writes` will hold before it stops growing.
    retained_writes: usize,
    /// The retained matching accesses — see [`Memory::record_access`] for why
    /// only matching ones, and only this many, are here.
    accesses: Vec<MemoryAccessEvent>,
    /// The ranges being watched. Empty means nothing is recorded at all.
    watchpoints: Vec<Watchpoint>,
    /// How many matching accesses `accesses` will hold before it stops growing.
    retained_watch_events: usize,
    /// Every matching access, counted whether or not it was retained.
    watch_events_total: u64,
    /// The first matching access since the latch was last cleared, which the run
    /// loop does once per instruction.
    watch_latch: Option<MemoryAccessEvent>,
    last_fault: Option<Fault>,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            regions: Vec::new(),
            writes: Vec::new(),
            writes_total: 0,
            retained_writes: DEFAULT_RETAINED_WRITES,
            accesses: Vec::new(),
            watchpoints: Vec::new(),
            retained_watch_events: DEFAULT_RETAINED_WATCH_EVENTS,
            watch_events_total: 0,
            watch_latch: None,
            last_fault: None,
        }
    }
}

impl Memory {
    /// An empty sandbox with no mapped memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `len` bytes of zeroed RAM at absolute address `origin`, joining it to
    /// any region it touches exactly.
    ///
    /// # Errors
    /// [`MemoryError::Overlap`] if the new region intersects one already mapped.
    pub fn map(&mut self, origin: u32, len: usize) -> Result<(), MemoryError> {
        if len == 0 {
            return Err(MemoryError::Empty { origin });
        }
        let end = u64::from(origin) + len as u64;
        if end > u64::from(u32::MAX) + 1 {
            return Err(MemoryError::AddressOverflow {
                origin,
                length: len,
            });
        }
        if self
            .regions
            .iter()
            .any(|region| u64::from(origin) < region.end() && u64::from(region.origin) < end)
        {
            return Err(MemoryError::Overlap {
                origin,
                length: len,
            });
        }
        // The neighbours this mapping touches with no gap. Either, both, or
        // neither: a mapping placed between two existing ones joins all three
        // into a single span, which is the case a merge that only looked one
        // way would leave half done.
        let below = self
            .regions
            .iter()
            .position(|region| region.end() == u64::from(origin));
        let above = self
            .regions
            .iter()
            .position(|region| u64::from(region.origin) == end);

        // The joined span is built whole before anything already mapped is
        // disturbed, so a mapping that cannot be allocated leaves the map
        // exactly as it was rather than half-merged.
        let below_bytes = below.map_or(0, |index| self.regions[index].ram.len());
        let above_bytes = above.map_or(0, |index| self.regions[index].ram.len());
        let joined_origin = below.map_or(origin, |index| self.regions[index].origin);
        let head = below_bytes.checked_add(len);
        let total = head
            .and_then(|joined| joined.checked_add(above_bytes))
            .ok_or(MemoryError::Allocation {
                origin,
                length: len,
            })?;
        let mut ram = Vec::new();
        ram.try_reserve_exact(total)
            .map_err(|_| MemoryError::Allocation {
                origin,
                length: total,
            })?;
        if let Some(index) = below {
            ram.extend_from_slice(&self.regions[index].ram);
        }
        // The new bytes are zeroed RAM; the neighbours keep whatever they hold.
        ram.resize(total - above_bytes, 0);
        if let Some(index) = above {
            ram.extend_from_slice(&self.regions[index].ram);
        }

        // The joined bitmap is built the same way and for the same reason: a
        // merge must not lose what the neighbours already had marked, and a
        // failed allocation must leave the map untouched.
        let mut dirty = DirtyBits::with_len(total).ok_or(MemoryError::Allocation {
            origin,
            length: total,
        })?;
        if let Some(index) = below {
            self.regions[index].dirty.copy_into(&mut dirty, 0);
        }
        if let Some(index) = above {
            self.regions[index]
                .dirty
                .copy_into(&mut dirty, total - above_bytes);
        }

        // Highest index first, so removing one does not renumber the other.
        let mut merged: Vec<usize> = [below, above].into_iter().flatten().collect();
        merged.sort_unstable_by(|a, b| b.cmp(a));
        for index in merged {
            self.regions.remove(index);
        }
        self.regions.push(Region {
            origin: joined_origin,
            ram,
            dirty,
        });
        Ok(())
    }

    /// The retained writes executing code has performed, in order.
    ///
    /// A **prefix**, not the whole set: at most
    /// [`Memory::retained_writes`] of them, with
    /// [`Memory::writes_total`] counting past the cap. A reader that needs
    /// every write of some kind must collect them as they happen rather than
    /// filter this afterwards.
    #[must_use]
    pub fn writes(&self) -> &[MemoryWrite] {
        &self.writes
    }

    /// Writes executing code has performed. Always the true total.
    #[must_use]
    pub const fn writes_total(&self) -> u64 {
        self.writes_total
    }

    /// Whether more writes happened than were retained.
    #[must_use]
    pub fn writes_truncated(&self) -> bool {
        self.writes_total > self.writes.len() as u64
    }

    /// How many writes the log will retain.
    #[must_use]
    pub const fn retained_writes(&self) -> usize {
        self.retained_writes
    }

    /// Retain at most `writes` log entries. The total keeps counting either way.
    pub const fn set_retained_writes(&mut self, writes: usize) {
        self.retained_writes = writes;
    }

    /// Borrow `length` mapped bytes at absolute address `at`, or `None` if the
    /// region is not fully mapped by a single region. Reads the current RAM
    /// contents (including anything executing code wrote), so callers can recover
    /// a routine's output.
    #[must_use]
    pub fn slice(&self, at: u32, length: usize) -> Option<&[u8]> {
        let (region, start) = self.locate(at, length)?;
        self.regions[region]
            .ram
            .get(start..start.checked_add(length)?)
    }

    /// Copy `bytes` into RAM at absolute address `at`, without logging a write.
    /// Used to place a code/data image before execution.
    ///
    /// # Errors
    /// [`MemoryError::OutOfRange`] if `[at, at + bytes.len())` is not fully mapped
    /// by a single region.
    pub fn load(&mut self, at: u32, bytes: &[u8]) -> Result<(), MemoryError> {
        let (region, start) = self
            .locate(at, bytes.len())
            .ok_or(MemoryError::OutOfRange {
                address: at,
                length: bytes.len(),
            })?;
        // `locate` guarantees the whole range is in bounds.
        self.regions[region].ram[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Store a big-endian longword at absolute address `at`, without logging a
    /// write. Used to seed the stack (e.g. a return marker or call arguments).
    ///
    /// # Errors
    /// [`MemoryError::OutOfRange`] if `[at, at + 4)` is not fully mapped.
    pub fn write_long(&mut self, at: u32, value: u32) -> Result<(), MemoryError> {
        self.load(at, &value.to_be_bytes())
    }

    /// Store a big-endian word on behalf of an attached device performing DMA:
    /// it changes RAM, marks it dirty, and is observable to a watchpoint, but it
    /// never enters the write log — see the type's own documentation for why the
    /// two records differ. Returns `None` if the word is not fully mapped.
    ///
    /// A miss records **no** [`Fault`]: DMA that leaves the map is the device's
    /// own business to refuse, and inventing a CPU bus error for it would trap an
    /// instruction that accessed nothing wrong.
    pub fn write_dma_word(&mut self, address: u32, value: u16) -> Option<()> {
        let (region, start) = self.locate(address, 2)?;
        let ram = &mut self.regions[region].ram;
        let before = u32::from(u16::from_be_bytes([ram[start], ram[start + 1]]));
        ram[start..start + 2].copy_from_slice(&value.to_be_bytes());
        self.regions[region].dirty.mark(start, 2);
        self.record_access(
            address,
            Access::Write,
            2,
            before,
            u32::from(value),
            AccessSource::DeviceDma,
        );
        Some(())
    }

    /// Read a big-endian word on behalf of an attached device performing DMA.
    /// Observable to a watchpoint, and — like [`Memory::write_dma_word`] — never
    /// a CPU access and never a [`Fault`].
    pub fn read_dma_word(&mut self, address: u32) -> Option<u16> {
        let (region, start) = self.locate(address, 2)?;
        let ram = &self.regions[region].ram;
        let value = u16::from_be_bytes([ram[start], ram[start + 1]]);
        self.record_access(
            address,
            Access::Read,
            2,
            u32::from(value),
            u32::from(value),
            AccessSource::DeviceDma,
        );
        Some(value)
    }

    /// Every mapped span as `(origin, length)`, ascending.
    ///
    /// Regions are stored in mapping order and touching ones are merged, so this
    /// is the map as it actually is rather than as it was requested — which is
    /// what a caller checking whether a device range collides with RAM needs.
    #[must_use]
    pub fn mapped_spans(&self) -> Vec<(u32, u32)> {
        let mut spans: Vec<(u32, u32)> = self
            .regions
            .iter()
            .filter_map(|region| {
                u32::try_from(region.ram.len())
                    .ok()
                    .map(|len| (region.origin, len))
            })
            .collect();
        spans.sort_unstable();
        spans
    }

    /// The region index and in-region offset of `[address, address + length)`,
    /// if a single mapped region fully contains it.
    fn locate(&self, address: u32, length: usize) -> Option<(usize, usize)> {
        self.regions.iter().enumerate().find_map(|(index, region)| {
            region.contains(address, length).map(|start| (index, start))
        })
    }

    /// Resolve an access for the CPU: the region index and in-region offset, or
    /// `None` after recording a [`Fault`] when the span is not mapped.
    fn access(&mut self, address: u32, access: Access, size: u8) -> Option<(usize, usize)> {
        match self.locate(address, usize::from(size)) {
            Some(found) => Some(found),
            None => {
                self.last_fault = Some(Fault {
                    address,
                    access,
                    size,
                });
                None
            }
        }
    }
}

impl MemoryAccess for Memory {
    fn get_byte(&mut self, addr: u32) -> Option<u8> {
        let (region, start) = self.access(addr, Access::Read, 1)?;
        let value = self.regions[region].ram[start];
        self.record_read(addr, 1, u32::from(value));
        Some(value)
    }

    fn get_word(&mut self, addr: u32) -> Option<u16> {
        let (region, start) = self.access(addr, Access::Read, 2)?;
        let ram = &self.regions[region].ram;
        let value = u16::from_be_bytes([ram[start], ram[start + 1]]);
        self.record_read(addr, 2, u32::from(value));
        Some(value)
    }

    fn get_long(&mut self, addr: u32) -> Option<u32> {
        let (region, start) = self.access(addr, Access::Read, 4)?;
        let ram = &self.regions[region].ram;
        let value =
            u32::from_be_bytes([ram[start], ram[start + 1], ram[start + 2], ram[start + 3]]);
        self.record_read(addr, 4, value);
        Some(value)
    }

    fn set_byte(&mut self, addr: u32, value: u8) -> Option<()> {
        let (region, start) = self.access(addr, Access::Write, 1)?;
        let before = u32::from(self.regions[region].ram[start]);
        self.regions[region].ram[start] = value;
        self.regions[region].dirty.mark(start, 1);
        self.record_write(addr, 1, u32::from(value));
        self.record_access(
            addr,
            Access::Write,
            1,
            before,
            u32::from(value),
            AccessSource::Cpu,
        );
        Some(())
    }

    fn set_word(&mut self, addr: u32, value: u16) -> Option<()> {
        let (region, start) = self.access(addr, Access::Write, 2)?;
        let before = u32::from(u16::from_be_bytes([
            self.regions[region].ram[start],
            self.regions[region].ram[start + 1],
        ]));
        self.regions[region].ram[start..start + 2].copy_from_slice(&value.to_be_bytes());
        self.regions[region].dirty.mark(start, 2);
        self.record_write(addr, 2, u32::from(value));
        self.record_access(
            addr,
            Access::Write,
            2,
            before,
            u32::from(value),
            AccessSource::Cpu,
        );
        Some(())
    }

    fn set_long(&mut self, addr: u32, value: u32) -> Option<()> {
        let (region, start) = self.access(addr, Access::Write, 4)?;
        let before = u32::from_be_bytes([
            self.regions[region].ram[start],
            self.regions[region].ram[start + 1],
            self.regions[region].ram[start + 2],
            self.regions[region].ram[start + 3],
        ]);
        self.regions[region].ram[start..start + 4].copy_from_slice(&value.to_be_bytes());
        self.regions[region].dirty.mark(start, 4);
        self.record_write(addr, 4, value);
        self.record_access(addr, Access::Write, 4, before, value, AccessSource::Cpu);
        Some(())
    }

    fn reset_instruction(&mut self) {
        // No external hardware to reset in the sandbox.
    }
}

impl Memory {
    fn record_write(&mut self, address: u32, size: u8, value: u32) {
        self.writes_total = self.writes_total.saturating_add(1);
        if self.writes.len() < self.retained_writes {
            self.writes.push(MemoryWrite {
                address,
                size,
                value,
            });
        }
    }

    fn record_read(&mut self, address: u32, size: u8, value: u32) {
        self.record_access(address, Access::Read, size, value, value, AccessSource::Cpu);
    }

    /// Record an access, if a watchpoint is watching it.
    ///
    /// The filter is here rather than in the run loop afterwards because the
    /// number of accesses one instruction can make is not bounded by anything
    /// the caller chose: an attached blitter turns a single `MOVE.W` into up to
    /// 262,144 of them. Storing every access and filtering later would mean the
    /// unbounded set had already been built.
    ///
    /// Retention is capped too, and the cap is deliberately not silent: the total
    /// keeps counting past it, so [`Bus::watch_events_truncated`] can say that
    /// the stored events are a prefix rather than the whole story. The latch is
    /// set whether or not the event was retained, which is what lets
    /// `stop_on_watch` still fire on a burst that overran the cap.
    fn record_access(
        &mut self,
        address: u32,
        access: Access,
        size: u8,
        before: u32,
        after: u32,
        source: AccessSource,
    ) {
        if self.watchpoints.is_empty() {
            return;
        }
        let event = MemoryAccessEvent {
            address,
            access,
            size,
            before,
            after,
            source,
        };
        if !self.watchpoints.iter().any(|watch| watch.matches(&event)) {
            return;
        }
        self.watch_events_total = self.watch_events_total.saturating_add(1);
        if self.watch_latch.is_none() {
            self.watch_latch = Some(event);
        }
        if self.accesses.len() < self.retained_watch_events {
            self.accesses.push(event);
        }
    }

    /// Record a device-served read into this memory's telemetry (the value came
    /// from a device, not RAM), so watchpoints still observe it.
    fn note_read(&mut self, address: u32, size: u8, value: u32) {
        self.record_access(address, Access::Read, size, value, value, AccessSource::Cpu);
    }

    /// Record a device-served write. A device has no cheap prior value, so the
    /// event's `before` is 0; a watchpoint matches on address and direction.
    fn note_device_write(&mut self, address: u32, size: u8, value: u32) {
        self.record_write(address, size, value);
        self.record_access(address, Access::Write, size, 0, value, AccessSource::Cpu);
    }

    /// Record a device-side fault so the run traps as it would on unmapped RAM.
    fn note_fault(&mut self, address: u32, access: Access, size: u8) {
        self.last_fault = Some(Fault {
            address,
            access,
            size,
        });
    }
}

/// A CPU register, for reporting a per-instruction change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Register {
    /// A data register `D0`–`D7`.
    Data(u8),
    /// An address register `A0`–`A6`.
    Address(u8),
    /// The user stack pointer.
    Usp,
    /// The supervisor stack pointer (the active SP during sandbox execution).
    Ssp,
    /// The status register.
    Status,
}

impl std::fmt::Display for Register {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(reg) => write!(formatter, "D{reg}"),
            Self::Address(reg) => write!(formatter, "A{reg}"),
            Self::Usp => formatter.write_str("USP"),
            Self::Ssp => formatter.write_str("SSP"),
            Self::Status => formatter.write_str("SR"),
        }
    }
}

/// A single register's change across one instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RegisterDelta {
    pub register: Register,
    pub before: u32,
    pub after: u32,
}

/// A stable, serializable snapshot of the whole register file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RegisterFile {
    /// Data registers `D0`–`D7`.
    pub d: [u32; 8],
    /// Address registers `A0`–`A6`.
    pub a: [u32; 7],
    /// User stack pointer.
    pub usp: u32,
    /// Supervisor stack pointer.
    pub ssp: u32,
    /// Program counter.
    pub pc: u32,
    /// Status register (packed).
    pub sr: u16,
}

impl RegisterFile {
    fn from_regs(regs: &Registers) -> Self {
        Self {
            d: std::array::from_fn(|index| regs.d[index].0),
            a: std::array::from_fn(|index| regs.a[index].0),
            usp: regs.usp.0,
            ssp: regs.ssp.0,
            pc: regs.pc.0,
            sr: u16::from(regs.sr),
        }
    }
}

/// Why [`run`] stopped executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum StopReason {
    /// The top-level routine executed `RTS` and popped the seeded return marker.
    Returned,
    /// The step budget ([`RunOptions::max_steps`]) was exhausted.
    StepLimit,
    /// A `STOP` instruction halted the CPU.
    Stopped,
    /// An unmapped memory access at instruction `site` trapped execution.
    Fault { fault: Fault, site: u32 },
    /// An exception vector (illegal instruction, zero divide, TRAP, …) other than
    /// an unmapped-memory access was raised at instruction `site`.
    Trap { vector: u8, site: u32 },
    /// Execution reached an address a [`Breakpoints`] host was told to stop at.
    ///
    /// The instruction there has *not* executed: `site` is where the machine is
    /// now, so a resumed run continues by executing it.
    Breakpoint { site: u32 },
    /// A watched access matched and stop-on-watch was requested.
    Watch { event: MemoryAccessEvent, site: u32 },
    /// A [`Host`] was asked to service a call it does not implement (`site` is
    /// the vector address; `offset` is its signed library-vector offset).
    UnhandledCall { site: u32, offset: i16 },
}

/// One executed instruction and the effects it produced.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Step {
    /// Zero-based index of the executing iteration. A [`Host`] that services a
    /// call (an emulated OS vector) advances this counter without adding a
    /// `Step`, so `index` can exceed the step's position in [`Execution::steps`];
    /// with a [`NoHost`] the two always coincide.
    pub index: usize,
    /// Address of the instruction (its PC).
    pub address: u32,
    /// Disassembled instruction text.
    pub text: String,
    /// Cycles the instruction took.
    pub cycles: usize,
    /// Registers this instruction changed (the program counter is excluded, as
    /// it is implied by the following step's address).
    pub register_deltas: Vec<RegisterDelta>,
    /// Memory writes this instruction performed, as far as the bounded write
    /// log retained them.
    pub writes: Vec<MemoryWrite>,
    /// Whether this instruction wrote more than [`Step::writes`] lists, because
    /// the write log was already at its retention cap.
    ///
    /// Without this an empty `writes` is ambiguous: past the cap every row would
    /// assert that an instruction which wrote sixty bytes wrote nothing. A
    /// single `MOVEM` can straddle the boundary, so the flag is set on the
    /// partial row too, not only on the wholly empty ones after it.
    pub writes_truncated: bool,
    /// Accesses made by this instruction that matched a watchpoint.
    pub watch_events: Vec<MemoryAccessEvent>,
    /// The exception vector this instruction raised, if any.
    pub trap: Option<u8>,
}

/// How to seed and bound an execution.
#[derive(Clone, Debug, Serialize)]
pub struct RunOptions {
    /// Maximum instructions to execute before stopping with [`StopReason::StepLimit`].
    pub max_steps: usize,
    /// Initial values of `D0`–`D7`.
    pub data: [u32; 8],
    /// Initial values of `A0`–`A6`.
    pub address: [u32; 7],
    /// Initial stack pointer (the supervisor SP; sandbox code runs supervisor).
    pub stack_pointer: u32,
    /// Return marker pushed as the top-level return address: when the program
    /// counter reaches it, the routine has returned and execution stops.
    pub return_marker: u32,
    /// Whether to retain a per-instruction [`Step`] trace in [`Execution::steps`].
    pub record_steps: bool,
    /// How many [`Step`]s to keep, when recording. `None` keeps every one.
    ///
    /// A step row holds the instruction's disassembled text, its register
    /// deltas, and its writes, so a long run's trace is far larger than the run
    /// itself: a budget a caller can raise is only finite in instructions if it
    /// is also finite in memory. Beyond the cap the run stops disassembling
    /// altogether — the rows would be discarded, and building a `String` to
    /// throw away is the cost, not the storing.
    ///
    /// [`Execution::steps_traced`] still counts every instruction that would
    /// have been recorded, so a capped trace never reads as a short run.
    pub retained_steps: Option<usize>,
    /// Address ranges whose matching accesses are attached to trace steps.
    pub watchpoints: Vec<Watchpoint>,
    /// How many matching accesses to retain across the whole run.
    ///
    /// A watched range's traffic is not bounded by the step count: an attached
    /// device can turn one instruction into a quarter of a million matching
    /// accesses. Past the cap, recording stops and later steps' windows are
    /// legitimately empty — [`Execution::watch_events_total`] and
    /// [`Execution::watch_events_truncated`] say that this is what happened.
    pub retained_watch_events: usize,
    /// Stop after the first instruction that touches a watchpoint.
    pub stop_on_watch: bool,
    /// Dispatch guest TRAP #0–#15 vectors (32–47) after an unclaimed host trap.
    /// Disabled by default. Handlers and six-byte supervisor frames must be
    /// mapped in RAM; other exception classes still stop. Handler instructions share
    /// the ordinary step budget, and RTE restores the saved SR and PC.
    pub guest_traps: bool,
    /// Continue a machine an earlier run left, instead of entering a routine.
    ///
    /// With this set the whole register file except the program counter is
    /// restored — the data and address registers, both stack pointers, and the
    /// status register — and **no return marker is pushed**: the frame the
    /// earlier run left on the stack is still there, and a second marker would
    /// make the routine appear to return one level too early. [`stack_pointer`]
    /// is therefore not used either; the supervisor stack pointer comes from the
    /// restored file.
    ///
    /// The program counter still comes from the `entry` argument, which the
    /// caller passes as the address the earlier run stopped at. Reading it out
    /// of the file instead would make `entry` a parameter that silently does
    /// nothing on this path.
    ///
    /// [`stack_pointer`]: RunOptions::stack_pointer
    pub resume: Option<RegisterFile>,
}

impl RunOptions {
    /// Default options for the given stack pointer and return marker, with no
    /// seeded registers and the default step budget, recording a full trace.
    #[must_use]
    pub fn new(stack_pointer: u32, return_marker: u32) -> Self {
        Self {
            max_steps: DEFAULT_MAX_STEPS,
            data: [0; 8],
            address: [0; 7],
            stack_pointer,
            return_marker,
            record_steps: true,
            retained_steps: Some(DEFAULT_RETAINED_STEPS),
            watchpoints: Vec::new(),
            retained_watch_events: DEFAULT_RETAINED_WATCH_EVENTS,
            stop_on_watch: false,
            guest_traps: false,
            resume: None,
        }
    }
}

/// The result of an execution.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Execution {
    /// The per-instruction trace, if [`RunOptions::record_steps`] was set, and
    /// as many rows of it as [`RunOptions::retained_steps`] allowed.
    pub steps: Vec<Step>,
    /// Instructions that would have been traced — every executed one, when
    /// recording. Reported beside the retained rows so a capped trace can never
    /// read as a short run.
    pub steps_traced: usize,
    /// How many instructions were executed.
    pub steps_executed: usize,
    /// Every access that matched a watchpoint, whether or not it was retained in
    /// a step's window. Includes accesses a [`Host`] hook made, which no step
    /// window contains.
    pub watch_events_total: u64,
    /// Whether more accesses matched than [`RunOptions::retained_watch_events`]
    /// allowed to be kept, so the events attached to steps are a prefix.
    pub watch_events_truncated: bool,
    pub stop: StopReason,
    /// The register file when execution stopped.
    pub registers: RegisterFile,
}

/// An object-safe memory view handed to a [`Host`] hook, so an emulated call can
/// read and write the sandbox. (The `m68000::MemoryAccess` trait is not
/// dyn-compatible, so hooks cannot take `&mut dyn MemoryAccess` directly.)
pub trait HostMemory {
    /// Read a byte, or `None` on an unmapped/invalid access.
    fn read_byte(&mut self, addr: u32) -> Option<u8>;
    /// Read a big-endian word.
    fn read_word(&mut self, addr: u32) -> Option<u16>;
    /// Read a big-endian longword.
    fn read_long(&mut self, addr: u32) -> Option<u32>;
    /// Write a byte (logged like executing code's writes).
    fn write_byte(&mut self, addr: u32, value: u8) -> Option<()>;
    /// Write a big-endian word.
    fn write_word(&mut self, addr: u32, value: u16) -> Option<()>;
    /// Write a big-endian longword.
    fn write_long(&mut self, addr: u32, value: u32) -> Option<()>;
    /// Copy `bytes` into RAM without logging (a bulk transfer, e.g. a disk read).
    /// Returns `None` if the range is not fully mapped RAM.
    fn load(&mut self, at: u32, bytes: &[u8]) -> Option<()>;
}

impl HostMemory for Memory {
    fn read_byte(&mut self, addr: u32) -> Option<u8> {
        self.get_byte(addr)
    }
    fn read_word(&mut self, addr: u32) -> Option<u16> {
        self.get_word(addr)
    }
    fn read_long(&mut self, addr: u32) -> Option<u32> {
        self.get_long(addr)
    }
    fn write_byte(&mut self, addr: u32, value: u8) -> Option<()> {
        self.set_byte(addr, value)
    }
    fn write_word(&mut self, addr: u32, value: u16) -> Option<()> {
        self.set_word(addr, value)
    }
    fn write_long(&mut self, addr: u32, value: u32) -> Option<()> {
        self.set_long(addr, value)
    }
    fn load(&mut self, at: u32, bytes: &[u8]) -> Option<()> {
        Memory::load(self, at, bytes).ok()
    }
}

/// The execution substrate [`run_with_host`] drives: memory access plus the
/// telemetry the loop reads. [`Memory`] implements it directly; [`DeviceBus`]
/// layers memory-mapped devices over an inner `Memory` while forwarding that
/// same telemetry, so watchpoints and the write log still observe device access.
pub trait Bus: MemoryAccess + HostMemory {
    /// Watch these ranges, retaining at most `retained` matching accesses, and
    /// discard whatever a previous run recorded. An empty list records nothing.
    fn set_watch(&mut self, watchpoints: &[Watchpoint], retained: usize);
    /// Number of **retained** accesses so far. This is the index space the run
    /// loop windows a step by, so it must stay the stored length rather than the
    /// true total.
    fn access_count(&self) -> usize;
    /// The retained accesses. Every one of them matched a watchpoint.
    fn accesses(&self) -> &[MemoryAccessEvent];
    /// Every matching access, counted whether or not it was retained. Counts
    /// accesses a [`Host`] hook made too, which no step window contains.
    fn watch_events_total(&self) -> u64;
    /// Whether more matching accesses happened than were retained, so a consumer
    /// reading [`Bus::accesses`] knows it is holding a prefix.
    fn watch_events_truncated(&self) -> bool;
    /// Forget the first-match latch, which the run loop does once per
    /// instruction so the latch means "since this instruction started".
    fn clear_watch_latch(&mut self);
    /// The first matching access since the latch was cleared, retained or not.
    fn watch_latch(&self) -> Option<MemoryAccessEvent>;
    /// Number of *retained* writes so far — the length of the bounded prefix
    /// [`Bus::writes`] returns, which stops growing once the log is full.
    fn write_count(&self) -> usize;
    /// Every write so far, retained or not. Always the true total, which is
    /// what makes a full log distinguishable from an instruction that wrote
    /// nothing.
    fn write_total(&self) -> u64;
    /// The logged writes.
    fn writes(&self) -> &[MemoryWrite];
    /// Clear the pending fault before a step.
    fn clear_fault(&mut self);
    /// The pending fault, if the last access trapped.
    fn last_fault(&self) -> Option<Fault>;
    /// Store a longword without logging a write (seed the return marker/args).
    fn seed_long(&mut self, at: u32, value: u32);
    /// Read a longword without logging an access (a host servicing a call).
    fn peek_long(&self, at: u32) -> Option<u32>;
    /// Read a mapped RAM word without logging an access (instruction preflight).
    fn peek_word(&self, at: u32) -> Option<u16>;
}

impl Bus for Memory {
    fn set_watch(&mut self, watchpoints: &[Watchpoint], retained: usize) {
        self.watchpoints = watchpoints.to_vec();
        self.retained_watch_events = retained;
        self.accesses.clear();
        self.watch_events_total = 0;
        self.watch_latch = None;
    }
    fn access_count(&self) -> usize {
        self.accesses.len()
    }
    fn accesses(&self) -> &[MemoryAccessEvent] {
        &self.accesses
    }
    fn watch_events_total(&self) -> u64 {
        self.watch_events_total
    }
    fn watch_events_truncated(&self) -> bool {
        self.watch_events_total > self.accesses.len() as u64
    }
    fn clear_watch_latch(&mut self) {
        self.watch_latch = None;
    }
    fn watch_latch(&self) -> Option<MemoryAccessEvent> {
        self.watch_latch
    }
    fn write_count(&self) -> usize {
        self.writes.len()
    }
    fn write_total(&self) -> u64 {
        self.writes_total
    }
    fn writes(&self) -> &[MemoryWrite] {
        &self.writes
    }
    fn clear_fault(&mut self) {
        self.last_fault = None;
    }
    fn last_fault(&self) -> Option<Fault> {
        self.last_fault
    }
    fn seed_long(&mut self, at: u32, value: u32) {
        let _ = self.write_long(at, value);
    }
    fn peek_word(&self, at: u32) -> Option<u16> {
        self.slice(at, 2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn peek_long(&self, at: u32) -> Option<u32> {
        self.slice(at, 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// The sandbox's RAM satisfies the DMA contract chip models are written
/// against, so a [`Device`] that performs DMA needs nothing beyond a `&mut
/// Memory`.
///
/// `contains_word` leaves no trace of any kind — no access event, no dirty bit,
/// and in particular **no pending [`Fault`]**, which is what lets a device
/// preflight a whole transfer without the run trapping on an address it only
/// asked about.
impl DmaMemory for Memory {
    fn contains_word(&self, address: u32) -> bool {
        self.locate(address, 2).is_some()
    }

    fn read_dma_word(&mut self, address: u32) -> Option<u16> {
        Self::read_dma_word(self, address)
    }

    fn write_dma_word(&mut self, address: u32, value: u16) -> Option<()> {
        Self::write_dma_word(self, address, value)
    }
}

/// The outcome of dispatching a memory access to a [`Device`]. A typed result
/// distinguishes "not my address" from "my address, invalid access" — which an
/// `Option` could not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccess {
    /// A read produced this value.
    Value(u32),
    /// A write was accepted.
    Wrote,
    /// This address is not claimed after all; fall back to RAM.
    NotMine,
    /// The access is invalid (e.g. an unmapped register); trap it.
    Fault,
}

/// A memory-mapped device claiming a fixed address range, with side effects on
/// access. Devices carry no Amiga-OS policy themselves; the environment that
/// installs them supplies the meaning of each range.
/// Both hooks receive a DMA handle to the sandbox's RAM, because a real chip
/// does not only answer register accesses — writing `BLTSIZE` starts a blit, and
/// the blit changes memory. The handle is [`DmaMemory`] rather than
/// [`HostMemory`]: what a device does to RAM is DMA, so it marks memory dirty
/// and a watchpoint sees it, but it never enters the write log that answers
/// *what the executing code did*. It is also RAM rather than the bus, so a
/// device cannot reach another device.
pub trait Device {
    /// The half-open address range this device claims.
    fn range(&self) -> Range<u32>;
    /// Handle a read of `size` bytes at `addr` (guaranteed within [`Device::range`]).
    fn read(&mut self, addr: u32, size: u8, memory: &mut dyn DmaMemory) -> DeviceAccess;
    /// Handle a write of `size` bytes at `addr` (guaranteed within [`Device::range`]).
    fn write(
        &mut self,
        addr: u32,
        size: u8,
        value: u32,
        memory: &mut dyn DmaMemory,
    ) -> DeviceAccess;
}

/// A [`Bus`] that owns a [`Memory`] (RAM plus all its diagnostics) and dispatches
/// memory-mapped I/O to attached [`Device`]s, merging device-side reads and
/// writes into the inner memory's telemetry so watchpoints observe MMIO too.
pub struct DeviceBus {
    ram: Memory,
    devices: Vec<Box<dyn Device>>,
}

/// How a [`DeviceBus`] access resolved.
enum Served {
    Value(u32),
    Wrote,
    Fault,
    /// No device claimed the address; RAM handles it.
    Ram,
}

impl DeviceBus {
    /// Wrap `ram`, dispatching claimed ranges to devices attached later.
    #[must_use]
    pub fn new(ram: Memory) -> Self {
        Self {
            ram,
            devices: Vec::new(),
        }
    }

    /// Attach `device`, rejecting a range that is empty or overlaps a RAM region
    /// or an already-attached device.
    ///
    /// # Errors
    /// [`MemoryError::Empty`] for an empty range, [`MemoryError::Overlap`] for a
    /// range intersecting RAM or another device.
    pub fn attach(&mut self, device: Box<dyn Device>) -> Result<(), MemoryError> {
        let range = device.range();
        if range.start >= range.end {
            return Err(MemoryError::Empty {
                origin: range.start,
            });
        }
        let length = (range.end - range.start) as usize;
        for region in &self.ram.regions {
            if u64::from(range.start) < region.end()
                && u64::from(region.origin) < u64::from(range.end)
            {
                return Err(MemoryError::Overlap {
                    origin: range.start,
                    length,
                });
            }
        }
        for existing in &self.devices {
            let other = existing.range();
            if range.start < other.end && other.start < range.end {
                return Err(MemoryError::Overlap {
                    origin: range.start,
                    length,
                });
            }
        }
        self.devices.push(device);
        Ok(())
    }

    /// The inner RAM (its writes/accesses are the merged telemetry).
    #[must_use]
    pub fn ram(&self) -> &Memory {
        &self.ram
    }

    /// Seed RAM bytes between runs, as [`Memory::load`] does before one.
    ///
    /// Deliberately narrower than handing out the whole `&mut Memory`: a caller
    /// holding that could map a region over an attached device's range, and
    /// [`DeviceBus::attach`] can only check the overlap that exists when the
    /// device arrives. Loading reaches RAM alone, so an address a device claims
    /// is simply not mapped here and is refused — which is the same answer a
    /// seed written before the bus existed would have got.
    ///
    /// # Errors
    /// [`MemoryError::OutOfRange`] if the range is not fully mapped by a single
    /// RAM region.
    pub fn load(&mut self, at: u32, bytes: &[u8]) -> Result<(), MemoryError> {
        self.ram.load(at, bytes)
    }

    fn serve_read(&mut self, addr: u32, size: u8) -> Served {
        let Some(end) = addr.checked_add(u32::from(size)) else {
            return Served::Ram;
        };
        // Destructured so a device can be handed the RAM while the device list
        // is borrowed: the two are disjoint fields, and only the compiler needs
        // telling.
        let Self { ram, devices } = self;
        for device in devices.iter_mut() {
            let range = device.range();
            if !range.contains(&addr) {
                continue;
            }
            if end > range.end {
                // A word/long access straddling a device boundary faults.
                ram.note_fault(addr, Access::Read, size);
                return Served::Fault;
            }
            return match device.read(addr, size, ram) {
                DeviceAccess::Value(value) => {
                    // Truncate to the access width so the telemetry (and any
                    // watch event) records the value the CPU actually observes,
                    // not the device's wider raw return.
                    let value = truncate(value, size);
                    ram.note_read(addr, size, value);
                    Served::Value(value)
                }
                DeviceAccess::NotMine => Served::Ram,
                DeviceAccess::Wrote | DeviceAccess::Fault => {
                    ram.note_fault(addr, Access::Read, size);
                    Served::Fault
                }
            };
        }
        Served::Ram
    }

    fn serve_write(&mut self, addr: u32, size: u8, value: u32) -> Served {
        let Some(end) = addr.checked_add(u32::from(size)) else {
            return Served::Ram;
        };
        let Self { ram, devices } = self;
        for device in devices.iter_mut() {
            let range = device.range();
            if !range.contains(&addr) {
                continue;
            }
            if end > range.end {
                ram.note_fault(addr, Access::Write, size);
                return Served::Fault;
            }
            // The device acts first and the CPU's own MMIO write is recorded
            // after it, so any DMA the write provoked appears *before* the
            // instruction that provoked it. That reads backwards, and it is
            // kept rather than reordered because reordering would change MMIO
            // event order for every device; `MemoryAccessEvent::source` is what
            // makes the sequence legible either way, and a test pins it.
            return match device.write(addr, size, value, ram) {
                DeviceAccess::Wrote => {
                    ram.note_device_write(addr, size, value);
                    Served::Wrote
                }
                DeviceAccess::NotMine => Served::Ram,
                DeviceAccess::Value(_) | DeviceAccess::Fault => {
                    ram.note_fault(addr, Access::Write, size);
                    Served::Fault
                }
            };
        }
        Served::Ram
    }
}

/// Keep only the low `size` bytes of `value` (1/2/4), as the CPU sees them.
fn truncate(value: u32, size: u8) -> u32 {
    match size {
        1 => value & 0xff,
        2 => value & 0xffff,
        _ => value,
    }
}

impl MemoryAccess for DeviceBus {
    fn get_byte(&mut self, addr: u32) -> Option<u8> {
        match self.serve_read(addr, 1) {
            Served::Value(value) => Some(value as u8),
            Served::Ram => self.ram.get_byte(addr),
            Served::Fault | Served::Wrote => None,
        }
    }
    fn get_word(&mut self, addr: u32) -> Option<u16> {
        match self.serve_read(addr, 2) {
            Served::Value(value) => Some(value as u16),
            Served::Ram => self.ram.get_word(addr),
            Served::Fault | Served::Wrote => None,
        }
    }
    fn get_long(&mut self, addr: u32) -> Option<u32> {
        match self.serve_read(addr, 4) {
            Served::Value(value) => Some(value),
            Served::Ram => self.ram.get_long(addr),
            Served::Fault | Served::Wrote => None,
        }
    }
    fn set_byte(&mut self, addr: u32, value: u8) -> Option<()> {
        match self.serve_write(addr, 1, u32::from(value)) {
            Served::Wrote => Some(()),
            Served::Ram => self.ram.set_byte(addr, value),
            Served::Fault | Served::Value(_) => None,
        }
    }
    fn set_word(&mut self, addr: u32, value: u16) -> Option<()> {
        match self.serve_write(addr, 2, u32::from(value)) {
            Served::Wrote => Some(()),
            Served::Ram => self.ram.set_word(addr, value),
            Served::Fault | Served::Value(_) => None,
        }
    }
    fn set_long(&mut self, addr: u32, value: u32) -> Option<()> {
        match self.serve_write(addr, 4, value) {
            Served::Wrote => Some(()),
            Served::Ram => self.ram.set_long(addr, value),
            Served::Fault | Served::Value(_) => None,
        }
    }
    fn reset_instruction(&mut self) {}
}

impl HostMemory for DeviceBus {
    fn read_byte(&mut self, addr: u32) -> Option<u8> {
        self.get_byte(addr)
    }
    fn read_word(&mut self, addr: u32) -> Option<u16> {
        self.get_word(addr)
    }
    fn read_long(&mut self, addr: u32) -> Option<u32> {
        self.get_long(addr)
    }
    fn write_byte(&mut self, addr: u32, value: u8) -> Option<()> {
        self.set_byte(addr, value)
    }
    fn write_word(&mut self, addr: u32, value: u16) -> Option<()> {
        self.set_word(addr, value)
    }
    fn write_long(&mut self, addr: u32, value: u32) -> Option<()> {
        self.set_long(addr, value)
    }
    fn load(&mut self, at: u32, bytes: &[u8]) -> Option<()> {
        // Bulk host transfers (served disk sectors) land in RAM.
        Memory::load(&mut self.ram, at, bytes).ok()
    }
}

impl Bus for DeviceBus {
    fn set_watch(&mut self, watchpoints: &[Watchpoint], retained: usize) {
        self.ram.set_watch(watchpoints, retained);
    }
    fn access_count(&self) -> usize {
        self.ram.access_count()
    }
    fn accesses(&self) -> &[MemoryAccessEvent] {
        self.ram.accesses()
    }
    fn watch_events_total(&self) -> u64 {
        self.ram.watch_events_total()
    }
    fn watch_events_truncated(&self) -> bool {
        self.ram.watch_events_truncated()
    }
    fn clear_watch_latch(&mut self) {
        self.ram.clear_watch_latch();
    }
    fn watch_latch(&self) -> Option<MemoryAccessEvent> {
        self.ram.watch_latch()
    }
    fn write_count(&self) -> usize {
        self.ram.writes.len()
    }
    fn write_total(&self) -> u64 {
        self.ram.writes_total
    }
    fn writes(&self) -> &[MemoryWrite] {
        &self.ram.writes
    }
    fn clear_fault(&mut self) {
        self.ram.last_fault = None;
    }
    fn last_fault(&self) -> Option<Fault> {
        self.ram.last_fault
    }
    fn seed_long(&mut self, at: u32, value: u32) {
        let _ = self.ram.write_long(at, value);
    }
    fn peek_word(&self, at: u32) -> Option<u16> {
        self.ram.peek_word(at)
    }
    fn peek_long(&self, at: u32) -> Option<u32> {
        self.ram.peek_long(at)
    }
}

/// A narrow, *mutable* view of the running CPU's registers, handed to a [`Host`]
/// so an emulated call takes effect — unlike the [`RegisterFile`] snapshot.
pub struct CpuContext<'a> {
    regs: &'a mut Registers,
}

impl CpuContext<'_> {
    /// Read data register `Dindex` (0..=7).
    #[must_use]
    pub fn d(&self, index: u8) -> u32 {
        self.regs.d.get(usize::from(index)).map_or(0, |reg| reg.0)
    }
    /// Set data register `Dindex` (0..=7).
    pub fn set_d(&mut self, index: u8, value: u32) {
        if let Some(reg) = self.regs.d.get_mut(usize::from(index)) {
            *reg = Wrapping(value);
        }
    }
    /// Read address register `Aindex` (0..=6).
    #[must_use]
    pub fn a(&self, index: u8) -> u32 {
        self.regs.a.get(usize::from(index)).map_or(0, |reg| reg.0)
    }
    /// Set address register `Aindex` (0..=6).
    pub fn set_a(&mut self, index: u8, value: u32) {
        if let Some(reg) = self.regs.a.get_mut(usize::from(index)) {
            *reg = Wrapping(value);
        }
    }
    /// The active (supervisor) stack pointer.
    #[must_use]
    pub fn sp(&self) -> u32 {
        self.regs.ssp.0
    }
    /// Set the active (supervisor) stack pointer.
    pub fn set_sp(&mut self, value: u32) {
        self.regs.ssp = Wrapping(value);
    }
    /// The program counter.
    #[must_use]
    pub fn pc(&self) -> u32 {
        self.regs.pc.0
    }
    /// Set the program counter.
    pub fn set_pc(&mut self, value: u32) {
        self.regs.pc = Wrapping(value);
    }
    /// The status register, as the exception frame spells it.
    #[must_use]
    pub fn sr(&self) -> u16 {
        u16::from(self.regs.sr)
    }
}

/// What a [`Host`] hook asks [`run_with_host`] to do next.
pub enum HostAction {
    /// Let the instruction at the current PC execute normally.
    Continue,
    /// Treat the current point as a returned subroutine: pop the return address
    /// the caller pushed into PC and continue.
    ReturnFromCall,
    /// Stop the run with this reason.
    Stop(StopReason),
}

/// A policy layer over [`run_with_host`]: it advances deterministic device state
/// each step, emulates calls into claimed OS-vector addresses, and may service
/// exceptions. All hooks are generic mechanism — the Amiga-OS meaning lives in
/// the host implementation, not here.
///
/// Memory a hook reads or writes is *not* attributed to any [`Step`], and cannot
/// stop a run through [`RunOptions::stop_on_watch`]: the per-step access window
/// and the first-match latch are both captured around the executed instruction,
/// not the hooks. It is still counted in [`Execution::watch_events_total`], which
/// is the count of everything a watchpoint saw rather than of what a step shows.
/// Such writes enter the global write log and mark memory dirty, so they appear
/// in [`touched_regions`] / [`changed_regions`].
pub trait Host {
    /// Once per instruction, before it executes: advance deterministic device
    /// state (e.g. a beam counter) by step count, not by memory-read count.
    fn tick(&mut self, _cpu: &mut CpuContext, _memory: &mut dyn HostMemory) {}
    /// Whether the host emulates the routine entered at `pc` (an OS vector).
    fn claims(&self, _pc: u32) -> bool {
        false
    }
    /// Emulate the call the host claimed at `pc`: set result registers, then
    /// usually return [`HostAction::ReturnFromCall`].
    fn on_call(
        &mut self,
        _pc: u32,
        _cpu: &mut CpuContext,
        _memory: &mut dyn HostMemory,
    ) -> HostAction {
        HostAction::Continue
    }
    /// A raised exception; return `None` to let `run` apply its standard,
    /// fault-aware stop, or `Some(action)` to service and resume.
    fn on_trap(
        &mut self,
        _vector: u8,
        _site: u32,
        _cpu: &mut CpuContext,
        _memory: &mut dyn HostMemory,
    ) -> Option<HostAction> {
        None
    }
}

/// A [`Host`] with every hook at its default, so [`run_with_host`] with `NoHost`
/// is byte-for-byte identical to [`run`].
pub struct NoHost;
impl Host for NoHost {}

/// Several [`Host`]s driven as one, for a run that needs more than one policy —
/// a device that must be advanced every instruction *and* a schedule that
/// delivers interrupts, say.
///
/// Each hook composes the only way it can:
///
/// | Hook | Rule |
/// |---|---|
/// | [`Host::tick`] | every host, in order |
/// | [`Host::claims`] | true if any host claims |
/// | [`Host::on_call`] | the **first host whose `claims` is true** |
/// | [`Host::on_trap`] | the **first host that returns `Some`** |
///
/// `on_trap` has no `claims` to ask and no `pc` to ask it about, so "the first
/// that claims" is not available there; returning `Some` *is* the claim. If none
/// does, the chain returns `None` and [`run_with_host`] applies its standard
/// fault-aware stop, exactly as a single host that serviced nothing would.
pub struct HostChain<'a> {
    hosts: Vec<&'a mut dyn Host>,
}

impl<'a> HostChain<'a> {
    /// Drive `hosts` in the given order. The order matters for `on_call` and
    /// `on_trap`, where the first to answer wins.
    #[must_use]
    pub fn new(hosts: Vec<&'a mut dyn Host>) -> Self {
        Self { hosts }
    }
}

impl Host for HostChain<'_> {
    fn tick(&mut self, cpu: &mut CpuContext, memory: &mut dyn HostMemory) {
        for host in &mut self.hosts {
            host.tick(cpu, memory);
        }
    }

    fn claims(&self, pc: u32) -> bool {
        self.hosts.iter().any(|host| host.claims(pc))
    }

    fn on_call(
        &mut self,
        pc: u32,
        cpu: &mut CpuContext,
        memory: &mut dyn HostMemory,
    ) -> HostAction {
        for host in &mut self.hosts {
            if host.claims(pc) {
                return host.on_call(pc, cpu, memory);
            }
        }
        HostAction::Continue
    }

    fn on_trap(
        &mut self,
        vector: u8,
        site: u32,
        cpu: &mut CpuContext,
        memory: &mut dyn HostMemory,
    ) -> Option<HostAction> {
        for host in &mut self.hosts {
            if let Some(action) = host.on_trap(vector, site, cpu, memory) {
                return Some(action);
            }
        }
        None
    }
}

/// A [`Host`] that stops the run when execution reaches one of a set of
/// addresses, before the instruction there executes.
///
/// Built on `claims`/`on_call` rather than on a check inside the run loop,
/// because that hook is already "the host answers for this address instead of
/// the bytes there" — and a breakpoint is the smallest possible such answer.
///
/// **A breakpoint at the address a run starts from does not stop it before it
/// has executed anything.** Without that rule a run resumed at a breakpoint
/// would stop again immediately, having executed nothing, and a caller stepping
/// through a loop could never make progress. The suppression lasts only while
/// the program counter is still there: a loop that comes back to the same
/// address does stop.
pub struct Breakpoints {
    addresses: std::collections::BTreeSet<u32>,
    /// The starting address, while the machine has not left it yet.
    suppressed: Option<u32>,
}

impl Breakpoints {
    /// Stop at each of `addresses`, except at `entry` before anything has run.
    #[must_use]
    pub fn new(addresses: impl IntoIterator<Item = u32>, entry: u32) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
            suppressed: Some(entry),
        }
    }

    /// Whether any address is set: a caller can skip attaching an empty host.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

impl Host for Breakpoints {
    fn tick(&mut self, cpu: &mut CpuContext, _memory: &mut dyn HostMemory) {
        if self.suppressed != Some(cpu.pc()) {
            self.suppressed = None;
        }
    }

    fn claims(&self, pc: u32) -> bool {
        self.addresses.contains(&pc) && self.suppressed != Some(pc)
    }

    fn on_call(
        &mut self,
        pc: u32,
        _cpu: &mut CpuContext,
        _memory: &mut dyn HostMemory,
    ) -> HostAction {
        HostAction::Stop(StopReason::Breakpoint { site: pc })
    }
}

/// Where a scheduled interrupt's handler lives.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum InterruptHandler {
    /// A fixed address, for a handler a recipe knows the location of.
    Address(u32),
    /// The longword in the 68000 vector table at `vector * 4`, so the handler
    /// the *program* installed is the one that runs. Read at delivery, not at
    /// setup: initialization installs the vector before it waits on it.
    Vector(u8),
}

/// How a scheduled handler returns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum InterruptFrame {
    /// The 68000 exception frame: status register at `SP`, program counter at
    /// `SP+2`. What a handler ending in `RTE` pops, which is what a hardware
    /// vector holds.
    #[default]
    Exception,
    /// A plain return address, for a handler ending in `RTS` — the shape an
    /// exec interrupt *server* has, since exec's own handler calls the chain.
    Subroutine,
}

/// One deterministic delivery schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduledInterrupt {
    pub handler: InterruptHandler,
    /// Instructions to execute before the first delivery.
    pub after_steps: usize,
    /// Instructions between deliveries. `None` delivers once.
    pub every_steps: Option<usize>,
    /// How many times to deliver at most. `None` is as often as the step budget
    /// allows, which is already finite.
    pub deliveries: Option<usize>,
    pub frame: InterruptFrame,
}

/// One delivery that happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct InterruptDelivery {
    /// Which scheduled entry delivered.
    pub index: usize,
    /// The instruction count at which it was delivered.
    pub step: u64,
    /// The handler address that ran.
    pub handler: u32,
    /// The address it interrupted, which is where the handler returns.
    pub resume: u32,
}

/// A [`Host`] that delivers scheduled interrupts at instruction counts.
///
/// Setup code commonly sets a synchronization flag and spins until an interrupt
/// handler clears it. The beam counter advances on its own, but nothing runs the
/// handler, so otherwise valid initialization never returns — and the only way
/// through was to patch each wait branch, which changes the code being studied.
///
/// The schedule is in *instructions*, not in wall-clock or beam time, because
/// that is the one clock a sandbox can reproduce exactly: the same recipe over
/// the same bytes delivers at the same instruction on every machine.
///
/// **Deliveries never nest.** A delivery records the stack pointer of the frame
/// it pushed and refuses to deliver again until the stack has unwound past it —
/// a handler that has not returned is still running, and interrupting it would
/// build a state no schedule describes.
#[derive(Clone, Debug, Default)]
pub struct InterruptSchedule {
    entries: Vec<ScheduledInterrupt>,
    counts: Vec<usize>,
    delivered: Vec<InterruptDelivery>,
    steps: usize,
    /// The stack pointer just after the most recent frame was pushed, while a
    /// handler is still running.
    frame_sp: Option<u32>,
}

impl InterruptSchedule {
    #[must_use]
    pub fn new(entries: Vec<ScheduledInterrupt>) -> Self {
        let counts = vec![0; entries.len()];
        Self {
            entries,
            counts,
            delivered: Vec::new(),
            steps: 0,
            frame_sp: None,
        }
    }

    /// Every delivery that happened, in order.
    #[must_use]
    pub fn delivered(&self) -> &[InterruptDelivery] {
        &self.delivered
    }

    /// Whether `entry` is due at the current step count.
    fn due(&self, index: usize, entry: &ScheduledInterrupt) -> bool {
        let count = self.counts.get(index).copied().unwrap_or(0);
        if entry.deliveries.is_some_and(|limit| count >= limit) {
            return false;
        }
        if count == 0 {
            return self.steps >= entry.after_steps;
        }
        let Some(period) = entry.every_steps else {
            return false;
        };
        let Some(next) = entry.after_steps.checked_add(period.saturating_mul(count)) else {
            return false;
        };
        self.steps >= next
    }
}

impl Host for InterruptSchedule {
    fn tick(&mut self, cpu: &mut CpuContext, memory: &mut dyn HostMemory) {
        self.steps = self.steps.saturating_add(1);
        // A handler that has not returned is still running: the stack has not
        // unwound past the frame the delivery pushed.
        if let Some(frame_sp) = self.frame_sp {
            if cpu.sp() <= frame_sp {
                return;
            }
            self.frame_sp = None;
        }
        let Some(index) = (0..self.entries.len()).find(|index| {
            self.entries
                .get(*index)
                .is_some_and(|entry| self.due(*index, entry))
        }) else {
            return;
        };
        let Some(entry) = self.entries.get(index).copied() else {
            return;
        };

        // Resolved at delivery: initialization installs a vector before it waits
        // on it, so reading the table at setup would read whatever was there.
        let handler = match entry.handler {
            InterruptHandler::Address(address) => address,
            InterruptHandler::Vector(vector) => {
                match memory.read_long(u32::from(vector) * 4) {
                    Some(handler) if handler != 0 => handler,
                    // No handler installed yet. Not an error and not a skipped
                    // slot either: the schedule tries again at the next period,
                    // which is what waiting for initialization to finish means.
                    _ => return,
                }
            }
        };

        let resume = cpu.pc();
        let mut sp = cpu.sp();
        sp = sp.wrapping_sub(4);
        if memory.write_long(sp, resume).is_none() {
            return;
        }
        if matches!(entry.frame, InterruptFrame::Exception) {
            sp = sp.wrapping_sub(2);
            if memory.write_word(sp, cpu.sr()).is_none() {
                return;
            }
        }
        cpu.set_sp(sp);
        cpu.set_pc(handler);
        self.frame_sp = Some(sp);
        if let Some(count) = self.counts.get_mut(index) {
            *count += 1;
        }
        self.delivered.push(InterruptDelivery {
            index,
            step: self.steps as u64,
            handler,
            resume,
        });
    }
}

/// Pop a caller's return address off the supervisor stack into PC (an emulated
/// call resuming). Returns the faulting address if the stack read is unmapped.
fn pop_return(regs: &mut Registers, bus: &(impl Bus + ?Sized)) -> Result<(), Fault> {
    let sp = regs.ssp.0;
    let ret = bus.peek_long(sp).ok_or(Fault {
        address: sp,
        access: Access::Read,
        size: 4,
    })?;
    regs.ssp = Wrapping(sp.wrapping_add(4));
    regs.pc = Wrapping(ret);
    Ok(())
}

/// Execute from `entry` over `memory`, seeded and bounded by `options`.
///
/// The return marker is pushed onto the seeded stack, then registers and the
/// program counter are set and instructions are executed one at a time until the
/// routine returns to the marker, the step budget is exhausted, a `STOP` halts
/// the CPU, or an exception (including an unmapped memory access) traps. The
/// instruction that traps is included in the trace; nothing after it runs.
#[must_use]
pub fn run(memory: &mut Memory, entry: u32, options: &RunOptions) -> Execution {
    run_with_host(memory, entry, &mut NoHost, options)
}

/// Execute over any [`Bus`] under the control of a [`Host`]. [`run`] is this with
/// a [`NoHost`]; a richer host emulates OS calls, services traps, and advances
/// device state, letting code that touches the OS or hardware run offline.
#[must_use]
pub fn run_with_host<B: Bus>(
    bus: &mut B,
    entry: u32,
    host: &mut dyn Host,
    options: &RunOptions,
) -> Execution {
    let mut cpu = M68000::<Mc68000>::new_no_reset();
    match options.resume {
        // Continuing a machine an earlier run left. The whole file is restored
        // and nothing is pushed: the frame that run left is still on the stack,
        // and a second return marker under it would make the routine appear to
        // return one level too early.
        Some(file) => {
            for (register, value) in cpu.regs.d.iter_mut().zip(file.d) {
                *register = Wrapping(value);
            }
            for (register, value) in cpu.regs.a.iter_mut().zip(file.a) {
                *register = Wrapping(value);
            }
            cpu.regs.usp = Wrapping(file.usp);
            cpu.regs.ssp = Wrapping(file.ssp);
            cpu.regs.sr = file.sr.into();
        }
        None => {
            for (register, value) in cpu.regs.d.iter_mut().zip(options.data) {
                *register = Wrapping(value);
            }
            for (register, value) in cpu.regs.a.iter_mut().zip(options.address) {
                *register = Wrapping(value);
            }

            // Push the return marker so the top-level RTS pops it; a failed push
            // (stack out of range) simply means the first RTS faults instead,
            // which is reported.
            let stack_pointer = options.stack_pointer.wrapping_sub(4);
            bus.seed_long(stack_pointer, options.return_marker);
            cpu.regs.ssp = Wrapping(stack_pointer);
        }
    }
    cpu.regs.pc = Wrapping(entry);

    let mut steps = Vec::new();
    let mut steps_traced = 0;
    let mut steps_executed = 0;
    let mut stop = StopReason::StepLimit;
    bus.set_watch(&options.watchpoints, options.retained_watch_events);

    for index in 0..options.max_steps {
        if cpu.regs.pc.0 == options.return_marker {
            stop = StopReason::Returned;
            break;
        }

        // Advance deterministic device state before the instruction (no-op for
        // NoHost, keeping `run` unchanged).
        host.tick(
            &mut CpuContext {
                regs: &mut cpu.regs,
            },
            &mut *bus,
        );

        // If the host emulates the routine at this PC (an OS vector), service it
        // instead of executing the bytes there.
        let pc = cpu.regs.pc.0;
        if host.claims(pc) {
            let action = host.on_call(
                pc,
                &mut CpuContext {
                    regs: &mut cpu.regs,
                },
                &mut *bus,
            );
            match action {
                HostAction::ReturnFromCall => {
                    // The host performed the routine at this address instead of
                    // the bytes there, so the emulated call *is* the step.
                    steps_executed = index + 1;
                    match pop_return(&mut cpu.regs, bus) {
                        Ok(()) => continue,
                        Err(fault) => {
                            stop = StopReason::Fault { fault, site: pc };
                            break;
                        }
                    }
                }
                // Nothing ran: the host looked at this address and stopped the
                // machine in front of it. Counting it would make a breakpoint
                // consume a step of the budget it never used, and would make a
                // run split at one report more instructions than the same run
                // executed in a single pass.
                HostAction::Stop(reason) => {
                    stop = reason;
                    break;
                }
                // The instruction executes normally below, and counts there.
                HostAction::Continue => {}
            }
        }

        // The instruction's address is the pre-step program counter. The driver
        // handles guest traps synchronously, so no pending exception processing
        // displaces the program counter before a step.
        let site = cpu.regs.pc.0;
        bus.clear_fault();
        // Cleared here, after the host hooks, so the latch means "since this
        // instruction started" and a hook's own access cannot stop the run —
        // matching the hook contract documented on [`Host`].
        bus.clear_watch_latch();
        let access_start = bus.access_count();

        // Beyond the retention cap the run stops disassembling: the row would
        // be discarded, and building the text to throw it away is the cost.
        // `steps_traced` still counts it, so the total stays true.
        if options.record_steps {
            steps_traced += 1;
        }
        let retain =
            options.record_steps && options.retained_steps.is_none_or(|cap| steps.len() < cap);
        let before = cpu.regs;
        let write_start = bus.write_count();
        let write_start_total = bus.write_total();
        let vector = if retain {
            // Two starting points, because they diverge: the retained length
            // stops growing once the log is full, while the total never does.
            // Windowing from the retained length alone makes a full log look
            // like an instruction that wrote nothing.
            let (_reported, text, cycles, vector) =
                cpu.disassembler_interpreter_exception(&mut *bus);
            let writes = bus.writes()[write_start..].to_vec();
            let writes_truncated =
                bus.write_total().saturating_sub(write_start_total) > writes.len() as u64;
            // Everything retained already matched a watchpoint, so the window is
            // the answer with no filtering. Past the retention cap the window is
            // legitimately empty for an instruction that did match.
            let watch_events = bus.accesses()[access_start..].to_vec();
            steps.push(Step {
                index,
                address: site,
                text,
                cycles,
                register_deltas: register_deltas(&before, &cpu.regs),
                writes,
                writes_truncated,
                watch_events,
                trap: vector,
            });
            vector
        } else {
            // No trace requested: run without disassembling (no discarded String).
            let (_cycles, vector) = cpu.interpreter_exception(&mut *bus);
            vector
        };

        steps_executed = index + 1;
        if let Some(vector) = vector {
            // A host may service the exception and resume; otherwise apply the
            // standard, fault-aware stop (what `run`/NoHost always does).
            let standard = trap_stop(vector, site, bus.last_fault());
            match host.on_trap(
                vector,
                site,
                &mut CpuContext {
                    regs: &mut cpu.regs,
                },
                &mut *bus,
            ) {
                None => {
                    if !options.guest_traps || !(32..=47).contains(&vector) {
                        stop = standard;
                        break;
                    }
                    let dispatched = dispatch_guest_trap(&mut cpu.regs, bus, vector, site);
                    if retain && let Some(step) = steps.last_mut() {
                        step.register_deltas = register_deltas(&before, &cpu.regs);
                        step.writes = bus.writes()[write_start..].to_vec();
                        step.writes_truncated = bus.write_total().saturating_sub(write_start_total)
                            > step.writes.len() as u64;
                        step.watch_events = bus.accesses()[access_start..].to_vec();
                        if dispatched.is_ok() {
                            step.cycles += Mc68000::vector_execution_time(vector);
                        }
                    }
                    if let Err(reason) = dispatched {
                        stop = reason;
                        break;
                    }
                }
                Some(HostAction::Stop(reason)) => {
                    stop = reason;
                    break;
                }
                Some(HostAction::ReturnFromCall) => match pop_return(&mut cpu.regs, bus) {
                    Ok(()) => continue,
                    Err(fault) => {
                        stop = StopReason::Fault { fault, site };
                        break;
                    }
                },
                Some(HostAction::Continue) => continue,
            }
        }
        if cpu.stop {
            stop = StopReason::Stopped;
            break;
        }
        // The latch, not the stored window: a blit is atomic inside one
        // instruction, so a single `MOVE.W` can produce more matching accesses
        // than retention allows and leave the window empty. Reading the window
        // here would make the run fail to stop at all — a behavioural loss, not
        // a reporting one.
        if options.stop_on_watch
            && let Some(event) = bus.watch_latch()
        {
            stop = StopReason::Watch { event, site };
            break;
        }
    }

    // The return marker is detected at the top of the loop, so a routine whose
    // final RTS is the last instruction the budget allows would otherwise fall
    // out as `StepLimit`; recognise that return here too.
    if matches!(stop, StopReason::StepLimit) && cpu.regs.pc.0 == options.return_marker {
        stop = StopReason::Returned;
    }

    Execution {
        steps,
        steps_traced,
        steps_executed,
        watch_events_total: bus.watch_events_total(),
        watch_events_truncated: bus.watch_events_truncated(),
        stop,
        registers: RegisterFile::from_regs(&cpu.regs),
    }
}

/// A contiguous run of addresses something changed, carrying the final bytes now
/// stored there.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TouchedRegion {
    pub address: u32,
    pub bytes: Vec<u8>,
}

/// Coalesce every address written while producing `memory` into contiguous
/// [`TouchedRegion`]s carrying the final bytes now at those addresses (last write
/// wins).
///
/// The result is ordered by address and is the canonical "touched memory" output
/// for a golden record: it depends only on *which* bytes ended up changed and to
/// what, not on the order or width of the individual writes that produced them.
/// Writes an attached device performed by DMA count as written; a seeded image
/// ([`Memory::load`]) does not.
#[must_use]
pub fn touched_regions(memory: &Memory) -> Vec<TouchedRegion> {
    changed_regions_impl(memory, None, &[])
}

/// Return final-state regions whose bytes differ from `before`, considering only
/// addresses written while producing `memory` and excluding the supplied address
/// ranges. This is intended for stable behavioral records: transient writes that
/// restore their original value disappear, and callers can omit sandbox-private
/// regions such as the simulated stack.
#[must_use]
pub fn changed_regions(
    before: &Memory,
    memory: &Memory,
    excluded: &Range<u32>,
) -> Vec<TouchedRegion> {
    changed_regions_impl(memory, Some(before), std::slice::from_ref(excluded))
}

fn changed_regions_impl(
    memory: &Memory,
    before: Option<&Memory>,
    excluded: &[Range<u32>],
) -> Vec<TouchedRegion> {
    // Regions are pushed in mapping order, not address order, so walking them
    // ascending is what makes the result ordered by address. Within a region the
    // dirty offsets are already ascending, and regions that touch are merged at
    // map time, so no two spans reported here can be contiguous across a
    // boundary.
    let mut order: Vec<usize> = (0..memory.regions.len()).collect();
    order.sort_unstable_by_key(|&index| memory.regions[index].origin);

    let mut regions: Vec<TouchedRegion> = Vec::new();
    for index in order {
        let region = &memory.regions[index];
        for offset in region.dirty.iter_set() {
            let Some(address) = u32::try_from(offset)
                .ok()
                .and_then(|offset| region.origin.checked_add(offset))
            else {
                continue;
            };
            if excluded.iter().any(|range| range.contains(&address)) {
                continue;
            }
            // The bitmap is exactly as long as the region, so this always hits;
            // indexing would make a future edit that broke that invariant panic.
            let Some(&byte) = region.ram.get(offset) else {
                continue;
            };
            if before
                .and_then(|baseline| baseline.slice(address, 1))
                .is_some_and(|slice| slice[0] == byte)
            {
                continue;
            }
            match regions.last_mut() {
                Some(previous)
                    if previous.address.checked_add(previous.bytes.len() as u32)
                        == Some(address) =>
                {
                    previous.bytes.push(byte);
                }
                _ => regions.push(TouchedRegion {
                    address,
                    bytes: vec![byte],
                }),
            }
        }
    }
    regions
}

/// Bounded TRAP dispatch, independently expressed from MC68000UM sections
/// 6.2.4 and 6.3.5: https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf.
/// The interpreter has already advanced PC past TRAP, but has not stacked it.
/// Do not enqueue interpreter exceptions: a failed frame could otherwise trigger
/// recursive bus-error handling inside the dependency instead of a bounded stop.
fn dispatch_guest_trap<B: Bus>(
    regs: &mut Registers,
    bus: &mut B,
    vector: u8,
    site: u32,
) -> Result<(), StopReason> {
    let refused = StopReason::Trap { vector, site };
    if let Some(fault) = bus.last_fault() {
        return Err(StopReason::Fault { fault, site });
    }
    let vector_address = u32::from(vector) * 4;
    let handler = bus.peek_long(vector_address).ok_or(refused)?;
    if handler == 0 || handler & 1 != 0 {
        return Err(refused);
    }
    // Confirm an instruction word is addressable before changing the frame.
    if bus.peek_word(handler).is_none() {
        return Err(refused);
    }
    let sp = regs.ssp.0.checked_sub(6).ok_or(refused)?;
    if sp & 1 != 0 || bus.peek_long(sp).is_none() || bus.peek_long(sp + 2).is_none() {
        return Err(refused);
    }
    // Only the actual vector fetch is observable here. Preflighting the first
    // handler word must not manufacture a watch hit before that instruction.
    if bus.get_long(vector_address).is_none() {
        return Err(trap_stop(vector, site, bus.last_fault()));
    }
    // Entire frame was checked above; ordinary bus writes retain provenance,
    // watchpoint hits and dirty bytes just like writes by an instruction.
    if bus.set_long(sp + 2, regs.pc.0).is_none() || bus.set_word(sp, regs.sr.into()).is_none() {
        return Err(trap_stop(vector, site, bus.last_fault()));
    }
    regs.ssp.0 = sp;
    regs.sr.s = true;
    regs.sr.t = false;
    regs.pc.0 = handler;
    Ok(())
}

/// Classify a raised exception into a [`StopReason`]: an unmapped access recorded
/// a [`Fault`] and becomes one; anything else is a plain trap by vector.
fn trap_stop(vector: u8, site: u32, fault: Option<Fault>) -> StopReason {
    match fault {
        Some(fault) => StopReason::Fault { fault, site },
        None => StopReason::Trap { vector, site },
    }
}

/// The registers that changed between `before` and `after` (the program counter
/// is deliberately omitted, as it changes every step).
fn register_deltas(before: &Registers, after: &Registers) -> Vec<RegisterDelta> {
    let mut deltas = Vec::new();
    let mut push = |register, old: u32, new: u32| {
        if old != new {
            deltas.push(RegisterDelta {
                register,
                before: old,
                after: new,
            });
        }
    };
    for index in 0..8 {
        push(
            Register::Data(index as u8),
            before.d[index].0,
            after.d[index].0,
        );
    }
    for index in 0..7 {
        push(
            Register::Address(index as u8),
            before.a[index].0,
            after.a[index].0,
        );
    }
    push(Register::Usp, before.usp.0, after.usp.0);
    push(Register::Ssp, before.ssp.0, after.ssp.0);
    push(
        Register::Status,
        u32::from(u16::from(before.sr)),
        u32::from(u16::from(after.sr)),
    );
    deltas
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A return marker outside the test RAM, so a fetch there would fault (the
    /// run stops on it before any such fetch).
    const MARKER: u32 = 0x00f0_0000;
    const LOAD: u32 = 0x1000;

    /// Build a sandbox with a single 0x3000-byte RAM region at address 0, `code`
    /// loaded at [`LOAD`], and options whose stack sits near the top of RAM.
    fn sandbox(code: &[u8]) -> (Memory, RunOptions) {
        let mut memory = Memory::new();
        memory
            .map(0, 0x3000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(LOAD, code)
            .unwrap_or_else(|error| panic!("{error}"));
        let options = RunOptions::new(0x2ffc, MARKER);
        (memory, options)
    }

    #[test]
    fn guest_traps_are_opt_in_and_other_vectors_remain_refused() {
        for (opcode, enabled, vector) in [(0x4e40_u16, false, 32), (0x4afc, true, 4)] {
            let (mut memory, mut options) = sandbox(&opcode.to_be_bytes());
            memory
                .write_long(u32::from(vector) * 4, LOAD + 0x40)
                .unwrap();
            memory.load(LOAD + 0x40, &[0x4e, 0x73]).unwrap();
            options.guest_traps = enabled;
            let result = run(&mut memory, LOAD, &options);
            assert_eq!(result.stop, StopReason::Trap { vector, site: LOAD });
            assert_eq!(result.steps_executed, 1);
        }
    }

    #[test]
    fn guest_trap_watches_observe_the_vector_fetch_and_no_speculative_handler_read() {
        for watch_address in [32 * 4, LOAD + 0x40] {
            let (mut memory, mut options) = sandbox(&[0x4e, 0x40]);
            memory.write_long(32 * 4, LOAD + 0x40).unwrap();
            memory.load(LOAD + 0x40, &[0x4e, 0x73]).unwrap();
            options.guest_traps = true;
            options.max_steps = 1;
            options.watchpoints =
                vec![Watchpoint::new(watch_address, 2, WatchAccess::Read).unwrap()];
            options.stop_on_watch = true;
            let result = run(&mut memory, LOAD, &options);
            if watch_address == 32 * 4 {
                assert!(matches!(result.stop, StopReason::Watch { site: LOAD, .. }));
                assert_eq!(result.steps[0].watch_events[0].address, 32 * 4);
                assert_eq!(result.steps[0].watch_events[0].after, LOAD + 0x40);
            } else {
                assert_eq!(result.stop, StopReason::StepLimit);
                assert!(result.steps[0].watch_events.is_empty());
            }
        }
    }

    #[test]
    fn guest_trap_frames_restore_user_status_and_both_stacks() {
        for retained_steps in [Some(0), Some(10)] {
            let (mut memory, mut options) = sandbox(&[0x4e, 0x4f]); // TRAP #15
            memory.write_long(47 * 4, LOAD + 0x40).unwrap();
            memory.load(LOAD + 0x40, &[0x4e, 0x73]).unwrap(); // RTE
            options.guest_traps = true;
            options.retained_steps = retained_steps;
            options.max_steps = 2;
            let initial = RegisterFile {
                d: [0; 8],
                a: [0; 7],
                usp: 0x2800,
                ssp: 0x2ff8,
                pc: LOAD,
                sr: 0x0515,
            };
            options.resume = Some(initial);
            let result = run(&mut memory, LOAD, &options);
            assert_eq!(result.stop, StopReason::StepLimit);
            assert_eq!(
                result.registers,
                RegisterFile {
                    pc: LOAD + 2,
                    ..initial
                }
            );
            assert_eq!(memory.slice(0x2ff2, 2).unwrap(), &[0x05, 0x15]);
            assert_eq!(memory.peek_long(0x2ff4), Some(LOAD + 2));
        }
    }

    #[test]
    fn guest_trap_frame_writes_honor_watchpoints_even_without_retained_events() {
        let (mut memory, mut options) = sandbox(&[0x4e, 0x40]);
        memory.write_long(32 * 4, LOAD + 0x40).unwrap();
        memory.load(LOAD + 0x40, &[0x4e, 0x73]).unwrap();
        options.guest_traps = true;
        options.watchpoints = vec![Watchpoint::new(0x2ff2, 6, WatchAccess::Write).unwrap()];
        options.stop_on_watch = true;
        options.retained_watch_events = 0;
        let result = run(&mut memory, LOAD, &options);
        assert!(matches!(result.stop, StopReason::Watch { site: LOAD, .. }));
        assert_eq!(result.steps_executed, 1);
        assert_eq!(result.registers.pc, LOAD + 0x40);
    }

    #[test]
    fn guest_trap_refuses_missing_vector_table_and_invalid_frames() {
        for stack in [0, 4, 0x2003, 0x4000] {
            let (mut memory, mut options) = sandbox(&[0x4e, 0x40]);
            memory.write_long(32 * 4, LOAD + 0x40).unwrap();
            memory.load(LOAD + 0x40, &[0x4e, 0x73]).unwrap();
            options.guest_traps = true;
            options.stack_pointer = stack;
            let result = run(&mut memory, LOAD, &options);
            assert_eq!(
                result.stop,
                StopReason::Trap {
                    vector: 32,
                    site: LOAD
                }
            );
            assert!(result.steps[0].writes.is_empty());
        }
        let mut memory = Memory::new();
        memory.map(LOAD, 0x100).unwrap();
        memory.load(LOAD, &[0x4e, 0x40]).unwrap();
        let mut options = RunOptions::new(LOAD + 0x100, MARKER);
        options.guest_traps = true;
        assert_eq!(
            run(&mut memory, LOAD, &options).stop,
            StopReason::Trap {
                vector: 32,
                site: LOAD
            }
        );
    }

    #[test]
    fn runs_arithmetic_and_returns() {
        // MOVEQ #5,D0 ; ADDQ.L #3,D0 ; RTS
        let code = [0x70, 0x05, 0x56, 0x80, 0x4e, 0x75];
        let (mut memory, options) = sandbox(&code);
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.registers.d[0], 8);
        // Three steps: MOVEQ, ADDQ, RTS.
        assert_eq!(execution.steps_executed, 3);
    }

    /// A run stopped by its budget continues from exactly where it left off,
    /// and the stack it left is the stack it resumes on.
    ///
    /// The second half is what the option exists for: the first run pushed the
    /// return marker under the routine's own frame, and a resume that pushed a
    /// second marker would let the inner `RTS` end the run one level early —
    /// which reads exactly like a routine that returned.
    #[test]
    fn a_resumed_run_continues_the_machine_the_previous_one_left() {
        // MOVEQ #5,D0 ; JSR (helper) ; ADDQ.L #1,D0 ; RTS
        // helper: ADDQ.L #3,D0 ; RTS
        let code = [
            0x70, 0x05, // MOVEQ #5,D0
            0x4e, 0xb9, 0x00, 0x00, 0x10, 0x0c, // JSR $100c
            0x52, 0x80, // ADDQ.L #1,D0
            0x4e, 0x75, // RTS
            0x56, 0x80, // helper: ADDQ.L #3,D0
            0x4e, 0x75, // RTS
        ];
        let (mut memory, mut options) = sandbox(&code);
        // Stop inside the helper, one instruction after the JSR.
        options.max_steps = 2;
        let first = run(&mut memory, LOAD, &options);
        assert_eq!(first.stop, StopReason::StepLimit);
        assert_eq!(first.registers.pc, LOAD + 12);
        assert_eq!(first.registers.d[0], 5);

        let mut resumed = RunOptions::new(0, MARKER);
        resumed.resume = Some(first.registers);
        let second = run(&mut memory, first.registers.pc, &resumed);
        // The helper's RTS returned into the caller, whose own RTS then popped
        // the marker the *first* run pushed: 5 + 3 + 1.
        assert_eq!(second.stop, StopReason::Returned);
        assert_eq!(second.registers.d[0], 9);
    }

    #[test]
    fn records_a_memory_write() {
        // MOVE.W D0,(A0) ; RTS, with D0 and A0 seeded.
        let code = [0x30, 0x80, 0x4e, 0x75];
        let (mut memory, mut options) = sandbox(&code);
        options.data[0] = 0x1234;
        options.address[0] = 0x2000;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        assert!(memory.writes().contains(&MemoryWrite {
            address: 0x2000,
            size: 2,
            value: 0x1234,
        }));
        assert_eq!(memory.slice(0x2000, 2), Some(&[0x12, 0x34][..]));
        // The step trace attributes the write to the MOVE instruction.
        let move_step = &execution.steps[0];
        assert_eq!(move_step.writes.len(), 1);
        assert_eq!(move_step.address, LOAD);
    }

    #[test]
    fn watchpoint_records_old_and_new_bytes_and_stops() {
        // MOVE.W #$1234,(A0) ; RTS
        let code = [0x30, 0xbc, 0x12, 0x34, 0x4e, 0x75];
        let (mut memory, mut options) = sandbox(&code);
        options.address[0] = 0x1800;
        options.watchpoints = vec![
            Watchpoint::new(0x1800, 2, WatchAccess::Write)
                .unwrap_or_else(|| panic!("valid watchpoint")),
        ];
        options.stop_on_watch = true;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.steps_executed, 1);
        assert_eq!(execution.steps[0].watch_events.len(), 1);
        assert_eq!(execution.steps[0].watch_events[0].before, 0);
        assert_eq!(execution.steps[0].watch_events[0].after, 0x1234);
        assert!(matches!(execution.stop, StopReason::Watch { .. }));
    }

    /// `MOVEM.L D0-D7,(A0) ; RTS` — one instruction, eight longword writes.
    /// A blitter turns one instruction into tens of thousands of accesses; this
    /// is the same shape at a size a test can assert exactly.
    const BURST: [u8; 6] = [0x48, 0xd0, 0x00, 0xff, 0x4e, 0x75];
    const BURST_TARGET: u32 = 0x2000;

    fn burst_sandbox() -> (Memory, RunOptions) {
        let (memory, mut options) = sandbox(&BURST);
        options.address[0] = BURST_TARGET;
        options.watchpoints = vec![
            Watchpoint::new(BURST_TARGET, 32, WatchAccess::Write)
                .unwrap_or_else(|| panic!("valid watchpoint")),
        ];
        (memory, options)
    }

    #[test]
    fn a_burst_past_the_retention_cap_still_stops_and_reports_its_first_access() {
        // The case that made the latch necessary. `stop_on_watch` used to be
        // decided by re-reading the stored window after the instruction, so an
        // instruction whose matches all overran the cap left an empty window and
        // the run did not stop at all — losing behaviour, not just reporting.
        let (mut memory, mut options) = burst_sandbox();
        options.retained_watch_events = 1;
        options.stop_on_watch = true;
        let execution = run(&mut memory, LOAD, &options);

        let StopReason::Watch { event, site } = execution.stop else {
            panic!("expected a watch stop, got {:?}", execution.stop);
        };
        assert_eq!(site, LOAD);
        assert_eq!(
            event.address, BURST_TARGET,
            "the reported event must be the first match, not whichever one survived retention"
        );
        assert_eq!(event.access, Access::Write);
        assert_eq!(execution.steps_executed, 1);
        assert_eq!(execution.watch_events_total, 8);
        assert!(execution.watch_events_truncated);
        assert_eq!(execution.steps[0].watch_events.len(), 1);
    }

    #[test]
    fn a_truncated_burst_says_so_and_the_run_continues() {
        let (mut memory, mut options) = burst_sandbox();
        options.retained_watch_events = 3;
        let execution = run(&mut memory, LOAD, &options);

        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.watch_events_total, 8);
        assert!(execution.watch_events_truncated);
        assert_eq!(execution.steps[0].watch_events.len(), 3);
        // Retained events are the first three, in the order they happened.
        let addresses: Vec<u32> = execution.steps[0]
            .watch_events
            .iter()
            .map(|event| event.address)
            .collect();
        assert_eq!(addresses, vec![0x2000, 0x2004, 0x2008]);
    }

    #[test]
    fn an_untruncated_run_reports_every_match_and_no_truncation() {
        let (mut memory, options) = burst_sandbox();
        let execution = run(&mut memory, LOAD, &options);

        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.watch_events_total, 8);
        assert!(!execution.watch_events_truncated);
        assert_eq!(execution.steps[0].watch_events.len(), 8);
    }

    #[test]
    fn accesses_that_match_nothing_are_never_stored() {
        // Filtering at record time is what bounds the log; storing everything
        // and filtering afterwards would mean the unbounded set already existed.
        let (mut memory, mut options) = burst_sandbox();
        options.watchpoints = vec![
            Watchpoint::new(0x2800, 2, WatchAccess::Write)
                .unwrap_or_else(|| panic!("valid watchpoint")),
        ];
        let execution = run(&mut memory, LOAD, &options);

        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.watch_events_total, 0);
        assert!(!execution.watch_events_truncated);
        assert_eq!(memory.access_count(), 0);
    }

    /// A host that writes a watched word from its `tick` hook, before every
    /// instruction.
    struct Meddler;

    impl Host for Meddler {
        fn tick(&mut self, _cpu: &mut CpuContext, memory: &mut dyn HostMemory) {
            let _ = memory.write_word(0x2400, 0x1234);
        }
    }

    #[test]
    fn a_host_hooks_access_is_counted_but_cannot_stop_the_run() {
        // The latch is cleared after the hooks and before the instruction, so it
        // means "since this instruction started" — which is what keeps the
        // documented hook contract true now that the stop reads the latch.
        let code = [0x70, 0x2a, 0x4e, 0x75]; // MOVEQ #42,D0 ; RTS
        let (mut memory, mut options) = sandbox(&code);
        options.watchpoints = vec![
            Watchpoint::new(0x2400, 2, WatchAccess::Write)
                .unwrap_or_else(|| panic!("valid watchpoint")),
        ];
        options.stop_on_watch = true;
        let execution = run_with_host(&mut memory, LOAD, &mut Meddler, &options);

        assert_eq!(execution.stop, StopReason::Returned);
        assert!(execution.watch_events_total >= 2, "one per instruction");
        for step in &execution.steps {
            assert!(
                step.watch_events.is_empty(),
                "a hook's access belongs to no step"
            );
        }
    }

    #[test]
    fn traps_on_an_unmapped_write() {
        // MOVE.W D0,(A0) ; RTS, with A0 pointing outside the mapped RAM.
        let code = [0x30, 0x80, 0x4e, 0x75];
        let (mut memory, mut options) = sandbox(&code);
        options.address[0] = 0x0010_0000;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(
            execution.stop,
            StopReason::Fault {
                fault: Fault {
                    address: 0x0010_0000,
                    access: Access::Write,
                    size: 2,
                },
                site: LOAD,
            }
        );
    }

    #[test]
    fn faults_in_the_gap_between_two_regions() {
        // Two non-adjacent regions leave a gap that must fault, not read as zero.
        let mut memory = Memory::new();
        memory
            .map(0, 0x2000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .map(0x4000, 0x1000)
            .unwrap_or_else(|error| panic!("{error}"));
        // MOVE.W (A0),D0 ; RTS, with A0 in the unmapped gap.
        let code = [0x30, 0x10, 0x4e, 0x75];
        memory
            .load(0x100, &code)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut options = RunOptions::new(0x1ffc, MARKER);
        options.address[0] = 0x3000;
        let execution = run(&mut memory, 0x100, &options);
        assert!(matches!(
            execution.stop,
            StopReason::Fault {
                fault: Fault {
                    address: 0x3000,
                    access: Access::Read,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_overlapping_regions() {
        let mut memory = Memory::new();
        memory
            .map(0, 0x2000)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            memory.map(0x1000, 0x1000),
            Err(MemoryError::Overlap { .. })
        ));
    }

    #[test]
    fn rejects_empty_and_wrapping_regions() {
        let mut memory = Memory::new();
        assert_eq!(
            memory.map(0x1000, 0),
            Err(MemoryError::Empty { origin: 0x1000 })
        );
        assert!(matches!(
            memory.map(0xffff_fff0, 0x20),
            Err(MemoryError::AddressOverflow { .. })
        ));
    }

    #[test]
    fn recognises_a_return_on_the_last_allowed_step() {
        // MOVEQ #5,D0 ; RTS returns in exactly 2 instructions; with max_steps=2
        // the RTS is the last step, and the run must still report Returned.
        let code = [0x70, 0x05, 0x4e, 0x75];
        let (mut memory, mut options) = sandbox(&code);
        options.max_steps = 2;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.steps_executed, 2);
    }

    #[test]
    fn stops_at_the_step_limit() {
        // BRA.S * (an infinite self-loop).
        let code = [0x60, 0xfe];
        let (mut memory, mut options) = sandbox(&code);
        options.max_steps = 16;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::StepLimit);
        assert_eq!(execution.steps_executed, 16);
    }

    #[test]
    fn reports_register_deltas() {
        // MOVEQ #5,D0 ; RTS
        let code = [0x70, 0x05, 0x4e, 0x75];
        let (mut memory, options) = sandbox(&code);
        let execution = run(&mut memory, LOAD, &options);
        let moveq = &execution.steps[0];
        assert!(moveq.register_deltas.contains(&RegisterDelta {
            register: Register::Data(0),
            before: 0,
            after: 5,
        }));
    }

    #[test]
    fn coalesces_touched_memory() {
        // MOVE.W D0,(A0) ; MOVE.W D1,(A1) ; MOVE.B D2,(A2) ; RTS — two adjacent
        // words merge into one region; the lone byte stays separate.
        let code = [
            0x30, 0x80, // MOVE.W D0,(A0)
            0x32, 0x81, // MOVE.W D1,(A1)
            0x14, 0x82, // MOVE.B D2,(A2)
            0x4e, 0x75, // RTS
        ];
        let (mut memory, mut options) = sandbox(&code);
        options.data[0] = 0x1122;
        options.data[1] = 0x3344;
        options.data[2] = 0x55;
        options.address[0] = 0x2000;
        options.address[1] = 0x2002;
        options.address[2] = 0x2100;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        let regions = touched_regions(&memory);
        assert_eq!(
            regions,
            vec![
                TouchedRegion {
                    address: 0x2000,
                    bytes: vec![0x11, 0x22, 0x33, 0x44],
                },
                TouchedRegion {
                    address: 0x2100,
                    bytes: vec![0x55],
                },
            ]
        );
    }

    #[test]
    fn an_access_across_two_touching_mappings_is_one_access() {
        // A selected CODE hunk and the BSS hunk mapped immediately after it were
        // two bus regions, so a legal MOVE.L across their shared boundary
        // faulted even though every byte was mapped — which forced
        // instruction-width patches into code that clears a buffer spanning the
        // seam.
        let mut memory = Memory::new();
        memory
            .map(0x2000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .map(0x2100, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));

        // Two bytes either side of 0x2100.
        assert_eq!(memory.set_long(0x20fe, 0x1122_3344), Some(()));
        assert_eq!(memory.get_long(0x20fe), Some(0x1122_3344));
        assert_eq!(
            memory.slice(0x20fe, 4),
            Some(&[0x11, 0x22, 0x33, 0x44][..]),
            "a borrow across the seam still saw two spans"
        );
        assert!(memory.load(0x20ff, &[1, 2, 3]).is_ok());
    }

    #[test]
    fn a_mapping_between_two_others_joins_all_three() {
        // A merge that only looked one way would leave this half done, and the
        // access across the seam it did not close would still fault.
        let mut memory = Memory::new();
        memory
            .map(0x3000, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .map(0x3020, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(0x3020, &[0xaa; 0x10])
            .unwrap_or_else(|error| panic!("{error}"));
        // The gap is still a gap until something fills it exactly.
        assert_eq!(memory.slice(0x300e, 4), None);
        memory
            .map(0x3010, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(memory.slice(0x3000, 0x30).map(<[u8]>::len), Some(0x30));
        // The region that was pushed above kept its bytes through the merge.
        assert_eq!(memory.slice(0x3020, 1), Some(&[0xaa][..]));
    }

    #[test]
    fn a_gap_of_one_byte_still_faults() {
        // Only an exact meeting joins two mappings. The derived stack sits above
        // the hunk behind a deliberate gap, and a runaway stack faulting there
        // is what this rule must not weaken.
        let mut memory = Memory::new();
        memory
            .map(0x4000, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .map(0x4011, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(memory.get_word(0x400f), None);
        assert_eq!(memory.get_byte(0x4010), None);
        assert_eq!(memory.get_byte(0x4011), Some(0));
    }

    #[test]
    fn changed_regions_omit_restored_bytes_and_excluded_stack() {
        let mut before = Memory::new();
        before
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        before
            .map(0x2000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        before
            .load(0x1000, &[0xaa, 0xbb])
            .unwrap_or_else(|error| panic!("{error}"));
        let mut after = before.clone();
        let _ = after.set_byte(0x1000, 0xaa); // touched, but restored/original
        let _ = after.set_byte(0x1001, 0xcc); // meaningful output
        let _ = after.set_long(0x2000, 0x1234_5678); // simulated stack

        assert_eq!(
            changed_regions(&before, &after, &(0x2000..0x2100)),
            vec![TouchedRegion {
                address: 0x1001,
                bytes: vec![0xcc],
            }]
        );
    }

    #[test]
    fn a_dma_write_changes_memory_without_entering_the_write_log() {
        // The whole point of the split: one MOVE.W that starts a blit is one
        // thing the code did, and the words the chipset writes in response are
        // changes to memory that must not bury it in the log.
        let mut before = Memory::new();
        before
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut after = before.clone();
        assert_eq!(after.write_dma_word(0x1010, 0xbeef), Some(()));

        assert_eq!(
            changed_regions(&before, &after, &(0..0)),
            vec![TouchedRegion {
                address: 0x1010,
                bytes: vec![0xbe, 0xef],
            }]
        );
        assert!(
            after.writes().is_empty(),
            "a DMA write is not something the executing code did"
        );
    }

    #[test]
    fn a_dma_write_outside_the_map_changes_nothing_and_raises_no_fault() {
        let mut memory = Memory::new();
        memory
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        // Straddling the end of the region is as unmapped as missing it entirely.
        assert_eq!(memory.write_dma_word(0x10ff, 0xbeef), None);
        assert_eq!(memory.write_dma_word(0x2000, 0xbeef), None);
        assert_eq!(
            memory.last_fault(),
            None,
            "DMA off the map is the device's refusal, not a CPU bus error"
        );
        assert!(touched_regions(&memory).is_empty());
    }

    #[test]
    fn a_write_spanning_a_merged_region_boundary_is_one_changed_region() {
        // The bytes either side of the seam live in different regions until the
        // merge, so a bitmap that did not merge with them would report the write
        // as two spans — or lose half of it.
        let mut memory = Memory::new();
        memory
            .map(0x2000, 0x40)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .map(0x2040, 0x40)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(memory.set_long(0x203e, 0x1122_3344), Some(()));

        assert_eq!(
            touched_regions(&memory),
            vec![TouchedRegion {
                address: 0x203e,
                bytes: vec![0x11, 0x22, 0x33, 0x44],
            }]
        );
    }

    #[test]
    fn a_merge_keeps_what_the_neighbours_had_already_changed() {
        let mut memory = Memory::new();
        memory
            .map(0x3000, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .map(0x3020, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(memory.set_byte(0x3001, 0x11), Some(()));
        assert_eq!(memory.set_byte(0x302f, 0x22), Some(()));
        // Joining all three spans must not lose either mark, and must not shift
        // the one that came from the region mapped above the new bytes.
        memory
            .map(0x3010, 0x10)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            touched_regions(&memory),
            vec![
                TouchedRegion {
                    address: 0x3001,
                    bytes: vec![0x11],
                },
                TouchedRegion {
                    address: 0x302f,
                    bytes: vec![0x22],
                },
            ]
        );
    }

    #[test]
    fn the_diff_is_bounded_by_the_map_not_by_the_number_of_writes() {
        // Replaying the write log made this quadratic in a way a blit reaches
        // easily: the same word rewritten a million times is one changed byte
        // pair, and the diff must cost the map, not the million.
        let mut before = Memory::new();
        before
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut after = before.clone();
        for index in 0..1_000_000_u32 {
            assert_eq!(after.set_word(0x1000, index as u16), Some(()));
        }

        // The log is a bounded prefix and the counter is the true answer, so a
        // run's peak memory is bounded by the map rather than by how long it
        // ran. A million writes cost a million log entries before this.
        assert_eq!(after.writes_total(), 1_000_000);
        assert_eq!(after.writes().len(), DEFAULT_RETAINED_WRITES);
        assert!(after.writes_truncated());
        assert_eq!(
            changed_regions(&before, &after, &(0..0)),
            vec![TouchedRegion {
                address: 0x1000,
                bytes: vec![0x42, 0x3f],
            }]
        );
    }

    /// Once the write log is full a trace row's window is empty, and an empty
    /// window must not read as "this instruction wrote nothing".
    ///
    /// Three `MOVEM.L D0-D7,(A1)` write eight longwords each against a retention
    /// cap of twelve, so the rows are the three cases in order: complete,
    /// partial, empty. The partial one is the reason the flag is not simply
    /// "the log was already full when this row started".
    #[test]
    fn a_trace_row_says_when_the_write_log_had_no_room_left() {
        // MOVEM.L D0-D7,(A1) ×3 ; RTS
        let movem = [0x48, 0xd1, 0x00, 0xff];
        let mut code = Vec::new();
        for _ in 0..3 {
            code.extend_from_slice(&movem);
        }
        code.extend_from_slice(&[0x4e, 0x75]);
        let (mut memory, mut options) = sandbox(&code);
        memory.set_retained_writes(12);
        options.address[1] = 0x2000;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::Returned);

        let rows: Vec<(usize, bool)> = execution.steps[..3]
            .iter()
            .map(|step| (step.writes.len(), step.writes_truncated))
            .collect();
        assert_eq!(
            rows,
            vec![(8, false), (4, true), (0, true)],
            "a full write log left trace rows claiming their instruction wrote nothing"
        );
        // The log itself is capped and still counts what it dropped, which is
        // what the per-row flag is derived from.
        assert_eq!(memory.writes().len(), 12);
        assert_eq!(memory.writes_total(), 24);
    }

    #[test]
    fn a_capped_write_log_keeps_the_first_writes_and_counts_the_rest() {
        let mut memory = Memory::new();
        memory
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        memory.set_retained_writes(4);
        for index in 0..10_u32 {
            assert_eq!(memory.set_word(0x1000 + index * 2, index as u16), Some(()));
        }
        // The prefix, not a sample: a reader of the first N writes is reading
        // what the run did first, which is what makes them worth reporting.
        assert_eq!(
            memory
                .writes()
                .iter()
                .map(|write| write.address)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x1002, 0x1004, 0x1006]
        );
        assert_eq!(memory.writes_total(), 10);
        assert!(memory.writes_truncated());

        // An uncapped-in-practice log does not claim truncation.
        memory.set_retained_writes(usize::MAX);
        let mut short = Memory::new();
        short
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(short.set_word(0x1000, 1), Some(()));
        assert!(!short.writes_truncated());
        assert_eq!(short.writes_total(), 1);
    }

    #[test]
    fn a_seeded_image_is_the_starting_state_not_a_change() {
        let mut memory = Memory::new();
        memory
            .map(0x1000, 0x100)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(0x1000, &[0xaa; 0x10])
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .write_long(0x1080, 0x1234_5678)
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(touched_regions(&memory).is_empty());
    }

    /// A host that records which hooks it was asked about, claims `claimed`, and
    /// services traps only if `services` is set.
    #[derive(Default)]
    struct Recorder {
        name: &'static str,
        claimed: Option<u32>,
        services: bool,
        ticks: usize,
        calls: Vec<u32>,
        traps: usize,
    }

    impl Host for Recorder {
        fn tick(&mut self, _cpu: &mut CpuContext, _memory: &mut dyn HostMemory) {
            self.ticks += 1;
        }
        fn claims(&self, pc: u32) -> bool {
            self.claimed == Some(pc)
        }
        fn on_call(
            &mut self,
            pc: u32,
            _cpu: &mut CpuContext,
            _memory: &mut dyn HostMemory,
        ) -> HostAction {
            self.calls.push(pc);
            HostAction::Continue
        }
        fn on_trap(
            &mut self,
            _vector: u8,
            _site: u32,
            _cpu: &mut CpuContext,
            _memory: &mut dyn HostMemory,
        ) -> Option<HostAction> {
            self.traps += 1;
            self.services.then_some(HostAction::Continue)
        }
    }

    #[test]
    fn a_host_chain_ticks_everything_and_lets_the_first_answer_win() {
        let mut first = Recorder {
            name: "first",
            claimed: Some(0x1000),
            services: false,
            ..Recorder::default()
        };
        let mut second = Recorder {
            name: "second",
            claimed: Some(0x2000),
            services: true,
            ..Recorder::default()
        };
        let mut registers = Registers::default();
        let mut memory = Memory::new();
        {
            let mut chain = HostChain::new(vec![&mut first, &mut second]);
            let mut cpu = CpuContext {
                regs: &mut registers,
            };

            chain.tick(&mut cpu, &mut memory);
            assert!(chain.claims(0x1000) && chain.claims(0x2000));
            assert!(!chain.claims(0x3000), "neither host claims this one");

            // `on_call` goes to the host that claims the address, not the first
            // host in the chain.
            chain.on_call(0x2000, &mut cpu, &mut memory);
            // `on_trap` has no `claims` to ask, so returning `Some` is the
            // claim: both are consulted, and the second one services it.
            assert!(chain.on_trap(3, 0x4000, &mut cpu, &mut memory).is_some());
        }

        assert_eq!((first.ticks, second.ticks), (1, 1), "every host ticks");
        assert!(first.calls.is_empty(), "{} did not claim it", first.name);
        assert_eq!(second.calls, vec![0x2000], "{} did", second.name);
        assert_eq!((first.traps, second.traps), (1, 1));
    }

    #[test]
    fn a_host_chain_that_services_nothing_leaves_the_standard_stop_alone() {
        let mut host = Recorder::default();
        let mut registers = Registers::default();
        let mut memory = Memory::new();
        let mut chain = HostChain::new(vec![&mut host]);
        let mut cpu = CpuContext {
            regs: &mut registers,
        };
        assert!(
            chain.on_trap(3, 0x4000, &mut cpu, &mut memory).is_none(),
            "so `run` applies its own fault-aware stop"
        );
    }

    /// A trivial memory-mapped device: each read returns an incrementing value
    /// (like a beam counter), and writes are accepted. Used to drive a poll loop.
    struct Counter {
        base: u32,
        value: u32,
    }

    impl Device for Counter {
        fn range(&self) -> Range<u32> {
            self.base..self.base + 4
        }
        fn read(&mut self, _addr: u32, _size: u8, _memory: &mut dyn DmaMemory) -> DeviceAccess {
            let value = self.value;
            self.value = self.value.wrapping_add(1);
            DeviceAccess::Value(value)
        }
        fn write(
            &mut self,
            _addr: u32,
            _size: u8,
            _value: u32,
            _memory: &mut dyn DmaMemory,
        ) -> DeviceAccess {
            DeviceAccess::Wrote
        }
    }

    const COUNTER: u32 = 0x00e0_0000;

    /// A device that performs DMA when written, the way the chipset does when a
    /// program writes `BLTSIZE`: one register write, several words of memory
    /// changed on the program's behalf.
    struct Scatterer {
        base: u32,
        target: u32,
        words: u16,
    }

    impl Device for Scatterer {
        fn range(&self) -> Range<u32> {
            self.base..self.base + 2
        }
        fn read(&mut self, _addr: u32, _size: u8, _memory: &mut dyn DmaMemory) -> DeviceAccess {
            DeviceAccess::Value(0)
        }
        fn write(
            &mut self,
            _addr: u32,
            _size: u8,
            value: u32,
            memory: &mut dyn DmaMemory,
        ) -> DeviceAccess {
            // Preflight the whole transfer before changing anything, which is
            // the shape a real refusal needs and the reason `contains_word` must
            // leave no pending fault behind.
            for step in 0..u32::from(self.words) {
                if !memory.contains_word(self.target + step * 2) {
                    return DeviceAccess::Wrote;
                }
            }
            for step in 0..u32::from(self.words) {
                let _ = memory.write_dma_word(self.target + step * 2, value as u16);
            }
            DeviceAccess::Wrote
        }
    }

    const SCATTERER: u32 = 0x00e0_0010;
    const SCATTER_TARGET: u32 = 0x2200;

    /// A sandbox whose `$00e00010` register makes the device write `words` words
    /// at [`SCATTER_TARGET`].
    fn scatter_bus(code: &[u8], words: u16) -> (DeviceBus, RunOptions) {
        let (memory, options) = sandbox(code);
        let mut bus = DeviceBus::new(memory);
        bus.attach(Box::new(Scatterer {
            base: SCATTERER,
            target: SCATTER_TARGET,
            words,
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        (bus, options)
    }

    /// `MOVE.W #$beef,($00e00010).L ; RTS` — one instruction that provokes DMA.
    const TRIGGER: [u8; 12] = [
        0x33, 0xfc, 0xbe, 0xef, 0x00, 0xe0, 0x00, 0x10, // MOVE.W #$beef,($00e00010).L
        0x4e, 0x75, // RTS
        0x00, 0x00, // padding
    ];

    #[test]
    fn a_devices_dma_changes_memory_without_entering_the_write_log() {
        let (mut bus, options) = scatter_bus(&TRIGGER, 4);
        let execution = run_with_host(&mut bus, LOAD, &mut NoHost, &options);
        assert_eq!(execution.stop, StopReason::Returned);

        assert_eq!(
            bus.ram().slice(SCATTER_TARGET, 8),
            Some(&[0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef][..]),
            "the device's DMA reached RAM"
        );
        assert!(
            touched_regions(bus.ram())
                .iter()
                .any(|region| region.address == SCATTER_TARGET),
            "and is visible as changed memory"
        );
        // The log answers what the executing code did: one MMIO write, not four
        // DMA words. Burying the instruction under the chipset's response is
        // exactly what this split exists to prevent.
        let dma_writes = bus
            .writes()
            .iter()
            .filter(|write| (SCATTER_TARGET..SCATTER_TARGET + 8).contains(&write.address))
            .count();
        assert_eq!(dma_writes, 0, "DMA never enters the write log");
        assert!(
            bus.writes().iter().any(|write| write.address == SCATTERER),
            "the CPU's MMIO write does"
        );
    }

    #[test]
    fn dma_events_say_they_are_dma_and_precede_the_cpu_write_that_caused_them() {
        // `serve_write` calls the device and only then records the CPU's own
        // MMIO write, so the DMA appears before the instruction that provoked
        // it. That reads backwards and is kept deliberately — reordering would
        // change MMIO event order for every device — so the ordering is pinned
        // here and `source` is what makes the sequence legible.
        let (mut bus, mut options) = scatter_bus(&TRIGGER, 2);
        options.watchpoints = vec![
            Watchpoint::new(SCATTER_TARGET, 4, WatchAccess::Both)
                .unwrap_or_else(|| panic!("valid watchpoint")),
            Watchpoint::new(SCATTERER, 2, WatchAccess::Both)
                .unwrap_or_else(|| panic!("valid watchpoint")),
        ];
        let execution = run_with_host(&mut bus, LOAD, &mut NoHost, &options);
        assert_eq!(execution.stop, StopReason::Returned);

        let events: Vec<(u32, AccessSource)> = bus
            .accesses()
            .iter()
            .map(|event| (event.address, event.source))
            .collect();
        assert_eq!(
            events,
            vec![
                (SCATTER_TARGET, AccessSource::DeviceDma),
                (SCATTER_TARGET + 2, AccessSource::DeviceDma),
                (SCATTERER, AccessSource::Cpu),
            ]
        );

        // All three belong to the one instruction that did it.
        let step = execution
            .steps
            .iter()
            .find(|step| step.address == LOAD)
            .unwrap_or_else(|| panic!("the MOVE was traced"));
        assert_eq!(step.watch_events.len(), 3);
        assert_eq!(
            step.writes.len(),
            1,
            "the step's writes hold only the CPU's own"
        );
        assert_eq!(step.writes[0].address, SCATTERER);
    }

    #[test]
    fn a_failed_preflight_leaves_no_pending_fault() {
        // `contains_word` must have no observable effect at all. If a refused
        // preflight left a fault behind, the very next instruction would trap on
        // an address the device only asked about.
        let (mut bus, options) = scatter_bus(&TRIGGER, 0x800);
        let execution = run_with_host(&mut bus, LOAD, &mut NoHost, &options);

        assert_eq!(
            execution.stop,
            StopReason::Returned,
            "asking about unmapped memory must not trap the run"
        );
        assert_eq!(bus.last_fault(), None);
        assert_eq!(
            bus.ram().slice(SCATTER_TARGET, 2),
            Some(&[0x00, 0x00][..]),
            "the device refused, so nothing was written"
        );
    }

    /// Assert `run` and `run_with_host` + `NoHost` produce an identical
    /// `Execution` and identical memory writes for `code` under `configure`.
    fn assert_run_equivalent(code: &[u8], configure: impl Fn(&mut RunOptions)) {
        let (mut m1, mut o1) = sandbox(code);
        configure(&mut o1);
        let (mut m2, mut o2) = sandbox(code);
        configure(&mut o2);
        let direct = run(&mut m1, LOAD, &o1);
        let hosted = run_with_host(&mut m2, LOAD, &mut NoHost, &o2);
        assert_eq!(direct, hosted);
        assert_eq!(m1.writes(), m2.writes());
    }

    #[test]
    fn run_matches_run_with_host_and_nohost() {
        // The regression guard: `run` must equal `run_with_host` + `NoHost`,
        // byte-for-byte, across every outcome the loop produces.
        // MOVEQ #5,D0; ADDQ.L #3,D0; RTS -> Returned.
        assert_run_equivalent(&[0x70, 0x05, 0x56, 0x80, 0x4e, 0x75], |_| {});
        // BRA.S * -> StepLimit.
        assert_run_equivalent(&[0x60, 0xfe], |options| options.max_steps = 8);
        // MOVE.W D0,(A0); RTS -> a memory write.
        assert_run_equivalent(&[0x30, 0x80, 0x4e, 0x75], |options| {
            options.address[0] = 0x2000;
            options.data[0] = 0x1234;
        });
        // MOVE.W D0,(A0); RTS with A0 unmapped -> Fault (via bus.last_fault()).
        assert_run_equivalent(&[0x30, 0x80, 0x4e, 0x75], |options| {
            options.address[0] = 0x0010_0000;
        });
        // MOVE.W #$1234,(A0); RTS with a write watchpoint -> Watch.
        assert_run_equivalent(&[0x30, 0xbc, 0x12, 0x34, 0x4e, 0x75], |options| {
            options.address[0] = 0x1800;
            options.watchpoints =
                vec![Watchpoint::new(0x1800, 2, WatchAccess::Write).expect("valid watchpoint")];
            options.stop_on_watch = true;
        });
        // TRAP #0 -> a non-fault Trap vector.
        assert_run_equivalent(&[0x4e, 0x40, 0x4e, 0x75], |_| {});
    }

    #[test]
    fn a_device_poll_loop_terminates() {
        // wait: MOVE.W (A0),D0 ; CMPI.W #3,D0 ; BNE.S wait ; RTS — the counter
        // advances on each read, so the loop ends when it reads 3.
        let code = [
            0x30, 0x10, // MOVE.W (A0),D0
            0x0c, 0x40, 0x00, 0x03, // CMPI.W #3,D0
            0x66, 0xf8, // BNE.S wait
            0x4e, 0x75, // RTS
        ];
        let mut memory = Memory::new();
        memory
            .map(0, 0x3000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(LOAD, &code)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bus = DeviceBus::new(memory);
        bus.attach(Box::new(Counter {
            base: COUNTER,
            value: 0,
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let mut options = RunOptions::new(0x2ffc, MARKER);
        options.address[0] = COUNTER;
        let execution = run_with_host(&mut bus, LOAD, &mut NoHost, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.registers.d[0], 3);
    }

    /// What a raised [`crate::MAXIMUM_SANDBOX_STEPS_CEILING`] costs, so the
    /// number in `amiga-operations` is measured rather than guessed.
    ///
    /// Ignored because it is a measurement, not an assertion. Run it with
    /// `cargo test -p amiga-disasm --release measure_run_cost -- --ignored
    /// --nocapture`, optionally with `PROBE_STEPS` set, and read the peak
    /// resident set beside the rate: the point of the bounded log and the
    /// bounded trace is that the first number moves with the map and not with
    /// the second.
    #[test]
    #[ignore = "a measurement, not an assertion"]
    fn measure_run_cost() {
        // A tight write loop, so a third of the executed instructions log:
        // MOVE.W D0,(A0) ; ADDQ.W #1,D0 ; BRA.S -6
        let code = [0x30, 0x80, 0x52, 0x40, 0x60, 0xfa];
        let mut memory = Memory::new();
        memory
            .map(0, 0x40_0000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(LOAD, &code)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut options = RunOptions::new(0x2ffc, MARKER);
        options.address[0] = 0x10_0000;
        options.max_steps = std::env::var("PROBE_STEPS")
            .ok()
            .and_then(|steps| steps.parse().ok())
            .unwrap_or(5_000_000);
        let start = std::time::Instant::now();
        let execution = run(&mut memory, LOAD, &options);
        let elapsed = start.elapsed();
        let peak = std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find(|line| line.starts_with("VmHWM"))
            .unwrap_or("VmHWM: unavailable")
            .to_string();
        eprintln!(
            "{} steps in {elapsed:?} ({:.1}M/s); log {} of {} writes; trace {} rows; {peak}",
            execution.steps_executed,
            execution.steps_executed as f64 / elapsed.as_secs_f64() / 1e6,
            memory.writes().len(),
            memory.writes_total(),
            execution.steps.len(),
        );
    }

    #[test]
    fn watchpoints_observe_device_reads() {
        // MOVE.W (A0),D0 ; RTS with A0 = the counter, watching device reads.
        let code = [0x30, 0x10, 0x4e, 0x75];
        let mut memory = Memory::new();
        memory
            .map(0, 0x3000)
            .unwrap_or_else(|error| panic!("{error}"));
        memory
            .load(LOAD, &code)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bus = DeviceBus::new(memory);
        bus.attach(Box::new(Counter {
            base: COUNTER,
            value: 0x1234,
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let mut options = RunOptions::new(0x2ffc, MARKER);
        options.address[0] = COUNTER;
        options.watchpoints = vec![
            Watchpoint::new(COUNTER, 2, WatchAccess::Read)
                .unwrap_or_else(|| panic!("valid watchpoint")),
        ];
        let execution = run_with_host(&mut bus, LOAD, &mut NoHost, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        assert!(
            execution
                .steps
                .iter()
                .any(|step| step.watch_events.iter().any(|event| event.after == 0x1234))
        );
    }

    #[test]
    fn a_straddling_device_access_faults() {
        // A long read whose last two bytes fall past the counter's 4-byte range.
        let mut bus = DeviceBus::new(Memory::new());
        bus.attach(Box::new(Counter {
            base: COUNTER,
            value: 0,
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(bus.get_long(COUNTER + 2), None);
        assert_eq!(
            bus.last_fault(),
            Some(Fault {
                address: COUNTER + 2,
                access: Access::Read,
                size: 4,
            })
        );
    }

    #[test]
    fn attach_rejects_overlapping_devices() {
        let mut memory = Memory::new();
        memory
            .map(0, 0x1000)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bus = DeviceBus::new(memory);
        // Overlaps the RAM region [0, 0x1000).
        assert!(matches!(
            bus.attach(Box::new(Counter {
                base: 0x800,
                value: 0
            })),
            Err(MemoryError::Overlap { .. })
        ));
    }

    #[test]
    fn skips_the_trace_when_not_recording() {
        // MOVEQ #5,D0 ; RTS, run without recording steps.
        let code = [0x70, 0x05, 0x4e, 0x75];
        let (mut memory, mut options) = sandbox(&code);
        options.record_steps = false;
        let execution = run(&mut memory, LOAD, &options);
        assert_eq!(execution.stop, StopReason::Returned);
        assert_eq!(execution.registers.d[0], 5);
        assert!(execution.steps.is_empty());
        assert_eq!(execution.steps_executed, 2);
    }
}
