//! A bounded, offline Amiga execution environment over the `amiga-disasm`
//! sandbox.
//!
//! Static analysis reads code without running it; `amiga-disasm` runs it in a
//! bare RAM sandbox where any OS call or hardware poke traps. This crate adds the
//! *environment* that missing half needs: a documented memory map, a fake
//! ExecBase, a synthetic already-open trackdisk IORequest, and a [`host::BootHost`]
//! that services the exec calls and disk reads a boot block makes — so a floppy's
//! boot code can execute far enough to reveal (and, later, dump) the tracks it
//! loads, without a full emulator and without any game-specific constants.
//!
//! [`Environment::boot`] seeds a floppy image's bootstrap contract;
//! [`Environment::run`] runs it and returns a [`BootRun`]. The environment sits above
//! the leaf crates and is composed by `amiga-operations`, which exposes
//! `env.boot.trace` and its export to the CLI and downstream tools.

pub mod chips;
pub mod host;
pub mod layout;

use std::cell::Cell;
use std::rc::Rc;

use amiga_disasm::{
    Bus, DeviceBus, Execution, Memory, MemoryAccessEvent, RunOptions, Watchpoint, run_with_host,
};
use thiserror::Error;

pub use chips::{
    BlitRow, BlitterTelemetry, ChipRegisterWrite, ChipRegisters, ChipWriteLog, ChipsOptions,
    CustomChips, HORIZONTAL, ObservationTally, RefusalTally, VERTICAL,
};
pub use host::{BeamHost, BootHost, ExecCall, ServedRead};

/// A failure building or running an environment.
#[derive(Debug, Error)]
pub enum EnvError {
    /// The boot image is shorter than a 1024-byte boot block.
    #[error("boot image is {0} bytes, too small for a 1024-byte boot block")]
    BootblockTooSmall(usize),
    /// A memory region could not be mapped or seeded.
    #[error(transparent)]
    Memory(#[from] amiga_disasm::MemoryError),
}

/// The outcome of a boot run: the raw execution plus the disk reads served.
#[derive(Clone, Debug)]
pub struct BootRun {
    /// The raw sandbox execution (steps, stop reason, final registers).
    pub execution: Execution,
    /// The disk transfers the environment served, in chronological order.
    pub served_reads: Vec<ServedRead>,
    /// The exec/library vectors the host serviced, in call order — the ground
    /// truth of which OS calls were made, not a static disassembly guess.
    pub exec_calls: Vec<ExecCall>,
}

/// A seeded Amiga environment ready to run a floppy's boot code.
///
/// An `Environment` is **single-use**: [`Environment::run`] executes over the
/// (mutable) memory image and the host's cumulative logs, so calling it more than
/// once runs over already-mutated memory and re-reports earlier served reads.
/// Build a fresh environment with [`Environment::boot`] for each run.
pub struct Environment {
    bus: DeviceBus,
    host: BootHost,
    options: RunOptions,
    entry: u32,
    /// Chip-register writes, collected by the page as they happen rather than
    /// recovered afterwards from the memory write log — which is capped, and so
    /// cannot be asked for a complete answer about anything.
    chip_writes: std::rc::Rc<std::cell::RefCell<ChipWriteLog>>,
}

impl Environment {
    /// Seed the environment for a floppy `image` whose first 1024 bytes are the
    /// boot block: map chip RAM, the ExecBase, the custom-chip page, and a stack;
    /// load the whole block; enable bounded guest TRAP #0–#15 dispatch; and
    /// set the bootstrap register contract (A6 =
    /// ExecBase, A1 = the already-open trackdisk IORequest, PC = block + 12).
    ///
    /// # Errors
    /// [`EnvError::BootblockTooSmall`] if `image` is shorter than 1024 bytes, or
    /// [`EnvError::Memory`] if a region cannot be mapped (it never can with the
    /// fixed layout, but the seed writes are still checked).
    pub fn boot(image: &[u8]) -> Result<Self, EnvError> {
        use layout::*;
        let block = image
            .get(..amiga_adf::Bootblock::SIZE)
            .ok_or(EnvError::BootblockTooSmall(image.len()))?;

        let mut memory = Memory::new();
        memory.map(CHIP_BASE, CHIP_SIZE)?;
        memory.map(EXEC_BASE, EXEC_SIZE)?;
        memory.map(STACK_BASE, STACK_SIZE)?;
        memory.map(HEAP_BASE, HEAP_SIZE)?; // AllocMem hands out from here
        // The fake-library region is deliberately left unmapped: OpenLibrary
        // returns a non-null base, but touching it faults (no library modelled).

        // The boot block, mapped whole: its code (from +12) may reference the
        // header.
        memory.load(BOOT_LOAD, block)?;
        memory.write_long(4, EXEC_BASE)?; // ExecBase pointer for MOVEA.L 4,A6
        memory.write_long(IOREQ + IO_DEVICE, DEVICE_BASE)?;
        memory.write_long(IOREQ + IO_UNIT, DEVICE_UNIT)?;

        // The custom-chip page ($DFF000) is a device with real register
        // semantics, not RAM; the beam counter is shared with the host's tick.
        let beam = Rc::new(Cell::new(0_u64));
        let mut bus = DeviceBus::new(memory);
        let (chips, chip_writes) = CustomChips::recording(Rc::clone(&beam));
        bus.attach(Box::new(chips))?;

        let stack_top = STACK_BASE
            .checked_add(STACK_SIZE as u32)
            .ok_or(EnvError::Memory(
                amiga_disasm::MemoryError::AddressOverflow {
                    origin: STACK_BASE,
                    length: STACK_SIZE,
                },
            ))?;
        let mut options = RunOptions::new(stack_top, RETURN_MARKER);
        options.record_steps = true;
        options.guest_traps = true;
        options.address[6] = EXEC_BASE; // A6 = ExecBase
        options.address[1] = IOREQ; // A1 = the already-open trackdisk IORequest

        Ok(Self {
            bus,
            host: BootHost::new(image.to_vec(), beam),
            options,
            entry: entry(),
            chip_writes,
        })
    }

    /// The absolute entry PC (the boot code at block + 12).
    #[must_use]
    pub fn entry(&self) -> u32 {
        self.entry
    }

    /// The writes executing code performed, in the order it performed them.
    ///
    /// **What this is for** is following what a boot run *did*: each write with
    /// its address, width and value, in sequence. No other accessor here gives
    /// that ordering, which is what a reader retracing an initialization by hand
    /// wants. It is deliberately the *executing code's* writes — blitter DMA
    /// marks memory dirty without entering this log — so it reports what the
    /// program wrote rather than everything that changed.
    ///
    /// **What it is not is a complete log**, and the difference is load-bearing
    /// rather than incidental. It is a prefix bounded by the sandbox's write
    /// retention cap (see [`amiga_disasm::Memory::writes`]);
    /// [`Self::memory_writes_total`] counts past the cap and
    /// [`Self::memory_writes_truncated`] says whether it did. That bound is what
    /// keeps a run's peak memory flat in its length, which the sandbox step
    /// ceiling rests on, so it will not be lifted to make a scan here work.
    ///
    /// Two readers therefore want something else, and both have it:
    ///
    /// - **every write of some kind** must be collected as it happens rather
    ///   than filtered out of this afterwards — [`Self::chip_writes`] is exactly
    ///   that for the custom-chip page, and is what the boot trace uses instead
    ///   of scanning here;
    /// - **which addresses changed** is [`amiga_disasm::changed_regions`], which
    ///   walks a dirty bitmap and is bounded by the mapped memory rather than by
    ///   the length of the run.
    #[must_use]
    pub fn memory_writes(&self) -> &[amiga_disasm::MemoryWrite] {
        self.bus.ram().writes()
    }

    /// Writes executing code performed. Always the true total, past the cap on
    /// what [`Self::memory_writes`] retains.
    #[must_use]
    pub fn memory_writes_total(&self) -> u64 {
        self.bus.ram().writes_total()
    }

    /// Whether more writes happened than [`Self::memory_writes`] retained.
    #[must_use]
    pub fn memory_writes_truncated(&self) -> bool {
        self.bus.ram().writes_truncated()
    }

    /// Every custom-chip register write the run performed, bounded and counted.
    #[must_use]
    pub fn chip_writes(&self) -> std::cell::Ref<'_, ChipWriteLog> {
        self.chip_writes.borrow()
    }

    /// The retained accesses that matched a watched range.
    ///
    /// Read from the bus rather than gathered from the trace rows, because the
    /// two are bounded separately and only this one is bounded by the watch
    /// budget. A row-derived answer silently loses every hit past the trace's
    /// retention cap — which a boot trace reaches at its *default* step budget
    /// — while the count that would have reported the loss is the bus's, and
    /// the bus retained the events perfectly well.
    #[must_use]
    pub fn watch_events(&self) -> &[MemoryAccessEvent] {
        self.bus.accesses()
    }

    /// Run the boot code for up to `max_steps` instructions, honoring the given
    /// `watchpoints` (stopping at the first match when `stop_on_watch`).
    pub fn run(
        &mut self,
        max_steps: usize,
        watchpoints: Vec<Watchpoint>,
        stop_on_watch: bool,
    ) -> BootRun {
        let mut options = self.options.clone();
        options.max_steps = max_steps;
        options.watchpoints = watchpoints;
        options.stop_on_watch = stop_on_watch;
        let execution = run_with_host(&mut self.bus, self.entry, &mut self.host, &options);
        BootRun {
            execution,
            served_reads: self.host.served_reads().to_vec(),
            exec_calls: self.host.exec_calls().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1024-byte boot block with `code` at the boot-code offset.
    fn boot_image(code: &[u8]) -> Vec<u8> {
        let mut block = vec![0_u8; amiga_adf::Bootblock::SIZE];
        let start = amiga_adf::Bootblock::CODE_OFFSET;
        block[start..start + code.len()].copy_from_slice(code);
        block
    }

    fn trap_boot(handler: u32, handler_code: &[u8]) -> Vec<u8> {
        // MOVE.L #handler,$80 ; TRAP #0 ; RTS
        let mut code = vec![0x23, 0xfc];
        code.extend_from_slice(&handler.to_be_bytes());
        code.extend_from_slice(&[0, 0, 0, 0x80, 0x4e, 0x40, 0x4e, 0x75]);
        let mut image = boot_image(&code);
        image[0x40..0x40 + handler_code.len()].copy_from_slice(handler_code);
        image
    }

    #[test]
    fn boot_dispatches_installed_trap_and_rte_returns_to_caller() {
        // MOVE.W #$1234,$2000 ; RTE
        let handler = [0x33, 0xfc, 0x12, 0x34, 0, 0, 0x20, 0, 0x4e, 0x73];
        let image = trap_boot(layout::BOOT_LOAD + 0x40, &handler);
        let mut env = Environment::boot(&image).unwrap();
        let run = env.run(5, vec![], false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.steps_executed, 5);
        assert_eq!(env.bus.ram().slice(0x2000, 2).unwrap(), &[0x12, 0x34]);
        let trap = &run.execution.steps[1];
        assert_eq!(trap.trap, Some(32));
        assert_eq!(trap.writes.len(), 2);
        assert_eq!(trap.cycles, 34);
        assert_eq!(run.execution.steps[2].address, layout::BOOT_LOAD + 0x40);
        assert_eq!(run.execution.steps[4].address, layout::entry() + 12);
    }

    #[test]
    fn boot_trap_handler_shares_the_instruction_budget() {
        let image = trap_boot(layout::BOOT_LOAD + 0x40, &[0x60, 0xfe]); // BRA.S self
        let mut env = Environment::boot(&image).unwrap();
        let run = env.run(7, vec![], false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::StepLimit);
        assert_eq!(run.execution.steps_executed, 7);
        assert_eq!(run.execution.registers.pc, layout::BOOT_LOAD + 0x40);
    }

    #[test]
    fn boot_refuses_absent_odd_or_unmapped_trap_handlers() {
        for handler in [0, layout::BOOT_LOAD + 0x41, 0x00ff_0000] {
            let mut env = Environment::boot(&trap_boot(handler, &[])).unwrap();
            let run = env.run(10, vec![], false);
            assert!(matches!(
                run.execution.stop,
                amiga_disasm::StopReason::Trap { vector: 32, .. }
                    | amiga_disasm::StopReason::Fault { .. }
            ));
            assert_eq!(run.execution.steps_executed, 2);
            assert!(run.execution.steps[1].writes.is_empty());
        }
    }

    #[test]
    fn a_watch_hit_past_the_trace_cap_is_still_reported() {
        // A DBRA loop long enough to exhaust the retained trace rows, then a
        // write to the watched address:
        //   MOVE.W #45000,D0 ; NOP ; DBRA D0,-4 ; MOVE.W #1,<target> ; RTS
        //
        // The hit happens after ~90,000 instructions, past
        // `DEFAULT_RETAINED_STEPS`, so it is attached to no retained step. It
        // must still be reported: gathering hits from the trace rows lost it
        // while `watch_events_truncated` — which measures the bus's retention,
        // not the trace's — went on saying nothing had been dropped.
        let target = layout::CHIP_BASE + 0x1000;
        let mut code = vec![
            0x30, 0x3c, 0xaf, 0xc8, // MOVE.W #45000,D0
            0x4e, 0x71, // NOP
            0x51, 0xc8, 0xff, 0xfc, // DBRA D0,-4
            0x33, 0xfc, 0x00, 0x01, // MOVE.W #1,<abs.L>
        ];
        code.extend_from_slice(&target.to_be_bytes());
        code.push(0x4e);
        code.push(0x75); // RTS

        let mut environment =
            Environment::boot(&boot_image(&code)).unwrap_or_else(|error| panic!("{error}"));
        let watch = Watchpoint::new(target, 2, amiga_disasm::WatchAccess::Both)
            .unwrap_or_else(|| panic!("a two-byte watch range is valid"));
        let run = environment.run(200_000, vec![watch], false);

        assert!(
            run.execution.steps_traced > run.execution.steps.len(),
            "the run must outlast the retained rows for this to test anything"
        );
        assert!(
            run.execution
                .steps
                .iter()
                .all(|step| step.watch_events.is_empty()),
            "the hit is past the row cap, so no retained row carries it"
        );
        assert_eq!(
            environment.watch_events().len(),
            1,
            "and the bus reports it anyway"
        );
        assert_eq!(environment.watch_events()[0].address, target);
    }

    #[test]
    fn boot_hands_the_io_request_and_execbase() {
        // MOVE.L (20,A1),D0 ; MOVE.L 4,D1 ; RTS — read io_Device and ExecBase.
        let image = boot_image(&[
            0x20, 0x29, 0x00, 0x14, // MOVE.L (io_Device,A1),D0
            0x22, 0x39, 0x00, 0x00, 0x00, 0x04, // MOVE.L $4,D1
            0x4e, 0x75, // RTS
        ]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(100, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.registers.d[0], layout::DEVICE_BASE);
        assert_eq!(run.execution.registers.d[1], layout::EXEC_BASE);
        assert!(run.served_reads.is_empty());
    }

    #[test]
    fn rejects_a_short_image() {
        assert!(matches!(
            Environment::boot(&[0_u8; 100]),
            Err(EnvError::BootblockTooSmall(100))
        ));
    }

    #[test]
    fn serves_a_cmd_read_through_the_a1_request() {
        // Fill the A1 IORequest for a 512-byte CMD_READ from offset 0 into a
        // chip-RAM buffer, DoIO it, then read io_Actual and the first longword.
        let mut image = boot_image(&[
            0x33, 0x7c, 0x00, 0x02, 0x00, 0x1c, // MOVE.W #CMD_READ,(io_Command,A1)
            0x23, 0x7c, 0x00, 0x00, 0x02, 0x00, 0x00, 0x24, // MOVE.L #512,(io_Length,A1)
            0x42, 0xa9, 0x00, 0x2c, // CLR.L (io_Offset,A1)
            0x23, 0x7c, 0x00, 0x00, 0x20, 0x00, 0x00, 0x28, // MOVE.L #$2000,(io_Data,A1)
            0x4e, 0xae, 0xfe, 0x38, // JSR (-456,A6) = DoIO
            0x20, 0x29, 0x00, 0x20, // MOVE.L (io_Actual,A1),D0
            0x22, 0x39, 0x00, 0x00, 0x20, 0x00, // MOVE.L ($2000),D1
            0x4e, 0x75, // RTS
        ]);
        // A recognizable tag at the start, so the read-back longword is known.
        image[0..4].copy_from_slice(b"DOS\0");

        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(200, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.registers.d[0], 512); // io_Actual
        assert_eq!(run.execution.registers.d[1], 0x444f_5300); // "DOS\0"

        assert_eq!(run.served_reads.len(), 1);
        let read = &run.served_reads[0];
        assert_eq!(read.command, "CMD_READ");
        assert_eq!(read.offset, 0);
        assert_eq!(read.dest, 0x2000);
        assert_eq!(read.requested, 512);
        assert_eq!(read.actual, 512);
        assert_eq!(read.status, 0);
    }

    #[test]
    fn rejects_a_non_sector_aligned_read() {
        // io_Length = 500 (not a multiple of 512): DoIO must error, not copy.
        let mut image = boot_image(&[
            0x33, 0x7c, 0x00, 0x02, 0x00, 0x1c, // MOVE.W #CMD_READ,(io_Command,A1)
            0x23, 0x7c, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x24, // MOVE.L #500,(io_Length,A1)
            0x42, 0xa9, 0x00, 0x2c, // CLR.L (io_Offset,A1)
            0x23, 0x7c, 0x00, 0x00, 0x20, 0x00, 0x00, 0x28, // MOVE.L #$2000,(io_Data,A1)
            0x4e, 0xae, 0xfe, 0x38, // JSR (-456,A6) = DoIO
            0x10, 0x29, 0x00, 0x1f, // MOVE.B (io_Error,A1),D0
            0x4e, 0x75, // RTS
        ]);
        image[0..4].copy_from_slice(b"DOS\0");
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(200, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        // io_Error is nonzero (IOERR_BADLENGTH = -4, byte 0xfc).
        assert_eq!(run.execution.registers.d[0] & 0xff, 0xfc);
        assert_eq!(run.served_reads[0].actual, 0);
    }

    #[test]
    fn a_beam_wait_loop_terminates() {
        // wait: MOVE.W $DFF006,D0 ; ANDI.W #$FF00,D0 ; CMPI.W #$0100,D0 ;
        // BNE.S wait ; RTS — spin until the beam reaches vertical line 1.
        let image = boot_image(&[
            0x30, 0x39, 0x00, 0xdf, 0xf0, 0x06, // MOVE.W $DFF006(VHPOSR),D0
            0x02, 0x40, 0xff, 0x00, // ANDI.W #$FF00,D0
            0x0c, 0x40, 0x01, 0x00, // CMPI.W #$0100,D0
            0x66, 0xf0, // BNE.S wait
            0x4e, 0x75, // RTS
        ]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(4000, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
    }

    #[test]
    fn an_unhandled_exec_vector_stops_cleanly() {
        // JSR (-30,A6) = Supervisor, which the stub does not model.
        let image = boot_image(&[0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(50, Vec::new(), false);
        assert!(matches!(
            run.execution.stop,
            amiga_disasm::StopReason::UnhandledCall { offset: -30, .. }
        ));
    }

    #[test]
    fn a_bogus_io_request_pointer_errors_without_panicking() {
        // MOVEA.L #$FFFFFFF0,A1 ; JSR (-456,A6) ; RTS — an unaddressable request.
        let image = boot_image(&[
            0x22, 0x7c, 0xff, 0xff, 0xff, 0xf0, // MOVEA.L #$FFFFFFF0,A1
            0x4e, 0xae, 0xfe, 0x38, // JSR (-456,A6) = DoIO
            0x4e, 0x75, // RTS
        ]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(50, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        // DoIO returns io_Error (IOERR_BADADDRESS = -5) sign-extended in D0.
        assert_eq!(run.execution.registers.d[0], 0xffff_fffb);
        assert_eq!(run.served_reads.len(), 1);
        assert_eq!(run.served_reads[0].status, -5);
    }

    #[test]
    fn a_housekeeping_command_succeeds() {
        // MOVE.W #TD_MOTOR,(io_Command,A1) ; JSR DoIO ; RTS — succeeds (D0 = 0).
        let image = boot_image(&[
            0x33, 0x7c, 0x00, 0x09, 0x00, 0x1c, // MOVE.W #9(TD_MOTOR),(io_Command,A1)
            0x4e, 0xae, 0xfe, 0x38, // JSR (-456,A6) = DoIO
            0x4e, 0x75, // RTS
        ]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(50, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.registers.d[0], 0);
        assert_eq!(run.served_reads[0].status, 0);
    }

    #[test]
    fn send_io_then_wait_io_transfers_once() {
        // Fill a CMD_READ, SendIO, WaitIO, then read io_Actual — one transfer.
        let mut image = boot_image(&[
            0x33, 0x7c, 0x00, 0x02, 0x00, 0x1c, // MOVE.W #CMD_READ,(io_Command,A1)
            0x23, 0x7c, 0x00, 0x00, 0x02, 0x00, 0x00, 0x24, // MOVE.L #512,(io_Length,A1)
            0x42, 0xa9, 0x00, 0x2c, // CLR.L (io_Offset,A1)
            0x23, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, // MOVE.L #0,(io_Data,A1)
            0x4e, 0xae, 0xfe, 0x32, // JSR (-462,A6) = SendIO
            0x4e, 0xae, 0xfe, 0x2c, // JSR (-468,A6) = WaitIO
            0x20, 0x29, 0x00, 0x20, // MOVE.L (io_Actual,A1),D0
            0x4e, 0x75, // RTS
        ]);
        image.resize(2048, 0);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(80, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.registers.d[0], 512); // io_Actual
        assert_eq!(run.served_reads.len(), 1); // not double-counted
    }

    #[test]
    fn open_device_rejects_a_non_trackdisk_device() {
        // MOVEA.L #name,A0 ; MOVEQ #0,D0 ; JSR OpenDevice ; RTS with a name that
        // is not trackdisk -> D0 = IOERR_OPENFAIL (-1).
        let mut image = boot_image(&[
            0x20, 0x7c, 0x00, 0x00, 0x10, 0x40, // MOVEA.L #$1040,A0 (name address)
            0x70, 0x00, // MOVEQ #0,D0 (unit)
            0x4e, 0xae, 0xfe, 0x44, // JSR (-444,A6) = OpenDevice
            0x4e, 0x75, // RTS
        ]);
        // The name sits at block offset 0x40 -> mapped address $1040.
        image[0x40..0x4d].copy_from_slice(b"audio.device\0");
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(50, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.registers.d[0], 0xffff_ffff); // IOERR_OPENFAIL
    }

    #[test]
    fn exec_calls_record_the_serviced_vectors() {
        // JSR (-198,A6) AllocMem ; RTS — one recorded exec call at the JSR site.
        let image = boot_image(&[
            0x70, 0x08, // MOVEQ #8,D0 (size)
            0x4e, 0xae, 0xff, 0x3a, // JSR (-198,A6) = AllocMem
            0x4e, 0x75, // RTS
        ]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(50, Vec::new(), false);
        assert_eq!(run.exec_calls.len(), 1);
        assert_eq!(run.exec_calls[0].offset, -198);
        // The JSR is at entry+2 (after the MOVEQ).
        assert_eq!(run.exec_calls[0].site, layout::entry() + 2);
    }

    #[test]
    fn an_enormous_allocation_fails_without_overflowing() {
        // MOVEQ #-1,D0 ; JSR (-198,A6) ; RTS — AllocMem(0xFFFFFFFF) must fail (0).
        let image = boot_image(&[
            0x70, 0xff, // MOVEQ #-1,D0
            0x4e, 0xae, 0xff, 0x3a, // JSR (-198,A6) = AllocMem
            0x4e, 0x75, // RTS
        ]);
        let mut env = Environment::boot(&image).unwrap_or_else(|error| panic!("{error}"));
        let run = env.run(50, Vec::new(), false);
        assert_eq!(run.execution.stop, amiga_disasm::StopReason::Returned);
        assert_eq!(run.execution.registers.d[0], 0);
    }
}
