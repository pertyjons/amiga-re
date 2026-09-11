//! The [`amiga_disasm::Host`] that services a boot run.
//!
//! This is where the Amiga-OS *policy* lives: the exec/library vectors the boot
//! code calls and the trackdisk reads it makes. The engine (`amiga-disasm`)
//! provides only the mechanism (intercept a claimed OS-vector address, service
//! it, and resume). Everything modelled here is generic AmigaOS behaviour — no
//! game-specific constants — and anything not modelled stops the run clearly
//! rather than fabricating a result.

use std::cell::Cell;
use std::rc::Rc;

use amiga_disasm::{CpuContext, HostAction, HostMemory, StopReason};
use serde::Serialize;

use crate::layout;

/// Bytes below a library base that hold its jump vectors; a `JSR (-N,An)` lands
/// here and is intercepted. Covers the whole exec LVO range with margin.
const VECTOR_SPAN: u32 = 0x1000;

// Exec library-vector offsets (negative), the subset a boot block uses.
const LVO_DISABLE: i16 = -120;
const LVO_ENABLE: i16 = -126;
const LVO_FORBID: i16 = -132;
const LVO_PERMIT: i16 = -138;
const LVO_ALLOC_MEM: i16 = -198;
const LVO_FREE_MEM: i16 = -210;
const LVO_OLD_OPEN_LIBRARY: i16 = -408;
const LVO_CLOSE_LIBRARY: i16 = -414;
const LVO_OPEN_DEVICE: i16 = -444;
const LVO_CLOSE_DEVICE: i16 = -450;
const LVO_DO_IO: i16 = -456;
const LVO_SEND_IO: i16 = -462;
const LVO_WAIT_IO: i16 = -468;
const LVO_OPEN_LIBRARY: i16 = -552;
const LVO_ALLOC_VEC: i16 = -684;
const LVO_FREE_VEC: i16 = -690;

// Trackdisk / exec-IO command values (`io_Command`, a UWORD).
const CMD_READ: u16 = 2;
const CMD_UPDATE: u16 = 4;
const CMD_CLEAR: u16 = 5;
const CMD_STOP: u16 = 6;
const CMD_START: u16 = 7;
const CMD_FLUSH: u16 = 8;
const TD_MOTOR: u16 = 9;
const TD_SEEK: u16 = 10;
const TD_REMOVE: u16 = 12;
const TD_CHANGENUM: u16 = 13;
const TD_CHANGESTATE: u16 = 14;
const TD_PROTSTATUS: u16 = 15;
const TD_RAWREAD: u16 = 16;
const TD_ADDCHANGEINT: u16 = 19;
const TD_REMCHANGEINT: u16 = 20;
const TD_EXTCOM: u16 = 0x8000;
const ETD_READ: u16 = TD_EXTCOM | CMD_READ;

// Exec-IO / trackdisk error codes (`io_Error`, a signed byte).
const IOERR_OPENFAIL: i8 = -1;
const IOERR_NOCMD: i8 = -3;
const IOERR_BADLENGTH: i8 = -4;
const IOERR_BADADDRESS: i8 = -5;
const TDERR_SEEK_ERROR: i8 = 30;
const TDERR_NOT_SPECIFIED: i8 = 20;

/// Read a NUL-terminated device name (up to 32 bytes) from `addr`, or `None` if
/// `addr` is 0 or unreadable.
fn read_device_name(memory: &mut dyn HostMemory, addr: u32) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut name = Vec::new();
    for index in 0..32 {
        let byte = memory.read_byte(addr.checked_add(index)?)?;
        if byte == 0 {
            break;
        }
        name.push(byte);
    }
    Some(String::from_utf8_lossy(&name).into_owned())
}

/// Trackdisk housekeeping commands with no data transfer, which real hardware
/// accepts trivially — we succeed as a no-op rather than fabricating a failure.
fn is_housekeeping(command: u16) -> bool {
    matches!(
        command,
        CMD_UPDATE
            | CMD_CLEAR
            | CMD_STOP
            | CMD_START
            | CMD_FLUSH
            | TD_MOTOR
            | TD_SEEK
            | TD_REMOVE
            | TD_CHANGENUM
            | TD_CHANGESTATE
            | TD_PROTSTATUS
            | TD_ADDCHANGEINT
            | TD_REMCHANGEINT
    )
}

/// One disk transfer the environment served, recorded for the dump manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServedRead {
    /// Chronological index of the read.
    pub index: usize,
    /// The trackdisk command name (e.g. `CMD_READ`).
    pub command: String,
    /// Byte offset into the source image the read started at.
    pub offset: u64,
    /// Destination address (`io_Data`) the bytes were copied to.
    pub dest: u32,
    /// Bytes requested (`io_Length`).
    pub requested: u32,
    /// Bytes actually transferred (`io_Actual`).
    pub actual: u32,
    /// The `io_Error` status set on the request (0 = success).
    pub status: i8,
}

/// One exec/library vector the host actually serviced — the ground truth for
/// the report, unlike a static disassembly heuristic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ExecCall {
    /// Address of the calling instruction (the `JSR (d16,A6)`).
    pub site: u32,
    /// The signed library-vector offset invoked (e.g. -456 = DoIO).
    pub offset: i16,
}

/// Services a boot run's exec calls and trackdisk reads. Holds the source image
/// (served straight from its decoded sectors), a bump allocator for `AllocMem`,
/// a pool of fake library bases, and the served-read and exec-call logs.
pub struct BootHost {
    image: Vec<u8>,
    heap_next: u32,
    heap_end: u32,
    library_next: u32,
    library_end: u32,
    served_reads: Vec<ServedRead>,
    exec_calls: Vec<ExecCall>,
    /// Instruction counter, shared with the custom-chip device so the beam
    /// counter advances deterministically per step rather than per read.
    beam: Rc<Cell<u64>>,
}

impl BootHost {
    /// A host serving disk reads from `image`, sharing `beam` with the
    /// custom-chip device, and allocating from the configured heap/library.
    #[must_use]
    pub fn new(image: Vec<u8>, beam: Rc<Cell<u64>>) -> Self {
        Self {
            image,
            heap_next: layout::HEAP_BASE,
            heap_end: layout::HEAP_BASE + layout::HEAP_SIZE as u32,
            library_next: layout::LIBRARY_BASE,
            library_end: layout::LIBRARY_BASE + layout::LIBRARY_SIZE as u32,
            served_reads: Vec::new(),
            exec_calls: Vec::new(),
            beam,
        }
    }

    /// The disk transfers served so far, in chronological order.
    #[must_use]
    pub fn served_reads(&self) -> &[ServedRead] {
        &self.served_reads
    }

    /// The exec/library vectors serviced so far, in call order.
    #[must_use]
    pub fn exec_calls(&self) -> &[ExecCall] {
        &self.exec_calls
    }

    /// Allocate `size` zeroed bytes from the bump heap (8-byte aligned, as exec
    /// guarantees), returning the address or 0 when the request cannot be met.
    /// A zero-size request returns NULL, as real exec does.
    fn alloc(&mut self, size: u32) -> u32 {
        if size == 0 {
            return 0;
        }
        let Some(size) = size.checked_next_multiple_of(8) else {
            return 0;
        };
        let Some(end) = self.heap_next.checked_add(size) else {
            return 0;
        };
        if end > self.heap_end {
            return 0;
        }
        let address = self.heap_next;
        self.heap_next = end;
        address
    }

    /// Hand out the next fake library base, or 0 when the pool is exhausted. The
    /// base is deliberately *unmapped* — a real library is not modelled, so any
    /// call into it or read of its fields faults, rather than fabricating data.
    fn open_library(&mut self) -> u32 {
        let next = self.library_next.saturating_add(0x400);
        if next > self.library_end {
            return 0;
        }
        let base = self.library_next;
        self.library_next = next;
        base
    }

    /// Service an exec vector at `offset` (a negative LVO). Returns the action
    /// for `run_with_host`: usually `ReturnFromCall` after setting D0.
    fn service_exec(
        &mut self,
        offset: i16,
        site: u32,
        cpu: &mut CpuContext,
        memory: &mut dyn HostMemory,
    ) -> HostAction {
        match offset {
            LVO_DISABLE | LVO_ENABLE | LVO_FORBID | LVO_PERMIT | LVO_FREE_MEM | LVO_FREE_VEC
            | LVO_CLOSE_LIBRARY | LVO_CLOSE_DEVICE => HostAction::ReturnFromCall,
            LVO_ALLOC_MEM | LVO_ALLOC_VEC => {
                let block = self.alloc(cpu.d(0));
                cpu.set_d(0, block);
                HostAction::ReturnFromCall
            }
            LVO_OPEN_LIBRARY | LVO_OLD_OPEN_LIBRARY => {
                cpu.set_d(0, self.open_library());
                HostAction::ReturnFromCall
            }
            LVO_OPEN_DEVICE => {
                // Only trackdisk.device is modelled. Accept it (fill io_Device/
                // io_Unit and clear io_Error), and reject an identifiable other
                // device with IOERR_OPENFAIL rather than fabricating success. An
                // unreadable name is accepted (we cannot tell it apart).
                let request = cpu.a(1);
                let is_trackdisk = read_device_name(memory, cpu.a(0))
                    .is_none_or(|name| name.contains("trackdisk"));
                let status = if is_trackdisk {
                    if let Some(field) = request.checked_add(layout::IO_DEVICE) {
                        memory.write_long(field, layout::DEVICE_BASE);
                    }
                    if let Some(field) = request.checked_add(layout::IO_UNIT) {
                        memory.write_long(field, cpu.d(0));
                    }
                    0
                } else {
                    IOERR_OPENFAIL
                };
                if let Some(field) = request.checked_add(layout::IO_ERROR) {
                    memory.write_byte(field, status.to_ne_bytes()[0]);
                }
                cpu.set_d(0, status as i32 as u32);
                HostAction::ReturnFromCall
            }
            LVO_DO_IO | LVO_SEND_IO => {
                // Our model is synchronous, so SendIO does the whole transfer
                // now (WaitIO below just reports the result). Real DoIO leaves
                // io_Error in D0 (sign-extended), so `TST.B D0; BNE fail` works.
                let status = self.service_io(cpu.a(1), memory);
                cpu.set_d(0, status as i32 as u32);
                HostAction::ReturnFromCall
            }
            LVO_WAIT_IO => {
                // The IO already completed at SendIO; WaitIO reports io_Error
                // without re-transferring (which would double-count the read).
                let status = cpu
                    .a(1)
                    .checked_add(layout::IO_ERROR)
                    .and_then(|field| memory.read_byte(field))
                    .map_or(0, |byte| byte as i8);
                cpu.set_d(0, status as i32 as u32);
                HostAction::ReturnFromCall
            }
            _ => HostAction::Stop(StopReason::UnhandledCall { site, offset }),
        }
    }

    /// Service a trackdisk IO request at `request` (an `IOStdReq` in memory):
    /// serve `CMD_READ`/`ETD_READ` from the image's decoded sectors, reject a
    /// non-sector-aligned, raw, or unknown command, and record the transfer.
    /// Returns the `io_Error` status (also placed in D0 by the caller).
    fn service_io(&mut self, request: u32, memory: &mut dyn HostMemory) -> i8 {
        // A request pointer so high that its fields would wrap the 32-bit
        // address space is bogus: touch no memory, report a bad address.
        if request.checked_add(layout::IO_OFFSET + 4).is_none() {
            // The pointer is not a disk offset, so record 0, not the pointer.
            self.served_reads.push(ServedRead {
                index: self.served_reads.len(),
                command: "invalid".to_owned(),
                offset: 0,
                dest: 0,
                requested: 0,
                actual: 0,
                status: IOERR_BADADDRESS,
            });
            return IOERR_BADADDRESS;
        }

        let command = memory.read_word(request + layout::IO_COMMAND).unwrap_or(0);
        let dest = memory.read_long(request + layout::IO_DATA).unwrap_or(0);
        let length = memory.read_long(request + layout::IO_LENGTH).unwrap_or(0);
        let offset = memory.read_long(request + layout::IO_OFFSET).unwrap_or(0);

        let name = match command {
            CMD_READ => "CMD_READ",
            ETD_READ => "ETD_READ",
            // Raw MFM is not recoverable from a decoded ADF.
            TD_RAWREAD => {
                return self.finish_io(
                    request,
                    memory,
                    "TD_RAWREAD",
                    offset,
                    dest,
                    0,
                    TDERR_NOT_SPECIFIED,
                );
            }
            // Housekeeping (motor, seek, clear, ...) succeeds with no transfer.
            command if is_housekeeping(command) => {
                return self.finish_io(request, memory, "housekeeping", offset, dest, 0, 0);
            }
            _ => {
                return self.finish_io(request, memory, "unknown", offset, dest, 0, IOERR_NOCMD);
            }
        };

        if !length.is_multiple_of(layout::TD_SECTOR) || !offset.is_multiple_of(layout::TD_SECTOR) {
            return self.finish_io(request, memory, name, offset, dest, 0, IOERR_BADLENGTH);
        }
        let image_len = self.image.len() as u64;
        let start = u64::from(offset);
        if start >= image_len {
            // The offset is past the end of the image: a seek error, no copy.
            return self.finish_io(request, memory, name, offset, dest, 0, TDERR_SEEK_ERROR);
        }
        // start < image_len, so `actual` bytes from `start` are in bounds.
        let available = (image_len - start).min(u64::from(length));
        let actual = usize::try_from(available).unwrap_or(0);
        let loaded = memory
            .load(dest, &self.image[start as usize..start as usize + actual])
            .is_some();
        let (copied, status) = if !loaded {
            // io_Data is unmapped or straddles a region: nothing was written.
            (0, IOERR_BADADDRESS)
        } else if available < u64::from(length) {
            // A short read past the end of the disk is an error on real
            // hardware; the bytes that exist are still copied and recorded.
            (available as u32, TDERR_SEEK_ERROR)
        } else {
            (available as u32, 0)
        };
        self.finish_io(request, memory, name, offset, dest, copied, status)
    }

    /// Write back the IO result (`io_Actual`, `io_Error`), record the read, and
    /// return the status. The caller guarantees `request`'s fields are addressable.
    #[allow(clippy::too_many_arguments)]
    fn finish_io(
        &mut self,
        request: u32,
        memory: &mut dyn HostMemory,
        command: &str,
        offset: u32,
        dest: u32,
        actual: u32,
        status: i8,
    ) -> i8 {
        // request + IO_ACTUAL/IO_ERROR are within request + IO_OFFSET + 4, which
        // service_io verified does not overflow.
        memory.write_long(request + layout::IO_ACTUAL, actual);
        memory.write_byte(request + layout::IO_ERROR, status.to_ne_bytes()[0]);
        let requested = memory.read_long(request + layout::IO_LENGTH).unwrap_or(0);
        self.served_reads.push(ServedRead {
            index: self.served_reads.len(),
            command: command.to_owned(),
            offset: u64::from(offset),
            dest,
            requested,
            actual,
            status,
        });
        status
    }
}

/// A [`Host`](amiga_disasm::Host) that advances the beam counter and does
/// nothing else.
///
/// [`CustomChips`](crate::CustomChips) derives `VPOSR`/`VHPOSR` from a shared
/// counter, and until now the only thing that advanced it was [`BootHost`]. A
/// run under a bare `NoHost` — which is what `env.sandbox.call` uses — would
/// therefore see a frozen beam, and a beam-wait loop would spin to the step
/// budget with no explanation of why. Compose this with
/// [`HostChain`](amiga_disasm::HostChain) to give any run a moving beam.
pub struct BeamHost {
    beam: Rc<Cell<u64>>,
}

impl BeamHost {
    /// Advance `beam` once per instruction.
    #[must_use]
    pub fn new(beam: Rc<Cell<u64>>) -> Self {
        Self { beam }
    }
}

impl amiga_disasm::Host for BeamHost {
    fn tick(&mut self, _cpu: &mut CpuContext, _memory: &mut dyn HostMemory) {
        self.beam.set(self.beam.get().wrapping_add(1));
    }
}

impl amiga_disasm::Host for BootHost {
    fn tick(&mut self, _cpu: &mut CpuContext, _memory: &mut dyn HostMemory) {
        // Advance the shared beam counter once per instruction, so a beam-wait
        // poll makes progress independently of how many reads it does.
        self.beam.set(self.beam.get().wrapping_add(1));
    }

    fn claims(&self, pc: u32) -> bool {
        // Exec vectors live just below ExecBase; that window is unmapped, so a
        // JSR (-N,A6) landing there is safe to intercept.
        pc >= layout::EXEC_BASE.wrapping_sub(VECTOR_SPAN) && pc < layout::EXEC_BASE
    }

    fn on_call(
        &mut self,
        pc: u32,
        cpu: &mut CpuContext,
        memory: &mut dyn HostMemory,
    ) -> HostAction {
        // Recover the signed library-vector offset (pc = ExecBase + offset).
        let offset = i64::from(pc) - i64::from(layout::EXEC_BASE);
        let Ok(offset) = i16::try_from(offset) else {
            return HostAction::Stop(StopReason::UnhandledCall {
                site: pc,
                offset: 0,
            });
        };
        // The JSR pushed its return address (the instruction after it), so the
        // call site is that address minus the 4-byte `JSR (d16,A6)` — the ground
        // truth of where the call was made, unlike a static disassembly guess.
        let site = memory
            .read_long(cpu.sp())
            .map_or(pc, |ret| ret.wrapping_sub(4));
        self.exec_calls.push(ExecCall { site, offset });
        self.service_exec(offset, pc, cpu, memory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_allocator_aligns_and_exhausts() {
        let mut host = BootHost::new(Vec::new(), Rc::new(Cell::new(0)));
        let a = host.alloc(1);
        let b = host.alloc(1);
        assert_eq!(a, layout::HEAP_BASE);
        assert_eq!(b, layout::HEAP_BASE + 8); // 8-byte aligned
        // A request larger than the whole heap fails.
        assert_eq!(host.alloc(layout::HEAP_SIZE as u32 + 1), 0);
        // A zero-size request returns NULL.
        assert_eq!(host.alloc(0), 0);
    }
}
