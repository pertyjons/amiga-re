//! The synthetic Amiga memory map the boot environment seeds.
//!
//! The addresses are arbitrary but fixed and non-overlapping, so the register/
//! memory contract a boot block sees is reproducible and documented. This is the
//! single source of truth for the layout, shared by the environment and the CLI.

/// Chip-RAM region, covering absolute 4, the IORequest, and the boot block.
pub const CHIP_BASE: u32 = 0;
/// Chip-RAM length (512 KiB — an A500's chip memory).
pub const CHIP_SIZE: usize = 0x8_0000;
/// The fake ExecBase, in its own region so the library-vector space just below
/// it is unmapped and an unemulated LVO call faults promptly.
pub const EXEC_BASE: u32 = 0x00f8_0000;
/// Length of the ExecBase region (enough for the positive-offset fields code
/// reads through A6).
pub const EXEC_SIZE: usize = 0x400;
/// The synthetic already-open `trackdisk.device` IORequest (an `IOStdReq`).
pub const IOREQ: u32 = 0x0000_0500;
/// Fake trackdisk device base stored in the IORequest's `io_Device`.
pub const DEVICE_BASE: u32 = 0x0000_0600;
/// Fake unit stored in the IORequest's `io_Unit`.
pub const DEVICE_UNIT: u32 = 0x0000_0700;
/// Where the 1024-byte boot block is loaded.
pub const BOOT_LOAD: u32 = 0x0000_1000;
/// Custom-chip register page base (`$DFF000`).
pub const CUSTOM_BASE: u32 = 0x00df_f000;
/// Custom-chip register page length (`$DFF000..$DFF200`).
pub const CUSTOM_SIZE: usize = 0x200;
/// Supervisor stack region base.
pub const STACK_BASE: u32 = 0x0010_0000;
/// Supervisor stack region length.
pub const STACK_SIZE: usize = 0x1_0000;
/// Base of the bump heap `AllocMem` hands out from.
pub const HEAP_BASE: u32 = 0x0020_0000;
/// Length of the bump heap.
pub const HEAP_SIZE: usize = 0x10_0000;
/// Base of the region holding fake library bases handed out by `OpenLibrary`.
/// Its vector space (just below each base) is unmapped, so calls into an
/// unmodelled library trap or are intercepted.
pub const LIBRARY_BASE: u32 = 0x00fc_0000;
/// Length of the fake-library region.
pub const LIBRARY_SIZE: usize = 0x4000;
/// Return marker parked in unmapped space; the top-level RTS pops it to stop.
pub const RETURN_MARKER: u32 = 0x00ff_fffe;

/// A trackdisk sector: `io_Offset`/`io_Length` for a `CMD_READ` must be multiples.
pub const TD_SECTOR: u32 = 512;

/// `io_Device` field offset within an Exec IORequest.
pub const IO_DEVICE: u32 = 20;
/// `io_Unit` field offset within an Exec IORequest.
pub const IO_UNIT: u32 = 24;
/// `io_Command` field offset (UWORD).
pub const IO_COMMAND: u32 = 28;
/// `io_Error` field offset (BYTE) — 0 on success.
pub const IO_ERROR: u32 = 31;
/// `io_Actual` field offset (ULONG) — bytes actually transferred.
pub const IO_ACTUAL: u32 = 32;
/// `io_Length` field offset (ULONG) — bytes requested.
pub const IO_LENGTH: u32 = 36;
/// `io_Data` field offset (APTR) — destination buffer.
pub const IO_DATA: u32 = 40;
/// `io_Offset` field offset (ULONG) — byte offset into the decoded image.
pub const IO_OFFSET: u32 = 44;

/// The absolute entry PC: the boot code at block + 12.
#[must_use]
pub const fn entry() -> u32 {
    BOOT_LOAD + amiga_adf::Bootblock::CODE_OFFSET as u32
}
