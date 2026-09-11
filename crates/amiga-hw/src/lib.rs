//! Amiga custom-chip knowledge shared across the toolkit.
//!
//! - [`blitter`]: the blitter's effect on memory, as an OCS area-mode blit.
//! - [`copper`]: conservative Copper-list discovery in raw binaries.
//! - [`registers`]: custom-chip register offset → name map.
//! - [`color`]: 12-bit Amiga color to 8-bit-per-channel RGB.
//! - [`planar`]: planar bitplane to chunky palette-index conversion.

pub mod blitter;
pub mod color;
pub mod copper;
pub mod detect;
pub mod display;
pub mod palette;
pub mod planar;
mod png;
pub mod registers;

pub use blitter::{
    BlitConditions, BlitObservation, BlitOutcome, BlitRefusal, Blitter, ChannelPointers, Chipset,
    DmaMemory, DmaPolicy, OcsBlitSize, RegisterWriteOutcome, StartRequest, is_blitter_register,
    is_unmodelled_start_trigger,
};
pub use color::rgb4_to_rgb8;
pub use copper::{
    BitplanePointer, CopperInstruction, CopperList, CopperMove, CopperOp, CopperPalette,
    CopperPatchSite, CopperWord, DisplaySpec, decode, display_spec, is_display_register,
    patch_site, scan,
};
pub use detect::{EntropyBlock, RegionClass, StrideScore};
pub use display::{
    DisplayError, DisplayRegisters, DisplayWarning, Frame, RasterInterval, reconstruct,
};
pub use palette::PaletteTable;
pub use planar::{
    Bob, BobImage, BobMask, Chunk, GlyphSheet, IndexedImage, PlanarError, PlaneOrder, deinterleave,
    deinterleave_cancellable,
};
pub use png::{PngError, encode_indexed_png, encode_rgba_png};
pub use registers::{
    CUSTOM_BASE, is_color_register, is_pointer_low, known_registers, register_name, subsystem,
};
