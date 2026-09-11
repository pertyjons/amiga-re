//! Amiga decompressors.
//!
//! - [`powerpacker`]: headerless PowerPacker bitstream decompression.
//! - [`rle`]: IFF ByteRun1 / PackBits run-length decoding.
//! - [`rle_xor`]: position-XOR + escape-marker run-length decoding.

pub mod powerpacker;
pub mod rle;
pub mod rle_xor;

pub use powerpacker::{
    PowerPackerError, decode_embedded_powerpacker, decode_embedded_powerpacker_bounded,
};
pub use rle::{RleError, decode_byte_run1, decode_byte_run1_bounded};
pub use rle_xor::{
    RleXorDecoded, RleXorError, RleXorParams, decode as decode_rle_xor,
    decode_bounded as decode_rle_xor_bounded,
};
