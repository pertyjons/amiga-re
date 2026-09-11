//! Shared primitives for the `amiga-re` toolkit.
//!
//! This crate holds the pieces every other crate would otherwise re-implement:
//! a bounds-checked big-endian [`Reader`], provenance helpers ([`sha256`],
//! [`Source`]), safe output-path handling ([`safepath`]), all-or-nothing
//! installation of a whole changeset ([`install`]), per-project
//! configuration ([`config`]), checked conversion between the address spaces of
//! a loaded image ([`address`]), and small numeric parsing used by the CLI.

pub mod address;
pub mod cancel;
pub mod config;
mod extraction;
pub mod hexdump;
pub mod install;
mod num;
pub mod pointers;
mod provenance;
mod reader;
pub mod record;
pub mod safepath;
pub mod strings;

pub use address::{
    Address, AddressMap, Anchor, EntityKind, FileOffset, HunkId, HunkOffset, Location,
    RuntimeAddress,
};
pub use cancel::{
    BYTES_PER_CHECKPOINT, Cancel, Cancellable, Cancelled, ITEMS_PER_CHECKPOINT, Never,
};
pub use config::{Config, ConfigError, media_reference};
pub use extraction::{
    ExtractionError, ExtractionPlan, MANIFEST_SUFFIX, PlannedFile, safe_archive_path,
};
pub use install::{InstallError, STAGING_DIRECTORY, StagedChangeset};
pub use num::{parse_u32, parse_u64};
pub use provenance::{Source, sha256};
pub use reader::{Reader, ReaderError};
pub use safepath::{
    PathError, ensure_dir, is_safe_component, prepare_output_dir, prepare_output_file,
    reject_symlink, validate_output_file,
};
pub use strings::{FoundString, latin1, latin1_cstr, scan as scan_strings};
