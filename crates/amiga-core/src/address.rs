//! The address spaces one byte of a loaded Amiga image lives in.
//!
//! A HUNK executable names the same byte in up to four ways, and confusing them
//! is one of the classic sources of wrong reverse-engineering notes:
//!
//! - a [`FileOffset`] into the source file, which is what a hex editor shows;
//! - a [`HunkOffset`] from the start of a hunk's contents, which is what a
//!   disassembly of that hunk shows;
//! - a [`RuntimeAddress`], the address the byte occupies once the image is
//!   mapped at a known origin;
//! - a symbolic name, which this module deliberately leaves to the caller
//!   because it comes from downstream configuration.
//!
//! [`AddressMap`] converts between the first three for one hunk, with every
//! conversion checked, and [`Location`] carries the frames that resolved so a
//! renderer can show them together. The frame-carrying types have no bare
//! [`Display`](std::fmt::Display) of their own: an address is printed through
//! [`Address`] or [`Location`], both of which name the space they belong to.

use std::fmt;

use serde::Serialize;

/// Index of a hunk inside a HUNK executable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[must_use]
pub struct HunkId(u32);

impl HunkId {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for HunkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "hunk{}", self.0)
    }
}

/// A byte offset from the start of a hunk's contents.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[must_use]
pub struct HunkOffset(u32);

impl HunkOffset {
    pub const fn new(offset: u32) -> Self {
        Self(offset)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A byte offset from the start of the source file.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[must_use]
pub struct FileOffset(u64);

impl FileOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The address a byte occupies once the image is mapped at its origin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[must_use]
pub struct RuntimeAddress(u32);

impl RuntimeAddress {
    pub const fn new(address: u32) -> Self {
        Self(address)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One address, printed with the space it belongs to.
///
/// Use this for an address that resolves in a single frame — a runtime address
/// outside the analyzed image, or a hunk offset before an [`AddressMap`] is
/// available. Use [`Location`] when several frames resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Address {
    /// An offset into a hunk's contents, printed as `hunk0+0x1a`.
    Hunk(HunkId, HunkOffset),
    /// A mapped address, printed as `abs 0x1a`.
    Runtime(RuntimeAddress),
    /// A whole-file offset, printed as `file 0x1a`.
    File(FileOffset),
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hunk(hunk, offset) => write!(formatter, "{hunk}+{:#x}", offset.get()),
            Self::Runtime(address) => write!(formatter, "abs {:#x}", address.get()),
            Self::File(offset) => write!(formatter, "file {:#x}", offset.get()),
        }
    }
}

/// What kind of entity a report [`Anchor`] names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// One decoded instruction, anchored at its first byte.
    Instruction,
    /// A function, anchored at its entry.
    Function,
    /// A configured symbol, anchored where it resolves.
    Symbol,
    /// A classified region of data, anchored at its first byte.
    DataRegion,
}

impl EntityKind {
    /// The short tag this kind contributes to an anchor.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Instruction => "insn",
            Self::Function => "fn",
            Self::Symbol => "sym",
            Self::DataRegion => "data",
        }
    }
}

/// A stable identifier for one entity of a report, e.g. `h0-fn-00000008`.
///
/// An anchor is derived only from the hunk, the kind, and the offset, so the
/// same entity of the same input always gets the same anchor: reports stay
/// comparable across runs, and a renderer can link to an entity it has not
/// emitted yet. The form is `h<hunk>-<kind>-<offset as 8 hex digits>`, which
/// is a valid HTML fragment identifier and contains no user-supplied text.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[must_use]
pub struct Anchor {
    kind: EntityKind,
    hunk: HunkId,
    offset: HunkOffset,
}

impl Anchor {
    pub const fn new(kind: EntityKind, hunk: HunkId, offset: HunkOffset) -> Self {
        Self { kind, hunk, offset }
    }

    pub const fn kind(self) -> EntityKind {
        self.kind
    }

    pub const fn hunk(self) -> HunkId {
        self.hunk
    }

    pub const fn offset(self) -> HunkOffset {
        self.offset
    }
}

impl fmt::Display for Anchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "h{}-{}-{:08x}",
            self.hunk.get(),
            self.kind.tag(),
            self.offset.get()
        )
    }
}

impl Serialize for Anchor {
    /// Anchors serialize as their printed form so JSON and text name the same
    /// entity with the same string.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Every address space in which one byte of a mapped hunk resolves.
///
/// Produced by [`AddressMap::locate`]. `file` and `runtime` are `None` when the
/// map has no file anchor or no mapped origin, so a report never invents a
/// frame it cannot prove.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Location {
    pub hunk: HunkId,
    pub offset: HunkOffset,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeAddress>,
}

impl Location {
    /// The hunk-relative form alone, for contexts too narrow for every frame.
    #[must_use]
    pub const fn short(&self) -> Address {
        Address::Hunk(self.hunk, self.offset)
    }
}

impl fmt::Display for Location {
    /// `hunk0+0x1a (abs 0xe658, file 0x3a)`, listing only the frames that
    /// resolved.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.short())?;
        let extra: Vec<String> = self
            .runtime
            .map(|address| Address::Runtime(address).to_string())
            .into_iter()
            .chain(self.file.map(|offset| Address::File(offset).to_string()))
            .collect();
        if extra.is_empty() {
            return Ok(());
        }
        write!(formatter, " ({})", extra.join(", "))
    }
}

/// Checked conversions between the address spaces of one hunk.
///
/// Build with [`AddressMap::new`] and add the frames the caller actually knows:
/// [`AddressMap::with_file_start`] for the hunk's position in the source file,
/// [`AddressMap::with_origin`] for the address hunk offset zero is mapped at.
/// Conversions into a frame that was never supplied return `None` rather than
/// guessing, and every conversion is checked so a hunk mapped near the end of
/// the address space cannot wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct AddressMap {
    hunk: HunkId,
    size: u32,
    file_start: Option<FileOffset>,
    origin: Option<RuntimeAddress>,
}

impl AddressMap {
    /// A map for `hunk`, whose contents are `size` bytes long, with no file
    /// anchor and no mapped origin.
    pub const fn new(hunk: HunkId, size: u32) -> Self {
        Self {
            hunk,
            size,
            file_start: None,
            origin: None,
        }
    }

    /// Anchor the whole-file frame on the hunk's first content byte.
    pub const fn with_file_start(mut self, start: FileOffset) -> Self {
        self.file_start = Some(start);
        self
    }

    /// Map hunk offset zero at `origin`, enabling the runtime frame.
    pub const fn with_origin(mut self, origin: RuntimeAddress) -> Self {
        self.origin = Some(origin);
        self
    }

    pub const fn hunk(&self) -> HunkId {
        self.hunk
    }

    /// The hunk's content length in bytes.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.size
    }

    pub const fn origin(&self) -> Option<RuntimeAddress> {
        self.origin
    }

    pub const fn file_start(&self) -> Option<FileOffset> {
        self.file_start
    }

    /// Whether `offset` addresses a byte of this hunk's contents.
    #[must_use]
    pub const fn contains(&self, offset: HunkOffset) -> bool {
        offset.get() < self.size
    }

    /// The whole-file offset of `offset`, when a file anchor is known.
    pub const fn file_offset(&self, offset: HunkOffset) -> Option<FileOffset> {
        match self.file_start {
            Some(start) => match start.get().checked_add(offset.get() as u64) {
                Some(sum) => Some(FileOffset::new(sum)),
                None => None,
            },
            None => None,
        }
    }

    /// The mapped address of `offset`, when an origin is known.
    pub const fn runtime(&self, offset: HunkOffset) -> Option<RuntimeAddress> {
        match self.origin {
            Some(origin) => match origin.get().checked_add(offset.get()) {
                Some(sum) => Some(RuntimeAddress::new(sum)),
                None => None,
            },
            None => None,
        }
    }

    /// The hunk offset of a mapped address, when an origin is known and the
    /// address is at or above it. The result may still lie outside the hunk;
    /// test it with [`AddressMap::contains`].
    pub const fn offset_of(&self, address: RuntimeAddress) -> Option<HunkOffset> {
        match self.origin {
            Some(origin) => match address.get().checked_sub(origin.get()) {
                Some(difference) => Some(HunkOffset::new(difference)),
                None => None,
            },
            None => None,
        }
    }

    /// The stable anchor of an entity of `kind` at `offset` in this hunk.
    pub const fn anchor(&self, kind: EntityKind, offset: HunkOffset) -> Anchor {
        Anchor::new(kind, self.hunk, offset)
    }

    /// Every frame in which `offset` resolves.
    pub const fn locate(&self, offset: HunkOffset) -> Location {
        Location {
            hunk: self.hunk,
            offset,
            file: self.file_offset(offset),
            runtime: self.runtime(offset),
        }
    }

    /// Every frame of a mapped address, when it maps into this hunk's
    /// contents; `None` when there is no origin, the address is below it, or
    /// it falls outside the hunk.
    pub const fn locate_runtime(&self, address: RuntimeAddress) -> Option<Location> {
        match self.offset_of(address) {
            Some(offset) if self.contains(offset) => Some(self.locate(offset)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> AddressMap {
        AddressMap::new(HunkId::new(0), 0x100)
            .with_file_start(FileOffset::new(0x20))
            .with_origin(RuntimeAddress::new(0xe63e))
    }

    #[test]
    fn resolves_every_frame_of_an_offset() {
        let location = map().locate(HunkOffset::new(0x10));
        assert_eq!(location.hunk, HunkId::new(0));
        assert_eq!(location.offset, HunkOffset::new(0x10));
        assert_eq!(location.file, Some(FileOffset::new(0x30)));
        assert_eq!(location.runtime, Some(RuntimeAddress::new(0xe64e)));
    }

    #[test]
    fn omits_frames_that_were_never_supplied() {
        let bare = AddressMap::new(HunkId::new(2), 0x10);
        let location = bare.locate(HunkOffset::new(4));
        assert_eq!(location.file, None);
        assert_eq!(location.runtime, None);
        assert_eq!(bare.offset_of(RuntimeAddress::new(0x1000)), None);
        assert_eq!(location.to_string(), "hunk2+0x4");
    }

    #[test]
    fn displays_the_space_of_every_address_it_prints() {
        assert_eq!(
            map().locate(HunkOffset::new(0x10)).to_string(),
            "hunk0+0x10 (abs 0xe64e, file 0x30)"
        );
        assert_eq!(
            Address::Runtime(RuntimeAddress::new(0xdff096)).to_string(),
            "abs 0xdff096"
        );
        assert_eq!(
            Address::File(FileOffset::new(0x30)).to_string(),
            "file 0x30"
        );
        assert_eq!(
            Address::Hunk(HunkId::new(1), HunkOffset::new(0)).to_string(),
            "hunk1+0x0"
        );
    }

    #[test]
    fn maps_a_runtime_address_back_into_the_hunk() {
        let map = map();
        assert_eq!(
            map.locate_runtime(RuntimeAddress::new(0xe64e))
                .map(|location| location.offset),
            Some(HunkOffset::new(0x10))
        );
        // Below the origin, and beyond the hunk's contents.
        assert_eq!(map.locate_runtime(RuntimeAddress::new(0xe000)), None);
        assert_eq!(map.locate_runtime(RuntimeAddress::new(0xf000)), None);
    }

    #[test]
    fn conversions_are_checked_at_the_end_of_each_space() {
        let high = AddressMap::new(HunkId::new(0), 0x10)
            .with_file_start(FileOffset::new(u64::MAX))
            .with_origin(RuntimeAddress::new(u32::MAX));
        assert_eq!(high.file_offset(HunkOffset::new(1)), None);
        assert_eq!(high.runtime(HunkOffset::new(1)), None);
        assert_eq!(
            high.runtime(HunkOffset::new(0)),
            Some(RuntimeAddress::new(u32::MAX))
        );
    }

    #[test]
    fn anchors_are_stable_and_distinguish_entity_kinds() {
        let map = map();
        let function = map.anchor(EntityKind::Function, HunkOffset::new(8));
        assert_eq!(function.to_string(), "h0-fn-00000008");
        assert_eq!(
            function,
            map.anchor(EntityKind::Function, HunkOffset::new(8))
        );
        // Same place, different entity: distinct anchors.
        assert_ne!(function, map.anchor(EntityKind::Symbol, HunkOffset::new(8)));
        assert_eq!(
            map.anchor(EntityKind::Symbol, HunkOffset::new(8))
                .to_string(),
            "h0-sym-00000008"
        );
        assert_eq!(
            map.anchor(EntityKind::Instruction, HunkOffset::new(0x1a))
                .to_string(),
            "h0-insn-0000001a"
        );
        assert_eq!(
            map.anchor(EntityKind::DataRegion, HunkOffset::new(0x44))
                .to_string(),
            "h0-data-00000044"
        );
        // Same offset and kind in another hunk is another entity.
        let other = AddressMap::new(HunkId::new(3), 0x10);
        assert_ne!(
            other.anchor(EntityKind::Function, HunkOffset::new(8)),
            function
        );
    }

    #[test]
    fn anchors_serialize_as_their_printed_form() {
        let anchor = map().anchor(EntityKind::Function, HunkOffset::new(0x42));
        let json = serde_json::to_string(&anchor).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(json, "\"h0-fn-00000042\"");
    }

    #[test]
    fn containment_follows_the_hunk_size() {
        let map = map();
        assert!(map.contains(HunkOffset::new(0xff)));
        assert!(!map.contains(HunkOffset::new(0x100)));
    }
}
