//! A small, read-only AmigaDOS reader, covering both the Old File System (OFS)
//! and the Fast File System (FFS).
//!
//! The reader deliberately tolerates damaged boot blocks, allocation bitmaps,
//! and inconsistent empty-file data pointers. Directory and file header blocks
//! must still be structurally valid, and non-empty file data chains are checked
//! carefully before bytes are returned.
//!
//! # The two filesystems
//!
//! Enumeration is identical: root, directory, and file *header* blocks have the
//! same layout in both, carry the same checksum, and are walked the same way.
//! Only file *contents* differ, and they differ completely:
//!
//! - **OFS** wraps every data block in a 24-byte header carrying the owning
//!   file, a sequence number, the payload length, and a pointer to the next
//!   block. Recovery follows that chain.
//! - **FFS** has no data-block header at all: all 512 bytes are payload, and
//!   there is no checksum to verify. The blocks are named instead by a table in
//!   the file header — 72 longwords at offset 24, **filled from the end**, so the
//!   first data block is the last entry and `high_seq` says how many are in use —
//!   continued through a chain of extension blocks. Because no block carries a
//!   length, the file header's declared size is what bounds the final partial
//!   block.
//!
//! Which one an image uses is bit 0 of the boot block's flag byte, read at
//! [`Image::open`] and recorded on the [`Image`], so a file is never recovered by
//! the wrong reader. The flag is only meaningful on a volume whose tag is `DOS`;
//! anything else has no AmigaDOS filesystem to declare, and such an image is read
//! as OFS.
//!
//! International (flag bit 1) and directory-cache (bit 2) modes change how names
//! are *hashed*, not how data is laid out. Enumeration walks every hash bucket
//! rather than looking a name up, so neither mode affects this reader.
//!
//! # What has been verified, and what has not
//!
//! Every checked-in fixture here is synthetic, OFS included — but the OFS path
//! has also been run against private media by the projects that depend on this
//! crate, which is what has kept it honest. **The FFS path has only ever been run
//! against synthetic fixtures**: no FFS image was available anywhere in the
//! workspace when it was written. The block offsets come from the AmigaDOS
//! filesystem layout rather than from a disk, and a fixture written by the same
//! author as the reader cannot prove them. Two things reduce that risk and
//! neither eliminates it: the tests assert exact recovered *content* of a
//! multi-block file, which a wrongly ordered table or a mistakenly skipped
//! header would corrupt visibly; and [`Image::read_file`] *refuses* a file whose
//! data table disagrees with the header's own redundant `first_data` field, so a
//! systematically wrong table index fails loudly on any real image rather than
//! returning bytes that are all present and all misplaced. Treat a first
//! successful read of a real FFS disk as the actual confirmation.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const BLOCK_SIZE: usize = 512;
/// Longwords in a header block's hash table, and in a file header's data-block
/// table: both occupy the same region, 72 entries at offset 24.
const HASH_SIZE: usize = 72;
const TYPE_HEADER: i32 = 2;
const TYPE_DATA: i32 = 8;
/// A file extension block, which carries nothing but more data-block pointers.
const TYPE_LIST: i32 = 16;
const ST_ROOT: i32 = 1;
const ST_USERDIR: i32 = 2;
const ST_FILE: i32 = -3;
/// Byte offset of the data-block / hash table within a header block.
const TABLE_OFFSET: usize = 24;
/// Byte offset of a file header's pointer to its first extension block.
const EXTENSION_OFFSET: usize = 504;

/// Which AmigaDOS filesystem an image holds.
///
/// Recorded at [`Image::open`] rather than guessed per file, so a file can never
/// be recovered by the reader for the other one — which would produce plausible
/// bytes rather than an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSystem {
    /// Old File System: every data block carries a 24-byte header.
    Ofs,
    /// Fast File System: data blocks are payload only, named by a table.
    Ffs,
}

impl fmt::Display for FileSystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ofs => "OFS",
            Self::Ffs => "FFS",
        })
    }
}

/// A block index within an image.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockNumber(u32);

impl BlockNumber {
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for BlockNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A size in bytes.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteSize(u32);

impl ByteSize {
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A failure that prevents reading the image or a file within it.
#[derive(Debug, Error)]
pub enum Error {
    #[error("image length {0} is not a non-zero multiple of 512 bytes")]
    InvalidImageSize(usize),
    #[error("no OFS root block was found")]
    RootNotFound,
    #[error("block {block} is outside the image")]
    BlockOutOfRange { block: u32 },
    #[error("block {block}: {message}")]
    InvalidBlock { block: u32, message: String },
    #[error("directory graph contains a cycle at block {block}")]
    DirectoryCycle { block: u32 },
    #[error("file {path} has a cyclic data chain at block {block}")]
    DataCycle { path: PathBuf, block: u32 },
    #[error("file {path}: expected {expected} bytes but recovered {actual}")]
    FileSizeMismatch {
        path: PathBuf,
        expected: u32,
        actual: usize,
    },
    #[error("image is {0} bytes, too small for a 1024-byte boot block")]
    BootblockTooSmall(usize),
}

/// A floppy boot block: the first two sectors (1024 bytes) of a disk.
///
/// The tag, checksum, and root-block pointer are meaningful for AmigaDOS disks;
/// non-DOS trackloader disks (custom-boot games) still carry 68k boot code from
/// [`Bootblock::CODE_OFFSET`], reachable via [`Bootblock::boot_code`].
#[derive(Clone, Copy, Debug)]
pub struct Bootblock<'a> {
    bytes: &'a [u8],
}

impl<'a> Bootblock<'a> {
    /// A boot block spans two 512-byte sectors.
    pub const SIZE: usize = BLOCK_SIZE * 2;
    /// Byte offset of the boot code within the block.
    pub const CODE_OFFSET: usize = 12;

    /// Borrow the first [`Bootblock::SIZE`] bytes of `image` as a boot block.
    ///
    /// # Errors
    /// [`Error::BootblockTooSmall`] if `image` is shorter than 1024 bytes.
    pub fn parse(image: &'a [u8]) -> Result<Self, Error> {
        let bytes = image
            .get(..Self::SIZE)
            .ok_or(Error::BootblockTooSmall(image.len()))?;
        Ok(Self { bytes })
    }

    /// The 4-byte disk-type tag (bytes 0..4, e.g. `DOS\0`).
    #[must_use]
    pub fn magic(&self) -> [u8; 4] {
        [self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]
    }

    /// The disk-type flag byte (bit 0: FFS, bit 1: international, bit 2: dir-cache).
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.bytes[3]
    }

    /// Whether the tag is the AmigaDOS `DOS` signature.
    #[must_use]
    pub fn is_dos(&self) -> bool {
        &self.bytes[0..3] == b"DOS"
    }

    /// Which filesystem this volume declares.
    ///
    /// Bit 0 of the flag byte, and only on a `DOS` volume: a trackloader disk's
    /// fourth byte is boot code or padding, not a filesystem flag, and reading it
    /// as one would pick a data-block layout from noise.
    #[must_use]
    pub fn filesystem(&self) -> FileSystem {
        if self.is_dos() && self.flags() & 1 == 1 {
            FileSystem::Ffs
        } else {
            FileSystem::Ofs
        }
    }

    /// The stored boot checksum (longword at offset 4).
    #[must_use]
    pub fn stored_checksum(&self) -> u32 {
        read_u32(self.bytes, 4)
    }

    /// The root-block pointer (longword at offset 8; usually 880 for a DD disk).
    #[must_use]
    pub fn root_block(&self) -> u32 {
        read_u32(self.bytes, 8)
    }

    /// Whether the end-around-carry boot checksum is valid.
    #[must_use]
    pub fn has_valid_checksum(&self) -> bool {
        valid_boot_checksum(self.bytes)
    }

    /// The boot code: the bytes from [`Bootblock::CODE_OFFSET`] to the block end.
    #[must_use]
    pub fn boot_code(&self) -> &'a [u8] {
        &self.bytes[Self::CODE_OFFSET..]
    }

    /// Whether the boot code carries any non-zero byte (i.e. is present).
    #[must_use]
    pub fn has_boot_code(&self) -> bool {
        self.boot_code().iter().any(|byte| *byte != 0)
    }
}

/// What kind of tolerated inconsistency a [`Warning`] describes.
///
/// Deliberately *not* `#[non_exhaustive]`. A consumer that maps a kind onto its
/// own vocabulary — `amiga-operations` maps each onto a stable diagnostic code —
/// should fail to compile when a new kind appears, so that adding one forces the
/// decision instead of silently widening a catch-all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WarningKind {
    /// The boot block's end-around-carry checksum does not verify. The volume is
    /// still walked, because the filesystem does not depend on the boot block.
    BootBlockChecksumInvalid,
    /// A file header declares a size of zero yet still points at a first data
    /// block. The declared size wins and the data pointer is ignored.
    EmptyFileWithDataPointer,
}

/// A tolerated inconsistency, reported rather than silently ignored.
///
/// `kind` is what a consumer may act on; `message` is its human rendering and
/// carries no contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Warning {
    pub kind: WarningKind,
    pub block: u32,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => formatter.write_str("file"),
            Self::Directory => formatter.write_str("directory"),
        }
    }
}

/// A file or directory located during the directory walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub path: PathBuf,
    pub name: String,
    pub kind: EntryKind,
    pub header_block: BlockNumber,
    pub size: ByteSize,
    first_data: u32,
}

/// An immutable view of an ADF image.
pub struct Image<'a> {
    bytes: &'a [u8],
    root_block: u32,
    filesystem: FileSystem,
    volume_name: String,
    entries: Vec<Entry>,
    warnings: Vec<Warning>,
}

impl<'a> Image<'a> {
    /// Open and index an image, walking its directory tree.
    ///
    /// # Errors
    /// Returns [`Error`](enum@Error) if the image is not a whole number of 512-byte blocks,
    /// lacks an OFS root block, or contains a structurally invalid or cyclic
    /// directory graph.
    pub fn open(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidImageSize(bytes.len()));
        }

        let root_block = find_root(bytes).ok_or(Error::RootNotFound)?;
        let root = block(bytes, root_block)?;
        let volume_name = block_name(root, root_block)?;
        // Decided once, here, from the boot block. Deciding per file — or worse,
        // sniffing a data block for an OFS header — would let one image be read
        // both ways and produce plausible bytes for the wrong one.
        let filesystem = Bootblock::parse(bytes).map_or(FileSystem::Ofs, |boot| boot.filesystem());
        let mut image = Self {
            bytes,
            root_block,
            filesystem,
            volume_name,
            entries: Vec::new(),
            warnings: Vec::new(),
        };
        if !valid_boot_checksum(bytes) {
            image.warnings.push(Warning {
                kind: WarningKind::BootBlockChecksumInvalid,
                block: 0,
                message: "boot block checksum is invalid; ignored for filesystem recovery".into(),
            });
        }
        let mut visited_directories = HashSet::new();
        image.walk_directory(root_block, Path::new(""), &mut visited_directories)?;
        image
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
        Ok(image)
    }

    #[must_use]
    pub fn volume_name(&self) -> &str {
        &self.volume_name
    }

    pub fn root_block(&self) -> BlockNumber {
        BlockNumber(self.root_block)
    }

    /// Which filesystem this image was opened as.
    #[must_use]
    pub const fn filesystem(&self) -> FileSystem {
        self.filesystem
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[must_use]
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Recover the bytes of `entry`, validating the data chain.
    ///
    /// Dispatches on the filesystem recorded at [`Image::open`]: an OFS chain of
    /// self-describing data blocks, or an FFS table of raw ones.
    ///
    /// # Errors
    /// Returns [`Error`](enum@Error) if the entry is not a file, its data chain is cyclic or
    /// structurally invalid, or the recovered length does not match the declared
    /// file size.
    pub fn read_file(&self, entry: &Entry) -> Result<Vec<u8>, Error> {
        if entry.kind != EntryKind::File {
            return Err(Error::InvalidBlock {
                block: entry.header_block.get(),
                message: "entry is not a file".into(),
            });
        }
        if entry.size.get() == 0 {
            // Some mastered disks retain a stale first-data pointer on an empty
            // save slot. Its declared length is authoritative.
            return Ok(Vec::new());
        }
        match self.filesystem {
            FileSystem::Ofs => self.read_file_ofs(entry),
            FileSystem::Ffs => self.read_file_ffs(entry),
        }
    }

    /// Recover an FFS file from its data-block tables.
    ///
    /// The table is read from its end, because that is how AmigaDOS fills it: the
    /// first data block is the last entry, so the `k`-th block of the file is at
    /// table index `72 - k`. Reading it forward would return a file whose blocks
    /// are in reverse order — bytes that are all present and all in the wrong
    /// place, which is why the tests assert content rather than length.
    ///
    /// A data block is taken whole and unverified: FFS stores no header and no
    /// checksum in one, so there is nothing to check it against. The declared file
    /// size is therefore the only bound on the final block, and the only thing
    /// that says the recovery is complete.
    fn read_file_ffs(&self, entry: &Entry) -> Result<Vec<u8>, Error> {
        let declared = entry.size.get() as usize;
        let mut result = Vec::with_capacity(declared);
        let mut seen_data = HashSet::new();
        let mut seen_headers = HashSet::new();
        let mut current_header = entry.header_block.get();
        let mut first_block_checked = false;

        loop {
            if !seen_headers.insert(current_header) {
                return Err(Error::DataCycle {
                    path: entry.path.clone(),
                    block: current_header,
                });
            }
            // Header and extension blocks *are* checksummed, unlike data blocks.
            let header = block(self.bytes, current_header)?;
            if current_header != entry.header_block.get() {
                let kind = read_i32(header, 0);
                let secondary = read_i32(header, 508);
                if kind != TYPE_LIST || secondary != ST_FILE {
                    return Err(Error::InvalidBlock {
                        block: current_header,
                        message: format!(
                            "expected a file extension block, found type {kind} / {secondary}"
                        ),
                    });
                }
            }

            let high_seq = read_u32(header, 8) as usize;
            if high_seq > HASH_SIZE {
                return Err(Error::InvalidBlock {
                    block: current_header,
                    message: format!("data table claims {high_seq} entries, above {HASH_SIZE}"),
                });
            }
            for sequence in 1..=high_seq {
                if result.len() >= declared {
                    // A table may name more blocks than the declared size needs.
                    // The size wins, as it does for the final partial block.
                    break;
                }
                let index = HASH_SIZE - sequence;
                let data_block = read_u32(header, TABLE_OFFSET + index * 4);
                if data_block == 0 {
                    return Err(Error::InvalidBlock {
                        block: current_header,
                        message: format!("data table entry {sequence} of {high_seq} is empty"),
                    });
                }
                // The header repeats its first data block in `first_data`. That
                // redundancy is the only independent check available on the table
                // index, so it is used rather than ignored.
                if !first_block_checked {
                    first_block_checked = true;
                    if entry.first_data != 0 && entry.first_data != data_block {
                        return Err(Error::InvalidBlock {
                            block: entry.header_block.get(),
                            message: format!(
                                "data table starts at block {data_block} but first_data \
                                 names {}",
                                entry.first_data
                            ),
                        });
                    }
                }
                if !seen_data.insert(data_block) {
                    return Err(Error::DataCycle {
                        path: entry.path.clone(),
                        block: data_block,
                    });
                }
                let data = raw_block(self.bytes, data_block)?;
                let take = (declared - result.len()).min(BLOCK_SIZE);
                result.extend_from_slice(&data[..take]);
            }

            let next = read_u32(header, EXTENSION_OFFSET);
            if next == 0 || result.len() >= declared {
                break;
            }
            current_header = next;
        }

        if result.len() != declared {
            return Err(Error::FileSizeMismatch {
                path: entry.path.clone(),
                expected: entry.size.get(),
                actual: result.len(),
            });
        }
        Ok(result)
    }

    /// Recover an OFS file by following its chain of self-describing data blocks.
    fn read_file_ofs(&self, entry: &Entry) -> Result<Vec<u8>, Error> {
        let mut result = Vec::with_capacity(entry.size.get() as usize);
        let mut current = entry.first_data;
        let mut seen = HashSet::new();
        let mut expected_sequence = 1_u32;
        while current != 0 && result.len() < entry.size.get() as usize {
            if !seen.insert(current) {
                return Err(Error::DataCycle {
                    path: entry.path.clone(),
                    block: current,
                });
            }
            let data = block(self.bytes, current)?;
            if read_i32(data, 0) != TYPE_DATA {
                return Err(Error::InvalidBlock {
                    block: current,
                    message: "expected an OFS data block".into(),
                });
            }
            let owner = read_u32(data, 4);
            if owner != entry.header_block.get() {
                return Err(Error::InvalidBlock {
                    block: current,
                    message: format!(
                        "data block belongs to header {owner}, expected {}",
                        entry.header_block
                    ),
                });
            }
            let sequence = read_u32(data, 8);
            if sequence != expected_sequence {
                return Err(Error::InvalidBlock {
                    block: current,
                    message: format!("data sequence is {sequence}, expected {expected_sequence}"),
                });
            }
            let data_size = read_u32(data, 12) as usize;
            if data_size > BLOCK_SIZE - 24 {
                return Err(Error::InvalidBlock {
                    block: current,
                    message: format!("data payload is too large: {data_size}"),
                });
            }
            let remaining = entry.size.get() as usize - result.len();
            result.extend_from_slice(&data[24..24 + data_size.min(remaining)]);
            current = read_u32(data, 16);
            expected_sequence += 1;
        }

        if result.len() != entry.size.get() as usize {
            return Err(Error::FileSizeMismatch {
                path: entry.path.clone(),
                expected: entry.size.get(),
                actual: result.len(),
            });
        }
        Ok(result)
    }

    fn walk_directory(
        &mut self,
        directory_block: u32,
        parent_path: &Path,
        visited_directories: &mut HashSet<u32>,
    ) -> Result<(), Error> {
        if !visited_directories.insert(directory_block) {
            return Err(Error::DirectoryCycle {
                block: directory_block,
            });
        }
        let directory = block(self.bytes, directory_block)?;
        let secondary = read_i32(directory, 508);
        if read_i32(directory, 0) != TYPE_HEADER
            || (secondary != ST_ROOT && secondary != ST_USERDIR)
        {
            return Err(Error::InvalidBlock {
                block: directory_block,
                message: "expected a root or directory header".into(),
            });
        }

        let bucket_heads: Vec<u32> = (0..HASH_SIZE)
            .map(|index| read_u32(directory, 24 + index * 4))
            .collect();
        for mut current in bucket_heads {
            let mut chain = HashSet::new();
            while current != 0 {
                if !chain.insert(current) {
                    return Err(Error::InvalidBlock {
                        block: current,
                        message: "directory hash chain contains a cycle".into(),
                    });
                }
                let header = block(self.bytes, current)?;
                if read_i32(header, 0) != TYPE_HEADER {
                    return Err(Error::InvalidBlock {
                        block: current,
                        message: "directory entry is not a header block".into(),
                    });
                }
                let name = block_name(header, current)?;
                validate_name(&name, current)?;
                let path = parent_path.join(&name);
                let secondary = read_i32(header, 508);
                let kind = match secondary {
                    ST_FILE => EntryKind::File,
                    ST_USERDIR => EntryKind::Directory,
                    other => {
                        return Err(Error::InvalidBlock {
                            block: current,
                            message: format!("unsupported secondary type {other}"),
                        });
                    }
                };
                let entry = Entry {
                    path: path.clone(),
                    name,
                    kind,
                    header_block: BlockNumber(current),
                    size: ByteSize(if kind == EntryKind::File {
                        read_u32(header, 324)
                    } else {
                        0
                    }),
                    first_data: read_u32(header, 16),
                };
                if entry.size.get() == 0 && entry.first_data != 0 && kind == EntryKind::File {
                    self.warnings.push(Warning {
                        kind: WarningKind::EmptyFileWithDataPointer,
                        block: current,
                        message: format!(
                            "{} is empty but retains data pointer {}; ignored",
                            entry.path.display(),
                            entry.first_data
                        ),
                    });
                }
                self.entries.push(entry);
                if kind == EntryKind::Directory {
                    self.walk_directory(current, &path, visited_directories)?;
                }
                current = read_u32(header, 496);
            }
        }
        Ok(())
    }
}

fn find_root(bytes: &[u8]) -> Option<u32> {
    let blocks = bytes.len() / BLOCK_SIZE;
    let midpoint = blocks / 2;
    let candidate = &bytes[midpoint * BLOCK_SIZE..(midpoint + 1) * BLOCK_SIZE];
    if is_root(candidate) {
        return Some(midpoint as u32);
    }
    (0..blocks).find_map(|index| {
        let candidate = &bytes[index * BLOCK_SIZE..(index + 1) * BLOCK_SIZE];
        is_root(candidate).then_some(index as u32)
    })
}

fn is_root(candidate: &[u8]) -> bool {
    read_i32(candidate, 0) == TYPE_HEADER
        && read_i32(candidate, 508) == ST_ROOT
        && valid_checksum(candidate)
}

/// One block, with its metadata checksum verified.
///
/// For header, root, directory, and file-extension blocks, and for OFS data
/// blocks — everything that carries a checksum longword.
fn block(bytes: &[u8], number: u32) -> Result<&[u8], Error> {
    let contents = raw_block(bytes, number)?;
    if !valid_checksum(contents) {
        return Err(Error::InvalidBlock {
            block: number,
            message: "invalid block checksum".into(),
        });
    }
    Ok(contents)
}

/// One block, bounds-checked and nothing more.
///
/// An FFS data block is 512 bytes of file content with no header and no
/// checksum, so there is nothing to verify and verifying anything would reject
/// payload that merely failed to sum to zero.
fn raw_block(bytes: &[u8], number: u32) -> Result<&[u8], Error> {
    let offset = (number as usize)
        .checked_mul(BLOCK_SIZE)
        .ok_or(Error::BlockOutOfRange { block: number })?;
    let end = offset
        .checked_add(BLOCK_SIZE)
        .ok_or(Error::BlockOutOfRange { block: number })?;
    bytes
        .get(offset..end)
        .ok_or(Error::BlockOutOfRange { block: number })
}

fn valid_checksum(bytes: &[u8]) -> bool {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .fold(0_u32, u32::wrapping_add)
        == 0
}

fn valid_boot_checksum(bytes: &[u8]) -> bool {
    let mut sum = 0_u32;
    for chunk in bytes[..BLOCK_SIZE * 2].as_chunks::<4>().0.iter() {
        let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let (next, carry) = sum.overflowing_add(value);
        sum = next.wrapping_add(u32::from(carry));
    }
    sum == u32::MAX
}

fn block_name(header: &[u8], block: u32) -> Result<String, Error> {
    let length = header[432] as usize;
    if length == 0 || length > 30 {
        return Err(Error::InvalidBlock {
            block,
            message: format!("invalid BCPL name length {length}"),
        });
    }
    Ok(amiga_core::latin1(&header[433..433 + length]))
}

fn validate_name(name: &str, block: u32) -> Result<(), Error> {
    if name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(Error::InvalidBlock {
            block,
            message: format!("unsafe entry name {name:?}"),
        });
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32(block: &mut [u8], offset: usize, value: u32) {
        block[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_name(block: &mut [u8], name: &str) {
        block[432] = name.len() as u8;
        block[433..433 + name.len()].copy_from_slice(name.as_bytes());
    }

    fn seal_checksum(block: &mut [u8]) {
        write_u32(block, 20, 0);
        let sum = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .fold(0_u32, u32::wrapping_add);
        write_u32(block, 20, 0_u32.wrapping_sub(sum));
    }

    /// Build an 8-block OFS image holding a single file `HELLO` with `payload`.
    /// The midpoint block (4) is the root, so `find_root` locates it directly.
    fn synthetic_image(payload: &[u8]) -> Vec<u8> {
        const ROOT: u32 = 4;
        const FILE_HEADER: u32 = 2;
        const DATA: u32 = 3;
        let mut image = vec![0_u8; 8 * BLOCK_SIZE];

        {
            let root = &mut image[ROOT as usize * BLOCK_SIZE..(ROOT as usize + 1) * BLOCK_SIZE];
            write_u32(root, 0, TYPE_HEADER as u32);
            // The reader follows any bucket that references a header, so the
            // exact hash bucket does not matter.
            write_u32(root, 24, FILE_HEADER);
            write_name(root, "DISK");
            write_u32(root, 508, ST_ROOT as u32);
            seal_checksum(root);
        }
        {
            let header = &mut image
                [FILE_HEADER as usize * BLOCK_SIZE..(FILE_HEADER as usize + 1) * BLOCK_SIZE];
            write_u32(header, 0, TYPE_HEADER as u32);
            write_u32(header, 4, FILE_HEADER); // own key
            write_u32(header, 16, DATA); // first data block
            write_u32(header, 324, payload.len() as u32); // byte size
            write_u32(header, 496, 0); // next in hash chain
            write_name(header, "HELLO");
            write_u32(header, 508, ST_FILE as u32);
            seal_checksum(header);
        }
        {
            let data = &mut image[DATA as usize * BLOCK_SIZE..(DATA as usize + 1) * BLOCK_SIZE];
            write_u32(data, 0, TYPE_DATA as u32);
            write_u32(data, 4, FILE_HEADER); // owner
            write_u32(data, 8, 1); // sequence
            write_u32(data, 12, payload.len() as u32);
            write_u32(data, 16, 0); // next data
            data[24..24 + payload.len()].copy_from_slice(payload);
            seal_checksum(data);
        }
        image
    }

    /// Seal a boot block's checksum so [`Bootblock::has_valid_checksum`] passes.
    fn seal_boot(block: &mut [u8]) {
        write_u32(block, 4, 0);
        let mut sum = 0_u32;
        for chunk in block[..Bootblock::SIZE].as_chunks::<4>().0.iter() {
            let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let (next, carry) = sum.overflowing_add(value);
            sum = next.wrapping_add(u32::from(carry));
        }
        write_u32(block, 4, !sum);
    }

    #[test]
    fn bootblock_reads_fields_and_validates_checksum() {
        let mut block = vec![0_u8; Bootblock::SIZE];
        block[0..4].copy_from_slice(b"DOS\0");
        write_u32(&mut block, 8, 880); // root block
        block[12..14].copy_from_slice(&[0x4e, 0x75]); // RTS as boot code
        seal_boot(&mut block);

        let boot = Bootblock::parse(&block).unwrap_or_else(|error| panic!("{error}"));
        assert!(boot.is_dos());
        assert_eq!(boot.flags(), 0);
        assert_eq!(boot.root_block(), 880);
        assert!(boot.has_valid_checksum());
        assert!(boot.has_boot_code());
        assert_eq!(&boot.boot_code()[0..2], &[0x4e, 0x75]);

        block[20] ^= 0xff; // corrupt a byte outside the checksum field
        let boot = Bootblock::parse(&block).unwrap_or_else(|error| panic!("{error}"));
        assert!(!boot.has_valid_checksum());
    }

    #[test]
    fn bootblock_rejects_short_input() {
        assert!(matches!(
            Bootblock::parse(&[0_u8; 100]),
            Err(Error::BootblockTooSmall(100))
        ));
    }

    #[test]
    fn lists_and_reads_a_synthetic_file() {
        let payload = b"Hello, Amiga!";
        let image_bytes = synthetic_image(payload);
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(image.volume_name(), "DISK");
        assert_eq!(image.root_block().get(), 4);
        assert_eq!(image.entries().len(), 1);

        let entry = &image.entries()[0];
        assert_eq!(entry.name, "HELLO");
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.size.get() as usize, payload.len());

        let recovered = image
            .read_file(entry)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovered, payload);
    }

    #[test]
    fn warns_about_an_invalid_boot_block() {
        let image_bytes = synthetic_image(b"data");
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        // The kind is what a consumer acts on; asserting it rather than the
        // block number is what keeps the message free to be reworded.
        assert!(image.warnings().iter().any(|warning| {
            warning.block == 0 && warning.kind == WarningKind::BootBlockChecksumInvalid
        }));
    }

    /// Build an FFS image holding one file `HELLO` with `payload`.
    ///
    /// Blocks: 0–1 boot, 2 file header, 3.. data, then extension blocks appended
    /// after the data as needed, root at the midpoint.
    ///
    /// The data table is written from its end — index `HASH_SIZE - sequence` — so
    /// that a reader which walked it forward would recover the blocks in reverse
    /// order. That is exactly what the content assertions below are for.
    fn synthetic_ffs_image(payload: &[u8], blocks: usize) -> Vec<u8> {
        const FILE_HEADER: u32 = 2;
        const FIRST_DATA: u32 = 3;
        let data_blocks = payload.len().div_ceil(BLOCK_SIZE);
        assert!(
            blocks > FIRST_DATA as usize + data_blocks + 8,
            "the image must have room for the data, the extensions, and a root"
        );
        let mut image = vec![0_u8; blocks * BLOCK_SIZE];
        // `DOS\1`: the FFS flag, and the only thing that selects this reader.
        image[0..4].copy_from_slice(b"DOS\x01");
        let root = (blocks / 2) as u32;
        // Extension blocks live above the data, and above the root so the
        // midpoint search still finds the root first.
        let mut next_extension = root + 1;

        {
            let slot = &mut image[root as usize * BLOCK_SIZE..(root as usize + 1) * BLOCK_SIZE];
            write_u32(slot, 0, TYPE_HEADER as u32);
            write_u32(slot, TABLE_OFFSET, FILE_HEADER);
            write_name(slot, "DISK");
            write_u32(slot, 508, ST_ROOT as u32);
            seal_checksum(slot);
        }

        // Fill the header, then extension blocks, with up to HASH_SIZE pointers
        // each, in the same reverse order AmigaDOS uses.
        let mut sequence_in_block = 0;
        let mut current = FILE_HEADER;
        let mut is_header = true;
        for index in 0..data_blocks {
            let data_block = FIRST_DATA + index as u32;
            {
                let start = index * BLOCK_SIZE;
                let end = (start + BLOCK_SIZE).min(payload.len());
                let slot = &mut image[data_block as usize * BLOCK_SIZE
                    ..data_block as usize * BLOCK_SIZE + (end - start)];
                slot.copy_from_slice(&payload[start..end]);
            }
            if sequence_in_block == HASH_SIZE {
                // This block is full; chain a new extension block and seal the
                // one being left behind.
                let extension = next_extension;
                next_extension += 1;
                {
                    let slot = &mut image
                        [current as usize * BLOCK_SIZE..(current as usize + 1) * BLOCK_SIZE];
                    write_u32(slot, 8, HASH_SIZE as u32);
                    write_u32(slot, EXTENSION_OFFSET, extension);
                    seal_checksum(slot);
                }
                {
                    let slot = &mut image
                        [extension as usize * BLOCK_SIZE..(extension as usize + 1) * BLOCK_SIZE];
                    write_u32(slot, 0, TYPE_LIST as u32);
                    write_u32(slot, 4, extension);
                    write_u32(slot, 508, ST_FILE as u32);
                }
                current = extension;
                sequence_in_block = 0;
                is_header = false;
            }
            sequence_in_block += 1;
            let table_index = HASH_SIZE - sequence_in_block;
            let slot =
                &mut image[current as usize * BLOCK_SIZE..(current as usize + 1) * BLOCK_SIZE];
            write_u32(slot, TABLE_OFFSET + table_index * 4, data_block);
            if is_header && sequence_in_block == 1 {
                write_u32(slot, 16, data_block); // first_data, the redundant copy
            }
        }
        {
            let slot =
                &mut image[current as usize * BLOCK_SIZE..(current as usize + 1) * BLOCK_SIZE];
            write_u32(slot, 8, sequence_in_block as u32);
            seal_checksum(slot);
        }
        if current != FILE_HEADER {
            // The header was sealed when it filled up; the name and size still
            // have to go in, so re-seal it below.
            let slot = &mut image
                [FILE_HEADER as usize * BLOCK_SIZE..(FILE_HEADER as usize + 1) * BLOCK_SIZE];
            write_u32(slot, 20, 0);
        }
        {
            let slot = &mut image
                [FILE_HEADER as usize * BLOCK_SIZE..(FILE_HEADER as usize + 1) * BLOCK_SIZE];
            write_u32(slot, 0, TYPE_HEADER as u32);
            write_u32(slot, 4, FILE_HEADER);
            write_u32(slot, 324, payload.len() as u32);
            write_u32(slot, 496, 0);
            write_name(slot, "HELLO");
            write_u32(slot, 508, ST_FILE as u32);
            seal_checksum(slot);
        }
        image
    }

    /// A payload whose every byte is a function of its position, so a block that
    /// arrives in the wrong order or shifted by a header is visible in the bytes.
    fn positional_payload(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index / BLOCK_SIZE + index) as u8)
            .collect()
    }

    #[test]
    fn an_ffs_image_is_recognized_from_its_boot_flag() {
        let image_bytes = synthetic_ffs_image(&positional_payload(600), 24);
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(image.filesystem(), FileSystem::Ffs);

        // And an OFS image is not: the flag is the only thing that decides, so
        // this is what keeps one image from being read both ways.
        let ofs_bytes = synthetic_image(b"data");
        let ofs = Image::open(&ofs_bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ofs.filesystem(), FileSystem::Ofs);
    }

    #[test]
    fn reads_an_ffs_file_spanning_several_data_blocks() {
        // Two full blocks and a partial third. A reader that skipped a 24-byte
        // OFS header, or walked the table forwards, returns the same *length*
        // and different bytes — which is why this asserts content.
        let payload = positional_payload(BLOCK_SIZE * 2 + 100);
        let image_bytes = synthetic_ffs_image(&payload, 32);
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));

        let entry = &image.entries()[0];
        assert_eq!(entry.name, "HELLO");
        assert_eq!(entry.size.get() as usize, payload.len());
        let recovered = image
            .read_file(entry)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovered, payload, "FFS content or block order is wrong");
    }

    #[test]
    fn reads_an_ffs_file_long_enough_to_need_an_extension_block() {
        // 73 blocks: one more than a single table holds, so this is the only test
        // that exercises the extension chain at all.
        let payload = positional_payload(BLOCK_SIZE * (HASH_SIZE + 1));
        let image_bytes = synthetic_ffs_image(&payload, 256);
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &image.entries()[0];
        let recovered = image
            .read_file(entry)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovered.len(), payload.len());
        assert_eq!(
            recovered, payload,
            "the extension chain lost or reordered a block"
        );
    }

    #[test]
    fn an_ffs_file_whose_table_disagrees_with_first_data_is_refused() {
        // The only independent check on the table index there is. If it were a
        // warning, a systematically wrong index would return bytes that are all
        // present and all in the wrong place.
        let payload = positional_payload(BLOCK_SIZE * 2);
        let mut image_bytes = synthetic_ffs_image(&payload, 32);
        {
            let header = &mut image_bytes[2 * BLOCK_SIZE..3 * BLOCK_SIZE];
            write_u32(header, 16, 99); // a first_data the table does not name
            seal_checksum(header);
        }
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &image.entries()[0];
        assert!(matches!(
            image.read_file(entry),
            Err(Error::InvalidBlock { .. })
        ));
    }

    #[test]
    fn a_cyclic_ffs_extension_chain_is_reported_rather_than_looped() {
        let payload = positional_payload(BLOCK_SIZE * 2);
        let mut image_bytes = synthetic_ffs_image(&payload, 32);
        {
            // Point the header's extension pointer at the header itself, and
            // under-declare the table so the reader still wants more blocks.
            let header = &mut image_bytes[2 * BLOCK_SIZE..3 * BLOCK_SIZE];
            write_u32(header, 8, 1);
            write_u32(header, EXTENSION_OFFSET, 2);
            seal_checksum(header);
        }
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &image.entries()[0];
        assert!(matches!(
            image.read_file(entry),
            Err(Error::DataCycle { .. })
        ));
    }

    #[test]
    fn an_ffs_chain_that_ends_early_is_a_size_mismatch_not_a_short_file() {
        // A truncated recovery must never be returned as if it were the file.
        let payload = positional_payload(BLOCK_SIZE * 3);
        let mut image_bytes = synthetic_ffs_image(&payload, 32);
        {
            let header = &mut image_bytes[2 * BLOCK_SIZE..3 * BLOCK_SIZE];
            write_u32(header, 8, 2); // two of the three blocks, and no extension
            seal_checksum(header);
        }
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &image.entries()[0];
        assert!(matches!(
            image.read_file(entry),
            Err(Error::FileSizeMismatch {
                expected, actual, ..
            }) if expected as usize == payload.len() && actual == BLOCK_SIZE * 2
        ));
    }

    #[test]
    fn an_ffs_table_entry_in_use_must_name_a_block() {
        let payload = positional_payload(BLOCK_SIZE * 2);
        let mut image_bytes = synthetic_ffs_image(&payload, 32);
        {
            let header = &mut image_bytes[2 * BLOCK_SIZE..3 * BLOCK_SIZE];
            // Claim three entries where only two were written, so the third is
            // a zero the reader must refuse rather than read block 0.
            write_u32(header, 8, 3);
            write_u32(header, 324, (BLOCK_SIZE * 3) as u32);
            seal_checksum(header);
        }
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &image.entries()[0];
        assert!(matches!(
            image.read_file(entry),
            Err(Error::InvalidBlock { .. })
        ));
    }

    #[test]
    fn an_ffs_data_table_above_the_block_capacity_is_refused() {
        let payload = positional_payload(BLOCK_SIZE);
        let mut image_bytes = synthetic_ffs_image(&payload, 32);
        {
            let header = &mut image_bytes[2 * BLOCK_SIZE..3 * BLOCK_SIZE];
            write_u32(header, 8, HASH_SIZE as u32 + 1);
            seal_checksum(header);
        }
        let image = Image::open(&image_bytes).unwrap_or_else(|error| panic!("{error}"));
        let entry = &image.entries()[0];
        assert!(matches!(
            image.read_file(entry),
            Err(Error::InvalidBlock { .. })
        ));
    }

    #[test]
    fn rejects_non_adf_sizes() {
        assert!(matches!(
            Image::open(&[0; 513]),
            Err(Error::InvalidImageSize(513))
        ));
    }

    #[test]
    fn rejects_an_image_without_a_root() {
        assert!(matches!(
            Image::open(&[0; BLOCK_SIZE]),
            Err(Error::RootNotFound)
        ));
    }
}
