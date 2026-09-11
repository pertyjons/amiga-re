//! Verifying that a project's pins still describe the bytes on disk.
//!
//! Three properties are the point, and each has a test.
//!
//! **Nothing is written.** Verification opens files read-only and produces a
//! report. A verify that repaired what it found would make the report a lie
//! about what was there.
//!
//! **Nothing is skipped silently.** A source that is missing, unreadable, or
//! unbound is reported as such. The failure this rules out is a verify that
//! says "all good" because it only checked what it could reach.
//!
//! **No symbolic link is followed.** An inventory walk uses symlink-aware
//! metadata and records a link as omitted rather than reading through it. A
//! link into `/etc` inside a project directory must not become project bytes.
//!
//! Recovery that needs a reader is delegated. This crate deliberately does not
//! depend on `amiga-adf`, `amiga-lha`, or `amiga-compress`: a byte range it can
//! take itself, and anything needing a parser or a decoder goes through
//! [`Recover`], which `amiga-operations` implements once for every frontend
//! (`amiga_operations::ContainerRecovery`). That keeps the format crate free of
//! every parser and codec it might one day describe — a project can be
//! *described* by a build that cannot open every container it names.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::document::{Id, InventoryFile, OmittedFile, Project, Selector, SourceKind};

/// Byte limits for source reads and the verified derivation graph.
///
/// Retention includes both sources and derived objects. A decoder must honor
/// the output allowance passed to [`Recover::recover_bounded`]; source reads
/// enforce their allowance on actual bytes, without trusting recorded sizes or
/// filesystem metadata.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct VerificationLimits {
    /// Maximum actual bytes read from one file source or inventory member.
    pub maximum_source_bytes: u64,
    /// Shared read allowance for all file sources and inventory members.
    pub maximum_total_source_bytes: u64,
    /// Maximum recovered output per object, also passed to delegated decoders.
    pub maximum_object_bytes: u64,
    /// Total verified source and object bytes held for derivation resolution.
    pub maximum_retained_bytes: u64,
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            maximum_source_bytes: 64 * 1024 * 1024,
            maximum_total_source_bytes: 1024 * 1024 * 1024,
            maximum_object_bytes: 64 * 1024 * 1024,
            maximum_retained_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// How a project's sources are found on this machine.
///
/// A project document never contains a host path. `locations` is a hint, and
/// `.amiga-re/local.json` binds a source ID to wherever this machine keeps it —
/// which is why a project opens on a machine that stores its media elsewhere.
#[derive(Clone, Debug, Default)]
pub struct Bindings {
    root: PathBuf,
    bound: BTreeMap<Id, PathBuf>,
}

impl Bindings {
    /// Bindings rooted at a project directory, with no machine-specific
    /// overrides.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            bound: BTreeMap::new(),
        }
    }

    /// Bind `id` to a host path, overriding the project's own hint.
    #[must_use]
    pub fn bind(mut self, id: impl Into<Id>, path: impl Into<PathBuf>) -> Self {
        self.bound.insert(id.into(), path.into());
        self
    }

    /// Where this machine keeps `id`, if anywhere.
    ///
    /// A binding wins over the project's hint; without either, the source is
    /// unbound and verification says so rather than guessing.
    #[must_use]
    pub fn locate(&self, project: &Project, id: &str) -> Option<PathBuf> {
        if let Some(path) = self.bound.get(id) {
            return Some(path.clone());
        }
        let source = project
            .sources
            .sources
            .iter()
            .find(|source| source.id == id)?;
        let crate::document::Location::ProjectRelative { path } = source.locations.first()?;
        Some(self.root.join(path))
    }
}

/// Recovering an object that needs a format parser or a decoder.
///
/// Implemented outside this crate. A `range` selector never reaches it — a byte
/// range needs no parser, and making the caller supply one for it would be
/// asking for a dependency to do arithmetic. A `decompressed` selector does
/// reach it: the recipe is complete enough to run, but running it means a codec,
/// and which codecs a build carries is the frontend's business.
pub trait Recover {
    /// The bytes `selector` recovers from `container`.
    ///
    /// # Errors
    /// Returns a human-readable reason. The caller turns it into a typed
    /// status; this trait stays free of the format crate's vocabulary so an
    /// implementor need not depend on it either.
    fn recover(&self, selector: &Selector, container: &[u8]) -> Result<Vec<u8>, String>;

    /// Recover using only the additional inputs whose project pins held.
    ///
    /// Keys are recipe-local source names, not host paths. Implementations
    /// supporting sandbox recipes must never resolve missing inputs from disk.
    ///
    /// # Errors
    /// Returns the reason the derivation could not be reproduced.
    fn recover_with_inputs(
        &self,
        selector: &Selector,
        container: &[u8],
        _inputs: &BTreeMap<&str, &[u8]>,
    ) -> Result<Vec<u8>, String> {
        self.recover(selector, container)
    }

    /// Recover within the available output budget, including intermediate output.
    ///
    /// Implementors must bound decoder allocations before producing bytes. The
    /// default refuses delegated recovery until a bounded implementation is
    /// supplied; an unbounded recoverer must not bypass verification limits.
    ///
    /// # Errors
    /// Refuses unsupported recovery or output exceeding `maximum_bytes`.
    fn recover_bounded(
        &self,
        _selector: &Selector,
        _container: &[u8],
        _inputs: &BTreeMap<&str, &[u8]>,
        _maximum_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        Err("this recoverer does not support bounded recovery".to_owned())
    }
}

/// A recoverer that refuses everything needing a parser or a decoder.
///
/// The default. A caller that has not supplied recovery gets an explicit
/// `Unrecoverable` for every ADF member, LHA member, and decompressed object
/// rather than a silently shorter report — and one that names what it refused,
/// so an unsupported codec is a stated refusal rather than a missing line.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRecovery;

impl Recover for NoRecovery {
    fn recover(&self, selector: &Selector, _container: &[u8]) -> Result<Vec<u8>, String> {
        Err(format!(
            "this verifier was given no recovery for a `{}` selector",
            selector.container()
        ))
    }

    fn recover_bounded(
        &self,
        selector: &Selector,
        container: &[u8],
        _inputs: &BTreeMap<&str, &[u8]>,
        _maximum_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        self.recover(selector, container)
    }
}

/// What verification found about one source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceStatus {
    /// The bytes on disk match the pin.
    Verified,
    /// This machine has no path for the source. Not an error: a project is
    /// meant to open without its private media.
    Unbound,
    /// A path is known but nothing is there.
    Missing { path: PathBuf },
    /// Something is there but could not be read.
    Unreadable { path: PathBuf, reason: String },
    /// The bytes are there and are not the pinned ones.
    Mismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    /// The bytes are the pinned ones and the recorded size is not their size.
    ///
    /// Separate from [`Self::Mismatch`] because the two failures have different
    /// causes and different repairs: a digest disagreement means the media
    /// changed, a size disagreement means the record is wrong about media that
    /// did not. Reporting the second as the first prints two identical digests
    /// under a heading that says they differ. `expected` is `None` when the
    /// record states no size at all, which the schema requires of a file source
    /// and a hand-written document can still omit.
    SizeMismatch {
        path: PathBuf,
        expected: Option<u64>,
        actual: u64,
    },
}

impl SourceStatus {
    /// Whether this status means the project's claim about the source holds.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Whether this status contradicts the project, as opposed to merely being
    /// unavailable. An unbound source is not a problem with the project.
    #[must_use]
    pub const fn contradicts(&self) -> bool {
        matches!(
            self,
            Self::Mismatch { .. } | Self::SizeMismatch { .. } | Self::Unreadable { .. }
        )
    }
}

/// What verification found about one object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectStatus {
    /// The object was reproduced from its parent and matches its pin.
    Verified,
    /// Its parent or a recipe input could not be verified, preventing recovery.
    ParentUnavailable,
    /// The selector names bytes that are not there.
    SelectorOutOfRange,
    /// A parser was needed and none was supplied, or the parser failed.
    Unrecoverable { reason: String },
    /// It was recovered and is not the pinned bytes.
    Mismatch { expected: String, actual: String },
    /// It was recovered as the pinned bytes, and the recorded size is not their
    /// size. See [`SourceStatus::SizeMismatch`] for why this is its own status.
    SizeMismatch { expected: u64, actual: u64 },
}

impl ObjectStatus {
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    #[must_use]
    pub const fn contradicts(&self) -> bool {
        matches!(
            self,
            Self::Mismatch { .. }
                | Self::SizeMismatch { .. }
                | Self::SelectorOutOfRange
                | Self::Unrecoverable { .. }
        )
    }

    /// Why this object did not produce usable bytes, in a sentence.
    ///
    /// For a caller that wanted the bytes rather than a report — an export, say
    /// — and has to say what it got instead.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Verified => "the object verified".to_owned(),
            Self::ParentUnavailable => "a parent or recipe input could not be recovered".to_owned(),
            Self::SelectorOutOfRange => "its selector names bytes that are not there".to_owned(),
            Self::Unrecoverable { reason } => reason.clone(),
            Self::Mismatch { expected, actual } => {
                format!("the recovered bytes are {actual}, not the pinned {expected}")
            }
            Self::SizeMismatch { expected, actual } => {
                format!("the recovered bytes are {actual} long, not the recorded {expected}")
            }
        }
    }
}

/// The complete result of verifying a project.
#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub sources: BTreeMap<Id, SourceStatus>,
    pub objects: BTreeMap<Id, ObjectStatus>,
}

impl VerifyReport {
    /// Whether anything contradicted the project.
    ///
    /// Deliberately not "everything verified": a project whose media is absent
    /// has nothing to contradict it, and reporting that as failure would make
    /// verification useless on the machines that need it most.
    #[must_use]
    pub fn contradicted(&self) -> bool {
        self.sources.values().any(SourceStatus::contradicts)
            || self.objects.values().any(ObjectStatus::contradicts)
    }

    #[must_use]
    pub fn verified_sources(&self) -> usize {
        self.sources
            .values()
            .filter(|status| status.is_verified())
            .count()
    }

    #[must_use]
    pub fn verified_objects(&self) -> usize {
        self.objects
            .values()
            .filter(|status| status.is_verified())
            .count()
    }
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Verify every source and object, writing nothing.
///
/// Uses default [`VerificationLimits`]; [`verify_with_limits`] accepts explicit
/// source and retention budgets.
///
/// Objects are attempted in derivation order — a chain deeper than its parent
/// is resolved only once the parent has been — so a chain whose root is
/// unavailable reports `ParentUnavailable` throughout rather than a cascade of
/// unrelated failures.
#[must_use]
pub fn verify(project: &Project, bindings: &Bindings, recover: &dyn Recover) -> VerifyReport {
    verify_with_limits(project, bindings, recover, VerificationLimits::default())
}

/// Verify with explicit source and graph byte budgets.
#[must_use]
pub fn verify_with_limits(
    project: &Project,
    bindings: &Bindings,
    recover: &dyn Recover,
    limits: VerificationLimits,
) -> VerifyReport {
    resolve(project, bindings, recover, limits).0
}

/// The bytes one object recovers to, through the chain [`verify`] walks.
///
/// The same resolution, deliberately: an export that recovered its bytes a
/// second way could produce a file from bytes a verify calls contradicted. An
/// object whose digest does not hold yields no bytes at all, for the same
/// reason.
///
/// # Errors
/// Returns the reason [`verify`] would report for that object, so the two
/// cannot disagree about whether it is recoverable.
pub fn recover_object(
    project: &Project,
    bindings: &Bindings,
    recover: &dyn Recover,
    object_id: &str,
) -> Result<Vec<u8>, String> {
    recover_object_with_limits(
        project,
        bindings,
        recover,
        object_id,
        VerificationLimits::default(),
    )
}

/// Recover an object using the same bounded resolution as verification.
///
/// # Errors
/// Returns the verification refusal, including exhausted byte budgets.
pub fn recover_object_with_limits(
    project: &Project,
    bindings: &Bindings,
    recover: &dyn Recover,
    object_id: &str,
    limits: VerificationLimits,
) -> Result<Vec<u8>, String> {
    let (report, mut bytes) = resolve(project, bindings, recover, limits);
    if let Some(recovered) = bytes.remove(object_id) {
        return Ok(recovered);
    }
    let status = report
        .objects
        .get(object_id)
        .ok_or_else(|| format!("no object {object_id} in this project"))?;
    Err(status.detail())
}

/// Verify every source and object, keeping the bytes each one resolved to.
fn resolve<'a>(
    project: &'a Project,
    bindings: &Bindings,
    recover: &dyn Recover,
    limits: VerificationLimits,
) -> (VerifyReport, BTreeMap<&'a str, Vec<u8>>) {
    let mut report = VerifyReport::default();
    let mut bytes_of: BTreeMap<&str, Vec<u8>> = BTreeMap::new();

    let mut source_remaining = limits.maximum_total_source_bytes;
    let mut retained_remaining = limits.maximum_retained_bytes;
    for source in &project.sources.sources {
        let status = verify_source(
            project,
            bindings,
            source,
            &mut bytes_of,
            limits.maximum_source_bytes,
            &mut source_remaining,
            &mut retained_remaining,
        );
        report.sources.insert(source.id.clone(), status);
    }

    // Repeat until nothing new resolves: a chain is at most as deep as the
    // object count, and the loop stops as soon as a pass adds nothing, so a
    // graph the validator already proved acyclic cannot spin here either.
    let mut pending: Vec<&crate::document::Object> = project.sources.objects.iter().collect();
    loop {
        let before = pending.len();
        pending.retain(|object| {
            let Some(parent) = bytes_of.get(object.parent_id.as_str()) else {
                return true;
            };
            let mut inputs = BTreeMap::new();
            if let Some(Selector::Sandbox { inputs: names, .. }) = &object.selector {
                for (name, id) in names {
                    let Some(bytes) = bytes_of.get(id.as_str()) else {
                        return true;
                    };
                    inputs.insert(name.as_str(), bytes.as_slice());
                }
            }
            let maximum = limits.maximum_object_bytes.min(retained_remaining);
            let recovered = if object.size > maximum {
                Err(ObjectStatus::Unrecoverable {
                    reason: format!(
                        "object exceeds the available {maximum}-byte verification budget"
                    ),
                })
            } else {
                match &object.selector {
                    Some(Selector::Range { offset, length }) => {
                        let start = usize::try_from(*offset).unwrap_or(usize::MAX);
                        let len = usize::try_from(*length).unwrap_or(usize::MAX);
                        match start
                            .checked_add(len)
                            .and_then(|end| parent.get(start..end))
                        {
                            Some(bytes) if bytes.len() as u64 <= maximum => Ok(bytes.to_vec()),
                            Some(_) => Err(ObjectStatus::Unrecoverable {
                                reason: format!(
                                    "range exceeds the available {maximum}-byte verification budget"
                                ),
                            }),
                            None => Err(ObjectStatus::SelectorOutOfRange),
                        }
                    }
                    Some(selector) => recover
                        .recover_bounded(selector, parent, &inputs, maximum)
                        .map_err(|reason| ObjectStatus::Unrecoverable { reason }),
                    None => Err(ObjectStatus::Unrecoverable {
                        reason: "the object has no selector".to_owned(),
                    }),
                }
            };
            let status = match recovered {
                Ok(bytes) => finish(
                    object,
                    bytes,
                    &mut bytes_of,
                    maximum,
                    &mut retained_remaining,
                ),
                Err(status) => status,
            };
            report.objects.insert(object.id.clone(), status);
            false
        });
        if pending.len() == before {
            break;
        }
    }
    for object in pending {
        report
            .objects
            .insert(object.id.clone(), ObjectStatus::ParentUnavailable);
    }
    (report, bytes_of)
}

/// Record a recovered object's bytes and compare them against its pin.
fn finish<'a>(
    object: &'a crate::document::Object,
    bytes: Vec<u8>,
    bytes_of: &mut BTreeMap<&'a str, Vec<u8>>,
    maximum: u64,
    retained_remaining: &mut u64,
) -> ObjectStatus {
    if bytes.len() as u64 > maximum {
        return ObjectStatus::Unrecoverable {
            reason: format!("recovered output exceeds the {maximum}-byte verification budget"),
        };
    }
    let actual = digest(&bytes);
    if actual != object.sha256 {
        return ObjectStatus::Mismatch {
            expected: object.sha256.clone(),
            actual,
        };
    }
    // The digest holds, so these *are* the recorded bytes and their length is
    // the true one — a size that disagrees is a wrong field in the document,
    // not corruption, and is reported as the thing it is.
    let length = bytes.len() as u64;
    if length != object.size {
        return ObjectStatus::SizeMismatch {
            expected: object.size,
            actual: length,
        };
    }
    *retained_remaining -= length;
    bytes_of.insert(object.id.as_str(), bytes);
    ObjectStatus::Verified
}

fn verify_source<'a>(
    project: &Project,
    bindings: &Bindings,
    source: &'a crate::document::Source,
    bytes_of: &mut BTreeMap<&'a str, Vec<u8>>,
    maximum_source_bytes: u64,
    source_remaining: &mut u64,
    retained_remaining: &mut u64,
) -> SourceStatus {
    let Some(path) = bindings.locate(project, &source.id) else {
        return SourceStatus::Unbound;
    };
    // Remove trailing separators and `.` so symlink_metadata cannot interpret
    // `link/` as a request to inspect the directory behind the link.
    let path: PathBuf = path.components().collect();
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return SourceStatus::Missing { path };
        }
        Err(error) => {
            return SourceStatus::Unreadable {
                path,
                reason: error.to_string(),
            };
        }
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return SourceStatus::Unreadable {
                path,
                reason: "source root is a symbolic link".to_owned(),
            };
        }
        Ok(metadata)
            if match source.kind {
                SourceKind::File => !metadata.is_file(),
                SourceKind::Directory => !metadata.is_dir(),
            } =>
        {
            return SourceStatus::Unreadable {
                path,
                reason: "source root has the wrong file type".to_owned(),
            };
        }
        Ok(_) => {}
    }
    match source.kind {
        SourceKind::File => match std::fs::File::open(&path).and_then(|file| {
            read_bounded(
                file,
                maximum_source_bytes.min(*retained_remaining),
                source_remaining,
            )
        }) {
            Ok(bytes) => {
                let actual = digest(&bytes);
                let expected = source.sha256.clone().unwrap_or_default();
                if actual != expected {
                    return SourceStatus::Mismatch {
                        path,
                        expected,
                        actual,
                    };
                }
                // Same rule as an object: with the digest confirmed, a size that
                // disagrees is the record being wrong about bytes that are not.
                let length = bytes.len() as u64;
                if Some(length) != source.size {
                    return SourceStatus::SizeMismatch {
                        path,
                        expected: source.size,
                        actual: length,
                    };
                }
                *retained_remaining -= length;
                bytes_of.insert(source.id.as_str(), bytes);
                SourceStatus::Verified
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                SourceStatus::Missing { path }
            }
            Err(error) => SourceStatus::Unreadable {
                path,
                reason: error.to_string(),
            },
        },
        SourceKind::Directory => {
            match inventory_bounded(&path, maximum_source_bytes, source_remaining) {
                Ok(walked) => {
                    let expected = source.tree_sha256.clone().unwrap_or_default();
                    let actual = crate::tree_sha256(
                        &walked
                            .files
                            .iter()
                            .map(|file| (file.path.clone(), file.size, file.sha256.clone()))
                            .collect::<Vec<_>>(),
                    );
                    if actual == expected {
                        SourceStatus::Verified
                    } else {
                        SourceStatus::Mismatch {
                            path,
                            expected,
                            actual,
                        }
                    }
                }
                Err(reason) => SourceStatus::Unreadable { path, reason },
            }
        }
    }
}

/// Read at most the allowance plus one probe byte, without metadata-sized
/// reservation. Charge aggregate input as it is consumed, even on a bad pin.
fn read_bounded(mut reader: impl Read, maximum: u64, remaining: &mut u64) -> io::Result<Vec<u8>> {
    let limit = maximum.min(*remaining);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let allowance = limit - bytes.len() as u64;
        let width = usize::try_from(allowance.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = match reader.read(&mut buffer[..width]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(bytes);
        }
        *remaining = remaining.saturating_sub(count as u64);
        if count as u64 > allowance {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!("source exceeds the available {limit}-byte verification budget"),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

/// One directory tree's files and what was left out of it.
#[derive(Clone, Debug, Default)]
pub struct WalkedTree {
    /// Regular files, sorted by their normalized path.
    pub files: Vec<InventoryFile>,
    /// What was deliberately not included, and why. Present so an inventory
    /// that skipped something says so rather than looking complete.
    pub omitted: Vec<OmittedFile>,
}

impl WalkedTree {
    /// The canonical tree hash of what was walked.
    #[must_use]
    pub fn tree_sha256(&self) -> String {
        crate::tree_sha256(
            &self
                .files
                .iter()
                .map(|file| (file.path.clone(), file.size, file.sha256.clone()))
                .collect::<Vec<_>>(),
        )
    }
}

/// The most entries one inventory walk will visit, including directories.
///
/// A bound rather than a limit anyone should reach: it exists so a directory
/// with a pathological structure fails instead of running until it exhausts
/// memory.
pub const MAX_INVENTORY_ENTRIES: usize = 1 << 20;

/// Maximum directory nesting below an inventory root (which has depth zero).
pub const MAX_INVENTORY_DEPTH: usize = 128;

/// Walk `root` and record every regular file, following no symbolic link.
///
/// # Errors
/// Returns a human-readable reason when the walk cannot complete — an
/// unreadable directory, a path that is not valid UTF-8, or more entries than
/// [`MAX_INVENTORY_ENTRIES`], nesting beyond [`MAX_INVENTORY_DEPTH`], a symbolic-link
/// root, or a file/aggregate read exceeding the default
/// [`VerificationLimits`]. A single unreadable *file* is recorded as omitted
/// instead, because one bad file must not cost the whole inventory.
pub fn build_inventory(root: &Path) -> Result<WalkedTree, String> {
    let limits = VerificationLimits::default();
    let mut remaining = limits.maximum_total_source_bytes;
    inventory_bounded(root, limits.maximum_source_bytes, &mut remaining)
}

fn inventory_bounded(root: &Path, maximum: u64, remaining: &mut u64) -> Result<WalkedTree, String> {
    let root: PathBuf = root.components().collect();
    let mut tree = WalkedTree::default();
    walk(&root, &mut tree, maximum, remaining, MAX_INVENTORY_ENTRIES)?;
    tree.files.sort_by(|left, right| left.path.cmp(&right.path));
    tree.omitted
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(tree)
}

fn walk(
    root: &Path,
    tree: &mut WalkedTree,
    maximum: u64,
    remaining: &mut u64,
    maximum_entries: usize,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| format!("failed to stat {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("inventory root must be a directory, not a symbolic link".to_owned());
    }
    let read_directory = |path: &Path| {
        std::fs::read_dir(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))
    };
    // Retain one iterator per ancestor, rather than collecting wide directories
    // or using the call stack for untrusted nesting.
    let mut stack = vec![read_directory(root)?];
    let mut visited = 0_usize;
    while let Some(entries) = stack.last_mut() {
        let Some(entry) = entries.next() else {
            stack.pop();
            continue;
        };
        if visited >= maximum_entries {
            return Err(format!(
                "more than {maximum_entries} entries under {}",
                root.display()
            ));
        }
        visited += 1;
        let entry = entry.map_err(|error| format!("failed to read an entry: {error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "an entry escaped the walk root".to_owned())?
            .to_str()
            .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))?
            .replace('\\', "/");

        // `symlink_metadata` does not follow the link, which is the whole
        // point: a link into `/etc` inside a project must not become project
        // bytes, and must be visibly recorded rather than quietly skipped.
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to stat {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            tree.omitted.push(OmittedFile {
                path: relative,
                reason: "symlink".to_owned(),
            });
            continue;
        }
        if metadata.is_dir() {
            if stack.len() > MAX_INVENTORY_DEPTH {
                return Err(format!(
                    "inventory nesting exceeds {MAX_INVENTORY_DEPTH} directories"
                ));
            }
            stack.push(read_directory(&path)?);
            continue;
        }
        if !metadata.is_file() {
            tree.omitted.push(OmittedFile {
                path: relative,
                reason: "not_regular".to_owned(),
            });
            continue;
        }
        match std::fs::File::open(&path).and_then(|file| read_bounded(file, maximum, remaining)) {
            Ok(bytes) => tree.files.push(InventoryFile {
                path: relative,
                size: bytes.len() as u64,
                sha256: digest(&bytes),
            }),
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge => {
                return Err(error.to_string());
            }
            Err(_) => tree.omitted.push(OmittedFile {
                path: relative,
                reason: "unreadable".to_owned(),
            }),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_directories_count_toward_the_entry_budget() {
        let root =
            std::env::temp_dir().join(format!("amiga-inventory-entries-{}", std::process::id()));
        std::fs::create_dir_all(root.join("one")).unwrap();
        std::fs::create_dir_all(root.join("two")).unwrap();
        let mut remaining = 0;
        let mut tree = WalkedTree::default();
        walk(&root, &mut tree, 0, &mut remaining, 2).unwrap();
        assert!(tree.files.is_empty());
        assert!(
            walk(&root, &mut tree, 0, &mut remaining, 1)
                .unwrap_err()
                .contains("more than 1 entries")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_reader_probes_only_one_byte_beyond_its_allowance() {
        let mut input = io::Cursor::new(vec![7; 100]);
        let mut total = 10;
        assert_eq!(
            read_bounded(&mut input, 4, &mut total).unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
        assert_eq!(input.position(), 5);
        assert_eq!(total, 5);
        let mut total = 4;
        assert_eq!(read_bounded(&b"1234"[..], 4, &mut total).unwrap(), b"1234");
        assert_eq!(total, 0);
    }

    #[test]
    fn an_unbound_source_is_not_a_contradiction() {
        // A project must open, and verify usefully, without its private media.
        assert!(!SourceStatus::Unbound.contradicts());
        assert!(!SourceStatus::Unbound.is_verified());
        assert!(
            !SourceStatus::Missing {
                path: PathBuf::from("x")
            }
            .contradicts()
        );
        // These do contradict it: the bytes are there and are wrong, or
        // something is there that cannot be read.
        assert!(
            SourceStatus::Mismatch {
                path: PathBuf::from("x"),
                expected: "a".to_owned(),
                actual: "b".to_owned()
            }
            .contradicts()
        );
        assert!(
            SourceStatus::Unreadable {
                path: PathBuf::from("x"),
                reason: "denied".to_owned()
            }
            .contradicts()
        );
    }

    #[test]
    fn an_object_whose_parent_is_unavailable_is_not_a_contradiction() {
        assert!(!ObjectStatus::ParentUnavailable.contradicts());
        assert!(ObjectStatus::SelectorOutOfRange.contradicts());
        assert!(
            ObjectStatus::Unrecoverable {
                reason: "no parser".to_owned()
            }
            .contradicts()
        );
    }

    #[test]
    fn the_default_recoverer_refuses_rather_than_returning_nothing() {
        let result = NoRecovery.recover(
            &Selector::Adf {
                path: "S/main".to_owned(),
                header_block: None,
            },
            &[],
        );
        assert!(result.is_err(), "a missing parser must be explicit");
    }

    #[test]
    fn a_refusal_names_the_kind_of_recovery_it_lacked() {
        // "unsupported" alone would leave the reader to guess whether a parser
        // or a codec was missing.
        let selector = Selector::Decompressed {
            codec: crate::document::Codec::ByteRun1 {},
            declared_size: None,
        };
        let Err(reason) = NoRecovery.recover(&selector, &[]) else {
            panic!("a missing decoder must be explicit");
        };
        assert!(reason.contains("decompressed"), "{reason}");
    }
}
