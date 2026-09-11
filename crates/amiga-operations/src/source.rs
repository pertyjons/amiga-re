//! Source identity, resolution, and pinning.
//!
//! A request names a source; a resolver turns that name into bytes. Separating identity
//! from resolution lets callers execute the same request over memory-backed or
//! disk-backed sources.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Longest source name a request may carry.
pub const MAX_SOURCE_NAME_BYTES: usize = 1024;

/// The canonical identity of one source in a normalized request.
///
/// This is an identity, not a host path. It is relative, uses `/` separators,
/// and contains no `.` or `..` component, so the same request document means
/// the same thing on another machine. Only a resolver decides what it refers
/// to, and only [`FilesystemSourceResolver`] turns one into a real path.
#[must_use]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceName(String);

/// Why a string is not a usable source identity.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceNameError {
    #[error("source name is empty")]
    Empty,
    #[error("source name is longer than {MAX_SOURCE_NAME_BYTES} bytes")]
    TooLong,
    #[error("source name contains a control character")]
    ControlCharacter,
    #[error("source name must be relative, not absolute")]
    Absolute,
    #[error("source name must use `/` separators, not `\\`")]
    Backslash,
    #[error("source name contains an empty path component")]
    EmptyComponent,
    #[error("source name contains a `{0}` component")]
    RelativeComponent(&'static str),
}

impl SourceName {
    /// Validate `raw` as a canonical source identity.
    ///
    /// # Errors
    /// Returns [`SourceNameError`] for anything that is not reproducible on
    /// another machine or that could escape a resolver's own root.
    pub fn parse(raw: &str) -> Result<Self, SourceNameError> {
        if raw.is_empty() {
            return Err(SourceNameError::Empty);
        }
        if raw.len() > MAX_SOURCE_NAME_BYTES {
            return Err(SourceNameError::TooLong);
        }
        if raw.chars().any(char::is_control) {
            return Err(SourceNameError::ControlCharacter);
        }
        if raw.contains('\\') {
            return Err(SourceNameError::Backslash);
        }
        if raw.starts_with('/') {
            return Err(SourceNameError::Absolute);
        }
        for component in raw.split('/') {
            match component {
                "" => return Err(SourceNameError::EmptyComponent),
                "." => return Err(SourceNameError::RelativeComponent(".")),
                ".." => return Err(SourceNameError::RelativeComponent("..")),
                _ => {}
            }
        }
        Ok(Self(raw.to_owned()))
    }

    /// A stable placeholder for a source with no usable name of its own.
    ///
    /// A frontend that holds its source in memory still has to name it in the
    /// request. When the source came from inside a container and its display
    /// label is not a usable identity, this keeps the request well-formed: an
    /// in-memory resolver holds exactly one source, so the name has to be
    /// stable, not unique.
    pub fn unnamed() -> Self {
        Self("source".to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SourceName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One source resolved to pinned bytes.
///
/// The hash covers exactly the bytes an operation will read, so a result citing
/// it is reproducible from the request and the hash alone.
#[derive(Clone, Debug)]
pub struct ResolvedSource {
    name: SourceName,
    bytes: Arc<[u8]>,
    sha256: String,
}

impl ResolvedSource {
    /// Pin `bytes` under `name`, hashing them.
    #[must_use]
    pub fn new(name: SourceName, bytes: Arc<[u8]>) -> Self {
        let sha256 = amiga_core::sha256(&bytes);
        Self {
            name,
            bytes,
            sha256,
        }
    }

    /// Pin `bytes` under `name` with an already-computed hash.
    ///
    /// For callers that hashed the bytes when they first read them. The hash is
    /// trusted; pass it only when it covers exactly these bytes.
    #[must_use]
    pub fn with_sha256(name: SourceName, bytes: Arc<[u8]>, sha256: String) -> Self {
        Self {
            name,
            bytes,
            sha256,
        }
    }

    pub const fn name(&self) -> &SourceName {
        &self.name
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// Why a named source could not be resolved.
#[derive(Clone, Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source `{name}` is not available")]
    Missing { name: SourceName },
    #[error("source `{name}` is {size} bytes, over the {limit}-byte limit")]
    TooLarge {
        name: SourceName,
        size: u64,
        limit: u64,
    },
    #[error("source `{name}` could not be read: {message}")]
    Unreadable { name: SourceName, message: String },
}

/// Turns a source name into pinned bytes.
///
/// Implementations must refuse anything larger than `maximum_bytes` rather than
/// silently reading a prefix: a truncated survey that looks complete is worse
/// than a refusal a caller can act on.
pub trait SourceResolver {
    /// Resolve `name`, refusing any source larger than `maximum_bytes`.
    ///
    /// # Errors
    /// Returns [`SourceError`] when the source is missing, oversized, or
    /// unreadable.
    fn resolve(&self, name: &SourceName, maximum_bytes: u64)
    -> Result<ResolvedSource, SourceError>;

    /// The directory names resolve against, for the operations that need a
    /// *location* rather than bytes — a project root, whose documents this
    /// layer does not read itself.
    ///
    /// `None` for a resolver with no directory, such as an in-memory one. An
    /// operation needing a root refuses rather than inventing one.
    fn root(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Resolves source names as read-only files beneath one base directory.
///
/// The base directory is the adapter's own, never part of a request: that is
/// what keeps host paths out of request documents.
#[derive(Clone, Debug)]
pub struct FilesystemSourceResolver {
    base: PathBuf,
}

impl FilesystemSourceResolver {
    #[must_use]
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Reject a symbolic link at any component between the base and the target.
    fn reject_symlinked_path(&self, name: &SourceName) -> Result<PathBuf, String> {
        let mut path = self.base.clone();
        for component in name.as_str().split('/') {
            path.push(component);
            amiga_core::safepath::reject_symlink(&path).map_err(|error| error.to_string())?;
        }
        Ok(path)
    }
}

impl SourceResolver for FilesystemSourceResolver {
    fn root(&self) -> Option<&std::path::Path> {
        Some(&self.base)
    }

    fn resolve(
        &self,
        name: &SourceName,
        maximum_bytes: u64,
    ) -> Result<ResolvedSource, SourceError> {
        let path = self
            .reject_symlinked_path(name)
            .map_err(|message| SourceError::Unreadable {
                name: name.clone(),
                message,
            })?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SourceError::Missing { name: name.clone() }
            } else {
                SourceError::Unreadable {
                    name: name.clone(),
                    message: error.to_string(),
                }
            }
        })?;
        if !metadata.is_file() {
            return Err(SourceError::Unreadable {
                name: name.clone(),
                message: "not a regular file".to_owned(),
            });
        }
        if metadata.len() > maximum_bytes {
            return Err(SourceError::TooLarge {
                name: name.clone(),
                size: metadata.len(),
                limit: maximum_bytes,
            });
        }
        let bytes = fs::read(&path).map_err(|error| SourceError::Unreadable {
            name: name.clone(),
            message: error.to_string(),
        })?;
        // The file may have grown between the metadata check and the read.
        let size = bytes.len() as u64;
        if size > maximum_bytes {
            return Err(SourceError::TooLarge {
                name: name.clone(),
                size,
                limit: maximum_bytes,
            });
        }
        Ok(ResolvedSource::new(name.clone(), bytes.into()))
    }
}

/// Resolves names to bytes the caller already holds.
///
/// A caller can reuse loaded bytes across requests without reading the file again. The
/// resolver holds several sources because an operation may name more than one, such as
/// the two inputs to a comparison.
#[derive(Clone, Debug)]
pub struct InMemorySourceResolver {
    sources: Vec<ResolvedSource>,
    root: Option<PathBuf>,
}

impl InMemorySourceResolver {
    #[must_use]
    pub fn new(source: ResolvedSource) -> Self {
        Self {
            sources: vec![source],
            root: None,
        }
    }

    /// Hold every source in `sources`.
    ///
    /// Names are matched exactly and the first match wins, so a caller that
    /// supplies two sources under one name gets the first deterministically
    /// rather than an arbitrary one.
    #[must_use]
    pub fn holding(sources: Vec<ResolvedSource>) -> Self {
        Self {
            sources,
            root: None,
        }
    }

    /// Also serve `root` to the operations that need a *location*.
    ///
    /// No source name is ever resolved through it: the bytes are the ones held.
    /// It exists because the two questions are separate — a frontend can hold
    /// the bytes it is looking at and still have to say where the open project
    /// is, and without this it had to choose between re-reading the file from
    /// disk and not being able to name a project at all.
    #[must_use]
    pub fn rooted_at(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }
}

impl SourceResolver for InMemorySourceResolver {
    fn root(&self) -> Option<&std::path::Path> {
        self.root.as_deref()
    }

    fn resolve(
        &self,
        name: &SourceName,
        maximum_bytes: u64,
    ) -> Result<ResolvedSource, SourceError> {
        let Some(source) = self.sources.iter().find(|source| source.name() == name) else {
            return Err(SourceError::Missing { name: name.clone() });
        };
        let size = source.size();
        if size > maximum_bytes {
            return Err(SourceError::TooLarge {
                name: name.clone(),
                size,
                limit: maximum_bytes,
            });
        }
        Ok(source.clone())
    }
}

/// Split a host path into the base directory a resolver owns and the source
/// name a request carries.
///
/// The name is always a single component, so a request document never contains
/// a directory an adapter chose. A path with no file name yields `None`.
#[must_use]
pub fn split_host_path(path: &Path) -> Option<(PathBuf, SourceName)> {
    let file_name = path.file_name()?.to_str()?;
    let name = SourceName::parse(file_name).ok()?;
    let base = path.parent().unwrap_or(Path::new("")).to_path_buf();
    let base = if base.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        base
    };
    Some((base, name))
}

/// Split several host paths into the one base directory a resolver owns and
/// the names a request carries.
///
/// The base is the deepest directory all the paths share, so an operation
/// naming two sources still goes through a single resolver rooted somewhere
/// neither request document mentions. Names may therefore have several
/// components, which is exactly what [`SourceName`] permits and what
/// [`FilesystemSourceResolver`] walks one component at a time.
///
/// Paths should be canonical: this compares components and does no I/O, so a
/// relative and an absolute spelling of the same file share no prefix.
#[must_use]
pub fn split_host_paths(paths: &[&Path]) -> Option<(PathBuf, Vec<SourceName>)> {
    let (first, rest) = paths.split_first()?;
    let mut base: Vec<std::path::Component<'_>> = first.parent()?.components().collect();
    for path in rest {
        let other: Vec<std::path::Component<'_>> = path.parent()?.components().collect();
        let shared = base
            .iter()
            .zip(other.iter())
            .take_while(|(left, right)| left == right)
            .count();
        base.truncate(shared);
    }
    let base: PathBuf = base.iter().collect();
    let base = if base.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        base
    };

    let mut names = Vec::with_capacity(paths.len());
    for path in paths {
        let relative = path.strip_prefix(&base).ok()?;
        // Built from components rather than from `Display`, so the identity in
        // the request does not depend on the host's path separator.
        let spelled = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?
            .join("/");
        names.push(SourceName::parse(&spelled).ok()?);
    }
    Some((base, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_name_must_be_a_reproducible_relative_identity() {
        assert!(SourceName::parse("fixtures/sample.bin").is_ok());
        assert!(SourceName::parse("a file with spaces.bin").is_ok());
        assert_eq!(SourceName::parse(""), Err(SourceNameError::Empty));
        assert_eq!(
            SourceName::parse("/etc/passwd"),
            Err(SourceNameError::Absolute)
        );
        assert_eq!(
            SourceName::parse("../secret.bin"),
            Err(SourceNameError::RelativeComponent(".."))
        );
        assert_eq!(
            SourceName::parse("data/../../secret.bin"),
            Err(SourceNameError::RelativeComponent(".."))
        );
        assert_eq!(
            SourceName::parse("./sample.bin"),
            Err(SourceNameError::RelativeComponent("."))
        );
        assert_eq!(
            SourceName::parse("data//sample.bin"),
            Err(SourceNameError::EmptyComponent)
        );
        assert_eq!(
            SourceName::parse("data\\sample.bin"),
            Err(SourceNameError::Backslash)
        );
        assert_eq!(
            SourceName::parse("sample\u{0}.bin"),
            Err(SourceNameError::ControlCharacter)
        );
        assert_eq!(
            SourceName::parse(&"a".repeat(MAX_SOURCE_NAME_BYTES + 1)),
            Err(SourceNameError::TooLong)
        );
    }

    #[test]
    fn splitting_a_host_path_keeps_the_directory_out_of_the_request() {
        let (base, name) = split_host_path(Path::new("/tmp/media/disk.adf"))
            .expect("an absolute path with a file name splits");
        assert_eq!(base, PathBuf::from("/tmp/media"));
        assert_eq!(name.as_str(), "disk.adf");

        let (base, name) = split_host_path(Path::new("disk.adf")).expect("a bare file name splits");
        assert_eq!(base, PathBuf::from("."));
        assert_eq!(name.as_str(), "disk.adf");

        assert!(split_host_path(Path::new("/")).is_none());
    }

    #[test]
    fn several_paths_share_one_base_and_keep_their_directories_out_of_the_name() {
        let (base, names) = split_host_paths(&[
            Path::new("/tmp/media/original/game.exe"),
            Path::new("/tmp/media/patched/game.exe"),
        ])
        .expect("two paths under one tree split");
        assert_eq!(base, PathBuf::from("/tmp/media"));
        assert_eq!(names[0].as_str(), "original/game.exe");
        assert_eq!(names[1].as_str(), "patched/game.exe");

        // The same directory collapses to the plain file names.
        let (base, names) =
            split_host_paths(&[Path::new("/tmp/media/a.exe"), Path::new("/tmp/media/b.exe")])
                .expect("two paths in one directory split");
        assert_eq!(base, PathBuf::from("/tmp/media"));
        assert_eq!(names[1].as_str(), "b.exe");
    }

    #[test]
    fn an_in_memory_resolver_serves_only_its_own_source() {
        let name = SourceName::parse("held.bin").expect("valid name");
        let resolver = InMemorySourceResolver::new(ResolvedSource::new(
            name.clone(),
            Arc::from(b"abcd".as_slice()),
        ));

        let resolved = resolver
            .resolve(&name, 64)
            .expect("its own source resolves");
        assert_eq!(resolved.bytes(), b"abcd");
        assert_eq!(resolved.size(), 4);

        let other = SourceName::parse("other.bin").expect("valid name");
        assert!(matches!(
            resolver.resolve(&other, 64),
            Err(SourceError::Missing { .. })
        ));
        assert!(matches!(
            resolver.resolve(&name, 2),
            Err(SourceError::TooLarge {
                size: 4,
                limit: 2,
                ..
            })
        ));
    }
}
