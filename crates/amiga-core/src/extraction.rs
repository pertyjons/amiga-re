//! Prevalidated, manifest-governed extraction.
//!
//! Two destinations, because two things get written and they need different
//! guarantees:
//!
//! - [`ExtractionPlan::commit`] installs a whole **directory** the toolkit owns.
//!   Replacing one requires a prior manifest that accounts for everything already
//!   there, which is the only way to replace a tree without losing bytes nobody
//!   listed.
//! - [`ExtractionPlan::commit_file`] installs **one named file** into a directory
//!   the toolkit does *not* own, with its provenance manifest beside it. The
//!   policy applies to that file: replacing it requires a sibling manifest saying
//!   this toolkit wrote it, and nothing else in the directory is touched or
//!   inspected.
//!
//! The second exists because a single-file output has no business demanding an
//! empty directory. Requiring one made the safe default unusable for an ordinary
//! `carve` into a folder that obviously exists, which trains a caller to pass
//! `--force` always — and a `--force` that is always passed protects nothing.
//!
//! Both are atomic in the same way: write beside the target, then rename over it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::{PathError, ensure_dir, reject_symlink};

/// What a single-file commit appends to its output's name to find its manifest.
///
/// One constant rather than a parameter: a manifest a reader cannot locate from
/// the file it describes is not provenance, and letting each caller choose the
/// spelling is how that happens.
pub const MANIFEST_SUFFIX: &str = ".manifest.json";

/// A recovered file that can be reviewed before an extraction is committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedFile {
    /// Safe path relative to the extraction root.
    pub path: PathBuf,
    /// Complete recovered contents.
    pub bytes: Vec<u8>,
}

/// A complete extraction whose paths and contents have been validated in memory.
#[derive(Clone, Debug)]
pub struct ExtractionPlan {
    files: Vec<PlannedFile>,
    directories: BTreeSet<PathBuf>,
}

/// Failure while validating or atomically committing an extraction.
#[derive(Debug, Error)]
pub enum ExtractionError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse prior manifest {path}: {source}")]
    Manifest {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    /// The recovered files could not be installed into the destination.
    ///
    /// Distinct from [`Self::Io`] because it says more than "a write failed":
    /// the installer reports whether the destination was left as it was, which
    /// is what decides whether a retry is safe.
    #[error("the recovered files could not be installed: {source}")]
    Install {
        #[source]
        source: crate::install::InstallError,
    },
}

type Result<T> = std::result::Result<T, ExtractionError>;

fn invalid(message: impl Into<String>) -> ExtractionError {
    ExtractionError::Invalid(message.into())
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> ExtractionError {
    ExtractionError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

/// Normalize an archive member name into a safe relative output path.
///
/// `/` is the one accepted separator. Container readers must normalize their
/// format-specific separator to it before calling this function; accepting a
/// second spelling here would make a name mean different things on different
/// hosts. Every component is validated before a [`PathBuf`] is built, so the
/// returned hierarchy is relative and cannot traverse out of its extraction
/// root.
///
/// A *trailing* slash is a type marker rather than hierarchy — LHA writes
/// directory entries that way — so one is trimmed before validation. Empty
/// components, traversal, drive-like names, raw backslashes and NUL are
/// refused.
///
/// This does not apply to names a *filesystem* reader assembled. `amiga-adf`
/// builds an entry path component by component from validated directory blocks,
/// with cycle detection, and keeps its hierarchy; those paths never reach this
/// function.
///
/// # Errors
/// Returns [`ExtractionError::Invalid`] for an empty name or any unsafe path
/// component.
pub fn safe_archive_path(name: &str) -> Result<PathBuf> {
    let relative = name.strip_suffix('/').unwrap_or(name);
    if relative.is_empty() {
        return Err(invalid("empty archive entry name"));
    }

    let mut path = PathBuf::new();
    for component in relative.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(['\0', ':', '\\'])
        {
            return Err(invalid(format!(
                "unsafe path component {component:?} in {name:?}"
            )));
        }
        path.push(component);
    }
    Ok(path)
}

impl ExtractionPlan {
    /// Validate every member and all file/directory relationships without writing.
    pub fn new(files: Vec<PlannedFile>, explicit_dirs: Vec<PathBuf>) -> Result<Self> {
        let mut file_paths = BTreeSet::new();
        let mut directories = BTreeSet::new();
        for directory in explicit_dirs {
            validate_relative(&directory)?;
            insert_directory(&mut directories, &directory);
        }
        for file in &files {
            validate_relative(&file.path)?;
            if !file_paths.insert(file.path.clone()) {
                return Err(invalid(format!(
                    "duplicate extraction path {}",
                    file.path.display()
                )));
            }
            if let Some(parent) = file.path.parent() {
                insert_directory(&mut directories, parent);
            }
        }
        for file in &file_paths {
            if directories.contains(file) {
                return Err(invalid(format!(
                    "extraction path {} is both a file and directory",
                    file.display()
                )));
            }
            for ancestor in file.ancestors().skip(1) {
                if ancestor.as_os_str().is_empty() {
                    break;
                }
                if file_paths.contains(ancestor) {
                    return Err(invalid(format!(
                        "extraction file {} is an ancestor of {}",
                        ancestor.display(),
                        file.display()
                    )));
                }
            }
        }
        Ok(Self { files, directories })
    }

    /// Files that will be installed, in source order.
    #[must_use]
    pub fn files(&self) -> &[PlannedFile] {
        &self.files
    }

    /// Explicit and inferred directories that will be installed.
    pub fn directories(&self) -> impl Iterator<Item = &Path> {
        self.directories.iter().map(PathBuf::as_path)
    }

    /// Number of recovered files.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Write to a sibling staging directory and atomically rename it into place.
    ///
    /// Replacement requires `force` and a prior manifest whose file and
    /// directory lists govern every path already present.
    pub fn commit(
        &self,
        output: &Path,
        force: bool,
        manifest_name: &str,
        manifest: &[u8],
    ) -> Result<Vec<String>> {
        self.validate_destination(output, force, manifest_name)?;
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        ensure_dir(parent)?;
        let name = output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("extraction output needs a UTF-8 final path component"))?;
        let nonce = std::process::id();
        let staging = parent.join(format!(".{name}.amiga-re-stage-{nonce}"));
        let backup = parent.join(format!(".{name}.amiga-re-backup-{nonce}"));
        if staging.exists() || backup.exists() {
            return Err(invalid(format!(
                "staging or backup path already exists beside {}",
                output.display()
            )));
        }

        let previous = output
            .exists()
            .then(|| preflight_previous(output, manifest_name))
            .transpose()?;

        ensure_dir(&staging)?;
        if let Err(error) = self.write_tree(&staging, manifest_name, manifest) {
            remove_known_tree(&staging, &self.files, &self.directories, manifest_name);
            return Err(error);
        }

        if output.exists()
            && let Err(source) = fs::rename(output, &backup)
        {
            remove_known_tree(&staging, &self.files, &self.directories, manifest_name);
            return Err(io("move prior extraction aside", output, source));
        }
        if let Err(source) = fs::rename(&staging, output) {
            if backup.exists() {
                let _ = fs::rename(&backup, output);
            }
            remove_known_tree(&staging, &self.files, &self.directories, manifest_name);
            return Err(io("install extraction", output, source));
        }
        let mut warnings = Vec::new();
        if let Some(previous) = previous
            && let Err(error) = remove_preflight_tree(&backup, previous)
        {
            warnings.push(format!(
                "extraction was installed at {}, but removing prior copy {} failed: {error}",
                output.display(),
                backup.display()
            ));
        }
        Ok(warnings)
    }

    /// Write one planned file and its manifest beside each other, atomically.
    ///
    /// For an output that *is* a file rather than a directory of them. The plan
    /// must hold exactly one file, whose own path is ignored in favour of
    /// `output`: the caller named the destination, and honouring a second name
    /// from inside the plan would let the two disagree.
    ///
    /// `force` governs `output` alone. Without it an existing file is refused;
    /// with it, the sibling manifest must already say this toolkit wrote that
    /// file, so a replacement still cannot silently take over something else's
    /// output. Nothing else in the directory is read, written, or removed.
    ///
    /// # Errors
    /// Returns [`ExtractionError`] if the plan does not hold exactly one file, the
    /// path is unusable or a symbolic link, the file exists and `force` is not
    /// set, `force` is set but no matching manifest governs it, or any write or
    /// rename fails.
    /// Write every planned file into `output`, a directory this toolkit does
    /// **not** own.
    ///
    /// The third shape, and the one an import into an existing repository
    /// needs. [`Self::commit`] stages a replacement of the whole directory,
    /// which for a project root would mean asking a user to authorize replacing
    /// everything they have; [`Self::commit_file`] handles one file and its
    /// manifest. This writes the named files and reads, writes, or removes
    /// nothing else — so what is already in the directory survives, and the
    /// `force` a caller gives means "replace these files" rather than "replace
    /// this tree".
    ///
    /// Every existing ancestor of every file is checked for a symbolic link, on
    /// the same terms as a single-file commit: a link above a file must not be
    /// able to redirect a write out of the directory the caller named.
    ///
    /// # Errors
    /// Returns [`ExtractionError`] if a path is unusable or a symbolic link, a
    /// file exists and `force` is not set, or any write fails.
    ///
    /// The provenance manifest is written beside the files, under the same
    /// rules.
    pub fn commit_into(
        &self,
        output: &Path,
        force: bool,
        manifest_name: &str,
        manifest: &[u8],
    ) -> Result<Vec<String>> {
        let mut written = Vec::with_capacity(self.files.len().saturating_add(1));
        // Validated for every file before anything is written, so a malformed
        // plan cannot leave half an import behind.
        for planned in &self.files {
            let destination = output.join(&planned.path);
            for ancestor in destination.ancestors() {
                if ancestor.as_os_str().is_empty() || !ancestor.exists() {
                    continue;
                }
                reject_symlink(ancestor)?;
            }
            if destination.exists() {
                if !destination.is_file() {
                    return Err(invalid(format!(
                        "{} exists and is not a regular file",
                        destination.display()
                    )));
                }
                if !force {
                    return Err(invalid(format!(
                        "output {} already exists; enable force to replace it",
                        destination.display()
                    )));
                }
            }
        }
        // The provenance record goes in beside them, under the same rules. A
        // directory this toolkit does not own still gets told what this toolkit
        // put there — losing it would leave the imported documents
        // indistinguishable from hand-written ones.
        let manifest_path = output.join(manifest_name);
        for ancestor in manifest_path.ancestors() {
            if ancestor.as_os_str().is_empty() || !ancestor.exists() {
                continue;
            }
            reject_symlink(ancestor)?;
        }
        if manifest_path.exists() && !force {
            return Err(invalid(format!(
                "output {} already exists; enable force to replace it",
                manifest_path.display()
            )));
        }

        // Staged whole and installed with renames, so a disk that fills up
        // half-way leaves the directory as it was rather than holding some of
        // this import and none of the record that explains it. The manifest is
        // part of the same changeset for exactly that reason.
        let mut changeset: Vec<(PathBuf, Vec<u8>)> = self
            .files
            .iter()
            .map(|planned| (planned.path.clone(), planned.bytes.clone()))
            .collect();
        changeset.push((PathBuf::from(manifest_name), manifest.to_vec()));
        let staged = crate::install::StagedChangeset::stage(output, changeset)
            .map_err(|source| ExtractionError::Install { source })?;
        let installed = staged
            .install()
            .map_err(|source| ExtractionError::Install { source })?;
        written.extend(installed.iter().map(|path| path.display().to_string()));
        Ok(written)
    }

    pub fn commit_file(&self, output: &Path, force: bool, manifest: &[u8]) -> Result<Vec<String>> {
        let [planned] = self.files.as_slice() else {
            return Err(invalid(format!(
                "a single-file commit needs exactly one planned file, not {}",
                self.files.len()
            )));
        };
        if !self.directories.is_empty() {
            return Err(invalid(
                "a single-file commit cannot create directories of its own",
            ));
        }
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        let name = output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("a single-file output needs a UTF-8 file name"))?;
        // Every existing ancestor, so a link somewhere above the file cannot
        // redirect the write out of the directory the caller named.
        for ancestor in output.ancestors() {
            if ancestor.as_os_str().is_empty() || !ancestor.exists() {
                continue;
            }
            reject_symlink(ancestor)?;
        }

        let manifest_path = parent.join(format!("{name}{MANIFEST_SUFFIX}"));
        if output.exists() {
            if !force {
                return Err(invalid(format!(
                    "output {} already exists; enable force to replace it",
                    output.display()
                )));
            }
            // The provenance check, at the granularity the caller chose: this
            // toolkit will replace a file it can see it wrote, and refuse one it
            // cannot vouch for.
            if !manifest_path.exists() {
                return Err(invalid(format!(
                    "{} exists with no {} beside it, so this toolkit cannot tell \
                     whether it wrote it",
                    output.display(),
                    manifest_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or(MANIFEST_SUFFIX)
                )));
            }
        }

        ensure_dir(parent)?;
        let nonce = std::process::id();
        let staging = parent.join(format!(".{name}.amiga-re-stage-{nonce}"));
        let manifest_staging =
            parent.join(format!(".{name}{MANIFEST_SUFFIX}.amiga-re-stage-{nonce}"));
        if staging.exists() || manifest_staging.exists() {
            return Err(invalid(format!(
                "staging path already exists beside {}",
                output.display()
            )));
        }

        // Both files are staged before either is installed, so a failure part way
        // through leaves the destination as it was rather than holding a file
        // whose provenance never arrived.
        if let Err(error) = fs::write(&staging, &planned.bytes) {
            let _ = fs::remove_file(&staging);
            return Err(io("stage the output file", &staging, error));
        }
        if let Err(error) = fs::write(&manifest_staging, manifest) {
            let _ = fs::remove_file(&staging);
            let _ = fs::remove_file(&manifest_staging);
            return Err(io("stage the manifest", &manifest_staging, error));
        }
        if let Err(error) = fs::rename(&staging, output) {
            let _ = fs::remove_file(&staging);
            let _ = fs::remove_file(&manifest_staging);
            return Err(io("install the output file", output, error));
        }
        if let Err(error) = fs::rename(&manifest_staging, &manifest_path) {
            let _ = fs::remove_file(&manifest_staging);
            return Err(io("install the manifest", &manifest_path, error));
        }
        Ok(Vec::new())
    }

    /// Validate a destination and any governed replacement without writing.
    pub fn validate_destination(
        &self,
        output: &Path,
        force: bool,
        manifest_name: &str,
    ) -> Result<()> {
        let reserved = Path::new(manifest_name);
        validate_relative(reserved)?;
        if self
            .files
            .iter()
            .any(|file| file.path.as_path() == reserved)
            || self.directories.contains(reserved)
        {
            return Err(invalid(format!(
                "extraction contains a path named {manifest_name:?}, which is reserved for the manifest"
            )));
        }
        if output.as_os_str().is_empty() {
            return Err(invalid("extraction output path is empty"));
        }
        for ancestor in output.ancestors() {
            if ancestor.as_os_str().is_empty() || !ancestor.exists() {
                continue;
            }
            reject_symlink(ancestor)?;
        }
        if output.exists() {
            if !force {
                return Err(invalid(format!(
                    "output {} already exists; enable force to replace it",
                    output.display()
                )));
            }
            preflight_previous(output, manifest_name)?;
        }
        Ok(())
    }

    fn write_tree(&self, root: &Path, manifest_name: &str, manifest: &[u8]) -> Result<()> {
        for directory in &self.directories {
            ensure_dir(&root.join(directory))?;
        }
        for file in &self.files {
            let destination = root.join(&file.path);
            reject_symlink(&destination)?;
            fs::write(&destination, &file.bytes)
                .map_err(|source| io("write", &destination, source))?;
        }
        let manifest_path = root.join(manifest_name);
        reject_symlink(&manifest_path)?;
        fs::write(&manifest_path, manifest)
            .map_err(|source| io("write", &manifest_path, source))?;
        Ok(())
    }
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "unsafe extraction path {}",
            path.display()
        )));
    }
    Ok(())
}

fn insert_directory(directories: &mut BTreeSet<PathBuf>, path: &Path) {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        directories.insert(ancestor.to_path_buf());
    }
}

fn read_manifest(path: &Path) -> Result<serde_json::Value> {
    let bytes = fs::read(path).map_err(|source| io("read", path, source))?;
    serde_json::from_slice(&bytes).map_err(|source| ExtractionError::Manifest {
        path: path.display().to_string(),
        source,
    })
}

fn manifest_paths(
    manifest: &serde_json::Value,
    key: &str,
    records: bool,
) -> Result<BTreeSet<PathBuf>> {
    let Some(values) = manifest.get(key).and_then(serde_json::Value::as_array) else {
        if key == "directories" {
            return Ok(BTreeSet::new());
        }
        return Err(invalid("prior extraction manifest has no files array"));
    };
    values
        .iter()
        .map(|value| {
            let name = if records {
                value.get("path").and_then(serde_json::Value::as_str)
            } else {
                value.as_str()
            }
            .ok_or_else(|| invalid(format!("prior extraction manifest has invalid {key} entry")))?;
            let path = PathBuf::from(name);
            validate_relative(&path)?;
            Ok(path)
        })
        .collect()
}

fn preflight_previous(output: &Path, manifest_name: &str) -> Result<Vec<(PathBuf, bool)>> {
    reject_symlink(output)?;
    if !output.is_dir() {
        return Err(invalid(format!(
            "output {} exists but is not a directory",
            output.display()
        )));
    }
    let manifest_path = output.join(manifest_name);
    reject_symlink(&manifest_path)?;
    let manifest = read_manifest(&manifest_path).map_err(|error| {
        invalid(format!(
            "refusing to replace {} without a valid prior {manifest_name}: {error}",
            output.display()
        ))
    })?;
    let mut allowed_files = manifest_paths(&manifest, "files", true)?;
    allowed_files.insert(PathBuf::from(manifest_name));
    let mut allowed_dirs = manifest_paths(&manifest, "directories", false)?;
    for directory in allowed_dirs.clone() {
        insert_directory(&mut allowed_dirs, &directory);
    }
    for file in &allowed_files {
        if let Some(parent) = file.parent() {
            insert_directory(&mut allowed_dirs, parent);
        }
    }
    let inventory = inventory(output)?;
    for (path, is_dir) in &inventory {
        let allowed = if *is_dir {
            allowed_dirs.contains(path)
        } else {
            allowed_files.contains(path)
        };
        if !allowed {
            return Err(invalid(format!(
                "refusing to replace {} because it contains unmanifested path {}",
                output.display(),
                path.display()
            )));
        }
    }
    Ok(inventory)
}

fn inventory(root: &Path) -> Result<Vec<(PathBuf, bool)>> {
    fn walk(root: &Path, relative: &Path, found: &mut Vec<(PathBuf, bool)>) -> Result<()> {
        let directory = root.join(relative);
        for entry in fs::read_dir(&directory).map_err(|source| io("inspect", &directory, source))? {
            let entry = entry.map_err(|source| io("inspect", &directory, source))?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| io("inspect", &path, source))?;
            if metadata.file_type().is_symlink() {
                return Err(invalid(format!(
                    "refusing to inspect extraction through symlink {}",
                    path.display()
                )));
            }
            let child = relative.join(entry.file_name());
            let is_dir = metadata.is_dir();
            if !is_dir && !metadata.is_file() {
                return Err(invalid(format!(
                    "unsupported filesystem entry {}",
                    path.display()
                )));
            }
            found.push((child.clone(), is_dir));
            if is_dir {
                walk(root, &child, found)?;
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    walk(root, Path::new(""), &mut found)?;
    Ok(found)
}

fn remove_preflight_tree(root: &Path, mut entries: Vec<(PathBuf, bool)>) -> Result<()> {
    entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (relative, is_dir) in entries {
        let path = root.join(relative);
        if is_dir {
            fs::remove_dir(&path).map_err(|source| io("remove directory", &path, source))?;
        } else {
            fs::remove_file(&path).map_err(|source| io("remove file", &path, source))?;
        }
    }
    fs::remove_dir(root).map_err(|source| io("remove directory", root, source))
}

fn remove_known_tree(
    root: &Path,
    files: &[PlannedFile],
    directories: &BTreeSet<PathBuf>,
    manifest_name: &str,
) {
    for file in files {
        let _ = fs::remove_file(root.join(&file.path));
    }
    let _ = fs::remove_file(root.join(manifest_name));
    for directory in directories.iter().rev() {
        let _ = fs::remove_dir(root.join(directory));
    }
    let _ = fs::remove_dir(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "amiga-core-extraction-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn rejects_unsafe_duplicate_and_colliding_paths() {
        for unsafe_name in [
            "../escape",
            "/absolute",
            "safe/../escape",
            "safe/./member.bin",
            "safe//member.bin",
            "safe/member.bin//",
            r"dir\escape",
            "volume:member.bin",
        ] {
            assert!(
                safe_archive_path(unsafe_name).is_err(),
                "accepted unsafe archive path {unsafe_name:?}"
            );
        }
        assert_eq!(
            safe_archive_path("member.bin").unwrap_or_else(|error| panic!("{error}")),
            PathBuf::from("member.bin")
        );
        assert_eq!(
            safe_archive_path("safe/member.bin").unwrap_or_else(|error| panic!("{error}")),
            PathBuf::from("safe").join("member.bin")
        );
        // A trailing slash marks an LHA directory entry rather than hierarchy.
        assert_eq!(
            safe_archive_path("graphics/icons/").unwrap_or_else(|error| panic!("{error}")),
            PathBuf::from("graphics").join("icons")
        );
        assert!(
            ExtractionPlan::new(
                vec![PlannedFile {
                    path: "../escape".into(),
                    bytes: vec![]
                }],
                vec![]
            )
            .is_err()
        );
        let duplicate = ["a", "a"]
            .into_iter()
            .map(|path| PlannedFile {
                path: path.into(),
                bytes: vec![],
            })
            .collect();
        assert!(ExtractionPlan::new(duplicate, vec![]).is_err());
        let collision = ["a", "a/b"]
            .into_iter()
            .map(|path| PlannedFile {
                path: path.into(),
                bytes: vec![],
            })
            .collect();
        assert!(ExtractionPlan::new(collision, vec![]).is_err());
    }

    #[test]
    fn force_refuses_unmanifested_content_without_modifying_it() {
        let output = test_root("unknown");
        if output.exists() {
            let entries = inventory(&output).unwrap_or_else(|error| panic!("{error}"));
            remove_preflight_tree(&output, entries).unwrap_or_else(|error| panic!("{error}"));
        }
        fs::create_dir(&output).unwrap_or_else(|error| panic!("{error}"));
        fs::write(output.join("manifest.json"), br#"{"files":[]}"#)
            .unwrap_or_else(|error| panic!("{error}"));
        fs::write(output.join("keep.txt"), b"private").unwrap_or_else(|error| panic!("{error}"));
        let plan = ExtractionPlan::new(vec![], vec![]).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            plan.commit(&output, true, "manifest.json", br#"{"files":[]}"#)
                .is_err()
        );
        assert_eq!(
            fs::read(output.join("keep.txt")).unwrap_or_else(|error| panic!("{error}")),
            b"private"
        );
        let entries = inventory(&output).unwrap_or_else(|error| panic!("{error}"));
        remove_preflight_tree(&output, entries).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn force_replaces_only_a_manifest_governed_tree() {
        let output = test_root("replace");
        if output.exists() {
            let entries = inventory(&output).unwrap_or_else(|error| panic!("{error}"));
            remove_preflight_tree(&output, entries).unwrap_or_else(|error| panic!("{error}"));
        }
        let first = ExtractionPlan::new(
            vec![PlannedFile {
                path: "old.bin".into(),
                bytes: b"old".to_vec(),
            }],
            vec![],
        )
        .unwrap_or_else(|error| panic!("{error}"));
        first
            .commit(
                &output,
                false,
                "manifest.json",
                br#"{"files":[{"path":"old.bin"}]}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let second = ExtractionPlan::new(
            vec![PlannedFile {
                path: "new.bin".into(),
                bytes: b"new".to_vec(),
            }],
            vec![],
        )
        .unwrap_or_else(|error| panic!("{error}"));
        second
            .commit(
                &output,
                true,
                "manifest.json",
                br#"{"files":[{"path":"new.bin"}]}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!output.join("old.bin").exists());
        assert_eq!(
            fs::read(output.join("new.bin")).unwrap_or_else(|error| panic!("{error}")),
            b"new"
        );
        let entries = inventory(&output).unwrap_or_else(|error| panic!("{error}"));
        remove_preflight_tree(&output, entries).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn reserves_the_manifest_name_before_writing() {
        let output = test_root("manifest-collision");
        let plan = ExtractionPlan::new(
            vec![PlannedFile {
                path: "manifest.json".into(),
                bytes: b"member".to_vec(),
            }],
            vec![],
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            plan.validate_destination(&output, false, "manifest.json")
                .is_err()
        );
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn validation_rejects_a_symlink_destination_without_writing() {
        use std::os::unix::fs::symlink;

        let target = test_root("symlink-target");
        let link = test_root("symlink-link");
        if link.exists() || fs::symlink_metadata(&link).is_ok() {
            fs::remove_file(&link).unwrap_or_else(|error| panic!("{error}"));
        }
        if target.exists() {
            let entries = inventory(&target).unwrap_or_else(|error| panic!("{error}"));
            remove_preflight_tree(&target, entries).unwrap_or_else(|error| panic!("{error}"));
        }
        fs::create_dir(&target).unwrap_or_else(|error| panic!("{error}"));
        symlink(&target, &link).unwrap_or_else(|error| panic!("{error}"));
        let plan = ExtractionPlan::new(vec![], vec![]).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            plan.validate_destination(&link, true, "manifest.json")
                .is_err()
        );
        fs::remove_file(link).unwrap_or_else(|error| panic!("{error}"));
        fs::remove_dir(target).unwrap_or_else(|error| panic!("{error}"));
    }
    fn single_file_plan(bytes: &[u8]) -> ExtractionPlan {
        ExtractionPlan::new(
            vec![PlannedFile {
                path: PathBuf::from("ignored.bin"),
                bytes: bytes.to_vec(),
            }],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("amiga-core-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
        root
    }

    #[test]
    fn a_single_file_commits_into_a_directory_it_does_not_own() {
        // The whole point: the directory already exists and holds someone else's
        // work, and that is not a reason to refuse.
        let root = scratch("commit-file");
        fs::write(root.join("unrelated.txt"), b"not ours")
            .unwrap_or_else(|error| panic!("{error}"));
        let output = root.join("piece.bin");

        let warnings = single_file_plan(b"carved")
            .commit_file(&output, false, b"{}")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(warnings.is_empty());
        assert_eq!(
            fs::read(&output).unwrap_or_else(|error| panic!("{error}")),
            b"carved"
        );
        // Provenance lands beside it, under the one spelling a reader can derive.
        assert_eq!(
            fs::read(root.join(format!("piece.bin{MANIFEST_SUFFIX}")))
                .unwrap_or_else(|error| panic!("{error}")),
            b"{}"
        );
        // And nothing else was touched.
        assert_eq!(
            fs::read(root.join("unrelated.txt")).unwrap_or_else(|error| panic!("{error}")),
            b"not ours"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn replacing_a_single_file_needs_force_and_a_manifest_that_claims_it() {
        let root = scratch("commit-file-force");
        let output = root.join("piece.bin");
        single_file_plan(b"first")
            .commit_file(&output, false, b"{}")
            .unwrap_or_else(|error| panic!("{error}"));

        // Without force, refused.
        assert!(
            single_file_plan(b"second")
                .commit_file(&output, false, b"{}")
                .is_err()
        );
        assert_eq!(
            fs::read(&output).unwrap_or_else(|error| panic!("{error}")),
            b"first"
        );

        // With force and our own manifest beside it, replaced.
        single_file_plan(b"second")
            .commit_file(&output, true, b"{}")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            fs::read(&output).unwrap_or_else(|error| panic!("{error}")),
            b"second"
        );

        // With force but no manifest, refused: force authorizes replacing what
        // this toolkit wrote, not whatever happens to be in the way.
        let foreign = root.join("theirs.bin");
        fs::write(&foreign, b"someone else's").unwrap_or_else(|error| panic!("{error}"));
        assert!(
            single_file_plan(b"ours")
                .commit_file(&foreign, true, b"{}")
                .is_err()
        );
        assert_eq!(
            fs::read(&foreign).unwrap_or_else(|error| panic!("{error}")),
            b"someone else's"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_single_file_commit_refuses_a_plan_that_is_not_one_file() {
        let root = scratch("commit-file-shape");
        let many = ExtractionPlan::new(
            vec![
                PlannedFile {
                    path: PathBuf::from("a.bin"),
                    bytes: b"a".to_vec(),
                },
                PlannedFile {
                    path: PathBuf::from("b.bin"),
                    bytes: b"b".to_vec(),
                },
            ],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            many.commit_file(&root.join("one.bin"), false, b"{}")
                .is_err()
        );

        let with_directory = ExtractionPlan::new(
            vec![PlannedFile {
                path: PathBuf::from("a.bin"),
                bytes: b"a".to_vec(),
            }],
            vec![PathBuf::from("sub")],
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            with_directory
                .commit_file(&root.join("one.bin"), false, b"{}")
                .is_err()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_single_file_commit_refuses_to_write_through_a_symbolic_link() {
        let root = scratch("commit-file-symlink");
        let outside = root.join("outside.bin");
        fs::write(&outside, b"outside").unwrap_or_else(|error| panic!("{error}"));
        let link = root.join("link.bin");
        std::os::unix::fs::symlink(&outside, &link).unwrap_or_else(|error| panic!("{error}"));

        assert!(
            single_file_plan(b"ours")
                .commit_file(&link, true, b"{}")
                .is_err(),
            "a link was followed out of the destination"
        );
        assert_eq!(
            fs::read(&outside).unwrap_or_else(|error| panic!("{error}")),
            b"outside"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// An import that fails part-way leaves the directory exactly as it was.
    ///
    /// `commit_into` writes into a directory this toolkit does not own, so a
    /// half-finished import is not merely untidy: the files it did write are
    /// indistinguishable from ones somebody put there deliberately, and the
    /// manifest that would have explained them is the part that did not land.
    #[cfg(unix)]
    #[test]
    fn an_import_that_fails_part_way_leaves_the_directory_as_it_was() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = scratch("commit-into-rollback");
        fs::write(root.join("keep.txt"), b"someone else's")
            .unwrap_or_else(|error| panic!("{error}"));
        fs::write(root.join("one.bin"), b"old one").unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir(root.join("nested")).unwrap_or_else(|error| panic!("{error}"));
        fs::write(root.join("nested/two.bin"), b"old two")
            .unwrap_or_else(|error| panic!("{error}"));

        let plan = ExtractionPlan::new(
            vec![
                PlannedFile {
                    path: PathBuf::from("one.bin"),
                    bytes: b"new one".to_vec(),
                },
                PlannedFile {
                    path: PathBuf::from("nested/two.bin"),
                    bytes: b"new two".to_vec(),
                },
            ],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        // The second file's directory refuses everything, which is the shape a
        // disk filling up between two writes has: the first file is in place
        // and the second cannot be.
        let nested = root.join("nested");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("{error}"));

        let failed = plan
            .commit_into(&root, true, "manifest.json", b"{}")
            .expect_err("the second write must fail");
        assert!(
            matches!(failed, ExtractionError::Install { .. }),
            "{failed:?}"
        );

        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            fs::read(root.join("one.bin")).unwrap_or_else(|error| panic!("{error}")),
            b"old one",
            "the first file was left as the new content"
        );
        assert_eq!(
            fs::read(root.join("nested/two.bin")).unwrap_or_else(|error| panic!("{error}")),
            b"old two"
        );
        assert!(
            !root.join("manifest.json").exists(),
            "a manifest describing an import that did not happen"
        );
        assert_eq!(
            fs::read(root.join("keep.txt")).unwrap_or_else(|error| panic!("{error}")),
            b"someone else's"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// A whole-directory replacement that fails leaves the previous tree.
    ///
    /// The third write path, and the one a project replacement would use: the
    /// new tree is built beside the old, the old is moved aside, and the new is
    /// renamed into place. A failure at the last step puts the old one back —
    /// which is what makes replacing a directory something a caller can retry.
    #[cfg(unix)]
    #[test]
    fn a_failed_directory_replacement_puts_the_previous_tree_back() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = scratch("replace-rollback");
        let output = base.join("tree");
        let plan = ExtractionPlan::new(
            vec![PlannedFile {
                path: PathBuf::from("one.bin"),
                bytes: b"first".to_vec(),
            }],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let manifest = br#"{"files":[{"path":"one.bin"}],"directories":[]}"#;
        plan.commit(&output, false, "manifest.json", manifest)
            .unwrap_or_else(|error| panic!("{error}"));

        let replacement = ExtractionPlan::new(
            vec![PlannedFile {
                path: PathBuf::from("one.bin"),
                bytes: b"second".to_vec(),
            }],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        // The parent refuses the renames the install needs.
        fs::set_permissions(&base, fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("{error}"));
        let failed = replacement.commit(&output, true, "manifest.json", manifest);
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(failed.is_err(), "the replacement must fail");

        assert_eq!(
            fs::read(output.join("one.bin")).unwrap_or_else(|error| panic!("{error}")),
            b"first",
            "the previous tree was not put back"
        );
        assert!(output.join("manifest.json").is_file());

        let _ = fs::remove_dir_all(&base);
    }
}
