//! Safe handling of user- and archive-controlled output paths.
//!
//! Extraction tools take names from untrusted media. These helpers enforce the
//! project's non-negotiable rules: never traverse outside the output tree, never
//! write through a symbolic link, and never clobber an existing path without an
//! explicit `--force`.

use std::fs;
use std::path::Path;

use thiserror::Error;

/// Failure while validating or preparing an output path.
#[derive(Debug, Error)]
pub enum PathError {
    /// A symbolic link on a path this toolkit is about to use.
    ///
    /// Worded as the *fact* rather than as one of its consequences, because both
    /// halves of the project use it: a destination must not be written through a
    /// link, and [`crate`]'s callers also refuse to *read* a source through one,
    /// so that a resolver cannot be pointed outside the root it serves. Saying
    /// "refusing to write" on the read path told a reader `adf list` had tried
    /// to write something, and sent them looking for an output path they had
    /// never given.
    #[error("refusing to follow symbolic link {path}")]
    Symlink { path: String },
    #[error("path {path} exists but is not a directory")]
    NotADirectory { path: String },
    #[error("output {path} exists but is not a regular file")]
    NotAFile { path: String },
    #[error("output {path} already exists; pass --force to replace it")]
    AlreadyExists { path: String },
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> PathError {
    PathError::Io {
        operation,
        path: display(path),
        source,
    }
}

/// Whether a single path component is safe to use verbatim: non-empty, not `.`
/// or `..`, and restricted to ASCII alphanumerics plus `.`, `_`, and `-`.
#[must_use]
pub fn is_safe_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

/// Fail if `path` exists and is a symbolic link. A missing path is fine.
pub fn reject_symlink(path: &Path) -> Result<(), PathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(PathError::Symlink {
            path: display(path),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io("inspect", path, error)),
    }
}

/// Ensure `path` is an existing directory, creating it and any missing parents.
/// Each existing component is checked for symlink substitution first.
pub fn ensure_dir(path: &Path) -> Result<(), PathError> {
    if path.exists() {
        reject_symlink(path)?;
        if !path.is_dir() {
            return Err(PathError::NotADirectory {
                path: display(path),
            });
        }
        return Ok(());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_dir(parent)?;
    }
    fs::create_dir(path).map_err(|error| io("create directory", path, error))
}

/// Prepare a directory to receive an extraction. Refuses to replace an existing
/// path unless `force` is set, and never follows a symlink.
pub fn prepare_output_dir(path: &Path, force: bool) -> Result<(), PathError> {
    if path.exists() {
        if !force {
            return Err(PathError::AlreadyExists {
                path: display(path),
            });
        }
        reject_symlink(path)?;
        if !path.is_dir() {
            return Err(PathError::NotADirectory {
                path: display(path),
            });
        }
        return Ok(());
    }
    ensure_dir(path)
}

/// Prepare to write a single output file: refuse to overwrite without `force`,
/// refuse to write through a symlink, and create the parent directory.
pub fn prepare_output_file(path: &Path, force: bool) -> Result<(), PathError> {
    validate_output_file(path, force)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_dir(parent)?;
    }
    Ok(())
}

/// Validate a future single-file output without changing the filesystem.
///
/// Existing ancestors and the destination itself are checked for symlinks.
/// An existing destination requires `force` and must be a regular file.
///
/// # Errors
/// Returns [`PathError`] for a symlink, non-directory ancestor, existing output
/// without `force`, or an existing destination that is not a regular file.
pub fn validate_output_file(path: &Path, force: bool) -> Result<(), PathError> {
    if path.as_os_str().is_empty() {
        return Err(PathError::NotAFile {
            path: display(path),
        });
    }
    if path.exists() {
        reject_symlink(path)?;
        if !path.is_file() {
            return Err(PathError::NotAFile {
                path: display(path),
            });
        }
        if !force {
            return Err(PathError::AlreadyExists {
                path: display(path),
            });
        }
    } else {
        reject_symlink(path)?;
    }
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() || !ancestor.exists() {
            continue;
        }
        reject_symlink(ancestor)?;
        if !ancestor.is_dir() {
            return Err(PathError::NotADirectory {
                path: display(ancestor),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        assert!(is_safe_component("SampleProject"));
        assert!(is_safe_component("gfx.chip"));
        assert!(is_safe_component("SMP3-5_v2"));
    }

    #[test]
    fn rejects_traversal_and_separators() {
        assert!(!is_safe_component(""));
        assert!(!is_safe_component("."));
        assert!(!is_safe_component(".."));
        assert!(!is_safe_component("a/b"));
        assert!(!is_safe_component("a\\b"));
        assert!(!is_safe_component("with space"));
        assert!(!is_safe_component("na\0me"));
    }

    #[test]
    #[cfg(unix)]
    fn refuses_to_write_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("amiga-core-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
        let target = base.join("real.txt");
        fs::write(&target, b"data").unwrap_or_else(|error| panic!("{error}"));
        let link = base.join("link.txt");
        symlink(&target, &link).unwrap_or_else(|error| panic!("{error}"));

        assert!(matches!(
            reject_symlink(&link),
            Err(PathError::Symlink { .. })
        ));
        assert!(reject_symlink(&target).is_ok());
        assert!(reject_symlink(&base.join("missing.txt")).is_ok());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn validates_an_output_plan_without_creating_parents() {
        let base = std::env::temp_dir().join(format!("amiga-core-plan-{}", std::process::id()));
        let nested = base.join("missing").join("preview.png");
        assert!(validate_output_file(&nested, false).is_ok());
        assert!(!base.exists());
    }
}
