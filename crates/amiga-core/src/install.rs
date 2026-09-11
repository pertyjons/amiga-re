//! Installing a set of files so a failure leaves the destination unchanged.
//!
//! Both of this toolkit's write paths validated everything up front and then
//! wrote sequentially. Both delivered what they promised — a malformed plan
//! wrote nothing — and neither survived a disk filling up mid-plan: the files
//! written before the failure stayed, and the destination held a mixture of two
//! changesets that no plan describes.
//!
//! That was tolerable while each commit touched one kind of thing. It stops
//! being tolerable as soon as a changeset spans documents that index each other:
//! a root document left in place over documents from a newer set indexes a
//! mixture, and nothing in the format can tell that from a consistent project.
//!
//! # What this guarantees, and what it does not
//!
//! Every file is written into a staging directory *under the destination* —
//! same filesystem, so the installs are renames rather than copies — and only
//! then moved into place. A destination file that already exists is displaced
//! into the staging directory first, so a failure part-way through can put it
//! back. On any error every install already made is undone, in reverse, and the
//! staging directory is removed.
//!
//! This is atomicity against *errors*, not against power loss. A rename is
//! atomic; a sequence of renames is not, and making one so needs a filesystem
//! journal rather than a library. A process killed between two renames leaves a
//! mixture and a staging directory beside it — which is why the staging
//! directory is named after what it is, so whoever finds one knows what they are
//! looking at.
//!
//! Parent directories created for a staged file are **not** removed on rollback.
//! An empty directory is inert and removing one could delete a directory that
//! was already there for another reason; the files are what a rollback is about.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// The directory name a changeset stages under, inside its destination.
///
/// Named rather than random so that a staging directory left behind by a killed
/// process is recognizable as one. A caller that finds one may remove it: it
/// holds copies, never the only copy of anything.
pub const STAGING_DIRECTORY: &str = ".amiga-re-staging";

/// Failure while staging or installing a changeset.
#[derive(Debug, Error)]
pub enum InstallError {
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: io::Error,
    },
    /// An install failed and every file already moved was put back.
    ///
    /// Its own variant because the two facts a caller needs are different: what
    /// went wrong, and whether the destination is the one it started in. A
    /// rollback that itself failed is [`Self::RolledBackPartially`].
    #[error("{path} could not be installed, and the destination was left unchanged: {source}")]
    RolledBack {
        path: String,
        #[source]
        source: Box<InstallError>,
    },
    /// An install failed and the undo failed too, so the destination holds a
    /// mixture. Reported by name rather than folded into the original error: a
    /// caller that cannot tell these apart cannot tell a safe retry from an
    /// unsafe one.
    #[error(
        "{path} could not be installed and the rollback did not complete ({rollback}); \
         {restored} of {attempted} file(s) were put back and the rest are not what they were"
    )]
    RolledBackPartially {
        path: String,
        rollback: String,
        restored: usize,
        /// How many files the undo pass had to put back.
        attempted: usize,
        #[source]
        source: Box<InstallError>,
    },
}

fn io(operation: &'static str, path: &Path, source: io::Error) -> InstallError {
    InstallError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

/// One file of a staged changeset.
#[derive(Clone, Debug)]
struct Staged {
    /// Where it goes, relative to the destination.
    relative: PathBuf,
    /// Where it is now.
    staged: PathBuf,
    /// Where the file it replaces was moved to, when there was one.
    displaced: Option<PathBuf>,
    /// Whether the staged copy actually reached the destination.
    ///
    /// Separate from `displaced` because an install has two steps and can fail
    /// between them: displacing the old file and then failing to move the new
    /// one in leaves a destination with nothing at it, and an undo that did not
    /// know the difference would try to remove a file that is not there.
    installed: bool,
}

/// A whole changeset written under its destination, ready to be installed.
///
/// Staging and installing are separate so that everything that can fail on the
/// way to the bytes being on disk — a full disk, an unwritable directory, a
/// path that is not what it claimed — happens before anything in the
/// destination is touched.
#[derive(Debug)]
#[must_use = "a staged changeset is not installed until `install` is called"]
pub struct StagedChangeset {
    destination: PathBuf,
    staging: PathBuf,
    files: Vec<Staged>,
}

impl StagedChangeset {
    /// Write every file of `files` into a staging directory under `destination`.
    ///
    /// `files` pairs a destination-relative path with its complete contents.
    /// Order is preserved and is the order they are installed in.
    ///
    /// # Errors
    /// Returns [`InstallError::Io`] if the staging directory cannot be created
    /// or a file cannot be written. Nothing in the destination has been touched
    /// when this fails.
    pub fn stage(
        destination: &Path,
        files: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
    ) -> Result<Self, InstallError> {
        let staging = destination.join(STAGING_DIRECTORY);
        // A staging directory left by a killed process holds only copies, so
        // clearing it is safe and is what keeps one failure from blocking every
        // later write.
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging).map_err(|error| io("create directory", &staging, error))?;

        let mut staged = Vec::new();
        for (index, (relative, bytes)) in files.into_iter().enumerate() {
            let path = staging.join(format!("{index}.staged"));
            if let Err(error) = fs::write(&path, &bytes) {
                let _ = fs::remove_dir_all(&staging);
                return Err(io("write", &path, error));
            }
            staged.push(Staged {
                relative,
                staged: path,
                displaced: None,
                installed: false,
            });
        }
        Ok(Self {
            destination: destination.to_path_buf(),
            staging,
            files: staged,
        })
    }

    /// The staged copies, in install order.
    ///
    /// Exposed so a caller can see what is about to be moved — and so a test can
    /// make one of the moves fail and check that the rest are undone, which is
    /// the property this type exists to have.
    pub fn staged_files(&self) -> impl Iterator<Item = &Path> {
        self.files.iter().map(|file| file.staged.as_path())
    }

    /// Move every staged file into place, or leave the destination as it was.
    ///
    /// Returns the destination-relative paths that were installed, in order.
    ///
    /// # Errors
    /// Returns [`InstallError::RolledBack`] when an install failed and every
    /// earlier one was undone, and [`InstallError::RolledBackPartially`] when
    /// the undo itself could not complete — which are different situations for
    /// a caller and are therefore different errors.
    pub fn install(self) -> Result<Vec<PathBuf>, InstallError> {
        let mut files = self.files;
        let mut installed = 0_usize;
        let mut failure = None;

        for (index, file) in files.iter_mut().enumerate() {
            match install_one(&self.destination, &self.staging, file, index) {
                Ok(()) => installed += 1,
                Err(error) => {
                    failure = Some((file.relative.clone(), error));
                    break;
                }
            }
        }

        let Some((path, error)) = failure else {
            let _ = fs::remove_dir_all(&self.staging);
            return Ok(files.into_iter().map(|file| file.relative).collect());
        };

        // Undo in reverse, so a destination that was displaced and then had
        // something else moved onto it is restored in the order it changed. The
        // *failing* entry is undone too: an install displaces before it moves,
        // so the file it was replacing is already out of the way even though
        // nothing took its place.
        let attempted = installed + 1;
        let mut restored = 0_usize;
        let mut rollback = None;
        for file in files.iter().take(attempted).rev() {
            match undo_one(&self.destination, file) {
                Ok(()) => restored += 1,
                Err(error) => {
                    if rollback.is_none() {
                        rollback = Some(error.to_string());
                    }
                }
            }
        }
        let path = path.display().to_string();
        if let Some(rollback) = rollback {
            return Err(InstallError::RolledBackPartially {
                path,
                rollback,
                restored,
                attempted,
                source: Box::new(error),
            });
        }
        let _ = fs::remove_dir_all(&self.staging);
        Err(InstallError::RolledBack {
            path,
            source: Box::new(error),
        })
    }
}

/// Displace whatever is at the destination, then move the staged file there.
fn install_one(
    destination: &Path,
    staging: &Path,
    file: &mut Staged,
    index: usize,
) -> Result<(), InstallError> {
    let target = destination.join(&file.relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| io("create directory", parent, error))?;
    }
    if fs::symlink_metadata(&target).is_ok() {
        let aside = staging.join(format!("{index}.displaced"));
        fs::rename(&target, &aside).map_err(|error| io("displace", &target, error))?;
        file.displaced = Some(aside);
    }
    fs::rename(&file.staged, &target).map_err(|error| {
        // The displaced original is still in the staging directory and the undo
        // pass will put it back; reporting the failed move is what the caller
        // needs to see.
        io("install", &target, error)
    })?;
    file.installed = true;
    Ok(())
}

/// Put one installed file back the way it was.
fn undo_one(destination: &Path, file: &Staged) -> Result<(), InstallError> {
    let target = destination.join(&file.relative);
    match (&file.displaced, file.installed) {
        // There was a file here: put it back, over whatever took its place.
        (Some(aside), _) => {
            fs::rename(aside, &target).map_err(|error| io("restore", &target, error))
        }
        // There was nothing here and something was installed: removing it is
        // what "nothing here" means.
        (None, true) => match fs::remove_file(&target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io("remove", &target, error)),
        },
        // Nothing was displaced and nothing was installed, which is the entry
        // whose own install failed before it touched anything.
        (None, false) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("amiga-core-install-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
        path
    }

    fn changeset() -> Vec<(PathBuf, Vec<u8>)> {
        vec![
            (PathBuf::from("one.json"), b"new one".to_vec()),
            (PathBuf::from("nested/two.json"), b"new two".to_vec()),
            (PathBuf::from("three.json"), b"new three".to_vec()),
        ]
    }

    #[test]
    fn a_complete_install_replaces_every_file_and_leaves_no_staging_behind() {
        let root = scratch("complete");
        fs::write(root.join("one.json"), b"old one").unwrap_or_else(|error| panic!("{error}"));

        let staged =
            StagedChangeset::stage(&root, changeset()).unwrap_or_else(|error| panic!("{error}"));
        let installed = staged.install().unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(installed.len(), 3);
        assert_eq!(
            fs::read(root.join("one.json")).unwrap_or_else(|error| panic!("{error}")),
            b"new one"
        );
        assert_eq!(
            fs::read(root.join("nested/two.json")).unwrap_or_else(|error| panic!("{error}")),
            b"new two"
        );
        assert!(
            !root.join(STAGING_DIRECTORY).exists(),
            "a completed install must leave nothing staged"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// The property the whole module exists for: the *n*th move failing leaves
    /// the destination exactly as it was, including the files already moved.
    #[test]
    fn a_failed_install_puts_back_every_file_it_had_already_moved() {
        let root = scratch("rollback");
        fs::write(root.join("one.json"), b"old one").unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir_all(root.join("nested")).unwrap_or_else(|error| panic!("{error}"));
        fs::write(root.join("nested/two.json"), b"old two")
            .unwrap_or_else(|error| panic!("{error}"));
        fs::write(root.join("three.json"), b"old three").unwrap_or_else(|error| panic!("{error}"));

        let staged =
            StagedChangeset::stage(&root, changeset()).unwrap_or_else(|error| panic!("{error}"));
        // Make the third move fail, which is what a disk filling up looks like
        // from here: two files are in place and the third cannot be written.
        let third = staged
            .staged_files()
            .nth(2)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| panic!("three files were staged"));
        fs::remove_file(&third).unwrap_or_else(|error| panic!("{error}"));

        let error = staged.install().expect_err("the third move must fail");
        assert!(
            matches!(error, InstallError::RolledBack { .. }),
            "{error:?}"
        );

        // Every file is the content it had before, not a mixture of two sets.
        assert_eq!(
            fs::read(root.join("one.json")).unwrap_or_else(|error| panic!("{error}")),
            b"old one"
        );
        assert_eq!(
            fs::read(root.join("nested/two.json")).unwrap_or_else(|error| panic!("{error}")),
            b"old two"
        );
        assert_eq!(
            fs::read(root.join("three.json")).unwrap_or_else(|error| panic!("{error}")),
            b"old three"
        );
        assert!(!root.join(STAGING_DIRECTORY).exists());

        let _ = fs::remove_dir_all(&root);
    }

    /// A file the changeset creates rather than replaces is removed again, so a
    /// rollback does not leave a file the destination never had.
    #[test]
    fn a_rollback_removes_the_files_the_changeset_would_have_created() {
        let root = scratch("created");

        let staged =
            StagedChangeset::stage(&root, changeset()).unwrap_or_else(|error| panic!("{error}"));
        let third = staged
            .staged_files()
            .nth(2)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| panic!("three files were staged"));
        fs::remove_file(&third).unwrap_or_else(|error| panic!("{error}"));

        assert!(staged.install().is_err());
        assert!(!root.join("one.json").exists());
        assert!(!root.join("nested/two.json").exists());
        assert!(!root.join("three.json").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn staging_writes_nothing_into_the_destination_itself() {
        let root = scratch("staged-only");
        let staged =
            StagedChangeset::stage(&root, changeset()).unwrap_or_else(|error| panic!("{error}"));

        assert!(!root.join("one.json").exists());
        assert_eq!(staged.staged_files().count(), 3);
        assert!(root.join(STAGING_DIRECTORY).is_dir());

        let _ = fs::remove_dir_all(&root);
    }
}
