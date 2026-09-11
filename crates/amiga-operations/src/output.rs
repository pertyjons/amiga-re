//! Reviewed output: what an operation intends to write, and the authorization
//! to write it.
//!
//! Nothing in this crate writes to the filesystem as a side effect of running.
//! An operation that produces files runs in two steps:
//!
//! 1. `execution.mode = prepare` builds a complete [`WritePlan`] — every
//!    destination path, its size, and its SHA-256 — and writes nothing at all.
//!    The response's status is `prepared`.
//! 2. `execution.mode = commit_reviewed` names the plan digest the caller
//!    approved. The operation prepares again from scratch, and commits only if
//!    the plan it now produces has the same digest.
//!
//! That second preparation is the point. Between reviewing a plan and
//! committing it, the source could change, the destination could gain files, or
//! the caller could have edited the request. Re-deriving and comparing digests
//! turns every one of those into a `conflict` instead of a surprise write. A
//! caller cannot skip it, because the digest is the only thing `commit_reviewed`
//! carries and it is checked against a plan this process built.
//!
//! Destinations are named the same way sources are: a relative identity the
//! adapter resolves against a root it chose. A request document never contains
//! a host path, so a plan reviewed on one machine describes the same thing on
//! another.
//!
//! A destination is either one file or a directory of them, and the difference
//! is a guarantee rather than a spelling — see [`DestinationKind`]. An operation
//! that writes a single file must not demand an empty directory to put it in:
//! that made `create_only` unusable for an ordinary output path and taught
//! callers to pass `--force` every time, which protects nothing.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::source::SourceNameError;

/// What an operation may do to a destination that already exists.
///
/// The three cases the toolkit already distinguished behind one `--force`
/// flag, now named. The normalized request records which one applied, so
/// provenance stops being ambiguous about why a replacement was allowed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputPolicy {
    /// The destination must not exist. The safe default, and the only policy
    /// under which no existing bytes can be lost.
    #[default]
    CreateOnly,
    /// Replace a destination governed by a matching amiga-re manifest — one
    /// this toolkit wrote and whose file list accounts for everything there.
    ReplaceMatchingProvenance,
    /// Replace a reviewed destination with no manifest. The caller has looked
    /// at it and accepted that this toolkit cannot vouch for what is there.
    ReplaceExplicitGenerated,
}

impl OutputPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateOnly => "create_only",
            Self::ReplaceMatchingProvenance => "replace_matching_provenance",
            Self::ReplaceExplicitGenerated => "replace_explicit_generated",
        }
    }

    /// Whether this policy permits replacing something already present.
    ///
    /// The underlying commit takes one boolean; this is the single place that
    /// decides which policies map onto it, so the mapping cannot drift between
    /// operations.
    #[must_use]
    pub const fn permits_replacement(self) -> bool {
        matches!(
            self,
            Self::ReplaceMatchingProvenance | Self::ReplaceExplicitGenerated
        )
    }
}

/// Whether a destination is one file or a directory of them.
///
/// Not decoration: it decides which guarantee applies. A `Directory` destination
/// is a tree this toolkit owns, so replacing it needs a manifest accounting for
/// everything already there. A `File` destination is one named file in a
/// directory the toolkit does *not* own, so the policy governs that file alone
/// and nothing else in the directory is read, written, or removed.
///
/// Recorded on the plan so a reviewer can see which rule was applied rather than
/// inferring it from the operation's name.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    /// One named file, plus its provenance manifest beside it.
    #[default]
    File,
    /// A directory this toolkit owns entirely.
    Directory,
    /// A directory this toolkit writes named files *into* without owning it.
    ///
    /// The shape an import into an existing repository needs. `Directory`
    /// stages a replacement of everything there, which for a project root would
    /// mean asking a user to authorize replacing all their work; this writes the
    /// planned files and touches nothing else, so `force` means "replace these
    /// files" rather than "replace this tree".
    DirectoryContents,
}

impl DestinationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::DirectoryContents => "directory_contents",
        }
    }
}

/// A destination identity, on the same terms as [`crate::SourceName`]: relative,
/// normal components only, never a host path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DestinationName(String);

impl DestinationName {
    /// Validate `name` as a destination identity.
    ///
    /// # Errors
    /// Returns [`SourceNameError`] for an empty, absolute, escaping, or
    /// otherwise non-relative name — the same rules a source name obeys,
    /// because the reason is the same: a request document must not be able to
    /// reach outside the root its adapter chose.
    pub fn parse(name: &str) -> Result<Self, SourceNameError> {
        // Reuse the source rules verbatim rather than restating them; two
        // path-safety checks that could disagree is exactly the bug to avoid.
        crate::source::SourceName::parse(name).map(|name| Self(name.as_str().to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One file an operation intends to write.
///
/// Carries the digest, not the bytes: a plan is reviewed, logged, and compared,
/// and none of that needs megabytes of payload. The bytes live in the prepared
/// operation until it commits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlannedOutput {
    /// Path relative to the destination root, `/`-separated.
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Everything an operation intends to write, and where.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WritePlan {
    /// The destination identity, relative to the adapter's output root.
    pub destination: String,
    /// Whether `destination` is one file or a directory this toolkit owns.
    pub destination_kind: DestinationKind,
    pub policy: OutputPolicy,
    /// Every file, in path order, so the digest does not depend on the order
    /// the operation happened to produce them.
    pub files: Vec<PlannedOutput>,
    /// Directories created for their own sake, in path order.
    pub directories: Vec<String>,
    /// The digest a `commit_reviewed` request must name to authorize this plan.
    pub plan_sha256: String,
}

impl WritePlan {
    /// Build a plan from what an operation intends to write.
    ///
    /// Sorting happens here rather than at each call site: two operations that
    /// produced the same files in a different order must produce the same
    /// digest, or a reviewed plan would fail to commit for no reason.
    #[must_use]
    pub fn new(
        destination: &DestinationName,
        destination_kind: DestinationKind,
        policy: OutputPolicy,
        mut files: Vec<PlannedOutput>,
        mut directories: Vec<String>,
    ) -> Self {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        directories.sort();
        directories.dedup();
        let mut plan = Self {
            destination: destination.as_str().to_owned(),
            destination_kind,
            policy,
            files,
            directories,
            plan_sha256: String::new(),
        };
        plan.plan_sha256 = plan.compute_digest();
        plan
    }

    /// The SHA-256 of the plan's canonical form.
    ///
    /// Covers the destination, the policy, and every path with its size and
    /// content hash — everything that decides what will exist afterwards. It
    /// deliberately does not cover the request that produced it: two different
    /// requests that write identical bytes to identical paths are, for the
    /// purpose of authorizing a write, the same plan.
    fn compute_digest(&self) -> String {
        let canonical = serde_json::json!({
            "destination": self.destination,
            "destination_kind": self.destination_kind,
            "policy": self.policy,
            "files": self.files,
            "directories": self.directories,
        });
        amiga_core::sha256(canonical.to_string().as_bytes())
    }

    /// Whether `approved` authorizes this plan.
    #[must_use]
    pub fn is_approved_by(&self, approved: &str) -> bool {
        // Constant-time comparison is not warranted: the digest is not a
        // secret, and an attacker who can supply it can supply the plan too.
        self.plan_sha256 == approved
    }
}

/// Where an adapter lets operations write.
///
/// A separate trait from the source resolver, and deliberately not implemented
/// by default: an adapter that has not said where output may go cannot be
/// tricked into writing anywhere.
pub trait DestinationResolver {
    /// The host directory `name` refers to.
    ///
    /// # Errors
    /// Returns [`DestinationError`] when this adapter serves no destinations,
    /// or when the name does not resolve to a usable path.
    fn resolve(&self, name: &DestinationName) -> Result<PathBuf, DestinationError>;
}

/// Why a destination could not be resolved.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DestinationError {
    /// The adapter did not offer an output root, so no write is authorized.
    #[error("this context serves no destinations, so nothing may be written")]
    Unavailable,
    /// The name resolved, but not to something a write may target.
    #[error("destination `{name}` is not usable: {reason}")]
    Unusable { name: String, reason: String },
}

/// The destinations under one host directory.
#[derive(Clone, Debug)]
pub struct FilesystemDestinationResolver {
    root: PathBuf,
}

impl FilesystemDestinationResolver {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl DestinationResolver for FilesystemDestinationResolver {
    fn resolve(&self, name: &DestinationName) -> Result<PathBuf, DestinationError> {
        // The name was already validated as relative with normal components
        // only, so joining cannot escape the root.
        Ok(self.root.join(Path::new(name.as_str())))
    }
}

/// A resolver that refuses everything.
///
/// The default for a context, so a read-only adapter — every `operations run`
/// invocation that did not ask for an output root — cannot write even if an
/// operation tried to.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDestinations;

impl DestinationResolver for NoDestinations {
    fn resolve(&self, _name: &DestinationName) -> Result<PathBuf, DestinationError> {
        Err(DestinationError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(files: Vec<PlannedOutput>) -> WritePlan {
        WritePlan::new(
            &DestinationName::parse("out").expect("a relative destination"),
            DestinationKind::Directory,
            OutputPolicy::CreateOnly,
            files,
            Vec::new(),
        )
    }

    fn file(path: &str, sha: &str) -> PlannedOutput {
        PlannedOutput {
            path: path.to_owned(),
            size: 4,
            sha256: sha.to_owned(),
        }
    }

    #[test]
    fn the_digest_does_not_depend_on_the_order_files_were_produced() {
        let forward = plan(vec![file("a.bin", "aa"), file("b.bin", "bb")]);
        let backward = plan(vec![file("b.bin", "bb"), file("a.bin", "aa")]);
        assert_eq!(forward.plan_sha256, backward.plan_sha256);
        assert_eq!(forward.files, backward.files, "files are stored in order");
    }

    #[test]
    fn the_digest_changes_when_what_would_be_written_changes() {
        let base = plan(vec![file("a.bin", "aa")]);
        for different in [
            plan(vec![file("a.bin", "bb")]),
            plan(vec![file("b.bin", "aa")]),
            plan(vec![file("a.bin", "aa"), file("b.bin", "bb")]),
            WritePlan::new(
                &DestinationName::parse("elsewhere").expect("a relative destination"),
                DestinationKind::Directory,
                OutputPolicy::CreateOnly,
                vec![file("a.bin", "aa")],
                Vec::new(),
            ),
            WritePlan::new(
                &DestinationName::parse("out").expect("a relative destination"),
                DestinationKind::Directory,
                OutputPolicy::ReplaceExplicitGenerated,
                vec![file("a.bin", "aa")],
                Vec::new(),
            ),
            // The kind is part of what will exist afterwards, so it changes the
            // digest: the same paths written under the other guarantee are not
            // the same plan.
            WritePlan::new(
                &DestinationName::parse("out").expect("a relative destination"),
                DestinationKind::File,
                OutputPolicy::CreateOnly,
                vec![file("a.bin", "aa")],
                Vec::new(),
            ),
        ] {
            assert_ne!(
                base.plan_sha256, different.plan_sha256,
                "two plans that would write differently share a digest"
            );
        }
    }

    #[test]
    fn a_plan_is_authorized_only_by_its_own_digest() {
        let plan = plan(vec![file("a.bin", "aa")]);
        assert!(plan.is_approved_by(&plan.plan_sha256));
        assert!(!plan.is_approved_by("not the digest"));
        assert!(!plan.is_approved_by(""));
    }

    #[test]
    fn a_destination_obeys_the_same_path_rules_as_a_source() {
        assert!(DestinationName::parse("out/images").is_ok());
        for refused in ["", "/absolute", "../escape", "out/../../escape"] {
            assert!(
                DestinationName::parse(refused).is_err(),
                "{refused:?} was accepted as a destination"
            );
        }
    }

    #[test]
    fn a_context_without_an_output_root_refuses_every_destination() {
        let name = DestinationName::parse("out").expect("a relative destination");
        assert_eq!(
            NoDestinations.resolve(&name),
            Err(DestinationError::Unavailable)
        );
    }

    #[test]
    fn only_the_replacing_policies_permit_replacement() {
        assert!(!OutputPolicy::CreateOnly.permits_replacement());
        assert!(OutputPolicy::ReplaceMatchingProvenance.permits_replacement());
        assert!(OutputPolicy::ReplaceExplicitGenerated.permits_replacement());
    }
}
