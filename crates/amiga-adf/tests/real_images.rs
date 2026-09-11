//! Verification against real disk images, when any are present.
//!
//! The fixtures inside the crate are synthetic, and their builder encodes the
//! same reading of the AmigaDOS layout as the reader does: a shared mistake in a
//! field offset, in the direction the data table is filled, or in the extension
//! chain would be invisible to every one of them. Only bytes recovered by
//! something that is not this crate can settle that, so this test compares the
//! reader against an expectation manifest produced by an independent
//! AmigaOS-compatible extractor.
//!
//! This test therefore asserts nothing about *which* images exist. Point it at
//! real media and it verifies them; leave it alone in a public checkout and it
//! skips, because private source media is never committed.
//!
//! Where it looks, in order:
//!
//! 1. every path in `AMIGA_RE_FFS_IMAGES`, separated by `:`;
//! 2. every `*.adf` / `*.hdf` directly inside the ignored repository-root
//!    `original/ffs/` directory.
//!
//! # The expectation manifest
//!
//! Every image needs a manifest beside it, named after the image with
//! `.expected` appended (`original/ffs/workbench.adf.expected`). It is a
//! line-oriented text file — deliberately, because it has to be *produced*
//! outside this workspace: `unadf`, `xdftool`, or an Amiga itself writes the
//! files out, `sha256sum` digests them, and a few lines of shell reshape that
//! into this. A format needing a serializer would have put a dependency between
//! the independent extractor and the pin, which is the one thing the pin exists
//! to avoid.
//!
//! Blank lines and lines starting with `#` are ignored. Every other line is
//! either the source pin or one expected file:
//!
//! ```text
//! # Workbench 3.1, recovered with unadf 0.7.11a.
//! image-sha256 4a4f...  (64 hex digits, of the image file itself)
//! file <sha256> <length> <normalized path>
//! ```
//!
//! The path comes last and runs to the end of the line, so a name containing a
//! space needs no quoting. It is the image-relative path with `/` separators
//! and no leading slash, exactly as [`amiga_adf::Entry::path`] renders.
//!
//! Only files are listed. Directories are not pinned: they carry no recovered
//! bytes, and an extractor that reports them at all does not agree with the next
//! one on whether an empty one exists.
//!
//! # What counts as a pass
//!
//! An image that is present but has no usable pin is a **failure**, not a skip.
//! Verification that quietly downgrades itself to "the parse did not crash" is
//! how the FFS path came to be trusted without evidence in the first place.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use amiga_adf::{BLOCK_SIZE, EntryKind, FileSystem, Image};

/// Longwords in a file header's data-block table. Not exported by the crate;
/// used here only to describe how large a file has to be before its recovery
/// must cross into an extension block.
const TABLE_CAPACITY: usize = 72;

/// One pinned file: what an independent extractor recovered for it.
struct ExpectedFile {
    length: u64,
    sha256: String,
}

/// A parsed expectation manifest.
struct Expectation {
    image_sha256: String,
    files: BTreeMap<String, ExpectedFile>,
}

/// Images to verify, from the environment and from the conventional directory.
/// Empty is the normal case in a public checkout.
fn images() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(list) = std::env::var("AMIGA_RE_FFS_IMAGES") {
        paths.extend(
            list.split(':')
                .filter(|entry| !entry.is_empty())
                .map(PathBuf::from),
        );
    }
    // `crates/amiga-adf` -> the repository root, where `original/` is ignored.
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../original/ffs");
    if let Ok(entries) = std::fs::read_dir(&directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            let extension = path
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase);
            if matches!(extension.as_deref(), Some("adf" | "hdf")) {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// The manifest that belongs to `image`: its own name with `.expected` appended.
fn manifest_path(image: &Path) -> PathBuf {
    let mut path = image.to_path_buf().into_os_string();
    path.push(".expected");
    PathBuf::from(path)
}

/// A lowercase 64-digit hex digest, or an explanation of why the text is not
/// one. A mistyped pin must be refused rather than compared and missed.
fn digest(text: &str) -> Result<String, String> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{text:?} is not a 64-digit hex SHA-256"));
    }
    Ok(text.to_ascii_lowercase())
}

/// Split `count` whitespace-separated fields off the front of `line`, returning
/// them and the untouched remainder, so that the last field of a manifest line
/// may itself contain spaces.
fn split_fields(line: &str, count: usize) -> Option<(Vec<&str>, &str)> {
    let mut fields = Vec::with_capacity(count);
    let mut rest = line;
    for _ in 0..count {
        let (head, tail) = rest.split_once(char::is_whitespace)?;
        fields.push(head);
        rest = tail.trim_start();
    }
    Some((fields, rest))
}

fn parse_expectation(text: &str) -> Result<Expectation, String> {
    let mut image_sha256 = None;
    let mut files = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let number = index + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("image-sha256") {
            let value = digest(rest.trim()).map_err(|error| format!("line {number}: {error}"))?;
            if image_sha256.replace(value).is_some() {
                return Err(format!("line {number}: image-sha256 is given twice"));
            }
            continue;
        }
        let Some((fields, path)) = split_fields(line, 3) else {
            return Err(format!(
                "line {number}: expected `file <sha256> <length> <path>`"
            ));
        };
        if fields[0] != "file" {
            return Err(format!("line {number}: unknown keyword {:?}", fields[0]));
        }
        let sha256 = digest(fields[1]).map_err(|error| format!("line {number}: {error}"))?;
        let length = fields[2]
            .parse::<u64>()
            .map_err(|error| format!("line {number}: bad length {:?}: {error}", fields[2]))?;
        if path.is_empty() {
            return Err(format!("line {number}: the path is missing"));
        }
        if files
            .insert(path.to_string(), ExpectedFile { length, sha256 })
            .is_some()
        {
            return Err(format!("line {number}: {path} is pinned twice"));
        }
    }
    let image_sha256 = image_sha256
        .ok_or_else(|| "no `image-sha256` line: the source is not pinned".to_string())?;
    if files.is_empty() {
        return Err("no `file` lines: nothing would be verified".to_string());
    }
    Ok(Expectation {
        image_sha256,
        files,
    })
}

/// An entry path as the manifest spells it: `/`-separated, no leading slash.
/// Entry names cannot contain a separator, so the components are the name.
fn normalized(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Verify one image against its manifest, appending every disagreement found.
/// Returns the number of files whose recovered bytes matched their pin.
fn verify(image_path: &Path, failures: &mut Vec<String>) -> usize {
    let manifest_path = manifest_path(image_path);
    let manifest = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(error) => {
            // Requirement, not an inconvenience: an unpinned image is reported
            // as unverified rather than counted as a pass.
            failures.push(format!(
                "{}: unverified, no expectation manifest at {} ({error})",
                image_path.display(),
                manifest_path.display()
            ));
            return 0;
        }
    };
    let expectation = match parse_expectation(&manifest) {
        Ok(expectation) => expectation,
        Err(error) => {
            failures.push(format!(
                "{}: unverified, {} is unusable: {error}",
                image_path.display(),
                manifest_path.display()
            ));
            return 0;
        }
    };

    let bytes = match std::fs::read(image_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!("{}: {error}", image_path.display()));
            return 0;
        }
    };
    let actual = amiga_core::sha256(&bytes);
    if actual != expectation.image_sha256 {
        // The pin describes a different image, so every file digest below would
        // be compared against the wrong source. Refuse it outright.
        failures.push(format!(
            "{}: expectation is pinned to source {} but this image is {actual}",
            image_path.display(),
            expectation.image_sha256
        ));
        return 0;
    }

    let image = match Image::open(&bytes) {
        Ok(image) => image,
        Err(error) => {
            failures.push(format!("{}: {error}", image_path.display()));
            return 0;
        }
    };
    if image.filesystem() != FileSystem::Ffs {
        failures.push(format!(
            "{}: opened as {}, but this test exists to exercise FFS",
            image_path.display(),
            image.filesystem()
        ));
        return 0;
    }

    let mut verified = 0_usize;
    let mut seen = BTreeSet::new();
    let mut largest = 0_u64;
    for entry in image.entries() {
        if entry.kind != EntryKind::File {
            continue;
        }
        let path = normalized(&entry.path);
        let Some(expected) = expectation.files.get(&path) else {
            // The enumerated set is compared whole in both directions: a file
            // the pin never mentions is as much a defect as a missing one.
            failures.push(format!(
                "{}: {path} was enumerated but is not pinned",
                image_path.display()
            ));
            continue;
        };
        seen.insert(path.clone());
        let recovered = match image.read_file(entry) {
            Ok(recovered) => recovered,
            Err(error) => {
                failures.push(format!("{}: {path}: {error}", image_path.display()));
                continue;
            }
        };
        let length = recovered.len() as u64;
        if length != expected.length {
            failures.push(format!(
                "{}: {path}: recovered {length} bytes, expected {}",
                image_path.display(),
                expected.length
            ));
            continue;
        }
        let digest = amiga_core::sha256(&recovered);
        if digest != expected.sha256 {
            failures.push(format!(
                "{}: {path}: recovered content is {digest}, expected {}",
                image_path.display(),
                expected.sha256
            ));
            continue;
        }
        largest = largest.max(length);
        verified += 1;
    }
    for path in expectation.files.keys() {
        if !seen.contains(path) {
            failures.push(format!(
                "{}: {path} is pinned but was not enumerated",
                image_path.display()
            ));
        }
    }

    // A pin made only of files that fit in one data block would exercise none of
    // what is actually unproven: the table walk, its fill direction, and the
    // extension chain.
    let block = BLOCK_SIZE as u64;
    // Saturating rather than panicking: an overflow here would only mean no
    // file could possibly need an extension block.
    let table_span = block.saturating_mul(TABLE_CAPACITY as u64);
    if largest <= block {
        failures.push(format!(
            "{}: nothing verified spans several data blocks, so the data table \
             walk is still unproven",
            image_path.display()
        ));
    } else if largest <= table_span {
        eprintln!(
            "{}: verified up to {largest} bytes; no file needs an extension block",
            image_path.display()
        );
    } else {
        eprintln!(
            "{}: verified up to {largest} bytes, crossing the extension chain",
            image_path.display()
        );
    }
    verified
}

#[test]
fn every_file_on_a_real_ffs_image_matches_an_independently_recovered_digest() {
    let images = images();
    if images.is_empty() {
        eprintln!(
            "skipping: no real FFS images present \
             (set AMIGA_RE_FFS_IMAGES or populate original/ffs/)"
        );
        return;
    }

    let mut failures = Vec::new();
    let mut verified = 0_usize;
    for path in &images {
        verified += verify(path, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "FFS verification failed:\n{}",
        failures.join("\n")
    );
    eprintln!(
        "verified {verified} file(s) across {} FFS image(s)",
        images.len()
    );
}
