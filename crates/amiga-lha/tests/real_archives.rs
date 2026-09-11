//! Verification against real archives, when any are present.
//!
//! Synthetic fixtures check exact recovered bytes. This optional test also
//! checks supplied real archives against their own member CRC-16 values.
//! CRC-16 detects many errors but is not proof of byte-for-byte correctness.
//!
//! This test therefore asserts nothing about *which* archives exist. Point it
//! at real media and it verifies them; leave it alone in a public checkout and
//! it skips, because private source media is never committed.
//!
//! Where it looks, in order:
//!
//! 1. every path in `AMIGA_RE_LHA_ARCHIVES`, separated by `:`;
//! 2. every `*.lha` / `*.lzh` directly inside `crates/amiga-lha/fixtures/real/`.

use std::path::{Path, PathBuf};

/// Archives to verify, from the environment and from the conventional
/// directory. Empty is the normal case in a public checkout.
fn archives() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(list) = std::env::var("AMIGA_RE_LHA_ARCHIVES") {
        paths.extend(
            list.split(':')
                .filter(|entry| !entry.is_empty())
                .map(PathBuf::from),
        );
    }
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/real");
    if let Ok(entries) = std::fs::read_dir(&directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            let extension = path
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase);
            if matches!(extension.as_deref(), Some("lha" | "lzh")) {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}

#[test]
fn every_readable_member_of_a_real_archive_matches_its_stored_crc() {
    let archives = archives();
    if archives.is_empty() {
        eprintln!(
            "skipping: no real archives present \
             (set AMIGA_RE_LHA_ARCHIVES or populate crates/amiga-lha/fixtures/real/)"
        );
        return;
    }

    let mut verified = 0_usize;
    let mut methods = std::collections::BTreeSet::new();
    for path in &archives {
        let bytes =
            std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let archive = amiga_lha::Archive::parse(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        for entry in archive.entries() {
            let method = amiga_core::latin1(entry.method());
            methods.insert(method.clone());
            if !entry.is_readable() {
                // An honest refusal is a pass: the point is that nothing is
                // decoded wrongly, not that everything is decoded.
                continue;
            }
            // `read` verifies the declared size and the stored CRC-16, so a
            // successful call *is* the verification.
            archive
                .read(entry, amiga_lha::OutputLimit::new(64 * 1024 * 1024))
                .unwrap_or_else(|error| {
                    panic!("{} member {}: {error}", path.display(), entry.name())
                });
            verified += 1;
        }
    }
    eprintln!(
        "verified {verified} members across {} archive(s); methods seen: {}",
        archives.len(),
        methods.into_iter().collect::<Vec<_>>().join(", ")
    );
}
