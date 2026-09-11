//! Provenance helpers: content hashing and a serializable source descriptor.
//!
//! Every extraction or decode this toolkit performs should record where its
//! bytes came from and their checksum, so a manifest is enough to reproduce the
//! result without redistributing copyrighted media.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A record of one source input: its path, byte size, and SHA-256.
///
/// Embed this in format-specific manifests to pin provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Source {
    pub path: String,
    pub size: usize,
    pub sha256: String,
}

impl Source {
    /// Describe `bytes` that were read from `path`.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            path: path.into(),
            size: bytes.len(),
            sha256: sha256(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_the_empty_input() {
        assert_eq!(
            sha256(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn source_records_size_and_hash() {
        let source = Source::new("disk.adf", b"abc");
        assert_eq!(source.size, 3);
        assert_eq!(
            source.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
