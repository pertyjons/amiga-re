use std::path::PathBuf;

use thiserror::Error;

const HUNK_HEADER: [u8; 4] = [0, 0, 3, 0xf3];
const MAX_DISCOVERED_HUNKS: usize = 4_096;

/// The outer format whose readable contents should be inventoried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HunkDiscoveryKind {
    /// A loose HUNK executable or arbitrary binary that may embed one.
    File,
    /// An AmigaDOS disk image, OFS or FFS.
    Adf,
    /// An LHA/LZH archive.
    Lha,
}

/// The logical object that contains a discovered HUNK executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HunkCarrier {
    /// The opened source itself.
    Source,
    /// A recovered file in an ADF image.
    AdfMember { path: PathBuf, header_block: u32 },
    /// A readable member in an LHA/LZH archive.
    LhaMember { name: String },
}

/// One parser-validated HUNK executable and its container provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HunkSource {
    pub carrier: HunkCarrier,
    /// Byte offset within `carrier`.
    pub offset: usize,
    /// Original size of `carrier`, used to distinguish whole members from
    /// embedded executables.
    pub carrier_size: usize,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub segments: usize,
    pub relocations: usize,
}

impl HunkSource {
    /// Whether this executable occupies the carrier in its entirety.
    #[must_use]
    pub fn is_whole_carrier(&self) -> bool {
        self.offset == 0 && self.bytes.len() == self.carrier_size
    }
}

/// A limitation or recoverable problem encountered during discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HunkDiscoveryWarning {
    pub context: String,
    pub message: String,
}

/// Complete HUNK inventory for the readable parts of one source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HunkDiscovery {
    pub sources: Vec<HunkSource>,
    pub warnings: Vec<HunkDiscoveryWarning>,
}

/// Failure that prevents HUNK discovery from completing.
#[derive(Debug, Error)]
pub enum HunkDiscoveryError {
    #[error("failed to parse ADF: {0}")]
    Adf(#[from] amiga_adf::Error),
    #[error("failed to parse LHA: {0}")]
    Lha(#[from] amiga_lha::LhaError),
    #[error("HUNK discovery was cancelled")]
    Cancelled,
}

/// Inventory every readable, parser-validated HUNK source in `bytes`.
///
/// `lha_limit` bounds cumulative decoded LHA member bytes.
/// This convenience wrapper never requests cancellation.
pub fn discover_hunk_sources(
    kind: HunkDiscoveryKind,
    bytes: &[u8],
    lha_limit: amiga_lha::OutputLimit,
) -> Result<HunkDiscovery, HunkDiscoveryError> {
    discover_hunk_sources_with_cancel(kind, bytes, lha_limit, || false)
}

/// Inventory HUNK sources while checking `cancelled` between carrier files and
/// HUNK candidates.
///
/// Unsupported compressed LHA members and unreadable recovered files are
/// returned as warnings so callers never mistake a partial inventory for a
/// complete one. Exceeding `lha_limit` is a fatal error, with no partial inventory.
pub fn discover_hunk_sources_with_cancel(
    kind: HunkDiscoveryKind,
    bytes: &[u8],
    lha_limit: amiga_lha::OutputLimit,
    mut cancelled: impl FnMut() -> bool,
) -> Result<HunkDiscovery, HunkDiscoveryError> {
    let mut discovery = HunkDiscovery::default();
    match kind {
        HunkDiscoveryKind::File => {
            scan_carrier(bytes, HunkCarrier::Source, &mut discovery, &mut cancelled)?;
        }
        HunkDiscoveryKind::Adf => {
            let image = amiga_adf::Image::open(bytes)?;
            for entry in image
                .entries()
                .iter()
                .filter(|entry| entry.kind == amiga_adf::EntryKind::File)
            {
                check_cancelled(&mut cancelled)?;
                match image.read_file(entry) {
                    Ok(member) => scan_carrier(
                        &member,
                        HunkCarrier::AdfMember {
                            path: entry.path.clone(),
                            header_block: entry.header_block.get(),
                        },
                        &mut discovery,
                        &mut cancelled,
                    )?,
                    Err(error) => discovery.warnings.push(HunkDiscoveryWarning {
                        context: entry.path.display().to_string(),
                        message: format!("file could not be scanned: {error}"),
                    }),
                }
            }
        }
        HunkDiscoveryKind::Lha => {
            let archive = amiga_lha::Archive::parse(bytes)?;
            let mut remaining = lha_limit.bytes();
            for entry in archive
                .entries()
                .iter()
                .filter(|entry| !entry.is_directory())
            {
                check_cancelled(&mut cancelled)?;
                if !entry.is_readable() {
                    discovery.warnings.push(HunkDiscoveryWarning {
                        context: entry.name().to_owned(),
                        message: format!(
                            "{} member could not be scanned because this compression method is unsupported",
                            entry.method_str()
                        ),
                    });
                    continue;
                }
                match archive.read(entry, amiga_lha::OutputLimit::new(remaining)) {
                    Ok(member) => {
                        remaining -= member.len() as u64;
                        scan_carrier(
                            &member,
                            HunkCarrier::LhaMember {
                                name: entry.name().to_owned(),
                            },
                            &mut discovery,
                            &mut cancelled,
                        )?;
                    }
                    Err(error @ amiga_lha::LhaError::OutputLimitExceeded { .. }) => {
                        return Err(error.into());
                    }
                    Err(error) => discovery.warnings.push(HunkDiscoveryWarning {
                        context: entry.name().to_owned(),
                        message: format!("member could not be scanned: {error}"),
                    }),
                }
            }
        }
    }
    Ok(discovery)
}

fn scan_carrier(
    bytes: &[u8],
    carrier: HunkCarrier,
    discovery: &mut HunkDiscovery,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HunkDiscoveryError> {
    let mut cursor = 0;
    while cursor <= bytes.len().saturating_sub(HUNK_HEADER.len()) {
        check_cancelled(cancelled)?;
        let Some(relative) = bytes[cursor..]
            .windows(HUNK_HEADER.len())
            .position(|window| window == HUNK_HEADER)
        else {
            break;
        };
        let offset = cursor + relative;
        match amiga_hunk::Executable::parse_prefix(&bytes[offset..]) {
            Ok((executable, consumed)) => {
                if discovery.sources.len() == MAX_DISCOVERED_HUNKS {
                    discovery.warnings.push(HunkDiscoveryWarning {
                        context: "source".to_owned(),
                        message: format!(
                            "discovery stopped after the safety limit of {MAX_DISCOVERED_HUNKS} HUNK sources"
                        ),
                    });
                    return Ok(());
                }
                let hunk_bytes = bytes[offset..offset + consumed].to_vec();
                discovery.sources.push(HunkSource {
                    carrier: carrier.clone(),
                    offset,
                    carrier_size: bytes.len(),
                    sha256: amiga_core::sha256(&hunk_bytes),
                    segments: executable.segments.len(),
                    relocations: executable.relocations.len(),
                    bytes: hunk_bytes,
                });
                cursor = offset + consumed;
            }
            Err(_) => cursor = offset + 1,
        }
    }
    Ok(())
}

fn check_cancelled(cancelled: &mut impl FnMut() -> bool) -> Result<(), HunkDiscoveryError> {
    if cancelled() {
        Err(HunkDiscoveryError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_adf_word(block: &mut [u8], offset: usize, value: u32) {
        block[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn seal_adf_block(block: &mut [u8]) {
        write_adf_word(block, 20, 0);
        let sum = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .fold(0_u32, u32::wrapping_add);
        write_adf_word(block, 20, 0_u32.wrapping_sub(sum));
    }

    fn write_adf_name(block: &mut [u8], name: &str) {
        block[432] = name.len() as u8;
        block[433..433 + name.len()].copy_from_slice(name.as_bytes());
    }

    fn synthetic_adf(payload: &[u8]) -> Vec<u8> {
        const BLOCK_SIZE: usize = 512;
        const ROOT: u32 = 4;
        const FILE_HEADER: u32 = 2;
        const DATA: u32 = 3;
        let mut image = vec![0_u8; 8 * BLOCK_SIZE];
        image[..4].copy_from_slice(b"DOS\0");

        let root = &mut image[ROOT as usize * BLOCK_SIZE..(ROOT as usize + 1) * BLOCK_SIZE];
        write_adf_word(root, 0, 2);
        write_adf_word(root, 24, FILE_HEADER);
        write_adf_name(root, "DISK");
        write_adf_word(root, 508, 1);
        seal_adf_block(root);

        let header =
            &mut image[FILE_HEADER as usize * BLOCK_SIZE..(FILE_HEADER as usize + 1) * BLOCK_SIZE];
        write_adf_word(header, 0, 2);
        write_adf_word(header, 4, FILE_HEADER);
        write_adf_word(header, 16, DATA);
        write_adf_word(header, 324, payload.len() as u32);
        write_adf_name(header, "PROGRAM");
        write_adf_word(header, 508, (-3_i32) as u32);
        seal_adf_block(header);

        let data = &mut image[DATA as usize * BLOCK_SIZE..(DATA as usize + 1) * BLOCK_SIZE];
        write_adf_word(data, 0, 8);
        write_adf_word(data, 4, FILE_HEADER);
        write_adf_word(data, 8, 1);
        write_adf_word(data, 12, payload.len() as u32);
        data[24..24 + payload.len()].copy_from_slice(payload);
        seal_adf_block(data);
        image
    }

    fn minimal_hunk() -> Vec<u8> {
        [0x03f3_u32, 0, 1, 0, 0, 1, 0x03e9, 1, 0x4e75_0000, 0x03f2]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect()
    }

    fn stored_lha(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"-lh0-");
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(0x20);
        body.push(0);
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        body.extend_from_slice(&lha_crc16(data).to_le_bytes());
        let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        let mut archive = vec![body.len() as u8, checksum];
        archive.extend_from_slice(&body);
        archive.extend_from_slice(data);
        archive.push(0);
        archive
    }

    fn lha_crc16(data: &[u8]) -> u16 {
        let mut crc = 0_u16;
        for byte in data {
            crc ^= u16::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xa001
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }

    #[test]
    fn finds_whole_and_embedded_hunk_sources() {
        let hunk = minimal_hunk();
        let whole = discover_hunk_sources(
            HunkDiscoveryKind::File,
            &hunk,
            amiga_lha::OutputLimit::new(1024 * 1024),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(whole.sources.len(), 1);
        assert!(whole.sources[0].is_whole_carrier());

        let mut carrier = b"prefix".to_vec();
        carrier.extend_from_slice(&hunk);
        carrier.extend_from_slice(b"suffix");
        let embedded = discover_hunk_sources(
            HunkDiscoveryKind::File,
            &carrier,
            amiga_lha::OutputLimit::new(1024 * 1024),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(embedded.sources.len(), 1);
        assert_eq!(embedded.sources[0].offset, 6);
        assert_eq!(embedded.sources[0].bytes, hunk);
        assert!(!embedded.sources[0].is_whole_carrier());
    }

    #[test]
    fn inventories_a_stored_lha_member() {
        let hunk = minimal_hunk();
        let archive = stored_lha(b"bin/tool", &hunk);
        let discovery = discover_hunk_sources(
            HunkDiscoveryKind::Lha,
            &archive,
            amiga_lha::OutputLimit::new(1024 * 1024),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(discovery.sources.len(), 1);
        assert_eq!(
            discovery.sources[0].carrier,
            HunkCarrier::LhaMember {
                name: "bin/tool".to_owned()
            }
        );
        assert!(discovery.sources[0].is_whole_carrier());
    }

    #[test]
    fn inventories_a_recovered_adf_file() {
        let hunk = minimal_hunk();
        let image = synthetic_adf(&hunk);
        let discovery = discover_hunk_sources(
            HunkDiscoveryKind::Adf,
            &image,
            amiga_lha::OutputLimit::new(1024 * 1024),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(discovery.sources.len(), 1);
        assert_eq!(
            discovery.sources[0].carrier,
            HunkCarrier::AdfMember {
                path: PathBuf::from("PROGRAM"),
                header_block: 2,
            }
        );
        assert_eq!(discovery.sources[0].bytes, hunk);
    }

    #[test]
    fn cancellation_returns_no_partial_inventory() {
        let hunk = minimal_hunk();
        let carrier: Vec<_> = hunk.iter().chain(&hunk).copied().collect();
        let mut checks = 0;
        let result = discover_hunk_sources_with_cancel(
            HunkDiscoveryKind::File,
            &carrier,
            amiga_lha::OutputLimit::new(1024 * 1024),
            || {
                checks += 1;
                checks > 1
            },
        );
        assert!(matches!(result, Err(HunkDiscoveryError::Cancelled)));
    }
}
