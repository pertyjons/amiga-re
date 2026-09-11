use amiga_core::{ExtractionPlan, PlannedFile, Source, safe_archive_path, sha256};
use serde::Serialize;
use thiserror::Error;

/// A completely recovered extraction ready for frontend review.
#[derive(Clone, Debug)]
pub struct PreparedExtraction {
    pub plan: ExtractionPlan,
    pub manifest: Vec<u8>,
    pub warnings: Vec<String>,
    /// Members the container holds and this build could not recover.
    ///
    /// Empty for a sound container. A non-empty list is not a partial *file* —
    /// every path in [`Self::plan`] is complete, and a member that could not be
    /// read whole is absent rather than filled in — so a caller may commit the
    /// plan and must also report this, because a directory silently missing a
    /// file is what makes an extraction untrustworthy.
    pub unreadable: Vec<UnreadableMember>,
}

/// One member a container names and this build could not recover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnreadableMember {
    /// The path it would have been written to, `/`-separated.
    pub path: String,
    /// Why it could not be read, as the reader that refused it said.
    pub reason: String,
}

/// Recovery ceilings for [`prepare_adf_extraction`].
///
/// The byte ceiling covers retained file content and the next file's declared
/// allocation. The member ceiling counts every indexed file and directory,
/// including empty and unreadable files. Input bytes, the parser's directory
/// index, and manifest metadata are not charged as recovered file bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct AdfExtractionLimits {
    maximum_output_bytes: u64,
    maximum_members: usize,
}

impl AdfExtractionLimits {
    /// Set explicit aggregate byte and member ceilings. Zero is a valid limit.
    pub const fn new(maximum_output_bytes: u64, maximum_members: usize) -> Self {
        Self {
            maximum_output_bytes,
            maximum_members,
        }
    }
}

/// Failure while recovering or validating a container extraction.
#[derive(Debug, Error)]
pub enum ExtractionPreparationError {
    #[error("ADF has {members} members, exceeding the {limit}-member extraction budget")]
    MemberLimitExceeded { members: usize, limit: usize },
    #[error(
        "{path}: {required} output bytes exceed the remaining {remaining}-byte extraction budget"
    )]
    OutputLimitExceeded {
        path: String,
        required: u64,
        remaining: u64,
    },
    #[error("failed to parse ADF: {0}")]
    Adf(#[from] amiga_adf::Error),
    #[error("failed to parse LHA: {0}")]
    Lha(#[from] amiga_lha::LhaError),
    #[error(transparent)]
    Plan(#[from] amiga_core::ExtractionError),
    #[error("failed to encode extraction manifest: {0}")]
    Manifest(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct AdfFileRecord {
    path: String,
    header_block: u32,
    size: u32,
    sha256: String,
}

#[derive(Serialize)]
struct WarningRecord {
    block: u32,
    message: String,
}

#[derive(Serialize)]
struct UnreadableRecord {
    path: String,
    header_block: u32,
    size: u32,
    reason: String,
}

#[derive(Serialize)]
struct AdfManifest {
    format_version: u32,
    source: Source,
    volume_name: String,
    root_block: u32,
    files: Vec<AdfFileRecord>,
    /// The files this volume holds and this build could not recover. Present
    /// even when empty, so a reader can tell "nothing was damaged" from a
    /// manifest written before the field existed.
    unreadable: Vec<UnreadableRecord>,
    warnings: Vec<WarningRecord>,
}

/// Recover every ADF file and validate the complete output tree in memory.
///
/// **One damaged file does not refuse the volume.** A file whose data chain the
/// reader cannot walk — a data block whose checksum fails, a table entry
/// pointing at a block that is not a data block at all — is refused by name,
/// and the other files are recovered. Boot-block checksum failures remain
/// warnings; corruption of one file's data does not prevent recovery of peers.
///
/// What is *not* relaxed is the rule that made this safe to offer: the whole
/// tree is still recovered and validated before anything is written, and a
/// damaged file is **absent** rather than short or zero-filled. A file in the
/// returned plan is complete or it is not there.
///
/// `limits` bounds aggregate file output and indexed members. Member counts are
/// checked before recovering any file; the remaining byte budget is checked
/// before each read and before retaining its result. Budget exhaustion returns
/// an error for the whole preparation, never a damaged-member warning.
pub fn prepare_adf_extraction(
    source_name: impl Into<String>,
    bytes: &[u8],
    limits: AdfExtractionLimits,
) -> Result<PreparedExtraction, ExtractionPreparationError> {
    let image = amiga_adf::Image::open(bytes)?;
    if image.entries().len() > limits.maximum_members {
        return Err(ExtractionPreparationError::MemberLimitExceeded {
            members: image.entries().len(),
            limit: limits.maximum_members,
        });
    }
    let mut remaining = limits.maximum_output_bytes;

    let mut files = Vec::new();
    let mut planned = Vec::new();
    let mut refused = Vec::new();
    let mut unreadable = Vec::new();
    for entry in image
        .entries()
        .iter()
        .filter(|entry| entry.kind == amiga_adf::EntryKind::File)
    {
        let path = normalized(&entry.path);
        let exceeds_budget = |required| ExtractionPreparationError::OutputLimitExceeded {
            path: path.clone(),
            required,
            remaining,
        };
        let declared = u64::from(entry.size.get());
        if declared > remaining {
            return Err(exceeds_budget(declared));
        }
        match image.read_file(entry) {
            Ok(data) => {
                remaining = remaining
                    .checked_sub(data.len() as u64)
                    .ok_or_else(|| exceeds_budget(data.len() as u64))?;
                files.push(AdfFileRecord {
                    path,
                    header_block: entry.header_block.get(),
                    size: entry.size.get(),
                    sha256: sha256(&data),
                });
                planned.push(PlannedFile {
                    path: entry.path.clone(),
                    bytes: data,
                });
            }
            Err(error) => {
                let reason = error.to_string();
                refused.push(UnreadableRecord {
                    path: path.clone(),
                    header_block: entry.header_block.get(),
                    size: entry.size.get(),
                    reason: reason.clone(),
                });
                unreadable.push(UnreadableMember { path, reason });
            }
        }
    }

    let mut warnings: Vec<String> = image
        .warnings()
        .iter()
        .map(|warning| format!("block {}: {}", warning.block, warning.message))
        .collect();
    warnings.extend(
        unreadable
            .iter()
            .map(|member| format!("{} could not be recovered: {}", member.path, member.reason)),
    );
    let manifest = AdfManifest {
        format_version: 1,
        source: Source::new(source_name, bytes),
        volume_name: image.volume_name().to_owned(),
        root_block: image.root_block().get(),
        files,
        unreadable: refused,
        warnings: image
            .warnings()
            .iter()
            .map(|warning| WarningRecord {
                block: warning.block,
                message: warning.message.clone(),
            })
            .collect(),
    };
    Ok(PreparedExtraction {
        plan: ExtractionPlan::new(planned, Vec::new())?,
        manifest: serde_json::to_vec_pretty(&manifest)?,
        warnings,
        unreadable,
    })
}

#[derive(Serialize)]
struct LhaFileRecord {
    path: String,
    method: String,
    compressed_size: u32,
    original_size: u32,
    sha256: String,
}

#[derive(Serialize)]
struct LhaManifest {
    format_version: u32,
    source: Source,
    files: Vec<LhaFileRecord>,
    directories: Vec<String>,
    skipped: Vec<String>,
}

/// Recover every supported LHA member and validate all archive names in memory.
/// `limit` bounds the sum of recovered file bytes, excluding manifest metadata.
pub fn prepare_lha_extraction(
    source_name: impl Into<String>,
    bytes: &[u8],
    limit: amiga_lha::OutputLimit,
) -> Result<PreparedExtraction, ExtractionPreparationError> {
    let archive = amiga_lha::Archive::parse(bytes)?;
    let mut remaining = limit.bytes();
    let mut recovered = Vec::new();
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for entry in archive.entries() {
        let path = safe_archive_path(entry.name())?;
        if entry.is_directory() {
            directories.push(path);
        } else if entry.is_readable() {
            let data = archive.read(entry, amiga_lha::OutputLimit::new(remaining))?;
            remaining -= data.len() as u64;
            files.push(LhaFileRecord {
                path: normalized(&path),
                method: entry.method_str(),
                compressed_size: entry.compressed_size(),
                original_size: entry.original_size(),
                sha256: sha256(&data),
            });
            recovered.push(PlannedFile { path, bytes: data });
        } else {
            skipped.push(format!("{} ({})", entry.name(), entry.method_str()));
        }
    }
    let directory_names = directories.iter().map(|path| normalized(path)).collect();
    let warnings = skipped
        .iter()
        .map(|entry| format!("unsupported compressed member skipped: {entry}"))
        .collect();
    let manifest = LhaManifest {
        format_version: 1,
        source: Source::new(source_name, bytes),
        files,
        directories: directory_names,
        skipped,
    };
    Ok(PreparedExtraction {
        plan: ExtractionPlan::new(recovered, directories)?,
        manifest: serde_json::to_vec_pretty(&manifest)?,
        warnings,
        // An unsupported compression method is not damage: the member is intact
        // and this build cannot decode it, which `skipped` above says by naming
        // the method. Reporting it as unreadable would conflate "we cannot read
        // this yet" with "these bytes are gone".
        unreadable: Vec::new(),
    })
}

fn normalized(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An uncompressed single-member LHA archive whose member is `name`.
    fn lha_with_member(name: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"-lh0-");
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(0x20);
        body.push(0);
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        body.extend_from_slice(&0_u16.to_le_bytes());
        let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        let mut bytes = vec![body.len() as u8, checksum];
        bytes.extend_from_slice(&body);
        bytes.push(0);
        bytes
    }

    #[test]
    fn unsafe_lha_member_fails_before_a_plan_is_returned() {
        let bytes = lha_with_member(b"../x");
        assert!(amiga_lha::Archive::parse(&bytes).is_ok());
        assert!(
            prepare_lha_extraction(
                "unsafe.lha",
                &bytes,
                amiga_lha::OutputLimit::new(1024 * 1024)
            )
            .is_err()
        );
    }

    #[test]
    fn a_file_and_descendant_collision_refuses_the_complete_lha_plan() {
        let mut bytes = lha_with_member(b"same");
        assert_eq!(bytes.pop(), Some(0));
        bytes.extend_from_slice(&lha_with_member(b"same/child"));
        assert!(amiga_lha::Archive::parse(&bytes).is_ok());
        assert!(
            prepare_lha_extraction(
                "collision.lha",
                &bytes,
                amiga_lha::OutputLimit::new(1024 * 1024)
            )
            .is_err()
        );
    }

    // --- the two hierarchy sources ---------------------------------------------
    //
    // LHA states a path in one header and must validate it component by
    // component. ADF assembles one from separately validated filesystem blocks.
    // Both retain their hierarchy, through deliberately different trust
    // boundaries.

    fn write_u32(block: &mut [u8], offset: usize, value: u32) {
        block[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_name(block: &mut [u8], name: &str) {
        block[432] = name.len() as u8;
        block[433..433 + name.len()].copy_from_slice(name.as_bytes());
    }

    fn seal_checksum(block: &mut [u8]) {
        write_u32(block, 20, 0);
        let sum = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .fold(0_u32, u32::wrapping_add);
        write_u32(block, 20, 0_u32.wrapping_sub(sum));
    }

    /// An OFS image holding `s/startup-sequence`, so the walk produces a nested
    /// path rather than a flat one. Block 4 is the midpoint, where `find_root`
    /// looks first.
    fn adf_with_nested_file(payload: &[u8]) -> Vec<u8> {
        // AmigaDOS block-type constants, spelled out because they are the format
        // rather than this crate's choice.
        const TYPE_HEADER: u32 = 2;
        const TYPE_DATA: u32 = 8;
        const ST_ROOT: u32 = 1;
        const ST_USERDIR: u32 = 2;
        const ST_FILE: i32 = -3;

        const ROOT: u32 = 4;
        const DIRECTORY: u32 = 2;
        const FILE_HEADER: u32 = 3;
        const DATA: u32 = 5;
        let size = amiga_adf::BLOCK_SIZE;
        let mut image = vec![0_u8; 8 * size];

        {
            let root = &mut image[ROOT as usize * size..(ROOT as usize + 1) * size];
            write_u32(root, 0, TYPE_HEADER);
            // Any bucket that references a header is followed, so the exact hash
            // bucket does not matter here.
            write_u32(root, 24, DIRECTORY);
            write_name(root, "DISK");
            write_u32(root, 508, ST_ROOT);
            seal_checksum(root);
        }
        {
            let directory = &mut image[DIRECTORY as usize * size..(DIRECTORY as usize + 1) * size];
            write_u32(directory, 0, TYPE_HEADER);
            write_u32(directory, 4, DIRECTORY); // own key
            write_u32(directory, 24, FILE_HEADER); // first bucket
            write_name(directory, "s");
            write_u32(directory, 508, ST_USERDIR);
            seal_checksum(directory);
        }
        {
            let header = &mut image[FILE_HEADER as usize * size..(FILE_HEADER as usize + 1) * size];
            write_u32(header, 0, TYPE_HEADER);
            write_u32(header, 4, FILE_HEADER); // own key
            write_u32(header, 16, DATA); // first data block
            write_u32(header, 324, payload.len() as u32); // byte size
            write_name(header, "startup-sequence");
            write_u32(header, 508, ST_FILE as u32);
            seal_checksum(header);
        }
        {
            let data = &mut image[DATA as usize * size..(DATA as usize + 1) * size];
            write_u32(data, 0, TYPE_DATA);
            write_u32(data, 4, FILE_HEADER); // owner
            write_u32(data, 8, 1); // sequence
            write_u32(data, 12, payload.len() as u32);
            data[24..24 + payload.len()].copy_from_slice(payload);
            seal_checksum(data);
        }
        image
    }

    /// An OFS image holding three files in the root: one sound, and one for
    /// each shape of damage a real disk shows.
    ///
    /// `bad-checksum`'s data block does not sum to zero — the block is there and
    /// its contents are not what was written. `not-data`'s data block is
    /// perfectly checksummed and its type longword is not `TYPE_DATA`, which is
    /// a file table pointing into a region the filesystem does not own. Both
    /// cases must refuse the affected file while recovering the sound peer.
    fn adf_with_damaged_files() -> Vec<u8> {
        const TYPE_HEADER: u32 = 2;
        const TYPE_DATA: u32 = 8;
        const ST_ROOT: u32 = 1;
        const ST_FILE: i32 = -3;

        const ROOT: u32 = 5;
        // Each file sits in a hash bucket of its own, so the walk reaches all
        // three without a chain between them.
        const FILES: [(u32, u32, &str, usize); 3] = [
            (2, 3, "good", 0),
            (4, 6, "bad-checksum", 1),
            (7, 8, "not-data", 2),
        ];
        let size = amiga_adf::BLOCK_SIZE;
        let mut image = vec![0_u8; 10 * size];

        {
            let root = &mut image[ROOT as usize * size..(ROOT as usize + 1) * size];
            write_u32(root, 0, TYPE_HEADER);
            for (header, _, _, bucket) in FILES {
                write_u32(root, 24 + bucket * 4, header);
            }
            write_name(root, "DAMAGED");
            write_u32(root, 508, ST_ROOT);
            seal_checksum(root);
        }
        let payload = b"0123456789";
        for (header_block, data_block, name, _) in FILES {
            {
                let header =
                    &mut image[header_block as usize * size..(header_block as usize + 1) * size];
                write_u32(header, 0, TYPE_HEADER);
                write_u32(header, 4, header_block);
                write_u32(header, 16, data_block);
                write_u32(header, 324, payload.len() as u32);
                write_name(header, name);
                write_u32(header, 508, ST_FILE as u32);
                seal_checksum(header);
            }
            let data = &mut image[data_block as usize * size..(data_block as usize + 1) * size];
            // `not-data`'s type longword is a plausible-looking value that is
            // not a data block, exactly as a table pointing at foreign bytes
            // produces. It is checksummed, so this is not the other case again.
            write_u32(
                data,
                0,
                if name == "not-data" {
                    0x1114_041c
                } else {
                    TYPE_DATA
                },
            );
            write_u32(data, 4, header_block);
            write_u32(data, 8, 1);
            write_u32(data, 12, payload.len() as u32);
            data[24..24 + payload.len()].copy_from_slice(payload);
            seal_checksum(data);
            if name == "bad-checksum" {
                // After sealing, so the block is damaged rather than never
                // sealed — one byte of payload changed under a stored sum.
                data[24] ^= 0xff;
            }
        }
        image
    }

    /// Sixteen independent FFS headers refer to the same eight raw data blocks.
    /// Each file is valid, but retaining all outputs exceeds the image's size.
    fn adf_with_shared_ffs_data(members: u32, declared: u32) -> Vec<u8> {
        assert!(members <= 16);
        let mut image = vec![0; 40 * 512];
        image[..4].copy_from_slice(b"DOS\x01");
        let root = &mut image[20 * 512..21 * 512];
        write_u32(root, 0, 2);
        write_u32(root, 508, 1);
        write_name(root, "SHARED");
        for n in 0..members {
            write_u32(root, 24 + n as usize * 4, 2 + n);
        }
        seal_checksum(root);
        for n in 0..members {
            let number = 2 + n;
            let header = &mut image[number as usize * 512..(number as usize + 1) * 512];
            write_u32(header, 0, 2);
            write_u32(header, 4, number);
            write_u32(header, 8, 8);
            write_u32(header, 16, if declared == 0 { 0 } else { 21 });
            write_u32(header, 324, declared);
            write_u32(header, 508, (-3_i32) as u32);
            write_name(header, &format!("file{n:02}"));
            for block in 0..8 {
                write_u32(header, 24 + (71 - block) * 4, 21 + block as u32);
            }
            seal_checksum(header);
        }
        for block in 0..8 {
            image[(21 + block) * 512..(22 + block) * 512].fill(block as u8);
        }
        image
    }

    #[test]
    fn shared_ffs_data_is_charged_for_each_recovered_copy() {
        let image = adf_with_shared_ffs_data(16, 4096);
        let total = 16 * 4096;
        assert!(total > image.len() as u64);
        let prepared =
            prepare_adf_extraction("shared.adf", &image, AdfExtractionLimits::new(total, 16))
                .unwrap();
        assert_eq!(prepared.plan.file_count(), 16);
        let expected: Vec<u8> = (0..8).flat_map(|n| [n; 512]).collect();
        for file in prepared.plan.files() {
            assert_eq!(file.bytes, expected);
        }
        for limit in [0, 4095, total - 1] {
            assert!(matches!(
                prepare_adf_extraction("shared.adf", &image, AdfExtractionLimits::new(limit, 16)),
                Err(ExtractionPreparationError::OutputLimitExceeded { .. })
            ));
        }
    }

    #[test]
    fn adf_member_budget_counts_empty_files_directories_and_damaged_files() {
        let image = adf_with_shared_ffs_data(4, 0);
        assert_eq!(
            prepare_adf_extraction("empty-files.adf", &image, AdfExtractionLimits::new(0, 4))
                .unwrap()
                .plan
                .file_count(),
            4
        );
        for limit in [0, 3] {
            assert!(matches!(
                prepare_adf_extraction(
                    "empty-files.adf",
                    &image,
                    AdfExtractionLimits::new(0, limit)
                ),
                Err(ExtractionPreparationError::MemberLimitExceeded { members: 4, .. })
            ));
        }
        let image = adf_with_nested_file(b"data");
        assert!(matches!(
            prepare_adf_extraction("nested.adf", &image, AdfExtractionLimits::new(4, 1)),
            Err(ExtractionPreparationError::MemberLimitExceeded { members: 2, .. })
        ));
        let image = adf_with_damaged_files();
        assert!(matches!(
            prepare_adf_extraction("damaged.adf", &image, AdfExtractionLimits::new(0, 2)),
            Err(ExtractionPreparationError::MemberLimitExceeded { members: 3, .. })
        ));
    }

    #[test]
    fn oversized_declarations_fail_before_reading_a_broken_data_chain() {
        // Attempting to recover this truncated file would allocate its declared
        // size. The preparation must return a budget error before that read.
        let image = adf_with_shared_ffs_data(1, u32::MAX);
        assert!(matches!(prepare_adf_extraction("huge.adf", &image,
            AdfExtractionLimits::new(4096, 1)),
            Err(ExtractionPreparationError::OutputLimitExceeded { required, remaining: 4096, .. })
            if required == u64::from(u32::MAX)));
    }

    #[test]
    fn damaged_file_buffers_do_not_consume_retained_output_budget() {
        let image = adf_with_damaged_files();
        let prepared =
            prepare_adf_extraction("damaged.adf", &image, AdfExtractionLimits::new(20, 3)).unwrap();
        assert_eq!(prepared.unreadable.len(), 2);
        assert_eq!(prepared.plan.files()[0].bytes, b"0123456789");
        assert!(
            prepared
                .warnings
                .iter()
                .any(|warning| warning.contains("could not be recovered"))
        );
        assert!(matches!(
            prepare_adf_extraction("damaged.adf", &image, AdfExtractionLimits::new(9, 3)),
            Err(ExtractionPreparationError::OutputLimitExceeded { .. })
        ));
    }

    #[test]
    fn an_empty_adf_accepts_zero_recovery_budgets() {
        let image = adf_with_shared_ffs_data(0, 0);
        let prepared =
            prepare_adf_extraction("empty.adf", &image, AdfExtractionLimits::new(0, 0)).unwrap();
        assert_eq!(prepared.plan.file_count(), 0);
        assert!(prepared.unreadable.is_empty());
    }

    /// One damaged file is refused by name and the rest of the volume extracts.
    ///
    /// The behaviour this replaces returned `Err` for the whole image, so a
    /// volume with one bad block produced nothing at all — while `adf list`
    /// walked it cleanly, because the damage is in a data chain the directory
    /// walk never touches.
    #[test]
    fn one_damaged_file_is_refused_by_name_and_the_others_still_extract() {
        let image = adf_with_damaged_files();
        let prepared =
            prepare_adf_extraction("damaged.adf", &image, AdfExtractionLimits::new(1024, 10))
                .unwrap_or_else(|error| panic!("a damaged volume still prepares: {error}"));

        let extracted: Vec<String> = prepared
            .plan
            .files()
            .iter()
            .map(|file| normalized(&file.path))
            .collect();
        assert_eq!(extracted, ["good"], "the sound file is recovered");

        let refused: Vec<&str> = prepared
            .unreadable
            .iter()
            .map(|member| member.path.as_str())
            .collect();
        assert_eq!(refused, ["bad-checksum", "not-data"]);
        assert!(
            prepared.unreadable[0].reason.contains("checksum"),
            "{:?}",
            prepared.unreadable[0]
        );
        assert!(
            prepared.unreadable[1].reason.contains("OFS data block"),
            "{:?}",
            prepared.unreadable[1]
        );

        // Both refusals reach a reader who never looks at the plan: on stderr
        // through the warnings, and in the manifest that stays beside the files.
        let recovery: Vec<&String> = prepared
            .warnings
            .iter()
            .filter(|warning| warning.contains("could not be recovered"))
            .collect();
        assert_eq!(recovery.len(), 2, "{:?}", prepared.warnings);
        let manifest: serde_json::Value = serde_json::from_slice(&prepared.manifest)
            .unwrap_or_else(|error| panic!("the manifest is JSON: {error}"));
        assert_eq!(manifest["unreadable"].as_array().map(Vec::len), Some(2));
        assert_eq!(manifest["unreadable"][0]["path"], "bad-checksum");
        assert!(manifest["unreadable"][0]["reason"].is_string());
        assert_eq!(manifest["files"].as_array().map(Vec::len), Some(1));
    }

    /// A sound volume reports nothing unreadable, so the field above is a
    /// finding rather than something every extraction carries.
    #[test]
    fn a_sound_volume_reports_no_unreadable_member() {
        let image = adf_with_nested_file(b"FailAt 21\n");
        let prepared =
            prepare_adf_extraction("sound.adf", &image, AdfExtractionLimits::new(1024, 10))
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(prepared.unreadable.is_empty());
        assert!(
            !prepared
                .warnings
                .iter()
                .any(|warning| warning.contains("could not be recovered")),
            "{:?}",
            prepared.warnings
        );
    }

    #[test]
    fn lha_and_adf_hierarchies_survive_their_respective_validation() {
        // LHA normalizes its native backslash spelling before validating every
        // component and planning the output.
        let archive = lha_with_member(br"graphics\title.iff");
        assert!(amiga_lha::Archive::parse(&archive).is_ok());
        let lha = prepare_lha_extraction(
            "nested.lha",
            &archive,
            amiga_lha::OutputLimit::new(1024 * 1024),
        )
        .unwrap_or_else(|error| panic!("nested LHA should extract: {error}"));
        assert_eq!(
            lha.plan.files()[0].path,
            std::path::PathBuf::from("graphics").join("title.iff")
        );

        // Filesystem-assembled: the hierarchy is kept.
        let payload = b"FailAt 21\n";
        let image = adf_with_nested_file(payload);
        let prepared =
            prepare_adf_extraction("disk.adf", &image, AdfExtractionLimits::new(1024, 10))
                .unwrap_or_else(|error| panic!("nested ADF should extract: {error}"));
        assert!(
            prepared
                .plan
                .files()
                .iter()
                .any(|file| normalized(&file.path) == "s/startup-sequence"),
            "expected s/startup-sequence, got {:?}",
            prepared
                .plan
                .files()
                .iter()
                .map(|file| normalized(&file.path))
                .collect::<Vec<_>>()
        );
    }
}
