use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn amiga_re() -> Command {
    Command::new(env!("CARGO_BIN_EXE_amiga-re"))
}

#[test]
fn boot_trace_dumps_served_tracks() {
    // A boot block whose loader DoIOs one 512-byte CMD_READ from image offset
    // 1024 into a chip-RAM buffer, then returns.
    let code: [u8; 28] = [
        0x33, 0x7c, 0x00, 0x02, 0x00, 0x1c, // MOVE.W #CMD_READ,(io_Command,A1)
        0x23, 0x7c, 0x00, 0x00, 0x02, 0x00, 0x00, 0x24, // MOVE.L #512,(io_Length,A1)
        0x23, 0x7c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x2c, // MOVE.L #1024,(io_Offset,A1)
        0x4e, 0xae, 0xfe, 0x38, // JSR (-456,A6) = DoIO
        0x4e, 0x75, // RTS
    ];
    // io_Data is left 0 in this fixture, so the copy targets address 0 (mapped
    // chip RAM); the manifest still records the served bytes from the image.
    let mut image = vec![0_u8; 2048];
    image[12..12 + code.len()].copy_from_slice(&code);
    image[0..4].copy_from_slice(b"DOS\0");
    image[1024..1028].copy_from_slice(b"SEC1");

    let base = std::env::temp_dir().join(format!("amiga-re-boot-trace-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let adf = base.join("loader.adf");
    fs::write(&adf, &image).unwrap_or_else(|error| panic!("{error}"));
    let output = base.join("tracks");

    let status = amiga_re()
        .args(["boot", "trace"])
        .arg(&adf)
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(status.success());

    let dumped = output.join("read_000_offset_0000400_len_00512.bin");
    let bytes = fs::read(&dumped).unwrap_or_else(|error| panic!("dump missing: {error}"));
    assert_eq!(bytes.len(), 512);
    assert_eq!(&bytes[0..4], b"SEC1");
    let manifest: PathBuf = output.join("manifest.json");
    assert!(manifest.is_file());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn boot_trace_names_vectors_from_the_project_fd_tables() {
    // The same loader as above, followed by a call to a vector the emulated
    // host does not service — so the run stops on it and the stop reason has
    // to name it.
    let code: [u8; 32] = [
        0x33, 0x7c, 0x00, 0x02, 0x00, 0x1c, // MOVE.W #CMD_READ,(io_Command,A1)
        0x23, 0x7c, 0x00, 0x00, 0x02, 0x00, 0x00, 0x24, // MOVE.L #512,(io_Length,A1)
        0x23, 0x7c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x2c, // MOVE.L #1024,(io_Offset,A1)
        0x4e, 0xae, 0xfe, 0x38, // JSR (-456,A6) = DoIO, serviced
        0x4e, 0xae, 0xfc, 0xf4, // JSR (-780,A6) = not serviced, and uncurated
        0x4e, 0x75, // RTS
    ];
    let mut image = vec![0_u8; 2048];
    image[12..12 + code.len()].copy_from_slice(&code);
    image[0..4].copy_from_slice(b"DOS\0");
    image[1024..1028].copy_from_slice(b"SEC1");

    let base = std::env::temp_dir().join(format!("amiga-re-boot-fd-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let adf = base.join("loader.adf");
    fs::write(&adf, &image).unwrap_or_else(|error| panic!("{error}"));
    fs::write(
        base.join("exec_lib.fd"),
        "\
* fd table for the boot-trace fixture
##base _SysBase
##bias 456
MyDoIO(iORequest)(a1)
##bias 780
ShinyNewCall(x)(d0)
##end
",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(
        &config,
        "[[fd]]\nlibrary = \"exec\"\npath = \"exec_lib.fd\"\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["boot", "trace"])
        .arg(&adf)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "boot trace failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("output not UTF-8: {error}"));

    // The stop reason names a vector no curated table knows, because the
    // project's own fd table describes it.
    assert!(
        stdout.contains("exec.library/ShinyNewCall"),
        "the stop reason did not use the fd name:\n{stdout}"
    );
    // And a serviced call takes the fd name over the curated one, so the two
    // halves of the same output cannot disagree about the same library.
    assert!(
        stdout.contains("exec.library/MyDoIO"),
        "the serviced-call log did not use the fd name:\n{stdout}"
    );
    assert!(
        !stdout.contains("exec.library/DoIO"),
        "the curated name outranked the project's own table:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn help_lists_dynamic_analysis_and_glyph_commands() {
    let output = amiga_re()
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("help was not UTF-8: {error}"));
    // Match each command as an entry in the Commands column (a line that, once
    // its indentation is stripped, is the command name followed by whitespace),
    // so an unrelated substring in a description cannot satisfy the assertion.
    for command in ["run", "trace", "call", "bitmap", "bob", "diff", "sample"] {
        let listed = stdout.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed == command
                || trimmed
                    .strip_prefix(command)
                    .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        });
        assert!(listed, "help did not list the {command:?} subcommand");
    }
}

#[test]
fn subcommand_help_lists_new_actions() {
    for (group, action) in [
        ("disasm", "symbols"),
        ("disasm", "callgraph"),
        ("disasm", "report"),
        ("copper", "patch-xref"),
    ] {
        let output = amiga_re()
            .args([group, "--help"])
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re {group}: {error}"));
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("{group} help was not UTF-8: {error}"));
        let listed = stdout.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed == action
                || trimmed
                    .strip_prefix(action)
                    .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        });
        assert!(
            listed,
            "{group} help did not list the {action:?} subcommand"
        );
    }
}

#[test]
fn lha_help_describes_supported_compressed_extraction() {
    for arguments in [&["lha", "--help"][..], &["lha", "extract", "--help"][..]] {
        let output = amiga_re()
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re {arguments:?}: {error}"));
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("lha help was not UTF-8: {error}"));
        let words = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("supported stored and compressed members"),
            "help does not describe supported compressed extraction:\n{help}"
        );
        assert!(
            words.contains("CRC verified"),
            "help does not describe CRC verification:\n{help}"
        );
        assert!(
            !help.contains("compressed members are skipped"),
            "obsolete extraction claim remains:\n{help}"
        );
    }
}

#[test]
fn hardware_register_listing_runs_end_to_end() {
    let output = amiga_re()
        .args(["hw", "registers"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("register listing was not UTF-8: {error}"));
    assert!(stdout.contains("DMACON"));
    assert!(stdout.contains("COLOR00"));
}

/// `survey` is the first command routed through `amiga-operations`. Its text
/// output stays a presentation concern, but the regions behind it must be the
/// ones the shared operation produces, and the command's default threshold must
/// be the survey's own named constant rather than a literal that can drift.
#[test]
fn survey_renders_the_shared_operations_regions() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/sample.bin");

    let output = amiga_re()
        .arg("survey")
        .arg(&fixture)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));

    let bytes = fs::read(&fixture).unwrap_or_else(|error| panic!("{error}"));
    let expected = amiga_analysis::survey(&bytes, amiga_analysis::DEFAULT_SURVEY_MIN_STRING_LENGTH);
    assert!(!expected.is_empty());

    let mut lines = text.lines();
    let header = lines.next().expect("a header line");
    assert!(
        header.ends_with(&format!("({} bytes):", bytes.len())),
        "header reports the surveyed size: {header}"
    );
    for (line, region) in lines.zip(&expected) {
        assert!(
            line.contains(region.kind.as_str()) && line.contains(&region.detail),
            "{line} describes {region:?}"
        );
    }
    assert_eq!(text.lines().count(), expected.len() + 1);
}

/// A source the request cannot name is refused before anything is read.
#[test]
fn survey_refuses_a_path_that_names_no_file() {
    let output = amiga_re()
        .arg("survey")
        .arg("/")
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(stderr.contains("does not name a readable file"), "{stderr}");
}

/// The request-settable bounds reach the shared operation, and a capped list is
/// never printed as if it were complete.
#[test]
fn survey_reports_the_total_it_capped_its_region_list_from() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/sample.bin");

    let output = amiga_re()
        .arg("survey")
        .arg(&fixture)
        .args(["--max-regions", "1"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());

    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    let bytes = fs::read(&fixture).unwrap_or_else(|error| panic!("{error}"));
    let total =
        amiga_analysis::survey(&bytes, amiga_analysis::DEFAULT_SURVEY_MIN_STRING_LENGTH).len();
    assert!(total > 1);
    assert!(
        text.contains(&format!("... 1 of {total} regions shown")),
        "{text}"
    );

    let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        stderr.contains(&format!("first 1 of {total} regions")),
        "{stderr}"
    );
}

/// `adf list` routes through `container.adf.list`: the volume, the entries, the
/// tolerated inconsistencies, and the cap all come from the shared operation.
#[test]
fn adf_list_renders_the_shared_operations_volume_listing() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/volume.adf");

    let output = amiga_re()
        .args(["adf", "list"])
        .arg(&fixture)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());

    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    // The filesystem is named, because it is what decides how a file's contents
    // would be recovered — a listing that omitted it would leave that to an
    // extraction that either works or does not.
    assert!(
        text.starts_with("Volume: \"AmigaRe\" (OFS, root block 10)\n"),
        "{text}"
    );
    for expected in [
        "directory        0  block    2  S",
        "file            28  block    3  S/startup-sequence",
        "file            49  block    5  readme.txt",
    ] {
        assert!(text.contains(expected), "{expected:?} missing from {text}");
    }

    // Recovered inconsistencies are warnings, not silence and not failure.
    let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        stderr.contains("boot block checksum is invalid"),
        "{stderr}"
    );
    assert!(stderr.contains("retains data pointer"), "{stderr}");
}

/// One damaged file costs that file and not the volume.
///
/// The synthetic volume below includes one damaged file and readable peers.

#[test]
fn adf_extract_recovers_the_files_a_damaged_one_used_to_take_with_it() {
    const TYPE_DATA: u32 = 8;
    /// `readme.txt`'s header block in the shared fixture, from `adf list`.
    const README_HEADER: u32 = 5;

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/volume.adf");
    let mut image = fs::read(&fixture).unwrap_or_else(|error| panic!("{error}"));

    // Damage exactly one payload byte of `readme.txt`, under a checksum that
    // was sealed over the original: the block is present and its contents are
    // no longer what was written, which is the shape a bad sector leaves.
    let mut damaged = 0;
    for block in image.as_chunks_mut::<512>().0 {
        let kind = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let owner = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        if kind == TYPE_DATA && owner == README_HEADER {
            block[24] ^= 0xff;
            damaged += 1;
        }
    }
    assert_eq!(
        damaged, 1,
        "the fixture holds one data block for readme.txt"
    );

    let base = std::env::temp_dir().join(format!("amiga-re-adf-damaged-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("damaged.adf");
    fs::write(&source, &image).unwrap_or_else(|error| panic!("{error}"));
    let out = base.join("recovered");

    let output = amiga_re()
        .args(["adf", "extract"])
        .arg(&source)
        .arg(&out)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));

    assert!(
        !output.status.success(),
        "a volume that lost a file must not report success"
    );
    let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        stderr.contains("readme.txt") && stderr.contains("damaged"),
        "the refusal names the file: {stderr}"
    );

    // The point of the change: the undamaged file is on disk, with its bytes.
    let recovered = fs::read(out.join("S/startup-sequence")).unwrap_or_else(|error| {
        panic!("the undamaged file should have been written: {error}");
    });
    assert_eq!(recovered.len(), 28);
    assert!(
        !out.join("readme.txt").exists(),
        "a damaged file is absent rather than written short"
    );

    // And the loss is recorded beside the files, not only on a stream that
    // scrolls away.
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(out.join("manifest.json")).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(manifest["unreadable"].as_array().map(Vec::len), Some(1));
    assert_eq!(manifest["unreadable"][0]["path"], "readme.txt");

    let _ = fs::remove_dir_all(&base);
}

/// A capped listing says so on both streams, and never prints as if complete.
#[test]
fn adf_list_reports_the_total_it_capped_its_entry_list_from() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/volume.adf");

    let output = amiga_re()
        .args(["adf", "list", "--max-entries", "2"])
        .arg(&fixture)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());

    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("... 2 of 4 entries shown"), "{text}");
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("file") || line.starts_with("directory"))
            .count(),
        2
    );
}

/// A source that is not a volume fails; nothing is printed as if it were one.
#[test]
fn adf_list_refuses_a_source_that_is_not_a_volume() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/sample.bin");

    let output = amiga_re()
        .args(["adf", "list"])
        .arg(&fixture)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(stderr.contains("failed to list"), "{stderr}");
}

/// A project whose only object is decompressed from its parent, and the bytes
/// on disk to back it.
///
/// Written out here rather than checked in because the packed stream is the
/// point: `project verify` has to *run* the recorded recipe and compare what it
/// produced, so the stream and the pin have to agree by construction.
fn packed_project(tag: &str, selector: serde_json::Value, plain: &[u8]) -> PathBuf {
    // Position-XOR + escape-marker run-length: a 4-byte big-endian size field,
    // then "AB", then (marker 0x90, 2, 'C') expanding to "CCC", then "D".
    let mut stream = 6_u32.to_be_bytes().to_vec();
    stream.extend_from_slice(&[b'A', b'B', 0x90, 2, b'C', b'D']);
    let packed: Vec<u8> = stream
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ (index as u8))
        .collect();

    let root = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("original")).unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(root.join("analysis")).unwrap_or_else(|error| panic!("{error}"));
    fs::write(root.join("original/packed.bin"), &packed).unwrap_or_else(|error| panic!("{error}"));

    let digest = |bytes: &[u8]| {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    fs::write(
        root.join("amiga-re.project.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "project",
            "format_version": 1,
            "project": { "id": "project:packed", "name": "Packed demo" },
            "documents": { "sources": "analysis/sources.json" }
        }))
        .unwrap(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    fs::write(
        root.join("analysis/sources.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "document_kind": "sources",
            "format_version": 1,
            "sources": [{
                "id": "source:packed",
                "kind": "file",
                "media_type": "binary",
                "display_name": "A packed blob",
                "size": packed.len(),
                "sha256": digest(&packed),
                "locations": [{ "kind": "project_relative", "path": "original/packed.bin" }]
            }],
            "objects": [{
                "id": "object:packed/unpacked",
                "kind": "decompressed",
                "parent_id": "source:packed",
                "selector": selector,
                "size": plain.len(),
                "sha256": digest(plain)
            }]
        }))
        .unwrap(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    root
}

/// The recipe that reproduces the fixture's packed blob.
fn rle_xor_recipe(marker: u32, declared_size: u32) -> serde_json::Value {
    serde_json::json!({
        "container": "decompressed",
        "codec": {
            "name": "rle_xor",
            "marker": marker,
            "xor": true,
            "inline_marker": false,
            "size_bytes": 4,
            "size_includes_field": false
        },
        "declared_size": declared_size
    })
}

#[test]
fn project_verify_re_derives_a_decompressed_object_from_its_parent() {
    // The capability end to end: nothing but the pinned packed source is on
    // disk, and the decompressed object still verifies — so a project whose
    // intermediate files were deleted is recoverable rather than unreproducible.
    let root = packed_project("verify-packed", rle_xor_recipe(0x90, 6), b"ABCCCD");

    let output = amiga_re()
        .args(["project", "verify"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("1/1 source(s) and 1/1 object(s) verified"),
        "{text}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn project_verify_contradicts_a_recipe_that_produces_other_bytes() {
    // The digest is what makes the recipe an authority. A wrong marker decodes
    // the same stream into something else, and that must be a contradiction
    // rather than a pass.
    let root = packed_project("verify-wrong-marker", rle_xor_recipe(0x91, 6), b"ABCCCD");

    let output = amiga_re()
        .args(["project", "verify"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("MISMATCH"), "{text}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn project_verify_refuses_a_declared_size_the_stream_disagrees_with() {
    // A declared size is a cross-check, not a hint: if the record and the stream
    // disagree, this is not the recipe that produced these bytes, and saying so
    // beats a digest mismatch whose cause nobody can see.
    let root = packed_project("verify-bad-declared", rle_xor_recipe(0x90, 7), b"ABCCCD");

    let output = amiga_re()
        .args(["project", "verify"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        text.contains("the record declares 7 output byte(s) but the stream declares 6"),
        "{text}"
    );
    let _ = fs::remove_dir_all(&root);
}

/// The bytes `source.carve` writes for the same request, through the router.
///
/// Compare the bytes written by the CLI against a direct router invocation. Merely
/// asserting that the command writes something would miss divergent extraction
/// behavior.
fn carve_through_the_router(source: &Path, offset: usize, length: usize, out: &Path) -> String {
    let (source_base, name) = amiga_operations::split_host_path(source).expect("a readable file");
    let directory = out.parent().expect("a parent directory");
    let base = directory.parent().expect("a directory to name");
    let destination = amiga_operations::DestinationName::parse(
        directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a name"),
    )
    .expect("a usable destination");
    let arguments =
        amiga_operations::CarveArguments::new(name.as_str(), offset, length, destination.as_str())
            .with_file_name(
                out.file_name()
                    .and_then(|name| name.to_str())
                    .expect("a file name"),
            );

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(base.to_path_buf());
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = amiga_operations::OperationRequestDocument::SourceCarve(arguments);

    let mut prepare = amiga_operations::RequestEnvelope::read(document.clone());
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    let plan = prepared
        .source_carve()
        .expect("the carve prepared")
        .plan
        .clone();

    let mut commit = amiga_operations::RequestEnvelope::read(document);
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: plan.plan_sha256.clone(),
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    assert_eq!(committed.status, amiga_operations::Status::Success);
    plan.plan_sha256
}

/// CRC-16/ARC, the check LHA level-0 headers carry.
fn lha_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// A one-member `-lh0-` (stored) archive with a level-0 header.
fn lha_archive(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"-lh0-");
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed size
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // original size
    body.extend_from_slice(&0_u32.to_le_bytes()); // timestamp
    body.push(0x20); // attribute
    body.push(0); // header level 0
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&lha_crc16(payload).to_le_bytes());

    let checksum = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    let mut bytes = vec![body.len() as u8, checksum];
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(payload);
    bytes.push(0); // terminator
    bytes
}

/// `container.lha.extract` driven straight through the router, returning the
/// plan digest it computes for the same request the command line should send.
fn lha_extract_plan_through_the_router(source: &Path, out: &Path) -> String {
    let (source_base, name) = amiga_operations::split_host_path(source).expect("a readable file");
    let base = out.parent().expect("a directory to name");
    let destination = amiga_operations::DestinationName::parse(
        out.file_name()
            .and_then(|name| name.to_str())
            .expect("a name"),
    )
    .expect("a usable destination");

    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations = amiga_operations::FilesystemDestinationResolver::new(base.to_path_buf());
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);

    let mut prepare = amiga_operations::RequestEnvelope::read(
        amiga_operations::OperationRequestDocument::ContainerLhaExtract(
            amiga_operations::ContainerExtractArguments::new(name.as_str(), destination.as_str()),
        ),
    );
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    prepared
        .container_extract()
        .expect("the extraction prepared")
        .plan
        .plan_sha256
        .clone()
}

#[test]
fn lha_extract_matches_the_shared_operation() {
    // Compare the extracted digest with the result of `container.lha.extract`; printing
    // a plan alone cannot prove the CLI writes the expected bytes.
    let base = std::env::temp_dir().join(format!("amiga-re-lha-extract-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let archive = base.join("bundle.lha");
    fs::write(
        &archive,
        lha_archive("Docs/readme.txt", b"stored payload bytes"),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let out = base.join("recovered");
    let expected = lha_extract_plan_through_the_router(&archive, &out);

    let output = amiga_re()
        .args(["lha", "extract"])
        .arg(&archive)
        .arg(&out)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "lha extract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("output is UTF-8");
    assert!(
        stdout.contains(&format!("Plan SHA-256: {expected}")),
        "the command line planned a different write than the router:\n{stdout}"
    );

    assert_eq!(
        fs::read(out.join("Docs").join("readme.txt")).unwrap_or_else(|error| panic!("{error}")),
        b"stored payload bytes"
    );
    assert!(out.join("manifest.json").is_file());

    // And the policy is the operation's: a second unforced extraction over the
    // same tree is refused rather than replacing it.
    let refused = amiga_re()
        .args(["lha", "extract"])
        .arg(&archive)
        .arg(&out)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        !refused.status.success(),
        "an unforced re-extraction succeeded"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn lha_extract_rejects_a_late_unsafe_member_before_writing() {
    let base = std::env::temp_dir().join(format!(
        "amiga-re-lha-unsafe-extract-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));

    let mut bytes = lha_archive("safe/first.bin", b"recovered first");
    assert_eq!(bytes.pop(), Some(0));
    bytes.extend_from_slice(&lha_archive("safe/../escape.bin", b"must be refused"));
    let archive = base.join("unsafe.lha");
    fs::write(&archive, bytes).unwrap_or_else(|error| panic!("{error}"));

    let output = base.join("recovered");
    let result = amiga_re()
        .args(["lha", "extract"])
        .arg(&archive)
        .arg(&output)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        !result.status.success(),
        "an unsafe archive extracted successfully"
    );
    assert!(
        !output.exists(),
        "the safe member was written before the late refusal"
    );

    let _ = fs::remove_dir_all(&base);
}

/// A minimal 8SVX carrying only the two chunks the format requires.
fn svx_form(pcm: &[u8], sample_rate: u16) -> Vec<u8> {
    let mut vhdr = Vec::new();
    vhdr.extend_from_slice(&(pcm.len() as u32).to_be_bytes()); // one-shot frames
    vhdr.extend_from_slice(&0_u32.to_be_bytes()); // repeat
    vhdr.extend_from_slice(&0_u32.to_be_bytes()); // samples per cycle
    vhdr.extend_from_slice(&sample_rate.to_be_bytes());
    vhdr.push(1); // octaves
    vhdr.push(0); // compression
    vhdr.extend_from_slice(&0x0001_0000_u32.to_be_bytes()); // volume

    let mut body = Vec::new();
    for (id, data) in [(b"VHDR", vhdr), (b"BODY", pcm.to_vec())] {
        body.extend_from_slice(id);
        body.extend_from_slice(&(data.len() as u32).to_be_bytes());
        body.extend_from_slice(&data);
        if !data.len().is_multiple_of(2) {
            body.push(0);
        }
    }

    let mut form = Vec::new();
    form.extend_from_slice(b"FORM");
    form.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    form.extend_from_slice(b"8SVX");
    form.extend_from_slice(&body);
    form
}

#[test]
fn iff_to_wav_names_the_file_it_writes() {
    // The single-file rule `carve`, `bitmap render`, and `bob extract` follow:
    // the path names the output, not a directory to derive one inside. The
    // sample also carries no `NAME`, which the parser no longer requires.
    let base = std::env::temp_dir().join(format!("amiga-re-to-wav-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("out")).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("beep.8svx");
    fs::write(&source, svx_form(&[0x80, 0xff, 0x00, 0x7f], 8_000))
        .unwrap_or_else(|error| panic!("{error}"));

    // The destination directory already holds something else, so a command that
    // claimed the whole directory would have to refuse or overwrite it.
    let neighbour = base.join("out/notes.txt");
    fs::write(&neighbour, b"someone else's work").unwrap_or_else(|error| panic!("{error}"));

    let target = base.join("out/beep.wav");
    let output = amiga_re()
        .args(["iff", "to-wav"])
        .arg(&source)
        .arg(&target)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "iff to-wav failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let wav = fs::read(&target).unwrap_or_else(|error| panic!("the WAV is missing: {error}"));
    assert_eq!(&wav[..4], b"RIFF");
    // Exactly that file plus its manifest, under a name derivable from it — and
    // no `manifest.json` claiming the directory the neighbour lives in.
    assert!(base.join("out/beep.wav.manifest.json").is_file());
    assert!(!base.join("out/manifest.json").exists());
    assert_eq!(
        fs::read(&neighbour).unwrap_or_else(|error| panic!("{error}")),
        b"someone else's work"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn diff_output_names_the_report_it_writes() {
    // `diff --output` used to name a directory and derive `hunk-diff.json`
    // inside it. It now names the report, so the command line has one rule.
    let base = std::env::temp_dir().join(format!("amiga-re-diff-output-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("out")).unwrap_or_else(|error| panic!("{error}"));

    let a = base.join("a.exe");
    let b = base.join("b.exe");
    fs::write(&a, hunk_image(&[0x4e, 0x71, 0x4e, 0x75])).unwrap_or_else(|error| panic!("{error}"));
    fs::write(&b, hunk_image(&[0x4e, 0x71, 0x60, 0xfe])).unwrap_or_else(|error| panic!("{error}"));

    let report = base.join("out/compared.json");
    let output = amiga_re()
        .args(["diff"])
        .arg(&a)
        .arg(&b)
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "diff --output failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = fs::read_to_string(&report).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        written.trim_start().starts_with('{'),
        "the report is not the JSON rendering:\n{written}"
    );
    assert!(base.join("out/compared.json.manifest.json").is_file());
    // The old spelling's derived name is nowhere: nothing silently kept it.
    assert!(!base.join("out/hunk-diff.json").exists());
    assert!(!base.join("out/compared.json/hunk-diff.json").exists());

    let _ = fs::remove_dir_all(&base);
}

/// A one-hunk LoadSeg image wrapping `code`.
fn hunk_image(code: &[u8]) -> Vec<u8> {
    let longwords = code.len().div_ceil(4);
    let mut image = Vec::new();
    image.extend_from_slice(&0x0000_03f3_u32.to_be_bytes()); // HUNK_HEADER
    image.extend_from_slice(&0_u32.to_be_bytes()); // no resident library names
    image.extend_from_slice(&1_u32.to_be_bytes()); // table size
    image.extend_from_slice(&0_u32.to_be_bytes()); // first hunk
    image.extend_from_slice(&0_u32.to_be_bytes()); // last hunk
    image.extend_from_slice(&(longwords as u32).to_be_bytes());
    image.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    image.extend_from_slice(&(longwords as u32).to_be_bytes());
    image.extend_from_slice(code);
    image.resize(image.len() + longwords * 4 - code.len(), 0);
    image.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    image
}

#[test]
fn trace_watch_only_filters_rows_without_changing_execution() {
    let root = std::env::temp_dir().join(format!(
        "amiga-re-trace-watch-only-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let source = root.join("routine");
    // MOVEQ #1,D0 ; MOVE.L D0,-(A7) ; MOVEQ #7,D0 ; ADDQ.L #4,A7 ; NOP ; RTS
    // The pushed value is watched; later instructions must still execute.
    fs::write(
        &source,
        hunk_image(&[
            0x70, 0x01, 0x2f, 0x00, 0x70, 0x07, 0x58, 0x8f, 0x4e, 0x71, 0x4e, 0x75,
        ]),
    )
    .unwrap();
    let trace = |watch: &str, flags: &[&str]| {
        let output = amiga_re()
            .arg("trace")
            .arg(&source)
            .args(["--stack-base", "0x100000", "--stack-size", "0x1000"])
            .args(["--watch", watch])
            .args(flags)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let ordinary = trace("w:0x100ff8:4", &[]);
    let filtered = trace("w:0x100ff8:4", &["--watch-only"]);
    let ordinary_rows: Vec<_> = ordinary
        .lines()
        .filter(|line| !line.starts_with(';'))
        .collect();
    let filtered_rows: Vec<_> = filtered
        .lines()
        .filter(|line| !line.starts_with(';'))
        .collect();
    assert_eq!(ordinary_rows.len(), 6, "{ordinary}");
    let watched_rows: Vec<_> = ordinary_rows
        .into_iter()
        .filter(|line| line.contains("WATCH "))
        .collect();
    assert_eq!(watched_rows.len(), 1, "{ordinary}");
    assert!(watched_rows[0].starts_with("00001002  "));
    assert!(watched_rows[0].contains("[0x100ff8].l:0x0->0x1"));
    assert_eq!(filtered_rows, watched_rows, "{filtered}");
    let summary: Vec<_> = ordinary
        .lines()
        .filter(|line| line.starts_with(';'))
        .collect();
    assert_eq!(
        filtered
            .lines()
            .filter(|line| line.starts_with(';'))
            .collect::<Vec<_>>(),
        summary,
        "filtering must preserve the stop reason, step count, registers and writes"
    );
    assert!(filtered.contains("6 instruction(s) executed"));
    assert!(filtered.contains("D0=0x00000007"));
    assert!(filtered.contains("routine returned"));

    let no_hits = trace("w:0x100000:4", &["--watch-only"]);
    assert!(no_hits.lines().all(|line| line.starts_with(';')));
    assert_eq!(no_hits.lines().collect::<Vec<_>>(), summary);

    let stopped = trace("w:0x100ff8:4", &["--watch-stop"]);
    assert!(stopped.contains("2 instruction(s) executed"), "{stopped}");
    assert!(stopped.contains("D0=0x00000001"), "{stopped}");
    assert!(!stopped.contains("routine returned"), "{stopped}");

    fs::remove_file(&source).unwrap();
    fs::remove_dir(&root).unwrap();
}

#[test]
fn call_returns_the_trace_and_honours_the_watch_it_was_given() {
    // `call` accepted `--watch`, `--watch-stop`, and a trace request and passed
    // none of them into the run, so a routine that faulted after a long
    // initialization could not be traced back to the instruction that caused
    // it. Both halves are asserted from the command line, because the record
    // printed here is what a person reads.
    let base = std::env::temp_dir().join(format!("amiga-re-call-trace-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("routine");
    // MOVE.L #42,($40000).L ; MOVE.L #43,($40004).L ; RTS
    let code: [u8; 22] = [
        0x23, 0xfc, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, //
        0x23, 0xfc, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x04, //
        0x4e, 0x75,
    ];
    fs::write(&source, hunk_image(&code)).unwrap_or_else(|error| panic!("{error}"));

    let traced = amiga_re()
        .arg("call")
        .arg(&source)
        .args(["--map", "0x40000:16", "--trace"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(traced.status.success());
    let record: serde_json::Value = serde_json::from_slice(&traced.stdout)
        .unwrap_or_else(|error| panic!("the record was not JSON: {error}"));
    assert_eq!(record["trace_total"], 3, "record: {record}");
    let rows = record["trace"].as_array().expect("a trace array");
    assert_eq!(rows.len(), 3);
    assert!(
        rows[0]["writes"]
            .as_array()
            .is_some_and(|writes| writes.iter().any(|write| write["address"] == 0x4_0000)),
        "the first store is not in its trace row: {record}"
    );

    let watched = amiga_re()
        .arg("call")
        .arg(&source)
        .args([
            "--map",
            "0x40000:16",
            "--watch",
            "w:0x40004:4",
            "--watch-stop",
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(watched.status.success());
    let record: serde_json::Value = serde_json::from_slice(&watched.stdout)
        .unwrap_or_else(|error| panic!("the record was not JSON: {error}"));
    assert_eq!(record["stop"]["reason"], "watch", "record: {record}");
    assert_eq!(record["stop"]["address"], 0x4_0004);
    assert_eq!(record["returned"], false);
    // Recorded, so the stop has something to point at; not reported, because a
    // watch was asked for and a trace was not.
    assert_eq!(record["trace_total"], 2);
    assert_eq!(record["trace"].as_array().map(Vec::len), Some(0));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_typed_step_budget_may_exceed_the_default_ceiling_and_is_still_bounded() {
    // An initialization routine that decodes graphics and builds tables can
    // legitimately run past 200,000 instructions, and splitting the run loses
    // the excluded call stack. Someone typing `--max-steps` against media on
    // their own disk is the reviewed local recipe the ceiling makes room for —
    // so the command line raises it, and the operation still refuses to remove
    // it.
    let base = std::env::temp_dir().join(format!("amiga-re-budget-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("loop");
    fs::write(&source, hunk_image(&[0x60, 0xfe])).unwrap_or_else(|error| panic!("{error}"));

    let long = amiga_re()
        .arg("run")
        .arg(&source)
        .args(["--max-steps", "400000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(long.status.success());
    let stdout = String::from_utf8(long.stdout)
        .unwrap_or_else(|error| panic!("output was not UTF-8: {error}"));
    assert!(
        stdout.contains("400000 instruction(s) executed"),
        "the budget was reduced to the default ceiling:\n{stdout}"
    );

    // Bounded, not removed: past the crate's absolute maximum the budget is cut
    // back and the reduction is reported rather than applied in silence. Asked
    // of a routine that returns at once, so the assertion is about the ceiling
    // rather than about waiting for five million instructions to run.
    let returns = base.join("returns");
    fs::write(&returns, hunk_image(&[0x4e, 0x75])).unwrap_or_else(|error| panic!("{error}"));
    let absurd = amiga_re()
        .arg("run")
        .arg(&returns)
        .args(["--max-steps", "999999999"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(absurd.status.success());
    let stderr = String::from_utf8(absurd.stderr)
        .unwrap_or_else(|error| panic!("stderr was not UTF-8: {error}"));
    assert!(
        stderr.contains("maximum_steps reduced from 999999999 to the 5000000"),
        "the reduction was silent or unbounded:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn call_saves_a_named_memory_range_beside_the_golden_record() {
    // Reconstructing a runtime framebuffer used to need an external program to
    // reapply thousands of recorded changes to the original image and then
    // carve the range back out. `--save` makes the range an output of the
    // recipe, written beside the record that says how it was produced.
    let base = std::env::temp_dir().join(format!("amiga-re-call-save-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("routine");
    // MOVE.L #42,($40000).L ; MOVE.L #43,($40004).L ; RTS
    let code: [u8; 22] = [
        0x23, 0xfc, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, //
        0x23, 0xfc, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x04, //
        0x4e, 0x75,
    ];
    fs::write(&source, hunk_image(&code)).unwrap_or_else(|error| panic!("{error}"));

    let record_path = base.join("out/golden.json");
    let status = amiga_re()
        .arg("call")
        .arg(&source)
        .args(["--map", "0x40000:16", "--save", "table.bin=0x40000:8"])
        .arg("--output")
        .arg(&record_path)
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(status.success());

    let saved = fs::read(base.join("out/table.bin")).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(saved, vec![0, 0, 0, 42, 0, 0, 0, 43]);

    // The record names the artifact and digests it, so a record and a file that
    // drifted apart can be told apart.
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(&record_path).unwrap_or_else(|error| panic!("{error}")))
            .unwrap_or_else(|error| panic!("the record was not JSON: {error}"));
    let regions = record["exported_regions"]
        .as_array()
        .expect("exported regions");
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0]["name"], "table.bin");
    assert_eq!(regions[0]["length"], 8);

    // Provenance travels under a name derived from the record's, not as a bare
    // `manifest.json`: the export writes files into a directory it does not own.
    assert!(base.join("out/golden.json.manifest.json").is_file());
    assert!(!base.join("out/manifest.json").exists());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn carve_writes_the_same_bytes_through_the_command_line_and_the_router() {
    let base = std::env::temp_dir().join(format!("amiga-re-carve-parity-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("cli")).unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(base.join("router")).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("source.bin");
    let bytes: Vec<u8> = (0..=255_u8).collect();
    fs::write(&source, &bytes).unwrap_or_else(|error| panic!("{error}"));

    let cli_out = base.join("cli/piece.bin");
    let status = amiga_re()
        .args(["carve"])
        .arg(&source)
        .arg(&cli_out)
        .args(["--offset", "0x10", "--length", "0x20"])
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(status.success());

    let router_out = base.join("router/piece.bin");
    carve_through_the_router(&source, 0x10, 0x20, &router_out);

    let from_cli = fs::read(&cli_out).unwrap_or_else(|error| panic!("{error}"));
    let from_router = fs::read(&router_out).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(from_cli, bytes[0x10..0x30]);
    assert_eq!(
        from_cli, from_router,
        "the CLI and router carved different bytes"
    );

    // The provenance manifest is the operation's, not a struct the command line
    // kept beside it, and it travels with the file under a name derivable from it.
    assert!(base.join("cli/piece.bin.manifest.json").is_file());
    // The directory was not claimed: a single-file carve owns its file, and one
    // `manifest.json` at the top would be a claim over whatever else lands here.
    assert!(!base.join("cli/manifest.json").exists());

    // A second carve over the same file is refused: the policy belongs to the
    // operation, and `--force` is what authorizes replacing provenance it wrote.
    let refused = amiga_re()
        .args(["carve"])
        .arg(&source)
        .arg(&cli_out)
        .args(["--offset", "0x10", "--length", "0x20"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!refused.status.success(), "an unforced overwrite succeeded");

    let forced = amiga_re()
        .args(["carve"])
        .arg(&source)
        .arg(&cli_out)
        .args(["--offset", "0x10", "--length", "0x20", "--force"])
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        forced.success(),
        "--force did not authorize the replacement"
    );

    // And `--force` authorizes replacing what this toolkit wrote, not whatever is
    // in the way: a file with no manifest beside it is refused and left alone.
    let foreign = base.join("cli/theirs.bin");
    fs::write(&foreign, b"someone else's work").unwrap_or_else(|error| panic!("{error}"));
    let refused_foreign = amiga_re()
        .args(["carve"])
        .arg(&source)
        .arg(&foreign)
        .args(["--offset", "0", "--length", "8", "--force"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        !refused_foreign.status.success(),
        "--force overwrote a file this toolkit did not write"
    );
    assert_eq!(
        fs::read(&foreign).unwrap_or_else(|error| panic!("{error}")),
        b"someone else's work"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn bitmap_render_writes_the_same_png_through_the_command_line_and_the_router() {
    let base = std::env::temp_dir().join(format!("amiga-re-render-parity-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("cli")).unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(base.join("router")).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("planes.bin");
    // Two planes of an 8x4 bitmap, distinct per plane so a wrong plane order or
    // stride would change the PNG.
    let bytes: Vec<u8> = (0..8_u8).map(|index| index.wrapping_mul(37)).collect();
    fs::write(&source, &bytes).unwrap_or_else(|error| panic!("{error}"));

    let cli_out = base.join("cli/preview.png");
    let status = amiga_re()
        .args(["bitmap", "render"])
        .arg(&source)
        .arg(&cli_out)
        .args(["--width", "8", "--height", "4", "--planes", "1"])
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(status.success());

    let (source_base, name) =
        amiga_operations::split_host_path(&source).expect("a readable source file");
    let router_out = base.join("router/preview.png");
    let directory = router_out.parent().expect("a parent");
    let destination = amiga_operations::DestinationName::parse(
        directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a name"),
    )
    .expect("a usable destination");
    let arguments = amiga_operations::BitmapExportArguments::new(
        amiga_operations::BitmapDecodeArguments::new(name.as_str(), 8, 4, 1),
        destination.as_str(),
    )
    .with_file_name("preview.png");
    let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
    let destinations =
        amiga_operations::FilesystemDestinationResolver::new(directory.parent().expect("a base"));
    let context =
        amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
    let document = amiga_operations::OperationRequestDocument::GraphicsBitmapExport(arguments);
    let mut prepare = amiga_operations::RequestEnvelope::read(document.clone());
    prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
    let prepared = amiga_operations::Router::execute(&prepare, &context);
    let digest = prepared
        .graphics_bitmap_export()
        .expect("the export prepared")
        .plan
        .plan_sha256
        .clone();
    let mut commit = amiga_operations::RequestEnvelope::read(document);
    commit.execution.mode = amiga_operations::ExecutionMode::CommitReviewed {
        approved_plan_sha256: digest,
    };
    let committed = amiga_operations::Router::execute(&commit, &context);
    assert_eq!(
        committed.status,
        amiga_operations::Status::Success,
        "{:?}",
        committed.diagnostics
    );

    let from_cli = fs::read(&cli_out).unwrap_or_else(|error| panic!("{error}"));
    let from_router = fs::read(&router_out).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        from_cli, from_router,
        "the CLI and router rendered different PNG bytes"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn each_plane_order_renders_its_own_png_and_an_unknown_one_is_refused() {
    // Word-interleaved data is not a display layout, so the same bytes read at
    // each chunk width must produce different pixels. If two of these files were
    // identical the flag would be doing nothing, which is exactly the silent
    // failure the option exists to prevent.
    let base = std::env::temp_dir().join(format!("amiga-re-plane-order-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("out")).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("planes.bin");
    // 32x1, two planes: one set bit per byte, so every layout puts it elsewhere.
    fs::write(&source, [0x80_u8, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01])
        .unwrap_or_else(|error| panic!("{error}"));

    let mut rendered = Vec::new();
    for order in ["contiguous", "byte-interleaved", "word-interleaved"] {
        let out = base.join(format!("out/{order}.png"));
        let status = amiga_re()
            .args(["bitmap", "render"])
            .arg(&source)
            .arg(&out)
            .args(["--width", "32", "--height", "1", "--planes", "2"])
            .args(["--plane-order", order])
            .status()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        assert!(status.success(), "{order} did not render");
        rendered.push(fs::read(&out).unwrap_or_else(|error| panic!("{error}")));
    }
    assert_ne!(rendered[0], rendered[1], "contiguous matched byte chunks");
    assert_ne!(rendered[1], rendered[2], "byte chunks matched word chunks");

    let refused = amiga_re()
        .args(["bitmap", "render"])
        .arg(&source)
        .arg(base.join("out/never.png"))
        .args(["--width", "32", "--height", "1", "--planes", "2"])
        .args(["--plane-order", "planar"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!refused.status.success());
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains("unknown --plane-order") && message.contains("word-interleaved"),
        "{message}"
    );
    let _ = fs::remove_dir_all(&base);
}

/// A legacy `amiga-re.toml` beside the media it pins.
///
/// The digest is the real one: the importer refuses an unpinned entry, and a
/// migrated project that cannot verify is exactly what these tests are about.
fn legacy_config(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("original")).unwrap_or_else(|error| panic!("{error}"));
    let media = b"0123456789ABCDEF".to_vec();
    fs::write(root.join("original/game.bin"), &media).unwrap_or_else(|error| panic!("{error}"));
    let digest = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(&media)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    fs::write(
        root.join("amiga-re.toml"),
        format!(
            "[project]\nname = \"Demo\"\n\n\
             [[media]]\nname = \"game\"\npath = \"original/game.bin\"\nsha256 = \"{digest}\"\n\n\
             [base]\norigin = 0x00e63e\nentry = 0x00e700\n\n\
             [bitmap]\nwidth = 320\nheight = 256\nplanes = 4\n"
        ),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    root
}

#[test]
fn a_migrated_project_verifies_rather_than_failing_on_every_source() {
    // The first thing anyone does after migrating is verify. A recorded size of
    // zero satisfies the schema and passes `project check`, and then every
    // source fails — so the size is read from the media, in place, where the
    // media still is.
    let root = legacy_config("migrate-verify");
    let config = root.join("amiga-re.toml");

    let output = amiga_re()
        .args(["project", "migrate", "Demo", "--in-place"])
        .args(["--image", "image:main", "--image-media", "game"])
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");

    // Nothing else in the directory was replaced: an in-place import writes the
    // documents it generates and leaves the repository it landed in alone.
    assert!(config.exists(), "the config it imported was removed");
    assert!(
        root.join("original/game.bin").exists(),
        "the media was lost"
    );

    let checked = amiga_re()
        .args(["project", "check"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let checked_text = String::from_utf8(checked.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(checked.status.success(), "{checked_text}");

    let verified = amiga_re()
        .args(["project", "verify"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let verified_text =
        String::from_utf8(verified.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(verified.status.success(), "{verified_text}");
    assert!(
        verified_text.contains("1/1 source(s) and 1/1 object(s) verified"),
        "{verified_text}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn migrating_an_image_without_naming_its_media_is_refused() {
    // An image is an object, and a legacy config has no vocabulary for one.
    // Half the decision produced a program document referencing an object
    // nothing declared, which the loader then refused as an unresolved
    // reference — a migration that could not be opened.
    let root = legacy_config("migrate-half-image");
    let output = amiga_re()
        .args(["project", "migrate", "Demo", "--image", "image:main"])
        .arg("--config")
        .arg(root.join("amiga-re.toml"))
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    let text = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("--image-media"), "{text}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn migrating_reports_the_bitmap_geometry_it_cannot_place() {
    // `[bitmap]` is default geometry with no bytes behind it, so it cannot
    // become a resource — but it was being dropped without a word, which is the
    // one outcome the importer is not allowed to have.
    let root = legacy_config("migrate-bitmap");
    let output = amiga_re()
        .args(["project", "migrate", "Demo"])
        .arg("--config")
        .arg(root.join("amiga-re.toml"))
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    let text = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        text.contains("[bitmap]") && text.contains("320x256"),
        "{text}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn run_and_trace_go_through_the_sandbox_operation() {
    // Verify that `run` and `trace` use the sandbox operation, including its execution
    // bounds and results.
    let root = std::env::temp_dir().join(format!("amiga-re-sandbox-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    // MOVEQ #7,D0 ; RTS
    let executable = root.join("routine");
    fs::write(&executable, hunk_image(&[0x70, 0x07, 0x4e, 0x75]))
        .unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .args(["trace"])
        .arg(&executable)
        .args(["--stack-base", "0x100000", "--stack-size", "0x1000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("routine returned"),
        "the stop reason is missing:\n{text}"
    );
    assert!(text.contains("D0=0x00000007"), "D0 was not seeded:\n{text}");
    // The trace comes from the operation, so its rows are the operation's rows.
    assert!(text.contains("moveq") || text.contains("MOVEQ"), "{text}");

    // A budget above the operation's ceiling is reduced, and the reduction is
    // reported rather than applied silently — behaviour the command line did
    // not have before it routed.
    let clamped = amiga_re()
        .args(["run"])
        .arg(&executable)
        // Above `MAXIMUM_SANDBOX_STEPS_CEILING`, whatever it currently is.
        .args(["--max-steps", "100000000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let stderr = String::from_utf8_lossy(&clamped.stderr).into_owned();
    assert!(clamped.status.success(), "{stderr}");
    assert!(
        stderr.contains("LIMIT_REDUCED") || stderr.to_lowercase().contains("reduced"),
        "the clamp was silent:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn sample_to_wav_and_mod_extract_review_their_writes() {
    // Both wrote with `prepare_output_file` + `fs::write`, so no plan digest
    // existed for either. They route now, which means the same `--force`
    // provenance rule as every other export applies to them.
    let root = std::env::temp_dir().join(format!("amiga-re-audio-raw-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("out")).unwrap_or_else(|error| panic!("{error}"));

    // A file holding a tracker module at offset 0 and PCM-ish bytes after it.
    let mut image = vec![0_u8; 1084];
    image[..5].copy_from_slice(b"TITLE");
    image[950] = 1; // song length
    image[1080..1084].copy_from_slice(b"M.K.");
    image.extend(std::iter::repeat_n(0_u8, 64 * 4 * 4));
    let module_len = image.len();
    image.extend((0..=255_u8).cycle().take(256));
    let source = root.join("game.bin");
    fs::write(&source, &image).unwrap_or_else(|error| panic!("{error}"));

    let wav = root.join("out/shot.wav");
    let output = amiga_re()
        .args(["sample", "to-wav"])
        .arg(&source)
        .arg(&wav)
        .args(["--offset", &format!("{module_len}"), "--length", "0x40"])
        .args(["--rate", "8287"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("Plan SHA-256: "),
        "no plan was reviewed:\n{text}"
    );
    let written = fs::read(&wav).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(&written[..4], b"RIFF");
    assert_eq!(written.len(), 44 + 0x40);
    assert!(root.join("out/shot.wav.manifest.json").is_file());

    let module = root.join("out/title.mod");
    let output = amiga_re()
        .args(["mod", "extract"])
        .arg(&source)
        .arg(&module)
        .args(["--offset", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("M.K."),
        "the module was not described:\n{text}"
    );
    assert!(
        text.contains("Plan SHA-256: "),
        "no plan was reviewed:\n{text}"
    );
    assert_eq!(
        fs::read(&module).unwrap_or_else(|error| panic!("{error}")),
        image[..module_len]
    );
    assert!(root.join("out/title.mod.manifest.json").is_file());

    // The policy is the operation's: an unforced second run is refused.
    let refused = amiga_re()
        .args(["mod", "extract"])
        .arg(&source)
        .arg(&module)
        .args(["--offset", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!refused.status.success(), "an unforced overwrite succeeded");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unpack_routes_through_the_operation_and_reviews_its_write() {
    // `unpack` used to decode and `fs::write` in place, so the plan digest a
    // user is meant to review never existed for it. The digest comparison is the
    // assertion that matters: printing *a* plan would pass against two
    // implementations that disagree about what they are writing.
    let root = std::env::temp_dir().join(format!("amiga-re-unpack-plan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("out")).unwrap_or_else(|error| panic!("{error}"));
    let stream = [b'A', b'B', 0x90, 3, b'Z'];
    let input = root.join("packed.bin");
    fs::write(&input, stream).unwrap_or_else(|error| panic!("{error}"));

    let target = root.join("out/map.bin");
    let expected = {
        let (source_base, name) =
            amiga_operations::split_host_path(&input).expect("a readable file");
        let base = target.parent().expect("a parent").parent().expect("a root");
        let destination = amiga_operations::DestinationName::parse("out").expect("a destination");
        let sources = amiga_operations::FilesystemSourceResolver::new(source_base);
        let destinations = amiga_operations::FilesystemDestinationResolver::new(base.to_path_buf());
        let context =
            amiga_operations::ExecutionContext::new(&sources).with_destinations(&destinations);
        let mut prepare = amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::CompressRleXorExport(
                amiga_operations::RleXorExportArguments::new(
                    amiga_operations::RleXorArguments::new(name.as_str(), 0x90).with_xor(false),
                    destination.as_str(),
                )
                .with_file_name("map.bin"),
            ),
        );
        prepare.execution.mode = amiga_operations::ExecutionMode::Prepare;
        amiga_operations::Router::execute(&prepare, &context)
            .compress_export()
            .expect("the export prepared")
            .plan
            .plan_sha256
            .clone()
    };

    let output = amiga_re()
        .args(["unpack", "rle-xor"])
        .arg(&input)
        .arg(&target)
        .args(["--marker", "0x90", "--no-xor", "--size-bytes", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains(&format!("Plan SHA-256: {expected}")),
        "the command line planned a different write than the router:\n{text}"
    );

    assert_eq!(
        fs::read(&target).unwrap_or_else(|error| panic!("{error}")),
        b"ABZZZZ"
    );
    // Beside the file, under a name derivable from it — the reviewed-write
    // layout every other export produces.
    assert!(root.join("out/map.bin.manifest.json").is_file());
    assert!(!root.join("out/manifest.json").exists());

    // And the policy is the operation's now: a second unforced run is refused.
    let refused = amiga_re()
        .args(["unpack", "rle-xor"])
        .arg(&input)
        .arg(&target)
        .args(["--marker", "0x90", "--no-xor", "--size-bytes", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!refused.status.success(), "an unforced overwrite succeeded");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unpack_powerpacker_exposes_the_output_limit() {
    let root =
        std::env::temp_dir().join(format!("amiga-re-powerpacker-limit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    let input = root.join("packed.pp");
    fs::write(&input, powerpacker_literal_abc()).unwrap_or_else(|error| panic!("{error}"));
    let output_path = root.join("decoded.bin");

    let output = amiga_re()
        .args(["unpack", "powerpacker"])
        .arg(&input)
        .arg(&output_path)
        .args(["--modes", "9,10,12,13", "--maximum-output-bytes", "2"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success(), "an oversized decode succeeded");
    let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(stderr.contains("2-byte limit"), "{stderr}");
    assert!(!output_path.exists(), "a refused decode wrote output");

    let _ = fs::remove_dir_all(&root);
}

fn powerpacker_literal_abc() -> Vec<u8> {
    let fields = [
        (0, 1),
        (2, 2),
        (u32::from(b'C'), 8),
        (u32::from(b'B'), 8),
        (u32::from(b'A'), 8),
    ];
    let mut bits = Vec::new();
    for (value, count) in fields {
        for shift in (0..count).rev() {
            bits.push((value >> shift) & 1);
        }
    }
    bits.resize(bits.len().next_multiple_of(32), 0);
    let word = bits
        .iter()
        .enumerate()
        .fold(0_u32, |word, (index, bit)| word | (bit << index));
    let mut packed = word.to_be_bytes().to_vec();
    packed.extend_from_slice(&(3_u32 << 8).to_be_bytes());
    packed
}

#[test]
fn unpack_rle_xor_decodes_a_marker_the_stream_carries_inline() {
    // The layout the toolkit could not state: the marker is the stream's first
    // byte, so the body starts one byte later than any size-field width can
    // express. Decoding it as an out-of-band marker succeeds and produces bytes
    // that were never in the original — no error, a wrong digest — so the two
    // decodes are compared here rather than only the successful one.
    let root = std::env::temp_dir().join(format!("amiga-re-inline-marker-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    let stream = [0x90, b'A', b'B', 0x90, 2, b'C', b'D'];
    let input = root.join("packed.bin");
    fs::write(&input, stream).unwrap_or_else(|error| panic!("{error}"));

    let inline = root.join("inline.bin");
    let output = amiga_re()
        .args(["unpack", "rle-xor"])
        .arg(&input)
        .arg(&inline)
        .args(["--marker", "0x90", "--no-xor", "--inline-marker"])
        .args(["--size-bytes", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert_eq!(
        fs::read(&inline).unwrap_or_else(|error| panic!("{error}")),
        b"ABCCCD"
    );

    let stated = root.join("stated.bin");
    let output = amiga_re()
        .args(["unpack", "rle-xor"])
        .arg(&input)
        .arg(&stated)
        .args(["--marker", "0x90", "--no-xor", "--size-bytes", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    assert_eq!(
        fs::read(&stated)
            .unwrap_or_else(|error| panic!("{error}"))
            .len(),
        70,
        "the silent failure this flag exists for stopped happening; the test is stale"
    );

    // The stated marker is a cross-check under the inline layout, so a stream
    // whose first byte is a different escape byte is refused rather than
    // decoded into something plausible.
    let wrong = amiga_re()
        .args(["unpack", "rle-xor"])
        .arg(&input)
        .arg(root.join("wrong.bin"))
        .args(["--marker", "0x91", "--no-xor", "--inline-marker"])
        .args(["--size-bytes", "0"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!wrong.status.success());
    let stderr = String::from_utf8(wrong.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(stderr.contains("0x90"), "{stderr}");
    let _ = fs::remove_dir_all(&root);
}

/// The contract fixture's main image, carved out as the file it is an image of.
///
/// The project pins that object by digest, which is the only thing that makes
/// its names applicable: a listing of some other file must not borrow them.
fn fixture_image(tag: &str) -> (PathBuf, PathBuf) {
    let project =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/amiga-project/fixtures/contract");
    let disk =
        fs::read(project.join("original/disk1.adf")).unwrap_or_else(|error| panic!("{error}"));
    let root = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    let image = root.join("main.bin");
    fs::write(&image, &disk[1024..1024 + 112]).unwrap_or_else(|error| panic!("{error}"));
    (project, image)
}

#[test]
fn a_disassembly_takes_its_labels_from_the_project_that_reviewed_them() {
    // The trap this closes: a project that adopted the format and deleted its
    // duplicated `[[symbols]]` table lost every label, silently, because an
    // unlabelled listing looks exactly like one that was never configured.
    // There is no config here at all — every name below comes from annotations.
    let (project, image) = fixture_image("project-labels");

    let output = amiga_re()
        .args(["disasm", "annotate"])
        .arg(&image)
        .args(["--base", "0xe63e"])
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("init_graphics:"),
        "the project's function name is missing: {text}"
    );
    // The listing says where the names came from, so a reader can check them.
    assert!(text.contains("image:main-executable"), "{text}");
    // And the stale annotation is withheld and said to be withheld, rather
    // than being applied to bytes it was not written about.
    let notes = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(notes.contains("annotation:main/stale-note"), "{notes}");
    assert!(!text.contains("old_entry_point"), "{text}");

    // Without the project, the same bytes fall back to a stub: the names are
    // the project's, not something the analysis could have invented.
    let bare = amiga_re()
        .args(["disasm", "annotate"])
        .arg(&image)
        .args(["--base", "0xe63e"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let bare_text = String::from_utf8(bare.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(bare_text.contains("sub_e63e:"), "{bare_text}");
    assert!(!bare_text.contains("init_graphics"), "{bare_text}");
    let _ = fs::remove_dir_all(image.parent().expect("a scratch directory"));
}

#[test]
fn the_control_flow_listing_labels_from_the_same_project_as_the_annotated_one() {
    // `flow` used to label from offsets alone, so one project named one
    // listing and not the other and a reader comparing them saw names appear
    // and disappear with no rule to infer. The header said a project was used,
    // which made the absence more confusing rather than less.
    let (project, image) = fixture_image("project-flow-labels");

    let flow = amiga_re()
        .args(["disasm", "flow"])
        .arg(&image)
        .args(["--base", "0xe63e"])
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let flow_text = String::from_utf8(flow.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(flow.status.success(), "{flow_text}");

    let annotated = amiga_re()
        .args(["disasm", "annotate"])
        .arg(&image)
        .args(["--base", "0xe63e"])
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let annotated_text =
        String::from_utf8(annotated.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(annotated.status.success(), "{annotated_text}");

    // The same label, spelled the same way, in both listings.
    assert!(
        annotated_text.contains("init_graphics:"),
        "the annotated listing lost the project's function name: {annotated_text}"
    );
    assert!(
        flow_text.contains("init_graphics:"),
        "the flow listing does not carry the project's function name: {flow_text}"
    );
    // And withheld annotations stay withheld here too.
    assert!(!flow_text.contains("old_entry_point"), "{flow_text}");

    // Without the project there is no name to take: unlike `annotate`, `flow`
    // does not invent a `sub_` stub for a discovered entry, so the label line
    // is simply absent.
    let bare = amiga_re()
        .args(["disasm", "flow"])
        .arg(&image)
        .args(["--base", "0xe63e"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let bare_text = String::from_utf8(bare.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(bare.status.success(), "{bare_text}");
    assert!(!bare_text.contains("init_graphics"), "{bare_text}");
    let _ = fs::remove_dir_all(image.parent().expect("a scratch directory"));
}

#[test]
fn a_project_names_only_the_image_whose_digest_matches() {
    // Names are applied by digest, never by path. Bytes the project does not
    // describe get no names — and are told so, because that is exactly when a
    // user expects labels and would otherwise be left guessing.
    let (project, image) = fixture_image("project-other-bytes");
    let other = image.with_file_name("other.bin");
    let mut bytes = fs::read(&image).unwrap_or_else(|error| panic!("{error}"));
    // A byte inside the code hunk (which starts at file 0x24), so the file is
    // still a HUNK executable and only its digest differs: the point is that
    // the digest is what decides.
    bytes[0x30] ^= 0xff;
    fs::write(&other, &bytes).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .args(["disasm", "annotate"])
        .arg(&other)
        .args(["--base", "0xe63e"])
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success(), "{text}");
    assert!(!text.contains("init_graphics"), "{text}");
    let notes = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        notes.contains("describes no image"),
        "the silent case must still be explained: {notes}"
    );
    let _ = fs::remove_dir_all(image.parent().expect("a scratch directory"));
}

/// A one-hunk LoadSeg image whose CODE hunk holds a run of longwords that
/// address the hunk itself once it is mapped at `origin`.
fn pointer_table_image(origin: u32) -> Vec<u8> {
    let mut code = Vec::new();
    for offset in [0x40_u32, 0x44, 0x48, 0x4c, 0x50] {
        code.extend_from_slice(&(origin + offset).to_be_bytes());
    }
    code.resize(0x60, 0);
    let longwords = (code.len() / 4) as u32;
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, longwords] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

#[test]
fn xref_addr_reads_one_number_in_every_frame() {
    // The arithmetic moved into `analysis.address.resolve`; what this pins is
    // that moving it changed nothing a reader sees. Every line here was printed
    // by the frontend's own arithmetic before the migration.
    let base = std::env::temp_dir().join(format!("amiga-re-xref-addr-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = base.join("game");
    fs::write(&image, pointer_table_image(0x1000)).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .args(["xref", "addr", "0x1042"])
        .arg(&image)
        .args(["--base", "0x1000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "0x1042:\n\
         \x20 as absolute    -> hunk-rel 0x42, whole-file 0x62\n\
         \x20 as hunk-rel    -> absolute 0x2042, whole-file 0x1062\n\
         \x20 as whole-file  -> hunk-rel 0x1022, absolute 0x2022\n"
    );

    // Below the mapped origin the value is not an offset into this hunk, and
    // saying so beats reporting a difference that wrapped.
    let below = amiga_re()
        .args(["xref", "addr", "0x10"])
        .arg(&image)
        .args(["--base", "0x1000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(below.status.success());
    assert_eq!(
        String::from_utf8_lossy(&below.stdout),
        "0x10:\n\
         \x20 as absolute    -> below the mapped origin 0x1000\n\
         \x20 as hunk-rel    -> absolute 0x1010, whole-file 0x30\n\
         \x20 as whole-file  -> before hunk 0 at file 0x20\n"
    );

    // With no image there is no file frame to report, for either reading.
    let unanchored = amiga_re()
        .args(["xref", "addr", "0x1042", "--base", "0x1000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(unanchored.status.success());
    assert_eq!(
        String::from_utf8_lossy(&unanchored.stdout),
        "0x1042:\n\
         \x20 as absolute    -> hunk-rel 0x42\n\
         \x20 as hunk-rel    -> absolute 0x2042\n"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn scan_pointers_seeds_flow_from_every_target_it_found() {
    // The table is printed from `analysis.pointers.scan`, and `--seed-flow`
    // analyzes from the operation's derived entry offsets rather than from the
    // printed target list, which is capped.
    let base = std::env::temp_dir().join(format!("amiga-re-scan-pointers-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = base.join("game");
    fs::write(&image, pointer_table_image(0x1000)).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .args(["scan", "pointers"])
        .arg(&image)
        .args(["--base", "0x1000", "--seed-flow"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.starts_with("  0x00000000  u32 x5  targets 0x00001040..=0x00001050\n"),
        "{text}"
    );
    // Five targets, five seeds: the count comes from the operation's
    // `entry_offsets`, so a capped target list cannot shrink it.
    assert!(text.contains("seeded flow: 5 entries,"), "{text}");

    // Judged against a different origin the same bytes address nothing, which
    // is why the origin is part of the request rather than assumed.
    let elsewhere = amiga_re()
        .args(["scan", "pointers"])
        .arg(&image)
        .args(["--base", "0x2000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(elsewhere.status.success());
    assert_eq!(
        String::from_utf8_lossy(&elsewhere.stdout),
        "no pointer tables found\n"
    );

    let _ = fs::remove_dir_all(&base);
}

/// A one-hunk CODE image with real control flow: a `BSR` into a subroutine, a
/// `BRA` past it, two `NOP`s nothing reaches, and two bytes of data.
fn control_flow_image() -> Vec<u8> {
    let code: [u8; 20] = [
        0x61, 0x00, 0x00, 0x08, // 0000 BSR.W -> 0x000a
        0x60, 0x00, 0x00, 0x0a, // 0004 BRA.W -> 0x0010
        0x4e, 0x71, // 0008 NOP, reached by nothing
        0x70, 0x07, // 000a MOVEQ #7,D0
        0x4e, 0x75, // 000c RTS
        0x4e, 0x71, // 000e NOP, reached by nothing
        0x4e, 0x75, // 0010 RTS
        0xab, 0xcd, // 0012 data
    ];
    let longwords = (code.len() / 4) as u32;
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, longwords] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// A project-recorded raw MC68000 image with the three public entry points
/// used by the downstream music/outro shape that requested this feature.
fn raw_multi_entry_project(tag: &str) -> (PathBuf, String) {
    let bytes = [
        0x70, 0x01, 0x4e, 0x75, // entry 0: MOVEQ #1,D0; RTS
        0x70, 0x02, 0x4e, 0x75, // entry 1
        0x70, 0x03, 0x4e, 0x75, // entry 2
    ];
    let digest = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let root = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("analysis/programs")).unwrap_or_else(|error| panic!("{error}"));
    fs::write(root.join("module.bin"), bytes).unwrap_or_else(|error| panic!("{error}"));

    let write = |relative: &str, value: serde_json::Value| {
        fs::write(
            root.join(relative),
            serde_json::to_vec_pretty(&value).expect("serializable fixture"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    };
    write(
        "amiga-re.project.json",
        serde_json::json!({
            "document_kind": "project", "format_version": 1,
            "project": { "id": "project:raw", "name": "Raw module" },
            "documents": {
                "sources": "analysis/sources.json",
                "programs": ["analysis/programs/main.json"]
            }
        }),
    );
    write(
        "analysis/sources.json",
        serde_json::json!({
            "document_kind": "sources", "format_version": 1,
            "sources": [{
                "id": "source:module", "kind": "file", "display_name": "module.bin",
                "size": bytes.len(), "sha256": digest,
                "locations": [{ "kind": "project_relative", "path": "module.bin" }]
            }],
            "objects": [{
                "id": "object:module", "kind": "whole_source", "parent_id": "source:module",
                "selector": { "container": "range", "offset": 0, "length": bytes.len() },
                "size": bytes.len(), "sha256": digest
            }]
        }),
    );
    write(
        "analysis/programs/main.json",
        serde_json::json!({
            "document_kind": "program", "format_version": 1,
            "id": "program:raw", "name": "Raw module",
            "images": [{
                "id": "image:module", "object_id": "object:module",
                "format": "raw", "architecture": "mc68000",
                "load_maps": [{
                    "id": "loadmap:module/default", "name": "Decoded allocation",
                    "segments": [{ "hunk": 0, "runtime_base": "0x00040000" }],
                    "entry_points": [
                        { "address": "0x00040000", "role": "program_entry" },
                        { "address": "0x00040004", "role": "program_entry" },
                        { "address": "0x00040008", "role": "program_entry" }
                    ]
                }]
            }]
        }),
    );
    (root, digest)
}

#[test]
fn project_raw_images_drive_flow_and_report_from_every_recorded_entry() {
    let (root, digest) = raw_multi_entry_project("raw-project-disasm");
    let nested = root.join("analysis/programs");

    let flow = amiga_re()
        .args(["disasm", "flow", "--image", "image:module", "--project"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let flow_text = String::from_utf8(flow.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        flow.status.success(),
        "{flow_text}{}",
        String::from_utf8_lossy(&flow.stderr)
    );
    assert!(flow_text.contains("; Raw image: 0xc bytes"), "{flow_text}");
    assert!(
        flow_text.contains("; Rebased; entry offsets: 0x0, 0x4, 0x8"),
        "{flow_text}"
    );
    assert_eq!(flow_text.matches("MOVEQ.L").count(), 3, "{flow_text}");

    let explicit_document = amiga_re()
        .args(["disasm", "flow", "--image", "image:module", "--project"])
        .arg(root.join("amiga-re.project.json"))
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        explicit_document.status.success(),
        "{}",
        String::from_utf8_lossy(&explicit_document.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&explicit_document.stdout),
        flow_text,
        "an explicit root document and its directory selected different projects"
    );

    for current_dir in [&root, &nested] {
        let implicit = amiga_re()
            .args(["disasm", "flow", "--image", "image:module"])
            .current_dir(current_dir)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        let stderr = String::from_utf8_lossy(&implicit.stderr);
        assert!(
            implicit.status.success(),
            "implicit flow from {} failed:\n{stderr}",
            current_dir.display()
        );
        assert!(
            !stderr.contains(".amiga-re/local.json"),
            "implicit flow treated the root document as a directory:\n{stderr}"
        );
        assert_eq!(
            String::from_utf8_lossy(&implicit.stdout),
            flow_text,
            "implicit and explicit flow differ from {}",
            current_dir.display()
        );
    }

    let report = amiga_re()
        .args([
            "disasm",
            "report",
            "--image",
            "image:module",
            "--format",
            "json",
            "--project",
        ])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let report_text = String::from_utf8(report.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        report.status.success(),
        "{report_text}{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let report_json: serde_json::Value =
        serde_json::from_str(&report_text).unwrap_or_else(|error| panic!("{error}: {report_text}"));
    assert_eq!(report_json["source_sha256"], digest);
    assert_eq!(report_json["region"], "raw");
    assert_eq!(report_json["entries"], serde_json::json!([0, 4, 8]));
    assert_eq!(
        report_json["functions"]
            .as_array()
            .expect("function index")
            .len(),
        3
    );

    for current_dir in [&root, &nested] {
        let implicit = amiga_re()
            .args([
                "disasm",
                "report",
                "--image",
                "image:module",
                "--format",
                "json",
            ])
            .current_dir(current_dir)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        let stderr = String::from_utf8_lossy(&implicit.stderr);
        assert!(
            implicit.status.success(),
            "implicit report from {} failed:\n{stderr}",
            current_dir.display()
        );
        assert!(
            !stderr.contains(".amiga-re/local.json"),
            "implicit report treated the root document as a directory:\n{stderr}"
        );
        let implicit_json: serde_json::Value = serde_json::from_slice(&implicit.stdout)
            .unwrap_or_else(|error| {
                panic!("{error}: {}", String::from_utf8_lossy(&implicit.stdout))
            });
        assert_eq!(
            implicit_json,
            report_json,
            "implicit and explicit reports differ from {}",
            current_dir.display()
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_explicit_raw_file_requires_the_digest_it_was_pinned_to() {
    let (root, _) = raw_multi_entry_project("raw-file-pin");
    let output = amiga_re()
        .args(["disasm", "flow"])
        .arg(root.join("module.bin"))
        .args(["--raw-sha256", &"0".repeat(64)])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not the pinned"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn disasm_renders_its_listings_from_the_operations_instructions() {
    // Both listings are now rendered by this frontend from
    // `analysis.code.disassemble`'s instruction list — the label, the columns,
    // the comment marker, and the `DC.W`/`DC.B` split are its choices, and the
    // operation carries no labels at all. What this pins is that moving the
    // decode changed nothing a reader sees.
    let base = std::env::temp_dir().join(format!("amiga-re-disasm-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = base.join("game");
    fs::write(&image, control_flow_image()).unwrap_or_else(|error| panic!("{error}"));

    let linear = amiga_re()
        .args(["disasm", "linear"])
        .arg(&image)
        .args(["--start", "0x8", "--end", "0xc"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(linear.status.success());
    assert_eq!(
        String::from_utf8_lossy(&linear.stdout),
        "00000008: 4e71               NOP\n\
         0000000a: 7007               MOVEQ.L #7, D0\n"
    );

    let flow = amiga_re()
        .args(["disasm", "flow"])
        .arg(&image)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(flow.status.success());
    let text = String::from_utf8_lossy(&flow.stdout);
    let body = text
        .split_once("\n\n")
        .unwrap_or_else(|| panic!("no listing body: {text}"))
        .1;
    // The two NOPs and the trailing data are what control flow never reached,
    // and a linear sweep decodes the first of them as an instruction. That
    // difference is the whole reason the operation has two modes.
    assert_eq!(
        body,
        // The instruction column is padded to `FLOW_INSTRUCTION_COLUMN`, so the
        // `;` comments line up. Both this renderer and `amiga_disasm::render`
        // pad to it; a listing that stops lining up means they have drifted.
        "L00000000:  BSR 8 <0xA>                  ; 61000008\n\
         L00000004:  BRA 10 <0x10>                ; 6000000a\n\
         L00000008:  DC.W    $4E71                ; not directly reached\n\
         L0000000A:  MOVEQ.L #7, D0               ; 7007\n\
         L0000000C:  RTS                          ; 4e75\n\
         L0000000E:  DC.W    $4E71                ; not directly reached\n\
         L00000010:  RTS                          ; 4e75\n\
         L00000012:  DC.W    $ABCD                ; not directly reached\n"
    );
    // The header reports the source digest and the coverage the operation
    // computed, not a second count taken here.
    assert!(
        text.contains("; Coverage: 14/20 bytes (70.00%), 5 instructions, 2 functions,"),
        "{text}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_bounded_flow_listing_prints_the_selection_and_says_what_it_left_out() {
    // Reading three small routines out of a whole image used to mean piping the
    // full listing through an external filter — which is also how the broken
    // pipe was found. A bound is a rendering choice: the traversal is still the
    // whole hunk, and the coverage line still counts it, which is why the
    // listing has to say so rather than let the reader assume otherwise.
    let base = std::env::temp_dir().join(format!("amiga-re-bounded-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = base.join("game");
    fs::write(&image, control_flow_image()).unwrap_or_else(|error| panic!("{error}"));

    let run = |args: &[&str]| {
        let output = amiga_re()
            .args(["disasm", "flow"])
            .arg(&image)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let body = |text: &str| {
        text.split_once("\n\n")
            .unwrap_or_else(|| panic!("no listing body: {text}"))
            .1
            .to_owned()
    };

    // The callee alone: its two instructions, and neither the caller's nor the
    // unreached word at 0xe that sits past its span.
    let (ok, text, _) = run(&["--function", "0xa"]);
    assert!(ok, "{text}");
    assert_eq!(
        body(&text),
        "L0000000A:  MOVEQ.L #7, D0               ; 7007\n\
         L0000000C:  RTS                          ; 4e75\n"
    );
    assert!(
        text.contains("; Bounded to 1 of 2 function(s): 0xa"),
        "{text}"
    );
    // The coverage line above it counts five instructions and two functions,
    // which is the hunk's answer and not this listing's.
    assert!(
        text.contains("; Coverage: 14/20 bytes (70.00%), 5 instructions, 2 functions,"),
        "{text}"
    );
    assert!(
        text.contains("; The coverage above is the whole hunk's"),
        "{text}"
    );

    // A call that leaves the selection is named, because the line that would
    // have shown the reader where it went is one of the lines now missing.
    let (ok, text, _) = run(&["--function", "0x0"]);
    assert!(ok, "{text}");
    assert!(
        text.contains("; Calls leaving the selection: 0xa"),
        "{text}"
    );

    // A window clips the run it straddles rather than printing all of it: the
    // unreached word at 0x12 is outside, and the one at 0xe is not.
    let (ok, text, _) = run(&["--start", "0xc", "--end", "0x12"]);
    assert!(ok, "{text}");
    assert_eq!(
        body(&text),
        "L0000000C:  RTS                          ; 4e75\n\
         L0000000E:  DC.W    $4E71                ; not directly reached\n\
         L00000010:  RTS                          ; 4e75\n"
    );

    // `--no-data` takes the DC.W lines *and* the legend explaining them, which
    // would otherwise describe output that is no longer there.
    let (ok, text, _) = run(&["--no-data"]);
    assert!(ok, "{text}");
    assert!(!text.contains("DC.W"), "{text}");
    assert!(!text.contains("does not prove data"), "{text}");
    assert_eq!(body(&text).lines().count(), 5, "{text}");

    // An offset that is inside the hunk but is not an entry the traversal found
    // is refused. Printing an empty listing would read as "this function has no
    // code", which is the one conclusion a bound must never invite.
    let (ok, _, stderr) = run(&["--function", "0xb"]);
    assert!(!ok, "{stderr}");
    assert!(
        stderr.contains("is not a function entry this traversal found")
            && stderr.contains("the nearest is 0xa"),
        "{stderr}"
    );

    // An unbounded run is unchanged, down to the absent bounds header: the
    // feature is opt-in and the default listing is the one already pinned above.
    let (ok, text, _) = run(&[]);
    assert!(ok, "{text}");
    assert!(!text.contains("; Bounded to"), "{text}");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn xref_answers_both_directions_from_one_traversal() {
    // `xref refs` and `xref to` are one operation in two modes now. Before
    // that, `to` analyzed without the image's relocations and `refs` with
    // them, so the same image could answer the two questions inconsistently.
    let base = std::env::temp_dir().join(format!("amiga-re-xref-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = base.join("game");
    fs::write(&image, control_flow_image()).unwrap_or_else(|error| panic!("{error}"));

    let refs = amiga_re()
        .args(["xref", "refs"])
        .arg(&image)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(refs.status.success());
    // This fixture's transfers are all PC-relative branches, which carry no
    // absolute-long or PC-relative *operand* — so there is nothing to report,
    // and saying so beats an empty listing.
    assert_eq!(String::from_utf8_lossy(&refs.stdout), "no references\n");

    let to = amiga_re()
        .args(["xref", "to"])
        .arg(&image)
        .arg("0xa")
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(to.status.success());
    assert_eq!(
        String::from_utf8_lossy(&to.stdout),
        "nothing references 0xa\n"
    );

    let _ = fs::remove_dir_all(&base);
}

/// Start a one-file project and return its root and the id of the object that
/// file became. The object id is read from `project init`'s own output rather
/// than predicted: how an id is derived from a file name is the operation's
/// business, and a test that hard-coded it would pass for the wrong reason.
fn started_project(tag: &str) -> (PathBuf, String) {
    let base = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let media = base.join("title.bin");
    fs::write(&media, b"PLANE0PLANE1PALETTE-AND-THEN-SOME")
        .unwrap_or_else(|error| panic!("{error}"));
    let root = base.join("proj");

    let output = amiga_re()
        .args(["project", "init", "Demo"])
        .arg(&root)
        .arg(&media)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        output.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let object = text
        .lines()
        .find_map(|line| line.split(" -> ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("init named no object: {text}"))
        .to_owned();
    (root, object)
}

#[test]
fn project_check_exits_nonzero_for_a_schema_forbidden_digest() {
    let (root, _) = started_project("schema-violation");
    let path = root.join("analysis/sources.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}"));
    let mut document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    document["sources"][0]["sha256"] = serde_json::json!("abc");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&document).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let checked = amiga_re()
        .args(["project", "check"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!checked.status.success());
    let error = String::from_utf8_lossy(&checked.stderr);
    assert!(
        error.contains("DOCUMENT_SCHEMA_VIOLATION") && error.contains("/sources/0/sha256"),
        "{error}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_region_is_classified_and_commented_from_the_command_line() {
    // Verify that the CLI can record region classifications and comments through the
    // operation API.
    let (root, object) = started_project("annotate");

    let annotated = amiga_re()
        .args(["project", "annotate", "annotation:title-pixels"])
        .args(["--kind", "region", "--object", &object])
        .args(["--offset", "0", "--length", "12"])
        .args(["--classification", "image"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        annotated.status.success(),
        "{}",
        String::from_utf8_lossy(&annotated.stderr)
    );

    // A comment about the *bytes*, which is the form the entity-only variant
    // could not express.
    let commented = amiga_re()
        .args(["project", "comment", "annotation:why-a-bitmap"])
        .arg("Two planes, and the palette follows them.")
        .args(["--object", &object, "--offset", "12", "--length", "8"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        commented.status.success(),
        "{}",
        String::from_utf8_lossy(&commented.stderr)
    );

    // Reloading is the assertion: the project must still be one.
    let checked = amiga_re()
        .args(["project", "check"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(checked.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(checked.status.success(), "{text}");
    assert!(text.contains("2 annotation(s)"), "{text}");

    // The digest is the operation's, taken from the object the project
    // describes — the caller never named one.
    let document = fs::read_to_string(root.join("analysis/annotations/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    let sources = fs::read_to_string(root.join("analysis/sources.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    let sources: serde_json::Value =
        serde_json::from_str(&sources).unwrap_or_else(|error| panic!("{error}"));
    let digest = sources["objects"][0]["sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("the object has no digest: {sources}"));
    assert!(document.contains(digest), "{document}");
    assert!(
        document.contains("\"classification\": \"image\""),
        "{document}"
    );

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn a_region_id_is_refused_by_the_prefix_the_format_actually_uses() {
    // `region:` is the natural thing to type and is not the grammar: a region
    // is an `annotation:`. The refusal has to name the prefix that works.
    let (root, object) = started_project("annotate-prefix");
    let output = amiga_re()
        .args(["project", "annotate", "region:title-pixels"])
        .args(["--kind", "region", "--object", &object, "--length", "12"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    let text = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("annotation:"), "{text}");

    // Nothing was written on the way to refusing.
    let document = fs::read_to_string(root.join("analysis/annotations/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!document.contains("title-pixels"), "{document}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn an_annotation_is_removed_only_once_nothing_is_about_it() {
    let (root, object) = started_project("annotate-remove");
    let annotate = amiga_re()
        .args(["project", "annotate", "annotation:title-pixels"])
        .args(["--kind", "region", "--object", &object, "--length", "12"])
        .args(["--classification", "image"])
        .arg(&root)
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(annotate.success());
    let comment = amiga_re()
        .args(["project", "comment", "annotation:why-a-bitmap"])
        .arg("Two planes.")
        .args(["--about", "annotation:title-pixels"])
        .arg(&root)
        .status()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(comment.success());

    // Refused rather than cascaded: deleting the name would delete the
    // reasoning about it, which is the more expensive mistake.
    let refused = amiga_re()
        .args(["project", "remove", "annotation:title-pixels"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!refused.status.success());
    let text = String::from_utf8(refused.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("annotation:why-a-bitmap"), "{text}");

    for id in ["annotation:why-a-bitmap", "annotation:title-pixels"] {
        let removed = amiga_re()
            .args(["project", "remove", id])
            .arg(&root)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        assert!(
            removed.status.success(),
            "{}",
            String::from_utf8_lossy(&removed.stderr)
        );
    }
    let document = fs::read_to_string(root.join("analysis/annotations/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!document.contains("title-pixels"), "{document}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn a_decode_becomes_a_resource_the_next_session_can_reproduce() {
    // The other half of classifying. A region annotation says "these bytes are
    // a bitmap"; without a resource nothing records that it is 8x8, two planes,
    // with that palette, so an export stays a one-off file in a directory.
    let (root, object) = started_project("resource");

    let palette = amiga_re()
        .args(["project", "resource", "define", "resource:title-palette"])
        .args(["--kind", "palette", "--name", "Title palette"])
        .args(["--object", &object, "--offset", "16", "--length", "8"])
        .args(["--parameter", "format=rgb4", "--parameter", "count=4"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        palette.status.success(),
        "{}",
        String::from_utf8_lossy(&palette.stderr)
    );

    let image = amiga_re()
        .args(["project", "resource", "define", "resource:title-logo"])
        .args(["--kind", "image", "--name", "Title logo"])
        .args(["--object", &object, "--offset", "0", "--length", "16"])
        .args(["--parameter", "format=planar", "--parameter", "width=8"])
        .args(["--parameter", "height=8", "--parameter", "planes=2"])
        .args(["--parameter", "palette_resource_id=resource:title-palette"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        image.status.success(),
        "{}",
        String::from_utf8_lossy(&image.stderr)
    );

    let shown = amiga_re()
        .args(["project", "show"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8(shown.stdout).unwrap_or_else(|error| panic!("{error}"));
    assert!(shown.status.success(), "{text}");
    assert!(text.contains("2 resource(s)"), "{text}");

    // The digest is the operation's, and `width` reached the document as a
    // number rather than the string it was typed as.
    let document = fs::read_to_string(root.join("analysis/resources/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(document.contains("\"width\": 8"), "{document}");
    assert!(document.contains("\"object_sha256\""), "{document}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn a_resource_reference_of_the_wrong_kind_is_refused_from_the_command_line() {
    let (root, object) = started_project("resource-kind");
    let define = |id: &str, kind: &str, extra: &[&str]| {
        amiga_re()
            .args(["project", "resource", "define", id])
            .args(["--kind", kind, "--name", "Thing"])
            .args(["--object", &object, "--length", "16"])
            .args(extra)
            .arg(&root)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"))
    };
    let made = define(
        "resource:some-audio",
        "audio",
        &["--parameter", "encoding=8svx"],
    );
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );

    // An ID proves only that *some* resource is there.
    let refused = define(
        "resource:title-logo",
        "image",
        &[
            "--parameter",
            "format=planar",
            "--parameter",
            "width=8",
            "--parameter",
            "height=8",
            "--parameter",
            "planes=2",
            "--parameter",
            "palette_resource_id=resource:some-audio",
        ],
    );
    assert!(!refused.status.success());
    let text = String::from_utf8(refused.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains("palette"), "{text}");

    let document = fs::read_to_string(root.join("analysis/resources/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!document.contains("title-logo"), "{document}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

/// A project holding an 8x8 two-plane image and the four-colour palette it
/// reads, both over one synthetic source. Returns the root.
fn project_with_a_decodable_image(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let media = base.join("title.bin");
    let mut bytes = vec![0b1010_1010_u8; 8];
    bytes.extend(std::iter::repeat_n(0b1100_1100_u8, 8));
    bytes.extend([0x00, 0x00, 0x0f, 0x00, 0x00, 0xf0, 0x0f, 0xff]);
    fs::write(&media, &bytes).unwrap_or_else(|error| panic!("{error}"));
    let root = base.join("proj");

    let init = amiga_re()
        .args(["project", "init", "Demo"])
        .arg(&root)
        .arg(&media)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let text = String::from_utf8(init.stdout).unwrap_or_else(|error| panic!("{error}"));
    let object = text
        .lines()
        .find_map(|line| line.split(" -> ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("init named no object: {text}"))
        .to_owned();

    define_palette(&root, &object, 4);
    let image = amiga_re()
        .args(["project", "resource", "define", "resource:title-logo"])
        .args(["--kind", "image", "--name", "Title logo"])
        .args(["--object", &object, "--offset", "0", "--length", "16"])
        .args(["--parameter", "format=planar", "--parameter", "width=8"])
        .args(["--parameter", "height=8", "--parameter", "planes=2"])
        .args(["--parameter", "palette_resource_id=resource:title-palette"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        image.status.success(),
        "{}",
        String::from_utf8_lossy(&image.stderr)
    );
    root
}

/// Define, or redefine, the palette the image reads.
fn define_palette(root: &Path, object: &str, count: u16) {
    let exists = fs::read_to_string(root.join("analysis/resources/main.json"))
        .is_ok_and(|text| text.contains("resource:title-palette"));
    let verb = if exists { "update" } else { "define" };
    let output = amiga_re()
        .args(["project", "resource", verb, "resource:title-palette"])
        .args(["--kind", "palette", "--name", "Title palette"])
        .args(["--object", object, "--offset", "16", "--length", "8"])
        .args(["--parameter", "format=rgb4"])
        .args(["--parameter", &format!("count={count}")])
        .arg(root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn export(root: &Path, id: &str) -> std::process::Output {
    amiga_re()
        .args(["project", "resource", "export", id])
        .arg(root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"))
}

/// Every artifact the project records, as (id, path).
fn artifacts(root: &Path) -> Vec<(String, String)> {
    let text = fs::read_to_string(root.join("analysis/resources/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    let document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    document["artifacts"]
        .as_array()
        .map(|artifacts| {
            artifacts
                .iter()
                .map(|artifact| {
                    (
                        artifact["id"].as_str().unwrap_or_default().to_owned(),
                        artifact["path"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_resource_is_reproduced_from_the_project_and_nothing_else() {
    // The whole point of a recipe: no width, no palette, no extension supplied
    // by the caller, and the same bytes come out of a second process.
    let root = project_with_a_decodable_image("export");
    let first = export(&root, "resource:title-logo");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let recorded = artifacts(&root);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    let (_, path) = &recorded[0];
    assert!(path.ends_with(".png"), "{path}");
    let bytes = fs::read(root.join(path)).unwrap_or_else(|error| panic!("{error}"));

    // Re-exporting an unchanged resource is the same recipe, so it is the same
    // key, the same path and the same bytes.
    fs::remove_file(root.join(path)).unwrap_or_else(|error| panic!("{error}"));
    let again = export(&root, "resource:title-logo");
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(artifacts(&root), recorded, "the record moved");
    assert_eq!(
        fs::read(root.join(path)).unwrap_or_else(|error| panic!("{error}")),
        bytes,
        "the same recipe produced different bytes"
    );

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn verify_tells_the_three_artifact_states_apart() {
    let root = project_with_a_decodable_image("artifact-states");
    assert!(export(&root, "resource:title-logo").status.success());
    let (_, path) = artifacts(&root).remove(0);
    let file = root.join(&path);

    let verify = |root: &Path| {
        let output = amiga_re()
            .args(["project", "verify"])
            .arg(root)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
        (output.status.success(), text)
    };

    let (ok, text) = verify(&root);
    assert!(ok, "{text}");
    assert!(text.contains("current:"), "{text}");

    // Editing the palette the image reads invalidates the key. Expected, and
    // informational: this is what "needs re-export" is.
    define_palette(&root, "object:title.bin/whole", 2);
    let (ok, text) = verify(&root);
    assert!(ok, "a stale recipe is not a failure: {text}");
    assert!(text.contains("stale:"), "{text}");
    assert!(text.contains("need re-exporting"), "{text}");

    // A missing file is regenerable, so deleting `decoded/` stays safe.
    fs::remove_file(&file).unwrap_or_else(|error| panic!("{error}"));
    let (ok, text) = verify(&root);
    assert!(ok, "a missing artifact is not a failure: {text}");
    assert!(text.contains("missing:"), "{text}");

    // Bytes that are not what the record pins are a contradiction, and this is
    // the one that should be loud.
    fs::write(&file, b"not a png").unwrap_or_else(|error| panic!("{error}"));
    let (ok, text) = verify(&root);
    assert!(!ok, "a digest mismatch must fail: {text}");
    assert!(text.contains("mismatch:"), "{text}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn a_re_export_never_overwrites_the_output_its_record_describes() {
    // The property the keyed path exists to give. Export, change the resource,
    // then make the document write fail: the old record must still describe
    // bytes that still exist at its own path, because the new file went
    // somewhere else.
    let root = project_with_a_decodable_image("re-export-fault");
    assert!(export(&root, "resource:title-logo").status.success());
    let before = artifacts(&root);
    let (_, first_path) = &before[0];
    let first_bytes = fs::read(root.join(first_path)).unwrap_or_else(|error| panic!("{error}"));

    define_palette(&root, "object:title.bin/whole", 2);
    let document = root.join("analysis/resources/main.json");
    let recorded = fs::read(&document).unwrap_or_else(|error| panic!("{error}"));
    // The project root, not the document: an edit is staged under the root and
    // installed with renames, so a read-only *file* is no longer what stops one
    // — a rename replaces a file whatever its own mode says, as long as the
    // directory permits it. A root nothing may create in is the failure this
    // test needs, and it is the shape a full disk has too.
    let mut permissions = fs::metadata(&root)
        .unwrap_or_else(|error| panic!("{error}"))
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&root, permissions).unwrap_or_else(|error| panic!("{error}"));

    let failed = export(&root, "resource:title-logo");
    assert!(!failed.status.success(), "the document write should fail");

    let mut writable = fs::metadata(&root)
        .unwrap_or_else(|error| panic!("{error}"))
        .permissions();
    #[expect(
        clippy::permissions_set_readonly_false,
        reason = "restoring the fixture"
    )]
    writable.set_readonly(false);
    fs::set_permissions(&root, writable).unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        fs::read(&document).unwrap_or_else(|error| panic!("{error}")),
        recorded,
        "the document changed despite the failed write"
    );
    assert_eq!(
        fs::read(root.join(first_path)).unwrap_or_else(|error| panic!("{error}")),
        first_bytes,
        "the previous output was overwritten by a re-export"
    );

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

#[test]
fn a_resource_is_removed_only_once_nothing_was_made_from_it() {
    let root = project_with_a_decodable_image("resource-artifact");
    assert!(export(&root, "resource:title-logo").status.success());
    let (artifact, _) = artifacts(&root).remove(0);

    let refused = amiga_re()
        .args(["project", "resource", "remove", "resource:title-logo"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!refused.status.success());
    let text = String::from_utf8(refused.stderr).unwrap_or_else(|error| panic!("{error}"));
    assert!(text.contains(&artifact), "{text}");

    // Forgetting the record leaves the file alone, and then the resource goes.
    let (_, path) = artifacts(&root).remove(0);
    let forgotten = amiga_re()
        .args(["project", "resource", "forget", &artifact])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        forgotten.status.success(),
        "{}",
        String::from_utf8_lossy(&forgotten.stderr)
    );
    assert!(
        root.join(&path).is_file(),
        "forgetting a record deleted the file it named"
    );
    let removed = amiga_re()
        .args(["project", "resource", "remove", "resource:title-logo"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

/// `MOVE.W #value,($DFFxxx).L`, as a program pokes a chip register.
fn poke_chip_register(code: &mut Vec<u8>, offset: u16, value: u16) {
    code.extend_from_slice(&[0x33, 0xfc]);
    code.extend_from_slice(&value.to_be_bytes());
    code.extend_from_slice(&(0x00df_f000_u32 + u32::from(offset)).to_be_bytes());
}

/// A routine that copies two words from `$40000` to `$40010` with the blitter.
fn blitting_routine() -> Vec<u8> {
    let mut code = Vec::new();
    poke_chip_register(&mut code, 0x040, 0x09f0); // BLTCON0: USEA | USED | copy A
    poke_chip_register(&mut code, 0x042, 0x0000); // BLTCON1
    poke_chip_register(&mut code, 0x044, 0xffff); // BLTAFWM
    poke_chip_register(&mut code, 0x046, 0xffff); // BLTALWM
    poke_chip_register(&mut code, 0x050, 0x0004); // BLTAPTH
    poke_chip_register(&mut code, 0x052, 0x0000); // BLTAPTL
    poke_chip_register(&mut code, 0x054, 0x0004); // BLTDPTH
    poke_chip_register(&mut code, 0x056, 0x0010); // BLTDPTL
    poke_chip_register(&mut code, 0x058, 0x0042); // BLTSIZE: two words, one line
    code.extend_from_slice(&[0x4e, 0x75]); // RTS
    code
}

#[test]
fn a_blitted_export_is_produced_and_stdout_stays_parseable_json() {
    let base = std::env::temp_dir().join(format!("amiga-re-call-blit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("routine");
    fs::write(&source, hunk_image(&blitting_routine())).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .arg("call")
        .arg(&source)
        .args([
            "--custom-chips",
            "--map",
            "0x40000:256",
            "--poke",
            "0x40000=12345678",
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success(), "{:?}", output);

    // Without --output the record is stdout's only content, so the blit log has
    // to go to stderr or the record stops being pipeable.
    let record: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout was not JSON: {error}"));
    assert_eq!(record["blits_total"], 1, "record: {record}");
    assert_eq!(record["executed_blit_words_total"], 2);
    assert_eq!(record["custom_chips"]["blitter"]["mode"], "emulate");
    let changed = record["changed_memory"]
        .as_array()
        .unwrap_or_else(|| panic!("changed_memory is an array"));
    assert!(
        changed
            .iter()
            .any(|region| region["address"] == 0x4_0010 && region["hex"] == "12345678"),
        "the blitted words are missing: {record}"
    );

    let stderr = String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("stderr was not UTF-8: {error}"));
    assert!(
        stderr.contains("1 blit"),
        "the blit log is missing: {stderr}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_refused_blit_reaches_the_rendered_output() {
    let base = std::env::temp_dir().join(format!("amiga-re-call-refuse-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("routine");
    let mut code = blitting_routine();
    // Patch BLTCON1 to set LINE, which this build does not implement.
    code[10] = 0x00;
    code[11] = 0x01;
    fs::write(&source, hunk_image(&code)).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .arg("call")
        .arg(&source)
        .args(["--custom-chips", "--map", "0x40000:256"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success(), "{:?}", output);

    let stderr = String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("stderr was not UTF-8: {error}"));
    assert!(
        stderr.contains("REFUSED") && stderr.contains("line mode"),
        "a refusal that reached nobody is the failure this exists to remove: {stderr}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_blitter_recipe_that_blitted_nothing_says_so() {
    let base = std::env::temp_dir().join(format!("amiga-re-call-noblit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("routine");
    fs::write(&source, hunk_image(&[0x4e, 0x75])).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .arg("call")
        .arg(&source)
        .arg("--custom-chips")
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());

    let stderr = String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("stderr was not UTF-8: {error}"));
    assert!(
        stderr.contains("started no blits"),
        "silence there looks like success: {stderr}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn blitter_dma_without_custom_chips_is_an_error_not_a_silent_no_op() {
    let base = std::env::temp_dir().join(format!("amiga-re-call-dmaflag-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let source = base.join("routine");
    fs::write(&source, hunk_image(&[0x4e, 0x75])).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .arg("call")
        .arg(&source)
        .args(["--blitter-dma", "require"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        !output.status.success(),
        "a flag that changes nothing is worse than a missing one"
    );
    let _ = fs::remove_dir_all(&base);
}

/// A project that keeps provisional outputs away from its source media can
/// still replay one, and only from the place it declared.
///
/// Three assertions, and the second is the one this exists for. A new project
/// declares where provisional outputs go, so the capability is reachable
/// without hand-editing the one document the format keeps small. An artifact
/// under that directory is replayed, and both it and the image are then named
/// relative to the project — a record that says which project the replayed
/// bytes came out of, rather than two bare file names with no shared root. An
/// artifact somewhere else is refused by name: the declaration is what opens
/// the door, not the caller's path.
#[test]
fn an_artifact_is_replayed_from_the_projects_declared_scratch_directory() {
    let base = std::env::temp_dir().join(format!("amiga-re-scratch-seed-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("media")).unwrap_or_else(|error| panic!("{error}"));

    // MOVE.L ($40000).L,($40100).L ; RTS — so the seeded bytes have to have
    // arrived for the changed memory to hold them.
    let code: [u8; 12] = [
        0x23, 0xf9, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, //
        0x4e, 0x75,
    ];
    let media = base.join("media/game.exe");
    fs::write(&media, hunk_image(&code)).unwrap_or_else(|error| panic!("{error}"));

    let project = base.join("project");
    let output = amiga_re()
        .args(["project", "init", "Scratch seeds"])
        .arg(&project)
        .arg(&media)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "project init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(project.join("amiga-re.project.json"))
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        root["directories"]["scratch"], "work-in-progress",
        "a new project must declare where provisional outputs go: {root}"
    );
    // `project init` names the copy after the source's digest, so the image's
    // project-relative path is read from the document rather than guessed.
    let sources: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(project.join("analysis/sources.json"))
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let image = sources["sources"][0]["locations"][0]["path"]
        .as_str()
        .expect("the registered image's project-relative path")
        .to_owned();

    let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    let digest = {
        let scratch = project.join("work-in-progress");
        fs::create_dir_all(&scratch).unwrap_or_else(|error| panic!("{error}"));
        fs::write(scratch.join("table.bin"), bytes).unwrap_or_else(|error| panic!("{error}"));
        sha256_of(&bytes)
    };
    // The same bytes outside the project, so the refusal below is about *where*
    // the file is and not about what is in it.
    fs::write(base.join("media/table.bin"), bytes).unwrap_or_else(|error| panic!("{error}"));

    let call = |artifact: PathBuf| {
        amiga_re()
            .args(["--project"])
            .arg(&project)
            .arg("call")
            .arg(project.join(&image))
            .args(["--map", "0x40000:0x200"])
            .arg("--poke-artifact")
            .arg(format!("0x40000={}@{digest}", artifact.display()))
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"))
    };

    let replayed = call(project.join("work-in-progress/table.bin"));
    assert!(
        replayed.status.success(),
        "the declared scratch directory was refused: {}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&replayed.stdout)
        .unwrap_or_else(|error| panic!("the record was not JSON: {error}"));
    // The seed's source is a project-relative identity rather than a bare file
    // name, which is the widening this buys: the image and the artifact are
    // named against one root, so neither name is ambiguous on its own.
    let seed = &record["memory_seeds"][0];
    assert_eq!(seed["hex"], "deadbeef", "{record}");
    assert_eq!(
        seed["from"]["source"], "work-in-progress/table.bin",
        "{record}"
    );
    assert_eq!(seed["from"]["length"], 4, "{record}");
    assert_eq!(seed["from"]["sha256"], digest, "{record}");
    assert!(
        record["changed_memory"]
            .as_array()
            .is_some_and(|regions| regions.iter().any(|region| region["address"] == 0x4_0100)),
        "the routine never saw the seeded bytes: {record}"
    );

    let refused = call(base.join("media/table.bin"));
    assert!(
        !refused.status.success(),
        "a file the project never declared a place for was replayed anyway"
    );
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains("work-in-progress"),
        "the refusal must name the declared directory the file is not under:\n{message}"
    );

    let _ = fs::remove_dir_all(&base);
}

/// Lowercase hex SHA-256, spelled here so the test pins the digest the way a
/// caller would type it rather than the way the toolkit computes it.
fn sha256_of(bytes: &[u8]) -> String {
    use std::process::Stdio;
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("sha256sum: {error}"));
    std::io::Write::write_all(child.stdin.as_mut().expect("a stdin pipe"), bytes)
        .unwrap_or_else(|error| panic!("{error}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("{error}"));
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("a digest")
        .to_owned()
}

/// Beside the image needs no project, and elsewhere needs a declaration.
///
/// The first half is what the widening must not cost: a `call` over two loose
/// files in a directory nobody has declared anything about still replays an
/// artifact, because the image's own directory is a root both sources share.
/// The second is why the widening is not simply "look anywhere" — a project
/// that never said where provisional outputs go has not opened the door, and
/// the refusal says which declaration is missing rather than that the path was
/// wrong.
#[test]
fn an_artifact_beside_the_image_needs_no_project_and_one_elsewhere_needs_a_declaration() {
    let base = std::env::temp_dir().join(format!("amiga-re-scratch-refuse-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("loose")).unwrap_or_else(|error| panic!("{error}"));

    let code: [u8; 12] = [
        0x23, 0xf9, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, //
        0x4e, 0x75,
    ];
    let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    let digest = sha256_of(&bytes);

    let loose = base.join("loose");
    fs::write(loose.join("game.exe"), hunk_image(&code)).unwrap_or_else(|error| panic!("{error}"));
    fs::write(loose.join("table.bin"), bytes).unwrap_or_else(|error| panic!("{error}"));

    let beside = amiga_re()
        .arg("call")
        .arg(loose.join("game.exe"))
        .args(["--map", "0x40000:0x200"])
        .arg("--poke-artifact")
        .arg(format!(
            "0x40000={}@{digest}",
            loose.join("table.bin").display()
        ))
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        beside.status.success(),
        "an artifact beside the image must still need no project: {}",
        String::from_utf8_lossy(&beside.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&beside.stdout)
        .unwrap_or_else(|error| panic!("the record was not JSON: {error}"));
    assert_eq!(
        record["memory_seeds"][0]["from"]["source"], "table.bin",
        "an unwidened call must still name its artifact by its bare file name: {record}"
    );

    // A project over the same image, with the declaration taken back out.
    let project = base.join("project");
    let output = amiga_re()
        .args(["project", "init", "No scratch"])
        .arg(&project)
        .arg(loose.join("game.exe"))
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "project init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root_path = project.join("amiga-re.project.json");
    let mut root: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&root_path).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    root["directories"]
        .as_object_mut()
        .expect("an object")
        .remove("scratch");
    let image = {
        let sources: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(project.join("analysis/sources.json"))
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        sources["sources"][0]["locations"][0]["path"]
            .as_str()
            .expect("the registered image's project-relative path")
            .to_owned()
    };
    fs::write(&root_path, serde_json::to_string_pretty(&root).unwrap())
        .unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(project.join("work-in-progress")).unwrap_or_else(|error| panic!("{error}"));
    fs::write(project.join("work-in-progress/table.bin"), bytes)
        .unwrap_or_else(|error| panic!("{error}"));

    let refused = amiga_re()
        .arg("--project")
        .arg(&project)
        .arg("call")
        .arg(project.join(&image))
        .args(["--map", "0x40000:0x200"])
        .arg("--poke-artifact")
        .arg(format!(
            "0x40000={}@{digest}",
            project.join("work-in-progress/table.bin").display()
        ))
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        !refused.status.success(),
        "a directory the project never declared was read anyway"
    );
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains("directories.scratch"),
        "the refusal must name the declaration that is missing:\n{message}"
    );

    let _ = fs::remove_dir_all(&base);
}

/// A project annotating one routine with a reviewed calling contract, and the
/// executable it describes.
///
/// Two routines: one at offset 0 that calls the other, and the annotated callee
/// at offset 8. The call site is what the listing has to label; the callee's
/// entry is what `call` builds a template from.
fn signature_project(tag: &str) -> PathBuf {
    // 0000 MOVEQ #3,D1 ; 0002 BSR.S $0008 ; 0004 RTS ; 0006 NOP
    // 0008 MOVEQ #0,D0 ; 000A RTS
    let code: [u8; 12] = [
        0x72, 0x03, 0x61, 0x04, 0x4e, 0x75, 0x4e, 0x71, 0x70, 0x00, 0x4e, 0x75,
    ];
    let mut program = Vec::new();
    for word in [0x03f3_u32, 0, 1, 0, 0, (code.len() / 4) as u32] {
        program.extend_from_slice(&word.to_be_bytes());
    }
    program.extend_from_slice(&0x03e9_u32.to_be_bytes());
    program.extend_from_slice(&((code.len() / 4) as u32).to_be_bytes());
    program.extend_from_slice(&code);
    program.extend_from_slice(&0x03f2_u32.to_be_bytes());

    let digest = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(&program)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };

    let root = std::env::temp_dir().join(format!("amiga-re-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for directory in [
        "analysis/annotations",
        "analysis/types",
        "analysis/programs",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap_or_else(|error| panic!("{error}"));
    }
    fs::write(root.join("prog"), &program).unwrap_or_else(|error| panic!("{error}"));

    let write = |relative: &str, value: serde_json::Value| {
        fs::write(
            root.join(relative),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    };
    write(
        "amiga-re.project.json",
        serde_json::json!({
            "document_kind": "project", "format_version": 1,
            "project": { "id": "project:sig", "name": "Signature demo" },
            "documents": {
                "sources": "analysis/sources.json",
                "programs": ["analysis/programs/main.json"],
                "annotations": ["analysis/annotations/main.json"],
                "types": ["analysis/types/main.json"]
            }
        }),
    );
    write(
        "analysis/sources.json",
        serde_json::json!({
            "document_kind": "sources", "format_version": 1,
            "sources": [{
                "id": "source:prog", "kind": "file", "display_name": "prog",
                "size": program.len(), "sha256": digest,
                "locations": [{ "kind": "project_relative", "path": "prog" }]
            }],
            "objects": [{
                "id": "object:prog", "kind": "whole_source", "parent_id": "source:prog",
                "selector": { "container": "range", "offset": 0, "length": program.len() },
                "size": program.len(), "sha256": digest
            }]
        }),
    );
    write(
        "analysis/programs/main.json",
        serde_json::json!({
            "document_kind": "program", "format_version": 1,
            "id": "program:main", "name": "Main",
            "images": [{
                "id": "image:main", "object_id": "object:prog",
                "format": "hunk", "architecture": "mc68000"
            }]
        }),
    );
    write(
        "analysis/types/main.json",
        serde_json::json!({
            "document_kind": "types", "format_version": 1,
            "types": [
                { "id": "type:u16", "kind": "integer", "name": "u16",
                  "size": 2, "signed": false, "byte_order": "big" },
                { "id": "type:s16", "kind": "integer", "name": "s16",
                  "size": 2, "signed": true, "byte_order": "big" },
                { "id": "type:load-sig", "kind": "function", "name": "LoadSig",
                  "parameters": [
                    { "name": "level", "type_id": "type:u16",
                      "location": { "kind": "register", "register": "d1" } },
                    // Two stack parameters, so the template's line continuation
                    // is exercised: a comment beside the first would comment out
                    // the backslash that continues to the second.
                    { "name": "flags", "type_id": "type:u16",
                      "location": { "kind": "stack", "offset": 4 } },
                    { "name": "mode", "type_id": "type:u16",
                      "location": { "kind": "stack", "offset": 8 } }
                  ],
                  "results": [
                    { "name": "status", "type_id": "type:s16",
                      "location": { "kind": "register", "register": "d0" } }
                  ],
                  "clobbers": ["d0", "d1"] }
            ]
        }),
    );
    write(
        "analysis/annotations/main.json",
        serde_json::json!({
            "document_kind": "annotations", "format_version": 1,
            "scope": { "program_id": "program:main", "image_id": "image:main" },
            "annotations": [{
                "id": "function:load-level", "kind": "function", "origin": "user",
                "name": "load_level", "type_id": "type:load-sig",
                "target": {
                    "space": "hunk", "image_id": "image:main", "hunk": 0,
                    "offset": 8, "length": 4, "object_sha256": digest
                }
            }]
        }),
    );
    root
}

/// The listing spends the signature at the *call site*, which is where a reader
/// asks what the routine is being handed.
///
/// `MOVEQ #3,D1` one line above is unreadable until something says D1 is
/// `level`; that is the whole content of this feature.
#[test]
fn an_annotated_listing_names_a_callee_s_parameters_at_the_call_site() {
    let root = signature_project("signature-listing");
    let output = amiga_re()
        .args(["disasm", "annotate", "prog"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("call load_level(level=D1, flags=+4(SP), mode=+8(SP)) -> status=D0"),
        "the call site does not carry the signature:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&root);
}

/// A template names every argument and supplies no value for any of them.
#[test]
fn a_call_template_states_the_locations_and_invents_no_values() {
    let root = signature_project("signature-template");
    let output = amiga_re()
        .args(["call", "prog", "--entry", "0x8", "--template"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--reg d1=VALUE"), "{stdout}");
    assert_eq!(stdout.matches("--arg VALUE").count(), 2, "{stdout}");
    // Which `--arg` is which, because `+8(SP)` does not say "the second one".
    assert!(stdout.contains("--arg order: 1 flags, 2 mode"), "{stdout}");
    // No value is invented anywhere — a template that ran as it stands would
    // produce a record of a call nobody meant to make.
    assert!(
        !stdout.contains("=0"),
        "the template filled in a value:\n{stdout}"
    );

    // **The command line has to survive being pasted.** Every continued line
    // ends in a bare backslash: a trailing `# name` beside an argument would put
    // the backslash inside a shell comment, so the continuation would be
    // swallowed and every argument after the first would become its own command.
    for line in stdout.lines().filter(|line| line.ends_with('\\')) {
        assert!(
            !line.contains('#'),
            "a continued line carries a comment, so its backslash is commented \
             out:\n{stdout}"
        );
    }
    let _ = fs::remove_dir_all(&root);
}

/// A parameter the command line leaves out is refused **by name**, and the
/// override is explicit.
#[test]
fn a_call_missing_an_argument_its_signature_names_is_refused() {
    let root = signature_project("signature-refusal");
    let call = |extra: &[&str]| {
        let mut arguments = vec!["call", "prog", "--entry", "0x8"];
        arguments.extend_from_slice(extra);
        amiga_re()
            .args(arguments)
            .current_dir(&root)
            .output()
            .unwrap_or_else(|error| panic!("{error}"))
    };

    // Neither argument supplied: both are named.
    let output = call(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("level (D1)"), "{stderr}");
    assert!(stderr.contains("flags (+4(SP))"), "{stderr}");

    // One supplied: only the other is named, so a reader learns what is left.
    let output = call(&["--reg", "d1=3"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("flags (+4(SP))"), "{stderr}");
    assert!(!stderr.contains("level (D1)"), "{stderr}");

    // All supplied: it runs.
    let output = call(&["--reg", "d1=3", "--arg", "0", "--arg", "0"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // And the refusal is overridable, because an incomplete call is sometimes
    // exactly the experiment.
    let output = call(&["--partial-arguments"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&root);
}

/// An entry no project annotates runs with whatever it was given, as it always
/// did. The check is knowledge being spent, not a new obligation.
#[test]
fn an_unannotated_entry_is_not_subject_to_the_argument_check() {
    let root = signature_project("signature-unannotated");
    let output = amiga_re()
        .args(["call", "prog", "--entry", "0x0"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&root);
}

/// A capture is registered from inside the project, which is the invocation the
/// documentation describes and the one nothing exercised.
///
/// `--file` is project-relative, and the project is discovered upward when no
/// path is given — but discovery answers with the root *document*, so joining
/// `--file` onto it named a path inside a JSON file and every default
/// invocation of this command failed with `Not a directory`. Passing the
/// directory explicitly worked, which is why an operation-level test could not
/// see it.
#[test]
fn a_capture_is_registered_from_inside_the_project_it_belongs_to() {
    let (root, _) = started_project("register-capture");
    fs::write(
        root.join("capture.bin"),
        b"WHAT-THE-ROUTINE-LEFT-IN-RAM!!!!",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let registered = amiga_re()
        .args(["project", "register-capture", "source:frame"])
        .args(["--name", "Frame the draw routine left"])
        .args(["--file", "capture.bin"])
        .args(["--notes", "env.sandbox.call over prog, entry 0x0, 12 steps"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        registered.status.success(),
        "{}{}",
        String::from_utf8_lossy(&registered.stdout),
        String::from_utf8_lossy(&registered.stderr)
    );

    // The size and the digest are the file's, read by the command rather than
    // transcribed, so the document verifies against the bytes it describes.
    let verified = amiga_re()
        .args(["project", "verify"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&verified.stdout);
    assert!(verified.status.success(), "{text}");
    assert!(text.contains("source:frame"), "{text}");

    // And it is recorded as what it is: a capture nothing can re-derive.
    let sources = fs::read_to_string(root.join("analysis/sources.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(sources.contains("\"captured\""), "{sources}");

    // A path climbing out of the project is refused naming the argument the
    // caller wrote, before anything outside the project is read.
    let escaped = amiga_re()
        .args(["project", "register-capture", "source:escape"])
        .args(["--name", "Outside"])
        .args(["--file", "../title.bin"])
        .args(["--notes", "should never be registered"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!escaped.status.success());
    let refusal = String::from_utf8_lossy(&escaped.stderr);
    assert!(refusal.contains("--file"), "{refusal}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

/// A listing refuses a document somebody edited outside the published shape,
/// and does so as a normal error rather than panicking in its renderer.
///
/// `project show` sliced a source digest as `&digest[..16]`. Nothing enforces
/// the bundled schema's `^[0-9a-f]{64}$` through Serde alone, so a shortened
/// digest once panicked the *listing*. Runtime schema validation now stops it
/// at the loader boundary and preserves the stable code and pointer.
#[test]
fn a_listing_refuses_a_digest_the_document_shortened_without_panicking() {
    let (root, _) = started_project("short-digest");
    let path = root.join("analysis/sources.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("{error}"));
    let mut document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}"));
    document["sources"][0]["sha256"] = serde_json::Value::String("abc".to_owned());
    fs::write(
        &path,
        serde_json::to_string_pretty(&document).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let shown = amiga_re()
        .args(["project", "show"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!shown.status.success());
    let error = String::from_utf8_lossy(&shown.stderr);
    assert!(error.contains("DOCUMENT_SCHEMA_VIOLATION"), "{error}");
    assert!(error.contains("/sources/0/sha256"), "{error}");

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

/// `resource update` is the correction half of `resource define`, and nothing
/// exercised it above the `amiga-project` edit engine — not the CLI and not the
/// operation. Correcting a reviewed decode is the ordinary case: the first
/// geometry somebody writes down is usually wrong by a plane or a row.
#[test]
fn a_resource_is_corrected_under_its_own_id_from_the_command_line() {
    let (root, object) = started_project("resource-update");
    let write = |verb: &str, height: &str| {
        amiga_re()
            .args(["project", "resource", verb, "resource:title-logo"])
            .args(["--kind", "image", "--name", "Title logo"])
            .args(["--object", &object, "--offset", "0", "--length", "16"])
            .args(["--parameter", "format=planar", "--parameter", "width=8"])
            .args(["--parameter", &format!("height={height}")])
            .args(["--parameter", "planes=2"])
            .arg(&root)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"))
    };

    let defined = write("define", "4");
    assert!(
        defined.status.success(),
        "{}",
        String::from_utf8_lossy(&defined.stderr)
    );

    // The same id, a corrected height: one record, not two.
    let updated = write("update", "8");
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );

    let document = fs::read_to_string(root.join("analysis/resources/main.json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(document.contains("\"height\": 8"), "{document}");
    assert!(!document.contains("\"height\": 4"), "{document}");

    let shown = amiga_re()
        .args(["project", "show"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&shown.stdout);
    assert!(text.contains("1 resource(s)"), "{text}");

    // And `update` is not a second way to create: an id nothing defined is
    // refused rather than quietly written.
    let unknown = amiga_re()
        .args(["project", "resource", "update", "resource:never-defined"])
        .args(["--kind", "image", "--name", "Nothing"])
        .args(["--object", &object, "--offset", "0", "--length", "16"])
        .args(["--parameter", "format=planar", "--parameter", "width=8"])
        .args(["--parameter", "height=8", "--parameter", "planes=2"])
        .arg(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!unknown.status.success());

    let _ = fs::remove_dir_all(root.parent().unwrap_or(&root));
}

/// `project extract` had no CLI test: the operation was exercised, the command
/// that drives it was not.
///
/// The carrier is the redistributable `volume.adf` the container tests already
/// use, so this runs in a public checkout. What it asserts is the property the
/// command's own help claims — every recovered member becomes an object
/// carrying the selector that reproduces it, so the extracted file is a
/// convenience rather than the truth.
#[test]
fn a_registered_carrier_is_taken_apart_from_the_command_line() {
    let base = std::env::temp_dir().join(format!("amiga-re-extract-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/volume.adf");
    let carrier = base.join("volume.adf");
    fs::copy(&image, &carrier).unwrap_or_else(|error| panic!("{error}"));
    let root = base.join("proj");

    let started = amiga_re()
        .args(["project", "init", "Disk"])
        .arg(&root)
        .arg(&carrier)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );

    let extracted = amiga_re()
        .args(["project", "extract"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&extracted.stdout);
    assert!(
        extracted.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    // Classified as the container it is. This fixture's boot block is zeroed —
    // an ordinary unbootable volume — and an LHA parse stops at the first zero
    // byte, so the archive branch used to claim the file and report
    // `[lha]: 0 member(s)` with `nothing to extract` and a zero exit. Asserting
    // the kind is what keeps the classifier ordered by evidence.
    assert!(text.contains("[adf]"), "{text}");
    assert!(!text.contains("nothing to extract"), "{text}");
    assert!(text.contains("file(s) written"), "{text}");

    // Every extracted member is an object of the project, and `verify` recovers
    // it from the carrier rather than from the file on disk — which is what
    // makes the file a convenience. Deleting one and verifying proves it.
    let objects: Vec<String> = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("object:"))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|id| format!("object:{id}"))
        .collect();
    assert!(!objects.is_empty(), "{text}");

    let verified = amiga_re()
        .args(["project", "verify"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let report = String::from_utf8_lossy(&verified.stdout);
    assert!(
        verified.status.success(),
        "{report}{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    for object in &objects {
        assert!(report.contains(object.as_str()), "{report}");
    }

    let _ = fs::remove_dir_all(&base);
}

/// Copy a directory tree, so a fixture project can be driven from a temporary
/// working directory without the test writing into the repository.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap_or_else(|error| panic!("{error}"));
    for entry in fs::read_dir(from).unwrap_or_else(|error| panic!("{error}")) {
        let entry = entry.unwrap_or_else(|error| panic!("{error}"));
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap_or_else(|error| panic!("{error}"));
        }
    }
}

/// `state snapshot` and `state compare` end to end, which nothing exercised:
/// the operations are covered, the command that drives them was not.
///
/// The whole point of the pair is that a difference is reported in the
/// project's own words — `player_lives`, not "byte 0x22011" — so that is what
/// is asserted. The two refusals on the way are asserted too, because they are
/// what a first-time caller actually meets: a project describing two images
/// will not guess which one a snapshot is of, and a variable in a hunk the
/// request does not place is refused by name rather than read from wherever
/// that hunk's default load map happens to point.
#[test]
fn a_machine_s_state_is_snapshotted_and_compared_in_the_project_s_own_words() {
    let base = std::env::temp_dir().join(format!("amiga-re-state-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/amiga-project/fixtures/contract"),
        &base.join("contract"),
    );
    let project = base.join("contract");

    let mut table = Vec::new();
    for (id, flags) in [(1_u16, 0_u16), (2, 1), (3, 2), (4, 9)] {
        table.extend_from_slice(&id.to_be_bytes());
        table.extend_from_slice(&320_u16.to_be_bytes());
        table.extend_from_slice(&200_u16.to_be_bytes());
        table.extend_from_slice(&flags.to_be_bytes());
    }
    fs::write(base.join("mem-table.bin"), table).unwrap_or_else(|error| panic!("{error}"));
    fs::write(base.join("mem-seed.bin"), [0x12, 0x34, 0x56, 0x78])
        .unwrap_or_else(|error| panic!("{error}"));

    let snapshot = |lives: u8, into: &str| {
        fs::write(base.join("mem-lives.bin"), [0, lives]).unwrap_or_else(|error| panic!("{error}"));
        let output = amiga_re()
            .args(["state", "snapshot"])
            .args(["--image", "image:main-executable"])
            .args(["--hunk-base", "1=0x20000"])
            .args(["--memory", "0x20000=../mem-table.bin"])
            .args(["--memory", "0x40000=../mem-seed.bin"])
            .args(["--memory", "0x22010=../mem-lives.bin"])
            .args(["--reg", "a5=0x40008"])
            .current_dir(&project)
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(base.join(into), &output.stdout).unwrap_or_else(|error| panic!("{error}"));
    };
    snapshot(3, "a.json");
    snapshot(5, "b.json");

    let compared = amiga_re()
        .args(["state", "compare", "a.json", "b.json"])
        .current_dir(&base)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&compared.stdout);
    assert!(
        compared.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&compared.stderr)
    );
    assert!(text.contains("1 of 18 field(s) differ"), "{text}");
    assert!(text.contains("player_lives: 3  |  5"), "{text}");

    // A project with more than one image will not guess which one a snapshot is
    // of, and says so by naming them.
    let unnamed = amiga_re()
        .args(["state", "snapshot"])
        .args(["--memory", "0x40000=../mem-seed.bin"])
        .current_dir(&project)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!unnamed.status.success());
    let refusal = String::from_utf8_lossy(&unnamed.stderr);
    assert!(refusal.contains("image:main-executable"), "{refusal}");

    // And a variable in a hunk the request does not place is refused rather
    // than read from wherever that hunk's default map points.
    let unplaced = amiga_re()
        .args(["state", "snapshot"])
        .args(["--image", "image:main-executable"])
        .args(["--memory", "0x40000=../mem-seed.bin"])
        .current_dir(&project)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!unplaced.status.success());
    let refusal = String::from_utf8_lossy(&unplaced.stderr);
    assert!(refusal.contains("hunk_bases"), "{refusal}");

    let _ = fs::remove_dir_all(&base);
}

/// The canonical one-plane lores screen must be capturable, and it was not.
///
/// `BPLCON0 = $1200` is one bitplane with the colour burst on — the value
/// essentially every real program writes. `amiga_hw::display` read bit 9 as
/// extra half-brite, so `frame capture` refused this frame by naming a mode it
/// was not in, and the display model's own test built its half-brite case from
/// the same wrong bit. Half-brite is six bitplanes, and the six-plane case is
/// asserted in `amiga-hw`; what belongs here is that the ordinary screen
/// reaches a picture at all, through the command a person actually runs.
#[test]
fn an_ordinary_lores_screen_is_captured_rather_than_refused_as_a_mode() {
    let base = std::env::temp_dir().join(format!("amiga-re-frame-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));

    // LEA $DFF000,A5, then the register writes a display needs, then RTS.
    let mut code: Vec<u8> = vec![0x4b, 0xf9, 0x00, 0xdf, 0xf0, 0x00];
    let mut write_word = |value: u16, register: u16| {
        code.extend_from_slice(&[0x3b, 0x7c]);
        code.extend_from_slice(&value.to_be_bytes());
        code.extend_from_slice(&register.to_be_bytes());
    };
    write_word(0x1200, 0x100); // BPLCON0: one plane, colour burst on
    write_word(0x0000, 0x102); // BPLCON1: no scroll
    write_word(0x2c81, 0x08e); // DIWSTRT
    write_word(0xf4c1, 0x090); // DIWSTOP
    write_word(0x0038, 0x092); // DDFSTRT
    write_word(0x00d0, 0x094); // DDFSTOP
    write_word(0x0fff, 0x182); // COLOR01: white
    // MOVE.L #$40000,BPL1PT(A5)
    code.extend_from_slice(&[0x2b, 0x7c]);
    code.extend_from_slice(&0x0004_0000_u32.to_be_bytes());
    code.extend_from_slice(&0x00e0_u16.to_be_bytes());
    code.extend_from_slice(&[0x4e, 0x75]); // RTS

    let program = base.join("display");
    fs::write(&program, hunk_image(&code)).unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .arg("frame")
        .arg("capture")
        .arg(&program)
        .args(["--map", "0x40000:0x2800"])
        .args(["--poke", "0x40000=FFFF0000"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let frame: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}: {text}"));
    assert_eq!(frame["planes"], 1, "{text}");
    assert_eq!(frame["width"], 320, "{text}");
    // The poked word reached the picture: sixteen set pixels, then sixteen
    // clear ones. One byte per pixel, hex-encoded.
    let indices = frame["indices"]
        .as_str()
        .unwrap_or_else(|| panic!("no indices: {text}"));
    assert!(indices.starts_with(&"01".repeat(16)), "{}", &indices[..64]);
    assert!(
        indices[32..64].starts_with(&"00".repeat(16)),
        "{}",
        &indices[..64]
    );

    let _ = fs::remove_dir_all(&base);
}

/// A code hunk ending in `0x0000` is an ordinary executable, and it panicked
/// the process from inside a dependency.
///
/// `0x0000` is the longword padding a HUNK image gives a short code hunk, and
/// it decodes as `ORI.B`, which reads an immediate. `m68000` panics when an
/// extension word cannot be fetched, so sweeping such a hunk to its own end
/// took `disasm linear` and `diff` down with a stack trace over the user's
/// output. Both are asserted here because they reached the same sweep by
/// different routes, and only one of them was noticed.
#[test]
fn a_hunk_ending_in_a_zero_word_is_refused_rather_than_panicking() {
    let base = std::env::temp_dir().join(format!("amiga-re-zeroword-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));

    // MOVEQ #1,D0 ; ADDQ.W #1,D0 ; RTS — six bytes, so the image pads to eight.
    let program = base.join("prog");
    fs::write(&program, hunk_image(&[0x70, 0x01, 0x52, 0x40, 0x4e, 0x75]))
        .unwrap_or_else(|error| panic!("{error}"));
    // The same image with that pad word disturbed, so the two differ inside the
    // hunk and `diff` has a changed range to render.
    let other = base.join("prog2");
    let mut bytes = fs::read(&program).unwrap_or_else(|error| panic!("{error}"));
    let last = bytes.len() - 6;
    bytes[last] = 0xff;
    fs::write(&other, &bytes).unwrap_or_else(|error| panic!("{error}"));

    let swept = amiga_re()
        .args(["disasm", "linear"])
        .arg(&program)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let refusal = String::from_utf8_lossy(&swept.stderr);
    assert!(!refusal.contains("panicked"), "{refusal}");
    // Refused by name: the instruction really does want a word that is not
    // there, and nothing is completed out of the padding that makes the decode
    // survivable.
    assert!(
        refusal.contains("extends past the requested end"),
        "{refusal}"
    );

    let compared = amiga_re()
        .arg("diff")
        .arg(&program)
        .arg(&other)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&compared.stdout);
    let notes = String::from_utf8_lossy(&compared.stderr);
    assert!(!notes.contains("panicked"), "{notes}");
    assert!(compared.status.success(), "{text}{notes}");
    assert!(text.contains("1 changed range(s)"), "{text}");

    let _ = fs::remove_dir_all(&base);
}

/// A listing's provenance header has to come before the listing.
///
/// `boot disasm` collected its header — what this is, which file, which digest,
/// what the annotation marks mean — into a document, printed the disassembly
/// separately, and then printed the document. The header therefore arrived
/// several hundred lines *below* what it introduces, and a reader going through
/// `head` never saw it at all. The same shape had put `copper patch-xref
/// --apply`'s heading under its own listing.
#[test]
fn a_listing_header_precedes_the_listing_it_introduces() {
    let image = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/volume.adf");
    let output = amiga_re()
        .args(["boot", "disasm"])
        .arg(&image)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let header = text
        .find("; Source SHA-256:")
        .unwrap_or_else(|| panic!("no provenance header:\n{text}"));
    let listing = text
        .find("L00000000:")
        .unwrap_or_else(|| panic!("no listing:\n{text}"));
    assert!(
        header < listing,
        "the header is below the listing it introduces:\n{text}"
    );
    // And it is genuinely at the top, not merely before one line of listing.
    assert!(text.starts_with("; Boot code disassembly"), "{text}");
}

/// A refusal must describe what the command was doing.
///
/// Reading a source through a symbolic link is refused so that a resolver
/// cannot be pointed outside the root it serves — deliberate, and unchanged.
/// What was wrong is that the refusal said "refusing to write through symbolic
/// link" for `adf list`, which writes nothing: a reader was told the toolkit
/// had tried to write, and sent looking for an output path they never gave.
#[test]
fn a_symlinked_source_is_refused_without_claiming_a_write() {
    let base = std::env::temp_dir().join(format!("amiga-re-symlink-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let image = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/amiga-operations/fixtures/volume.adf");
    let link = base.join("linked.adf");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&image, &link).unwrap_or_else(|error| panic!("{error}"));
    #[cfg(not(unix))]
    return;

    let output = amiga_re()
        .args(["adf", "list"])
        .arg(&link)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success());
    let refusal = String::from_utf8_lossy(&output.stderr);
    assert!(refusal.contains("symbolic link"), "{refusal}");
    assert!(
        !refusal.contains("write"),
        "a read refusal claims a write:\n{refusal}"
    );

    let _ = fs::remove_dir_all(&base);
}
