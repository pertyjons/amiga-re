//! Every operation's bundled payload and envelope schemas, checked against responses the
//! router actually produced.
//!
//! The per-operation schemas are what a JSON consumer reads: `operations schema`
//! serves them, they are compiled into the binary, and until this file existed
//! they were validated against nothing. A field added to a Rust result and not to
//! its schema left the two describing different APIs while every test passed —
//! which is exactly how `status` reached `VerifiedEntity` before the schema knew
//! about it.
//!
//! Two properties, and both matter:
//!
//! **Exhaustive over the catalog.** [`representative`] matches on
//! [`OperationName`] with no wildcard, so a new operation cannot be added without
//! deciding how this test exercises it.
//!
//! **No silent skip.** An operation this build cannot yet produce a request for
//! must be named in [`UNCOVERED`] with its reason, and the second test proves the
//! list and the reality agree in *both* directions. A sweep that quietly covered
//! half the catalog would be the failure being fixed, not a smaller version of
//! it.

use std::path::{Path, PathBuf};

use amiga_operations::{
    AddressReferencesArguments, AddressResolveArguments, AdfListArguments, AudioSampleArguments,
    AudioSampleExportArguments, BitmapCompareArguments, BitmapCompareExportArguments,
    BitmapDecodeArguments, BitmapDetectArguments, BitmapExportArguments, BootInfoArguments,
    BootTraceArguments, BootTraceExportArguments, CarveArguments, CodeCallgraphArguments,
    CodeDisassembleArguments, CodeFactsArguments, CodeFixedPointArguments, CodeGlobalsArguments,
    ComparedBitmap, ContainerExtractArguments, CopperDecodeArguments, CopperReferencesArguments,
    CopperScanArguments, ExecutionContext, ExecutionMode, FilesystemDestinationResolver,
    FilesystemSourceResolver, FrameCaptureArguments, FrameCaptureExportArguments,
    HardwareRegisterListArguments, HunkAnchor, HunkDiffArguments, HunkDiffExportArguments,
    HunkListArguments, HunkNormalizeArguments, HunkNormalizeExportArguments, IlbmDecodeArguments,
    LhaListArguments, ManifestArguments, ManifestExportArguments, ModuleArguments,
    ModuleExportArguments, ModuleScanArguments, OperationName, OperationRequestDocument,
    PaletteArguments, PaletteExportArguments, PaletteScanArguments, PcmArguments,
    PcmExportArguments, PcmScanArguments, PointerScanArguments, PowerpackerArguments,
    PowerpackerExportArguments, ProjectAnnotationsArguments, ProjectArguments, ProjectEdit,
    ProjectEditArguments, ProjectInventoryArguments, ProjectLocator, ProjectMigrateArguments,
    RegisterReferencesArguments, RequestEnvelope, RleXorArguments, RleXorExportArguments, Router,
    SandboxCallArguments, SandboxCallExportArguments, SandboxCompareArguments,
    SandboxMatrixArguments, SandboxMatrixCase, SandboxMatrixExportArguments, SandboxRunArguments,
    SourceReadArguments, SourceSurveyArguments, StateCompareArguments, StateRegion,
    StateSnapshotArguments, StringsScanArguments, TableDecodeArguments,
};

/// The shared schemas a per-operation schema's `$ref`s resolve against.
///
/// Built offline from what the crate compiles in. A validator that reached for
/// `https://amiga-re.invalid/...` over the network would be neither reproducible
/// nor, given that host, possible.
fn registry() -> jsonschema::Registry<'static> {
    let parse = |schema: &str| -> serde_json::Value {
        serde_json::from_str(schema)
            .unwrap_or_else(|error| panic!("a bundled schema parses: {error}"))
    };
    let mut documents: Vec<(String, serde_json::Value)> =
        amiga_operations::descriptor::schemas::ALL
            .iter()
            .map(|(_, schema)| {
                let value = parse(schema);
                (schema_id(&value), value)
            })
            .collect();
    // The response envelope references every per-operation result shape, so the
    // registry is not resolvable without them.
    for described in amiga_operations::catalog() {
        for schema in [described.request_schema, described.response_schema] {
            let value = parse(schema);
            documents.push((schema_id(&value), value));
        }
    }
    jsonschema::Registry::new()
        .extend(documents)
        .unwrap_or_else(|error| panic!("every bundled schema has a usable $id: {error}"))
        .prepare()
        .unwrap_or_else(|error| panic!("the bundled schemas form a resolvable set: {error}"))
}

fn schema_id(schema: &serde_json::Value) -> String {
    schema["$id"]
        .as_str()
        .unwrap_or_else(|| panic!("every bundled schema declares an $id: {schema}"))
        .to_owned()
}

/// The operations that have no representative request yet, and why.
///
/// Empty, and meant to stay that way. An entry here is a stated hole in the
/// sweep; the test below fails if it names an operation that is in fact covered,
/// so the list cannot rot into a permanent excuse.
const UNCOVERED: &[(OperationName, &str)] = &[];

/// One directory serving every source the sweep needs, plus an output root.
///
/// A filesystem resolver rather than an in-memory one because the project
/// operations need a *directory*: they resolve a project root under the
/// resolver's root, and an in-memory resolver has none.
fn workspace() -> PathBuf {
    let base =
        std::env::temp_dir().join(format!("amiga-operations-schemas-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("out")).unwrap_or_else(|error| panic!("{error}"));

    // The two checked-in fixtures, copied so every source the sweep names lives
    // under one root.
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    for name in ["sample.bin", "volume.adf"] {
        std::fs::copy(fixtures.join(name), base.join(name))
            .unwrap_or_else(|error| panic!("{name} is readable: {error}"));
    }

    std::fs::write(base.join("beep.8svx"), svx()).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("title.ilbm"), ilbm()).unwrap_or_else(|error| panic!("{error}"));
    // A legacy config for `project.migrate`, which converts one rather than
    // consulting it.
    // A legacy config for `project.migrate`, which converts one rather than
    // consulting it.
    std::fs::write(base.join("amiga-re.toml"), "[base]\norigin = 4096\n")
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("a.hunk"), hunk(0x4e75)).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("display.hunk"), display_hunk())
        .unwrap_or_else(|error| panic!("{error}"));
    // Two index images differing in one pixel, so the comparison has something
    // to report and something to agree about.
    let mut frame = vec![0_u8; 32];
    frame[5] = 1;
    std::fs::write(base.join("frame-a.idx"), &frame).unwrap_or_else(|error| panic!("{error}"));
    frame[5] = 0;
    frame[6] = 1;
    std::fs::write(base.join("frame-b.idx"), &frame).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("b.hunk"), hunk(0x4e71)).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("archive.lha"), lha()).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("packed.pp"), powerpacker()).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("packed.rle"), rle_xor()).unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("song.mod"), tracker_module())
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("compact.hunk"), compact_hunk())
        .unwrap_or_else(|error| panic!("{error}"));

    // Two golden records for `env.sandbox.compare`, produced by *running*
    // `env.sandbox.call` rather than hand-written. A hand-written record would
    // be this test's idea of the format rather than the format, and the whole
    // point of the comparison refusing a record it cannot read is that the two
    // must not be allowed to drift apart.
    for (name, seed) in [("record-a.json", 1_u32), ("record-b.json", 2_u32)] {
        let sources = FilesystemSourceResolver::new(base.clone());
        let context = ExecutionContext::new(&sources);
        let mut run = SandboxRunArguments::new("a.hunk").with_maximum_steps(16);
        run.data_registers = Some([seed, 0, 0, 0, 0, 0, 0, 0]);
        run.trace = true;
        let outcome = Router::execute(
            &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(
                SandboxCallArguments::new(run),
            )),
            &context,
        );
        let record = outcome
            .env_sandbox_call()
            .unwrap_or_else(|| panic!("a golden record: {:?}", outcome.diagnostics));
        std::fs::write(
            base.join(name),
            serde_json::to_vec_pretty(record).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    // The project format's contract fixture, so `project.check` and
    // `project.verify` answer about a real project rather than an empty one.
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../amiga-project/fixtures/contract"),
        &base.join("contract"),
    );

    // The three ranges of machine memory the contract project's globals live
    // in, so `analysis.state.snapshot` decodes a real project's variables
    // rather than an invented one's.
    std::fs::write(base.join("mem-table.bin"), vec![0_u8; 32])
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("mem-seed.bin"), [0x12, 0x34, 0x56, 0x78])
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(base.join("mem-lives.bin"), [0xff, 0xfe])
        .unwrap_or_else(|error| panic!("{error}"));

    // Two snapshot documents for `analysis.state.compare`, produced by *running*
    // the snapshot rather than hand-written — for the reason the golden records
    // above are: a hand-written one would be this test's idea of the format.
    for (name, lives) in [
        ("state-a.json", [0xff_u8, 0xfe]),
        ("state-b.json", [0x00, 0x03]),
    ] {
        std::fs::write(base.join("mem-lives.bin"), lives).unwrap_or_else(|error| panic!("{error}"));
        let sources = FilesystemSourceResolver::new(base.clone());
        let context = ExecutionContext::new(&sources);
        let mut envelope = RequestEnvelope::read(OperationRequestDocument::AnalysisStateSnapshot(
            state_snapshot_arguments(),
        ));
        envelope.project = Some(ProjectLocator::Path {
            path: "contract".to_owned(),
        });
        let outcome = Router::execute(&envelope, &context);
        let snapshot = outcome
            .analysis_state_snapshot()
            .unwrap_or_else(|| panic!("a state snapshot: {:?}", outcome.diagnostics));
        std::fs::write(
            base.join(name),
            serde_json::to_vec_pretty(snapshot).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }
    base
}

/// Two 8x4 index images that differ in one pixel.
///
/// Both sides are read as one palette index per byte, which is the shape a
/// decoded frame's indices have — the case the comparison exists for.
fn bitmap_compare_arguments() -> BitmapCompareArguments {
    BitmapCompareArguments::new(
        ComparedBitmap::new("frame-a.idx", 8, 4).with_palette(vec![0x0000, 0x0f00]),
        ComparedBitmap::new("frame-b.idx", 8, 4).with_palette(vec![0x0000, 0x0f00]),
    )
}

/// A capture of the display `display.hunk` programs.
///
/// The routine writes the registers a display needs and returns, so the frame is
/// reconstructed from a machine that really configured one rather than from a
/// register file this test wrote by hand.
fn frame_capture_arguments() -> FrameCaptureArguments {
    FrameCaptureArguments::new(
        SandboxCallArguments::new(
            SandboxRunArguments::new("display.hunk")
                .at_origin(0x2_0000)
                .with_maximum_steps(64),
        )
        .with_custom_chips(amiga_operations::CustomChips::default()),
    )
}

/// The contract project's machine, as this sweep lays it out.
///
/// Hunk 1 is placed away from the project's own default load map on purpose:
/// under that map the level table and `player_lives` overlap, which the snapshot
/// refuses. The layout is the *run's* to state, and this one states a run in
/// which the two are distinct.
fn state_snapshot_arguments() -> StateSnapshotArguments {
    let mut registers = amiga_operations::SandboxRegisters {
        d: [0; 8],
        a: [0; 7],
        usp: 0,
        ssp: 0,
        pc: 0,
        sr: 0x2700,
    };
    registers.a[5] = 0x0004_0008;
    StateSnapshotArguments::new(vec![
        StateRegion::new(0x0003_0000, "mem-table.bin"),
        StateRegion::new(0x0004_0000, "mem-seed.bin"),
        StateRegion::new(0x0002_2010, "mem-lives.bin"),
    ])
    .of_image("image:main-executable")
    .with_registers(registers)
    .with_hunk_base(1, 0x0003_0000)
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|error| panic!("{error}"));
    for entry in std::fs::read_dir(from).unwrap_or_else(|error| panic!("{error}")) {
        let entry = entry.unwrap_or_else(|error| panic!("{error}"));
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap_or_else(|error| panic!("{error}"));
        }
    }
}

/// A one-hunk image whose code programs a one-bitplane display and returns.
///
/// Every instruction is `MOVE.W #value,($DFFxxx).L`, which is what a real
/// initialization writes and what makes the capture's register state come from
/// executing code rather than from a fixture's idea of one. The bitplane points
/// at the hunk itself, which is mapped — so the picture is the program's own
/// bytes, which is a perfectly good picture for a schema to be checked against.
fn display_hunk() -> Vec<u8> {
    let mut code = Vec::new();
    for (offset, value) in [
        (0x100_u16, 0x1000_u16), // BPLCON0: one bitplane
        (0x08e, 0x9481),         // DIWSTRT: from raster line 148
        (0x090, 0x96c1),         // DIWSTOP: to 150, so two lines
        (0x092, 0x0038),         // DDFSTRT
        (0x094, 0x0038),         // DDFSTOP: one fetch word, so sixteen pixels
        (0x0e0, 0x0002),         // BPL1PTH
        (0x0e2, 0x0000),         // BPL1PTL: the hunk itself
        (0x182, 0x0f00),         // COLOR01
        (0x096, 0x8300),         // DMACON: set DMAEN and BPLEN
    ] {
        code.extend_from_slice(&0x33fc_u16.to_be_bytes());
        code.extend_from_slice(&value.to_be_bytes());
        code.extend_from_slice(&(0x00df_f000_u32 | u32::from(offset)).to_be_bytes());
    }
    code.extend_from_slice(&0x4e75_u16.to_be_bytes());
    hunk_with(&code)
}

/// A minimal 8SVX: a `VHDR` and a `BODY`, which is everything the format
/// requires.
///
/// It deliberately carries no `NAME`, so the sweep also proves that the
/// `name` the schema declares — "empty when the file carries none" — is a
/// string the response really can produce.
/// A minimal one-plane ILBM: an 8x2 uncompressed bitmap with a two-entry CMAP.
fn ilbm() -> Vec<u8> {
    let mut bmhd = Vec::new();
    bmhd.extend_from_slice(&8_u16.to_be_bytes()); // width
    bmhd.extend_from_slice(&2_u16.to_be_bytes()); // height
    bmhd.extend_from_slice(&0_u16.to_be_bytes()); // x
    bmhd.extend_from_slice(&0_u16.to_be_bytes()); // y
    bmhd.push(1); // planes
    bmhd.push(0); // masking: none
    bmhd.push(0); // compression: none
    bmhd.push(0); // pad
    bmhd.extend_from_slice(&0_u16.to_be_bytes()); // transparent colour
    bmhd.push(1); // x aspect
    bmhd.push(1); // y aspect
    bmhd.extend_from_slice(&8_u16.to_be_bytes()); // page width
    bmhd.extend_from_slice(&2_u16.to_be_bytes()); // page height

    let cmap = vec![0, 0, 0, 0xff, 0xff, 0xff];
    // One plane, eight pixels a row, two rows. A row is word-aligned, so each
    // is two bytes with the second unused.
    let body = vec![0b1010_1010, 0, 0b0101_0101, 0];

    let mut chunks = Vec::new();
    for (id, data) in [(b"BMHD", bmhd), (b"CMAP", cmap), (b"BODY", body)] {
        chunks.extend_from_slice(id);
        chunks.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunks.extend_from_slice(&data);
        if !data.len().is_multiple_of(2) {
            chunks.push(0);
        }
    }

    let mut form = Vec::new();
    form.extend_from_slice(b"FORM");
    form.extend_from_slice(&((chunks.len() + 4) as u32).to_be_bytes());
    form.extend_from_slice(b"ILBM");
    form.extend_from_slice(&chunks);
    form
}

fn svx() -> Vec<u8> {
    let pcm: Vec<u8> = (0..64_u8).collect();
    let mut vhdr = Vec::new();
    vhdr.extend_from_slice(&(pcm.len() as u32).to_be_bytes()); // one-shot frames
    vhdr.extend_from_slice(&0_u32.to_be_bytes()); // repeat
    vhdr.extend_from_slice(&0_u32.to_be_bytes()); // samples per cycle
    vhdr.extend_from_slice(&8000_u16.to_be_bytes()); // frames per second
    vhdr.push(1); // octaves
    vhdr.push(0); // compression
    vhdr.extend_from_slice(&0x0001_0000_u32.to_be_bytes()); // volume

    let mut body = Vec::new();
    for (id, data) in [(b"VHDR", vhdr), (b"BODY", pcm)] {
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

/// A minimal HUNK executable: one four-byte code hunk holding `instruction`.
///
/// The word layout is the one `amiga-hunk`'s own `parses_a_minimal_code_hunk`
/// test pins, so a change to the parser's expectations breaks that test rather
/// than silently making this one vacuous.
fn hunk(instruction: u16) -> Vec<u8> {
    hunk_with(&instruction.to_be_bytes())
}

/// A one-hunk image whose CODE hunk holds `code`, padded to a longword.
fn hunk_with(code: &[u8]) -> Vec<u8> {
    let longwords = code.len().div_ceil(4) as u32;
    let mut bytes = Vec::new();
    for word in [
        0x03f3_u32, // HUNK_HEADER
        0,          // no resident library names
        1,          // one hunk in the table
        0,          // first hunk
        0,          // last hunk
        longwords,  // allocation, in longwords
        0x03e9,     // HUNK_CODE
        longwords,  // size, in longwords
    ] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(code);
    bytes.resize(bytes.len() + (longwords as usize * 4 - code.len()), 0);
    bytes.extend_from_slice(&0x03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// A level-0 LHA archive with one stored member.
///
/// The CRC-16 comes from `amiga_lha::crc16` rather than a second implementation:
/// a hand-rolled one that agreed with a hand-rolled reader would prove nothing,
/// and that function is checked against the standard vector in its own crate.
fn lha() -> Vec<u8> {
    let payload = b"stored member bytes";
    let name = "readme.txt";
    let mut header = Vec::new();
    header.extend_from_slice(b"-lh0-");
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // original
    header.extend_from_slice(&0_u32.to_le_bytes()); // timestamp
    header.push(0x20); // attribute
    header.push(0); // header level
    header.push(name.len() as u8);
    header.extend_from_slice(name.as_bytes());
    header.extend_from_slice(&amiga_lha::crc16(payload).to_le_bytes());

    let checksum = header
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    let mut bytes = vec![header.len() as u8, checksum];
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(payload);
    bytes.push(0); // the terminating zero-length header
    bytes
}

/// A headerless PowerPacker stream decoding to `ABC` under the `[9,10,12,13]`
/// mode table.
///
/// Built here rather than checked in because the format is a bitstream read
/// backwards: a blob would be unreadable, and this states the fields it holds.
fn powerpacker() -> Vec<u8> {
    // One literal run of three bytes, written most-significant bit first, then
    // the trailer carrying the output size and the initial bit skip.
    let fields: &[(u32, u32)] = &[
        (0, 1),
        (2, 2),
        (u32::from(b'C'), 8),
        (u32::from(b'B'), 8),
        (u32::from(b'A'), 8),
    ];
    let mut bits = Vec::new();
    for &(value, count) in fields {
        for shift in (0..count).rev() {
            bits.push((value >> shift) & 1);
        }
    }
    bits.resize(bits.len().next_multiple_of(32), 0);
    let mut words = Vec::new();
    for chunk in bits.as_chunks::<32>().0.iter() {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |word, (index, bit)| word | (bit << index));
        words.push(word.to_be_bytes());
    }
    let mut packed = Vec::new();
    for word in words.into_iter().rev() {
        packed.extend_from_slice(&word);
    }
    packed.extend_from_slice(&(3_u32 << 8).to_be_bytes());
    packed
}

/// A position-XOR RLE stream with a four-byte leading size field.
///
/// `AB` followed by a run of four `Z`, so the decode exercises both the literal
/// and the escape path, and the size field agrees with what comes out.
fn rle_xor() -> Vec<u8> {
    const MARKER: u8 = 0x90;
    let mut stream = Vec::new();
    stream.extend_from_slice(&6_u32.to_be_bytes()); // decoded length
    stream.extend_from_slice(b"AB");
    stream.extend_from_slice(&[MARKER, 3, b'Z']); // count is the extra repeats
    // Layer 1 is position XOR, applied over the whole stream including the size
    // field, so the fixture has to carry it too.
    stream
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ (index as u8))
        .collect()
}

/// A one-file loader image whose relocations use the compact encoding.
///
/// One four-longword CODE hunk with three relocations at 0, 4, and 8 — the
/// second reached by a short delta and the third by the 24-bit escape. Nothing
/// in the file says which encoding it uses, which is why the operation refuses
/// an image that already parses rather than guessing.
fn compact_hunk() -> Vec<u8> {
    let mut image = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 4] {
        image.extend_from_slice(&value.to_be_bytes());
    }
    image.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    image.extend_from_slice(&4_u32.to_be_bytes());
    image.extend_from_slice(&[0; 16]);
    image.extend_from_slice(&0x0000_03ec_u32.to_be_bytes()); // HUNK_RELOC32
    image.extend_from_slice(&3_u16.to_be_bytes()); // count
    image.extend_from_slice(&0_u16.to_be_bytes()); // target hunk
    image.extend_from_slice(&0_u32.to_be_bytes()); // first offset
    image.push(2); // short delta: +4
    image.extend_from_slice(&[0, 0, 0, 2]); // escaped delta: +4
    image.push(0xa5); // alignment byte, deliberately not zero
    image.extend_from_slice(&0_u16.to_be_bytes()); // end of groups
    image.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    image
}

/// A minimal four-channel ProTracker module: one pattern, no sample data.
///
/// 1084 header bytes — title, 31 sample slots, song length, order table, and
/// the `M.K.` signature at 1080 — followed by one 1024-byte pattern. Every
/// sample slot is left at zero length, which is a real thing a module does and
/// is exactly what the decode must still report rather than drop.
fn tracker_module() -> Vec<u8> {
    let mut module = vec![0_u8; 1084];
    module[0..5].copy_from_slice(b"TITLE");
    module[950] = 1; // song length, which the parser requires to be 1..=128
    module[1080..1084].copy_from_slice(b"M.K.");
    // One pattern: 64 rows x 4 channels x 4 bytes.
    module.extend(std::iter::repeat_n(0_u8, 64 * 4 * 4));
    module
}

/// A request that makes `name` produce a result, or `None` when this build has
/// no way to ask it anything.
///
/// Exhaustive on purpose. A new operation stops this compiling until someone
/// decides whether the sweep can exercise it.
fn representative(name: OperationName) -> Option<RequestEnvelope> {
    let arguments = match name {
        OperationName::SourceRead => {
            OperationRequestDocument::SourceRead(SourceReadArguments::new("sample.bin"))
        }
        OperationName::SourceSurvey => {
            OperationRequestDocument::SourceSurvey(SourceSurveyArguments::new("sample.bin"))
        }
        OperationName::ContainerAdfList => {
            OperationRequestDocument::ContainerAdfList(AdfListArguments::new("volume.adf"))
        }
        OperationName::GraphicsBitmapDecode => OperationRequestDocument::GraphicsBitmapDecode(
            BitmapDecodeArguments::new("sample.bin", 8, 4, 1),
        ),
        OperationName::ContainerAdfExtract => OperationRequestDocument::ContainerAdfExtract(
            ContainerExtractArguments::new("volume.adf", "out/adf"),
        ),
        OperationName::ContainerLhaExtract => OperationRequestDocument::ContainerLhaExtract(
            ContainerExtractArguments::new("archive.lha", "out/lha"),
        ),
        OperationName::ContainerLhaList => {
            OperationRequestDocument::ContainerLhaList(LhaListArguments::new("archive.lha"))
        }
        OperationName::GraphicsBitmapExport => {
            OperationRequestDocument::GraphicsBitmapExport(BitmapExportArguments::new(
                BitmapDecodeArguments::new("sample.bin", 8, 4, 1),
                "out/png",
            ))
        }
        OperationName::ProjectInventory => {
            OperationRequestDocument::ProjectInventory(ProjectInventoryArguments::new("contract"))
        }
        OperationName::ProjectAnnotations => OperationRequestDocument::ProjectAnnotations(
            ProjectAnnotationsArguments::image("image:main-executable"),
        ),
        OperationName::ProjectDescribe => {
            OperationRequestDocument::ProjectDescribe(ProjectArguments::default())
        }
        OperationName::GraphicsBitmapCompare => {
            OperationRequestDocument::GraphicsBitmapCompare(bitmap_compare_arguments())
        }
        OperationName::GraphicsBitmapCompareExport => {
            OperationRequestDocument::GraphicsBitmapCompareExport(
                BitmapCompareExportArguments::new(bitmap_compare_arguments(), "out/compare"),
            )
        }
        OperationName::EnvFrameCapture => {
            OperationRequestDocument::EnvFrameCapture(frame_capture_arguments())
        }
        OperationName::EnvFrameCaptureExport => OperationRequestDocument::EnvFrameCaptureExport(
            FrameCaptureExportArguments::new(frame_capture_arguments(), "out/frame"),
        ),
        OperationName::AnalysisStateSnapshot => {
            OperationRequestDocument::AnalysisStateSnapshot(state_snapshot_arguments())
        }
        OperationName::AnalysisStateCompare => {
            OperationRequestDocument::AnalysisStateCompare(StateCompareArguments::of([
                "state-a.json",
                "state-b.json",
            ]))
        }
        OperationName::ProjectCheck => {
            OperationRequestDocument::ProjectCheck(ProjectArguments::default())
        }
        OperationName::ProjectVerify => {
            OperationRequestDocument::ProjectVerify(ProjectArguments::default())
        }
        OperationName::AnalysisHunkDiff => {
            OperationRequestDocument::AnalysisHunkDiff(HunkDiffArguments::new("a.hunk", "b.hunk"))
        }
        OperationName::AnalysisHunkDiffExport => OperationRequestDocument::AnalysisHunkDiffExport(
            HunkDiffExportArguments::new(HunkDiffArguments::new("a.hunk", "b.hunk"), "out/diff"),
        ),
        OperationName::SourceCarve => OperationRequestDocument::SourceCarve(CarveArguments::new(
            "sample.bin",
            0,
            16,
            "out/carved",
        )),
        OperationName::AnalysisTableDecode => OperationRequestDocument::AnalysisTableDecode(
            TableDecodeArguments::new("sample.bin", "u16,u16", 2),
        ),
        OperationName::AnalysisTableSummarize => OperationRequestDocument::AnalysisTableSummarize(
            amiga_operations::TableSummarizeArguments::new(
                ["sample.bin", "sample.bin"],
                "u16,u16",
                2,
            ),
        ),
        OperationName::AudioSampleDecode => {
            OperationRequestDocument::AudioSampleDecode(AudioSampleArguments::new("beep.8svx"))
        }
        OperationName::AudioSampleExport => OperationRequestDocument::AudioSampleExport(
            AudioSampleExportArguments::new(AudioSampleArguments::new("beep.8svx"), "out/wav"),
        ),
        OperationName::CompressPowerpackerDecode => {
            OperationRequestDocument::CompressPowerpackerDecode(PowerpackerArguments::new(
                "packed.pp",
                [9, 10, 12, 13],
            ))
        }
        OperationName::CompressPowerpackerExport => {
            OperationRequestDocument::CompressPowerpackerExport(PowerpackerExportArguments::new(
                PowerpackerArguments::new("packed.pp", [9, 10, 12, 13]),
                "out/unpacked",
            ))
        }
        OperationName::CompressRleXorDecode => OperationRequestDocument::CompressRleXorDecode(
            RleXorArguments::new("packed.rle", 0x90).with_size_field(4, false),
        ),
        OperationName::CompressRleXorExport => {
            OperationRequestDocument::CompressRleXorExport(RleXorExportArguments::new(
                RleXorArguments::new("packed.rle", 0x90).with_size_field(4, false),
                "out/unpacked",
            ))
        }
        OperationName::AudioPcmDecode => {
            OperationRequestDocument::AudioPcmDecode(PcmArguments::new("sample.bin", 0, 64, 8287))
        }
        OperationName::AudioPcmExport => OperationRequestDocument::AudioPcmExport(
            PcmExportArguments::new(PcmArguments::new("sample.bin", 0, 64, 8287), "out/pcm"),
        ),
        OperationName::AudioModuleDecode => {
            OperationRequestDocument::AudioModuleDecode(ModuleArguments::new("song.mod"))
        }
        OperationName::AudioModuleExport => OperationRequestDocument::AudioModuleExport(
            ModuleExportArguments::new(ModuleArguments::new("song.mod"), "out/module"),
        ),
        OperationName::AnalysisHunkNormalize => OperationRequestDocument::AnalysisHunkNormalize(
            HunkNormalizeArguments::new("compact.hunk"),
        ),
        OperationName::AnalysisHunkNormalizeExport => {
            OperationRequestDocument::AnalysisHunkNormalizeExport(
                HunkNormalizeExportArguments::new(
                    HunkNormalizeArguments::new("compact.hunk"),
                    "out/normalized",
                ),
            )
        }
        OperationName::ProvenanceManifest => {
            OperationRequestDocument::ProvenanceManifest(ManifestArguments::new("sample.bin"))
        }
        OperationName::ProvenanceManifestExport => {
            OperationRequestDocument::ProvenanceManifestExport(ManifestExportArguments::new(
                ManifestArguments::new("sample.bin"),
                "out/manifest",
            ))
        }
        OperationName::GraphicsPaletteDecode => OperationRequestDocument::GraphicsPaletteDecode(
            PaletteArguments::new("sample.bin", 16).at_offset(64),
        ),
        OperationName::GraphicsPaletteExport => {
            OperationRequestDocument::GraphicsPaletteExport(PaletteExportArguments::new(
                PaletteArguments::new("sample.bin", 16).at_offset(64),
                "out/palette",
            ))
        }
        OperationName::EnvSandboxCall => OperationRequestDocument::EnvSandboxCall(
            SandboxCallArguments::new(SandboxRunArguments::new("a.hunk").with_maximum_steps(16)),
        ),
        // One case with one export, which is the smallest sweep that writes
        // anything at all.
        OperationName::EnvSandboxMatrixExport => {
            OperationRequestDocument::EnvSandboxMatrixExport(SandboxMatrixExportArguments::new(
                SandboxMatrixArguments::new(
                    SandboxCallArguments::new(
                        SandboxRunArguments::new("a.hunk")
                            .at_origin(0x2_0000)
                            .with_maximum_steps(16),
                    )
                    // The hunk's own bytes, so the range is inside something
                    // that is mapped whatever the layout defaults to.
                    .with_memory_exports(vec![
                        amiga_operations::MemoryExport {
                            address: 0x2_0000,
                            length: 4,
                            name: "probe".to_owned(),
                        },
                    ]),
                    vec![SandboxMatrixCase::new("only")],
                ),
                "out/sweep",
            ))
        }
        // Two cases that differ only in what D0 is handed, which is the smallest
        // thing a matrix can be and still be one.
        OperationName::EnvSandboxCompare => {
            OperationRequestDocument::EnvSandboxCompare(SandboxCompareArguments::of([
                "record-a.json",
                "record-b.json",
            ]))
        }
        OperationName::EnvSandboxSlice => {
            OperationRequestDocument::EnvSandboxSlice(amiga_operations::SandboxSliceArguments::new(
                SandboxCallArguments::new(
                    SandboxRunArguments::new("a.hunk").with_maximum_steps(16),
                ),
                amiga_operations::SliceSeedArgument::Register {
                    register: "d0".to_owned(),
                },
            ))
        }
        // The same two steps, checkpointing four bytes of the hunk each, which is
        // the smallest timeline that writes anything at all.
        OperationName::EnvSandboxTimelineExport => {
            OperationRequestDocument::EnvSandboxTimelineExport(
                amiga_operations::SandboxTimelineExportArguments::new(
                    amiga_operations::SandboxTimelineArguments::new(
                        SandboxCallArguments::new(
                            SandboxRunArguments::new("a.hunk")
                                .at_origin(0x2_0000)
                                .with_maximum_steps(16),
                        ),
                        vec![
                            amiga_operations::TimelineStep::call("first", 0).with_checkpoints(
                                vec![amiga_operations::MemoryExport {
                                    address: 0x2_0000,
                                    length: 4,
                                    name: "probe".to_owned(),
                                }],
                            ),
                        ],
                    )
                    .with_maximum_total_steps(64),
                    "out/timeline",
                ),
            )
        }
        OperationName::EnvSandboxTimeline => OperationRequestDocument::EnvSandboxTimeline(
            amiga_operations::SandboxTimelineArguments::new(
                SandboxCallArguments::new(
                    SandboxRunArguments::new("a.hunk").with_maximum_steps(16),
                ),
                vec![
                    amiga_operations::TimelineStep::call("first", 0),
                    amiga_operations::TimelineStep::call("second", 0),
                ],
            )
            .with_maximum_total_steps(64),
        ),
        OperationName::EnvSandboxMatrix => OperationRequestDocument::EnvSandboxMatrix(
            SandboxMatrixArguments::new(
                SandboxCallArguments::new(
                    SandboxRunArguments::new("a.hunk").with_maximum_steps(16),
                ),
                vec![
                    SandboxMatrixCase::new("zero").with_data_registers([0; 8]),
                    SandboxMatrixCase::new("one").with_data_registers([1, 0, 0, 0, 0, 0, 0, 0]),
                ],
            )
            .with_maximum_total_steps(64),
        ),
        OperationName::EnvSandboxCallExport => {
            OperationRequestDocument::EnvSandboxCallExport(SandboxCallExportArguments::new(
                SandboxCallArguments::new(
                    SandboxRunArguments::new("a.hunk").with_maximum_steps(16),
                ),
                "out/golden",
            ))
        }
        OperationName::AnalysisStringsScan => {
            OperationRequestDocument::AnalysisStringsScan(StringsScanArguments::new("sample.bin"))
        }
        OperationName::AnalysisHunkList => {
            OperationRequestDocument::AnalysisHunkList(HunkListArguments::new("a.hunk"))
        }
        OperationName::AnalysisAddressResolve => OperationRequestDocument::AnalysisAddressResolve(
            AddressResolveArguments::new(0x1042, 0x1000).anchored_on(HunkAnchor::new("a.hunk")),
        ),
        OperationName::AnalysisPointersScan => {
            OperationRequestDocument::AnalysisPointersScan(PointerScanArguments::new("a.hunk"))
        }
        OperationName::AnalysisAddressReferences => {
            OperationRequestDocument::AnalysisAddressReferences(
                AddressReferencesArguments::new("a.hunk").naming(0),
            )
        }
        OperationName::AnalysisCodeCallgraph => {
            OperationRequestDocument::AnalysisCodeCallgraph(CodeCallgraphArguments::new("a.hunk"))
        }
        OperationName::GraphicsIlbmDecode => {
            OperationRequestDocument::GraphicsIlbmDecode(IlbmDecodeArguments::new("title.ilbm"))
        }
        OperationName::GraphicsBitmapDetect => OperationRequestDocument::GraphicsBitmapDetect(
            BitmapDetectArguments::new("sample.bin").over(0, Some(64)),
        ),
        OperationName::GraphicsPaletteScan => OperationRequestDocument::GraphicsPaletteScan(
            PaletteScanArguments::new("sample.bin").with_minimum_colours(2),
        ),
        OperationName::HardwareCopperScan => {
            OperationRequestDocument::HardwareCopperScan(CopperScanArguments::new("sample.bin"))
        }
        OperationName::HardwareCopperDecode => {
            OperationRequestDocument::HardwareCopperDecode(CopperDecodeArguments::new("sample.bin"))
        }
        OperationName::AudioPcmScan => {
            OperationRequestDocument::AudioPcmScan(PcmScanArguments::new("sample.bin"))
        }
        OperationName::AudioModuleScan => {
            OperationRequestDocument::AudioModuleScan(ModuleScanArguments::new("song.mod"))
        }
        OperationName::HardwareCopperReferences => {
            OperationRequestDocument::HardwareCopperReferences(CopperReferencesArguments::new(
                "a.hunk",
                vec![0],
                0,
            ))
        }
        OperationName::HardwareRegisterReferences => {
            OperationRequestDocument::HardwareRegisterReferences(RegisterReferencesArguments::new(
                "a.hunk",
            ))
        }
        OperationName::HardwareRegisterList => {
            OperationRequestDocument::HardwareRegisterList(HardwareRegisterListArguments::new())
        }
        OperationName::AnalysisCodeFacts => {
            OperationRequestDocument::AnalysisCodeFacts(CodeFactsArguments::new("a.hunk"))
        }
        OperationName::AnalysisCodeGlobals => {
            OperationRequestDocument::AnalysisCodeGlobals(CodeGlobalsArguments::new("a.hunk"))
        }
        OperationName::AnalysisCodeFixedPoint => {
            OperationRequestDocument::AnalysisCodeFixedPoint(CodeFixedPointArguments::new("a.hunk"))
        }
        OperationName::AnalysisCodeDisassemble => {
            OperationRequestDocument::AnalysisCodeDisassemble(
                CodeDisassembleArguments::new("a.hunk").following_flow(vec![0]),
            )
        }
        OperationName::EnvBootTrace => {
            OperationRequestDocument::EnvBootTrace(BootTraceArguments::new("volume.adf"))
        }
        OperationName::EnvBootTraceExport => OperationRequestDocument::EnvBootTraceExport(
            BootTraceExportArguments::new(BootTraceArguments::new("volume.adf"), "out/tracks"),
        ),
        OperationName::EnvBootInfo => {
            OperationRequestDocument::EnvBootInfo(BootInfoArguments::new("volume.adf"))
        }
        OperationName::ProjectMigrate => OperationRequestDocument::ProjectMigrate(
            ProjectMigrateArguments::new("amiga-re.toml", "Imported", "out/imported"),
        ),
        OperationName::ProjectFormat => {
            OperationRequestDocument::ProjectFormat(ProjectArguments::default())
        }
        OperationName::ProjectExtract => OperationRequestDocument::ProjectExtract(
            amiga_operations::ProjectExtractArguments::default(),
        ),
        OperationName::ProjectResourceExport => OperationRequestDocument::ProjectResourceExport(
            amiga_operations::ResourceExportArguments::new("resource:title-logo"),
        ),
        // Prepared only: the sweep never commits, so the fixture is not
        // rewritten by running the tests.
        OperationName::ProjectInit => {
            OperationRequestDocument::ProjectInit(amiga_operations::ProjectInitArguments::new(
                "Sweep project",
                "out/project",
                vec!["sample.bin".to_owned()],
            ))
        }
        OperationName::ProjectEdit => {
            OperationRequestDocument::ProjectEdit(ProjectEditArguments::new(vec![
                ProjectEdit::Rename {
                    id: "function:init-graphics".to_owned(),
                    name: "setup_display".to_owned(),
                },
            ]))
        }
        OperationName::EnvSandboxRun => OperationRequestDocument::EnvSandboxRun(
            SandboxRunArguments::new("a.hunk")
                .with_maximum_steps(16)
                .tracing(),
        ),
    };

    let mut envelope = RequestEnvelope::read(arguments);
    // A `prepared_output` operation refuses `read`: there is no useful answer to
    // "write this but tell me nothing about what it would write". `prepare`
    // produces the plan and writes nothing, which is the response shape the
    // schema describes.
    if amiga_operations::descriptor(name).access == amiga_operations::AccessClass::PreparedOutput {
        envelope.execution.mode = ExecutionMode::Prepare;
    }
    // The project's location arrives through the locator, never through
    // arguments.
    if matches!(
        name,
        OperationName::ProjectCheck
            | OperationName::ProjectVerify
            | OperationName::ProjectDescribe
            | OperationName::ProjectAnnotations
            | OperationName::ProjectEdit
            | OperationName::ProjectFormat
            | OperationName::ProjectExtract
            | OperationName::ProjectResourceExport
            | OperationName::AnalysisStateSnapshot
    ) {
        envelope.project = Some(ProjectLocator::Path {
            path: "contract".to_owned(),
        });
    }
    Some(envelope)
}

/// Serialize the real router outcome, including errors without a payload.
fn response_of(
    base: &Path,
    envelope: &RequestEnvelope,
    cancelled: bool,
    limits: amiga_operations::OperationLimits,
) -> serde_json::Value {
    let sources = FilesystemSourceResolver::new(base.to_path_buf());
    let destinations = FilesystemDestinationResolver::new(base.to_path_buf());
    let cancel = std::sync::atomic::AtomicBool::new(cancelled);
    let context = ExecutionContext::new(&sources)
        .with_destinations(&destinations)
        .with_cancel(&cancel)
        .with_limits(limits);
    let outcome = Router::execute(envelope, &context);
    serde_json::to_value(amiga_operations::ResponseEnvelope::from_outcome(
        &outcome,
        envelope.request_id.as_deref(),
    ))
    .expect("a router outcome serializes")
}

/// Record directories and file bytes so even empty output creation is visible.
fn snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(
        root: &Path,
        path: &Path,
        result: &mut std::collections::BTreeMap<PathBuf, Option<Vec<u8>>>,
    ) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if path.is_dir() {
                result.insert(relative, None);
                walk(root, &path, result);
            } else {
                result.insert(relative, Some(std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    walk(root, root, &mut result);
    result
}

fn validate_response(validator: &jsonschema::Validator, document: &serde_json::Value) {
    if let Err(error) = validator.validate(document) {
        panic!("response envelope violates the schema: {error}\n{document}");
    }
}

#[test]
fn every_operation_s_response_schema_is_checked_against_a_real_response() {
    use amiga_operations::OperationLimits;
    let base = workspace();
    let before = snapshot(&base);
    let registry = registry();
    let envelope_validator = jsonschema::options()
        .with_registry(&registry)
        .build(
            &serde_json::from_str::<serde_json::Value>(
                amiga_operations::descriptor::schemas::RESPONSE,
            )
            .unwrap(),
        )
        .unwrap();
    let mut responses = std::collections::BTreeMap::new();
    let mut cancelled_count = 0;
    let mut prepared_count = 0;
    let mut conflict_count = 0;
    for descriptor in amiga_operations::catalog() {
        let Some(mut request) = representative(descriptor.name) else {
            continue;
        };
        request.request_id = Some("schema-correlation".to_owned());
        let response = response_of(&base, &request, false, OperationLimits::default());
        validate_response(&envelope_validator, &response);
        assert_eq!(response["request_id"], "schema-correlation");
        let result = response
            .get("result")
            .unwrap_or_else(|| panic!("no representative result: {response}"));
        let schema: serde_json::Value = serde_json::from_str(descriptor.response_schema).unwrap();
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&serde_json::json!({ "$ref": schema_id(&schema) }))
            .unwrap();
        if let Err(error) = validator.validate(result) {
            panic!(
                "{} payload violates its schema: {error}\n{result}",
                descriptor.name.as_str()
            );
        }
        match descriptor.access {
            amiga_operations::AccessClass::ReadOnly => {
                assert_eq!(response["status"], "success", "{response}")
            }
            amiga_operations::AccessClass::PreparedOutput => {
                assert_eq!(response["status"], "prepared", "{response}");
                prepared_count += 1;
                let mut conflict = request.clone();
                conflict.execution.mode = ExecutionMode::CommitReviewed {
                    approved_plan_sha256: "0".repeat(64),
                };
                let document = response_of(&base, &conflict, false, OperationLimits::default());
                assert_eq!(document["status"], "conflict", "{document}");
                if matches!(
                    descriptor.name,
                    OperationName::ProjectEdit
                        | OperationName::ProjectFormat
                        | OperationName::ProjectMigrate
                ) {
                    assert_eq!(
                        document["result"], response["result"],
                        "a conflict must retain the current uncommitted plan"
                    );
                }
                conflict_count += 1;
                validate_response(&envelope_validator, &document);
            }
        }
        responses.insert(descriptor.name.as_str(), response);

        let cancelled = response_of(&base, &request, true, OperationLimits::default());
        assert_eq!(cancelled["status"], "cancelled", "{cancelled}");
        assert!(cancelled.get("result").is_none(), "{cancelled}");
        cancelled_count += 1;
        validate_response(&envelope_validator, &cancelled);
        let mut cancelled_commit = request.clone();
        if descriptor.access == amiga_operations::AccessClass::PreparedOutput {
            cancelled_commit.execution.mode = ExecutionMode::CommitReviewed {
                approved_plan_sha256: "0".repeat(64),
            };
            let cancelled = response_of(&base, &cancelled_commit, true, OperationLimits::default());
            assert_eq!(cancelled["status"], "cancelled", "{cancelled}");
            assert!(cancelled.get("result").is_none());
            validate_response(&envelope_validator, &cancelled);
        }
        assert_eq!(
            snapshot(&base),
            before,
            "{} wrote files",
            descriptor.name.as_str()
        );
        request.protocol_version = 0;
        let error = response_of(&base, &request, false, OperationLimits::default());
        assert_eq!(error["status"], "error", "{error}");
        assert!(error.get("result").is_none());
        let cancelled_invalid = response_of(&base, &request, true, OperationLimits::default());
        assert_eq!(
            cancelled_invalid, error,
            "normalization must precede cancellation"
        );
        validate_response(&envelope_validator, &error);
    }
    assert!(prepared_count > 0 && conflict_count > 0);
    assert!(
        cancelled_count == amiga_operations::catalog().len(),
        "the sweep must exercise actual cancellation"
    );
    assert_eq!(
        responses.len() + UNCOVERED.len(),
        amiga_operations::catalog().len()
    );

    // Same envelope fields, incompatible payload. Checking payloads separately
    // cannot detect this swap, and a bag of result schemas would accept it.
    for (operation, other) in [
        ("source.survey", "hardware.register.list"),
        ("graphics.bitmap.decode", "container.adf.list"),
        ("env.sandbox.run", "project.verify"),
    ] {
        let mut swapped = responses[operation].clone();
        swapped["result"] = responses[other]["result"].clone();
        assert!(
            !envelope_validator.is_valid(&swapped),
            "accepted a {other} result for {operation}"
        );
    }
    let mut unknown = responses["source.survey"].clone();
    unknown["operation"] = serde_json::json!("unknown.operation");
    assert!(!envelope_validator.is_valid(&unknown));

    // Verification errors retain their report; callers need to see which pins
    // failed, and the envelope must validate that report too.
    let verify = representative(OperationName::ProjectVerify).unwrap();
    let contradicted = response_of(
        &base,
        &verify,
        false,
        OperationLimits::default().with_maximum_input_bytes(1),
    );
    assert_eq!(contradicted["status"], "error");
    assert!(contradicted.get("result").is_some());
    validate_response(&envelope_validator, &contradicted);
    let matrix = representative(OperationName::EnvSandboxMatrix).unwrap();
    let refused_matrix = response_of(
        &base,
        &matrix,
        false,
        OperationLimits::default().with_maximum_sandbox_memory_bytes(1),
    );
    assert_eq!(refused_matrix["status"], "error");
    assert!(refused_matrix.get("result").is_some());
    validate_response(&envelope_validator, &refused_matrix);
    // These project writers used to label preparation as success. Check the
    // complete transition, including cancellation of a genuinely approved plan.
    for name in [
        OperationName::ProjectEdit,
        OperationName::ProjectFormat,
        OperationName::ProjectMigrate,
    ] {
        let mut request = representative(name).unwrap();
        let prepared = response_of(&base, &request, false, OperationLimits::default());
        assert_eq!(prepared["status"], "prepared", "{prepared}");
        let plan_digest = prepared["result"]
            .get("plan_sha256")
            .unwrap_or(&prepared["result"]["plan"]["plan_sha256"])
            .as_str()
            .unwrap();
        request.execution.mode = ExecutionMode::CommitReviewed {
            approved_plan_sha256: plan_digest.to_owned(),
        };
        let before_commit = snapshot(&base);
        let cancelled = response_of(&base, &request, true, OperationLimits::default());
        assert_eq!(cancelled["status"], "cancelled");
        assert_eq!(snapshot(&base), before_commit);
        let committed = response_of(&base, &request, false, OperationLimits::default());
        assert_eq!(committed["status"], "success", "{committed}");
        assert_eq!(committed["result"]["committed"], true);
        validate_response(&envelope_validator, &committed);
    }
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn the_uncovered_list_and_the_sweep_agree_in_both_directions() {
    // The half of the rule that keeps the list honest. A name left here after
    // its request became buildable would quietly shrink the sweep, and an
    // operation `representative` returns `None` for without saying so here would
    // be the silent skip this test exists to forbid.
    for (name, reason) in UNCOVERED {
        assert!(
            representative(*name).is_none(),
            "{} is named as uncovered ({reason}) but has a representative request",
            name.as_str()
        );
        assert!(
            !reason.is_empty(),
            "{} is uncovered for no stated reason",
            name.as_str()
        );
    }
    for descriptor in amiga_operations::catalog() {
        if representative(descriptor.name).is_some() {
            continue;
        }
        assert!(
            UNCOVERED.iter().any(|(name, _)| *name == descriptor.name),
            "{} has no representative request and is not named in UNCOVERED",
            descriptor.name.as_str()
        );
    }
}
