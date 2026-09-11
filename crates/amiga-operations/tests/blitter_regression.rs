//! The reviewed end-to-end regression for blitter emulation.
//!
//! Every feature of the datapath has its own isolated test in
//! `amiga_hw::blitter`, because a test combining shift, mask, modulo and fill
//! proves nothing about which one is wrong. This file is the other half: one
//! routine that drives the real chip page through `env.sandbox.call` and
//! produces a bitmap, asserted against a table computed by hand.
//!
//! It deliberately **does not** exercise the `BLTBDAT` shift-order rule. That is
//! the subtlest rule in the model and it has its own isolated tests; the primary
//! reviewed image should not depend on it, or a regression in it would show up
//! here as a wrong picture rather than as the specific thing it is.

use std::sync::Arc;

use amiga_operations::{
    ExecutionContext, InMemorySourceResolver, OperationRequestDocument, RequestEnvelope,
    ResolvedSource, Router, SandboxRunArguments, SourceName, Status,
};

/// Where the source rectangle is seeded.
const SOURCE: u32 = 0x0004_0000;
/// Where the two-plane bitmap lives.
const BITMAP: u32 = 0x0004_0100;
/// Words per bitmap row. The blit is two words wide, so one word per row is
/// skipped — which is what makes the destination modulo non-zero.
const ROW_WORDS: u32 = 3;
const ROWS: u32 = 4;
/// Bytes of one plane, and so the offset of plane 1.
const PLANE_BYTES: u32 = ROW_WORDS * ROWS * 2;

/// A one-hunk LoadSeg image whose CODE hunk holds `code`.
fn image(code: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [0x0000_03f3_u32, 0, 1, 0, 0, 256] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0000_03e9_u32.to_be_bytes()); // HUNK_CODE
    let longwords = code.len().div_ceil(4) as u32;
    bytes.extend_from_slice(&longwords.to_be_bytes());
    bytes.extend_from_slice(code);
    bytes.resize(bytes.len() + (longwords as usize * 4 - code.len()), 0);
    bytes.extend_from_slice(&0x0000_03f2_u32.to_be_bytes()); // HUNK_END
    bytes
}

/// `MOVE.W #value,($DFFxxx).L`.
fn poke(code: &mut Vec<u8>, offset: u16, value: u16) {
    code.extend_from_slice(&[0x33, 0xfc]);
    code.extend_from_slice(&value.to_be_bytes());
    code.extend_from_slice(&(0x00df_f000_u32 + u32::from(offset)).to_be_bytes());
}

/// The routine under review.
///
/// Two blits into one two-plane bitmap:
///
/// 1. A **shifted, masked rectangle** into plane 0 — `ASH` 4, the last-word mask
///    clipping the right edge, a non-zero destination modulo stepping over the
///    third word of each row, and the A latch carrying across every row
///    boundary.
/// 2. A **disabled-A masked edge** into plane 1 — `USEA` clear with `BLTADAT`
///    preloaded, so the blit is driven entirely by the first/last-word masks.
///    This is the manual's own case, and the one a model that gated the masks on
///    the channel-enable bit would render as a solid block.
///
/// The second blit deliberately names no destination pointer: it continues from
/// where the first one left its D pointer, which is exactly plane 1's start.
fn routine(source: u32, bitmap: u32) -> Vec<u8> {
    let mut code = Vec::new();

    // --- blit 1: shifted, masked, into plane 0 ---
    poke(&mut code, 0x040, 0x49f0); // BLTCON0: ASH=4, USEA | USED, copy A
    poke(&mut code, 0x042, 0x0000); // BLTCON1: ascending, no fill
    poke(&mut code, 0x044, 0xffff); // BLTAFWM: the left edge is whole
    poke(&mut code, 0x046, 0xff00); // BLTALWM: clip the right edge
    poke(&mut code, 0x050, (source >> 16) as u16); // BLTAPTH
    poke(&mut code, 0x052, source as u16); // BLTAPTL
    poke(&mut code, 0x064, 0x0000); // BLTAMOD: source rows are contiguous
    poke(&mut code, 0x054, (bitmap >> 16) as u16); // BLTDPTH
    poke(&mut code, 0x056, bitmap as u16); // BLTDPTL
    poke(&mut code, 0x066, 0x0002); // BLTDMOD: step over the row's third word
    poke(&mut code, 0x058, 0x0102); // BLTSIZE: two words wide, four lines

    // --- blit 2: disabled A, masks only, into plane 1 ---
    poke(&mut code, 0x040, 0x01f0); // BLTCON0: USED only — USEA deliberately clear
    poke(&mut code, 0x074, 0xffff); // BLTADAT: the constant the masks clip
    poke(&mut code, 0x044, 0x0fff); // BLTAFWM
    poke(&mut code, 0x046, 0xfff0); // BLTALWM
    poke(&mut code, 0x058, 0x0082); // BLTSIZE: two words wide, two lines

    code.extend_from_slice(&[0x4e, 0x75]); // RTS
    code
}

/// The source rectangle, four rows of two words.
const SOURCE_WORDS: [u16; 8] = [
    0x1111, 0x2222, // row 0
    0x3333, 0x4444, // row 1
    0x5555, 0x6666, // row 2
    0x7777, 0x8888, // row 3
];

/// The bitmap this routine must produce, computed by hand.
///
/// Plane 0 is the shifted, masked copy. Each word is
/// `((previous_masked << 16) | masked) >> 4`, where `previous_masked` carries
/// across the row boundary — the pinned choice that the A latch is reset once
/// per blit rather than once per row. The third word of every row is untouched,
/// which is the destination modulo doing its job.
///
/// Plane 1 is `$ffff` clipped by the two word masks, on a channel whose DMA is
/// off. A model that skipped the masks because `USEA` was clear would write
/// `$ffff` into all four words and produce a plausible, wrong picture.
const EXPECTED_WORDS: [u16; 24] = [
    // plane 0
    0x0111, 0x1220, 0x0000, // row 0: 0x1111 and 0x2222 & 0xff00, shifted by 4
    0x0333, 0x3440, 0x0000, // row 1: shifted against row 0's last masked word
    0x0555, 0x5660, 0x0000, // row 2
    0x0777, 0x7880, 0x0000, // row 3
    // plane 1
    0x0fff, 0xfff0, 0x0000, // row 0: the two masks, and nothing else
    0x0fff, 0xfff0, 0x0000, // row 1
    0x0000, 0x0000, 0x0000, // rows 2 and 3 are outside this blit
    0x0000, 0x0000, 0x0000,
];

fn words_to_bytes(words: &[u16]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_shifted_masked_two_plane_bitmap_comes_out_exactly_as_computed() {
    let bytes = image(&routine(SOURCE, BITMAP));
    let name = SourceName::parse("game").expect("a valid name");
    let resolver = InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)));
    let context = ExecutionContext::new(&resolver);

    let mut arguments = amiga_operations::SandboxCallArguments::new(
        SandboxRunArguments::new("game").at_origin(0x2_0000),
    )
    .with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: SOURCE,
        size: 0x400,
    }])
    .with_memory_seeds(vec![amiga_operations::MemorySeed {
        address: SOURCE,
        hex: Some(hex(&words_to_bytes(&SOURCE_WORDS))),
        from: None,
        artifact: None,
    }])
    .with_memory_exports(vec![amiga_operations::MemoryExport {
        name: "bitmap.bin".to_owned(),
        address: BITMAP,
        length: PLANE_BYTES * 2,
    }]);
    arguments.custom_chips = Some(amiga_operations::CustomChips::default());

    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(arguments)),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");
    assert!(record.returned, "stopped at {:?}", record.stop);

    // The picture, region by region. Each row's two written words form their
    // own span because the third word of the row was stepped over and never
    // written — so the destination modulo is visible here as the gaps between
    // the regions, not merely inferable from the values.
    let expected_regions: Vec<(u32, String)> = [
        (0, [0x0111_u16, 0x1220]),
        (6, [0x0333, 0x3440]),
        (12, [0x0555, 0x5660]),
        (18, [0x0777, 0x7880]),
        // Plane 1, driven entirely by the word masks on a channel whose DMA is
        // off. A model that skipped the masks because `USEA` was clear would
        // write $ffff into all four of these.
        (24, [0x0fff, 0xfff0]),
        (30, [0x0fff, 0xfff0]),
    ]
    .into_iter()
    .map(|(offset, words)| (BITMAP + offset, hex(&words_to_bytes(&words))))
    .collect();
    let produced: Vec<(u32, String)> = record
        .changed_memory
        .iter()
        .filter(|region| region.address >= BITMAP)
        .map(|region| (region.address, region.hex.clone()))
        .collect();
    assert_eq!(
        produced, expected_regions,
        "the bitmap does not match the hand-computed table"
    );

    // The exported range is digested over the whole bitmap, trailing zeros and
    // all: an export is the bytes at those addresses, not the ones that changed.
    let export = record
        .exported_regions
        .iter()
        .find(|export| export.name == "bitmap.bin")
        .unwrap_or_else(|| panic!("the export is missing"));
    assert_eq!(export.address, BITMAP);
    assert_eq!(export.length, PLANE_BYTES * 2);
    assert_eq!(
        export.sha256,
        amiga_core::sha256(&words_to_bytes(&EXPECTED_WORDS))
    );

    // Two blits, both performed, with the second continuing from the first's
    // final destination pointer.
    assert_eq!(record.blits_total, 2);
    assert_eq!(record.blits[0].refused, None);
    assert_eq!(record.blits[1].refused, None);
    assert_eq!(
        record.blits[0].final_pointers[3],
        BITMAP + PLANE_BYTES,
        "the first blit should leave D exactly at plane 1"
    );
    assert_eq!(record.blits[1].initial_pointers[3], BITMAP + PLANE_BYTES);
    assert_eq!(record.executed_blit_words_total, 8 + 4);
    // Blit 2 has A DMA off, so it fetched nothing and still wrote four words.
    assert_eq!(record.blits[1].words_written, 4);
}

#[test]
fn an_in_place_scroll_through_the_operation_does_not_smear() {
    // The dangerous overlap, end to end. The one-word pipeline is what makes
    // this behave as the hardware does; writing each word as it is computed
    // would make every source read after the first see a word this same blit had
    // already overwritten, and the row would come out solid.
    let mut code = Vec::new();
    poke(&mut code, 0x040, 0x09f0); // BLTCON0: USEA | USED, copy A, no shift
    poke(&mut code, 0x042, 0x0000);
    poke(&mut code, 0x044, 0xffff);
    poke(&mut code, 0x046, 0xffff);
    poke(&mut code, 0x050, (SOURCE >> 16) as u16); // A at the row's first word
    poke(&mut code, 0x052, SOURCE as u16);
    poke(&mut code, 0x064, 0x0000);
    poke(&mut code, 0x054, (SOURCE >> 16) as u16); // D one word ahead of A
    poke(&mut code, 0x056, (SOURCE + 2) as u16);
    poke(&mut code, 0x066, 0x0000);
    poke(&mut code, 0x058, 0x0043); // three words, one line
    code.extend_from_slice(&[0x4e, 0x75]);

    let bytes = image(&code);
    let name = SourceName::parse("game").expect("a valid name");
    let resolver = InMemorySourceResolver::new(ResolvedSource::new(name, Arc::from(bytes)));
    let context = ExecutionContext::new(&resolver);

    let mut arguments = amiga_operations::SandboxCallArguments::new(
        SandboxRunArguments::new("game").at_origin(0x2_0000),
    )
    .with_mapped_regions(vec![amiga_operations::MappedRegion {
        address: SOURCE,
        size: 0x100,
    }])
    .with_memory_seeds(vec![amiga_operations::MemorySeed {
        address: SOURCE,
        hex: Some(hex(&words_to_bytes(&[0x1111, 0x2222, 0x3333, 0x4444]))),
        from: None,
        artifact: None,
    }]);
    arguments.custom_chips = Some(amiga_operations::CustomChips::default());

    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(arguments)),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a record");

    let changed = record
        .changed_memory
        .iter()
        .find(|region| region.address == SOURCE + 2)
        .unwrap_or_else(|| panic!("nothing changed: {:?}", record.changed_memory));
    assert_eq!(
        changed.hex,
        hex(&words_to_bytes(&[0x1111, 0x2222, 0x3333])),
        "each word should be the one before it, not the first one three times"
    );
    // And the overlap is reported, because it is where this model's fidelity is
    // least certain: the real queue depth varies with which channels are active.
    assert!(
        record.blits[0]
            .observations
            .iter()
            .any(|observation| observation.kind == "destination_overlaps_source"),
        "the overlap went unreported: {:?}",
        record.blits[0].observations
    );
}

/// A complete private execution recipe plus independently reviewed output pins.
/// The operation envelope is the public API, not a second sandbox schema.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct MediaRecipe {
    version: u32,
    sources: Vec<MediaSource>,
    request: RequestEnvelope,
    expected_exports: std::collections::BTreeMap<String, String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct MediaSource {
    name: String,
    path: std::path::PathBuf,
    sha256: String,
}

fn verify_recipe(recipe: &MediaRecipe, bytes: Vec<Vec<u8>>) -> amiga_operations::SandboxCallResult {
    assert_eq!(recipe.version, 1, "unsupported media recipe version");
    assert!(!recipe.sources.is_empty() && recipe.sources.len() <= 16);
    assert_eq!(recipe.sources.len(), bytes.len());
    let OperationRequestDocument::EnvSandboxCall(arguments) = &recipe.request.request else {
        panic!("the recipe must contain env.sandbox.call");
    };
    assert!(
        arguments.run.load_origin.is_some(),
        "state the load origin explicitly"
    );
    assert!(
        arguments.run.maximum_steps.is_some(),
        "state the execution budget explicitly"
    );
    assert!(
        !arguments.memory_exports.is_empty(),
        "a regression must pin exported bytes"
    );
    let exports: std::collections::BTreeSet<_> = arguments
        .memory_exports
        .iter()
        .map(|export| export.name.as_str())
        .collect();
    assert_eq!(
        exports.len(),
        arguments.memory_exports.len(),
        "duplicate export name"
    );
    assert_eq!(
        exports,
        recipe.expected_exports.keys().map(String::as_str).collect()
    );
    let mut names = std::collections::BTreeSet::new();
    let mut total = 0_usize;
    let sources = recipe
        .sources
        .iter()
        .zip(bytes)
        .map(|(source, bytes)| {
            assert!(names.insert(source.name.clone()), "duplicate source name");
            total = total
                .checked_add(bytes.len())
                .expect("source size overflow");
            assert!(total <= 64 * 1024 * 1024, "source byte budget exceeded");
            assert_eq!(
                amiga_core::sha256(&bytes),
                source.sha256,
                "source digest mismatch: {}",
                source.name
            );
            ResolvedSource::new(
                SourceName::parse(&source.name).expect("valid source name"),
                Arc::from(bytes),
            )
        })
        .collect();
    let resolver = InMemorySourceResolver::holding(sources);
    let outcome = Router::execute(&recipe.request, &ExecutionContext::new(&resolver));
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let record = outcome.env_sandbox_call().expect("a call record");
    assert!(record.returned, "routine did not return: {:?}", record.stop);
    assert!(record.blits_total > 0, "routine triggered no blits");
    assert!(record.blits.iter().all(|blit| blit.refused.is_none()));
    assert_eq!(record.exported_regions.len(), recipe.expected_exports.len());
    for export in &record.exported_regions {
        assert_eq!(
            Some(&export.sha256),
            recipe.expected_exports.get(&export.name),
            "reviewed export changed: {}",
            export.name
        );
        let requested = arguments
            .memory_exports
            .iter()
            .find(|e| e.name == export.name)
            .unwrap();
        assert_eq!(
            (export.address, export.length),
            (requested.address, requested.length)
        );
    }
    record.clone()
}

fn synthetic_recipe(origin: u32, source: u32, bitmap: u32) -> (MediaRecipe, Vec<Vec<u8>>) {
    let program = image(&routine(source, bitmap));
    let mut run = SandboxRunArguments::new("program").at_origin(origin);
    run.maximum_steps = Some(1_000);
    let arguments = amiga_operations::SandboxCallArguments::new(run)
        .with_mapped_regions(vec![
            amiga_operations::MappedRegion {
                address: source,
                size: 16,
            },
            amiga_operations::MappedRegion {
                address: bitmap,
                size: PLANE_BYTES * 2,
            },
        ])
        .with_memory_seeds(vec![amiga_operations::MemorySeed {
            address: source,
            hex: Some(hex(&words_to_bytes(&SOURCE_WORDS))),
            from: None,
            artifact: None,
        }])
        .with_memory_exports(vec![amiga_operations::MemoryExport {
            name: "bitmap.bin".to_owned(),
            address: bitmap,
            length: PLANE_BYTES * 2,
        }])
        .with_custom_chips(amiga_operations::CustomChips::default());
    let recipe = MediaRecipe {
        version: 1,
        sources: vec![MediaSource {
            name: "program".to_owned(),
            path: "synthetic.hunk".into(),
            sha256: amiga_core::sha256(&program),
        }],
        request: RequestEnvelope::read(OperationRequestDocument::EnvSandboxCall(arguments)),
        expected_exports: [(
            "bitmap.bin".to_owned(),
            amiga_core::sha256(&words_to_bytes(&EXPECTED_WORDS)),
        )]
        .into(),
    };
    // Exercise precisely the JSON vocabulary accepted by the private harness.
    (
        serde_json::from_slice(&serde_json::to_vec(&recipe).unwrap()).unwrap(),
        vec![program],
    )
}

#[test]
fn complete_recipes_reproduce_the_bitmap_in_two_disjoint_memory_maps() {
    for (origin, source, bitmap) in [(0x10000, 0x60000, 0x70000), (0x30000, 0x100000, 0x180000)] {
        let (recipe, bytes) = synthetic_recipe(origin, source, bitmap);
        let record = verify_recipe(&recipe, bytes);
        let mut recovered = vec![0; (PLANE_BYTES * 2) as usize];
        for region in &record.changed_memory {
            if let Some(offset) = region.address.checked_sub(bitmap) {
                let data: Vec<u8> = region
                    .hex
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                let start = offset as usize;
                if start < recovered.len() {
                    recovered[start..start + data.len()].copy_from_slice(&data);
                }
            }
        }
        assert_eq!(recovered, words_to_bytes(&EXPECTED_WORDS));
        assert_eq!(record.blits_total, 2);
    }
}

#[test]
#[should_panic(expected = "source digest mismatch")]
fn a_recipe_cannot_run_unpinned_source_bytes() {
    let (recipe, mut bytes) = synthetic_recipe(0x10000, 0x60000, 0x70000);
    bytes[0][0] ^= 1;
    verify_recipe(&recipe, bytes);
}

#[test]
#[should_panic(expected = "a regression must pin exported bytes")]
fn a_recipe_cannot_downgrade_to_a_blit_count_smoke_test() {
    let (mut recipe, bytes) = synthetic_recipe(0x10000, 0x60000, 0x70000);
    if let OperationRequestDocument::EnvSandboxCall(arguments) = &mut recipe.request.request {
        arguments.memory_exports.clear();
    }
    verify_recipe(&recipe, bytes);
}

#[test]
#[should_panic(expected = "unsupported media recipe version")]
fn unsupported_recipe_versions_are_refused() {
    let (mut recipe, bytes) = synthetic_recipe(0x10000, 0x60000, 0x70000);
    recipe.version = 2;
    verify_recipe(&recipe, bytes);
}

fn read_bounded(path: &std::path::Path, limit: u64) -> Vec<u8> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .expect("read source");
    assert!(bytes.len() as u64 <= limit, "input exceeds its byte budget");
    bytes
}

/// Set AMIGA_RE_BLIT_RECIPE to a version-1 JSON recipe. Absence skips; an
/// explicitly configured missing/malformed input fails instead of hiding it.
#[test]
fn a_real_routine_blits_what_the_pinned_media_says_it_does() {
    let Some(path) = std::env::var_os("AMIGA_RE_BLIT_RECIPE") else {
        eprintln!("skipped: set AMIGA_RE_BLIT_RECIPE to a complete pinned JSON recipe");
        return;
    };
    let path = std::path::PathBuf::from(path);
    let recipe: MediaRecipe = serde_json::from_slice(&read_bounded(&path, 1024 * 1024))
        .expect("a complete recipe document");
    assert!(!recipe.sources.is_empty() && recipe.sources.len() <= 16);
    let root = path.parent().expect("recipe parent");
    let mut remaining = 64 * 1024 * 1024;
    let bytes = recipe
        .sources
        .iter()
        .map(|source| {
            let bytes = read_bounded(&root.join(&source.path), remaining);
            remaining -= bytes.len() as u64;
            bytes
        })
        .collect();
    verify_recipe(&recipe, bytes);
}
