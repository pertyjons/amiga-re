//! Golden-snapshot and acceptance tests for the semantic fact report
//! (`disasm report`), over a synthetic, redistributable HUNK fixture.
//!
//! The fixture exercises the roadmap Stage 0 checklist: a direct call and a
//! conditional branch, a PC-relative string reference, ExecBase plus
//! `OpenLibrary` result flow, absolute and base-relative custom-chip accesses,
//! an A5-relative global, a HUNK relocation, an unresolved indirect jump, and
//! a conflicting library inference where two function owners reach the same
//! call site with different bases.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn amiga_re() -> Command {
    Command::new(env!("CARGO_BIN_EXE_amiga-re"))
}

/// The synthetic CODE hunk: two seeded entries (0x0 and 0x8) whose flows join
/// at `shared` (0x2c) with different inferred A6 bases.
fn fixture_code() -> Vec<u8> {
    let mut code = vec![
        0x2c, 0x78, 0x00, 0x04, // 0x00 entry A: MOVEA.L 4.W,A6 (ExecBase)
        0x60, 0x00, 0x00, 0x26, // 0x04 BRA.W shared (0x2c)
        0x2c, 0x78, 0x00, 0x04, // 0x08 entry B: MOVEA.L 4.W,A6
        0x43, 0xfa, 0x00, 0x36, // 0x0c LEA (0x36,PC),A1 -> 0x44 "graphics.library"
        0x4e, 0xae, 0xfd, 0xd8, // 0x10 JSR (-552,A6) = exec/OpenLibrary
        0x2b, 0x40, 0x00, 0x08, // 0x14 MOVE.L D0,(8,A5) (A5 global write)
        0x2c, 0x40, // 0x18 MOVEA.L D0,A6 (A6 = graphics)
        0x49, 0xf9, 0x00, 0xdf, 0xf0, 0x00, // 0x1a LEA $DFF000,A4
        0x39, 0x7c, 0x80, 0x20, 0x00, 0x96, // 0x20 MOVE.W #$8020,(0x96,A4) = DMACON
        0x4a, 0x41, // 0x26 TST.W D1
        0x67, 0x02, // 0x28 BEQ.S shared (conditional branch)
        0x4e, 0x71, // 0x2a NOP
        0x4e, 0xae, 0xff, 0xe2, // 0x2c shared: JSR (-30,A6) (conflicting base)
        0x30, 0x39, 0x00, 0xdf, 0xf0, 0x1c, // 0x30 MOVE.W $DFF01C,D0 = INTENAR read
        0xc7, 0xc1, // 0x36 MULS.W D1,D3
        0xe0, 0x83, // 0x38 ASR.L #8,D3 (Q8 fixed point)
        0x61, 0x06, // 0x3a BSR.S sub (0x42) (direct call)
        0x4e, 0xd0, // 0x3c JMP (A0) (unresolved indirect jump)
        0x4e, 0x71, // 0x3e unreached filler
        0x4e, 0x71, // 0x40 unreached filler
        0x4e, 0x75, // 0x42 sub: RTS
    ];
    code.extend_from_slice(b"graphics.library\0"); // 0x44..0x55
    code.push(0); // 0x55 pad
    code.extend_from_slice(&[0x00, 0x00, 0x00, 0x42]); // 0x56 relocated pointer to sub
    code.extend_from_slice(&[0x00, 0x00]); // 0x5a pad to a whole number of words
    assert_eq!(code.len(), 0x5c);
    code
}

/// Wrap the CODE hunk in a minimal HUNK executable with one RELOC32 patching
/// the pointer at 0x56.
fn fixture_executable() -> Vec<u8> {
    let code = fixture_code();
    let words = u32::try_from(code.len() / 4).unwrap();
    let mut bytes = Vec::new();
    for word in [0x03f3, 0, 1, 0, 0, words, 0x03e9, words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    for word in [0x03ec, 1, 0, 0x56, 0, 0x03f2] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes
}

fn dual_ea_executable(patched: u32) -> Vec<u8> {
    // MOVE.L $0.L,$0.L ; RTS. The equal source and destination addends begin
    // at offsets 2 and 6 respectively.
    let code = [
        0x23, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x75,
    ];
    let mut bytes = Vec::new();
    for word in [0x03f3, 0, 1, 0, 0, 3, 0x03e9, 3] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    for word in [0x03ec, 1, 0, patched, 0, 0x03f2] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes
}

const FIXTURE_CONFIG: &str = r#"
[[symbols]]
addr = 0x8
name = "init_gfx"

[[symbols]]
addr = 0x42
name = "helper"
"#;

/// Write the fixture executable and config into a fresh temp directory.
fn fixture_dir(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("amiga-re-semantic-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("fixture.hunk");
    fs::write(&executable, fixture_executable()).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(&config, FIXTURE_CONFIG).unwrap_or_else(|error| panic!("{error}"));
    (base, executable, config)
}

fn run_report(executable: &Path, config: &Path, format: &str) -> String {
    run_report_with(executable, config, format, &[])
}

/// The same report with extra flags, for the narrowing tests.
fn run_report_with(executable: &Path, config: &Path, format: &str, extra: &[&str]) -> String {
    let output = amiga_re()
        .args(["--config"])
        .arg(config)
        .args(["disasm", "report"])
        .arg(executable)
        .args(["--entry", "0", "--entry", "0x8", "--format", format])
        .args(extra)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

fn assert_matches_golden(actual: &str, name: &str) {
    let path = golden_path(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&path, actual).unwrap_or_else(|error| panic!("{error}"));
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden {} ({error}); run with UPDATE_GOLDEN=1 to create it",
            path.display()
        )
    });
    assert_eq!(
        actual,
        expected,
        "output differs from golden {} (run with UPDATE_GOLDEN=1 after auditing the change)",
        path.display()
    );
}

#[test]
fn report_text_matches_golden_and_is_deterministic() {
    let (base, executable, config) = fixture_dir("text");
    let first = run_report(&executable, &config, "text");
    let second = run_report(&executable, &config, "text");
    assert_eq!(first, second, "text report is not deterministic");
    assert_matches_golden(&first, "semantic-report.txt");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn report_json_matches_golden_and_is_deterministic() {
    let (base, executable, config) = fixture_dir("json");
    let first = run_report(&executable, &config, "json");
    let second = run_report(&executable, &config, "json");
    assert_eq!(first, second, "JSON report is not deterministic");
    assert_matches_golden(&first, "semantic-report.json");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn every_json_fact_names_its_producer_and_evidence() {
    let (base, executable, config) = fixture_dir("integrity");
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    assert_eq!(report["schema"], "amiga-re.semantic-report");
    assert_eq!(report["version"], amiga_disasm::SCHEMA_VERSION);
    let facts = report["facts"]
        .as_array()
        .unwrap_or_else(|| panic!("facts is not an array"));
    assert!(!facts.is_empty());
    for fact in facts {
        assert!(
            fact["producer"].is_string(),
            "fact without a producer: {fact}"
        );
        let evidence = fact["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("fact without evidence array: {fact}"));
        assert!(!evidence.is_empty(), "fact with empty evidence: {fact}");
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn conflicting_inference_is_an_explicit_ambiguity() {
    let (base, executable, config) = fixture_dir("conflict");
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = report["facts"].as_array().unwrap();
    let conflict = facts
        .iter()
        .find(|fact| fact["kind"] == "library_conflict")
        .unwrap_or_else(|| panic!("no library_conflict fact"));
    assert_eq!(conflict["subject"], 0x2c);
    assert_eq!(conflict["confidence"], "probable");
    // Each candidate cites the instruction sites that established it: entry
    // A's ExecBase load, and entry B's name setup, OpenLibrary call, and D0
    // copy into A6.
    assert_eq!(
        conflict["candidates"],
        serde_json::json!([
            { "library": "exec.library", "sites": [0x00] },
            { "library": "graphics.library", "sites": [0x0c, 0x10, 0x18] },
        ])
    );
    // The call itself stays unnamed instead of picking a winner.
    let call = facts
        .iter()
        .find(|fact| fact["kind"] == "library_call" && fact["subject"] == 0x2c)
        .unwrap_or_else(|| panic!("no library_call fact at the conflict site"));
    assert_eq!(call["library"], serde_json::Value::Null);
    assert_eq!(call["confidence"], "probable");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn hardware_confidence_separates_absolute_from_base_relative() {
    let (base, executable, config) = fixture_dir("hardware");
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = report["facts"].as_array().unwrap();
    let base_relative = facts
        .iter()
        .find(|fact| fact["kind"] == "hardware_access" && fact["subject"] == 0x20)
        .unwrap_or_else(|| panic!("no base-relative hardware fact"));
    assert_eq!(base_relative["register_name"], "DMACON");
    assert_eq!(base_relative["confidence"], "inferred");
    assert_eq!(base_relative["access"], "write");
    let absolute = facts
        .iter()
        .find(|fact| fact["kind"] == "hardware_access" && fact["subject"] == 0x30)
        .unwrap_or_else(|| panic!("no absolute hardware fact"));
    assert_eq!(absolute["register_name"], "INTENAR");
    assert_eq!(absolute["confidence"], "certain");
    assert_eq!(absolute["access"], "read");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn relocation_and_config_symbols_become_facts() {
    let (base, executable, config) = fixture_dir("compose");
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = report["facts"].as_array().unwrap();
    let relocation = facts
        .iter()
        .find(|fact| fact["kind"] == "relocation")
        .unwrap_or_else(|| panic!("no relocation fact"));
    assert_eq!(relocation["subject"], 0x56);
    assert_eq!(relocation["target_hunk"], 0);
    assert_eq!(relocation["target_offset"], 0x42);
    assert_eq!(relocation["confidence"], "certain");
    let symbol = facts
        .iter()
        .find(|fact| fact["kind"] == "symbol" && fact["subject"] == 0x42)
        .unwrap_or_else(|| panic!("no symbol fact for helper"));
    assert_eq!(symbol["name"], "helper");
    assert_eq!(symbol["confidence"], "user");
    // The function fact at the same entry resolves to the config name.
    let function = facts
        .iter()
        .find(|fact| fact["kind"] == "function" && fact["subject"] == 0x42)
        .unwrap_or_else(|| panic!("no function fact for helper"));
    assert_eq!(function["name"], "helper");
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 2: address spaces -------------------------------------------------

/// The fixture config plus a mapped origin, so the runtime address space
/// resolves too. `0x42` is `helper`'s absolute address at this origin.
const MAPPED_CONFIG: &str = r#"
[base]
origin = 0x10000

[[symbols]]
addr = 0x10008
name = "init_gfx"

[[symbols]]
addr = 0x10042
name = "helper"
"#;

/// Write the fixture with a config that maps the image at a fixed origin.
fn mapped_fixture_dir(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let (base, executable, config) = fixture_dir(tag);
    fs::write(&config, MAPPED_CONFIG).unwrap_or_else(|error| panic!("{error}"));
    (base, executable, config)
}

/// Run the report over a mapped image. With an origin configured, entry points
/// are absolute addresses, so the fixture's two entries move up by the origin.
fn run_mapped_report(executable: &Path, config: &Path, format: &str) -> String {
    let output = amiga_re()
        .args(["--config"])
        .arg(config)
        .args(["disasm", "report"])
        .arg(executable)
        .args([
            "--entry", "0x10000", "--entry", "0x10008", "--format", format,
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

#[test]
fn every_displayed_target_names_its_address_space() {
    let (base, executable, config) = mapped_fixture_dir("spaces");
    let report = run_mapped_report(&executable, &config, "text");
    // The header declares the spaces and the frame of the subject column.
    assert!(
        report.contains(
            "; Address spaces: hunk0+0x.. hunk-relative, abs 0x.. runtime, file 0x.. whole-file"
        ),
        "no address-space legend:\n{report}"
    );
    assert!(
        report.contains("; L######## subjects and evidence sites are offsets into hunk 0"),
        "the subject column does not declare its space:\n{report}"
    );
    assert!(
        report.contains("; Hunk: 0 (CODE, 0x5c bytes) at file 0x20..0x7c"),
        "the hunk header does not resolve the whole-file frame:\n{report}"
    );
    // A PC-relative target inside the image resolves in all three spaces.
    assert!(
        report.contains("-> hunk0+0x44 (abs 0x10044, file 0x64) [pcrel operand]"),
        "the string reference does not resolve every space:\n{report}"
    );
    // A target outside the image stays in the one space that names it.
    assert!(
        report.contains("-> abs 0xdff000 [abs operand]"),
        "the hardware reference is not labelled absolute:\n{report}"
    );
    // Custom-chip register offsets are their own space, not image addresses.
    assert!(
        report.contains("write DMACON (custom+$096) [base-reg operand]"),
        "the register offset is not labelled:\n{report}"
    );
    // Symbols, calls, and relocations all resolve through the same frames.
    assert!(
        report.contains("call -> helper @ hunk0+0x42 (abs 0x10042, file 0x62)"),
        "the call target does not resolve every space:\n{report}"
    );
    assert!(
        report.contains("reloc32 -> helper @ hunk0+0x42 (abs 0x10042, file 0x62)"),
        "the relocation target does not resolve every space:\n{report}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn an_unmapped_image_reports_no_runtime_address() {
    let (base, executable, config) = fixture_dir("unmapped");
    let report = run_report(&executable, &config, "text");
    assert!(
        report.contains("; Base: none (no mapped origin, so no runtime address space)"),
        "the missing origin is not stated:\n{report}"
    );
    // Without an origin there is no runtime frame to show, and none is invented.
    assert!(
        report.contains("-> hunk0+0x44 (file 0x64) [pcrel operand]"),
        "the string reference invented or dropped a space:\n{report}"
    );
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    assert_eq!(
        json["address_spaces"]["runtime_origin"],
        serde_json::Value::Null
    );
    assert_eq!(json["address_spaces"]["file_start"], 0x20);
    for fact in json["facts"].as_array().unwrap() {
        assert!(
            fact["location"]["runtime"].is_null(),
            "a fact carries a runtime address without a mapped origin: {fact}"
        );
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn json_locations_agree_with_the_mapped_frames() {
    let (base, executable, config) = mapped_fixture_dir("json-spaces");
    let json: serde_json::Value =
        serde_json::from_str(&run_mapped_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    assert_eq!(json["address_spaces"]["hunk"], 0);
    assert_eq!(json["address_spaces"]["size"], 0x5c);
    assert_eq!(json["address_spaces"]["file_start"], 0x20);
    assert_eq!(json["address_spaces"]["runtime_origin"], 0x10000);
    let facts = json["facts"].as_array().unwrap();
    // Every fact's own location agrees with the declared origin and anchor.
    for fact in facts {
        let location = &fact["location"];
        let offset = location["offset"].as_u64().unwrap_or_else(|| {
            panic!("fact without a resolved location: {fact}");
        });
        assert_eq!(location["hunk"], 0);
        assert_eq!(location["file"].as_u64(), Some(offset + 0x20));
        assert_eq!(location["runtime"].as_u64(), Some(offset + 0x10000));
    }
    // A reference target resolves to the same frames as the entity it names.
    let reference = facts
        .iter()
        .find(|fact| fact["kind"] == "reference" && fact["subject"] == 0x0c)
        .unwrap_or_else(|| panic!("no PC-relative reference fact"));
    assert_eq!(reference["target_location"]["offset"], 0x44);
    assert_eq!(reference["target_location"]["runtime"], 0x10044);
    assert_eq!(reference["target_location"]["file"], 0x64);
    // A target outside the image has no location at all rather than a guess.
    let hardware = facts
        .iter()
        .find(|fact| fact["kind"] == "reference" && fact["subject"] == 0x1a)
        .unwrap_or_else(|| panic!("no absolute reference fact"));
    assert!(hardware["target_location"].is_null());
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 2: anchored entities ----------------------------------------------

#[test]
fn every_fact_carries_a_stable_anchor() {
    let (base, executable, config) = fixture_dir("anchors");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    assert_eq!(
        json["anchor_format"],
        "h<hunk>-<kind>-<offset as 8 hex digits>"
    );
    for fact in json["facts"].as_array().unwrap() {
        let anchor = fact["anchor"]
            .as_str()
            .unwrap_or_else(|| panic!("fact without an anchor: {fact}"));
        // The anchor encodes the entity's own offset, which is the subject for
        // every kind but `function`, whose entity is its entry.
        let offset = match fact["kind"].as_str() {
            Some("function") => fact["entry"].as_u64(),
            _ => fact["subject"].as_u64(),
        }
        .unwrap_or_else(|| panic!("fact without an offset: {fact}"));
        assert!(
            anchor.ends_with(&format!("{offset:08x}")),
            "anchor {anchor} does not encode offset {offset:#x}"
        );
        assert!(anchor.starts_with("h0-"), "anchor {anchor} names no hunk");
    }
    // Re-running the same input produces the same anchors.
    let again: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    assert_eq!(json["facts"], again["facts"]);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn anchors_separate_the_entities_sharing_one_offset() {
    let (base, executable, config) = fixture_dir("anchor-kinds");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();
    let anchor_of = |kind: &str, subject: u64| -> String {
        facts
            .iter()
            .find(|fact| fact["kind"] == kind && fact["subject"] == subject)
            .and_then(|fact| fact["anchor"].as_str())
            .unwrap_or_else(|| panic!("no {kind} fact at {subject:#x}"))
            .to_owned()
    };
    // `helper` is a function entry and a configured symbol at the same offset:
    // two entities, two anchors.
    assert_eq!(anchor_of("function", 0x42), "h0-fn-00000042");
    assert_eq!(anchor_of("symbol", 0x42), "h0-sym-00000042");
    // A decoded instruction and an offset control flow never reached differ.
    assert_eq!(anchor_of("reference", 0x0c), "h0-insn-0000000c");
    assert_eq!(anchor_of("relocation", 0x56), "h0-data-00000056");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn the_entity_table_matches_the_facts_that_name_it() {
    let (base, executable, config) = mapped_fixture_dir("entities");
    let json: serde_json::Value =
        serde_json::from_str(&run_mapped_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let entities = json["entities"].as_array().unwrap();
    assert!(!entities.is_empty(), "no entities in the report");
    let facts = json["facts"].as_array().unwrap();
    for entity in entities {
        let anchor = entity["anchor"].as_str().unwrap();
        // Every listed entity is the entity of at least one fact, and both
        // agree on where it lives.
        let fact = facts
            .iter()
            .find(|fact| fact["anchor"] == *anchor)
            .unwrap_or_else(|| panic!("entity {anchor} has no fact"));
        assert_eq!(entity["location"], fact["location"]);
        assert!(entity["name"].is_string(), "entity {anchor} has no name");
        assert!(
            entity["location"]["runtime"].is_number(),
            "entity {anchor} did not resolve the runtime frame"
        );
    }
    // Functions and symbols are entities; instructions are anchored by rule.
    let kinds: Vec<&str> = entities
        .iter()
        .filter_map(|entity| entity["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"function"), "no function entity: {kinds:?}");
    assert!(kinds.contains(&"symbol"), "no symbol entity: {kinds:?}");
    assert!(
        !kinds.contains(&"instruction"),
        "instructions should not be enumerated: {kinds:?}"
    );
    // The text report lists the same anchors.
    let text = run_mapped_report(&executable, &config, "text");
    assert!(text.contains("; Entities: anchor  kind  location  name"));
    for entity in entities {
        let anchor = entity["anchor"].as_str().unwrap();
        assert!(
            text.contains(&format!("@{anchor}")),
            "the text report omits entity {anchor}"
        );
    }
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 2: forward and reverse cross-references ----------------------------

#[test]
fn a_forward_reference_and_its_reverse_resolve_to_the_same_entity() {
    let (base, executable, config) = mapped_fixture_dir("xrefs");
    let json: serde_json::Value =
        serde_json::from_str(&run_mapped_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();
    let reverse: Vec<&serde_json::Value> = facts
        .iter()
        .filter(|fact| fact["kind"] == "referenced_by")
        .collect();
    assert!(!reverse.is_empty(), "no reverse cross-references");

    // Every forward reference that lands in the image is answered by a reverse
    // link at the target, anchored to the very same entity.
    let mut forward = 0;
    for fact in facts {
        let Some(anchor) = fact["target_anchor"].as_str() else {
            continue;
        };
        forward += 1;
        let site = fact["subject"].as_u64().unwrap();
        let answered = reverse.iter().any(|target| {
            target["anchor"] == anchor
                && target["sites"]
                    .as_array()
                    .is_some_and(|sites| sites.iter().any(|listed| listed.as_u64() == Some(site)))
        });
        assert!(
            answered,
            "no reverse link at {anchor} for the forward reference from {site:#x}: {fact}"
        );
    }
    assert!(forward >= 3, "expected call, operand, and relocation links");

    // And the reverse direction: every listed site really names that target.
    for target in &reverse {
        let anchor = target["anchor"].as_str().unwrap();
        for site in target["sites"].as_array().unwrap() {
            let site = site.as_u64().unwrap();
            assert!(
                facts
                    .iter()
                    .any(|fact| fact["subject"].as_u64() == Some(site)
                        && fact["target_anchor"] == anchor),
                "site {site:#x} is listed under {anchor} but references nothing there"
            );
        }
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn reverse_links_separate_calls_operands_and_relocations() {
    let (base, executable, config) = fixture_dir("xref-kinds");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();
    let reverse = |via: &str, subject: u64| -> Vec<u64> {
        facts
            .iter()
            .find(|fact| {
                fact["kind"] == "referenced_by" && fact["via"] == via && fact["subject"] == subject
            })
            .and_then(|fact| fact["sites"].as_array())
            .unwrap_or_else(|| panic!("no {via} reverse link at {subject:#x}"))
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .collect()
    };
    // `helper` is reached by a BSR and by a relocated pointer: two ways in,
    // two facts, never merged into one undifferentiated list.
    assert_eq!(reverse("call", 0x42), vec![0x3a]);
    assert_eq!(reverse("relocation", 0x42), vec![0x56]);
    // The string is only addressed by an operand.
    assert_eq!(reverse("operand", 0x44), vec![0x0c]);
    // A target outside the image gets no reverse link: there is no entity here.
    assert!(
        !facts
            .iter()
            .any(|fact| fact["kind"] == "referenced_by" && fact["subject"] == 0xdff000u64),
        "a hardware register grew a reverse link"
    );
    // Every reverse fact reports how many sites there were in total.
    for fact in facts.iter().filter(|fact| fact["kind"] == "referenced_by") {
        let sites = fact["sites"].as_array().unwrap().len();
        assert_eq!(
            fact["total"].as_u64(),
            Some(sites as u64),
            "an uncapped list disagrees with its total: {fact}"
        );
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_call_whose_operand_spells_the_address_is_not_counted_twice() {
    let (base, executable, config) = fixture_dir("xref-dedup");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    // The fixture's only call is a BSR, so no operand link may duplicate it.
    for fact in json["facts"].as_array().unwrap() {
        if fact["kind"] != "referenced_by" || fact["via"] != "operand" {
            continue;
        }
        let subject = fact["subject"].as_u64().unwrap();
        let sites: Vec<u64> = fact["sites"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .collect();
        for site in sites {
            let calls_the_same_target = json["facts"].as_array().unwrap().iter().any(|other| {
                other["kind"] == "call"
                    && other["subject"].as_u64() == Some(site)
                    && other["callee"].as_u64() == Some(subject)
            });
            assert!(
                !calls_the_same_target,
                "site {site:#x} is reported both as a caller and as an addresser of {subject:#x}"
            );
        }
    }
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 2: relocation-backed references -----------------------------------

/// A two-hunk executable whose CODE hunk contains:
///
/// - `LEA $0.L,A0` at 0x00, relocated into hunk 1 — an operand whose stored
///   addend says "address zero" and only the relocation says otherwise;
/// - `LEA $8.L,A1` at 0x06, *not* relocated — an addend that happens to land
///   inside this hunk and must not be mistaken for a relocated reference;
/// - `LEA $12.L,A2` at 0x0c, relocated within hunk 0, to the `JSR` at 0x12;
/// - `JSR $0.L` at 0x12, relocated into hunk 1 — a call whose stored addend
///   says "offset zero of this hunk" and which the traversal must not trace
///   there.
fn two_hunk_executable() -> Vec<u8> {
    let code: Vec<u8> = vec![
        0x41, 0xf9, 0x00, 0x00, 0x00, 0x00, // 0x00 LEA $0.L,A0 (reloc -> hunk1+0)
        0x43, 0xf9, 0x00, 0x00, 0x00, 0x08, // 0x06 LEA $8.L,A1 (no relocation)
        0x45, 0xf9, 0x00, 0x00, 0x00, 0x12, // 0x0c LEA $12.L,A2 (reloc -> hunk0+0x12)
        0x4e, 0xb9, 0x00, 0x00, 0x00, 0x00, // 0x12 JSR $0.L (reloc -> hunk1+0)
        0x4e, 0x71, // 0x18 NOP
        0x4e, 0x75, // 0x1a RTS
    ];
    assert_eq!(code.len(), 0x1c);
    let data: Vec<u8> = vec![0x4e, 0x75, 0x4e, 0x75]; // hunk 1: two RTS
    let code_words = u32::try_from(code.len() / 4).unwrap();
    let data_words = u32::try_from(data.len() / 4).unwrap();

    let mut bytes = Vec::new();
    // Header: no name, two hunks, first 0, last 1, then both allocations.
    for word in [0x03f3, 0, 2, 0, 1, code_words, data_words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    // Hunk 0: the code, a RELOC32 block per target hunk, then HUNK_END.
    for word in [0x03e9, code_words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    for word in [0x03ec, 2, 1, 0x02, 0x14, 1, 0, 0x0e, 0, 0x03f2] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    // Hunk 1: the data it points into.
    for word in [0x03e9, data_words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&data);
    bytes.extend_from_slice(&u32::to_be_bytes(0x03f2));
    bytes
}

/// Write the two-hunk executable with an empty config.
fn two_hunk_fixture(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("amiga-re-reloc-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("two-hunk.hunk");
    fs::write(&executable, two_hunk_executable()).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(&config, "").unwrap_or_else(|error| panic!("{error}"));
    (base, executable, config)
}

fn run_two_hunk_report(executable: &Path, config: &Path, format: &str) -> String {
    let output = amiga_re()
        .args(["--config"])
        .arg(config)
        .args(["disasm", "report"])
        .arg(executable)
        .args(["--entry", "0", "--format", format])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

/// Ask the two-hunk fixture a question, as JSON.
fn two_hunk_query(executable: &Path, config: &Path, args: &[&str]) -> serde_json::Value {
    let output = amiga_re()
        .args(["--config"])
        .arg(config)
        .args(["disasm", "query"])
        .arg(executable)
        .args(["--entry", "0", "--format", "json"])
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm query {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("answer is not valid JSON: {error}"))
}

/// A CODE hunk in which three decoded instructions overlap the patched
/// longword at 0x06, and only one of them really owns it:
///
/// - `MOVE.L $00006000.L,$0.L` at 0x00, ten bytes, whose *destination* longword
///   is the patched one — the only reading in which 0x06 is an operand;
/// - `BRA.S 0x04` at 0x0a, which makes the traversal decode
/// - `BRA.W 0x06` at 0x04, four bytes of the `MOVE`'s own encoding, which in
///   turn makes it decode
/// - `ORI.B #0,D0` at 0x06 — the patched longword read as an *opcode*, not as
///   an operand.
///
/// The last one is the trap. "Nearest instruction starting at or before the
/// patched offset that is long enough to contain it" answers 0x06, attributing
/// the relocation to an instruction whose opcode word it overwrites. The
/// operand-range rule the traversal uses answers 0x00. Two rules, two answers,
/// one set of bytes — which is exactly what having two indexes allowed.
fn overlapping_executable() -> Vec<u8> {
    let code: Vec<u8> = vec![
        0x23, 0xf9, // 0x00 MOVE.L (xxx).L,(xxx).L
        0x00, 0x00, 0x60, 0x00, //   source longword — also `BRA.W` at 0x04
        0x00, 0x00, 0x00, 0x00, //   destination longword at 0x06 (reloc -> hunk1+0)
        0x60, 0xf8, // 0x0a BRA.S 0x04 — decode the overlapping readings too
    ];
    assert_eq!(code.len(), 0x0c);
    let data: Vec<u8> = vec![0x4e, 0x75, 0x4e, 0x75]; // hunk 1: two RTS
    let code_words = u32::try_from(code.len() / 4).unwrap();
    let data_words = u32::try_from(data.len() / 4).unwrap();

    let mut bytes = Vec::new();
    for word in [0x03f3, 0, 2, 0, 1, code_words, data_words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    for word in [0x03e9, code_words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    // One RELOC32 record: offset 0x06, into hunk 1.
    for word in [0x03ec, 1, 1, 0x06, 0, 0x03f2] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    for word in [0x03e9, data_words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&data);
    bytes.extend_from_slice(&u32::to_be_bytes(0x03f2));
    bytes
}

#[test]
fn overlapping_instructions_agree_on_which_owns_a_patched_longword() {
    let base = std::env::temp_dir().join(format!("amiga-re-reloc-overlap-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("overlap.hunk");
    fs::write(&executable, overlapping_executable()).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(&config, "").unwrap_or_else(|error| panic!("{error}"));

    let json: serde_json::Value =
        serde_json::from_str(&run_two_hunk_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();

    // All three overlapping readings were decoded — plus the `BRA.S` that
    // forces them — or the fixture proves nothing.
    assert_eq!(
        json["stats"]["hunk"]["instructions"], 4,
        "the overlapping readings were not all decoded: {json}"
    );

    // One patched offset, one owner, and it is the instruction in whose
    // *operand* the longword sits — not the one whose opcode it would
    // overwrite, however neatly that instruction's span contains it.
    let relocation = facts
        .iter()
        .find(|fact| fact["kind"] == "relocation" && fact["subject"] == 0x06)
        .unwrap_or_else(|| panic!("no relocation fact at 0x06: {json}"));
    assert_eq!(relocation["instruction"], 0x00, "{relocation}");
    assert!(
        relocation["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["type"] == "instruction" && item["site"] == 0x00),
        "the fact cites a different instruction than it names: {relocation}"
    );

    // The text renderer reads the same index, so it names the same owner.
    let text = run_two_hunk_report(&executable, &config, "text");
    assert!(
        text.contains("reloc32 (operand of L00000000) -> hunk1+0x0"),
        "the text renderer disagrees with the fact list:\n{text}"
    );

    // And the reference at that same site agrees it is relocation-backed,
    // which is the other half of what the two indexes used to answer apart.
    assert!(
        text.contains("-> hunk1+0x0 [abs operand, reloc32]"),
        "the relocated operand was not resolved through its record:\n{text}"
    );
    // The *source* longword of the same instruction stores a different addend,
    // so it must not be swept up by the same record.
    assert!(
        !text.contains("hunk1+0x6000"),
        "an unrelated addend was read as relocated:\n{text}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_relocation_is_attached_to_the_operand_it_patches() {
    let (base, executable, config) = two_hunk_fixture("operand");
    let json: serde_json::Value =
        serde_json::from_str(&run_two_hunk_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();
    let relocation = |patched: u64| -> &serde_json::Value {
        facts
            .iter()
            .find(|fact| fact["kind"] == "relocation" && fact["subject"] == patched)
            .unwrap_or_else(|| panic!("no relocation at {patched:#x}"))
    };
    // The patched longword of `JSR $0.L` belongs to the instruction at 0x00,
    // and the relocation cites that instruction as well as its own record.
    let cross_hunk = relocation(0x02);
    assert_eq!(cross_hunk["instruction"], 0x00);
    assert_eq!(cross_hunk["target_hunk"], 1);
    let evidence = cross_hunk["evidence"].as_array().unwrap();
    assert!(
        evidence
            .iter()
            .any(|item| item["type"] == "relocation" && item["offset"] == 0x02),
        "the relocation record is not cited: {cross_hunk}"
    );
    assert!(
        evidence
            .iter()
            .any(|item| item["type"] == "instruction" && item["site"] == 0x00),
        "the patched operand's instruction is not cited: {cross_hunk}"
    );
    assert_eq!(relocation(0x0e)["instruction"], 0x0c);
    // The text report names the owning instruction too. A relocation into
    // another hunk shows that hunk's frame only: this report maps hunk 0.
    let text = run_two_hunk_report(&executable, &config, "text");
    assert!(
        text.contains("reloc32 (operand of L00000000) -> hunk1+0x0"),
        "the relocation does not name its operand:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn equal_dual_ea_addends_resolve_only_the_relocated_operand() {
    let base =
        std::env::temp_dir().join(format!("amiga-re-semantic-dual-ea-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("dual-ea.hunk");
    let config = base.join("amiga-re.toml");
    fs::write(&config, "").unwrap_or_else(|error| panic!("{error}"));
    for (patched, source_relocated, destination_relocated) in [(2, true, false), (6, false, true)] {
        fs::write(&executable, dual_ea_executable(patched))
            .unwrap_or_else(|error| panic!("{error}"));
        let output = amiga_re()
            .args(["--config"])
            .arg(&config)
            .args(["disasm", "report"])
            .arg(&executable)
            .args(["--entry", "0", "--format", "json"])
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        assert!(
            output.status.success(),
            "disasm report failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
        let references: Vec<_> = json["facts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|fact| fact["kind"] == "reference" && fact["subject"] == 0)
            .collect();
        assert_eq!(references.len(), 2);
        let source = references
            .iter()
            .find(|fact| fact["operand"] == 2)
            .unwrap_or_else(|| panic!("no source reference: {json}"));
        let destination = references
            .iter()
            .find(|fact| fact["operand"] == 6)
            .unwrap_or_else(|| panic!("no destination reference: {json}"));
        assert_eq!(
            source.get("relocated").and_then(|value| value.as_bool()),
            source_relocated.then_some(true),
            "source relocation disagrees for patched offset {patched}: {json}"
        );
        assert_eq!(
            destination
                .get("relocated")
                .and_then(|value| value.as_bool()),
            destination_relocated.then_some(true),
            "destination relocation disagrees for patched offset {patched}: {json}"
        );
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_relocated_reference_resolves_to_its_target_hunk_not_its_addend() {
    let (base, executable, config) = two_hunk_fixture("addend");
    let text = run_two_hunk_report(&executable, &config, "text");
    // `JSR $0.L` is resolved by its relocation, into the other hunk, and is
    // marked as relocation-backed rather than as an address of this hunk.
    assert!(
        text.contains("-> hunk1+0x0 [abs operand, reloc32]"),
        "the cross-hunk reference was not resolved by its relocation:\n{text}"
    );
    // `LEA $12.L` is relocated within this hunk, so it keeps every frame.
    assert!(
        text.contains("-> hunk0+0x12 (file 0x36) [abs operand, reloc32]"),
        "the in-hunk relocated reference lost its frames:\n{text}"
    );
    // `LEA $8.L` has no relocation: it is read as a plain address, and is not
    // reported as relocation-backed just because its addend is in range.
    assert!(
        text.contains("-> hunk0+0x8 (file 0x2c) [abs operand]"),
        "the unrelocated reference was misreported:\n{text}"
    );
    assert!(
        !text.contains("-> hunk0+0x8 (file 0x2c) [abs operand, reloc32]"),
        "an unrelocated addend was counted as relocated:\n{text}"
    );
    // Four references, all resolved, three of them by relocation.
    assert!(
        text.contains("; References (this report): 4 resolved (3 by relocation), 0 unresolved"),
        "the reference statistics disagree with the relocations:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn text_and_json_do_not_name_a_cross_hunk_reference_from_its_local_addend() {
    let (base, executable, config) = two_hunk_fixture("cross-hunk-symbol");
    fs::write(
        &config,
        r#"
[[symbols]]
addr = 0
name = "wrong_local_zero"
"#,
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let text = run_two_hunk_report(&executable, &config, "text");
    assert!(
        text.contains("-> hunk1+0x0 [abs operand, reloc32]"),
        "the text report lost the relocated destination:\n{text}"
    );
    assert!(
        !text.contains("wrong_local_zero @ hunk1+0x0"),
        "the text report named the target from the stored addend:\n{text}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&run_two_hunk_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let reference = json["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "reference" && fact["subject"] == 0 && fact["operand"] == 2)
        .unwrap_or_else(|| panic!("no cross-hunk reference: {json}"));
    assert_eq!(reference["relocation_target"]["hunk"], 1);
    assert_eq!(reference["relocation_target"]["offset"], 0);
    assert!(reference.get("symbol").is_none(), "{reference}");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_cross_hunk_call_is_external_and_never_an_in_hunk_edge() {
    let (base, executable, config) = two_hunk_fixture("cross-call");
    let json: serde_json::Value =
        serde_json::from_str(&run_two_hunk_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();
    // The relocated `JSR $0.L` resolves to the other hunk, citing both the
    // instruction and the record that proves where it goes.
    let external = facts
        .iter()
        .find(|fact| fact["kind"] == "external_flow")
        .unwrap_or_else(|| panic!("no external-flow fact: {json}"));
    assert_eq!(external["subject"], 0x12);
    assert_eq!(external["transfer"], "call");
    assert_eq!(external["target_hunk"], 1);
    assert_eq!(external["target_offset"], 0);
    // The transfer names the function whose flow reaches it, exactly as a call
    // fact does — that is what makes `callees` answerable from the JSON alone.
    assert_eq!(external["owners"], serde_json::json!([0]));
    assert_eq!(external["owner_total"], 1);
    assert_eq!(external["confidence"], "certain");
    assert_eq!(external["producer"], "control_flow");
    assert_eq!(
        external["evidence"],
        serde_json::json!([
            { "type": "instruction", "site": 0x12 },
            { "type": "relocation", "offset": 0x14 },
        ])
    );
    assert_eq!(json["stats"]["report"]["external_flow"], 1);
    // Nothing at offset zero: no call edge, no invented function entry, and
    // no reverse link claiming this hunk's first byte is a target.
    assert!(
        !facts.iter().any(|fact| fact["kind"] == "call"),
        "a cross-hunk call became an in-hunk call edge: {json}"
    );
    assert_eq!(json["stats"]["hunk"]["calls"], 0);
    let entries: Vec<&serde_json::Value> = facts
        .iter()
        .filter(|fact| fact["kind"] == "function")
        .collect();
    assert_eq!(entries.len(), 1, "unexpected function entries: {entries:?}");
    assert_eq!(entries[0]["entry"], 0);
    assert!(
        !facts
            .iter()
            .any(|fact| fact["kind"] == "referenced_by" && fact["subject"] == 0),
        "a relocated addend became a reverse link into this hunk: {json}"
    );
    // The control flow and the reference at the same site agree on where the
    // operand points, which is the contradiction this fixture guards against.
    let reference = facts
        .iter()
        .find(|fact| fact["kind"] == "reference" && fact["subject"] == 0x12)
        .unwrap_or_else(|| panic!("no reference at 0x12"));
    assert_eq!(reference["relocation_target"]["hunk"], 1);
    assert_eq!(reference["relocation_target"]["offset"], 0);
    // The text listing annotates the site as the transfer it is.
    let text = run_two_hunk_report(&executable, &config, "text");
    assert!(
        text.contains("external_flow     certain   control_flow       external call -> hunk1+0x0"),
        "the external call is not reported:\n{text}"
    );
    // The whole point of the owners payload: the only outgoing transfer of the
    // function at 0x0 leaves the hunk, so `callees` must say "calls hunk 1"
    // rather than "no matches", which would read as "calls nothing".
    let callees = two_hunk_query(&executable, &config, &["callees", "0x0"]);
    assert_eq!(callees["total"], 1, "{callees}");
    assert_eq!(callees["results"][0]["site"], 0x12);
    assert_eq!(callees["results"][0]["fact"], "external_flow");
    assert!(
        callees["results"][0]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("hunk1+0x0"),
        "the answer must name the target hunk: {callees}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_query_reads_a_relocated_operand_the_way_the_report_does() {
    let (base, executable, config) = two_hunk_fixture("query-reloc");
    // Both operands whose addend spells `0` are relocated into hunk 1, so
    // nothing in this hunk is referenced at offset zero — the report says so,
    // and the query must not disagree by reading the raw addend.
    let nothing = two_hunk_query(&executable, &config, &["refs-to", "0x0"]);
    assert_eq!(
        nothing["total"], 0,
        "a cross-hunk addend was answered as a reference into this hunk: {nothing}"
    );
    // The `LEA $12.L,A2` is relocated *within* hunk 0, so it does reference
    // 0x12 — through the record, alongside the relocation itself.
    let here = two_hunk_query(&executable, &config, &["refs-to", "0x12"]);
    let sites: Vec<u64> = here["results"]
        .as_array()
        .unwrap_or_else(|| panic!("results is not an array: {here}"))
        .iter()
        .filter_map(|row| row["site"].as_u64())
        .collect();
    assert_eq!(sites, vec![0x0c, 0x0e], "unexpected refs-to answer: {here}");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn relocation_backed_targets_are_distinguishable_in_json() {
    let (base, executable, config) = two_hunk_fixture("json-reloc");
    let json: serde_json::Value =
        serde_json::from_str(&run_two_hunk_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    assert_eq!(json["stats"]["report"]["references_relocated"], 3);
    assert_eq!(json["stats"]["report"]["references_resolved"], 4);
    assert_eq!(json["stats"]["report"]["references_unresolved"], 0);
    // The cross-hunk reference has no location in this report: the target
    // lives in a hunk this report does not map, and nothing pretends it does.
    let facts = json["facts"].as_array().unwrap();
    let cross = facts
        .iter()
        .find(|fact| fact["kind"] == "reference" && fact["subject"] == 0x00)
        .unwrap_or_else(|| panic!("no reference at 0x0"));
    assert_eq!(cross["target"], 0);
    assert!(cross["target_location"].is_null());
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 2: data regions and previews ---------------------------------------

#[test]
fn a_referenced_string_is_previewed_within_its_own_extent() {
    let (base, executable, config) = fixture_dir("preview");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let region = json["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "data_region")
        .unwrap_or_else(|| panic!("no data region"));
    assert_eq!(region["subject"], 0x44);
    assert_eq!(region["class"], "text");
    assert_eq!(region["text"], "graphics.library");
    assert_eq!(region["truncated"], false);
    // The string and its terminator, not the whole gap to the next code.
    assert_eq!(region["end"], 0x55);
    // Classification is an interpretation, never a decode.
    assert_eq!(region["confidence"], "probable");
    assert_eq!(region["producer"], "data_scan");
    // The operand that made the region interesting is its evidence.
    assert_eq!(
        region["evidence"],
        serde_json::json!([{ "type": "instruction", "site": 0x0c }])
    );
    // And the region is an entity a reference can point at.
    let anchor = region["anchor"].as_str().unwrap();
    assert_eq!(anchor, "h0-data-00000044");
    assert!(
        json["entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["anchor"] == anchor && entity["kind"] == "data_region"),
        "the region is not listed as an entity"
    );
    let _ = fs::remove_dir_all(&base);
}

/// A CODE hunk whose referenced data is deliberately hostile: a string full of
/// control characters, quotes, and markup, plus a pointer table.
fn hostile_data_executable() -> Vec<u8> {
    let mut code: Vec<u8> = vec![
        0x41, 0xfa, 0x00, 0x0a, // 0x00 LEA (0xa,PC),A0 -> 0x0c (hostile string)
        0x43, 0xfa, 0x00, 0x1c, // 0x04 LEA (0x1c,PC),A1 -> 0x22 (pointer table)
        0x4e, 0x75, // 0x08 RTS
        0x4e, 0x71, // 0x0a filler
    ];
    // 0x0c: a string that tries to break a line, a quote, and a tag.
    code.extend_from_slice(b"a\nb\"<script>\\\0");
    while code.len() < 0x22 {
        code.push(0);
    }
    // 0x22: two in-range longwords.
    code.extend_from_slice(&8u32.to_be_bytes());
    code.extend_from_slice(&4u32.to_be_bytes());
    while !code.len().is_multiple_of(4) {
        code.push(0);
    }
    let words = u32::try_from(code.len() / 4).unwrap();
    let mut bytes = Vec::new();
    for word in [0x03f3, 0, 1, 0, 0, words, 0x03e9, words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&u32::to_be_bytes(0x03f2));
    bytes
}

#[test]
fn a_hostile_string_preview_cannot_break_the_output() {
    let base = std::env::temp_dir().join(format!("amiga-re-hostile-data-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("hostile.hunk");
    fs::write(&executable, hostile_data_executable()).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(&config, "").unwrap_or_else(|error| panic!("{error}"));

    let text = run_report(&executable, &config, "text");
    // Every fact stays on one line: the count of fact lines equals the count
    // of lines starting with an `L` label.
    let fact_lines = text
        .lines()
        .filter(|line| line.starts_with('L'))
        .collect::<Vec<_>>();
    assert!(!fact_lines.is_empty(), "no facts:\n{text}");
    assert!(
        fact_lines.iter().any(|line| line.contains("data_region")),
        "no data region:\n{text}"
    );
    // The escaped preview carries no raw control characters or line breaks.
    let preview_line = fact_lines
        .iter()
        .find(|line| line.contains("data text"))
        .unwrap_or_else(|| panic!("no text region:\n{text}"));
    assert!(
        preview_line.contains("\\x0a"),
        "the line break was not escaped: {preview_line}"
    );
    assert!(
        preview_line.contains("\\\\"),
        "the backslash was not escaped: {preview_line}"
    );
    assert!(
        preview_line.contains("\\\""),
        "the quote was not escaped: {preview_line}"
    );
    assert!(
        !preview_line.chars().any(char::is_control),
        "a control character survived: {preview_line}"
    );

    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = json["facts"].as_array().unwrap();
    let string = facts
        .iter()
        .find(|fact| fact["kind"] == "data_region" && fact["class"] == "text")
        .unwrap_or_else(|| panic!("no text region"));
    let preview = string["text"].as_str().unwrap();
    assert!(
        !preview.chars().any(char::is_control),
        "a control character reached JSON: {preview:?}"
    );
    assert!(preview.is_ascii(), "a non-ASCII byte reached JSON");
    assert!(
        preview.len() <= 48 * 4,
        "the preview is not length-bounded: {preview:?}"
    );
    // Anchors, which a renderer may put in markup, never contain file bytes.
    for fact in facts {
        if let Some(anchor) = fact["anchor"].as_str() {
            assert!(
                anchor
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-'),
                "an anchor carries unexpected characters: {anchor}"
            );
        }
    }
    // The pointer table is classified as pointers, with in-range offsets.
    let pointers = facts
        .iter()
        .find(|fact| fact["kind"] == "data_region" && fact["class"] == "pointers")
        .unwrap_or_else(|| panic!("no pointer table: {facts:?}"));
    assert_eq!(pointers["offsets"], serde_json::json!([8, 4]));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_reference_into_a_decoded_instruction_is_reported_as_disputed() {
    let base = std::env::temp_dir().join(format!("amiga-re-disputed-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    // LEA (0,PC),A0 addresses 0x02, inside its own encoding, then RTS. Padded
    // to twelve bytes so the shared `--entry 0x8` names an offset inside the
    // hunk: an entry past the end is refused now, in every command rather than
    // only those with a configured base.
    let code: Vec<u8> = vec![
        0x41, 0xfa, 0x00, 0x00, 0x4e, 0x75, 0x00, 0x00, 0x4e, 0x75, 0x00, 0x00,
    ];
    let words = u32::try_from(code.len() / 4).unwrap();
    let mut bytes = Vec::new();
    for word in [0x03f3, 0, 1, 0, 0, words, 0x03e9, words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&u32::to_be_bytes(0x03f2));
    let executable = base.join("disputed.hunk");
    fs::write(&executable, bytes).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(&config, "").unwrap_or_else(|error| panic!("{error}"));

    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let conflict = json["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "target_conflict")
        .unwrap_or_else(|| panic!("no disagreement reported: {}", json["facts"]));
    assert_eq!(conflict["subject"], 0x02);
    assert_eq!(conflict["conflict"], "into_instruction");
    assert_eq!(conflict["instruction"], 0x00);
    // A disputed offset is not silently previewed as data as well.
    assert!(
        !json["facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fact| fact["kind"] == "data_region" && fact["subject"] == 0x02),
        "a disputed offset was also classified as data"
    );
    let text = run_report(&executable, &config, "text");
    assert!(
        text.contains(
            "disputed target: referenced inside a decoded instruction, not at its start \
             (inside L00000000)"
        ),
        "the disagreement is not explained:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 2: fact-graph queries ----------------------------------------------

/// Run `disasm query` and return its stdout, asserting it succeeded.
fn run_query(executable: &Path, config: &Path, args: &[&str]) -> String {
    let output = amiga_re()
        .args(["--config"])
        .arg(config)
        .args(["disasm", "query"])
        .arg(executable)
        .args(["--entry", "0", "--entry", "0x8"])
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm query {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

/// Run `disasm query` expecting a diagnostic, and return stderr.
fn run_failing_query(executable: &Path, config: &Path, args: &[&str]) -> String {
    let output = amiga_re()
        .args(["--config"])
        .arg(config)
        .args(["disasm", "query"])
        .arg(executable)
        .args(["--entry", "0", "--entry", "0x8"])
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        !output.status.success(),
        "disasm query {args:?} unexpectedly succeeded"
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn query_json(executable: &Path, config: &Path, args: &[&str]) -> serde_json::Value {
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(args);
    serde_json::from_str(&run_query(executable, config, &all))
        .unwrap_or_else(|error| panic!("answer is not valid JSON: {error}"))
}

#[test]
fn queries_answer_the_stage_two_questions() {
    let (base, executable, config) = fixture_dir("query");

    // Who calls `helper`?
    let callers = query_json(&executable, &config, &["callers", "0x42"]);
    assert_eq!(callers["question"], "callers");
    assert_eq!(callers["total"], 1);
    assert_eq!(callers["results"][0]["site"], 0x3a);
    assert_eq!(callers["results"][0]["fact"], "call");
    assert_eq!(callers["results"][0]["location"]["offset"], 0x3a);

    // What does `init_gfx` call? The BSR at 0x3a is on its flow.
    let callees = query_json(&executable, &config, &["callees", "0x8"]);
    assert_eq!(callees["total"], 1);
    assert_eq!(callees["results"][0]["site"], 0x3a);

    // Entry 0x0 branches to 0x2c and flows through the same BSR, so it owns
    // that call too. Ownership is a set, not "whichever traversal decoded the
    // instruction first" — answering nothing here would read as "calls
    // nothing" rather than "shares a tail with 0x8".
    let shared = query_json(&executable, &config, &["callees", "0x0"]);
    assert_eq!(shared["total"], 1, "{shared}");
    assert_eq!(shared["results"][0]["site"], 0x3a);

    // What names the string at 0x44?
    let refs = query_json(&executable, &config, &["refs-to", "0x44"]);
    assert_eq!(refs["total"], 1);
    assert_eq!(refs["results"][0]["site"], 0x0c);
    assert!(
        refs["results"][0]["description"]
            .as_str()
            .unwrap()
            .contains("addresses it")
    );

    // Both a call and a relocation reach `helper`.
    let to_helper = query_json(&executable, &config, &["refs-to", "0x42"]);
    assert_eq!(to_helper["total"], 2);
    let sites: Vec<u64> = to_helper["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["site"].as_u64())
        .collect();
    assert_eq!(sites, vec![0x3a, 0x56]);

    // Who writes the A5 global?
    let global = query_json(&executable, &config, &["global", "A5+0x8"]);
    assert_eq!(global["total"], 1);
    assert_eq!(global["results"][0]["site"], 0x14);
    assert!(
        global["results"][0]["description"]
            .as_str()
            .unwrap()
            .starts_with("write")
    );

    // Who writes DMACON, by name and by offset?
    let by_name = query_json(&executable, &config, &["register", "DMACON"]);
    assert_eq!(by_name["total"], 1);
    assert_eq!(by_name["results"][0]["site"], 0x20);
    let by_offset = query_json(&executable, &config, &["register", "$096"]);
    assert_eq!(by_offset["results"], by_name["results"]);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_query_answer_agrees_with_the_report_it_is_derived_from() {
    let (base, executable, config) = fixture_dir("query-parity");
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = report["facts"].as_array().unwrap();

    // The reverse-link fact and the query must name the same caller sites.
    let reverse: Vec<u64> = facts
        .iter()
        .find(|fact| {
            fact["kind"] == "referenced_by" && fact["via"] == "call" && fact["subject"] == 0x42
        })
        .and_then(|fact| fact["sites"].as_array())
        .unwrap_or_else(|| panic!("no reverse call link"))
        .iter()
        .filter_map(serde_json::Value::as_u64)
        .collect();
    let queried: Vec<u64> = query_json(&executable, &config, &["callers", "0x42"])["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["site"].as_u64())
        .collect();
    assert_eq!(reverse, queried);

    // Same question, same answer, every time.
    let first = run_query(&executable, &config, &["refs-to", "0x42"]);
    let second = run_query(&executable, &config, &["refs-to", "0x42"]);
    assert_eq!(first, second, "the query is not deterministic");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn callees_are_reproducible_from_the_json_report_alone() {
    let (base, executable, config) = fixture_dir("query-ownership");
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = report["facts"].as_array().unwrap();
    let call = facts
        .iter()
        .find(|fact| fact["kind"] == "call")
        .unwrap_or_else(|| panic!("no call fact: {report}"));
    // Ownership is a payload of the fact, so a consumer holding only the JSON
    // can answer "what does this function call?" without the analysis. Both
    // entries reach the call: 0x8 decodes the shared block, and 0x0 branches
    // into it at 0x2c and flows on through 0x3a.
    assert_eq!(call["subject"], 0x3a);
    assert_eq!(call["owners"], serde_json::json!([0x0, 0x8]));
    assert_eq!(call["owner_total"], 2);

    // Reproduce the query from the facts, then ask the CLI the same question.
    let from_facts: Vec<u64> = facts
        .iter()
        .filter(|fact| {
            fact["kind"] == "call"
                && fact["owners"]
                    .as_array()
                    .is_some_and(|owners| owners.contains(&serde_json::json!(0x8)))
        })
        .filter_map(|fact| fact["subject"].as_u64())
        .collect();
    let answer = query_json(&executable, &config, &["callees", "0x8"]);
    let queried: Vec<u64> = answer["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["site"].as_u64())
        .collect();
    assert_eq!(from_facts, queried);
    // Nothing was capped, and the answer says so rather than staying silent.
    assert_eq!(answer["ownership_capped"], 0);
    assert!(
        !run_query(&executable, &config, &["callees", "0x8"]).contains("owning functions"),
        "an uncapped answer should not warn about ownership"
    );

    // An offset with no function entry is refused, using the same facts.
    let text = run_failing_query(&executable, &config, &["callees", "0x2a"]);
    assert!(
        text.contains("no function entry at"),
        "expected a refusal naming the missing entry:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_query_bounds_its_results_and_says_when_it_did() {
    let (base, executable, config) = fixture_dir("query-limit");
    let text = run_query(&executable, &config, &["refs-to", "0x42", "--limit", "1"]);
    assert!(
        text.contains("; Showing 1 of 2 matches"),
        "the bound is not reported:\n{text}"
    );
    let json = query_json(&executable, &config, &["refs-to", "0x42", "--limit", "1"]);
    assert_eq!(json["total"], 2);
    assert_eq!(json["truncated"], true);
    assert_eq!(json["results"].as_array().unwrap().len(), 1);
    // An unbounded answer says so too.
    let json = query_json(&executable, &config, &["refs-to", "0x42"]);
    assert_eq!(json["truncated"], false);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn no_match_is_distinguishable_from_a_rejected_question() {
    let (base, executable, config) = fixture_dir("query-empty");
    // A well-formed question with nothing to report is not an error.
    let text = run_query(&executable, &config, &["callers", "0x2a"]);
    assert!(
        text.contains("; No matches."),
        "expected no matches:\n{text}"
    );
    let json = query_json(&executable, &config, &["callers", "0x2a"]);
    assert_eq!(json["total"], 0);
    assert_eq!(json["results"].as_array().unwrap().len(), 0);

    // A subject the report cannot resolve is refused with a reason.
    let outside = run_failing_query(&executable, &config, &["callers", "0x1000"]);
    assert!(
        outside.contains("outside hunk 0"),
        "unhelpful diagnostic: {outside}"
    );
    let unknown = run_failing_query(&executable, &config, &["register", "NOTAREGISTER"]);
    assert!(
        unknown.contains("not a known custom-chip register"),
        "unhelpful diagnostic: {unknown}"
    );
    let malformed = run_failing_query(&executable, &config, &["global", "A9+0x2"]);
    assert!(
        malformed.contains("address register"),
        "unhelpful diagnostic: {malformed}"
    );
    // `callees` needs a function entry, not any address inside one.
    let not_a_function = run_failing_query(&executable, &config, &["callees", "0x14"]);
    assert!(
        not_a_function.contains("no function entry"),
        "unhelpful diagnostic: {not_a_function}"
    );
    let _ = fs::remove_dir_all(&base);
}

// --- Stage 1: unified annotated listing --------------------------------------

fn run_annotate(executable: &Path, config: &Path, verbose: bool) -> String {
    let mut command = amiga_re();
    command
        .args(["--config"])
        .arg(config)
        .args(["disasm", "annotate"])
        .arg(executable)
        .args(["--entry", "0", "--entry", "0x8"]);
    if verbose {
        command.arg("--verbose");
    }
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm annotate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

fn run_subcommand(executable: &Path, config: &Path, args: &[&str]) -> String {
    let mut command = amiga_re();
    command.args(["--config"]).arg(config).args(&args[..2]);
    command.arg(executable);
    command.args(&args[2..]);
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "amiga-re {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("output not UTF-8: {error}"))
}

#[test]
fn annotate_compact_and_verbose_match_goldens() {
    let (base, executable, config) = fixture_dir("annotate");
    let compact = run_annotate(&executable, &config, false);
    assert_eq!(
        compact,
        run_annotate(&executable, &config, false),
        "annotate output is not deterministic"
    );
    assert_matches_golden(&compact, "semantic-annotate.txt");
    let verbose = run_annotate(&executable, &config, true);
    assert_matches_golden(&verbose, "semantic-annotate-verbose.txt");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn annotate_marks_uncertain_annotations_and_keeps_warnings() {
    let (base, executable, config) = fixture_dir("markers");
    let compact = run_annotate(&executable, &config, false);
    // Inferred library naming and base-relative hardware access are marked.
    assert!(compact.contains("; ~exec.library/OpenLibrary"));
    assert!(compact.contains("; ~write DMACON"));
    // The conflicting call site shows the ambiguity, not a certain winner.
    assert!(compact.contains("; ?lvo -30: exec.library|graphics.library"));
    // Exact facts carry no marker.
    assert!(compact.contains("; read INTENAR"));
    assert!(compact.contains("; write A5+0x8"));
    // The unresolved indirect jump warning survives annotation selection.
    assert!(compact.contains("; !unresolved flow"));
    // Config symbols and discovered functions label the listing.
    assert!(compact.contains("init_gfx:"));
    assert!(compact.contains("helper:"));
    assert!(compact.contains("sub_0:"));
    let _ = fs::remove_dir_all(&base);
}

/// Stage 1 acceptance: the unified listing agrees with the standalone
/// commands on the shared fixture.
#[test]
fn annotate_agrees_with_standalone_commands() {
    let (base, executable, config) = fixture_dir("parity");
    let annotate = run_annotate(&executable, &config, false);
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let facts = report["facts"].as_array().unwrap();

    // hw xref: both hardware accesses, same registers and directions.
    let hw = run_subcommand(
        &executable,
        &config,
        &["hw", "xref", "--entry", "0", "--entry", "0x8"],
    );
    assert!(hw.contains("0x00000020") && hw.contains("DMACON"));
    assert!(hw.contains("0x00000030") && hw.contains("INTENAR"));
    assert!(annotate.contains("~write DMACON") && annotate.contains("read INTENAR"));
    let hardware_sites: Vec<u64> = facts
        .iter()
        .filter(|fact| fact["kind"] == "hardware_access")
        .map(|fact| fact["subject"].as_u64().unwrap())
        .collect();
    assert_eq!(hardware_sites, vec![0x20, 0x30]);

    // xref refs: same reference sites as the report's reference facts.
    let refs = run_subcommand(
        &executable,
        &config,
        &["xref", "refs", "--entry", "0", "--entry", "0x8"],
    );
    let reference_sites: Vec<u64> = facts
        .iter()
        .filter(|fact| fact["kind"] == "reference")
        .map(|fact| fact["subject"].as_u64().unwrap())
        .collect();
    // 0x0 and 0x8 are the two `MOVEA.L (0x4).W,A6` reads. They are references
    // like any other operand that names an address — under `abs.w`, which is
    // the kind that stops a consumer reading `0x4` as hunk offset 4.
    assert_eq!(reference_sites, vec![0x0, 0x8, 0x0c, 0x1a, 0x30]);
    for site in &reference_sites {
        assert!(
            refs.contains(&format!("{site:#010x}")),
            "xref refs is missing site {site:#x}:\n{refs}"
        );
    }

    // disasm globals: the A5 slot with the same direction and size.
    let globals = run_subcommand(
        &executable,
        &config,
        &["disasm", "globals", "--entry", "0", "--entry", "0x8"],
    );
    assert!(globals.contains("A5+0x8"), "missing A5 slot:\n{globals}");
    assert!(annotate.contains("write A5+0x8"));

    // disasm fixed-point: the same multiply idiom and Q scale.
    let fixed = run_subcommand(
        &executable,
        &config,
        &["disasm", "fixed-point", "--entry", "0", "--entry", "0x8"],
    );
    assert!(fixed.contains("L00000036") && fixed.contains("scaled multiply"));
    assert!(fixed.contains("(Q8)"));
    let fixed_fact = facts
        .iter()
        .find(|fact| fact["kind"] == "fixed_point")
        .unwrap_or_else(|| panic!("no fixed_point fact"));
    assert_eq!(fixed_fact["subject"], 0x36);
    assert_eq!(fixed_fact["fractional_bits"], 8);
    // The local idiom remains a hint, but the unresolved JMP can introduce
    // unknown predecessors, so no propagated Q scale is trustworthy.
    assert!(!facts.iter().any(|fact| fact["kind"] == "q_scale"));

    let _ = fs::remove_dir_all(&base);
}

// --- config-supplied fd tables -----------------------------------------------

/// A tiny fd table overriding a curated exec vector and naming a vector the
/// curated tables do not know.
const FIXTURE_FD: &str = "\
* sample exec fd table
##base _SysBase
##bias 552
MyOpenLibrary(libName,version)(a1,d0)
##bias 780
ShinyNewCall(x)(d0)
##end
";

#[test]
fn fd_tables_extend_and_override_the_curated_lvo_names() {
    let (base, executable, _config) = fixture_dir("fd");
    fs::write(base.join("exec_lib.fd"), FIXTURE_FD).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("config-fd.toml");
    fs::write(
        &config,
        format!("{FIXTURE_CONFIG}\n[[fd]]\nlibrary = \"exec\"\npath = \"exec_lib.fd\"\n"),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    // The fd name wins over the curated OpenLibrary for the same vector.
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let call = report["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "library_call" && fact["subject"] == 0x10)
        .unwrap_or_else(|| panic!("no library_call fact at the OpenLibrary site"));
    assert_eq!(call["function"], "MyOpenLibrary");
    assert_eq!(call["library"], "exec.library");
    let annotate = run_annotate(&executable, &config, false);
    assert!(
        annotate.contains("~exec.library/MyOpenLibrary"),
        "annotate did not use the fd name:\n{annotate}"
    );
    let _ = fs::remove_dir_all(&base);
}

/// The same vector, described inside a `##private` region.
const PRIVATE_FIXTURE_FD: &str = "\
* sample exec fd table with a private region
##base _SysBase
##private
##bias 552
InternalOpen(libName,version)(a1,d0)
##end
";

#[test]
fn a_private_fd_vector_is_marked_rather_than_read_as_public_api() {
    let (base, executable, _config) = fixture_dir("fd-private");
    fs::write(base.join("exec_lib.fd"), PRIVATE_FIXTURE_FD)
        .unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("config-fd.toml");
    fs::write(
        &config,
        format!("{FIXTURE_CONFIG}\n[[fd]]\nlibrary = \"exec\"\npath = \"exec_lib.fd\"\n"),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let call = report["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "library_call" && fact["subject"] == 0x10)
        .unwrap_or_else(|| panic!("no library_call fact at the OpenLibrary site"));
    assert_eq!(call["function"], "InternalOpen");
    // The curated tables never name a private vector, so without this field a
    // consumer could not tell documented API from an internal entry point.
    assert_eq!(call["public"], false, "{call}");

    // A vector the same table leaves outside a `##private` region, and every
    // curated name, stay public — the field must mark, not blanket.
    let unnamed = report["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "library_call" && fact["subject"] != 0x10)
        .unwrap_or_else(|| panic!("expected a second library_call fact"));
    assert_eq!(unnamed["public"], true, "{unnamed}");

    // Text output says so where a human reads it.
    let text = run_report(&executable, &config, "text");
    assert!(
        text.contains("exec.library/InternalOpen (private)"),
        "the private vector is not marked in text output:\n{text}"
    );
    let annotate = run_annotate(&executable, &config, false);
    assert!(
        annotate.contains("InternalOpen (private)"),
        "annotate did not mark the private vector:\n{annotate}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_broken_fd_table_is_a_hard_error() {
    let (base, executable, _config) = fixture_dir("fd-broken");
    fs::write(base.join("exec_lib.fd"), "##bogus\n").unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("config-fd.toml");
    fs::write(
        &config,
        format!("{FIXTURE_CONFIG}\n[[fd]]\nlibrary = \"exec\"\npath = \"exec_lib.fd\"\n"),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["disasm", "report"])
        .arg(&executable)
        .args(["--entry", "0", "--entry", "0x8"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(!output.status.success(), "malformed fd table was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exec_lib.fd"),
        "error does not name the fd file: {stderr}"
    );
    let _ = fs::remove_dir_all(&base);
}

/// A minimal executable that opens `mathffp.library` and calls its first
/// vector: only a config fd table can name calls through an `Other` library.
fn mathffp_executable() -> Vec<u8> {
    let mut code = vec![
        0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6 (ExecBase)
        0x43, 0xfa, 0x00, 0x12, // 0x04 LEA (0x12,PC),A1 -> 0x18 "mathffp.library"
        0x4e, 0xae, 0xfd, 0xd8, // 0x08 JSR (-552,A6) = OpenLibrary
        0x2c, 0x40, // 0x0c MOVEA.L D0,A6
        0x4e, 0xae, 0xff, 0xe2, // 0x0e JSR (-30,A6) = mathffp/SPFix (fd-named)
        0x4e, 0x75, // 0x12 RTS
        0x4e, 0x71, // 0x14 pad
        0x4e, 0x71, // 0x16 pad
    ];
    code.extend_from_slice(b"mathffp.library\0"); // 0x18..0x28
    assert_eq!(code.len() % 4, 0);
    let words = u32::try_from(code.len() / 4).unwrap();
    let mut bytes = Vec::new();
    for word in [0x03f3, 0, 1, 0, 0, words, 0x03e9, words] {
        bytes.extend_from_slice(&u32::to_be_bytes(word));
    }
    bytes.extend_from_slice(&code);
    bytes.extend_from_slice(&u32::to_be_bytes(0x03f2));
    bytes
}

#[test]
fn fd_tables_name_calls_through_other_libraries() {
    let base =
        std::env::temp_dir().join(format!("amiga-re-semantic-mathffp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("mathffp.hunk");
    fs::write(&executable, mathffp_executable()).unwrap_or_else(|error| panic!("{error}"));
    fs::write(
        base.join("mathffp_lib.fd"),
        "##base _MathBase\n##bias 30\nSPFix(parm)(d0)\n##end\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(
        &config,
        "[[fd]]\nlibrary = \"mathffp.library\"\npath = \"mathffp_lib.fd\"\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["disasm", "report"])
        .arg(&executable)
        .args(["--format", "json"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(
        output.status.success(),
        "disasm report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let call = report["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "library_call" && fact["subject"] == 0x0e)
        .unwrap_or_else(|| panic!("no library_call fact at the mathffp call site"));
    assert_eq!(call["library"], "mathffp.library");
    assert_eq!(call["function"], "SPFix");
    assert_eq!(call["confidence"], "inferred");
    // The fd table's registers become typed call arguments. D0 has no value
    // here and the argument says which stop cost it: the call the fixture makes
    // before this one, past which nothing is live.
    assert_eq!(
        call["arguments"],
        serde_json::json!([{ "name": "parm", "register": "d0", "unresolved": "call" }])
    );

    // The text report renders the same signature.
    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["disasm", "report"])
        .arg(&executable)
        .output()
        .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        text.contains("mathffp.library/SPFix(parm=d0=?call)"),
        "text report lacks the fd signature:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn resolution_statistics_agree_between_the_two_renderers() {
    // The measurement exists to settle a decision, so it has to be the same
    // measurement whichever renderer a reader reaches for. Both are folded from
    // one fact list; this asserts the folding is not undone on the way out.
    let (base, executable, config) = fixture_dir("resolution");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let resolution = &json["stats"]["report"]["resolution"];
    let count = |key: &str| {
        resolution[key]
            .as_u64()
            .unwrap_or_else(|| panic!("{key} missing from the resolution stats: {resolution}"))
    };

    // Both partitions cover every site exactly once.
    let sites = count("sites");
    assert_eq!(
        count("unknown_library") + count("named") + count("unnamed_vector"),
        sites,
        "the naming partition does not cover every site: {resolution}"
    );
    assert_eq!(
        count("unknown_library") + count("described") + count("undescribed"),
        sites,
        "the description partition does not cover every site: {resolution}"
    );

    // Every argument is exact, symbolic, or accounted for by exactly one
    // reason, so a histogram can never quietly omit a lost value.
    let reasons: u64 = resolution["reasons"]
        .as_object()
        .unwrap_or_else(|| panic!("reasons is not an object: {resolution}"))
        .values()
        .map(|count| count.as_u64().unwrap_or_default())
        .sum();
    assert_eq!(
        count("resolved") + count("symbolic") + reasons,
        count("arguments"),
        "arguments are neither resolved nor explained: {resolution}"
    );

    // The text report states the same numbers.
    let text = run_report(&executable, &config, "text");
    let expected = format!(
        "; Library calls (this report): {sites} sites — {} named, {} unnamed vector, \
         {} unknown base; {} described, {} undescribed",
        count("named"),
        count("unnamed_vector"),
        count("unknown_library"),
        count("described"),
        count("undescribed")
    );
    assert!(
        text.contains(&expected),
        "text header disagrees with the JSON.\nexpected: {expected}\n{text}"
    );
    let arguments = format!(
        "; Call arguments (this report): {}/{} resolved",
        count("resolved"),
        count("arguments")
    );
    assert!(
        text.contains(&arguments),
        "text argument line disagrees with the JSON.\nexpected: {arguments}\n{text}"
    );
    // The fixture's own reading, so a regression in the walk shows up here as
    // well as in the golden: both described arguments are refused because the
    // fixture contains an unresolved indirect jump.
    assert!(
        text.contains("; Unresolved because: unresolved_flow 2"),
        "the reason histogram is missing or changed:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn symbolic_values_and_refusal_reasons_are_counted_apart() {
    // The shared fixture contains an unresolved jump, which refuses every value
    // for one reason, so it cannot show the histogram doing its job. This one
    // has no unresolved flow and classifies its four arguments three ways:
    //
    //   AllocMem   d0  nothing before the entry sets it   -> no_predecessor
    //              d1  written from memory                -> symbolic
    //   OpenLibrary a1 the AllocMem call clobbers it      -> call
    //              d0  likewise                           -> call
    //
    // Counting the symbolic expression as either exact or refused would hide
    // the distinction the whole measurement exists to draw.
    let code = vec![
        0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6 (ExecBase)
        0x22, 0x2a, 0x00, 0x08, // 0x04 MOVE.L (8,A2),D1
        0x4e, 0xae, 0xff, 0x3a, // 0x08 JSR (-198,A6) = exec/AllocMem
        0x4e, 0xae, 0xfd, 0xd8, // 0x0c JSR (-552,A6) = exec/OpenLibrary
        0x4e, 0x71, // 0x10 NOP
        0x4e, 0x75, // 0x12 RTS
    ];
    let words = u32::try_from(code.len() / 4).expect("the fixture is a whole number of longwords");
    let mut executable = Vec::new();
    for word in [0x03f3, 0, 1, 0, 0, words, 0x03e9, words] {
        executable.extend_from_slice(&u32::to_be_bytes(word));
    }
    executable.extend_from_slice(&code);
    executable.extend_from_slice(&u32::to_be_bytes(0x03f2));

    let base =
        std::env::temp_dir().join(format!("amiga-re-semantic-reasons-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let path = base.join("reasons.hunk");
    fs::write(&path, &executable).unwrap_or_else(|error| panic!("{error}"));

    let run = |format: &str| {
        let output = amiga_re()
            .args(["disasm", "report"])
            .arg(&path)
            .args(["--entry", "0", "--format", format])
            .output()
            .unwrap_or_else(|error| panic!("failed to run amiga-re: {error}"));
        assert!(
            output.status.success(),
            "disasm report failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("not UTF-8: {error}"))
    };

    let json: serde_json::Value =
        serde_json::from_str(&run("json")).unwrap_or_else(|error| panic!("not JSON: {error}"));
    let resolution = &json["stats"]["report"]["resolution"];
    assert_eq!(resolution["arguments"], 4, "{resolution}");
    assert_eq!(resolution["resolved"], 0, "{resolution}");
    assert_eq!(resolution["symbolic"], 1, "{resolution}");
    assert_eq!(
        resolution["reasons"],
        serde_json::json!({
            "no_predecessor": 1,
            "call": 2,
        }),
        "the refusal reasons were not kept apart: {resolution}"
    );

    let symbolic = json["facts"]
        .as_array()
        .and_then(|facts| {
            facts.iter().find_map(|fact| {
                (fact["kind"] == "library_call" && fact["function"] == "AllocMem")
                    .then(|| fact["arguments"][1]["symbolic"].clone())
            })
        })
        .expect("AllocMem should carry its symbolic requirements argument");
    assert_eq!(symbolic["rendered"], "memory32[A2+$8]");
    assert_eq!(symbolic["source"]["kind"], "register_relative");
    assert_eq!(symbolic["source"]["register"], "A2");
    assert_eq!(symbolic["source"]["displacement"], 8);
    assert_eq!(symbolic["offset"], 0);

    let text = run("text");
    // Declaration order in the list, so the line stays diffable; the leader is
    // named separately because declaration order is not count order.
    assert!(
        text.contains(
            "; Call arguments (this report): 0/4 resolved (0.0%); 1 symbolic; 3 refused by the walk"
        ),
        "the exact/symbolic/refused partition is wrong:\n{text}"
    );
    assert!(
        text.contains("; Unresolved because: no_predecessor 1, call 2 (most often call)"),
        "the histogram or its leader is wrong:\n{text}"
    );
    assert!(
        text.contains("requirements=d1=~memory32[A2+$8]"),
        "the symbolic argument was not distinguished in text:\n{text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_narrowed_report_counts_only_what_it_kept() {
    // The counters are folded from the kept facts, so narrowing must shrink
    // them. The header says "this report" for exactly this reason: a narrowed
    // count that read as a whole-program measurement would be the wrong input
    // to the decision this measurement exists to settle.
    let (base, executable, config) = fixture_dir("resolution-narrowed");
    let whole: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    let narrowed: serde_json::Value = serde_json::from_str(&run_report_with(
        &executable,
        &config,
        "json",
        &["--only", "hardware"],
    ))
    .unwrap_or_else(|error| panic!("narrowed report is not valid JSON: {error}"));

    let sites = |report: &serde_json::Value| {
        report["stats"]["report"]["resolution"]["sites"]
            .as_u64()
            .unwrap_or_else(|| panic!("sites missing: {report}"))
    };
    assert!(sites(&whole) > 0, "the fixture has no library calls");
    assert_eq!(
        sites(&narrowed),
        0,
        "a report narrowed to hardware facts still counted library calls"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn hostile_config_names_cannot_break_the_line_shape() {
    let (base, executable, _config) = fixture_dir("hostile");
    let config = base.join("config-hostile.toml");
    fs::write(
        &config,
        "[[symbols]]\naddr = 0x8\nname = \"evil\\nname:\\tx\"\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let report = run_report(&executable, &config, "text");
    // The control characters are replaced, so the symbol stays on one line.
    assert!(report.contains("symbol evil?name:?x"), "{report}");
    let annotate = run_annotate(&executable, &config, true);
    assert!(annotate.contains("evil?name:?x"), "{annotate}");
    assert!(
        !annotate.contains("evil\nname"),
        "control character survived into the listing:\n{annotate}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn fd_register_groups_pair_with_parameters_by_matching_count() {
    let (base, executable, _config) = fixture_dir("fd-groups");
    // One vector pairs params to comma groups (64-bit d0/d1 + d2/d3 pairs),
    // the other flat-zips because the flattened count matches.
    fs::write(
        base.join("mathdouble_lib.fd"),
        "##base _MathDoubBas\n##bias 66\nIEEEDPAdd(y,z)(d0/d1,d2/d3)\n\
         ##bias 552\nMyOpen(a,b,c)(a1,d0/d1)\n##end\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("config-fd.toml");
    fs::write(
        &config,
        "[[fd]]\nlibrary = \"exec\"\npath = \"mathdouble_lib.fd\"\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let report: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("report is not valid JSON: {error}"));
    // The fixture's OpenLibrary call (lvo -552) picks up the second entry.
    let call = report["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact["kind"] == "library_call" && fact["subject"] == 0x10)
        .unwrap_or_else(|| panic!("no library_call fact at the OpenLibrary site"));
    assert_eq!(call["function"], "MyOpen");
    // The shared fixture contains an unresolved jump, which refuses every value
    // in the function that reaches it — so all three arguments name the same
    // stop rather than silently having none.
    assert_eq!(
        call["arguments"],
        serde_json::json!([
            { "name": "a", "register": "a1", "unresolved": "unresolved_flow" },
            { "name": "b", "register": "d0", "unresolved": "unresolved_flow" },
            { "name": "c", "register": "d1", "unresolved": "unresolved_flow" },
        ])
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_narrowed_report_says_what_it_left_out() {
    // The acceptance criterion this stage turns on: a filtered report states
    // what it excluded, and a narrowed one is never mistakable for a complete
    // one. Both renderers have to say so, not just the human one.
    let (base, executable, config) = fixture_dir("narrowed");
    let text = run_report_with(&executable, &config, "text", &["--function", "0x42"]);
    assert!(text.contains("; Selection: function 0x42"), "{text}");
    assert!(text.contains("; Excluded:"), "{text}");
    assert!(text.contains("This report is NOT complete"), "{text}");
    // The selected function is still described; the others are gone.
    assert!(text.contains("F00000042"), "{text}");
    assert!(!text.contains("F00000008"), "{text}");

    let json: serde_json::Value = serde_json::from_str(&run_report_with(
        &executable,
        &config,
        "json",
        &["--function", "0x42"],
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(json["selection"]["complete"], false);
    assert_eq!(json["selection"]["description"], "function 0x42");
    assert!(
        json["selection"]["excluded"]["by_selection"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(json["functions"].as_array().map(Vec::len), Some(1));

    let _ = fs::remove_dir_all(base);
}

#[test]
fn an_unnarrowed_report_states_its_completeness_rather_than_implying_it() {
    // Absence of an "excluded" section is not evidence of completeness, so the
    // JSON says so outright.
    let (base, executable, config) = fixture_dir("complete");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(json["selection"]["complete"], true);
    assert_eq!(json["selection"]["excluded"]["by_selection"], 0);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_category_filter_keeps_only_what_was_asked_for() {
    let (base, executable, config) = fixture_dir("categories");
    let json: serde_json::Value = serde_json::from_str(&run_report_with(
        &executable,
        &config,
        "json",
        &["--only", "hardware"],
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    let kinds: Vec<String> = json["facts"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|fact| fact["kind"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(!kinds.is_empty(), "the filter kept nothing");
    assert!(
        kinds.iter().all(|kind| kind == "hardware_access"),
        "a category filter leaked other kinds: {kinds:?}"
    );
    assert!(
        json["selection"]["excluded"]["by_category"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn every_fact_a_function_header_states_is_in_the_report() {
    // The stage's other acceptance criterion. The headers are a fold of the
    // fact list, so anything they mention must be findable below them.
    let (base, executable, config) = fixture_dir("summaries");
    let json: serde_json::Value = serde_json::from_str(&run_report(&executable, &config, "json"))
        .unwrap_or_else(|error| panic!("{error}"));
    let facts = json["facts"].as_array().cloned().unwrap_or_default();
    for function in json["functions"].as_array().cloned().unwrap_or_default() {
        let entry = function["entry"].as_u64().unwrap_or_default();
        for callee in function["callees"].as_array().cloned().unwrap_or_default() {
            let callee = callee.as_u64().unwrap_or_default();
            assert!(
                facts.iter().any(|fact| {
                    fact["kind"] == "call" && fact["callee"].as_u64() == Some(callee)
                }),
                "function {entry:#x} claims a call to {callee:#x} with no call fact"
            );
        }
        for site in function["unresolved_exits"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let site = site.as_u64().unwrap_or_default();
            assert!(
                facts.iter().any(|fact| {
                    fact["kind"] == "unresolved_flow" && fact["subject"].as_u64() == Some(site)
                }),
                "function {entry:#x} claims an unresolved exit at {site:#x} with no fact"
            );
        }
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn the_call_graph_is_written_beside_the_report_with_the_same_anchors() {
    let (base, executable, config) = fixture_dir("dot");
    let dot_path = base.join("callgraph.dot");
    let text = run_report_with(
        &executable,
        &config,
        "text",
        &["--dot", dot_path.to_str().unwrap_or_default()],
    );
    assert!(text.contains("; Call graph:"), "{text}");
    let dot = fs::read_to_string(&dot_path).unwrap_or_else(|error| panic!("{error}"));
    assert!(dot.starts_with("digraph callgraph {"), "{dot}");
    // The same anchor the report's index uses, so following one lands on the
    // same entity in either artifact.
    assert!(dot.contains("h0-fn-00000042"), "{dot}");
    assert!(
        dot.contains(r#""h0-fn-00000000" -> "h0-fn-00000042""#),
        "{dot}"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn an_existing_graph_is_not_replaced_without_force() {
    // Generating a report must not write beside source media unless the
    // destination was explicitly chosen — and never over something already
    // there.
    let (base, executable, config) = fixture_dir("dot-force");
    let dot_path = base.join("callgraph.dot");
    fs::write(&dot_path, b"user data").unwrap_or_else(|error| panic!("{error}"));
    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["disasm", "report"])
        .arg(&executable)
        .args(["--entry", "0", "--dot"])
        .arg(&dot_path)
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!output.status.success(), "an existing graph was replaced");
    assert_eq!(
        fs::read_to_string(&dot_path).unwrap_or_default(),
        "user data"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_narrowed_report_does_not_claim_a_caller_is_a_leaf() {
    // The defect this guards: `leaf` is the one header field that is true
    // because facts are *absent*, so filtering out the call facts turned a
    // caller into a claimed leaf — a new wrong claim rather than an omission.
    let (base, executable, config) = fixture_dir("leaf");
    let complete: serde_json::Value =
        serde_json::from_str(&run_report(&executable, &config, "json"))
            .unwrap_or_else(|error| panic!("{error}"));
    let caller = complete["functions"]
        .as_array()
        .and_then(|functions| {
            functions.iter().find(|function| {
                function["callees"]
                    .as_array()
                    .is_some_and(|c| !c.is_empty())
            })
        })
        .cloned()
        .unwrap_or_default();
    assert_eq!(caller["leaf"], false, "the fixture has no calling function");

    let narrowed: serde_json::Value = serde_json::from_str(&run_report_with(
        &executable,
        &config,
        "json",
        &["--only", "hardware"],
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    for function in narrowed["functions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        assert!(
            function["leaf"].is_null(),
            "a narrowed report answered the leaf question: {function}"
        );
    }
    let text = run_report_with(&executable, &config, "text", &["--only", "hardware"]);
    assert!(
        !text.contains("leaf (calls nothing)"),
        "a narrowed report printed a leaf claim:\n{text}"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_configured_name_cannot_inject_a_row_into_the_index() {
    // Config symbols are the only free text in a report. An unescaped newline
    // in one would add an index row and make the function count above it false.
    let base = std::env::temp_dir().join(format!(
        "amiga-re-semantic-injection-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap_or_else(|error| panic!("{error}"));
    let executable = base.join("fixture.hunk");
    fs::write(&executable, fixture_executable()).unwrap_or_else(|error| panic!("{error}"));
    let config = base.join("amiga-re.toml");
    fs::write(
        &config,
        "[[symbols]]\nname = \"helper\\nF00000099  @evil  0x0..0x0  99  9/9  spoofed\"\naddr = 0x42\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let text = run_report(&executable, &config, "text");
    let index_rows = text
        .lines()
        .filter(|line| line.starts_with('F') && line.contains("0x"))
        .count();
    let declared = text
        .lines()
        .find_map(|line| line.strip_prefix("; Functions: "))
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or_default();
    assert_eq!(
        index_rows, declared,
        "the index has more rows than it declares:\n{text}"
    );
    assert!(
        !text.lines().any(|line| line.starts_with("F00000099")),
        "a configured name started a row of its own:\n{text}"
    );
    // The control character is replaced, not passed through.
    assert!(
        text.contains("helper?F00000099"),
        "the injected newline was not sanitized:\n{text}"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_rejected_invocation_writes_no_call_graph() {
    // Every argument is checked before anything is written, so a report that
    // was never produced leaves nothing behind.
    let (base, executable, config) = fixture_dir("dot-format");
    let dot_path = base.join("callgraph.dot");
    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["disasm", "report"])
        .arg(&executable)
        .args(["--entry", "0", "--format", "bogus", "--dot"])
        .arg(&dot_path)
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!output.status.success());
    assert!(
        !dot_path.exists(),
        "a rejected invocation left a call graph behind"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn the_index_can_be_ordered_by_name_as_well_as_by_address() {
    let (base, executable, config) = fixture_dir("order");
    let by_name = run_report_with(&executable, &config, "text", &["--order", "name"]);
    let names: Vec<&str> = by_name
        .lines()
        .filter(|line| line.starts_with('F'))
        .filter_map(|line| line.split_whitespace().last())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "--order name did not order by name:\n{by_name}"
    );
    // The default stays address order, which is what the analysis found.
    let by_address = run_report(&executable, &config, "text");
    let entries: Vec<&str> = by_address
        .lines()
        .filter(|line| line.starts_with('F'))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let mut ascending = entries.clone();
    ascending.sort_unstable();
    assert_eq!(entries, ascending);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_subsystem_filter_narrows_the_hardware_category() {
    let (base, executable, config) = fixture_dir("subsystem");
    let json: serde_json::Value = serde_json::from_str(&run_report_with(
        &executable,
        &config,
        "json",
        &["--only", "hardware", "--subsystem", "dma"],
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    let facts = json["facts"].as_array().cloned().unwrap_or_default();
    assert!(!facts.is_empty(), "the subsystem filter kept nothing");
    assert!(
        facts.iter().all(|fact| fact["subsystem"] == "dma"),
        "a subsystem filter leaked other subsystems: {facts:?}"
    );
    // And an unknown subsystem is refused rather than matching nothing.
    let output = amiga_re()
        .args(["--config"])
        .arg(&config)
        .args(["disasm", "report"])
        .arg(&executable)
        .args(["--entry", "0", "--subsystem", "nonsense"])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!output.status.success());
    let _ = fs::remove_dir_all(base);
}
