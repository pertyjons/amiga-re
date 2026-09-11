//! The diagnostic vocabulary and the schema that describes it agree.
//!
//! `diagnostic.schema.json` enumerates the codes, and the response schema refers
//! to it, so a response carrying a code the enum has not heard of fails
//! validation — against a schema this build ships. A lagging enum is therefore a
//! broken contract rather than a documentation gap, and it lagged badly: the
//! enum listed sixteen of thirty-six codes before this test existed, so any
//! consumer validating a response about a sample, an export plan, or a project
//! would have rejected it.

use std::collections::BTreeSet;

use amiga_operations::DiagnosticCode;

/// The wire spelling of `code`, taken from the serializer rather than restated,
/// so this cannot drift from what a response actually carries.
fn wire(code: DiagnosticCode) -> String {
    serde_json::to_value(code)
        .unwrap_or_else(|error| panic!("a diagnostic code serializes: {error}"))
        .as_str()
        .unwrap_or_else(|| panic!("a diagnostic code serializes as a string"))
        .to_owned()
}

fn schema_codes() -> BTreeSet<String> {
    let schema: serde_json::Value =
        serde_json::from_str(amiga_operations::descriptor::schemas::DIAGNOSTIC)
            .unwrap_or_else(|error| panic!("the diagnostic schema is valid JSON: {error}"));
    schema["properties"]["code"]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("the diagnostic schema enumerates its codes"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("every enumerated code is a string"))
                .to_owned()
        })
        .collect()
}

#[test]
fn all_lists_every_code_exactly_once_and_in_catalog_order() {
    // Exhaustive by construction: a new variant cannot be added without deciding
    // where it sits, which is what keeps `ALL` honest. Same guard the operation
    // catalog uses, for the same reason.
    const fn position(code: DiagnosticCode) -> usize {
        match code {
            DiagnosticCode::RequestProtocolVersionUnsupported => 0,
            DiagnosticCode::RequestMalformed => 1,
            DiagnosticCode::RequestProjectUnsupported => 2,
            DiagnosticCode::RequestProjectRequired => 3,
            DiagnosticCode::RequestEventsUnsupported => 4,
            DiagnosticCode::RequestExecutionModeUnsupported => 5,
            DiagnosticCode::RequestArgumentOutOfRange => 6,
            DiagnosticCode::RequestSourceNameInvalid => 7,
            DiagnosticCode::LimitReduced => 8,
            DiagnosticCode::LimitExceeded => 9,
            DiagnosticCode::SourceMissing => 10,
            DiagnosticCode::SourceUnreadable => 11,
            DiagnosticCode::SourceTooLarge => 12,
            DiagnosticCode::SourceRangeOutsideSource => 13,
            DiagnosticCode::ResultRegionsTruncated => 14,
            DiagnosticCode::ResultEntriesTruncated => 15,
            DiagnosticCode::ContainerAdfUnreadable => 16,
            DiagnosticCode::ContainerUnreadable => 17,
            DiagnosticCode::ContainerAdfBootChecksumInvalid => 18,
            DiagnosticCode::ContainerAdfEmptyFileWithDataPointer => 19,
            DiagnosticCode::ContainerMemberSkipped => 20,
            DiagnosticCode::ContainerMemberUnreadable => 21,
            DiagnosticCode::ProjectUnreadable => 22,
            DiagnosticCode::LocalBindingsUnreadable => 23,
            DiagnosticCode::ProjectHasProblems => 24,
            DiagnosticCode::ProjectContradicted => 25,
            DiagnosticCode::ProjectResourceUnexportable => 26,
            DiagnosticCode::GraphicsOutputTooLarge => 27,
            DiagnosticCode::GraphicsOffsetOutsideSource => 28,
            DiagnosticCode::GraphicsPlanarUndecodable => 29,
            DiagnosticCode::GraphicsEncodeFailed => 30,
            DiagnosticCode::GraphicsPaletteWordInvalid => 31,
            DiagnosticCode::AnalysisHunkUnreadable => 32,
            DiagnosticCode::AnalysisReportEncodeFailed => 33,
            DiagnosticCode::AnalysisRecordUnreadable => 34,
            DiagnosticCode::AnalysisHunkAlreadyNormal => 35,
            DiagnosticCode::AnalysisCodeUndecodable => 36,
            DiagnosticCode::SandboxMemoryUnmappable => 37,
            DiagnosticCode::SandboxBlitterUnsupported => 38,
            DiagnosticCode::SandboxBlitterRefused => 39,
            DiagnosticCode::SandboxBlitterDmaAssumed => 40,
            DiagnosticCode::AudioSampleUnreadable => 41,
            DiagnosticCode::AudioEncodeFailed => 42,
            DiagnosticCode::AudioModuleUnreadable => 43,
            DiagnosticCode::CompressStreamUnreadable => 44,
            DiagnosticCode::CompressDeclaredSizeMismatch => 45,
            DiagnosticCode::SourceDigestMismatch => 46,
            DiagnosticCode::OutputDestinationUnavailable => 47,
            DiagnosticCode::OutputDestinationUnusable => 48,
            DiagnosticCode::OutputDestinationRefused => 49,
            DiagnosticCode::OutputPlanChanged => 50,
        }
    }

    assert_eq!(DiagnosticCode::ALL.len(), 51);
    for (index, code) in DiagnosticCode::ALL.iter().enumerate() {
        assert_eq!(position(*code), index, "{code:?} is out of order in ALL");
    }
}

#[test]
fn the_schema_enumerates_every_code_this_build_can_emit() {
    let listed = schema_codes();
    let emitted: BTreeSet<String> = DiagnosticCode::ALL.iter().copied().map(wire).collect();

    let missing: Vec<&String> = emitted.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "diagnostic.schema.json does not enumerate {missing:?}; a response carrying one \
         would fail validation against a schema this build ships"
    );

    // And the other direction: an enum entry with no code behind it would tell a
    // consumer to expect something that can never arrive.
    let unreachable: Vec<&String> = listed.difference(&emitted).collect();
    assert!(
        unreachable.is_empty(),
        "diagnostic.schema.json enumerates {unreachable:?}, which no code produces"
    );
}
