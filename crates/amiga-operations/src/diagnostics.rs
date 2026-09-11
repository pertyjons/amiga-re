//! Stable diagnostic codes and their structured locations.
//!
//! The code and the location are the contract. Human messages may be reworded
//! without a protocol-version decision, so consumers must never parse them.

use serde::Serialize;

/// How severely a diagnostic affects the operation that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The operation could not produce its result.
    Error,
    /// The operation produced a result that a caller must interpret carefully.
    Warning,
    /// Context that changes nothing about how the result should be read.
    Note,
}

/// A stable machine-readable reason a diagnostic was emitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticCode {
    /// The document declares a `protocol_version` this build cannot serve.
    RequestProtocolVersionUnsupported,
    /// The document is not a well-formed request.
    RequestMalformed,
    /// The request carries a project locator for an operation that takes none.
    RequestProjectUnsupported,
    /// The operation runs against a project and the request named none.
    RequestProjectRequired,
    /// The request asks for an event mode this build cannot deliver.
    RequestEventsUnsupported,
    /// The request asks for an execution mode this operation does not offer.
    RequestExecutionModeUnsupported,
    /// A numeric argument lies outside the range the operation accepts.
    RequestArgumentOutOfRange,
    /// A source name is not a usable canonical identity.
    RequestSourceNameInvalid,
    /// A request-settable limit was reduced to the context's own ceiling.
    LimitReduced,
    /// The work described exceeds an aggregate ceiling, and is refused whole.
    ///
    /// Distinct from [`DiagnosticCode::LimitReduced`], which negotiates a
    /// request down and proceeds. This one cannot: truncating a *listing* is a
    /// defensible answer, but truncating an extraction leaves a destination
    /// that looks complete and is not. So nothing is written and the refusal
    /// names the limit, what was reached, and what would have to change.
    LimitExceeded,
    /// The named source is not available to the resolver.
    SourceMissing,
    /// The named source exists but could not be read.
    SourceUnreadable,
    /// The named source is larger than the effective input limit.
    SourceTooLarge,
    /// The result list was capped; the response reports the true total.
    ResultRegionsTruncated,
    /// The entry list was capped; the response reports the true total.
    ResultEntriesTruncated,
    /// The source is not a readable AmigaDOS volume.
    ContainerAdfUnreadable,
    /// The source is not a readable container of the requested kind.
    ContainerUnreadable,
    /// The named project could not be loaded.
    ProjectUnreadable,
    /// `.amiga-re/local.json` exists but could not be used, in whole or in
    /// part. A warning rather than an error: the project still loads, and the
    /// sources whose overrides were dropped report as unbound.
    LocalBindingsUnreadable,
    /// The project loaded and carries problems.
    ProjectHasProblems,
    /// The bytes on disk contradict what the project pins.
    ProjectContradicted,
    /// The resource cannot be turned into bytes by this build: no decoder for
    /// its kind, no encoder for its export profile, or a target space the
    /// export path cannot address yet. Stated rather than silently skipped.
    ProjectResourceUnexportable,
    /// The volume was read despite a boot block whose checksum does not verify.
    /// The filesystem does not depend on the boot block, so the walk continued.
    ContainerAdfBootChecksumInvalid,
    /// A file declares a size of zero yet still points at a first data block.
    /// The declared size won and the pointer was ignored.
    ContainerAdfEmptyFileWithDataPointer,
    /// The requested geometry decodes to more pixels than the effective limit
    /// allows. Refused from the declared geometry, before anything is read.
    GraphicsOutputTooLarge,
    /// The planar data starts past the end of the source.
    GraphicsOffsetOutsideSource,
    /// The source does not hold the planar data the geometry describes —
    /// usually too few bytes for the requested planes and dimensions.
    GraphicsPlanarUndecodable,
    /// The adapter offered no output root, so nothing may be written.
    OutputDestinationUnavailable,
    /// The destination resolved but is not something a write may target.
    OutputDestinationUnusable,
    /// The plan the caller approved no longer describes what would be written.
    OutputPlanChanged,
    /// The destination itself refuses the write: present under `create_only`,
    /// or holding files the prior manifest does not account for.
    OutputDestinationRefused,
    /// A container member could not be recovered and was left out. The
    /// extraction still describes every member it did recover.
    ContainerMemberSkipped,
    /// A member the container names is damaged: this build walked its chain and
    /// could not read it whole. Distinct from
    /// [`Self::ContainerMemberSkipped`], which is a member this build declines
    /// to decode — an LHA method with no decoder — where the bytes are intact
    /// and a later build would recover them. This one says the bytes are gone.
    /// The member is absent from the plan rather than written short.
    ContainerMemberUnreadable,
    /// The decoded image could not be encoded in the requested output format.
    GraphicsEncodeFailed,
    /// One or more colour words are not `$0RGB` — their high nibble is not zero.
    /// Counted rather than refused: a table with one stray entry is still the
    /// table, and the count is what tells a caller whether an offset guess was
    /// good.
    GraphicsPaletteWordInvalid,
    /// The source is not a readable HUNK executable.
    AnalysisHunkUnreadable,
    /// The comparison could not be rendered in the requested report format.
    AnalysisReportEncodeFailed,
    /// The requested byte range lies outside the source.
    SourceRangeOutsideSource,
    /// A record could not be read even though its bytes are present.
    AnalysisRecordUnreadable,
    /// The source is not a readable IFF 8SVX sample.
    AudioSampleUnreadable,
    /// The sample could not be encoded in the requested output format.
    AudioEncodeFailed,
    /// The sandbox memory map the request describes cannot be built: regions
    /// overlap, an address overflows, or a relocation site is unmapped.
    SandboxMemoryUnmappable,
    /// A blit asked for hardware this build does not implement: line mode, or a
    /// write to `BLTSIZH` on an OCS chipset, where it starts nothing at all.
    ///
    /// Not raised for `BLTCON0L` or `BLTSIZV`, which prepare state and start
    /// nothing even on ECS; those stay observations on the record.
    SandboxBlitterUnsupported,
    /// A blit this run would not perform: a channel outside the mapped memory,
    /// an address that overflowed, blitter DMA disabled under a policy that
    /// requires it, or a run out of blit budget.
    ///
    /// The value of the code is that the record says a blit did **not** happen.
    /// The failure worth removing is an incomplete picture nothing reported.
    SandboxBlitterRefused,
    /// A blit ran with `DMACON` saying blitter DMA was off, under the default
    /// policy that assumes it on. Raised once per run.
    ///
    /// A call starts in the middle of a program, after an initialization the
    /// sandbox never ran, so `DMACON` holding zero says nothing about what the
    /// program intended — but the assumption is still an assumption.
    SandboxBlitterDmaAssumed,
    /// The source already parses as an ordinary HUNK executable, so there is
    /// nothing to normalize. Rewriting it anyway would read ordinary records as
    /// compact ones and shift every record after the first.
    AnalysisHunkAlreadyNormal,
    /// The source holds no tracker module at the offset the request named.
    AudioModuleUnreadable,
    /// The source is not a packed stream of the requested kind, or it ends
    /// before the stream it declares does.
    CompressStreamUnreadable,
    /// A range of a CODE hunk could not be decoded as MC68000 instructions:
    /// the range is outside the hunk, an opcode is not one this decoder knows,
    /// or an instruction would run past the requested end.
    AnalysisCodeUndecodable,
    /// The stream carried a size field and decoded to a different length. The
    /// decoded bytes are still reported — the field is a claim about them, and
    /// a claim that disagrees is a fact about the source worth surfacing rather
    /// than a reason to refuse what decoded.
    CompressDeclaredSizeMismatch,
    /// A source's bytes do not hash to the digest the request pinned them with.
    ///
    /// Distinct from a missing or unreadable source, and the distinction is the
    /// point: the file is there and readable, and it is not the one the recipe
    /// names. A run seeded from it would produce outputs that look like evidence
    /// about a file it never read.
    SourceDigestMismatch,
}

impl DiagnosticCode {
    /// Every code this build can emit.
    ///
    /// Exists so `every_diagnostic_code_appears_in_the_schema` can compare the
    /// vocabulary against the bundled `diagnostic.schema.json`. The schema
    /// enumerates the codes, so one it has not heard of makes a response this
    /// toolkit legitimately produced fail validation — a stale enum is a broken
    /// contract, not a documentation lag.
    pub const ALL: &'static [Self] = &[
        Self::RequestProtocolVersionUnsupported,
        Self::RequestMalformed,
        Self::RequestProjectUnsupported,
        Self::RequestProjectRequired,
        Self::RequestEventsUnsupported,
        Self::RequestExecutionModeUnsupported,
        Self::RequestArgumentOutOfRange,
        Self::RequestSourceNameInvalid,
        Self::LimitReduced,
        Self::LimitExceeded,
        Self::SourceMissing,
        Self::SourceUnreadable,
        Self::SourceTooLarge,
        Self::SourceRangeOutsideSource,
        Self::ResultRegionsTruncated,
        Self::ResultEntriesTruncated,
        Self::ContainerAdfUnreadable,
        Self::ContainerUnreadable,
        Self::ContainerAdfBootChecksumInvalid,
        Self::ContainerAdfEmptyFileWithDataPointer,
        Self::ContainerMemberSkipped,
        Self::ContainerMemberUnreadable,
        Self::ProjectUnreadable,
        Self::LocalBindingsUnreadable,
        Self::ProjectHasProblems,
        Self::ProjectContradicted,
        Self::ProjectResourceUnexportable,
        Self::GraphicsOutputTooLarge,
        Self::GraphicsOffsetOutsideSource,
        Self::GraphicsPlanarUndecodable,
        Self::GraphicsEncodeFailed,
        Self::GraphicsPaletteWordInvalid,
        Self::AnalysisHunkUnreadable,
        Self::AnalysisReportEncodeFailed,
        Self::AnalysisRecordUnreadable,
        Self::AnalysisHunkAlreadyNormal,
        Self::AnalysisCodeUndecodable,
        Self::SandboxMemoryUnmappable,
        Self::SandboxBlitterUnsupported,
        Self::SandboxBlitterRefused,
        Self::SandboxBlitterDmaAssumed,
        Self::AudioSampleUnreadable,
        Self::AudioEncodeFailed,
        Self::AudioModuleUnreadable,
        Self::CompressStreamUnreadable,
        Self::CompressDeclaredSizeMismatch,
        Self::SourceDigestMismatch,
        Self::OutputDestinationUnavailable,
        Self::OutputDestinationUnusable,
        Self::OutputDestinationRefused,
        Self::OutputPlanChanged,
    ];

    /// Whether this code means the request was refused before any work ran.
    ///
    /// Drives the dedicated "invalid request" process exit code, which exists
    /// so automation can distinguish a bad request from a failed operation.
    #[must_use]
    pub const fn is_request_validation(self) -> bool {
        matches!(
            self,
            Self::RequestProtocolVersionUnsupported
                | Self::RequestMalformed
                | Self::RequestProjectUnsupported
                | Self::RequestProjectRequired
                | Self::RequestEventsUnsupported
                | Self::RequestExecutionModeUnsupported
                | Self::RequestArgumentOutOfRange
                | Self::RequestSourceNameInvalid
        )
    }
}

/// One machine-readable finding about a request or its execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub severity: Severity,
    pub message: String,
    /// JSON Pointer-style path into the request document, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<String>,
    /// The `kind:value` identity of what this diagnostic is about, when the
    /// subject is a thing inside the source rather than a place in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn error(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Error, message)
    }

    #[must_use]
    pub fn warning(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Warning, message)
    }

    #[must_use]
    pub fn note(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Note, message)
    }

    /// A diagnostic whose severity the caller chooses.
    ///
    /// Exists for a handler that carries another layer's findings through: a
    /// project problem already has a severity, and re-deciding it here would
    /// make one finding mean two different things.
    #[must_use]
    pub fn new_with_severity(
        code: DiagnosticCode,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self::new(code, severity, message)
    }

    fn new(code: DiagnosticCode, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            json_path: None,
            entity_id: None,
        }
    }

    /// Attach the request location this diagnostic refers to.
    #[must_use]
    pub fn at(mut self, json_path: impl Into<String>) -> Self {
        self.json_path = Some(json_path.into());
        self
    }

    /// Attach the `kind:value` identity this diagnostic is about.
    #[must_use]
    pub fn about(mut self, entity_id: impl Into<String>) -> Self {
        self.entity_id = Some(entity_id.into());
        self
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.severity, Severity::Error)
    }
}
