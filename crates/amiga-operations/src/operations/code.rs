//! The setup every `analysis.code.*` operation needs, in one place.
//!
//! Locating a CODE hunk, refusing one that is not code, checking the entry
//! offsets, reading the relocations, and tracing control flow are the same five
//! steps for a disassembly, a cross-reference, a call graph, a globals map, and
//! a fixed-point scan. Five copies of them is how one of the five ends up
//! analyzing the same image differently — which is exactly what `xref to` was
//! doing before it routed. One copy, and the question of *which* traversal
//! answered a request stops having more than one answer.

use crate::diagnostics::{Diagnostic, DiagnosticCode};

/// Refuse bytes that do not match the request's explicit pin.
pub(crate) fn verify_pin(
    source: &crate::source::ResolvedSource,
    expected_sha256: Option<&str>,
) -> Result<(), Diagnostic> {
    if let Some(expected) = expected_sha256
        && !source.sha256().eq_ignore_ascii_case(expected)
    {
        return Err(Diagnostic::error(
            DiagnosticCode::SourceDigestMismatch,
            format!(
                "the source hashes to {}, not the pinned {expected}",
                source.sha256()
            ),
        )
        .at("$.request.arguments.expected_sha256"));
    }
    Ok(())
}

/// Validate entry offsets into a raw code image.
pub(crate) fn raw_code_length(bytes: &[u8], entries: &[u32]) -> Result<u32, Diagnostic> {
    let Ok(length) = u32::try_from(bytes.len()) else {
        return Err(Diagnostic::error(
            DiagnosticCode::AnalysisCodeUndecodable,
            format!(
                "raw code holds {} bytes, more than an offset can name",
                bytes.len()
            ),
        ));
    };
    if let Some(outside) = entries
        .iter()
        .find(|entry| **entry >= length || !entry.is_multiple_of(2))
    {
        return Err(Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            format!(
                "entry {outside:#x} is not an even offset inside the raw image's {length:#x} bytes"
            ),
        )
        .at("$.request.arguments.entries"));
    }
    Ok(length)
}

/// A located CODE hunk, ready to analyze.
pub(crate) struct CodeHunk<'a> {
    pub(crate) executable: amiga_hunk::Executable<'a>,
    pub(crate) hunk: u32,
    pub(crate) code: &'a [u8],
    /// The hunk's length, which every offset in a response is bounded by.
    pub(crate) hunk_bytes: u32,
}

/// Locate `hunk` as CODE and check that every entry offset names an
/// instruction boundary inside it.
///
/// Returns the diagnostic to report rather than pushing it, so the caller keeps
/// its own `outcome` shape and its own status.
pub(crate) fn locate<'a>(
    bytes: &'a [u8],
    hunk: u32,
    entries: &[u32],
) -> Result<CodeHunk<'a>, Diagnostic> {
    let executable = amiga_hunk::Executable::parse(bytes).map_err(|error| {
        Diagnostic::error(DiagnosticCode::AnalysisHunkUnreadable, error.to_string())
    })?;
    let Some(segment) = executable.segment(hunk) else {
        return Err(Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            format!("the image has no hunk {hunk}"),
        )
        .at("$.request.arguments.hunk"));
    };
    // A BSS or DATA hunk holds no instructions, and analyzing it anyway would
    // produce a plausible answer about something that is not code. Refused by
    // name, as every unsupported shape in this toolkit is.
    if segment.kind != amiga_hunk::SegmentKind::Code {
        return Err(Diagnostic::error(
            DiagnosticCode::AnalysisHunkUnreadable,
            format!("hunk {hunk} is {}, not CODE", segment.kind),
        )
        .at("$.request.arguments.hunk"));
    }
    let code = segment.bytes;
    let Ok(hunk_bytes) = u32::try_from(code.len()) else {
        return Err(Diagnostic::error(
            DiagnosticCode::AnalysisHunkUnreadable,
            format!(
                "hunk {hunk} holds {} bytes, more than an offset can name",
                code.len()
            ),
        ));
    };
    // An odd entry is not an instruction boundary — an MC68000 raises an
    // address error on the first fetch — and one past the end names no byte at
    // all. Either would traverse nothing and report a hunk with no code in it.
    if let Some(outside) = entries
        .iter()
        .find(|entry| **entry >= hunk_bytes || !entry.is_multiple_of(2))
    {
        return Err(Diagnostic::error(
            DiagnosticCode::RequestArgumentOutOfRange,
            format!(
                "entry {outside:#x} is not an even offset inside hunk {hunk}'s {hunk_bytes:#x} \
                 bytes"
            ),
        )
        .at("$.request.arguments.entries"));
    }
    Ok(CodeHunk {
        executable,
        hunk,
        code,
        hunk_bytes,
    })
}

impl CodeHunk<'_> {
    /// Trace control flow from `entries`, reading absolute operands through the
    /// image's own relocations.
    ///
    /// The relocations are read here rather than asked for: they are a fact
    /// about the image, and a request that carried them could describe an image
    /// other than the one it names. A record whose stored longword could not be
    /// read is left out — it proves nothing about where the operand points, and
    /// the traversal must not act on it.
    pub(crate) fn analyze(
        &self,
        entries: &[u32],
        origin: Option<u32>,
    ) -> amiga_disasm::ControlFlowAnalysis {
        let relocations = amiga_disasm::Relocations::new(
            self.hunk,
            self.executable
                .relocations
                .iter()
                .filter(|relocation| relocation.source_hunk == self.hunk)
                .filter_map(|relocation| {
                    Some(amiga_disasm::Relocation {
                        patched: relocation.source_offset,
                        target_hunk: relocation.target_hunk,
                        target_offset: self.executable.stored_pointer(relocation)?,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let options = amiga_disasm::FlowOptions {
            rebase: origin.map(amiga_disasm::Rebase::new),
            relocations: Some(relocations),
        };
        amiga_disasm::analyze_entries_with(self.code, entries, &options)
    }
}
