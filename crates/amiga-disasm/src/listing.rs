//! Text listings from decoded MC68000 code.
//!
//! Two forms: a plain [`linear`] sweep over an explicit range, and a
//! control-flow-aware [`render`] that labels every byte, emitting reached
//! instructions and marking everything else as `DC.W`/`DC.B`. As the listing
//! itself notes, unreached does not prove data — only that recursive direct
//! control flow did not arrive there.

use std::fmt::Write;

use m68000::instruction::Instruction;
use m68000::memory_access::MemoryAccess;
use thiserror::Error;

use crate::control_flow::ControlFlowAnalysis;

/// A failure while producing a listing.
#[derive(Debug, Error)]
pub enum DisasmError {
    #[error("start address {start:#x} must be word-aligned")]
    UnalignedStart { start: u32 },
    #[error("range {start:#x}..{end:#x} is outside the {len:#x}-byte code")]
    RangeOutOfBounds { start: u32, end: u32, len: usize },
    #[error("instruction decode failed at {address:#x}: exception vector {detail}")]
    DecodeFailed { address: u32, detail: String },
    #[error("instruction at {address:#x} extends past the requested end {end:#x}")]
    RunsPastEnd { address: u32, end: u32 },
    #[error("address {address:#x} does not fit the host address space")]
    AddressOverflow { address: u32 },
    #[error("failed to format listing")]
    Format(#[from] std::fmt::Error),
}

/// Static-coverage statistics for an analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Coverage {
    pub total_bytes: usize,
    pub decoded_bytes: usize,
    pub instructions: usize,
    pub functions: usize,
    /// Statically resolved direct calls, counted as distinct (site, callee)
    /// pairs rather than as control-flow edges.
    pub calls: usize,
    /// Convention-explained `JSR`/`JMP (d16,An)` library-call sites.
    pub library_calls: usize,
    /// Control flow with no static target and no explaining convention.
    pub unresolved: usize,
    /// Calls and jumps a relocation proves leave the analyzed hunk. They are
    /// resolved, so they are not counted as [`Self::unresolved`], but they are
    /// not [`Self::calls`] of this hunk either.
    pub external: usize,
}

impl Coverage {
    /// Fraction of bytes reached by control flow, as a percentage.
    #[must_use]
    pub fn percent(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.decoded_bytes as f64 / self.total_bytes as f64 * 100.0
        }
    }
}

/// Summarize how much of `total_bytes` the `analysis` reached.
#[must_use]
pub fn coverage(analysis: &ControlFlowAnalysis, total_bytes: usize) -> Coverage {
    Coverage {
        total_bytes,
        decoded_bytes: analysis
            .instructions
            .values()
            .map(|instruction| instruction.encoded.len())
            .sum(),
        instructions: analysis.instructions.len(),
        functions: analysis.functions.len(),
        // Distinct (site, callee) pairs: shared code records one edge per
        // owning entry, so counting edges would report the same call once per
        // entry that reaches it. A dispatch site resolving to several callees
        // stays several calls, which is what the pair — rather than the site
        // alone — preserves. This matches the call facts a report emits.
        calls: analysis
            .calls
            .iter()
            .map(|call| (call.call_site, call.callee))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        library_calls: analysis.library_calls.len(),
        // Distinct sites: the same undecodable address reached from several
        // owners is one unresolved site, matching the per-address facts a
        // semantic report emits.
        unresolved: analysis
            .unresolved
            .iter()
            .map(|unresolved| unresolved.address)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        // Distinct sites here too, for the same reason.
        external: analysis
            .external
            .iter()
            .map(|external| external.site)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
    }
}

/// Width the flow listing pads its instruction column to, so that the `; …`
/// comments line up under one another.
///
/// Public because the command line renders the same listing from
/// `analysis.code.disassemble`'s instructions rather than through [`render`],
/// and the two must produce identical lines. A caller that pads to its own
/// number is the drift this constant exists to prevent.
pub const FLOW_INSTRUCTION_COLUMN: usize = 28;

fn hex_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// One instruction from a linear sweep, decoded but not rendered.
///
/// The mnemonic arrives as text because that is what the decoder produces and
/// what every consumer wants; the *layout* of a listing line is not decided
/// here. A caller that wants a listing formats these, and a caller that wants
/// the facts reads them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SweptInstruction {
    pub address: u32,
    /// Address of the following instruction.
    pub end: u32,
    pub encoded: Vec<u8>,
    /// The mnemonic and its operands, as the decoder renders them.
    pub text: String,
}

/// Decode `code` linearly over `start..end`, one entry per instruction.
///
/// # Errors
/// Returns [`DisasmError`] if `start` is not word-aligned, the range is outside
/// `code`, an instruction fails to decode, or an instruction would extend past
/// `end`.
pub fn sweep(code: &[u8], start: u32, end: u32) -> Result<Vec<SweptInstruction>, DisasmError> {
    if !start.is_multiple_of(2) {
        return Err(DisasmError::UnalignedStart { start });
    }
    let end_usize =
        usize::try_from(end).map_err(|_| DisasmError::AddressOverflow { address: end })?;
    if start > end || end_usize > code.len() {
        return Err(DisasmError::RangeOutOfBounds {
            start,
            end,
            len: code.len(),
        });
    }

    // **The decoder must never be able to read past the buffer**, because
    // `m68000` *panics* when an extension word cannot be fetched rather than
    // failing the decode. The last word of a range routinely begins an
    // instruction that wants one: `0x0000` — the longword padding a HUNK image
    // gets, and an ordinary run of zeroes at the end of a code hunk — decodes as
    // `ORI.B`, which reads an immediate. Sweeping such a hunk took the process
    // down with a stack trace out of a dependency.
    //
    // Padding is the same answer `control_flow::decode` already gives for the
    // same reason, and it fabricates nothing: the bounds below are unchanged, so
    // an instruction that really does extend past `end` is still reported as
    // [`DisasmError::RunsPastEnd`] rather than completed out of the padding.
    let padded;
    // The longest an instruction can be: opcode plus two long extensions.
    const EXTENSION_HEADROOM: usize = 10;
    let headroom = end_usize.saturating_add(EXTENSION_HEADROOM);
    let mut swept = Vec::new();
    // `iter_u16` borrows its receiver mutably for the iterator's lifetime, so it
    // reads through a separate binding while `code` stays available for slicing.
    let mut memory = if code.len() >= headroom {
        code
    } else {
        padded = {
            let mut bytes = code.to_vec();
            bytes.resize(headroom, 0);
            bytes
        };
        padded.as_slice()
    };
    let mut words = memory.iter_u16(start);
    while words.next_addr < end {
        let address = words.next_addr;
        let instruction =
            Instruction::from_memory(&mut words).map_err(|vector| DisasmError::DecodeFailed {
                address,
                detail: format!("{vector}"),
            })?;
        let first =
            usize::try_from(address).map_err(|_| DisasmError::AddressOverflow { address })?;
        let opaque_end = address.checked_add(4);
        let opaque = opaque_end.and_then(|opaque_end| {
            let last = usize::try_from(opaque_end).ok()?;
            let encoded = code.get(first..last)?;
            crate::control_flow::opaque_fallthrough_text(instruction.opcode, encoded)
                .map(|text| (opaque_end, text))
        });
        if let Some((opaque_end, _)) = &opaque {
            words.next_addr = *opaque_end;
        }
        if words.next_addr > end {
            return Err(DisasmError::RunsPastEnd { address, end });
        }
        let last = usize::try_from(words.next_addr).map_err(|_| DisasmError::AddressOverflow {
            address: words.next_addr,
        })?;
        let encoded = code
            .get(first..last)
            .ok_or(DisasmError::AddressOverflow { address })?;
        swept.push(SweptInstruction {
            address,
            end: words.next_addr,
            encoded: encoded.to_vec(),
            text: opaque
                .map(|(_, text)| text)
                .unwrap_or_else(|| format!("{instruction}")),
        });
    }
    Ok(swept)
}

/// Disassemble `code` linearly over `start..end`, one instruction per line.
///
/// A rendering of [`sweep`], kept so callers that only want text need not
/// format it themselves. The two cannot disagree: there is one decode.
///
/// # Errors
/// Returns [`DisasmError`] if `start` is not word-aligned, the range is outside
/// `code`, an instruction fails to decode, or an instruction would extend past
/// `end`.
pub fn linear(code: &[u8], start: u32, end: u32) -> Result<String, DisasmError> {
    let mut listing = String::new();
    for instruction in sweep(code, start, end)? {
        writeln!(
            listing,
            "{:08x}: {:<18} {}",
            instruction.address,
            hex_bytes(&instruction.encoded),
            instruction.text
        )?;
    }
    Ok(listing)
}

/// Render a control-flow-aware listing body for the whole `code`.
///
/// Reached instructions become `L########:  <insn> ; <hex>`; unreached bytes
/// become `DC.W`/`DC.B` lines. Callers typically prepend their own provenance
/// header (see [`coverage`]).
///
/// # Errors
/// Returns [`DisasmError`] only if an address does not fit the host address
/// space (formatting into a `String` cannot otherwise fail).
pub fn render(code: &[u8], analysis: &ControlFlowAnalysis) -> Result<String, DisasmError> {
    let mut listing = String::new();
    let mut cursor = 0_usize;
    while cursor < code.len() {
        let address = u32::try_from(cursor)
            .map_err(|_| DisasmError::AddressOverflow { address: u32::MAX })?;
        match analysis.instructions.get(&address) {
            Some(decoded) => {
                // Formatted to a `String` first on purpose: the decoder's
                // `Instruction` writes through `write!` without consulting the
                // formatter, so passing it directly drops the width silently.
                let text = decoded.text();
                writeln!(
                    listing,
                    "L{address:08X}:  {text:<FLOW_INSTRUCTION_COLUMN$} ; {}",
                    hex_bytes(&decoded.encoded)
                )?;
                let next =
                    usize::try_from(decoded.end).map_err(|_| DisasmError::AddressOverflow {
                        address: decoded.end,
                    })?;
                // Our own analysis never yields a zero-length instruction, but
                // guard against a stuck cursor regardless.
                cursor = next.max(cursor + 2);
            }
            None if cursor + 1 < code.len() => {
                let word = u16::from_be_bytes([code[cursor], code[cursor + 1]]);
                let text = format!("DC.W    ${word:04X}");
                writeln!(
                    listing,
                    "L{address:08X}:  {text:<FLOW_INSTRUCTION_COLUMN$} ; not directly reached"
                )?;
                cursor += 2;
            }
            None => {
                let text = format!("DC.B    ${:02X}", code[cursor]);
                writeln!(
                    listing,
                    "L{address:08X}:  {text:<FLOW_INSTRUCTION_COLUMN$} ; not directly reached"
                )?;
                cursor += 1;
            }
        }
    }
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::analyze;

    /// A sweep must not be able to read past what it was given.
    ///
    /// `m68000` panics when an extension word cannot be fetched, and the last
    /// word of a code hunk routinely wants one: `0x0000` is what a HUNK image
    /// pads a short code hunk with, and it decodes as `ORI.B`, which reads an
    /// immediate. Sweeping such a hunk to its own end panicked the process from
    /// inside a dependency, which `diff` and `disasm linear` both did on an
    /// ordinary executable.
    ///
    /// What must happen instead is the refusal this function already documents:
    /// the instruction extends past the end, and nothing is completed out of
    /// the padding that makes the decode survivable.
    #[test]
    fn an_instruction_wanting_an_operand_past_the_end_is_refused_not_panicked() {
        // MOVEQ #1,D0 ; ADDQ.W #1,D0 ; RTS ; 0x0000 — the longword pad.
        let code = [0x70, 0x01, 0x52, 0x40, 0x4e, 0x75, 0x00, 0x00];
        assert!(matches!(
            sweep(&code, 0, 8),
            Err(DisasmError::RunsPastEnd { address: 6, end: 8 })
        ));

        // The same word with room for its operand decodes, which is what says
        // the refusal above is about the boundary rather than about `ORI.B`.
        let roomy = [0x00, 0x00, 0x00, 0x2a, 0x4e, 0x75];
        let swept = sweep(&roomy, 0, 6).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(swept.len(), 2);
        assert_eq!(swept[0].encoded, vec![0x00, 0x00, 0x00, 0x2a]);
        assert_eq!(swept[1].address, 4);
    }

    #[test]
    fn linear_lists_encoded_bytes() {
        // NOP (0x4e71) then RTS (0x4e75).
        let code = [0x4e, 0x71, 0x4e, 0x75];
        let listing = linear(&code, 0, 4).unwrap_or_else(|error| panic!("{error}"));
        assert!(listing.contains("4e71"));
        assert!(listing.contains("4e75"));
        assert_eq!(listing.lines().count(), 2);
    }

    #[test]
    fn linear_keeps_movec_and_its_extension_together() {
        let code = [0x4e, 0x7a, 0x08, 0x01, 0x4e, 0x75];
        let swept = sweep(&code, 0, 6).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(swept.len(), 2);
        assert_eq!(swept[0].encoded, code[..4]);
        assert_eq!(swept[0].text, "MOVEC VBR,D0");
        assert_eq!(swept[1].address, 4);
    }

    #[test]
    fn linear_rejects_an_unaligned_start() {
        assert!(matches!(
            linear(&[0; 4], 1, 4),
            Err(DisasmError::UnalignedStart { start: 1 })
        ));
    }

    #[test]
    fn render_labels_instructions_and_marks_unreached_data() {
        // RTS at 0, then two bytes that are not reached.
        let code = [0x4e, 0x75, 0xab, 0xcd];
        let analysis = analyze(&code, 0);
        let listing = render(&code, &analysis).unwrap_or_else(|error| panic!("{error}"));
        assert!(listing.contains("L00000000:"));
        assert!(listing.contains("4e75"));
        assert!(listing.contains("DC.W    $ABCD"));
    }

    #[test]
    fn coverage_counts_reached_bytes() {
        let code = [0x4e, 0x75, 0xab, 0xcd];
        let analysis = analyze(&code, 0);
        let stats = coverage(&analysis, code.len());
        assert_eq!(stats.decoded_bytes, 2);
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.total_bytes, 4);
        assert!((stats.percent() - 50.0).abs() < 1e-9);
    }
}
