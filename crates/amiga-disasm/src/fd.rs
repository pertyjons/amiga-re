//! Parsing AmigaOS NDK function-descriptor (`.fd`) files.
//!
//! An `.fd` file lists a library's vectors in table order: `##base` names the
//! library base symbol, `##bias` sets the positive offset of the next vector
//! (the call site uses `JSR (-bias,A6)`), `##public`/`##private` mark
//! visibility, and each `Name(params)(registers)` line consumes one 6-byte
//! vector slot. Downstream projects reference their own fd files from config
//! to name vectors beyond the curated built-in tables; the files themselves
//! are frequently not redistributable, so they never enter this repository.
//!
//! The parser is strict: unknown directives, function lines before a
//! `##bias`, malformed entries, offsets outside the 16-bit displacement
//! range, and duplicate offsets are all errors rather than silent skips.

use thiserror::Error;

/// The most entries one fd file may define; real NDK tables stay far below.
const MAX_ENTRIES: usize = 2048;

/// Every vector slot is 6 bytes wide.
const SLOT_SIZE: u32 = 6;

/// A parsed fd file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdFile {
    /// The `##base` symbol as written (e.g. `_SysBase`), if declared.
    pub base: Option<String>,
    /// The vectors, in file order.
    pub entries: Vec<FdEntry>,
}

/// One function vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdEntry {
    pub name: String,
    /// Positive vector offset; the call form is `JSR (-bias,An)`.
    pub bias: u16,
    /// Whether the vector was inside a `##public` region.
    pub public: bool,
    /// Parameter names as written, split on `,` and `/`.
    pub params: Vec<String>,
    /// Comma-separated register groups as written. A group may join several
    /// registers with `/` — either one multi-register argument
    /// (`IEEEDPAdd(y,z)(d0/d1,d2/d3)`) or plain single registers
    /// (`Draw(rp,x,y)(a1,d0/d1)`); which reading applies is decided by
    /// whichever count matches the parameter list.
    pub registers: Vec<String>,
}

impl FdEntry {
    /// The negative LVO displacement a call site uses for this vector. The
    /// parser bounds every accepted bias to `1..=i16::MAX`, so the negation
    /// always exists.
    #[must_use]
    pub fn lvo_offset(&self) -> i16 {
        i16::try_from(self.bias)
            .ok()
            .and_then(i16::checked_neg)
            .unwrap_or(i16::MIN)
    }
}

/// A failure while parsing an fd file. Line numbers are 1-based.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum FdError {
    #[error("line {line}: unknown directive {directive:?}")]
    UnknownDirective { line: usize, directive: String },
    #[error("line {line}: ##base without a symbol")]
    MissingBase { line: usize },
    #[error("line {line}: duplicate ##base directive")]
    DuplicateBase { line: usize },
    #[error("line {line}: bias 0 does not address a vector (calls use negative displacements)")]
    ZeroBias { line: usize },
    #[error("line {line}: invalid ##bias value {value:?}")]
    InvalidBias { line: usize, value: String },
    #[error("line {line}: function entry before any ##bias directive")]
    MissingBias { line: usize },
    #[error("line {line}: malformed function entry {text:?}")]
    MalformedFunction { line: usize, text: String },
    #[error("line {line}: bias {bias} exceeds the 16-bit displacement range")]
    BiasOverflow { line: usize, bias: u32 },
    #[error("line {line}: duplicate bias {bias}")]
    DuplicateBias { line: usize, bias: u16 },
    #[error("more than {limit} entries")]
    TooManyEntries { limit: usize },
}

/// Parse fd `text` into its base symbol and vector entries.
///
/// # Errors
/// Returns [`FdError`] on any directive, entry, or offset the strict grammar
/// does not accept.
pub fn parse(text: &str) -> Result<FdFile, FdError> {
    let mut file = FdFile {
        base: None,
        entries: Vec::new(),
    };
    let mut bias: Option<u32> = None;
    let mut public = true;
    for (index, raw_line) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('*') {
            continue;
        }
        if let Some(directive) = trimmed.strip_prefix("##") {
            let mut words = directive.split_whitespace();
            match words.next() {
                Some("base") => {
                    let symbol = words.next().ok_or(FdError::MissingBase { line })?;
                    if file.base.is_some() {
                        return Err(FdError::DuplicateBase { line });
                    }
                    file.base = Some(symbol.to_owned());
                }
                Some("bias") => {
                    let value = words.next().unwrap_or("");
                    let parsed = value.parse::<u32>().map_err(|_| FdError::InvalidBias {
                        line,
                        value: value.to_owned(),
                    })?;
                    bias = Some(parsed);
                }
                Some("public") => public = true,
                Some("private") => public = false,
                Some("end") => break,
                _ => {
                    return Err(FdError::UnknownDirective {
                        line,
                        directive: trimmed.to_owned(),
                    });
                }
            }
            continue;
        }
        let current = bias.ok_or(FdError::MissingBias { line })?;
        let entry = parse_function(trimmed, line, current, public)?;
        if file
            .entries
            .iter()
            .any(|existing| existing.bias == entry.bias)
        {
            return Err(FdError::DuplicateBias {
                line,
                bias: entry.bias,
            });
        }
        file.entries.push(entry);
        if file.entries.len() > MAX_ENTRIES {
            return Err(FdError::TooManyEntries { limit: MAX_ENTRIES });
        }
        // parse_function bounds the accepted bias to i16::MAX, so this cannot
        // overflow; keep it checked per the parser-safety conventions.
        bias = Some(
            current
                .checked_add(SLOT_SIZE)
                .ok_or(FdError::BiasOverflow {
                    line,
                    bias: current,
                })?,
        );
    }
    Ok(file)
}

/// Parse one `Name(params)(registers)` entry at the given bias.
fn parse_function(text: &str, line: usize, bias: u32, public: bool) -> Result<FdEntry, FdError> {
    let malformed = || FdError::MalformedFunction {
        line,
        text: text.to_owned(),
    };
    // The bias must fit a negative 16-bit displacement: `JSR (-bias,An)`.
    // Bias 0 negates to 0, which no call form ever uses.
    if bias == 0 {
        return Err(FdError::ZeroBias { line });
    }
    let bias = u16::try_from(bias)
        .ok()
        .filter(|bias| i16::try_from(*bias).is_ok())
        .ok_or(FdError::BiasOverflow { line, bias })?;

    let (name, rest) = text.split_once('(').ok_or_else(malformed)?;
    let name = name.trim();
    let valid_name = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        && !name.starts_with(|character: char| character.is_ascii_digit());
    if !valid_name {
        return Err(malformed());
    }
    let (params, rest) = rest.split_once(')').ok_or_else(malformed)?;
    let registers = rest
        .trim()
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .ok_or_else(malformed)?;
    Ok(FdEntry {
        name: name.to_owned(),
        bias,
        public,
        params: split_list(params),
        registers: split_groups(registers),
    })
}

/// Split an fd parameter list on `,` and `/`, dropping empty items.
fn split_list(text: &str) -> Vec<String> {
    text.split([',', '/'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Split an fd register list on `,` only, keeping `/`-joined groups together
/// (see [`FdEntry::registers`]); empty items are dropped.
fn split_groups(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
* \"exec_lib.fd\" — a tiny sample in NDK layout.
##base _SysBase
##bias 30
Supervisor(userFunction)(a5)
##private
ExitIntr()()
##public
##bias 552
OpenLibrary(libName,version)(a1,d0)
CloseLibrary(library)(a1)
##end
IgnoredAfterEnd()()
";

    #[test]
    fn parses_directives_bias_stepping_and_visibility() {
        let file = parse(SAMPLE).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(file.base.as_deref(), Some("_SysBase"));
        assert_eq!(file.entries.len(), 4);
        assert_eq!(file.entries[0].name, "Supervisor");
        assert_eq!(file.entries[0].bias, 30);
        assert!(file.entries[0].public);
        assert_eq!(file.entries[0].params, vec!["userFunction"]);
        assert_eq!(file.entries[0].registers, vec!["a5"]);
        // The private entry follows at the next slot.
        assert_eq!(file.entries[1].name, "ExitIntr");
        assert_eq!(file.entries[1].bias, 36);
        assert!(!file.entries[1].public);
        assert!(file.entries[1].params.is_empty());
        // ##bias resets; the next entry steps by 6 again.
        assert_eq!(file.entries[2].bias, 552);
        assert_eq!(file.entries[2].registers, vec!["a1", "d0"]);
        assert_eq!(file.entries[3].name, "CloseLibrary");
        assert_eq!(file.entries[3].bias, 558);
    }

    #[test]
    fn keeps_slash_joined_register_groups_together() {
        let file =
            parse("##bias 30\nDraw(rp,x,y)(a1,d0/d1)\n").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(file.entries[0].registers, vec!["a1", "d0/d1"]);
        assert_eq!(file.entries[0].params, vec!["rp", "x", "y"]);
        assert_eq!(file.entries[0].lvo_offset(), -30);
    }

    #[test]
    fn tolerates_empty_list_items() {
        // Doubled or trailing separators are dropped rather than producing
        // empty parameter names or register groups.
        let file = parse("##bias 30\nOpen(a,,b)(d0,,)\n").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(file.entries[0].params, vec!["a", "b"]);
        assert_eq!(file.entries[0].registers, vec!["d0"]);
    }

    #[test]
    fn rejects_bias_zero_and_duplicate_base() {
        assert_eq!(
            parse("##bias 0\nZero()()\n"),
            Err(FdError::ZeroBias { line: 2 })
        );
        assert_eq!(
            parse("##base _A\n##base _B\n"),
            Err(FdError::DuplicateBase { line: 2 })
        );
    }

    #[test]
    fn rejects_a_function_before_any_bias() {
        assert_eq!(
            parse("Open(name)(d1)\n"),
            Err(FdError::MissingBias { line: 1 })
        );
    }

    #[test]
    fn rejects_unknown_directives_and_malformed_entries() {
        assert_eq!(
            parse("##shadow\n"),
            Err(FdError::UnknownDirective {
                line: 1,
                directive: "##shadow".to_owned(),
            })
        );
        assert_eq!(parse("##base\n"), Err(FdError::MissingBase { line: 1 }));
        assert_eq!(
            parse("##bias x\n"),
            Err(FdError::InvalidBias {
                line: 1,
                value: "x".to_owned(),
            })
        );
        assert!(matches!(
            parse("##bias 30\nOpen(name\n"),
            Err(FdError::MalformedFunction { line: 2, .. })
        ));
        assert!(matches!(
            parse("##bias 30\n1BadName()()\n"),
            Err(FdError::MalformedFunction { line: 2, .. })
        ));
    }

    #[test]
    fn rejects_bias_overflow_and_duplicates() {
        assert_eq!(
            parse("##bias 32766\nAlmost()()\nOver()()\n"),
            Err(FdError::BiasOverflow {
                line: 3,
                bias: 32772,
            })
        );
        assert_eq!(
            parse("##bias 30\nFirst()()\n##bias 30\nSecond()()\n"),
            Err(FdError::DuplicateBias { line: 4, bias: 30 })
        );
    }

    #[test]
    fn rejects_too_many_entries() {
        let mut text = String::from("##bias 30\n");
        for index in 0..2049 {
            text.push_str(&format!("F{index}()()\n"));
        }
        assert_eq!(parse(&text), Err(FdError::TooManyEntries { limit: 2048 }));
    }
}
