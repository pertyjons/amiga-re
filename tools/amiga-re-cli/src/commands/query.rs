//! Deterministic questions asked of the composed fact graph (`disasm query`).
//!
//! These are the cross-reference questions a reader otherwise answers by
//! grepping a listing: who calls this, what does it call, what points here,
//! who touches this global, who touches this hardware register. Every answer
//! is computed from the same typed facts `disasm report` renders — never from
//! its text — so the two can never disagree, and every hit names its site,
//! confidence, and producer.
//!
//! Results are bounded. A question with more hits than the limit reports the
//! total alongside the truncated list, so a capped answer never reads as a
//! complete one.

use anyhow::anyhow;

use amiga_disasm::report::{Fact, FactKind, MemoryAddressing};

use super::*;

/// The identifier stored in every JSON answer.
const QUERY_SCHEMA: &str = "amiga-re.semantic-query";

/// Results returned when `--limit` is not given.
pub(crate) const DEFAULT_QUERY_LIMIT: usize = 200;

/// A question that can be asked of the fact graph.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum Question {
    /// Sites that call the function at the subject address.
    Callers,
    /// Calls made by the function entered at the subject address.
    Callees,
    /// Sites whose operand, call, or relocation names the subject address.
    RefsTo,
    /// Accesses to a global slot: `A5+0x8`, `A5-0x4`, or an absolute address.
    Global,
    /// Accesses to a custom-chip register, by name (`DMACON`) or offset
    /// (`$096`).
    Register,
}

impl Question {
    /// The snake_case name shared by the text header and the JSON answer.
    const fn label(self) -> &'static str {
        match self {
            Self::Callers => "callers",
            Self::Callees => "callees",
            Self::RefsTo => "refs_to",
            Self::Global => "global",
            Self::Register => "register",
        }
    }
}

/// One answer row: a site and what it does there.
struct Hit {
    site: u32,
    description: String,
    fact: &'static str,
    confidence: &'static str,
    producer: &'static str,
}

/// What a global-access question is about.
enum Slot {
    /// A base-register-relative slot, e.g. `A5+0x8`.
    BaseRelative { register: u8, displacement: i16 },
    /// An absolute address inside the loaded image.
    Absolute(u32),
}

/// One question and how to answer it, as the command line supplied them.
pub(crate) struct QueryRequest<'a> {
    pub(crate) question: Question,
    /// The unparsed subject, kept verbatim for the answer's provenance.
    pub(crate) subject: &'a str,
    pub(crate) library: Option<&'a str>,
    pub(crate) base_register: u8,
    pub(crate) format: &'a str,
    /// Maximum rows returned; zero selects [`DEFAULT_QUERY_LIMIT`].
    pub(crate) limit: usize,
}

pub(crate) fn disasm_query(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    request: &QueryRequest<'_>,
) -> Result<()> {
    let mut out = Document::new();
    let QueryRequest {
        question,
        subject,
        format,
        ..
    } = *request;
    let prepared = prepare_code_analysis(config_override, target)?;
    let library = report::parse_library(request.library)?;
    let facts = report::compose_facts(&prepared, library, request.base_register)?;
    let resolver = report::Resolver::for_prepared(&prepared);

    // Ownership is the only capped payload a question reads through, and only
    // `callees` reads it.
    let mut capped = 0;
    let (subject_text, hits) = match question {
        Question::Callers => {
            let offset = subject_offset(&prepared, subject)?;
            (
                offset_subject(&resolver, offset),
                callers(&facts, &resolver, offset),
            )
        }
        Question::Callees => {
            let offset = subject_offset(&prepared, subject)?;
            let hits = callees(&facts, &resolver, offset)?;
            capped = capped_ownership(&facts, offset);
            (offset_subject(&resolver, offset), hits)
        }
        Question::RefsTo => {
            let offset = subject_offset(&prepared, subject)?;
            (
                offset_subject(&resolver, offset),
                refs_to(&facts, &resolver, offset),
            )
        }
        Question::Global => {
            let slot = parse_slot(subject)?;
            (slot_subject(&resolver, &slot), globals(&facts, &slot))
        }
        Question::Register => {
            let offset = parse_register(subject)?;
            (
                format!("{} (custom+${offset:03x})", hardware_register_label(offset)),
                registers(&facts, offset),
            )
        }
    };

    let limit = if request.limit == 0 {
        DEFAULT_QUERY_LIMIT
    } else {
        request.limit
    };
    let total = hits.len();
    let shown: Vec<&Hit> = hits.iter().take(limit).collect();
    match format {
        "text" => print_document(&render_text(
            question,
            &subject_text,
            &shown,
            total,
            limit,
            capped,
        )?)?,
        "json" => row!(
            out,
            "{}",
            render_json(
                &prepared,
                question,
                subject,
                &subject_text,
                &shown,
                total,
                capped
            )?
        ),
        other => bail!("unknown --format {other:?} (use text or json)"),
    }
    out.print()
}

// --- subjects ----------------------------------------------------------------

/// Resolve an address argument to a hunk offset, following the same rule as
/// `--entry`: with a mapped origin the argument is absolute, without one it is
/// already an offset.
fn subject_offset(prepared: &Prepared, subject: &str) -> Result<u32> {
    let value = amiga_core::parse_u32(subject)
        .map_err(|error| anyhow!("{subject:?} is not an address: {error}"))?;
    let offset = match prepared.base {
        Some(base) => base
            .abs_to_offset(value)
            .with_context(|| format!("{value:#x} is below the mapped origin {:#x}", base.origin))?,
        None => value,
    };
    if (offset as usize) >= prepared.code().len() {
        bail!(
            "{value:#x} is outside hunk {} ({:#x} bytes)",
            prepared.hunk(),
            prepared.code().len()
        );
    }
    Ok(offset)
}

/// `helper @ hunk0+0x42 (abs 0x10042, file 0x62)` for an offset subject.
fn offset_subject(resolver: &report::Resolver<'_>, offset: u32) -> String {
    resolver.describe_offset(offset)
}

/// Parse `A5+0x8`, `A5-0x4`, or an absolute address.
fn parse_slot(subject: &str) -> Result<Slot> {
    let text = subject.trim();
    let rest = text
        .strip_prefix('A')
        .or_else(|| text.strip_prefix('a'))
        .filter(|rest| rest.starts_with(|character: char| character.is_ascii_digit()));
    let Some(rest) = rest else {
        let address = amiga_core::parse_u32(text).map_err(|error| {
            anyhow!("{subject:?} is neither an `A5+0x8` slot nor an address: {error}")
        })?;
        return Ok(Slot::Absolute(address));
    };
    let split = rest
        .find(['+', '-'])
        .with_context(|| format!("{subject:?} has no displacement (expected `A5+0x8`)"))?;
    let (register, displacement) = rest.split_at(split);
    let register: u8 = register
        .parse()
        .map_err(|_| anyhow!("{subject:?} does not name an address register"))?;
    if register > 7 {
        bail!("{subject:?} does not name an address register (A0-A7)");
    }
    let (sign, magnitude) = displacement.split_at(1);
    let magnitude = amiga_core::parse_u32(magnitude)
        .map_err(|error| anyhow!("{subject:?} has no numeric displacement: {error}"))?;
    let magnitude = i32::try_from(magnitude)
        .ok()
        .filter(|value| i16::try_from(*value).is_ok())
        .with_context(|| format!("{subject:?} does not fit a 16-bit displacement"))?;
    let displacement = if sign == "-" { -magnitude } else { magnitude };
    let displacement = i16::try_from(displacement)
        .map_err(|_| anyhow!("{subject:?} does not fit a 16-bit displacement"))?;
    Ok(Slot::BaseRelative {
        register,
        displacement,
    })
}

fn slot_subject(resolver: &report::Resolver<'_>, slot: &Slot) -> String {
    match slot {
        Slot::BaseRelative {
            register,
            displacement,
        } => format!("A{register}{}", signed_hex(*displacement)),
        Slot::Absolute(address) => resolver.describe_runtime(*address),
    }
}

/// Parse `DMACON`, `$096`, or `0x96` into a custom-chip register offset.
fn parse_register(subject: &str) -> Result<u16> {
    let text = subject.trim();
    if let Some(hex) = text.strip_prefix('$') {
        let offset = u16::from_str_radix(hex, 16)
            .map_err(|error| anyhow!("{subject:?} is not a register offset: {error}"))?;
        return Ok(offset);
    }
    if text.starts_with("0x") || text.starts_with("0X") {
        let value = amiga_core::parse_u32(text)
            .map_err(|error| anyhow!("{subject:?} is not a register offset: {error}"))?;
        return u16::try_from(value)
            .map_err(|_| anyhow!("{subject:?} is not a custom-chip register offset"));
    }
    amiga_hw::known_registers()
        .into_iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(text))
        .map(|(offset, _)| offset)
        .with_context(|| {
            format!("{subject:?} is not a known custom-chip register; pass `$096` for an offset")
        })
}

// --- questions ---------------------------------------------------------------

fn hit(fact: &Fact, description: String) -> Hit {
    Hit {
        site: fact.subject,
        description,
        fact: fact.kind.label(),
        confidence: fact.confidence.label(),
        producer: fact.producer.label(),
    }
}

/// Call sites whose callee is `offset`, read from the call facts themselves
/// rather than from the capped reverse-link summary.
fn callers(facts: &[Fact], resolver: &report::Resolver<'_>, offset: u32) -> Vec<Hit> {
    facts
        .iter()
        .filter(|fact| matches!(&fact.kind, FactKind::Call { callee, .. } if *callee == offset))
        .map(|fact| hit(fact, format!("calls {}", resolver.describe_offset(offset))))
        .collect()
}

/// Outgoing transfers made from inside the function entered at `offset`: calls
/// resolved inside this hunk, and calls or jumps a relocation proves leave it.
///
/// Ownership is read from the facts themselves — a transfer site names every
/// function whose traversal reached it — so this answer, like every other, is
/// reproducible from the JSON report alone.
fn callees(facts: &[Fact], resolver: &report::Resolver<'_>, offset: u32) -> Result<Vec<Hit>> {
    if !facts
        .iter()
        .any(|fact| matches!(fact.kind, FactKind::Function { entry } if entry == offset))
    {
        bail!(
            "no function entry at {}; the analysis reached no function there",
            resolver.describe_offset(offset)
        );
    }
    Ok(facts
        .iter()
        .filter_map(|fact| {
            // A transfer that leaves the hunk is still an outgoing call. Only
            // its destination is unmappable here, so it is named in the target
            // hunk's own frame rather than omitted — "calls nothing" and "calls
            // hunk 1" must not read the same.
            let (owners, description) = match &fact.kind {
                FactKind::Call { callee, owners, .. } => (
                    owners,
                    format!("calls {}", resolver.describe_offset(*callee)),
                ),
                FactKind::ExternalFlow {
                    transfer,
                    target_hunk,
                    target_offset,
                    owners,
                    ..
                } => (
                    owners,
                    format!(
                        "external {} -> {}",
                        transfer.label(),
                        resolver.relocation_target_text(*target_hunk, *target_offset)
                    ),
                ),
                _ => return None,
            };
            owners.contains(&offset).then(|| hit(fact, description))
        })
        .collect())
}

/// Transfer sites this `callees` answer could be missing: those whose
/// owning-function list hit the [`amiga_disasm::MAX_XREF_SITES`] cap without
/// naming `offset`, so the queried function may be one of the owners the list
/// left out. A site whose list already names `offset` is in the answer, capped
/// or not. Counted for external transfers on the same terms as in-hunk calls.
fn capped_ownership(facts: &[Fact], offset: u32) -> usize {
    facts
        .iter()
        .filter(|fact| {
            let (owners, owner_total) = match &fact.kind {
                FactKind::Call {
                    owners,
                    owner_total,
                    ..
                }
                | FactKind::ExternalFlow {
                    owners,
                    owner_total,
                    ..
                } => (owners, *owner_total),
                _ => return false,
            };
            owner_total > owners.len() && !owners.contains(&offset)
        })
        .count()
}

/// Every site whose call, operand, or relocation names `offset`.
fn refs_to(facts: &[Fact], resolver: &report::Resolver<'_>, offset: u32) -> Vec<Hit> {
    facts
        .iter()
        .filter_map(|fact| match &fact.kind {
            FactKind::Call { callee, .. } if *callee == offset => {
                Some(hit(fact, "calls it".to_owned()))
            }
            // Read through the relocation that patches the operand, so a
            // cross-hunk addend never reads as a reference to this hunk.
            FactKind::Reference {
                target,
                addressing,
                operand,
            } if resolver.reference_target_in_image(
                fact.subject,
                *target,
                *addressing,
                *operand,
            ) == Some(offset) =>
            {
                Some(hit(
                    fact,
                    format!("addresses it ({} operand)", ref_kind_str(*addressing)),
                ))
            }
            FactKind::Relocation {
                target_hunk,
                target_offset: Some(target),
                ..
            } if *target == offset && resolver.analyzed_hunk() == Some(*target_hunk) => {
                Some(hit(fact, "relocates to it".to_owned()))
            }
            _ => None,
        })
        .collect()
}

/// Every read, write, or address-of of one global slot.
fn globals(facts: &[Fact], slot: &Slot) -> Vec<Hit> {
    facts
        .iter()
        .filter_map(|fact| {
            let FactKind::MemoryAccess {
                target,
                access,
                size,
                value,
                ..
            } = &fact.kind
            else {
                return None;
            };
            let matches = match (target, slot) {
                (
                    MemoryAddressing::BaseRelative {
                        register,
                        displacement,
                    },
                    Slot::BaseRelative {
                        register: wanted,
                        displacement: wanted_displacement,
                    },
                ) => register == wanted && displacement == wanted_displacement,
                (MemoryAddressing::Absolute { address }, Slot::Absolute(wanted)) => {
                    address == wanted
                }
                _ => false,
            };
            if !matches {
                return None;
            }
            let mut description = access_kind_str(*access).to_owned();
            if let Some(size) = size {
                let _ = write!(description, " size={size}");
            }
            if let Some(value) = value {
                let _ = write!(description, " value={value:#x}");
            }
            Some(hit(fact, description))
        })
        .collect()
}

/// Every access to one custom-chip register.
fn registers(facts: &[Fact], wanted: u16) -> Vec<Hit> {
    facts
        .iter()
        .filter_map(|fact| {
            let FactKind::HardwareAccess {
                offset,
                form,
                access,
            } = &fact.kind
            else {
                return None;
            };
            (*offset == wanted).then(|| {
                let form = match form {
                    amiga_disasm::AccessForm::Absolute => "abs",
                    amiga_disasm::AccessForm::BaseRelative => "base-reg",
                };
                hit(
                    fact,
                    format!("{} [{form} operand]", access_kind_str(*access)),
                )
            })
        })
        .collect()
}

// --- renderers ---------------------------------------------------------------

fn render_text(
    question: Question,
    subject: &str,
    hits: &[&Hit],
    total: usize,
    limit: usize,
    capped: usize,
) -> Result<String> {
    let mut text = String::new();
    writeln!(text, "; Semantic query by amiga-re: {}", question.label())?;
    writeln!(text, "; Subject: {subject}")?;
    if capped > 0 {
        writeln!(
            text,
            "; Warning: {capped} call sites list only their first {} owning functions, \
             so this answer may be incomplete",
            amiga_disasm::MAX_XREF_SITES
        )?;
    }
    if hits.is_empty() {
        writeln!(text, "; No matches.")?;
        return Ok(text);
    }
    if total > hits.len() {
        writeln!(
            text,
            "; Showing {} of {total} matches (raise --limit above {limit} for the rest)",
            hits.len()
        )?;
    } else {
        writeln!(text, "; {total} matches")?;
    }
    writeln!(
        text,
        "; Columns: site  fact  confidence  producer  description"
    )?;
    writeln!(text)?;
    for hit in hits {
        writeln!(
            text,
            "L{:08X}  {:<17} {:<9} {:<18} {}",
            hit.site, hit.fact, hit.confidence, hit.producer, hit.description
        )?;
    }
    Ok(text)
}

fn render_json(
    prepared: &Prepared,
    question: Question,
    subject: &str,
    subject_text: &str,
    hits: &[&Hit],
    total: usize,
    capped: usize,
) -> Result<String> {
    let resolver = report::Resolver::for_prepared(prepared);
    let results: Vec<serde_json::Value> = hits
        .iter()
        .map(|hit| {
            serde_json::json!({
                "site": hit.site,
                "location": resolver.locate(hit.site),
                "fact": hit.fact,
                "confidence": hit.confidence,
                "producer": hit.producer,
                "description": hit.description,
            })
        })
        .collect();
    let answer = serde_json::json!({
        "schema": QUERY_SCHEMA,
        "version": amiga_disasm::SCHEMA_VERSION,
        "source_sha256": sha256(&prepared.bytes),
        "hunk": prepared.hunk(),
        "question": question.label(),
        "subject": subject,
        "subject_resolved": subject_text,
        "total": total,
        // True when `total` exceeds the returned rows, so a bounded answer is
        // never mistaken for the whole set.
        "truncated": total > results.len(),
        // Call sites whose owning-function list was capped without naming the
        // queried function, so a `callees` answer may be missing them. Zero
        // for every other question, which reads no capped payload.
        "ownership_capped": capped,
        "results": results,
    });
    Ok(serde_json::to_string_pretty(&answer)?)
}
