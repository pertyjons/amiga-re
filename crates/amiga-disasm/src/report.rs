//! Typed semantic facts derived from a control-flow analysis.
//!
//! Every analysis in this crate reports its findings through separate, shaped
//! result types. This module composes them into one deterministic list of
//! [`Fact`]s so renderers (text listings, JSON reports, future UIs) share a
//! single data model instead of scraping each other's output.
//!
//! ## Confidence terminology
//!
//! Every fact carries a [`Confidence`] stating how strongly the evidence
//! supports it:
//!
//! - **Certain** — read directly from decoded instruction encodings or
//!   relocation records; wrong only if the input itself is not code.
//! - **Inferred** — derived by a conservative dataflow pass (library-base
//!   tracking, custom-base register scanning). Correct for the common idioms
//!   the pass models, but a register reuse the pass does not model can
//!   invalidate it.
//! - **Probable** — a pattern match that reads intent into an idiom (fixed
//!   point arithmetic, clamps, "this indirect call is a library call"). Can be
//!   a false positive even on well-formed input.
//! - **Observed** — seen during one dynamic execution. Proves the behavior
//!   happened for that input; proves nothing about other paths.
//! - **User** — supplied by downstream project configuration. Authoritative
//!   for presentation, but never verified by the toolkit.
//!
//! ## Evidence
//!
//! Every fact lists the [`Evidence`] that supports it: the instruction sites
//! it was derived from, the relocation record, the config entry, or the
//! curated ABI table entry. A reader can always audit an annotation against
//! the raw bytes it cites.
//!
//! ## Determinism
//!
//! [`collect`] returns facts sorted by their total order ([`Ord`]), with exact
//! duplicates removed, so the same input and options always produce an
//! identical fact list.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::access::{AccessForm, register_accesses};
use crate::constants::Unresolved;
use crate::control_flow::{ControlFlowAnalysis, ExternalKind, Relocations};
use crate::data::{DataPreview, TargetConflict};
use crate::fixed_point::{
    ClampKind, FixedPointKind, clamp_hints, fixed_point_hints, fixed_point_scales,
};
use crate::function::function_signatures;
use crate::globals::{AccessKind, absolute_accesses, global_accesses};
use crate::lvo::{Library, infer_library_candidates, library_call, lvo_name};
use crate::xref::{RefKind, references};

/// Version of the fact vocabulary and its serialized shape. Bump on any change
/// to fact kinds, fields, or serialization so a report identifies its schema.
pub const SCHEMA_VERSION: u32 = 16;

/// How strongly the evidence supports a fact (see the module docs).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Certain,
    Inferred,
    Probable,
    Observed,
    User,
}

/// The analysis pass (or external source) that produced a fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Producer {
    /// Recursive control-flow traversal ([`crate::analyze_entries_with`]).
    ControlFlow,
    /// LVO call detection and library-base inference ([`crate::lvo`]).
    LibraryInference,
    /// Custom-chip register access scan ([`crate::access`]).
    HardwareScan,
    /// Base-relative and absolute global access scan ([`crate::globals`]).
    GlobalScan,
    /// Absolute and PC-relative reference extraction ([`crate::xref`]).
    ReferenceScan,
    /// Fixed-point idiom, clamp, and Q-scale recognition
    /// ([`crate::fixed_point`]).
    FixedPointScan,
    /// HUNK relocation records, attached by the composing caller.
    Relocations,
    /// Downstream project configuration, attached by the composing caller.
    Config,
    /// Classification of referenced, undecoded regions ([`crate::data`]).
    DataScan,
    /// Function-interface and stack-frame inference ([`crate::function`]).
    FunctionAnalysis,
}

impl Confidence {
    /// The snake_case name shared by text renderers and the JSON
    /// serialization (kept in lockstep by a unit test).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Certain => "certain",
            Self::Inferred => "inferred",
            Self::Probable => "probable",
            Self::Observed => "observed",
            Self::User => "user",
        }
    }
}

impl Producer {
    /// The snake_case name shared by text renderers and the JSON
    /// serialization (kept in lockstep by a unit test).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ControlFlow => "control_flow",
            Self::LibraryInference => "library_inference",
            Self::HardwareScan => "hardware_scan",
            Self::GlobalScan => "global_scan",
            Self::ReferenceScan => "reference_scan",
            Self::FixedPointScan => "fixed_point_scan",
            Self::Relocations => "relocations",
            Self::Config => "config",
            Self::DataScan => "data_scan",
            Self::FunctionAnalysis => "function_analysis",
        }
    }
}

/// A citation supporting a fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    /// The decoded instruction at this hunk offset.
    Instruction { site: u32 },
    /// The HUNK relocation record patching this hunk offset.
    Relocation { offset: u32 },
    /// A downstream config entry keyed by this address.
    Config { addr: u32 },
    /// An ABI table entry naming this library vector — either the built-in
    /// curated tables or a config-supplied fd table (see [`crate::fd`]).
    Abi { library: String, lvo: i16 },
}

/// How a reverse cross-reference reaches its target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefVia {
    /// A direct call edge resolved by control flow.
    Call,
    /// An absolute or PC-relative operand naming the target.
    Operand,
    /// A HUNK relocation whose stored pointer lands on the target.
    Relocation,
}

impl XrefVia {
    /// The pass that establishes this kind of cross-reference.
    #[must_use]
    pub const fn producer(self) -> Producer {
        match self {
            Self::Call => Producer::ControlFlow,
            Self::Operand => Producer::ReferenceScan,
            Self::Relocation => Producer::Relocations,
        }
    }
}

/// What to append after a library-vector name that is not public API.
///
/// One definition, so a `##private` fd vector reads the same in a CLI listing and a
/// sandbox stop reason. Empty for a public vector, which is every vector the curated
/// built-in tables name.
#[must_use]
pub const fn private_suffix(public: bool) -> &'static str {
    if public { "" } else { " (private)" }
}

/// The most referencing sites one [`FactKind::ReferencedBy`] fact lists. A
/// heavily shared target (a jump-table entry, a common helper) must not turn
/// one fact into an unbounded allocation; the fact's `total` still reports how
/// many sites there were.
pub const MAX_XREF_SITES: usize = 32;

/// How a memory access names its slot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "addressing", rename_all = "snake_case")]
pub enum MemoryAddressing {
    /// A base-register-relative (small-data) slot, e.g. `(8,A5)`.
    BaseRelative { register: u8, displacement: i16 },
    /// An absolute-long address inside the loaded image.
    Absolute { address: u32 },
}

/// The typed payload of a [`Fact`].
///
/// Variant order defines the sort order of facts sharing a subject, so it is
/// part of the deterministic-output contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactKind {
    /// A function entry discovered (or seeded) by control flow.
    Function { entry: u32 },
    /// A bounded register-oriented interface and stack-frame inference.
    FunctionSignature {
        #[serde(flatten)]
        signature: crate::function::FunctionSignature,
    },
    /// A resolved direct call from the subject instruction.
    Call {
        callee: u32,
        /// Entries of the functions whose traversal reached this call site, in
        /// offset order and capped at [`MAX_XREF_SITES`]. Shared code has
        /// several, which is what makes ownership a set rather than one
        /// caller. This is the fact that answers "what does this function
        /// call?" without reading the control-flow analysis back.
        owners: Vec<u32>,
        /// Every owner, including those beyond the cap, so a truncated list
        /// never reads as a complete one.
        owner_total: usize,
    },
    /// A call or jump the relocation patching its operand proves leaves the
    /// analyzed hunk. Resolved, but to an entity no report of this hunk maps.
    ExternalFlow {
        transfer: ExternalKind,
        target_hunk: u32,
        target_offset: u32,
        /// Entries of the functions whose traversal reached this transfer, on
        /// the same terms as [`FactKind::Call`]'s: offset order, capped at
        /// [`MAX_XREF_SITES`]. Without it a function whose only outgoing
        /// transfer leaves the hunk would answer `callees` with nothing, which
        /// reads as "calls nothing" rather than "calls hunk N".
        owners: Vec<u32>,
        /// Every owner, including those beyond the cap, so a truncated list
        /// never reads as a complete one.
        owner_total: usize,
    },
    /// An AmigaOS library call (`JSR`/`JMP (lvo,An)` with a negative offset).
    /// `library`/`function` stay `None` when the base register's library could
    /// not be inferred or the vector is not in the curated tables.
    /// `arguments` is populated only when an externally supplied table (an fd
    /// file) describes the vector's argument registers.
    LibraryCall {
        register: u8,
        lvo: i16,
        library: Option<String>,
        function: Option<String>,
        /// Empty unless an externally supplied table describes the vector, so
        /// every `library_call` fact keeps the same JSON shape.
        arguments: Vec<CallArgument>,
        /// Whether `function` names a vector the supplying table marked
        /// public. `true` for a curated built-in name — those tables carry
        /// public API only — and for an unnamed vector, which claims nothing.
        /// `false` only when an fd table placed the vector in a `##private`
        /// region, so a consumer can tell documented API from internals.
        public: bool,
    },
    /// Conflicting library-base inferences at the subject call site.
    LibraryConflict {
        register: u8,
        lvo: i16,
        candidates: Vec<ConflictCandidate>,
    },
    /// A custom-chip register access. `offset` is relative to the custom base.
    HardwareAccess {
        offset: u16,
        form: AccessForm,
        access: AccessKind,
    },
    /// A read/write/modify/address-of access to a memory slot.
    MemoryAccess {
        #[serde(flatten)]
        target: MemoryAddressing,
        access: AccessKind,
        /// Operand size in bytes, where the encoding specifies one.
        size: Option<u8>,
        /// Constant stored by a direct immediate write (or zero by `CLR`).
        value: Option<u32>,
        /// The slot is loaded into a register used for an LVO call.
        library_base: bool,
    },
    /// An absolute or PC-relative address named by the subject instruction.
    Reference {
        target: u32,
        addressing: RefKind,
        /// Exact longword extension offset when the reference uses one.
        #[serde(skip_serializing_if = "Option::is_none")]
        operand: Option<u32>,
    },
    /// The reverse of the references that reach the subject offset: every
    /// site that calls, addresses, or relocates to it. One fact per way of
    /// reaching it, so `called from` and `addressed from` stay distinguishable.
    ReferencedBy {
        via: XrefVia,
        /// Referencing sites in offset order, capped at [`MAX_XREF_SITES`].
        sites: Vec<u32>,
        /// Every referencing site, including those beyond the cap, so a
        /// truncated list never reads as a complete one.
        total: usize,
    },
    /// A fixed-point multiply/divide idiom.
    FixedPoint {
        idiom: FixedPointKind,
        register: u8,
        fractional_bits: Option<u8>,
    },
    /// A compare/branch/constant-write saturation clamp.
    Clamp {
        register: u8,
        size: u8,
        bound: u32,
        clamp: ClampKind,
    },
    /// A data register acquiring a known Q fractional-bit scale.
    QScale { register: u8, fractional_bits: u8 },
    /// Control flow whose target could not be resolved statically.
    UnresolvedFlow,
    /// A HUNK relocation patching the subject offset, attached by the caller.
    /// `target_offset` is the stored pointer's offset into the target hunk;
    /// `None` when the stored pointer could not be read. `instruction` is the
    /// decoded instruction whose encoding covers the patched longword, so the
    /// relocation is attached to the exact operand it patches; `None` when the
    /// patched bytes are not inside any instruction this analysis decoded.
    Relocation {
        target_hunk: u32,
        target_offset: Option<u32>,
        instruction: Option<u32>,
    },
    /// A config-supplied symbol for the subject offset, attached by the caller.
    Symbol { addr: u32, name: String },
    /// A referenced region of this hunk that control flow never decoded, with
    /// a bounded, escaped preview of what its bytes look like (see
    /// [`crate::data`]). The subject is the region's first byte.
    DataRegion {
        /// Hunk offset one past the last byte examined.
        end: u32,
        #[serde(flatten)]
        preview: DataPreview,
    },
    /// A referenced offset whose classification as code or data is disputed.
    /// The subject is the disputed offset.
    TargetConflict {
        conflict: TargetConflict,
        /// The decoded instruction the offset falls inside, where one does.
        instruction: Option<u32>,
    },
}

impl FactKind {
    /// The snake_case kind tag shared by text renderers and the JSON
    /// serialization (kept in lockstep by a unit test).
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Function { .. } => "function",
            Self::FunctionSignature { .. } => "function_signature",
            Self::Call { .. } => "call",
            Self::ExternalFlow { .. } => "external_flow",
            Self::LibraryCall { .. } => "library_call",
            Self::LibraryConflict { .. } => "library_conflict",
            Self::HardwareAccess { .. } => "hardware_access",
            Self::MemoryAccess { .. } => "memory_access",
            Self::Reference { .. } => "reference",
            Self::ReferencedBy { .. } => "referenced_by",
            Self::FixedPoint { .. } => "fixed_point",
            Self::Clamp { .. } => "clamp",
            Self::QScale { .. } => "q_scale",
            Self::UnresolvedFlow => "unresolved_flow",
            Self::Relocation { .. } => "relocation",
            Self::Symbol { .. } => "symbol",
            Self::DataRegion { .. } => "data_region",
            Self::TargetConflict { .. } => "target_conflict",
        }
    }
}

/// One argument of an externally described library vector: the register that
/// carries it and, when the table lists one, its parameter name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CallArgument {
    pub name: Option<String>,
    pub register: String,
    /// What the register held at this call site, when bounded dataflow
    /// could establish it. Absent means *not established*, never zero: an
    /// argument nobody can value is exactly the one a reader must go and read
    /// the code for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<ArgumentValue>,
    /// A memory-backed expression whose source is known but whose numeric
    /// contents are not. Kept separate from [`Self::value`] so a symbolic
    /// description can never masquerade as an exact result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbolic: Option<ArgumentSymbolicValue>,
    /// Why both [`Self::value`] and [`Self::symbolic`] are absent — which
    /// conservative limit lost them.
    ///
    /// After [`collect`] has run, exactly one of the three is set: an exact
    /// value, a symbolic expression, or a reason. All are absent only on an
    /// argument description that has not been resolved against a call site
    /// yet, which is how [`LvoEntry`] carries one before it reaches a site.
    ///
    /// It is here rather than only in a statistics counter because a reader
    /// looking at one call deserves the same answer a whole-program count
    /// gives: `requirements=d1` with `join` beside it says *go read the two
    /// paths*, where a bare `requirements=d1` says only *give up*.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved: Option<Unresolved>,
}

impl CallArgument {
    /// An argument description with no value and no refusal yet: what a table
    /// knows before the walk has been asked about a particular call site.
    #[must_use]
    pub fn new(name: Option<String>, register: String) -> Self {
        Self {
            name,
            register,
            value: None,
            symbolic: None,
            unresolved: None,
        }
    }
}

/// One argument's resolved value, as its type reads it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ArgumentValue {
    /// The raw constant, so a consumer can compare or re-render it.
    pub value: u32,
    /// How the ABI table's type for this argument reads that constant —
    /// `MEMF_CHIP|MEMF_CLEAR` where the type is known, the number otherwise.
    pub rendered: String,
    /// The instruction that put the value there: the evidence for the claim.
    pub site: u32,
    /// Every instruction that established or copied the value, in flow order.
    pub evidence: Vec<u32>,
}

/// An argument named by a location rather than by a number: a memory read whose
/// bytes are not claimed, or an address in a frame this hunk cannot number.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ArgumentSymbolicValue {
    /// Compact expression used by text reports.
    pub rendered: String,
    /// Whether the address or a sized/extended memory value is held.
    pub subject: SymbolicSubject,
    /// The stable, typed location.
    pub source: SymbolicMemorySource,
    /// A wrapping 32-bit offset applied after the read or address formation.
    pub offset: u32,
    /// The instruction that most recently established or transformed it.
    pub site: u32,
    /// Every instruction that established, copied, or transformed it, in flow
    /// order.
    pub evidence: Vec<u32>,
}

/// Which 32-bit quantity of a [`SymbolicMemorySource`] an argument holds.
///
/// Serialized on every symbolic argument so a consumer never has to guess
/// whether `hunk1+$1c` was the pointer or the longword stored there.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolicSubject {
    /// The longword read from the location.
    Contents,
    /// A 16-bit memory read sign-extended to 32 bits.
    SignExtendedWord,
    /// Replace only the low byte/word, preserving the remaining bits of Dn
    /// immediately before `read_site`. This is a snapshot, not its later value.
    PreserveHigh {
        register: u8,
        read_site: u32,
        low_bytes: u8,
    },
    /// The location's own address, retained because no number in this hunk's
    /// address space names it.
    Address,
}

/// An effective address retained as the location behind a symbolic 32-bit
/// argument.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SymbolicMemorySource {
    /// An encoded absolute-short or absolute-long address, which no relocation
    /// patches.
    Absolute { address: u32 },
    /// A PC-relative address, or an absolute-long operand a relocation patches
    /// into the analyzed hunk, in the analyzed image.
    ImageRelative {
        offset: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime_address: Option<u32>,
    },
    /// An offset into another hunk, proved by the relocation patching the
    /// operand. No runtime address is offered: nothing in this analysis maps
    /// that hunk.
    HunkRelative { hunk: u32, offset: u32 },
    /// An access through the configured small-data/global base register.
    GlobalRelative { register: String, displacement: i32 },
    /// An access through another address register.
    RegisterRelative { register: String, displacement: i32 },
    /// A memory read through `(An)+`. The read site identifies the address
    /// register's value before this particular instruction incremented it.
    RegisterPostincrement { register: String, read_site: u32 },
    /// A memory read through `-(An)`. The read site identifies the address
    /// register's value after this particular instruction decremented it.
    RegisterPredecrement { register: String, read_site: u32 },
    /// Brief-extension indexed memory, with both registers sampled at the read
    /// site. MC68000 supports scale 1; later-CPU extension encodings are refused.
    Indexed {
        base: Box<Self>,
        index_register: String,
        index_bytes: u8,
        scale: u8,
        displacement: i8,
        read_site: u32,
    },
    /// Byte offset of one register's transfer in an ascending MOVEM load.
    /// The base is sampled before any postincrement; offsets are not arithmetic
    /// applied to the value after loading it.
    MovemSlot {
        base: Box<Self>,
        byte_offset: u32,
        read_site: u32,
    },
}

/// An externally supplied description of one library vector, typically parsed
/// from an NDK fd table entry (see [`crate::fd`]).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LvoEntry {
    pub name: String,
    pub arguments: Vec<CallArgument>,
    /// Whether the table placed the vector in a `##public` region.
    ///
    /// The curated built-in tables deliberately leave private vectors (dos
    /// -162/-168, say) unnamed. An fd table names them anyway, so carrying the
    /// distinction is what keeps an fd-supplied private name from reading like
    /// public API.
    pub public: bool,
}

/// One candidate base in a [`FactKind::LibraryConflict`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ConflictCandidate {
    pub library: String,
    /// Instruction sites whose dataflow established this candidate, in flow
    /// order. Empty when the base was seeded by an entry convention.
    pub sites: Vec<u32>,
}

/// One typed, evidence-backed statement about a subject offset.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Fact {
    /// Hunk offset of the entity the fact is about: the instruction site for
    /// instruction facts, the entry for [`FactKind::Function`], the patched
    /// offset for [`FactKind::Relocation`].
    pub subject: u32,
    #[serde(flatten)]
    pub kind: FactKind,
    pub confidence: Confidence,
    pub producer: Producer,
    pub evidence: Vec<Evidence>,
}

/// Options steering [`collect`].
#[derive(Clone, Debug)]
pub struct CollectOptions {
    /// Absolute address of hunk offset zero, for an image copied to a fixed
    /// load address. Enables absolute-global classification and absolute
    /// library-name lookups.
    pub image_origin: Option<u32>,
    /// The library initially in A6, for entry conventions the caller knows
    /// (boot code starts with ExecBase in A6).
    pub default_a6: Option<Library>,
    /// Base register for small-data global accesses (5 = A5, the convention).
    pub global_base_register: u8,
    /// Custom-chip register base (normally `$DFF000`).
    pub custom_base: u32,
    /// Extra LVO descriptions per library, keyed by negative vector offset,
    /// consulted before the curated built-in tables. Typically parsed from
    /// NDK fd files supplied by downstream config (see [`crate::fd`]); the
    /// only way an [`Library::Other`] identity gets named vectors.
    pub lvo_names: BTreeMap<Library, BTreeMap<i16, LvoEntry>>,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            image_origin: None,
            default_a6: None,
            global_base_register: 5,
            custom_base: 0x00df_f000,
            lvo_names: BTreeMap::new(),
        }
    }
}

/// Compose every analysis in this crate into one sorted, deduplicated fact
/// list for the code already traversed by `analysis`.
///
/// Library-call-form sites never appear as unresolved-flow warnings: the
/// control-flow analysis classifies them into
/// [`ControlFlowAnalysis::library_calls`], and they carry
/// [`FactKind::LibraryCall`] facts here instead.
#[must_use]
pub fn collect(analysis: &ControlFlowAnalysis, code: &[u8], options: &CollectOptions) -> Vec<Fact> {
    let mut facts = Vec::new();
    collect_control_flow(analysis, &mut facts);
    collect_function_signatures(analysis, &mut facts);
    collect_library_calls(analysis, code, options, &mut facts);
    collect_hardware(analysis, options, &mut facts);
    collect_memory(analysis, code, options, &mut facts);
    collect_references(analysis, &mut facts);
    // Resolving a reference now costs a relocation lookup, so the two passes
    // that need the resolved targets share one map instead of each rebuilding
    // it from a fresh reference scan.
    let referencing_sites = referencing_sites(analysis, code, options);
    collect_reverse_references(analysis, &referencing_sites, &mut facts);
    collect_data(analysis, code, &referencing_sites, &mut facts);
    collect_fixed_point(analysis, &mut facts);
    facts.sort();
    facts.dedup();
    facts
}

fn collect_function_signatures(analysis: &ControlFlowAnalysis, facts: &mut Vec<Fact>) {
    for signature in function_signatures(analysis) {
        facts.push(Fact {
            subject: signature.entry,
            confidence: Confidence::Probable,
            producer: Producer::FunctionAnalysis,
            evidence: signature
                .evidence
                .iter()
                .map(|site| Evidence::Instruction { site: *site })
                .collect(),
            kind: FactKind::FunctionSignature { signature },
        });
    }
}

/// Fill in each argument's exact value, symbolic expression, or refusal from
/// the tracked values reaching the call site.
///
/// The evidence for a value is the instruction that wrote it, which is added
/// to the fact's evidence by the caller — a value with no site to check would
/// be an assertion rather than a finding. An argument that resolved carries no
/// exact result, symbolic result, and refusal are exclusive, so an argument
/// never says two things at once.
fn resolve_arguments(
    constants: &crate::constants::ConstantAnalysis,
    site: u32,
    library: &str,
    lvo: i16,
    global_base_register: u8,
    arguments: &mut [CallArgument],
) {
    for argument in arguments {
        // A register the tracker cannot even name is a defect in the table that
        // described this vector, not a limit of the walk, so it is recorded as
        // its own reason rather than folded into the walk's stops.
        let Some((kind, register)) = crate::constants::parse_register(&argument.register) else {
            argument.value = None;
            argument.symbolic = None;
            argument.unresolved = Some(Unresolved::UnknownRegister);
            continue;
        };
        match crate::constants::constant_before_with(constants, site, kind, register) {
            Ok(crate::constants::TrackedValue::Exact(constant)) => {
                argument.value = Some(ArgumentValue {
                    value: constant.value,
                    rendered: crate::abi::render(
                        crate::abi::argument_type(library, lvo, &argument.register),
                        constant.value,
                    ),
                    site: constant.site,
                    evidence: constant.evidence,
                });
                argument.symbolic = None;
                argument.unresolved = None;
            }
            Ok(crate::constants::TrackedValue::Symbolic(symbolic)) => {
                let source = symbolic_source(symbolic.location, global_base_register);
                let subject = symbolic_subject(symbolic.subject);
                argument.value = None;
                argument.symbolic = Some(ArgumentSymbolicValue {
                    rendered: render_symbolic(subject, &source, symbolic.offset),
                    subject,
                    source,
                    offset: symbolic.offset,
                    site: symbolic.site,
                    evidence: symbolic.evidence,
                });
                argument.unresolved = None;
            }
            Err(reason) => {
                argument.value = None;
                argument.symbolic = None;
                argument.unresolved = Some(reason);
            }
        }
    }
}

fn symbolic_source(
    location: crate::constants::SymbolicLocation,
    global_base_register: u8,
) -> SymbolicMemorySource {
    match location {
        crate::constants::SymbolicLocation::Absolute { address } => {
            SymbolicMemorySource::Absolute { address }
        }
        crate::constants::SymbolicLocation::ImageRelative {
            offset,
            runtime_address,
        } => SymbolicMemorySource::ImageRelative {
            offset,
            runtime_address,
        },
        crate::constants::SymbolicLocation::HunkRelative { hunk, offset } => {
            SymbolicMemorySource::HunkRelative { hunk, offset }
        }
        crate::constants::SymbolicLocation::RegisterRelative {
            register,
            displacement,
        } if register == global_base_register => SymbolicMemorySource::GlobalRelative {
            register: format!("A{register}"),
            displacement,
        },
        crate::constants::SymbolicLocation::RegisterRelative {
            register,
            displacement,
        } => SymbolicMemorySource::RegisterRelative {
            register: format!("A{register}"),
            displacement,
        },
        crate::constants::SymbolicLocation::RegisterPostincrement { register, site } => {
            SymbolicMemorySource::RegisterPostincrement {
                register: format!("A{register}"),
                read_site: site,
            }
        }
        crate::constants::SymbolicLocation::RegisterPredecrement { register, site } => {
            SymbolicMemorySource::RegisterPredecrement {
                register: format!("A{register}"),
                read_site: site,
            }
        }
        crate::constants::SymbolicLocation::Indexed {
            base,
            index_address,
            index_register,
            index_bytes,
            displacement,
            read_site,
        } => SymbolicMemorySource::Indexed {
            base: Box::new(symbolic_source(*base, global_base_register)),
            index_register: format!("{}{index_register}", if index_address { 'A' } else { 'D' }),
            index_bytes,
            scale: 1,
            displacement,
            read_site,
        },
        crate::constants::SymbolicLocation::MovemSlot {
            base,
            byte_offset,
            read_site,
        } => SymbolicMemorySource::MovemSlot {
            base: Box::new(symbolic_source(*base, global_base_register)),
            byte_offset,
            read_site,
        },
    }
}

const fn symbolic_subject(subject: crate::constants::SymbolicSubject) -> SymbolicSubject {
    match subject {
        crate::constants::SymbolicSubject::Contents => SymbolicSubject::Contents,
        crate::constants::SymbolicSubject::SignExtendedWord => SymbolicSubject::SignExtendedWord,
        crate::constants::SymbolicSubject::PreserveHigh {
            register,
            read_site,
            low_bytes,
        } => SymbolicSubject::PreserveHigh {
            register,
            read_site,
            low_bytes,
        },
        crate::constants::SymbolicSubject::Address => SymbolicSubject::Address,
    }
}

/// Where a symbolic value lives, without saying whether the value is that place
/// or its contents.
fn render_place(source: &SymbolicMemorySource) -> String {
    match source {
        SymbolicMemorySource::Absolute { address } => format!("${address:08x}"),
        SymbolicMemorySource::ImageRelative { offset, .. } => format!("image+${offset:08x}"),
        SymbolicMemorySource::HunkRelative { hunk, offset } => {
            format!("hunk{hunk}+${offset:08x}")
        }
        SymbolicMemorySource::GlobalRelative {
            register,
            displacement,
        }
        | SymbolicMemorySource::RegisterRelative {
            register,
            displacement,
        } => render_register_offset(register, *displacement),
        SymbolicMemorySource::RegisterPostincrement { register, .. } => format!("({register})+"),
        SymbolicMemorySource::RegisterPredecrement { register, .. } => format!("-({register})"),
        SymbolicMemorySource::Indexed {
            base,
            index_register,
            index_bytes,
            scale,
            displacement,
            read_site,
        } => {
            let index = if *index_bytes == 2 {
                format!("sext16({index_register}@${read_site:x})")
            } else {
                format!("{index_register}@${read_site:x}")
            };
            format!(
                "index({}@${read_site:x},{index}*{scale},{displacement})",
                render_place(base)
            )
        }
        SymbolicMemorySource::MovemSlot {
            base,
            byte_offset,
            read_site,
        } => {
            format!(
                "movem_base({})@${read_site:x}+${byte_offset:x}",
                render_place(base)
            )
        }
    }
}

fn render_symbolic(subject: SymbolicSubject, source: &SymbolicMemorySource, offset: u32) -> String {
    let place = render_place(source);
    let source = match (subject, source) {
        // An address is the place itself, so wrapping it in a load would say
        // the opposite of what the value is.
        (SymbolicSubject::Address, _) => place,
        (SymbolicSubject::SignExtendedWord, _) => format!("sext16(memory16[{place}])"),
        (
            SymbolicSubject::PreserveHigh {
                register,
                read_site,
                low_bytes,
            },
            _,
        ) => {
            let bits = u32::from(low_bytes) * 8;
            format!("replace_low{bits}(D{register}@${read_site:x},memory{bits}[{place}])")
        }
        (SymbolicSubject::Contents, SymbolicMemorySource::GlobalRelative { .. }) => {
            format!("global({place})")
        }
        (SymbolicSubject::Contents, _) => format!("memory32[{place}]"),
    };
    render_wrapping_offset(source, offset)
}

fn render_register_offset(register: &str, displacement: i32) -> String {
    match displacement.cmp(&0) {
        std::cmp::Ordering::Less => format!("{register}-${:x}", displacement.unsigned_abs()),
        std::cmp::Ordering::Equal => register.to_owned(),
        std::cmp::Ordering::Greater => format!("{register}+${displacement:x}"),
    }
}

fn render_wrapping_offset(expression: String, offset: u32) -> String {
    if offset == 0 {
        expression
    } else if let Ok(positive) = i32::try_from(offset) {
        format!("{expression}+${positive:x}")
    } else {
        format!("{expression}-${:x}", offset.wrapping_neg())
    }
}

/// One reverse cross-reference fact for `target`, capped at
/// [`MAX_XREF_SITES`] listed sites and citing each listed site as evidence.
///
/// Exposed so a caller holding cross-references this crate cannot see — HUNK
/// relocations, for instance — builds them the same way, with the same cap.
#[must_use]
pub fn referenced_by(target: u32, via: XrefVia, sites: &BTreeSet<u32>) -> Fact {
    let listed: Vec<u32> = sites.iter().copied().take(MAX_XREF_SITES).collect();
    Fact {
        subject: target,
        // Cite each listed site as what it actually is: an instruction for a
        // call or operand, a relocation record for a relocated pointer.
        evidence: listed
            .iter()
            .map(|&site| match via {
                XrefVia::Relocation => Evidence::Relocation { offset: site },
                XrefVia::Call | XrefVia::Operand => Evidence::Instruction { site },
            })
            .collect(),
        kind: FactKind::ReferencedBy {
            via,
            sites: listed,
            total: sites.len(),
        },
        confidence: Confidence::Certain,
        producer: via.producer(),
    }
}

/// Index `facts` by subject offset, preserving their sorted order, so a
/// renderer can annotate a listing without rescanning the whole fact list per
/// instruction.
#[must_use]
pub fn index_by_subject(facts: &[Fact]) -> BTreeMap<u32, Vec<&Fact>> {
    let mut index: BTreeMap<u32, Vec<&Fact>> = BTreeMap::new();
    for fact in facts {
        index.entry(fact.subject).or_default().push(fact);
    }
    index
}

fn collect_control_flow(analysis: &ControlFlowAnalysis, facts: &mut Vec<Fact>) {
    // Index call sites per callee once; scanning all edges per function would
    // be O(functions x edges).
    // A site reached from several entries records one edge per entry, so the
    // sites are collected as a set: a function cites each call site once.
    let mut call_sites = BTreeMap::<u32, BTreeSet<u32>>::new();
    for call in &analysis.calls {
        call_sites
            .entry(call.callee)
            .or_default()
            .insert(call.call_site);
    }
    for &entry in &analysis.functions {
        // A called function cites its call sites; a seeded root cites itself.
        let mut evidence: Vec<Evidence> = call_sites
            .get(&entry)
            .into_iter()
            .flatten()
            .map(|&site| Evidence::Instruction { site })
            .collect();
        if evidence.is_empty() {
            evidence.push(Evidence::Instruction { site: entry });
        }
        facts.push(Fact {
            subject: entry,
            kind: FactKind::Function { entry },
            confidence: Confidence::Certain,
            producer: Producer::ControlFlow,
            evidence,
        });
    }
    for call in &analysis.calls {
        // One edge per (caller, site, callee), so a site in shared code yields
        // several edges that differ only in caller. Taking ownership from the
        // decoded instruction makes those edges collapse into one identical
        // fact, which `collect` dedups.
        // An edge is only recorded after its site was decoded, so the fallback
        // cannot happen; the edge's own caller is the honest one.
        let (owners, owner_total) =
            owning_functions(analysis, call.call_site).unwrap_or_else(|| (vec![call.caller], 1));
        facts.push(Fact {
            subject: call.call_site,
            kind: FactKind::Call {
                callee: call.callee,
                owners,
                owner_total,
            },
            confidence: Confidence::Certain,
            producer: Producer::ControlFlow,
            evidence: vec![Evidence::Instruction {
                site: call.call_site,
            }],
        });
    }
    // One fact per external site, not per owner: the transfer is the same
    // whichever traversal found it. Who reaches it is a separate question, and
    // the decoded instruction is what answers it.
    for external in &analysis.external {
        let (owners, owner_total) =
            owning_functions(analysis, external.site).unwrap_or_else(|| (Vec::new(), 0));
        facts.push(Fact {
            subject: external.site,
            kind: FactKind::ExternalFlow {
                transfer: external.kind,
                target_hunk: external.target_hunk,
                target_offset: external.target_offset,
                owners,
                owner_total,
            },
            confidence: Confidence::Certain,
            producer: Producer::ControlFlow,
            evidence: vec![
                Evidence::Instruction {
                    site: external.site,
                },
                Evidence::Relocation {
                    offset: external.relocation,
                },
            ],
        });
    }
    // Library-call-form sites are classified out of `unresolved` by the
    // control-flow analysis itself and carry `LibraryCall` facts instead.
    for unresolved in &analysis.unresolved {
        facts.push(Fact {
            subject: unresolved.address,
            kind: FactKind::UnresolvedFlow,
            confidence: Confidence::Certain,
            producer: Producer::ControlFlow,
            evidence: vec![Evidence::Instruction {
                site: unresolved.address,
            }],
        });
    }
}

fn collect_library_calls(
    analysis: &ControlFlowAnalysis,
    code: &[u8],
    options: &CollectOptions,
    facts: &mut Vec<Fact>,
) {
    // Built once for the whole pass: every argument of every call site would
    // otherwise rebuild it, turning one walk of the flow edges into thousands.
    let constants = crate::constants::ConstantAnalysis::new(
        analysis,
        crate::constants::ValueOptions {
            image_origin: options.image_origin,
        },
    );
    let candidates = infer_library_candidates(
        analysis,
        code,
        options.image_origin,
        options.default_a6.clone(),
    );
    for (site, decoded) in &analysis.instructions {
        let Some(call) = library_call(decoded) else {
            continue;
        };
        // No candidates: the base is unknown. One candidate: an inferred
        // attribution. Several: an explicit conflict, never a winner.
        let site_candidates = candidates
            .get(site)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        match site_candidates.as_slice() {
            [] => facts.push(unknown_library_call(*site, call.register, call.offset)),
            [(library, chain)] => {
                let external = options
                    .lvo_names
                    .get(library)
                    .and_then(|names| names.get(&call.offset));
                let function = external
                    .map(|entry| entry.name.as_str())
                    .or_else(|| lvo_name(library, call.offset));
                // An fd table wins where the caller supplied one; otherwise
                // the curated ABI table names what it is sure of. Either way
                // the values come from the same dataflow analysis.
                let mut arguments = external.map_or_else(
                    || {
                        crate::abi::arguments(library.as_str(), call.offset)
                            .iter()
                            .map(|argument| {
                                CallArgument::new(
                                    Some(argument.name.to_owned()),
                                    argument.register.to_owned(),
                                )
                            })
                            .collect::<Vec<_>>()
                    },
                    |entry| entry.arguments.clone(),
                );
                resolve_arguments(
                    &constants,
                    *site,
                    library.as_str(),
                    call.offset,
                    options.global_base_register,
                    &mut arguments,
                );
                // Only an fd table can say "private"; the curated tables carry
                // public API only, and an unnamed vector claims nothing.
                let public = external.is_none_or(|entry| entry.public);
                // The establishing chain, then the call itself, then the ABI
                // table entry that names the vector.
                let mut evidence: Vec<Evidence> = chain
                    .iter()
                    .map(|site| Evidence::Instruction { site: *site })
                    .collect();
                evidence.push(Evidence::Instruction { site: *site });
                // Each resolved argument cites the instruction that set it, so
                // a value in the signature can be checked rather than trusted.
                for argument in &arguments {
                    let argument_evidence = argument
                        .value
                        .as_ref()
                        .map(|value| value.evidence.as_slice())
                        .or_else(|| {
                            argument
                                .symbolic
                                .as_ref()
                                .map(|value| value.evidence.as_slice())
                        });
                    if let Some(argument_evidence) = argument_evidence {
                        for value_site in argument_evidence {
                            let instruction = Evidence::Instruction { site: *value_site };
                            if !evidence.contains(&instruction) {
                                evidence.push(instruction);
                            }
                        }
                    }
                }
                if function.is_some() {
                    evidence.push(Evidence::Abi {
                        library: library.as_str().to_owned(),
                        lvo: call.offset,
                    });
                }
                facts.push(Fact {
                    subject: *site,
                    kind: FactKind::LibraryCall {
                        register: call.register,
                        lvo: call.offset,
                        library: Some(library.as_str().to_owned()),
                        function: function.map(str::to_owned),
                        arguments,
                        public,
                    },
                    confidence: Confidence::Inferred,
                    producer: Producer::LibraryInference,
                    evidence,
                });
            }
            _ => {
                facts.push(unknown_library_call(*site, call.register, call.offset));
                let conflict_candidates: Vec<ConflictCandidate> = site_candidates
                    .iter()
                    .map(|(library, chain)| ConflictCandidate {
                        library: library.as_str().to_owned(),
                        sites: (*chain).clone(),
                    })
                    .collect();
                // Every establishing site of every candidate, then the call
                // itself, so plain evidence traversal reaches the same sites
                // the per-candidate payload attributes.
                let mut evidence = Vec::new();
                for candidate in &conflict_candidates {
                    for chain_site in &candidate.sites {
                        let instruction = Evidence::Instruction { site: *chain_site };
                        if !evidence.contains(&instruction) {
                            evidence.push(instruction);
                        }
                    }
                }
                evidence.push(Evidence::Instruction { site: *site });
                facts.push(Fact {
                    subject: *site,
                    kind: FactKind::LibraryConflict {
                        register: call.register,
                        lvo: call.offset,
                        candidates: conflict_candidates,
                    },
                    confidence: Confidence::Probable,
                    producer: Producer::LibraryInference,
                    evidence,
                });
            }
        }
    }
}

/// A library-call fact whose base library is unknown (or conflicting).
fn unknown_library_call(site: u32, register: u8, lvo: i16) -> Fact {
    Fact {
        subject: site,
        kind: FactKind::LibraryCall {
            register,
            lvo,
            library: None,
            function: None,
            arguments: Vec::new(),
            // Nothing named it, so nothing claimed it was private either.
            public: true,
        },
        confidence: Confidence::Probable,
        producer: Producer::LibraryInference,
        evidence: vec![Evidence::Instruction { site }],
    }
}

fn collect_hardware(
    analysis: &ControlFlowAnalysis,
    options: &CollectOptions,
    facts: &mut Vec<Fact>,
) {
    for access in register_accesses(analysis, options.custom_base) {
        // An absolute $DFFxxx operand names its register exactly; a
        // base-relative access relies on the sticky base-register scan.
        let confidence = match access.form {
            AccessForm::Absolute => Confidence::Certain,
            AccessForm::BaseRelative => Confidence::Inferred,
        };
        facts.push(Fact {
            subject: access.site,
            kind: FactKind::HardwareAccess {
                offset: access.offset,
                form: access.form,
                access: access.kind,
            },
            confidence,
            producer: Producer::HardwareScan,
            evidence: vec![Evidence::Instruction { site: access.site }],
        });
    }
}

fn collect_memory(
    analysis: &ControlFlowAnalysis,
    code: &[u8],
    options: &CollectOptions,
    facts: &mut Vec<Fact>,
) {
    for access in global_accesses(analysis, options.global_base_register, options.image_origin) {
        facts.push(memory_fact(
            access.site,
            MemoryAddressing::BaseRelative {
                register: options.global_base_register,
                displacement: access.offset,
            },
            access.kind,
            access.size,
            access.value,
            access.library_base,
        ));
    }
    if let Some(origin) = options.image_origin {
        // An image whose size does not fit the 32-bit address space cannot be
        // mapped at a fixed origin; emit no absolute facts rather than
        // widening the window.
        let Ok(size) = u32::try_from(code.len()) else {
            return;
        };
        for access in absolute_accesses(analysis, origin, size) {
            facts.push(memory_fact(
                access.site,
                MemoryAddressing::Absolute {
                    address: access.address,
                },
                access.kind,
                access.size,
                access.value,
                access.library_base,
            ));
        }
    }
}

/// One memory-access fact; both addressing flavors share every other field.
fn memory_fact(
    site: u32,
    target: MemoryAddressing,
    access: AccessKind,
    size: Option<u8>,
    value: Option<u32>,
    library_base: bool,
) -> Fact {
    Fact {
        subject: site,
        kind: FactKind::MemoryAccess {
            target,
            access,
            size,
            value,
            library_base,
        },
        confidence: Confidence::Certain,
        producer: Producer::GlobalScan,
        evidence: vec![Evidence::Instruction { site }],
    }
}

fn collect_references(analysis: &ControlFlowAnalysis, facts: &mut Vec<Fact>) {
    for reference in references(analysis) {
        facts.push(Fact {
            subject: reference.site,
            kind: FactKind::Reference {
                target: reference.target,
                addressing: reference.kind,
                operand: reference.operand,
            },
            confidence: Confidence::Certain,
            producer: Producer::ReferenceScan,
            evidence: vec![Evidence::Instruction {
                site: reference.site,
            }],
        });
    }
}

/// Every reference that lands inside the analyzed code, as target offset to
/// the sites naming it. Built once because resolving a reference reads the
/// relocation index, and both the reverse-link and data passes need it.
fn referencing_sites(
    analysis: &ControlFlowAnalysis,
    code: &[u8],
    options: &CollectOptions,
) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut sites: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for reference in references(analysis) {
        if let Some(offset) = resolve_into_code(analysis, &reference, code, options) {
            sites.entry(offset).or_default().insert(reference.site);
        }
    }
    sites
}

/// Emit, at each target inside the analyzed code, the sites that reach it.
///
/// Only targets that resolve to an offset of this code get a reverse link: a
/// hardware register or an address in another hunk has no entity here to
/// attach one to. An operand that merely spells out the address of a call the
/// control flow already resolved is not repeated as a second cross-reference.
fn collect_reverse_references(
    analysis: &ControlFlowAnalysis,
    referencing_sites: &BTreeMap<u32, BTreeSet<u32>>,
    facts: &mut Vec<Fact>,
) {
    let mut callers: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for call in &analysis.calls {
        callers
            .entry(call.callee)
            .or_default()
            .insert(call.call_site);
    }
    for (&target, sites) in referencing_sites {
        // The call edge already says this; do not report the same site twice.
        let called_from = callers.get(&target);
        let addressers: BTreeSet<u32> = sites
            .iter()
            .copied()
            .filter(|site| !called_from.is_some_and(|calls| calls.contains(site)))
            .collect();
        if !addressers.is_empty() {
            facts.push(referenced_by(target, XrefVia::Operand, &addressers));
        }
    }
    for (target, sites) in callers {
        facts.push(referenced_by(target, XrefVia::Call, &sites));
    }
}

/// Classify what the referenced offsets of this hunk point at, and report the
/// ones whose reading as code or as data is disputed.
///
/// The sites that reach each region are its evidence, so a preview is always
/// auditable against the operand that made the region interesting.
fn collect_data(
    analysis: &ControlFlowAnalysis,
    code: &[u8],
    sites: &BTreeMap<u32, BTreeSet<u32>>,
    facts: &mut Vec<Fact>,
) {
    let targets: BTreeSet<u32> = sites.keys().copied().collect();
    let scan = crate::data::scan(code, analysis, &targets);
    for region in scan.regions {
        facts.push(Fact {
            subject: region.start,
            evidence: citing_sites(sites, region.start),
            kind: FactKind::DataRegion {
                end: region.end,
                preview: region.preview,
            },
            // Reading bytes as a string, a table, or neither is an
            // interpretation, never a decode.
            confidence: Confidence::Probable,
            producer: Producer::DataScan,
        });
    }
    for disputed in scan.disputed {
        let mut evidence = citing_sites(sites, disputed.offset);
        if let Some(site) = disputed.instruction.filter(|site| *site != disputed.offset) {
            evidence.push(Evidence::Instruction { site });
        }
        facts.push(Fact {
            subject: disputed.offset,
            evidence,
            kind: FactKind::TargetConflict {
                conflict: disputed.conflict,
                instruction: disputed.instruction,
            },
            confidence: Confidence::Probable,
            producer: Producer::DataScan,
        });
    }
}

/// The instruction sites that reference `offset`, capped like any other site
/// list so one heavily referenced region stays bounded.
/// The functions whose traversal reached `site`, capped for the wire, with the
/// true count beside the capped list.
///
/// The decoded instruction is the single source of ownership. A control-flow
/// edge records only the traversal that discovered it, so reading ownership
/// from an edge would name one arbitrary function out of several.
fn owning_functions(analysis: &ControlFlowAnalysis, site: u32) -> Option<(Vec<u32>, usize)> {
    let decoded = analysis.instructions.get(&site)?;
    Some((
        decoded
            .owners
            .iter()
            .copied()
            .take(MAX_XREF_SITES)
            .collect(),
        decoded.owner_total,
    ))
}

fn citing_sites(sites: &BTreeMap<u32, BTreeSet<u32>>, offset: u32) -> Vec<Evidence> {
    sites
        .get(&offset)
        .into_iter()
        .flatten()
        .take(MAX_XREF_SITES)
        .map(|&site| Evidence::Instruction { site })
        .collect()
}

/// The offset of a reference target inside the analyzed code, if it lands
/// there. PC-relative targets already are offsets; absolute targets go through
/// the mapped origin, or — with no origin configured, where the offset and
/// absolute frames coincide — through the raw value.
///
/// A relocation patching the operand outranks both readings: it is the only
/// evidence of which hunk the stored longword belongs to. One into another
/// hunk lands nowhere in this code, however in-range its addend looks.
fn resolve_into_code(
    analysis: &ControlFlowAnalysis,
    reference: &crate::xref::Reference,
    code: &[u8],
    options: &CollectOptions,
) -> Option<u32> {
    if let Some(relocations) = analysis.relocations()
        && let Some(relocation) = relocating(analysis, reference, relocations)
    {
        return (relocation.target_hunk == relocations.hunk())
            .then_some(relocation.target_offset)
            .filter(|offset| in_code(*offset, code));
    }
    let offset = match (reference.kind, options.image_origin) {
        (RefKind::PcRelative, _) => reference.target,
        (RefKind::Absolute, Some(origin)) => reference.target.checked_sub(origin)?,
        (RefKind::Absolute, None) => reference.target,
        (RefKind::AbsoluteShort, Some(origin)) => reference.target.checked_sub(origin)?,
        // Without a mapped origin the frames coincide only by assumption, and
        // for the short form the assumption is false by encoding: sixteen bits
        // cannot be relocated, so the operand names an absolute address and
        // nothing else. Reading `(4).W` as hunk offset 4 would put a `certain`
        // "addressed from" fact on whatever instruction sits there.
        (RefKind::AbsoluteShort, None) => return None,
    };
    in_code(offset, code).then_some(offset)
}

/// The relocation patching this reference's operand, when the operand is the
/// absolute longword one of the records patches.
fn relocating(
    analysis: &ControlFlowAnalysis,
    reference: &crate::xref::Reference,
    relocations: &Relocations,
) -> Option<crate::control_flow::Relocation> {
    if reference.kind != RefKind::Absolute {
        return None;
    }
    let end = analysis.instructions.get(&reference.site)?.end;
    relocations.resolve_operand(reference.site, end, reference.operand, reference.target)
}

fn in_code(offset: u32, code: &[u8]) -> bool {
    u64::from(offset) < u64::try_from(code.len()).unwrap_or(u64::MAX)
}

fn collect_fixed_point(analysis: &ControlFlowAnalysis, facts: &mut Vec<Fact>) {
    for hint in fixed_point_hints(analysis) {
        facts.push(Fact {
            subject: hint.site,
            kind: FactKind::FixedPoint {
                idiom: hint.kind,
                register: hint.register,
                fractional_bits: hint.fractional_bits,
            },
            confidence: Confidence::Probable,
            producer: Producer::FixedPointScan,
            evidence: vec![
                Evidence::Instruction { site: hint.site },
                Evidence::Instruction {
                    site: hint.shift_site,
                },
            ],
        });
    }
    for clamp in clamp_hints(analysis) {
        facts.push(Fact {
            subject: clamp.site,
            kind: FactKind::Clamp {
                register: clamp.register,
                size: clamp.size,
                bound: clamp.bound,
                clamp: clamp.kind,
            },
            confidence: Confidence::Probable,
            producer: Producer::FixedPointScan,
            evidence: vec![
                Evidence::Instruction { site: clamp.site },
                Evidence::Instruction {
                    site: clamp.assign_site,
                },
            ],
        });
    }
    for scale in fixed_point_scales(analysis) {
        facts.push(Fact {
            subject: scale.site,
            kind: FactKind::QScale {
                register: scale.register,
                fractional_bits: scale.fractional_bits,
            },
            confidence: Confidence::Probable,
            producer: Producer::FixedPointScan,
            evidence: vec![Evidence::Instruction { site: scale.site }],
        });
    }
}

#[cfg(test)]
mod tests {

    /// The stage's own target example, end to end: `MOVEA.L 4.W,A6` gives the
    /// base, the two immediates give the arguments, and the ABI table gives
    /// the flag names.
    #[test]
    fn an_alloc_mem_call_reports_its_size_and_its_flags() {
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6 (ExecBase)
            0x20, 0x3c, 0x00, 0x00, 0x7d, 0x00, // 0x04 MOVE.L #32000,D0
            0x22, 0x3c, 0x00, 0x01, 0x00, 0x02, // 0x0a MOVE.L #$10002,D1
            0x4e, 0xae, 0xff, 0x3a, // 0x10 JSR (-198,A6) = AllocMem
            0x4e, 0x75, // 0x14 RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let call = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall {
                    arguments,
                    function,
                    ..
                } if fact.subject == 0x10 => {
                    Some((function.clone(), arguments.clone(), fact.evidence.clone()))
                }
                _ => None,
            })
            .expect("the AllocMem call was not recognized");
        let (function, arguments, evidence) = call;
        assert_eq!(function.as_deref(), Some("AllocMem"));
        assert_eq!(arguments.len(), 2);

        assert_eq!(arguments[0].name.as_deref(), Some("byteSize"));
        let size = arguments[0].value.as_ref().expect("byteSize resolved");
        assert_eq!(size.value, 32_000);
        assert_eq!(size.rendered, "32000");
        assert_eq!(size.site, 0x04);
        assert_eq!(size.evidence, vec![0x04]);

        assert_eq!(arguments[1].name.as_deref(), Some("requirements"));
        let flags = arguments[1].value.as_ref().expect("requirements resolved");
        assert_eq!(flags.rendered, "MEMF_CHIP|MEMF_CLEAR");
        assert_eq!(flags.site, 0x0a);
        assert_eq!(flags.evidence, vec![0x0a]);

        // Both setup sites are cited, so the values can be checked.
        assert!(evidence.contains(&Evidence::Instruction { site: 0x04 }));
        assert!(evidence.contains(&Evidence::Instruction { site: 0x0a }));
    }

    /// An unresolved indirect call later in the same owner has a known
    /// fallthrough and must not discard values established before it.
    #[test]
    fn an_alloc_mem_call_survives_a_later_unresolved_indirect_call() {
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6 (ExecBase)
            0x20, 0x3c, 0x00, 0x00, 0x7d, 0x00, // 0x04 MOVE.L #32000,D0
            0x72, 0x02, // 0x0a MOVEQ #2,D1
            0x4e, 0xae, 0xff, 0x3a, // 0x0c JSR (-198,A6) = AllocMem
            0x4e, 0x90, // 0x10 JSR (A0), unresolved target
            0x4e, 0x75, // 0x12 RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let arguments = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall { arguments, .. } if fact.subject == 0x0c => Some(arguments),
                _ => None,
            })
            .expect("the AllocMem call was not recognized");

        assert_eq!(
            arguments[0]
                .value
                .as_ref()
                .expect("byteSize resolved")
                .rendered,
            "32000"
        );
        assert_eq!(
            arguments[1]
                .value
                .as_ref()
                .expect("requirements resolved")
                .rendered,
            "MEMF_CHIP"
        );
        assert!(
            facts.iter().any(|fact| {
                fact.subject == 0x10 && matches!(fact.kind, FactKind::UnresolvedFlow)
            })
        );
    }

    #[test]
    fn a_copied_call_argument_keeps_its_complete_evidence_chain() {
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x26, 0x3c, 0x00, 0x00, 0x7d, 0x00, // 0x04 MOVE.L #32000,D3
            0x20, 0x03, // 0x0a MOVE.L D3,D0
            0x72, 0x02, // 0x0c MOVEQ #2,D1
            0x4e, 0xae, 0xff, 0x3a, // 0x0e JSR (-198,A6) = AllocMem
            0x4e, 0x75, // 0x12 RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let (arguments, fact_evidence) = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall { arguments, .. } if fact.subject == 0x0e => {
                    Some((arguments, &fact.evidence))
                }
                _ => None,
            })
            .expect("the AllocMem call was not recognized");
        let value = arguments[0].value.as_ref().expect("the copy resolved");
        assert_eq!(value.value, 32_000);
        assert_eq!(value.site, 0x0a);
        assert_eq!(value.evidence, vec![0x04, 0x0a]);
        assert_eq!(
            serde_json::to_value(value).expect("argument value serializes"),
            serde_json::json!({
                "value": 32_000,
                "rendered": "32000",
                "site": 0x0a,
                "evidence": [0x04, 0x0a],
            })
        );
        for site in &value.evidence {
            assert!(fact_evidence.contains(&Evidence::Instruction { site: *site }));
        }
    }

    #[test]
    fn a_pc_relative_call_argument_is_reported_as_an_exact_address() {
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x43, 0xfa, 0x00, 0x0a, // 0x04 LEA (10,PC),A1 -> 0x10
            0x70, 0x00, // 0x08 MOVEQ #0,D0
            0x4e, 0xae, 0xfd, 0xd8, // 0x0a JSR (-552,A6) = OpenLibrary
            0x4e, 0x75, // 0x0e RTS
        ];
        code.extend_from_slice(b"dos.library\0"); // 0x10
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(
            &analysis,
            &code,
            &CollectOptions {
                image_origin: Some(0x1000),
                ..CollectOptions::default()
            },
        );
        let arguments = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall { arguments, .. } if fact.subject == 0x0a => Some(arguments),
                _ => None,
            })
            .expect("the OpenLibrary call was not recognized");
        let name = arguments[0].value.as_ref().expect("A1 is exact");
        assert_eq!(name.value, 0x1010);
        assert_eq!(name.evidence, vec![0x04]);
    }

    #[test]
    fn an_argument_relocated_into_another_hunk_names_its_frame_instead_of_its_addend() {
        // `MOVE.L #$1c,D0` stores an addend, not a size. Reading the encoded
        // bytes would report `AllocMem(byteSize=28)` for a call that asks for
        // whatever hunk 1 offset $1c becomes once loaded.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x20, 0x3c, 0x00, 0x00, 0x00, 0x1c, // 0x04 MOVE.L #$1c,D0
            0x72, 0x02, // 0x0a MOVEQ #2,D1
            0x4e, 0xae, 0xff, 0x3a, // 0x0c JSR (-198,A6) = AllocMem
            0x4e, 0x75, // 0x10 RTS
        ];
        let analysis = crate::analyze_entries_with(
            &code,
            &[0],
            &crate::FlowOptions {
                relocations: Some(Relocations::new(
                    0,
                    [crate::control_flow::Relocation {
                        patched: 0x06,
                        target_hunk: 1,
                        target_offset: 0x1c,
                    }],
                )),
                ..crate::FlowOptions::default()
            },
        );
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let arguments = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall { arguments, .. } if fact.subject == 0x0c => {
                    Some(arguments.clone())
                }
                _ => None,
            })
            .expect("the call was not recognized");
        assert_eq!(arguments[0].register, "d0");
        assert!(
            arguments[0].value.is_none(),
            "an addend was reported as the argument's value"
        );
        let symbolic = arguments[0]
            .symbolic
            .as_ref()
            .expect("the relocation's frame should be retained");
        assert_eq!(symbolic.subject, SymbolicSubject::Address);
        assert_eq!(
            symbolic.source,
            SymbolicMemorySource::HunkRelative {
                hunk: 1,
                offset: 0x1c
            }
        );
        assert_eq!(symbolic.rendered, "hunk1+$0000001c");
        assert_eq!(symbolic.site, 0x04);
        assert_eq!(arguments[0].unresolved, None);
    }

    #[test]
    fn a_memory_backed_argument_is_symbolic_without_becoming_exact() {
        // The size comes out of memory. Its source can be described, but its
        // numeric contents cannot — a zero here would be a fabrication.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x20, 0x2a, 0x00, 0x08, // 0x04 MOVE.L (8,A2),D0
            0x72, 0x02, // 0x08 MOVEQ #2,D1
            0x4e, 0xae, 0xff, 0x3a, // 0x0a JSR (-198,A6)
            0x4e, 0x75, // 0x0e RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let arguments = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall { arguments, .. } if fact.subject == 0x0a => {
                    Some(arguments.clone())
                }
                _ => None,
            })
            .expect("the call was not recognized");
        assert_eq!(arguments[0].register, "d0");
        assert!(
            arguments[0].value.is_none(),
            "an unknowable argument was given a value"
        );
        let symbolic = arguments[0]
            .symbolic
            .as_ref()
            .expect("the stable memory source should be retained");
        assert_eq!(symbolic.rendered, "memory32[A2+$8]");
        assert_eq!(symbolic.site, 4);
        assert_eq!(symbolic.evidence, vec![4]);
        assert_eq!(arguments[0].unresolved, None);
        assert_eq!(
            arguments[1]
                .value
                .as_ref()
                .map(|value| value.rendered.as_str()),
            Some("MEMF_CHIP")
        );
        assert_eq!(
            arguments[1].unresolved, None,
            "a resolved argument also carried a refusal"
        );
    }

    #[test]
    fn extended_symbolic_reads_serialize_and_keep_resolution_partitions_exclusive() {
        let cases = [
            (
                vec![0x20, 0x30, 0x10, 0xfe],
                serde_json::json!("contents"),
                "indexed",
                "sext16(D1@",
            ),
            (
                vec![0x4c, 0x90, 0x00, 0x01],
                serde_json::json!("sign_extended_word"),
                "movem_slot",
                "sext16(memory16[",
            ),
            (
                vec![0x4c, 0xd8, 0x00, 0x01],
                serde_json::json!("contents"),
                "movem_slot",
                "movem_base((A0)+)",
            ),
            (
                vec![0x30, 0x10],
                serde_json::json!({"preserve_high":{"register":0,"read_site":4,"low_bytes":2}}),
                "register_relative",
                "replace_low16(D0@$4,memory16[A0])",
            ),
            (
                vec![0x10, 0x10],
                serde_json::json!({"preserve_high":{"register":0,"read_site":4,"low_bytes":1}}),
                "register_relative",
                "replace_low8(D0@$4,memory8[A0])",
            ),
            (
                vec![0x32, 0x50, 0x20, 0x09],
                serde_json::json!("sign_extended_word"),
                "register_relative",
                "sext16(memory16[A0])",
            ),
        ];
        for (idiom, subject, source_kind, rendered) in cases {
            let mut code = vec![0x2c, 0x78, 0x00, 0x04]; // ExecBase in A6.
            code.extend(idiom);
            code.extend([0x72, 0x02]); // Exact flags in D1.
            let site = code.len() as u32;
            code.extend([0x4e, 0xae, 0xff, 0x3a, 0x4e, 0x75]); // AllocMem ; RTS.
            let analysis = crate::analyze_entries(&code, &[0]);
            let facts = collect(&analysis, &code, &CollectOptions::default());
            let arguments = facts
                .iter()
                .find_map(|fact| match &fact.kind {
                    FactKind::LibraryCall { arguments, .. } if fact.subject == site => {
                        Some(arguments)
                    }
                    _ => None,
                })
                .unwrap();
            let argument = &arguments[0];
            assert!(argument.value.is_none() && argument.unresolved.is_none());
            let symbolic = argument.symbolic.as_ref().unwrap();
            assert!(
                symbolic.rendered.contains(rendered),
                "{}",
                symbolic.rendered
            );
            let json = serde_json::to_value(symbolic).unwrap();
            assert_eq!(json["subject"], subject);
            assert_eq!(json["source"]["kind"], source_kind);
            if source_kind == "indexed" {
                assert_eq!(json["source"]["scale"], 1);
                assert_eq!(json["source"]["index_bytes"], 2);
                assert_eq!(json["source"]["displacement"], -2);
                assert_eq!(json["source"]["read_site"], 4);
            }
            let stats = crate::resolution::ResolutionStats::from_facts(&facts);
            assert_eq!(
                (
                    stats.arguments,
                    stats.resolved,
                    stats.symbolic,
                    stats.unresolved()
                ),
                (2, 1, 1, 0)
            );
        }
    }

    #[test]
    fn a_predecrement_argument_names_the_consumed_longword() {
        // MOVEA.L 4.W,A6 ; MOVE.L -(A2),D0 ; MOVEQ #2,D1 ;
        // JSR AllocMem ; RTS
        let code = [
            0x2c, 0x78, 0x00, 0x04, 0x20, 0x22, 0x72, 0x02, 0x4e, 0xae, 0xff, 0x3a, 0x4e, 0x75,
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let symbolic = facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::LibraryCall { arguments, .. } if fact.subject == 8 => {
                    arguments[0].symbolic.as_ref()
                }
                _ => None,
            })
            .expect("the predecrement source should be retained");
        assert_eq!(symbolic.rendered, "memory32[-(A2)]");
        assert_eq!(
            symbolic.source,
            SymbolicMemorySource::RegisterPredecrement {
                register: "A2".to_owned(),
                read_site: 4,
            }
        );
        assert_eq!(symbolic.site, 4);
        assert_eq!(symbolic.evidence, vec![4]);
    }

    #[test]
    fn every_collected_argument_says_exactly_one_of_exact_symbolic_or_reason() {
        // The three states must never say two things at once, and must never
        // say nothing: an argument with none reads as "not looked at", which
        // after collection is not true of any of them.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x20, 0x3c, 0x00, 0x00, 0x7d, 0x00, // 0x04 MOVE.L #32000,D0
            0x4e, 0xae, 0xff, 0x3a, // 0x0a JSR (-198,A6) = AllocMem
            0x4e, 0xae, 0xfd, 0xd8, // 0x0e JSR (-552,A6) = OpenLibrary
            0x4e, 0x75, // 0x12 RTS
        ];
        let analysis = crate::analyze_entries(&code, &[0]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let mut seen = 0_usize;
        for fact in &facts {
            let FactKind::LibraryCall { arguments, .. } = &fact.kind else {
                continue;
            };
            for argument in arguments {
                seen += 1;
                let states = usize::from(argument.value.is_some())
                    + usize::from(argument.symbolic.is_some())
                    + usize::from(argument.unresolved.is_some());
                assert_eq!(
                    states, 1,
                    "argument {argument:?} of the call at {:#x} has {states} states",
                    fact.subject
                );
            }
        }
        assert!(seen >= 3, "the fixture described too few arguments: {seen}");
    }

    use super::*;
    use crate::control_flow::{analyze, analyze_entries};

    fn kinds_at(facts: &[Fact], subject: u32) -> Vec<&FactKind> {
        facts
            .iter()
            .filter(|fact| fact.subject == subject)
            .map(|fact| &fact.kind)
            .collect()
    }

    #[test]
    fn symbolic_memory_rendering_keeps_source_and_wrapping_offset_distinct() {
        assert_eq!(
            render_symbolic(
                SymbolicSubject::Contents,
                &SymbolicMemorySource::GlobalRelative {
                    register: "A5".to_owned(),
                    displacement: 0x33c,
                },
                0,
            ),
            "global(A5+$33c)"
        );
        assert_eq!(
            render_symbolic(
                SymbolicSubject::Contents,
                &SymbolicMemorySource::RegisterRelative {
                    register: "A2".to_owned(),
                    displacement: -8,
                },
                4,
            ),
            "memory32[A2-$8]+$4"
        );
        assert_eq!(
            render_symbolic(
                SymbolicSubject::Contents,
                &SymbolicMemorySource::Absolute { address: 0x846 },
                u32::MAX,
            ),
            "memory32[$00000846]-$1"
        );
        assert_eq!(
            render_symbolic(
                SymbolicSubject::Contents,
                &SymbolicMemorySource::ImageRelative {
                    offset: 0x85a,
                    runtime_address: Some(0x1085a),
                },
                0,
            ),
            "memory32[image+$0000085a]"
        );
        let postincrement = SymbolicMemorySource::RegisterPostincrement {
            register: "A0".to_owned(),
            read_site: 0x20,
        };
        assert_eq!(
            render_symbolic(SymbolicSubject::Contents, &postincrement, 0),
            "memory32[(A0)+]"
        );
        assert_eq!(
            serde_json::to_value(postincrement).expect("the source serializes"),
            serde_json::json!({
                "kind": "register_postincrement",
                "register": "A0",
                "read_site": 32,
            })
        );
        let predecrement = SymbolicMemorySource::RegisterPredecrement {
            register: "A1".to_owned(),
            read_site: 0x24,
        };
        assert_eq!(
            render_symbolic(SymbolicSubject::Contents, &predecrement, 0),
            "memory32[-(A1)]"
        );
        assert_eq!(
            serde_json::to_value(predecrement).expect("the source serializes"),
            serde_json::json!({
                "kind": "register_predecrement",
                "register": "A1",
                "read_site": 36,
            })
        );
    }

    #[test]
    fn a_hunk_address_renders_as_its_frame_and_never_as_a_load() {
        let source = SymbolicMemorySource::HunkRelative {
            hunk: 1,
            offset: 0x1c,
        };
        assert_eq!(
            render_symbolic(SymbolicSubject::Address, &source, 0),
            "hunk1+$0000001c"
        );
        assert_eq!(
            render_symbolic(SymbolicSubject::Contents, &source, 4),
            "memory32[hunk1+$0000001c]+$4"
        );
    }

    #[test]
    fn a_heavily_referenced_target_caps_its_site_list_but_not_its_count() {
        let sites: BTreeSet<u32> = (0..(MAX_XREF_SITES as u32 + 10)).map(|n| n * 2).collect();
        let fact = referenced_by(0x100, XrefVia::Call, &sites);
        let FactKind::ReferencedBy {
            via,
            sites: listed,
            total,
        } = &fact.kind
        else {
            panic!("not a reverse cross-reference: {:?}", fact.kind);
        };
        assert_eq!(*via, XrefVia::Call);
        assert_eq!(listed.len(), MAX_XREF_SITES);
        assert_eq!(*total, sites.len());
        // The listed sites are the lowest ones, in order, and each is cited.
        assert_eq!(listed[0], 0);
        assert_eq!(listed[MAX_XREF_SITES - 1], (MAX_XREF_SITES as u32 - 1) * 2);
        assert_eq!(fact.evidence.len(), MAX_XREF_SITES);
        assert_eq!(fact.producer, Producer::ControlFlow);
    }

    #[test]
    fn a_relocation_cross_reference_cites_relocation_records() {
        let sites = BTreeSet::from([0x56]);
        let fact = referenced_by(0x42, XrefVia::Relocation, &sites);
        assert_eq!(fact.producer, Producer::Relocations);
        assert_eq!(fact.evidence, vec![Evidence::Relocation { offset: 0x56 }]);
    }

    #[test]
    fn a_function_signature_is_a_typed_evidence_backed_fact() {
        // MOVE.L (A0),D0 ; RTS
        let code = [0x20, 0x10, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let fact = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::FunctionSignature { .. }))
            .expect("the function interface is present");
        let FactKind::FunctionSignature { signature } = &fact.kind else {
            unreachable!();
        };
        assert_eq!(fact.subject, 0);
        assert_eq!(fact.producer, Producer::FunctionAnalysis);
        assert_eq!(fact.confidence, Confidence::Probable);
        assert_eq!(signature.prototype("load"), "load(A0: ptr) -> D0");
        assert_eq!(
            fact.evidence,
            signature
                .evidence
                .iter()
                .map(|site| { Evidence::Instruction { site: *site } })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn collect_is_deterministic_and_every_fact_cites_evidence() {
        // MOVEA.L 4.W,A6 ; JSR (-552,A6) ; MOVE.W #$8020,$DFF096 ; RTS
        let code = [
            0x2c, 0x78, 0x00, 0x04, 0x4e, 0xae, 0xfd, 0xd8, 0x33, 0xfc, 0x80, 0x20, 0x00, 0xdf,
            0xf0, 0x96, 0x4e, 0x75,
        ];
        let analysis = analyze(&code, 0);
        let options = CollectOptions::default();
        let first = collect(&analysis, &code, &options);
        let second = collect(&analysis, &code, &options);
        assert_eq!(first, second);
        assert!(!first.is_empty());
        for fact in &first {
            assert!(!fact.evidence.is_empty(), "fact without evidence: {fact:?}");
        }
        assert!(first.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn names_an_inferred_library_call_with_abi_evidence() {
        // MOVEA.L 4.W,A6 ; JSR (-552,A6) ; RTS
        let code = [0x2c, 0x78, 0x00, 0x04, 0x4e, 0xae, 0xfd, 0xd8, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let call = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::LibraryCall { .. }))
            .unwrap_or_else(|| panic!("expected a library-call fact"));
        assert_eq!(call.subject, 4);
        assert_eq!(call.confidence, Confidence::Inferred);
        assert_eq!(
            call.kind,
            FactKind::LibraryCall {
                register: 6,
                lvo: -552,
                library: Some("exec.library".to_owned()),
                function: Some("OpenLibrary".to_owned()),
                // The curated ABI table names the vector's arguments even
                // without an fd file; neither is valued here, because nothing
                // in this fixture sets A1 or D0. The walk runs off the front of
                // the entry looking, and says so rather than just saying no.
                arguments: vec![
                    CallArgument {
                        name: Some("libName".to_owned()),
                        register: "a1".to_owned(),
                        value: None,
                        symbolic: None,
                        unresolved: Some(Unresolved::NoPredecessor),
                    },
                    CallArgument {
                        name: Some("version".to_owned()),
                        register: "d0".to_owned(),
                        value: None,
                        symbolic: None,
                        unresolved: Some(Unresolved::NoPredecessor),
                    },
                ],
                public: true,
            }
        );
        assert!(call.evidence.contains(&Evidence::Abi {
            library: "exec.library".to_owned(),
            lvo: -552,
        }));
    }

    #[test]
    fn unknown_library_base_stays_probable_and_unnamed() {
        // JSR (-30,A6) ; RTS — nothing establishes what A6 holds.
        let code = [0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let call = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::LibraryCall { .. }))
            .unwrap_or_else(|| panic!("expected a library-call fact"));
        assert_eq!(call.confidence, Confidence::Probable);
        assert_eq!(
            call.kind,
            FactKind::LibraryCall {
                register: 6,
                lvo: -30,
                library: None,
                function: None,
                arguments: Vec::new(),
                public: true,
            }
        );
    }

    #[test]
    fn external_lvo_entries_supply_names_and_arguments() {
        // JSR (-30,A6) with ExecBase seeded and an external table describing
        // the vector.
        let code = [0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let mut vectors = BTreeMap::new();
        vectors.insert(
            -30,
            LvoEntry {
                name: "Supervisor2".to_owned(),
                arguments: vec![CallArgument::new(
                    Some("userFunction".to_owned()),
                    "a5".to_owned(),
                )],
                public: true,
            },
        );
        let mut lvo_names = BTreeMap::new();
        lvo_names.insert(Library::Exec, vectors);
        let options = CollectOptions {
            default_a6: Some(Library::Exec),
            lvo_names,
            ..Default::default()
        };
        let facts = collect(&analysis, &code, &options);
        let call = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::LibraryCall { .. }))
            .unwrap_or_else(|| panic!("expected a library-call fact"));
        assert_eq!(
            call.kind,
            FactKind::LibraryCall {
                register: 6,
                lvo: -30,
                library: Some("exec.library".to_owned()),
                function: Some("Supervisor2".to_owned()),
                arguments: vec![CallArgument {
                    name: Some("userFunction".to_owned()),
                    register: "a5".to_owned(),
                    value: None,
                    symbolic: None,
                    // The call is the entry instruction, so the walk has
                    // nowhere to step back to.
                    unresolved: Some(Unresolved::NoPredecessor),
                }],
                public: true,
            }
        );
    }

    #[test]
    fn conflicting_library_inference_produces_an_explicit_ambiguity() {
        // Entry A: MOVEA.L 4.W,A6 ; BRA.W shared.
        // Entry B: MOVEA.L 4.W,A6 ; LEA (name,PC),A1 ; JSR OpenLibrary ;
        //          MOVEA.L D0,A6 ; falls through to shared.
        // shared:  JSR (-30,A6) — A6 is exec via A, graphics via B.
        let mut code = vec![
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x60, 0x00, 0x00, 0x14, // 0x04 BRA.W 0x1a
            0x2c, 0x78, 0x00, 0x04, // 0x08 MOVEA.L 4.W,A6
            0x43, 0xfa, 0x00, 0x12, // 0x0c LEA (0x20,PC),A1
            0x4e, 0xae, 0xfd, 0xd8, // 0x10 JSR (-552,A6)
            0x2c, 0x40, // 0x14 MOVEA.L D0,A6
            0x4e, 0x71, // 0x16 NOP
            0x4e, 0x71, // 0x18 NOP
            0x4e, 0xae, 0xff, 0xe2, // 0x1a shared: JSR (-30,A6)
            0x4e, 0x75, // 0x1e RTS
        ];
        code.resize(0x20, 0);
        code.extend_from_slice(b"graphics.library\0");
        let analysis = analyze_entries(&code, &[0, 8]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let conflict = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::LibraryConflict { .. }))
            .unwrap_or_else(|| panic!("expected a library-conflict fact"));
        assert_eq!(conflict.subject, 0x1a);
        assert_eq!(conflict.confidence, Confidence::Probable);
        assert_eq!(
            conflict.kind,
            FactKind::LibraryConflict {
                register: 6,
                lvo: -30,
                candidates: vec![
                    ConflictCandidate {
                        library: "exec.library".to_owned(),
                        // Entry A's ExecBase load.
                        sites: vec![0x00],
                    },
                    ConflictCandidate {
                        library: "graphics.library".to_owned(),
                        // Entry B's name setup, OpenLibrary, and D0 move.
                        sites: vec![0x0c, 0x10, 0x14],
                    },
                ],
            }
        );
        // The evidence list carries every candidate's establishing sites plus
        // the call itself, so plain evidence traversal needs no payload
        // knowledge.
        assert_eq!(
            conflict.evidence,
            vec![
                Evidence::Instruction { site: 0x00 },
                Evidence::Instruction { site: 0x0c },
                Evidence::Instruction { site: 0x10 },
                Evidence::Instruction { site: 0x14 },
                Evidence::Instruction { site: 0x1a },
            ]
        );
        // The call fact itself stays unnamed rather than picking a winner.
        let call = kinds_at(&facts, 0x1a)
            .into_iter()
            .find_map(|kind| match kind {
                FactKind::LibraryCall { library, .. } => Some(library.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected a library-call fact at the conflict site"));
        assert_eq!(call, None);
    }

    #[test]
    fn library_call_facts_cover_exactly_the_flow_classified_sites() {
        // A named call (ExecBase in A6), a call with an unknown base after A6
        // is clobbered, and a library-form tail jump: every site the
        // control-flow analysis classifies as a library call carries at least
        // one LibraryCall fact, and no other site does.
        let code = [
            0x2c, 0x78, 0x00, 0x04, // 0x00 MOVEA.L 4.W,A6
            0x4e, 0xae, 0xfd, 0xd8, // 0x04 JSR (-552,A6)
            0x2c, 0x40, // 0x08 MOVEA.L D0,A6 (unknown: no name was set up)
            0x4e, 0xae, 0xff, 0xe2, // 0x0a JSR (-30,A6)
            0x4e, 0xee, 0xff, 0x88, // 0x0e JMP (-120,A6) (tail call)
        ];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let fact_sites: std::collections::BTreeSet<u32> = facts
            .iter()
            .filter(|fact| matches!(fact.kind, FactKind::LibraryCall { .. }))
            .map(|fact| fact.subject)
            .collect();
        assert_eq!(fact_sites, analysis.library_calls);
        assert_eq!(fact_sites.len(), 3);
    }

    #[test]
    fn a_cross_hunk_call_is_a_resolved_external_fact_not_an_in_hunk_call() {
        // JSR $0.L ; RTS ; RTS, whose operand a relocation patches into hunk 1.
        let code = [0x4e, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x75, 0x4e, 0x75];
        let relocations = Relocations::new(
            0,
            [crate::control_flow::Relocation {
                patched: 2,
                target_hunk: 1,
                target_offset: 0,
            }],
        );
        let analysis = crate::control_flow::analyze_entries_with(
            &code,
            &[0],
            &crate::control_flow::FlowOptions {
                relocations: Some(relocations.clone()),
                ..Default::default()
            },
        );
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let external = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::ExternalFlow { .. }))
            .unwrap_or_else(|| panic!("expected an external-flow fact"));
        assert_eq!(external.subject, 0);
        assert_eq!(external.confidence, Confidence::Certain);
        assert_eq!(external.producer, Producer::ControlFlow);
        assert_eq!(
            external.kind,
            FactKind::ExternalFlow {
                transfer: ExternalKind::Call,
                target_hunk: 1,
                target_offset: 0,
                owners: vec![0],
                owner_total: 1,
            }
        );
        // The instruction and the record that proves where it goes.
        assert_eq!(
            external.evidence,
            vec![
                Evidence::Instruction { site: 0 },
                Evidence::Relocation { offset: 2 },
            ]
        );
        // Nothing pretends offset 0 is a callee, a function, or referenced.
        assert!(
            !facts
                .iter()
                .any(|fact| matches!(fact.kind, FactKind::Call { .. }))
        );
        assert_eq!(
            facts
                .iter()
                .filter(|fact| matches!(fact.kind, FactKind::Function { .. }))
                .count(),
            1
        );
        assert!(
            !facts
                .iter()
                .any(|fact| matches!(fact.kind, FactKind::ReferencedBy { .. }))
        );
    }

    /// `MOVEA.L (0x4).W,A6` is AbsExecBase, and the address it names is not an
    /// offset into anything. It is reported as a reference — an operand naming
    /// an address is one — and it must not produce a reverse cross-reference on
    /// whatever instruction happens to sit at offset 4, which here is the
    /// second half of the very instruction that read it.
    ///
    /// The absolute *long* spelling of the same idiom is deliberately not
    /// asserted here: `(4).L` may carry a `HUNK_RELOC32` record, so a consumer
    /// with no base still reads it as an offset. Only the encoding rules that
    /// reading out, which is why the two forms are separate kinds.
    #[test]
    fn an_absolute_short_operand_addresses_no_hunk_offset() {
        // MOVEA.L (0x4).W,A6 ; NOP ; RTS
        let code = [0x2c, 0x78, 0x00, 0x04, 0x4e, 0x71, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        assert!(
            kinds_at(&facts, 0).iter().any(|kind| matches!(
                kind,
                FactKind::Reference {
                    target: 4,
                    addressing: RefKind::AbsoluteShort,
                    ..
                }
            )),
            "the AbsExecBase read named no address"
        );
        assert!(
            !facts
                .iter()
                .any(|fact| matches!(fact.kind, FactKind::ReferencedBy { .. })),
            "a reverse cross-reference was fabricated on an absolute-short target"
        );
    }

    #[test]
    fn suppresses_unresolved_flow_at_library_calls_but_not_indirect_jumps() {
        // JSR (-30,A6) ; JMP (A0)
        let code = [0x4e, 0xae, 0xff, 0xe2, 0x4e, 0xd0];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        assert!(
            !kinds_at(&facts, 0)
                .iter()
                .any(|kind| matches!(kind, FactKind::UnresolvedFlow))
        );
        assert!(
            kinds_at(&facts, 4)
                .iter()
                .any(|kind| matches!(kind, FactKind::UnresolvedFlow))
        );
    }

    #[test]
    fn absolute_hardware_access_is_certain_and_base_relative_inferred() {
        // MOVE.W #$8020,$DFF096 ; LEA $DFF000,A4 ; MOVE.W #$8020,(0x96,A4) ; RTS
        let code = [
            0x33, 0xfc, 0x80, 0x20, 0x00, 0xdf, 0xf0, 0x96, // MOVE.W #$8020,$DFF096
            0x49, 0xf9, 0x00, 0xdf, 0xf0, 0x00, // LEA $DFF000,A4
            0x39, 0x7c, 0x80, 0x20, 0x00, 0x96, // MOVE.W #$8020,(0x96,A4)
            0x4e, 0x75, // RTS
        ];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let hardware: Vec<&Fact> = facts
            .iter()
            .filter(|fact| matches!(fact.kind, FactKind::HardwareAccess { .. }))
            .collect();
        assert_eq!(hardware.len(), 2);
        assert_eq!(hardware[0].subject, 0);
        assert_eq!(hardware[0].confidence, Confidence::Certain);
        assert_eq!(hardware[1].subject, 14);
        assert_eq!(hardware[1].confidence, Confidence::Inferred);
    }

    #[test]
    fn reports_base_relative_memory_and_fixed_point_evidence_sites() {
        // MOVE.W D0,(4,A5) ; MULS.W D1,D3 ; ASR.L #8,D3 ; RTS
        let code = [0x3b, 0x40, 0x00, 0x04, 0xc7, 0xc1, 0xe0, 0x83, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let memory = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::MemoryAccess { .. }))
            .unwrap_or_else(|| panic!("expected a memory-access fact"));
        assert_eq!(memory.confidence, Confidence::Certain);
        assert_eq!(
            memory.kind,
            FactKind::MemoryAccess {
                target: MemoryAddressing::BaseRelative {
                    register: 5,
                    displacement: 4,
                },
                access: AccessKind::Write,
                size: Some(2),
                value: None,
                library_base: false,
            }
        );
        let fixed = facts
            .iter()
            .find(|fact| matches!(fact.kind, FactKind::FixedPoint { .. }))
            .unwrap_or_else(|| panic!("expected a fixed-point fact"));
        assert_eq!(fixed.confidence, Confidence::Probable);
        assert_eq!(
            fixed.evidence,
            vec![
                Evidence::Instruction { site: 4 },
                Evidence::Instruction { site: 6 },
            ]
        );
    }

    /// The owning entries a call fact lists, and how many there were.
    fn call_owners(facts: &[Fact]) -> (Vec<u32>, usize) {
        facts
            .iter()
            .find_map(|fact| match &fact.kind {
                FactKind::Call {
                    owners,
                    owner_total,
                    ..
                } => Some((owners.clone(), *owner_total)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected a call fact"))
    }

    #[test]
    fn a_call_site_reached_from_two_entries_names_both_owners() {
        // Entry 0 falls through into the call site at 0x2; entry 2 is the call
        // site itself. Only the first traversal to arrive records the edge, so
        // the edge's caller alone would name one of the two.
        // NOP ; BSR.S sub ; RTS ; sub: RTS
        let code = [0x4e, 0x71, 0x61, 0x02, 0x4e, 0x75, 0x4e, 0x75];
        let analysis = analyze_entries(&code, &[0, 2]);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        assert_eq!(call_owners(&facts), (vec![0, 2], 2));
    }

    #[test]
    fn a_call_site_owned_by_very_many_entries_caps_its_list_but_not_its_count() {
        // Every entry is a `BRA.W` to one shared call site, so the site is
        // owned by all of them and the payload must stay bounded.
        let count = MAX_XREF_SITES + 5;
        let call_site = u32::try_from(4 * count).unwrap_or_else(|error| panic!("{error}"));
        let mut code = Vec::new();
        for index in 0..count {
            let site = u32::try_from(4 * index).unwrap_or_else(|error| panic!("{error}"));
            let displacement = i16::try_from(i64::from(call_site) - i64::from(site) - 2)
                .unwrap_or_else(|error| panic!("{error}"));
            code.extend_from_slice(&[0x60, 0x00]);
            code.extend_from_slice(&displacement.to_be_bytes());
        }
        // BSR.S sub ; RTS ; sub: RTS
        code.extend_from_slice(&[0x61, 0x02, 0x4e, 0x75, 0x4e, 0x75]);
        let entries: Vec<u32> = (0..count)
            .map(|index| u32::try_from(4 * index).unwrap_or_else(|error| panic!("{error}")))
            .collect();
        let analysis = analyze_entries(&code, &entries);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let (owners, total) = call_owners(&facts);
        assert_eq!(total, count);
        assert_eq!(owners.len(), MAX_XREF_SITES);
        // The listed owners are the lowest entries, in offset order.
        assert_eq!(owners, entries[..MAX_XREF_SITES]);
    }

    #[test]
    fn function_facts_cite_call_sites_and_roots_cite_themselves() {
        // BSR.S +4 ; RTS ; sub: RTS
        let code = [0x61, 0x00, 0x00, 0x04, 0x4e, 0x75, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let functions: Vec<&Fact> = facts
            .iter()
            .filter(|fact| matches!(fact.kind, FactKind::Function { .. }))
            .collect();
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].subject, 0);
        assert_eq!(
            functions[0].evidence,
            vec![Evidence::Instruction { site: 0 }]
        );
        assert_eq!(functions[1].subject, 6);
        assert_eq!(
            functions[1].evidence,
            vec![Evidence::Instruction { site: 0 }]
        );
    }

    #[test]
    fn labels_match_the_serde_names() {
        for confidence in [
            Confidence::Certain,
            Confidence::Inferred,
            Confidence::Probable,
            Confidence::Observed,
            Confidence::User,
        ] {
            let json = serde_json::to_value(confidence).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json.as_str(), Some(confidence.label()));
        }
        for producer in [
            Producer::ControlFlow,
            Producer::LibraryInference,
            Producer::HardwareScan,
            Producer::GlobalScan,
            Producer::ReferenceScan,
            Producer::FixedPointScan,
            Producer::Relocations,
            Producer::Config,
            Producer::DataScan,
        ] {
            let json = serde_json::to_value(producer).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json.as_str(), Some(producer.label()));
        }
        for kind in [
            FactKind::Function { entry: 0 },
            FactKind::Call {
                callee: 0,
                owners: vec![0],
                owner_total: 1,
            },
            FactKind::ExternalFlow {
                transfer: ExternalKind::Call,
                target_hunk: 1,
                target_offset: 0,
                owners: vec![0],
                owner_total: 1,
            },
            FactKind::UnresolvedFlow,
            FactKind::QScale {
                register: 0,
                fractional_bits: 8,
            },
            FactKind::Symbol {
                addr: 0,
                name: "x".to_owned(),
            },
            FactKind::ReferencedBy {
                via: XrefVia::Call,
                sites: vec![0],
                total: 1,
            },
            FactKind::DataRegion {
                end: 4,
                preview: DataPreview::Bytes {
                    bytes: vec![0],
                    truncated: false,
                },
            },
            FactKind::TargetConflict {
                conflict: TargetConflict::IntoInstruction,
                instruction: Some(0),
            },
        ] {
            let json = serde_json::to_value(&kind).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json["kind"].as_str(), Some(kind.label()));
        }
        for (via, name) in [
            (XrefVia::Call, "call"),
            (XrefVia::Operand, "operand"),
            (XrefVia::Relocation, "relocation"),
        ] {
            let json = serde_json::to_value(via).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json.as_str(), Some(name));
        }
        for conflict in [
            TargetConflict::IntoInstruction,
            TargetConflict::CodeReadsAsText,
        ] {
            let json = serde_json::to_value(conflict).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json.as_str(), Some(conflict.label()));
        }
        for preview in [
            DataPreview::Text {
                text: String::new(),
                truncated: false,
            },
            DataPreview::Pointers {
                offsets: Vec::new(),
                truncated: false,
            },
            DataPreview::Bytes {
                bytes: Vec::new(),
                truncated: false,
            },
        ] {
            let json = serde_json::to_value(&preview).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(json["class"].as_str(), Some(preview.class()));
        }
    }

    #[test]
    fn index_by_subject_groups_sorted_facts() {
        let code = [0x4e, 0xae, 0xff, 0xe2, 0x4e, 0x75];
        let analysis = analyze(&code, 0);
        let facts = collect(&analysis, &code, &CollectOptions::default());
        let index = index_by_subject(&facts);
        assert!(index.contains_key(&0));
        let total: usize = index.values().map(Vec::len).sum();
        assert_eq!(total, facts.len());
    }
}
