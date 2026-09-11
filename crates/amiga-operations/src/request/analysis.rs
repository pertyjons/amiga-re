//! Arguments for the `analysis.*` operations: the HUNK container, the code
//! inside it, the addresses that code names, and the tables it reads.
use super::*;

/// Where the code a fact set describes lives.
///
/// A boot block's code is not a hunk's, and `boot disasm` asks exactly the same
/// question of it. One selector rather than two operations, so the fact model
/// has one definition whichever bytes it is about.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeRegion {
    /// A CODE hunk of a LoadSeg image.
    #[default]
    Hunk,
    /// A complete raw MC68000 image. The source must be pinned explicitly,
    /// because no container header identifies what the bytes are.
    Raw,
    /// The boot code of an AmigaDOS boot block, which starts with ExecBase in
    /// A6 — a convention the fact model is told rather than left to guess.
    BootBlock,
}

/// One vector an externally supplied table names.
///
/// The tables travel as *data*, never as a path. A frontend reads its own fd
/// files and puts the entries here, so two adapters given the same table get
/// the same facts and no request names a host path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryVector {
    /// The library the vector belongs to: `exec`, `dos`, `graphics`,
    /// `intuition`, or an open-name such as `mathffp.library`.
    pub library: String,
    /// The negative vector offset from the library base.
    pub lvo: i16,
    pub name: String,
    /// The vector's arguments: the register each arrives in, and the
    /// parameter name the table gives it. Both, because a table that named
    /// `parm` in `d0` and one that only said `d0` describe different amounts of
    /// knowledge, and a fact that lost the name would be the weaker of the two
    /// wearing the stronger one's shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<VectorArgument>,
    /// Whether the supplying table marked the vector public. False keeps an
    /// fd-supplied private name from reading like documented API.
    #[serde(default = "crate::request::vector_public_default")]
    pub public: bool,
}

pub(crate) const fn vector_public_default() -> bool {
    true
}

/// One argument a supplied vector declares.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VectorArgument {
    /// The register it arrives in, e.g. `d0` or `a1`.
    pub register: String,
    /// The parameter's name, when the table gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Arguments for `analysis.code.facts`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodeFactsArguments {
    pub source: SourceLocator,
    #[serde(default)]
    pub region: CodeRegion,
    /// CODE hunk to analyze, for the `hunk` region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Required for a raw region: the digest that makes otherwise
    /// self-describing bytes an explicit, reproducible input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    /// Address register the small-data convention uses. Defaults to A5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_register: Option<u8>,
    /// The library initially in A6, when the caller knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_library: Option<String>,
    /// Extra vectors, consulted before this build's curated tables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library_vectors: Vec<LibraryVector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_facts: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_instructions: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CodeFactsArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            region: CodeRegion::Hunk,
            hunk: None,
            expected_sha256: None,
            entries: Vec::new(),
            origin: None,
            base_register: None,
            default_library: None,
            library_vectors: Vec::new(),
            maximum_facts: None,
            maximum_instructions: None,
            maximum_input_bytes: None,
        }
    }

    /// Ask about a boot block's code rather than a hunk's.
    #[must_use]
    pub const fn in_boot_block(mut self) -> Self {
        self.region = CodeRegion::BootBlock;
        self
    }

    /// Ask about a pinned raw MC68000 image rather than a HUNK container.
    #[must_use]
    pub fn in_raw(mut self, expected_sha256: impl Into<String>) -> Self {
        self.region = CodeRegion::Raw;
        self.hunk = None;
        self.expected_sha256 = Some(expected_sha256.into());
        self
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub fn from_entries(mut self, entries: Vec<u32>) -> Self {
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn through_register(mut self, register: u8) -> Self {
        self.base_register = Some(register);
        self
    }

    #[must_use]
    pub fn with_default_library(mut self, library: impl Into<String>) -> Self {
        self.default_library = Some(library.into());
        self
    }

    #[must_use]
    pub fn with_library_vectors(mut self, vectors: Vec<LibraryVector>) -> Self {
        self.library_vectors = vectors;
        self
    }
}

/// Arguments for `analysis.code.globals`.
///
/// All three kinds of access are reported together rather than selected by a
/// mode, because they are three ways one program reaches its variables and a
/// caller guessing which convention a binary uses wants to see which one
/// actually appears. The derived pass is the exception: it propagates address
/// registers through straight-line code, which is work nobody should pay for
/// unless they asked.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodeGlobalsArguments {
    pub source: SourceLocator,
    /// CODE hunk to analyze. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the traversal starts, as hunk offsets. Defaults to offset 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    /// The address the hunk is mapped at. Absolute accesses cannot be
    /// identified without it — "inside the image" has no meaning until the
    /// image has a place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    /// Address register the small-data convention uses. Defaults to A5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_register: Option<u8>,
    /// Also resolve indirect accesses through propagated address registers.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub derived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_accesses: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CodeGlobalsArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            entries: Vec::new(),
            origin: None,
            base_register: None,
            derived: false,
            maximum_accesses: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub fn from_entries(mut self, entries: Vec<u32>) -> Self {
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn through_register(mut self, register: u8) -> Self {
        self.base_register = Some(register);
        self
    }

    #[must_use]
    pub const fn with_derived(mut self) -> Self {
        self.derived = true;
        self
    }
}

/// Arguments for `analysis.code.fixed-point`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodeFixedPointArguments {
    pub source: SourceLocator,
    /// CODE hunk to analyze. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the traversal starts, as hunk offsets. Defaults to offset 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    /// The address the hunk is mapped at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_hints: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CodeFixedPointArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            entries: Vec::new(),
            origin: None,
            maximum_hints: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub fn from_entries(mut self, entries: Vec<u32>) -> Self {
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }
}

/// Arguments for `analysis.code.callgraph`.
///
/// The same traversal `analysis.code.disassemble` runs, reduced to functions and the
/// calls between them. This operation collapses call sites onto caller/callee pairs and
/// counts degrees so consumers share the same connectivity measurements.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodeCallgraphArguments {
    pub source: SourceLocator,
    /// CODE hunk to analyze. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the traversal starts, as hunk offsets. Defaults to offset 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    /// The address the hunk is mapped at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_nodes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_edges: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CodeCallgraphArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            entries: Vec::new(),
            origin: None,
            maximum_nodes: None,
            maximum_edges: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub fn from_entries(mut self, entries: Vec<u32>) -> Self {
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn with_maximum_nodes(mut self, nodes: usize) -> Self {
        self.maximum_nodes = Some(nodes);
        self
    }
}

/// Arguments for `analysis.address.references`.
///
/// One operation in two modes: without a `target` it reports every address the
/// code names, and with one it reports only the sites naming that address.
/// Naming a target also brings in the image's relocations, because a stored
/// pointer is a reference too — and without a target there is no way to say
/// which relocation references what, only the full list `analysis.hunk.list`
/// already gives.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddressReferencesArguments {
    pub source: SourceLocator,
    /// CODE hunk whose instructions are examined. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Report only references naming this address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<u32>,
    /// Where the traversal starts, as hunk offsets. Defaults to offset 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    /// The address the hunk is mapped at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_references: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl AddressReferencesArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            target: None,
            entries: Vec::new(),
            origin: None,
            maximum_references: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub const fn naming(mut self, target: u32) -> Self {
        self.target = Some(target);
        self
    }

    #[must_use]
    pub fn from_entries(mut self, entries: Vec<u32>) -> Self {
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn with_maximum_references(mut self, references: usize) -> Self {
        self.maximum_references = Some(references);
        self
    }
}

/// Which question `analysis.code.disassemble` is being asked.
///
/// One operation in two modes rather than two operations differing by a
/// boolean: both answer "what instructions are in this hunk", and they differ
/// only in how the instructions are found.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeDisassembleMode {
    /// Decode every word in a range, in order, whether or not anything reaches
    /// it. Finds instructions where control flow never arrives, and decodes
    /// data as instructions where it is data.
    #[default]
    Linear,
    /// Follow control flow from entry points. Reports what was reached, and
    /// what was not.
    Flow,
}

/// Arguments for `analysis.code.disassemble`.
///
/// The response carries instructions and edges, never a listing. A listing is a
/// display format, and freezing one into the machine contract would make every
/// consumer of the facts depend on how one frontend chose to print them.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodeDisassembleArguments {
    pub source: SourceLocator,
    /// Whether the source is a HUNK container or pinned raw code.
    #[serde(default)]
    pub region: CodeRegion,
    /// CODE hunk to disassemble. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Required for a raw region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub mode: CodeDisassembleMode,
    /// Linear mode: where the sweep starts, as a hunk offset. Must be even —
    /// an MC68000 cannot fetch an instruction from an odd address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    /// Linear mode: where the sweep stops. Defaults to the end of the hunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<u32>,
    /// Flow mode: where the traversal starts, as hunk offsets. Defaults to
    /// offset 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    /// The address the hunk is mapped at. With one, every instruction also
    /// reports its runtime address and the traversal resolves absolute
    /// operands through it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_instructions: Option<usize>,
    /// Cap on each edge list and on the unreached runs. Every list reports its
    /// true total beside the capped one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_edges: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CodeDisassembleArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            region: CodeRegion::Hunk,
            hunk: None,
            expected_sha256: None,
            mode: CodeDisassembleMode::Linear,
            start: None,
            end: None,
            entries: Vec::new(),
            origin: None,
            maximum_instructions: None,
            maximum_edges: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    /// Decode a pinned raw MC68000 image instead of parsing a HUNK container.
    #[must_use]
    pub fn in_raw(mut self, expected_sha256: impl Into<String>) -> Self {
        self.region = CodeRegion::Raw;
        self.hunk = None;
        self.expected_sha256 = Some(expected_sha256.into());
        self
    }

    /// Follow control flow instead of sweeping.
    #[must_use]
    pub fn following_flow(mut self, entries: Vec<u32>) -> Self {
        self.mode = CodeDisassembleMode::Flow;
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn over_range(mut self, start: u32, end: Option<u32>) -> Self {
        self.start = Some(start);
        self.end = end;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn with_maximum_instructions(mut self, instructions: usize) -> Self {
        self.maximum_instructions = Some(instructions);
        self
    }

    #[must_use]
    pub const fn with_maximum_edges(mut self, edges: usize) -> Self {
        self.maximum_edges = Some(edges);
        self
    }
}

/// The hunk whose position in an image anchors a whole-file frame.
///
/// Source and hunk travel together because neither means anything alone: a hunk
/// index with no image names nothing, and an image with no index leaves the
/// frame unanchored. One optional pair makes the useless combination
/// unrepresentable rather than something normalization has to refuse.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkAnchor {
    pub source: SourceLocator,
    /// Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
}

impl HunkAnchor {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }
}

/// Arguments for `analysis.address.resolve`.
///
/// The mapped origin is an argument rather than something the operation reads,
/// because nothing in a LoadSeg image says where it was loaded. It is the
/// caller's claim about the machine, and the answer is only as good as it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddressResolveArguments {
    /// The number to interpret. Which frame it is in is exactly the question.
    pub value: u32,
    /// The address the hunk is mapped at.
    pub origin: u32,
    /// Anchor the whole-file frame on a hunk's position in an image. Without
    /// one, only the absolute and hunk-relative readings can be given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<HunkAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl AddressResolveArguments {
    #[must_use]
    pub const fn new(value: u32, origin: u32) -> Self {
        Self {
            value,
            origin,
            anchor: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub fn anchored_on(mut self, anchor: HunkAnchor) -> Self {
        self.anchor = Some(anchor);
        self
    }
}

/// Arguments for `analysis.pointers.scan`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PointerScanArguments {
    pub source: SourceLocator,
    /// Hunk to scan. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// The address the hunk is mapped at. Targets are plausible when they land
    /// inside `[origin, origin + hunk bytes)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    /// Consecutive plausible entries a run needs before it counts as a table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_entries: Option<usize>,
    /// Read unsigned words scaled by this factor instead of absolute longwords.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word_scale: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_tables: Option<usize>,
    /// Cap on the targets reported per table. Each table always reports its
    /// true total beside the capped list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_targets: Option<usize>,
    /// Cap on the derived entry offsets. Its own bound rather than the target
    /// cap's: the targets are what a table *shows* and the entry offsets are
    /// what a caller *analyzes from*, so narrowing the display must not narrow
    /// the analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_entry_offsets: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl PointerScanArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            origin: None,
            minimum_entries: None,
            word_scale: None,
            maximum_tables: None,
            maximum_targets: None,
            maximum_entry_offsets: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub const fn with_minimum_entries(mut self, entries: usize) -> Self {
        self.minimum_entries = Some(entries);
        self
    }

    #[must_use]
    pub const fn with_word_scale(mut self, scale: u32) -> Self {
        self.word_scale = Some(scale);
        self
    }

    #[must_use]
    pub const fn with_maximum_tables(mut self, tables: usize) -> Self {
        self.maximum_tables = Some(tables);
        self
    }

    #[must_use]
    pub const fn with_maximum_targets(mut self, targets: usize) -> Self {
        self.maximum_targets = Some(targets);
        self
    }

    #[must_use]
    pub const fn with_maximum_entry_offsets(mut self, offsets: usize) -> Self {
        self.maximum_entry_offsets = Some(offsets);
        self
    }
}

/// Arguments for `analysis.strings.scan`.
///
/// The substring filter is part of the request rather than something a caller
/// applies afterwards, because it decides *which* strings a capped result holds:
/// filtering a truncated list would silently drop matches the scan found and
/// the cap discarded.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StringsScanArguments {
    pub source: SourceLocator,
    /// Scan only this hunk's bytes, rather than the whole file. Offsets are
    /// then relative to the hunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Shortest printable run to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_length: Option<usize>,
    /// Report only strings holding this substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_strings: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl StringsScanArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            minimum_length: None,
            contains: None,
            maximum_strings: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub const fn with_minimum_length(mut self, length: usize) -> Self {
        self.minimum_length = Some(length);
        self
    }

    #[must_use]
    pub fn containing(mut self, needle: impl Into<String>) -> Self {
        self.contains = Some(needle.into());
        self
    }

    #[must_use]
    pub const fn with_maximum_strings(mut self, strings: usize) -> Self {
        self.maximum_strings = Some(strings);
        self
    }
}

/// Arguments for `analysis.hunk.list`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkListArguments {
    pub source: SourceLocator,
    /// Cap on the relocations reported per hunk. The true total is always
    /// beside the capped list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_relocations: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl HunkListArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_relocations: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_relocations(mut self, relocations: usize) -> Self {
        self.maximum_relocations = Some(relocations);
        self
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }
}

/// Arguments for `analysis.hunk.normalize`.
///
/// Nothing to configure: a one-file loader's compact relocation records either
/// rewrite into standard ones or they do not. An option here would be an
/// invitation to produce a second, differently-wrong image.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkNormalizeArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl HunkNormalizeArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_input_bytes(mut self, bytes: u64) -> Self {
        self.maximum_input_bytes = Some(bytes);
        self
    }
}

/// Arguments for `analysis.hunk.normalize.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkNormalizeExportArguments {
    #[serde(flatten)]
    pub normalize: HunkNormalizeArguments,
    /// Directory the rewritten image goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl HunkNormalizeExportArguments {
    #[must_use]
    pub fn new(normalize: HunkNormalizeArguments, destination: impl Into<String>) -> Self {
        Self {
            normalize,
            destination: destination.into(),
            file_name: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `analysis.table.decode`.
///
/// The layout is a spec string rather than a structured field list, because it
/// is what a person types while guessing at a table and what they paste back
/// when the guess was right.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableDecodeArguments {
    pub source: SourceLocator,
    /// Field list, e.g. `u16,u16,ptr,char[16]`.
    ///
    /// One of this and `type_id`, never both: they are two spellings of the
    /// same thing, and a request carrying both would have to decide which wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,
    /// A struct the project defines, naming the record layout instead of
    /// spelling it out.
    ///
    /// This is what closes the loop the project format always implied: a table
    /// resource names its record through `type_id`, and until now nothing could
    /// decode through the thing that id points at. Needs the envelope's
    /// `project` locator, because the definition lives in the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    /// Byte offset of the first record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// How many records to decode.
    pub rows: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_rows: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl TableDecodeArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, layout: impl Into<String>, rows: usize) -> Self {
        Self {
            source: SourceLocator::file(source),
            layout: Some(layout.into()),
            type_id: None,
            offset: None,
            rows,
            maximum_rows: None,
            maximum_input_bytes: None,
        }
    }

    /// Decode through a struct the project defines rather than a layout string.
    #[must_use]
    pub fn through_type(
        source: impl Into<String>,
        type_id: impl Into<String>,
        rows: usize,
    ) -> Self {
        Self {
            source: SourceLocator::file(source),
            layout: None,
            type_id: Some(type_id.into()),
            offset: None,
            rows,
            maximum_rows: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_rows(mut self, rows: usize) -> Self {
        self.maximum_rows = Some(rows);
        self
    }
}

/// Arguments for `analysis.table.summarize`.
///
/// One layout over one or more sources. Decoding each separately and comparing
/// the answers outside the toolkit is what this replaces, and it is where the
/// comparison goes wrong: the layout has to be identical for a column-by-column
/// comparison to mean anything, and two requests cannot promise that.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableSummarizeArguments {
    /// The tables to summarize, each read with the same layout at the same
    /// offset. Several is the point: comparing one column across the memory
    /// several sandbox runs exported is the question this exists for.
    pub sources: Vec<SourceLocator>,
    /// Field list, e.g. `u16,u16,ptr,char[16]`. One of this and `type_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,
    /// A struct the project defines, naming the record layout instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    /// Byte offset of the first record, in every source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// How many records to read from each.
    pub rows: usize,
    /// Cap on the distinct values listed per column. The distinct *count* is
    /// always exact, so a capped list cannot be read as the whole set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_values: Option<usize>,
    /// Cap on the rows listed per column where the sources disagree. The
    /// differing count is always exact, for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_differences: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_rows: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl TableSummarizeArguments {
    #[must_use]
    pub fn new(
        sources: impl IntoIterator<Item = impl Into<String>>,
        layout: impl Into<String>,
        rows: usize,
    ) -> Self {
        Self {
            sources: sources.into_iter().map(SourceLocator::file).collect(),
            layout: Some(layout.into()),
            type_id: None,
            offset: None,
            rows,
            maximum_values: None,
            maximum_differences: None,
            maximum_rows: None,
            maximum_input_bytes: None,
        }
    }

    /// Summarize through a struct the project defines rather than a layout
    /// string.
    #[must_use]
    pub fn through_type(
        sources: impl IntoIterator<Item = impl Into<String>>,
        type_id: impl Into<String>,
        rows: usize,
    ) -> Self {
        Self {
            sources: sources.into_iter().map(SourceLocator::file).collect(),
            layout: None,
            type_id: Some(type_id.into()),
            offset: None,
            rows,
            maximum_values: None,
            maximum_differences: None,
            maximum_rows: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn with_maximum_values(mut self, values: usize) -> Self {
        self.maximum_values = Some(values);
        self
    }
}

/// Arguments for `analysis.hunk.diff`.
///
/// Two sources and nothing else: which hunks to compare is not a choice, since
/// a structural comparison that skipped one would answer a question nobody
/// asked.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkDiffArguments {
    /// The first image, reported as the `a` side.
    pub a: SourceLocator,
    /// The second image, reported as the `b` side.
    pub b: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
    /// Cap on the changed ranges reported per hunk. The true count is always
    /// reported, so a capped comparison cannot be read as a complete one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_changed_ranges: Option<usize>,
}

impl HunkDiffArguments {
    #[must_use]
    pub fn new(a: impl Into<String>, b: impl Into<String>) -> Self {
        Self {
            a: SourceLocator::file(a),
            b: SourceLocator::file(b),
            maximum_input_bytes: None,
            maximum_changed_ranges: None,
        }
    }
}

/// How an exported comparison is written.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HunkDiffFormat {
    /// The structured report, for another program to read.
    #[default]
    Json,
    /// The rendered report, for a person to read.
    Text,
}

impl HunkDiffFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }

    /// The file name an export uses when the request names none.
    #[must_use]
    pub const fn default_file_name(self) -> &'static str {
        match self {
            Self::Json => "hunk-diff.json",
            Self::Text => "hunk-diff.txt",
        }
    }
}

/// Arguments for `analysis.hunk.diff.export`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkDiffExportArguments {
    #[serde(flatten)]
    pub diff: HunkDiffArguments,
    /// Directory the report goes in, as a destination identity.
    pub destination: String,
    /// File name within the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<HunkDiffFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::output::OutputPolicy>,
}

impl HunkDiffExportArguments {
    #[must_use]
    pub fn new(diff: HunkDiffArguments, destination: impl Into<String>) -> Self {
        Self {
            diff,
            destination: destination.into(),
            file_name: None,
            format: None,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_format(mut self, format: HunkDiffFormat) -> Self {
        self.format = Some(format);
        self
    }

    #[must_use]
    pub fn with_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: crate::output::OutputPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Arguments for `analysis.state.snapshot`.
///
/// Decode a machine's memory and registers through the reviewed types and
/// global-variable annotations a project holds, and report one named,
/// field-addressed value per leaf.
///
/// The point is to stop comparing opaque memory ranges. A digest over a
/// framebuffer-sized region says two runs differ and nothing about *what*
/// differs; a snapshot says `vehicle.velocity.x` changed from 3 to -1. It is
/// also what lets a clean-room port be checked against the original: the port
/// writes a snapshot document of its own, and `analysis.state.compare` reads
/// both.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshotArguments {
    /// Which of the project's images the variables belong to. Omitted, the
    /// project's only image — and a project with more than one is refused
    /// rather than having one picked for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The machine's memory, as ranges of bytes at absolute addresses.
    ///
    /// Typically what `call --save` wrote. A variable whose storage no range
    /// covers is a refusal naming it: a snapshot that quietly omitted a field
    /// would be compared against one that had it and read as a difference in
    /// the program.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<StateRegion>,
    /// The register file the snapshot was taken with.
    ///
    /// The same shape a call record reports its `outputs` in, because that is
    /// where a caller pastes it from. Needed for a base-register global, whose
    /// address is a register plus a displacement; absent, such a variable is
    /// refused rather than read at whatever zero would point at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registers: Option<crate::response::SandboxRegisters>,
    /// Where each hunk was mapped, for a variable targeting a hunk offset.
    ///
    /// The same shape `env.sandbox.call` takes, and for the same reason: the
    /// layout is the run's, not the project's, and a snapshot decoded against a
    /// different one would name the right variable at the wrong address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunk_bases: Vec<HunkBase>,
    /// Cap on reported fields. The true total is always reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_fields: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl StateSnapshotArguments {
    #[must_use]
    pub fn new(regions: Vec<StateRegion>) -> Self {
        Self {
            image: None,
            regions,
            registers: None,
            hunk_bases: Vec::new(),
            maximum_fields: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub fn of_image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    #[must_use]
    pub fn with_registers(mut self, registers: crate::response::SandboxRegisters) -> Self {
        self.registers = Some(registers);
        self
    }

    /// State where one hunk was mapped, for a variable targeting its offsets.
    #[must_use]
    pub fn with_hunk_base(mut self, hunk: u32, address: u32) -> Self {
        self.hunk_bases.push(HunkBase { hunk, address });
        self
    }
}

/// One range of the machine's memory, and where it sits.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateRegion {
    /// The absolute address the first byte of the range is at.
    pub address: u32,
    pub source: SourceLocator,
    /// The digest the file is expected to have, as the run that wrote it
    /// reported.
    ///
    /// Optional, unlike an artifact seed's — a seed changes what a run *does*,
    /// while a snapshot only reads. The digest of what was actually read is
    /// reported either way, so an unpinned snapshot still says which bytes it
    /// described.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Where the range starts in the file. Omitted means the start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// How many bytes. Omitted means the rest of the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
}

impl StateRegion {
    #[must_use]
    pub fn new(address: u32, source: impl Into<String>) -> Self {
        Self {
            address,
            source: SourceLocator::file(source),
            sha256: None,
            offset: None,
            length: None,
        }
    }
}

/// Arguments for `analysis.state.compare`.
///
/// Reads snapshot documents that already exist rather than decoding anything.
/// One of them may have been written by something other than this toolkit,
/// which is the point: a clean-room implementation states its own state in the
/// same shape and is compared field by field against the original's.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateCompareArguments {
    /// The snapshot documents to compare, in the order they are reported. At
    /// least two: comparing one against nothing has no answer.
    pub snapshots: Vec<SourceLocator>,
    /// Cap on the differences listed. The true total is always reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_differences: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl StateCompareArguments {
    #[must_use]
    pub fn new(snapshots: Vec<SourceLocator>) -> Self {
        Self {
            snapshots,
            maximum_differences: None,
            maximum_input_bytes: None,
        }
    }

    /// Compare snapshots named by path.
    #[must_use]
    pub fn of(paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(paths.into_iter().map(SourceLocator::file).collect())
    }
}
