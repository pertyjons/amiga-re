//! `amiga-re`: a unified command-line interface over the amiga-re toolkit.
//!
//! Every command opens its input read-only and writes only to explicit,
//! symlink-checked output paths. Extraction refuses to overwrite without
//! `--force` and rejects unsafe archive-provided names.

use std::fmt::Write as _;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

#[cfg(test)]
use amiga_core::safe_archive_path;
use amiga_core::{ExtractionPlan, PlannedFile, prepare_output_file, sha256};

mod commands;

use commands::*;

#[derive(Parser)]
#[command(
    name = "amiga-re",
    version,
    about = "Reverse-engineering toolkit for Amiga files"
)]
struct Cli {
    /// Path to an amiga-re.toml (otherwise auto-discovered upward from the CWD).
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Project root to take reviewed names from (otherwise auto-discovered
    /// upward from the CWD). Names apply only to the image whose object digest
    /// matches the bytes being analyzed.
    #[arg(long, global = true, value_name = "DIR")]
    project: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

/// The mapped origin shared by every command that rebases addresses.
#[derive(Args, Default)]
struct BaseArgs {
    /// Absolute address where hunk offset zero is mapped (default config [base].origin).
    #[arg(long, value_parser = amiga_core::parse_u32)]
    base: Option<u32>,
}

impl BaseArgs {
    /// The mapped origin these flags select, falling back to config `[base]` when
    /// `--base` is absent.
    fn resolve(&self, config: Option<&amiga_core::Config>) -> Option<amiga_core::config::Base> {
        match self.base {
            Some(origin) => Some(amiga_core::config::Base {
                origin,
                entry: None,
            }),
            None => config.and_then(|config| config.base),
        }
    }
}

/// One title's position-XOR + escape-marker run-length layout.
///
/// Grouped rather than passed as five loose parameters because they describe one
/// thing: where in the stream each part lives. Where the marker is kept is as
/// much a part of that as the size field's width.
#[derive(Args)]
pub(crate) struct RleXorArgs {
    /// The escape byte that introduces a run (title-specific). A cross-check
    /// rather than the source when --inline-marker is set.
    #[arg(long, value_parser = amiga_core::parse_u32)]
    pub(crate) marker: u32,
    /// Skip the position-XOR layer (decode only the run-length body).
    #[arg(long)]
    pub(crate) no_xor: bool,
    /// The stream's first byte is the escape marker; the size field, if any,
    /// and the body follow it.
    #[arg(long)]
    pub(crate) inline_marker: bool,
    /// Width of the leading big-endian size field: 0, 2, or 4 bytes.
    #[arg(long, default_value_t = 4)]
    pub(crate) size_bytes: u8,
    /// The size field counts its own bytes, so the declared output is the field
    /// minus its width.
    #[arg(long)]
    pub(crate) size_includes_field: bool,
    /// Refuse the decode before its output grows past this many bytes.
    #[arg(long)]
    pub(crate) maximum_output_bytes: Option<u64>,
}

/// Shared inputs for the commands that trace control flow from entry points.
#[derive(Args)]
struct AnalysisArgs {
    executable: PathBuf,
    /// Hunk index to analyze.
    #[arg(long, default_value_t = 0)]
    hunk: u32,
    /// Entry point(s): offsets, or absolute addresses when --base is set. Repeatable.
    #[arg(long, value_parser = amiga_core::parse_u32)]
    entry: Vec<u32>,
    #[command(flatten)]
    base: BaseArgs,
}

/// Inputs accepted by the two human-facing disassembly commands that can work
/// from either a container file or a project-recorded raw image.
#[derive(Args)]
struct DisasmTargetArgs {
    /// HUNK executable, or raw bytes when --raw-sha256 is supplied.
    #[arg(conflicts_with = "image")]
    executable: Option<PathBuf>,
    /// Raw project image ID. Uses --project or discovers a project upward.
    #[arg(long, value_name = "ID", conflicts_with = "executable")]
    image: Option<String>,
    /// Load map whose origin and recorded entry points apply to --image.
    #[arg(long, value_name = "ID", requires = "image")]
    load_map: Option<String>,
    /// Pin an explicitly supplied raw file and analyze the whole file as code.
    #[arg(
        long,
        value_name = "SHA256",
        requires = "executable",
        conflicts_with = "image"
    )]
    raw_sha256: Option<String>,
    /// Hunk index for a HUNK executable.
    #[arg(long, default_value_t = 0)]
    hunk: u32,
    /// Entry point(s): offsets, or absolute addresses when an origin applies.
    #[arg(long, value_parser = amiga_core::parse_u32)]
    entry: Vec<u32>,
    #[command(flatten)]
    base: BaseArgs,
}

trait CodeTargetArgs {
    fn executable(&self) -> Option<&Path>;
    fn image(&self) -> Option<&str>;
    fn load_map(&self) -> Option<&str>;
    fn raw_sha256(&self) -> Option<&str>;
    fn hunk(&self) -> u32;
    fn entries(&self) -> &[u32];
    fn explicit_base(&self) -> Option<u32>;
}

impl CodeTargetArgs for AnalysisArgs {
    fn executable(&self) -> Option<&Path> {
        Some(&self.executable)
    }

    fn image(&self) -> Option<&str> {
        None
    }

    fn load_map(&self) -> Option<&str> {
        None
    }

    fn raw_sha256(&self) -> Option<&str> {
        None
    }

    fn hunk(&self) -> u32 {
        self.hunk
    }

    fn entries(&self) -> &[u32] {
        &self.entry
    }

    fn explicit_base(&self) -> Option<u32> {
        self.base.base
    }
}

impl CodeTargetArgs for DisasmTargetArgs {
    fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }

    fn load_map(&self) -> Option<&str> {
        self.load_map.as_deref()
    }

    fn raw_sha256(&self) -> Option<&str> {
        self.raw_sha256.as_deref()
    }

    fn hunk(&self) -> u32 {
        self.hunk
    }

    fn entries(&self) -> &[u32] {
        &self.entry
    }

    fn explicit_base(&self) -> Option<u32> {
        self.base.base
    }
}

/// Which part of a flow listing is printed.
///
/// Bounds are a *rendering* choice and nothing else: the traversal is the whole
/// hunk either way, the coverage header keeps saying so, and the operation is
/// asked exactly the same question. What changes is which of the answer's lines
/// reach stdout — which is what a reader inspecting three small routines wants,
/// and what they were reaching for an external filter to get.
#[derive(Args)]
struct FlowBoundsArgs {
    /// Print only instructions this function entry owns: an offset, or an
    /// absolute address when --base is set. Repeatable.
    #[arg(long = "function", value_name = "ADDR", value_parser = amiga_core::parse_u32)]
    function: Vec<u32>,
    /// Print nothing below this offset (absolute address when --base is set).
    #[arg(long, value_parser = amiga_core::parse_u32)]
    start: Option<u32>,
    /// Stop at this offset, exclusive (absolute address when --base is set).
    #[arg(long, value_parser = amiga_core::parse_u32)]
    end: Option<u32>,
    /// Omit the DC.W/DC.B runs standing for bytes no traversal reached.
    #[arg(long)]
    no_data: bool,
}

/// Shared inputs for the sandbox-execution commands (`run`, `trace`).
#[derive(Args)]
struct ExecArgs {
    executable: PathBuf,
    /// CODE hunk to execute.
    #[arg(long, default_value_t = 0)]
    hunk: u32,
    /// Entry point: an offset, or an absolute address when --base is set
    /// (defaults to config [base].entry, then [base].origin, else the hunk start).
    #[arg(long, value_parser = amiga_core::parse_u32)]
    entry: Option<u32>,
    #[command(flatten)]
    base: BaseArgs,
    /// Maximum instructions to execute.
    #[arg(long, default_value_t = amiga_disasm::execute::DEFAULT_MAX_STEPS)]
    max_steps: usize,
    /// Base address of the sandbox stack region.
    #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0x100000")]
    stack_base: u32,
    /// Size of the sandbox stack region, in bytes.
    #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0x10000")]
    stack_size: u32,
    /// Seed a register before entry, e.g. `--reg d0=0x10 --reg a6=0xdff000`. Repeatable.
    #[arg(long = "reg", value_name = "NAME=VALUE")]
    reg: Vec<String>,
    /// Map another HUNK segment at its real load address, as `HUNK=ADDR`.
    /// Repeat for every relocation target the selected CODE hunk needs.
    #[arg(long = "hunk-base", value_name = "HUNK=ADDR")]
    hunk_base: Vec<String>,
}

/// Watched ranges, shared by every command that executes in the sandbox.
///
/// `--watch-only` is not here: it selects which rows `trace` prints, which is
/// a property of that one command's rendering rather than of the run.
#[derive(Args)]
struct WatchArgs {
    /// Watch `ACCESS:ADDR[:LENGTH]`, where ACCESS is r, w, or rw. Repeatable.
    #[arg(long = "watch", value_name = "ACCESS:ADDR[:LENGTH]")]
    watch: Vec<String>,
    /// Stop after the first instruction that matches a watchpoint.
    #[arg(long, requires = "watch")]
    watch_stop: bool,
}

/// What one `call` recipe states beyond the sandbox layout it shares with
/// `run`: the arguments, the regions, the seeds, and where the record goes.
#[derive(Args)]
pub(crate) struct CallArgs {
    /// Record the per-instruction trace into the golden record.
    #[arg(long)]
    pub(crate) trace: bool,
    /// Longword stack argument in C order (arg1 first). Repeatable.
    #[arg(long = "arg", value_parser = amiga_core::parse_u32)]
    pub(crate) args: Vec<u32>,
    /// Map an extra RAM region `ADDR:SIZE` for input/output buffers. Repeatable.
    #[arg(long = "map", value_name = "ADDR:SIZE")]
    pub(crate) map: Vec<String>,
    /// Seed memory with `ADDR=HEXBYTES` before the call. Repeatable.
    #[arg(long = "poke", value_name = "ADDR=HEX")]
    pub(crate) poke: Vec<String>,
    /// Seed memory from a range of the image itself, as `ADDR=SRC:LEN` or
    /// `ADDR=HUNK/SRC:LEN`. Repeatable; the alternative to converting the bytes
    /// to hex by hand.
    #[arg(long = "poke-from", value_name = "ADDR=[HUNK/]OFF:LEN")]
    pub(crate) poke_from: Vec<String>,
    /// Replay a file an earlier run wrote, as `ADDR=FILE@SHA256[:OFF:LEN]`.
    /// Repeatable. The digest is required and is checked before the routine
    /// runs: seeding from a file that has since changed produces outputs that
    /// look like evidence about a file this recipe never read. Omitting the
    /// range replays the whole file, which the digest makes exact. The file
    /// sits beside the image, or under the scratch directory a project
    /// declares — for a project that keeps provisional outputs away from its
    /// source media, that declaration is what names the second place.
    #[arg(long = "poke-artifact", value_name = "ADDR=FILE@SHA256[:OFF:LEN]")]
    pub(crate) poke_artifact: Vec<String>,
    /// Deliver an interrupt on a schedule, as `vNN=AFTER[:EVERY]` for a 68000
    /// vector (v27 is level 3: vertical blank and Copper) or
    /// `ADDR[/rte|/rts]=AFTER[:EVERY]` for a fixed handler. Fixed handlers
    /// default to `rte`; select `rts` for a plain subroutine. AFTER and EVERY
    /// are instruction counts. Repeatable.
    #[arg(long = "interrupt", value_name = "vNN|ADDR[/rte|/rts]=AFTER[:EVERY]")]
    pub(crate) interrupt: Vec<String>,
    /// Print the arguments the entry's reviewed signature states, and run
    /// nothing.
    ///
    /// The template names each parameter and where it goes and supplies **no
    /// value for any of them**: a signature says where an argument lives and
    /// never what it should be, so a filled-in zero would be an input this
    /// toolkit invented. Needs a project annotating the entry with a callable
    /// type.
    #[arg(long, conflicts_with_all = ["output", "cases", "save"])]
    pub(crate) template: bool,
    /// Run even though the entry's reviewed signature names a parameter this
    /// command line does not supply.
    ///
    /// The refusal exists because an unsupplied argument is not zero — it is
    /// whatever the sandbox happens to start that register at, and a record of
    /// such a run reads exactly like a record of a call that was made properly.
    #[arg(long = "partial-arguments")]
    pub(crate) partial_arguments: bool,
    /// Name a range of the routine's final memory as `NAME=ADDR:LEN`.
    /// Repeatable; needs --output or --cases.
    ///
    /// With --output the bytes are written beside the golden record. With
    /// --cases each case reports the digest of its own range instead, because a
    /// sweep of three hundred cases writing its memory is a directory nobody
    /// reads — the one case that matters is re-run through `call` for the bytes.
    #[arg(long = "save", value_name = "NAME=ADDR:LEN")]
    pub(crate) save: Vec<String>,
    /// Model the custom chips at $DFF000, so a routine that drives the blitter
    /// changes memory. Refuses any mapping that overlaps $DFF000..$DFF200.
    #[arg(long = "custom-chips")]
    pub(crate) custom_chips: bool,
    /// What to do when a blit starts with DMACON saying blitter DMA is off.
    /// `assume` blits anyway and says so — the default, because a call starts
    /// mid-program after an initialization the sandbox never ran. `require`
    /// refuses the blit, for a recipe that did run it. Needs --custom-chips.
    #[arg(
        long = "blitter-dma",
        value_name = "assume|require",
        requires = "custom_chips"
    )]
    pub(crate) blitter_dma: Option<BlitterDmaArg>,
    /// Run a matrix of cases from this JSON file instead of one call.
    ///
    /// Every other argument becomes the shared recipe — the source, the map,
    /// the stack, the chip model, the watches and the saves — and each case in
    /// the file overrides only what the routine is handed. The file is a JSON
    /// array of `{"name": ..., "data_registers": [...], "address_registers":
    /// [...], "entry_offset": ..., "stack_arguments": [...], "memory_seeds":
    /// [...], "notes": ...}`, of which only `name` is required.
    ///
    /// The result reports each case's registers, stop reason and changed-region
    /// digests. It does not carry the changed bytes: a sweep of three hundred
    /// cases carrying its memory is a file nobody reads. Re-run the one case
    /// that matters through `call` with its own inputs to get them.
    #[arg(long = "cases", value_name = "FILE", conflicts_with = "output")]
    pub(crate) cases: Option<PathBuf>,
    /// Run a timeline of steps from this JSON file instead of one call.
    ///
    /// The opposite claim from --cases. A matrix's cases are deliberately
    /// independent, each starting from the same state; a timeline's steps share
    /// one evolving machine, so step N+1 sees the memory, registers, chip state
    /// and interrupt state step N left. A game loop's second tick means nothing
    /// otherwise.
    ///
    /// Every other argument becomes the machine — the source, the map, the
    /// stack, the chip model, the watches and the initial seeds. The file is a
    /// JSON array of `{"name": ..., "entry_offset": ...}` or `{"name": ...,
    /// "resume": true}`, optionally with `data_registers`, `address_registers`,
    /// `stack_arguments`, `memory_seeds`, `maximum_steps`, `stop_at`,
    /// `checkpoints` and `notes`.
    ///
    /// The result reports each step's registers, stop reason, changed-region
    /// digests and checkpoint digests. It does not carry the bytes: pass
    /// --steps-output to write them.
    #[arg(
        long = "steps",
        value_name = "FILE",
        conflicts_with_all = ["output", "cases", "cases_output"]
    )]
    pub(crate) steps: Option<PathBuf>,
    /// Write each step's `checkpoints` into this directory, under the step's own
    /// name. Needs --steps.
    ///
    /// The only way to get a step's bytes. Re-running the step through `call`
    /// with --save works when the step can be reproduced as a standalone call,
    /// and a step deep in an evolving timeline cannot: its inputs are the
    /// machine every step before it produced.
    ///
    /// Nothing is written until every step has run, and the manifest records
    /// each file's step and the timeline's recipe digest — so a later run can
    /// tell its own outputs from another's that reused the step names.
    #[arg(long = "steps-output", value_name = "DIR", requires = "steps")]
    pub(crate) steps_output: Option<PathBuf>,
    /// Instructions the whole sweep or timeline may execute.
    ///
    /// Needs --cases or --steps. A case or a step is never clipped to what is
    /// left: it either runs with the budget it asked for or is reported as not
    /// run.
    #[arg(long = "max-total-steps")]
    pub(crate) max_total_steps: Option<usize>,
    /// Write each case's --save ranges into this directory, under the case's own
    /// name. Needs --cases.
    ///
    /// Nothing is written until every case has run, and the manifest records
    /// each file's case and that case's recipe digest — so a later sweep can
    /// tell its own outputs from another's that reused the case names.
    #[arg(long = "cases-output", value_name = "DIR", requires = "cases")]
    pub(crate) cases_output: Option<PathBuf>,
    /// Follow one value backwards through the instructions that produced it,
    /// instead of reporting the run.
    ///
    /// Spelled as a register (`d0`, `a5`, `ccr`), a byte of memory
    /// (`mem:0x21000`), or an instruction and which execution of it
    /// (`at:0x2104` or `at:0x2104#3`). Trace comparison identifies the first
    /// instruction two runs disagree at; a slice says *why* — which earlier
    /// value made that instruction behave differently, and which reviewed input
    /// made that one.
    ///
    /// The trace is turned on whatever `--trace` says, and the answer is a
    /// superset: definitions are exact and uses are over-approximated, so the
    /// slice may include a dependency the run did not really have and will not
    /// miss one it did.
    #[arg(
        long = "slice",
        value_name = "REG|mem:ADDR|at:ADDR[#N]",
        conflicts_with_all = ["output", "cases", "steps", "template"]
    )]
    pub(crate) slice: Option<String>,
    /// Edges a slice follows before stopping. The bound is stated in the result
    /// rather than producing a shorter answer that reads as a complete one.
    #[arg(long = "slice-depth", requires = "slice")]
    pub(crate) slice_depth: Option<usize>,
    /// Write the golden record JSON here instead of standard output.
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    #[arg(long)]
    pub(crate) force: bool,
}

/// How `--blitter-dma` is spelled on the command line.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum BlitterDmaArg {
    /// Blit even with DMA off, and say the assumption was made.
    Assume,
    /// Refuse a blit started with DMA off.
    Require,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect or extract AmigaDOS disk images (OFS and FFS).
    Adf {
        #[command(subcommand)]
        action: AdfAction,
    },
    /// Inspect a floppy boot block or disassemble its boot code.
    Boot {
        #[command(subcommand)]
        action: BootAction,
    },
    /// Inspect Amiga HUNK executables.
    Hunk {
        #[command(subcommand)]
        action: HunkAction,
    },
    /// Disassemble MC68000 code from a HUNK executable.
    Disasm {
        #[command(subcommand)]
        action: DisasmAction,
    },
    /// Execute a routine in a sandbox and print its final state.
    Run {
        #[command(flatten)]
        target: ExecArgs,
        #[command(flatten)]
        watch: WatchArgs,
    },
    /// Execute a routine in a sandbox and print a per-instruction trace.
    Trace {
        #[command(flatten)]
        target: ExecArgs,
        #[command(flatten)]
        watch: WatchArgs,
        /// Print only instructions that match a watchpoint.
        #[arg(long, requires = "watch", conflicts_with = "watch_stop")]
        watch_only: bool,
    },
    /// Invoke one routine to RTS and emit a golden input/output record.
    Call {
        #[command(flatten)]
        target: ExecArgs,
        #[command(flatten)]
        watch: WatchArgs,
        #[command(flatten)]
        recipe: CallArgs,
    },
    /// Compare golden call records by what they were given and what they did.
    ///
    /// A textual diff of two records answers the wrong question: it has no idea
    /// which fields are inputs, so a changed input register and a changed output
    /// register read as the same kind of finding, when one is the question and
    /// the other is the answer.
    Compare {
        /// The golden records to compare, in the order they are reported. At
        /// least two.
        #[arg(required = true, num_args = 2..)]
        records: Vec<PathBuf>,
        /// Cap on the differences of each kind that are listed. The true totals
        /// are always reported.
        #[arg(long)]
        max_differences: Option<usize>,
        /// Emit the full comparison as JSON instead of the summary.
        #[arg(long)]
        json: bool,
    },
    /// Reconstruct the frame the display hardware would have shown.
    Frame {
        #[command(subcommand)]
        action: FrameAction,
    },
    /// Read a machine's state through a project's reviewed types and globals.
    State {
        #[command(subcommand)]
        action: StateAction,
    },
    /// Resolve addresses and cross-reference pointers.
    Xref {
        #[command(subcommand)]
        action: XrefAction,
    },
    /// Scan a binary for Copper lists.
    Copper {
        #[command(subcommand)]
        action: CopperAction,
    },
    /// Query Amiga custom-chip hardware knowledge.
    Hw {
        #[command(subcommand)]
        action: HwAction,
    },
    /// Render planar bitplane data to an image.
    Bitmap {
        #[command(subcommand)]
        action: BitmapAction,
    },
    /// Extract blitter objects (BOBs) with their transparency mask.
    Bob {
        #[command(subcommand)]
        action: BobAction,
    },
    /// Locate or export raw RGB4 ($0RGB) palette tables.
    Palette {
        #[command(subcommand)]
        action: PaletteAction,
    },
    /// Inspect or convert IFF media.
    Iff {
        #[command(subcommand)]
        action: IffAction,
    },
    /// Locate or export raw 8-bit signed PCM (Paula) samples.
    Sample {
        #[command(subcommand)]
        action: SampleAction,
    },
    /// Detect and rip ProTracker/SoundTracker modules.
    Mod {
        #[command(subcommand)]
        action: ModAction,
    },
    /// Decompress packed data.
    Unpack {
        #[command(subcommand)]
        action: UnpackAction,
    },
    /// Inspect or extract LHA/LZH archives.
    Lha {
        #[command(subcommand)]
        action: LhaAction,
    },
    /// Dump printable strings with their offsets.
    Strings {
        file: PathBuf,
        /// Minimum run length.
        #[arg(long, default_value_t = amiga_core::strings::DEFAULT_MIN_LENGTH)]
        min: usize,
        /// Restrict to one hunk of a HUNK executable; offsets become hunk-relative.
        #[arg(long)]
        hunk: Option<u32>,
        /// Only show strings containing this substring.
        #[arg(long)]
        contains: Option<String>,
    },
    /// List the structured operations this build serves, or run one.
    ///
    /// With no subcommand this lists the catalog. `operations run` is the
    /// structured boundary automation uses: it takes a request document and
    /// writes back a response document, never human prose.
    Operations {
        #[command(subcommand)]
        action: Option<OperationsAction>,
        /// How to write the listing.
        #[arg(long, value_enum, default_value_t = ResponseMode::Text)]
        response: ResponseMode,
    },
    /// Print a bundled operation JSON Schema, or emit the whole set.
    Schema {
        /// Operation to describe. Omitted, this prints the request or response
        /// *envelope* schema, which is the document a caller actually writes.
        operation: Option<String>,
        /// Which half of the contract to print.
        #[arg(long, value_enum, default_value_t = SchemaKind::Request)]
        kind: SchemaKind,
        /// Write every bundled schema into this directory instead of printing.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Inspect or verify a versioned amiga-re project.
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Show or verify the per-project amiga-re.toml.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Write a provenance manifest (path, size, SHA-256) for a file.
    Manifest {
        path: PathBuf,
        /// Write JSON to this file instead of standard output.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Cut a byte region to a file, next to a provenance manifest.
    Carve {
        file: PathBuf,
        output: PathBuf,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        #[arg(long, value_parser = amiga_core::parse_u32)]
        length: u32,
        #[arg(long)]
        force: bool,
    },
    /// Decode a region as an array of fixed-layout records.
    Table {
        #[command(subcommand)]
        action: TableAction,
    },
    /// Compare two HUNK executables hunk-by-hunk (structural comparison).
    Diff {
        a: PathBuf,
        b: PathBuf,
        /// Path of the report to write instead of printing the comparison.
        #[arg(long)]
        output: Option<PathBuf>,
        /// How an exported comparison is rendered.
        #[arg(long, value_enum, default_value_t)]
        format: DiffFormat,
        #[arg(long)]
        force: bool,
    },
    /// Run every locator and print one ordered offset-range → type map.
    Survey {
        file: PathBuf,
        /// Minimum printable-string run length to report.
        #[arg(long, default_value_t = amiga_operations::DEFAULT_SURVEY_MIN_STRING_LENGTH)]
        min_string: usize,
        /// Refuse a source larger than this many bytes.
        #[arg(long)]
        max_input_bytes: Option<u64>,
        /// Report at most this many regions. The true total is always printed.
        #[arg(long)]
        max_regions: Option<usize>,
    },
    /// Scan binaries for structural tables.
    Scan {
        #[command(subcommand)]
        action: ScanAction,
    },
    /// Print a hex + ASCII view of a region, addressed like the rest of the toolkit.
    Dump {
        file: PathBuf,
        /// Start position: a whole-file offset, hunk-relative with --hunk, or absolute with --address.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        /// Number of bytes to show.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "256")]
        length: u32,
        /// Read from this hunk; --offset is hunk-relative and relocation sites are marked.
        #[arg(long)]
        hunk: Option<u32>,
        /// Interpret --offset as an absolute address resolved through the base.
        #[arg(long)]
        address: bool,
        #[command(flatten)]
        base: BaseArgs,
    },
}

#[derive(Subcommand)]
enum ScanAction {
    /// Discover runs of plausible in-image pointers or scaled offsets.
    Pointers {
        executable: PathBuf,
        /// Hunk index to scan.
        #[arg(long, default_value_t = 0)]
        hunk: u32,
        /// Minimum consecutive entries required for a candidate table.
        #[arg(long, default_value_t = 3)]
        min: usize,
        /// Scan u16 offsets multiplied by this scale instead of absolute u32 pointers.
        #[arg(long, value_parser = amiga_core::parse_u32, value_name = "SCALE")]
        word_scale: Option<u32>,
        /// Analyze a CODE hunk from every discovered target as an additional entry.
        #[arg(long)]
        seed_flow: bool,
        #[command(flatten)]
        base: BaseArgs,
    },
}

#[derive(Subcommand)]
enum TableAction {
    /// Dump `count` big-endian records, resolving pointer fields via the base.
    Dump {
        file: PathBuf,
        /// Field layout, e.g. "u16,u16,u32ptr,char[16]".
        layout: String,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "1")]
        count: u32,
        #[command(flatten)]
        base: BaseArgs,
    },
    /// Summarize a table's columns, and compare them across several files.
    ///
    /// What `dump` leaves to external sorting: which values a column actually
    /// takes, how often, and — with more than one file — the rows where they
    /// disagree. Every count is exact; only the lists beside them are capped.
    Summary {
        /// The files to read, each with the same layout at the same offset.
        #[arg(required = true, num_args = 1..)]
        files: Vec<PathBuf>,
        /// Field layout, e.g. "u16,u16,u32ptr,char[16]".
        #[arg(long)]
        layout: String,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "1")]
        count: u32,
        /// List at most this many distinct values per column.
        #[arg(long, default_value_t = 8)]
        max_values: usize,
        /// List at most this many differing rows per column.
        #[arg(long, default_value_t = 16)]
        max_differences: usize,
        #[command(flatten)]
        base: BaseArgs,
    },
}

#[derive(Subcommand)]
enum AdfAction {
    /// List the volume and its files.
    List {
        image: PathBuf,
        /// Report at most this many entries. The true total is always printed.
        #[arg(long)]
        max_entries: Option<usize>,
    },
    /// Extract every file to a directory, writing a provenance manifest.
    Extract {
        image: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum HunkAction {
    /// List segments and relocation counts.
    List { executable: PathBuf },
    /// Rewrite a one-file loader's compact relocations as standard records.
    ///
    /// The input must already be known to carry the compact encoding: the two
    /// encodings are not distinguishable, so an image that already parses is
    /// reported as needing nothing rather than rewritten.
    Normalize {
        executable: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum BootAction {
    /// Decode the boot-block header and validate its checksum.
    Info { image: PathBuf },
    /// Control-flow-disassemble the boot code (A6 = ExecBase on entry).
    Disasm { image: PathBuf },
    /// Run the boot code in a sandbox: report what it pokes and calls, and
    /// optionally dump the disk tracks its trackloader reads.
    Trace {
        image: PathBuf,
        /// Maximum instructions to execute.
        #[arg(long, default_value_t = amiga_disasm::execute::DEFAULT_MAX_STEPS)]
        max_steps: usize,
        /// Watch `ACCESS:ADDR[:LENGTH]` (r/w/rw). Observes CPU accesses only;
        /// bulk-copied disk reads are not seen (watch the code that reads them).
        #[arg(long = "watch", value_name = "ACCESS:ADDR[:LENGTH]")]
        watch: Vec<String>,
        /// Stop after the first instruction that matches a watchpoint.
        #[arg(long, requires = "watch")]
        watch_stop: bool,
        /// Dump the served track reads to this directory, with a manifest.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, requires = "output")]
        force: bool,
    },
}

#[derive(Subcommand)]
enum DisasmAction {
    /// Linear sweep of a code range.
    Linear {
        executable: PathBuf,
        #[arg(long, default_value_t = 0)]
        hunk: u32,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        start: u32,
        #[arg(long, value_parser = amiga_core::parse_u32)]
        end: Option<u32>,
    },
    /// Control-flow-aware listing from one or more entry points.
    Flow {
        #[command(flatten)]
        target: DisasmTargetArgs,
        #[command(flatten)]
        bounds: FlowBoundsArgs,
    },
    /// Map base-register-relative (small-data) global accesses.
    Globals {
        #[command(flatten)]
        target: AnalysisArgs,
        /// Base address register (5 = A5, the small-data convention).
        #[arg(long, default_value_t = 5)]
        base_register: u8,
        /// Fixed-address mode: map absolute-long accesses inside the loaded image.
        #[arg(long)]
        absolute: bool,
        /// Resolve indirect accesses through conservatively propagated address registers.
        #[arg(long, requires = "absolute")]
        derived: bool,
    },
    /// Unified annotated listing: symbols, library calls, hardware registers,
    /// globals, references, arithmetic hints, and unresolved-flow warnings.
    Annotate {
        #[command(flatten)]
        target: AnalysisArgs,
        /// The library in A6 *at entry*, for a convention you know (boot code
        /// starts with ExecBase there). Not an assertion about the whole run:
        /// bases the code establishes — from AbsExecBase, from OpenLibrary, and
        /// through the globals it stores them in — are tracked per call site.
        #[arg(long)]
        library: Option<String>,
        /// Base address register for small-data globals (5 = A5, the convention).
        #[arg(long, default_value_t = 5)]
        base_register: u8,
        /// Show every fact with confidence, producer, and evidence on
        /// continuation lines instead of only the best annotation.
        #[arg(long)]
        verbose: bool,
    },
    /// Report fixed-point idioms, saturating clamps, and propagated Q scales.
    FixedPoint {
        #[command(flatten)]
        target: AnalysisArgs,
    },
    /// Emit discovered function entries as a pasteable `[[symbols]]` stub.
    Symbols {
        #[command(flatten)]
        target: AnalysisArgs,
    },
    /// Compose every analysis into one semantic fact report (text or JSON).
    Report {
        #[command(flatten)]
        target: DisasmTargetArgs,
        /// The library in A6 *at entry*, for a convention you know (boot code
        /// starts with ExecBase there). Not an assertion about the whole run:
        /// bases the code establishes — from AbsExecBase, from OpenLibrary, and
        /// through the globals it stores them in — are tracked per call site.
        #[arg(long)]
        library: Option<String>,
        /// Base address register for small-data globals (5 = A5, the convention).
        #[arg(long, default_value_t = 5)]
        base_register: u8,
        /// Output format: `text` or `json`.
        #[arg(long, default_value = "text")]
        format: String,
        /// Narrow the report to one function, by its code-region offset.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        function: Option<u32>,
        /// Narrow the report to `START..END` code-region offsets.
        #[arg(long)]
        range: Option<String>,
        /// Keep only these fact categories. Repeatable.
        #[arg(long)]
        only: Vec<String>,
        /// Keep only facts at least this confident.
        #[arg(long)]
        min_confidence: Option<String>,
        /// Keep only hardware accesses to these custom-chip subsystems. Repeatable.
        #[arg(long)]
        subsystem: Vec<String>,
        /// Order the function index: `address` (default) or `name`.
        #[arg(long)]
        order: Option<String>,
        /// Also write the call graph as DOT to this path.
        #[arg(long)]
        dot: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Ask a cross-reference question of the composed fact graph.
    Query {
        #[command(flatten)]
        target: AnalysisArgs,
        /// The question to ask.
        #[arg(value_enum)]
        question: commands::Question,
        /// What to ask about: an address for `callers`, `callees`, and
        /// `refs-to`; an `A5+0x8` slot or an address for `global`; a register
        /// name or `$096` offset for `register`. Addresses are absolute when
        /// a base is set, hunk offsets otherwise.
        subject: String,
        /// The library in A6 *at entry*, for a convention you know (boot code
        /// starts with ExecBase there). Not an assertion about the whole run:
        /// bases the code establishes — from AbsExecBase, from OpenLibrary, and
        /// through the globals it stores them in — are tracked per call site.
        #[arg(long)]
        library: Option<String>,
        /// Base address register for small-data globals (5 = A5, the convention).
        #[arg(long, default_value_t = 5)]
        base_register: u8,
        /// Output format: `text` or `json`.
        #[arg(long, default_value = "text")]
        format: String,
        /// Maximum results to return.
        #[arg(long, default_value_t = commands::DEFAULT_QUERY_LIMIT)]
        limit: usize,
    },
    /// Export the function/call graph found by flow analysis as JSON or DOT.
    Callgraph {
        #[command(flatten)]
        target: AnalysisArgs,
        /// Output format: `json` or `dot`.
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum FrameAction {
    /// Run a custom-chip sandbox and reconstruct the frame it left.
    ///
    /// Not a byte range: which bytes reach the screen is decided by the
    /// bitplane pointers, BPLCON0, the display window, the data fetch, the
    /// modulos, the palette — and by whatever the Copper changes part-way down
    /// the frame. A program that double-buffers is showing one of two buffers
    /// and a range says nothing about which; the reported bands do.
    ///
    /// A mode this build does not model — HAM, dual playfield, extra
    /// half-brite, hires, interlace — is refused by name rather than rendered
    /// as plain lores planar, because that would be a different picture rather
    /// than a partial one.
    Capture {
        #[command(flatten)]
        target: ExecArgs,
        #[command(flatten)]
        watch: WatchArgs,
        #[command(flatten)]
        frame: FrameArgs,
    },
}

/// What a frame capture states beyond the sandbox layout it shares with `run`.
#[derive(Args)]
pub(crate) struct FrameArgs {
    /// Map an extra RAM region `ADDR:SIZE` for the framebuffer. Repeatable.
    #[arg(long = "map", value_name = "ADDR:SIZE")]
    pub(crate) map: Vec<String>,
    /// Seed memory with `ADDR=HEXBYTES` before the run. Repeatable.
    #[arg(long = "poke", value_name = "ADDR=HEX")]
    pub(crate) poke: Vec<String>,
    /// Stop when the beam reaches this raster line.
    ///
    /// The beam is derived from the instruction counter, so a raster line is an
    /// instruction count: line n is reached after n*227 instructions. That is
    /// what makes this exactly reproducible — the same recipe stops at the same
    /// instruction on every machine.
    #[arg(long = "until-line")]
    pub(crate) until_line: Option<u16>,
    /// Write the indexed PNG, the RGBA PNG and their manifest here.
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Subcommand)]
enum StateAction {
    /// Decode a machine's memory into named, typed values.
    ///
    /// The project's `variable` annotations say what lives where and the type
    /// documents say how to read it; the result is one row per leaf, addressed
    /// by path — `level_table[2].flags`, not `0x30014`. That is what makes two
    /// runs under different load maps comparable, and what lets a clean-room
    /// port state its own state in the same shape.
    ///
    /// Everything that would make a field silently missing refuses the
    /// snapshot: an undefined type, a type whose size disagrees with the
    /// storage, two variables over the same bytes, and storage no region
    /// covers. A field left out would compare cleanly against one that had it.
    Snapshot {
        /// Read `ADDR=FILE` as the machine's memory at that address.
        /// Repeatable, and at least one is needed.
        ///
        /// Typically what `call --save` wrote. Pin it with `ADDR=FILE@SHA256`
        /// to refuse a snapshot of bytes this command line does not name.
        #[arg(long = "memory", value_name = "ADDR=FILE[@SHA256]", required = true)]
        memory: Vec<String>,
        /// Which of the project's images the variables belong to. Needed when
        /// the project describes more than one.
        #[arg(long)]
        image: Option<String>,
        /// Seed a register, e.g. `--reg a5=0x40008`. Repeatable.
        ///
        /// A small-data global's address is a base register plus a
        /// displacement, so a project holding any is refused without the
        /// register it is taken from.
        #[arg(long = "reg", value_name = "NAME=VALUE")]
        reg: Vec<String>,
        /// Where a hunk was mapped, as `HUNK=ADDR`, for a variable targeting
        /// that hunk's offsets. Repeatable.
        ///
        /// The layout is the run's rather than the project's: a snapshot
        /// decoded against a different one names the right variable at the
        /// wrong address.
        #[arg(long = "hunk-base", value_name = "HUNK=ADDR")]
        hunk_base: Vec<String>,
        /// Cap on reported fields. The true total is always reported.
        #[arg(long)]
        max_fields: Option<usize>,
    },
    /// Compare state snapshots field by field.
    ///
    /// Alignment is by field path, so a port that lays the same state out at
    /// different addresses still compares. A document this build does not fully
    /// understand is refused rather than diffed.
    Compare {
        /// The snapshot documents to compare, in the order they are reported.
        /// At least two.
        #[arg(required = true, num_args = 2..)]
        snapshots: Vec<PathBuf>,
        /// Cap on the differences listed. The true total is always reported.
        #[arg(long)]
        max_differences: Option<usize>,
        /// Emit the full comparison as JSON instead of the summary.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum XrefAction {
    /// Report an address in its absolute, hunk-relative, and whole-file frames.
    Addr {
        #[arg(value_parser = amiga_core::parse_u32)]
        value: u32,
        /// Executable to anchor the whole-file frame on a hunk's file offset.
        executable: Option<PathBuf>,
        /// Hunk index whose file offset anchors the whole-file frame.
        #[arg(long, default_value_t = 0)]
        hunk: u32,
        #[command(flatten)]
        base: BaseArgs,
    },
    /// Follow every relocation to the offset its stored pointer targets.
    Relocs { executable: PathBuf },
    /// List the absolute-long and PC-relative references code makes.
    Refs {
        #[command(flatten)]
        target: AnalysisArgs,
    },
    /// Find the code sites and relocations that point at an address.
    To {
        executable: PathBuf,
        #[arg(value_parser = amiga_core::parse_u32)]
        address: u32,
        #[arg(long, default_value_t = 0)]
        hunk: u32,
    },
}

#[derive(Subcommand)]
enum CopperAction {
    /// Report every plausible Copper list found in a binary.
    Scan { file: PathBuf },
    /// Decode a Copper list instruction-by-instruction from an offset.
    Decode {
        file: PathBuf,
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
    },
    /// Trace CPU writes that patch a runtime copy of a Copper list.
    PatchXref {
        #[command(flatten)]
        target: AnalysisArgs,
        /// Whole-file byte offset of the Copper template in the Copper source
        /// (like `copper decode`), not the hunk/absolute frame --entry uses.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        copper: u32,
        /// Read the Copper template from this file instead of the executable
        /// (--copper is then a whole-file offset into that file).
        #[arg(long)]
        copper_file: Option<PathBuf>,
        /// Address register (0-7 = A0-A7) holding the copy base at --entry.
        #[arg(long, default_value_t = 0)]
        pointer_reg: u8,
        /// Absolute address the Copper list runs at. Needed only when the
        /// routine loads that address itself (`MOVEA.L #list,A0`) instead of
        /// receiving it: without it such a load is an unrelated address and
        /// every following store is dropped.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        copper_address: Option<u32>,
        /// Print the effective palette after applying the immediate writes.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum HwAction {
    /// Print the custom-chip register map.
    Registers,
    /// Map the custom-chip register accesses a code hunk makes.
    Xref {
        #[command(flatten)]
        target: AnalysisArgs,
        /// Only show accesses to one subsystem (e.g. audio, blitter, dma).
        #[arg(long)]
        subsystem: Option<String>,
    },
}

#[derive(Subcommand)]
enum BitmapAction {
    /// Compare two decoded images in palette-index space and in colour space.
    ///
    /// A digest over two framebuffers says they differ and nothing else. This
    /// says how many pixels, inside what rectangle, in what connected regions,
    /// and which palette index was substituted for which — and it answers
    /// separately in index space and in colour space, because a port whose
    /// palette came out in a different order differs in every pixel while being
    /// wholly correct.
    ///
    /// Differing dimensions are refused rather than resampled: a resampler's
    /// rounding would be reported as a difference in the picture.
    Compare {
        a: PathBuf,
        b: PathBuf,
        /// Pixel width of both images.
        #[arg(long)]
        width: usize,
        /// Pixel height of both images.
        #[arg(long)]
        height: usize,
        /// Read both sides as planar data with this many bitplanes. Omitted,
        /// each source is already one palette index per byte — which is what a
        /// decoded frame's indices are.
        #[arg(long)]
        planes: Option<u8>,
        /// Shift the second image by `X,Y` before comparing.
        ///
        /// An explicit alignment: a comparison that searched for its own would
        /// report whichever offset made the two agree best rather than the one
        /// you meant.
        #[arg(long = "align", value_name = "X,Y")]
        align: Option<String>,
        /// A reviewed mask, as `FILE@SHA256`: one byte per compared pixel, zero
        /// to exclude. Pinned because a mask decides what the comparison
        /// ignores.
        #[arg(long = "mask", value_name = "FILE@SHA256")]
        mask: Option<String>,
        /// Cap on the listed substitutions and regions. The true totals are
        /// always reported.
        #[arg(long)]
        max_entries: Option<usize>,
        /// Write the heatmap, the overlay and their manifest here.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Decode a planar region to an indexed PNG.
    Render {
        file: PathBuf,
        output: PathBuf,
        /// Byte offset of the bitmap within the file.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        offset: Option<u32>,
        /// Pixel width (falls back to config [bitmap].width).
        #[arg(long, value_parser = amiga_core::parse_u32)]
        width: Option<u32>,
        /// Pixel height (falls back to config [bitmap].height).
        #[arg(long, value_parser = amiga_core::parse_u32)]
        height: Option<u32>,
        /// Bitplane count (falls back to config [bitmap].planes, else 4).
        #[arg(long)]
        planes: Option<u8>,
        /// How the bitplanes are stored: `contiguous`, `interleaved` (per
        /// scanline), or `byte-`/`word-`/`longword-interleaved` (per chunk of
        /// that width).
        #[arg(long, default_value = "contiguous")]
        plane_order: String,
        /// Take plane count and palette from the Copper list at this offset.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        from_copper: Option<u32>,
        /// Read the Copper list from this file instead of the bitmap input.
        #[arg(long, requires = "from_copper")]
        copper_file: Option<PathBuf>,
        #[command(flatten)]
        base: BaseArgs,
        /// Font mode: tile `--count` glyphs of this `WxH` size into a contact
        /// sheet instead of rendering one bitmap (e.g. `--glyph 8x8`).
        #[arg(long, value_name = "WxH")]
        glyph: Option<String>,
        /// Font mode: number of glyphs to tile.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "256")]
        count: u32,
        /// Font mode: glyphs per row in the contact sheet.
        #[arg(long, default_value_t = 16)]
        columns: usize,
        /// Font mode: separator pixels between glyphs.
        #[arg(long, default_value_t = 1)]
        gap: usize,
        #[arg(long)]
        force: bool,
    },
    /// Classify a binary by entropy and guess a region's bitmap geometry.
    Detect {
        file: PathBuf,
        /// Restrict analysis to a region starting here (whole-file offset).
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        /// Region length; enables row-stride autocorrelation for the region.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        length: Option<u32>,
        /// Entropy-map block size in bytes.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "4096")]
        block: u32,
        /// Largest row stride to test in autocorrelation.
        #[arg(long, default_value_t = 512)]
        max_stride: usize,
        /// How many top strides to report.
        #[arg(long, default_value_t = 8)]
        top: usize,
    },
}

#[derive(Subcommand)]
enum BobAction {
    /// Decode a blitter object at an offset to an indexed PNG, masking out
    /// transparent pixels.
    Extract {
        file: PathBuf,
        output: PathBuf,
        /// Byte offset of the bitplane data within the file.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        /// Pixel width (falls back to config [bitmap].width).
        #[arg(long, value_parser = amiga_core::parse_u32)]
        width: Option<u32>,
        /// Pixel height (falls back to config [bitmap].height).
        #[arg(long, value_parser = amiga_core::parse_u32)]
        height: Option<u32>,
        /// Bitplane count (falls back to config [bitmap].planes, else 4).
        #[arg(long)]
        planes: Option<u8>,
        /// How the bitplanes are stored: `contiguous`, `interleaved` (per
        /// scanline), or `byte-`/`word-`/`longword-interleaved` (per chunk of
        /// that width).
        #[arg(long, default_value = "contiguous")]
        plane_order: String,
        /// Mask mode: `none`, `interleaved`, `separate[:FILE_OFFSET]`, or
        /// `color:INDEX`. `separate` without an offset uses the bytes right
        /// after the bitplane data.
        #[arg(long, default_value = "none")]
        mask: String,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum PaletteAction {
    /// Report standalone runs of valid RGB4 color words.
    Scan {
        file: PathBuf,
        /// Minimum run length (in color words) to report.
        #[arg(long, default_value_t = 8)]
        min: usize,
    },
    /// Carve a palette to a swatch PNG (+ manifest) and a pasteable config line.
    Export {
        file: PathBuf,
        output: PathBuf,
        /// Byte offset of the first color word.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        /// Number of color words to export.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        count: u32,
        /// Pixel size of each swatch square.
        #[arg(long, default_value_t = 16)]
        block: usize,
        /// Swatches per row.
        #[arg(long, default_value_t = 16)]
        columns: usize,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum IffAction {
    /// Describe a standalone ILBM image FORM.
    Image { file: PathBuf },
    /// Describe a standalone 8SVX sample FORM.
    Samples { file: PathBuf },
    /// Convert a standalone 8SVX FORM to a WAV file.
    ToWav {
        file: PathBuf,
        /// Path of the WAV to write. Its provenance manifest goes beside it.
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum SampleAction {
    /// Heuristically flag regions that look like raw 8-bit signed PCM.
    Scan {
        file: PathBuf,
        /// Block size in bytes used to score the file.
        #[arg(long, default_value_t = 1024)]
        block: usize,
        /// Minimum total region length in bytes to report.
        #[arg(long, default_value_t = 2048)]
        min_len: usize,
    },
    /// Export a raw PCM region (offset + length + rate) to a WAV file.
    ToWav {
        file: PathBuf,
        output: PathBuf,
        /// Byte offset of the first sample.
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        /// Number of sample bytes to export.
        #[arg(long, value_parser = amiga_core::parse_u32)]
        length: u32,
        /// Playback sample rate in Hz (defaults to a PAL Paula rate).
        #[arg(long, default_value_t = 8287)]
        rate: u16,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ModAction {
    /// Report every tracker module found in a binary.
    Scan { file: PathBuf },
    /// Rip one module to a `.mod` file (+ manifest), with a sample listing.
    Extract {
        file: PathBuf,
        output: PathBuf,
        /// Byte offset of the module's start (from `mod scan`).
        #[arg(long, value_parser = amiga_core::parse_u32, default_value = "0")]
        offset: u32,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum UnpackAction {
    /// Decode a headerless PowerPacker stream using a loader mode table.
    Powerpacker {
        input: PathBuf,
        output: PathBuf,
        /// The four mode-table bit widths, e.g. `9,10,12,13`.
        #[arg(long)]
        modes: String,
        /// Refuse the decode before allocating more than this many bytes.
        #[arg(long)]
        maximum_output_bytes: Option<u64>,
        #[arg(long)]
        force: bool,
    },
    /// Decode a position-XOR + escape-marker run-length stream.
    RleXor {
        input: PathBuf,
        output: PathBuf,
        #[command(flatten)]
        layout: RleXorArgs,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum LhaAction {
    /// List archive members.
    List { archive: PathBuf },
    /// Safely extract supported stored and compressed members (size and CRC verified).
    Extract {
        archive: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum OperationsAction {
    /// Execute one request document and write its response.
    ///
    /// Named under `operations` rather than as a bare `amiga-re run`, which is
    /// what the operations plan originally sketched: `run` is already the
    /// MC68000 sandbox executor, and silently changing what it means would be
    /// worse than the extra word.
    Run {
        /// Request document to execute; `-` reads standard input.
        #[arg(long, value_name = "FILE|-")]
        request: PathBuf,
        /// How to write the exchange.
        #[arg(long, value_enum, default_value_t = ResponseMode::Json)]
        response: ResponseMode,
        /// Do not echo diagnostics to standard error.
        #[arg(long)]
        quiet: bool,
    },
    /// List the catalog (the same as `operations` with no subcommand).
    List {
        #[arg(long, value_enum, default_value_t = ResponseMode::Text)]
        response: ResponseMode,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Create a project from chosen source files.
    ///
    /// Refuses a directory that already holds one: replacing a project safely
    /// needs staging and rollback, so removing it and running this again is the
    /// deliberate act it should be.
    Init {
        /// The project's display name. Its id is derived from this.
        name: String,
        /// The directory to create.
        output: PathBuf,
        /// The source files to register. At least one.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Leave the media where it is instead of copying it into `original/`.
        ///
        /// A file already under the project root gets a project-relative
        /// location; one outside it gets a `.amiga-re/local.json` binding that
        /// is true on this machine only.
        #[arg(long)]
        in_place: bool,
    },
    /// Take the project's registered carriers apart into `extracted/`.
    ///
    /// Every recovered member becomes an object carrying the selector that
    /// reproduces it, so the extracted file is a convenience: delete it and
    /// `project verify` still recovers the bytes from the carrier.
    Extract {
        /// Extract only these source IDs. All of them when omitted.
        #[arg(long = "source", value_name = "ID")]
        sources: Vec<String>,
        path: Option<PathBuf>,
    },
    /// Load the project and report every problem, by stable code.
    Check {
        /// The project root or its directory; discovered upward when omitted.
        path: Option<PathBuf>,
    },
    /// Summarize what the project contains.
    Show { path: Option<PathBuf> },
    /// Verify every source and object against the bytes on disk. Writes nothing.
    Verify { path: Option<PathBuf> },
    /// Print the inventory a directory source would pin, following no symlink.
    Inventory { directory: PathBuf },
    /// Rename a function or symbol through a reviewed edit.
    Rename {
        /// The annotation ID, e.g. `function:init-graphics`.
        id: String,
        /// The new name.
        name: String,
        /// Show what would change and write nothing.
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Accept an annotation's changed object, recording its current digest.
    Rebase {
        id: String,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Register bytes a capture produced as a project source.
    ///
    /// For what a routine left in memory: `call --save` writes the range and
    /// reports the sentence saying what produced it, and this records it. Such
    /// bytes are on no disk and nothing in the format can re-derive them, so
    /// they are registered as `captured` and the note is required.
    RegisterCapture {
        /// The source's own id, which must start `source:`.
        id: String,
        /// What to call it in a listing.
        #[arg(long, value_name = "TEXT")]
        name: String,
        /// Where the bytes are, relative to the project root.
        #[arg(long, value_name = "PATH")]
        file: String,
        /// What produced these bytes. `call --save` reports one composed from
        /// the recipe; prefer it over prose written from memory.
        #[arg(long, value_name = "TEXT")]
        notes: String,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Record what a range of bytes is, through a reviewed edit.
    ///
    /// The digest the annotation is established against is not an argument: it
    /// is a fact about the project, derived by the operation from the object
    /// named here, the same way a rebase's is.
    Annotate {
        /// The new annotation's id. A `region` or `bookmark` takes an
        /// `annotation:` id; a `function` or `symbol` takes its own kind.
        id: String,
        /// What this annotation is: function, symbol, region or bookmark.
        #[arg(long)]
        kind: String,
        /// The object the bytes are in, e.g. `object:disk-1/title.iff`.
        #[arg(long, value_name = "ID")]
        object: String,
        /// Where the range starts in that object.
        #[arg(long, value_parser = amiga_core::parse_u64, default_value = "0")]
        offset: u64,
        /// How many bytes it covers.
        #[arg(long, value_parser = amiga_core::parse_u64)]
        length: u64,
        /// The name, for a function or a symbol.
        #[arg(long)]
        name: Option<String>,
        /// What the bytes are, for a region — `bitmap`, `palette`, `code`, …
        #[arg(long)]
        classification: Option<String>,
        /// Show what would change and write nothing.
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Say why, about a range of bytes or about an annotation.
    Comment {
        /// The new comment's id, which is an `annotation:` id.
        id: String,
        /// The comment itself.
        text: String,
        /// The annotation this is about, for a comment on a name.
        #[arg(long, value_name = "ID", conflicts_with = "object")]
        about: Option<String>,
        /// The object the bytes are in, for a comment on a selection.
        #[arg(long, value_name = "ID", requires = "length")]
        object: Option<String>,
        #[arg(long, value_parser = amiga_core::parse_u64, default_value = "0")]
        offset: u64,
        #[arg(long, value_parser = amiga_core::parse_u64)]
        length: Option<u64>,
        /// Where the comment sits: before, inline or after.
        #[arg(long, default_value = "before")]
        placement: String,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Delete an annotation.
    ///
    /// Refused while a comment is about it: cascading would delete a person's
    /// reasoning along with the name it was about.
    Remove {
        id: String,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Record how a range of bytes decodes, so an export can be reproduced.
    Resource {
        #[command(subcommand)]
        action: ResourceAction,
    },
    /// Import a legacy amiga-re.toml into project documents.
    Migrate {
        /// The project's display name.
        name: String,
        /// The image a bare `[base]` maps. Omitted, the base is reported as
        /// ambiguous rather than guessed.
        #[arg(long)]
        image: Option<String>,
        /// The [[media]] name whose whole file that image is. An image needs an
        /// object, and a legacy config cannot name one.
        #[arg(long, requires = "image")]
        image_media: Option<String>,
        /// Write the documents into a new directory, replacing it only with
        /// --force.
        #[arg(long, conflicts_with = "in_place")]
        output: Option<PathBuf>,
        /// Write the generated documents into the config's own directory,
        /// touching nothing else there.
        #[arg(long)]
        in_place: bool,
        #[arg(long)]
        force: bool,
    },
    /// Rewrite every document in canonical form.
    Format {
        /// Report what is unformatted instead of rewriting it.
        #[arg(long)]
        check: bool,
        path: Option<PathBuf>,
    },
    /// List what the project says about one image or one object.
    Annotations {
        /// The image ID, e.g. `image:main-executable`. Resolved in hunk space.
        image: Option<String>,
        /// The object ID, e.g. `object:title-screen`. Listed in file space.
        ///
        /// A project created by `project init` has objects and no image, so
        /// this is the scope that answers for one.
        #[arg(long, conflicts_with = "image")]
        object: Option<String>,
        path: Option<PathBuf>,
    },
    /// Print a bundled document schema, or emit the whole set.
    Schema {
        /// Which document kind to describe (default `project`).
        kind: Option<String>,
        /// Write every schema into this directory instead of printing.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

/// The resource half of a project's knowledge: what bytes decode to, and how.
///
/// `define` and `update` take the same arguments because they write the same
/// record; only whether the ID must already exist differs.
#[derive(Subcommand)]
enum ResourceAction {
    /// Record a new resource.
    Define {
        #[command(flatten)]
        resource: ResourceArgs,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Replace an existing resource under the same ID.
    Update {
        #[command(flatten)]
        resource: ResourceArgs,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Produce this resource's file from the project alone.
    ///
    /// Takes no parameters and no destination: everything an export needs is
    /// already recorded, which is what makes the file reproducible.
    Export { id: String, path: Option<PathBuf> },
    /// Delete a resource, refusing while an artifact was produced from it.
    Remove {
        id: String,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
    /// Forget a produced file, leaving the file itself alone.
    Forget {
        id: String,
        #[arg(long)]
        dry_run: bool,
        path: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
pub(crate) struct ResourceArgs {
    /// The resource's id, e.g. `resource:title-logo`.
    pub(crate) id: String,
    /// What it is: image, palette, audio, table, text, code, copper, data or
    /// opaque.
    #[arg(long)]
    pub(crate) kind: String,
    /// A display name. Never part of the artifact key.
    #[arg(long)]
    pub(crate) name: String,
    /// The object the bytes are in.
    #[arg(long, value_name = "ID")]
    pub(crate) object: String,
    #[arg(long, value_parser = amiga_core::parse_u64, default_value = "0")]
    pub(crate) offset: u64,
    #[arg(long, value_parser = amiga_core::parse_u64)]
    pub(crate) length: u64,
    /// One decode parameter, `key=value`, repeated. The keys are the ones the
    /// resources schema defines for this kind: `width`, `planes`, `count`, …
    ///
    /// A value that parses as JSON is used as that JSON — `8` is a number,
    /// `true` a boolean — and anything else is a string, so `format=planar`
    /// needs no quoting.
    #[arg(long = "parameter", value_name = "KEY=VALUE")]
    pub(crate) parameters: Vec<String>,
    /// What an export of this resource produces. Defaulted per kind when
    /// omitted: PNG for an image or palette, WAV for audio, plain text for a
    /// table, text, code or copper listing, raw bytes otherwise.
    #[arg(long = "export", value_name = "MEDIA_TYPE")]
    pub(crate) export_media_type: Option<String>,
    #[arg(long)]
    pub(crate) notes: Option<String>,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the resolved configuration and its source path.
    Show,
    /// Verify pinned media SHA-256s against the files on disk.
    Check,
}

/// The `--config` override, stored so `load` can resolve `@name` media
/// references against the same config the commands use.
static CONFIG_OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The `--project` override, stored the same way and for the same reason: the
/// commands that render names are several layers below the parsed command line,
/// and threading one path through every one of them would say nothing the name
/// of this static does not.
static PROJECT_OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The project root the user named, if any.
pub(crate) fn project_override() -> Option<&'static Path> {
    PROJECT_OVERRIDE.get().and_then(Option::as_deref)
}

/// The directory a project's documents and machine-local bindings sit in.
///
/// Project discovery returns the canonical root document, while `--project`
/// commonly names its directory. Loading accepts both, but resolving anything
/// *inside* the project must not append a relative path to the JSON file.
///
/// A missing path that is not explicitly the canonical root file is left as a
/// directory. This preserves the useful error for a mistyped `--project DIR`:
/// treating every non-directory as a document would silently move the lookup to
/// its parent and could load an unrelated project there.
pub(crate) fn project_directory(path: &Path) -> PathBuf {
    let names_root_document = path
        .file_name()
        .is_some_and(|name| name == amiga_project::load::ROOT_FILE_NAME);
    if path.is_file() || names_root_document {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        path.to_path_buf()
    }
}

/// Parse the process command line and run the selected command.
pub fn run() -> Result<()> {
    let Cli {
        config,
        project,
        command,
    } = Cli::parse();
    let _ = CONFIG_OVERRIDE.set(config.clone());
    let _ = PROJECT_OVERRIDE.set(project);
    match command {
        Command::Adf { action } => match action {
            AdfAction::List { image, max_entries } => adf_list(&image, max_entries),
            AdfAction::Extract {
                image,
                output,
                force,
            } => adf_extract(&image, &output, force),
        },
        Command::Hunk { action } => match action {
            HunkAction::List { executable } => hunk_list(&executable),
            HunkAction::Normalize {
                executable,
                output,
                force,
            } => hunk_normalize(&executable, &output, force),
        },
        Command::Boot { action } => match action {
            BootAction::Info { image } => boot_info(&image),
            BootAction::Disasm { image } => boot_disasm(&image),
            BootAction::Trace {
                image,
                max_steps,
                watch,
                watch_stop,
                output,
                force,
            } => boot_trace(
                config.as_deref(),
                &image,
                max_steps,
                &watch,
                watch_stop,
                output.as_deref(),
                force,
            ),
        },
        Command::Disasm { action } => match action {
            DisasmAction::Linear {
                executable,
                hunk,
                start,
                end,
            } => disasm_linear(&executable, hunk, start, end),
            DisasmAction::Flow { target, bounds } => {
                disasm_flow(config.as_deref(), &target, &bounds)
            }
            DisasmAction::Globals {
                target,
                base_register,
                absolute,
                derived,
            } => disasm_globals(config.as_deref(), &target, base_register, absolute, derived),
            DisasmAction::Annotate {
                target,
                library,
                base_register,
                verbose,
            } => disasm_annotate(
                config.as_deref(),
                &target,
                library.as_deref(),
                base_register,
                verbose,
            ),
            DisasmAction::FixedPoint { target } => disasm_fixed_point(config.as_deref(), &target),
            DisasmAction::Symbols { target } => disasm_symbols(config.as_deref(), &target),
            DisasmAction::Report {
                target,
                library,
                base_register,
                format,
                function,
                range,
                only,
                min_confidence,
                subsystem,
                order,
                dot,
                force,
            } => disasm_report(
                config.as_deref(),
                &target,
                library.as_deref(),
                base_register,
                &format,
                &commands::ReportView {
                    function,
                    range,
                    only,
                    minimum_confidence: min_confidence,
                    subsystems: subsystem,
                    order,
                },
                dot.as_deref(),
                force,
            ),
            DisasmAction::Query {
                target,
                question,
                subject,
                library,
                base_register,
                format,
                limit,
            } => disasm_query(
                config.as_deref(),
                &target,
                &QueryRequest {
                    question,
                    subject: &subject,
                    library: library.as_deref(),
                    base_register,
                    format: &format,
                    limit,
                },
            ),
            DisasmAction::Callgraph { target, format } => {
                disasm_callgraph(config.as_deref(), &target, &format)
            }
        },
        Command::Run { target, watch } => {
            execute_routine(config.as_deref(), &target, &watch, false, false)
        }
        Command::Trace {
            target,
            watch,
            watch_only,
        } => execute_routine(config.as_deref(), &target, &watch, true, watch_only),
        Command::Call {
            target,
            watch,
            recipe,
        } => call_routine(config.as_deref(), &target, &watch, &recipe),
        Command::Frame { action } => match action {
            FrameAction::Capture {
                target,
                watch,
                frame,
            } => frame_capture(config.as_deref(), &target, &watch, &frame),
        },
        Command::State { action } => match action {
            StateAction::Snapshot {
                memory,
                image,
                reg,
                hunk_base,
                max_fields,
            } => state_snapshot(&memory, image.as_deref(), &reg, &hunk_base, max_fields),
            StateAction::Compare {
                snapshots,
                max_differences,
                json,
            } => state_compare(&snapshots, max_differences, json),
        },
        Command::Compare {
            records,
            max_differences,
            json,
        } => compare_records(&records, max_differences, json),
        Command::Xref { action } => match action {
            XrefAction::Addr {
                value,
                executable,
                hunk,
                base,
            } => xref_addr(config.as_deref(), value, executable.as_deref(), hunk, &base),
            XrefAction::Relocs { executable } => xref_relocs(config.as_deref(), &executable),
            XrefAction::Refs { target } => xref_refs(config.as_deref(), &target),
            XrefAction::To {
                executable,
                address,
                hunk,
            } => xref_to(config.as_deref(), &executable, address, hunk),
        },
        Command::Copper { action } => match action {
            CopperAction::Scan { file } => copper_scan(&file),
            CopperAction::Decode { file, offset } => copper_decode(&file, offset),
            CopperAction::PatchXref {
                target,
                copper,
                copper_file,
                pointer_reg,
                copper_address,
                apply,
            } => copper_patch_xref(
                config.as_deref(),
                &target,
                copper,
                copper_file.as_deref(),
                pointer_reg,
                copper_address,
                apply,
            ),
        },
        Command::Hw { action } => match action {
            HwAction::Registers => hw_registers(),
            HwAction::Xref { target, subsystem } => {
                hw_xref(config.as_deref(), &target, subsystem.as_deref())
            }
        },
        Command::Bitmap { action } => match action {
            BitmapAction::Compare {
                a,
                b,
                width,
                height,
                planes,
                align,
                mask,
                max_entries,
                output,
                force,
            } => compare_images(
                &a,
                &b,
                &CompareRequest {
                    width,
                    height,
                    planes,
                    align: align.as_deref(),
                    mask: mask.as_deref(),
                    maximum_entries: max_entries,
                    output: output.as_deref(),
                    force,
                },
            ),
            BitmapAction::Render {
                file,
                output,
                offset,
                width,
                height,
                planes,
                plane_order,
                from_copper,
                copper_file,
                base,
                glyph,
                count,
                columns,
                gap,
                force,
            } => match glyph {
                Some(spec) => bitmap_glyphs(
                    config.as_deref(),
                    &file,
                    &output,
                    offset.unwrap_or(0),
                    &spec,
                    planes,
                    &plane_order,
                    count,
                    columns,
                    gap,
                    force,
                ),
                None => bitmap_render(
                    config.as_deref(),
                    &file,
                    &output,
                    offset,
                    width,
                    height,
                    planes,
                    &plane_order,
                    from_copper,
                    copper_file.as_deref(),
                    &base,
                    force,
                ),
            },
            BitmapAction::Detect {
                file,
                offset,
                length,
                block,
                max_stride,
                top,
            } => bitmap_detect(&file, offset, length, block, max_stride, top),
        },
        Command::Bob { action } => match action {
            BobAction::Extract {
                file,
                output,
                offset,
                width,
                height,
                planes,
                plane_order,
                mask,
                force,
            } => bob_extract(
                config.as_deref(),
                &file,
                &output,
                offset,
                width,
                height,
                planes,
                &plane_order,
                &mask,
                force,
            ),
        },
        Command::Palette { action } => match action {
            PaletteAction::Scan { file, min } => palette_scan(&file, min),
            PaletteAction::Export {
                file,
                output,
                offset,
                count,
                block,
                columns,
                force,
            } => palette_export(&file, &output, offset, count, block, columns, force),
        },
        Command::Iff { action } => match action {
            IffAction::Image { file } => iff_image(&file),
            IffAction::Samples { file } => iff_samples(&file),
            IffAction::ToWav {
                file,
                output,
                force,
            } => iff_to_wav(&file, &output, force),
        },
        Command::Sample { action } => match action {
            SampleAction::Scan {
                file,
                block,
                min_len,
            } => sample_scan(&file, block, min_len),
            SampleAction::ToWav {
                file,
                output,
                offset,
                length,
                rate,
                force,
            } => sample_to_wav(&file, &output, offset, length, rate, force),
        },
        Command::Mod { action } => match action {
            ModAction::Scan { file } => mod_scan(&file),
            ModAction::Extract {
                file,
                output,
                offset,
                force,
            } => mod_extract(&file, &output, offset, force),
        },
        Command::Unpack { action } => match action {
            UnpackAction::Powerpacker {
                input,
                output,
                modes,
                maximum_output_bytes,
                force,
            } => unpack_powerpacker(&input, &output, &modes, maximum_output_bytes, force),
            UnpackAction::RleXor {
                input,
                output,
                layout,
                force,
            } => unpack_rle_xor(&input, &output, &layout, force),
        },
        Command::Lha { action } => match action {
            LhaAction::List { archive } => lha_list(&archive),
            LhaAction::Extract {
                archive,
                output,
                force,
            } => lha_extract(&archive, &output, force),
        },
        Command::Strings {
            file,
            min,
            hunk,
            contains,
        } => strings_dump(&file, min, hunk, contains.as_deref()),
        Command::Operations { action, response } => match action {
            None => operations_list(response),
            Some(OperationsAction::List { response }) => operations_list(response),
            Some(OperationsAction::Run {
                request,
                response,
                quiet,
            }) => {
                // The exit code is part of the contract, so it is chosen by the
                // operation's status rather than by whether this function
                // returned `Ok`. Success still exits 0 through the normal path.
                let code = operations_run(&request, response, quiet)?;
                if code != 0 {
                    std::process::exit(i32::from(code));
                }
                Ok(())
            }
        },
        Command::Schema {
            operation,
            kind,
            output,
            force,
        } => operations_schema(operation.as_deref(), kind, output.as_deref(), force),
        Command::Project { action } => match action {
            ProjectAction::Check { path } => project_check(path.as_deref()),
            ProjectAction::Show { path } => project_show(path.as_deref()),
            ProjectAction::Verify { path } => project_verify(path.as_deref()),
            ProjectAction::Inventory { directory } => project_inventory(&directory),
            ProjectAction::Annotations {
                image,
                object,
                path,
            } => project_annotations(path.as_deref(), image.as_deref(), object.as_deref()),
            ProjectAction::Rename {
                id,
                name,
                dry_run,
                path,
            } => project_rename(path.as_deref(), &id, &name, dry_run),
            ProjectAction::Rebase { id, dry_run, path } => {
                project_rebase(path.as_deref(), &id, dry_run)
            }
            ProjectAction::RegisterCapture {
                id,
                name,
                file,
                notes,
                dry_run,
                path,
            } => project_register_capture(path.as_deref(), &id, &name, &file, &notes, dry_run),
            ProjectAction::Annotate {
                id,
                kind,
                object,
                offset,
                length,
                name,
                classification,
                dry_run,
                path,
            } => project_annotate(
                path.as_deref(),
                &id,
                &kind,
                &object,
                offset,
                length,
                name.as_deref(),
                classification.as_deref(),
                dry_run,
            ),
            ProjectAction::Comment {
                id,
                text,
                about,
                object,
                offset,
                length,
                placement,
                dry_run,
                path,
            } => project_comment(
                path.as_deref(),
                &id,
                &text,
                about.as_deref(),
                object.as_deref(),
                offset,
                length,
                &placement,
                dry_run,
            ),
            ProjectAction::Remove { id, dry_run, path } => {
                project_remove(path.as_deref(), &id, dry_run)
            }
            ProjectAction::Resource { action } => match action {
                ResourceAction::Define {
                    resource,
                    dry_run,
                    path,
                } => project_resource_write(path.as_deref(), resource, true, dry_run),
                ResourceAction::Update {
                    resource,
                    dry_run,
                    path,
                } => project_resource_write(path.as_deref(), resource, false, dry_run),
                ResourceAction::Export { id, path } => {
                    project_resource_export(path.as_deref(), &id)
                }
                ResourceAction::Remove { id, dry_run, path } => {
                    project_resource_remove(path.as_deref(), &id, dry_run)
                }
                ResourceAction::Forget { id, dry_run, path } => {
                    project_artifact_forget(path.as_deref(), &id, dry_run)
                }
            },
            ProjectAction::Extract { sources, path } => project_extract(path.as_deref(), sources),
            ProjectAction::Format { check, path } => project_format(path.as_deref(), check),
            ProjectAction::Init {
                name,
                output,
                files,
                in_place,
            } => project_init(&name, &output, &files, in_place),
            ProjectAction::Migrate {
                name,
                image,
                image_media,
                output,
                in_place,
                force,
            } => project_migrate(
                config.as_deref(),
                &name,
                image.as_deref(),
                image_media.as_deref(),
                output.as_deref(),
                in_place,
                force,
            ),
            ProjectAction::Schema {
                kind,
                output,
                force,
            } => project_schema(kind.as_deref(), output.as_deref(), force),
        },
        Command::Config { action } => match action {
            ConfigAction::Show => config_show(config.as_deref()),
            ConfigAction::Check => config_check(config.as_deref()),
        },
        Command::Manifest {
            path,
            output,
            force,
        } => manifest(&path, output.as_deref(), force),
        Command::Carve {
            file,
            output,
            offset,
            length,
            force,
        } => carve(&file, &output, offset, length, force),
        Command::Table { action } => match action {
            TableAction::Dump {
                file,
                layout,
                offset,
                count,
                base,
            } => table_dump(config.as_deref(), &file, &layout, offset, count, &base),
            TableAction::Summary {
                files,
                layout,
                offset,
                count,
                max_values,
                max_differences,
                base,
            } => table_summary(
                config.as_deref(),
                &files,
                &layout,
                offset,
                count,
                max_values,
                max_differences,
                &base,
            ),
        },
        Command::Dump {
            file,
            offset,
            length,
            hunk,
            address,
            base,
        } => dump(
            config.as_deref(),
            &file,
            offset,
            length,
            hunk,
            address,
            &base,
        ),
        Command::Diff {
            a,
            b,
            output,
            format,
            force,
        } => diff(&a, &b, output.as_deref(), format, force),
        Command::Survey {
            file,
            min_string,
            max_input_bytes,
            max_regions,
        } => survey(&file, min_string, max_input_bytes, max_regions),
        Command::Scan { action } => match action {
            ScanAction::Pointers {
                executable,
                hunk,
                min,
                word_scale,
                seed_flow,
                base,
            } => scan_pointers(
                config.as_deref(),
                &executable,
                hunk,
                min,
                word_scale,
                seed_flow,
                &base,
            ),
        },
    }
}

fn load(path: &Path) -> Result<Vec<u8>> {
    Ok(load_source(path)?.1)
}

/// Like [`load`], but also returns the resolved source path, so provenance
/// records the real file behind a `@name` reference rather than the alias.
fn load_source(path: &Path) -> Result<(PathBuf, Vec<u8>)> {
    let resolved = resolve_media_path(path)?;
    let bytes =
        fs::read(&resolved).with_context(|| format!("failed to read {}", resolved.display()))?;
    Ok((resolved, bytes))
}

/// Resolve a `@name` media reference against the discovered config; any other
/// path is returned unchanged. This lets every command that reads a source file
/// accept `@name` in place of a literal path.
fn resolve_media_path(path: &Path) -> Result<PathBuf> {
    let Some(name) = path.to_str().and_then(amiga_core::media_reference) else {
        return Ok(path.to_path_buf());
    };
    let override_path = CONFIG_OVERRIDE.get().and_then(Option::as_deref);
    let (config_path, config) = optional_config(override_path)?
        .with_context(|| format!("media reference '@{name}' needs an amiga-re.toml, none found"))?;
    let directory = config_path.parent().unwrap_or_else(|| Path::new("."));
    config
        .media_path(directory, name)
        .with_context(|| format!("no [[media]] named {name:?} in {}", config_path.display()))
}
