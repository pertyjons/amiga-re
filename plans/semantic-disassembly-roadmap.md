# Plan: semantic, navigable Amiga disassembly

> A staged roadmap for turning the existing control-flow listing into an
> evidence-backed explanation of an Amiga program. The stages are deliberately
> independently shippable: the project should stop after any stage whose added
> value no longer justifies its complexity.

Status of this document: **Stages 0–3 are implemented** — the recommended cut
line the plan itself names. Stage 4 groundwork (fd tables, open-library
identity, typed call arguments) and the library-base follow-up have landed.
Stage 5A is complete at its bounded, measured cut, and the bounded Stage 5B
function-signature and stack-frame analysis has landed. Everything not
explicitly marked as landed remains a proposal and does not commit the project
to further work.

**Stage 3 did not become an operation, and that was the right call.**
`analysis.disasm.report` was a name in the operations plan's version-1 catalog sketch, but that plan's signed-off
Milestone 0 review was more specific: it placed the report's *rendering and selection* in the frontend, on the grounds
that the facts behind it already live in `amiga-disasm::report`. Stage 3 followed the review, not the sketch — the
summaries and the narrowing are library code (`amiga_disasm::summary`, `amiga_disasm::select`), and the text, JSON, and
DOT rendering is the command line's. What an operation would have added is a schema for a document that composes
CLI-owned knowledge (config symbols, fd tables, HUNK relocations); when a second frontend needs the report, moving that
composition into `amiga-operations` is the first step, not writing a schema for it.

The completed operation plans are no longer in the working tree; Git history
retains their rationale and inventories.

A browsable rendering of the report — self-contained HTML or any other interactive presentation — is deliberately **out
of scope** for this roadmap and is deferred until a concrete consumer needs it. The fact model, JSON interchange format,
and stable anchors are designed so such a renderer can be added later without changing the analysis; nothing in the
stages below assumes one exists.

## 1. Goal

Make MC68000 listings understandable without requiring the reader to remember AmigaOS LVO offsets, custom-chip
addresses, address-space conversions, flag layouts, or every definition and use of a register.

The end state is not necessarily a C decompiler. It is a reproducible analysis report in which raw instructions remain
visible and every higher-level claim:

- links to the instruction (s) and data that support it;
- says whether it is certain, inferred, probable, observed, or user-supplied;
- records which analysis pass, ABI definition, trace, or config entry produced it;
- remains game-agnostic in the toolkit, with title-specific knowledge supplied by the downstream project's config.

A representative listing should progress from:

```asm
L000012A0:  JSR      (-552,A6)          ; 4eaefdd8
L000012A4:  MOVE.W   #$8020,($96,A5)    ; 3b7c80200096
```

to:

```asm
L000012A0:  JSR      (-552,A6)          ; call exec.library/OpenLibrary
                                             A1 = "graphics.library"
                                             returns D0: Library *
L000012A4:  MOVE.W   #$8020,($96,A5)    ; write DMACON: set DMAEN | SPREN
```

The raw operand and encoded bytes stay present so an annotation can always be audited.

## 2. Constraints and design principles

1. **Keep the toolkit neutral.** AmigaOS ABI and Amiga hardware knowledge belong in the toolkit. Game function names,
   object layouts, enum values, and resource meanings belong in downstream config.
2. **Facts before presentation.** Analysis passes emit typed facts; text, JSON, and any future renderer present the same
   facts. Do not scrape text listings to build reports.
3. **No silent guesses.** Unknown or conflicting state stays unknown. Probable interpretations must be visibly weaker
   than exact address or relocation facts.
4. **Preserve address spaces.** Every location must distinguish file offset, hunk-relative offset, relocated/runtime
   address, and symbolic name.
5. **Static and dynamic evidence stay distinct.** A trace proves that something happened for one execution; it does not
   prove all possible behavior.
6. **Deterministic output.** Facts, generated IDs, ordering, JSON, and text must be stable for the same inputs and
   configuration.
7. **Bounded analysis.** Value propagation, type inference, and pattern matching need explicit limits so malformed or
   hostile inputs cannot cause unbounded work or allocation.
8. **Warnings are data.** Decode gaps, conflicting inferences, unsupported instructions, tolerated corruption, and
   incomplete control flow appear in the report instead of being silently omitted.
9. **No source-media mutation.** All analysis remains read-only. Any generated report or extracted preview follows the
   existing safe-path, force, checksum, and provenance rules.

## 3. Existing foundation

This roadmap should compose existing capabilities rather than replace them:

| Existing capability                                                   | Current location                        | Reuse                                   |
|-----------------------------------------------------------------------|-----------------------------------------|-----------------------------------------|
| Recursive control-flow analysis and listing                           | `amiga-disasm::control_flow`, `listing` | Instruction/function backbone           |
| AmigaOS LVO recognition and library-base inference                    | `amiga-disasm::lvo`                     | Named library calls                     |
| Custom-chip access detection                                          | `amiga-disasm::access`                  | Site, register offset, access direction |
| Custom-chip names and subsystem classification                        | `amiga-hw::registers`                   | Human-readable hardware facts           |
| Direct and PC-relative references                                     | `amiga-disasm::xref`                    | Data/code links                         |
| A5-relative and absolute globals                                      | `amiga-disasm::globals`                 | Read/write/modify/address facts         |
| Derived address-register targets                                      | `amiga-disasm::derived`                 | Conservative indirect references        |
| Function/call graph                                                   | `amiga-disasm::callgraph`               | Function navigation and summaries       |
| Fixed-point and clamp hints                                           | `amiga-disasm::fixed_point`             | Arithmetic semantics                    |
| Runtime trace, memory events, and watchpoints                         | `amiga-disasm::execute`                 | Observed evidence                       |
| Strings, pointers, HUNK relocations, Copper, graphics and audio tools | existing crates and CLI                 | Referenced-data classification          |
| Per-project base, media, and symbols                                  | `amiga-core::config`                    | Downstream knowledge                    |

The current gap is mostly integration: these analyses are exposed through separate commands and are not represented as
one navigable semantic report.

## 4. Common architecture

Before adding new inference, establish a small internal report model.

### 4.1 Stable locations and entities

Use explicit domain types rather than raw `u32` values:

```text
ImageId
HunkId
InstructionId
FunctionId
DataRegionId
RuntimeAddress
HunkOffset
FileOffset
```

An entity may have several resolved locations, but conversions must be checked and retain their provenance.

### 4.2 Typed facts

The exact Rust shape is an implementation decision, but the model must express at least:

```text
Fact {
    subject
    kind
    value/target
    evidence[]
    confidence
    producer
}

Evidence {
    instruction site, relocation, config entry, ABI definition,
    pattern match, or trace/run identifier
}

Confidence {
    Certain, Inferred, Probable, Observed, User
}
```

Initial fact kinds:

- symbol definition and reference;
- direct call, branch, and unresolved control flow;
- library call;
- memory read/write/modify/address-of;
- hardware-register access;
- constant value and decoded flags;
- function ownership;
- warning or ambiguity.

Later stages extend the vocabulary instead of changing the rendering contract.

### 4.3 Producers and composer

- `amiga-disasm` emits instruction, flow, reference, dataflow, and arithmetic facts without needing game knowledge.
- `amiga-hw` resolves register metadata, flag fields, and hardware operation descriptions.
- `amiga-hunk` supplies relocation and segment evidence.
- `amiga-core` owns generic config/provenance/address helpers.
- The CLI composes facts from multiple crates and selects output formats.

Do not introduce a new crate until the shared model has at least two library consumers. A private module in
`amiga-disasm` or the CLI is sufficient for the first milestone; promote it only when the boundary is demonstrated.

### 4.4 Renderers

Plan for two renderers over the same report:

1. **Text** — reviewable, grep-friendly, and suitable for terminals.
2. **JSON** — complete typed facts for downstream automation.

JSON is the semantic interchange format. Any renderer added later must present only facts that JSON already exposes, so
no presentation layer becomes a second source of truth.

## 5. Staged implementation

## Stage 0 — fixtures, contracts, and measurements

> **Status: implemented.** Fact model and terminology in
> `amiga-disasm::report` (`SCHEMA_VERSION` 1); composed report with baseline
> statistics in `disasm report` (text + JSON); synthetic fixture, golden
> snapshots, determinism and ambiguity tests in
> `tools/amiga-re-cli/tests/semantic_report.rs`.

**Purpose:** make later changes measurable and prevent a visually impressive renderer from hiding incorrect analysis.

### Deliverables

- Add small synthetic fixtures covering:
    - a direct call and conditional branch;
    - a PC-relative string reference;
    - `ExecBase` plus `OpenLibrary` result flow;
    - absolute and base-relative custom-chip accesses;
    - an A5-relative global;
    - a HUNK relocation;
    - an unresolved indirect jump;
    - conflicting inference at a control-flow join.
- Define golden text and JSON snapshots for the fixture, using synthetic, redistributable bytes only.
- Record baseline analysis statistics:
    - decoded/reached bytes;
    - functions and call edges;
    - resolved/unresolved references;
    - named/unnamed LVO calls;
    - resolved/unknown hardware accesses.
- Decide versioning for generated JSON. Backward compatibility is not required during active development, but reports
  must identify their schema version.
- Document confidence and evidence terminology.

### Acceptance criteria

- Every fact in the golden report names its producer and evidence site.
- Conflicting facts produce an explicit ambiguity, not an arbitrary winner.
- Re-running the same input produces byte-identical JSON and text.

### Stop decision

Proceed only if the report model can represent all existing analyses without turning their output into untyped comment
strings.

---

## Stage 1 — unified inline annotations from existing analyses

> **Status: implemented.** `disasm annotate` renders the unified listing from
> facts pre-indexed by site, with compact/verbose modes and confidence
> markers; `boot disasm` shares the renderer. Parity with the standalone
> commands is asserted on the shared fixture.
>
> **Identified improvements:**
>
> - Compact mode deliberately hides fd-supplied call signatures to keep lines
>   short; an opt-in flag (e.g. `--signatures`) could render
>   `library/Function(parm=d0)` inline for readers who want them without
>   switching to `--verbose`.

**Purpose:** deliver the first large readability improvement without developing new program analysis.

### Deliverables

- Extend or replace `disasm annotate` so one listing combines:
    - config symbols;
    - LVO library names;
    - custom-chip register names;
    - read/write/modify/address direction;
    - direct and PC-relative target symbols;
    - A5-relative and absolute global symbols;
    - fixed-point and clamp hints;
    - unresolved-flow warnings.
- Pre-index facts by instruction site; do not rescan the full fact set for each rendered instruction.
- Keep raw instructions, offsets, and encoded bytes visible.
- Add compact and verbose modes:
    - compact: highest-value annotation on the instruction line;
    - verbose: all facts and evidence on continuation lines.
- Add explicit confidence markers only where a fact is not certain; avoid cluttering exact decoded facts.

### Example

```asm
load_graphics:
L00000120: LEA      ($38,PC),A1       ; → "graphics.library"
L00000124: JSR      (-552,A6)         ; exec.library/OpenLibrary
L00000128: MOVE.L   D0,(224,A5)       ; write graphics_base
L0000012C: MOVE.W   #$8020,($96,A4)   ; write DMACON: $8020
```

### Acceptance criteria

- Results agree with the current standalone `disasm fixed-point`, `hw xref`,
  `xref refs`, and `disasm globals` outputs on the shared fixtures.
- Unknown library bases and reused hardware-base registers are not named as certain.
- Direct absolute hardware accesses and base-relative accesses are both shown.

### Recommended release

This is the first independently useful release.

---

## Stage 2 — complete cross-references and referenced-data summaries

> **Status: implemented.** Address spaces and stable anchors in
> `amiga-core::address` (`HunkId`/`HunkOffset`/`FileOffset`/`RuntimeAddress`,
> `AddressMap`, `Location`, `Anchor`); referenced-data classification and
> escaped previews in `amiga-disasm::data`; reverse cross-references
> (`FactKind::ReferencedBy`), relocation-backed reference resolution, and an
> anchored entity table in `disasm report` (text + JSON); cross-reference
> questions in `disasm query`. Control flow, references, and data
> classification all read an absolute operand through the relocation that
> patches it (`FlowOptions::relocations`, `CollectOptions::relocations`), so a
> cross-hunk transfer is an `external_flow` fact rather than an invented
> in-hunk edge; function ownership is a payload of `FactKind::Call`, so every
> `disasm query` answer is reproducible from the JSON alone. Acceptance tests
> for all four criteria, a two-hunk relocation fixture, and a hostile-data
> fixture live in `tools/amiga-re-cli/tests/semantic_report.rs`.
>
> Ownership propagates through shared code: a traversal arriving at an
> already-decoded instruction adds its owner and keeps walking instead of
> stopping there, so `DecodedInstruction::owners`, `FactKind::Call`'s `owners`,
> the `callees` query, and the per-owner call and unresolved-exit sets name
> every entry that reaches a block rather than whichever traversal decoded it
> first. `visited` bounds the re-walk to one pass per (instruction, owner), and
> `Coverage::calls` counts distinct (site, callee) pairs so a shared call is
> not counted once per owner.
>
> **Identified improvements:**
>
> - Previews escape control characters, non-ASCII bytes, backslashes, and
>   quotes, which is what the text and JSON renderers need. Markup escaping
>   remains each renderer's own responsibility: a renderer whose output format
>   has its own metacharacters must escape previews itself, even though anchors
>   are already safe by construction.

**Purpose:** eliminate manual address arithmetic and let readers follow code to data and back.

### Deliverables

- Give every instruction, function, symbol, and classified data region a stable report anchor.
- Show forward links at reference sites and reverse links at targets.
- Resolve and display together:
    - file offset;
    - hunk and hunk-relative offset;
    - relocated/runtime address;
    - symbol.
- Attach HUNK relocation evidence to the exact operand/site.
- Inline safe previews for referenced:
    - printable strings;
    - arrays of in-range pointers;
    - short constant tables;
    - known symbols.
- Classify code targets versus data targets and report disagreements.
- Add queries to text/JSON output:
    - callers/callees;
    - references to an address;
    - reads/writes of a global;
    - accesses to a hardware register.

### Acceptance criteria

- Every displayed address says which address space it belongs to.
- A forward reference and its reverse reference resolve to the same entity.
- Strings are escaped and length-bounded; malformed data cannot inject markup.
- Relocation-backed targets are distinguished from heuristic pointer matches.

---

## Stage 3 — function summaries and report selection

> **Status: implemented.** `amiga_disasm::summary` folds per-function headers
> out of the fact list; `amiga_disasm::select` narrows a report by function,
> range, category, and confidence, returning what it excluded beside what it
> kept. `disasm report` gained `--function`, `--range`, `--only`,
> `--subsystem`, `--min-confidence`, `--order`, and `--dot`; both renderers
> gained the index, the headers, and a full provenance header.
> `SCHEMA_VERSION` is 5.
>
> The review that closed the stage found one class of defect worth recording:
> `leaf` is the only header field that is true *because* facts are absent, so
> folding a narrowed list turned a caller into a claimed leaf. It is now
> `Option<bool>`, answered only when the fact list is complete *and* no
> instruction hit the owner cap — a traversal refused at the cap stops walking,
> so the refused function is missing from the call facts with no way to learn
> it. The general rule the stage ended with: a narrowing may shrink what a
> report says, never add to it.
>
> **Identified improvements:**
>
> - The summaries are folded per report. A large hunk re-folds them on every
>   invocation, which is cheap today and would not be if a frontend asked per
>   keystroke; a cache keyed by the fact list's digest is the obvious answer if
>   that ever happens.
> - `--range` selects by subject offset, so a fact whose subject sits outside
>   the range but whose evidence sits inside it is excluded. That is the honest
>   reading of "narrow to these bytes", but a `--range --with-evidence` variant
>   would answer the other question if a reader turns out to want it.
> - The coverage counters describe the hunk while the fact counters describe the
>   report. Both scopes are labelled, in text and in JSON, but a caller wanting
>   coverage *of the selection* would have to compute it from the kept facts.

**Purpose:** make large binaries explorable without reading one giant listing, using only the text and JSON renderers.

### Deliverables

- Add a function index to the text and JSON report: every function with its anchor, address range, and one-line summary,
  orderable by address or name.
- Let the reader narrow the report instead of scrolling it:
    - select a single function, address range, or entry point;
    - filter facts by library I/O, hardware subsystem, reads, writes, warnings, and confidence.
- Emit the existing callgraph DOT export alongside the report, referencing the same function anchors.
- Add function headers containing only well-supported facts:
    - address range and reached instruction count;
    - callers and callees;
    - library calls;
    - globals read/written;
    - hardware subsystems touched;
    - unresolved exits;
    - leaf/non-leaf classification.
- Add provenance header: source SHA-256, selected hunk/entries/base, config SHA-256, tool version, and analysis options.

### Acceptance criteria

- Every fact shown in a function summary also exists in JSON.
- Anchors and cross-references remain correct when a mapped origin differs from the default entry, and when the report
  is narrowed to a subset.
- A filtered report states what it excluded; a narrowed report is never mistakable for a complete one.
- Generating a report never writes beside source media unless that destination was explicitly selected.

### Recommended cut line

Stages 0–3 form the recommended first project, and **that project is done**. They integrate existing capabilities into a
complete, useful artifact. Review real downstream usage before starting deeper inference: Stage 4 and later are
proposals, not commitments, and the argument for each should be re-made against what the report is actually used for.

---

## Stage 4 — AmigaOS ABI signatures, arguments, returns, flags, and enums

> **Status: groundwork landed, both identified gaps closed, and the stage's own
> stop decision is now measurable; the remaining deliverables below are still
> proposed.**
> Implemented so far: a strict NDK fd-file parser (`amiga-disasm::fd`) with
> config-supplied per-library tables (`[[fd]]`) consulted before the curated
> built-in names; open library identity (`Library::Other`), so any
> `name.library`/`name.device` a program opens is inferred like the built-in
> four and can be fd-described; fd argument registers surfaced as typed
> `arguments` on library-call facts; **resolved argument values**
> (`amiga-disasm::constants`) with a curated argument-type table
> (`amiga-disasm::abi`) that decodes flag words and enumerations, rendering the
> stage's target example verbatim:
>
> ```text
> exec.library/AllocMem(byteSize=d0=32000, requirements=d1=MEMF_CHIP|MEMF_CLEAR)
> ```
>
> and **`OpenDevice` attribution**, which tracks the device base through the
> `io_Device` field of the IORequest rather than through D0, so a call through
> a device base names the device the program opened.
>
> Three rules that work established, worth keeping when the rest of the stage
> is built:
>
> - **A value is resolved or it is absent — never guessed.** The tracker used
>   here walks backwards from the call site and stops at a join, at a call, or
>   at a step cap, and every one of those yields *unknown*. A wrong argument
>   value is worse than an absent one: absent invites reading the code, wrong
>   invites trusting it.
> - **Decoding is gated on the type, never on the value.** `$10002` in
>   `requirements` is `MEMF_CHIP|MEMF_CLEAR`; the same constant in `byteSize`
>   stays `0x10002`. Flag bits with no name are shown as a number rather than
>   dropped, so a partly-understood word never reads as fully understood.
> - **Every resolved value cites the instruction that set it.** A value with
>   nothing to check would be an assertion rather than a finding.
>
> A fourth rule the review that closed this work forced: **an unclassified
> instruction form must mean "wrote something", never "left it alone".** The
> classification is an exhaustive match with no wildcard, so a decoder that
> grows a variant fails to compile until someone decides what it does. The
> wildcard it replaced had ten holes — `EXT`, `SWAP`, `BSET`, `Scc`, `ADDX`,
> `DBcc`, `TAS`, `NBCD`, `MOVE SR`, `UNLK` — and two of them produced silent
> lies in real reports: `MOVEQ #2,D1 ; BSET #16,D1` is idiomatic 68k for adding
> `MEMF_CLEAR`, and the walk sailed past it to report `MEMF_CHIP`.
>
> A fifth rule the measurement work added: **a refusal is a finding, not an
> absence.** The tracker had eight distinct stop conditions and collapsed them
> all into "no value", which cost the reader the most useful half of the answer.
> Each stop is now named, carried on the argument into the JSON, and counted per
> program — so "we could not value this" became "we could not value this
> *because*", which is both a better annotation and the input to this stage's
> stop decision.
>
> **Identified improvements:**
>
> - The constant tracker at this point sees immediates only. A value arriving
>   through a register copy (`MOVE.L D3,D0` ahead of the call) is unknown, which Stage 5A's
>   abstract interpretation is what properly fixes — a copy-following special
>   case here would be the first step toward reimplementing it badly. It reports
>   as `write_not_valued`, so the histogram says how much this one costs.
> - A function containing *any* unresolved transfer refuses every value in it,
>   because an indirect jump could land between a write and its call site and
>   the flow graph cannot say where. That is sound but blunt: a program that
>   uses one jump table loses argument values everywhere. Narrowing it needs
>   resolved indirect targets, which is Stage 5A's work again.
> - A word-sized argument written with `MOVE.W` is unknown, because the ABI
>   table records no argument widths and answering for 32 bits a write that
>   touched 16 would be the same class of error. Widths belong in the stage's
>   validated ABI format.
> - The curated ABI table covers the vectors a program calls early
>   (`exec` allocation, library and device opens, `dos` file I/O). Extending it
>   is cheap but is a claim per entry; the stage's own deliverable is a
>   validated, sourced ABI *format*, which is the right home for breadth.
> - `OpenDevice` is followed through `io_Device(A1)` only. A program that
>   stashes the IORequest and reloads it elsewhere loses the attribution, by
>   design: the slot dies with its pointer.

**Purpose:** explain what named library calls mean at each site.

### Deliverables

- Define a validated, generated-or-curated ABI data format containing:
    - library and function name;
    - LVO;
    - supported OS/library version where relevant;
    - input registers and types;
    - return registers and types;
    - flag/enum definitions;
    - clobber information where authoritative.
- Expand beyond the current curated `exec`, `dos`, `graphics`, and `intuition`
  subset only from traceable source material.
- Propagate immediate constants, known strings, and simple register copies into call arguments.
- Track return values through immediate tests, address-register copies, and fixed global slots.
- Decode constants only when the destination type is known:

```asm
JSR (-198,A6) ; exec.library/AllocMem(
              ;   byteSize=D0=32000,
              ;   requirements=D1=MEMF_CHIP|MEMF_CLEAR)
              ; returns D0: memory pointer
```

- Model library/device/resource open and close lifecycles.
- Report unbalanced or uncertain lifecycle observations as hints, not errors.

### Acceptance criteria

- ABI records have source/version metadata and validation tests.
- The same LVO under two libraries resolves to different functions correctly.
- Unknown register values display as unknown rather than stale propagated values.
- A call or control-flow join invalidates facts according to the ABI/clobber model.

### Stop decision

Measure how often arguments resolve on real programs. Do not proceed to a much larger ABI database if the current
dataflow cannot usefully consume it.

> **The measurement now exists.** `disasm report` reports it in both renderers, folded from the fact list by
> `amiga_disasm::resolution` so the numbers are reproducible from the JSON alone:
>
> ```text
> ; Library calls (this report): 2 sites — 1 named, 0 unnamed vector, 1 unknown base; 1 described, 0 undescribed
> ; Call arguments (this report): 0/2 resolved (0.0%); 2 refused by the walk
> ; Unresolved because: unresolved_flow 2
> ```
>
> A rate alone cannot settle this stage, because a low one looks identical whether the tables are too small or the walk
> is too short-sighted. The histogram is what separates them, and every argument that has no value carries its reason in
> the fact itself (`unresolved` on `CallArgument`), so a single call site answers the same question the totals do.
>
> **How to read it.** Run it over the real programs the report is actually used on, and compare two quantities:
>
> | Dominant finding | What limits the analysis | What to do |
> |---|---|---|
> | Many `undescribed` sites, or `unknown_register` refusals | The **tables**: vectors nobody described | Build the rest of Stage 4 — the validated ABI format and its breadth |
> | `refused_by_walk` dominates, especially `join`, `write_not_valued`, `unresolved_flow` | The **walk**: values it can see but will not read | Do Stage 5A first; more ABI entries would be refused just the same |
> | Many `unknown base` sites | Library-base inference, upstream of both | Neither stage helps until the base is attributed |
>
> The middle row is the one to take seriously, because Stage 4's own identified improvements above already predict it:
> a register copy, a join, and any function containing one unresolved transfer all yield nothing today, and all three are
> Stage 5A's work rather than table work. If the measurement confirms that on real programs, **Stage 5A should be built
> before the rest of Stage 4**, which inverts this document's own ordering. That would not be a defect in the plan; it is
> the plan's stop decision doing its job.
>
> Note the scope. The counters describe the facts a report kept, so a narrowed report measures the narrowing — the header
> labels them `this report` for that reason, and coverage stays labelled `whole hunk` beside them.
>
> ---
>
> Base propagation and argument propagation must be measured separately: adding
> ABI entries cannot resolve a value lost by the dataflow walk. Use reproducible
> synthetic branch, copy, memory-source, and call-clobber cases to identify each
> limitation, then validate against caller-supplied pinned media.

---

## Stage 5 — stronger dataflow, stack frames, and inferred signatures

**Purpose:** explain values and function interfaces rather than isolated instructions.

This is the first analysis-heavy stage and should be split into separate increments.

### Stage 5A — control-flow-aware abstract interpretation

**Implemented at the measured cut.** Six bounded increments now exist:

- The library-base tracker (`lvo::infer_library_candidates`) runs a bounded worklist in control-flow order with a
  conservative join, so a base survives into joined code only when every predecessor agrees.
- `amiga-disasm::dataflow` is now a reusable, owner-local basic-block worklist. The constant-argument tracker is its
  first consumer. Its initial domain was deliberately only unknown or one exact 32-bit value; whole-register immediate
  writes, absolute `LEA`, and direct `MOVE.L`/`MOVEA.L` register copies are propagated across branches and loops. Equal
  exact values survive a join, incompatible or unknown incoming values erase precision, calls and unclassified writes
  clobber it, work and evidence are bounded, and each result carries its complete establishing/copy chain. Semantic
  report schema 7 serializes that chain on each resolved argument and cites it on the containing fact.
- The second exact-domain increment adds PC-relative displacement `LEA`, immediate `ADDA`/`SUBA`, whole-address-register
  `ADDQ`/`SUBQ`, and selected whole-data-register operations: long `ADDI`, `SUBI`, `ANDI`, `ORI`, `EORI`, `ADDQ`,
  `SUBQ`, `CLR`, `NEG`, and `NOT`. Arithmetic follows the MC68000's 32-bit wrapping semantics, extends the evidence
  chain, and preserves the existing unknown reason when its input is unknown.
- The third increment retains a direct longword memory read as a typed symbolic expression rather than either inventing
  its contents or discarding its source. Absolute, PC/image-relative, configured global-base-relative, and other
  address-register-relative sources remain distinct; whole-register copies and wrapping addition/subtraction preserve
  them and extend their evidence chain. Exact, symbolic, and refused arguments are exclusive report states. Semantic
  report schema 8 serializes the source and post-load offset, while resolution statistics keep symbolic findings out of
  the exact resolution rate.
- The fourth increment distinguishes an unresolved indirect `JSR` from control flow that can introduce an unknown
  intraprocedural predecessor. The call keeps its known fallthrough and the existing full-register call clobber; only
  unresolved jumps, opaque instructions, and missing decode targets retain the owner-wide refusal. Shared owners are
  therefore no longer poisoned merely because one of their other paths contains an unknown callee target.
- The fifth increment is correctness rather than coverage: an address-bearing longword operand is now read through
  the relocation that patches it instead of through its stored bytes. A patched operand into the analyzed hunk is an
  offset, converted to a runtime address only where a mapped origin proves one; a patched operand into another hunk is
  retained as an explicit hunk and offset, which is a symbolic finding rather than a number. A patched immediate feeding
  arithmetic is refused, because an addend is not an amount. Semantic report schema 9 serializes which of a location's
  two quantities a symbolic argument holds, so `hunk1+$1c` and `memory32[hunk1+$1c]` are never confused.
- The sixth and final increment retains a longword `(An)+` memory read as a site-specific symbolic source while
  invalidating the incremented address register. Distinct read sites cannot join merely because they use the same
  register, and schema 10 exposes both the postincrement mode and its read site. Later synthetic cases add predecrement, indexed, MOVEM, and sized memory
  reads; [schema 16 expressions](../docs/symbolic-read-expressions.md) records the
  vocabulary, bounds, and regression coverage.

Two correctness follow-ups to those increments have also landed. `ControlFlowAnalysis` now retains the relocation
index used by traversal, and report collection, value propagation, absolute-global scanning, and derived-address
tracking all read operands through that one record; callers can no longer supply a contradictory second relocation
input. The unresolved-`JSR` exemption is also bounded by internal target evidence: if the called address register is
assigned an owned instruction address by a resolved `LEA` or immediate, the owner-wide refusal returns because the
graph is missing a possible predecessor. Synthetic same-hunk, cross-hunk, mapped-address, and internal-handler
fixtures cover both follow-ups.

The following work remains; the first bullet now means updating the other independent trackers to use the shared state, not rebuilding the
constant tracker again.

- Replace the remaining independent straight-line trackers with one bounded worklist engine over basic blocks.
- Extend the deliberately small initial domain with:
    - small finite constant set;
    - bounded integer/address range;
    - symbolic address expressions beyond the direct memory-source forms now retained;
    - known Q-format scale.
- Define conservative join and widening behavior for every added value kind.
- Track register definitions, uses, and clobbers beyond the current exhaustive write and call-clobber classification.
- Preserve evidence chains as new transfer functions and value kinds are added.

**Acceptance:** results are independent of block visitation order, terminate under configured bounds, and never become
more precise after an incompatible join.

The regression suite measures these increments using synthetic programs. Exact,
symbolic, and refused results are exclusive. Cross-hunk relocated operands must
be symbolic until a mapping establishes a runtime address; unresolved indirect
jumps and incompatible joins continue to refuse precision. Future vocabulary
extensions need fixtures exercising the added idiom, including its side effects.

### Stage 5B — function signatures and stack frames

**Implemented, 2026-08-17.** `amiga-disasm::function` now runs a bounded,
owner-local forward analysis for every discovered function. It reports probable
register inputs read before definition, registers defined on every ordinary
return, clobbered and preserved registers, fixed `LINK` and A7-relative frames,
stack arguments and locals, return shapes, leaf status, and direct tail calls to
other discovered functions. Unsupported non-call flow clears register claims
and marks the result incomplete instead of presenting a partial prototype as a
complete interface.

Function signatures are evidence-backed semantic facts in report schema 11.
The text and JSON renderers expose register-oriented prototypes and frame
details from the same typed facts. Synthetic fixtures cover `LINK`/`UNLK`,
explicit A7 allocation, frameless routines,
interrupt returns, `MOVEM` saved registers, branches, tail calls, and incomplete
control flow.

- Recognize common `LINK`/`UNLK`, stack argument, saved-register, and return idioms.
- Infer:
    - registers read before definition (probable inputs);
    - consistently returned registers;
    - clobbered and preserved registers;
    - stack arguments and local slots;
    - leaf functions and tail calls.
- Render a register-oriented prototype without pretending it is C:

```text
draw_object(A0: ptr, A1: ptr, D0.w, D1.w) -> D0
preserves D2-D7/A2-A6; stack locals: 24 bytes
```

**Acceptance:** compiler/runtime fixtures cover at least two common frame styles, frameless functions, and interrupt
handlers.

### Stage 5C — arrays, structures, and user types

- Group repeated offsets from the same symbolic base into a probable record.
- Infer field width, signedness hints, pointer use, array stride, and observed index bounds.
- Extend downstream config with optional functions, globals, types, structs, arrays, enums, constants, comments, and
  register prototypes.
- Keep inferred and user-confirmed types separate.
- Match known AmigaOS structures only when enough independently accessed fields agree.

**Acceptance:** a wrong probable structure can be rejected or overridden in config without changing toolkit code.

---

## Stage 6 — deeper hardware semantics

**Purpose:** turn register writes into understandable hardware operations.

Split this by subsystem so each increment remains reviewable.

### Stage 6A — register metadata and constant decoding

- Give each custom-chip register:
    - access width and read/write behavior;
    - bitfield definitions;
    - chipset/version availability where relevant;
    - subsystem and short description.
- Decode `DMACON`, `INTENA`, `INTREQ`, `ADKCON`, `BPLCON*`, blitter controls, and other well-documented constant writes.
- Respect Amiga set/clear semantics; never describe `$8020` as a plain assigned value when bit 15 changes the operation.

### Stage 6B — CIA and other memory-mapped hardware

- Add CIA-A/CIA-B address decoding with byte-lane behavior.
- Decode timers, interrupt control, joystick/mouse/button, keyboard serial, floppy control, and serial/parallel
  accesses.
- Keep custom-chip, CIA, ROM/vector, and ordinary memory regions distinct.

### Stage 6C — grouped hardware operations

- Pair high/low pointer-register writes.
- Recognize bounded sequences that configure:
    - bitplane and sprite pointers;
    - Copper lists;
    - Paula audio channels;
    - interrupts;
    - blitter jobs;
    - display windows and fetch modes.
- Emit one probable operation linked to every contributing instruction.
- Do not hide or collapse the underlying writes.

### Acceptance criteria

- Each decoded field has a table-driven test from authoritative semantics.
- Partial sequences remain partial and do not invent missing values.
- Interleaved writes from different paths are not combined without supporting control-flow evidence.
- ECS/AGA-only meanings are not silently applied to incompatible targets.

---

## Stage 7 — program phases, interrupts, and shared state

**Purpose:** explain the major execution contexts of an Amiga program.

### Deliverables

- Recognize vector-table installation and restoration.
- Create separate roots/callgraphs for interrupt handlers.
- Summarize interrupt acknowledgement, enabled sources, shared globals, library calls, and hardware accesses.
- Flag globals accessed by both normal and interrupt contexts.
- Identify evidence-backed phases such as:
    - AmigaOS startup;
    - allocation/library setup;
    - hardware takeover;
    - main loop;
    - shutdown/restoration.
- Detect common wait loops:
    - beam position;
    - blitter busy;
    - vertical blank;
    - disk completion;
    - input polling.

### Acceptance criteria

- Phase names are `Probable` unless directly user-supplied.
- Interrupt entry discovery cites the vector write or configured entry.
- Shared-state reports list exact read/write sites.

---

## Stage 8 — static and dynamic evidence integration

**Purpose:** use execution traces to resolve questions static analysis cannot, without confusing observed behavior with
all possible behavior.

### Deliverables

- Import a stable trace/golden-run record into the semantic report.
- Attach observed:
    - register values;
    - effective memory addresses;
    - call targets;
    - memory before/after values;
    - execution counts;
    - device and hardware events.
- Give every trace a run ID plus input, mapping, source checksum, config checksum, stop reason, and step bound.
- Compare static target sets with observed targets.
- Add timeline views for:
    - calls;
    - watched variables;
    - hardware writes;
    - disk/file reads;
    - interrupt events.
- Detect memory written and later executed; offer it as a separately identified generated-code image.
- Detect writes into already decoded code and report self-modifying sites and observed variants.

### Acceptance criteria

- Observed facts are never upgraded to `Certain` static facts.
- Reports from different inputs/runs can be enabled, disabled, and compared.
- Generated code retains a provenance chain back to its writer instructions and source run.
- Trace import validates source/config checksums before attaching observations.

---

## Stage 9 — resource and hardware-state reconstruction

**Purpose:** connect code to the graphics, audio, Copper, and disk data it controls.

Implement each subsection as a separate optional feature.

### Stage 9A — referenced resource classification

- Classify referenced regions as probable:
    - strings/string tables;
    - pointer tables and fixed-stride records;
    - Copper lists;
    - RGB4 palettes;
    - planar bitmaps or glyph sheets;
    - signed PCM samples or tracker data;
    - compressed/packed data;
    - generated code.
- Link classifications to existing inspect/render/export commands.
- Keep embedded previews bounded and explicitly generated.

### Stage 9B — display and Copper reconstruction

- Combine CPU writes with Copper-list semantics.
- Link CPU sites that build or patch a Copper list to the affected Copper instructions.
- Produce an effective display-state summary: resolution, bitplanes, fetch window, pointers, palette, and DMA state.
- For dynamic traces, allow a raster/frame timeline when timing evidence exists.

### Stage 9C — blitter reconstruction

- Group a trigger write with the control, pointer, modulo, mask, width, and height state that reaches it.
- Explain minterms and channel participation.
- Optionally preview a blit only when all source/destination geometry is known and the input bytes are available.

### Stage 9D — Paula audio reconstruction

- Group sample address, length, period, volume, DMA enable, and interrupt behavior per channel.
- Link known sample regions and offer WAV previews through existing safe output machinery.
- Estimate pitch/note only as derived metadata with the clock assumption shown.

### Acceptance criteria

- Resource classification never writes extracted bytes without an explicit destination.
- Preview manifests include source and output checksums.
- Static state snapshots and trace timelines are labeled separately.

---

## Stage 10 — behavior recognition and suggested names

**Purpose:** reduce manual work by recognizing common code roles while keeping the evidence inspectable.

### Deliverables

- Add deterministic recognizers for well-understood idioms:
    - memory copy/fill/compare;
    - string operations;
    - switch/jump tables;
    - checksum/CRC families;
    - common PRNG shapes;
    - fixed-point multiply/divide and clamp patterns;
    - known generic decompression families;
    - compiler runtime/startup helpers.
- Infer coarse side-effect summaries:
    - allocation/free;
    - file or disk I/O;
    - graphics/hardware;
    - audio;
    - input;
    - interrupt/shared-state;
    - pure/read-only/write-only where provable.
- Suggest function names from behavior and callees, never silently install them.
- Cluster functions by callgraph proximity and shared effects into probable subsystems.
- Let downstream config accept, rename, or reject suggestions.

### Acceptance criteria

- Every suggested name lists its evidence.
- A false-positive fixture exists for every accepted recognizer.
- Recognizers are deterministic and do not require a network service.
- User-confirmed names always take precedence over generated suggestions.

---

## Stage 11 — comparison across builds and versions

**Purpose:** transfer understanding between PAL/NTSC, demo/full, localized, or patched variants.

### Deliverables

- Normalize functions for comparison while retaining raw bytes.
- Match functions using multiple signals:
    - control-flow shape;
    - normalized instruction sequence;
    - called libraries;
    - referenced strings/data;
    - hardware and global side effects.
- Report exact, probable, split, merged, added, and removed matches.
- Transfer symbols/types/comments only as reviewable suggestions.
- Show semantic differences such as changed constants, buffer sizes, branches, library calls, and hardware flags.

### Acceptance criteria

- Exact byte matches are distinguished from heuristic matches.
- Transferred knowledge records the source binary checksum and source entity.
- Ambiguous one-to-many matches are never applied automatically.

---

## Stage 12 — query and investigation interface

**Purpose:** answer common reverse-engineering questions from the accumulated fact graph.

### Initial deterministic queries

```text
Who writes DMACON?
Who reads or writes this global?
What calls dos.library/Read?
What points to this string or resource?
Which functions touch both disk data and chip memory?
Which globals are shared with interrupt handlers?
Show call paths from an entry point to this function/register access.
Where was this runtime address derived?
Which static indirect targets were observed in traces?
```

### Deliverables

- Implement queries against the JSON/report graph, not against rendered text.
- Return entity IDs, evidence, confidence, and anchors resolvable in the report.
- Bound graph traversal depth and result count.
- Keep any future natural-language layer as a front end to deterministic queries; it must link answers to the underlying
  facts.

### Acceptance criteria

- The same query over the same report is deterministic.
- “No result” is distinguishable from “analysis incomplete.”
- Every answer can be reproduced through JSON entities and edges.

## 6. Suggested release sequence

The stages above are intentionally finer-grained than releases. A pragmatic sequence is:

| Release               | Included stages | Value                                            | Cost/risk   |
|-----------------------|-----------------|--------------------------------------------------|-------------|
| R1: semantic text     | 0–1             | Existing analyses become readable in one listing | Low         |
| R2: navigation        | 2–3             | Cross-linked JSON/text investigation report      | Low–medium  |
| R3: OS meaning        | 4               | Library arguments, returns, flags, lifecycles    | Medium      |
| R4: program data      | 5A–5C           | Values, signatures, stack, structures            | High        |
| R5: machine meaning   | 6–7             | Hardware operations, interrupts, phases          | Medium–high |
| R6: observed behavior | 8               | Static/dynamic integration and generated code    | High        |
| R7: media meaning     | 9               | Display, blitter, audio, resource links          | High        |
| R8: assistance        | 10–12           | Recognition, version transfer, questions         | Very high   |

Recommended initial commitment: **R1 and R2 only**. Re-evaluate with real downstream programs before accepting R3. Treat
every later release as a separate proposal, not an implied continuation.

## 7. Config evolution

Do not design the complete schema up front. Add sections only when their stage lands. Likely future concepts are:

```toml
[[functions]]
addr = 0x12a40
name = "load_bitmap"
comment = "Loads a raw planar image into chip memory"

[[globals]]
addr = 0x20420
name = "screen_buffer"
type = "chip_ptr<u8>"

[[types.enums]]
name = "GameMode"
values = { 0 = "menu", 1 = "race", 2 = "replay" }

[[types.structs]]
name = "Object"
# Field syntax must be designed when structure support is implemented.
```

Requirements for every addition:

- strict duplicate/conflict diagnostics;
- checked address conversion;
- names and comments escaped by every renderer;
- optional source/comment metadata;
- no game-specific defaults in `amiga-re`;
- config facts visibly distinguished from inferred facts.

## 8. Testing strategy

Every stage must add synthetic fixtures for success, ambiguity, and malformed input.

### Unit tests

- individual fact producers and joins;
- address-space conversions and overflow;
- hardware/ABI tables;
- escaping and bounded previews;
- confidence/evidence propagation;
- false positives and invalidation behavior.

### Integration tests

- CLI text/JSON snapshots;
- anchor and cross-reference resolution across the whole report;
- consistent behavior across commands;
- report regeneration determinism;
- safe output paths, symlink refusal, and `--force`.

### Optional private-media tests

- run only when pinned media exists;
- verify source SHA-256 before assertions;
- skip cleanly in public checkouts;
- assert semantic facts and recovered bytes, not only counts or names.

### Required gate before each implementation commit

[AGENTS.md](../AGENTS.md) defines the canonical gate. All five checks must pass
with zero warnings:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## 9. Risks and controls

| Risk                                  | Control                                                                         |
|---------------------------------------|---------------------------------------------------------------------------------|
| Convincing but wrong annotations      | Evidence and confidence on every inferred fact; conservative joins              |
| Annotation noise                      | Compact/verbose modes, categories, filters                                      |
| Analysis passes disagree              | Preserve competing facts and emit ambiguity                                     |
| Renderer becomes the data model       | JSON/fact graph is authoritative                                                |
| Huge reports                          | Intern strings/entities, index facts, bound previews, selectable report subsets |
| Dataflow state explosion              | Small abstract domains, caps, widening, metrics                                 |
| Incorrect OS-version assumptions      | Versioned ABI records with source metadata                                      |
| Chipset-specific register confusion   | Target/chipset selection and availability metadata                              |
| Game-specific logic leaks into crates | Config-driven downstream extensions and review                                  |
| Dynamic trace mistaken for proof      | `Observed` confidence and run provenance                                        |
| Private media enters fixtures         | Synthetic public fixtures; checksum-gated optional tests                        |
| Scope becomes a decompiler project    | Stop after each release and measure concrete downstream value                   |

## 10. Decisions to make only when needed

These are intentionally deferred:

1. Whether the fact/report model graduates into a new crate.
2. Which authoritative ABI/register sources may be redistributed or converted into generated tables.
3. Which compilers and calling conventions deserve first-class support.
4. Whether dataflow should use an internal SSA-like representation.
5. Whether trace records need a new stable schema or can wrap the current one.
6. Whether cross-version matching belongs in this repository or a downstream preservation tool.
7. Whether a browsable renderer over the JSON report is worth building, and in what form, once a consumer actually needs
   one.
8. Whether a natural-language front end provides enough value beyond deterministic graph queries.

Deferring these choices prevents late, speculative stages from over-constraining the first useful releases.

## 11. Definition of success

The roadmap succeeds even if development stops after Stage 3. At that point a reader should be able to open one
reproducible report, navigate from a function to its callers, library calls, globals, strings, relocations, and hardware
registers, and verify every annotation against raw MC68000 bytes.

Later stages are successful only if they measurably reduce manual investigation on more than one downstream project
without weakening accuracy, neutrality, safety, or provenance.
