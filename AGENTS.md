# Project Instructions for `amiga-re`

`amiga-re` is a standalone, game-agnostic toolkit for reverse engineering Amiga
files: disk images (ADF), archives (LHA/LZH), HUNK executables, MC68000 code, and
custom-chip / graphics / audio formats. It is intended to be depended on by
individual game-preservation projects instead of re-implementing these parsers.

These conventions define the shared library and CLI development contract.
Follow them exactly.

## Language

All code, comments, CLI strings, documentation, and commit messages are in
**English**. User-facing conversation may follow the user's language.

## Project Phase

Active development — **no backward compatibility is required yet**. Prefer clear,
documented formats and APIs over preserving experimental interfaces.

## Documenting Discovered Work

Whenever you discover an improvement opportunity, defect, limitation, missing
test, or other actionable problem, document it in the repository-root
`TODO.md`. Do this even when fixing it is outside the scope of the current task.
Do not add duplicate entries; update an existing entry when it describes the
same underlying work.

Every entry must be actionable without requiring the person implementing it to
rediscover the original context. State clearly:

- **Purpose:** the intended outcome.
- **Why:** the problem, risk, or benefit that justifies the work.
- **Where:** the relevant crates, modules, files, APIs, or commands.
- **How:** concrete implementation guidance, important constraints, and the
  tests or verification needed to consider the work complete.

## Scope and Neutrality

- This is a **reusable library + CLI**, not a game. It must contain **no
  game-specific assumptions**: no hard-coded palettes, resource counts, or
  executable addresses belonging to a particular title. Those belong in the
  downstream project that *uses* this package.
- No rendering-engine (e.g. Bevy), audio-device, or OS-window types in any crate.

## Original Media and Copyrighted Assets

- Treat files in `original/`, `extracted/`, and `decoded/` as private source
  media. They are git-ignored and must never be committed unless the user
  explicitly confirms they are redistributable.
- All inspection and extraction code opens source media **read-only**.
- Preserve provenance: generated manifests must record source and output
  checksums sufficient to reproduce an extraction (`amiga-core::provenance`).
- Keep recovery behavior explicit. Tolerated corruption must produce a **warning**
  rather than being silently ignored.

## Commands

Before committing, all checks must pass with zero warnings:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

The last one is in the gate because a doc link that resolves to the wrong item,
or to nothing, renders as plain text and is invisible in review. Thirteen of them
accumulated across seven crates while `cargo doc` was outside the gate, two of
them copied from a line that already had the problem.

Never push, tag, publish, or merge unless the user asks.

### Available development tools

The `ast-grep` command is installed. It parses source code into an abstract
syntax tree and performs structural searches or rewrites, so use it when a
query depends on syntax rather than plain text or when a refactor must match
code shapes independently of whitespace and formatting. Review structural
rewrite matches before applying them; continue to use `rg` for ordinary text
and file searches.

## Architecture

Dependencies flow in one direction. Libraries never depend on the CLI.

- `amiga-core` — shared primitives: a bounds-checked big-endian `Reader`,
  provenance/manifest helpers, and safe output-path handling. Depends on nothing
  internal.
- `amiga-hunk` — read-only Amiga LoadSeg/HUNK executable parser.
- `amiga-adf` — read-only, recovery-oriented AmigaDOS disk-image reader.
- `amiga-hw` — Amiga custom-chip knowledge: Copper-list scanning, hardware
  register map, RGB4→RGB8, planar bitplane primitives.
- `amiga-disasm` — MC68000 recursive control-flow analysis and listing
  generation over the external `m68000` crate, plus the bare RAM sandbox that
  executes one. Depends on `amiga-core` + `amiga-hw` — **not** on `amiga-hunk`:
  it analyses a byte range at an address, and who parsed the container out of
  which those bytes came is the caller's business. `amiga-hw` is there for
  `amiga_hw::blitter::DmaMemory`, because what the sandbox's DMA handle
  satisfies is chip knowledge rather than CPU knowledge.
- `amiga-env` — a bounded, offline execution environment above that sandbox: a
  documented memory map, a fake ExecBase, a synthetic trackdisk IORequest, and
  the OCS chip emulation a boot block needs to run. Depends on `amiga-core`,
  `amiga-adf`, `amiga-disasm`, `amiga-hw`.
- `amiga-compress` — Amiga decompressors (headerless PowerPacker, IFF ByteRun1,
  position-XOR + escape-marker RLE). Depends on nothing internal.
- `amiga-iff` — generic IFF container reader plus 8SVX sampling, ILBM image
  decoding, PCM scanning, tracker-module detection, and WAV export. Depends on
  `amiga-core`, `amiga-compress` (ILBM `BODY` compression is ByteRun1), and
  `amiga-hw`.
- `amiga-lha` — LHA/LZH archive reader.
- `amiga-project` — the versioned project format: bundled Draft 2020-12 schemas,
  typed documents, a bounded loader, and semantic validation with stable problem
  codes. Depends on `amiga-core` only: the format crate carries no parser and no
  codec, so a recipe it records is re-derived by whoever holds the decoders.
- `amiga-analysis` — shared typed survey and extraction orchestration over the
  domain crates, consumed by `amiga-operations`.
- `amiga-operations` — the shared typed operation API: one request/response
  vocabulary, bounded limits, stable diagnostics, source resolution, a
  descriptor catalog, bundled JSON schemas, and exhaustive routing. The CLI
  is an adapter over it. Depends on `amiga-analysis`, `amiga-project`,
  and every domain crate.
- `amiga-re-cli` (`tools/`, binary `amiga-re`) — orchestration, provenance, and
  the unified command-line interface. May use `anyhow` at its outer boundary.

## Parser and Extraction Safety

- Parse every Amiga integer field explicitly as **big-endian**.
- Bounds-check every offset, length, allocation, relocation, chain, block, and
  user-controlled output path. Use `checked_*` arithmetic.
- Detect cycles in directory and data chains.
- Reject absolute paths, `..`, empty or unsafe path components, and ambiguous
  platform separators from archive-provided names. An extraction may retain an
  archive's hierarchy only by normalizing its format-specific separator and
  validating every component before any output is planned.
- Refuse to write through symbolic links. Never recursively delete an arbitrary
  output directory. Overwrite known generated paths only with an explicit `--force`.
- Recover and validate all source data before modifying the destination, so
  malformed input does not leave a misleading partial result.
- Add a regression test for every accepted malformed-input behavior.

## Domain Types and Code Style

- Prefer small newtypes over raw primitives for public domain concepts
  (block numbers, byte sizes, sample rates, resource offsets, …). Raw primitives
  are fine for local indices, intermediate arithmetic, and serialization.
- Use `Self` in impl blocks.
- Use `thiserror` for library error types; `anyhow` only at the CLI boundary.
- Do not use `.unwrap()` or `.expect()` in production code (tests may).
- Minimize the public API surface; prefer `pub(crate)` for internals.
- Add `#[must_use]` to newtypes and builder-style methods.
- No `unsafe` code without prior discussion and a documented safety argument.

## Testing

- Unit tests use synthetic, redistributable fixtures for general parser behavior
  and malformed input.
- Tests against private media may run when those files are present but must
  **skip cleanly** in public checkouts.
- Pin known source SHA-256 values before trusting media-specific expectations.
- Test recovered byte content, not only names and declared lengths.
