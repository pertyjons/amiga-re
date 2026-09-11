# Operation reference

Generated from the operation catalog and the bundled Draft 2020-12 schemas by
`amiga_operations::reference::markdown`. Edit the generator or schemas, then update
this file with:

```bash
UPDATE_GOLDEN=1 cargo test -p amiga-operations --test catalog the_checked_in_operation_reference_matches_the_catalog
```

Review the resulting diff. Without `UPDATE_GOLDEN`, the test checks for drift
and leaves the file unchanged.

Protocol version: `1`

The argument tables describe operation payloads. Requests wrap them in an
envelope with `protocol_version` and `request`; `request` contains `operation` and
`arguments`. Inspect the catalog and bundled schemas through the CLI:

```bash
amiga-re operations list --response json
amiga-re schema
amiga-re schema source.survey --kind request
amiga-re schema source.survey --kind response
```

Schema identifiers below are offline identities, not downloadable URLs. Use
`amiga-re schema --output schemas` to export the complete bundled set. Nested
object fields and validation constraints are described in those schemas.

Defaults apply when an argument is omitted; they are not host ceilings.
`ExecutionContext` supplies `OperationLimits`, including aggregate recovery
and object budgets that are not request arguments. Requests cannot raise
those host limits. Limit reductions are reported in diagnostics.

`read_only` operations return results without writing output files.
`prepared_output` operations require a destination resolver and produce a
plan for review before commit. `amiga-re operations run --request request.json`
uses the current directory for source resolution and supplies no destination
resolver; use the corresponding export/extraction command or a library host
with destinations configured for prepared output.

| Operation | Access | Summary |
|---|---|---|
| [`source.survey`](#source-survey) | `read_only` | Classify a source into one ordered, non-overlapping map of typed regions. |
| [`container.adf.list`](#container-adf-list) | `read_only` | List an AmigaDOS volume and the files and directories it contains. |
| [`graphics.bitmap.decode`](#graphics-bitmap-decode) | `read_only` | Decode a planar region into one palette index per pixel. |
| [`container.adf.extract`](#container-adf-extract) | `prepared_output` | Recover an AmigaDOS volume's files through a reviewed write plan. |
| [`container.lha.extract`](#container-lha-extract) | `prepared_output` | Recover an LHA archive's members through a reviewed write plan. |
| [`graphics.bitmap.export`](#graphics-bitmap-export) | `prepared_output` | Export a decoded planar region as an indexed PNG through a reviewed write plan. |
| [`project.check`](#project-check) | `read_only` | Load a versioned project and report every problem by stable code. |
| [`project.verify`](#project-verify) | `read_only` | Verify a project's sources and objects against the bytes on disk. |
| [`analysis.hunk.diff`](#analysis-hunk-diff) | `read_only` | Compare two HUNK executables hunk by hunk, byte range by byte range. |
| [`analysis.hunk.diff.export`](#analysis-hunk-diff-export) | `prepared_output` | Write a HUNK comparison as a report through a reviewed write plan. |
| [`source.carve`](#source-carve) | `prepared_output` | Write one byte range of a source as its own file through a reviewed write plan. |
| [`analysis.table.decode`](#analysis-table-decode) | `read_only` | Read a byte region as an array of fixed-layout big-endian records. |
| [`analysis.table.summarize`](#analysis-table-summarize) | `read_only` | Summarize a fixed-layout table's columns and compare them across several sources. |
| [`audio.sample.decode`](#audio-sample-decode) | `read_only` | Read an IFF 8SVX sample and summarize it with a bounded waveform envelope. |
| [`audio.sample.export`](#audio-sample-export) | `prepared_output` | Write an IFF 8SVX sample as a WAV file through a reviewed write plan. |
| [`compress.powerpacker.decode`](#compress-powerpacker-decode) | `read_only` | Decompress a headerless PowerPacker stream and report what it holds. |
| [`compress.powerpacker.export`](#compress-powerpacker-export) | `prepared_output` | Write a decompressed PowerPacker stream through a reviewed write plan. |
| [`compress.rle-xor.decode`](#compress-rle-xor-decode) | `read_only` | Decompress a position-XOR marker-RLE stream and report what it holds. |
| [`compress.rle-xor.export`](#compress-rle-xor-export) | `prepared_output` | Write a decompressed position-XOR marker-RLE stream through a reviewed write plan. |
| [`audio.pcm.decode`](#audio-pcm-decode) | `read_only` | Read a raw 8-bit signed PCM region and summarize it with a bounded envelope. |
| [`audio.pcm.export`](#audio-pcm-export) | `prepared_output` | Write a raw PCM region as a WAV file through a reviewed write plan. |
| [`audio.module.decode`](#audio-module-decode) | `read_only` | Read a ProTracker/SoundTracker module and report its layout and sample slots. |
| [`audio.module.export`](#audio-module-export) | `prepared_output` | Write a tracker module out as its own file through a reviewed write plan. |
| [`analysis.hunk.normalize`](#analysis-hunk-normalize) | `read_only` | Report what rewriting a one-file loader's compact relocations would produce. |
| [`analysis.hunk.normalize.export`](#analysis-hunk-normalize-export) | `prepared_output` | Write a normalized HUNK image through a reviewed write plan. |
| [`provenance.manifest`](#provenance-manifest) | `read_only` | Report the name, size, and SHA-256 a provenance manifest would record. |
| [`provenance.manifest.export`](#provenance-manifest-export) | `prepared_output` | Write a provenance manifest through a reviewed write plan. |
| [`graphics.palette.decode`](#graphics-palette-decode) | `read_only` | Read a run of Amiga $0RGB colour words and report both encodings of each. |
| [`graphics.palette.export`](#graphics-palette-export) | `prepared_output` | Draw a palette as a swatch PNG through a reviewed write plan. |
| [`env.sandbox.run`](#env-sandbox-run) | `read_only` | Execute one CODE hunk under stated bounds and report how it stopped. |
| [`env.boot.info`](#env-boot-info) | `read_only` | Report what a floppy's boot block declares about itself. |
| [`env.sandbox.call`](#env-sandbox-call) | `read_only` | Invoke one routine to RTS and report a diffable input/output record. |
| [`env.sandbox.call.export`](#env-sandbox-call-export) | `prepared_output` | Write a routine's golden record through a reviewed write plan. |
| [`env.boot.trace`](#env-boot-trace) | `read_only` | Boot a floppy in a seeded Amiga and report the calls, writes, and reads it made. |
| [`env.boot.trace.export`](#env-boot-trace-export) | `prepared_output` | Write a boot run's served track reads through a reviewed write plan. |
| [`analysis.hunk.list`](#analysis-hunk-list) | `read_only` | List a LoadSeg image's hunks and the relocations between them. |
| [`analysis.strings.scan`](#analysis-strings-scan) | `read_only` | Find printable runs in a source and report where they sit. |
| [`analysis.address.resolve`](#analysis-address-resolve) | `read_only` | Report one number in its absolute, hunk-relative, and whole-file frames. |
| [`analysis.pointers.scan`](#analysis-pointers-scan) | `read_only` | Find runs of plausible in-hunk pointers and report what they address. |
| [`analysis.code.disassemble`](#analysis-code-disassemble) | `read_only` | Decode a CODE hunk or pinned raw image, by sweep or control flow. |
| [`analysis.address.references`](#analysis-address-references) | `read_only` | Report the addresses a hunk's code names, or the sites that name one address. |
| [`analysis.code.callgraph`](#analysis-code-callgraph) | `read_only` | Reduce a CODE hunk's control flow to its functions and the calls between them. |
| [`analysis.code.globals`](#analysis-code-globals) | `read_only` | Map the base-relative, absolute, and derived accesses a hunk's code makes. |
| [`analysis.code.fixed-point`](#analysis-code-fixed-point) | `read_only` | Report fixed-point multiply and divide idioms, saturating clamps, and Q scales. |
| [`container.lha.list`](#container-lha-list) | `read_only` | List an LHA archive's members and the method each is stored with. |
| [`hardware.register.list`](#hardware-register-list) | `read_only` | Report the custom-chip register map this build knows. |
| [`audio.pcm.scan`](#audio-pcm-scan) | `read_only` | Find runs of bytes that score like raw 8-bit signed PCM. |
| [`audio.module.scan`](#audio-module-scan) | `read_only` | Find tracker modules by signature and report what each declares. |
| [`graphics.palette.scan`](#graphics-palette-scan) | `read_only` | Find runs of $0RGB colour words that score as palette tables. |
| [`hardware.copper.scan`](#hardware-copper-scan) | `read_only` | Find plausible Copper lists and the palettes and pointers each carries. |
| [`hardware.copper.decode`](#hardware-copper-decode) | `read_only` | Decode a Copper stream instruction by instruction from an offset. |
| [`graphics.ilbm.decode`](#graphics-ilbm-decode) | `read_only` | Describe an ILBM form: geometry, masking, viewport mode, and palette. |
| [`graphics.bitmap.detect`](#graphics-bitmap-detect) | `read_only` | Score a region's entropy and row strides to suggest a bitmap's geometry. |
| [`hardware.register.references`](#hardware-register-references) | `read_only` | Report every custom-chip register a hunk's code touches, and how. |
| [`hardware.copper.references`](#hardware-copper-references) | `read_only` | Trace the CPU writes that patch a runtime copy of a Copper list. |
| [`project.describe`](#project-describe) | `read_only` | Summarize a project: its sources, objects, programs, and counts. |
| [`project.annotations`](#project-annotations) | `read_only` | Report a project's reviewed knowledge about one image or one object. |
| [`project.inventory`](#project-inventory) | `read_only` | Walk a directory and report the inventory a directory source would pin. |
| [`project.edit`](#project-edit) | `prepared_output` | Apply reviewed changes to a project's annotations through a plan. |
| [`project.format`](#project-format) | `prepared_output` | Bring every document a project names into canonical form. |
| [`analysis.code.facts`](#analysis-code-facts) | `read_only` | Compose every code analysis into one fact list, with the instructions it is about. |
| [`source.read`](#source-read) | `read_only` | Read a window of a source's bytes, with the relocations inside it. |
| [`project.init`](#project-init) | `prepared_output` | Create a project document set from chosen source files, through a plan. |
| [`project.extract`](#project-extract) | `prepared_output` | Extract a project's registered carriers into it, through a plan. |
| [`project.resource.export`](#project-resource-export) | `prepared_output` | Produce a resource's file from the project alone, and record that it exists. |
| [`env.sandbox.matrix`](#env-sandbox-matrix) | `read_only` | Run a named set of sandbox calls that share one recipe and vary its inputs. |
| [`env.sandbox.compare`](#env-sandbox-compare) | `read_only` | Compare golden call records by what they were given and what they did. |
| [`env.sandbox.matrix.export`](#env-sandbox-matrix-export) | `prepared_output` | Write each case of a sandbox sweep's exported ranges through a reviewed write plan. |
| [`env.sandbox.timeline`](#env-sandbox-timeline) | `read_only` | Run a sequence of sandbox steps over one evolving machine state. |
| [`analysis.state.snapshot`](#analysis-state-snapshot) | `read_only` | Decode a machine's memory through a project's reviewed types and globals. |
| [`analysis.state.compare`](#analysis-state-compare) | `read_only` | Compare state snapshots field by field. |
| [`env.frame.capture`](#env-frame-capture) | `read_only` | Reconstruct the frame the display hardware would have shown after a run. |
| [`env.frame.capture.export`](#env-frame-capture-export) | `prepared_output` | Write a captured frame as indexed and RGBA PNGs through a reviewed write plan. |
| [`graphics.bitmap.compare`](#graphics-bitmap-compare) | `read_only` | Compare two decoded images in palette-index space and in colour space. |
| [`graphics.bitmap.compare.export`](#graphics-bitmap-compare-export) | `prepared_output` | Write a comparison's heatmap and overlay through a reviewed write plan. |
| [`env.sandbox.slice`](#env-sandbox-slice) | `read_only` | Follow one value backwards through the instructions that produced it. |
| [`env.sandbox.timeline.export`](#env-sandbox-timeline-export) | `prepared_output` | Write each step of a sandbox timeline's checkpointed ranges through a reviewed write plan. |

<a id="source-survey"></a>

## `source.survey`

Classify a source into one ordered, non-overlapping map of typed regions.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/source.survey.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/source.survey.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_regions` | `integer` | no | `65536` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `minimum_string_length` | `integer` | no | `6` | Minimum printable-run length the string locator reports. Deliberately higher by default than a plain string dump uses: a survey weighs string runs against Copper, palette, and module locators, and short runs cost it accuracy. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="container-adf-list"></a>

## `container.adf.list`

List an AmigaDOS volume and the files and directories it contains.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.adf.list.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.adf.list.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_entries` | `integer` | no | `65536` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-bitmap-decode"></a>

## `graphics.bitmap.decode`

Decode a planar region into one palette index per pixel.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `bob_mask` | `object` | no | — | `bob` only: where transparency comes from. |
| `glyph_columns` | `integer` | no | `1` | `glyph_sheet` only: glyphs per row of the contact sheet. |
| `glyph_count` | `integer` | no | `1` | `glyph_sheet` only: how many glyphs to decode. |
| `glyph_gap` | `integer` | no | `0` | `glyph_sheet` only: separator pixels between tiled glyphs. |
| `height` | `integer` | yes | — | Pixel height of one image; for `glyph_sheet`, of one glyph. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_output_pixels` | `integer` | no | `67108864` | Refuse a decode whose output would exceed this many pixels. Checked from the declared geometry before anything is read, because a planar decode's cost is its output rather than its input. |
| `offset` | `integer` | no | `0` | Byte offset of the planar data within the source. |
| `plane_order` | `contiguous` \| `interleaved` \| `byte_interleaved` \| `word_interleaved` \| `longword_interleaved` | no | `"contiguous"` | `contiguous` stores every row of one plane before the next; `interleaved` stores all planes of each row together; `byte_interleaved`, `word_interleaved`, and `longword_interleaved` store all planes of each 8-, 16-, or 32-pixel chunk together, which are storage layouts code scatters into bitplanes at load time rather than ones the chipset displays. |
| `planes` | `integer` | yes | — | Bitplanes. The blitter addresses at most eight, and a palette index is one byte. |
| `shape` | `bitmap` \| `glyph_sheet` \| `bob` | no | `"bitmap"` | What the region decodes to. `bitmap` is one image; `glyph_sheet` tiles `glyph_count` images into a contact sheet; `bob` is one blitter object whose mask says which pixels are opaque. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `width` | `integer` | yes | — | Pixel width of one image; for `glyph_sheet`, of one glyph. |

<a id="container-adf-extract"></a>

## `container.adf.extract`

Recover an AmigaDOS volume's files through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.adf.extract.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.adf.extract.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Where the recovered files go, as an identity the adapter resolves against its own output root. Obeys the same rules as a source path: relative, normal components only, so a request cannot reach outside the root its adapter chose. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="container-lha-extract"></a>

## `container.lha.extract`

Recover an LHA archive's members through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.lha.extract.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.lha.extract.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Where the recovered files go, as an identity the adapter resolves against its own output root. Obeys the same rules as a source path: relative, normal components only, so a request cannot reach outside the root its adapter chose. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-bitmap-export"></a>

## `graphics.bitmap.export`

Export a decoded planar region as an indexed PNG through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `bob_mask` | `object` | no | — | `bob` only: where transparency comes from. |
| `destination` | `string` | yes | — | Directory the PNG goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"bitmap.png"` | File name within the destination: one relative path component, so an export cannot write beside its destination let alone outside it. |
| `glyph_columns` | `integer` | no | `1` | `glyph_sheet` only: glyphs per row of the contact sheet. |
| `glyph_count` | `integer` | no | `1` | `glyph_sheet` only: how many glyphs to decode. |
| `glyph_gap` | `integer` | no | `0` | `glyph_sheet` only: separator pixels between tiled glyphs. |
| `height` | `integer` | yes | — | Pixel height of one image; for `glyph_sheet`, of one glyph. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_output_pixels` | `integer` | no | `67108864` | Refuse a decode whose output would exceed this many pixels. Checked from the declared geometry before anything is read, because a planar decode's cost is its output rather than its input. |
| `offset` | `integer` | no | `0` | Byte offset of the planar data within the source. |
| `palette` | `array` | no | — | RGB4 (`$0RGB`) colors, at least `1 << planes` of them. Omitted, the export uses an evenly spaced grayscale ramp and records it in the result — an export with no palette still commits to specific colors, and the result says which. |
| `plane_order` | `contiguous` \| `interleaved` \| `byte_interleaved` \| `word_interleaved` \| `longword_interleaved` | no | `"contiguous"` | `contiguous` stores every row of one plane before the next; `interleaved` stores all planes of each row together; `byte_interleaved`, `word_interleaved`, and `longword_interleaved` store all planes of each 8-, 16-, or 32-pixel chunk together, which are storage layouts code scatters into bitplanes at load time rather than ones the chipset displays. |
| `planes` | `integer` | yes | — | Bitplanes. The blitter addresses at most eight, and a palette index is one byte. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `shape` | `bitmap` \| `glyph_sheet` \| `bob` | no | `"bitmap"` | What the region decodes to. `bitmap` is one image; `glyph_sheet` tiles `glyph_count` images into a contact sheet; `bob` is one blitter object whose mask says which pixels are opaque. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `width` | `integer` | yes | — | Pixel width of one image; for `glyph_sheet`, of one glyph. |

<a id="project-check"></a>

## `project.check`

Load a versioned project and report every problem by stable code.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.check.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.check.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|

<a id="project-verify"></a>

## `project.verify`

Verify a project's sources and objects against the bytes on disk.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.verify.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.verify.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|

<a id="analysis-hunk-diff"></a>

## `analysis.hunk.diff`

Compare two HUNK executables hunk by hunk, byte range by byte range.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.diff.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.diff.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `a` | `object` | yes | — | The first image, reported as the `a` side. |
| `b` | `object` | yes | — | The second image, reported as the `b` side. |
| `maximum_changed_ranges` | `integer` | no | `10000` | Cap on the changed ranges reported per hunk. The true count is always reported, so a capped comparison can never be read as a complete one. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |

<a id="analysis-hunk-diff-export"></a>

## `analysis.hunk.diff.export`

Write a HUNK comparison as a report through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.diff.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.diff.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `a` | `object` | yes | — | The first image, reported as the `a` side. |
| `b` | `object` | yes | — | The second image, reported as the `b` side. |
| `destination` | `string` | yes | — | Directory the report goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | — | File name within the destination: one relative path component, so an export cannot write beside its destination let alone outside it. Defaults to `hunk-diff.json` or `hunk-diff.txt`, by format. |
| `format` | `json` \| `text` | no | `"json"` | `json` is the structured report another program reads; `text` is the rendered one a person reads. Both describe the same comparison. |
| `maximum_changed_ranges` | `integer` | no | `10000` | Cap on the changed ranges reported per hunk. The true count is always reported, so a capped comparison can never be read as a complete one. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |

<a id="source-carve"></a>

## `source.carve`

Write one byte range of a source as its own file through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/source.carve.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/source.carve.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the carved file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"carve.bin"` | File name within the destination: one relative path component, so a carve cannot write beside its destination let alone outside it. |
| `length` | `integer` | yes | — | Length of the range in bytes. At least one: an empty carve writes nothing. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | yes | — | Byte offset of the range within the source. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-table-decode"></a>

## `analysis.table.decode`

Read a byte region as an array of fixed-layout big-endian records.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.table.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.table.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `layout` | `string` | no | — | Comma-separated field list, e.g. `u16,u16,ptr,char[16]`. Scalars are `u8`/`u16`/`u32` and their signed forms, `ptr` is a 32-bit pointer, `char[N]` a NUL-terminated Latin-1 string, `bytes[N]` raw bytes, and `pad[N]` skipped bytes. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_rows` | `integer` | no | `65536` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `offset` | `integer` | no | `0` | Byte offset of the first record. |
| `rows` | `integer` | yes | — | How many records to decode. A region that holds fewer whole rows returns the ones that fit and reports the true count. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `type_id` | `string` | no | — | A `type:` id naming a struct the project defines, used instead of `layout`. The struct's fields are read back as a record layout, so a table saved as a resource decodes from the stored type alone — which is what `type_id` on a table resource has always meant and nothing could act on. The struct must describe a contiguous run of fields a layout can express: a gap, an overlap, a declared size its fields do not reach, or a field of a type no layout has is refused rather than decoded as something else. |

<a id="analysis-table-summarize"></a>

## `analysis.table.summarize`

Summarize a fixed-layout table's columns and compare them across several sources.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.table.summarize.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.table.summarize.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `layout` | `string` | no | — | Comma-separated field list, e.g. `u16,u16,ptr,char[16]`. Scalars are `u8`/`u16`/`u32` and their signed forms, `ptr` is a 32-bit pointer, `char[N]` a NUL-terminated Latin-1 string, `bytes[N]` raw bytes, and `pad[N]` skipped bytes. |
| `maximum_differences` | `integer` | no | `65536` | Cap on the rows listed per column where the sources disagree. `differing_total` beside the list is always exact. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_rows` | `integer` | no | `65536` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_values` | `integer` | no | `65536` | Cap on the distinct values listed per column. `distinct_total` beside the list is always exact. |
| `offset` | `integer` | no | `0` | Byte offset of the first record. |
| `rows` | `integer` | yes | — | How many records to read from each source. A region that holds fewer whole rows contributes the ones that fit and reports its true count. |
| `sources` | `array` | yes | — | The tables to summarize, each read with the same layout at the same offset. Naming several is the point: comparing one column across the memory several sandbox runs exported is the question this exists for. The order is part of the question — a comparison reports one value per table by position. |
| `type_id` | `string` | no | — | A `type:` id naming a struct the project defines, used instead of `layout`. The struct's fields are read back as a record layout, so a table saved as a resource decodes from the stored type alone — which is what `type_id` on a table resource has always meant and nothing could act on. The struct must describe a contiguous run of fields a layout can express: a gap, an overlap, a declared size its fields do not reach, or a field of a type no layout has is refused rather than decoded as something else. |

<a id="audio-sample-decode"></a>

## `audio.sample.decode`

Read an IFF 8SVX sample and summarize it with a bounded waveform envelope.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.sample.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.sample.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_buckets` | `integer` | no | `512` | How many min/max pairs the waveform envelope is reduced to. A few hundred is what a waveform is actually drawn at; more transfers detail nobody can see. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Byte offset of the IFF FORM within the source, for a sample carved out of a larger file. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="audio-sample-export"></a>

## `audio.sample.export`

Write an IFF 8SVX sample as a WAV file through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.sample.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.sample.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the WAV goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"sample.wav"` | File name within the destination: one relative path component. |
| `maximum_buckets` | `integer` | no | `512` | How many min/max pairs the waveform envelope is reduced to. A few hundred is what a waveform is actually drawn at; more transfers detail nobody can see. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Byte offset of the IFF FORM within the source, for a sample carved out of a larger file. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="compress-powerpacker-decode"></a>

## `compress.powerpacker.decode`

Decompress a headerless PowerPacker stream and report what it holds.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.powerpacker.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.powerpacker.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_output_bytes` | `integer` | no | `67108864` | Refuse a decompression before its decoded output would grow beyond this many bytes. |
| `modes` | `array` | yes | — | The four PowerPacker offset widths in bits, most significant first. Required and never guessed: a headerless stream stores them outside the data, so a wrong table decodes to plausible rubbish instead of failing. |
| `offset` | `integer` | no | `0` | Byte offset the packed stream starts at, for a stream embedded in a larger file. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="compress-powerpacker-export"></a>

## `compress.powerpacker.export`

Write a decompressed PowerPacker stream through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.powerpacker.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.powerpacker.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | no | — | Directory the decoded file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"decoded.bin"` | File name within the destination: one relative path component. Not derived from the source, because a packed stream says nothing about what it holds. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_output_bytes` | `integer` | no | `67108864` | Refuse a decompression before its decoded output would grow beyond this many bytes. |
| `modes` | `array` | yes | — | The four PowerPacker offset widths in bits, most significant first. Required and never guessed: a headerless stream stores them outside the data, so a wrong table decodes to plausible rubbish instead of failing. |
| `offset` | `integer` | no | `0` | Byte offset the packed stream starts at, for a stream embedded in a larger file. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="compress-rle-xor-decode"></a>

## `compress.rle-xor.decode`

Decompress a position-XOR marker-RLE stream and report what it holds.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.rle-xor.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.rle-xor.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `inline_marker` | `boolean` | no | `false` | Whether the stream carries its marker in its own first byte, with the size field and body after it. Two streams differing only in this decode to different bytes without either failing, which is why it is stated rather than sniffed. |
| `marker` | `integer` | yes | — | The escape byte that introduces a run. Stated even when `inline_marker` is set, where it becomes a cross-check: a recipe whose marker the stream contradicts is not the recipe that produced these bytes. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_output_bytes` | `integer` | no | `67108864` | Refuse a decompression before its decoded output would grow beyond this many bytes. |
| `offset` | `integer` | no | `0` | Byte offset the packed stream starts at, for a stream embedded in a larger file. |
| `size_bytes` | `0` \| `2` \| `4` | no | `0` | Width of the leading big-endian decoded-size field. Zero means the stream has none; the format uses no other widths. |
| `size_includes_field` | `boolean` | no | `false` | Whether that size field counts its own bytes as well as the output. Refused when `size_bytes` is zero: it would describe a field the request says is absent. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `xor` | `boolean` | no | `true` | Whether literal bytes are XOR-ed with their output position. |

<a id="compress-rle-xor-export"></a>

## `compress.rle-xor.export`

Write a decompressed position-XOR marker-RLE stream through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.rle-xor.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/compress.rle-xor.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | no | — | Directory the decoded file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"decoded.bin"` | File name within the destination: one relative path component. Not derived from the source, because a packed stream says nothing about what it holds. |
| `inline_marker` | `boolean` | no | `false` | Whether the stream carries its marker in its own first byte, with the size field and body after it. Two streams differing only in this decode to different bytes without either failing, which is why it is stated rather than sniffed. |
| `marker` | `integer` | yes | — | The escape byte that introduces a run. Stated even when `inline_marker` is set, where it becomes a cross-check: a recipe whose marker the stream contradicts is not the recipe that produced these bytes. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_output_bytes` | `integer` | no | `67108864` | Refuse a decompression before its decoded output would grow beyond this many bytes. |
| `offset` | `integer` | no | `0` | Byte offset the packed stream starts at, for a stream embedded in a larger file. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `size_bytes` | `0` \| `2` \| `4` | no | `0` | Width of the leading big-endian decoded-size field. Zero means the stream has none; the format uses no other widths. |
| `size_includes_field` | `boolean` | no | `false` | Whether that size field counts its own bytes as well as the output. Refused when `size_bytes` is zero: it would describe a field the request says is absent. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `xor` | `boolean` | no | `true` | Whether literal bytes are XOR-ed with their output position. |

<a id="audio-pcm-decode"></a>

## `audio.pcm.decode`

Read a raw 8-bit signed PCM region and summarize it with a bounded envelope.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.pcm.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.pcm.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `length` | `integer` | yes | — | Number of sample bytes. One byte per frame: this is 8-bit signed mono. |
| `maximum_buckets` | `integer` | no | `512` | How many min/max pairs the waveform envelope is reduced to. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | yes | — | Byte offset of the first sample. |
| `sample_rate` | `integer` | yes | — | Playback rate in Hz. Required and never guessed: raw Paula PCM has no header, so nothing in the bytes states it, and every consumer divides by it. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="audio-pcm-export"></a>

## `audio.pcm.export`

Write a raw PCM region as a WAV file through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.pcm.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.pcm.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"sample.wav"` | File name within the destination: one relative path component. |
| `length` | `integer` | yes | — | Number of sample bytes. One byte per frame: this is 8-bit signed mono. |
| `maximum_buckets` | `integer` | no | `512` | How many min/max pairs the waveform envelope is reduced to. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | yes | — | Byte offset of the first sample. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `sample_rate` | `integer` | yes | — | Playback rate in Hz. Required and never guessed: raw Paula PCM has no header, so nothing in the bytes states it, and every consumer divides by it. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="audio-module-decode"></a>

## `audio.module.decode`

Read a ProTracker/SoundTracker module and report its layout and sample slots.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.module.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.module.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Byte offset of the module's first byte. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="audio-module-export"></a>

## `audio.module.export`

Write a tracker module out as its own file through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.module.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.module.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"module.mod"` | File name within the destination: one relative path component. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Byte offset of the module's first byte. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-hunk-normalize"></a>

## `analysis.hunk.normalize`

Report what rewriting a one-file loader's compact relocations would produce.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.normalize.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.normalize.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-hunk-normalize-export"></a>

## `analysis.hunk.normalize.export`

Write a normalized HUNK image through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.normalize.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.normalize.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"normalized.exe"` | File name within the destination: one relative path component. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="provenance-manifest"></a>

## `provenance.manifest`

Report the name, size, and SHA-256 a provenance manifest would record.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/provenance.manifest.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/provenance.manifest.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="provenance-manifest-export"></a>

## `provenance.manifest.export`

Write a provenance manifest through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/provenance.manifest.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/provenance.manifest.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the file goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | `"manifest.json"` | File name within the destination: one relative path component. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-palette-decode"></a>

## `graphics.palette.decode`

Read a run of Amiga $0RGB colour words and report both encodings of each.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.palette.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.palette.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `count` | `integer` | yes | — | How many colour words to read. Capped at 256, which is the indexed-PNG format's ceiling. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Byte offset of the first colour word. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-palette-export"></a>

## `graphics.palette.export`

Draw a palette as a swatch PNG through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.palette.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.palette.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `block` | `integer` | no | `16` | Side of one swatch square, in pixels. |
| `columns` | `integer` | no | `8` | Swatches per row. |
| `count` | `integer` | yes | — | How many colour words to read. Capped at 256, which is the indexed-PNG format's ceiling. |
| `destination` | `string` | yes | — | Directory the swatch PNG goes in, as an identity the adapter resolves against its own output root. |
| `file_name` | `string` | no | `"palette.png"` | File name within the destination: one relative path component. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Byte offset of the first colour word. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="env-sandbox-run"></a>

## `env.sandbox.run`

Execute one CODE hunk under stated bounds and report how it stopped.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.run.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.run.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-boot-info"></a>

## `env.boot.info`

Report what a floppy's boot block declares about itself.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.boot.info.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.boot.info.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="env-sandbox-call"></a>

## `env.sandbox.call`

Invoke one routine to RTS and report a diffable input/output record.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.call.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.call.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-sandbox-call-export"></a>

## `env.sandbox.call.export`

Write a routine's golden record through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.call.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.call.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `destination` | `string` | yes | — | Directory the golden record goes in, as an identity the adapter resolves against its own output root. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `file_name` | `string` | no | `"golden.json"` | What the golden record is called inside the destination directory. A single component: the destination names the directory, and a name that could contain a separator would be deciding a second one. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-boot-trace"></a>

## `env.boot.trace`

Boot a floppy in a seeded Amiga and report the calls, writes, and reads it made.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.boot.trace.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.boot.trace.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-boot-trace-export"></a>

## `env.boot.trace.export`

Write a boot run's served track reads through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.boot.trace.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.boot.trace.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Directory the served track dumps go in, as an identity the adapter resolves against its own output root. A directory, unlike every other export here: a boot run serves however many reads it serves, and there is no single file to name. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="analysis-hunk-list"></a>

## `analysis.hunk.list`

List a LoadSeg image's hunks and the relocations between them.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.list.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.hunk.list.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_relocations` | `integer` | no | — | Cap on the relocations reported per hunk. Each hunk always reports its true total beside the capped list. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-strings-scan"></a>

## `analysis.strings.scan`

Find printable runs in a source and report where they sit.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.strings.scan.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.strings.scan.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `contains` | `string` | no | — | Report only strings holding this substring. Part of the request rather than something a caller applies afterwards: filtering a capped list would silently drop matches the scan found and the cap discarded. |
| `hunk` | `integer` | no | — | Scan only this hunk's bytes. Offsets are then relative to the hunk. Omitted, the whole file is scanned and never parsed — a data file that is not a HUNK executable is an ordinary thing to scan. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_strings` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `minimum_length` | `integer` | no | `4` | Shortest printable run to report. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-address-resolve"></a>

## `analysis.address.resolve`

Report one number in its absolute, hunk-relative, and whole-file frames.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.address.resolve.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.address.resolve.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `anchor` | `object` | no | — | Anchor the whole-file frame on a hunk's position in an image. Source and hunk travel together because neither means anything alone. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `origin` | `integer` | yes | — | The address the hunk is mapped at. An argument rather than something the operation reads: nothing in a LoadSeg image says where it was loaded, so this is the caller's claim about the machine. |
| `value` | `integer` | yes | — | The number to interpret. Which frame it came from is the question, so every reading of it is answered. |

<a id="analysis-pointers-scan"></a>

## `analysis.pointers.scan`

Find runs of plausible in-hunk pointers and report what they address.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.pointers.scan.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.pointers.scan.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `hunk` | `integer` | no | `0` | Hunk to scan. |
| `maximum_entry_offsets` | `integer` | no | — | Cap on the derived entry offsets. Its own bound rather than the target cap's: the targets are what a table shows and the entry offsets are what a caller analyzes from, so narrowing the display must not narrow the analysis. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_tables` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_targets` | `integer` | no | — | Cap on the targets reported per table. Each table always reports its true total and its full span beside the capped list. |
| `minimum_entries` | `integer` | no | `3` | Consecutive plausible entries a run needs before it counts as a table. Three by default: two in-range longwords in a row happen by accident in ordinary data and three do so far less often. |
| `origin` | `integer` | no | `0` | The address the hunk is mapped at. A target is plausible when it lands inside `[origin, origin + hunk bytes)`, so this is the claim the scan tests. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `word_scale` | `integer` | no | — | Read unsigned words scaled by this factor and added to the origin, instead of absolute longwords. A scale of zero is refused — it would decode every word to the origin. |

<a id="analysis-code-disassemble"></a>

## `analysis.code.disassemble`

Decode a CODE hunk or pinned raw image, by sweep or control flow.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.disassemble.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.disassemble.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `end` | `integer` | no | — | Linear mode: where the sweep stops. Defaults to the end of the hunk. |
| `entries` | `array` | no | — | Flow mode: where the traversal starts, as offsets within the selected code region. Defaults to offset 0 — an empty list would traverse nothing and report an image with no code in it. |
| `expected_sha256` | `string` | no | — | Required for raw code: the exact digest the source must have before any instruction is decoded. |
| `hunk` | `integer` | no | `0` | CODE hunk to disassemble when `region` is `hunk`. A hunk that is not CODE is refused by name rather than decoded into a plausible listing of something that is not code. |
| `maximum_edges` | `integer` | no | — | Cap on each edge list and on the unreached runs. Every list reports its true total beside the capped one. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_instructions` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `mode` | `linear` \| `flow` | no | `"linear"` | `linear` decodes every word in a range whether or not anything reaches it; `flow` follows control flow from the entry points and reports what it did not reach. |
| `origin` | `integer` | no | — | The address the selected code region is mapped at. With one, every instruction also reports the address the MC68000 would fetch it from, and the traversal resolves absolute operands through it. |
| `region` | `hunk` \| `raw` | no | `"hunk"` | Where the code lives. Raw code must be pinned by digest so format detection can never turn arbitrary bytes into an implicit executable. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `start` | `integer` | no | `0` | Linear mode: where the sweep starts, as a hunk offset. Must be even — an MC68000 fetches instructions on word boundaries. |

<a id="analysis-address-references"></a>

## `analysis.address.references`

Report the addresses a hunk's code names, or the sites that name one address.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.address.references.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.address.references.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `entries` | `array` | no | — | Where the traversal starts, as hunk offsets. Defaults to offset 0. |
| `hunk` | `integer` | no | `0` | CODE hunk whose instructions are examined. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_references` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. With one, a PC-relative target also reports the runtime address it names. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `target` | `integer` | no | — | Report only references naming this address. Naming one also brings in the image's relocations, because a stored pointer is a reference too; without one there is nothing to match a relocation against, and the full list is `analysis.hunk.list`'s answer already. |

<a id="analysis-code-callgraph"></a>

## `analysis.code.callgraph`

Reduce a CODE hunk's control flow to its functions and the calls between them.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.callgraph.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.callgraph.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `entries` | `array` | no | — | Where the traversal starts, as hunk offsets. Defaults to offset 0. |
| `hunk` | `integer` | no | `0` | CODE hunk to analyze. |
| `maximum_edges` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_nodes` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. With one, every node also reports the runtime address of its entry. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-code-globals"></a>

## `analysis.code.globals`

Map the base-relative, absolute, and derived accesses a hunk's code makes.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.globals.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.globals.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `base_register` | `integer` | no | `5` | Address register the small-data convention uses. A5 by convention, and the convention is what makes a displacement from it a global rather than an arbitrary offset from an arbitrary pointer. |
| `derived` | `boolean` | no | `false` | Also resolve indirect accesses through propagated address registers. Off by default: it is an extra pass over straight-line code, and nobody should pay for it unless they asked. |
| `entries` | `array` | no | — | Where the traversal starts, as hunk offsets. Defaults to offset 0. |
| `hunk` | `integer` | no | `0` | CODE hunk to analyze. |
| `maximum_accesses` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. Absolute accesses cannot be identified without it — "inside the image" has no meaning until the image has a place — so that list is empty rather than guessed at. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="analysis-code-fixed-point"></a>

## `analysis.code.fixed-point`

Report fixed-point multiply and divide idioms, saturating clamps, and Q scales.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.fixed-point.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.fixed-point.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `entries` | `array` | no | — | Where the traversal starts, as hunk offsets. Defaults to offset 0. |
| `hunk` | `integer` | no | `0` | CODE hunk to analyze. |
| `maximum_hints` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="container-lha-list"></a>

## `container.lha.list`

List an LHA archive's members and the method each is stored with.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.lha.list.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/container.lha.list.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_members` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="hardware-register-list"></a>

## `hardware.register.list`

Report the custom-chip register map this build knows.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.register.list.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.register.list.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|

<a id="audio-pcm-scan"></a>

## `audio.pcm.scan`

Find runs of bytes that score like raw 8-bit signed PCM.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.pcm.scan.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.pcm.scan.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `block` | `integer` | no | `1024` | Block size in bytes used to score the image. At least 2: a single byte has no step between samples to measure, and smoothness is the statistic that separates a waveform from noise. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_regions` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `minimum_length` | `integer` | no | `2048` | Shortest merged region to report, in bytes. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="audio-module-scan"></a>

## `audio.module.scan`

Find tracker modules by signature and report what each declares.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.module.scan.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/audio.module.scan.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_modules` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-palette-scan"></a>

## `graphics.palette.scan`

Find runs of $0RGB colour words that score as palette tables.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.palette.scan.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.palette.scan.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_tables` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `minimum_colours` | `integer` | no | `8` | Shortest run to report as a table. At least 2: a single $0RGB word is one byte pair in sixteen and not a table. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="hardware-copper-scan"></a>

## `hardware.copper.scan`

Find plausible Copper lists and the palettes and pointers each carries.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.copper.scan.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.copper.scan.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_lists` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="hardware-copper-decode"></a>

## `hardware.copper.decode`

Decode a Copper stream instruction by instruction from an offset.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.copper.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.copper.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_instructions` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `offset` | `integer` | no | `0` | Byte offset the stream starts at. Nothing in an image marks a Copper list, so this is a claim about the bytes rather than something read from them. Must be even — a Copper instruction begins on a word boundary. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-ilbm-decode"></a>

## `graphics.ilbm.decode`

Describe an ILBM form: geometry, masking, viewport mode, and palette.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.ilbm.decode.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.ilbm.decode.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="graphics-bitmap-detect"></a>

## `graphics.bitmap.detect`

Score a region's entropy and row strides to suggest a bitmap's geometry.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.detect.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.detect.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `block` | `integer` | no | `4096` | Block size the entropy map scores in. At least 1: entropy over no bytes is undefined. |
| `length` | `integer` | no | — | How much of it to examine. Without a length the entropy map still runs, but the stride search does not: autocorrelation over an unbounded tail measures whatever follows the bitmap as much as the bitmap. |
| `maximum_blocks` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_stride` | `integer` | no | `512` | Largest row stride the search considers. |
| `maximum_strides` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `offset` | `integer` | no | `0` | Where the examined region starts. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="hardware-register-references"></a>

## `hardware.register.references`

Report every custom-chip register a hunk's code touches, and how.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.register.references.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.register.references.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `entries` | `array` | no | — | Where the traversal starts, as hunk offsets. Defaults to offset 0. |
| `hunk` | `integer` | no | `0` | CODE hunk to analyze. |
| `maximum_accesses` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="hardware-copper-references"></a>

## `hardware.copper.references`

Trace the CPU writes that patch a runtime copy of a Copper list.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.copper.references.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/hardware.copper.references.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `apply` | `boolean` | no | `false` | Also apply every immediate write and report the resulting list. |
| `entries` | `array` | yes | — | The patch routine's entry, as hunk offsets. Required: the pointer register's value is read at the entry, so without one the writes have no origin to be measured from, and assuming offset zero would measure them from the wrong place. |
| `hunk` | `integer` | no | `0` | CODE hunk holding the patch routine. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_instructions` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_writes` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. |
| `pointer_register` | `integer` | yes | — | Address register holding the runtime copy's base. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `template` | `object` | no | — | Where the Copper list lives. Its own source, because a loader routinely copies a template out of one file and patches the copy. An absent source means the same one the code came from. |

<a id="project-describe"></a>

## `project.describe`

Summarize a project: its sources, objects, programs, and counts.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.describe.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.describe.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|

<a id="project-annotations"></a>

## `project.annotations`

Report a project's reviewed knowledge about one image or one object.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.annotations.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.annotations.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | `string` | no | — | Which of the project's images to resolve against, in hunk space. An offset means nothing until you say which image it is an offset into. |
| `maximum_locations` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `object` | `string` | no | — | Which of the project's objects to list annotations for, in file space. A project created by `project.init` has objects and no image at all, so this is the scope that answers for one. |

<a id="project-inventory"></a>

## `project.inventory`

Walk a directory and report the inventory a directory source would pin.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.inventory.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.inventory.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `directory` | `string` | yes | — | Resolver-relative identity of the directory to walk. An argument rather than the envelope's project locator, because the thing being inventoried is media — the tree a directory source would pin — and not a project. |
| `maximum_files` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |

<a id="project-edit"></a>

## `project.edit`

Apply reviewed changes to a project's annotations through a plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.edit.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.edit.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `edits` | `array` | yes | — | Applied together: one plan, one set of expected digests, one commit. Splitting them into separate requests would let a document change between two edits that were meant to land as a unit. A plan that removes an annotation another one is about is refused rather than cascaded, unless it removes that one too. |

<a id="project-format"></a>

## `project.format`

Bring every document a project names into canonical form.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.format.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.format.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|

<a id="analysis-code-facts"></a>

## `analysis.code.facts`

Compose every code analysis into one fact list, with the instructions it is about.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.facts.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.code.facts.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `base_register` | `integer` | no | `5` | Address register the small-data convention uses. A5 by convention, and the convention is what makes a displacement from it a global rather than an arbitrary offset from an arbitrary pointer. |
| `default_library` | `string` | no | — | The library initially in A6. Defaults to `exec` for a boot block, which the machine guarantees — the fact model is told rather than left to infer it from code that never opens exec. |
| `entries` | `array` | no | — | Where the traversal starts, as offsets within the selected code region. Defaults to offset 0. Every fact is about code some entry reaches, so an entry list that misses a routine produces no facts about it rather than wrong ones. |
| `expected_sha256` | `string` | no | — | Required for raw code: the exact digest the source must have before any instruction is decoded. |
| `hunk` | `integer` | no | `0` | CODE hunk to analyze. Omit for `boot_block` and `raw`, which have no hunks. |
| `library_vectors` | `array` | no | — | Extra vectors, consulted before this build's curated tables. The tables travel as data, never as a path: a frontend reads its own fd files and puts the entries here, so two adapters given the same table get the same facts. |
| `maximum_facts` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_instructions` | `integer` | no | — | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `origin` | `integer` | no | — | The address the hunk is mapped at. Nothing in a LoadSeg image says where it was loaded, so this is the caller's claim about the machine: absolute references cannot be identified without one, and are left unresolved rather than guessed at. |
| `region` | `hunk` \| `boot_block` \| `raw` | no | `"hunk"` | Where the code lives. A boot block and a raw project image are not hunks, and the same question is asked of all three — one selector rather than separate fact models. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="source-read"></a>

## `source.read`

Read a window of a source's bytes, with the relocations inside it.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/source.read.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/source.read.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `hunk` | `integer` | no | — | Read out of this hunk's bytes rather than the whole file. Naming one does the thing a raw file read cannot: it reports which offsets inside the window a relocation sits at. Omitted, the file is never parsed — a data file is an ordinary thing to look at. |
| `length` | `integer` | no | `256` | How many bytes the window holds. A window running past the end is reported short rather than refused — the tail of a file is an ordinary place to look, and refusing would make the last screen of every file unviewable. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `offset` | `integer` | no | `0` | Where the window starts, in whichever frame `hunk` selected: within that hunk's bytes when one is named, and within the file otherwise. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |

<a id="project-init"></a>

## `project.init`

Create a project document set from chosen source files, through a plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.init.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.init.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `string` | yes | — | Where the project is created, as an identity the adapter resolves against its own output root. Never a host path. |
| `maximum_input_bytes` | `integer` | no | — | Per-source ceiling. The aggregate ceilings — source count, total input bytes — are the context's and are not request-settable, because they exist to bound what a caller asks for. |
| `media` | `copy` \| `in_place` | no | `"copy"` | `copy` puts each source under the project's `original/` directory, making the project self-contained. `in_place` leaves it where it is: under the root it gets a project-relative location, outside it a `.amiga-re/local.json` binding that is true on this machine only. There is no third option, because a source with neither verifies as unbound next session. |
| `name` | `string` | yes | — | The project's display name. Its id is derived from this. |
| `sources` | `array` | yes | — | The files to register, as identities the resolver resolves. Each becomes a source with its size and digest pinned, and a whole-file object — an object with no selector would verify as unrecoverable. |

<a id="project-extract"></a>

## `project.extract`

Extract a project's registered carriers into it, through a plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.extract.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.extract.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_input_bytes` | `integer` | no | — | Per-source ceiling. The aggregate ceilings — objects, total recovered bytes — are the context's. |
| `sources` | `array` | no | — | Which registered sources to extract. Omitted or empty means every one of them, which is what makes a five-disk project one decision rather than five. |

<a id="project-resource-export"></a>

## `project.resource.export`

Produce a resource's file from the project alone, and record that it exists.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.resource.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/project.resource.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | — | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `resource` | `string` | yes | — | The resource to produce. Deliberately the only argument: the bytes, the recipe, the encoding and the destination are all already in the project, and a caller that could pass a width or an extension could produce a file the record claiming to reproduce it does not describe. |

<a id="env-sandbox-matrix"></a>

## `env.sandbox.matrix`

Run a named set of sandbox calls that share one recipe and vary its inputs.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.matrix.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.matrix.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `cases` | `array` | yes | — | The cases, in the order they run and are reported. Every field but `name` is an override; absent means "as the shared recipe has it", which is what makes a case readable as a difference rather than as a whole recipe repeated. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_cases` | `integer` | no | — | Cap on expanded cases. Clamped by the context, with LIMIT_REDUCED. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_total_steps` | `integer` | no | — | Instructions the whole matrix may execute. Separate from the per-case budget and not its multiple: a case is never clipped to what is left, it either runs with the budget it asked for or is reported as not run. Defaults to one run's budget, which is deliberately conservative. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-sandbox-compare"></a>

## `env.sandbox.compare`

Compare golden call records by what they were given and what they did.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.compare.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.compare.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_differences` | `integer` | no | — | Cap on the differences of each kind that are listed. The true totals are always reported. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `records` | `array` | yes | — | The golden records to compare, in the order they are reported. At least two: one compared against nothing has no answer. The order is part of the question — a difference reports one value per record positionally. |

<a id="env-sandbox-matrix-export"></a>

## `env.sandbox.matrix.export`

Write each case of a sandbox sweep's exported ranges through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.matrix.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.matrix.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `cases` | `array` | yes | — | The cases, in the order they run and are reported. Every field but `name` is an override; absent means "as the shared recipe has it", which is what makes a case readable as a difference rather than as a whole recipe repeated. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `destination` | `string` | yes | — | Directory the golden record goes in, as an identity the adapter resolves against its own output root. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `file_name` | `string` | no | `"golden.json"` | What the aggregate result is written as. Defaults to `matrix.json`. Each case's exported ranges go under `<case>/<range>`, which is why a case name is validated as one path component. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_cases` | `integer` | no | — | Cap on expanded cases. Clamped by the context, with LIMIT_REDUCED. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_total_steps` | `integer` | no | — | Instructions the whole matrix may execute. Separate from the per-case budget and not its multiple: a case is never clipped to what is left, it either runs with the budget it asked for or is reported as not run. Defaults to one run's budget, which is deliberately conservative. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-sandbox-timeline"></a>

## `env.sandbox.timeline`

Run a sequence of sandbox steps over one evolving machine state.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.timeline.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.timeline.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_total_steps` | `integer` | no | — | Instructions the whole timeline may execute. Separate from a step's own budget and not its multiple: a step is never clipped to what is left, it either runs with the budget it asked for or is reported as not run. Defaults to one run's budget, which is deliberately conservative. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the memory the whole timeline leaves behind, each under a name. A step's own `checkpoints` are the same thing recorded as that step left it. The result digests each range; a range that is not mapped refuses the timeline before any step runs. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `steps` | `array` | yes | — | The steps, in the order they run and are reported. Each one either enters a routine with `entry_offset` or continues the previous step's machine with `resume`. Once a step is refused or does not run, no step after it runs either: the order is the experiment, and a later step continuing a machine that skipped its predecessor would be a different timeline reported under this one's name. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="analysis-state-snapshot"></a>

## `analysis.state.snapshot`

Decode a machine's memory through a project's reviewed types and globals.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.state.snapshot.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.state.snapshot.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `hunk_bases` | `array` | no | — | Where each hunk was mapped, for a variable targeting a hunk offset. The layout is the run's rather than the project's, and a snapshot decoded against a different one would name the right variable at the wrong address. |
| `image` | `string` | no | — | Which of the project's images the variables belong to. Omitted, the project's only image — and a project with more than one is refused rather than having one picked for it, because the wrong choice produces a complete, plausible snapshot of the wrong program. |
| `maximum_fields` | `integer` | no | `4096` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `regions` | `array` | yes | — | The machine's memory, as ranges of bytes at absolute addresses — typically what `call --save` wrote. A variable whose storage no range covers is a refusal naming it: a snapshot that quietly omitted a field would compare cleanly against one that had it and read as agreement. Ranges are never stitched across a seam: two files that happen to abut are two files, and a value read across the boundary would be half of each with nothing saying so. |
| `registers` | `object` | no | — | The register file the snapshot was taken with — the shape a call record reports its outputs in, because that is where a caller pastes it from. A base-register global's address is a register plus a displacement, so a project holding any is refused without this rather than read at whatever zero points at. |

<a id="analysis-state-compare"></a>

## `analysis.state.compare`

Compare state snapshots field by field.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.state.compare.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/analysis.state.compare.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `maximum_differences` | `integer` | no | `256` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `snapshots` | `array` | yes | — | The snapshot documents to compare, in the order they are reported. At least two: comparing one against nothing has no answer. One of them may have been written by something other than this toolkit — a clean-room implementation stating its own state in the same shape is the case this exists for. |

<a id="env-frame-capture"></a>

## `env.frame.capture`

Reconstruct the frame the display hardware would have shown after a run.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.frame.capture.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.frame.capture.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | yes | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_pixels` | `integer` | no | — | Pixels the reconstructed frame may hold. The geometry comes from registers a half-initialized run may have left at anything, so the bound is on the answer rather than on the request. Defaults to 128000 and is clamped to 4194304. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `until_raster_line` | `integer` | no | — | Run until the beam reaches this raster line, instead of to the step budget. The beam is derived from the instruction counter, so a raster line *is* an instruction count: line n is reached after n*227 instructions. That is why this is expressible without a hook in the run loop, and why it is exactly reproducible — the same recipe stops at the same instruction on every machine. Stated together with maximum_steps, whichever comes first wins. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-frame-capture-export"></a>

## `env.frame.capture.export`

Write a captured frame as indexed and RGBA PNGs through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.frame.capture.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.frame.capture.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | yes | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `destination` | `string` | yes | — | Directory the golden record goes in, as an identity the adapter resolves against its own output root. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `file_name` | `string` | no | `"golden.json"` | What the indexed PNG is called. The RGBA image and the manifest are named from it, so one name decides all three. Defaults to frame.png. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_pixels` | `integer` | no | — | Pixels the reconstructed frame may hold. The geometry comes from registers a half-initialized run may have left at anything, so the bound is on the answer rather than on the request. Defaults to 128000 and is clamped to 4194304. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `until_raster_line` | `integer` | no | — | Run until the beam reaches this raster line, instead of to the step budget. The beam is derived from the instruction counter, so a raster line *is* an instruction count: line n is reached after n*227 instructions. That is why this is expressible without a hook in the run loop, and why it is exactly reproducible — the same recipe stops at the same instruction on every machine. Stated together with maximum_steps, whichever comes first wins. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="graphics-bitmap-compare"></a>

## `graphics.bitmap.compare`

Compare two decoded images in palette-index space and in colour space.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.compare.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.compare.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `a` | `object` | yes | — | Image a. |
| `b` | `object` | yes | — | Image b. |
| `crop` | `object` | no | — | The rectangle compared, in the first image's coordinates. Omitted, the whole of it. Differing dimensions are refused rather than resampled — a resampler's rounding would be reported as a difference in the picture — so a crop is how two images of different sizes are made comparable. |
| `mask` | `object` | no | — | A reviewed mask saying which pixels are worth comparing: one byte per pixel of the compared rectangle, zero to exclude. Pinned by digest, unlike either image, because a mask decides what the comparison ignores — an unpinned one could turn a failing comparison into a passing one and leave nothing in the record to say it had. |
| `maximum_entries` | `integer` | no | `256` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |

<a id="graphics-bitmap-compare-export"></a>

## `graphics.bitmap.compare.export`

Write a comparison's heatmap and overlay through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.compare.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/graphics.bitmap.compare.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `a` | `object` | yes | — | Image a. |
| `b` | `object` | yes | — | Image b. |
| `crop` | `object` | no | — | The rectangle compared, in the first image's coordinates. Omitted, the whole of it. Differing dimensions are refused rather than resampled — a resampler's rounding would be reported as a difference in the picture — so a crop is how two images of different sizes are made comparable. |
| `destination` | `string` | yes | — | Directory the PNG goes in, as an identity the adapter resolves against its own output root. Relative, normal components only. |
| `file_name` | `string` | no | — | What the heatmap is called. The overlay and the manifest are named from it, so one name decides all three. Defaults to heatmap.png. |
| `mask` | `object` | no | — | A reviewed mask saying which pixels are worth comparing: one byte per pixel of the compared rectangle, zero to exclude. Pinned by digest, unlike either image, because a mask decides what the comparison ignores — an unpinned one could turn a failing comparison into a passing one and leave nothing in the record to say it had. |
| `maximum_entries` | `integer` | no | `256` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |

<a id="env-sandbox-slice"></a>

## `env.sandbox.slice`

Follow one value backwards through the instructions that produced it.

- Access class: `read_only`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.slice.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.slice.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_depth` | `integer` | no | `256` | Maximum dependency depth followed backwards from the seed. Reaching the bound reports depth_reached in the slice stops; it does not establish the size of the unexplored chain. |
| `maximum_entries` | `integer` | no | `512` | Maximum defining instruction steps retained by the slice walk. Reaching the bound reports steps_reached and sets steps_truncated; steps_total counts encountered definitions, not the size of the unexplored dependency graph. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the sandbox's final memory the recipe names as artifacts. The record digests each one; `env.sandbox.call.export` writes their bytes beside the record. A range not fully mapped is refused rather than exported short. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `seed` | `object` | yes | — | What the slice is asked to explain. A closed union rather than three optional fields: a slice with two seeds would have two answers, and one with none would have no question. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |

<a id="env-sandbox-timeline-export"></a>

## `env.sandbox.timeline.export`

Write each step of a sandbox timeline's checkpointed ranges through a reviewed write plan.

- Access class: `prepared_output`
- Request schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.timeline.export.request.schema.json`
- Response schema: `https://amiga-re.invalid/schemas/operations/v1/operations/env.sandbox.timeline.export.response.schema.json`

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `address_registers` | `array` | no | — | Initial A0-A6. |
| `custom_chips` | `object` | no | — | Model the custom chips at $DFF000 rather than leaving that range to be whatever mapped_regions made of it. An empty object means an emulating OCS blitter with the defaults, so one request cannot be spelled two ways that mean two things. Naming this refuses any mapping that overlaps $DFF000..$DFF200: RAM and the chips cannot both answer an address. |
| `data_registers` | `array` | no | — | Initial D0-D7. |
| `destination` | `string` | yes | — | Directory the golden record goes in, as an identity the adapter resolves against its own output root. |
| `entry_offset` | `integer` | no | `0` | Byte offset within the hunk to start at. |
| `file_name` | `string` | no | `"timeline.json"` | What the aggregate result is written as. The per-step files are named `<step>/<checkpoint>` beside it, and the manifest is named from this. Defaults to timeline.json. |
| `hunk` | `integer` | no | — | Which CODE hunk to run. Defaults to the first. |
| `hunk_bases` | `array` | no | — | Additional hunks to map, for relocations that target them. A hunk relocated into but not mapped is an error, not a silent skip: the code would run with an address that means nothing and the trace would not say so. |
| `interrupts` | `array` | no | — | Interrupts delivered on a deterministic instruction schedule. Setup code commonly sets a synchronization flag and spins until an interrupt handler clears it; the beam counter advances on its own, but nothing runs the handler, so otherwise valid initialization never returns. The schedule is in instructions rather than in beam or wall-clock time because that is the one clock a sandbox reproduces exactly. |
| `load_origin` | `integer` | no | — | Absolute address the selected hunk is mapped at. |
| `mapped_regions` | `array` | no | — | Regions the routine reads or writes, beyond the hunks it runs in. |
| `maximum_input_bytes` | `integer` | no | `67108864` | Refuse the source outright when it is larger than this. A prefix is never surveyed in place of the whole. |
| `maximum_steps` | `integer` | no | `100000` | Instructions to execute before stopping. Clamped to what the executing context allows — 200000 by default, and at most 50000000 for a host running local media it has reviewed. Sandbox code is unknown code, and a request for an unbounded run would be asking the process to hang, so the budget is always finite. A reduction is reported as LIMIT_REDUCED. |
| `maximum_total_steps` | `integer` | no | — | Instructions the whole timeline may execute. Separate from a step's own budget and not its multiple: a step is never clipped to what is left, it either runs with the budget it asked for or is reported as not run. Defaults to one run's budget, which is deliberately conservative. |
| `maximum_trace_rows` | `integer` | no | `20000` | Cap a reported collection at this many entries. The response always reports the true total beside the capped list. |
| `memory_exports` | `array` | no | — | Ranges of the memory the whole timeline leaves behind, each under a name. A step's own `checkpoints` are the same thing recorded as that step left it. The result digests each range; a range that is not mapped refuses the timeline before any step runs. |
| `memory_seeds` | `array` | no | — | Bytes written into the sandbox before entry. Each seed spells its bytes out as `hex`, copies them from a range with `from`, or replays them from a pinned `artifact` — exactly one of the three, since a seed with two would have two answers to what it seeds and one with none would seed nothing while looking like it seeded something. |
| `policy` | `create_only` \| `replace_matching_provenance` \| `replace_explicit_generated` | no | `"create_only"` | What may happen to a destination that already exists. `create_only` is the default and the only one under which no existing bytes can be lost. |
| `source` | `object` | yes | — | How a caller names one input source: a whole file, or bytes recovered from inside one. A `member` names its container as a locator of its own, so a chain — a PowerPacked file inside an LHA member inside an ADF — is three selectors rather than a special case. The pin an operation reports covers the recovered bytes, not the container's: that is what it read. |
| `stack` | `object` | no | — | Where the stack lives. Omitted, it is placed above the hunk with an unmapped gap, so a runaway stack faults instead of quietly overwriting the code being run. |
| `stack_arguments` | `array` | no | — | Longwords placed above the return marker: at entry SP holds the marker and SP+4 is the first argument, as a JSR would leave them. |
| `steps` | `array` | yes | — | The steps, in the order they run and are reported. Each one either enters a routine with `entry_offset` or continues the previous step's machine with `resume`. Once a step is refused or does not run, no step after it runs either: the order is the experiment, and a later step continuing a machine that skipped its predecessor would be a different timeline reported under this one's name. |
| `stop_on_watch` | `boolean` | no | `false` | Stop at the first instruction that touches a watched range. |
| `trace` | `boolean` | no | `false` | Whether to return the per-instruction trace. Watching implies recording even without this, or a watch hit would stop the run with nothing to point at. |
| `watch` | `array` | no | — | Absolute ranges whose accesses are attached to trace rows. At most 64: every watched range is compared against every memory access, so the list is a per-access cost rather than a per-request one. An excess is refused rather than truncated, because a dropped watchpoint would make a run that observed nothing indistinguishable from one that had nothing to observe. |
