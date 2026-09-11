# `amiga-operations` contract fixtures

Synthetic, redistributable request/response documents for the operations this
crate implements. Every hash is a real digest, and the tests under `tests/`
execute each request and compare its serialized response to the recorded document.
Canonical schemas live in `crates/amiga-operations/schemas/`; executable coverage
for reviewed extraction, multi-source bitmap appearance, conflicts, event framing,
and capped results lives in the crate's integration tests.

Regenerate binary inputs with `python3 crates/amiga-operations/fixtures/build-media.py`.
The generator defines all strings, RGB4 words, OFS block fields, and the LCG seed
and recurrence. `--check` regenerates into a temporary directory and compares both
files byte-for-byte without modifying the fixtures.

Regenerate after auditing a deliberate change:

```bash
UPDATE_GOLDEN=1 cargo test -p amiga-operations
```

| File | What it is |
|------|------------|
| `sample.bin` | 336 synthetic bytes: three neutral printable runs, a 16-entry `$0RGB` table, and a high-entropy tail from a fixed linear congruential generator. Contains no third-party data. |
| `source.survey.request.json` | A read-only operation on a loose file: no project, explicit bounds, a source named relative to the resolver's own root |
| `source.survey.response.json` | The typed result, with the pinned source hash, the normalized-request digest, and a `region_total` / `regions_truncated` pair so a capped list can never read as a complete one |
| `volume.adf` | A 20-block synthetic OFS volume: a directory, two files, one file declared empty that still holds a data pointer, and a deliberately invalid boot-block checksum. Both inconsistencies are recovered and reported, which is what makes the warning path testable. Contains no third-party data. |
| `container.adf.list.request.json` | The minimal request — nothing but a source locator |
| `container.adf.list.response.json` | The volume, its entries with canonical `/`-separated volume-relative paths, an `entry_total` / `entries_truncated` pair, and tolerated corruption surfaced as `warning` diagnostics carrying the block they concern |

Each request names its source relative to the resolver's root — `fixtures/sample.bin`,
never a host path — and the tests supply the crate directory as that root. The
split is the point: a request document must mean the same thing on another
machine.

The exact `volume.adf` path is allowed by `.gitignore`. Other disk images in a
fixture directory remain private. `tests/fixtures.rs` checks required inputs;
CI also checks byte-for-byte binary regeneration.
