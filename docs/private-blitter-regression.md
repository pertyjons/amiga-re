# Private blitter regression recipes

Set `AMIGA_RE_BLIT_RECIPE` to a JSON file and run:

```bash
cargo test -p amiga-operations --test blitter_regression -- --nocapture
```

The optional media test skips when this variable is absent. A configured but
missing/malformed input fails. Keep private recipes and media under `original/`.
The harness reads at most 1 MiB of recipe JSON and 64 MiB of source bytes across
at most 16 sources, then executes under the operation API's bounded context.

The document has four fields:

- `version`: `1`; other recipe versions are refused.
- `sources`: an array of `{ "name": "program", "path": "input.hunk", "sha256": "..." }`.
  Names match file locators in the request. Paths resolve relative to the recipe
  directory; each source is checked against its SHA-256 before execution.
- `request`: the complete version-1 request envelope for `env.sandbox.call`.
  Use the installed operation schema or the CLI schema command for its vocabulary.
  Supply `load_origin` and `maximum_steps` explicitly. The request carries hunk
  mappings, RAM regions, seeds, registers, stack, interrupts, chip configuration,
  and named memory exports. All source bytes come from the pinned `sources` set.
- `expected_exports`: an object mapping every export name to the independently
  reviewed SHA-256 of its complete bytes. Missing or extra names are refused.

The harness requires the routine to return and execute at least one blit without
refusals, then checks each named export's address, length, and digest. A count of
blits alone cannot pass. Output pins must come from independent verification,
not from blindly accepting a new emulator result.

The integration suite builds two complete synthetic recipes in different memory
maps and checks their hand-computed bitmap bytes. Those tests exercise the same
JSON and verification path; they do not replace a media-backed regression.
