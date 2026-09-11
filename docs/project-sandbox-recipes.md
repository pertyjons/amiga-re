# Deriving project objects with sandbox recipes

A `sandbox_export` object is one named final-memory export from a bounded
`env.sandbox.call`. Its parent holds an immutable recipe document; its `inputs`
map names the checksum-verified sources or objects that the call reads.
`project verify` executes the call and checks the export's size and SHA-256.
No saved RAM dump is needed to reproduce the object.

## Freeze the execution recipe

Build a complete version-1 `env.sandbox.call` request using the existing
operation schema. Name its files with recipe-local identities such as `program`
and `seed`, rather than host paths. Supply `hunk`, `load_origin`, `entry_offset`,
`stack`, and `maximum_steps` explicitly. Registers, memory seeds, scheduled
interrupts, mapped RAM, custom chips, and named memory exports use the ordinary
sandbox request vocabulary.

Freeze the request using `amiga_operations::sandbox_recipe::SandboxRecipe::new`
and serde. The repository also provides a small stdin/stdout adapter:

```bash
cargo run -p amiga-operations --example freeze_sandbox_recipe \
  < decoded/call.request.json > decoded/call.recipe.json
```

The recipe records `recipe_version: 1`, `execution_version: 1`, the complete
request, and `normalized_request_sha256`. That digest binds resolved defaults:
a replay whose normalization changes is refused, including a context limit that
would shorten the requested execution. The existing operation schemas remain
the sole execution vocabulary; `sandbox-recipe.schema.json` references them.
Serialize the recipe through the supplied type. Replay rejects unknown fields
and spellings that do not round-trip through that type.

Execution version 1 means the current bounded MC68000 call environment and OCS
chip model. An incompatible change to CPU, chip, interrupt, initial-state, or
return semantics requires a new execution version. Unsupported versions and
features fail explicitly. A golden result is evidence about a run and is not
accepted as a recipe.

## Register the recipe and its inputs

Register the recipe file as a source with its exact byte size and SHA-256. Its
location is a project-relative hint, and the pin is its identity. Register or
derive the executable and any seed files separately. The executable must be a
HUNK image supplied as a direct input; extract container members as project
objects before using them. Raw-code wrapping, if needed, must be reproducible
and documented separately with original and wrapped checksums.

For example, an object's fields include:

```json
{
  "id": "object:picture",
  "kind": "sandbox_export",
  "parent_id": "source:draw-recipe",
  "selector": {
    "container": "sandbox",
    "export": "bitmap.bin",
    "inputs": {
      "program": "object:executable",
      "seed": "source:initial-state"
    }
  }
}
```

Also supply the object's required `size` and `sha256`, established by reviewing
its expected output. Do not blindly promote an emulator result to an expected
pin. Several objects may select different exports of the same recipe. Names
identify exports across relocation; addresses only select memory within one
particular run. A RAM-transformed result is never a `range` selector.

The project validator checks every input edge, including cycles through an
input rather than the parent. Verification supplies bytes only after their
pins hold. Missing or corrupted inputs prevent execution, and the in-memory
resolver never falls back to host files. A sandbox selector cannot be used as
an ordinary container-member locator, since that would bypass the project's
verified dependency graph. Captures without a complete replay recipe remain
`captured` sources.

## Bounds and verification

One recipe document is at most 1 MiB, with 1–16 input bindings and at most
64 MiB of total input bytes, additionally constrained by the operation context.
The sum of all HUNK allocations, additional RAM, and the explicit stack is
limited to 64 MiB before execution. All declared exports together must fit the
context's output-byte budget. A non-returning call, missing export, execution
diagnostic, or output mismatch refuses verification; warnings are not silently
accepted as successful derivations.

A `ContainerRecovery` instance shares its instruction budget across calls,
reserving each call's requested maximum before execution. It retains only the
last successful recipe's exports, bounded by the output budget, so consecutive
objects selecting the same recipe need one execution. Use a fresh recoverer
for a separate verification pass. Project verification and resource export
pass through the operation context's limits.

Synthetic integration tests cover external memory seeds, multiple exports,
relocation, normalization/version refusals, allocation and instruction limits,
input corruption, and graph validation. To verify a private project containing
reviewed real recipes, run:

```bash
AMIGA_RE_SANDBOX_PROJECT=/path/to/private/project \
  cargo test -p amiga-operations --test sandbox_recipe -- --nocapture
```

The media test skips when the variable is absent. Configured missing files,
invalid projects, or non-verifying objects fail. Keep private source material,
recipes containing title-specific addresses, and derived bytes under ignored
`original/`, `extracted/`, or `decoded/` directories.
