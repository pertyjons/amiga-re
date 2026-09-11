# Bundled operation schemas

The canonical JSON Schema (Draft 2020-12) contract for the operation protocol,
compiled into the crate with `include_str!` and reachable through
`amiga_operations::descriptor`. An installed binary carries them; there is no
repository-root copy to drift from.

```text
v1/
|- common.schema.json      identities, digests, and bounds the others reference
|- request.schema.json     the request envelope, operations as tagged variants
|- response.schema.json    the response envelope
|- diagnostic.schema.json  one diagnostic
`- operations/
   |- source.survey.request.schema.json
   |- source.survey.response.schema.json
   |- container.adf.list.request.schema.json
   `- container.adf.list.response.schema.json
```

Per-operation files exist so documentation and editor use do not require
loading an unrelated envelope. `$id` values use the reserved `.invalid` domain:
nothing is ever fetched, and a resolution attempt would fail loudly rather than
reach the network. `$schema` in a request document is an offline editor hint
and is never followed.

## What the schema is, and what it is not

The schema is the **published contract**. It is not the enforcement mechanism.

A request is refused by the Rust types (`serde` with `deny_unknown_fields`) and
then by `normalize`, which produces typed diagnostics carrying stable codes and
the exact request location at fault. Re-running a JSON Schema pass at runtime
would restate the same rules in a second place with worse diagnostics, so the
crate deliberately does not do it. The two artifacts are instead proven to
agree: `tests/catalog.rs` validates every fixture and every live response
against the bundled schemas, and proves the schema rejects each shape the code
rejects.

Where the two differ, they differ **deliberately and in one direction**: the
schema bounds shape, and the code additionally enforces semantics the schema
cannot express without lookahead regexes or filesystem access. A source path of
`../secret.bin` is well-shaped and still refused. A test pins that split so it
stays intentional.

## Changing a schema

No backward-compatibility obligation exists during active development. If a
version-1 shape turns out wrong, replace it together with its fixtures rather
than preserving it behind a compatibility layer — `protocol_version` records
which shape a document uses; it is not a promise to keep old ones working.

Adding an operation requires a request and a response schema, an
`OperationDescriptor` naming both, and an entry in `OperationName::ALL`. The
catalog tests fail until all three exist.

The response envelope selects its payload schema by `operation`, including when
several operations share the same payload shape. Its operation names and schema
references are checked exhaustively against the descriptor catalog. The response
sweep validates real complete success, prepared, cancelled, conflict, and error
responses. Errors may retain a typed report or uncommitted plan; cancellation
carries no authoritative result.
