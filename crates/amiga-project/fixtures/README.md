# The contract fixture

A synthetic, redistributable project that exercises every version-1 concept.
Nothing here comes from original media: `build-media.py` generates the bytes
under `contract/original/`, and the checked-in documents pin them by digest.

What it deliberately contains, and why each thing is there:

| In the fixture | Because the format has to handle |
| --- | --- |
| Three ADF sources plus a directory source in one set | An ordered multi-disk release with support files |
| A loose binary holding a palette, pixels, and PCM | Three resources in one file, so a resource targets a *range* |
| Two HUNK modules with **overlapping numeric offsets** | Hunk 0 offset 4 exists in both, so no target can resolve by number alone |
| Two named load maps for one image | No single runtime address is universally true for a relocatable executable |
| A function, a register local with a lifetime, comments | Knowledge that is scoped rather than global |
| A comment targeting an *entity* | Renaming or rebasing the function must carry it |
| One annotation marked `stale` | A recorded digest that no longer matches must stay visible and unusable |
| A palette, an image, raw audio, a table, text | Every resource kind's required interpretation data |
| A PNG artifact with provenance | Generated output is recorded, never authoritative |
| A struct, an enum, an array, a pointer with an address space | Explicit offsets, explicit byte order, explicit frames |
| All five directory roles, `scratch` among them | A project states where provisional outputs go, so a tool reads one back from a declared place rather than from wherever it is pointed |

`tests/contract.rs` proves the acceptance criterion mechanically: every object
is recovered from its pinned source and selector and compared against its own
digest, and every annotated range is checked to lie inside the object it names
and to carry that object's current digest — except the one annotation that is
supposed to be stale, which is asserted to *not* match.

## Regenerating

```bash
python3 crates/amiga-project/fixtures/build-media.py
```

The script prints the sizes and digests. The documents are written by hand
against those values, so a regeneration that changes the bytes will fail
`tests/contract.rs` rather than silently disagreeing with the metadata.
