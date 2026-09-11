# Synthetic LHA payloads

These are byte-identical copies of `amiga-lha/fixtures/synthetic/lh45-literals.bin`
and `lh45-hunk.bin`, kept here so this crate's tests also work when packaged
separately. The construction, verification and SHA-256 values are recorded in
[the LHA fixture record](../../../amiga-lha/fixtures/synthetic/README.md).
They contain generated text and a tiny generated HUNK executable, with no private media.
