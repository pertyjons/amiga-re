# Local release preparation

These commands create and verify local artifacts. Publication requires a separate
explicit decision. The current repository URL matches the configured Git remote;
confirm the intended public account before publishing.

Run the complete gate in `AGENTS.md`, then:

```bash
cargo fetch --locked
python3 scripts/third_party_notices.py --check
python3 -m unittest discover -s scripts
cargo package --workspace --allow-dirty --offline
python3 scripts/release.py check-packages
```

Cargo packages the workspace in dependency order using a temporary local
registry and builds each unpacked package. This checks version requirements and
standalone builds without publishing internal crates. `check-packages` reads the
actual `.crate` archives, checks both project license texts, rejects unsafe/private
paths, and checks that normalized dependency manifests contain no workspace paths.
Each crate carries copies of the root licenses; keep those copies byte-identical.

If publishing to crates.io is chosen, dependency order is:

1. `amiga-core`, `amiga-compress`, `amiga-lha`.
2. `amiga-hunk`, `amiga-adf`, `amiga-hw`, `amiga-project`.
3. `amiga-disasm`, `amiga-iff`.
4. `amiga-env`, `amiga-analysis`.
5. `amiga-operations`.
6. `amiga-re-cli`.

For a binary archive:

```bash
cargo build --release -p amiga-re-cli --locked
python3 scripts/release.py binary --binary target/release/amiga-re --output /tmp/amiga-re-binary.tar.gz
```

The archive includes both project licenses, locked third-party notices, the
provenance record, exact MPL-covered source, and an inventory with output digests.
Use a new output path; existing files and symbolic links are refused. Regenerate
and review notices after dependency updates. The maintainer's acceptance of the
completed reference documentation is recorded in `SOURCE_PROVENANCE.md`; the
implementation-provenance TODO is closed.

For a public source export, stage intended changes first, then create an inventory:

```bash
python3 scripts/release.py inventory --output /tmp/amiga-re-inventory.json
```

Inspect every listed path and digest before creating the archive:

```bash
python3 scripts/release.py source --inventory /tmp/amiga-re-inventory.json --output /tmp/amiga-re-source.tar.gz
```

Only indexed files with their reviewed current bytes are exported. Private media,
local tool state, unsafe paths, symlinks and changed inventories are refused. The
archive contains the inventory, so recipients can verify its files. This exports
source files only, with no repository history or untracked working-directory data.
