# Source and reference provenance

This record documents repository history, reference sources, verification work
and retained third-party notices. The project declares MIT OR Apache-2.0. The
maintainer has accepted the documented references and comparisons as sufficient
to close the implementation-provenance TODO; see the decision below.

## Curated knowledge and implementations

| Files under `crates/` | Retained knowledge / code | Inspectable origin | Reference and current status |
| --- | --- | --- | --- |
| `amiga-disasm/src/abi.rs` | Vector argument registers, flag names and numeric assignments | Introduced in `c128cb4`; extended in `f53e8e5` | All 17 argument-register lists and 17 constants were checked against NDK 3.2 R4 on 2026-09-11; see the reference check below. **Reference sources confirmed by the maintainer on 2026-09-11;** see the confirmation below. No SDK files are bundled. |
| `amiga-disasm/src/lvo.rs` | Library names and signed vector offsets; Rust inference code | Initial table in `5b3b550`; subsequent history records inference changes | All 245 name/offset pairs match NDK 3.2 R4. The incorrect blanket AmigaOS 1.x description was corrected; some entries require V36. **Reference sources confirmed by the maintainer on 2026-09-11;** see the confirmation below. |
| `amiga-hw/src/registers.rs` | Custom-register addresses, names and subsystem classifications | Initial toolkit commit `b79ca73` and subsequent history | 190 name/offset pairs match Hardware Reference Manual Appendix B; the remaining seven match NDK 3.2 R4. The Hardware Reference Manual and NDK are the retained reference sources; see the check below and the maintainer decision. |
| `amiga-hw/src/blitter.rs` | OCS area-mode datapath, masks, shifts, minterms and synthetic tests | `732537a` and correctness follow-ups | The retained reference source is Hardware Reference Manual Chapter 6, cited in the module documentation, with section links and hashes in the reference check. See the maintainer decision. |
| `amiga-compress/src/powerpacker.rs` | Reverse bit reader and headerless stream decoder | `b79ca73`, bounded-output follow-up `9667e92` | The retained implementation reference is Teemu Suutari's Ancient (C++, BSD-2-Clause), compared on 2026-09-11 alongside libxmp ppDecrunch (C, file declares Public Domain); see [PowerPacker reference check](docs/powerpacker-reference-check.md). Both pass the documented exact-byte comparisons; Ancient's terminal-match difference is recorded. The comparison imported no decoder source. See the maintainer decision. |

## Maintainer decision on reference documentation

On 2026-09-11, the maintainer requested closure of the remaining provenance TODO
and accepted the Ancient citation as sufficient for PowerPacker. The completed
reference documentation is retained as the basis for that closure: Ancient for
PowerPacker, Hardware Reference Manual Appendix B and NDK 3.2 R4 for the register
table, and Hardware Reference Manual Chapter 6 for the blitter.

This records acceptance of the current references and verification work. It does
not assert that the original coding agent consulted Ancient or establish an
otherwise undocumented historical derivation. The comparison reports retain
pinned revisions, hashes, license information and test results. No further
historical source investigation or implementation replacement is required by
this closed TODO. Retain applicable upstream notices for any future code reuse.

## Maintainer confirmation for ABI/LVO

On 2026-09-11, the maintainer confirmed that the previously identified reference
sources were used for ABI/LVO, explicitly naming the *Amiga Hardware Reference
Manual*. This statement is the source-use evidence for `abi.rs` and `lvo.rs`;
their reference origin is no longer recorded as unknown.

The citations retain the technical distinction between the sources: the Hardware
Reference Manual describes the custom hardware, while NDK FD files and autodocs
supply library-vector offsets, argument registers and OS constants. The exact
NDK 3.2 R4 archive and hashes below identify our verification material; the
confirmation does not specify the SDK edition originally consulted. It also
does not state that SDK source or manual prose was copied or translated.

## Verified hardware and ABI references

The [hardware and ABI reference check](docs/hardware-and-abi-references.md)
records Commodore's Hardware Reference Manual and Hyperion's NDK 3.2 R4,
source hashes, comparison counts, version boundaries and a manual erratum.
These sources provide references for the current interface facts without
importing AROS implementations. The comparison establishes current technical
references; the maintainer statement above separately records historical source
use for ABI/LVO.

## External implementation references

A web review on 2026-09-11 identified the following external implementations.
Ancient is the retained PowerPacker reference; vAmiga and AROS remain alternatives
reviewed for possible reuse. These are newly consulted references,
not evidence of what the original coding agent used. The initial review
imported no code.

| Area | Candidate and inspected revision | Relevant source and declared license |
| --- | --- | --- |
| PowerPacker in C++ | [Ancient](https://github.com/temisu/ancient/tree/d52dc0c1eec35f14e0da78dd48836ac9542f2f0f), Teemu Suutari | [`src/PPDecompressor.cpp`](https://github.com/temisu/ancient/blob/d52dc0c1eec35f14e0da78dd48836ac9542f2f0f/src/PPDecompressor.cpp); [`LICENSE`](https://github.com/temisu/ancient/blob/d52dc0c1eec35f14e0da78dd48836ac9542f2f0f/LICENSE) is BSD-2-Clause. The completed [comparison](docs/powerpacker-reference-check.md) accounts for our headerless input convention. |
| Blitter in C++ | [vAmiga](https://github.com/dirkwhoffmann/vAmiga/tree/db1d4e5a4898cf9ec220d4c4620c87ae20a1384c), Dirk W. Hoffmann | [`Core/Components/Agnus/Blitter/Blitter.cpp`](https://github.com/dirkwhoffmann/vAmiga/blob/db1d4e5a4898cf9ec220d4c4620c87ae20a1384c/Core/Components/Agnus/Blitter/Blitter.cpp) explicitly carries MPL-2.0. The top-level application's GPL license and the CPU's MIT license do not describe this file. |
| Registers and Exec ABI | [AROS](https://github.com/aros-development-team/AROS/tree/992cf7007decc06b492f118f869d3feec221cfaa), AROS Development Team | `compiler/include/hardware/custom.h` and `rom/exec/exec.conf`; the project declares the [AROS Public License](https://github.com/aros-development-team/AROS/blob/992cf7007decc06b492f118f869d3feec221cfaa/LICENSE) and contains separately licensed components. Check selected files and classic m68k ABI/version correspondence before reuse. |

Preserve upstream notices when incorporating code, record the selected revision
and affected files, and verify our existing bounds, CRC, malformed-input and
output-path behavior before
replacing a decoder. For PowerPacker, compare synthetic streams after explicitly
adapting the framing expected by Ancient; do not assume identical input APIs.

## Third-party dependencies

`THIRD_PARTY_NOTICES.md` is generated from every registry package in `Cargo.lock`,
including build/test/target dependencies. It records exact versions, registry
archive SHA-256 values, authors, source locations, and preserved license texts.
Repeated identical texts are shared by digest; author notices are retained.

Most texts come from the exact downloaded crate. Some crates omit their license
file from the published archive. The missing texts are retained in
`licenses/upstream/`, with immutable source URLs in `sources.json`. Those Git
revisions come from the corresponding crate's `.cargo_vcs_info.json`:

- `m68000 0.2.3`: `cd4e0b1e02e811660b6ce1876d040f7f79682014`, MPL-2.0.
- `jsonschema-regex` / `jsonschema-value 0.49.1`:
  `e157402705596c6335261f79d54d4c79221a20d6`, MIT.
- `uuid-simd` / `vsimd 0.8.0`:
  `d74c030d9dc4f3cae02146d1f497ff62726ef09a`, MIT.

`r-efi 5.3.0` carries its MIT permission and copyright statements in `AUTHORS`;
that file is included in the generated notices.

The MPL-covered dependency is unmodified registry source. Binary assembly
includes its exact source archive and tells recipients where to obtain it,
following [Mozilla's MPL FAQ Q8](https://www.mozilla.org/en-US/MPL/2.0/FAQ/#q8-i-want-to-distribute-outside-my-organization-executable-programs-or-libraries-that-i-have-compiled-from-someone-elses-unchanged-mpl-licensed-source-code-either-standalone-or-part-of-a-larger-work-what-do-i-have-to-do).

## Fixtures

Operations binary fixtures are generated by
`crates/amiga-operations/fixtures/build-media.py`; project contract media are
created by `crates/amiga-project/fixtures/build-media.py`. Other parser tests
construct synthetic inputs directly in source. These generators need no private
media. Private input folders and local bindings remain excluded from exports.

The independent FFS reference uses the separately installed amitools 0.8.1
writer and reader via their public Python API. `scripts/ffs-requirements.txt`
pins its source distribution hash. No tool source is bundled;
`crates/amiga-adf/fixtures/ffs-reference.expected` pins the generated disk and
recovered payloads. This independent test-tool use does not establish the
historical origin of the implementations above.
