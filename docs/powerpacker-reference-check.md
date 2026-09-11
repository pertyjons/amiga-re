# PowerPacker reference check

Checked on 2026-09-11 against two external implementations. This is a current
behavioral comparison, not evidence of what the original coding agent consulted.
No external decoder source is imported into `amiga-compress`.

## References

- Teemu Suutari's [Ancient](https://github.com/temisu/ancient/tree/d52dc0c1eec35f14e0da78dd48836ac9542f2f0f),
  revision `d52dc0c1eec35f14e0da78dd48836ac9542f2f0f` (two commits after
  `v2.3.0`). Its PowerPacker implementation is **C++**, under
  [BSD-2-Clause](https://github.com/temisu/ancient/blob/d52dc0c1eec35f14e0da78dd48836ac9542f2f0f/LICENSE).
  Inspected `PPDecompressor::decompressImpl`, the backward input/bit reader,
  and `BackwardOutputStream::copy`.
- The **C** `ppDecrunch` routine in
  [libxmp 4.7.0](https://github.com/libxmp/libxmp/blob/8a4fdf7d09aedc921de537853b59e1d15b534f24/src/depackers/ppdepack.c),
  revision `8a4fdf7d09aedc921de537853b59e1d15b534f24`. The file declares its
  code Public Domain and credits Stuart Caie, Heikki Orsila's amigadepack 0.02,
  and Claudio Matsuoka's libxmp modifications. That file-level notice is the
  relevant declaration for this reference, rather than an inferred license
  from the encompassing project.

| Inspected source | SHA-256 |
| --- | --- |
| Ancient `src/PPDecompressor.cpp` | `5f404b5cf013a040eb2e5de82b4d222fe3870e14b814b4b491517b2a9a19477c` |
| Ancient `src/InputStream.hpp` | `80c44bf03c085eaa963d81d0ddb14094074e5edadac77a282bb32cac19626fc8` |
| Ancient `src/InputStream.cpp` | `1a4c8876bfa9bfaeb24ca8e6c3fc7b167477150a5f70041c999fc09a49dac01f` |
| Ancient `src/OutputStream.cpp` | `ee508f45baa497f3625278adb2dcee7ac28465c8bd28662d049693362431671d` |
| Ancient `LICENSE` | `c6348e1d7eff0ecf862d7f7ff49062f00fba54ead832e871e4835d57b836e5c5` |
| libxmp `src/depackers/ppdepack.c` | `45be9b8d66a4c5fc3e2c75ba0d55bd687d6a6655b2e56138d8468fd911bde33c` |

## Framing and preserved behavior

Our API receives the compressed words and four-byte trailer, with mode widths
supplied separately by the caller. The comparison prepends `PP20` and those four
mode bytes; it does not alter the compressed words or trailer. PX20 encryption,
PP11, XPK framing and executable-loader detection are outside this API's scope.

The shared checks use all five standard tables: `[9,9,9,9]`, `[9,10,10,10]`,
`[9,10,11,11]`, `[9,10,12,12]`, and `[9,10,12,13]`. Our embedded API additionally
accepts loader-supplied widths from 1 through 31. Ancient's PP20 constructor
accepts only the five standard tables; this is a framing-policy difference,
not a reason to remove custom loader support.

The existing backward bit order, literal lengths, short match lengths,
extended lengths, distance-plus-one rule and overlapping copies agree with the
references for the compared streams. Our explicit word alignment, skip range
0–31, nonzero 24-bit output size, checked arithmetic and caller output limit
remain enforced. PowerPacker carries no checksum to authenticate recovered data.

**Terminal-match difference:** the pinned Ancient decoder tests output completion
after reading another flag and an optional literal run. If a match fills the
output, a subsequent zero padding bit makes it attempt another literal and fail;
a one padding bit lets it finish. Our decoder stops immediately when the output
is full. The C routine's loop also stops at that boundary. We preserve this
behavior rather than make output depend on otherwise unused padding. The
external Ancient test explicitly verifies both padding-bit outcomes.

For the shared Ancient corpus, an explicit final `!` literal is appended to
cases that would otherwise end with a match, and prepended to their expected
output. The C comparison uses the original cases, including terminal matches.
Neither comparison silently discards a disagreement.

## Improvements and coverage

- Literal and extended-match lengths now fail as soon as they exceed remaining
  output space, without scanning a continuation chain that cannot fit.
- A long match's minimum length is checked before reading its distance.
- Output allocation uses `try_reserve_exact` and returns `AllocationFailed` on
  failure; the declared-size and caller-budget checks still precede allocation.
- Four-byte reads use checked offset addition.

`crates/amiga-compress/src/powerpacker_tests.rs` specifies token sequences and
expected bytes separately; its helper only serializes explicit fields and does
not search for matches or implement a compressor. Seven patterns exercise
literal extensions, all match modes, seven-bit and table-sized distances,
overlapping matches, multiple length extensions and literal/match transitions.
Each runs with five standard tables and all 32 initial skips: **1120 cases**.
The independent C comparison checks all 1120; Ancient checks all 1120 adapted
cases described above. Every comparison checks the entire output byte sequence.

Additional Rust tests cover invalid modes, skip values, size/alignment errors,
truncated leading words, unseeded matches, immediate overflow rejection, output
budgets, custom widths, and bit reads across 32-bit boundaries. The C oracle is
used only for valid synthetic streams, not as our malformed-input validator.
These tests do not constitute an exhaustive proof of format correctness or
historical implementation provenance.

## Reproduce the external checks

The Rust tests run without external tools. Each external comparison reports a
clean skip unless its executable environment variable is set. To reproduce the
checks performed here, build the pinned references outside the repository:

```sh
work=$(mktemp -d)
git clone https://github.com/temisu/ancient.git "$work/ancient"
git -C "$work/ancient" checkout d52dc0c1eec35f14e0da78dd48836ac9542f2f0f
make -C "$work/ancient" -f Makefile.unix -j4 obj/ancient
curl -fL https://raw.githubusercontent.com/libxmp/libxmp/8a4fdf7d09aedc921de537853b59e1d15b534f24/src/depackers/ppdepack.c -o "$work/ppdepack.c"
python3 scripts/build_powerpacker_c_reference.py "$work/ppdepack.c" "$work/pp-c-reference"
AMIGA_RE_ANCIENT="$work/ancient/obj/ancient" \
AMIGA_RE_PP_C_REFERENCE="$work/pp-c-reference" \
    cargo test -p amiga-compress compare_with_ -- --nocapture
```

The C builder verifies the exact upstream file hash, extracts its unchanged
`ppDecrunch` core and macros with their notices, and adds a small file-comparison
driver. It uses `cc -std=c99 -O2`, refuses existing output paths, and bundles no
upstream implementation. Ancient uses its unmodified `Makefile.unix`. This check
used GCC/G++ `16.2.1 20260819` on Linux x86_64. Neither reference becomes a runtime
or Cargo dependency.
