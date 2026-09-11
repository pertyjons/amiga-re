# Hardware and ABI references

The reference check on 2026-09-11 uses published interface documentation for
register names, offsets, argument registers and numeric constants. It imports
no AROS source, SDK files, manual text or example programs into this repository.
The maintainer subsequently confirmed on 2026-09-11 that the previously identified
sources were used for ABI/LVO, explicitly naming the Hardware Reference Manual.
See `SOURCE_PROVENANCE.md` for that statement and its scope. The precise editions
and hashes here identify verification material; they do not date the original
source consultation. ABI/LVO citations use the NDK and autodocs for library
interfaces, while hardware citations use the Hardware Reference Manual.

## Hardware Reference Manual

The primary hardware reference is Commodore's *Amiga Hardware Reference Manual*,
as reproduced in the Amiga Developer CD v2.1 collection on
[Amiga Developer Docs](http://amigadev.elowar.com/). The inspected preface identifies
this as the revised edition for AmigaOS 2.0, including the A3000. Its scope covers
OCS/ECS; it does not document the complete later AGA register set.

Appendices A and B support the custom register address base, names and offsets.
Of the 197 entries returned by `amiga_hw::registers::known_registers`, 190 match
Appendix B directly. Seven later entries are absent there: `BPL7PTH`, `BPL7PTL`,
`BPL8PTH`, `BPL8PTL`, `BPL7DAT`, `BPL8DAT`, and `FMODE`. Those were checked against
the eight-element bitplane arrays in NDK `Include_H/hardware/custom.h` and the
base offsets in `Include_I/hardware/custom.i`.

Two naming/address conventions need care when comparing references:

- The manual's `POTGOR` is the SDK's `potinp`, at word offset `0x016`.
- The manual lists `BLTCON0L` at word offset `0x05a`; the SDK gives its low-byte
  address as `0x05b`. Our register-name API takes even word offsets.

Chapter 6 is the behavioral reference for the blitter's Boolean minterms,
first/last-word masks, shifts, descending operation, fill and destination
pipeline. In particular, the Shifts and Masks section describes disabled source
channels and loading immediate data after setting the shift count; Pipeline
Register describes the ordering of source reads and destination writes.
These references establish where to check the model; this documentation pass
is not a complete behavioral or timing validation of the emulator.

The online Area Fill Mode prose calls fill carry-in bit 3, while the detailed
BLTCON1 register diagram places `FCI` at bit 2. Use the register diagram for the
bit assignment; `amiga-hw` already uses bit 2. Do not reproduce that prose typo
as an implementation change.

The following hashes identify the exact retrieved HTML responses, not scans of
the printed book. The mirror's HTTPS certificate failed validation during the
check, so these pages were retrieved over its public HTTP endpoint. A working
HTTPS mirror is available under
[the same manual collection at Grimore](https://scratch.grimore.org/Hardware_Manual_guide/node0000.html).
Mirror markup differs; its file hashes are not interchangeable with these.

| Inspected section | HTML SHA-256 |
| --- | --- |
| [Preface](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0001.html) | `ebcdc7176ca332b4fb6207d264dd1d0ab3cee91866585d114d6f418dabf16de2` |
| [Appendix A: alphabetical register summary](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0011.html) | `23c9d7e84a9ebc06f64874ab9adfb773d368626b29e3ae860167a1db145d9b0a` |
| [Appendix B: registers in address order](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0060.html) | `22560503b58a57b4b112f4b61f199a62bc15ef592ee03b868d222b0df55ab79a` |
| [BLTCON0/BLTCON1 bit definitions](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node001A.html) | `536e360bb7b2e3931bd9b125cb64f15788bee50a547f5959135ae3119546cbf3` |
| [Chapter 6: Blitter Hardware](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0118.html) | `9e8089b88e2b1eefad331207b1b6bdc42a546faeffeaa283d716b9a88417e690` |
| [Function Generator](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node011C.html) | `30aa10c363051f138aab802ec5c7a8bbe5b13ada1cf6017cafce596a42735c7a` |
| [Shifts and Masks](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node011F.html) | `178144256a2f31861d7f4fa068be59a0b28e3be450fcc49d1e3aa9f2620d1779` |
| [Descending Mode](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0120.html) | `63cfa30872926c4ec3f3657cfa1dfca8969d07f59c4d343b79ea5a729a26887e` |
| [Area Fill Mode](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0122.html) | `db819834efa0771b63b3fe75e6308e30fad045553a0457bdcfe2f1c7b5e09117` |
| [Pipeline Register](http://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node0127.html) | `b365d5747b51199b35987b71d6132b0086727ce05cfe9e48d57b7fe89133dc14` |

## Native Developer Kit and autodocs

The SDK reference is *Native Developer Kit for AmigaOS 3.2, Release 4*, published
by Hyperion Entertainment through
[the NDK 3.2 Aminet listing](https://aminet.net/package/dev/misc/NDK3.2).
The downloaded archive contains `ReadMe-NDK.txt` identifying Release 4 and has
SHA-256 `96cabd4ad683dced632e147bf86dee0f50dcb1254386216c25c362916a6409bb`.
All inspected SDK files were held outside the repository.

The comparison produced these results:

| Local data | Reference | Result |
| --- | --- | --- |
| Exec LVO names | `FD/exec_lib.fd` | 85 of 85 match |
| DOS LVO names | `FD/dos_lib.fd` | 31 of 31 match |
| Graphics LVO names | `FD/graphics_lib.fd` | 61 of 61 match |
| Intuition LVO names | `FD/intuition_lib.fd` | 68 of 68 match |
| Curated argument-register lists | Exec and DOS FD files | 17 of 17 match |
| Memory flags and DOS open/seek values | `Include_H/exec/memory.h`, `Include_H/dos/dos.h` | 17 of 17 match |

To reproduce the comparison, verify the archive hash, extract only the files
listed below, and interpret each FD `##bias` as a negative byte offset. Each
function entry subtracts another six bytes, including private entries;
comments do not advance the offset. Compare name/offset pairs with the four
`*_lvo` match expressions in `amiga-disasm/src/lvo.rs`. The check extracted
those functions with `ast-grep` and enumerated `abi::arguments` and
`registers::known_registers` from the local Rust modules. FD argument-register
lists use both commas and slashes as separators. For constants, compare the
numeric values, including the u32 representation of DOS's negative seek origin.

Matching NDK 3.2 does not imply that every symbol exists on AmigaOS 1.x.
For example, [AllocVec](https://developer.amigaos3.net/autodocs/exec.library/AllocVec.html),
[FreeVec](https://developer.amigaos3.net/autodocs/exec.library/FreeVec.html), and
[ZipWindow](https://developer.amigaos3.net/autodocs/intuition.library/ZipWindow.html)
are documented as V36 additions. The local tables are selected classic m68k
interfaces, not a version-specific availability guarantee. The Intuition FD
also names `OpenIntuition` while explicitly leaving it undocumented; a known
vector name is not a recommendation to call it.

Autodocs describe argument conventions and behavior; the FD files provide the
exact vector offsets. Hardware Reference Manual alone does not cover these
library interfaces. References can substantiate technical interface facts;
public availability is not a general permission to redistribute a manual's
prose, SDK headers, example code or an AROS implementation under our license.
This check adds references and comparisons only.

| Inspected SDK file | SHA-256 |
| --- | --- |
| `FD/dos_lib.fd` | `0d2fd82f887e0a980f89fd317bfd348d3f4476009374c8729918af2063ca4c5c` |
| `FD/exec_lib.fd` | `016d3cbd9624a12d6b3cc4caf1fc6772a685e678c3e44276b007781b204494ef` |
| `FD/graphics_lib.fd` | `77565cd82bcae40b5828e47f514825677a4050fd11029efb56a45b82f13f92cd` |
| `FD/intuition_lib.fd` | `233cf8d12e225db25f455ecd03c3949ebfcf5c254c29555248a469137a908fa5` |
| `Include_H/dos/dos.h` | `40ff825550769cf997f6f2234eeeb38c1ea531dd52cb5c0e4fe58dfde68e0fa7` |
| `Include_H/exec/memory.h` | `1334ecff45e5945c3ab90aff36eddc934305130b8923c53a32d51872062ddfb4` |
| `Include_H/hardware/custom.h` | `70dccd8177f2a524554d98fdf2da033236349152a2833f793d23b6b87b0ebfee` |
| `Include_I/hardware/custom.i` | `5928fcd86265ab102d5623d60975bb05d047d37d88e94e564d45ac318e70fa4f` |
| `ReadMe-NDK.txt` | `96de329dd13c847259203a271371b9a416b398fda6c38e9d66dc994855c5278f` |
