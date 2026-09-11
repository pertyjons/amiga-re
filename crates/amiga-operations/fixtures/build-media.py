#!/usr/bin/env python3
"""Generate the two synthetic operations inputs; requires only Python's stdlib."""
import argparse
from pathlib import Path
import struct
import tempfile

FIXTURES = Path(__file__).resolve().parent
BLOCK_BYTES = 512


def sample():
    data = bytearray(b"AMIGA SAMPLE SOURCE\0SYNTHETIC DATA\0LOADER V2.1\0")
    data.extend(bytes(48 - len(data)))
    for word in (0x000, 0xeef, 0xabc, 0x777, 0x123, 0xfff, 0x666, 0x333,
                 0x999, 0x222, 0xccc, 0x444, 0xfab, 0x111, 0x888, 0xddd):
        data.extend(struct.pack(">H", word))
    # Fixed 32-bit LCG. Emit the high byte after each recurrence.
    state = 0x414d4947
    for _ in range(256):
        state = (1664525 * state + 1013904223) & 0xffffffff
        data.append(state >> 24)
    return bytes(data)


def volume():
    # Twenty blocks, root at the midpoint. A zeroed boot block deliberately
    # exercises legacy OFS recovery and its invalid-checksum warning.
    data = bytearray(20 * BLOCK_BYTES)

    def put(block, fields, name=None, payload=None):
        raw = bytearray(BLOCK_BYTES)
        for index, value in fields.items():
            struct.pack_into(">I", raw, index * 4, value & 0xffffffff)
        if name is not None:
            encoded = name.encode("ascii")
            raw[432:433 + len(encoded)] = bytes([len(encoded)]) + encoded
        if payload is not None:
            raw[24:24 + len(payload)] = payload
        checksum = -sum(struct.unpack(">128I", raw)) & 0xffffffff
        struct.pack_into(">I", raw, 20, checksum)
        data[block * BLOCK_BYTES:(block + 1) * BLOCK_BYTES] = raw

    put(10, {0: 2, 6: 2, 7: 5, 127: 1}, name="AmigaRe")
    put(2, {0: 2, 1: 2, 6: 3, 9: 7, 127: 2}, name="S")
    for header, block, name, payload in (
        (3, 4, "startup-sequence", b"echo AmigaRe fixture volume\n"),
        (5, 6, "readme.txt", b"Synthetic OFS volume for amiga-operations tests.\n"),
    ):
        put(header, {0: 2, 1: header, 4: block, 81: len(payload), 127: -3}, name=name)
        put(block, {0: 8, 1: header, 2: 1, 3: len(payload)}, payload=payload)
    # Empty file with a stale pointer into another file's data, deliberately.
    put(7, {0: 2, 1: 7, 4: 4, 127: -3}, name="stale")
    return bytes(data)


def generate(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name, contents in (("sample.bin", sample()), ("volume.adf", volume())):
        path = destination / name
        if path.is_symlink():
            raise ValueError(f"refusing symbolic link: {path}")
        path.write_bytes(contents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=FIXTURES)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="amiga-operations-fixtures-") as tmp:
            generated = Path(tmp)
            generate(generated)
            for name in ("sample.bin", "volume.adf"):
                if (generated / name).read_bytes() != (args.output / name).read_bytes():
                    raise SystemExit(f"fixture differs: {name}")
        print("Both binary fixtures reproduce byte-for-byte.")
    else:
        generate(args.output)


if __name__ == "__main__":
    main()
