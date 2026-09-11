#!/usr/bin/env python3
"""Build a pinned external C oracle for synthetic PowerPacker tests only.

No reference implementation is bundled. Supply the upstream ppdepack.c file;
the exact source hash is required before extracting its unchanged decoding core.
See docs/powerpacker-reference-check.md for download and test commands.
"""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

SOURCE_SHA256 = "45be9b8d66a4c5fc3e2c75ba0d55bd687d6a6655b2e56138d8468fd911bde33c"
PRELUDE = '#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\ntypedef uint8_t uint8;\ntypedef uint32_t uint32;\n'
DRIVER = r"""
static unsigned char *load(const char *path, long *size) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) || (*size = ftell(f)) < 0 || *size > 1048576 || fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
    unsigned char *bytes = malloc(*size ? (size_t)*size : 1);
    if (!bytes || fread(bytes, 1, (size_t)*size, f) != (size_t)*size) { free(bytes); fclose(f); return NULL; }
    fclose(f); return bytes;
}
int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "verify")) return 2;
    long size = 0, expected_size = 0;
    unsigned char *packed = load(argv[2], &size), *expected = load(argv[3], &expected_size);
    if (!packed || !expected || size < 16 || memcmp(packed, "PP20", 4)) return 2;
    uint32 decoded_size = ((uint32)packed[size-4] << 16) | ((uint32)packed[size-3] << 8) | packed[size-2];
    if (!decoded_size || decoded_size > 1048576 || decoded_size != expected_size) return 2;
    unsigned char *decoded = malloc(decoded_size); if (!decoded) return 2;
    int ok = ppDecrunch(packed+8, decoded, packed+4, (uint32)size-12, decoded_size, packed[size-1]);
    int status = ok && !memcmp(decoded, expected, decoded_size) ? 0 : 1;
    free(decoded); free(expected); free(packed); return status;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.is_symlink() or args.source.stat().st_size > 65536:
        raise ValueError("expected a regular upstream source file under 64 KiB")
    raw = args.source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("ppdepack.c does not match the pinned source SHA-256")
    if args.output.exists() or any(p.is_symlink() for p in (args.output, *args.output.parents)):
        raise ValueError("output must be a new path without symbolic links")
    source = raw.decode("utf-8")
    # Keep the original credits and Public Domain notice with the temporary core.
    notice = source[:source.index('#include "../common.h"')]
    core = source[source.index("#define PP_READ_BITS"):source.index("static int ppdepack(")]
    with tempfile.TemporaryDirectory(prefix="amiga-pp-c-build-") as directory:
        directory = Path(directory)
        wrapped = directory / "reference.c"
        executable = directory / "reference"
        wrapped.write_text(notice + PRELUDE + core + DRIVER)
        subprocess.run(["cc", "-std=c99", "-O2", str(wrapped), "-o", str(executable)], check=True)
        with args.output.open("xb") as output, executable.open("rb") as built:
            shutil.copyfileobj(built, output)
        args.output.chmod(0o755)
    print(f"Built PowerPacker C reference from {SOURCE_SHA256}")


if __name__ == "__main__":
    main()
