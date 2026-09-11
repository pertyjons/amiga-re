# Independently recovered FFS reference

`ffs-reference.expected` pins a full 880 KiB DOS1 image and every recovered file.
The disk is generated entirely from redistributable synthetic payloads by the
external [amitools](https://github.com/cnvogelg/amitools) 0.8.1 filesystem writer,
then reopened read-only and recovered with that tool. No amiga-adf parser or
block-layout helper participates in generating the disk or the expected digests.

The 90,017-byte file crosses two extension blocks; the other files exercise empty
content and a filename containing spaces. Fixed timestamps and deterministic
payloads reproduce the image across timezones. The disk's SHA-256 is
`5a6afcc2976d3e0b428b0d0519478a87b576924ea4127d9a12001c4558fdebb1`.
The generator refuses any mismatch against the committed expectation manifest.

Reproduce in new temporary directories:

```bash
python3 -m venv /tmp/ffs-tools
/tmp/ffs-tools/bin/pip install --require-hashes -r scripts/ffs-requirements.txt
/tmp/ffs-tools/bin/python scripts/ffs_reference.py /tmp/ffs-reference
AMIGA_RE_FFS_IMAGES=/tmp/ffs-reference/reference.adf cargo test -p amiga-adf --test real_images -- --nocapture
```

The integration test verifies all three files and reports crossing the extension
chain. CI runs this path so the evidence remains reproducible without private
media. Historical media may still be supplied through the same environment
variable or `original/ffs/`; they are never committed. This is an independently
written filesystem image, not a claim of verification against a historical disk.
The external tool remains an optional test dependency and is not redistributed.
