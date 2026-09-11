#!/usr/bin/env python3
"""Create and independently recover a DOS1 volume using amitools 0.8.1.

The writer and extractor are external implementations. This script specifies
only payloads and public API calls, never Amiga block layouts or checksums.
"""
import argparse
import hashlib
import importlib.metadata
from pathlib import Path


def generate(destination):
    if importlib.metadata.version("amitools") != "0.8.1":
        raise ValueError("use amitools 0.8.1 for reproducible reference media")
    from amitools.fs.ADFSVolume import ADFSVolume
    from amitools.fs.FSString import FSString
    from amitools.fs.MetaInfo import MetaInfo
    from amitools.fs.RootMetaInfo import RootMetaInfo
    from amitools.fs.TimeStamp import TimeStamp
    from amitools.fs.blkdev.ADFBlockDevice import ADFBlockDevice

    # New directory only: never modify caller media or overwrite prior evidence.
    for parent in (destination, *destination.parents):
        if parent.is_symlink():
            raise ValueError(f"refusing symbolic link: {parent}")
    destination.mkdir(parents=True, exist_ok=False)
    path = destination / "reference.adf"
    stamp = TimeStamp(1, 2, 3)
    metadata = MetaInfo(protect=0, mod_ts=stamp)
    device = ADFBlockDevice(str(path))
    device.create()
    volume = ADFSVolume(device)
    volume.create(FSString("IndependentFFS"),
                  meta_info=RootMetaInfo(stamp, stamp, stamp), is_ffs=True)
    directory = volume.root_dir.create_dir(FSString("Data"), meta_info=metadata, update_ts=False)
    # 90,017 bytes exceeds two 72-block tables of 512-byte data blocks. The
    # nonperiodic payload exposes swapped/reversed/duplicated block-table slots.
    payload = bytearray()
    for index in range(2814):
        payload.extend(hashlib.sha256(f"amiga-re-ffs-reference:{index}".encode()).digest())
    payload = bytes(payload[:90017])
    directory.create_file(FSString("large.bin"), payload, meta_info=metadata, update_ts=False)
    volume.root_dir.create_file(FSString("empty"), b"", meta_info=metadata, update_ts=False)
    volume.root_dir.create_file(FSString("read me.txt"), b"Independent FFS reference volume.\n",
                                meta_info=metadata, update_ts=False)
    volume.close()
    device.close()

    # Close the writer completely and reopen the saved disk read-only. Pins
    # come from independently recovered bytes, not from amiga-adf or metadata.
    device = ADFBlockDevice(str(path), read_only=True)
    device.open()
    volume = ADFSVolume(device)
    volume.open()
    expected = {"Data/large.bin": payload, "empty": b"",
                "read me.txt": b"Independent FFS reference volume.\n"}
    disk = path.read_bytes()
    assert disk[:4] == b"DOS\1"
    lines = ["# Written and independently recovered by amitools 0.8.1.",
             f"image-sha256 {hashlib.sha256(disk).hexdigest()}"]
    recovered_root = destination / "recovered"
    for name, original in sorted(expected.items()):
        recovered = volume.read_file(FSString(name))
        if recovered != original:
            raise ValueError(f"independent tool did not recover the written bytes: {name}")
        output = recovered_root / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(recovered)
        lines.append(f"file {hashlib.sha256(recovered).hexdigest()} {len(recovered)} {name}")
    volume.close()
    device.close()
    manifest = "\n".join(lines) + "\n"
    pin = Path(__file__).resolve().parent.parent / "crates/amiga-adf/fixtures/ffs-reference.expected"
    if manifest != pin.read_text():
        raise ValueError("independent fixture changed; review before updating the pin")
    path.with_suffix(".adf.expected").write_text(manifest)
    print(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    generate(parser.parse_args().destination)
