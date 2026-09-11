#!/usr/bin/env python3
"""Inspect package archives and assemble local distributions. Never publishes."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC_MEDIA = {
    "crates/amiga-operations/fixtures/volume.adf",
    *("crates/amiga-project/fixtures/contract/original/" + name for name in (
        "disk1.adf", "disk2.adf", "disk3.adf", "assets.bin", "installed/startup",
        "installed/data/levels.tbl")),
}
PRIVATE_EXTENSIONS = {".adf", ".hdf", ".dms", ".ipf", ".lha", ".lzh", ".exe"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def public_path(name):
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts) or "\\" in name or ":" in name:
        return False
    if name in SYNTHETIC_MEDIA:
        return True
    return (not any(p in {"original", "extracted", "decoded", ".git", ".claude", ".codex",
                          ".agents", ".amiga-re", "target", "__pycache__"} for p in parts)
            and PurePosixPath(name).suffix.lower() not in PRIVATE_EXTENSIONS
            and not name.startswith("crates/amiga-lha/fixtures/real/"))


def reject_symlinks(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f"refusing symbolic link: {part}")


def read(path):
    reject_symlinks(path)
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError(f"file too large: {path}")
    return path.read_bytes()


def inventory():
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")[:-1]
    records = []
    for name in sorted(names):
        if not public_path(name):
            raise ValueError(f"private or unsafe tracked path: {name}")
        data = read(ROOT / name)
        records.append({"path": name, "size": len(data), "sha256": digest(data)})
    return records


def write_new(path, data):
    reject_symlinks(path)
    with path.open("xb") as output:
        output.write(data)


def archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name == "amiga-re" else 0o644
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def source_distribution(reviewed):
    if reviewed != inventory():
        raise ValueError("source inventory changed; generate and inspect it again")
    files = {record["path"]: read(ROOT / record["path"]) for record in reviewed}
    # Recheck the exact held bytes, before producing any output.
    for record in reviewed:
        data = files[record["path"]]
        if len(data) != record["size"] or digest(data) != record["sha256"]:
            raise ValueError(f"source changed: {record['path']}")
    files["SOURCE_INVENTORY.json"] = (json.dumps(reviewed, indent=2) + "\n").encode()
    return archive(files)


def binary_distribution(binary):
    subprocess.run(["python3", str(ROOT / "scripts/third_party_notices.py"), "--check"], check=True)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"], cwd=ROOT))
    package = next(p for p in metadata["packages"] if p["name"] == "m68000")
    name = f"m68000-{package['version']}.crate"
    package_root = Path(package["manifest_path"]).parent
    registry = package_root.parent
    source = read(registry.parent.parent / "cache" / registry.name / name)
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    pin = next(p["checksum"] for p in lock["package"] if p["name"] == "m68000")
    if digest(source) != pin:
        raise ValueError("MPL source archive does not match Cargo.lock")
    files = {name: read(ROOT / name) for name in
             ("LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md", "SOURCE_PROVENANCE.md")}
    files["amiga-re"] = read(binary)
    files[f"third-party-source/{name}"] = source
    records = [{"path": name, "size": len(data), "sha256": digest(data)}
               for name, data in sorted(files.items())]
    files["ARTIFACT_INVENTORY.json"] = (json.dumps(records, indent=2) + "\n").encode()
    return archive(files)


def check_packages(directory):
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT))
    for package in metadata["packages"]:
        prefix = f"{package['name']}-{package['version']}"
        path = directory / (prefix + ".crate")
        with tarfile.open(path) as tar:
            members = tar.getmembers()
            names = [m.name.removeprefix(prefix + "/") for m in members]
            for license in ("LICENSE-MIT", "LICENSE-APACHE"):
                stream = tar.extractfile(f"{prefix}/{license}")
                if stream is None or stream.read() != (ROOT / license).read_bytes():
                    raise ValueError(f"missing or changed license: {path}/{license}")
            manifest_stream = tar.extractfile(f"{prefix}/Cargo.toml")
            manifest = tomllib.loads(manifest_stream.read().decode())
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                for dep in manifest.get(table, {}).values():
                    if isinstance(dep, dict) and "path" in dep:
                        raise ValueError(f"workspace path in packaged manifest: {path}")
            crate_root = Path(package["manifest_path"]).parent.relative_to(ROOT).as_posix()
            for member, name in zip(members, names):
                if not member.isfile() or not public_path(f"{crate_root}/{name}"):
                    raise ValueError(f"unsafe package entry: {member.name}")
        print(f"Verified licenses, paths, and inventory: {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inventory")
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("source")
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("binary")
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("check-packages")
    p.add_argument("--directory", type=Path, default=ROOT / "target/package")
    args = parser.parse_args()
    if args.command == "check-packages":
        check_packages(args.directory)
    elif args.command == "inventory":
        write_new(args.output, (json.dumps(inventory(), indent=2) + "\n").encode())
    elif args.command == "source":
        write_new(args.output, source_distribution(json.loads(read(args.inventory))))
    else:
        write_new(args.output, binary_distribution(args.binary))


if __name__ == "__main__":
    main()
