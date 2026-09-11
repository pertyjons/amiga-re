"""Checks independent of local Git excludes and private source media."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import release

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = (
    "crates/amiga-operations/fixtures/volume.adf",
    "crates/amiga-project/fixtures/contract/original/disk1.adf",
    "crates/amiga-project/fixtures/contract/original/disk2.adf",
    "crates/amiga-project/fixtures/contract/original/disk3.adf",
)


class PublicationTests(unittest.TestCase):
    def test_private_paths_are_ignored_without_local_excludes(self):
        with tempfile.TemporaryDirectory(prefix="amiga-re-ignore-") as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            shutil.copyfile(ROOT / ".gitignore", Path(tmp) / ".gitignore")
            private = ["original/notes.txt", "extracted/asset.bin", "decoded/image.png",
                       ".claude/scheduled_tasks.lock", ".amiga-re/bindings.json",
                       "crates/amiga-lha/fixtures/real/review.lha",
                       "crates/amiga-lha/fixtures/real/review.lzh",
                       "crates/amiga-lha/fixtures/real/notes.txt"]
            for extension in ("adf", "hdf", "dms", "ipf", "lha", "lzh", "exe"):
                for case in (extension, extension.upper(), extension.capitalize()):
                    private.extend((f"review.{case}", f"crates/amiga-lha/fixtures/review.{case}"))
            for name in private:
                result = subprocess.run(["git", "-C", tmp, "check-ignore", "-q", "--", name])
                self.assertEqual(result.returncode, 0, name)
            for name in SYNTHETIC:
                result = subprocess.run(["git", "-C", tmp, "check-ignore", "-q", "--", name])
                self.assertEqual(result.returncode, 1, name)
                self.assertTrue((ROOT / name).is_file(), name)

    def test_source_inventory_rejects_private_and_ambiguous_paths(self):
        for name in ("/absolute", "a/../b", "a//b", "a\\b", "C:/file",
                     "original/input.bin", "docs/private.ADF", ".claude/state",
                     "crates/amiga-lha/fixtures/real/notes.txt"):
            self.assertFalse(release.public_path(name), name)
        for name in (*SYNTHETIC, "src/lib.rs", "LICENSE-MIT"):
            self.assertTrue(release.public_path(name), name)

    def test_release_outputs_refuse_overwrite_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="amiga-release-") as tmp:
            path = Path(tmp) / "existing"
            path.write_bytes(b"retained")
            with self.assertRaises(FileExistsError):
                release.write_new(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"retained")
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                release.write_new(link, b"replacement")
            with self.assertRaises(ValueError):
                release.read(link)

    def test_crate_license_copies_match_the_root(self):
        apache = (ROOT / "LICENSE-APACHE").read_text()
        self.assertIn("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", apache)
        self.assertIn("END OF TERMS AND CONDITIONS", apache)
        self.assertIn("Copyright 2026 amiga-re contributors", apache)
        manifests = [*ROOT.glob("crates/*/Cargo.toml"), ROOT / "tools/amiga-re-cli/Cargo.toml"]
        for manifest in manifests:
            for name in ("LICENSE-MIT", "LICENSE-APACHE"):
                self.assertEqual((manifest.parent / name).read_bytes(),
                                 (ROOT / name).read_bytes(), str(manifest))

    def test_release_archive_has_deterministic_metadata(self):
        first = release.archive({"src/lib.rs": b"pub fn example() {}\n"})
        second = release.archive({"src/lib.rs": b"pub fn example() {}\n"})
        self.assertEqual(first, second)
        self.assertEqual(first[4:8], bytes(4), "gzip timestamp must be zero")

    def test_operations_media_regenerates(self):
        subprocess.run(["python3", str(ROOT / "crates/amiga-operations/fixtures/build-media.py"),
                        "--check"], check=True)


if __name__ == "__main__":
    unittest.main()
