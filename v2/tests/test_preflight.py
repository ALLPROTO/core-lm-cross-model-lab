from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from v2.preflight import verify_file_beneath, verify_regular_file


class PreflightFileTests(unittest.TestCase):
    def test_regular_file_digest_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve(strict=True) / "asset.bin"
            value = b"protocol-control-only"
            path.write_bytes(value)
            verify_regular_file(
                path,
                {
                    "bytes": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                },
            )

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            link = root / "link.bin"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "no-follow regular file"):
                verify_regular_file(
                    link,
                    {
                        "bytes": len(b"fixture"),
                        "sha256": hashlib.sha256(b"fixture").hexdigest(),
                    },
                )

    def test_intermediate_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            actual = root / "actual"
            actual.mkdir()
            value = b"fixture"
            (actual / "asset.bin").write_bytes(value)
            (root / "linked").symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink|invalid component"):
                verify_file_beneath(
                    root,
                    Path("linked") / "asset.bin",
                    {
                        "bytes": len(value),
                        "sha256": hashlib.sha256(value).hexdigest(),
                    },
                )
