from __future__ import annotations

import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from blind_v1.model_card_evidence import ModelCardEvidenceError, _read_regular


class ModelCardEvidenceIOTests(unittest.TestCase):
    def _metadata(self, path: Path, **changes: int) -> types.SimpleNamespace:
        observed = path.stat()
        values = {
            "st_dev": observed.st_dev,
            "st_ino": observed.st_ino,
            "st_mode": observed.st_mode,
            "st_nlink": observed.st_nlink,
            "st_uid": observed.st_uid,
            "st_gid": observed.st_gid,
            "st_size": observed.st_size,
            "st_atime_ns": observed.st_atime_ns,
            "st_mtime_ns": observed.st_mtime_ns,
        }
        values.update(changes)
        return types.SimpleNamespace(**values)

    def test_atime_only_change_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "card.md"
            raw = b"model card\n"
            path.write_bytes(raw)
            before = self._metadata(path)
            after = self._metadata(path, st_atime_ns=before.st_atime_ns + 1)

            with mock.patch(
                "blind_v1.model_card_evidence.os.fstat",
                side_effect=[before, after],
            ):
                self.assertEqual(_read_regular(path, maximum_bytes=1024), raw)

    def test_content_change_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "card.md"
            original = b"original\n"
            path.write_bytes(original)
            before = path.stat()
            real_read = os.read
            changed = False

            def read_then_change(descriptor: int, count: int) -> bytes:
                nonlocal changed
                chunk = real_read(descriptor, count)
                if chunk and not changed:
                    changed = True
                    path.write_bytes(b"mutated!\n")
                    os.utime(
                        path,
                        ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
                    )
                return chunk

            with mock.patch(
                "blind_v1.model_card_evidence.os.read",
                side_effect=read_then_change,
            ):
                with self.assertRaisesRegex(
                    ModelCardEvidenceError,
                    "changed while read",
                ):
                    _read_regular(path, maximum_bytes=1024)

    def test_descriptor_identity_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "card.md"
            path.write_bytes(b"model card\n")
            before = self._metadata(path)
            after = self._metadata(path, st_ino=before.st_ino + 1)

            with mock.patch(
                "blind_v1.model_card_evidence.os.fstat",
                side_effect=[before, after],
            ):
                with self.assertRaisesRegex(
                    ModelCardEvidenceError,
                    "changed while read",
                ):
                    _read_regular(path, maximum_bytes=1024)


if __name__ == "__main__":
    unittest.main()
