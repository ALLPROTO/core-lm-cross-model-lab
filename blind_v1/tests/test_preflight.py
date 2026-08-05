from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from blind_v1.preflight import (
    _open_directory_no_symlinks,
    verify_asset_receipt,
    verify_file_beneath,
    verify_regular_file,
)
from blind_v1.reproducibility import sha256_bytes, with_content_digest


class PreflightFileTests(unittest.TestCase):
    def test_fixed_macos_temporary_alias_is_opened_without_general_resolution(
        self,
    ) -> None:
        if sys.platform != "darwin":
            return
        self.assertTrue(os.path.islink("/tmp"))
        self.assertEqual(os.path.realpath("/tmp"), "/private/tmp")
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            descriptor, canonical = _open_directory_no_symlinks(Path(directory))
            try:
                self.assertEqual(canonical.parts[:3], ("/", "private", "tmp"))
            finally:
                os.close(descriptor)

    def test_full_asset_receipt_is_bound_to_exact_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            manifest = {
                "models": {
                    "fixture-model": {
                        "repository": "fixture/model",
                        "revision": "a" * 40,
                        "license": "mit",
                        "licenseURL": "https://example.invalid/license",
                        "files": {
                            "model.safetensors": {
                                "bytes": 10,
                                "sha256": "b" * 64,
                            }
                        },
                    }
                }
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            receipt = with_content_digest(
                {
                    "schemaVersion": "corelm-blind-crossmodel-v1-asset-receipt-v1",
                    "status": "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED",
                    "countsTowardScientificVerdict": False,
                    "networkUsed": False,
                    "modelInferenceUsed": False,
                    "fullSafetensorsBytesLocallyVerified": True,
                    "manifestFileSHA256": sha256_bytes(manifest_path.read_bytes()),
                    "manifestFileBytes": len(manifest_path.read_bytes()),
                    "fileCount": 1,
                    "totalBytes": 10,
                    "fullSafetensorsBytes": 10,
                    "models": {
                        "fixture-model": {
                            "repository": "fixture/model",
                            "revision": "a" * 40,
                            "license": "mit",
                            "licenseURL": "https://example.invalid/license",
                            "files": {
                                "model.safetensors": {
                                    "bytes": 10,
                                    "sha256": "b" * 64,
                                }
                            },
                        }
                    },
                }
            )
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            observed = verify_asset_receipt(
                receipt_path,
                manifest_path=manifest_path,
                manifest=manifest,
                local_assets={"verified": True, "files": 1},
            )
            self.assertTrue(observed["verified"])
            receipt["totalBytes"] = 11
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "self-digest mismatch"):
                verify_asset_receipt(
                    receipt_path,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    local_assets={"verified": True, "files": 1},
                )

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
