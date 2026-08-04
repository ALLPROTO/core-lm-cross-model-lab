from __future__ import annotations

import hashlib
import json
import platform
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from v3.github_release_attestation import build_attestation_record
from v3 import release_attestation_crypto
from v3.tests import integration_release_attestation_crypto_known_answer as subject


class RealReleaseAttestationVectorTests(unittest.TestCase):
    def test_tracked_real_vector_provenance_rights_and_bytes_are_pinned(self) -> None:
        raw, assets = subject._load_vector()
        metadata = json.loads((subject.VECTOR_ROOT / "metadata.json").read_bytes())
        self.assertEqual(len(raw), subject.RAW_OUTPUT_BYTES)
        self.assertEqual(len(assets), 22)
        self.assertEqual(
            min(assets, key=lambda item: item[0].encode("ascii")),
            (subject.ASSET_NAME, subject.ASSET_SHA256),
        )
        self.assertIs(metadata["synthetic"], False)
        self.assertIs(metadata["expectedVerification"]["networkUsed"], False)
        self.assertEqual(metadata["provenance"]["repository"], "cli/cli")
        self.assertEqual(metadata["provenance"]["commit"], subject.COMMIT)
        self.assertEqual(
            metadata["rights"]["chosenAsset"]["spdxLicenseExpression"],
            "MIT",
        )
        self.assertEqual(
            metadata["rights"]["attestationOutput"]["classification"],
            "MACHINE_GENERATED_PUBLIC_CRYPTOGRAPHIC_AND_FACTUAL_RECORD",
        )

    def test_cosign_receives_private_digest_checked_asset_copy(self) -> None:
        raw_output, _assets = subject._load_vector()
        asset_raw = (subject.VECTOR_ROOT / subject.ASSET_NAME).read_bytes()
        with tempfile.TemporaryDirectory() as temporary_value:
            temporary = Path(temporary_value)
            asset_root = temporary / "assets"
            asset_root.mkdir()
            original_asset = asset_root / subject.ASSET_NAME
            original_asset.write_bytes(asset_raw)
            fake_cosign = temporary / "cosign"
            fake_cosign.write_bytes(b"pinned-cosign-fixture")
            fake_cosign.chmod(0o700)
            system_variant = (platform.system(), platform.machine())
            variant = {
                "platform": "darwin/arm64",
                "bytes": len(fake_cosign.read_bytes()),
                "sha256": hashlib.sha256(fake_cosign.read_bytes()).hexdigest(),
                "url": "https://example.invalid/pinned-cosign-fixture",
            }

            def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
                private_asset = Path(command[-1])
                self.assertNotEqual(private_asset, original_asset)
                self.assertEqual(private_asset.parent, Path(command[0]).parent)
                self.assertEqual(private_asset.read_bytes(), asset_raw)
                return SimpleNamespace(
                    returncode=0,
                    stdout=b"",
                    stderr=b"Verified OK\n",
                )

            with (
                patch.dict(
                    release_attestation_crypto.COSIGN_BINARY_VARIANTS,
                    {system_variant: variant},
                    clear=True,
                ),
                patch.object(
                    release_attestation_crypto.PinnedCosignReleaseAttestationVerifier,
                    "_version",
                    return_value=None,
                ),
                patch.object(
                    release_attestation_crypto.subprocess,
                    "run",
                    side_effect=fake_run,
                ),
            ):
                verified = (
                    release_attestation_crypto.PinnedCosignReleaseAttestationVerifier(
                        fake_cosign
                    ).verify(
                        attestation_record=build_attestation_record(raw_output, {}),
                        asset_root=asset_root,
                        expected_assets=((subject.ASSET_NAME, subject.ASSET_SHA256),),
                    )
                )
            self.assertEqual(verified.verified_asset_sha256, subject.ASSET_SHA256)

    def test_cosign_rejects_symlink_and_hardlink_asset_paths(self) -> None:
        raw_output, _assets = subject._load_vector()
        asset_raw = (subject.VECTOR_ROOT / subject.ASSET_NAME).read_bytes()
        with tempfile.TemporaryDirectory() as temporary_value:
            temporary = Path(temporary_value)
            fake_cosign = temporary / "cosign"
            fake_cosign.write_bytes(b"unused")
            fake_cosign.chmod(0o700)
            target = temporary / "target"
            target.write_bytes(asset_raw)
            for link_kind in ("symlink", "hardlink"):
                asset_root = temporary / link_kind
                asset_root.mkdir()
                path = asset_root / subject.ASSET_NAME
                if link_kind == "symlink":
                    path.symlink_to(target)
                else:
                    path.hardlink_to(target)
                with self.assertRaisesRegex(
                    release_attestation_crypto.ReleaseAttestationCryptoError,
                    "asset type differs",
                ):
                    release_attestation_crypto.PinnedCosignReleaseAttestationVerifier(
                        fake_cosign
                    ).verify(
                        attestation_record=build_attestation_record(raw_output, {}),
                        asset_root=asset_root,
                        expected_assets=((subject.ASSET_NAME, subject.ASSET_SHA256),),
                    )
                path.unlink()


if __name__ == "__main__":
    unittest.main()
