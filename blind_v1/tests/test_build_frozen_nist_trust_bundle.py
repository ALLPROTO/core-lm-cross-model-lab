from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from blind_v1 import build_frozen_nist_trust_bundle as subject
from blind_v1.independent_verifier_core import load_independent_trust_bundle
from blind_v1.nist_beacon import (
    NIST_TRUST_ROOT_DER_SHA256,
    load_offline_trust_bundle,
)
from blind_v1.protocol import load_json_strict
from blind_v1.reproducibility import canonical_json_bytes


class FrozenNISTTrustBundleBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / "frozen-nist-trust"

    def test_builds_self_contained_status_only_bundle_without_overwrite(self) -> None:
        report = subject._historical_build_frozen_nist_trust_bundle(output_root=self.output)
        candidate = load_json_strict(subject.TRACKED_CANDIDATE_MANIFEST)
        frozen_path = self.output / "manifest.json"
        frozen = load_json_strict(frozen_path)
        self.assertEqual(candidate["status"], "CANDIDATE_OFFLINE_TRUST_BUNDLE")
        self.assertEqual(frozen["status"], "FROZEN_OFFLINE_TRUST_BUNDLE")
        subject.assert_status_only_promotion(candidate, frozen)
        self.assertEqual(
            self._without_status(candidate), self._without_status(frozen)
        )
        self.assertEqual(
            frozen_path.read_bytes(), canonical_json_bytes(frozen)
        )
        self.assertEqual(
            report["frozenManifestSHA256"],
            hashlib.sha256(frozen_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["candidateManifestSHA256"],
            subject.CANDIDATE_MANIFEST_SHA256,
        )
        self.assertEqual(
            report["frozenManifestSHA256"], subject.FROZEN_MANIFEST_SHA256
        )
        self.assertEqual(
            report["frozenManifestBytes"], subject.FROZEN_MANIFEST_BYTES
        )
        self.assertEqual(len(frozen_path.read_bytes()), subject.FROZEN_MANIFEST_BYTES)
        self.assertEqual(len(report["copiedFiles"]), 4)
        for relative in report["copiedFiles"]:
            self.assertTrue((self.output / relative).is_file())
        producer = load_offline_trust_bundle(
            frozen_path,
            expected_time=subject.TARGET_TIME,
            expected_manifest_sha256=report["frozenManifestSHA256"],
            expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
        )
        independent = load_independent_trust_bundle(
            frozen_path,
            expected_time=subject.TARGET_TIME,
            expected_manifest_sha256=report["frozenManifestSHA256"],
            expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
        )
        self.assertEqual(tuple(producer.records), tuple(independent.records))
        with self.assertRaises(FileExistsError):
            subject._historical_build_frozen_nist_trust_bundle(output_root=self.output)

    def test_structural_diff_rejects_every_non_status_mutation(self) -> None:
        candidate = load_json_strict(subject.TRACKED_CANDIDATE_MANIFEST)
        promoted = copy.deepcopy(candidate)
        promoted["status"] = "FROZEN_OFFLINE_TRUST_BUNDLE"
        promoted["trustPolicy"]["revocationChecked"] = True
        with self.assertRaisesRegex(
            subject.FrozenNISTTrustBuildError, "exactly candidate status"
        ):
            subject.assert_status_only_promotion(candidate, promoted)

    def test_exact_candidate_commitment_cannot_be_replaced_by_compatible_policy(self) -> None:
        candidate = load_json_strict(subject.TRACKED_CANDIDATE_MANIFEST)
        candidate["trustPolicy"]["revocationResidualRisk"] += " "
        replacement = self.root / "compatible-but-unregistered.json"
        replacement.write_bytes(canonical_json_bytes(candidate))
        with mock.patch.object(subject, "TRACKED_CANDIDATE_MANIFEST", replacement):
            with self.assertRaisesRegex(
                subject.FrozenNISTTrustBuildError,
                "tracked NIST trust input",
            ):
                subject._historical_build_frozen_nist_trust_bundle(output_root=self.output)

    def test_write_failure_leaves_no_final_or_staging_output(self) -> None:
        original_write = subject.write_new_bytes
        calls = 0

        def fail_second(path: Path, value: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected staging failure")
            original_write(path, value)

        with mock.patch.object(subject, "write_new_bytes", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "injected staging failure"):
                subject._historical_build_frozen_nist_trust_bundle(output_root=self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(
            list(self.root.glob(".corelm-nist-trust-staging-*")), []
        )

    def test_concurrent_destination_is_never_replaced(self) -> None:
        original_publish = subject._publish_directory_exclusive
        sentinel_raw = b"concurrent publisher owns this directory\n"

        def race(staging: Path, destination: Path) -> None:
            destination.mkdir(mode=0o700)
            (destination / "sentinel").write_bytes(sentinel_raw)
            original_publish(staging, destination)

        with mock.patch.object(
            subject,
            "_publish_directory_exclusive",
            side_effect=race,
        ):
            with self.assertRaises(FileExistsError):
                subject._historical_build_frozen_nist_trust_bundle(output_root=self.output)
        self.assertEqual((self.output / "sentinel").read_bytes(), sentinel_raw)
        self.assertFalse((self.output / "manifest.json").exists())
        self.assertEqual(
            list(self.root.glob(".corelm-nist-trust-staging-*")), []
        )

    def test_native_at_fdcwd_values_are_platform_specific(self) -> None:
        self.assertEqual(subject._at_fdcwd_for_platform("darwin"), -2)
        self.assertEqual(subject._at_fdcwd_for_platform("linux"), -100)
        self.assertEqual(subject._at_fdcwd_for_platform("linux-musl"), -100)
        with self.assertRaisesRegex(
            subject.FrozenNISTTrustBuildError,
            "platform lacks atomic exclusive directory publication",
        ):
            subject._at_fdcwd_for_platform("win32")

    def test_refuses_to_write_inside_tracked_project(self) -> None:
        destination = subject.BLIND_V1_ROOT / ".forbidden-nist-trust-output"
        self.assertFalse(destination.exists())
        with self.assertRaisesRegex(
            subject.FrozenNISTTrustBuildError, "outside the tracked project"
        ):
            subject._historical_build_frozen_nist_trust_bundle(output_root=destination)
        self.assertFalse(destination.exists())

    @staticmethod
    def _without_status(value: dict[str, object]) -> dict[str, object]:
        result = copy.deepcopy(value)
        result.pop("status")
        return result


if __name__ == "__main__":
    unittest.main()
