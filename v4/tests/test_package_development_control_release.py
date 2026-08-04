from __future__ import annotations

import copy
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from v4 import freeze_manifest
from v4 import package_development_control_release as subject
from v4.development_artifact_verifier import FULL_ASSET_RECEIPT_PATH
from v4.reproducibility import canonical_json_bytes, sha256_bytes


class DevelopmentControlReleasePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.artifact_root = self.root / "completed-control"
        self.artifact_root.mkdir()
        item_root = self.artifact_root / "items"
        item_root.mkdir()
        self.dataset = (
            b"# sent_id = packaging-fixture-1\n"
            b"# text = Package the pinned PUD evidence.\n"
            b"1\tPackage\tpackage\tVERB\t_\t_\t0\troot\t_\t_\n\n"
        )
        dataset_identity = mock.patch.multiple(
            freeze_manifest,
            DEVELOPMENT_DATASET_BYTES=len(self.dataset),
            DEVELOPMENT_DATASET_SHA256=sha256_bytes(self.dataset),
        )
        dataset_identity.start()
        self.addCleanup(dataset_identity.stop)

        project_root = freeze_manifest.PROJECT_ROOT
        self.full_asset_receipt = (
            project_root / "v4/manifests/model-assets.full-rehash.json"
        ).read_bytes()
        rights_files = {
            FULL_ASSET_RECEIPT_PATH: self.full_asset_receipt,
            "inputs/development-corpus.draft.json": (
                project_root / "v4/development-corpus.draft.json"
            ).read_bytes(),
            "inputs/corpus/en_pud-ud-test.conllu": self.dataset,
            "inputs/LICENSES/source-evidence.json": (
                project_root / "LICENSES/source-evidence.json"
            ).read_bytes(),
            "inputs/LICENSES/ASSET_LICENSES.md": (
                project_root / "LICENSES/ASSET_LICENSES.md"
            ).read_bytes(),
            "inputs/LICENSES/upstream/ud-english-pud-r2.18-README.md": (
                project_root
                / "LICENSES/upstream/ud-english-pud-r2.18-README.md"
            ).read_bytes(),
            "inputs/LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt": (
                project_root
                / "LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"
            ).read_bytes(),
            "inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md": (
                project_root / "LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md"
            ).read_bytes(),
        }
        raw = b"x"
        digest = sha256_bytes(raw)
        self.inventory = []
        for relative, rights_raw in rights_files.items():
            destination = self.artifact_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(rights_raw)
            self.inventory.append(
                {
                    "path": relative,
                    "bytes": len(rights_raw),
                    "sha256": sha256_bytes(rights_raw),
                }
            )
        for index in range(2088 - len(rights_files)):
            relative = f"items/{index:04d}.bin"
            (self.artifact_root / relative).write_bytes(raw)
            self.inventory.append(
                {"path": relative, "bytes": len(raw), "sha256": digest}
            )
        self.report_path = self.artifact_root / "development-control-report.json"
        self.report_path.write_bytes(
            canonical_json_bytes({"artifactInventory": self.inventory}) + b"\n"
        )
        self.runtime_path = self.root / "runtime-manifest.json"
        self.runtime_path.write_bytes(b"runtime\n")
        self.output = self.root / "release-assets"
        self.summary = {
            "reportFileSHA256": sha256_bytes(self.report_path.read_bytes()),
            "reportFileBytes": len(self.report_path.read_bytes()),
            "artifactSetSHA256": sha256_bytes(canonical_json_bytes(self.inventory)),
            "controlConfigurationSHA256": "c" * 64,
            "artifactCount": 2088,
            "executionId": (
                "development-execution-20260814T100000Z-0123456789abcdef"
            ),
            "startedAt": "2026-09-06T09:00:00Z",
            "completedAt": "2026-09-06T10:00:00Z",
        }
        verifier = mock.patch.object(
            subject,
            "verify_development_control_report",
            side_effect=lambda *_args, **_kwargs: copy.deepcopy(self.summary),
        )
        self.report_verifier = verifier.start()
        self.addCleanup(verifier.stop)

    def package(self) -> dict[str, object]:
        return subject.package_development_control_release(
            report_path=self.report_path,
            artifact_root=self.artifact_root,
            runtime_manifest_path=self.runtime_path,
            lab_repository="https://github.com/ALLPROTO/core-lm-cross-model-lab.git",
            lab_commit="1" * 40,
            lab_tree="2" * 40,
            codec_repository="https://github.com/ALLPROTO/core-lm-benchmark.git",
            codec_commit="3" * 40,
            codec_tree="4" * 40,
            output_root=self.output,
        )

    def refresh_report(self) -> None:
        self.report_path.write_bytes(
            canonical_json_bytes({"artifactInventory": self.inventory}) + b"\n"
        )
        report_raw = self.report_path.read_bytes()
        self.summary.update(
            {
                "reportFileSHA256": sha256_bytes(report_raw),
                "reportFileBytes": len(report_raw),
                "artifactSetSHA256": sha256_bytes(
                    canonical_json_bytes(self.inventory)
                ),
                "artifactCount": len(self.inventory),
            }
        )

    def replace_artifact(self, relative: str, raw: bytes) -> None:
        (self.artifact_root / relative).write_bytes(raw)
        commitment = next(item for item in self.inventory if item["path"] == relative)
        commitment.update({"bytes": len(raw), "sha256": sha256_bytes(raw)})
        self.refresh_report()

    def remove_artifact(self, relative: str) -> None:
        (self.artifact_root / relative).unlink()
        self.inventory[:] = [item for item in self.inventory if item["path"] != relative]
        self.refresh_report()

    def test_packages_all_reported_bytes_in_deterministic_read_only_zip(self) -> None:
        report = self.package()
        self.assertEqual(self.report_verifier.call_count, 2)
        self.assertEqual(
            self.report_verifier.call_args_list[0],
            mock.call(
                self.report_path,
                artifact_root=self.artifact_root,
                expected_implementation={
                    "repository": (
                        "https://github.com/ALLPROTO/core-lm-cross-model-lab.git"
                    ),
                    "commit": "1" * 40,
                    "tree": "2" * 40,
                },
                expected_codec={
                    "repository": "https://github.com/ALLPROTO/core-lm-benchmark.git",
                    "commit": "3" * 40,
                    "tree": "4" * 40,
                },
                completed_no_later_than=freeze_manifest.DESIGN_PUBLISH_DEADLINE,
                expected_runtime_manifest_sha256=sha256_bytes(
                    self.runtime_path.read_bytes()
                ),
                require_artifacts=True,
            ),
        )
        self.assertEqual(
            report["status"],
            "VERIFIED_LOCAL_DEVELOPMENT_CONTROL_RELEASE_ASSETS",
        )
        self.assertEqual(report["artifactCount"], 2088)
        self.assertEqual(
            {path.name for path in self.output.iterdir()}, set(subject.ASSET_NAMES)
        )
        self.assertEqual(stat.S_IMODE(os.lstat(self.output).st_mode), 0o555)
        for name in subject.ASSET_NAMES:
            self.assertEqual(
                stat.S_IMODE(os.lstat(self.output / name).st_mode), 0o444
            )
        with zipfile.ZipFile(
            self.output / "development-control-artifacts.zip", "r"
        ) as archive:
            information = archive.infolist()
            member_names = {item.filename for item in information}
            self.assertEqual(len(information), 2088)
            self.assertIn(FULL_ASSET_RECEIPT_PATH, member_names)
            self.assertNotIn("inputs/full-asset-receipt.json", member_names)
            self.assertEqual(
                archive.read(FULL_ASSET_RECEIPT_PATH), self.full_asset_receipt
            )
            self.assertEqual(
                [item.filename for item in information],
                sorted((item["path"] for item in self.inventory), key=os.fsencode),
            )
            self.assertTrue(
                all(item.date_time == subject.ZIP_TIMESTAMP for item in information)
            )
            self.assertTrue(
                all(item.compress_type == zipfile.ZIP_STORED for item in information)
            )
        manifest = freeze_manifest._load_canonical_line_bytes(
            (self.output / "sha256-manifest.json").read_bytes(),
            label="test development archive manifest",
        )
        self.assertEqual(
            manifest["rights"], freeze_manifest.DEVELOPMENT_RIGHTS_DECLARATION
        )
        verified = subject.verify_development_control_release_assets(
            self.output, expected_report_path=self.report_path
        )
        self.assertEqual(verified["artifactSetSHA256"], self.summary["artifactSetSHA256"])

    def test_report_archive_and_manifest_tampering_fail_closed(self) -> None:
        self.package()
        os.chmod(self.output, 0o755)
        archive_path = self.output / "development-control-artifacts.zip"
        os.chmod(archive_path, 0o644)
        archive_path.write_bytes(archive_path.read_bytes() + b"tamper")
        os.chmod(archive_path, 0o444)
        os.chmod(self.output, 0o555)
        with self.assertRaisesRegex(
            subject.FreezeManifestError,
            "archive asset inventory differs|archive SHA-256 manifest differs",
        ):
            subject.verify_development_control_release_assets(
                self.output, expected_report_path=self.report_path
            )

    def test_archive_member_set_rejects_missing_and_extra_files(self) -> None:
        self.package()
        archive_path = self.output / "development-control-artifacts.zip"
        archive_sha256 = sha256_bytes(archive_path.read_bytes())
        missing_member_inventory = [
            *self.inventory,
            {"path": "items/missing.bin", "bytes": 1, "sha256": "0" * 64},
        ]
        extra_member_inventory = self.inventory[:-1]
        for label, inventory in (
            ("missing", missing_member_inventory),
            ("extra", extra_member_inventory),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                freeze_manifest.FreezeManifestError,
                "member order/set differs",
            ):
                freeze_manifest._verify_development_archive_zip(
                    archive_path,
                    inventory=inventory,
                    expected_sha256=archive_sha256,
                )

    def test_archive_rejects_accidentally_embedded_model_asset(self) -> None:
        self.package()
        archive_path = self.output / "development-control-artifacts.zip"
        os.chmod(self.output, 0o755)
        os.chmod(archive_path, 0o644)
        with zipfile.ZipFile(archive_path, "a", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(
                "models/smollm2-360m/model.safetensors",
                b"must remain an external private input",
            )
        os.chmod(archive_path, 0o444)
        os.chmod(self.output, 0o555)
        with self.assertRaisesRegex(
            freeze_manifest.FreezeManifestError,
            "member order/set differs",
        ):
            freeze_manifest._verify_development_archive_zip(
                archive_path,
                inventory=self.inventory,
                expected_sha256=sha256_bytes(archive_path.read_bytes()),
            )

    def test_archive_size_cap_fails_before_write_and_during_verify(self) -> None:
        with mock.patch.object(subject, "DEVELOPMENT_ARCHIVE_MAX_BYTES", 1024):
            with self.assertRaisesRegex(
                subject.DevelopmentControlPackageError,
                "cannot fit below",
            ):
                self.package()
        self.assertFalse(self.output.exists())

        self.package()
        archive_path = self.output / "development-control-artifacts.zip"
        archive_raw = archive_path.read_bytes()
        exact_size = len(archive_raw)
        with mock.patch.object(
            subject, "DEVELOPMENT_ARCHIVE_MAX_BYTES", exact_size
        ), self.assertRaisesRegex(
            subject.DevelopmentControlPackageError, "size cap"
        ):
            subject._bounded_archive_commitment(archive_path)
        with mock.patch.object(
            freeze_manifest, "DEVELOPMENT_ARCHIVE_MAX_BYTES", exact_size
        ), self.assertRaisesRegex(
            freeze_manifest.FreezeManifestError, "size cap"
        ):
            freeze_manifest._verify_development_archive_zip(
                archive_path,
                inventory=self.inventory,
                expected_sha256=sha256_bytes(archive_raw),
            )

    def test_tampered_pud_rights_fail_before_package_verification_succeeds(self) -> None:
        relative = "inputs/LICENSES/upstream/ud-english-pud-r2.18-README.md"
        self.replace_artifact(
            relative,
            (self.artifact_root / relative).read_bytes().replace(
                b"License: CC BY-SA 3.0", b"License: MIT", 1
            ),
        )
        with self.assertRaisesRegex(
            subject.FreezeManifestError,
            "rights evidence differs|rights or attribution declaration differs",
        ):
            self.package()
        self.assertFalse(self.output.exists())

    def test_missing_pud_rights_fail_before_package_verification_succeeds(self) -> None:
        self.remove_artifact(
            "inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md"
        )
        with self.assertRaisesRegex(
            subject.FreezeManifestError,
            "rights artifact|rights evidence differs|attribution",
        ):
            self.package()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
