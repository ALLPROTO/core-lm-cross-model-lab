from __future__ import annotations

import copy
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from v3 import freeze_manifest
from v3 import package_design_release as subject
from v3.collect_github_gate_receipt import collect_github_gate_receipt_to_path
from v3.create_sbom import build_sbom
from v3.protocol import load_json_strict
from v3.release_attestation_crypto import expected_known_answer_result
from v3.reproducibility import (
    canonical_json_bytes,
    sha256_bytes,
    with_content_digest,
)
from v3.tests import test_freeze_manifest as freeze_fixture_module
from v3.tests.test_github_gate_receipt import (
    PR as GATE_PR,
    RUN_ID as GATE_RUN_ID,
    WORKFLOW_NAME as GATE_WORKFLOW_NAME,
    WORKFLOW_PATH as GATE_WORKFLOW_PATH,
    FakeTransport as GateFakeTransport,
    _base_bodies as gate_base_bodies,
)


class PackageDesignReleaseTests(unittest.TestCase):
    @staticmethod
    def _pretty(value: dict[str, Any]) -> bytes:
        return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    @staticmethod
    def _zip_members(members: dict[str, bytes]) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(
            output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=False,
        ) as archive:
            for name, raw in members.items():
                member = zipfile.ZipInfo(name, date_time=(2026, 8, 3, 12, 0, 0))
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o444) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, raw)
        return output.getvalue()

    def _ci_runtime(
        self,
        *,
        role: str,
        system: str,
        machine: str,
        platform_tag: str,
    ) -> bytes:
        runtime = load_json_strict(self.fixture.runtime_path)
        del runtime["contentSHA256"]
        runtime["python"]["platformTag"] = platform_tag
        runtime["host"] = {
            "system": system,
            "release": "unit-release",
            "version": "unit-version",
            "machine": machine,
            "processor": machine,
            "macVersion": "15.0" if system == "Darwin" else None,
        }
        runtime["environment"] = {
            name: None for name in sorted(subject.RUNTIME_ENVIRONMENT_KEYS)
        }
        if role == "linux-ci-artifact":
            runtime["requirementsLocks"] = [
                {
                    "name": name,
                    "bytes": index + 1,
                    "sha256": f"{index + 1:x}" * 64,
                }
                for index, name in enumerate(
                    subject.CI_REQUIREMENTS_LOCK_NAMES[role]
                )
            ]
            runtime["requirementsLocks"][0] = {
                "name": "pip-bootstrap.txt",
                "bytes": 173,
                "sha256": self.draft["runtime"][
                    "pipBootstrapLockSHA256"
                ],
            }
        else:
            runtime["requirementsLocks"] = [
                {
                    "name": "pip-bootstrap.txt",
                    "bytes": 173,
                    "sha256": self.draft["runtime"][
                        "pipBootstrapLockSHA256"
                    ],
                },
                {
                    "name": "requirements.lock",
                    "bytes": 55781,
                    "sha256": self.draft["runtime"]["requirementsLockSHA256"],
                },
            ]
        for source_name in ("labSource", "codecSource"):
            runtime[source_name]["worktreeStatusSHA256"] = sha256_bytes(b"")
        return canonical_json_bytes(with_content_digest(runtime)) + b"\n"

    def _ci_members(
        self,
        *,
        role: str,
        system: str,
        machine: str,
        platform_tag: str,
    ) -> dict[str, bytes]:
        suffix = subject.CI_PLATFORM_SPECS[role]["memberSuffix"]
        design_raw = (subject.V3_ROOT / "design-registration.draft.json").read_bytes()
        design_sha256 = sha256_bytes(design_raw)
        preflight = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-preflight-v1",
            "status": "DEVELOPMENT_PREFLIGHT_ONLY",
            "countsTowardScientificVerdict": False,
            "networkUsed": False,
            "modelInferenceUsed": False,
            "corpusOpened": False,
            "attemptMarkerCreated": False,
            "primaryPlatformRequired": "Darwin-arm64",
            "designSHA256": design_sha256,
            "codec": {
                "commit": self.freeze_fixture_codec["commit"],
                "tree": self.freeze_fixture_codec["tree"],
                "files": self.draft["codecSource"]["requiredFiles"],
            },
            "assetManifest": {"fixture": "unit-contract"},
            "localAssets": {"provided": False, "verified": False, "files": 0},
            "assetReceipt": {"provided": False, "verified": False},
            "platformSafety": {
                "system": system,
                "machine": machine,
                "acPower": None,
                "freeMemoryPercent": None,
            },
            "resultBoundary": {"pristine": True, "entries": ["README.md"]},
            "executionReady": False,
            "readinessFailures": ["unit-contract draft is not frozen"],
        }
        design_check = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-design-check-v1",
            "status": "DRAFT_VERIFIED_NOT_PREREGISTERED",
            "readyToFreeze": False,
            "freezeValidatorImplemented": True,
            "countsTowardScientificVerdict": False,
            "designRegistrationFileSHA256": design_sha256,
            "canonicalDesignSHA256": sha256_bytes(
                canonical_json_bytes(self.draft)
            ),
            "modelAssetManifestFileSHA256": sha256_bytes(
                (subject.V3_ROOT / "model-assets.draft.json").read_bytes()
            ),
            "modelAssetSummary": {"fixture": "unit-contract"},
            "knownAnswerSelectionSHA256": "4" * 64,
            "knownAnswerDrawsSHA256": "5" * 64,
            "freezeBlockers": list(self.draft["freezeBlockers"]),
            "workflowFileBytes": self.draft["continuousIntegration"][
                "workflowFileBytes"
            ],
            "workflowFileSHA256": self.draft["continuousIntegration"][
                "workflowFileSHA256"
            ],
            "platformSafety": {"system": system, "machine": machine},
            "networkUsed": False,
            "modelInferenceUsed": False,
            "corpusOpened": False,
        }
        log = (
            b"test_contract (v3.tests.UnitContract.test_contract) ... ok\n"
            b"\n----------------------------------------------------------------------\n"
            b"Ran 1 test in 0.001s\n\nOK\n"
            b"ZERO-SKIP POLICY PASS: 1 tests, 0 skipped\n"
        )
        return {
            f"v3-preflight-{suffix}.json": self._pretty(preflight),
            f"v3-runtime-{suffix}.json": self._ci_runtime(
                role=role,
                system=system,
                machine=machine,
                platform_tag=platform_tag,
            ),
            f"v3-zero-skip-{suffix}.log": log,
            f"v3-design-check-{suffix}.json": self._pretty(design_check),
            f"v3-release-attestation-known-answer-{suffix}.json": self._pretty(
                expected_known_answer_result(
                    expected_platform=subject.CI_PLATFORM_SPECS[role][
                        "cosignPlatform"
                    ]
                )
            ),
        }

    def setUp(self) -> None:
        fixture = freeze_fixture_module.FreezeManifestTests(
            "test_generator_is_canonical_binds_inputs_and_has_no_file_self_reference"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root

        self.asset_source_path = subject.V3_ROOT / "model-assets.draft.json"
        self.design_path = self.root / "design-registration.json"
        self.freeze_path = self.root / "freeze-manifest.json"
        self.sbom_path = self.root / "sbom.cdx.json"
        self.development_report_path = (
            self.root / "development-control-report.json"
        )
        self.development_archive_receipt_path = (
            self.root / "development-control-archive-receipt.json"
        )
        self.key_path = self.root / "design-release-signing-key.pub"

        draft = load_json_strict(subject.V3_ROOT / "design-registration.draft.json")
        self.draft = draft
        codec = draft["codecSource"]
        self.freeze_fixture_codec = {
            "commit": codec["commit"],
            "tree": codec["tree"],
        }
        self.development_report_path.write_bytes(
            canonical_json_bytes({"unitFixture": True}) + b"\n"
        )
        archive_receipt = with_content_digest(
            {
                "schemaVersion": "corelm-github-release-receipt-v2",
                "suiteId": subject.SUITE_ID,
                "kind": "development-control",
                "tag": freeze_manifest.DEVELOPMENT_ARCHIVE_TAG,
                "source": {
                    "commit": freeze_fixture_module.LAB_COMMIT,
                    "tree": freeze_fixture_module.LAB_TREE,
                },
                "release": {
                    "publishedAt": "2026-08-08T10:05:00Z",
                    "deadline": "2026-08-15T00:00:00Z",
                },
            }
        )
        self.development_archive_receipt_path.write_bytes(
            canonical_json_bytes(archive_receipt) + b"\n"
        )

        def fake_development_verifier(
            report_path: Path, **_kwargs: Any
        ) -> dict[str, Any]:
            raw = report_path.read_bytes()
            return {
                "reportFileSHA256": sha256_bytes(raw),
                "reportFileBytes": len(raw),
                "artifactSetSHA256": "b" * 64,
                "controlConfigurationSHA256": "c" * 64,
                "artifactCount": 2088,
                "executionId": (
                    "development-execution-20260808T100000Z-0123456789abcdef"
                ),
                "startedAt": "2026-08-08T09:00:00Z",
                "completedAt": "2026-08-08T10:00:00Z",
            }

        def fake_archive_verifier(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "status": "VERIFIED_GITHUB_ATTESTED_DEVELOPMENT_ARCHIVE",
                "receiptSHA256": sha256_bytes(
                    self.development_archive_receipt_path.read_bytes()
                ),
                "publishedAt": "2026-08-08T10:05:00Z",
                "attestedAt": "2026-08-08T10:05:01Z",
                "attestationBundleSHA256": "1" * 64,
                "attestationOutputSHA256": "2" * 64,
                "artifactArchiveSHA256": "e" * 64,
                "archiveManifestSHA256": "f" * 64,
                "reportSHA256": sha256_bytes(
                    self.development_report_path.read_bytes()
                ),
            }

        self.fake_development_verifier = fake_development_verifier
        self.fake_archive_verifier = fake_archive_verifier
        verifier_patch = mock.patch.object(
            freeze_manifest,
            "verify_development_control_report",
            side_effect=fake_development_verifier,
        )
        verifier_patch.start()
        self.addCleanup(verifier_patch.stop)
        runtime = load_json_strict(fixture.runtime_path)
        del runtime["contentSHA256"]
        runtime["requirementsLocks"] = copy.deepcopy(
            freeze_manifest.REGISTERED_REQUIREMENTS_LOCKS
        )
        runtime["installedDistributions"] = [
            {
                "name": "unit-contract",
                "normalizedName": "unit-contract",
                "version": "1.0",
                "metadataSHA256": None,
                "recordSHA256": None,
                "declaredFiles": 0,
                "licenseExpression": "MIT",
                "licenseDeclared": None,
                "requiresDist": [],
            }
        ]
        runtime["labSource"] = fixture._source(
            freeze_fixture_module.LAB_REPOSITORY,
            freeze_fixture_module.LAB_COMMIT,
            freeze_fixture_module.LAB_TREE,
            clean=True,
        )
        runtime["codecSource"] = fixture._source(
            codec["repository"], codec["commit"], codec["tree"], clean=True
        )
        fixture.runtime_path.write_bytes(
            canonical_json_bytes(with_content_digest(runtime)) + b"\n"
        )

        self.linux_ci_path = self.root / "linux-actions-artifact.zip"
        self.macos_ci_path = self.root / "macos-actions-artifact.zip"
        self.ci_member_bytes = {
            "linux-ci-artifact": self._ci_members(
                role="linux-ci-artifact",
                system="Linux",
                machine="x86_64",
                platform_tag="linux-x86_64",
            ),
            "macos-arm64-ci-artifact": self._ci_members(
                role="macos-arm64-ci-artifact",
                system="Darwin",
                machine="arm64",
                platform_tag="macosx-15.0-arm64",
            ),
        }
        self.linux_ci_path.write_bytes(
            self._zip_members(self.ci_member_bytes["linux-ci-artifact"])
        )
        self.macos_ci_path.write_bytes(
            self._zip_members(self.ci_member_bytes["macos-arm64-ci-artifact"])
        )

        fixture.gate_path.unlink()
        collect_github_gate_receipt_to_path(
            output=fixture.gate_path,
            repository="ALLPROTO/core-lm-cross-model-lab",
            pull_request_number=GATE_PR,
            implementation_commit=freeze_fixture_module.LAB_COMMIT,
            workflow_run_id=GATE_RUN_ID,
            workflow_name=GATE_WORKFLOW_NAME,
            workflow_path=GATE_WORKFLOW_PATH,
            transport=GateFakeTransport(
                gate_base_bodies(
                    linux_artifact_sha256=sha256_bytes(
                        self.linux_ci_path.read_bytes()
                    ),
                    macos_artifact_sha256=sha256_bytes(
                        self.macos_ci_path.read_bytes()
                    ),
                )
            ),
            now=lambda: "2026-08-08T10:05:30Z",
        )

        manifest = freeze_manifest.build_freeze_manifest(
            runtime_manifest_path=fixture.runtime_path,
            asset_receipt_path=fixture.asset_path,
            ca_bundle_path=fixture.ca_path,
            trust_manifest_path=fixture.trust_path,
            lab_repository=freeze_fixture_module.LAB_REPOSITORY,
            lab_commit=freeze_fixture_module.LAB_COMMIT,
            lab_tree=freeze_fixture_module.LAB_TREE,
            codec_repository=codec["repository"],
            codec_commit=codec["commit"],
            codec_tree=codec["tree"],
            github_gate_receipt_path=fixture.gate_path,
            development_control_report_path=self.development_report_path,
            development_control_artifact_root=fixture.development_artifact_root,
            development_control_archive_receipt_path=(
                self.development_archive_receipt_path
            ),
            development_control_archive_asset_root=(
                fixture.development_archive_asset_root
            ),
            created_at="2026-08-08T10:06:00Z",
            ca_verifier=fixture.ca_verifier,
            trust_verifier=fixture.trust_verifier,
            development_control_verifier=fake_development_verifier,
            development_archive_verifier=fake_archive_verifier,
        )
        freeze_raw = freeze_manifest.canonical_freeze_manifest_bytes(manifest)
        self.freeze_path.write_bytes(freeze_raw)

        key_raw = (
            subject.V3_ROOT / "signing" / "corelm-crossmodel-v3-signing.pub"
        ).read_bytes()
        self.key_path.write_bytes(key_raw)

        design = copy.deepcopy(draft)
        design.update(
            schemaVersion="corelm-crossmodel-livewiki-v3-design-v1",
            status="PUBLIC_DESIGN_FROZEN",
            readyToFreeze=True,
            freezeBlockers=[],
        )
        design["labSource"].update(
            status="FROZEN_BOUND",
            commit=freeze_fixture_module.LAB_COMMIT,
            tree=freeze_fixture_module.LAB_TREE,
            freezeManifestSHA256=sha256_bytes(freeze_raw),
        )
        design["runtime"].update(
            status="FROZEN_BOUND",
            runtimeManifestSHA256=manifest["artifacts"]["runtimeManifestSHA256"],
        )
        design["developmentControls"]["realDataE2EFreezeGate"].update(
            status="ARCHIVED_VERIFIED_BEFORE_FREEZE",
            executionId=manifest["developmentControl"]["executionId"],
            archiveReceiptSHA256=manifest["artifacts"][
                "developmentControlArchiveReceiptSHA256"
            ],
            archivePublishedAt=manifest["developmentControl"][
                "archivePublishedAt"
            ],
            archiveAttestedAt=manifest["developmentControl"][
                "archiveAttestedAt"
            ],
            releaseAttestationBundleSHA256=manifest["artifacts"][
                "developmentControlReleaseAttestationBundleSHA256"
            ],
            releaseAttestationOutputSHA256=manifest["artifacts"][
                "developmentControlReleaseAttestationOutputSHA256"
            ],
            reportSHA256=manifest["artifacts"][
                "developmentControlReportSHA256"
            ],
            artifactSetSHA256=manifest["artifacts"][
                "developmentControlArtifactSetSHA256"
            ],
            controlConfigurationSHA256=manifest["artifacts"][
                "developmentControlConfigurationSHA256"
            ],
            completedAt=manifest["developmentControl"]["completedAt"],
        )
        design["beacon"].update(
            transportCABundleSHA256=manifest["artifacts"][
                "transportCABundleSHA256"
            ],
            offlineTrustBundleSHA256=manifest["artifacts"][
                "offlineTrustBundleSHA256"
            ],
        )
        for role in (
            "designRelease",
            "snapshotRelease",
            "evidenceRelease",
            "closeoutRelease",
        ):
            self.assertEqual(
                design[role]["signingPublicKeySHA256"], sha256_bytes(key_raw)
            )
        self.design_path.write_bytes(canonical_json_bytes(design) + b"\n")

        runtime = load_json_strict(fixture.runtime_path)
        assets = load_json_strict(fixture.asset_path)
        self.sbom_path.write_bytes(
            canonical_json_bytes(build_sbom(runtime, assets)) + b"\n"
        )

    def _package(self, name: str) -> subject.DesignReleaseVerification:
        return subject.package_design_release(
            frozen_design_path=self.design_path,
            development_control_report_path=self.development_report_path,
            development_control_archive_receipt_path=(
                self.development_archive_receipt_path
            ),
            freeze_manifest_path=self.freeze_path,
            github_gate_receipt_path=self.fixture.gate_path,
            linux_ci_artifact_path=self.linux_ci_path,
            macos_arm64_ci_artifact_path=self.macos_ci_path,
            asset_source_manifest_path=self.asset_source_path,
            full_asset_receipt_path=self.fixture.asset_path,
            runtime_manifest_path=self.fixture.runtime_path,
            sbom_path=self.sbom_path,
            signing_public_key_path=self.key_path,
            output_root=self.root / name,
        )

    def _verify_payload(
        self, role: str, raw_zip: bytes
    ) -> subject.CIArtifactVerification:
        design = load_json_strict(self.design_path)
        freeze = load_json_strict(self.freeze_path)
        spec = subject.CI_PLATFORM_SPECS[role]
        return subject._verify_ci_artifact_payload(
            role=role,
            raw_zip=raw_zip,
            github_actions_artifact_name=(
                f"{spec['artifactPrefix']}{GATE_RUN_ID}-1"
            ),
            expected_archive_sha256=sha256_bytes(raw_zip),
            workflow_run_id=GATE_RUN_ID,
            design=design,
            freeze=freeze,
        )

    def test_package_is_deterministic_exact_read_only_and_self_excluding(self) -> None:
        first = self._package("release-a")
        second = self._package("release-b")
        first_root = first.asset_root
        second_root = second.asset_root

        self.assertEqual(tuple(record.role for record in first.assets), subject.ASSET_ROLES)
        self.assertEqual(len(first.assets), 12)
        self.assertEqual(
            [item.role for item in first.ci_artifacts],
            ["linux-ci-artifact", "macos-arm64-ci-artifact"],
        )
        ci_schema = load_json_strict(
            subject.V3_ROOT / "schemas" / "ci-artifact-verification.schema.json"
        )
        validator = jsonschema.Draft202012Validator(ci_schema)
        for item in first.ci_artifacts:
            validator.validate(item.as_dict())
            self.assertEqual(item.tests_run, 1)
            self.assertEqual(len(item.members), 5)
        self.assertEqual(
            {path.name for path in first_root.iterdir()},
            set(subject.ASSET_NAMES.values()),
        )
        self.assertNotIn(self.key_path.name, {path.name for path in first_root.iterdir()})
        for role, filename in subject.ASSET_NAMES.items():
            first_raw = (first_root / filename).read_bytes()
            second_raw = (second_root / filename).read_bytes()
            self.assertEqual(first_raw, second_raw, role)
            metadata = os.lstat(first_root / filename)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o444)
            self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(os.lstat(first_root).st_mode), 0o555)

        sha_manifest = load_json_strict(first_root / "sha256-manifest.json")
        self.assertEqual(sha_manifest["excludedRole"], "sha256-manifest")
        self.assertEqual(sha_manifest["assetCount"], 11)
        self.assertEqual(sha_manifest["releaseAssetCount"], 12)
        self.assertNotIn(
            "sha256-manifest",
            [record["role"] for record in sha_manifest["assets"]],
        )
        verified = subject.verify_design_release_package(
            first_root, signing_public_key_path=self.key_path
        )
        self.assertEqual(verified.assets, first.assets)

    def test_cross_binding_tampering_fails_before_output_creation(self) -> None:
        original = self.sbom_path.read_bytes()
        sbom = load_json_strict(self.sbom_path)
        sbom["version"] = 2
        self.sbom_path.write_bytes(canonical_json_bytes(sbom) + b"\n")
        output = self.root / "bad-sbom"
        with self.assertRaisesRegex(subject.DesignReleaseError, "SBOM differs"):
            self._package(output.name)
        self.assertFalse(output.exists())
        self.sbom_path.write_bytes(original)

        key_raw = self.key_path.read_bytes()
        key_fields = key_raw.rstrip(b"\n").split(b" ", 2)
        self.key_path.write_bytes(
            key_fields[0] + b" " + key_fields[1] + b" changed-comment\n"
        )
        output = self.root / "bad-key"
        with self.assertRaisesRegex(subject.DesignReleaseError, "SSH key differs"):
            self._package(output.name)
        self.assertFalse(output.exists())

    def test_ci_zip_digest_inventory_platform_workflow_and_zero_skip_fail_closed(self) -> None:
        original_linux = self.linux_ci_path.read_bytes()
        self.linux_ci_path.write_bytes(original_linux + b"trailer")
        with self.assertRaisesRegex(subject.DesignReleaseError, "raw ZIP differs"):
            self._package("bad-ci-digest")
        self.assertFalse((self.root / "bad-ci-digest").exists())
        self.linux_ci_path.write_bytes(original_linux)

        expected_names = tuple(self.ci_member_bytes["linux-ci-artifact"])
        unsafe_members = dict(self.ci_member_bytes["linux-ci-artifact"])
        first_name = expected_names[0]
        unsafe_members["../" + first_name] = unsafe_members.pop(first_name)
        with self.assertRaisesRegex(
            subject.DesignReleaseError, "member name/inventory"
        ):
            subject._read_ci_zip_members(
                self._zip_members(unsafe_members),
                expected_names=expected_names,
                label="unsafe-unit-ZIP",
            )

        platform_members = dict(self.ci_member_bytes["linux-ci-artifact"])
        preflight_name = "v3-preflight-linux.json"
        preflight = json.loads(platform_members[preflight_name])
        preflight["platformSafety"]["machine"] = "arm64"
        platform_members[preflight_name] = self._pretty(preflight)
        with self.assertRaisesRegex(subject.DesignReleaseError, "preflight content/platform"):
            self._verify_payload(
                "linux-ci-artifact", self._zip_members(platform_members)
            )

        runtime_members = dict(self.ci_member_bytes["linux-ci-artifact"])
        runtime_name = "v3-runtime-linux.json"
        runtime = json.loads(runtime_members[runtime_name])
        del runtime["contentSHA256"]
        runtime["host"]["machine"] = "arm64"
        runtime_members[runtime_name] = (
            canonical_json_bytes(with_content_digest(runtime)) + b"\n"
        )
        with self.assertRaisesRegex(subject.DesignReleaseError, "runtime host platform"):
            self._verify_payload(
                "linux-ci-artifact", self._zip_members(runtime_members)
            )

        lock_members = dict(self.ci_member_bytes["macos-arm64-ci-artifact"])
        macos_runtime_name = "v3-runtime-macos.json"
        macos_runtime = json.loads(lock_members[macos_runtime_name])
        del macos_runtime["contentSHA256"]
        macos_runtime["requirementsLocks"][0]["sha256"] = "8" * 64
        lock_members[macos_runtime_name] = (
            canonical_json_bytes(with_content_digest(macos_runtime)) + b"\n"
        )
        with self.assertRaisesRegex(subject.DesignReleaseError, "pip-bootstrap lock"):
            self._verify_payload(
                "macos-arm64-ci-artifact", self._zip_members(lock_members)
            )

        workflow_members = dict(self.ci_member_bytes["linux-ci-artifact"])
        design_check_name = "v3-design-check-linux.json"
        design_check = json.loads(workflow_members[design_check_name])
        design_check["workflowFileSHA256"] = "9" * 64
        workflow_members[design_check_name] = self._pretty(design_check)
        with self.assertRaisesRegex(
            subject.DesignReleaseError, "design check/workflow/platform"
        ):
            self._verify_payload(
                "linux-ci-artifact", self._zip_members(workflow_members)
            )

        known_answer_members = dict(
            self.ci_member_bytes["linux-ci-artifact"]
        )
        known_answer_name = (
            "v3-release-attestation-known-answer-linux.json"
        )
        known_answer = json.loads(known_answer_members[known_answer_name])
        known_answer["bundleSHA256"] = "9" * 64
        known_answer_members[known_answer_name] = self._pretty(known_answer)
        with self.assertRaisesRegex(
            subject.DesignReleaseError,
            "release-attestation known answer differs",
        ):
            self._verify_payload(
                "linux-ci-artifact", self._zip_members(known_answer_members)
            )

        skip_members = dict(self.ci_member_bytes["linux-ci-artifact"])
        skip_members["v3-zero-skip-linux.log"] = (
            b"Ran 1 test in 0.001s\n\nOK (skipped=1)\n"
            b"ZERO-SKIP POLICY PASS: 1 tests, 0 skipped\n"
        )
        with self.assertRaisesRegex(subject.DesignReleaseError, "zero-skip test run"):
            self._verify_payload(
                "linux-ci-artifact", self._zip_members(skip_members)
            )

    def test_input_symlink_hardlink_and_existing_output_are_rejected(self) -> None:
        symlink = self.root / "key-link.pub"
        symlink.symlink_to(self.key_path)
        with self.assertRaisesRegex(subject.DesignReleaseError, "non-symlink"):
            subject.package_design_release(
                frozen_design_path=self.design_path,
                development_control_report_path=self.development_report_path,
                development_control_archive_receipt_path=(
                    self.development_archive_receipt_path
                ),
                freeze_manifest_path=self.freeze_path,
                github_gate_receipt_path=self.fixture.gate_path,
                linux_ci_artifact_path=self.linux_ci_path,
                macos_arm64_ci_artifact_path=self.macos_ci_path,
                asset_source_manifest_path=self.asset_source_path,
                full_asset_receipt_path=self.fixture.asset_path,
                runtime_manifest_path=self.fixture.runtime_path,
                sbom_path=self.sbom_path,
                signing_public_key_path=symlink,
                output_root=self.root / "symlink-output",
            )

        hardlink = self.root / "key-hardlink.pub"
        os.link(self.key_path, hardlink)
        with self.assertRaisesRegex(subject.DesignReleaseError, "hard-linked"):
            self._package("hardlink-output")
        hardlink.unlink()

        report = self._package("existing")
        before = {
            path.name: path.read_bytes() for path in report.asset_root.iterdir()
        }
        with self.assertRaisesRegex(subject.DesignReleaseError, "already exists"):
            self._package("existing")
        after = {
            path.name: path.read_bytes() for path in report.asset_root.iterdir()
        }
        self.assertEqual(after, before)

    def test_independent_verifier_rejects_mutable_special_extra_and_tampered_assets(self) -> None:
        mutable = self._package("mutable").asset_root
        os.chmod(mutable / "sbom.cdx.json", 0o644)
        with self.assertRaisesRegex(subject.DesignReleaseError, "writable"):
            subject.verify_design_release_package(
                mutable, signing_public_key_path=self.key_path
            )

        special = self._package("special").asset_root
        os.chmod(special, 0o755)
        (special / "sbom.cdx.json").unlink()
        (special / "sbom.cdx.json").symlink_to("runtime-manifest.json")
        os.chmod(special, 0o555)
        with self.assertRaisesRegex(subject.DesignReleaseError, "symlink or special"):
            subject.verify_design_release_package(
                special, signing_public_key_path=self.key_path
            )

        hardlinked = self._package("hardlinked").asset_root
        os.chmod(hardlinked, 0o755)
        (hardlinked / "sbom.cdx.json").unlink()
        os.link(
            hardlinked / "runtime-manifest.json",
            hardlinked / "sbom.cdx.json",
        )
        os.chmod(hardlinked, 0o555)
        with self.assertRaisesRegex(subject.DesignReleaseError, "hard-linked"):
            subject.verify_design_release_package(
                hardlinked, signing_public_key_path=self.key_path
            )

        extra = self._package("extra").asset_root
        os.chmod(extra, 0o755)
        (extra / "unregistered.txt").write_text("extra", encoding="utf-8")
        os.chmod(extra, 0o555)
        with self.assertRaisesRegex(subject.DesignReleaseError, "exactly the twelve"):
            subject.verify_design_release_package(
                extra, signing_public_key_path=self.key_path
            )

        tampered = self._package("tampered").asset_root
        os.chmod(tampered, 0o755)
        sbom_path = tampered / "sbom.cdx.json"
        os.chmod(sbom_path, 0o644)
        sbom_path.write_bytes(sbom_path.read_bytes() + b"\n")
        os.chmod(sbom_path, 0o444)
        os.chmod(tampered, 0o555)
        with self.assertRaisesRegex(subject.DesignReleaseError, "exactly one LF"):
            subject.verify_design_release_package(
                tampered, signing_public_key_path=self.key_path
            )

    def test_cli_contract_requires_external_key_and_exact_roles_match_collector(self) -> None:
        parsed = subject.parse_arguments(
            [
                "verify",
                "--asset-root",
                str(self.root),
                "--signing-public-key",
                str(self.key_path),
            ]
        )
        self.assertEqual(parsed.signing_public_key, self.key_path)
        self.assertEqual(
            subject.ASSET_ROLES,
            tuple(subject.REQUIRED_ASSET_ROLES["design"]),
        )


if __name__ == "__main__":
    unittest.main()
