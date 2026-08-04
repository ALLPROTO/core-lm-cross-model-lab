from __future__ import annotations

import copy
import subprocess
import unittest
from pathlib import Path

from v3 import build_frozen_design as subject
from v3 import freeze_manifest
from v3.collect_github_gate_receipt import collect_github_gate_receipt_to_path
from v3.protocol import load_json_strict
from v3.reproducibility import canonical_json_bytes, sha256_bytes, with_content_digest
from v3.tests import test_freeze_manifest as freeze_fixture
from v3.tests.test_github_gate_receipt import (
    PR,
    RUN_ID,
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    FakeTransport,
    _base_bodies,
)


class FrozenDesignBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        helper = freeze_fixture.FreezeManifestTests(
            "test_generator_is_canonical_binds_inputs_and_has_no_file_self_reference"
        )
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        self.helper = helper
        self.lab_root = helper.root / "author-verified-lab"
        (self.lab_root / "v3").mkdir(parents=True)
        self.draft_raw = (subject.V3_ROOT / "design-registration.draft.json").read_bytes()
        (self.lab_root / subject.DRAFT_RELATIVE_PATH).write_bytes(self.draft_raw)
        self._git("init", "-q")
        self._git("config", "user.name", "Unit Contract")
        self._git("config", "user.email", "unit@example.invalid")
        self._git("remote", "add", "origin", freeze_fixture.LAB_REPOSITORY)
        self._git("add", subject.DRAFT_RELATIVE_PATH)
        self._git("commit", "-q", "-m", "author-verified fixture")
        self.commit = self._git("rev-parse", "HEAD").strip()
        self.tree = self._git("rev-parse", "HEAD^{tree}").strip()

        runtime = load_json_strict(helper.runtime_path)
        runtime.pop("contentSHA256")
        runtime["labSource"].update(commit=self.commit, tree=self.tree)
        helper.runtime_path.write_bytes(
            canonical_json_bytes(with_content_digest(runtime)) + b"\n"
        )

        helper.gate_path.unlink()
        bodies = _base_bodies()
        bodies["pull-request"]["head"]["sha"] = self.commit
        bodies["workflow-run"]["head_sha"] = self.commit
        for job in bodies["workflow-jobs"]["jobs"]:
            job["head_sha"] = self.commit
        collect_github_gate_receipt_to_path(
            output=helper.gate_path,
            repository="ALLPROTO/core-lm-cross-model-lab",
            pull_request_number=PR,
            implementation_commit=self.commit,
            workflow_run_id=RUN_ID,
            workflow_name=WORKFLOW_NAME,
            workflow_path=WORKFLOW_PATH,
            transport=FakeTransport(bodies),
            now=lambda: "2026-08-14T10:05:30Z",
        )
        manifest = freeze_manifest.build_freeze_manifest(
            runtime_manifest_path=helper.runtime_path,
            asset_receipt_path=helper.asset_path,
            ca_bundle_path=helper.ca_path,
            trust_manifest_path=helper.trust_path,
            lab_repository=freeze_fixture.LAB_REPOSITORY,
            lab_commit=self.commit,
            lab_tree=self.tree,
            codec_repository=freeze_fixture.CODEC_REPOSITORY,
            codec_commit=freeze_fixture.CODEC_COMMIT,
            codec_tree=freeze_fixture.CODEC_TREE,
            github_gate_receipt_path=helper.gate_path,
            development_control_report_path=helper.development_report_path,
            development_control_artifact_root=helper.development_artifact_root,
            development_control_archive_receipt_path=(
                helper.development_archive_receipt_path
            ),
            development_control_archive_asset_root=(
                helper.development_archive_asset_root
            ),
            created_at="2026-08-14T10:06:00Z",
            ca_verifier=helper.ca_verifier,
            trust_verifier=helper.trust_verifier,
            development_control_verifier=helper.development_control_verifier,
            development_archive_verifier=helper.development_archive_verifier,
        )
        self.manifest_raw = freeze_manifest.canonical_freeze_manifest_bytes(manifest)
        helper.manifest_path.write_bytes(self.manifest_raw)
        self.output = helper.root / "external-release" / "design-registration.json"

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=self.lab_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout

    def _arguments(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "lab_root": self.lab_root,
            "expected_lab_commit": self.commit,
            "expected_lab_tree": self.tree,
            "expected_freeze_manifest_sha256": sha256_bytes(self.manifest_raw),
            "freeze_manifest_path": self.helper.manifest_path,
            "runtime_manifest_path": self.helper.runtime_path,
            "asset_receipt_path": self.helper.asset_path,
            "transport_ca_bundle_path": self.helper.ca_path,
            "offline_trust_manifest_path": self.helper.trust_path,
            "github_gate_receipt_path": self.helper.gate_path,
            "development_control_report_path": (
                self.helper.development_report_path
            ),
            "development_control_artifact_root": (
                self.helper.development_artifact_root
            ),
            "development_control_archive_receipt_path": (
                self.helper.development_archive_receipt_path
            ),
            "development_control_archive_asset_root": (
                self.helper.development_archive_asset_root
            ),
            "signing_public_key_path": subject.V3_ROOT
            / "signing/corelm-crossmodel-v3-signing.pub",
            "output_path": self.output,
            "ca_verifier": self.helper.ca_verifier,
            "trust_verifier": self.helper.trust_verifier,
            "development_control_verifier": (
                self.helper.development_control_verifier
            ),
            "development_archive_verifier": (
                self.helper.development_archive_verifier
            ),
            "require_running_checkout": False,
        }
        arguments.update(overrides)
        return arguments

    def test_builds_canonical_validated_external_asset_without_overwrite(self) -> None:
        report = subject.build_frozen_design(**self._arguments())
        raw = self.output.read_bytes()
        value = load_json_strict(self.output)
        self.assertEqual(raw, canonical_json_bytes(value) + b"\n")
        self.assertEqual(report["sha256"], sha256_bytes(raw))
        self.assertEqual(value["status"], "PUBLIC_DESIGN_FROZEN")
        self.assertIs(value["readyToFreeze"], True)
        self.assertEqual(value["freezeBlockers"], [])
        self.assertEqual(value["labSource"]["commit"], self.commit)
        self.assertEqual(value["labSource"]["tree"], self.tree)
        self.assertEqual(
            value["developmentControls"]["realDataE2EFreezeGate"][
                "archiveAttestedAt"
            ],
            load_json_strict(self.helper.manifest_path)["developmentControl"][
                "archiveAttestedAt"
            ],
        )
        self.assertEqual(
            value["developmentControls"]["realDataE2EFreezeGate"][
                "releaseAttestationBundleSHA256"
            ],
            load_json_strict(self.helper.manifest_path)["artifacts"][
                "developmentControlReleaseAttestationBundleSHA256"
            ],
        )
        self.assertEqual(
            report["designBinding"]["status"],
            "VERIFIED_TWO_STAGE_DESIGN_BINDING",
        )
        with self.assertRaises(FileExistsError):
            subject.build_frozen_design(**self._arguments())

    def test_wrong_commit_tree_and_manifest_hash_fail_closed(self) -> None:
        cases = (
            {"expected_lab_commit": "f" * 40},
            {"expected_lab_tree": "e" * 40},
            {"expected_freeze_manifest_sha256": "d" * 64},
        )
        for override in cases:
            with self.subTest(override=override):
                with self.assertRaises(subject.FrozenDesignBuildError):
                    subject.build_frozen_design(**self._arguments(**override))
                self.assertFalse(self.output.exists())

    def test_dirty_tracked_draft_is_rejected(self) -> None:
        draft_path = self.lab_root / subject.DRAFT_RELATIVE_PATH
        draft_path.write_bytes(self.draft_raw + b" ")
        with self.assertRaisesRegex(subject.FrozenDesignBuildError, "not clean"):
            subject.build_frozen_design(**self._arguments())
        self.assertFalse(self.output.exists())

    def test_late_manifest_is_rejected_before_output(self) -> None:
        manifest = load_json_strict(self.helper.manifest_path)
        manifest.pop("contentSHA256")
        manifest["createdAt"] = "2026-08-15T00:00:01Z"
        late_raw = canonical_json_bytes(with_content_digest(manifest)) + b"\n"
        late_path = self.helper.root / "late-freeze-manifest.json"
        late_path.write_bytes(late_raw)
        with self.assertRaisesRegex(freeze_manifest.FreezeManifestError, "deadline"):
            subject.build_frozen_design(
                **self._arguments(
                    freeze_manifest_path=late_path,
                    expected_freeze_manifest_sha256=sha256_bytes(late_raw),
                )
            )
        self.assertFalse(self.output.exists())

    def test_non_lifecycle_mutation_is_rejected(self) -> None:
        draft = load_json_strict(subject.V3_ROOT / "design-registration.draft.json")
        manifest = load_json_strict(self.helper.manifest_path)
        frozen = subject.construct_frozen_design(draft, manifest, self.manifest_raw)
        mutated = copy.deepcopy(frozen)
        mutated["candidate"]["groupSize"] = 64
        with self.assertRaisesRegex(
            subject.FrozenDesignBuildError, "non-lifecycle field"
        ):
            subject.assert_only_allowed_freeze_mutations(draft, mutated)

    def test_bound_ca_bytes_and_release_key_identity_are_reopened(self) -> None:
        self.helper.ca_path.write_bytes(b"different CA\n")
        with self.assertRaisesRegex(freeze_manifest.FreezeManifestError, "CA bundle"):
            subject.build_frozen_design(**self._arguments())
        self.assertFalse(self.output.exists())

        self.helper.ca_path.write_bytes(b"unit-contract CA bytes\n")
        wrong_key = self.helper.root / "wrong-key.pub"
        wrong_key.write_bytes(
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA unit\n"
        )
        with self.assertRaisesRegex(
            subject.FrozenDesignBuildError, "release identity differs"
        ):
            subject.build_frozen_design(
                **self._arguments(signing_public_key_path=wrong_key)
            )


if __name__ == "__main__":
    unittest.main()
