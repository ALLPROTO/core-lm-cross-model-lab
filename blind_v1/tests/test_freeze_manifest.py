from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from blind_v1 import development_artifact_verifier
from blind_v1 import development_model_replay
from blind_v1 import freeze_manifest as subject
from blind_v1 import run_real_e2e_control
from blind_v1.build_frozen_nist_trust_bundle import (
    build_frozen_nist_trust_bundle,
)
from blind_v1.collect_github_gate_receipt import collect_github_gate_receipt_to_path
from blind_v1.github_gate_receipt import (
    AUTHOR_GITHUB_LOGIN,
    AUTHOR_NAME,
    AUTHOR_ORCID,
    AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
    AUTHOR_VERIFICATION_DECLARATION,
    AUTHOR_VERIFICATION_MODE,
)
from blind_v1.protocol import load_json_strict
from blind_v1.reproducibility import (
    RUNTIME_ENVIRONMENT_KEYS,
    canonical_json_bytes,
    sha256_bytes,
    with_content_digest,
)
from blind_v1.tests.test_github_gate_receipt import (
    COMMIT as GATE_COMMIT,
    PR as GATE_PR,
    RUN_ID as GATE_RUN_ID,
    WORKFLOW_NAME as GATE_WORKFLOW_NAME,
    WORKFLOW_PATH as GATE_WORKFLOW_PATH,
    FakeTransport as GateFakeTransport,
    _base_bodies as gate_base_bodies,
)


LAB_REPOSITORY = "https://github.com/ALLPROTO/core-lm-cross-model-lab.git"
LAB_COMMIT = GATE_COMMIT
LAB_TREE = "2" * 40
CODEC_REPOSITORY = "https://github.com/ALLPROTO/core-lm-benchmark.git"
CODEC_COMMIT = "2e8d3b1591ee4a1ed822310f330317936871ff2b"
CODEC_TREE = "c0bb15784d252cd5036757bc64765c773a5f16e8"


class FreezeManifestStaticContractTests(unittest.TestCase):
    def test_development_receipt_archive_path_matches_semantic_verifier(self) -> None:
        expected = development_artifact_verifier.FULL_ASSET_RECEIPT_PATH
        self.assertEqual(
            f"inputs/{run_real_e2e_control.FULL_ASSET_RECEIPT_ARCHIVE_NAME}",
            expected,
        )
        self.assertEqual(development_model_replay.FULL_ASSET_RECEIPT_PATH, expected)
        self.assertEqual(
            subject.DEVELOPMENT_ARCHIVED_INPUTS["fullAssetReceipt"][0],
            expected,
        )


class FreezeManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.live_source_verifier = subject._verify_live_implementation_source
        live_source_patcher = mock.patch.object(
            subject, "_verify_live_implementation_source"
        )
        self.live_source_check = live_source_patcher.start()
        self.addCleanup(live_source_patcher.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.runtime_path = self.root / "runtime-manifest.json"
        self.asset_path = self.root / "asset-receipt.json"
        self.ca_path = self.root / "ca.pem"
        self.trust_root = self.root / "frozen-nist-trust"
        self.trust_path = self.trust_root / "manifest.json"
        self.gate_path = self.root / "github-gate-receipt.json"
        self.development_report_path = self.root / "development-control-report.json"
        self.development_artifact_root = self.root / "development-artifacts"
        self.development_archive_receipt_path = (
            self.root / "development-control-archive-receipt.json"
        )
        self.development_archive_asset_root = self.root / "development-archive"
        self.manifest_path = self.root / "freeze-manifest.json"
        self._write_runtime(clean=True)
        self._write_assets()
        self.ca_path.write_bytes(b"unit-contract CA bytes\n")
        build_frozen_nist_trust_bundle(output_root=self.trust_root)
        self.ca_calls: list[tuple[Path, str]] = []
        self.trust_calls: list[tuple[Path, str]] = []
        collect_github_gate_receipt_to_path(
            output=self.gate_path,
            repository="ALLPROTO/core-lm-cross-model-lab",
            pull_request_number=GATE_PR,
            implementation_commit=LAB_COMMIT,
            workflow_run_id=GATE_RUN_ID,
            workflow_name=GATE_WORKFLOW_NAME,
            workflow_path=GATE_WORKFLOW_PATH,
            transport=GateFakeTransport(
                gate_base_bodies(),
                base=datetime(2026, 8, 8, 10, 5, 0, tzinfo=timezone.utc),
            ),
            now=lambda: "2026-08-08T10:05:10Z",
        )

    def _git(self, repository: Path, *arguments: str) -> bytes:
        completed = subprocess.run(
            [str(subject.GIT_EXECUTABLE), "-C", str(repository), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    def _live_git_fixture(self) -> tuple[Path, Path, dict[str, str]]:
        repository = self.root / "live-source"
        repository.mkdir()
        self._git(repository, "init", "-q")
        dependency = repository / "blind_v1" / "release_receipt.py"
        dependency.parent.mkdir()
        dependency.write_text("RECEIPT = 'author-verified'\n", encoding="utf-8")
        (repository / ".gitignore").write_text(
            "ignored-runtime/\n", encoding="utf-8"
        )
        self._git(repository, "add", ".")
        self._git(
            repository,
            "-c",
            "user.name=Freeze Test",
            "-c",
            "user.email=freeze-test@example.invalid",
            "commit",
            "-q",
            "-m",
            "author-verified source",
        )
        self._git(repository, "remote", "add", "origin", LAB_REPOSITORY)
        implementation = {
            "repository": LAB_REPOSITORY,
            "commit": self._git(
                repository, "rev-parse", "--verify", "HEAD^{commit}"
            ).decode("ascii").strip(),
            "tree": self._git(
                repository, "rev-parse", "--verify", "HEAD^{tree}"
            ).decode("ascii").strip(),
        }
        return repository, dependency, implementation

    @staticmethod
    def _source(repository: str, commit: str, tree: str, *, clean: bool) -> dict[str, Any]:
        return {
            "commit": commit,
            "tree": tree,
            "origin": repository,
            "worktreeClean": clean,
            "worktreeStatusSHA256": sha256_bytes(b"") if clean else "0" * 64,
        }

    @staticmethod
    def _runtime_tree() -> dict[str, Any]:
        entries = [
            {
                "path": "bin/python3.12",
                "type": "file",
                "bytes": 1,
                "mode": "0755",
                "sha256": "5" * 64,
            }
        ]
        return {
            "entries": entries,
            "entryCount": len(entries),
            "regularFileBytes": 1,
            "treeSHA256": sha256_bytes(canonical_json_bytes(entries)),
        }

    def _write_runtime(self, *, clean: bool) -> None:
        payload = {
            "schemaVersion": subject.RUNTIME_SCHEMA,
            "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
            "countsTowardScientificVerdict": False,
            "networkUsed": False,
            "modelInferenceUsed": False,
            "python": {
                "registeredVersion": "3.12.10",
                "version": "3.12.10",
                "versionDetail": "3.12.10 (unit contract)",
                "implementation": "CPython",
                "cacheTag": "cpython-312",
                "byteorder": "little",
                "platformTag": "macosx-15.0-arm64",
                "executable": {
                    "bytes": 1,
                    "mode": "0755",
                    "sha256": "5" * 64,
                },
                "soabi": "cpython-312-darwin",
                "multiarch": "darwin",
            },
            "host": {
                "system": "Darwin",
                "release": "unit-release",
                "version": "unit-version",
                "machine": "arm64",
                "processor": "arm",
                "macVersion": "15.0",
            },
            "environment": {key: None for key in sorted(RUNTIME_ENVIRONMENT_KEYS)},
            "requirementsLocks": copy.deepcopy(
                subject.REGISTERED_REQUIREMENTS_LOCKS
            ),
            "installedDistributions": [
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
            ],
            "installedDistributionCount": 1,
            "runtimeTree": self._runtime_tree(),
            "basePythonTree": self._runtime_tree(),
            "basePythonDistinctFromRuntime": False,
            "labSource": self._source(
                LAB_REPOSITORY, LAB_COMMIT, LAB_TREE, clean=clean
            ),
            "codecSource": self._source(
                CODEC_REPOSITORY, CODEC_COMMIT, CODEC_TREE, clean=clean
            ),
        }
        self.runtime_path.write_bytes(
            canonical_json_bytes(with_content_digest(payload)) + b"\n"
        )

    def _write_assets(self) -> None:
        manifest_path = subject.BLIND_V1_ROOT / "model-assets.draft.json"
        asset_manifest = load_json_strict(manifest_path)
        models = {
            model_key: {
                "repository": model["repository"],
                "revision": model["revision"],
                "license": model["license"],
                "licenseURL": model["licenseURL"],
                "files": {
                    filename: {
                        "bytes": commitment["bytes"],
                        "sha256": commitment["sha256"],
                    }
                    for filename, commitment in model["files"].items()
                },
            }
            for model_key, model in asset_manifest["models"].items()
        }
        manifest_raw = manifest_path.read_bytes()
        payload = {
            "schemaVersion": subject.ASSET_RECEIPT_SCHEMA,
            "status": "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED",
            "countsTowardScientificVerdict": False,
            "networkUsed": False,
            "modelInferenceUsed": False,
            "manifestFile": manifest_path.name,
            "manifestSchemaVersion": asset_manifest["schemaVersion"],
            "manifestDeclaredStatus": asset_manifest["status"],
            "manifestDeclaredFullSafetensorsBytesLocallyVerified": asset_manifest[
                "fullSafetensorsBytesLocallyVerified"
            ],
            "manifestFileBytes": len(manifest_raw),
            "manifestFileSHA256": sha256_bytes(manifest_raw),
            "assetLayout": "<asset-root>/<model-key>/<manifest-relative-file>",
            "fileCount": subject.EXPECTED_ASSET_FILES,
            "totalBytes": subject.EXPECTED_ASSET_BYTES,
            "fullSafetensorsBytesLocallyVerified": True,
            "fullSafetensorsBytes": subject.EXPECTED_WEIGHT_BYTES,
            "models": models,
        }
        self.asset_path.write_bytes(
            canonical_json_bytes(with_content_digest(payload)) + b"\n"
        )

    def ca_verifier(self, path: Path, digest: str) -> None:
        self.ca_calls.append((path, digest))

    def trust_verifier(self, path: Path, digest: str) -> None:
        self.trust_calls.append((path, digest))

    @staticmethod
    def development_control_verifier(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "reportFileSHA256": "a" * 64,
            "reportFileBytes": 1,
            "artifactSetSHA256": "b" * 64,
            "controlConfigurationSHA256": "c" * 64,
            "artifactCount": 2088,
            "executionId": (
                "development-execution-20260906T100000Z-0123456789abcdef"
            ),
            "startedAt": "2026-08-08T09:00:00Z",
            "completedAt": "2026-08-08T10:00:00Z",
        }

    @staticmethod
    def development_archive_verifier(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "VERIFIED_GITHUB_ATTESTED_DEVELOPMENT_ARCHIVE",
            "receiptSHA256": "d" * 64,
            "publishedAt": "2026-08-08T10:05:00Z",
            "attestedAt": "2026-08-08T10:05:01Z",
            "attestationBundleSHA256": "1" * 64,
            "attestationOutputSHA256": "2" * 64,
            "artifactArchiveSHA256": "e" * 64,
            "archiveManifestSHA256": "f" * 64,
            "reportSHA256": "a" * 64,
        }

    @staticmethod
    def _digest_bytes(raw: bytes) -> dict[str, Any]:
        return {"bytes": len(raw), "sha256": sha256_bytes(raw)}

    def _pud_rights_raw(self) -> dict[str, bytes]:
        result: dict[str, bytes] = {}
        for binding in (
            "developmentCorpusManifest",
            "licenseSourceEvidence",
            "assetLicenseMatrix",
            "udEnglishPudReadme",
            "udEnglishPudLicense",
            "udEnglishPudAttribution",
        ):
            _, tracked = subject.DEVELOPMENT_ARCHIVED_INPUTS[binding]
            self.assertIsNotNone(tracked)
            result[binding] = (subject.PROJECT_ROOT / str(tracked)).read_bytes()
        return result

    def _pud_plan_fixture(
        self,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, bytes], bytes]:
        archived: dict[str, bytes] = {}
        for binding, (_, tracked) in subject.DEVELOPMENT_ARCHIVED_INPUTS.items():
            if binding == "runtimeManifest":
                archived[binding] = self.runtime_path.read_bytes()
            else:
                self.assertIsNotNone(tracked)
                archived[binding] = (
                    subject.PROJECT_ROOT / str(tracked)
                ).read_bytes()

        dataset_raw = b"unit-contract PUD source bytes\n\n"
        dataset_digest = self._digest_bytes(dataset_raw)
        design = load_json_strict(subject.BLIND_V1_ROOT / "design-registration.draft.json")
        bindings: dict[str, Any] = {
            binding: self._digest_bytes(raw) for binding, raw in archived.items()
        }
        bindings.update(
            developmentDataset=dataset_digest,
            labSource={
                "repository": LAB_REPOSITORY,
                "commit": LAB_COMMIT,
                "tree": LAB_TREE,
                "worktreeClean": True,
            },
            joinedCorpusText={
                "bytes": subject.DEVELOPMENT_JOINED_TEXT_BYTES,
                "sha256": subject.DEVELOPMENT_JOINED_TEXT_SHA256,
            },
            conlluDecode={
                "parser": "strict-stdlib-conllu-text-v1",
                "sentences": subject.DEVELOPMENT_DATASET_SENTENCES,
                "sourceConlluSHA256": dataset_digest["sha256"],
            },
            codecSource=copy.deepcopy(design["codecSource"]),
            controlSources=[
                {
                    "path": relative,
                    **self._digest_bytes(
                        (subject.PROJECT_ROOT / relative).read_bytes()
                    ),
                }
                for relative in subject.DEVELOPMENT_CONTROL_SOURCE_PATHS
            ],
            adapter={
                "source": "pinned-ud-english-pud-r2.18-test-conllu",
                "sentenceText": "exact-single-#-text-comment-per-block",
                "join": "two-LF-between-sentence-texts-within-each-slice",
                "partition": "all-source-sentences-equal-floor-boundaries-32",
                "partitions": subject.DEVELOPMENT_PAGES_PER_MODEL,
                "records": subject.DEVELOPMENT_PAGES_PER_MODEL,
                "contentSynthetic": False,
                "metadataEnvelopeScientificUse": "forbidden",
            },
        )

        models: list[dict[str, Any]] = []
        private_files: list[dict[str, Any]] = []
        for model_key in subject.DEVELOPMENT_MODEL_KEYS:
            identity = subject.DEVELOPMENT_MODEL_IDENTITIES[model_key]
            files: dict[str, dict[str, Any]] = {}
            for filename in subject.DEVELOPMENT_MODEL_FILES:
                path = f"models/{model_key}/{filename}"
                if filename == "model.safetensors":
                    commitment = {
                        "bytes": identity["weightBytes"],
                        "sha256": identity["weightSHA256"],
                    }
                else:
                    commitment = {
                        "bytes": 1,
                        "sha256": sha256_bytes(path.encode("utf-8")),
                    }
                files[filename] = {"path": path, **commitment}
                private_files.append(
                    {"path": path, **commitment, "role": "model-asset"}
                )
            models.append(
                {
                    "key": model_key,
                    "repository": identity["repository"],
                    "revision": identity["revision"],
                    "layers": identity["layers"],
                    "vocabSize": identity["vocabSize"],
                    "candidateBitsByLayer": [
                        9 if index in {0, identity["layers"] // 3} else 8
                        for index in range(identity["layers"])
                    ],
                    "files": files,
                }
            )

        pages: list[dict[str, Any]] = []
        for index, (start, end) in enumerate(subject.partition_bounds()):
            path = f"{subject.DEVELOPMENT_RECORD_ROOT}/slice-{index:02d}.bin"
            record = f"record-{index}".encode("ascii")
            text = f"text-{index}".encode("ascii")
            page = {
                "pageSelectionIndex": index,
                "sourceSliceIndex": index,
                "sentenceStart": start,
                "sentenceEnd": end,
                "recordPath": path,
                "recordBytes": len(record),
                "recordSHA256": sha256_bytes(record),
                "inputTextBytes": len(text),
                "inputTextSHA256": sha256_bytes(text),
            }
            pages.append(page)
            private_files.append(
                {
                    "path": path,
                    "bytes": page["recordBytes"],
                    "sha256": page["recordSHA256"],
                    "role": "development-corpus-record",
                }
            )
        private_files.append(
            {
                "path": subject.DEVELOPMENT_DATASET_PATH,
                **dataset_digest,
                "role": "development-corpus-source",
            }
        )
        private_files.sort(key=lambda item: item["path"])

        artifact_bytes = {
            archived_path: archived[binding]
            for binding, (archived_path, _) in subject.DEVELOPMENT_ARCHIVED_INPUTS.items()
        }
        artifact_bytes[subject.DEVELOPMENT_DATASET_PATH] = dataset_raw
        jobs: dict[str, dict[str, Any]] = {}
        for model_key in subject.DEVELOPMENT_MODEL_KEYS:
            path = f"jobs/{model_key}.json"
            raw = f"{model_key}\n".encode("ascii")
            artifact_bytes[path] = raw
            jobs[model_key] = {"path": path, **self._digest_bytes(raw)}

        base_plan: dict[str, Any] = {
            "schemaVersion": subject.DEVELOPMENT_PLAN_SCHEMA,
            "suiteId": subject.DEVELOPMENT_SUITE_ID,
            "runId": "",
            "status": "SEALED_NON_SCIENTIFIC_DEVELOPMENT_INPUT",
            "countsTowardScientificVerdict": False,
            "usedForCandidateSelectionOrTuning": False,
            "scientificAttemptStateCreated": False,
            "nistUsed": False,
            "futureCorpusUsed": False,
            "thresholdsApplied": False,
            "modelExecutionOrder": list(subject.DEVELOPMENT_MODEL_KEYS),
            "selectedCorpora": [subject.DEVELOPMENT_DATASET_ID],
            "candidate": copy.deepcopy(subject.DEVELOPMENT_CANDIDATE),
            "models": models,
            "pages": {subject.DEVELOPMENT_DATASET_ID: pages},
            "privateFiles": private_files,
            "jobs": jobs,
            "inputBindings": bindings,
            "execution": copy.deepcopy(subject.DEVELOPMENT_EXECUTION),
            "controlConfigurationSHA256": "",
        }
        configuration = {
            "schemaVersion": (
                "corelm-blind-crossmodel-v1-real-e2e-development-configuration-v1"
            ),
            "suiteId": subject.DEVELOPMENT_SUITE_ID,
            "countsTowardScientificVerdict": False,
            "usedForCandidateSelectionOrTuning": False,
            "scientificAttemptStateCreated": False,
            "nistUsed": False,
            "futureCorpusUsed": False,
            "thresholdsApplied": False,
            "modelExecutionOrder": list(subject.DEVELOPMENT_MODEL_KEYS),
            "selectedCorpora": [subject.DEVELOPMENT_DATASET_ID],
            "candidate": subject.DEVELOPMENT_CANDIDATE,
            "models": models,
            "pages": base_plan["pages"],
            "execution": subject.DEVELOPMENT_EXECUTION,
            "inputBindings": bindings,
        }
        configuration_sha256 = sha256_bytes(canonical_json_bytes(configuration))
        base_plan["runId"] = f"development-e2e-{configuration_sha256}"
        base_plan["controlConfigurationSHA256"] = configuration_sha256
        plan = with_content_digest(base_plan)
        report = {
            "runId": plan["runId"],
            "controlConfigurationSHA256": configuration_sha256,
            "inputs": bindings,
        }
        return plan, report, artifact_bytes, dataset_raw

    @staticmethod
    def _pud_report_fixture() -> dict[str, Any]:
        configuration_sha256 = "c" * 64
        phases = [
            "before-output-materialization",
            *(f"before-producer:{model}" for model in subject.DEVELOPMENT_MODEL_KEYS),
            "before-independent-replay",
        ]
        safety = [
            {
                "phase": phase,
                "system": "Darwin",
                "machine": "arm64",
                "osProductVersion": "15.0",
                "osBuildVersion": "unit-build",
                "kernelRelease": "unit-release",
                "kernelVersion": "unit-version",
                "cpuBrand": "unit-cpu",
                "logicalCPUCount": 8,
                "physicalMemoryBytes": 16_000_000_000,
                "pythonVersion": "3.12.10",
                "pythonExecutableSHA256": "d" * 64,
                "effectiveExecutionEnvironment": {"PYTHONHASHSEED": "0"},
                "acPower": True,
                "freeMemoryPercent": 80,
                "freeDiskBytes": 20_000_000_000,
            }
            for phase in phases
        ]
        payload = {
            "schemaVersion": subject.DEVELOPMENT_REPORT_SCHEMA,
            "suiteId": subject.DEVELOPMENT_SUITE_ID,
            "runId": f"development-e2e-{configuration_sha256}",
            "executionId": (
                "development-execution-20260906T100000Z-0123456789abcdef"
            ),
            "status": "NON_SCIENTIFIC_REAL_DATA_E2E_CONTROL_PASS",
            "countsTowardScientificVerdict": False,
            "usedForCandidateSelectionOrTuning": False,
            "scientificAttemptStateCreated": False,
            "nistUsed": False,
            "futureCorpusUsed": False,
            "thresholdsApplied": False,
            "candidateCodecInvoked": True,
            "realModelsUsed": True,
            "realDevelopmentCorpusUsed": True,
            "independentRealModelReplayComplete": True,
            "startedAt": "2026-08-08T09:00:00Z",
            "completedAt": "2026-08-08T10:00:00Z",
            "controlConfigurationSHA256": configuration_sha256,
            "plan": {"bytes": 1, "sha256": "e" * 64},
            "inputs": {},
            "runtime": {
                "dontWriteBytecode": True,
                "hashAlgorithm": "siphash13",
                "hashBits": 64,
                "hashRandomization": 0,
                "hashValue": -5471761816802073765,
                "ignoreEnvironment": 0,
                "noUserSite": 1,
                "pythonVersion": "3.12.10",
                "safePath": True,
                "seedBits": 128,
            },
            "hostSafetyChecks": safety,
            "networkIsolationBackend": "macOS-sandbox-exec-deny-network",
            "workerProcessesSequential": True,
            "replayModelsSequential": True,
            "supervision": [],
            "independentReplay": {},
            "artifactInventory": [],
            "artifactSetSHA256": sha256_bytes(canonical_json_bytes([])),
            "scientificClaim": "forbidden",
            "candidateSelectionOrTuning": "forbidden",
        }
        return with_content_digest(payload)

    def build(self) -> dict[str, Any]:
        return subject.build_freeze_manifest(
            runtime_manifest_path=self.runtime_path,
            asset_receipt_path=self.asset_path,
            ca_bundle_path=self.ca_path,
            trust_manifest_path=self.trust_path,
            lab_repository=LAB_REPOSITORY,
            lab_commit=LAB_COMMIT,
            lab_tree=LAB_TREE,
            codec_repository=CODEC_REPOSITORY,
            codec_commit=CODEC_COMMIT,
            codec_tree=CODEC_TREE,
            github_gate_receipt_path=self.gate_path,
            development_control_report_path=self.development_report_path,
            development_control_artifact_root=self.development_artifact_root,
            development_control_archive_receipt_path=(
                self.development_archive_receipt_path
            ),
            development_control_archive_asset_root=(
                self.development_archive_asset_root
            ),
            created_at="2026-08-08T10:06:00Z",
            ca_verifier=self.ca_verifier,
            trust_verifier=self.trust_verifier,
            development_control_verifier=self.development_control_verifier,
            development_archive_verifier=self.development_archive_verifier,
        )

    def test_live_source_verifier_rejects_dirty_dependency_and_untracked_path(
        self,
    ) -> None:
        repository, dependency, implementation = self._live_git_fixture()
        ignored = repository / "ignored-runtime" / "artifact.bin"
        ignored.parent.mkdir()
        ignored.write_bytes(b"allowed ignored artifact")
        with mock.patch.object(subject, "PROJECT_ROOT", repository):
            self.live_source_verifier(implementation)

            dependency.write_text("RECEIPT = 'mutated'\n", encoding="utf-8")
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "worktree is not clean"
            ):
                self.live_source_verifier(implementation)

            dependency.write_text("RECEIPT = 'author-verified'\n", encoding="utf-8")
            self.live_source_verifier(implementation)
            self._git(
                repository,
                "update-index",
                "--assume-unchanged",
                "blind_v1/release_receipt.py",
            )
            dependency.write_text("RECEIPT = 'hidden mutation'\n", encoding="utf-8")
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "non-canonical tracked flags"
            ):
                self.live_source_verifier(implementation)
            dependency.write_text("RECEIPT = 'author-verified'\n", encoding="utf-8")
            self._git(
                repository,
                "update-index",
                "--no-assume-unchanged",
                "blind_v1/release_receipt.py",
            )
            self.live_source_verifier(implementation)

            untracked = repository / "blind_v1" / "github_gate_receipt.py"
            untracked.write_text("UNVERIFIED = True\n", encoding="utf-8")
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "worktree is not clean"
            ):
                self.live_source_verifier(implementation)

    def test_live_source_verifier_rejects_wrong_head_tree_and_origin(self) -> None:
        repository, _dependency, implementation = self._live_git_fixture()
        with mock.patch.object(subject, "PROJECT_ROOT", repository):
            wrong_commit = dict(implementation, commit="0" * 40)
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "HEAD commit differs"
            ):
                self.live_source_verifier(wrong_commit)

            wrong_tree = dict(implementation, tree="0" * 40)
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "HEAD tree differs"
            ):
                self.live_source_verifier(wrong_tree)

            wrong_origin = dict(
                implementation,
                repository="https://github.com/ALLPROTO/not-the-lab.git",
            )
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "origin differs"
            ):
                self.live_source_verifier(wrong_origin)

    def test_create_and_verify_check_live_source_before_receipts(self) -> None:
        self.live_source_check.side_effect = subject.FreezeManifestError(
            "live source rejected"
        )
        with mock.patch.object(subject, "_verify_github_gate_input") as gate:
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "live source rejected"
            ):
                self.build()
            gate.assert_not_called()

        self.live_source_check.side_effect = None
        manifest = self.build()
        self.live_source_check.side_effect = subject.FreezeManifestError(
            "live source rejected"
        )
        with mock.patch.object(subject, "_load_canonical_receipt") as loader:
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "live source rejected"
            ):
                subject.verify_artifact_inputs(
                    manifest,
                    runtime_manifest_path=self.runtime_path,
                    asset_receipt_path=self.asset_path,
                    ca_bundle_path=self.ca_path,
                    trust_manifest_path=self.trust_path,
                    github_gate_receipt_path=self.gate_path,
                    development_control_report_path=self.development_report_path,
                    development_control_artifact_root=self.development_artifact_root,
                    development_control_archive_receipt_path=(
                        self.development_archive_receipt_path
                    ),
                    development_control_archive_asset_root=(
                        self.development_archive_asset_root
                    ),
                    ca_verifier=self.ca_verifier,
                    trust_verifier=self.trust_verifier,
                    development_control_verifier=(
                        self.development_control_verifier
                    ),
                    development_archive_verifier=(
                        self.development_archive_verifier
                    ),
                )
            loader.assert_not_called()

    def test_generator_is_canonical_binds_inputs_and_has_no_file_self_reference(self) -> None:
        manifest = self.build()
        schema = load_json_strict(
            subject.BLIND_V1_ROOT / "schemas" / "freeze-manifest.schema.json"
        )
        jsonschema.Draft202012Validator(schema).validate(manifest)
        encoded = subject.canonical_freeze_manifest_bytes(manifest)
        self.manifest_path.write_bytes(encoded)
        loaded, observed = subject.load_freeze_manifest(self.manifest_path)
        self.assertEqual(loaded, manifest)

        self.assertEqual(observed, encoded)
        self.assertNotIn("freezeManifestSHA256", manifest)
        self.assertIs(
            manifest["freezeProcedure"]["manifestContainsOwnFileSHA256"], False
        )
        self.assertNotEqual(sha256_bytes(encoded), manifest["contentSHA256"])
        self.assertEqual(
            manifest["artifacts"]["runtimeManifestSHA256"],
            sha256_bytes(self.runtime_path.read_bytes()),
        )
        self.assertEqual(
            manifest["artifacts"]["fullAssetReceiptSHA256"],
            sha256_bytes(self.asset_path.read_bytes()),
        )
        self.assertEqual(
            manifest["artifacts"]["githubGateReceiptSHA256"],
            sha256_bytes(self.gate_path.read_bytes()),
        )
        self.assertEqual(
            manifest["authorVerification"],
            {
                "pullRequestURL": (
                    f"https://github.com/ALLPROTO/core-lm-cross-model-lab/pull/"
                    f"{GATE_PR}"
                ),
                "pullRequestNumber": GATE_PR,
                "mode": AUTHOR_VERIFICATION_MODE,
                "authorName": AUTHOR_NAME,
                "authorORCID": AUTHOR_ORCID,
                "authorGitHubLogin": AUTHOR_GITHUB_LOGIN,
                "implementationCommit": LAB_COMMIT,
                "independentHumanReviewRequired": False,
                "independentHumanReviewPerformed": False,
                "declaration": AUTHOR_VERIFICATION_DECLARATION,
                "claimBoundary": AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
            },
        )
        self.assertEqual(
            manifest["authorVerification"]["implementationCommit"],
            manifest["implementation"]["commit"],
        )
        self.assertEqual(
            manifest["continuousIntegration"]["workflowPath"],
            GATE_WORKFLOW_PATH,
        )
        self.assertIs(
            manifest["continuousIntegration"]["zeroSkippedOrCancelledJobs"],
            True,
        )
        self.assertEqual(len(self.ca_calls), 1)
        self.assertEqual(len(self.trust_calls), 1)

    def test_pud_rights_are_exact_and_tampering_is_rejected(self) -> None:
        rights = self._pud_rights_raw()
        subject._validate_development_rights_evidence(rights)

        tampered_manifest = copy.deepcopy(rights)
        tampered_manifest["developmentCorpusManifest"] += b"\n"

        evidence = json.loads(rights["licenseSourceEvidence"].decode("utf-8"))
        pud_readme = next(
            item
            for item in evidence["sources"]
            if item["component"] == "UD English PUD development corpus README"
        )
        pud_readme["sha256"] = "0" * 64
        tampered_evidence = copy.deepcopy(rights)
        tampered_evidence["licenseSourceEvidence"] = canonical_json_bytes(evidence)

        tampered_matrix = copy.deepcopy(rights)
        tampered_matrix["assetLicenseMatrix"] = rights[
            "assetLicenseMatrix"
        ].replace(b"without added restrictions", b"without extra restrictions", 1)

        tampered: dict[str, dict[str, bytes]] = {
            "development corpus manifest": tampered_manifest,
            "source-evidence manifest": tampered_evidence,
            "asset-license matrix": tampered_matrix,
        }
        for label, binding in (
            ("README", "udEnglishPudReadme"),
            ("LICENSE", "udEnglishPudLicense"),
            ("attribution", "udEnglishPudAttribution"),
        ):
            values = copy.deepcopy(rights)
            raw = bytearray(values[binding])
            raw[0] ^= 1
            values[binding] = bytes(raw)
            tampered[label] = values

        for label, values in tampered.items():
            with self.subTest(label=label), self.assertRaises(
                subject.FreezeManifestError
            ):
                subject._validate_development_rights_evidence(values)

    def test_pud_plan_contract_has_exact_bindings_paths_roles_and_sentences(self) -> None:
        plan, report, artifact_bytes, dataset_raw = self._pud_plan_fixture()
        expected_bindings = {
            "designRegistration",
            "modelAssetManifest",
            "fullAssetReceipt",
            "developmentCorpusManifest",
            "licenseSourceEvidence",
            "assetLicenseMatrix",
            "udEnglishPudReadme",
            "udEnglishPudLicense",
            "udEnglishPudAttribution",
            "developmentDataset",
            "runtimeManifest",
            "labSource",
            "codecSource",
            "controlSources",
            "joinedCorpusText",
            "conlluDecode",
            "adapter",
        }
        self.assertEqual(set(plan["inputBindings"]), expected_bindings)
        self.assertEqual(len(expected_bindings), 17)
        self.assertEqual(len(subject.DEVELOPMENT_ARCHIVED_INPUTS), 10)
        self.assertEqual(subject.DEVELOPMENT_DATASET_PATH, "inputs/corpus/en_pud-ud-test.conllu")
        self.assertEqual(subject.DEVELOPMENT_RECORD_ROOT, "records/ud-english-pud")

        expected_paths = subject._expected_development_artifact_paths()
        self.assertEqual(len(expected_paths), 2088)
        self.assertIn(subject.DEVELOPMENT_DATASET_PATH, expected_paths)
        self.assertIn(
            "containers/gpt-neo-125m/UniversalDependencies/"
            "UD_English-PUD:r2.18:test/slice-00/layer-00.vtl5",
            expected_paths,
        )
        self.assertTrue(
            {
                archived_path
                for archived_path, _ in subject.DEVELOPMENT_ARCHIVED_INPUTS.values()
            }.issubset(expected_paths)
        )
        self.assertFalse(any("wikitext" in path.lower() for path in expected_paths))

        pages = plan["pages"][subject.DEVELOPMENT_DATASET_ID]
        expected_page_fields = {
            "pageSelectionIndex",
            "sourceSliceIndex",
            "sentenceStart",
            "sentenceEnd",
            "recordPath",
            "recordBytes",
            "recordSHA256",
            "inputTextBytes",
            "inputTextSHA256",
        }
        self.assertTrue(all(set(page) == expected_page_fields for page in pages))
        self.assertEqual(pages[0]["sentenceStart"], 0)
        self.assertEqual(
            pages[-1]["sentenceEnd"], subject.DEVELOPMENT_DATASET_SENTENCES
        )
        roles = {item["role"] for item in plan["privateFiles"]}
        self.assertEqual(
            roles,
            {
                "model-asset",
                "development-corpus-record",
                "development-corpus-source",
            },
        )

        def read_bound(
            _root: Path,
            _inventory: dict[str, Any],
            relative: str,
            *,
            maximum_bytes: int,
        ) -> bytes:
            self.assertLessEqual(len(artifact_bytes[relative]), maximum_bytes)
            return artifact_bytes[relative]

        validation = mock.patch.multiple(
            subject,
            DEVELOPMENT_DATASET_BYTES=len(dataset_raw),
            DEVELOPMENT_DATASET_SHA256=sha256_bytes(dataset_raw),
            _read_bound_development_artifact=mock.DEFAULT,
            _verify_runtime_receipt=mock.DEFAULT,
        )
        with validation as patched:
            patched["_read_bound_development_artifact"].side_effect = read_bound
            patched["_verify_runtime_receipt"].return_value = None
            subject._validate_development_plan(
                plan,
                report=report,
                artifact_root=self.root,
                inventory={},
                expected_codec={
                    "repository": CODEC_REPOSITORY,
                    "commit": CODEC_COMMIT,
                    "tree": CODEC_TREE,
                },
                expected_implementation={
                    "repository": LAB_REPOSITORY,
                    "commit": LAB_COMMIT,
                    "tree": LAB_TREE,
                },
                expected_runtime_manifest_sha256=None,
            )

            old_binding_plan = copy.deepcopy(plan)
            old_binding_plan["inputBindings"]["legacyDataset"] = (
                old_binding_plan["inputBindings"].pop("developmentDataset")
            )
            old_binding_report = copy.deepcopy(report)
            old_binding_report["inputs"] = old_binding_plan["inputBindings"]
            del old_binding_plan["contentSHA256"]
            old_binding_plan = with_content_digest(old_binding_plan)
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "development input bindings fields differ"
            ):
                subject._validate_development_plan(
                    old_binding_plan,
                    report=old_binding_report,
                    artifact_root=self.root,
                    inventory={},
                    expected_codec={
                        "repository": CODEC_REPOSITORY,
                        "commit": CODEC_COMMIT,
                        "tree": CODEC_TREE,
                    },
                    expected_implementation={
                        "repository": LAB_REPOSITORY,
                        "commit": LAB_COMMIT,
                        "tree": LAB_TREE,
                    },
                    expected_runtime_manifest_sha256=None,
                )

            old_page_plan = copy.deepcopy(plan)
            old_page = old_page_plan["pages"][subject.DEVELOPMENT_DATASET_ID][0]
            old_page["rowStart"] = old_page.pop("sentenceStart")
            old_page["rowEnd"] = old_page.pop("sentenceEnd")
            del old_page_plan["contentSHA256"]
            old_page_plan = with_content_digest(old_page_plan)
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "development plan page fields differ"
            ):
                subject._validate_development_plan(
                    old_page_plan,
                    report=report,
                    artifact_root=self.root,
                    inventory={},
                    expected_codec={
                        "repository": CODEC_REPOSITORY,
                        "commit": CODEC_COMMIT,
                        "tree": CODEC_TREE,
                    },
                    expected_implementation={
                        "repository": LAB_REPOSITORY,
                        "commit": LAB_COMMIT,
                        "tree": LAB_TREE,
                    },
                    expected_runtime_manifest_sha256=None,
                )

            tampered_manifest = dict(artifact_bytes)
            tampered_manifest["inputs/development-corpus.draft.json"] += b"\n"
            patched["_read_bound_development_artifact"].side_effect = (
                lambda _root, _inventory, relative, **_kwargs: tampered_manifest[
                    relative
                ]
            )
            with self.assertRaisesRegex(
                subject.FreezeManifestError,
                "archived development input differs from frozen source",
            ):
                subject._validate_development_plan(
                    plan,
                    report=report,
                    artifact_root=self.root,
                    inventory={},
                    expected_codec={
                        "repository": CODEC_REPOSITORY,
                        "commit": CODEC_COMMIT,
                        "tree": CODEC_TREE,
                    },
                    expected_implementation={
                        "repository": LAB_REPOSITORY,
                        "commit": LAB_COMMIT,
                        "tree": LAB_TREE,
                    },
                    expected_runtime_manifest_sha256=None,
                )

            tampered_source = dict(artifact_bytes)
            tampered_source[subject.DEVELOPMENT_DATASET_PATH] += b"tamper"
            patched["_read_bound_development_artifact"].side_effect = (
                lambda _root, _inventory, relative, **_kwargs: tampered_source[relative]
            )
            with self.assertRaisesRegex(
                subject.FreezeManifestError, "archived development corpus bytes differ"
            ):
                subject._validate_development_plan(
                    plan,
                    report=report,
                    artifact_root=self.root,
                    inventory={},
                    expected_codec={
                        "repository": CODEC_REPOSITORY,
                        "commit": CODEC_COMMIT,
                        "tree": CODEC_TREE,
                    },
                    expected_implementation={
                        "repository": LAB_REPOSITORY,
                        "commit": LAB_COMMIT,
                        "tree": LAB_TREE,
                    },
                    expected_runtime_manifest_sha256=None,
                )

    def test_report_requires_real_development_corpus_flag(self) -> None:
        report = self._pud_report_fixture()
        patches = (
            mock.patch.object(subject, "_validate_development_supervision"),
            mock.patch.object(subject, "_validate_development_replay"),
            mock.patch.object(
                subject, "_validate_development_artifact_inventory", return_value=[]
            ),
        )
        with patches[0], patches[1], patches[2]:
            summary = subject.validate_development_control_report(report)
            self.assertEqual(summary["artifactCount"], 0)

            false_flag = copy.deepcopy(report)
            del false_flag["contentSHA256"]
            false_flag["realDevelopmentCorpusUsed"] = False
            false_flag = with_content_digest(false_flag)
            with self.assertRaisesRegex(
                subject.FreezeManifestError,
                "development-control report boundary differs",
            ):
                subject.validate_development_control_report(false_flag)

            legacy_flag = copy.deepcopy(report)
            del legacy_flag["contentSHA256"]
            legacy_flag["realLegacyDatasetUsed"] = legacy_flag.pop(
                "realDevelopmentCorpusUsed"
            )
            legacy_flag = with_content_digest(legacy_flag)
            with self.assertRaisesRegex(
                subject.FreezeManifestError,
                "development-control report fields differ",
            ):
                subject.validate_development_control_report(legacy_flag)

    def test_validator_rejects_cross_identity_extra_field_and_self_digest_tampering(self) -> None:
        manifest = self.build()
        wrong_head = copy.deepcopy(manifest)
        wrong_head["continuousIntegration"]["headSHA"] = "9" * 40
        del wrong_head["contentSHA256"]
        wrong_head = with_content_digest(wrong_head)
        with self.assertRaisesRegex(subject.FreezeManifestError, "CI head SHA"):
            subject.validate_freeze_manifest(wrong_head)

        extra = copy.deepcopy(manifest)
        del extra["contentSHA256"]
        extra["freezeManifestSHA256"] = "a" * 64
        extra = with_content_digest(extra)
        with self.assertRaisesRegex(subject.FreezeManifestError, "fields differ"):
            subject.validate_freeze_manifest(extra)

        tampered = copy.deepcopy(manifest)
        tampered["createdAt"] = "2026-08-08T10:07:00Z"
        with self.assertRaisesRegex(subject.FreezeManifestError, "self-digest"):
            subject.validate_freeze_manifest(tampered)

    def test_decision_checkpoint_and_publication_deadline_fail_closed(self) -> None:
        manifest = self.build()
        late_gate = copy.deepcopy(manifest)
        late_gate["continuousIntegration"]["gateLastServerDate"] = (
            "2026-08-08T12:00:01Z"
        )
        late_gate["createdAt"] = "2026-08-08T12:00:02Z"
        del late_gate["contentSHA256"]
        late_gate = with_content_digest(late_gate)
        with self.assertRaisesRegex(subject.FreezeManifestError, "decision checkpoint"):
            subject.validate_freeze_manifest(late_gate)

        late_freeze = copy.deepcopy(manifest)
        late_freeze["createdAt"] = "2026-08-09T00:00:01Z"
        del late_freeze["contentSHA256"]
        late_freeze = with_content_digest(late_freeze)
        with self.assertRaisesRegex(subject.FreezeManifestError, "publication deadline"):
            subject.validate_freeze_manifest(late_freeze)

    def test_artifact_reverification_rejects_mutation_and_dirty_runtime(self) -> None:
        manifest = self.build()
        self.ca_path.write_bytes(b"changed CA bytes\n")
        with self.assertRaisesRegex(subject.FreezeManifestError, "CA bundle SHA-256"):
            subject.verify_artifact_inputs(
                manifest,
                runtime_manifest_path=self.runtime_path,
                asset_receipt_path=self.asset_path,
                ca_bundle_path=self.ca_path,
                trust_manifest_path=self.trust_path,
                github_gate_receipt_path=self.gate_path,
                development_control_report_path=self.development_report_path,
                development_control_artifact_root=self.development_artifact_root,
                development_control_archive_receipt_path=(
                    self.development_archive_receipt_path
                ),
                development_control_archive_asset_root=(
                    self.development_archive_asset_root
                ),
                ca_verifier=self.ca_verifier,
                trust_verifier=self.trust_verifier,
                development_control_verifier=self.development_control_verifier,
                development_archive_verifier=self.development_archive_verifier,
            )

        self.ca_path.write_bytes(b"unit-contract CA bytes\n")
        self._write_runtime(clean=False)
        with self.assertRaisesRegex(subject.FreezeManifestError, "worktree was not clean"):
            self.build()

    def test_freeze_recomputes_runtime_tree_instead_of_trusting_its_self_digest(self) -> None:
        runtime = load_json_strict(self.runtime_path)
        del runtime["contentSHA256"]
        runtime["runtimeTree"]["entries"][0]["bytes"] = 2
        self.runtime_path.write_bytes(
            canonical_json_bytes(with_content_digest(runtime)) + b"\n"
        )
        with self.assertRaisesRegex(
            subject.FreezeManifestError, "runtime manifest integrity failed"
        ):
            self.build()

    def test_freeze_rejects_linux_or_unregistered_primary_runtime(self) -> None:
        runtime = load_json_strict(self.runtime_path)
        del runtime["contentSHA256"]
        runtime["host"].update(system="Linux", machine="x86_64", macVersion=None)
        runtime["python"]["platformTag"] = "linux-x86_64"
        self.runtime_path.write_bytes(
            canonical_json_bytes(with_content_digest(runtime)) + b"\n"
        )
        with self.assertRaisesRegex(subject.FreezeManifestError, "Python identity"):
            self.build()

        self._write_runtime(clean=True)
        runtime = load_json_strict(self.runtime_path)
        del runtime["contentSHA256"]
        runtime["requirementsLocks"].append(
            {"name": "extra.lock", "bytes": 1, "sha256": "9" * 64}
        )
        self.runtime_path.write_bytes(
            canonical_json_bytes(with_content_digest(runtime)) + b"\n"
        )
        with self.assertRaisesRegex(subject.FreezeManifestError, "requirements lock"):
            self.build()

    def test_gate_receipt_is_reopened_and_cli_typed_ci_cannot_replace_it(self) -> None:
        manifest = self.build()
        gate_raw = self.gate_path.read_bytes()
        self.gate_path.write_bytes(gate_raw + b"\n")
        with self.assertRaisesRegex(subject.FreezeManifestError, "GitHub CI receipt"):
            subject.verify_artifact_inputs(
                manifest,
                runtime_manifest_path=self.runtime_path,
                asset_receipt_path=self.asset_path,
                ca_bundle_path=self.ca_path,
                trust_manifest_path=self.trust_path,
                github_gate_receipt_path=self.gate_path,
                development_control_report_path=self.development_report_path,
                development_control_artifact_root=self.development_artifact_root,
                development_control_archive_receipt_path=(
                    self.development_archive_receipt_path
                ),
                development_control_archive_asset_root=(
                    self.development_archive_asset_root
                ),
                ca_verifier=self.ca_verifier,
                trust_verifier=self.trust_verifier,
                development_control_verifier=self.development_control_verifier,
                development_archive_verifier=self.development_archive_verifier,
            )

        create = subject.parse_arguments(
            [
                "create",
                "--runtime-manifest",
                str(self.runtime_path),
                "--asset-receipt",
                str(self.asset_path),
                "--transport-ca-bundle",
                str(self.ca_path),
                "--offline-trust-manifest",
                str(self.trust_path),
                "--github-gate-receipt",
                str(self.gate_path),
                "--development-control-report",
                str(self.development_report_path),
                "--development-control-artifact-root",
                str(self.development_artifact_root),
                "--development-control-archive-receipt",
                str(self.development_archive_receipt_path),
                "--development-control-archive-asset-root",
                str(self.development_archive_asset_root),
                "--cosign",
                "/unit/pinned-cosign",
                "--lab-repository",
                LAB_REPOSITORY,
                "--lab-commit",
                LAB_COMMIT,
                "--lab-tree",
                LAB_TREE,
                "--codec-repository",
                CODEC_REPOSITORY,
                "--codec-commit",
                CODEC_COMMIT,
                "--codec-tree",
                CODEC_TREE,
                "--output",
                str(self.manifest_path),
            ]
        )
        self.assertFalse(hasattr(create, "ci_head_sha"))
        self.assertFalse(hasattr(create, "created_at"))

    def test_fixture_trust_manifest_is_forbidden_before_injected_crypto_verifier(self) -> None:
        trust = load_json_strict(self.trust_path)
        trust["status"] = "KNOWN_ANSWER_FIXTURE_ONLY"
        trust["fixtureOnly"] = True
        self.trust_path.write_bytes(canonical_json_bytes(trust))
        with self.assertRaisesRegex(subject.FreezeManifestError, "not normative"):
            self.build()
        self.assertEqual(self.trust_calls, [])

    def test_candidate_trust_is_forbidden_before_injected_verifier(self) -> None:
        trust = load_json_strict(self.trust_path)
        trust["status"] = "CANDIDATE_OFFLINE_TRUST_BUNDLE"
        self.trust_path.write_bytes(canonical_json_bytes(trust))
        with self.assertRaisesRegex(subject.FreezeManifestError, "not normative"):
            self.build()
        self.assertEqual(self.trust_calls, [])

    def test_injected_verifier_cannot_bypass_exact_policy_or_leaf_checks(self) -> None:
        trust = load_json_strict(self.trust_path)
        trust["trustPolicy"]["revocationChecked"] = True
        self.trust_path.write_bytes(canonical_json_bytes(trust))
        with self.assertRaisesRegex(
            subject.FreezeManifestError, "preregistered status-only artifact"
        ):
            self.build()
        self.assertEqual(self.trust_calls, [])

    def test_producer_independent_trust_disagreement_fails_before_injection(self) -> None:
        actual = subject.load_independent_trust_bundle(
            self.trust_path,
            expected_time=subject.PULSE_TIME,
            expected_manifest_sha256=sha256_bytes(self.trust_path.read_bytes()),
            expected_root_der_sha256=(subject.NIST_TRUST_ROOT_DER_SHA256,),
            allow_known_answer_fixture=False,
            allow_candidate=False,
        )
        record = next(iter(actual.records.values()))
        disagreement = mock.Mock(
            fixture_only=False,
            manifest_sha256=actual.manifest_sha256,
            records={"0" * 128: record},
        )
        with mock.patch.object(
            subject,
            "load_independent_trust_bundle",
            return_value=disagreement,
        ):
            with self.assertRaisesRegex(
                subject.FreezeManifestError,
                "producer/independent outcomes disagree",
            ):
                self.build()
        self.assertEqual(self.trust_calls, [])

    def test_stage_two_design_binds_exact_manifest_file_sha(self) -> None:
        manifest = self.build()
        raw = subject.canonical_freeze_manifest_bytes(manifest)
        design = copy.deepcopy(
            load_json_strict(subject.BLIND_V1_ROOT / "design-registration.draft.json")
        )
        design.update(
            schemaVersion="corelm-blind-crossmodel-v1-design-v1",
            status="PUBLIC_DESIGN_FROZEN",
            readyToFreeze=True,
            freezeBlockers=[],
        )
        design["labSource"].update(
            status="FROZEN_BOUND",
            commit=LAB_COMMIT,
            tree=LAB_TREE,
            freezeManifestSHA256=sha256_bytes(raw),
        )
        design["runtime"].update(
            status="FROZEN_BOUND",
            runtimeManifestSHA256=manifest["artifacts"][
                "runtimeManifestSHA256"
            ],
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
            trustBundleStatus="FROZEN_OFFLINE_TRUST_BUNDLE",
            transportCABundleSHA256=manifest["artifacts"][
                "transportCABundleSHA256"
            ],
            offlineTrustBundleSHA256=manifest["artifacts"][
                "offlineTrustBundleSHA256"
            ],
        )
        design_path = self.root / "frozen-design.json"
        design_path.write_bytes(canonical_json_bytes(design) + b"\n")
        report = subject.verify_design_binding(manifest, raw, design_path)
        self.assertEqual(report["freezeManifestSHA256"], sha256_bytes(raw))

        design["developmentControls"]["realDataE2EFreezeGate"][
            "releaseAttestationBundleSHA256"
        ] = "e" * 64
        design_path.write_bytes(canonical_json_bytes(design) + b"\n")
        with self.assertRaisesRegex(
            subject.FreezeManifestError, "development-control binding"
        ):
            subject.verify_design_binding(manifest, raw, design_path)
        design["developmentControls"]["realDataE2EFreezeGate"][
            "releaseAttestationBundleSHA256"
        ] = manifest["artifacts"][
            "developmentControlReleaseAttestationBundleSHA256"
        ]

        design["labSource"]["freezeManifestSHA256"] = "f" * 64
        design_path.write_bytes(canonical_json_bytes(design) + b"\n")
        with self.assertRaisesRegex(subject.FreezeManifestError, "lab/freeze"):
            subject.verify_design_binding(manifest, raw, design_path)

    def test_schema_exposes_exact_two_stage_author_verification_and_ci_contract(
        self,
    ) -> None:
        schema = load_json_strict(
            subject.BLIND_V1_ROOT / "schemas" / "freeze-manifest.schema.json"
        )
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        procedure = schema["$defs"]["freezeProcedure"]["properties"]
        self.assertIs(procedure["manifestContainsOwnFileSHA256"]["const"], False)
        self.assertEqual(
            procedure["designBindingField"]["const"],
            "labSource.freezeManifestSHA256",
        )
        author = schema["$defs"]["authorVerification"]["properties"]
        self.assertEqual(author["mode"]["const"], AUTHOR_VERIFICATION_MODE)
        self.assertEqual(author["authorName"]["const"], AUTHOR_NAME)
        self.assertEqual(author["authorORCID"]["const"], AUTHOR_ORCID)
        self.assertEqual(
            author["authorGitHubLogin"]["const"], AUTHOR_GITHUB_LOGIN
        )
        self.assertIs(
            author["independentHumanReviewRequired"]["const"], False
        )
        self.assertIs(
            author["independentHumanReviewPerformed"]["const"], False
        )
        self.assertEqual(
            author["declaration"]["const"], AUTHOR_VERIFICATION_DECLARATION
        )
        self.assertEqual(
            author["claimBoundary"]["const"],
            AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
        )
        ci = schema["$defs"]["continuousIntegration"]["properties"]
        self.assertEqual(ci["status"]["const"], "completed")
        self.assertEqual(ci["conclusion"]["const"], "success")
        self.assertIs(ci["allJobsCompletedSuccess"]["const"], True)
        self.assertIs(ci["zeroSkippedOrCancelledJobs"]["const"], True)
        self.assertEqual(ci["workflowName"]["const"], GATE_WORKFLOW_NAME)
        self.assertEqual(ci["workflowPath"]["const"], GATE_WORKFLOW_PATH)
        artifacts = ci["artifactSHA256"]
        self.assertEqual(len(artifacts["prefixItems"]), 2)
        self.assertIs(artifacts["items"], False)
        self.assertIn(
            "linux-development",
            artifacts["prefixItems"][0]["properties"]["name"]["pattern"],
        )
        self.assertIn(
            "macos-development",
            artifacts["prefixItems"][1]["properties"]["name"]["pattern"],
        )
        self.assertIn(
            "githubGateReceiptSHA256",
            schema["$defs"]["artifacts"]["required"],
        )


if __name__ == "__main__":
    unittest.main()
