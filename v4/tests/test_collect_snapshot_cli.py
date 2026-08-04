from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from v4 import collect_snapshot as subject


MODEL_REVISIONS = {
    "gpt-neo-125m": "21def0189f5705e2521767faed922f1f15e7d7db",
    "smollm2-360m": "f8027fd0eaeea54caa13c31d31b9fdc459c38b49",
    "tiny-starcoder-py": "8547527bef0bc927268c1653cce6948c5c242dd1",
}


class FixtureTokenizer:
    vocab_size = 1024

    def encode(self, text: str, *, add_special_tokens: bool) -> list[int]:
        del text, add_special_tokens
        return [1] * 512


class CollectorCLIContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.asset_root = self.root / "assets"
        self.asset_root.mkdir()
        models: dict[str, Any] = {}
        self.tokenizer_payloads: dict[str, bytes] = {}
        for index, model_key in enumerate(subject.MODEL_KEYS):
            model_root = self.asset_root / model_key
            model_root.mkdir()
            tokenizer_bytes = (
                '{"fixtureControl":true,"model":' + json.dumps(model_key) + "}"
            ).encode("utf-8")
            weight_bytes = f"weight-commitment-control-{index}".encode("ascii")
            (model_root / "tokenizer.json").write_bytes(tokenizer_bytes)
            (model_root / "model.safetensors").write_bytes(weight_bytes)
            self.tokenizer_payloads[model_key] = tokenizer_bytes
            models[model_key] = {
                "repository": f"Fixture/{model_key}",
                "revision": MODEL_REVISIONS[model_key],
                "files": {
                    "tokenizer.json": {
                        "bytes": len(tokenizer_bytes),
                        "sha256": hashlib.sha256(tokenizer_bytes).hexdigest(),
                    },
                    "model.safetensors": {
                        "bytes": len(weight_bytes),
                        "sha256": hashlib.sha256(weight_bytes).hexdigest(),
                    },
                },
            }
        manifest = {
            "schemaVersion": "corelm-crossmodel-livewiki-v4-model-assets-draft-v1",
            "completeRuntimeFileList": True,
            "models": models,
        }
        self.manifest_path = self.root / "model-assets.json"
        self.manifest_path.write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        self.manifest_sha256 = hashlib.sha256(
            self.manifest_path.read_bytes()
        ).hexdigest()
        self.ca_bundle = self.root / "ca.pem"
        self.ca_bundle.write_bytes(b"unit contract only; client is injected\n")
        self.ca_sha256 = hashlib.sha256(self.ca_bundle.read_bytes()).hexdigest()
        self.output_root = self.root / "new-snapshot"
        self.factory_payloads: dict[str, bytes] = {}
        self.client_arguments: dict[str, Any] = {}

    def tokenizer_factory(self, model_key: str, value: bytes) -> FixtureTokenizer:
        self.factory_payloads[model_key] = value
        return FixtureTokenizer()

    def client_factory(self, **arguments: Any) -> object:
        self.client_arguments = arguments
        return object()

    @staticmethod
    def verify_ready(root: Path, *, tokenizers: Any) -> dict[str, Any]:
        if not root.is_dir() or tuple(tokenizers) != subject.MODEL_KEYS:
            raise AssertionError("verification contract differs")
        return {
            "status": "VERIFIED_SNAPSHOT_BYTES",
            "readyForFreeze": True,
            "eligibleRecords": 192,
            "manifestSHA256": "ab" * 32,
            "tokenCommitmentsRecomputed": True,
            "modelInferenceUsed": False,
        }

    def run_phase(self, phase: str, **overrides: Any) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "phase": phase,
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "asset_root": self.asset_root,
            "ca_bundle": self.ca_bundle,
            "ca_bundle_sha256": self.ca_sha256,
            "output_root": self.output_root,
            "clock": lambda: datetime(2026, 9, 23, 6, 0, 2, tzinfo=timezone.utc),
            "tokenizer_factory": self.tokenizer_factory,
            "https_client_factory": self.client_factory,
            "verify_snapshot_fn": self.verify_ready,
        }
        arguments.update(overrides)
        return subject.run_collector_phase(**arguments)

    def test_contract_verifies_all_assets_and_loads_owned_tokenizer_bytes(self) -> None:
        def stage(**arguments: Any) -> dict[str, Any]:
            self.assertTrue(arguments["root"].is_dir())
            return {
                "schemaVersion": subject.CRAWL_STAGE_SCHEMA,
                "crawlIndex": 1,
                "notBefore": "2026-09-22T06:00:00Z",
                "projects": {project: {} for project in subject.PROJECTS},
                "countsTowardScientificVerdict": False,
            }

        report = self.run_phase("crawl-1", collect_crawl_stage_fn=stage)
        self.assertEqual(report["status"], "CRAWL_1_ARCHIVED")
        self.assertFalse(report["countsTowardScientificVerdict"])
        self.assertFalse(report["modelInferenceUsed"])
        self.assertEqual(report["assetFilesVerified"], 6)
        self.assertEqual(report["tokenizerFilesLoaded"], 3)
        self.assertEqual(self.factory_payloads, self.tokenizer_payloads)
        for value in self.factory_payloads.values():
            self.assertIs(type(value), bytes)
        self.assertEqual(self.client_arguments["ca_bundle"], self.ca_bundle)
        self.assertEqual(
            self.client_arguments["ca_bundle_sha256"], self.ca_sha256
        )
        self.assertEqual(
            tuple(self.client_arguments["allowed_hosts"]), subject.PROJECTS
        )

    def test_tampered_non_tokenizer_asset_fails_before_transport(self) -> None:
        weight = self.asset_root / subject.MODEL_KEYS[1] / "model.safetensors"
        value = weight.read_bytes()
        weight.write_bytes(value[:-1] + bytes([value[-1] ^ 1]))
        with self.assertRaisesRegex(subject.CollectorCLIError, "digest mismatch"):
            self.run_phase("crawl-1")
        self.assertEqual(self.client_arguments, {})
        self.assertFalse(self.output_root.exists())

    def test_manifest_requires_explicit_exact_digest_pin(self) -> None:
        with self.assertRaisesRegex(subject.CollectorCLIError, "explicit pin"):
            self.run_phase("crawl-1", manifest_sha256="00" * 32)
        self.assertEqual(self.client_arguments, {})

    def test_output_root_must_be_absent_even_when_empty(self) -> None:
        self.output_root.mkdir()
        with self.assertRaisesRegex(subject.CollectorCLIError, "must not already exist"):
            self.run_phase("crawl-1")
        self.assertEqual(self.client_arguments, {})

    def test_insufficient_snapshot_is_replayed_but_rejected(self) -> None:
        self.output_root.mkdir()

        def finalize_insufficient(**arguments: Any) -> dict[str, Any]:
            del arguments
            return {
                "status": "INSUFFICIENT_ELIGIBLE_REVISIONS",
                "countsTowardScientificVerdict": False,
            }

        with self.assertRaisesRegex(subject.CollectorCLIError, "not freeze-ready"):
            self.run_phase("finalize", finalize_snapshot_fn=finalize_insufficient)
        self.assertTrue(self.output_root.is_dir())

    def test_verifier_must_recompute_token_commitments_without_inference(self) -> None:
        self.output_root.mkdir()

        def finalize(**arguments: Any) -> dict[str, Any]:
            del arguments
            return {
                "status": "SNAPSHOT_READY_FOR_FREEZE",
                "countsTowardScientificVerdict": False,
            }

        def weak_verifier(root: Path, *, tokenizers: Any) -> dict[str, Any]:
            report = self.verify_ready(root, tokenizers=tokenizers)
            report["tokenCommitmentsRecomputed"] = False
            return report

        with self.assertRaisesRegex(subject.CollectorCLIError, "did not recompute"):
            self.run_phase(
                "finalize",
                finalize_snapshot_fn=finalize,
                verify_snapshot_fn=weak_verifier,
            )

    def test_two_durable_cli_phases_preserve_one_new_root(self) -> None:
        observed: list[int] = []

        def stage(**arguments: Any) -> dict[str, Any]:
            crawl_index = arguments["crawl_index"]
            observed.append(crawl_index)
            self.assertTrue(arguments["root"].is_dir())
            return {
                "schemaVersion": subject.CRAWL_STAGE_SCHEMA,
                "crawlIndex": crawl_index + 1,
                "notBefore": subject.CRAWL_NOT_BEFORE[crawl_index].strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "projects": {project: {} for project in subject.PROJECTS},
                "countsTowardScientificVerdict": False,
            }

        first = self.run_phase("crawl-1", collect_crawl_stage_fn=stage)
        second = self.run_phase("crawl-2", collect_crawl_stage_fn=stage)
        self.assertEqual(observed, [0, 1])
        self.assertEqual(first["status"], "CRAWL_1_ARCHIVED")
        self.assertEqual(second["status"], "CRAWL_2_ARCHIVED")
        self.assertFalse(first["freezeReady"])
        self.assertFalse(second["countsTowardScientificVerdict"])

    def test_finalize_phase_requires_freeze_ready_replay(self) -> None:
        self.output_root.mkdir()

        def finalize(**arguments: Any) -> dict[str, Any]:
            self.assertEqual(tuple(arguments["tokenizers"]), subject.MODEL_KEYS)
            return {
                "status": "SNAPSHOT_READY_FOR_FREEZE",
                "countsTowardScientificVerdict": False,
            }

        report = self.run_phase("finalize", finalize_snapshot_fn=finalize)
        self.assertEqual(report["eligibleRecords"], 192)

        def insufficient(**arguments: Any) -> dict[str, Any]:
            del arguments
            return {
                "status": "INSUFFICIENT_ELIGIBLE_REVISIONS",
                "countsTowardScientificVerdict": False,
            }

        with self.assertRaisesRegex(subject.CollectorCLIError, "not freeze-ready"):
            self.run_phase("finalize", finalize_snapshot_fn=insufficient)

    def test_uppercase_or_unpinned_ca_digest_is_rejected_before_io(self) -> None:
        with self.assertRaisesRegex(subject.CollectorCLIError, "lowercase"):
            self.run_phase("crawl-1", ca_bundle_sha256=self.ca_sha256.upper())
        self.assertEqual(self.client_arguments, {})

        self.ca_bundle.write_bytes(b"different CA bytes\n")
        with self.assertRaisesRegex(subject.CollectorCLIError, "explicit pin"):
            self.run_phase("crawl-1")
        self.assertEqual(self.client_arguments, {})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_tokenizer_symlink_is_rejected(self) -> None:
        target = self.asset_root / subject.MODEL_KEYS[0] / "tokenizer.json"
        saved = self.root / "saved-tokenizer.json"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaisesRegex(subject.CollectorCLIError, "symlink|no-follow"):
            self.run_phase("crawl-1")
        self.assertEqual(self.client_arguments, {})


if __name__ == "__main__":
    unittest.main()
