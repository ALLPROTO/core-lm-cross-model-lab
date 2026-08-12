#!/usr/bin/env python3
"""Static contract tests for the non-scientific RunPod adapter sweep."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path, PurePosixPath
from typing import Any


SWEEP = Path(__file__).resolve().parent
ROOT = SWEEP.parent
WORKLOADS = SWEEP / "workloads.json"
PROFILES = SWEEP / "profiles.json"
PROTOCOL = SWEEP / "PROTOCOL.md"


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=_reject_constant,
        object_pairs_hook=_reject_duplicate_pairs,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def _git_blob(path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"HEAD:{path}"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"{path} is not an exact blob at HEAD: "
            f"{completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed.stdout


class AdapterSweepContractTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.document = _load_json(WORKLOADS)

    def test_top_level_boundary_and_token_geometry_are_exact(self) -> None:
        self.assertEqual(
            set(self.document),
            {
                "adapterTargets",
                "classification",
                "concatenation",
                "horizonTokens",
                "schemaVersion",
                "scientificEvidence",
                "selection",
                "sourceBinding",
                "targetSemantics",
                "workloads",
            },
        )
        self.assertEqual(
            self.document["schemaVersion"],
            "corelm-runpod-adapter-sweep-workloads-v1",
        )
        self.assertEqual(
            self.document["classification"],
            "EXPLORATORY_PUBLIC_REGRESSION_ONLY",
        )
        self.assertIs(self.document["scientificEvidence"], False)
        self.assertEqual(self.document["horizonTokens"], 32)
        self.assertEqual(
            self.document["targetSemantics"],
            "maximum-codec-bounded-prefill-plus-greedy-horizon-v1",
        )
        self.assertEqual(
            self.document["selection"],
            {
                "addSpecialTokens": False,
                "generationTokens": 32,
                "prefillTokens": "maxCompressedPrefillTokens",
                "promptFinalInputTokens": 1,
                "selectedTokenRange": "first-maxCompressedPrefillTokens-plus-one",
                "truncation": False,
            },
        )
        self.assertEqual(
            self.document["sourceBinding"],
            {
                "allowWorkingTreeBytes": False,
                "requireCleanCheckout": True,
                "revision": "HEAD",
                "trackedBlobSource": "git-object-database",
                "tree": "HEAD^{tree}",
            },
        )
        forbidden_result_keys = {
            "compressionRatio",
            "deltaNLLNatPerToken",
            "metricVerdict",
            "pass",
            "result",
            "top1Agreement",
        }

        def assert_no_result_values(value: Any) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_result_keys.isdisjoint(value))
                for child in value.values():
                    assert_no_result_values(child)
            elif isinstance(value, list):
                for child in value:
                    assert_no_result_values(child)

        assert_no_result_values(self.document)

    def test_seven_adapter_context_targets_are_closed_and_sorted(self) -> None:
        expected = {
            "gemma-dynamic-cache-v1": (8192, 4096, "full-context"),
            "gpt-neox-dynamic-cache-v1": (2048, 2015, "full-context"),
            "gpt2-dynamic-cache-v1": (1024, 991, "full-context"),
            "llama-dynamic-cache-v1": (8192, 5461, "full-context"),
            "mistral-dynamic-cache-v1": (
                4096,
                1024,
                "sliding-window-effective",
            ),
            "opt-dynamic-cache-v1": (2048, 1365, "full-context"),
            "qwen2-dynamic-cache-v1": (32768, 8192, "full-context"),
        }
        targets = self.document["adapterTargets"]
        self.assertIsInstance(targets, list)
        self.assertEqual(
            [target["adapterId"] for target in targets], sorted(expected)
        )
        self.assertEqual(len(targets), 7)
        for target in targets:
            self.assertEqual(
                set(target), {"adapterId", "cachePolicy", "contextTargetTokens", "maxCompressedPrefillTokens"}
            )
            self.assertEqual(
                (
                    target["contextTargetTokens"],
                    target["maxCompressedPrefillTokens"],
                    target["cachePolicy"],
                ),
                expected[target["adapterId"]],
            )
            self.assertGreater(
                target["contextTargetTokens"], target["maxCompressedPrefillTokens"]
            )

    def test_four_workloads_are_exact_sorted_disjoint_tracked_groups(self) -> None:
        expected = {
            "tracked-legal-protocol-v1": "legal-and-protocol",
            "tracked-source-code-v1": "source-code",
            "tracked-structured-json-v1": "structured-json",
            "tracked-technical-prose-v1": "technical-prose",
        }
        workloads = self.document["workloads"]
        self.assertIsInstance(workloads, list)
        self.assertEqual(
            [workload["workloadId"] for workload in workloads], sorted(expected)
        )
        self.assertEqual(len(workloads), 4)

        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout.decode("utf-8").split("\0")
        tracked_paths = {path for path in tracked if path}
        all_paths: set[str] = set()
        for workload in workloads:
            self.assertEqual(
                set(workload),
                {
                    "contentClass",
                    "instruction",
                    "minimumTrackedUtf8Bytes",
                    "paths",
                    "workloadId",
                },
            )
            self.assertEqual(
                workload["contentClass"], expected[workload["workloadId"]]
            )
            self.assertEqual(workload["minimumTrackedUtf8Bytes"], 131072)
            paths = workload["paths"]
            self.assertGreaterEqual(len(paths), 10)
            self.assertEqual(paths, sorted(paths))
            self.assertEqual(len(paths), len(set(paths)))
            for path in paths:
                self.assertIsInstance(path, str)
                pure = PurePosixPath(path)
                self.assertFalse(pure.is_absolute())
                self.assertNotIn("..", pure.parts)
                self.assertNotIn(path, all_paths)
                self.assertIn(path, tracked_paths)
                all_paths.add(path)

    def test_git_blob_concatenation_is_utf8_deterministic_and_long(self) -> None:
        contract = self.document["concatenation"]
        self.assertEqual(
            contract,
            {
                "algorithm": "corelm-tracked-utf8-file-frames-v1",
                "beginFrame": "===== BEGIN CORELM TRACKED FILE: {path} =====\n",
                "contentBytes": "exact-git-head-blob",
                "contentEncoding": "utf-8-strict",
                "endFrame": "\n===== END CORELM TRACKED FILE: {path} =====\n",
                "instructionBeginFrame": "===== BEGIN OPERATOR REQUEST =====\n",
                "instructionEndFrame": "\n===== END OPERATOR REQUEST =====\n",
                "normalization": "none",
                "pathEncoding": "utf-8",
                "pathOrder": "ascending-posix-bytewise",
            },
        )
        observed_digests: set[str] = set()
        for workload in self.document["workloads"]:
            chunks: list[bytes] = [
                contract["instructionBeginFrame"].encode("utf-8"),
                workload["instruction"].encode("utf-8"),
                contract["instructionEndFrame"].encode("utf-8"),
            ]
            raw_bytes = 0
            for path in workload["paths"]:
                blob = _git_blob(path)
                blob.decode("utf-8", errors="strict")
                self.assertNotIn(b"\0", blob)
                raw_bytes += len(blob)
                chunks.extend(
                    (
                        contract["beginFrame"].format(path=path).encode("utf-8"),
                        blob,
                        contract["endFrame"].format(path=path).encode("utf-8"),
                    )
                )
            framed = b"".join(chunks)
            self.assertGreaterEqual(
                raw_bytes, workload["minimumTrackedUtf8Bytes"]
            )
            framed.decode("utf-8", errors="strict")
            digest = hashlib.sha256(framed).hexdigest()
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(digest, observed_digests)
            observed_digests.add(digest)

    def test_profile_registry_shape_when_present(self) -> None:
        if not PROFILES.exists():
            self.skipTest("profiles.json is supplied by the profile task")
        profiles = _load_json(PROFILES)
        self.assertEqual(
            set(profiles),
            {
                "classification",
                "executionPolicy",
                "profiles",
                "schemaVersion",
                "scientificEvidence",
            },
        )
        self.assertEqual(
            profiles["classification"], "EXPLORATORY_PUBLIC_REGRESSION_ONLY"
        )
        self.assertIs(profiles["scientificEvidence"], False)
        entries = profiles["profiles"]
        self.assertIsInstance(entries, list)
        self.assertEqual(len(entries), 7)
        expected_adapters = {
            target["adapterId"] for target in self.document["adapterTargets"]
        }
        self.assertEqual(
            {entry["adapterId"] for entry in entries}, expected_adapters
        )
        required = {
            "adapterId",
            "architecture",
            "cachePolicy",
            "gating",
            "geometry",
            "license",
            "modelType",
            "profileId",
            "repository",
            "requiredAssets",
            "revision",
            "gpuAdmission",
            "status",
            "trustRemoteCode",
            "weights",
        }
        for entry in entries:
            self.assertTrue(required.issubset(set(entry)))
            self.assertIs(entry["trustRemoteCode"], False)
            self.assertRegex(entry["revision"], r"^[0-9a-f]{40}$")
            self.assertIsInstance(entry["requiredAssets"], list)
            self.assertTrue(entry["requiredAssets"])
            target = next(
                item
                for item in self.document["adapterTargets"]
                if item["adapterId"] == entry["adapterId"]
            )
            self.assertGreaterEqual(
                entry["geometry"]["contextLength"],
                target["contextTargetTokens"],
            )
            self.assertEqual(
                entry["cachePolicy"]["slidingWindowEnabled"],
                entry["adapterId"] == "mistral-dynamic-cache-v1",
            )

    def test_optional_runner_and_verifier_fail_closed_contracts(self) -> None:
        python_files = [
            path
            for path in SWEEP.glob("*.py")
            if path.name != Path(__file__).name and not path.name.startswith("test_")
        ]
        runners = [
            path
            for path in python_files
            if path.stem in {"run", "runner", "run_sweep", "run_adapter_sweep"}
            or "runner" in path.stem
        ]
        verifiers = [path for path in python_files if "verif" in path.stem]

        for path in runners:
            source = path.read_text(encoding="utf-8")
            for required in (
                "HF_HUB_OFFLINE",
                "TRANSFORMERS_OFFLINE",
                "HF_HUB_DISABLE_IMPLICIT_TOKEN",
                "trust_remote_code=False",
                "subprocess",
            ):
                self.assertIn(required, source, path.name)
            for forbidden in ("shell=True", "eval(", "exec("):
                self.assertNotIn(forbidden, source, path.name)

        for path in verifiers:
            source = path.read_text(encoding="utf-8")
            for required in (
                "object_pairs_hook",
                "parse_constant",
                "is_symlink",
                "sha256",
            ):
                self.assertIn(required, source, path.name)
            self.assertNotIn("from runner import", source, path.name)
            self.assertNotIn("shell=True", source, path.name)

    def test_tracked_documents_contain_no_secret_or_endpoint_material(self) -> None:
        combined = WORKLOADS.read_text(encoding="utf-8") + PROTOCOL.read_text(
            encoding="utf-8"
        )
        for pattern in (
            r"hf_[A-Za-z0-9]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----",
            r"RUNPOD_API_KEY\s*=\s*[^<\s]+",
            r"ssh-ed25519\s+[A-Za-z0-9+/]{40,}",
            r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b",
        ):
            self.assertIsNone(re.search(pattern, combined))
        self.assertLess(WORKLOADS.stat().st_size, 64 * 1024)


if __name__ == "__main__":
    unittest.main()
