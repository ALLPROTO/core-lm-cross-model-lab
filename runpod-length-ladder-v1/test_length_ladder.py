#!/usr/bin/env python3
"""Model-free contract tests for the preregistered length ladder."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SUITE = Path(__file__).resolve().parent
sys.path.insert(0, str(SUITE))
import common  # noqa: E402


def load_verifier():
    spec = importlib.util.spec_from_file_location("length_verifier_tests", SUITE / "verify_length_ladder.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_cgroup_contract():
    path = SUITE.parent / "runpod-adapter-sweep-v1" / "cgroup_contract.py"
    spec = importlib.util.spec_from_file_location("length_cgroup_contract_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RegistrationTests(unittest.TestCase):
    def test_registration_is_closed_and_prior_record_is_bound(self) -> None:
        value = common.load_ladder()
        self.assertEqual(tuple(item["prefillTokens"] for item in value["lengths"]), common.PREFILL_LEVELS)
        self.assertEqual(tuple(value["executionOrder"]), common.EXECUTION_LEVEL_IDS)
        self.assertEqual(value["timeoutPolicy"]["directSecondsByLevel"], common.DIRECT_TIMEOUT_BY_LEVEL)
        self.assertEqual(value["timeoutPolicy"]["secondarySecondsPerLevel"], 300)
        self.assertTrue(value["priorKnowledge"]["priorPromptAndTokenIdsDifferFromCurrentSourceTree"])
        self.assertEqual(value["hardwarePolicy"]["cpuLogicalMinimum"], 8)
        self.assertEqual(value["hardwarePolicy"]["cgroupCpuQuotaCoreMinimum"], 7)
        self.assertEqual(value["amendment"]["cgroupCpuQuotaCoreMinimumOld"], 8)
        self.assertFalse(value["amendment"]["modelAssetDownloadCompletedBeforeAmendment"])
        self.assertFalse(value["amendment"]["modelInferenceStartedBeforeAmendment"])
        self.assertFalse(value["amendment"]["resultObservedBeforeAmendment"])

        contract = load_cgroup_contract()
        memory = 32 * 1024**3
        with self.assertRaises(contract.CgroupContractError):
            contract.admit(
                contract.CgroupObservation("v2", 699_999, 100_000, 1, 1, memory),
                7,
                memory,
            )
        for quota in (700_000, 765_000, None):
            contract.admit(
                contract.CgroupObservation("v2", quota, 100_000, 1, 1, memory),
                7,
                memory,
            )

    def test_no_seventh_model_forward_or_generate_master_command(self) -> None:
        source = (SUITE / "run_length_ladder.py").read_text(encoding="utf-8")
        self.assertNotIn("generate-master", source)
        self.assertNotIn("MASTER_STARTED", source)
        self.assertIn("registered-primary-direct-cell-p008192", (SUITE / "ladder.json").read_text())
        self.assertLess(source.index("for level_id in EXECUTION_LEVEL_IDS"), source.index("if direct_complete:"))

    def test_external_cli_parity(self) -> None:
        runner = subprocess.run([sys.executable, str(SUITE / "run_length_ladder.py"), "--help"], capture_output=True, text=True, check=True).stdout
        verifier = subprocess.run([sys.executable, str(SUITE / "verify_length_ladder.py"), "--help"], capture_output=True, text=True, check=True).stdout
        for command in ("preflight", "orchestrate", "run-cell", "run-secondary"):
            self.assertIn(command, runner)
        for command in ("verify", "replay-cell", "render-results"):
            self.assertIn(command, verifier)
        for level in common.LEVEL_IDS:
            help_text = subprocess.run([sys.executable, str(SUITE / "verify_length_ladder.py"), "replay-cell", "--help"], capture_output=True, text=True, check=True).stdout
            self.assertIn(level, help_text)

    def test_replay_fast_path_does_not_repeat_full_verify(self) -> None:
        source = (SUITE / "verify_length_ladder.py").read_text(encoding="utf-8")
        start = source.index("def _load_structural_context(")
        end = source.index("\ndef replay_cell(", start)
        self.assertNotIn("verify_run(", source[start:end])
        self.assertIn("_read_direct_raw_fast", source)
        for gate in (
            "require_exact_keys(run, RUN_MANIFEST_KEYS",
            "_require_source_bindings(run, source",
            "_record_fields(",
            "_verify_attempt(",
            'row["directResultSHA256"] == result_digest',
        ):
            self.assertIn(gate, source)


class ArithmeticTests(unittest.TestCase):
    @staticmethod
    def points(containers: list[int], payloads: list[int] | None = None):
        values = []
        for index, (level, prefill, container) in enumerate(zip(common.LEVEL_IDS, common.PREFILL_LEVELS, containers)):
            point = {"lengthLevelId": level, "prefillTokens": prefill, "denseBF16Bytes": prefill * 100, "containerBytes": container}
            if payloads is not None:
                point["payloadBytes"] = payloads[index]
            values.append(point)
        return values

    def test_exact_strong_weak_equal_decrease_and_materiality(self) -> None:
        strong = common.length_analysis(self.points([200, 390, 760, 1480, 2880, 5600]))
        self.assertEqual(common.support_decision(complete=True, primary_analysis=strong), "STRONG_DIRECTIONAL_SUPPORT")
        weak = common.length_analysis(self.points([200, 410, 790, 1600, 3100, 6000]))
        self.assertEqual(common.support_decision(complete=True, primary_analysis=weak), "WEAK_DIRECTIONAL_SUPPORT")
        equal = common.length_analysis(self.points([256, 512, 1024, 2048, 4096, 8192]))
        self.assertEqual(common.support_decision(complete=True, primary_analysis=equal), "NO_POSITIVE_SUPPORT_EQUAL")
        decrease = common.length_analysis(self.points([200, 400, 800, 1600, 3200, 7000]))
        self.assertEqual(common.support_decision(complete=True, primary_analysis=decrease), "NO_POSITIVE_SUPPORT_DECREASE")
        self.assertEqual(common.support_decision(complete=False, primary_analysis=None), "INDETERMINATE")
        for analysis in (strong, weak, equal, decrease):
            int(analysis["endpointExactCrossProductNumeratorDecimal"])
            int(analysis["endpointOnePercentMaterialityNumeratorDecimal"])

    def test_independent_verifier_arithmetic_does_not_call_producer(self) -> None:
        verifier = load_verifier()
        points = self.points([200, 390, 760, 1480, 2880, 5600])
        expected = verifier._independent_analysis(points)
        with mock.patch.object(common, "length_analysis", side_effect=AssertionError("producer called")):
            self.assertEqual(verifier._independent_analysis(points), expected)
        self.assertEqual(common.length_analysis(points), expected)

    def test_payload_diagnostic_parity_and_never_controls_class(self) -> None:
        verifier = load_verifier()
        points = self.points([200, 390, 760, 1480, 2880, 5600], [190, 380, 750, 1470, 2870, 5590])
        self.assertEqual(common.payload_analysis(points), verifier._independent_payload_analysis(points))
        self.assertIn("never-controls-support-decision", common.payload_analysis(points)["role"])


class SafetyTests(unittest.TestCase):
    def test_safe_relative_rejects_absolute_and_traversal(self) -> None:
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "okay").write_bytes(b"x")
            with self.assertRaises(Exception):
                verifier._safe_relative(root, "/etc/passwd", "okay", "test")
            with self.assertRaises(Exception):
                verifier._safe_relative(root, "../okay", "okay", "test")

    def test_bf16_matrix_rejects_wrong_size_and_nonfinite(self) -> None:
        verifier = load_verifier()
        try:
            import numpy as np
        except ModuleNotFoundError:
            self.skipTest("numpy is supplied by the pinned RunPod runtime")
        verifier.np = np
        with self.assertRaises(Exception):
            verifier._bf16_matrix(b"\0", 1, 1)
        with self.assertRaises(Exception):
            verifier._bf16_matrix((0x7F80).to_bytes(2, "little"), 1, 1)

    def test_asset_preparer_rejects_generic_credential_names(self) -> None:
        spec = importlib.util.spec_from_file_location("length_assets_tests", SUITE / "prepare_assets.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ("RUNPOD_TOKEN", "CI_JOB_TOKEN", "REFRESH_TOKEN", "CUSTOM_API_KEY"):
            with self.subTest(name=name), mock.patch.dict(os.environ, {name: "redacted"}, clear=True):
                with self.assertRaises(Exception):
                    module.require_clean_credentials()
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin", "LANG": "C"}, clear=True):
            module.require_clean_credentials()

    def test_timestamp_and_decimal_grammar_fail_closed(self) -> None:
        verifier = load_verifier()
        for value in ("2026-01-01", "2026-01-01T00:00:00+00:00", "bad"):
            with self.subTest(value=value), self.assertRaises(Exception):
                verifier._timestamp(value, "test")
        self.assertIsNotNone(verifier.DECIMAL_INTEGER.fullmatch("0"))
        self.assertIsNotNone(verifier.DECIMAL_INTEGER.fullmatch("-17"))
        for value in ("+1", "01", "-0", "1.0", " 1"):
            self.assertIsNone(verifier.DECIMAL_INTEGER.fullmatch(value))

    def test_container_bounds_are_checked_before_backend_decode(self) -> None:
        source = (SUITE / "verify_length_ladder.py").read_text(encoding="utf-8")
        bound = source.index("0 < status.st_size <= MAX_CONTAINER_BYTES")
        decode = source.index("parsed = backend.from_bytes(raw)")
        self.assertLess(bound, decode)
        self.assertIn("total_container <= MAX_TOTAL_CONTAINER_BYTES", source)

    def test_producer_and_verifier_closed_direct_result_keys_match(self) -> None:
        producer = (SUITE / "run_length_ladder.py").read_text(encoding="utf-8")
        verifier = (SUITE / "verify_length_ladder.py").read_text(encoding="utf-8")
        for key in (
            "directRawEvidence",
            "selectedTokenIds",
            "directCanonicalCacheBF16SHA256",
            "inputManifestSHA256",
            "inputTokenMasterSHA256",
            "directBehavior",
        ):
            self.assertIn(f'"{key}"', producer)
            self.assertIn(f'"{key}"', verifier)
        self.assertIn('require_exact_keys(result, DIRECT_RESULT_KEYS, "direct result")', verifier)
        self.assertIn('require_exact_keys(result, DIRECT_RESULT_KEYS, "selected replay result")', verifier)

    def test_cross_process_order_is_enforced(self) -> None:
        source = (SUITE / "verify_length_ladder.py").read_text(encoding="utf-8")
        self.assertIn("direct cells overlap or violate registered execution order", source)
        self.assertIn("secondary controls began before all direct cells completed", source)
        self.assertIn("secondary controls overlap or violate ascending order", source)


if __name__ == "__main__":
    unittest.main()
