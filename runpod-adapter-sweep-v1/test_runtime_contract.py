#!/usr/bin/env python3
"""Focused offline tests for the sweep runtime and codec projection."""

from __future__ import annotations

import ast
import hashlib
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
LAB = ROOT.parent
CODEC_ENV = os.environ.get("CORELM_SWEEP_TEST_CODEC_ROOT")
CODEC = Path(CODEC_ENV).resolve() if CODEC_ENV else None
sys.path.insert(0, str(ROOT))

import common  # noqa: E402
import launch_runpod  # noqa: E402


PRODUCER = ROOT / "run_adapter_sweep.py"
VERIFIER = ROOT / "verify_adapter_sweep.py"
PREPARER = ROOT / "prepare_assets.py"
WRAPPER = ROOT / "run_on_runpod.sh"
ENTRY = ROOT / "launch_runpod.py"
TOKEN_SCANNER = ROOT / "scan_token_persistence.py"
CUDA_BUILDER = ROOT / "build_cuda_runtime.sh"
CUDA_LOCK = ROOT / "torch-linux-cu130-py312.txt"
RUNBOOK = ROOT / "RUNPOD.md"
CGROUP_CONTRACT = ROOT / "cgroup_contract.py"


def _syntax_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _literal_dict_key_sets(path: Path) -> list[frozenset[str]]:
    """Return string keys from dict literals, ignoring a deliberate ** expansion."""

    result: list[frozenset[str]] = []
    for node in ast.walk(_syntax_tree(path)):
        if not isinstance(node, ast.Dict) or not node.keys:
            continue
        if not all(
            key is None
            or (isinstance(key, ast.Constant) and isinstance(key.value, str))
            for key in node.keys
        ):
            continue
        result.append(
            frozenset(key.value for key in node.keys if key is not None)
        )
    return result


def _literal_set_values(path: Path) -> list[frozenset[str]]:
    result: list[frozenset[str]] = []
    for node in ast.walk(_syntax_tree(path)):
        if not isinstance(node, ast.Set) or not node.elts:
            continue
        if all(
            isinstance(element, ast.Constant) and isinstance(element.value, str)
            for element in node.elts
        ):
            result.append(frozenset(element.value for element in node.elts))
    return result


def _function(path: Path, name: str) -> ast.FunctionDef:
    matches = [
        node
        for node in _syntax_tree(path).body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one function {name!r} in {path}")
    return matches[0]


def _function_source(path: Path, name: str) -> str:
    source = path.read_text(encoding="utf-8")
    segment = ast.get_source_segment(source, _function(path, name))
    if segment is None:
        raise AssertionError(f"cannot recover source for {name!r} in {path}")
    return segment


class RuntimeContractTests(unittest.TestCase):
    def _new_private_temporary_directory(self, label: str) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix=f"corelm-{label}-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        os.chmod(root, 0o700)
        self.assertTrue(root.is_absolute())
        self.assertTrue(root.is_dir())
        self.assertFalse(root.is_symlink())
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        return root

    def _defer_process_cleanup(self, pid_path: Path, sentinel: str) -> None:
        """Register cleanup before launch and kill only our marked Linux child."""

        def cleanup() -> None:
            try:
                raw = pid_path.read_text(encoding="ascii").strip()
                pid = int(raw)
            except (FileNotFoundError, ValueError):
                return
            command_path = Path(f"/proc/{pid}/cmdline")
            try:
                command = command_path.read_bytes()
            except (FileNotFoundError, PermissionError):
                return
            if sentinel.encode("ascii") not in command:
                return
            for signum in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(pid, signum)
                except ProcessLookupError:
                    return
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if not command_path.exists():
                        return
                    time.sleep(0.02)

        self.addCleanup(cleanup)

    def _assert_pid_disappears(self, pid: int, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
        self.fail(f"process {pid} survived the cleanup deadline")

    def test_pid1_hf_token_parser_is_bounded_exact_and_ascii(self) -> None:
        token = "hf_" + "a" * 34
        self.assertEqual(
            launch_runpod.parse_pid1_hf_token(
                b"PUBLIC_KEY=not-copied\0HF_TOKEN="
                + token.encode("ascii")
                + b"\0RUNPOD_API_KEY=not-copied\0"
            ),
            token,
        )
        rejected = (
            b"PUBLIC_KEY=value\0",
            b"HF_TOKEN=" + token.encode("ascii") + b"\0HF_TOKEN=" + token.encode("ascii") + b"\0",
            b"HF_TOKEN=hf_" + b"a" * 20 + b"\xff\0",
            b"HF_TOKEN=" + token.encode("ascii"),
            b"HF_TOKEN=hf_short\0",
            b"HF_TOKEN=hf_" + b"a" * 20 + b"\n\0",
            b"HF_TOKEN=hf_" + b"a" * 20 + b"-\0",
            b"X=" + b"a" * launch_runpod.MAX_PID1_ENVIRON_BYTES + b"\0",
        )
        for raw in rejected:
            with self.subTest(raw_length=len(raw)):
                with self.assertRaises(SystemExit):
                    launch_runpod.parse_pid1_hf_token(raw)

    def test_launcher_uses_pid1_only_when_hf_token_is_absent(self) -> None:
        source = _function_source(ENTRY, "main")
        self.assertIn('if values["HF_TOKEN"] is None:', source)
        self.assertIn('values["HF_TOKEN"] = read_pid1_hf_token()', source)
        self.assertNotIn("os.environ.update", ENTRY.read_text(encoding="utf-8"))

    def test_profiles_bind_codec_matrix_limit_exactly(self) -> None:
        profiles = common.load_profiles()["profiles"]
        self.assertEqual([entry["modelId"] for entry in profiles], list(common.MODEL_ORDER))
        targets = {
            entry["adapterId"]: entry["maxCompressedPrefillTokens"]
            for entry in common.load_workloads()["adapterTargets"]
        }
        for profile in profiles:
            geometry = profile["geometry"]
            columns = 2 * geometry["kvHeads"] * geometry["headDimension"]
            expected = min(
                geometry["contextTokens"] - common.HORIZON - 1,
                common.MAX_MATRIX_ELEMENTS // columns,
            )
            self.assertEqual(profile["maxPrefillTokens"], expected)
            self.assertEqual(targets[profile["adapterId"]], expected)

    def test_hard_gpu_admission_arithmetic_fits_every_profile_cap(self) -> None:
        profiles = common.load_profiles()["profiles"]
        registered_timeouts: list[int] = []
        for profile in profiles:
            geometry = profile["geometry"]
            admission = profile["gpuAdmission"]
            prefill_tokens = int(profile["maxPrefillTokens"])
            dense_bytes = (
                prefill_tokens
                * 2
                * int(geometry["kvHeads"])
                * int(geometry["headDimension"])
                * int(geometry["layers"])
                * 2
            )
            weight_bytes = sum(
                int(asset["bytes"])
                for asset in profile["files"]
                if asset["path"].endswith((".safetensors", ".bin"))
            )
            estimate = weight_bytes + 6 * dense_bytes + 4 * 1024**3
            self.assertIs(admission["hardLimit"], True)
            self.assertLessEqual(
                estimate,
                int(admission["maxGpuMemoryBytes"]),
                profile["modelId"],
            )
            self.assertLessEqual(
                prefill_tokens + common.HORIZON,
                int(admission["maxInputTokens"]),
                profile["modelId"],
            )
            self.assertLessEqual(
                int(admission["maxInputTokens"]),
                int(geometry["contextTokens"]),
                profile["modelId"],
            )
            registered_timeouts.append(int(admission["executionTimeoutSeconds"]))
        self.assertEqual(max(registered_timeouts), 2700)

        producer_run_cell = _function(PRODUCER, "run_cell")
        verifier_runtime = _function(VERIFIER, "_verify_runtime")
        producer_estimates = [
            ast.unparse(node.value)
            for node in ast.walk(producer_run_cell)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "estimate" for target in node.targets)
        ]
        verifier_estimates = [
            ast.unparse(node.value)
            for node in ast.walk(verifier_runtime)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "expected_estimate"
                for target in node.targets
            )
        ]
        self.assertEqual(producer_estimates, ["weight_bytes + 6 * dense_bytes + 4 * 1024 ** 3"])
        self.assertEqual(verifier_estimates, ["weight_bytes + 6 * dense_bytes + 4 * 1024 ** 3"])

    def test_schedule_projection_is_closed_for_every_layer_count(self) -> None:
        for layers in (6, 12, 18, 24, 30, 32):
            schedule = common.bits_schedule(layers)
            self.assertEqual(len(schedule), layers)
            self.assertTrue(set(schedule).issubset({8, 9}))
            self.assertEqual(schedule[0], 9)
            self.assertEqual(schedule[layers // 3], 9)
            self.assertEqual(schedule.count(9), 2)

    def test_workloads_start_with_distinct_real_operator_requests(self) -> None:
        seen: set[str] = set()
        for workload in common.load_workloads()["workloads"]:
            text, inventory = common.workload_text(workload)
            self.assertTrue(text.startswith("===== BEGIN OPERATOR REQUEST =====\n"))
            self.assertIn(workload["instruction"], text)
            self.assertGreaterEqual(len(inventory), 10)
            digest = common.sha256_bytes(text.encode("utf-8"))
            self.assertNotIn(digest, seen)
            seen.add(digest)

    def test_arbitrary_layer_projection_round_trips_canonical_containers(self) -> None:
        if CODEC is None or not CODEC.exists():
            self.skipTest("CORELM_SWEEP_TEST_CODEC_ROOT is not an available checkout")
        try:
            import numpy as np
        except ModuleNotFoundError:
            self.skipTest("NumPy is unavailable in this test interpreter")
        sys.path.insert(0, str(CODEC))
        from RealLLM.voidtoken_v5 import VoidTokenV5Backend

        for layers in (6, 18, 30, 32):
            schedule = common.bits_schedule(layers)
            for layer_index in (0, layers // 3, layers - 1):
                matrix = np.arange(4 * 128, dtype=np.float32).reshape(4, 128) / 100.0
                encoded = VoidTokenV5Backend.encode(
                    matrix,
                    bits=schedule[layer_index],
                    group_size=128,
                    transform_block_size=128,
                    layer_index=layer_index,
                    scale_compression="zlib-9",
                    code_compression="zlib-9",
                    sign_mode="none",
                )
                parsed = VoidTokenV5Backend.from_bytes(encoded.to_bytes())
                self.assertEqual(parsed.to_bytes(), encoded.to_bytes())
                self.assertEqual(parsed.metadata["layerIndex"], layer_index)
                self.assertEqual(parsed.metadata["bits"], schedule[layer_index])
                self.assertTrue(np.array_equal(parsed.reconstructed, encoded.reconstructed))

    def test_producer_and_verifier_exact_object_keys_are_in_lockstep(self) -> None:
        attempt = frozenset(
            {
                "schemaVersion",
                "status",
                "classification",
                "countsTowardScientificVerdict",
                "runId",
                "attemptId",
                "startedAt",
                "modelId",
                "adapterId",
                "workloadId",
                "timeoutLimitSeconds",
                "source",
                "codecSource",
                "preflightSHA256",
                "assetReceiptSHA256",
                "profilesSHA256",
                "workloadsSHA256",
                "protocolSHA256",
            }
        )
        result = frozenset(
            {
                "schemaVersion",
                "status",
                "classification",
                "countsTowardScientificVerdict",
                "model",
                "workload",
                "codecSource",
                "assetReceiptSHA256",
                "canonicalCacheBF16SHA256",
                "cacheObservation",
                "structuralReplay",
                "encoding",
                "behavior",
                "runtime",
            }
        )
        record = frozenset(
            {
                "modelId",
                "workloadId",
                "startedAt",
                "completedAt",
                "returnCode",
                "exitSignal",
                "timedOut",
                "timeoutLimitSeconds",
                "terminationReason",
                "status",
                "resultPath",
                "resultSHA256",
                "stdoutSHA256",
                "stderrSHA256",
            }
        )
        cache = frozenset(
            {
                "cacheClass",
                "layerClass",
                "tensorLayout",
                "batchSize",
                "layers",
                "kvHeads",
                "headDimension",
                "dtype",
                "targetContextTokens",
                "prefillTokens",
                "finalPromptTokens",
                "continuationTokens",
                "effectiveCacheTokens",
                "evictedTokens",
            }
        )
        behavior = frozenset(
            {
                "predictionTokens",
                "controlledTop1AgreementCount",
                "controlledTop1Agreement",
                "meanKLDivergenceNat",
                "meanBaselineSelectedTokenSurprisalDeltaNat",
                "maxAbsLogitDifference",
                "perTokenKLDivergenceNat",
                "perTokenBaselineSelectedTokenSurprisalDeltaNat",
                "perTokenMaxAbsLogitDifference",
                "baselineTokenIds",
                "controlledCandidateTop1TokenIds",
                "candidateFreeRunTokenIds",
                "freeRunExact",
                "freeRunSamePositionCount",
                "freeRunLongestCommonPrefixTokens",
                "baselineContinuation",
                "candidateFreeRunContinuation",
            }
        )
        cgroup_runtime = frozenset(
            {
                "cgroupMemoryCurrentBytesAtCompletion",
                "cgroupMemoryPeakBytesAtCompletion",
                "cgroupMemoryLimitBytes",
            }
        )
        runtime = frozenset(
            {
                "startedAt",
                "completedAt",
                "python",
                "torch",
                "cuda",
                "gpuName",
                "gpuDriverVersion",
                "gpuTotalBytes",
                "gpuFreeBytesBeforeCell",
                "memoryEstimateBytes",
                "peakAllocatedBytes",
                "peakReservedBytes",
                "peakRssBytes",
                "diskFreeBytesBeforeCell",
                "diskRequiredBytes",
                "modelRequirementsLockSHA256",
                "pipBootstrapLockSHA256",
                "portableRuntimeLockSHA256",
                "cudaRuntimeLockSHA256",
                "packages",
                *cgroup_runtime,
                "dtype",
                "attentionImplementation",
                "deterministicAlgorithms",
            }
        )

        producer_dicts = _literal_dict_key_sets(PRODUCER)
        verifier_dicts = _literal_dict_key_sets(VERIFIER)
        verifier_sets = _literal_set_values(VERIFIER)
        for expected in (attempt, result, cache, behavior, record):
            self.assertIn(expected, producer_dicts)
            self.assertIn(expected, verifier_sets)
        self.assertIn(cache, verifier_dicts)  # fresh-model replay observation
        self.assertIn(behavior, verifier_dicts)  # fresh-model replay metrics
        self.assertIn(cgroup_runtime, producer_dicts)
        self.assertIn(runtime - cgroup_runtime, producer_dicts)
        self.assertIn(runtime, verifier_sets)
        runtime_literals = [
            node
            for node in ast.walk(_syntax_tree(PRODUCER))
            if isinstance(node, ast.Dict)
            and any(
                isinstance(key, ast.Constant)
                and key.value == "cudaRuntimeLockSHA256"
                for key in node.keys
                if key is not None
            )
        ]
        self.assertEqual(len(runtime_literals), 1)
        runtime_literal = runtime_literals[0]
        expansions = [
            value
            for key, value in zip(runtime_literal.keys, runtime_literal.values)
            if key is None
        ]
        self.assertEqual(len(expansions), 1)
        self.assertEqual(ast.unparse(expansions[0]), "cgroup_memory")
        run_cell_source = _function_source(PRODUCER, "run_cell")
        self.assertIn("cgroup_memory = cgroup_memory_observation()", run_cell_source)
        self.assertTrue(
            {
                "perTokenKLDivergenceNat",
                "perTokenBaselineSelectedTokenSurprisalDeltaNat",
                "perTokenMaxAbsLogitDifference",
            }.issubset(behavior)
        )

    def test_attempt_precedes_child_model_load_and_child_is_isolated(self) -> None:
        orchestrator = _function(PRODUCER, "orchestrate")
        command_assignments = [
            node
            for node in ast.walk(orchestrator)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "command" for target in node.targets)
        ]
        self.assertEqual(len(command_assignments), 1)
        command = command_assignments[0].value
        self.assertIsInstance(command, ast.List)
        assert isinstance(command, ast.List)
        self.assertEqual(ast.unparse(command.elts[0]), "python")
        self.assertEqual(
            [ast.literal_eval(element) for element in command.elts[1:4]],
            ["-E", "-s", "-B"],
        )
        self.assertEqual(ast.literal_eval(command.elts[5]), "run-cell")

        orchestrator_source = _function_source(PRODUCER, "orchestrate")
        self.assertLess(
            orchestrator_source.index('cell_root / "attempt.json"'),
            orchestrator_source.index("run_process_group("),
        )
        run_cell_source = _function_source(PRODUCER, "run_cell")
        attempt_index = run_cell_source.index(
            'attempt = strict_json_file(cell_root / "attempt.json"'
        )
        for later in (
            "load_tokenizer_and_config(",
            "configure_torch()",
            "load_model(",
        ):
            self.assertLess(attempt_index, run_cell_source.index(later), later)

        process_source = _function_source(PRODUCER, "run_process_group")
        for invariant in (
            "start_new_session=True",
            "os.killpg(process.pid, signal.SIGTERM)",
            "os.killpg(process.pid, signal.SIGKILL)",
            "require(not group_exists()",
            "signal.signal(signum, previous)",
        ):
            self.assertIn(invariant, process_source)
        self.assertLess(
            process_source.index("signal.signal(signum, interrupt_handler)"),
            process_source.index("process = subprocess.Popen("),
        )
        self.assertLess(
            process_source.index("process = subprocess.Popen("),
            process_source.index("if pending_signal:"),
        )

        import run_adapter_sweep as runner

        installed: dict[int, object] = {}
        alive = {"value": True}

        class FakeProcess:
            pid = 424242

            def poll(self) -> int | None:
                return None if alive["value"] else 0

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        def fake_signal(signum: int, handler: object) -> object:
            installed[signum] = handler
            return signal.SIG_DFL

        def fake_popen(*_args: object, **_kwargs: object) -> FakeProcess:
            handler = installed.get(signal.SIGTERM)
            self.assertTrue(callable(handler))
            assert callable(handler)
            handler(signal.SIGTERM, None)
            return FakeProcess()

        def fake_killpg(pid: int, signum: int) -> None:
            self.assertEqual(pid, FakeProcess.pid)
            if signum == 0:
                if not alive["value"]:
                    raise ProcessLookupError
                return
            self.assertEqual(signum, signal.SIGTERM)
            alive["value"] = False

        with mock.patch.object(signal, "signal", side_effect=fake_signal), \
             mock.patch.object(subprocess, "Popen", side_effect=fake_popen), \
             mock.patch.object(os, "killpg", side_effect=fake_killpg):
            with self.assertRaises(SystemExit) as interrupted:
                runner.run_process_group(
                    ["unused"],
                    stdout=None,
                    stderr=None,
                    timeout_seconds=5,
                    termination_grace_seconds=0.01,
                )
        self.assertEqual(interrupted.exception.code, 128 + signal.SIGTERM)
        self.assertFalse(alive["value"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process-group semantics required")
    def test_process_group_timeout_leaves_no_child(self) -> None:
        import run_adapter_sweep as runner

        root = self._new_private_temporary_directory("timeout-contract")
        pid_path = root / "child.pid"
        sentinel = root.name
        self._defer_process_cleanup(pid_path, sentinel)
        child = (
            "import os,pathlib,sys,time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
            "time.sleep(60)"
        )
        command = [
            sys.executable,
            "-E",
            "-s",
            "-B",
            "-c",
            child,
            str(pid_path),
            sentinel,
        ]
        with (root / "stdout.log").open("xb") as stdout, (
            root / "stderr.log"
        ).open("xb") as stderr:
            outcome = runner.run_process_group(
                command,
                stdout=stdout,
                stderr=stderr,
                timeout_seconds=1,
                termination_grace_seconds=0.15,
            )
        self.assertEqual(outcome, (124, True))
        pid = int(pid_path.read_text(encoding="ascii"))
        self._assert_pid_disappears(pid)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process-group semantics required")
    def test_completed_parent_cannot_leave_an_orphan_in_its_process_group(self) -> None:
        import run_adapter_sweep as runner

        root = self._new_private_temporary_directory("orphan-contract")
        pid_path = root / "descendant.pid"
        sentinel = root.name
        self._defer_process_cleanup(pid_path, sentinel)
        descendant = "import time; time.sleep(60)"
        parent = (
            "import pathlib,subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-E','-s','-B','-c',sys.argv[3],sys.argv[2]]); "
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')"
        )
        command = [
            sys.executable,
            "-E",
            "-s",
            "-B",
            "-c",
            parent,
            str(pid_path),
            sentinel,
            descendant,
        ]
        with (root / "stdout.log").open("xb") as stdout, (
            root / "stderr.log"
        ).open("xb") as stderr:
            outcome = runner.run_process_group(
                command,
                stdout=stdout,
                stderr=stderr,
                timeout_seconds=5,
                termination_grace_seconds=0.15,
            )
        self.assertEqual(outcome, (125, False))
        pid = int(pid_path.read_text(encoding="ascii"))
        self._assert_pid_disappears(pid)

    def test_opt_tied_storage_conversion_clones_every_sorted_tensor(self) -> None:
        import prepare_assets

        root = self._new_private_temporary_directory("opt-conversion")
        model_root = root / "opt-125m"
        model_root.mkdir(mode=0o700)
        source = model_root / "pytorch_model.bin"
        source.write_bytes(b"pinned-opt-source")
        os.chmod(source, 0o600)

        class FakeTensor:
            layout = "strided"
            dtype = "float16"
            shape = (2, 2)

            def __init__(self, value: bytes) -> None:
                self.value = value

            def detach(self) -> "FakeTensor":
                return self

            def contiguous(self) -> "FakeTensor":
                return self

            def clone(self) -> "FakeTensor":
                return FakeTensor(bytes(self.value))

        shared = FakeTensor(b"shared-tied-storage")
        state = {
            "model.decoder.embed_tokens.weight": shared,
            "lm_head.weight": shared,
        }
        fake_torch = types.ModuleType("torch")
        fake_torch.Tensor = FakeTensor
        fake_torch.strided = "strided"
        fake_torch.load = lambda *args, **kwargs: state
        fake_torch.equal = lambda left, right: left.value == right.value
        fake_safetensors = types.ModuleType("safetensors")
        fake_safetensors.__path__ = []  # type: ignore[attr-defined]
        fake_safetensors_torch = types.ModuleType("safetensors.torch")
        captured: dict[str, object] = {}

        def save_file(tensors: dict[str, FakeTensor], path: Path, *, metadata: dict[str, str]) -> None:
            captured["keys"] = list(tensors)
            captured["tensors"] = list(tensors.values())
            captured["mapping"] = dict(tensors)
            captured["metadata"] = metadata
            Path(path).write_bytes(b"fake-safetensors")

        fake_safetensors_torch.save_file = save_file
        fake_safetensors_torch.load_file = lambda *args, **kwargs: captured["mapping"]
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        profile = {
            "modelId": "opt-125m",
            "weightConversion": "torch-weights-only-to-safetensors-v1",
            "files": [
                {
                    "path": "pytorch_model.bin",
                    "bytes": source.stat().st_size,
                    "sha256": source_digest,
                }
            ],
            "weights": {"conversion": {"inputSha256": source_digest}},
        }
        with mock.patch.dict(
            os.environ,
            {
                "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
            },
            clear=True,
        ):
            with mock.patch.dict(
                sys.modules,
                {
                    "torch": fake_torch,
                    "safetensors": fake_safetensors,
                    "safetensors.torch": fake_safetensors_torch,
                },
            ):
                receipt = prepare_assets.convert_opt_weights(profile, root)

        converted = captured["tensors"]
        assert isinstance(converted, list)
        self.assertEqual(captured["keys"], sorted(state))
        self.assertEqual(len({id(tensor) for tensor in converted}), len(state))
        self.assertTrue(all(tensor is not shared for tensor in converted))
        self.assertEqual(captured["metadata"], {
            "format": "pt",
            "source_sha256": source_digest,
            "conversion": "torch-weights-only-to-safetensors-v1",
        })
        self.assertEqual(receipt["path"], "model.safetensors")
        self.assertIs(receipt["sourceTensorEqualityVerified"], True)
        self.assertEqual(
            receipt["environment"]["boundary"],
            "application-offline-single-purpose-process",
        )
        self.assertFalse((model_root / "model.safetensors.partial").exists())

        conversion_source = _function_source(PREPARER, "convert_opt_weights")
        self.assertIn("weights_only=True", conversion_source)
        self.assertIn("for key in sorted(state)", conversion_source)
        self.assertIn("value.detach().contiguous().clone()", conversion_source)

    def test_distilgpt2_strict_load_restores_and_proves_weight_tying(self) -> None:
        profile = next(
            item
            for item in common.load_profiles()["profiles"]
            if item["modelId"] == "distilgpt2"
        )
        self.assertEqual(profile["modelType"], "gpt2")
        self.assertIs(profile["weights"]["disableMmap"], True)
        for path, function_name in (
            (PRODUCER, "load_model"),
            (VERIFIER, "_load_model_and_tokenizer"),
        ):
            source = _function_source(path, function_name)
            markers = (
                'state["lm_head.weight"] = state["transformer.wte.weight"]',
                "model.load_state_dict(state, strict=True, assign=False)",
                "model.tie_weights()",
                "model.get_input_embeddings().weight.data_ptr()",
                "model.get_output_embeddings().weight.data_ptr()",
            )
            positions = [source.index(marker) for marker in markers]
            self.assertEqual(positions, sorted(positions), function_name)
            self.assertIn('"lm_head.weight" not in state', source)

        import verify_adapter_sweep as verifier

        cache = self._new_private_temporary_directory("converted-receipt")
        snapshot = cache / "opt-fixture"
        snapshot.mkdir(mode=0o700)
        source = snapshot / "pytorch_model.bin"
        source.write_bytes(b"pinned-source")
        converted = snapshot / "model.safetensors"
        converted.write_bytes(b"converted-weight-bytes")
        os.chmod(source, 0o600)
        os.chmod(converted, 0o600)
        fixture_profile = {
            "modelId": "opt-fixture",
            "files": [
                {
                    "path": source.name,
                    "bytes": source.stat().st_size,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ],
            "weightConversion": "torch-weights-only-to-safetensors-v1",
        }
        stale_receipt = {
            "bytes": converted.stat().st_size,
            "sha256": "0" * 64,
        }
        with self.assertRaisesRegex(
            common.ContractError, "differs from the bound asset receipt"
        ):
            verifier._asset_snapshot(cache, fixture_profile, stale_receipt)

    def test_cuda_runtime_lock_and_atomic_clean_build_are_frozen(self) -> None:
        lock = CUDA_LOCK.read_bytes()
        self.assertEqual(
            hashlib.sha256(lock).hexdigest(),
            "17a32aaa2f2ed1c7a730b08ae6109a00dae0a726804e536e5b0e6f4bc6356ca2",
        )
        lock_text = lock.decode("utf-8")
        self.assertEqual(lock_text.count("torch=="), 1)
        self.assertEqual(
            len(re.findall(r"(?m)^[A-Za-z0-9_.-]+==", lock_text)),
            20,
        )
        self.assertIn("torch==2.13.0+cu130", lock_text)
        for dependency in (
            "cuda-bindings==13.0.3",
            "cuda-toolkit==13.0.3.0",
            "nvidia-cudnn-cu13==9.20.0.48",
            "nvidia-nccl-cu13==2.29.7",
            "triton==3.7.1",
        ):
            self.assertIn(dependency, lock_text)
        self.assertIn(
            "sha256:8db7338e6895c3d4bd89a02ff4209507d1f0cf2ffeb3b898538b5a07d1ea8c1e",
            lock_text,
        )

        build = CUDA_BUILDER.read_text(encoding="utf-8")
        self.assertEqual(build.count("--require-hashes"), 3)
        self.assertIn("--extra-index-url https://pypi.org/simple", build)
        self.assertIn("exec /usr/bin/env -i", build)
        self.assertIn("/bin/sh \"$0\" --corelm-sanitized", build)
        self.assertIn("${HF_TOKEN+x}${HUGGING_FACE_HUB_TOKEN+x}${RUNPOD_API_KEY+x}", build)
        self.assertIn("sanitized environment contains an unregistered name", build)
        self.assertEqual(build.count("core.fsmonitor=false"), 1)
        self.assertEqual(build.count('verify_exact_checkout "$SWEEP_ROOT"'), 2)
        self.assertEqual(build.count('verify_exact_checkout "$CODEC_ROOT"'), 2)
        self.assertIn("--format='%(objectmode) %(objecttype) %(objectname)'", build)
        self.assertIn("hash-object --no-filters", build)
        self.assertIn("PUBLISHED_DIR=$RUNTIME_DIR", build)
        self.assertIn("BUILD_COMPLETE=1", build)
        for expected in (
            'checkout_label checkout is not byte-clean',
            "runtime destination must not already exist",
            'trap cleanup EXIT',
            '"$RUNTIME_PARENT"/.corelm-cuda-runtime-stage.*',
            'publish-runtime \\\n    --staging "$STAGING_DIR" \\\n    --destination "$RUNTIME_DIR"',
        ):
            self.assertIn(expected, build)

        stage = build.index('STAGING_DIR=$(mktemp -d')
        install = build.index('"$runtime_python" -I -B -m pip install', stage)
        locked_install = build.index('-r "$SCRIPT_DIR/torch-linux-cu130-py312.txt"', install)
        prepublish_verify = build.index('"$runtime_python" -I -B "$VERIFY_LOCKS"', locked_install)
        identity_check = build.index('"$runtime_python" -I -B - <<\'PY\'', prepublish_verify)
        publish = build.index('"$BASE_PYTHON" -I -B "$SAFETY_SCRIPT" publish-runtime', identity_check)
        clear_staging = build.index("STAGING_DIR=", publish)
        published_validate = build.index('validate-runtime \\\n    --runtime "$RUNTIME_DIR"', clear_staging)
        published_verify = build.index('"$runtime_python" -I -B "$VERIFY_LOCKS"', published_validate)
        self.assertEqual(
            [stage, install, locked_install, prepublish_verify, identity_check, publish, clear_staging, published_validate, published_verify],
            sorted([stage, install, locked_install, prepublish_verify, identity_check, publish, clear_staging, published_validate, published_verify]),
        )
        self.assertLess(build.index('trap cleanup EXIT'), stage)
        self.assertLess(build.index("runtime destination must not already exist"), stage)

        expected_packages = {
            "huggingface-hub": "1.25.1",
            "numpy": "2.5.1",
            "safetensors": "0.8.0",
            "tokenizers": "0.22.2",
            "torch": "2.13.0+cu130",
            "transformers": "5.14.1",
        }
        wrapper = WRAPPER.read_text(encoding="utf-8")
        entry = ENTRY.read_text(encoding="utf-8")
        self.assertIn('os.execve(', entry)
        self.assertIn('["/bin/bash", str(script), "--corelm-clean-entry"]', entry)
        self.assertIn('if not sys.flags.ignore_environment', entry)
        self.assertNotIn('BASH_FUNC_', entry)
        self.assertIn('if [[ "$#" -ne 1 || "$1" != --corelm-clean-entry ]]', wrapper)
        self.assertIn('compgen -A function', wrapper)
        self.assertIn("-c gpg.ssh.program=/usr/bin/ssh-keygen", wrapper)
        self.assertIn('unset HF_TOKEN', wrapper)
        self.assertIn('builtin printf \'%s\' "$hf_token" |', wrapper)
        scanner = TOKEN_SCANNER.read_text(encoding="utf-8")
        self.assertIn('sys.stdin.buffer.read(', scanner)
        self.assertNotIn('os.environ', scanner)
        for source_path in (ROOT / "common.py", PRODUCER, VERIFIER):
            self.assertIn("core.fsmonitor=false", source_path.read_text(encoding="utf-8"))
        for package, version in expected_packages.items():
            marker = f'"{package}": "{version}"'
            self.assertIn(marker, build)
            self.assertIn(marker, wrapper)

    def test_runpod_wrapper_cli_timeouts_digest_replays_and_package_are_exact(self) -> None:
        wrapper = WRAPPER.read_text(encoding="utf-8")
        runbook = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("image_digest=${CORELM_SWEEP_IMAGE_DIGEST-}", wrapper)
        self.assertIn('[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]', wrapper)
        self.assertIn("containerImageDigest=$image_digest", wrapper)
        self.assertIn("verify-commit \"$commit\"", wrapper)
        self.assertIn(
            "36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16",
            wrapper,
        )
        self.assertIn(
            "containerImageDigestAuthority=operator-supplied-control-plane-value",
            wrapper,
        )
        self.assertEqual(wrapper.count('"$python_executable" -E -s -B'), 14)
        self.assertIn("gpuDriverVersion=$gpu_driver_version", wrapper)
        self.assertIn("cgroupVersion=$cgroup_version", wrapper)
        self.assertIn('"$script_dir/cgroup_contract.py" admission', wrapper)
        self.assertIn("--minimum-cpu-cores 16", wrapper)
        self.assertIn("--minimum-memory-bytes 118111600640", wrapper)
        self.assertNotIn("/sys/fs/cgroup/cpu.max", wrapper)
        self.assertNotIn("/sys/fs/cgroup/memory.max", wrapper)
        self.assertLess(
            wrapper.index('assert_exact_checkout "$sweep_repo"'),
            wrapper.index('"$script_dir/cgroup_contract.py" admission'),
        )
        self.assertIn("/proc/self/cgroup", CGROUP_CONTRACT.read_text(encoding="utf-8"))
        self.assertIn("/proc/self/mountinfo", CGROUP_CONTRACT.read_text(encoding="utf-8"))
        self.assertIn("pipBootstrapLockSHA256=", wrapper)
        self.assertIn("portableRuntimeLockSHA256=", wrapper)
        checksum_grammar = (
            'rb"[0-9a-f]{64}  corelm-runpod-adapter-sweep-v1'
            '[.]tar[.]gz\\n"'
        )
        self.assertIn(checksum_grammar, runbook)
        self.assertIn("LOCAL_EVIDENCE_DIR=$(mktemp -d", runbook)
        self.assertIn("status.st_nlink != 1", runbook)
        self.assertIn("root_status.st_mode & 0o077", runbook)
        self.assertLess(
            runbook.index(checksum_grammar),
            runbook.index("sha256sum -c SHA256SUMS"),
        )
        self.assertEqual(len(re.findall(r"^\s+--assets ", wrapper, re.MULTILINE)), 4)
        self.assertEqual(len(re.findall(r"^\s+--output ", wrapper, re.MULTILINE)), 3)
        self.assertEqual(len(re.findall(r"^\s+--run-dir ", wrapper, re.MULTILINE)), 3)
        for pattern in (
            r"run_timed ASSET_DOWNLOAD 3600",
            r"run_timed OPT_CONVERSION 900",
            r"run_timed ASSET_VERIFY 900",
            r"run_timed SWEEP_PREFLIGHT 900",
            r"run_timed SWEEP_ORCHESTRATE 41400",
            r"run_timed SWEEP_VERIFY 900",
            r'run_timed "REPLAY_\$\{replay_model\}" "\$replay_timeout"',
            r"--cell-timeout-seconds 2700",
            r"timeout --foreground --signal=TERM --kill-after=60s",
            r"CORELM_SWEEP_TEST_CODEC_ROOT=\"\$codec_root\"",
            r"-m unittest discover",
        ):
            self.assertRegex(wrapper, pattern)

        replay_match = re.search(r"replay_pairs=\(\n(?P<body>.*?)\n\)", wrapper, re.DOTALL)
        self.assertIsNotNone(replay_match)
        assert replay_match is not None
        replay_pairs = re.findall(r"'([^']+)'", replay_match.group("body"))
        self.assertEqual(
            replay_pairs,
            [
                "qwen2.5-0.5b:tracked-legal-protocol-v1:1350",
                "smollm2-135m:tracked-source-code-v1:900",
                "mistral-7b-v0.1:tracked-structured-json-v1:2700",
                "pythia-14m:tracked-technical-prose-v1:900",
                "distilgpt2:tracked-legal-protocol-v1:900",
                "opt-125m:tracked-source-code-v1:900",
                "gemma-2b:tracked-structured-json-v1:1800",
            ],
        )
        self.assertEqual(
            [pair.split(":", 1)[0] for pair in replay_pairs],
            list(common.MODEL_ORDER),
        )
        for packaging_marker in (
            "--sort=name",
            "--mtime='UTC 1970-01-01'",
            "--owner=0",
            "--group=0",
            "gzip -n",
            "sha256sum -c SHA256SUMS",
        ):
            self.assertIn(packaging_marker, wrapper)

        verifier_replay = _function_source(VERIFIER, "replay_cell")
        for invariant in (
            'replay_cache_observation == result["cacheObservation"]',
            '_cache_digest(raw_layers) == result["canonicalCacheBF16SHA256"]',
            'result["structuralReplay"]',
            '_compare_behavior(observed_behavior, result["behavior"])',
        ):
            self.assertIn(invariant, verifier_replay)

    def test_cli_help_has_only_fixed_subcommands(self) -> None:
        for script, commands in (
            ("prepare_assets.py", ("download", "convert", "verify")),
            ("run_adapter_sweep.py", ("preflight", "orchestrate", "run-cell")),
            ("verify_adapter_sweep.py", ("verify-run", "replay-cell")),
        ):
            completed = subprocess.run(
                [sys.executable, str(ROOT / script), "--help"],
                cwd=LAB,
                text=True,
                capture_output=True,
                check=False,
                env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for command in commands:
                self.assertIn(command, completed.stdout)

        command_flags = {
            ("prepare_assets.py", "download"): {"--cache", "--receipt"},
            ("prepare_assets.py", "convert"): {"--cache", "--receipt"},
            ("prepare_assets.py", "verify"): {"--cache", "--receipt", "--conversion-receipt"},
            ("run_adapter_sweep.py", "preflight"): {
                "--codec-root",
                "--cache",
                "--assets",
                "--output",
            },
            ("run_adapter_sweep.py", "orchestrate"): {
                "--codec-root",
                "--cache",
                "--assets",
                "--preflight",
                "--run-dir",
                "--cell-timeout-seconds",
            },
            ("run_adapter_sweep.py", "run-cell"): {
                "--codec-root",
                "--cache",
                "--assets",
                "--preflight",
                "--run-dir",
                "--model-id",
                "--workload-id",
            },
            ("verify_adapter_sweep.py", "verify-run"): {
                "--codec-root",
                "--cache",
                "--assets",
                "--preflight",
                "--run-dir",
                "--output",
            },
            ("verify_adapter_sweep.py", "replay-cell"): {
                "--codec-root",
                "--cache",
                "--assets",
                "--preflight",
                "--run-dir",
                "--structural",
                "--model-id",
                "--workload-id",
                "--output",
            },
        }
        for (script, command), flags in command_flags.items():
            completed = subprocess.run(
                [sys.executable, str(ROOT / script), command, "--help"],
                cwd=LAB,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
                env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for flag in flags:
                self.assertIn(flag, completed.stdout, f"{script} {command}")

        replay_context = _function_source(VERIFIER, "_selected_replay_context")
        for binding in (
            '"preflightSHA256": preflight_digest',
            '"assetReceiptSHA256": asset_receipt_digest',
            '"runSHA256": run_digest',
            '"structuralVerificationSHA256": structural_digest',
        ):
            self.assertIn(binding, replay_context)
        sidecar = _function_source(VERIFIER, "_verify_sidecar")
        self.assertLess(
            sidecar.index("require_regular(path"),
            sidecar.index("sha256_file(path)"),
        )


if __name__ == "__main__":
    unittest.main()
