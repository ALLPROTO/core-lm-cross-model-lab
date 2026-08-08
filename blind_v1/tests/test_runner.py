from __future__ import annotations

import copy
import inspect
import os
import platform
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from datetime import datetime, timedelta
from pathlib import Path

import blind_v1.runner as runner_module
from blind_v1.protocol import canonical_json_bytes, load_json_strict, sha256_bytes
from blind_v1.reproducibility import digest_regular_file, with_content_digest
from blind_v1.runner import (
    ATTEMPT_ID,
    HARD_DEADLINE,
    MARKER_DEADLINE,
    ONE_SHOT_NOT_BEFORE,
    PRIVATE_ROLES,
    PRIVATE_SCHEMA,
    NETWORK_DENY_PROFILE,
    SCIENTIFIC_HASH_KNOWN_ANSWER,
    SCIENTIFIC_PYTHON_FLAGS,
    RunnerError,
    _networkless_macos_command,
    _process_group_usage,
    _require_publication_source,
    _scientific_python_command,
    _require_design_publication_source,
    _supervise_worker,
    _worker_job,
    ensure_one_shot_window,
    require_reserved_attempt_id,
    scientific_tokenizer_vocabulary_sizes,
    scientific_subprocess_environment,
    scientific_result,
    validate_frozen_design,
    verify_external_attempt_time_anchor,
    verify_private_snapshot,
    verify_runtime_live,
    verify_registered_ci_workflow_bytes,
    verify_scientific_runtime_imports_subprocess,
    verify_scientific_python_subprocess,
)


BLIND_V1_ROOT = Path(__file__).resolve().parents[1]


def frozen_design() -> dict[str, object]:
    value = copy.deepcopy(load_json_strict(BLIND_V1_ROOT / "design-registration.draft.json"))
    value["schemaVersion"] = "corelm-blind-crossmodel-v1-design-v1"
    value["status"] = "PUBLIC_DESIGN_FROZEN"
    value["readyToFreeze"] = True
    value["freezeBlockers"] = []
    value["labSource"].update(
        status="FROZEN_BOUND",
        commit="1" * 40,
        tree="2" * 40,
        freezeManifestSHA256="3" * 64,
    )
    value["runtime"].update(
        status="FROZEN_BOUND", runtimeManifestSHA256="4" * 64
    )
    value["developmentControls"]["realDataE2EFreezeGate"].update(
        status="ARCHIVED_VERIFIED_BEFORE_FREEZE",
        executionId="development-execution-20260814T100000Z-0123456789abcdef",
        archiveReceiptSHA256="7" * 64,
        archivePublishedAt="2026-08-08T10:05:00Z",
        archiveAttestedAt="2026-08-08T10:05:01Z",
        releaseAttestationBundleSHA256="b" * 64,
        releaseAttestationOutputSHA256="c" * 64,
        reportSHA256="8" * 64,
        artifactSetSHA256="9" * 64,
        controlConfigurationSHA256="a" * 64,
        completedAt="2026-08-08T10:00:00Z",
    )
    value["beacon"].update(
        trustBundleStatus="FROZEN_OFFLINE_TRUST_BUNDLE",
        transportCABundleSHA256="5" * 64,
        offlineTrustBundleSHA256=value["beacon"][
            "frozenOfflineTrustBundleSHA256"
        ],
    )
    return value


class RunnerContractTests(unittest.TestCase):
    def test_prepare_cli_requires_cosign_and_all_development_control_roots(self) -> None:
        options = (
            "design",
            "snapshot-registration",
            "corpus-root",
            "asset-manifest",
            "asset-receipt",
            "asset-root",
            "runtime-manifest",
            "runtime-root",
            "freeze-manifest",
            "github-gate-receipt",
            "development-control-report",
            "development-control-artifact-root",
            "development-control-archive-receipt",
            "development-control-archive-assets",
            "sbom",
            "design-sha256-manifest",
            "design-publication-receipt",
            "design-release-assets",
            "snapshot-publication-receipt",
            "snapshot-release-assets",
            "reservation-publication-receipt",
            "reservation-release-assets",
            "signing-public-key",
            "nist-trust-manifest",
            "ca-bundle",
            "cosign",
            "codec-root",
            "destination",
        )
        argv = ["runner.py", "prepare"]
        for option in options:
            argv.extend((f"--{option}", option))
        with mock.patch.object(sys, "argv", argv):
            arguments = runner_module.parse_arguments()
        self.assertEqual(arguments.cosign, Path("cosign"))
        self.assertEqual(
            arguments.development_control_archive_assets,
            Path("development-control-archive-assets"),
        )
        for required in (
            "cosign",
            "development-control-artifact-root",
            "development-control-archive-assets",
            "reservation-publication-receipt",
            "reservation-release-assets",
        ):
            index = argv.index(f"--{required}")
            incomplete = argv[:index] + argv[index + 2 :]
            with self.subTest(required=required), mock.patch.object(
                sys, "argv", incomplete
            ), mock.patch("sys.stderr"), self.assertRaises(SystemExit):
                runner_module.parse_arguments()

    def test_success_path_calls_registered_phases_once_in_exact_order(self) -> None:
        inner = inspect.getsource(runner_module._historical_execute_private_one_shot)
        outer = inspect.getsource(runner_module.reexec_private_one_shot)
        self.assertEqual(inner.count("verify_scientific_python_subprocess("), 1)
        self.assertNotIn("verify_scientific_python_subprocess(", outer)
        ordered_boundaries = [
            "verify_private_snapshot(private_root)",
            "verify_scientific_python_subprocess(sys.executable, scientific_environment)",
            "marker = create_attempt_marker(",
            "response = fetch_exact_pulse_with_total_timeout(",
            "install_trusted_supervisor_socket_denial()",
            "selection = resolve_selection(",
            "_run_workers(",
            "_consolidate_worker_evidence(",
            'write_new_bytes(result_root / "result.json", result_raw)',
            "evidence_manifest = build_sha256_manifest(",
            "verifier_supervisor_receipt = _supervise_worker(",
            'verifier_report.get("producerResultExactMatch")',
            "create_terminal_outcome(",
        ]
        positions = [inner.index(boundary) for boundary in ordered_boundaries]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(
            frozen_design()["oneShotStateMachine"]["phaseOrder"],
            [
                "verify-public-execution-reservation-receipt",
                "preflight-seal-assets",
                "pre-marker-networkless-locked-runtime-import-probe",
                "durable-attempt-reservation",
                "durable-attempt-marker",
                "supervisor-fetch-and-verify-exact-nist-pulse",
                "seal-pulse-and-install-scoped-supervisor-socket-denial",
                "derive-selection",
                "spawn-networkless-inference-workers-in-registered-order",
                "consolidate-worker-evidence",
                "publish-producer-result",
                "publish-producer-evidence-manifest",
                "spawn-networkless-independent-verifier",
                "require-independent-real-model-replay-and-exact-result-match",
                "publish-terminal-outcome",
            ],
        )

    def test_private_and_worker_publication_use_atomic_no_replace(self) -> None:
        prepare_source = inspect.getsource(
            runner_module._historical_prepare_private_snapshot
        )
        consolidate_source = inspect.getsource(
            runner_module._consolidate_worker_evidence
        )
        self.assertIn(
            "publish_new_path_exclusive(temporary, destination)", prepare_source
        )
        self.assertIn(
            "publish_new_path_exclusive(source, destination)", consolidate_source
        )
        self.assertNotIn("os.replace(", prepare_source)
        self.assertNotIn("os.replace(", consolidate_source)

    def test_private_execution_accepts_live_parent_bound_pipe_handoff(self) -> None:
        private_root = Path("/private/frozen-snapshot")
        result_root = Path("/private/frozen-snapshot.one-shot-result")
        read_descriptor, write_descriptor = os.pipe()
        raw = runner_module._outer_supervision_authorization_bytes(
            private_root=private_root,
            result_root=result_root,
            outer_pid=111,
            child_pid=222,
            nonce="a" * 64,
        )
        os.write(write_descriptor, raw)
        os.close(write_descriptor)
        with (
            mock.patch.object(runner_module.os, "getpid", return_value=222),
            mock.patch.object(runner_module.os, "getppid", return_value=111),
            mock.patch.object(runner_module.os, "getpgrp", return_value=222),
        ):
            authorization = runner_module._read_outer_supervision_authorization(
                read_descriptor,
                private_root=private_root,
                result_root=result_root,
            )
        self.assertEqual(authorization["status"], "OUTER_SUPERVISION_AUTHORIZED")
        self.assertEqual(authorization["processGroupId"], 222)

        with tempfile.TemporaryFile() as ordinary_file:
            duplicate = os.dup(ordinary_file.fileno())
            with self.assertRaisesRegex(RunnerError, "is not a pipe"):
                runner_module._read_outer_supervision_authorization(
                    duplicate,
                    private_root=private_root,
                    result_root=result_root,
                )

    def test_hidden_private_cli_without_inherited_handoff_is_rejected(self) -> None:
        arguments = SimpleNamespace(
            command="run-one-shot",
            confirm_scientific_one_shot=runner_module.SUITE_ID,
            private_execution=True,
            outer_authorization_fd=None,
            private_root=Path("/private/frozen-snapshot"),
            result_root=Path("/private/frozen-snapshot.one-shot-result"),
        )
        with (
            mock.patch.object(runner_module, "parse_arguments", return_value=arguments),
            mock.patch.object(runner_module, "execute_private_one_shot") as execute,
            mock.patch("sys.stderr"),
        ):
            self.assertEqual(runner_module.main(), 1)
        execute.assert_not_called()

        spawn_source = inspect.getsource(
            runner_module._spawn_authorized_private_execution
        )
        self.assertIn("start_new_session=True", spawn_source)
        self.assertIn("pass_fds=(authorization_fd,)", spawn_source)
        self.assertIn("child_pid=process.pid", spawn_source)

    def test_pipe_handoff_does_not_claim_parent_implementation_identity(self) -> None:
        execution = frozen_design()["execution"]
        self.assertNotIn("privateChildAuthorization", execution)
        self.assertIn("privateChildHandoff", execution)
        self.assertIn(
            "custom-same-user-parent-can-reproduce-it",
            execution["outerSupervisorIdentityClaim"],
        )
        protocol_text = (BLIND_V1_ROOT / "PROTOCOL.md").read_text()
        runbook_text = (BLIND_V1_ROOT / "REPRODUCIBILITY.md").read_text()
        for text in (protocol_text, runbook_text):
            normalized = " ".join(text.replace("-", " ").split())
            self.assertIn(
                "does not authenticate the parent implementation", normalized
            )
            self.assertIn("custom", normalized)
            self.assertIn("same user", normalized)

    def test_private_execution_uses_only_the_sealed_v4_lab_tree(self) -> None:
        source = "\n".join(
            (
                inspect.getsource(runner_module._run_workers),
                inspect.getsource(runner_module._historical_execute_private_one_shot),
                inspect.getsource(runner_module.reexec_private_one_shot),
            )
        )
        self.assertNotIn('"v2"', source)
        for script in ("model_worker.py", "runner.py", "verify_evidence.py"):
            self.assertIn(f'"blind_v1" / "{script}"', source)

    def test_registered_ci_workflow_bytes_are_reopened_exactly(self) -> None:
        design = frozen_design()
        workflow = (BLIND_V1_ROOT.parent / design["continuousIntegration"]["workflowPath"]).read_bytes()
        verify_registered_ci_workflow_bytes(design, workflow)
        with self.assertRaisesRegex(RunnerError, "workflow bytes differ"):
            verify_registered_ci_workflow_bytes(design, workflow + b"\n")

    def test_design_release_cannot_introduce_a_second_source_identity(self) -> None:
        design = frozen_design()
        publication = SimpleNamespace(
            source_commit=design["labSource"]["commit"],
            source_tree=design["labSource"]["tree"],
        )
        _require_design_publication_source(publication, design)
        publication.source_tree = "f" * 40
        with self.assertRaisesRegex(RunnerError, "frozen lab commit/tree"):
            _require_design_publication_source(publication, design)

        publication.source_tree = design["labSource"]["tree"]
        _require_publication_source(publication, design, kind="snapshot")
        publication.source_commit = "f" * 40
        with self.assertRaisesRegex(RunnerError, "snapshot publication tag"):
            _require_publication_source(publication, design, kind="snapshot")

    def test_scientific_child_environment_is_closed_and_secret_free(self) -> None:
        environment = scientific_subprocess_environment(frozen_design()["execution"])
        self.assertEqual(environment["OMP_NUM_THREADS"], "2")
        self.assertEqual(environment["VECLIB_MAXIMUM_THREADS"], "2")
        self.assertEqual(environment["HF_HUB_OFFLINE"], "1")
        self.assertEqual(environment["NO_PROXY"], "*")
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertNotIn("HOME", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)

    def test_scientific_python_probe_proves_seed_and_safe_startup(self) -> None:
        environment = scientific_subprocess_environment(frozen_design()["execution"])
        observed = verify_scientific_python_subprocess(sys.executable, environment)
        command = _scientific_python_command(sys.executable, "worker.py")
        self.assertEqual(SCIENTIFIC_PYTHON_FLAGS, ("-P", "-s", "-B"))
        self.assertNotIn("-I", command)
        self.assertEqual(command[0], os.path.abspath(sys.executable))
        self.assertEqual(Path(command[0]).parent, Path(sys.prefix) / "bin")
        self.assertEqual(observed["hashValue"], SCIENTIFIC_HASH_KNOWN_ANSWER)
        self.assertEqual(observed["hashRandomization"], 0)
        self.assertEqual(observed["ignoreEnvironment"], 0)
        self.assertTrue(observed["safePath"])
        imported = verify_scientific_runtime_imports_subprocess(
            sys.executable, environment
        )
        self.assertTrue(imported["venvActive"])
        self.assertEqual(imported["prefix"], os.path.abspath(sys.prefix))
        self.assertEqual(imported["executable"], os.path.abspath(sys.executable))
        self.assertEqual(
            set(imported["versions"]),
            {
                "jsonschema",
                "numpy",
                "pyarrow",
                "safetensors",
                "tokenizers",
                "torch",
                "transformers",
            },
        )
        resolved_base = Path(sys.executable).resolve(strict=True)
        if resolved_base != Path(os.path.abspath(sys.executable)):
            with self.assertRaisesRegex(RunnerError, "active locked runtime"):
                _scientific_python_command(resolved_base, "worker.py")
            bad_launcher = str(resolved_base)

            def resolved_command(_executable, *arguments):
                return [bad_launcher, *SCIENTIFIC_PYTHON_FLAGS, *arguments]

            with (
                mock.patch(
                    "blind_v1.runner._scientific_python_command",
                    side_effect=resolved_command,
                ),
                self.assertRaisesRegex(
                    RunnerError, "runtime dependency imports failed"
                ),
            ):
                verify_scientific_python_subprocess(sys.executable, environment)
        with self.assertRaisesRegex(RunnerError, "absolute path"):
            _scientific_python_command(Path("bin/python"), "worker.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_parent = root / "real-parent"
            runtime = real_parent / "runtime"
            (runtime / "bin").mkdir(parents=True)
            (runtime / "bin" / "python").symlink_to(resolved_base)
            alias = root / "parent-alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            aliased_runtime = alias / "runtime"
            aliased_launcher = aliased_runtime / "bin" / "python"
            with (
                mock.patch.object(sys, "executable", str(aliased_launcher)),
                mock.patch.object(sys, "prefix", str(aliased_runtime)),
                self.assertRaisesRegex(RunnerError, "symlink/non-directory parent"),
            ):
                _scientific_python_command(aliased_launcher, "worker.py")
        mutated = dict(environment)
        mutated["PYTHONHASHSEED"] = "1"
        with self.assertRaisesRegex(RunnerError, "PYTHONHASHSEED"):
            verify_scientific_python_subprocess(sys.executable, mutated)
        with (
            mock.patch("blind_v1.runner.SCIENTIFIC_PYTHON_FLAGS", ("-I", "-B")),
            self.assertRaisesRegex(RunnerError, "known-answer differs"),
        ):
            verify_scientific_python_subprocess(sys.executable, environment)

    def test_runtime_live_recomputes_runtime_and_base_python_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "runtime"
            base_root = root / "base-python"
            runtime_root.mkdir()
            base_root.mkdir()
            runtime_root = runtime_root.resolve(strict=True)
            base_root = base_root.resolve(strict=True)
            runtime_tree = {
                "entries": [],
                "entryCount": 11,
                "regularFileBytes": 101,
                "treeSHA256": "1" * 64,
            }
            base_tree = {
                "entries": [],
                "entryCount": 7,
                "regularFileBytes": 71,
                "treeSHA256": "2" * 64,
            }
            manifest = with_content_digest(
                {
                    "schemaVersion": "corelm-blind-crossmodel-v1-runtime-manifest-v1",
                    "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
                    "host": {"system": "Darwin", "machine": "arm64"},
                    "runtimeTree": runtime_tree,
                    "basePythonTree": base_tree,
                    "basePythonDistinctFromRuntime": True,
                    "python": {
                        "executable": digest_regular_file(
                            Path(sys.executable).resolve(strict=True)
                        )
                    },
                }
            )
            with (
                mock.patch.object(sys, "prefix", str(runtime_root)),
                mock.patch.object(sys, "base_prefix", str(base_root)),
                mock.patch("blind_v1.runner.platform.system", return_value="Darwin"),
                mock.patch("blind_v1.runner.platform.machine", return_value="arm64"),
                mock.patch(
                    "blind_v1.runner.scan_tree", side_effect=[runtime_tree, base_tree]
                ) as scanner,
            ):
                verify_runtime_live(manifest, runtime_root)
            scanner.assert_any_call(base_root)
            self.assertEqual(scanner.call_count, 2)

    def test_runtime_live_rejects_base_python_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "runtime"
            base_root = root / "base-python"
            runtime_root.mkdir()
            base_root.mkdir()
            runtime_root = runtime_root.resolve(strict=True)
            base_root = base_root.resolve(strict=True)
            runtime_tree = {
                "entries": [], "entryCount": 1, "regularFileBytes": 1,
                "treeSHA256": "1" * 64,
            }
            base_tree = {
                "entries": [], "entryCount": 1, "regularFileBytes": 1,
                "treeSHA256": "2" * 64,
            }
            tampered_base_tree = {**base_tree, "treeSHA256": "3" * 64}
            manifest = with_content_digest(
                {
                    "schemaVersion": "corelm-blind-crossmodel-v1-runtime-manifest-v1",
                    "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
                    "host": {"system": "Darwin", "machine": "arm64"},
                    "runtimeTree": runtime_tree,
                    "basePythonTree": base_tree,
                    "basePythonDistinctFromRuntime": True,
                    "python": {
                        "executable": digest_regular_file(
                            Path(sys.executable).resolve(strict=True)
                        )
                    },
                }
            )
            with (
                mock.patch.object(sys, "prefix", str(runtime_root)),
                mock.patch.object(sys, "base_prefix", str(base_root)),
                mock.patch("blind_v1.runner.platform.system", return_value="Darwin"),
                mock.patch("blind_v1.runner.platform.machine", return_value="arm64"),
                mock.patch(
                    "blind_v1.runner.scan_tree",
                    side_effect=[runtime_tree, tampered_base_tree],
                ),
                self.assertRaisesRegex(RunnerError, "base Python tree differs"),
            ):
                verify_runtime_live(manifest, runtime_root)

    def test_runtime_live_rejects_non_primary_manifest_and_live_hosts(self) -> None:
        runtime_tree = {
            "entries": [], "entryCount": 1, "regularFileBytes": 1,
            "treeSHA256": "1" * 64,
        }

        def manifest_for(system: str, machine: str) -> dict[str, object]:
            return with_content_digest(
                {
                    "schemaVersion": "corelm-blind-crossmodel-v1-runtime-manifest-v1",
                    "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
                    "host": {"system": system, "machine": machine},
                    "runtimeTree": runtime_tree,
                    "basePythonTree": runtime_tree,
                    "basePythonDistinctFromRuntime": False,
                    "python": {"executable": {"bytes": 1, "sha256": "2" * 64}},
                }
            )

        with self.assertRaisesRegex(RunnerError, "manifest host"):
            verify_runtime_live(manifest_for("Linux", "x86_64"), Path(sys.prefix))
        with (
            mock.patch("blind_v1.runner.platform.system", return_value="Linux"),
            mock.patch("blind_v1.runner.platform.machine", return_value="x86_64"),
            self.assertRaisesRegex(RunnerError, "active runtime host"),
        ):
            verify_runtime_live(manifest_for("Darwin", "arm64"), Path(sys.prefix))

    def test_networkless_child_is_sandboxed_before_python_startup(self) -> None:
        command = [
            *_scientific_python_command(sys.executable),
            "-c",
            "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0))",
        ]
        if platform.system() == "Darwin" and platform.machine() == "arm64":
            import_probe = _networkless_macos_command(
                _scientific_python_command(
                    sys.executable,
                    "-c",
                    "import numpy,torch,tokenizers,transformers; print('LOCKED_IMPORTS_OK')",
                )
            )
            import_result = subprocess.run(
                import_probe,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=scientific_subprocess_environment(frozen_design()["execution"]),
            )
            self.assertEqual(import_result.returncode, 0, import_result.stderr)
            self.assertEqual(import_result.stdout, b"LOCKED_IMPORTS_OK\n")
            self.assertEqual(import_result.stderr, b"")
            wrapped = _networkless_macos_command(command)
            self.assertEqual(wrapped[:3], [
                "/usr/bin/sandbox-exec",
                "-p",
                NETWORK_DENY_PROFILE,
            ])
            completed = subprocess.run(
                wrapped,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"Operation not permitted", completed.stderr)
        else:
            with self.assertRaises(RunnerError):
                _networkless_macos_command(command)

    def test_supervisor_socket_guard_is_explicitly_not_child_capability_isolation(self) -> None:
        script = r'''from blind_v1.runner import RunnerError, install_trusted_supervisor_socket_denial
import socket
import subprocess
import sys
install_trusted_supervisor_socket_denial()
try:
    socket.socket()
except RunnerError:
    pass
else:
    raise SystemExit("parent socket was not denied")
child = subprocess.run(
    [sys.executable, "-c", "import socket; socket.socket(); print('child-socket-created')"],
    check=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
if child.returncode != 0 or child.stdout.strip() != "child-socket-created":
    raise SystemExit("scoped-boundary probe differed")
print("SCOPED_GUARD_CONFIRMED")
'''
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[2],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "SCOPED_GUARD_CONFIRMED")

    def test_watchdog_aggregates_descendants_and_kills_the_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "processes.txt"
            child_program = "import time; payload=bytearray(200*1024*1024); time.sleep(10)"
            root_program = (
                "import os,pathlib,subprocess,sys,time;"
                f"child=subprocess.Popen([sys.executable,'-c',{child_program!r}]);"
                f"pathlib.Path({str(identity)!r}).write_text(f'{{os.getpid()}} {{child.pid}}');"
                "time.sleep(10)"
            )
            log_path = root / "worker.log"
            started = time.monotonic()
            with log_path.open("wb") as log:
                with self.assertRaisesRegex(RunnerError, "RSS bound"):
                    _supervise_worker(
                        [sys.executable, "-I", "-B", "-c", root_program],
                        cwd=root,
                        environment=os.environ,
                        log=log,
                        maximum_rss_bytes=50 * 1024 * 1024,
                        poll_milliseconds=10,
                    )
            self.assertLess(time.monotonic() - started, 8)
            root_pid, _child_pid = map(int, identity.read_text().split())
            deadline = time.monotonic() + 2
            members: tuple[int, ...] = (root_pid,)
            while members and time.monotonic() < deadline:
                _rss, members = _process_group_usage(root_pid)
                time.sleep(0.02)
            self.assertEqual(members, ())

    def test_successful_root_cannot_leave_a_descendant_running(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "processes.txt"
            root_program = (
                "import os,pathlib,subprocess;"
                "child=subprocess.Popen(['/bin/sleep','10']);"
                f"pathlib.Path({str(identity)!r}).write_text(f'{{os.getpid()}} {{child.pid}}')"
            )
            with (root / "worker.log").open("wb") as log:
                with self.assertRaisesRegex(RunnerError, "descendants remained"):
                    _supervise_worker(
                        [sys.executable, "-I", "-B", "-c", root_program],
                        cwd=root,
                        environment=os.environ,
                        log=log,
                        maximum_rss_bytes=1024 * 1024 * 1024,
                        poll_milliseconds=10,
                    )
            root_pid, _child_pid = map(int, identity.read_text().split())
            _rss, members = _process_group_usage(root_pid)
            self.assertEqual(members, ())

    def test_exit_observation_contributes_to_sampled_peak_rss(self) -> None:
        process = SimpleNamespace(pid=43210, poll=mock.Mock(return_value=0))
        final_rss = 123_456_789
        with tempfile.TemporaryFile() as log, mock.patch.object(
            runner_module.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            runner_module,
            "_process_group_usage",
            return_value=(final_rss, (process.pid,)),
        ) as observe:
            receipt = _supervise_worker(
                ["unused-worker"],
                cwd=Path.cwd(),
                environment={},
                log=log,
                maximum_rss_bytes=4_294_967_296,
                poll_milliseconds=250,
            )
        self.assertEqual(receipt["exitCode"], 0)
        self.assertEqual(receipt["peakAggregateRSSBytes"], final_rss)
        observe.assert_called_once_with(process.pid)

    def test_frozen_design_allows_only_lifecycle_bindings(self) -> None:
        design = frozen_design()
        validate_frozen_design(design)
        mutated = copy.deepcopy(design)
        mutated["candidate"]["groupSize"] = 64
        with self.assertRaises(RunnerError):
            validate_frozen_design(mutated)
        mutated = copy.deepcopy(design)
        mutated["beacon"]["trustBundleStatus"] = (
            "CANDIDATE_OFFLINE_TRUST_BUNDLE"
        )
        mutated["beacon"]["offlineTrustBundleSHA256"] = mutated["beacon"][
            "candidateOfflineTrustBundleSHA256"
        ]
        with self.assertRaises(RunnerError):
            validate_frozen_design(mutated)

    def test_one_shot_window_is_half_open_and_pre_marker(self) -> None:
        with self.assertRaises(RunnerError):
            ensure_one_shot_window(ONE_SHOT_NOT_BEFORE - timedelta(seconds=1))
        ensure_one_shot_window(ONE_SHOT_NOT_BEFORE)
        ensure_one_shot_window(MARKER_DEADLINE - timedelta(seconds=1))
        with self.assertRaises(RunnerError):
            ensure_one_shot_window(MARKER_DEADLINE)
        self.assertGreater(HARD_DEADLINE, MARKER_DEADLINE)
        with self.assertRaises(RunnerError):
            ensure_one_shot_window(datetime(2026, 8, 24, 18))

    def test_nist_https_date_is_an_external_half_open_start_anchor(self) -> None:
        self.assertEqual(
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T18:00:00Z"}
            ),
            ONE_SHOT_NOT_BEFORE,
        )
        with self.assertRaisesRegex(RunnerError, "outside"):
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T17:59:59Z"}
            )
        self.assertEqual(
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T18:14:59Z"}
            ),
            MARKER_DEADLINE - timedelta(seconds=1),
        )
        with self.assertRaisesRegex(RunnerError, "outside"):
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T18:15:00Z"}
            )
        with self.assertRaisesRegex(RunnerError, "outside"):
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-22T18:00:00Z"}
            )

    def test_attempt_identity_must_come_from_public_reservation(self) -> None:
        reserved = "20260821T180000Z-0123456789abcdef"
        verification = {
            "attemptId": reserved,
            "markerNoLaterThan": "2026-08-21T18:15:00Z",
        }
        self.assertEqual(require_reserved_attempt_id(verification), reserved)
        for invalid in (
            None,
            "",
            "attempt-1",
            "20260821T180000Z-XYZ",
            "20260926T180000Z-0123456789abcdef",
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                RunnerError, "public execution reservation"
            ):
                require_reserved_attempt_id(
                    {
                        "attemptId": invalid,
                        "markerNoLaterThan": "2026-08-21T18:15:00Z",
                    }
                )
        for marker_deadline in (None, "", "2026-08-21T18:15:01Z"):
            with self.subTest(marker_deadline=marker_deadline), self.assertRaisesRegex(
                RunnerError, "public execution reservation"
            ):
                require_reserved_attempt_id(
                    {
                        "attemptId": reserved,
                        "markerNoLaterThan": marker_deadline,
                    }
                )
        source = inspect.getsource(runner_module._historical_execute_private_one_shot)
        self.assertIn(
            "reserved_attempt_id = require_reserved_attempt_id(reservation_verification)",
            source,
        )
        self.assertIn("attempt_id=reserved_attempt_id", source)
        self.assertNotIn("attempt_id=attempt_id(", source)

    def test_attempt_id_contract_is_exact(self) -> None:
        self.assertIsNotNone(
            ATTEMPT_ID.fullmatch("20260821T180000Z-0123456789abcdef")
        )
        self.assertIsNone(ATTEMPT_ID.fullmatch("attempt-1"))
        self.assertIsNone(
            ATTEMPT_ID.fullmatch("20260926T180000Z-0123456789abcdef")
        )

    def test_corpus_evidence_uses_tokenizer_not_padded_logits_vocabulary(self) -> None:
        design = frozen_design()
        observed = scientific_tokenizer_vocabulary_sizes(design)
        self.assertEqual(observed["pythia-160m"], 50_277)
        self.assertEqual(observed["pythia-70m"], 50_277)
        pythia = next(
            item for item in design["models"] if item["key"] == "pythia-160m"
        )
        self.assertEqual(pythia["vocabSize"], 50_304)
        self.assertNotEqual(observed["pythia-160m"], pythia["vocabSize"])

        for field, value in (
            ("tokenizerVocabSize", 50_305),
            ("tokenizerVocabSize", True),
            ("vocabSize", 0),
        ):
            with self.subTest(field=field, value=value):
                forged = copy.deepcopy(design)
                target = next(
                    item
                    for item in forged["models"]
                    if item["key"] == "pythia-160m"
                )
                target[field] = value
                with self.assertRaisesRegex(
                    RunnerError, "model/tokenizer vocabulary"
                ):
                    scientific_tokenizer_vocabulary_sizes(forged)

    def test_private_snapshot_rejects_unmanifested_and_tampered_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = []
            for index, role in enumerate(sorted(PRIVATE_ROLES)):
                if role == "reservation-release-asset":
                    for name in (
                        "execution-reservation.json",
                        "sha256-manifest.json",
                        "snapshot-publication-receipt.json",
                    ):
                        payload = f"exact-{role}-{name}\n".encode()
                        path = f"publication/reservation-assets/{name}"
                        destination = root / path
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(payload)
                        files.append(
                            {
                                "path": path,
                                "bytes": len(payload),
                                "sha256": sha256_bytes(payload),
                                "role": role,
                            }
                        )
                    continue
                payload = f"exact-{role}\n".encode()
                if role == "lab-source-manifest":
                    path = "bindings/lab-source-manifest.json"
                elif role == "codec-source-manifest":
                    path = "bindings/codec-source-manifest.json"
                elif role == "lab-source":
                    path = "lab/source.py"
                elif role == "codec-source":
                    path = "codec/source.py"
                elif role == "pinned-cosign-binary":
                    path = "tools/cosign"
                elif role == "reservation-publication-receipt":
                    path = "publication/reservation-receipt.json"
                else:
                    path = f"payload-{index:02d}.bin"
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                files.append(
                    {
                        "path": path,
                        "bytes": len(payload),
                        "sha256": sha256_bytes(payload),
                        "role": role,
                    }
                )
            files.sort(key=lambda item: item["path"])
            manifest = {
                "schemaVersion": PRIVATE_SCHEMA,
                "suiteId": "corelm-blind-crossmodel-v1",
                "status": "SEALED_BEFORE_ATTEMPT",
                "createdAt": "2026-08-22T17:00:00Z",
                "countsTowardScientificVerdict": False,
                "designSHA256": "1" * 64,
                "snapshotRegistrationSHA256": "2" * 64,
                "designPublicationReceiptSHA256": "a" * 64,
                "snapshotPublicationReceiptSHA256": "b" * 64,
                "reservationPublicationReceiptSHA256": "e" * 64,
                "signingPublicKeySHA256": "c" * 64,
                "runtimeManifestSHA256": "3" * 64,
                "modelAssetSourceManifestSHA256": "4" * 64,
                "fullAssetReceiptSHA256": "5" * 64,
                "corpusManifestSHA256": "6" * 64,
                "freezeManifestSHA256": "7" * 64,
                "githubGateReceiptSHA256": "d" * 64,
                "transportCABundleSHA256": "8" * 64,
                "offlineTrustBundleSHA256": "9" * 64,
                "cosignBinarySHA256": next(
                    item["sha256"]
                    for item in files
                    if item["role"] == "pinned-cosign-binary"
                ),
                "labCommit": "1" * 40,
                "labTree": "2" * 40,
                "codecCommit": "3" * 40,
                "codecTree": "4" * 40,
                "labSourceManifestSHA256": next(
                    item["sha256"]
                    for item in files
                    if item["role"] == "lab-source-manifest"
                ),
                "codecSourceManifestSHA256": next(
                    item["sha256"]
                    for item in files
                    if item["role"] == "codec-source-manifest"
                ),
                "files": files,
            }
            manifest["contentSHA256"] = sha256_bytes(canonical_json_bytes(manifest))
            raw = canonical_json_bytes(manifest) + b"\n"
            (root / "private-snapshot-manifest.json").write_bytes(raw)
            with mock.patch("blind_v1.runner.verify_copied_source") as verifier:
                observed, digest = verify_private_snapshot(root)
                self.assertEqual(verifier.call_count, 2)
            self.assertEqual(observed, manifest)
            self.assertEqual(digest, sha256_bytes(raw))
            (root / "extra.bin").write_bytes(b"extra")
            with mock.patch("blind_v1.runner.verify_copied_source"):
                with self.assertRaises(RunnerError):
                    verify_private_snapshot(root)

    def test_worker_job_uses_sealed_record_not_normalized_text_path(self) -> None:
        design = frozen_design()
        model = design["models"][0]
        entries = []
        for filename in (
            "config.json",
            "generation_config.json",
            "merges.txt",
            "model.safetensors",
            "special_tokens_map.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "vocab.json",
        ):
            entries.append(
                {
                    "path": f"models/{model['key']}/{filename}",
                    "bytes": 1,
                    "sha256": "1" * 64,
                    "role": "model-asset",
                }
            )
        corpora = ["de.wikipedia.org", "en.wikipedia.org"]
        pages = {}
        for corpus_index, corpus in enumerate(corpora):
            pages[corpus] = []
            for index in range(16):
                revision = 1000 + corpus_index * 100 + index
                pages[corpus].append({"revid": revision})
                entries.append(
                    {
                        "path": f"records/{corpus}/{revision}.bin",
                        "bytes": 20,
                        "sha256": "2" * 64,
                        "role": "eligible-corpus-record",
                    }
                )
        selection = {
            "selectedCorpora": corpora,
            "selectedPages": pages,
        }
        job = _worker_job(
            design=design,
            selection=selection,
            private_manifest={"files": entries},
            model_key=model["key"],
            attempt="20260821T180000Z-0123456789abcdef",
        )
        first = job["pages"][corpora[0]][0]
        self.assertIn("recordPath", first)
        self.assertNotIn("inputPath", first)
        self.assertEqual(job["model"]["vocabSize"], model["vocabSize"])

    def test_scientific_result_strips_noncanonical_intermediates(self) -> None:
        cells = []
        for model in ("pythia-160m", "smollm-360m", "gpt2-124m"):
            for corpus in ("de.wikipedia.org", "en.wikipedia.org"):
                cells.append(
                    {
                        "modelKey": model,
                        "corpusProject": corpus,
                        "pages": 16,
                        "predictions": 2048,
                        "denseBF16Bytes": 100,
                        "containerBytes": 40,
                        "compressionRatioVsBF16": 2.5,
                        "deltaNLLNatPerToken": 0.0,
                        "top1ExactMatches": 2048,
                        "top1Agreement": 1.0,
                        "structuralReplay": True,
                        "pass": True,
                    }
                )
        aggregates = [
            {
                "modelKey": model,
                "blocks": 32,
                "predictions": 4096,
                "totalExactMatches": 4096,
                "deltaUpper": 0.0,
                "top1Lower": 1.0,
                "wilsonLower": 0.999,
                "pass": True,
            }
            for model in ("pythia-160m", "smollm-360m", "gpt2-124m")
        ]
        result = scientific_result(
            {
                "suiteId": "corelm-blind-crossmodel-v1",
                "attemptId": "20260821T180000Z-0123456789abcdef",
                "cells": cells,
                "modelAggregates": aggregates,
                "verdict": "PASS",
            },
            selection_sha256="a" * 64,
            pulse_sha256="b" * 64,
        )
        self.assertTrue(result["suitePass"])
        self.assertNotIn("top1ExactMatches", result["cells"][0])
        self.assertEqual(result["modelAggregates"][0]["pages"], 32)


if __name__ == "__main__":
    unittest.main()
