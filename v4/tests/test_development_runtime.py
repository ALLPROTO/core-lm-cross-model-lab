from __future__ import annotations

import ast
import inspect
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import v4.development_runtime as runtime
from v4.protocol import canonical_json_bytes


def _canonical_line(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


class DevelopmentRuntimeTests(unittest.TestCase):
    def test_module_has_only_neutral_v4_dependencies(self) -> None:
        tree = ast.parse(inspect.getsource(runtime))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        v4_imports = {name for name in imported if name.startswith("v4.")}
        self.assertEqual(
            v4_imports,
            {"v4.evidence", "v4.protocol", "v4.reproducibility"},
        )
        self.assertTrue(
            {
                "v4.runner",
                "v4.nist_beacon",
                "v4.state_machine",
                "v4.publication",
            }.isdisjoint(imported)
        )

    def test_development_supervisor_does_not_import_scientific_runner(self) -> None:
        source = Path(runtime.__file__).with_name("run_real_e2e_control.py").read_text(
            encoding="utf-8"
        )
        imported = {
            node.module
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertTrue(
            {
                "v4.runner",
                "v4.nist_beacon",
                "v4.state_machine",
                "v4.publication",
            }.isdisjoint(imported)
        )

    def test_closed_environment_is_exact_and_secret_free(self) -> None:
        self.assertEqual(
            runtime.closed_environment({"intraOpThreads": 3}),
            {
                "HF_DATASETS_OFFLINE": "1",
                "HF_HUB_OFFLINE": "1",
                "LANG": "C",
                "LC_ALL": "C",
                "MKL_NUM_THREADS": "3",
                "NO_PROXY": "*",
                "NUMEXPR_NUM_THREADS": "3",
                "OMP_NUM_THREADS": "3",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
                "TOKENIZERS_PARALLELISM": "false",
                "TRANSFORMERS_OFFLINE": "1",
                "VECLIB_MAXIMUM_THREADS": "3",
                "no_proxy": "*",
            },
        )
        for execution in ({}, {"intraOpThreads": 0}, {"intraOpThreads": True}):
            with self.subTest(execution=execution):
                with self.assertRaises(runtime.DevelopmentRuntimeError):
                    runtime.closed_environment(execution)
        with self.assertRaises(runtime.DevelopmentRuntimeError):
            runtime.closed_environment(None)  # type: ignore[arg-type]

    def test_python_command_preserves_lexical_virtualenv_launcher(self) -> None:
        resolved_executable = Path(sys.executable).resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            runtime_root = root / "runtime"
            launcher = runtime_root / "bin" / "python"
            launcher.parent.mkdir(parents=True)
            launcher.symlink_to(resolved_executable)
            with (
                mock.patch.object(runtime.sys, "executable", str(launcher)),
                mock.patch.object(runtime.sys, "prefix", str(runtime_root)),
                mock.patch.object(runtime.sys, "base_prefix", str(root / "base")),
            ):
                command = runtime.python_command(launcher, "worker.py", "--fixed")
                self.assertEqual(
                    command,
                    [str(launcher), "-P", "-s", "-B", "worker.py", "--fixed"],
                )
                self.assertNotEqual(command[0], str(resolved_executable))
                with self.assertRaisesRegex(
                    runtime.DevelopmentRuntimeError, "active locked runtime"
                ):
                    runtime.python_command(resolved_executable)
                with self.assertRaisesRegex(
                    runtime.DevelopmentRuntimeError, "argument is invalid"
                ):
                    runtime.python_command(launcher, "bad\x00argument")

    def test_python_command_rejects_relative_and_symlink_parent(self) -> None:
        with self.assertRaisesRegex(
            runtime.DevelopmentRuntimeError, "normalized absolute path"
        ):
            runtime.python_command(Path("bin/python"))

        resolved_executable = Path(sys.executable).resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            real_parent = root / "real-parent"
            real_runtime = real_parent / "runtime"
            (real_runtime / "bin").mkdir(parents=True)
            (real_runtime / "bin" / "python").symlink_to(resolved_executable)
            alias = root / "parent-alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            aliased_runtime = alias / "runtime"
            launcher = aliased_runtime / "bin" / "python"
            with (
                mock.patch.object(runtime.sys, "executable", str(launcher)),
                mock.patch.object(runtime.sys, "prefix", str(aliased_runtime)),
                mock.patch.object(runtime.sys, "base_prefix", str(root / "base")),
                self.assertRaisesRegex(
                    runtime.DevelopmentRuntimeError,
                    "symlink/non-directory parent",
                ),
            ):
                runtime.python_command(launcher)

    def test_active_python_startup_requires_exact_state(self) -> None:
        expected = runtime._expected_python_state()
        with mock.patch.object(runtime, "_python_state", return_value=expected):
            runtime.verify_active_python_startup()
        mutated = dict(expected)
        mutated["hashRandomization"] = 1
        with (
            mock.patch.object(runtime, "_python_state", return_value=mutated),
            self.assertRaisesRegex(
                runtime.DevelopmentRuntimeError, "startup differs"
            ),
        ):
            runtime.verify_active_python_startup()

    def test_registered_hash_known_answer_is_executed_by_real_python(self) -> None:
        completed = subprocess.run(
            [
                os.path.abspath(sys.executable),
                "-P",
                "-s",
                "-B",
                "-c",
                "import sys; print(hash(sys.argv[1]))",
                runtime.HASH_INPUT,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=10,
            env={"PYTHONHASHSEED": "0"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(
            completed.stdout,
            f"{runtime.HASH_KNOWN_ANSWER}\n",
        )

    def test_python_subprocess_checks_startup_and_exact_import_versions(self) -> None:
        launcher = "/private/runtime/bin/python"
        startup = runtime._expected_python_state()
        imports = {
            "basePrefix": os.path.abspath(sys.base_prefix),
            "executable": launcher,
            "prefix": os.path.abspath(sys.prefix),
            "venvActive": True,
            "versions": dict(runtime.RUNTIME_IMPORT_VERSIONS),
        }
        completed = [
            SimpleNamespace(returncode=0, stderr=b"", stdout=_canonical_line(startup)),
            SimpleNamespace(returncode=0, stderr=b"", stdout=_canonical_line(imports)),
        ]

        def command(_executable: object, *arguments: str) -> list[str]:
            return [launcher, *runtime.PYTHON_FLAGS, *arguments]

        with (
            mock.patch.object(runtime, "python_command", side_effect=command),
            mock.patch.object(
                runtime,
                "networkless_macos_command",
                side_effect=lambda value: ["sandbox", *value],
            ),
            mock.patch.object(runtime.subprocess, "run", side_effect=completed) as run,
        ):
            observed = runtime.verify_python_subprocess(
                launcher, {"PYTHONHASHSEED": "0"}
            )
        self.assertEqual(observed, startup)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].kwargs["timeout"], 10)
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], 30)
        self.assertEqual(run.call_args_list[1].args[0][0], "sandbox")
        self.assertEqual(
            set(imports["versions"]),
            {
                "jsonschema",
                "numpy",
                "safetensors",
                "tokenizers",
                "torch",
                "transformers",
            },
        )
        self.assertNotIn("pyarrow", runtime.RUNTIME_IMPORT_VERSIONS)
        self.assertNotIn("pyarrow", run.call_args_list[1].args[0][-1])

    def test_python_subprocess_rejects_dependency_version_drift(self) -> None:
        launcher = "/private/runtime/bin/python"
        imports = {
            "basePrefix": os.path.abspath(sys.base_prefix),
            "executable": launcher,
            "prefix": os.path.abspath(sys.prefix),
            "venvActive": True,
            "versions": {**runtime.RUNTIME_IMPORT_VERSIONS, "torch": "0.0.0"},
        }
        completed = [
            SimpleNamespace(
                returncode=0,
                stderr=b"",
                stdout=_canonical_line(runtime._expected_python_state()),
            ),
            SimpleNamespace(returncode=0, stderr=b"", stdout=_canonical_line(imports)),
        ]

        def command(_executable: object, *arguments: str) -> list[str]:
            return [launcher, *runtime.PYTHON_FLAGS, *arguments]

        with (
            mock.patch.object(runtime, "python_command", side_effect=command),
            mock.patch.object(
                runtime, "networkless_macos_command", side_effect=lambda x: x
            ),
            mock.patch.object(runtime.subprocess, "run", side_effect=completed),
            self.assertRaisesRegex(
                runtime.DevelopmentRuntimeError, "dependency identity differs"
            ),
        ):
            runtime.verify_python_subprocess(
                launcher, {"PYTHONHASHSEED": "0"}
            )

    def test_python_subprocess_rejects_open_or_non_string_environment(self) -> None:
        environments = (
            {},
            {"PYTHONHASHSEED": "1"},
            {"PYTHONHASHSEED": "0", 1: "x"},
        )
        for environment in environments:
            with self.subTest(environment=environment):
                with self.assertRaisesRegex(
                    runtime.DevelopmentRuntimeError, "environment is invalid"
                ):
                    runtime.verify_python_subprocess(
                        "/private/runtime/bin/python",
                        environment,  # type: ignore[arg-type]
                    )

    def test_networkless_macos_command_binds_sandbox_profile(self) -> None:
        with (
            mock.patch.object(runtime.platform, "system", return_value="Darwin"),
            mock.patch.object(runtime.platform, "machine", return_value="arm64"),
            mock.patch.object(
                runtime,
                "digest_regular_file",
                return_value={"bytes": 10, "sha256": "a" * 64},
            ) as digest,
        ):
            command = runtime.networkless_macos_command(["python", "worker.py"])
        self.assertEqual(
            command,
            [
                "/usr/bin/sandbox-exec",
                "-p",
                "(version 1)(allow default)(deny network*)",
                "python",
                "worker.py",
            ],
        )
        digest.assert_called_once_with(Path("/usr/bin/sandbox-exec"))

        with (
            mock.patch.object(runtime.platform, "system", return_value="Linux"),
            mock.patch.object(runtime.platform, "machine", return_value="x86_64"),
            self.assertRaisesRegex(
                runtime.DevelopmentRuntimeError, "requires macOS arm64"
            ),
        ):
            runtime.networkless_macos_command(["python"])

    def test_process_group_usage_aggregates_sorted_members(self) -> None:
        completed = SimpleNamespace(
            returncode=0,
            stdout="7 9 10\n3 4 99\n5 9 20\n",
            stderr="",
        )
        with mock.patch.object(runtime.subprocess, "run", return_value=completed):
            rss, members = runtime.process_group_usage(9)
        self.assertEqual(rss, 30 * 1024)
        self.assertEqual(members, (5, 7))

    def test_process_group_usage_rejects_malformed_or_failed_ps(self) -> None:
        malformed = SimpleNamespace(returncode=0, stdout="7 nine 10\n", stderr="")
        with (
            mock.patch.object(runtime.subprocess, "run", return_value=malformed),
            self.assertRaisesRegex(
                runtime.DevelopmentRuntimeError, "observation was malformed"
            ),
        ):
            runtime.process_group_usage(9)
        failed = SimpleNamespace(returncode=2, stdout="", stderr="denied")
        with (
            mock.patch.object(runtime.subprocess, "run", return_value=failed),
            self.assertRaisesRegex(
                runtime.DevelopmentRuntimeError, "ps exit 2: denied"
            ),
        ):
            runtime.process_group_usage(9)

    def test_terminate_process_group_handles_missing_and_cleared_groups(self) -> None:
        process = SimpleNamespace(pid=44)
        with mock.patch.object(runtime.os, "killpg", side_effect=ProcessLookupError):
            runtime.terminate_process_group(process)

        process = SimpleNamespace(
            pid=45,
            poll=mock.Mock(return_value=0),
            wait=mock.Mock(),
        )
        with (
            mock.patch.object(runtime.os, "killpg") as kill,
            mock.patch.object(runtime, "process_group_usage", return_value=(0, ())),
        ):
            runtime.terminate_process_group(process)
        kill.assert_called_once_with(45, signal.SIGTERM)
        process.wait.assert_not_called()

    def test_consolidate_worker_evidence_merges_and_moves_declared_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary).resolve(strict=True) / "result"
            worker_root = result_root / "workers" / "model-a"
            worker_root.mkdir(parents=True)
            raw_records = [{"modelKey": "model-a", "token": 7}]
            container_records = [
                {
                    "modelKey": "model-a",
                    "relativePath": "containers/model-a/page.vtl5",
                }
            ]
            page_records = [{"modelKey": "model-a", "tokens": [1, 2, 3]}]
            (worker_root / "raw-token-evidence.jsonl").write_bytes(
                b"".join(_canonical_line(value) for value in raw_records)
            )
            (worker_root / "container-evidence.jsonl").write_bytes(
                b"".join(_canonical_line(value) for value in container_records)
            )
            (worker_root / "page-token-evidence.jsonl").write_bytes(
                b"".join(_canonical_line(value) for value in page_records)
            )
            source = worker_root / "containers" / "model-a" / "page.vtl5"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"real-container-bytes")

            raw, containers, pages, manifest = runtime.consolidate_worker_evidence(
                result_root=result_root, model_order=("model-a",)
            )

            self.assertEqual(raw.read_bytes(), _canonical_line(raw_records[0]))
            self.assertEqual(
                containers.read_bytes(), _canonical_line(container_records[0])
            )
            self.assertEqual(pages.read_bytes(), _canonical_line(page_records[0]))
            destination = result_root / "containers" / "model-a" / "page.vtl5"
            self.assertEqual(destination.read_bytes(), b"real-container-bytes")
            self.assertFalse(source.exists())
            self.assertEqual(manifest, ["containers/model-a/page.vtl5"])

    def test_consolidate_worker_evidence_rejects_escaping_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary).resolve(strict=True) / "result"
            worker_root = result_root / "workers" / "model-a"
            worker_root.mkdir(parents=True)
            (worker_root / "raw-token-evidence.jsonl").write_bytes(
                _canonical_line({"raw": True})
            )
            (worker_root / "container-evidence.jsonl").write_bytes(
                _canonical_line({"relativePath": "../escape.vtl5"})
            )
            (worker_root / "page-token-evidence.jsonl").write_bytes(
                _canonical_line({"page": True})
            )
            with self.assertRaisesRegex(
                runtime.DevelopmentRuntimeError, "escapes its root"
            ):
                runtime.consolidate_worker_evidence(
                    result_root=result_root, model_order=("model-a",)
                )


if __name__ == "__main__":
    unittest.main()
