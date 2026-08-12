#!/usr/bin/env python3
"""Model-free security and topology tests for the RunPod wrapper."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ENTRY_PATH = ROOT / "launch_runpod.py"
WRAPPER_PATH = ROOT / "run_on_runpod.sh"
RUNBOOK_PATH = ROOT / "RUNPOD.md"


def load_entry():
    spec = importlib.util.spec_from_file_location(
        "_corelm_length_runpod_entry_test", ENTRY_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load launch_runpod.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RunPodEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entry = load_entry()

    def test_generic_and_registered_credential_names_are_rejected(self) -> None:
        forbidden = {
            "HF_TOKEN",
            "HUGGING_FACE_HUB_TOKEN",
            "RUNPOD_API_KEY",
            "RUNPOD_TOKEN",
            "CI_JOB_TOKEN",
            "REFRESH_TOKEN",
            "ID_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_CLIENT_SECRET",
            "SSH_AUTH_SOCK",
            "DEPLOY_PRIVATE_KEY",
            "SERVICE_PASSWORD",
            "FOO_SECRET_FILE",
            "DB_PASSWORD_PATH",
            "X_ACCESS_TOKEN_FILE",
            "SERVICE_CREDENTIALS_JSON",
            "CUSTOM_AUTH_HEADER",
        }
        for name in forbidden:
            with self.subTest(name=name):
                self.assertTrue(self.entry.credential_name(name))

    def test_registered_non_secret_inputs_are_allowed(self) -> None:
        allowed = {
            *self.entry.INPUT_NAMES,
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "RUNPOD_POD_ID",
        }
        for name in allowed:
            with self.subTest(name=name):
                self.assertFalse(self.entry.credential_name(name))

    def test_pid1_parser_never_returns_values(self) -> None:
        names = self.entry.parse_environment_names(
            b"HOME=/root\0RUNPOD_TOKEN=secret-value\0", label="fixture"
        )
        self.assertEqual(names, ("HOME", "RUNPOD_TOKEN"))
        with self.assertRaises(SystemExit):
            self.entry.reject_credentials(names, label="fixture")

    def test_pid1_parser_is_bounded_and_strict(self) -> None:
        with self.assertRaises(SystemExit):
            self.entry.parse_environment_names(b"HOME=/root", label="fixture")
        with self.assertRaises(SystemExit):
            self.entry.parse_environment_names(
                b"HOME=/root\0HOME=/other\0", label="fixture"
            )
        with self.assertRaises(SystemExit):
            self.entry.parse_environment_names(b"BROKEN\0", label="fixture")


class RunPodWrapperStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WRAPPER_PATH.read_text(encoding="utf-8")

    def test_bash_syntax(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-n", str(WRAPPER_PATH)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_all_six_registered_replays_are_in_one_closed_loop(self) -> None:
        self.assertIn(
            "for replay_level in p000256 p000512 p001024 p002048 p004096 p008192; do",
            self.text,
        )
        self.assertIn(
            "p000256|p000512|p001024|p002048) replay_timeout=600",
            self.text,
        )
        self.assertIn("p004096) replay_timeout=900", self.text)
        self.assertIn("p008192) replay_timeout=1350", self.text)
        self.assertEqual(self.text.count('"$verifier" replay-cell'), 1)
        self.assertIn("'samePodModelReplays=6'", self.text)
        self.assertIn("'allSeriesModelReplay=true'", self.text)
        self.assertIn("'independentModelReplay=false'", self.text)
        verifier_text = (ROOT / "verify_length_ladder.py").read_text(
            encoding="utf-8"
        )
        context_start = verifier_text.index("def _load_structural_context(")
        context_end = verifier_text.index("\ndef replay_cell(", context_start)
        self.assertNotIn(
            "verify_run(", verifier_text[context_start:context_end]
        )

    def test_anonymous_then_application_offline_boundary(self) -> None:
        download = self.text.index("run_timed ASSET_DOWNLOAD")
        offline = self.text.index("export HF_HUB_OFFLINE=1")
        orchestrate = self.text.index("run_timed LENGTH_ORCHESTRATE")
        structural = self.text.index("run_timed LENGTH_STRUCTURAL_VERIFY")
        render = self.text.index("run_timed LENGTH_RENDER_RESULTS")
        replay = self.text.index('run_timed "REPLAY_${replay_level}"')
        self.assertLess(download, offline)
        self.assertLess(offline, orchestrate)
        self.assertLess(orchestrate, structural)
        self.assertLess(structural, render)
        self.assertLess(render, replay)
        self.assertIn('"$verifier" render-results', self.text)
        self.assertIn('--output "$run_root/evidence/RESULTS.md"', self.text)
        self.assertNotIn("export HF_TOKEN", self.text)
        self.assertIn("assert_no_auth_files /root", self.text)
        self.assertIn(".config/gh/hosts.yml", self.text)
        self.assertIn(".aws/credentials", self.text)
        self.assertIn("! -name '*.pub'", self.text)

    def test_archive_is_evidence_only_and_gnu_deterministic(self) -> None:
        self.assertIn("--format=gnu", self.text)
        self.assertIn("--mtime='UTC 1970-01-01'", self.text)
        self.assertIn("-C \"$run_root\"", self.text)
        self.assertIn("-cf \"$archive_tar\" evidence", self.text)
        self.assertNotIn("--format=pax", self.text)

    def test_exact_triton_executable_cache_smoke_precedes_download(self) -> None:
        smoke = self.text.index("run_timed EXECUTABLE_CACHE_SMOKE")
        download = self.text.index("run_timed ASSET_DOWNLOAD")
        self.assertLess(smoke, download)
        self.assertIn(
            "torch._native.ops.bmm_outer_product.triton_kernels import bmm_outer_product",
            self.text,
        )
        self.assertIn('rglob(\"cuda_utils*.so\")', self.text)
        self.assertIn('(\"HOME\", \"TMPDIR\", \"XDG_CACHE_HOME\")', self.text)

    def test_privacy_pattern_allows_registered_runpod_labels(self) -> None:
        begin = self.text.index("grep -R -I -q -E")
        end = self.text.index('  "$run_root/evidence"', begin)
        fragments = re.findall(r"'([^']*)'", self.text[begin:end])
        self.assertGreaterEqual(len(fragments), 2)
        pattern = "".join(fragments)
        allowed = b"schemaVersion=corelm-runpod-length-ladder-source-v1\nplatform=RunPod Pod\n"
        forbidden = b"podId=private\nHF_TOKEN=never-retain\n"
        admitted = subprocess.run(
            ["/usr/bin/grep", "-E", "-q", pattern],
            input=allowed,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        rejected = subprocess.run(
            ["/usr/bin/grep", "-E", "-q", pattern],
            input=forbidden,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(admitted.returncode, 1, admitted.stderr.decode())
        self.assertEqual(rejected.returncode, 0, rejected.stderr.decode())


class RunPodRunbookStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_external_trust_bootstrap_precedes_checked_in_programs(self) -> None:
        self.assertIn("verify_source_checkout()", self.text)
        self.assertIn("hash-object --no-filters", self.text)
        self.assertIn("--is-shallow-repository", self.text)
        self.assertIn("refs/replace", self.text)
        self.assertIn("ls-files -v", self.text)
        self.assertIn("verify-commit", self.text)
        self.assertNotIn('test -z "$(/usr/bin/git', self.text)
        self.assertEqual(
            self.text.count('verify_source_checkout "$SWEEP_SOURCE"'), 3
        )
        first_verification = self.text.index(
            'verify_source_checkout "$SWEEP_SOURCE"'
        )
        builder = self.text.index(
            '"$SWEEP_SOURCE/runpod-adapter-sweep-v1/build_cuda_runtime.sh"'
        )
        launcher = self.text.index(
            './runpod-length-ladder-v1/launch_runpod.py'
        )
        self.assertLess(first_verification, builder)
        self.assertLess(first_verification, launcher)

    def test_cost_and_time_fuses_are_closed(self) -> None:
        self.assertIn(
            "provider-side terminate-after **10 hours** from Pod creation",
            self.text,
        )
        self.assertIn(
            "combined live rate at most **USD 0.50/hour**", self.text
        )
        self.assertIn("projected total at most **USD 5.00**", self.text)
        self.assertIn("27,030 seconds", self.text)
        self.assertIn("Six registered-length replays", self.text)
        self.assertIn("Complete orchestrator | 8,400", self.text)

    def test_runbook_shell_and_retrieval_python_syntax(self) -> None:
        bash_blocks = re.findall(r"```bash\n(.*?)\n```", self.text, re.DOTALL)
        self.assertGreaterEqual(len(bash_blocks), 4)
        for index, block in enumerate(bash_blocks):
            completed = subprocess.run(
                ["/bin/bash", "-n"],
                input=block.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                f"bash block {index}: {completed.stderr.decode()}",
            )
        marker = 'python3 - "$LOCAL_EVIDENCE_DIR" <<\'PY\'\n'
        self.assertIn(marker, self.text)
        retrieval = self.text.split(marker, 1)[1].split("\nPY\n", 1)[0]
        compile(retrieval, "RUNPOD.md retrieval block", "exec")


if __name__ == "__main__":
    unittest.main()
