from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


BLIND_V1_ROOT = Path(__file__).resolve().parents[1]


class SafePathCLIEntrypointTests(unittest.TestCase):
    def test_every_argparse_entrypoint_can_render_help_in_isolated_mode(self) -> None:
        entrypoints = tuple(
            sorted(
                path
                for path in BLIND_V1_ROOT.glob("*.py")
                if b"import argparse" in path.read_bytes()
            )
        )
        self.assertGreaterEqual(len(entrypoints), 30)
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for entrypoint in entrypoints:
            with self.subTest(entrypoint=entrypoint.name):
                completed = subprocess.run(
                    (
                        sys.executable,
                        "-I",
                        "-B",
                        os.fspath(entrypoint),
                        "--help",
                    ),
                    cwd=Path("/"),
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stderr.decode("utf-8", errors="replace"),
                )
                self.assertIn(b"usage:", completed.stdout.lower())


if __name__ == "__main__":
    unittest.main()
