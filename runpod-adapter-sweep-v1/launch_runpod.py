#!/usr/bin/env python3
"""Enter the RunPod Bash launcher through one exact, sterile environment."""

from __future__ import annotations

import os
import resource
import sys
from pathlib import Path


INPUT_NAMES = (
    "CORELM_SWEEP_CODEC_ROOT",
    "CORELM_SWEEP_EXPECTED_COMMIT",
    "CORELM_SWEEP_EXPECTED_TREE",
    "CORELM_SWEEP_IMAGE_DIGEST",
    "CORELM_SWEEP_PYTHON",
    "CORELM_SWEEP_ROOT",
    "HF_TOKEN",
)


def fail(message: str) -> None:
    raise SystemExit(f"RUNPOD SWEEP ENTRY FAIL: {message}")


def main() -> None:
    if not sys.flags.ignore_environment or not sys.flags.no_user_site:
        fail("invoke this entrypoint with the exact runtime and -I -B")
    if not sys.dont_write_bytecode:
        fail("bytecode generation must be disabled")
    values = {name: os.environ.get(name) for name in INPUT_NAMES}
    if any(not isinstance(value, str) or not value for value in values.values()):
        fail("a required launcher input is absent")
    expected_python = Path(values["CORELM_SWEEP_PYTHON"]).resolve(strict=True)
    if expected_python != Path(sys.executable).resolve(strict=True):
        fail("entry interpreter differs from CORELM_SWEEP_PYTHON")
    token = values["HF_TOKEN"]
    if (
        len(token) < 20
        or not token.startswith("hf_")
        or any(character.isspace() for character in token)
    ):
        fail("HF_TOKEN is not a plausible fine-grained Hugging Face token")
    home = os.environ.get("HOME")
    if not isinstance(home, str) or not home.startswith("/"):
        fail("HOME must be an absolute provider-controlled directory")
    script = Path(__file__).resolve(strict=True).with_name("run_on_runpod.sh")
    if not script.is_file() or script.is_symlink():
        fail("the Bash launcher is absent or unsafe")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    clean_environment = {name: values[name] for name in INPUT_NAMES}
    clean_environment["HOME"] = home
    os.execve(
        "/bin/bash",
        ["/bin/bash", str(script), "--corelm-clean-entry"],
        clean_environment,
    )


if __name__ == "__main__":
    main()
