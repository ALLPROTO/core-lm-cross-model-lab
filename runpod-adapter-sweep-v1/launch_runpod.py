#!/usr/bin/env python3
"""Enter the RunPod Bash launcher through one exact, sterile environment."""

from __future__ import annotations

import os
import resource
import stat
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
PID1_ENVIRON = Path("/proc/1/environ")
MAX_PID1_ENVIRON_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"RUNPOD SWEEP ENTRY FAIL: {message}")


def plausible_hf_token(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) >= 20
        and value.startswith("hf_")
        and value.isascii()
        and value[3:].isalnum()
    )


def parse_pid1_hf_token(raw: bytes) -> str:
    """Extract only one strictly encoded HF_TOKEN field from PID 1."""

    if len(raw) > MAX_PID1_ENVIRON_BYTES:
        fail("PID 1 environment exceeds its read bound")
    if not raw or not raw.endswith(b"\0"):
        fail("PID 1 environment is not a terminated NUL-field sequence")
    matches = []
    for field in raw[:-1].split(b"\0"):
        name, separator, value = field.partition(b"=")
        if name == b"HF_TOKEN":
            if separator != b"=":
                fail("PID 1 HF_TOKEN field is malformed")
            matches.append(value)
    if len(matches) != 1:
        fail("PID 1 must contain exactly one HF_TOKEN field")
    try:
        token = matches[0].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("PID 1 HF_TOKEN is not strict ASCII")
    if not plausible_hf_token(token):
        fail("PID 1 HF_TOKEN is not a plausible fine-grained token")
    return token


def read_pid1_hf_token(path: Path = PID1_ENVIRON) -> str:
    """Boundedly read PID 1 without importing any other environment field."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open PID 1 environment: {error.strerror or error}")
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            fail("PID 1 environment is not a regular procfs file")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PID1_ENVIRON_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, MAX_PID1_ENVIRON_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    except OSError as error:
        fail(f"cannot read PID 1 environment: {error.strerror or error}")
    finally:
        os.close(descriptor)
    return parse_pid1_hf_token(raw)


def main() -> None:
    if not sys.flags.ignore_environment or not sys.flags.no_user_site:
        fail("invoke this entrypoint with the exact runtime and -I -B")
    if not sys.dont_write_bytecode:
        fail("bytecode generation must be disabled")
    values = {name: os.environ.get(name) for name in INPUT_NAMES}
    if values["HF_TOKEN"] is None:
        values["HF_TOKEN"] = read_pid1_hf_token()
    if any(not isinstance(value, str) or not value for value in values.values()):
        fail("a required launcher input is absent")
    expected_python = Path(values["CORELM_SWEEP_PYTHON"]).resolve(strict=True)
    if expected_python != Path(sys.executable).resolve(strict=True):
        fail("entry interpreter differs from CORELM_SWEEP_PYTHON")
    token = values["HF_TOKEN"]
    if not plausible_hf_token(token):
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
