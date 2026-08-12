#!/usr/bin/env python3
"""Enter the public-Qwen RunPod launcher through a sterile environment."""

from __future__ import annotations

import os
import re
import resource
import stat
import sys
from pathlib import Path


INPUT_NAMES = (
    "CORELM_LENGTH_CODEC_ROOT",
    "CORELM_LENGTH_EXPECTED_COMMIT",
    "CORELM_LENGTH_EXPECTED_TREE",
    "CORELM_LENGTH_IMAGE_DIGEST",
    "CORELM_LENGTH_PYTHON",
    "CORELM_LENGTH_ROOT",
)
PID1_ENVIRON = Path("/proc/1/environ")
MAX_PID1_ENVIRON_BYTES = 1024 * 1024

# A Pod for this public-model contour must not receive any model, source-host,
# cloud-provider, or forwarded-login credential.  Match names only: values are
# never retained or printed.
EXACT_FORBIDDEN_NAMES = frozenset(
    {
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "RUNPOD_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "SSH_AUTH_SOCK",
    }
)
FORBIDDEN_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|CREDENTIALS?|PRIVATE_KEY|API_KEY|AUTH)(?:_|$)"
)


def fail(message: str) -> None:
    raise SystemExit(f"RUNPOD LENGTH ENTRY FAIL: {message}")


def credential_name(name: str) -> bool:
    return name in EXACT_FORBIDDEN_NAMES or FORBIDDEN_NAME_PATTERN.search(name) is not None


def parse_environment_names(raw: bytes, *, label: str) -> tuple[str, ...]:
    if len(raw) > MAX_PID1_ENVIRON_BYTES:
        fail(f"{label} environment exceeds its read bound")
    if raw and not raw.endswith(b"\0"):
        fail(f"{label} environment is not a terminated NUL-field sequence")
    names: list[str] = []
    for field in raw[:-1].split(b"\0") if raw else ():
        name, separator, _value = field.partition(b"=")
        if separator != b"=":
            fail(f"{label} environment contains a malformed field")
        try:
            decoded = name.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            fail(f"{label} environment contains a non-ASCII name")
        if not decoded or decoded in names:
            fail(f"{label} environment contains an empty or duplicate name")
        names.append(decoded)
    return tuple(names)


def read_bounded_proc_environment(path: Path = PID1_ENVIRON) -> bytes:
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
        return b"".join(chunks)
    except OSError as error:
        fail(f"cannot read PID 1 environment: {error.strerror or error}")
    finally:
        os.close(descriptor)


def reject_credentials(names: tuple[str, ...], *, label: str) -> None:
    rejected = sorted(name for name in names if credential_name(name))
    if rejected:
        # Names, unlike values, are safe to identify and make remediation exact.
        fail(f"{label} contains forbidden credential fields: {','.join(rejected)}")


def main() -> None:
    if not sys.flags.ignore_environment or not sys.flags.no_user_site:
        fail("invoke this entrypoint with the exact runtime and -I -B")
    if not sys.dont_write_bytecode:
        fail("bytecode generation must be disabled")

    reject_credentials(tuple(os.environ), label="entry environment")
    pid1_names = parse_environment_names(
        read_bounded_proc_environment(), label="PID 1"
    )
    reject_credentials(pid1_names, label="PID 1 environment")

    values = {name: os.environ.get(name) for name in INPUT_NAMES}
    if any(not isinstance(value, str) or not value for value in values.values()):
        fail("a required launcher input is absent")
    expected_python = Path(values["CORELM_LENGTH_PYTHON"]).resolve(strict=True)
    if expected_python != Path(sys.executable).resolve(strict=True):
        fail("entry interpreter differs from CORELM_LENGTH_PYTHON")
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
        ["/bin/bash", str(script), "--corelm-length-clean-entry"],
        clean_environment,
    )


if __name__ == "__main__":
    main()
