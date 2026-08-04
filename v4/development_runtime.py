#!/usr/bin/env python3
"""Neutral runtime, process, and evidence helpers for development controls.

This module deliberately contains no experiment lifecycle or publication
logic.  It only closes a child environment, proves the pinned interpreter
identity, supervises process groups, and consolidates already-produced worker
evidence.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from v4.evidence import canonical_json_line, load_canonical_jsonl
from v4.protocol import canonical_json_bytes, load_json_strict_bytes
from v4.reproducibility import (
    digest_regular_file,
    scan_tree,
    verify_content_digest,
    write_new_bytes,
)


MACOS_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
NETWORK_DENY_PROFILE = "(version 1)(allow default)(deny network*)"
CLOSED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON_FLAGS = ("-P", "-s", "-B")
RUNTIME_IMPORT_VERSIONS = {
    "jsonschema": "4.25.1",
    "numpy": "2.5.1",
    "safetensors": "0.8.0",
    "tokenizers": "0.22.2",
    "torch": "2.13.0",
    "transformers": "5.14.1",
}
HASH_INPUT = "corelm-crossmodel-livewiki-v4"
HASH_KNOWN_ANSWER = 6381993545148000455


class DevelopmentRuntimeError(RuntimeError):
    """Raised when a development runtime boundary cannot be proved safe."""


def closed_environment(execution: Mapping[str, Any]) -> dict[str, str]:
    """Return the complete, secret-free environment inherited by children."""

    if not isinstance(execution, Mapping):
        raise DevelopmentRuntimeError("development execution settings are invalid")
    intra_threads = execution.get("intraOpThreads")
    if type(intra_threads) is not int or intra_threads < 1:
        raise DevelopmentRuntimeError("development intra-op thread count is invalid")
    threads = str(intra_threads)
    return {
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_OFFLINE": "1",
        "LANG": "C",
        "LC_ALL": "C",
        "MKL_NUM_THREADS": threads,
        "NO_PROXY": "*",
        "NUMEXPR_NUM_THREADS": threads,
        "OMP_NUM_THREADS": threads,
        "PATH": CLOSED_PATH,
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TOKENIZERS_PARALLELISM": "false",
        "TRANSFORMERS_OFFLINE": "1",
        "VECLIB_MAXIMUM_THREADS": threads,
        "no_proxy": "*",
    }


def python_command(executable: str | Path, *arguments: str) -> list[str]:
    """Build a hardened command while retaining lexical virtualenv identity."""

    try:
        raw = os.fspath(executable)
    except TypeError as error:
        raise DevelopmentRuntimeError(
            "development Python launcher path is invalid"
        ) from error
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or not os.path.isabs(raw)
        or raw != os.path.abspath(raw)
    ):
        raise DevelopmentRuntimeError(
            "development Python launcher must be a normalized absolute path"
        )

    launcher = Path(os.path.abspath(raw))
    active_launcher = Path(os.path.abspath(sys.executable))
    runtime_root = Path(os.path.abspath(sys.prefix))
    base_root = Path(os.path.abspath(sys.base_prefix))
    if runtime_root == base_root:
        raise DevelopmentRuntimeError(
            "development Python requires an active virtual environment"
        )
    if launcher != active_launcher or launcher != runtime_root / "bin" / "python":
        raise DevelopmentRuntimeError(
            "development Python launcher differs from the active locked runtime"
        )

    try:
        current = Path(launcher.anchor)
        for component in launcher.parts[1:-1]:
            current /= component
            parent_metadata = os.lstat(current)
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise DevelopmentRuntimeError(
                    "development Python launcher has a symlink/non-directory parent"
                )
        launcher_metadata = os.lstat(launcher)
        resolved = launcher.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except DevelopmentRuntimeError:
        raise
    except OSError as error:
        raise DevelopmentRuntimeError(
            "development Python launcher cannot be verified"
        ) from error

    if (
        not (
            stat.S_ISREG(launcher_metadata.st_mode)
            or stat.S_ISLNK(launcher_metadata.st_mode)
        )
        or not stat.S_ISREG(resolved_metadata.st_mode)
        or not os.access(resolved, os.X_OK)
    ):
        raise DevelopmentRuntimeError(
            "development Python launcher is not executable"
        )
    if any(
        not isinstance(argument, str) or "\x00" in argument
        for argument in arguments
    ):
        raise DevelopmentRuntimeError("development Python argument is invalid")
    return [str(launcher), *PYTHON_FLAGS, *arguments]


def _python_state() -> dict[str, Any]:
    return {
        "dontWriteBytecode": bool(sys.dont_write_bytecode),
        "hashAlgorithm": sys.hash_info.algorithm,
        "hashBits": sys.hash_info.width,
        "hashRandomization": sys.flags.hash_randomization,
        "hashValue": hash(HASH_INPUT),
        "ignoreEnvironment": sys.flags.ignore_environment,
        "noUserSite": sys.flags.no_user_site,
        "pythonVersion": ".".join(str(value) for value in sys.version_info[:3]),
        "safePath": bool(getattr(sys.flags, "safe_path", False)),
        "seedBits": sys.hash_info.seed_bits,
    }


def _expected_python_state() -> dict[str, Any]:
    return {
        "dontWriteBytecode": True,
        "hashAlgorithm": "siphash13",
        "hashBits": 64,
        "hashRandomization": 0,
        "hashValue": HASH_KNOWN_ANSWER,
        "ignoreEnvironment": 0,
        "noUserSite": 1,
        "pythonVersion": "3.12.10",
        "safePath": True,
        "seedBits": 128,
    }


def verify_active_python_startup() -> None:
    """Require this supervisor to have the pinned Python startup state."""

    if _python_state() != _expected_python_state():
        raise DevelopmentRuntimeError(
            "active development Python startup differs from the registered state"
        )


def _validated_environment(environment: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise DevelopmentRuntimeError("development child environment is invalid")
    if environment.get("PYTHONHASHSEED") != "0" or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise DevelopmentRuntimeError("development child environment is invalid")
    return dict(environment)


def _canonical_probe_output(raw: bytes, *, label: str) -> Any:
    try:
        observed = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise DevelopmentRuntimeError(f"{label} output is invalid") from error
    if canonical_json_bytes(observed) + b"\n" != raw:
        raise DevelopmentRuntimeError(f"{label} output is not canonical")
    return observed


def _verify_runtime_imports_subprocess(
    executable: str | Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    child_environment = _validated_environment(environment)
    probe = (
        "import importlib.metadata,json,sys\n"
        "import jsonschema,numpy,safetensors,tokenizers,torch,transformers\n"
        "names=('jsonschema','numpy','safetensors','tokenizers',"
        "'torch','transformers')\n"
        "value={'basePrefix':sys.base_prefix,'executable':sys.executable,"
        "'prefix':sys.prefix,'venvActive':sys.prefix!=sys.base_prefix,"
        "'versions':{name:importlib.metadata.version(name) for name in names}}\n"
        "sys.stdout.write(json.dumps(value,sort_keys=True,"
        "separators=(',',':'))+'\\n')\n"
    )
    launcher = python_command(executable)[0]
    command = networkless_macos_command(python_command(executable, "-c", probe))
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env=child_environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DevelopmentRuntimeError(
            "development runtime import subprocess failed"
        ) from error
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > 4096
    ):
        raise DevelopmentRuntimeError("development runtime dependency imports failed")
    observed = _canonical_probe_output(
        completed.stdout, label="development runtime import subprocess"
    )
    expected = {
        "basePrefix": os.path.abspath(sys.base_prefix),
        "executable": launcher,
        "prefix": os.path.abspath(sys.prefix),
        "venvActive": True,
        "versions": dict(RUNTIME_IMPORT_VERSIONS),
    }
    if observed != expected:
        raise DevelopmentRuntimeError("development runtime dependency identity differs")
    return observed


def verify_python_subprocess(
    executable: str | Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    """Prove startup state and exact dependency identity in child processes."""

    child_environment = _validated_environment(environment)
    probe = (
        "import json,sys\n"
        "value={"
        "'dontWriteBytecode':bool(sys.dont_write_bytecode),"
        "'hashAlgorithm':sys.hash_info.algorithm,"
        "'hashBits':sys.hash_info.width,"
        "'hashRandomization':sys.flags.hash_randomization,"
        f"'hashValue':hash({HASH_INPUT!r}),"
        "'ignoreEnvironment':sys.flags.ignore_environment,"
        "'noUserSite':sys.flags.no_user_site,"
        "'pythonVersion':'.'.join(str(v) for v in sys.version_info[:3]),"
        "'safePath':bool(getattr(sys.flags,'safe_path',False)),"
        "'seedBits':sys.hash_info.seed_bits}\n"
        "sys.stdout.write(json.dumps(value,sort_keys=True,"
        "separators=(',',':'))+'\\n')\n"
    )
    try:
        completed = subprocess.run(
            python_command(executable, "-c", probe),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env=child_environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DevelopmentRuntimeError(
            "development Python known-answer subprocess failed"
        ) from error
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > 4096
    ):
        raise DevelopmentRuntimeError(
            "development Python known-answer subprocess produced invalid output"
        )
    observed = _canonical_probe_output(
        completed.stdout, label="development Python known-answer subprocess"
    )
    if observed != _expected_python_state():
        raise DevelopmentRuntimeError("development Python known-answer differs")
    _verify_runtime_imports_subprocess(executable, child_environment)
    return observed


def verify_runtime_live(
    runtime_manifest: Mapping[str, Any], runtime_root: Path
) -> None:
    """Rehash the complete locked macOS runtime used by the control."""

    try:
        verify_content_digest(dict(runtime_manifest))
    except (TypeError, ValueError) as error:
        raise DevelopmentRuntimeError("runtime manifest digest differs") from error
    if (
        runtime_manifest.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v4-runtime-manifest-v1"
        or runtime_manifest.get("status")
        != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY"
    ):
        raise DevelopmentRuntimeError("runtime manifest is incomplete")
    host = runtime_manifest.get("host")
    if (
        not isinstance(host, Mapping)
        or host.get("system") != "Darwin"
        or host.get("machine") != "arm64"
        or platform.system() != "Darwin"
        or platform.machine() != "arm64"
    ):
        raise DevelopmentRuntimeError("development runtime is not macOS arm64")
    try:
        active_root = Path(sys.prefix).resolve(strict=True)
        expected_root = Path(runtime_root).resolve(strict=True)
        base_root = Path(sys.base_prefix).resolve(strict=True)
    except OSError as error:
        raise DevelopmentRuntimeError("development runtime root is unavailable") from error
    if active_root != expected_root or tuple(sys.version_info[:3]) != (3, 12, 10):
        raise DevelopmentRuntimeError("active interpreter differs from locked runtime")
    base_is_distinct = base_root != expected_root
    if runtime_manifest.get("basePythonDistinctFromRuntime") is not base_is_distinct:
        raise DevelopmentRuntimeError("runtime base-Python boundary differs")
    expected_runtime = runtime_manifest.get("runtimeTree")
    expected_base = runtime_manifest.get("basePythonTree")
    if not isinstance(expected_runtime, Mapping) or not isinstance(
        expected_base, Mapping
    ):
        raise DevelopmentRuntimeError("runtime tree commitment is absent")
    try:
        if base_is_distinct:
            observed_runtime = scan_tree(
                expected_root, external_roots={"base-python-root": base_root}
            )
            observed_base = scan_tree(base_root)
        else:
            observed_runtime = scan_tree(expected_root)
            observed_base = observed_runtime
        executable = digest_regular_file(Path(sys.executable).resolve(strict=True))
    except (OSError, ValueError) as error:
        raise DevelopmentRuntimeError("live runtime inventory failed") from error
    for field in ("treeSHA256", "entryCount", "regularFileBytes"):
        if observed_runtime.get(field) != expected_runtime.get(field):
            raise DevelopmentRuntimeError(f"live runtime tree differs: {field}")
        if observed_base.get(field) != expected_base.get(field):
            raise DevelopmentRuntimeError(f"live base Python tree differs: {field}")
    python_record = runtime_manifest.get("python")
    expected_executable = (
        python_record.get("executable")
        if isinstance(python_record, Mapping)
        else None
    )
    if not isinstance(expected_executable, Mapping):
        raise DevelopmentRuntimeError("runtime executable commitment is absent")
    for field in ("bytes", "sha256"):
        if executable.get(field) != expected_executable.get(field):
            raise DevelopmentRuntimeError(f"runtime executable differs: {field}")


def _bounded_command(command: list[str], *, label: str) -> str:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"PATH": CLOSED_PATH, "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DevelopmentRuntimeError(f"cannot inspect {label}") from error
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > 16 * 1024
    ):
        raise DevelopmentRuntimeError(f"cannot inspect {label}")
    try:
        value = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise DevelopmentRuntimeError(f"invalid UTF-8 while inspecting {label}") from error
    if not value or "\x00" in value:
        raise DevelopmentRuntimeError(f"invalid value while inspecting {label}")
    return value


def verify_primary_host_safety(
    design: Mapping[str, Any], *, output_parent: Path
) -> dict[str, Any]:
    """Enforce the registered Mac/power/memory/disk gate before each child."""

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise DevelopmentRuntimeError("development E2E requires macOS arm64")
    execution = design.get("execution")
    if not isinstance(execution, Mapping):
        raise DevelopmentRuntimeError("development execution settings are absent")
    battery = _bounded_command(["/usr/bin/pmset", "-g", "batt"], label="AC power")
    pressure = _bounded_command(
        ["/usr/bin/memory_pressure", "-Q"], label="memory pressure"
    )
    match = re.search(r"free percentage:\s*(\d+)%", pressure)
    ac_power = "AC Power" in battery
    free_percent = int(match.group(1)) if match else None
    if execution.get("acPowerRequired") is True and not ac_power:
        raise DevelopmentRuntimeError("development Mac is not connected to AC power")
    minimum_memory = execution.get("minimumFreeMemoryPercent")
    if (
        type(minimum_memory) is not int
        or type(free_percent) is not int
        or free_percent < minimum_memory
    ):
        raise DevelopmentRuntimeError("free memory is below the development floor")
    candidate = Path(output_parent)
    while not candidate.exists():
        if candidate == candidate.parent:
            raise DevelopmentRuntimeError("cannot resolve output filesystem")
        candidate = candidate.parent
    free_disk = shutil.disk_usage(candidate).free
    minimum_disk = execution.get("minimumFreeDiskBytes")
    if type(minimum_disk) is not int or free_disk < minimum_disk:
        raise DevelopmentRuntimeError("free disk is below the development floor")
    logical_cpu_count = os.cpu_count()
    if type(logical_cpu_count) is not int or logical_cpu_count < 1:
        raise DevelopmentRuntimeError("logical CPU count is unavailable")
    physical_text = _bounded_command(
        ["/usr/sbin/sysctl", "-n", "hw.memsize"], label="physical memory"
    )
    try:
        physical_memory_bytes = int(physical_text, 10)
    except ValueError as error:
        raise DevelopmentRuntimeError("physical memory is not an integer") from error
    if physical_memory_bytes < 1:
        raise DevelopmentRuntimeError("physical memory is invalid")
    executable = digest_regular_file(Path(sys.executable).resolve(strict=True))
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "osProductVersion": _bounded_command(
            ["/usr/bin/sw_vers", "-productVersion"], label="macOS product version"
        ),
        "osBuildVersion": _bounded_command(
            ["/usr/bin/sw_vers", "-buildVersion"], label="macOS build version"
        ),
        "kernelRelease": platform.release(),
        "kernelVersion": platform.version(),
        "cpuBrand": _bounded_command(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
            label="CPU brand",
        ),
        "logicalCPUCount": logical_cpu_count,
        "physicalMemoryBytes": physical_memory_bytes,
        "pythonVersion": platform.python_version(),
        "pythonExecutableSHA256": executable["sha256"],
        "effectiveExecutionEnvironment": closed_environment(execution),
        "acPower": ac_power,
        "freeMemoryPercent": free_percent,
        "freeDiskBytes": free_disk,
    }


def networkless_macos_command(command: list[str]) -> list[str]:
    """Wrap a child in the macOS network-deny sandbox before Python starts."""

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise DevelopmentRuntimeError(
            "development networkless child requires macOS arm64"
        )
    if not isinstance(command, list) or any(
        not isinstance(argument, str) or "\x00" in argument for argument in command
    ):
        raise DevelopmentRuntimeError("development child command is invalid")
    try:
        observed = digest_regular_file(MACOS_SANDBOX_EXEC)
    except (OSError, ValueError) as error:
        raise DevelopmentRuntimeError(
            "macOS sandbox executor is unavailable"
        ) from error
    if observed["bytes"] <= 0 or not observed["sha256"]:
        raise DevelopmentRuntimeError("macOS sandbox executor is unavailable")
    return [
        str(MACOS_SANDBOX_EXEC),
        "-p",
        NETWORK_DENY_PROFILE,
        *command,
    ]


def process_group_usage(process_group_id: int) -> tuple[int, tuple[int, ...]]:
    """Return aggregate RSS bytes and sorted member PIDs for one process group."""

    try:
        completed = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,rss="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise DevelopmentRuntimeError(
            "worker process-group observation failed"
        ) from error
    if completed.returncode != 0:
        raise DevelopmentRuntimeError(
            "worker process-group observation failed: "
            f"ps exit {completed.returncode}: {completed.stderr.strip()[:256]}"
        )
    total_kibibytes = 0
    members: list[int] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not field.isdigit() for field in fields):
            raise DevelopmentRuntimeError(
                "worker process-group observation was malformed"
            )
        process_id, observed_group, rss_kibibytes = map(int, fields)
        if observed_group == process_group_id:
            members.append(process_id)
            total_kibibytes += rss_kibibytes
    return total_kibibytes * 1024, tuple(sorted(members))


def terminate_process_group(process: subprocess.Popen[Any]) -> None:
    """Terminate a worker session and prove that no descendants survived."""

    group_exists = True
    observation_error: DevelopmentRuntimeError | None = None
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _rss, members = process_group_usage(process.pid)
            if not members:
                group_exists = False
                break
            time.sleep(0.05)
    except DevelopmentRuntimeError as error:
        observation_error = error
    finally:
        if group_exists:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                group_exists = False
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise DevelopmentRuntimeError(
                "worker process did not exit after SIGKILL"
            ) from error
    if group_exists:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _rss, members = process_group_usage(process.pid)
            if not members:
                return
            time.sleep(0.05)
        raise DevelopmentRuntimeError("worker process group survived SIGKILL")
    if observation_error is not None:
        raise DevelopmentRuntimeError(
            "worker process group required SIGKILL after an observation failure"
        ) from observation_error


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise DevelopmentRuntimeError("worker evidence path is not canonical")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or any(part in ("", ".") for part in relative.parts)
        or str(relative) != value
    ):
        raise DevelopmentRuntimeError("worker evidence path escapes its root")
    return relative


def _safe_model_key(value: str) -> str:
    relative = _safe_relative(value)
    if len(relative.parts) != 1:
        raise DevelopmentRuntimeError("worker model key is not one path component")
    return value


def consolidate_worker_evidence(
    *, result_root: Path, model_order: Iterable[str]
) -> tuple[Path, Path, Path, list[str]]:
    """Merge canonical worker JSONL and move declared containers into the root."""

    result_root = Path(result_root)
    raw_records: list[dict[str, Any]] = []
    container_records: list[dict[str, Any]] = []
    page_token_records: list[dict[str, Any]] = []
    manifest_paths: list[str] = []
    try:
        for model_key_value in model_order:
            model_key = _safe_model_key(model_key_value)
            worker_root = result_root / "workers" / model_key
            raw_path = worker_root / "raw-token-evidence.jsonl"
            container_path = worker_root / "container-evidence.jsonl"
            page_token_path = worker_root / "page-token-evidence.jsonl"
            raw_records.extend(
                load_canonical_jsonl(raw_path, maximum_bytes=128 * 1024 * 1024)
            )
            records = load_canonical_jsonl(
                container_path, maximum_bytes=64 * 1024 * 1024
            )
            container_records.extend(records)
            page_token_records.extend(
                load_canonical_jsonl(
                    page_token_path, maximum_bytes=16 * 1024 * 1024
                )
            )
            for record in records:
                relative = _safe_relative(record.get("relativePath"))
                source = worker_root.joinpath(*relative.parts)
                destination = result_root.joinpath(*relative.parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    raise DevelopmentRuntimeError(
                        "duplicate consolidated container path"
                    )
                os.replace(source, destination)
                manifest_paths.append(relative.as_posix())

        raw_final = result_root / "raw-token-evidence.jsonl"
        containers_final = result_root / "container-evidence.jsonl"
        page_tokens_final = result_root / "page-token-evidence.jsonl"
        write_new_bytes(
            raw_final,
            b"".join(canonical_json_line(item) for item in raw_records),
        )
        write_new_bytes(
            containers_final,
            b"".join(canonical_json_line(item) for item in container_records),
        )
        write_new_bytes(
            page_tokens_final,
            b"".join(canonical_json_line(item) for item in page_token_records),
        )
    except DevelopmentRuntimeError:
        raise
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise DevelopmentRuntimeError(
            "worker evidence consolidation failed"
        ) from error
    return raw_final, containers_final, page_tokens_final, manifest_paths
