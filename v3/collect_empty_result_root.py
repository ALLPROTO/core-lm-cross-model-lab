#!/usr/bin/env python3
"""Create a bounded post-deadline empty-result-root observation and audit report."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.experiment_closeout import (
    ExperimentCloseoutError,
    collect_empty_result_root_observation,
)


OBSERVATION_NAME = "empty-result-root-observation.json"
AUDIT_REPORT_NAME = "empty-result-root-audit-report.json"
MAXIMUM_HOST_ENVIRONMENT_BYTES = 64 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _safe_read(path: Path) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAXIMUM_HOST_ENVIRONMENT_BYTES
        ):
            raise ExperimentCloseoutError("host environment type or size is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAXIMUM_HOST_ENVIRONMENT_BYTES:
                raise ExperimentCloseoutError("host environment exceeds its byte bound")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or observed != before.st_size
        ):
            raise ExperimentCloseoutError("host environment changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_exclusive(directory: Path, name: str, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(directory / name, flags, 0o444)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ExperimentCloseoutError("audit output write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def collect_to_directory(
    *,
    result_root: Path,
    host_environment_path: Path,
    auditor_identity: str,
    output_directory: Path,
) -> tuple[Path, Path]:
    if output_directory.exists() or output_directory.is_symlink():
        raise ExperimentCloseoutError("audit output already exists")
    host_environment_raw = _safe_read(host_environment_path)
    observation_raw, report_raw = collect_empty_result_root_observation(
        result_root=result_root,
        host_environment_raw=host_environment_raw,
        auditor_identity=auditor_identity,
        now=_utc_now,
    )
    output_directory.mkdir(mode=0o755, parents=False)
    _write_exclusive(output_directory, AUDIT_REPORT_NAME, report_raw)
    _write_exclusive(output_directory, OBSERVATION_NAME, observation_raw)
    descriptor = os.open(
        output_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return output_directory / OBSERVATION_NAME, output_directory / AUDIT_REPORT_NAME


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--host-environment", type=Path, required=True)
    parser.add_argument("--auditor-identity", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        observation, report = collect_to_directory(
            result_root=args.result_root,
            host_environment_path=args.host_environment,
            auditor_identity=args.auditor_identity,
            output_directory=args.output_directory,
        )
    except (ExperimentCloseoutError, OSError, ValueError):
        print("empty-result-root audit failed (fail-closed)", file=sys.stderr)
        return 2
    print(f"empty-result-root audit created: {observation} {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUDIT_REPORT_NAME",
    "OBSERVATION_NAME",
    "collect_to_directory",
]
