#!/usr/bin/env python3
"""Resolve and validate the current process cgroup without host-root drift."""

from __future__ import annotations

import argparse
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


PROC_CGROUP = Path("/proc/self/cgroup")
PROC_MOUNTINFO = Path("/proc/self/mountinfo")
MAX_PROC_BYTES = 4 * 1024 * 1024
MAX_COUNTER_BYTES = 128


class CgroupContractError(ValueError):
    """A cgroup topology or counter violates the admitted contract."""


@dataclass(frozen=True)
class CgroupLayout:
    version: str
    cpu_directory: Path
    memory_directory: Path


@dataclass(frozen=True)
class CgroupObservation:
    version: str
    cpu_quota: int | None
    cpu_period: int
    memory_current: int
    memory_peak: int
    memory_limit: int | None


@dataclass(frozen=True)
class _Mount:
    root: PurePosixPath
    point: Path
    filesystem: str
    controllers: frozenset[str]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CgroupContractError(message)


def _read_bounded(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CgroupContractError(f"cannot open {path}") from error
    try:
        status = os.fstat(descriptor)
        _require(stat.S_ISREG(status.st_mode), f"{path} is not a regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        result = b"".join(chunks)
        _require(len(result) <= maximum, f"{path} exceeds the byte limit")
        return result
    finally:
        os.close(descriptor)


def _ascii_file(path: Path, maximum: int) -> str:
    try:
        return _read_bounded(path, maximum).decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise CgroupContractError(f"{path} is not ASCII") from error


def _absolute_kernel_path(raw: str, label: str) -> PurePosixPath:
    _require(raw.startswith("/"), f"{label} is not absolute")
    path = PurePosixPath(raw)
    _require(str(path) == raw, f"{label} is not canonical")
    _require(".." not in path.parts and "." not in path.parts, f"{label} escapes")
    return path


def _decode_mount_field(raw: str) -> str:
    replacements = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}

    def replace(match: re.Match[str]) -> str:
        code = match.group(1)
        _require(code in replacements, "mountinfo contains an unknown escape")
        return replacements[code]

    decoded = re.sub(r"\\([0-9]{3})", replace, raw)
    _require("\\" not in decoded, "mountinfo contains an unsafe backslash")
    _require("\n" not in decoded and "\r" not in decoded, "mountinfo path is multiline")
    return decoded


def _parse_self_paths(raw: str) -> tuple[PurePosixPath | None, dict[str, PurePosixPath]]:
    unified: PurePosixPath | None = None
    controllers: dict[str, PurePosixPath] = {}
    lines = raw.splitlines()
    _require(lines, "the self cgroup file is empty")
    for line in lines:
        fields = line.split(":", 2)
        _require(len(fields) == 3, "the self cgroup grammar differs")
        hierarchy, names, path_raw = fields
        _require(hierarchy.isascii() and hierarchy.isdigit(), "cgroup hierarchy is invalid")
        path = _absolute_kernel_path(path_raw, "self cgroup path")
        if hierarchy == "0" and names == "":
            _require(unified is None, "multiple unified cgroup paths exist")
            unified = path
            continue
        _require(names != "", "a legacy cgroup controller list is empty")
        for name in names.split(","):
            _require(
                re.fullmatch(r"(?:name=)?[A-Za-z0-9_.-]+", name) is not None,
                "a legacy cgroup controller name is invalid",
            )
            _require(name not in controllers, "a legacy cgroup controller is duplicated")
            controllers[name] = path
    return unified, controllers


def _parse_mounts(raw: str) -> tuple[_Mount, ...]:
    mounts: list[_Mount] = []
    lines = raw.splitlines()
    _require(lines, "mountinfo is empty")
    for line in lines:
        halves = line.split(" - ")
        _require(len(halves) == 2, "mountinfo separator differs")
        before = halves[0].split()
        after = halves[1].split()
        _require(len(before) >= 6 and len(after) >= 3, "mountinfo grammar differs")
        filesystem = after[0]
        if filesystem not in {"cgroup", "cgroup2"}:
            continue
        root_raw = _decode_mount_field(before[3])
        point_raw = _decode_mount_field(before[4])
        root = _absolute_kernel_path(root_raw, "cgroup mount root")
        point_kernel = _absolute_kernel_path(point_raw, "cgroup mount point")
        controllers = frozenset(after[2].split(",")) if filesystem == "cgroup" else frozenset()
        mounts.append(
            _Mount(
                root=root,
                point=Path(str(point_kernel)),
                filesystem=filesystem,
                controllers=controllers,
            )
        )
    _require(mounts, "no cgroup filesystem is mounted")
    return tuple(mounts)


def _resolve_mount(
    mount: _Mount,
    self_path: PurePosixPath,
    counter_names: tuple[str, ...],
) -> Path:
    """Resolve both private-namespace and host-relative cgroup coordinates."""

    candidates: set[Path] = set()

    # In a private cgroup namespace, /proc/self/cgroup is namespace-relative.
    # A self path of / therefore denotes the mount point even when mountinfo's
    # root retains the underlying host path (for example /docker/<id>).
    candidates.add(mount.point.joinpath(*self_path.parts[1:]))

    # In a host cgroup namespace the self path and the mount root share host
    # coordinates.  Strip the mount root before appending the relative suffix.
    root_parts = mount.root.parts
    self_parts = self_path.parts
    if len(self_parts) >= len(root_parts) and self_parts[: len(root_parts)] == root_parts:
        candidates.add(mount.point.joinpath(*self_parts[len(root_parts) :]))

    admitted: set[Path] = set()
    for target in candidates:
        try:
            resolved = target.resolve(strict=True)
        except OSError:
            continue
        if resolved != target or not target.is_dir() or target.is_symlink():
            continue
        if all(
            path.is_file() and not path.is_symlink()
            for path in (target / name for name in counter_names)
        ):
            admitted.add(target)
    _require(len(admitted) == 1, "the current cgroup directory is absent or ambiguous")
    return admitted.pop()


def resolve_layout(cgroup_text: str, mountinfo_text: str) -> CgroupLayout:
    unified, self_paths = _parse_self_paths(cgroup_text)
    mounts = _parse_mounts(mountinfo_text)
    candidates: list[CgroupLayout] = []

    if unified is not None:
        unified_mounts = [mount for mount in mounts if mount.filesystem == "cgroup2"]
        _require(len(unified_mounts) <= 1, "multiple cgroup v2 mounts exist")
        if unified_mounts:
            directory = _resolve_mount(
                unified_mounts[0],
                unified,
                ("cpu.max", "memory.current", "memory.peak", "memory.max"),
            )
            candidates.append(CgroupLayout("v2", directory, directory))

    if "cpu" in self_paths and "memory" in self_paths:
        cpu_mounts = [
            mount
            for mount in mounts
            if mount.filesystem == "cgroup" and "cpu" in mount.controllers
        ]
        memory_mounts = [
            mount
            for mount in mounts
            if mount.filesystem == "cgroup" and "memory" in mount.controllers
        ]
        _require(len(cpu_mounts) <= 1, "multiple cgroup v1 CPU mounts exist")
        _require(len(memory_mounts) <= 1, "multiple cgroup v1 memory mounts exist")
        if cpu_mounts and memory_mounts:
            cpu_directory = _resolve_mount(
                cpu_mounts[0],
                self_paths["cpu"],
                ("cpu.cfs_quota_us", "cpu.cfs_period_us"),
            )
            memory_directory = _resolve_mount(
                memory_mounts[0],
                self_paths["memory"],
                (
                    "memory.usage_in_bytes",
                    "memory.max_usage_in_bytes",
                    "memory.limit_in_bytes",
                ),
            )
            candidates.append(CgroupLayout("v1", cpu_directory, memory_directory))

    _require(len(candidates) == 1, "the current cgroup hierarchy is absent or ambiguous")
    return candidates[0]


def _counter(path: Path, *, allow_max: bool = False, allow_minus_one: bool = False) -> int | None:
    raw = _ascii_file(path, MAX_COUNTER_BYTES).strip()
    if allow_max and raw == "max":
        return None
    if allow_minus_one and raw == "-1":
        return None
    _require(re.fullmatch(r"[0-9]+", raw) is not None, f"{path.name} is invalid")
    return int(raw)


def observe(
    cgroup_path: Path = PROC_CGROUP,
    mountinfo_path: Path = PROC_MOUNTINFO,
) -> CgroupObservation:
    layout = resolve_layout(
        _ascii_file(cgroup_path, MAX_PROC_BYTES),
        _ascii_file(mountinfo_path, MAX_PROC_BYTES),
    )
    if layout.version == "v2":
        cpu_raw = _ascii_file(layout.cpu_directory / "cpu.max", MAX_COUNTER_BYTES).strip()
        fields = cpu_raw.split()
        _require(len(fields) == 2, "cpu.max grammar differs")
        quota_raw, period_raw = fields
        if quota_raw == "max":
            quota = None
        else:
            _require(quota_raw.isascii() and quota_raw.isdigit(), "cpu.max quota is invalid")
            quota = int(quota_raw)
        _require(period_raw.isascii() and period_raw.isdigit(), "cpu.max period is invalid")
        period = int(period_raw)
        current = _counter(layout.memory_directory / "memory.current")
        peak = _counter(layout.memory_directory / "memory.peak")
        limit = _counter(layout.memory_directory / "memory.max", allow_max=True)
    else:
        quota = _counter(layout.cpu_directory / "cpu.cfs_quota_us", allow_minus_one=True)
        period = _counter(layout.cpu_directory / "cpu.cfs_period_us")
        current = _counter(layout.memory_directory / "memory.usage_in_bytes")
        peak = _counter(layout.memory_directory / "memory.max_usage_in_bytes")
        limit = _counter(layout.memory_directory / "memory.limit_in_bytes")
    _require(isinstance(period, int) and period > 0, "cgroup CPU period is invalid")
    _require(quota is None or quota > 0, "cgroup CPU quota is invalid")
    _require(isinstance(current, int) and isinstance(peak, int), "cgroup memory counters differ")
    _require(peak >= current, "cgroup memory peak is below current usage")
    _require(limit is None or limit >= peak, "cgroup memory limit is below observed usage")
    return CgroupObservation(layout.version, quota, period, current, peak, limit)


def admit(observation: CgroupObservation, minimum_cpu_cores: int, minimum_memory_bytes: int) -> None:
    _require(minimum_cpu_cores > 0 and minimum_memory_bytes > 0, "minimum resources are invalid")
    if observation.cpu_quota is not None:
        _require(
            observation.cpu_quota >= minimum_cpu_cores * observation.cpu_period,
            "cgroup CPU quota is below the minimum",
        )
    if observation.memory_limit is not None:
        _require(
            observation.memory_limit >= minimum_memory_bytes,
            "cgroup memory limit is below the minimum",
        )


def memory_evidence() -> dict[str, int | None]:
    observation = observe()
    return {
        "cgroupMemoryCurrentBytesAtCompletion": observation.memory_current,
        "cgroupMemoryPeakBytesAtCompletion": observation.memory_peak,
        "cgroupMemoryLimitBytes": observation.memory_limit,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("admission",))
    parser.add_argument("--minimum-cpu-cores", type=int, required=True)
    parser.add_argument("--minimum-memory-bytes", type=int, required=True)
    arguments = parser.parse_args()
    observation = observe()
    admit(observation, arguments.minimum_cpu_cores, arguments.minimum_memory_bytes)
    quota = "max" if observation.cpu_quota is None else str(observation.cpu_quota)
    limit = "max" if observation.memory_limit is None else str(observation.memory_limit)
    print("\t".join((observation.version, quota, str(observation.cpu_period), limit)))


if __name__ == "__main__":
    try:
        main()
    except CgroupContractError as error:
        raise SystemExit(f"CGROUP CONTRACT FAIL: {error}") from error
