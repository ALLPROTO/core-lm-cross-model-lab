#!/usr/bin/env python3
"""Deterministic, dependency-free provenance helpers for blind-v2.

These helpers inventory already materialized bytes.  They do not perform
network access, import model runtimes, load model weights, or create a
scientific attempt marker.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


READ_CHUNK_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
FILE_MODE = re.compile(r"[0-7]{4}\Z")
RUNTIME_MANIFEST_SCHEMA = "corelm-crossmodel-livewiki-v2-runtime-manifest-v1"
RUNTIME_MANIFEST_FIELDS = {
    "schemaVersion",
    "status",
    "countsTowardScientificVerdict",
    "networkUsed",
    "modelInferenceUsed",
    "python",
    "host",
    "environment",
    "requirementsLocks",
    "installedDistributions",
    "installedDistributionCount",
    "runtimeTree",
    "basePythonTree",
    "basePythonDistinctFromRuntime",
    "labSource",
    "codecSource",
    "contentSHA256",
}
RUNTIME_ENVIRONMENT_KEYS = {
    "HF_HUB_DISABLE_TELEMETRY",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "PYTHONHASHSEED",
    "TOKENIZERS_PARALLELISM",
    "TRANSFORMERS_OFFLINE",
}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_regular_file(path: Path) -> dict[str, Any]:
    """Hash one no-follow regular file and detect mutation during the read."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"regular file required: {absolute}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_after != identity_before or size != before.st_size:
            raise ValueError(f"file changed while hashing: {absolute}")
        return {
            "bytes": size,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def verify_expected_file(
    path: Path, *, expected_bytes: int, expected_sha256: str
) -> dict[str, Any]:
    observed = digest_regular_file(path)
    if observed["bytes"] != expected_bytes:
        raise ValueError(
            f"file byte count mismatch: {path}: "
            f"{observed['bytes']} != {expected_bytes}"
        )
    if observed["sha256"] != expected_sha256:
        raise ValueError(f"file SHA-256 mismatch: {path}")
    return observed


def _assert_safe_output_parent(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent = absolute.parent
    current = Path(parent.anchor)
    root_status = os.lstat(current)
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise ValueError(f"unsafe output filesystem anchor: {current}")
    for component in parent.parts[1:]:
        previous = current
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except FileExistsError:
                metadata = os.lstat(current)
            else:
                _fsync_directory(previous)
                metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"unsafe output directory component: {current}")
    return absolute


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_bytes(path: Path, value: bytes) -> None:
    """Durably create a new file without replacing an existing receipt."""

    destination = _assert_safe_output_parent(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    published = False
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing provenance artifact")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _fsync_directory(destination.parent)
        published = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass


def with_content_digest(value: dict[str, Any], *, field: str = "contentSHA256") -> dict[str, Any]:
    if field in value:
        raise ValueError(f"digest field already exists: {field}")
    result = dict(value)
    result[field] = sha256_bytes(canonical_json_bytes(value))
    return result


def verify_content_digest(value: dict[str, Any], *, field: str = "contentSHA256") -> None:
    expected = value.get(field)
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError(f"missing or invalid self-digest: {field}")
    payload = dict(value)
    del payload[field]
    if sha256_bytes(canonical_json_bytes(payload)) != expected:
        raise ValueError(f"self-digest mismatch: {field}")


def _strict_digest_record(value: Any, *, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"bytes", "mode", "sha256"}:
        raise ValueError(f"{label} digest-record fields differ")
    if type(value["bytes"]) is not int or value["bytes"] < 0:
        raise ValueError(f"{label} byte count is invalid")
    if not isinstance(value["mode"], str) or FILE_MODE.fullmatch(value["mode"]) is None:
        raise ValueError(f"{label} file mode is invalid")
    if not isinstance(value["sha256"], str) or SHA256.fullmatch(value["sha256"]) is None:
        raise ValueError(f"{label} SHA-256 is invalid")


def _runtime_relative_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{label} is not canonical POSIX syntax")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise ValueError(f"{label} is not a safe relative path")
    return value


def _runtime_directory_symlink_target(
    path: str, target: Any, *, label: str
) -> str:
    if (
        not isinstance(target, str)
        or not target
        or "\\" in target
        or "\x00" in target
        or PurePosixPath(target).is_absolute()
    ):
        raise ValueError(f"{label} is not a safe relative target")
    components = list(PurePosixPath(path).parent.parts)
    for component in PurePosixPath(target).parts:
        if component in {"", "."}:
            continue
        if component == "..":
            if not components:
                raise ValueError(f"{label} escapes the runtime tree")
            components.pop()
            continue
        components.append(component)
    if not components:
        raise ValueError(f"{label} resolves to the runtime tree root")
    return PurePosixPath(*components).as_posix()


def _verify_runtime_tree(value: Any, *, label: str) -> None:
    fields = {"entries", "entryCount", "regularFileBytes", "treeSHA256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields differ")
    entries = value["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{label} entry inventory is empty")
    paths: list[str] = []
    regular_bytes = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{label} entry {index} is not an object")
        path = _runtime_relative_path(
            entry.get("path"), label=f"{label} entry {index} path"
        )
        paths.append(path)
        kind = entry.get("type")
        if kind == "file":
            if set(entry) != {"path", "type", "bytes", "mode", "sha256"}:
                raise ValueError(f"{label} file entry fields differ: {path}")
            _strict_digest_record(
                {key: entry[key] for key in ("bytes", "mode", "sha256")},
                label=f"{label} file entry {path}",
            )
            regular_bytes += entry["bytes"]
        elif kind == "symlink":
            allowed = {
                "path",
                "type",
                "target",
                "resolvedTarget",
                "absoluteTargetSHA256",
            }
            required = {"path", "type", "target", "resolvedTarget"}
            if not required.issubset(entry) or not set(entry).issubset(allowed):
                raise ValueError(f"{label} symlink entry fields differ: {path}")
            target = entry["target"]
            if not isinstance(target, str) or not target or "\x00" in target:
                raise ValueError(f"{label} symlink target is invalid: {path}")
            _strict_digest_record(
                entry["resolvedTarget"], label=f"{label} symlink target {path}"
            )
            absolute_digest = entry.get("absoluteTargetSHA256")
            if target == "<absolute-external-target>":
                if (
                    not isinstance(absolute_digest, str)
                    or SHA256.fullmatch(absolute_digest) is None
                ):
                    raise ValueError(
                        f"{label} absolute symlink target digest is absent: {path}"
                    )
            elif "absoluteTargetSHA256" in entry:
                raise ValueError(
                    f"{label} non-absolute symlink has an absolute target digest: {path}"
                )
        elif kind == "directory-symlink":
            if set(entry) != {
                "path",
                "type",
                "target",
                "resolvedDirectory",
            }:
                raise ValueError(
                    f"{label} directory-symlink entry fields differ: {path}"
                )
            expected_directory = _runtime_directory_symlink_target(
                path,
                entry["target"],
                label=f"{label} directory-symlink target {path}",
            )
            observed_directory = _runtime_relative_path(
                entry["resolvedDirectory"],
                label=f"{label} directory-symlink resolved target {path}",
            )
            if observed_directory != expected_directory:
                raise ValueError(
                    f"{label} directory-symlink target binding differs: {path}"
                )
        else:
            raise ValueError(f"{label} entry type is unsupported: {path}")
    if len(paths) != len(set(paths)):
        raise ValueError(f"{label} contains duplicate paths")
    if paths != sorted(paths, key=os.fsencode):
        raise ValueError(f"{label} paths are not in canonical byte order")
    if value["entryCount"] != len(entries):
        raise ValueError(f"{label} entryCount differs from entries")
    if value["regularFileBytes"] != regular_bytes:
        raise ValueError(f"{label} regularFileBytes differs from entries")
    expected_digest = sha256_bytes(canonical_json_bytes(entries))
    if value["treeSHA256"] != expected_digest:
        raise ValueError(f"{label} treeSHA256 differs from entries")


def _verify_runtime_source(value: Any, *, label: str) -> None:
    fields = {
        "commit",
        "tree",
        "origin",
        "worktreeClean",
        "worktreeStatusSHA256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields differ")
    for field in ("commit", "tree"):
        if not isinstance(value[field], str) or GIT_OID.fullmatch(value[field]) is None:
            raise ValueError(f"{label} {field} is not a full Git OID")
    if value["origin"] is not None and (
        not isinstance(value["origin"], str) or not value["origin"]
    ):
        raise ValueError(f"{label} origin is invalid")
    if type(value["worktreeClean"]) is not bool:
        raise ValueError(f"{label} worktreeClean is not boolean")
    status_digest = value["worktreeStatusSHA256"]
    if not isinstance(status_digest, str) or SHA256.fullmatch(status_digest) is None:
        raise ValueError(f"{label} worktree status digest is invalid")
    if value["worktreeClean"] and status_digest != sha256_bytes(b""):
        raise ValueError(f"{label} clean worktree has a non-empty status digest")


def verify_runtime_manifest_integrity(value: Any) -> None:
    """Strictly recompute one complete runtime manifest's internal inventory."""

    if not isinstance(value, dict) or set(value) != RUNTIME_MANIFEST_FIELDS:
        raise ValueError("runtime manifest fields differ")
    verify_content_digest(value)
    if (
        value["schemaVersion"] != RUNTIME_MANIFEST_SCHEMA
        or value["status"] != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY"
        or any(
            value[field] is not False
            for field in (
                "countsTowardScientificVerdict",
                "networkUsed",
                "modelInferenceUsed",
            )
        )
    ):
        raise ValueError("runtime manifest provenance boundary differs")

    python = value["python"]
    python_fields = {
        "registeredVersion",
        "version",
        "versionDetail",
        "implementation",
        "cacheTag",
        "byteorder",
        "executable",
        "soabi",
        "multiarch",
        "platformTag",
    }
    if not isinstance(python, dict) or set(python) != python_fields:
        raise ValueError("runtime Python fields differ")
    for field in (
        "registeredVersion",
        "version",
        "versionDetail",
        "implementation",
        "cacheTag",
        "platformTag",
    ):
        if not isinstance(python[field], str) or not python[field]:
            raise ValueError(f"runtime Python {field} is invalid")
    if python["byteorder"] not in {"little", "big"}:
        raise ValueError("runtime Python byteorder is invalid")
    for field in ("soabi", "multiarch"):
        if python[field] is not None and not isinstance(python[field], str):
            raise ValueError(f"runtime Python {field} is invalid")
    _strict_digest_record(python["executable"], label="runtime Python executable")

    host = value["host"]
    host_fields = {"system", "release", "version", "machine", "processor", "macVersion"}
    if not isinstance(host, dict) or set(host) != host_fields:
        raise ValueError("runtime host fields differ")
    for field in ("system", "release", "version", "machine"):
        if not isinstance(host[field], str) or not host[field]:
            raise ValueError(f"runtime host {field} is invalid")
    if not isinstance(host["processor"], str):
        raise ValueError("runtime host processor is invalid")
    if host["macVersion"] is not None and not isinstance(host["macVersion"], str):
        raise ValueError("runtime host macVersion is invalid")

    environment = value["environment"]
    if (
        not isinstance(environment, dict)
        or set(environment) != RUNTIME_ENVIRONMENT_KEYS
        or any(item is not None and not isinstance(item, str) for item in environment.values())
    ):
        raise ValueError("runtime environment inventory differs")

    locks = value["requirementsLocks"]
    if not isinstance(locks, list) or not locks:
        raise ValueError("runtime requirements lock inventory is empty")
    lock_names: list[str] = []
    for lock in locks:
        if not isinstance(lock, dict) or set(lock) != {"name", "bytes", "sha256"}:
            raise ValueError("runtime requirements lock fields differ")
        name = lock["name"]
        if not isinstance(name, str) or not name or "/" in name or "\\" in name:
            raise ValueError("runtime requirements lock name is invalid")
        if type(lock["bytes"]) is not int or lock["bytes"] <= 0:
            raise ValueError("runtime requirements lock byte count is invalid")
        if not isinstance(lock["sha256"], str) or SHA256.fullmatch(lock["sha256"]) is None:
            raise ValueError("runtime requirements lock SHA-256 is invalid")
        lock_names.append(name)
    if len(lock_names) != len(set(lock_names)) or lock_names != sorted(lock_names):
        raise ValueError("runtime requirements locks are duplicated or unsorted")

    distributions = value["installedDistributions"]
    if not isinstance(distributions, list) or not distributions:
        raise ValueError("runtime distribution inventory is empty")
    distribution_fields = {
        "name",
        "normalizedName",
        "version",
        "metadataSHA256",
        "recordSHA256",
        "declaredFiles",
        "licenseExpression",
        "licenseDeclared",
        "requiresDist",
    }
    identities: list[tuple[str, str]] = []
    normalized_names: set[str] = set()
    for distribution in distributions:
        if not isinstance(distribution, dict) or set(distribution) != distribution_fields:
            raise ValueError("runtime distribution fields differ")
        name = distribution["name"]
        normalized = distribution["normalizedName"]
        version = distribution["version"]
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(normalized, str)
            or normalized != name.lower().replace("_", "-")
            or not isinstance(version, str)
            or not version
            or normalized in normalized_names
        ):
            raise ValueError("runtime distribution identity is invalid or duplicated")
        normalized_names.add(normalized)
        identities.append((normalized, version))
        for field in ("metadataSHA256", "recordSHA256"):
            digest = distribution[field]
            if digest is not None and (
                not isinstance(digest, str) or SHA256.fullmatch(digest) is None
            ):
                raise ValueError(f"runtime distribution {field} is invalid")
        if type(distribution["declaredFiles"]) is not int or distribution["declaredFiles"] < 0:
            raise ValueError("runtime distribution declaredFiles is invalid")
        for field in ("licenseExpression", "licenseDeclared"):
            if distribution[field] is not None and not isinstance(distribution[field], str):
                raise ValueError(f"runtime distribution {field} is invalid")
        requirements = distribution["requiresDist"]
        if (
            not isinstance(requirements, list)
            or any(not isinstance(item, str) or not item for item in requirements)
            or requirements != sorted(requirements)
        ):
            raise ValueError("runtime distribution requirements are invalid or unsorted")
    if identities != sorted(identities):
        raise ValueError("runtime distributions are not in canonical order")
    if value["installedDistributionCount"] != len(distributions):
        raise ValueError("runtime installedDistributionCount differs")

    _verify_runtime_tree(value["runtimeTree"], label="runtimeTree")
    _verify_runtime_tree(value["basePythonTree"], label="basePythonTree")
    distinct = value["basePythonDistinctFromRuntime"]
    if type(distinct) is not bool:
        raise ValueError("runtime basePythonDistinctFromRuntime is not boolean")
    if not distinct and value["runtimeTree"] != value["basePythonTree"]:
        raise ValueError("runtime/base Python trees differ despite a shared prefix")
    _verify_runtime_source(value["labSource"], label="runtime labSource")
    _verify_runtime_source(value["codecSource"], label="runtime codecSource")


def scan_tree(
    root: Path, *, external_roots: dict[str, Path] | None = None
) -> dict[str, Any]:
    """Inventory every regular file and symlink beneath one existing root."""

    lexical_root = Path(os.path.abspath(os.fspath(root)))
    root_status = os.lstat(lexical_root)
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise ValueError(f"tree root must be a non-symlink directory: {lexical_root}")
    # macOS exposes ordinary temporary paths through the system /var ->
    # /private/var parent symlink.  Canonicalize only after rejecting a symlink
    # at the caller-selected root itself, then use that one physical identity
    # for traversal and all containment comparisons.
    absolute = lexical_root.resolve(strict=True)

    normalized_external_roots = {
        label: path.resolve(strict=True)
        for label, path in (external_roots or {}).items()
    }
    entries: list[dict[str, Any]] = []
    stack: list[tuple[Path, Path]] = [(absolute, Path())]
    while stack:
        directory, relative_directory = stack.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: os.fsencode(item.name))
        for child in children:
            relative = relative_directory / child.name
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                stack.append((Path(child.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                entries.append(
                    {
                        "path": relative.as_posix(),
                        "type": "file",
                        **digest_regular_file(Path(child.path)),
                    }
                )
            elif stat.S_ISLNK(metadata.st_mode):
                raw_target = os.readlink(child.path)
                item: dict[str, Any] = {
                    "path": relative.as_posix(),
                    "type": "symlink",
                }
                resolved = Path(child.path).resolve(strict=True)
                resolved_status = os.stat(resolved)
                if stat.S_ISDIR(resolved_status.st_mode):
                    expected_relative = _runtime_directory_symlink_target(
                        relative.as_posix(),
                        raw_target,
                        label=f"runtime directory symlink target {child.path}",
                    )
                    try:
                        resolved_relative = resolved.relative_to(absolute)
                    except ValueError as error:
                        raise ValueError(
                            "runtime directory symlink must remain inside the tree: "
                            f"{child.path}"
                        ) from error
                    if not resolved_relative.parts:
                        raise ValueError(
                            "runtime directory symlink cannot resolve to the tree root: "
                            f"{child.path}"
                        )
                    if resolved_relative.as_posix() != expected_relative:
                        raise ValueError(
                            "runtime directory symlink traverses another symlink: "
                            f"{child.path}"
                        )
                    item["type"] = "directory-symlink"
                    item["target"] = raw_target
                    item["resolvedDirectory"] = resolved_relative.as_posix()
                    entries.append(item)
                    continue
                if not stat.S_ISREG(resolved_status.st_mode):
                    raise ValueError(
                        f"runtime symlink must resolve to a file or directory: {child.path}"
                    )
                if os.path.isabs(raw_target):
                    normalized_target = None
                    for label, external_root in sorted(
                        normalized_external_roots.items()
                    ):
                        try:
                            relative_target = resolved.relative_to(external_root)
                        except ValueError:
                            continue
                        normalized_target = f"<{label}>/{relative_target.as_posix()}"
                        break
                    if normalized_target is None:
                        item["target"] = "<absolute-external-target>"
                        item["absoluteTargetSHA256"] = sha256_bytes(
                            os.fsencode(raw_target)
                        )
                    else:
                        item["target"] = normalized_target
                else:
                    item["target"] = raw_target
                item["resolvedTarget"] = digest_regular_file(resolved)
                entries.append(item)
            else:
                raise ValueError(f"unsupported file type in runtime tree: {child.path}")

    entries.sort(key=lambda item: os.fsencode(item["path"]))
    total_regular_bytes = sum(
        int(item["bytes"]) for item in entries if item["type"] == "file"
    )
    return {
        "entries": entries,
        "entryCount": len(entries),
        "regularFileBytes": total_regular_bytes,
        "treeSHA256": sha256_bytes(canonical_json_bytes(entries)),
    }


def ensure_unique_strings(values: Iterable[str], *, label: str) -> list[str]:
    result = list(values)
    if len(result) != len(set(result)):
        raise ValueError(f"duplicate values in {label}")
    return result
