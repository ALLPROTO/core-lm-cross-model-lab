#!/usr/bin/env python3
"""Build, verify, and safely extract the four public evidence-release assets.

The input evidence directory is the already sealed output of
``package_evidence_release.py``.  This outer layer does not reinterpret the
scientific result.  It binds that exact directory to its external package
verifier report and emits the four roles required by ``release_receipt.py``:

* evidence-package
* evidence-release-manifest
* evidence-package-verifier-report
* sha256-manifest

The evidence package is an uncompressed deterministic POSIX USTAR stream.  It
contains regular files only, in UTF-8 byte order, with uid/gid/mtime zero,
empty owner names, and mode 0444.  Verification compares every raw header to
the canonical header it would have generated and streams every body through a
bounded SHA-256 calculation.  No generic archive extraction API is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping, Sequence


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
INNER_MANIFEST_SCHEMA = (
    "corelm-crossmodel-livewiki-v3-evidence-release-manifest-v1"
)
INNER_REPORT_SCHEMA = (
    "corelm-crossmodel-livewiki-v3-evidence-release-verification-v1"
)
SHA256_MANIFEST_SCHEMA = (
    "corelm-crossmodel-livewiki-v3-evidence-release-sha256-manifest-v1"
)
VERIFICATION_SCHEMA = (
    "corelm-crossmodel-livewiki-v3-evidence-assets-verification-v1"
)

INNER_MANIFEST_NAME = "evidence-release-manifest.json"
ASSET_NAMES: dict[str, str] = {
    "evidence-package": "evidence-package.tar",
    "evidence-release-manifest": INNER_MANIFEST_NAME,
    "evidence-package-verifier-report": "evidence-package-verifier-report.json",
    "sha256-manifest": "sha256-manifest.json",
}
ASSET_ROLES = tuple(ASSET_NAMES)
MANIFEST_ROLES = tuple(
    role for role in ASSET_ROLES if role != "sha256-manifest"
)

READ_CHUNK_BYTES = 1024 * 1024
TAR_BLOCK_BYTES = 512
TAR_RECORD_BYTES = 20 * TAR_BLOCK_BYTES
MAXIMUM_ENTRY_COUNT = 250_000
MAXIMUM_MEMBER_BYTES = (1 << 33) - 1
MAXIMUM_TOTAL_BYTES = 2 * 1024**4
MAXIMUM_MANIFEST_BYTES = 512 * 1024**2
MAXIMUM_REPORT_BYTES = 64 * 1024**2
MAXIMUM_SHA256_MANIFEST_BYTES = 16 * 1024**2
MAXIMUM_PATH_BYTES = 255

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
UTC_SECOND = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
WINDOWS_RESERVED = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z",
    re.IGNORECASE,
)

INNER_MANIFEST_FIELDS = {
    "schemaVersion",
    "suiteId",
    "attemptId",
    "createdAt",
    "packageStatus",
    "recoveryClassification",
    "terminalState",
    "attemptCountsTowardScientificVerdict",
    "artifactPresence",
    "forensicArtifacts",
    "missingArtifacts",
    "groups",
    "entries",
    "entryCount",
    "totalBytes",
    "entriesSHA256",
    "contentSHA256",
}
INNER_REPORT_FIELDS = {
    "schemaVersion",
    "status",
    "suiteId",
    "attemptId",
    "recoveryClassification",
    "terminalState",
    "attemptCountsTowardScientificVerdict",
    "entryCount",
    "totalBytes",
    "manifestFileSHA256",
    "manifestContentSHA256",
    "missingArtifacts",
    "forensicArtifacts",
    "contentSHA256",
}


class EvidenceAssetError(ValueError):
    """The outer evidence assets are unsafe, noncanonical, or inconsistent."""


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    path: Path
    bytes: int
    sha256: str
    identity: tuple[int, ...]


@dataclass(frozen=True)
class AssetRecord:
    role: str
    name: str
    bytes: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "name": self.name,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class EvidenceSource:
    root: Path
    manifest: Mapping[str, Any]
    manifest_raw: bytes
    report: Mapping[str, Any]
    report_raw: bytes
    files: Mapping[str, FileRecord]
    directories: frozenset[str]


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise EvidenceAssetError("value is not canonical JSON data") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceAssetError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvidenceAssetError(f"non-finite JSON number is forbidden: {value}")


def _load_canonical_line(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise EvidenceAssetError(f"{label} must end with exactly one LF")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceAssetError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) + b"\n" != raw:
        raise EvidenceAssetError(f"{label} is not canonical JSON plus LF")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise EvidenceAssetError(f"{label} is not lowercase SHA-256")
    return value


def _utc_second(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise EvidenceAssetError(f"{label} must be UTC with whole seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise EvidenceAssetError(f"{label} is not a real timestamp") from error
    return value


def _safe_relative(value: Any, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvidenceAssetError(f"{label} is not canonical POSIX syntax")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise EvidenceAssetError(f"{label} is not strict UTF-8") from error
    if len(encoded) > MAXIMUM_PATH_BYTES or unicodedata.normalize("NFC", value) != value:
        raise EvidenceAssetError(f"{label} is not a portable NFC path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(part in {"", "."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise EvidenceAssetError(f"{label} escapes its root")
    for component in relative.parts:
        component_bytes = component.encode("utf-8")
        if (
            len(component_bytes) > 100
            or component.endswith((" ", "."))
            or any(ord(character) < 32 or ord(character) == 127 for character in component)
            or WINDOWS_RESERVED.fullmatch(component) is not None
        ):
            raise EvidenceAssetError(f"{label} contains a non-portable component")
    return relative


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _resolved_real_path(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        direct = os.lstat(absolute)
    except OSError as error:
        raise EvidenceAssetError(f"path is missing: {path}") from error
    if stat.S_ISLNK(direct.st_mode):
        raise EvidenceAssetError(f"path itself is a symlink: {path}")
    resolved = absolute.resolve(strict=True)
    current = Path(resolved.anchor)
    for component in resolved.parts[1:]:
        current /= component
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise EvidenceAssetError(f"resolved path contains a symlink: {current}")
    metadata = os.lstat(resolved)
    matches = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not matches:
        kind = "directory" if directory else "regular file"
        raise EvidenceAssetError(f"path is not a real {kind}: {resolved}")
    return resolved


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_relative(root: Path, relative_text: str) -> int:
    relative = _safe_relative(relative_text, label="file path")
    descriptor = os.open(root, _directory_flags())
    try:
        for component in relative.parts[:-1]:
            next_descriptor = os.open(
                component,
                _directory_flags(),
                dir_fd=descriptor,
            )
            if not stat.S_ISDIR(os.fstat(next_descriptor).st_mode):
                os.close(next_descriptor)
                raise EvidenceAssetError(f"non-directory path component: {relative_text}")
            os.close(descriptor)
            descriptor = next_descriptor
        result = os.open(relative.parts[-1], _file_flags(), dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result)
            raise EvidenceAssetError(f"path is not regular: {relative_text}")
        return result
    except OSError as error:
        raise EvidenceAssetError(
            f"path is missing, changed, or contains a symlink: {relative_text}"
        ) from error
    finally:
        os.close(descriptor)


def _read_all_fd(descriptor: int, *, maximum: int, label: str) -> bytes:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise EvidenceAssetError(f"{label} exceeds its bounded regular-file contract")
    chunks: list[bytes] = []
    remaining = metadata.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
        if not chunk:
            raise EvidenceAssetError(f"{label} was truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1) != b"":
        raise EvidenceAssetError(f"{label} grew while being read")
    return b"".join(chunks)


def _read_regular_path(path: Path, *, maximum: int, label: str) -> bytes:
    resolved = _resolved_real_path(path, directory=False)
    descriptor = os.open(resolved, _file_flags())
    try:
        before = os.fstat(descriptor)
        if before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o222:
            raise EvidenceAssetError(f"{label} must be sealed and have one link")
        raw = _read_all_fd(descriptor, maximum=maximum, label=label)
        if _identity(before) != _identity(os.fstat(descriptor)):
            raise EvidenceAssetError(f"{label} changed while being read")
        return raw
    finally:
        os.close(descriptor)


def _hash_relative(
    root: Path,
    relative: str,
    *,
    expected_bytes: int,
    expected_identity: tuple[int, ...] | None = None,
) -> tuple[str, tuple[int, ...]]:
    descriptor = _open_relative(root, relative)
    try:
        before = os.fstat(descriptor)
        if (
            before.st_size != expected_bytes
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o222
            or expected_identity is not None
            and _identity(before) != expected_identity
        ):
            raise EvidenceAssetError(f"sealed file metadata differs: {relative}")
        digest = hashlib.sha256()
        observed = 0
        while observed < expected_bytes:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, expected_bytes - observed),
            )
            if not chunk:
                raise EvidenceAssetError(f"sealed file is truncated: {relative}")
            observed += len(chunk)
            digest.update(chunk)
        if os.read(descriptor, 1) != b"" or _identity(before) != _identity(os.fstat(descriptor)):
            raise EvidenceAssetError(f"sealed file changed while hashing: {relative}")
        return digest.hexdigest(), _identity(before)
    finally:
        os.close(descriptor)


def _enumerate_sealed_tree(root: Path) -> tuple[dict[str, tuple[Path, os.stat_result]], set[str]]:
    root = _resolved_real_path(root, directory=True)
    root_metadata = os.lstat(root)
    if stat.S_IMODE(root_metadata.st_mode) & 0o222:
        raise EvidenceAssetError("evidence root is not sealed read-only")
    files: dict[str, tuple[Path, os.stat_result]] = {}
    directories = {"."}
    casefolded: set[str] = set()
    stack: list[tuple[Path, PurePosixPath | None]] = [(root, None)]
    while stack:
        directory, prefix = stack.pop()
        directory_metadata = os.lstat(directory)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_ISLNK(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) & 0o222
        ):
            raise EvidenceAssetError(f"evidence directory is unsafe or writable: {directory}")
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda child: os.fsencode(child.name))
        for child in children:
            relative = PurePosixPath(child.name) if prefix is None else prefix / child.name
            relative_text = _safe_relative(
                relative.as_posix(), label="evidence source path"
            ).as_posix()
            folded = relative_text.casefold()
            if folded in casefolded:
                raise EvidenceAssetError("case-fold-colliding evidence paths are forbidden")
            casefolded.add(folded)
            metadata = child.stat(follow_symlinks=False)
            path = Path(child.path)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                directories.add(relative_text)
                stack.append((path, relative))
            elif stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o222:
                    raise EvidenceAssetError(f"evidence file is linked or writable: {path}")
                files[relative_text] = (path, metadata)
                if len(files) > MAXIMUM_ENTRY_COUNT + 1:
                    raise EvidenceAssetError("evidence tree has too many files")
            elif stat.S_ISLNK(metadata.st_mode):
                raise EvidenceAssetError(f"symlink is forbidden in evidence: {path}")
            else:
                raise EvidenceAssetError(f"special file is forbidden in evidence: {path}")
    return files, directories


def _expected_directories(paths: Sequence[str]) -> set[str]:
    result = {"."}
    for path in paths:
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _verify_content_digest(value: Mapping[str, Any], *, label: str) -> None:
    expected = _digest(value.get("contentSHA256"), label=f"{label} content digest")
    unsigned = dict(value)
    del unsigned["contentSHA256"]
    if sha256_bytes(canonical_json_bytes(unsigned)) != expected:
        raise EvidenceAssetError(f"{label} content self-digest differs")


def _validate_inner_manifest(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != INNER_MANIFEST_FIELDS:
        raise EvidenceAssetError("evidence release manifest fields differ")
    if (
        value["schemaVersion"] != INNER_MANIFEST_SCHEMA
        or value["suiteId"] != SUITE_ID
        or not isinstance(value["attemptId"], str)
        or ATTEMPT_ID.fullmatch(value["attemptId"]) is None
        or value["packageStatus"] not in {
            "COMPLETE_TERMINAL",
            "PARTIAL_CONSUMED_INCOMPLETE",
        }
        or type(value["attemptCountsTowardScientificVerdict"]) is not bool
    ):
        raise EvidenceAssetError("evidence release manifest identity differs")
    _utc_second(value["createdAt"], label="evidence package timestamp")
    if value["packageStatus"] == "PARTIAL_CONSUMED_INCOMPLETE":
        if (
            value["terminalState"] is not None
            or value["recoveryClassification"] != "CONSUMED_INCOMPLETE"
            or value["attemptCountsTowardScientificVerdict"] is not False
        ):
            raise EvidenceAssetError("partial evidence package claims a verdict")
    elif (
        value["terminalState"] not in {"PASS", "FAIL_GATES", "FAIL_EXECUTION"}
        or value["recoveryClassification"] is not None
    ):
        raise EvidenceAssetError("complete evidence package terminal state differs")
    entries = value["entries"]
    if not isinstance(entries, list) or not entries or len(entries) > MAXIMUM_ENTRY_COUNT:
        raise EvidenceAssetError("evidence entry inventory is empty or too large")
    previous: bytes | None = None
    observed: set[str] = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256", "role"}:
            raise EvidenceAssetError("evidence entry fields differ")
        path = _safe_relative(entry["path"], label="evidence entry path").as_posix()
        encoded = path.encode("utf-8")
        if previous is not None and encoded <= previous or path in observed:
            raise EvidenceAssetError("evidence entries are not strictly sorted and unique")
        previous = encoded
        observed.add(path)
        if (
            type(entry["bytes"]) is not int
            or not 0 <= entry["bytes"] <= MAXIMUM_MEMBER_BYTES
            or not isinstance(entry["role"], str)
            or not entry["role"]
        ):
            raise EvidenceAssetError("evidence entry size/role differs")
        _digest(entry["sha256"], label="evidence entry digest")
        total += entry["bytes"]
        if total > MAXIMUM_TOTAL_BYTES:
            raise EvidenceAssetError("evidence entry bytes exceed the package bound")
        _canonical_tar_header(path, entry["bytes"])
    if (
        value["entryCount"] != len(entries)
        or value["totalBytes"] != total
        or value["entriesSHA256"] != sha256_bytes(canonical_json_bytes(entries))
    ):
        raise EvidenceAssetError("evidence entry aggregate commitments differ")
    if not isinstance(value["groups"], dict):
        raise EvidenceAssetError("evidence groups are not an object")
    if not isinstance(value["artifactPresence"], dict):
        raise EvidenceAssetError("evidence artifact presence is not an object")
    if not isinstance(value["missingArtifacts"], list) or not isinstance(
        value["forensicArtifacts"], list
    ):
        raise EvidenceAssetError("evidence missing/forensic inventory differs")
    _verify_content_digest(value, label="evidence release manifest")
    return value


def _validate_inner_report(
    value: Any,
    *,
    manifest: Mapping[str, Any],
    manifest_raw: bytes,
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != INNER_REPORT_FIELDS:
        raise EvidenceAssetError("evidence package verifier report fields differ")
    expected_status = (
        "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE"
        if manifest["terminalState"] is None
        else "VERIFIED_COMPLETE_TERMINAL"
    )
    if (
        value["schemaVersion"] != INNER_REPORT_SCHEMA
        or value["status"] != expected_status
        or value["suiteId"] != manifest["suiteId"]
        or value["attemptId"] != manifest["attemptId"]
        or value["recoveryClassification"] != manifest["recoveryClassification"]
        or value["terminalState"] != manifest["terminalState"]
        or value["attemptCountsTowardScientificVerdict"]
        is not manifest["attemptCountsTowardScientificVerdict"]
        or value["entryCount"] != manifest["entryCount"]
        or value["totalBytes"] != manifest["totalBytes"]
        or value["manifestFileSHA256"] != sha256_bytes(manifest_raw)
        or value["manifestContentSHA256"] != manifest["contentSHA256"]
        or value["missingArtifacts"] != manifest["missingArtifacts"]
        or value["forensicArtifacts"] != manifest["forensicArtifacts"]
    ):
        raise EvidenceAssetError("verifier report does not bind the evidence manifest")
    _verify_content_digest(value, label="evidence package verifier report")
    return value


def _load_evidence_source(evidence_root: Path, verifier_report: Path) -> EvidenceSource:
    root = _resolved_real_path(evidence_root, directory=True)
    report_path = _resolved_real_path(verifier_report, directory=False)
    try:
        report_path.relative_to(root)
    except ValueError:
        pass
    else:
        raise EvidenceAssetError("external verifier report must be outside evidence root")
    report_raw = _read_regular_path(
        report_path,
        maximum=MAXIMUM_REPORT_BYTES,
        label="external verifier report",
    )
    observed_files, observed_directories = _enumerate_sealed_tree(root)
    manifest_pair = observed_files.get(INNER_MANIFEST_NAME)
    if manifest_pair is None or manifest_pair[1].st_size > MAXIMUM_MANIFEST_BYTES:
        raise EvidenceAssetError("sealed evidence has no bounded top manifest")
    manifest_descriptor = _open_relative(root, INNER_MANIFEST_NAME)
    try:
        manifest_raw = _read_all_fd(
            manifest_descriptor,
            maximum=MAXIMUM_MANIFEST_BYTES,
            label="evidence release manifest",
        )
    finally:
        os.close(manifest_descriptor)
    manifest = _validate_inner_manifest(
        _load_canonical_line(manifest_raw, label="evidence release manifest")
    )
    report = _validate_inner_report(
        _load_canonical_line(report_raw, label="external verifier report"),
        manifest=manifest,
        manifest_raw=manifest_raw,
    )
    expected_files = {INNER_MANIFEST_NAME} | {
        entry["path"] for entry in manifest["entries"]
    }
    if set(observed_files) != expected_files:
        raise EvidenceAssetError("sealed evidence file inventory differs from top manifest")
    if observed_directories != _expected_directories(sorted(expected_files)):
        raise EvidenceAssetError("sealed evidence directory inventory differs")
    records: dict[str, FileRecord] = {}
    entry_by_path = {entry["path"]: entry for entry in manifest["entries"]}
    for relative in sorted(expected_files, key=lambda item: item.encode("utf-8")):
        path, metadata = observed_files[relative]
        if relative == INNER_MANIFEST_NAME:
            expected_size = len(manifest_raw)
            expected_digest = sha256_bytes(manifest_raw)
        else:
            expected_size = entry_by_path[relative]["bytes"]
            expected_digest = entry_by_path[relative]["sha256"]
        observed_digest, identity = _hash_relative(
            root,
            relative,
            expected_bytes=expected_size,
            expected_identity=_identity(metadata),
        )
        if observed_digest != expected_digest:
            raise EvidenceAssetError(f"sealed evidence SHA-256 differs: {relative}")
        records[relative] = FileRecord(
            relative_path=relative,
            path=path,
            bytes=expected_size,
            sha256=expected_digest,
            identity=identity,
        )
    return EvidenceSource(
        root=root,
        manifest=manifest,
        manifest_raw=manifest_raw,
        report=report,
        report_raw=report_raw,
        files=records,
        directories=frozenset(observed_directories),
    )


def _canonical_tar_header(relative: str, size: int) -> bytes:
    _safe_relative(relative, label="USTAR member path")
    if type(size) is not int or not 0 <= size <= MAXIMUM_MEMBER_BYTES:
        raise EvidenceAssetError("USTAR member size exceeds the portable bound")
    information = tarfile.TarInfo(relative)
    information.size = size
    information.mode = 0o444
    information.uid = 0
    information.gid = 0
    information.mtime = 0
    information.uname = ""
    information.gname = ""
    information.type = tarfile.REGTYPE
    information.linkname = ""
    information.devmajor = 0
    information.devminor = 0
    information.pax_headers = {}
    try:
        header = information.tobuf(
            format=tarfile.USTAR_FORMAT,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeError, ValueError) as error:
        raise EvidenceAssetError(
            f"path or size cannot be represented as portable USTAR: {relative}"
        ) from error
    if len(header) != TAR_BLOCK_BYTES:
        raise EvidenceAssetError("canonical USTAR header has an unexpected length")
    return header


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise EvidenceAssetError("short file write")
        view = view[written:]


def _copy_record_to_archive(
    source_root: Path,
    record: FileRecord,
    archive_descriptor: int,
) -> None:
    source = _open_relative(source_root, record.relative_path)
    try:
        before = os.fstat(source)
        if _identity(before) != record.identity:
            raise EvidenceAssetError(f"evidence source changed: {record.relative_path}")
        digest = hashlib.sha256()
        observed = 0
        while observed < record.bytes:
            chunk = os.read(source, min(READ_CHUNK_BYTES, record.bytes - observed))
            if not chunk:
                raise EvidenceAssetError(f"evidence source truncated: {record.relative_path}")
            _write_all(archive_descriptor, chunk)
            digest.update(chunk)
            observed += len(chunk)
        if (
            os.read(source, 1) != b""
            or digest.hexdigest() != record.sha256
            or _identity(os.fstat(source)) != record.identity
        ):
            raise EvidenceAssetError(f"evidence source changed: {record.relative_path}")
    finally:
        os.close(source)


def _archive_size(records: Sequence[FileRecord]) -> int:
    body = sum(
        TAR_BLOCK_BYTES
        + ((record.bytes + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES
        for record in records
    )
    with_end_blocks = body + 2 * TAR_BLOCK_BYTES
    result = (
        (with_end_blocks + TAR_RECORD_BYTES - 1) // TAR_RECORD_BYTES
    ) * TAR_RECORD_BYTES
    if result > MAXIMUM_TOTAL_BYTES:
        raise EvidenceAssetError("canonical USTAR exceeds the archive byte bound")
    return result


def _write_archive(path: Path, source: EvidenceSource) -> AssetRecord:
    records = [source.files[name] for name in sorted(source.files, key=lambda item: item.encode("utf-8"))]
    expected_archive_size = _archive_size(records)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    written = 0
    try:
        for record in records:
            header = _canonical_tar_header(record.relative_path, record.bytes)
            _write_all(descriptor, header)
            written += len(header)
            _copy_record_to_archive(source.root, record, descriptor)
            written += record.bytes
            padding = (-record.bytes) % TAR_BLOCK_BYTES
            if padding:
                _write_all(descriptor, b"\0" * padding)
                written += padding
        tail = expected_archive_size - written
        if tail < 2 * TAR_BLOCK_BYTES:
            raise EvidenceAssetError("canonical USTAR end padding is invalid")
        _write_all(descriptor, b"\0" * tail)
        written += tail
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if written != expected_archive_size:
        raise EvidenceAssetError("canonical USTAR byte count differs")
    os.chmod(path, 0o444, follow_symlinks=False)
    size, digest = _hash_regular_path(path, label="evidence package archive")
    return AssetRecord("evidence-package", path.name, size, digest)


def _hash_regular_path(path: Path, *, label: str) -> tuple[int, str]:
    resolved = _resolved_real_path(path, directory=False)
    descriptor = os.open(resolved, _file_flags())
    try:
        before = os.fstat(descriptor)
        if before.st_nlink != 1 or before.st_size > MAXIMUM_TOTAL_BYTES:
            raise EvidenceAssetError(f"{label} metadata exceeds bounds")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
            if observed > MAXIMUM_TOTAL_BYTES:
                raise EvidenceAssetError(f"{label} exceeds its byte bound")
        if observed != before.st_size or _identity(before) != _identity(os.fstat(descriptor)):
            raise EvidenceAssetError(f"{label} changed while hashing")
        return observed, digest.hexdigest()
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, _directory_flags())
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new_bytes(path: Path, value: bytes) -> AssetRecord:
    role = next((role for role, name in ASSET_NAMES.items() if name == path.name), None)
    if role is None:
        raise EvidenceAssetError("release asset filename has no canonical role")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o444, follow_symlinks=False)
    return AssetRecord(role, path.name, len(value), sha256_bytes(value))


def _sha256_manifest(records: Mapping[str, AssetRecord]) -> Mapping[str, Any]:
    if tuple(records) != MANIFEST_ROLES:
        raise EvidenceAssetError("SHA-256 manifest role order/set differs")
    return {
        "schemaVersion": SHA256_MANIFEST_SCHEMA,
        "suiteId": SUITE_ID,
        "algorithm": "SHA-256",
        "scope": "all evidence release assets except this manifest",
        "selfDigestExcluded": True,
        "assets": [records[role].as_dict() for role in MANIFEST_ROLES],
    }


def _validate_sha256_manifest(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "suiteId",
        "algorithm",
        "scope",
        "selfDigestExcluded",
        "assets",
    }:
        raise EvidenceAssetError("evidence SHA-256 manifest fields differ")
    if (
        value["schemaVersion"] != SHA256_MANIFEST_SCHEMA
        or value["suiteId"] != SUITE_ID
        or value["algorithm"] != "SHA-256"
        or value["scope"] != "all evidence release assets except this manifest"
        or value["selfDigestExcluded"] is not True
    ):
        raise EvidenceAssetError("evidence SHA-256 manifest identity differs")
    assets = value["assets"]
    if not isinstance(assets, list) or len(assets) != len(MANIFEST_ROLES):
        raise EvidenceAssetError("evidence SHA-256 manifest inventory differs")
    for role, item in zip(MANIFEST_ROLES, assets):
        if not isinstance(item, dict) or set(item) != {"role", "name", "bytes", "sha256"}:
            raise EvidenceAssetError("evidence SHA-256 asset fields differ")
        if (
            item["role"] != role
            or item["name"] != ASSET_NAMES[role]
            or type(item["bytes"]) is not int
            or not 0 <= item["bytes"] <= MAXIMUM_TOTAL_BYTES
        ):
            raise EvidenceAssetError("evidence SHA-256 asset identity differs")
        _digest(item["sha256"], label="evidence release asset digest")
    return value


def _read_exact(descriptor: int, size: int, *, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
        if not chunk:
            raise EvidenceAssetError(f"{label} is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _create_extraction_file(root: Path, relative_text: str) -> tuple[int, list[Path]]:
    relative = _safe_relative(relative_text, label="extraction path")
    current = root
    created_directories: list[Path] = []
    for component in relative.parts[:-1]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            _fsync_directory(current.parent)
            created_directories.append(current)
            metadata = os.lstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise EvidenceAssetError("unsafe extraction directory")
    destination = current / relative.parts[-1]
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(destination, flags, 0o600), created_directories


def _stream_verify_archive(
    archive_path: Path,
    expected: Sequence[tuple[str, int, str]],
    *,
    extraction_root: Path | None = None,
) -> tuple[int, str]:
    records = [
        FileRecord(name, Path(), size, digest, ())
        for name, size, digest in expected
    ]
    expected_size = _archive_size(records)
    resolved = _resolved_real_path(archive_path, directory=False)
    descriptor = os.open(resolved, _file_flags())
    archive_digest = hashlib.sha256()
    consumed = 0
    extraction_directories: set[Path] = set()

    def read_and_hash(size: int, *, label: str) -> bytes:
        nonlocal consumed
        value = _read_exact(descriptor, size, label=label)
        archive_digest.update(value)
        consumed += len(value)
        return value

    try:
        before = os.fstat(descriptor)
        if before.st_nlink != 1 or before.st_size != expected_size:
            raise EvidenceAssetError("evidence package USTAR size differs")
        for name, size, expected_digest in expected:
            header = read_and_hash(TAR_BLOCK_BYTES, label="USTAR header")
            if header != _canonical_tar_header(name, size):
                raise EvidenceAssetError(f"USTAR header or member order differs: {name}")
            output_descriptor: int | None = None
            if extraction_root is not None:
                output_descriptor, created = _create_extraction_file(
                    extraction_root, name
                )
                extraction_directories.update(created)
            digest = hashlib.sha256()
            observed = 0
            try:
                while observed < size:
                    chunk = read_and_hash(
                        min(READ_CHUNK_BYTES, size - observed),
                        label=f"USTAR member {name}",
                    )
                    digest.update(chunk)
                    observed += len(chunk)
                    if output_descriptor is not None:
                        _write_all(output_descriptor, chunk)
                if output_descriptor is not None:
                    os.fsync(output_descriptor)
            finally:
                if output_descriptor is not None:
                    os.close(output_descriptor)
                    destination = extraction_root.joinpath(*PurePosixPath(name).parts)
                    os.chmod(destination, 0o444, follow_symlinks=False)
                    _fsync_directory(destination.parent)
            if digest.hexdigest() != expected_digest:
                raise EvidenceAssetError(f"USTAR member SHA-256 differs: {name}")
            padding = (-size) % TAR_BLOCK_BYTES
            if padding and read_and_hash(padding, label="USTAR member padding") != b"\0" * padding:
                raise EvidenceAssetError(f"USTAR member padding differs: {name}")
        tail = expected_size - consumed
        if tail < 2 * TAR_BLOCK_BYTES:
            raise EvidenceAssetError("USTAR end padding is too short")
        while tail:
            amount = min(tail, READ_CHUNK_BYTES)
            if read_and_hash(amount, label="USTAR end padding") != b"\0" * amount:
                raise EvidenceAssetError("USTAR end padding differs")
            tail -= amount
        if os.read(descriptor, 1) != b"" or _identity(before) != _identity(os.fstat(descriptor)):
            raise EvidenceAssetError("evidence package archive changed during verification")
    finally:
        os.close(descriptor)
    if extraction_root is not None:
        all_directories = list(extraction_directories) + [extraction_root]
        for directory in sorted(
            set(all_directories), key=lambda value: len(value.parts), reverse=True
        ):
            _fsync_directory(directory)
            os.chmod(directory, 0o555, follow_symlinks=False)
    return expected_size, archive_digest.hexdigest()


def _read_asset_bytes(root: Path, name: str, *, maximum: int, label: str) -> bytes:
    descriptor = _open_relative(root, name)
    try:
        before = os.fstat(descriptor)
        if before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o222:
            raise EvidenceAssetError(f"{label} is linked or writable")
        value = _read_all_fd(descriptor, maximum=maximum, label=label)
        if _identity(before) != _identity(os.fstat(descriptor)):
            raise EvidenceAssetError(f"{label} changed while being read")
        return value
    finally:
        os.close(descriptor)


def _asset_root(root: Path) -> Path:
    resolved = _resolved_real_path(root, directory=True)
    metadata = os.lstat(resolved)
    if stat.S_IMODE(metadata.st_mode) & 0o222:
        raise EvidenceAssetError("evidence asset root is writable")
    with os.scandir(resolved) as iterator:
        children = list(iterator)
    if {child.name for child in children} != set(ASSET_NAMES.values()):
        raise EvidenceAssetError("evidence release asset inventory differs")
    for child in children:
        metadata = child.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o222
        ):
            raise EvidenceAssetError("evidence release asset is unsafe or writable")
    return resolved


def verify_evidence_assets(asset_root: Path) -> dict[str, Any]:
    root = _asset_root(asset_root)
    manifest_raw = _read_asset_bytes(
        root,
        ASSET_NAMES["evidence-release-manifest"],
        maximum=MAXIMUM_MANIFEST_BYTES,
        label="evidence release manifest asset",
    )
    manifest = _validate_inner_manifest(
        _load_canonical_line(manifest_raw, label="evidence release manifest asset")
    )
    report_raw = _read_asset_bytes(
        root,
        ASSET_NAMES["evidence-package-verifier-report"],
        maximum=MAXIMUM_REPORT_BYTES,
        label="evidence package verifier report asset",
    )
    report = _validate_inner_report(
        _load_canonical_line(report_raw, label="evidence package verifier report asset"),
        manifest=manifest,
        manifest_raw=manifest_raw,
    )
    sha_manifest_raw = _read_asset_bytes(
        root,
        ASSET_NAMES["sha256-manifest"],
        maximum=MAXIMUM_SHA256_MANIFEST_BYTES,
        label="evidence SHA-256 manifest",
    )
    sha_manifest = _validate_sha256_manifest(
        _load_canonical_line(sha_manifest_raw, label="evidence SHA-256 manifest")
    )
    records: dict[str, AssetRecord] = {}
    for item in sha_manifest["assets"]:
        path = root / item["name"]
        size, digest = _hash_regular_path(path, label=f"release asset {item['role']}")
        if size != item["bytes"] or digest != item["sha256"]:
            raise EvidenceAssetError(f"release asset commitment differs: {item['role']}")
        records[item["role"]] = AssetRecord(item["role"], item["name"], size, digest)
    expected_members = [
        (entry["path"], entry["bytes"], entry["sha256"])
        for entry in manifest["entries"]
    ]
    expected_members.append(
        (INNER_MANIFEST_NAME, len(manifest_raw), sha256_bytes(manifest_raw))
    )
    expected_members.sort(key=lambda item: item[0].encode("utf-8"))
    archive_size, archive_digest = _stream_verify_archive(
        root / ASSET_NAMES["evidence-package"], expected_members
    )
    archive_record = records["evidence-package"]
    if archive_size != archive_record.bytes or archive_digest != archive_record.sha256:
        raise EvidenceAssetError("canonical USTAR differs from SHA-256 manifest")
    if (
        records["evidence-release-manifest"].sha256 != sha256_bytes(manifest_raw)
        or records["evidence-package-verifier-report"].sha256
        != sha256_bytes(report_raw)
    ):
        raise EvidenceAssetError("release roles differ from cross-bound JSON bytes")
    result = {
        "schemaVersion": VERIFICATION_SCHEMA,
        "status": "VERIFIED_CANONICAL_EVIDENCE_RELEASE_ASSETS",
        "suiteId": manifest["suiteId"],
        "attemptId": manifest["attemptId"],
        "terminalState": manifest["terminalState"],
        "attemptCountsTowardScientificVerdict": manifest[
            "attemptCountsTowardScientificVerdict"
        ],
        "archiveFormat": "POSIX-USTAR-UNCOMPRESSED",
        "archiveMemberCount": len(expected_members),
        "archiveBytes": archive_size,
        "archiveSHA256": archive_digest,
        "evidenceManifestSHA256": sha256_bytes(manifest_raw),
        "packageVerifierReportSHA256": sha256_bytes(report_raw),
        "sha256ManifestSHA256": sha256_bytes(sha_manifest_raw),
        "releaseRoles": list(ASSET_ROLES),
    }
    result["contentSHA256"] = sha256_bytes(canonical_json_bytes(result))
    return result


def package_evidence_assets(
    *,
    evidence_root: Path,
    verifier_report: Path,
    output_directory: Path,
) -> dict[str, Any]:
    source = _load_evidence_source(evidence_root, verifier_report)
    absolute_output = Path(os.path.abspath(os.fspath(output_directory)))
    parent = _resolved_real_path(absolute_output.parent, directory=True)
    output = parent / absolute_output.name
    if not output.name or output.name in {".", ".."}:
        raise EvidenceAssetError("output directory has no safe leaf name")
    try:
        output.relative_to(source.root)
    except ValueError:
        pass
    else:
        raise EvidenceAssetError("output directory is inside the sealed evidence root")
    try:
        os.mkdir(output, 0o700)
    except OSError as error:
        raise EvidenceAssetError("output directory already exists or cannot be created") from error
    _fsync_directory(parent)
    records: dict[str, AssetRecord] = {}
    try:
        records["evidence-package"] = _write_archive(
            output / ASSET_NAMES["evidence-package"], source
        )
        records["evidence-release-manifest"] = _write_new_bytes(
            output / ASSET_NAMES["evidence-release-manifest"],
            source.manifest_raw,
        )
        records["evidence-package-verifier-report"] = _write_new_bytes(
            output / ASSET_NAMES["evidence-package-verifier-report"],
            source.report_raw,
        )
        sha_manifest_raw = canonical_json_bytes(_sha256_manifest(records)) + b"\n"
        _write_new_bytes(
            output / ASSET_NAMES["sha256-manifest"], sha_manifest_raw
        )
        _fsync_directory(output)
        os.chmod(output, 0o555, follow_symlinks=False)
        return verify_evidence_assets(output)
    except BaseException:
        # Never overwrite or hide a failed publication attempt.  The new output
        # remains visibly incomplete for forensic inspection.
        raise


def extract_evidence_package(
    *, asset_root: Path, output_directory: Path
) -> dict[str, Any]:
    verification = verify_evidence_assets(asset_root)
    root = _asset_root(asset_root)
    manifest_raw = _read_asset_bytes(
        root,
        ASSET_NAMES["evidence-release-manifest"],
        maximum=MAXIMUM_MANIFEST_BYTES,
        label="evidence release manifest asset",
    )
    manifest = _validate_inner_manifest(
        _load_canonical_line(manifest_raw, label="evidence release manifest asset")
    )
    expected_members = [
        (entry["path"], entry["bytes"], entry["sha256"])
        for entry in manifest["entries"]
    ]
    expected_members.append(
        (INNER_MANIFEST_NAME, len(manifest_raw), sha256_bytes(manifest_raw))
    )
    expected_members.sort(key=lambda item: item[0].encode("utf-8"))
    absolute_output = Path(os.path.abspath(os.fspath(output_directory)))
    parent = _resolved_real_path(absolute_output.parent, directory=True)
    output = parent / absolute_output.name
    extracted_report_path = output.parent / (
        "." + output.name + ".external-verifier-report"
    )
    if extracted_report_path.exists() or extracted_report_path.is_symlink():
        raise EvidenceAssetError("temporary extraction verifier path already exists")
    try:
        os.mkdir(output, 0o700)
    except OSError as error:
        raise EvidenceAssetError("extraction output already exists or cannot be created") from error
    _fsync_directory(parent)
    _stream_verify_archive(
        root / ASSET_NAMES["evidence-package"],
        expected_members,
        extraction_root=output,
    )
    # Reuse the same independent tree/report binding without adding the report
    # to the extracted sealed directory.
    report_raw = _read_asset_bytes(
        root,
        ASSET_NAMES["evidence-package-verifier-report"],
        maximum=MAXIMUM_REPORT_BYTES,
        label="evidence package verifier report asset",
    )
    report_descriptor = os.open(
        extracted_report_path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        _write_all(report_descriptor, report_raw)
        os.fsync(report_descriptor)
    finally:
        os.close(report_descriptor)
    try:
        _load_evidence_source(output, extracted_report_path)
    finally:
        os.chmod(extracted_report_path, 0o600, follow_symlinks=False)
        extracted_report_path.unlink()
        _fsync_directory(output.parent)
    return verification


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    package = subparsers.add_parser("package", help="create the four release assets")
    package.add_argument("--evidence-root", type=Path, required=True)
    package.add_argument("--verifier-report", type=Path, required=True)
    package.add_argument("--output-directory", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify all four release assets")
    verify.add_argument("--asset-root", type=Path, required=True)
    extract = subparsers.add_parser(
        "extract", help="verify and safely extract the sealed evidence directory"
    )
    extract.add_argument("--asset-root", type=Path, required=True)
    extract.add_argument("--output-directory", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "package":
            report = package_evidence_assets(
                evidence_root=arguments.evidence_root,
                verifier_report=arguments.verifier_report,
                output_directory=arguments.output_directory,
            )
        elif arguments.command == "verify":
            report = verify_evidence_assets(arguments.asset_root)
        else:
            report = extract_evidence_package(
                asset_root=arguments.asset_root,
                output_directory=arguments.output_directory,
            )
        sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
        return 0
    except (EvidenceAssetError, OSError, ValueError) as error:
        print(f"EVIDENCE ASSETS FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
