#!/usr/bin/env python3
"""Build and independently verify a blind-v4 public evidence package.

The package is a byte-for-byte directory artifact.  It contains the complete
one-shot result root, the complete public corpus collector root, and every
frozen provenance input needed to audit those bytes.  The implementation uses
only the Python standard library, never follows a symlink, never overwrites an
existing package, and records an explicit consumed-incomplete state whenever a
durable attempt reservation lacks a canonical terminal outcome. Raw
interrupted state-file bytes are retained as forensic evidence.

This verifier checks package integrity and cross-file bindings.  It does not
replace ``v4/verify_evidence.py``, which independently recomputes the scientific
metrics from the raw token and container evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator


SCHEMA_VERSION = "corelm-crossmodel-livewiki-v4-evidence-release-manifest-v1"
VERIFICATION_SCHEMA = (
    "corelm-crossmodel-livewiki-v4-evidence-release-verification-v1"
)
SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v4-author-verified"
MANIFEST_FILENAME = "evidence-release-manifest.json"
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
UTC_SECOND = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
TARGET_PULSE_TIMESTAMP = "2026-09-25T18:00:00.000Z"
ONE_SHOT_NOT_BEFORE = "2026-09-26T18:00:00Z"
HARD_DEADLINE = "2026-09-27T18:00:00Z"
READ_CHUNK_BYTES = 1024 * 1024

ROLES = frozenset(
    {
        "attempt-evidence",
        "public-corpus",
        "frozen-design",
        "frozen-snapshot-registration",
        "design-publication-receipt",
        "snapshot-publication-receipt",
        "release-signing-public-key",
        "design-release-asset",
        "snapshot-release-asset",
        "freeze-manifest",
        "runtime-manifest",
        "model-asset-source-manifest",
        "full-asset-receipt",
        "sbom",
        "nist-trust",
        "transport-ca-bundle",
    }
)
TERMINAL_STATES = frozenset(
    {"PASS", "FAIL_GATES", "FAIL_EXECUTION", "CONSUMED_INCOMPLETE"}
)

# These paths are required for a complete PASS or FAIL_GATES outcome.  For an
# execution failure, each absence remains explicit in the top-level manifest;
# the packager never creates a placeholder that could be confused for evidence.
ARTIFACT_PATHS = {
    "attemptReservation": "payload/attempt/attempt-reservation.json",
    "attemptMarker": "payload/attempt/attempt-marker.json",
    "terminalOutcome": "payload/attempt/terminal-outcome.json",
    "privateSnapshotManifest": "payload/attempt/private-snapshot-manifest.json",
    "hostEnvironment": "payload/attempt/environment/host-preflight.json",
    "nistRequestURI": "payload/attempt/nist/request-uri.txt",
    "nistResponseHeaders": "payload/attempt/nist/response-headers.bin",
    "nistResponseBody": "payload/attempt/nist/response-body.json",
    "nistVerification": "payload/attempt/nist/verification.json",
    "selection": "payload/attempt/selection.json",
    "pageTokenEvidence": "payload/attempt/page-token-evidence.jsonl",
    "rawTokenEvidence": "payload/attempt/raw-token-evidence.jsonl",
    "containerEvidence": "payload/attempt/container-evidence.jsonl",
    "producerResult": "payload/attempt/result.json",
    "producerEvidenceManifest": "payload/attempt/evidence-manifest.json",
    "independentVerifierReport": (
        "payload/attempt/independent-verifier-report.json"
    ),
    "independentVerifierLog": (
        "payload/attempt/logs/independent-verifier.log"
    ),
    "gptNeoWorkerPageTokenEvidence": (
        "payload/attempt/workers/gpt-neo-125m/page-token-evidence.jsonl"
    ),
    "smolLM2WorkerPageTokenEvidence": (
        "payload/attempt/workers/smollm2-360m/page-token-evidence.jsonl"
    ),
    "tinyStarcoderWorkerPageTokenEvidence": (
        "payload/attempt/workers/tiny-starcoder-py/page-token-evidence.jsonl"
    ),
}

FORENSIC_PATHS = {
    "payload/attempt/attempt-reservation.pending": (
        "INTERRUPTED_RESERVATION_PUBLICATION_CLEANUP"
    ),
    "payload/attempt/attempt-marker.pending": (
        "INTERRUPTED_ATTEMPT_MARKER_PUBLICATION"
    ),
    "payload/attempt/terminal-outcome.pending": (
        "INTERRUPTED_TERMINAL_OUTCOME_PUBLICATION"
    ),
}

COMMITMENT_FIELDS = (
    "suiteId",
    "attemptId",
    "createdAt",
    "designSHA256",
    "snapshotRegistrationSHA256",
    "designPublicationReceiptSHA256",
    "snapshotPublicationReceiptSHA256",
    "privateSnapshotManifestSHA256",
    "runtimeManifestSHA256",
    "modelAssetSourceManifestSHA256",
    "fullAssetReceiptSHA256",
    "githubGateReceiptSHA256",
    "corpusManifestSHA256",
    "codecCommit",
    "codecTree",
    "labCommit",
    "labTree",
    "targetPulseTimestamp",
    "retryPermitted",
)

INNER_PAGE_TOKEN_PATHS = frozenset(
    {
        "page-token-evidence.jsonl",
        "workers/gpt-neo-125m/page-token-evidence.jsonl",
        "workers/smollm2-360m/page-token-evidence.jsonl",
        "workers/tiny-starcoder-py/page-token-evidence.jsonl",
    }
)
INNER_DURABLE_STATE_PATHS = frozenset(
    {"attempt-reservation.json", "attempt-marker.json"}
)

BINDING_DESTINATIONS = {
    "design": ("payload/bindings/design.json", "frozen-design"),
    "snapshot": (
        "payload/bindings/snapshot-registration.json",
        "frozen-snapshot-registration",
    ),
    "freeze": ("payload/bindings/freeze-manifest.json", "freeze-manifest"),
    "runtime": ("payload/bindings/runtime-manifest.json", "runtime-manifest"),
    "assetSource": (
        "payload/bindings/model-assets-source.json",
        "model-asset-source-manifest",
    ),
    "assetReceipt": (
        "payload/bindings/asset-receipt.json",
        "full-asset-receipt",
    ),
    "sbom": ("payload/bindings/sbom.cdx.json", "sbom"),
    "designReceipt": (
        "payload/bindings/publication/design-receipt.json",
        "design-publication-receipt",
    ),
    "snapshotReceipt": (
        "payload/bindings/publication/snapshot-receipt.json",
        "snapshot-publication-receipt",
    ),
    "signingKey": (
        "payload/bindings/publication/signing-key.pub",
        "release-signing-public-key",
    ),
    "ca": ("payload/bindings/transport-ca.pem", "transport-ca-bundle"),
}


class EvidenceReleaseError(RuntimeError):
    """Raised when a release package is unsafe, incomplete, or inconsistent."""


def _reject_constant(value: str) -> None:
    raise EvidenceReleaseError(f"non-finite JSON number is forbidden: {value}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


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


def utc_now_seconds() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _validate_utc_second(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise EvidenceReleaseError(f"{label} must be UTC with whole seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise EvidenceReleaseError(f"{label} is not a real UTC timestamp") from error
    return value


def _validate_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise EvidenceReleaseError(f"{label} is not a lowercase SHA-256")
    return value


def _safe_relative(value: str, *, label: str = "relative path") -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvidenceReleaseError(f"{label} is not canonical POSIX syntax")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise EvidenceReleaseError(f"{label} is not strict UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise EvidenceReleaseError(f"{label} is not NFC-normalized")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(part in {"", "."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise EvidenceReleaseError(f"{label} escapes its package root")
    return relative


def _resolved_real_path(path: Path, *, directory: bool) -> Path:
    absolute_input = Path(os.path.abspath(os.fspath(path)))
    try:
        input_metadata = os.lstat(absolute_input)
    except OSError as error:
        raise EvidenceReleaseError(f"source path is missing: {path}") from error
    if stat.S_ISLNK(input_metadata.st_mode):
        raise EvidenceReleaseError(f"source path itself is a symlink: {path}")
    try:
        resolved = absolute_input.resolve(strict=True)
    except OSError as error:
        raise EvidenceReleaseError(f"source path is missing: {path}") from error
    current = Path(resolved.anchor)
    for component in resolved.parts[1:]:
        current /= component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceReleaseError(f"resolved source contains a symlink: {current}")
    metadata = os.lstat(resolved)
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected:
        kind = "directory" if directory else "regular file"
        raise EvidenceReleaseError(f"source must be a real {kind}: {resolved}")
    return resolved


def _load_json_bytes(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceReleaseError(f"invalid JSON: {label}") from error


def _load_canonical_line(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise EvidenceReleaseError(f"{label} must end with one LF")
    value = _load_json_bytes(raw, label=label)
    if not isinstance(value, dict) or canonical_json_bytes(value) + b"\n" != raw:
        raise EvidenceReleaseError(f"{label} is not canonical JSON plus LF")
    return value


def _load_json_document(raw: bytes, *, label: str) -> dict[str, Any]:
    value = _load_json_bytes(raw, label=label)
    if not isinstance(value, dict):
        raise EvidenceReleaseError(f"{label} must contain a JSON object")
    return value


def _verify_content_digest(value: dict[str, Any], *, label: str) -> str:
    expected = value.get("contentSHA256")
    _validate_sha256(expected, f"{label} contentSHA256")
    unsigned = dict(value)
    del unsigned["contentSHA256"]
    if sha256_bytes(canonical_json_bytes(unsigned)) != expected:
        raise EvidenceReleaseError(f"{label} content self-digest differs")
    return expected


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_destination_parent(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            _fsync_directory(current.parent)
            metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceReleaseError(f"unsafe package directory: {current}")
    return current / relative.parts[-1]


def _write_new_bytes(root: Path, relative_text: str, value: bytes) -> None:
    relative = _safe_relative(relative_text)
    destination = _ensure_destination_parent(root, relative)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceReleaseError(f"short package write: {relative_text}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o444, follow_symlinks=False)
    _fsync_directory(destination.parent)


def _walk_regular(root: Path) -> Iterator[tuple[str, Path]]:
    root = _resolved_real_path(root, directory=True)
    stack: list[tuple[Path, PurePosixPath | None]] = [(root, None)]
    observed: list[tuple[str, Path]] = []
    while stack:
        directory, relative_directory = stack.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: os.fsencode(item.name))
        for child in children:
            if (
                child.name in {"", ".", ".."}
                or "\\" in child.name
                or unicodedata.normalize("NFC", child.name) != child.name
            ):
                raise EvidenceReleaseError(f"non-canonical source name: {child.path}")
            relative = (
                PurePosixPath(child.name)
                if relative_directory is None
                else relative_directory / child.name
            )
            relative_text = relative.as_posix()
            _safe_relative(relative_text, label="source relative path")
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                stack.append((Path(child.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed.append((relative_text, Path(child.path)))
            elif stat.S_ISLNK(metadata.st_mode):
                raise EvidenceReleaseError(f"symlink is forbidden in source: {child.path}")
            else:
                raise EvidenceReleaseError(f"unsupported source object: {child.path}")
    observed.sort(key=lambda item: item[0].encode("utf-8"))
    yield from observed


def _open_regular_nofollow(path: Path) -> int:
    """Open a physical absolute path one no-follow component at a time."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or not absolute.name:
        raise EvidenceReleaseError(f"regular source path is invalid: {path}")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor, directory_flags)
    try:
        for component in absolute.parts[1:-1]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=descriptor
            )
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise EvidenceReleaseError(
                    f"source parent is not a real directory: {path}"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(file_descriptor)
            raise EvidenceReleaseError(f"source is not a regular file: {path}")
        return file_descriptor
    except OSError as error:
        raise EvidenceReleaseError(
            f"source path changed or contains a symlink: {path}"
        ) from error
    finally:
        os.close(descriptor)


def _copy_regular(source: Path, package_root: Path, relative_text: str) -> dict[str, Any]:
    relative = _safe_relative(relative_text)
    destination = _ensure_destination_parent(package_root, relative)
    source = _resolved_real_path(source, directory=False)
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    write_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = _open_regular_nofollow(source)
    destination_descriptor = os.open(destination, write_flags, 0o600)
    digest = hashlib.sha256()
    copied = 0
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceReleaseError(f"source is not a regular file: {source}")
        while True:
            chunk = os.read(source_descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            copied += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise EvidenceReleaseError(f"short package copy: {relative_text}")
                view = view[written:]
        after = os.fstat(source_descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        )
        if identity(before) != identity(after) or copied != before.st_size:
            raise EvidenceReleaseError(f"source changed during package copy: {source}")
        os.fsync(destination_descriptor)
    finally:
        os.close(destination_descriptor)
        os.close(source_descriptor)
    os.chmod(destination, 0o444, follow_symlinks=False)
    _fsync_directory(destination.parent)
    return {"path": relative_text, "bytes": copied, "sha256": digest.hexdigest()}


def _copy_tree(
    source_root: Path,
    package_root: Path,
    destination_prefix: str,
    role: str,
) -> list[dict[str, Any]]:
    files = list(_walk_regular(source_root))
    if not files:
        raise EvidenceReleaseError(f"required source tree is empty: {source_root}")
    entries: list[dict[str, Any]] = []
    for relative, source in files:
        entry = _copy_regular(
            source,
            package_root,
            f"{destination_prefix}/{relative}",
        )
        entry["role"] = role
        entries.append(entry)
    return entries


def _copy_binding(
    source: Path,
    package_root: Path,
    destination: str,
    role: str,
) -> dict[str, Any]:
    entry = _copy_regular(source, package_root, destination)
    entry["role"] = role
    return entry


def _read_beneath(root: Path, relative_text: str, *, expected_bytes: int | None = None) -> bytes:
    relative = _safe_relative(relative_text)
    root = _resolved_real_path(root, directory=True)
    descriptor = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        for component in relative.parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise EvidenceReleaseError(f"non-directory package component: {relative_text}")
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            relative.parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceReleaseError(f"package path is not regular: {relative_text}")
            if expected_bytes is not None and before.st_size != expected_bytes:
                raise EvidenceReleaseError(f"package byte count differs: {relative_text}")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(file_descriptor, min(remaining, READ_CHUNK_BYTES))
                if not chunk:
                    raise EvidenceReleaseError(f"package file truncated: {relative_text}")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(file_descriptor)
            identity = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
            )
            if identity(before) != identity(after):
                raise EvidenceReleaseError(f"package file changed during read: {relative_text}")
            return b"".join(chunks)
        finally:
            os.close(file_descriptor)
    except OSError as error:
        raise EvidenceReleaseError(
            f"package path is missing or contains a symlink: {relative_text}"
        ) from error
    finally:
        os.close(descriptor)


def _validate_reservation(raw: bytes) -> dict[str, Any]:
    reservation = _load_canonical_line(raw, label="attempt reservation")
    fields = {
        "schemaVersion",
        "status",
        "suiteId",
        "attemptId",
        "createdAt",
        "designSHA256",
        "snapshotRegistrationSHA256",
        "designPublicationReceiptSHA256",
        "snapshotPublicationReceiptSHA256",
        "privateSnapshotManifestSHA256",
        "runtimeManifestSHA256",
        "modelAssetSourceManifestSHA256",
        "fullAssetReceiptSHA256",
        "githubGateReceiptSHA256",
        "corpusManifestSHA256",
        "codecCommit",
        "codecTree",
        "labCommit",
        "labTree",
        "targetPulseTimestamp",
        "countsTowardScientificVerdict",
        "retryPermitted",
        "reservationContentSHA256",
    }
    if set(reservation) != fields:
        raise EvidenceReleaseError("attempt reservation fields differ")
    if (
        reservation["schemaVersion"]
        != "corelm-crossmodel-livewiki-v4-attempt-reservation-v1"
        or reservation["status"] != "RESERVED"
        or reservation["suiteId"] != SUITE_ID
        or reservation["countsTowardScientificVerdict"] is not False
        or reservation["retryPermitted"] is not False
        or reservation["targetPulseTimestamp"] != TARGET_PULSE_TIMESTAMP
    ):
        raise EvidenceReleaseError("attempt reservation identity/state differs")
    if (
        not isinstance(reservation["attemptId"], str)
        or ATTEMPT_ID.fullmatch(reservation["attemptId"]) is None
    ):
        raise EvidenceReleaseError("attempt reservation ID is invalid")
    created = _validate_utc_second(
        reservation["createdAt"], "reservation createdAt"
    )
    if not ONE_SHOT_NOT_BEFORE <= created < HARD_DEADLINE:
        raise EvidenceReleaseError("attempt reservation is outside the frozen window")
    for field in (
        "designSHA256",
        "snapshotRegistrationSHA256",
        "designPublicationReceiptSHA256",
        "snapshotPublicationReceiptSHA256",
        "privateSnapshotManifestSHA256",
        "runtimeManifestSHA256",
        "modelAssetSourceManifestSHA256",
        "fullAssetReceiptSHA256",
        "githubGateReceiptSHA256",
        "corpusManifestSHA256",
        "reservationContentSHA256",
    ):
        _validate_sha256(reservation[field], f"reservation {field}")
    for field in ("codecCommit", "codecTree", "labCommit", "labTree"):
        if (
            not isinstance(reservation[field], str)
            or HEX_40.fullmatch(reservation[field]) is None
        ):
            raise EvidenceReleaseError(
                f"reservation {field} is not a Git object ID"
            )
    unsigned = dict(reservation)
    digest = unsigned.pop("reservationContentSHA256")
    if sha256_bytes(canonical_json_bytes(unsigned)) != digest:
        raise EvidenceReleaseError("attempt reservation self-digest differs")
    return reservation


def _validate_marker(raw: bytes) -> dict[str, Any]:
    marker = _load_canonical_line(raw, label="attempt marker")
    fields = {
        "schemaVersion",
        "status",
        "suiteId",
        "attemptId",
        "createdAt",
        "designSHA256",
        "snapshotRegistrationSHA256",
        "designPublicationReceiptSHA256",
        "snapshotPublicationReceiptSHA256",
        "privateSnapshotManifestSHA256",
        "runtimeManifestSHA256",
        "modelAssetSourceManifestSHA256",
        "fullAssetReceiptSHA256",
        "githubGateReceiptSHA256",
        "corpusManifestSHA256",
        "codecCommit",
        "codecTree",
        "labCommit",
        "labTree",
        "targetPulseTimestamp",
        "countsTowardScientificVerdict",
        "retryPermitted",
        "markerContentSHA256",
    }
    if set(marker) != fields:
        raise EvidenceReleaseError("attempt marker fields differ")
    if (
        marker["schemaVersion"] != "corelm-crossmodel-livewiki-v4-attempt-v1"
        or marker["status"] != "STARTED"
        or marker["suiteId"] != SUITE_ID
        or marker["countsTowardScientificVerdict"] is not True
        or marker["retryPermitted"] is not False
        or marker["targetPulseTimestamp"] != TARGET_PULSE_TIMESTAMP
    ):
        raise EvidenceReleaseError("attempt marker identity/state differs")
    if (
        not isinstance(marker["attemptId"], str)
        or ATTEMPT_ID.fullmatch(marker["attemptId"]) is None
    ):
        raise EvidenceReleaseError("attempt marker ID is invalid")
    created = _validate_utc_second(marker["createdAt"], "attempt createdAt")
    if not ONE_SHOT_NOT_BEFORE <= created < HARD_DEADLINE:
        raise EvidenceReleaseError("attempt marker is outside the frozen window")
    for field in (
        "designSHA256",
        "snapshotRegistrationSHA256",
        "designPublicationReceiptSHA256",
        "snapshotPublicationReceiptSHA256",
        "privateSnapshotManifestSHA256",
        "runtimeManifestSHA256",
        "modelAssetSourceManifestSHA256",
        "fullAssetReceiptSHA256",
        "githubGateReceiptSHA256",
        "corpusManifestSHA256",
        "markerContentSHA256",
    ):
        _validate_sha256(marker[field], f"marker {field}")
    for field in ("codecCommit", "codecTree", "labCommit", "labTree"):
        if not isinstance(marker[field], str) or HEX_40.fullmatch(marker[field]) is None:
            raise EvidenceReleaseError(f"marker {field} is not a Git object ID")
    unsigned = dict(marker)
    digest = unsigned.pop("markerContentSHA256")
    if sha256_bytes(canonical_json_bytes(unsigned)) != digest:
        raise EvidenceReleaseError("attempt marker self-digest differs")
    return marker


def _bind_reservation_to_marker(
    reservation: dict[str, Any], marker: dict[str, Any]
) -> None:
    for field in COMMITMENT_FIELDS:
        if reservation[field] != marker[field]:
            raise EvidenceReleaseError(
                f"attempt marker differs from reservation: {field}"
            )


def _validate_outcome(
    raw: bytes, *, marker: dict[str, Any], marker_raw: bytes
) -> dict[str, Any]:
    outcome = _load_canonical_line(raw, label="terminal outcome")
    fields = {
        "schemaVersion",
        "suiteId",
        "attemptId",
        "terminalState",
        "completedAt",
        "attemptMarkerFileSHA256",
        "resultSHA256",
        "evidenceManifestSHA256",
        "independentVerifierSHA256",
        "failureReason",
        "retryPermitted",
        "countsTowardScientificVerdict",
    }
    if set(outcome) != fields:
        raise EvidenceReleaseError("terminal outcome fields differ")
    state = outcome["terminalState"]
    if (
        outcome["schemaVersion"] != "corelm-crossmodel-livewiki-v4-outcome-v1"
        or outcome["suiteId"] != marker["suiteId"]
        or outcome["attemptId"] != marker["attemptId"]
        or state not in TERMINAL_STATES
        or outcome["retryPermitted"] is not False
        or outcome["attemptMarkerFileSHA256"] != sha256_bytes(marker_raw)
    ):
        raise EvidenceReleaseError("terminal outcome binding/state differs")
    completed = _validate_utc_second(outcome["completedAt"], "outcome completedAt")
    if completed < marker["createdAt"]:
        raise EvidenceReleaseError("terminal outcome precedes the attempt marker")
    if state in {"PASS", "FAIL_GATES"}:
        if completed >= HARD_DEADLINE:
            raise EvidenceReleaseError(
                "gate outcome was not durably completed before the hard deadline"
            )
        for field in (
            "resultSHA256",
            "evidenceManifestSHA256",
            "independentVerifierSHA256",
        ):
            _validate_sha256(outcome[field], f"outcome {field}")
        if (
            outcome["failureReason"] is not None
            or outcome["countsTowardScientificVerdict"] is not True
        ):
            raise EvidenceReleaseError("gate outcome has invalid verdict fields")
    else:
        for field in (
            "resultSHA256",
            "evidenceManifestSHA256",
            "independentVerifierSHA256",
        ):
            if outcome[field] is not None:
                _validate_sha256(outcome[field], f"outcome {field}")
        if not isinstance(outcome["failureReason"], str) or not outcome["failureReason"]:
            raise EvidenceReleaseError("execution outcome has no failure reason")
        if outcome["countsTowardScientificVerdict"] is not False:
            raise EvidenceReleaseError("execution outcome incorrectly claims a verdict")
    return outcome


def _entry_digest(entries: Iterable[dict[str, Any]]) -> str:
    return sha256_bytes(canonical_json_bytes(list(entries)))


def _expected_role(path: str) -> str:
    if path.startswith("payload/attempt/"):
        return "attempt-evidence"
    if path.startswith("payload/corpus/"):
        return "public-corpus"
    if path.startswith("payload/bindings/nist-trust/"):
        return "nist-trust"
    if path.startswith("payload/bindings/publication/design-assets/"):
        return "design-release-asset"
    if path.startswith("payload/bindings/publication/snapshot-assets/"):
        return "snapshot-release-asset"
    fixed = {
        destination: role for destination, role in BINDING_DESTINATIONS.values()
    }
    role = fixed.get(path)
    if role is None:
        raise EvidenceReleaseError(f"path has no canonical evidence role: {path}")
    return role


def _group_summaries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {
        "attempt": [],
        "corpus": [],
        "frozenBindings": [],
        "nistTrust": [],
    }
    for entry in entries:
        path = entry["path"]
        if path.startswith("payload/attempt/"):
            groups["attempt"].append(entry)
        elif path.startswith("payload/corpus/"):
            groups["corpus"].append(entry)
        elif path.startswith("payload/bindings/nist-trust/"):
            groups["nistTrust"].append(entry)
        elif path.startswith("payload/bindings/"):
            groups["frozenBindings"].append(entry)
        else:
            raise EvidenceReleaseError(f"entry is outside a canonical group: {path}")
    result: dict[str, Any] = {}
    prefixes = {
        "attempt": "payload/attempt/",
        "corpus": "payload/corpus/",
        "frozenBindings": "payload/bindings/",
        "nistTrust": "payload/bindings/nist-trust/",
    }
    for name in ("attempt", "corpus", "frozenBindings", "nistTrust"):
        values = groups[name]
        result[name] = {
            "prefix": prefixes[name],
            "entryCount": len(values),
            "totalBytes": sum(item["bytes"] for item in values),
            "entriesSHA256": _entry_digest(values),
        }
    return result


def _validate_required_source_layout(entry_paths: set[str]) -> None:
    corpus_required = {
        "payload/corpus/corpus-manifest.json",
        "payload/corpus/crawl-1-manifest.json",
        "payload/corpus/crawl-2-manifest.json",
    }
    missing = sorted(corpus_required - entry_paths)
    if missing:
        raise EvidenceReleaseError(
            "public corpus package is incomplete: " + ", ".join(missing)
        )
    prefix_requirements = {
        "crawl-1 raw HTTP archive": "payload/corpus/archive/crawl-1/",
        "crawl-2 raw HTTP archive": "payload/corpus/archive/crawl-2/",
        "revision raw HTTP archive": "payload/corpus/archive/revisions/",
        "eligible ledgers": "payload/corpus/ledgers/",
        "canonical corpus records": "payload/corpus/records/",
        "NIST certificate chain": "payload/bindings/nist-trust/certificates/",
    }
    for label, prefix in prefix_requirements.items():
        if not any(path.startswith(prefix) for path in entry_paths):
            raise EvidenceReleaseError(f"package has no {label}")
    if "payload/bindings/nist-trust/manifest.json" not in entry_paths:
        raise EvidenceReleaseError("package has no NIST trust manifest")


def _verify_inner_evidence_manifest(
    root: Path, *, expected_digest: str | None
) -> None:
    path = "payload/attempt/evidence-manifest.json"
    raw = _read_beneath(root, path)
    if expected_digest is not None and sha256_bytes(raw) != expected_digest:
        raise EvidenceReleaseError("producer evidence manifest differs from outcome")
    manifest = _load_canonical_line(raw, label="producer evidence manifest")
    if set(manifest) != {"schemaVersion", "entries", "entriesSHA256"}:
        raise EvidenceReleaseError("producer evidence manifest fields differ")
    if manifest["schemaVersion"] != "corelm-crossmodel-livewiki-v4-evidence-manifest-v1":
        raise EvidenceReleaseError("producer evidence manifest schema differs")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise EvidenceReleaseError("producer evidence manifest is empty")
    if manifest["entriesSHA256"] != sha256_bytes(canonical_json_bytes(entries)):
        raise EvidenceReleaseError("producer evidence entry digest differs")
    previous: str | None = None
    observed_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise EvidenceReleaseError("producer evidence entry fields differ")
        relative = _safe_relative(entry["path"], label="producer evidence path")
        if previous is not None and entry["path"] <= previous:
            raise EvidenceReleaseError("producer evidence paths are not sorted")
        previous = entry["path"]
        observed_paths.add(entry["path"])
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise EvidenceReleaseError("producer evidence byte count is invalid")
        _validate_sha256(entry["sha256"], "producer evidence SHA-256")
        payload = _read_beneath(
            root,
            "payload/attempt/" + relative.as_posix(),
            expected_bytes=entry["bytes"],
        )
        if sha256_bytes(payload) != entry["sha256"]:
            raise EvidenceReleaseError("producer evidence entry digest differs")
    missing_page_tokens = sorted(INNER_PAGE_TOKEN_PATHS - observed_paths)
    if missing_page_tokens:
        raise EvidenceReleaseError(
            "producer evidence manifest omits page-token evidence: "
            + ", ".join(missing_page_tokens)
        )
    missing_state = sorted(INNER_DURABLE_STATE_PATHS - observed_paths)
    if missing_state:
        raise EvidenceReleaseError(
            "producer evidence manifest omits durable attempt state: "
            + ", ".join(missing_state)
        )


def _forensic_record(
    root: Path, path: str, condition: str
) -> dict[str, Any]:
    raw = _read_beneath(root, path)
    return {
        "path": path,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "condition": condition,
    }


def _classify_state_files(
    root: Path, *, entry_paths: set[str]
) -> tuple[
    dict[str, Any],
    dict[str, Any] | None,
    bytes | None,
    dict[str, Any] | None,
    list[dict[str, Any]],
]:
    reservation_path = ARTIFACT_PATHS["attemptReservation"]
    if reservation_path not in entry_paths:
        raise EvidenceReleaseError("result root has no durable attempt reservation")
    reservation = _validate_reservation(_read_beneath(root, reservation_path))
    forensic = [
        _forensic_record(root, path, condition)
        for path, condition in FORENSIC_PATHS.items()
        if path in entry_paths
    ]

    marker: dict[str, Any] | None = None
    marker_raw: bytes | None = None
    marker_path = ARTIFACT_PATHS["attemptMarker"]
    if marker_path in entry_paths:
        candidate = _read_beneath(root, marker_path)
        try:
            marker = _validate_marker(candidate)
            _bind_reservation_to_marker(reservation, marker)
            marker_raw = candidate
        except EvidenceReleaseError:
            forensic.append(
                _forensic_record(
                    root,
                    marker_path,
                    "PARTIAL_OR_NONCANONICAL_ATTEMPT_MARKER",
                )
            )

    outcome: dict[str, Any] | None = None
    outcome_path = ARTIFACT_PATHS["terminalOutcome"]
    if outcome_path in entry_paths:
        if marker is None or marker_raw is None:
            forensic.append(
                _forensic_record(
                    root,
                    outcome_path,
                    "UNVERIFIABLE_OR_PARTIAL_TERMINAL_OUTCOME",
                )
            )
        else:
            candidate = _read_beneath(root, outcome_path)
            try:
                outcome = _validate_outcome(
                    candidate, marker=marker, marker_raw=marker_raw
                )
            except EvidenceReleaseError:
                forensic.append(
                    _forensic_record(
                        root,
                        outcome_path,
                        "PARTIAL_OR_NONCANONICAL_TERMINAL_OUTCOME",
                    )
                )
    forensic.sort(key=lambda item: (item["path"], item["condition"]))
    return reservation, marker, marker_raw, outcome, forensic


def _verify_component_bindings(
    root: Path,
    *,
    artifact_presence: dict[str, bool],
    terminal_state: str | None,
    entry_paths: set[str],
    forensic_artifacts: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    reservation, marker, _marker_raw, outcome, observed_forensic = (
        _classify_state_files(root, entry_paths=entry_paths)
    )
    if forensic_artifacts != observed_forensic:
        raise EvidenceReleaseError("forensic state-file inventory differs")
    binding = marker if marker is not None else reservation
    if outcome is not None:
        if terminal_state != outcome["terminalState"]:
            raise EvidenceReleaseError("manifest terminal state differs from outcome")
    elif terminal_state is not None:
        raise EvidenceReleaseError("partial package cannot declare a terminal state")

    binding_paths = {
        "designSHA256": "payload/bindings/design.json",
        "snapshotRegistrationSHA256": "payload/bindings/snapshot-registration.json",
        "designPublicationReceiptSHA256": (
            "payload/bindings/publication/design-receipt.json"
        ),
        "snapshotPublicationReceiptSHA256": (
            "payload/bindings/publication/snapshot-receipt.json"
        ),
        "runtimeManifestSHA256": "payload/bindings/runtime-manifest.json",
        "modelAssetSourceManifestSHA256": (
            "payload/bindings/model-assets-source.json"
        ),
        "fullAssetReceiptSHA256": "payload/bindings/asset-receipt.json",
        "githubGateReceiptSHA256": (
            "payload/bindings/publication/design-assets/github-gate-receipt.json"
        ),
        "corpusManifestSHA256": "payload/corpus/corpus-manifest.json",
    }
    binding_raw: dict[str, bytes] = {}
    for marker_field, path in binding_paths.items():
        raw = _read_beneath(root, path)
        binding_raw[path] = raw
        if sha256_bytes(raw) != binding[marker_field]:
            raise EvidenceReleaseError(
                f"package binding differs from attempt commitment: {marker_field}"
            )
    if artifact_presence["privateSnapshotManifest"]:
        private_raw = _read_beneath(root, ARTIFACT_PATHS["privateSnapshotManifest"])
        if sha256_bytes(private_raw) != binding["privateSnapshotManifestSHA256"]:
            raise EvidenceReleaseError(
                "private snapshot manifest differs from attempt commitment"
            )
        private_manifest = _load_canonical_line(
            private_raw, label="private snapshot manifest"
        )
        for field in (
            "designSHA256",
            "snapshotRegistrationSHA256",
            "designPublicationReceiptSHA256",
            "snapshotPublicationReceiptSHA256",
            "runtimeManifestSHA256",
            "modelAssetSourceManifestSHA256",
            "fullAssetReceiptSHA256",
            "corpusManifestSHA256",
            "codecCommit",
            "codecTree",
            "labCommit",
            "labTree",
        ):
            if private_manifest.get(field) != binding[field]:
                raise EvidenceReleaseError(
                    f"private snapshot/attempt binding differs: {field}"
                )

    design = _load_json_document(
        binding_raw["payload/bindings/design.json"], label="frozen design"
    )
    snapshot = _load_json_document(
        binding_raw["payload/bindings/snapshot-registration.json"],
        label="snapshot registration",
    )
    freeze_raw = _read_beneath(root, "payload/bindings/freeze-manifest.json")
    runtime_raw = binding_raw["payload/bindings/runtime-manifest.json"]
    asset_source_raw = binding_raw["payload/bindings/model-assets-source.json"]
    asset_raw = binding_raw["payload/bindings/asset-receipt.json"]
    trust_raw = _read_beneath(root, "payload/bindings/nist-trust/manifest.json")
    ca_raw = _read_beneath(root, "payload/bindings/transport-ca.pem")
    sbom = _load_json_document(
        _read_beneath(root, "payload/bindings/sbom.cdx.json"), label="SBOM"
    )
    freeze = _load_json_document(freeze_raw, label="freeze manifest")
    runtime_manifest = _load_json_document(runtime_raw, label="runtime manifest")
    asset_source = _load_json_document(
        asset_source_raw, label="model asset source manifest"
    )
    asset_receipt = _load_json_document(asset_raw, label="asset receipt")
    _verify_content_digest(freeze, label="freeze manifest")
    runtime_content = _verify_content_digest(
        runtime_manifest, label="runtime manifest"
    )
    asset_content = _verify_content_digest(asset_receipt, label="asset receipt")
    if (
        runtime_manifest.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v4-runtime-manifest-v1"
        or runtime_manifest.get("status")
        != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY"
    ):
        raise EvidenceReleaseError("packaged runtime manifest identity differs")
    if (
        asset_source.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v4-model-assets-draft-v1"
        or asset_source.get("status")
        != "DRAFT_METADATA_VERIFIED_NO_WEIGHT_DOWNLOAD"
        or asset_source.get("completeRuntimeFileList") is not True
        or asset_source.get("weightsRedistributed") is not False
    ):
        raise EvidenceReleaseError("packaged model asset source manifest differs")
    if (
        asset_receipt.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v4-asset-receipt-v1"
        or asset_receipt.get("status") != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED"
        or asset_receipt.get("fullSafetensorsBytesLocallyVerified") is not True
    ):
        raise EvidenceReleaseError("packaged asset receipt is not a full verified receipt")
    if (
        design.get("schemaVersion") != "corelm-crossmodel-livewiki-v4-design-v1"
        or design.get("suiteId") != SUITE_ID
        or design.get("status") != "PUBLIC_DESIGN_FROZEN"
        or design.get("readyToFreeze") is not True
    ):
        raise EvidenceReleaseError("packaged design is not the frozen public design")
    lab = design.get("labSource")
    runtime = design.get("runtime")
    beacon = design.get("beacon")
    if not isinstance(lab, dict) or lab.get("freezeManifestSHA256") != sha256_bytes(freeze_raw):
        raise EvidenceReleaseError("freeze manifest differs from frozen design")
    if (
        not isinstance(runtime, dict)
        or runtime.get("runtimeManifestSHA256") != sha256_bytes(runtime_raw)
    ):
        raise EvidenceReleaseError("runtime manifest differs from frozen design")
    if not isinstance(beacon, dict):
        raise EvidenceReleaseError("frozen design has no beacon bindings")
    if beacon.get("offlineTrustBundleSHA256") != sha256_bytes(trust_raw):
        raise EvidenceReleaseError("NIST trust manifest differs from frozen design")
    if beacon.get("transportCABundleSHA256") != sha256_bytes(ca_raw):
        raise EvidenceReleaseError("transport CA bundle differs from frozen design")
    if snapshot.get("suiteId") != SUITE_ID:
        raise EvidenceReleaseError("snapshot registration suite differs")
    if snapshot.get("modelAssetSourceManifestSHA256") != sha256_bytes(
        asset_source_raw
    ):
        raise EvidenceReleaseError(
            "model asset source manifest differs from snapshot registration"
        )
    if snapshot.get("fullAssetReceiptSHA256") != sha256_bytes(asset_raw):
        raise EvidenceReleaseError(
            "full asset receipt differs from snapshot registration"
        )
    if snapshot.get("corpusManifestSHA256") != binding["corpusManifestSHA256"]:
        raise EvidenceReleaseError("corpus manifest differs from snapshot registration")
    design_receipt_raw = binding_raw[
        "payload/bindings/publication/design-receipt.json"
    ]
    snapshot_receipt_raw = binding_raw[
        "payload/bindings/publication/snapshot-receipt.json"
    ]
    signing_key_raw = _read_beneath(
        root, "payload/bindings/publication/signing-key.pub"
    )
    if (
        snapshot.get("designPublicationReceiptSHA256")
        != sha256_bytes(design_receipt_raw)
    ):
        raise EvidenceReleaseError("snapshot does not bind the design publication receipt")
    release = design.get("designRelease")
    if (
        not isinstance(release, dict)
        or release.get("signingPublicKeySHA256") != sha256_bytes(signing_key_raw)
    ):
        raise EvidenceReleaseError("release signing public key differs from frozen design")
    if sha256_bytes(snapshot_receipt_raw) != binding[
        "snapshotPublicationReceiptSHA256"
    ]:
        raise EvidenceReleaseError(
            "snapshot publication receipt differs from attempt commitment"
        )
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise EvidenceReleaseError("packaged SBOM is not the frozen CycloneDX 1.5 SBOM")
    metadata = sbom.get("metadata")
    properties = metadata.get("properties") if isinstance(metadata, dict) else None
    if not isinstance(properties, list):
        raise EvidenceReleaseError("packaged SBOM has no provenance properties")
    observed_properties: dict[str, Any] = {}
    for item in properties:
        if not isinstance(item, dict) or set(item) != {"name", "value"}:
            raise EvidenceReleaseError("packaged SBOM property fields differ")
        name = item["name"]
        if not isinstance(name, str) or name in observed_properties:
            raise EvidenceReleaseError("packaged SBOM property name is invalid/duplicated")
        observed_properties[name] = item["value"]
    if (
        observed_properties.get("corelm:runtime-manifest-content-sha256")
        != runtime_content
        or observed_properties.get("corelm:asset-receipt-content-sha256")
        != asset_content
        or observed_properties.get("corelm:counts-toward-scientific-verdict")
        != "false"
    ):
        raise EvidenceReleaseError("packaged SBOM provenance bindings differ")

    if outcome is not None:
        digest_paths = {
            "resultSHA256": ARTIFACT_PATHS["producerResult"],
            "evidenceManifestSHA256": ARTIFACT_PATHS["producerEvidenceManifest"],
            "independentVerifierSHA256": ARTIFACT_PATHS[
                "independentVerifierReport"
            ],
        }
        for field, path in digest_paths.items():
            expected = outcome[field]
            if expected is None:
                continue
            if not artifact_presence[
                {
                    "resultSHA256": "producerResult",
                    "evidenceManifestSHA256": "producerEvidenceManifest",
                    "independentVerifierSHA256": "independentVerifierReport",
                }[field]
            ]:
                raise EvidenceReleaseError(f"outcome binds an absent file: {field}")
            if sha256_bytes(_read_beneath(root, path)) != expected:
                raise EvidenceReleaseError(f"outcome digest differs: {field}")

        if outcome["terminalState"] in {"PASS", "FAIL_GATES"}:
            result = _load_canonical_line(
                _read_beneath(root, ARTIFACT_PATHS["producerResult"]),
                label="producer result",
            )
            report = _load_canonical_line(
                _read_beneath(root, ARTIFACT_PATHS["independentVerifierReport"]),
                label="independent verifier report",
            )
            if (
                result.get("suiteId") != binding["suiteId"]
                or result.get("attemptId") != binding["attemptId"]
                or result.get("countsTowardScientificVerdict") is not True
                or report.get("suiteId") != binding["suiteId"]
                or report.get("attemptId") != binding["attemptId"]
                or report.get("producerResultExactMatch") is not True
            ):
                raise EvidenceReleaseError("result/verifier report binding differs")
            replay = report.get("modelReplaySummary")
            if not isinstance(replay, dict):
                raise EvidenceReleaseError(
                    "independent verifier report omits real-model replay"
                )
            replay_unsigned = dict(replay)
            replay_digest = replay_unsigned.pop("contentSHA256", None)
            if (
                replay_digest
                != sha256_bytes(canonical_json_bytes(replay_unsigned))
                or report.get("modelReplaySummarySHA256") != replay_digest
                or replay.get("replayComplete") is not True
                or replay.get("exactTokenIds") is not True
                or replay.get("exactLossFloat32Bits") is not True
                or replay.get("exactTop1TokenIds") is not True
                or replay.get("allContainerInputsBoundToBaselineCache") is not True
                or replay.get("countsTowardScientificVerdict") is not True
            ):
                raise EvidenceReleaseError(
                    "independent real-model replay proof is incomplete"
                )
            expected_state = "PASS" if result.get("suitePass") is True else "FAIL_GATES"
            if (
                outcome["terminalState"] != expected_state
                or report.get("verdict") != expected_state
            ):
                raise EvidenceReleaseError("terminal result and verifier verdict disagree")
            _verify_inner_evidence_manifest(
                root, expected_digest=outcome["evidenceManifestSHA256"]
            )
    return binding, outcome


def _manifest_without_digest(manifest: dict[str, Any]) -> dict[str, Any]:
    value = dict(manifest)
    value.pop("contentSHA256", None)
    return value


def _finalize_manifest_for_root(
    root: Path, entries: list[dict[str, Any]], *, created_at: str
) -> dict[str, Any]:
    entries.sort(key=lambda item: item["path"].encode("utf-8"))
    entry_paths = {item["path"] for item in entries}
    if len(entry_paths) != len(entries):
        raise EvidenceReleaseError("package contains duplicate destination paths")
    _validate_required_source_layout(entry_paths)
    artifact_presence = {
        name: path in entry_paths for name, path in ARTIFACT_PATHS.items()
    }
    reservation, marker, _marker_raw, outcome, forensic_artifacts = (
        _classify_state_files(root, entry_paths=entry_paths)
    )
    binding = marker if marker is not None else reservation
    terminal_state: str | None = None
    package_status = "PARTIAL_CONSUMED_INCOMPLETE"
    recovery_classification: str | None = "CONSUMED_INCOMPLETE"
    attempt_counts = False
    if outcome is not None:
        terminal_state = outcome["terminalState"]
        package_status = "COMPLETE_TERMINAL"
        recovery_classification = None
        attempt_counts = outcome["countsTowardScientificVerdict"]
    if terminal_state in {"PASS", "FAIL_GATES"}:
        missing_gate = sorted(
            path
            for name, path in ARTIFACT_PATHS.items()
            if not artifact_presence[name]
        )
        if missing_gate:
            raise EvidenceReleaseError(
                "gate outcome is missing required evidence: " + ", ".join(missing_gate)
            )
    missing = sorted(
        path for name, path in ARTIFACT_PATHS.items() if not artifact_presence[name]
    )
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "suiteId": binding["suiteId"],
        "attemptId": binding["attemptId"],
        "createdAt": _validate_utc_second(created_at, "package createdAt"),
        "packageStatus": package_status,
        "recoveryClassification": recovery_classification,
        "terminalState": terminal_state,
        "attemptCountsTowardScientificVerdict": attempt_counts,
        "artifactPresence": artifact_presence,
        "forensicArtifacts": forensic_artifacts,
        "missingArtifacts": missing,
        "groups": _group_summaries(entries),
        "entries": entries,
        "entryCount": len(entries),
        "totalBytes": sum(item["bytes"] for item in entries),
        "entriesSHA256": _entry_digest(entries),
    }
    manifest["contentSHA256"] = sha256_bytes(canonical_json_bytes(manifest))
    return manifest


def _verify_manifest_structure(manifest: Any) -> None:
    fields = {
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
    if not isinstance(manifest, dict) or set(manifest) != fields:
        raise EvidenceReleaseError("evidence release manifest fields differ")
    if (
        manifest["schemaVersion"] != SCHEMA_VERSION
        or manifest["suiteId"] != SUITE_ID
        or not isinstance(manifest["attemptId"], str)
        or ATTEMPT_ID.fullmatch(manifest["attemptId"]) is None
        or manifest["packageStatus"] not in {
            "COMPLETE_TERMINAL",
            "PARTIAL_CONSUMED_INCOMPLETE",
        }
        or type(manifest["attemptCountsTowardScientificVerdict"]) is not bool
    ):
        raise EvidenceReleaseError("evidence release manifest identity/state differs")
    _validate_utc_second(manifest["createdAt"], "manifest createdAt")
    if manifest["packageStatus"] == "PARTIAL_CONSUMED_INCOMPLETE":
        if (
            manifest["terminalState"] is not None
            or manifest["attemptCountsTowardScientificVerdict"] is not False
            or manifest["recoveryClassification"] != "CONSUMED_INCOMPLETE"
        ):
            raise EvidenceReleaseError("partial package declares a terminal verdict")
    elif (
        manifest["terminalState"] not in TERMINAL_STATES
        or manifest["recoveryClassification"] is not None
    ):
        raise EvidenceReleaseError("complete package has invalid recovery/terminal state")
    presence = manifest["artifactPresence"]
    if not isinstance(presence, dict) or set(presence) != set(ARTIFACT_PATHS):
        raise EvidenceReleaseError("artifact presence fields differ")
    if any(type(value) is not bool for value in presence.values()):
        raise EvidenceReleaseError("artifact presence values must be booleans")
    if presence["attemptReservation"] is not True:
        raise EvidenceReleaseError("package does not contain its attempt reservation")
    expected_missing = sorted(
        path for name, path in ARTIFACT_PATHS.items() if not presence[name]
    )
    if manifest["missingArtifacts"] != expected_missing:
        raise EvidenceReleaseError("explicit missing-artifact list differs")
    forensic = manifest["forensicArtifacts"]
    if not isinstance(forensic, list):
        raise EvidenceReleaseError("forensic artifact inventory is not a list")
    previous_forensic: tuple[str, str] | None = None
    for item in forensic:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "bytes",
            "sha256",
            "condition",
        }:
            raise EvidenceReleaseError("forensic artifact fields differ")
        path = _safe_relative(item["path"], label="forensic artifact path").as_posix()
        if not path.startswith("payload/attempt/"):
            raise EvidenceReleaseError("forensic artifact is outside the attempt root")
        key = (path, item["condition"])
        if previous_forensic is not None and key <= previous_forensic:
            raise EvidenceReleaseError("forensic artifacts are not strictly sorted")
        previous_forensic = key
        if type(item["bytes"]) is not int or item["bytes"] < 0:
            raise EvidenceReleaseError("forensic artifact byte count is invalid")
        _validate_sha256(item["sha256"], "forensic artifact SHA-256")
        if item["condition"] not in {
            "INTERRUPTED_RESERVATION_PUBLICATION_CLEANUP",
            "INTERRUPTED_ATTEMPT_MARKER_PUBLICATION",
            "INTERRUPTED_TERMINAL_OUTCOME_PUBLICATION",
            "PARTIAL_OR_NONCANONICAL_ATTEMPT_MARKER",
            "PARTIAL_OR_NONCANONICAL_TERMINAL_OUTCOME",
            "UNVERIFIABLE_OR_PARTIAL_TERMINAL_OUTCOME",
        }:
            raise EvidenceReleaseError("forensic artifact condition is invalid")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise EvidenceReleaseError("evidence release has no entries")
    previous: bytes | None = None
    observed: set[str] = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256", "role"}:
            raise EvidenceReleaseError("evidence release entry fields differ")
        path = _safe_relative(entry["path"], label="manifest entry path").as_posix()
        encoded = path.encode("utf-8")
        if previous is not None and encoded <= previous:
            raise EvidenceReleaseError("manifest entry paths are not strictly sorted")
        previous = encoded
        if path in observed:
            raise EvidenceReleaseError("manifest entry path is duplicated")
        observed.add(path)
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise EvidenceReleaseError("manifest entry byte count is invalid")
        total += entry["bytes"]
        _validate_sha256(entry["sha256"], "manifest entry SHA-256")
        if entry["role"] not in ROLES or entry["role"] != _expected_role(path):
            raise EvidenceReleaseError("manifest entry role/path binding is invalid")
    if (
        manifest["entryCount"] != len(entries)
        or manifest["totalBytes"] != total
        or manifest["entriesSHA256"] != _entry_digest(entries)
        or manifest["groups"] != _group_summaries(entries)
    ):
        raise EvidenceReleaseError("manifest aggregate commitments differ")
    content_digest = _validate_sha256(manifest["contentSHA256"], "manifest content digest")
    if sha256_bytes(canonical_json_bytes(_manifest_without_digest(manifest))) != content_digest:
        raise EvidenceReleaseError("manifest content self-digest differs")
    expected_presence = {
        name: path in observed for name, path in ARTIFACT_PATHS.items()
    }
    if presence != expected_presence:
        raise EvidenceReleaseError("artifact presence differs from manifest entries")
    _validate_required_source_layout(observed)


def _observed_package_files(root: Path) -> set[str]:
    observed = {relative for relative, _ in _walk_regular(root)}
    if MANIFEST_FILENAME not in observed:
        raise EvidenceReleaseError("evidence release manifest is absent")
    return observed


def verify_release(root: Path) -> dict[str, Any]:
    root = _resolved_real_path(root, directory=True)
    manifest_raw = _read_beneath(root, MANIFEST_FILENAME)
    manifest = _load_canonical_line(manifest_raw, label="evidence release manifest")
    _verify_manifest_structure(manifest)
    expected_files = {MANIFEST_FILENAME}
    for entry in manifest["entries"]:
        raw = _read_beneath(root, entry["path"], expected_bytes=entry["bytes"])
        if sha256_bytes(raw) != entry["sha256"]:
            raise EvidenceReleaseError(f"package entry SHA-256 differs: {entry['path']}")
        expected_files.add(entry["path"])
    observed_files = _observed_package_files(root)
    if observed_files != expected_files:
        extras = sorted(observed_files - expected_files)
        missing = sorted(expected_files - observed_files)
        raise EvidenceReleaseError(
            "package file set differs; extra="
            + repr(extras)
            + "; missing="
            + repr(missing)
        )
    entry_paths = {entry["path"] for entry in manifest["entries"]}
    binding, outcome = _verify_component_bindings(
        root,
        artifact_presence=manifest["artifactPresence"],
        terminal_state=manifest["terminalState"],
        entry_paths=entry_paths,
        forensic_artifacts=manifest["forensicArtifacts"],
    )
    if (
        binding["suiteId"] != manifest["suiteId"]
        or binding["attemptId"] != manifest["attemptId"]
    ):
        raise EvidenceReleaseError("top manifest differs from attempt commitment")
    if manifest["createdAt"] < binding["createdAt"]:
        raise EvidenceReleaseError("package timestamp precedes the attempt reservation")
    if outcome is not None and manifest["createdAt"] < outcome["completedAt"]:
        raise EvidenceReleaseError("package timestamp precedes the terminal outcome")
    expected_counts = (
        outcome["countsTowardScientificVerdict"] if outcome is not None else False
    )
    if manifest["attemptCountsTowardScientificVerdict"] is not expected_counts:
        raise EvidenceReleaseError("top manifest verdict flag differs from outcome")
    status = (
        "VERIFIED_COMPLETE_TERMINAL"
        if outcome is not None
        else "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE"
    )
    report = {
        "schemaVersion": VERIFICATION_SCHEMA,
        "status": status,
        "suiteId": manifest["suiteId"],
        "attemptId": manifest["attemptId"],
        "recoveryClassification": manifest["recoveryClassification"],
        "terminalState": manifest["terminalState"],
        "attemptCountsTowardScientificVerdict": manifest[
            "attemptCountsTowardScientificVerdict"
        ],
        "entryCount": manifest["entryCount"],
        "totalBytes": manifest["totalBytes"],
        "manifestFileSHA256": sha256_bytes(manifest_raw),
        "manifestContentSHA256": manifest["contentSHA256"],
        "missingArtifacts": manifest["missingArtifacts"],
        "forensicArtifacts": manifest["forensicArtifacts"],
    }
    report["contentSHA256"] = sha256_bytes(canonical_json_bytes(report))
    return report


def _seal_directories(root: Path) -> None:
    directories: list[Path] = []
    for directory, child_directories, _filenames in os.walk(root, topdown=True, followlinks=False):
        directories.append(Path(directory))
        for child in child_directories:
            path = Path(directory) / child
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceReleaseError(f"unsafe package directory before seal: {path}")
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        _fsync_directory(directory)
        os.chmod(directory, 0o555, follow_symlinks=False)


def _link_stage_member_exclusive(
    stage: Path, output: Path, relative_text: str
) -> None:
    """Publish one verified staged file without any overwrite primitive."""

    relative = _safe_relative(relative_text, label="staged publication path")
    source = stage.joinpath(*relative.parts)
    destination = _ensure_destination_parent(output, relative)
    source_metadata = os.lstat(source)
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISREG(
        source_metadata.st_mode
    ):
        raise EvidenceReleaseError(
            f"unsafe staged publication member: {relative_text}"
        )
    try:
        # stage and output are siblings on the same filesystem.  POSIX link(2)
        # is atomic and fails when destination already exists; unlike rename,
        # it can never replace a concurrent empty directory or regular file.
        os.link(source, destination, follow_symlinks=False)
    except OSError as error:
        raise EvidenceReleaseError(
            f"staged publication member already exists or cannot be linked: {relative_text}"
        ) from error
    destination_metadata = os.lstat(destination)
    if (
        stat.S_ISLNK(destination_metadata.st_mode)
        or not stat.S_ISREG(destination_metadata.st_mode)
        or (destination_metadata.st_dev, destination_metadata.st_ino)
        != (source_metadata.st_dev, source_metadata.st_ino)
    ):
        raise EvidenceReleaseError(
            f"published member identity differs: {relative_text}"
        )
    _fsync_directory(destination.parent)


def _remove_successful_stage(stage: Path) -> None:
    """Remove the private hard-link alias only after final verification."""

    files = list(_walk_regular(stage))
    for _relative, path in files:
        os.unlink(path)
    directories: list[Path] = []
    for directory, child_directories, _filenames in os.walk(
        stage, topdown=False, followlinks=False
    ):
        for child in child_directories:
            path = Path(directory) / child
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceReleaseError(
                    f"unsafe staged directory during successful cleanup: {path}"
                )
            directories.append(path)
    for directory in directories:
        os.rmdir(directory)
    os.rmdir(stage)


def _publish_stage_exclusive(stage: Path, output: Path) -> None:
    """Publish a stage under a never-before-existing final root.

    The top manifest is linked last, so an interruption can expose only an
    explicitly incomplete final directory that ``verify_release`` rejects.
    The complete ``.partial-*`` stage remains intact until the materialized
    final directory has passed verification.
    """

    try:
        os.mkdir(output, 0o700)
    except OSError as error:
        raise EvidenceReleaseError(
            "output appeared during package construction or cannot be created"
        ) from error
    _fsync_directory(output.parent)
    staged_files = list(_walk_regular(stage))
    staged_paths = [relative for relative, _path in staged_files]
    if staged_paths.count(MANIFEST_FILENAME) != 1:
        raise EvidenceReleaseError("verified stage has no unique top manifest")
    for relative in staged_paths:
        if relative != MANIFEST_FILENAME:
            _link_stage_member_exclusive(stage, output, relative)
    _fsync_directory(output)
    _link_stage_member_exclusive(stage, output, MANIFEST_FILENAME)
    _fsync_directory(output)


def package_release(
    *,
    attempt_root: Path,
    corpus_root: Path,
    design: Path,
    snapshot_registration: Path,
    freeze_manifest: Path,
    runtime_manifest: Path,
    asset_source_manifest: Path,
    asset_receipt: Path,
    sbom: Path,
    design_publication_receipt: Path,
    snapshot_publication_receipt: Path,
    signing_public_key: Path,
    design_release_assets: Path,
    snapshot_release_assets: Path,
    nist_trust_root: Path,
    transport_ca_bundle: Path,
    output_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    source_directories = {
        "attempt": _resolved_real_path(attempt_root, directory=True),
        "corpus": _resolved_real_path(corpus_root, directory=True),
        "trust": _resolved_real_path(nist_trust_root, directory=True),
        "designReleaseAssets": _resolved_real_path(
            design_release_assets, directory=True
        ),
        "snapshotReleaseAssets": _resolved_real_path(
            snapshot_release_assets, directory=True
        ),
    }
    source_files = {
        "design": _resolved_real_path(design, directory=False),
        "snapshot": _resolved_real_path(snapshot_registration, directory=False),
        "freeze": _resolved_real_path(freeze_manifest, directory=False),
        "runtime": _resolved_real_path(runtime_manifest, directory=False),
        "assetSource": _resolved_real_path(
            asset_source_manifest, directory=False
        ),
        "assetReceipt": _resolved_real_path(asset_receipt, directory=False),
        "sbom": _resolved_real_path(sbom, directory=False),
        "designReceipt": _resolved_real_path(
            design_publication_receipt, directory=False
        ),
        "snapshotReceipt": _resolved_real_path(
            snapshot_publication_receipt, directory=False
        ),
        "signingKey": _resolved_real_path(signing_public_key, directory=False),
        "ca": _resolved_real_path(transport_ca_bundle, directory=False),
    }
    output = Path(os.path.abspath(os.fspath(output_directory)))
    output_parent = _resolved_real_path(output.parent, directory=True)
    output = output_parent / output.name
    if output.name in {"", ".", ".."}:
        raise EvidenceReleaseError("output directory has no safe leaf name")
    for source_root in source_directories.values():
        try:
            output.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise EvidenceReleaseError("output directory is nested inside a source tree")
    if output.exists() or output.is_symlink():
        raise EvidenceReleaseError("output directory already exists")
    stage = output_parent / (
        "." + output.name + ".partial-" + secrets.token_hex(8)
    )
    os.mkdir(stage, 0o700)
    _fsync_directory(output_parent)
    entries: list[dict[str, Any]] = []
    try:
        entries.extend(
            _copy_tree(
                source_directories["attempt"],
                stage,
                "payload/attempt",
                "attempt-evidence",
            )
        )
        entries.extend(
            _copy_tree(
                source_directories["designReleaseAssets"],
                stage,
                "payload/bindings/publication/design-assets",
                "design-release-asset",
            )
        )
        entries.extend(
            _copy_tree(
                source_directories["snapshotReleaseAssets"],
                stage,
                "payload/bindings/publication/snapshot-assets",
                "snapshot-release-asset",
            )
        )
        entries.extend(
            _copy_tree(
                source_directories["corpus"],
                stage,
                "payload/corpus",
                "public-corpus",
            )
        )
        entries.extend(
            _copy_tree(
                source_directories["trust"],
                stage,
                "payload/bindings/nist-trust",
                "nist-trust",
            )
        )
        for name in (
            "design",
            "snapshot",
            "freeze",
            "runtime",
            "assetSource",
            "assetReceipt",
            "sbom",
            "designReceipt",
            "snapshotReceipt",
            "signingKey",
            "ca",
        ):
            destination, role = BINDING_DESTINATIONS[name]
            entries.append(
                _copy_binding(source_files[name], stage, destination, role)
            )
        manifest = _finalize_manifest_for_root(
            stage, entries, created_at=created_at or utc_now_seconds()
        )
        manifest_raw = canonical_json_bytes(manifest) + b"\n"
        _write_new_bytes(stage, MANIFEST_FILENAME, manifest_raw)
        report = verify_release(stage)
        _publish_stage_exclusive(stage, output)
        # Re-open under the public final name before removing the complete
        # forensic stage.  A successful return therefore always reports the
        # bytes an uploader will actually publish.
        final_report = verify_release(output)
        if final_report != report:
            raise EvidenceReleaseError("package changed during final publication")
        _remove_successful_stage(stage)
        _fsync_directory(output_parent)
        _seal_directories(output)
        _fsync_directory(output_parent)
        final_report = verify_release(output)
        if final_report != report:
            raise EvidenceReleaseError("package changed while sealing final publication")
        return final_report
    except BaseException:
        # Deliberately preserve the .partial-* directory for forensic recovery.
        # If exclusive final-root creation already succeeded, that requested
        # directory is also retained; it cannot verify unless the top manifest
        # was linked last and every preceding member is present and exact.
        raise


def _write_report(path: Path, report: dict[str, Any], *, release_root: Path) -> None:
    destination = Path(os.path.abspath(os.fspath(path)))
    release = _resolved_real_path(release_root, directory=True)
    try:
        destination.relative_to(release)
    except ValueError:
        pass
    else:
        raise EvidenceReleaseError("verification report must be outside the sealed package")
    parent = _resolved_real_path(destination.parent, directory=True)
    raw = canonical_json_bytes(report) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent / destination.name, flags, 0o444)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceReleaseError("short verification report write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(parent)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    package = subparsers.add_parser("package", help="build a new immutable package")
    package.add_argument("--attempt-root", type=Path, required=True)
    package.add_argument("--corpus-root", type=Path, required=True)
    package.add_argument("--design", type=Path, required=True)
    package.add_argument("--snapshot-registration", type=Path, required=True)
    package.add_argument("--freeze-manifest", type=Path, required=True)
    package.add_argument("--runtime-manifest", type=Path, required=True)
    package.add_argument("--asset-source-manifest", type=Path, required=True)
    package.add_argument("--asset-receipt", type=Path, required=True)
    package.add_argument("--sbom", type=Path, required=True)
    package.add_argument("--design-publication-receipt", type=Path, required=True)
    package.add_argument("--snapshot-publication-receipt", type=Path, required=True)
    package.add_argument("--signing-public-key", type=Path, required=True)
    package.add_argument("--design-release-assets", type=Path, required=True)
    package.add_argument("--snapshot-release-assets", type=Path, required=True)
    package.add_argument("--nist-trust-root", type=Path, required=True)
    package.add_argument("--transport-ca-bundle", type=Path, required=True)
    package.add_argument("--output-directory", type=Path, required=True)
    package.add_argument("--created-at", help="optional exact UTC whole-second timestamp")
    verify = subparsers.add_parser("verify", help="verify an extracted package offline")
    verify.add_argument("--release-root", type=Path, required=True)
    verify.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "package":
            report = package_release(
                attempt_root=arguments.attempt_root,
                corpus_root=arguments.corpus_root,
                design=arguments.design,
                snapshot_registration=arguments.snapshot_registration,
                freeze_manifest=arguments.freeze_manifest,
                runtime_manifest=arguments.runtime_manifest,
                asset_source_manifest=arguments.asset_source_manifest,
                asset_receipt=arguments.asset_receipt,
                sbom=arguments.sbom,
                design_publication_receipt=arguments.design_publication_receipt,
                snapshot_publication_receipt=arguments.snapshot_publication_receipt,
                signing_public_key=arguments.signing_public_key,
                design_release_assets=arguments.design_release_assets,
                snapshot_release_assets=arguments.snapshot_release_assets,
                nist_trust_root=arguments.nist_trust_root,
                transport_ca_bundle=arguments.transport_ca_bundle,
                output_directory=arguments.output_directory,
                created_at=arguments.created_at,
            )
        else:
            report = verify_release(arguments.release_root)
            if arguments.report is not None:
                _write_report(
                    arguments.report, report, release_root=arguments.release_root
                )
        sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
        return 0
    except (EvidenceReleaseError, OSError, ValueError) as error:
        print(f"EVIDENCE RELEASE FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
