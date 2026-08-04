#!/usr/bin/env python3
"""Durable, fail-closed state transitions for the blind-v2 one-shot.

The result root contains one global attempt reservation, one marker and, at
most, one terminal outcome. A different checkout is not an independent
scientific attempt. This module provides the local durability layer; the later
evidence publication and its verified RFC3161 release-attestation timestamp
provide the public audit trail.
A local file alone does not prove that no hidden attempt existed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESERVATION_FILENAME = "attempt-reservation.json"
ATTEMPT_FILENAME = "attempt-marker.json"
OUTCOME_FILENAME = "terminal-outcome.json"
RESERVATION_PENDING_FILENAME = "attempt-reservation.pending"
ATTEMPT_PENDING_FILENAME = "attempt-marker.pending"
OUTCOME_PENDING_FILENAME = "terminal-outcome.pending"
TERMINAL_STATES = frozenset(
    {
        "PASS",
        "FAIL_GATES",
        "FAIL_EXECUTION",
        "CONSUMED_INCOMPLETE",
    }
)
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
UTC_SECOND = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v2"
TARGET_PULSE_TIMESTAMP = "2026-08-27T18:00:00.000Z"
ONE_SHOT_NOT_BEFORE = "2026-08-28T18:00:00Z"
HARD_DEADLINE = "2026-08-29T18:00:00Z"


class StateMachineError(RuntimeError):
    """Raised when an irreversible one-shot transition is invalid."""


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
        .isoformat()
        .replace("+00:00", "Z")
    )


def _validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise StateMachineError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_git_object(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_40.fullmatch(value) is None:
        raise StateMachineError(f"{label} must be a lowercase Git object ID")
    return value


def _validate_utc_second(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise StateMachineError(f"{label} must be UTC with whole seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise StateMachineError(f"{label} is not a real UTC timestamp") from error
    return value


def _open_result_directory(root: Path) -> tuple[int, Path]:
    # macOS exposes /var and /tmp as fixed system aliases below /private (and
    # tempfile can return paths below either alias).  Translate only those
    # known prefixes after proving their exact system targets.  Calling
    # realpath() on the complete caller path would silently accept an
    # attacker-controlled symlink at the result root or in one of its other
    # components, defeating the no-follow traversal below.
    absolute = Path(os.path.abspath(os.fspath(root)))
    parts = absolute.parts
    if len(parts) >= 2:
        system_aliases = {
            "var": ("/var", "/private/var"),
            "tmp": ("/tmp", "/private/tmp"),
        }
        alias = system_aliases.get(parts[1])
        if (
            alias is not None
            and os.path.islink(alias[0])
            and os.path.realpath(alias[0]) == alias[1]
        ):
            absolute = Path(alias[1], *parts[2:])
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(os.sep, flags)
    try:
        components = absolute.parts[1:]
        if not components:
            raise StateMachineError("filesystem root is not an allowed result root")
        for index, component in enumerate(components):
            final = index == len(components) - 1
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError as error:
                if not final:
                    raise StateMachineError(
                        "result-root parent must already exist and be durable"
                    ) from error
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except OSError as create_error:
                    raise StateMachineError("cannot create result root") from create_error
                _fsync_directory(descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise StateMachineError(
                    "result root cannot be opened without following symlinks"
                ) from error
            observed = os.fstat(child)
            if not stat.S_ISDIR(observed.st_mode):
                os.close(child)
                raise StateMachineError("result-root component is not a directory")
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, absolute


def _fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise StateMachineError("result directory could not be durably synchronized") from error


def _fault_injection(_stage: str) -> None:
    """Test-only crash point.

    Production callers never replace this function.  Tests patch it to raise at
    every persistence boundary and then inspect the bytes left on disk.
    """


def _atomic_publish_at(
    directory: int,
    filename: str,
    pending_filename: str,
    payload: bytes,
) -> None:
    """Publish *payload* once without ever exposing a partial final file.

    The pending inode is deliberately retained after every error.  Once the
    hard link at *filename* exists, a directory fsync makes the publication
    durable before the pending name is removed.  This is supported by both the
    frozen macOS arm64 and Linux runtimes and, unlike rename, cannot overwrite
    an independently published irreversible state.
    """

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(pending_filename, flags, 0o600, dir_fd=directory)
    except FileExistsError as error:
        raise StateMachineError(
            f"pending irreversible state already exists: {pending_filename}"
        ) from error
    except OSError as error:
        raise StateMachineError(
            f"cannot create pending irreversible state: {pending_filename}"
        ) from error
    try:
        _fault_injection(f"{filename}:pending-created")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise StateMachineError(
                    f"short write while creating {pending_filename}"
                )
            written += count
        _fault_injection(f"{filename}:payload-written")
        os.fsync(descriptor)
        _fault_injection(f"{filename}:file-fsynced")
    except BaseException:
        # Never unlink pending bytes.  Once a reservation exists they are raw
        # forensic evidence of a consumed, interrupted transition.
        _fsync_directory(directory)
        raise
    finally:
        os.close(descriptor)
    try:
        os.link(
            pending_filename,
            filename,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
    except FileExistsError as error:
        _fsync_directory(directory)
        raise StateMachineError(
            f"irreversible state already exists: {filename}"
        ) from error
    except OSError as error:
        _fsync_directory(directory)
        raise StateMachineError(
            f"cannot atomically publish irreversible state: {filename}"
        ) from error
    _fault_injection(f"{filename}:final-linked")
    _fsync_directory(directory)
    _fault_injection(f"{filename}:directory-fsynced")
    try:
        os.unlink(pending_filename, dir_fd=directory)
    except OSError as error:
        _fsync_directory(directory)
        raise StateMachineError(
            f"cannot remove published pending state: {pending_filename}"
        ) from error
    _fault_injection(f"{filename}:pending-unlinked")
    _fsync_directory(directory)
    _fault_injection(f"{filename}:cleanup-directory-fsynced")


def _read_at(directory: int, filename: str) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(filename, flags, dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise StateMachineError(f"cannot safely open state file: {filename}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise StateMachineError(f"invalid state file: {filename}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise StateMachineError(f"truncated state file: {filename}")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_canonical_object(raw: bytes, filename: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StateMachineError(f"invalid JSON state file: {filename}") from error
    if not isinstance(value, dict):
        raise StateMachineError(f"state file must contain an object: {filename}")
    if canonical_json_bytes(value) + b"\n" != raw:
        raise StateMachineError(f"state file is not canonical JSON: {filename}")
    return value


def create_attempt_marker(
    result_root: Path,
    *,
    suite_id: str,
    attempt_id: str,
    design_sha256: str,
    snapshot_registration_sha256: str,
    design_publication_receipt_sha256: str,
    snapshot_publication_receipt_sha256: str,
    private_snapshot_manifest_sha256: str,
    runtime_manifest_sha256: str,
    model_asset_source_manifest_sha256: str,
    full_asset_receipt_sha256: str,
    github_gate_receipt_sha256: str,
    corpus_manifest_sha256: str,
    codec_commit: str,
    codec_tree: str,
    lab_commit: str,
    lab_tree: str,
    target_pulse_timestamp: str = TARGET_PULSE_TIMESTAMP,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Reserve and then publish the global attempt marker exactly once.

    The canonical reservation is the first durable consumption boundary.  It
    is published before the marker and therefore before the NIST pulse is
    fetched, selection is resolved, or selected corpus/model bytes are opened.
    A crash after reservation can never be retried as a new scientific attempt.
    """

    if suite_id != SUITE_ID:
        raise StateMachineError("suite_id differs from the frozen protocol")
    if not isinstance(attempt_id, str) or ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise StateMachineError("attempt_id has an invalid canonical form")
    created = _validate_utc_second(created_at or utc_now_seconds(), "created_at")
    if not ONE_SHOT_NOT_BEFORE <= created < HARD_DEADLINE:
        raise StateMachineError("attempt marker is outside the frozen one-shot window")
    commitments = {
        "suiteId": suite_id,
        "attemptId": attempt_id,
        "createdAt": created,
        "designSHA256": _validate_digest(design_sha256, "design_sha256"),
        "snapshotRegistrationSHA256": _validate_digest(
            snapshot_registration_sha256, "snapshot_registration_sha256"
        ),
        "designPublicationReceiptSHA256": _validate_digest(
            design_publication_receipt_sha256,
            "design_publication_receipt_sha256",
        ),
        "snapshotPublicationReceiptSHA256": _validate_digest(
            snapshot_publication_receipt_sha256,
            "snapshot_publication_receipt_sha256",
        ),
        "privateSnapshotManifestSHA256": _validate_digest(
            private_snapshot_manifest_sha256,
            "private_snapshot_manifest_sha256",
        ),
        "runtimeManifestSHA256": _validate_digest(
            runtime_manifest_sha256, "runtime_manifest_sha256"
        ),
        "modelAssetSourceManifestSHA256": _validate_digest(
            model_asset_source_manifest_sha256,
            "model_asset_source_manifest_sha256",
        ),
        "fullAssetReceiptSHA256": _validate_digest(
            full_asset_receipt_sha256,
            "full_asset_receipt_sha256",
        ),
        "githubGateReceiptSHA256": _validate_digest(
            github_gate_receipt_sha256,
            "github_gate_receipt_sha256",
        ),
        "corpusManifestSHA256": _validate_digest(
            corpus_manifest_sha256, "corpus_manifest_sha256"
        ),
        "codecCommit": _validate_git_object(codec_commit, "codec_commit"),
        "codecTree": _validate_git_object(codec_tree, "codec_tree"),
        "labCommit": _validate_git_object(lab_commit, "lab_commit"),
        "labTree": _validate_git_object(lab_tree, "lab_tree"),
        "targetPulseTimestamp": target_pulse_timestamp,
    }
    if target_pulse_timestamp != TARGET_PULSE_TIMESTAMP:
        raise StateMachineError("target pulse timestamp differs from the frozen protocol")

    reservation = {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-attempt-reservation-v1",
        "status": "RESERVED",
        **commitments,
        "countsTowardScientificVerdict": False,
        "retryPermitted": False,
    }
    reservation["reservationContentSHA256"] = sha256_bytes(
        canonical_json_bytes(reservation)
    )
    reservation_raw = canonical_json_bytes(reservation) + b"\n"

    marker = {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-attempt-v1",
        "status": "STARTED",
        **commitments,
        "countsTowardScientificVerdict": True,
        "retryPermitted": False,
    }
    unsigned = canonical_json_bytes(marker)
    marker["markerContentSHA256"] = sha256_bytes(unsigned)
    raw = canonical_json_bytes(marker) + b"\n"
    directory, _ = _open_result_directory(result_root)
    try:
        for existing in (
            RESERVATION_FILENAME,
            RESERVATION_PENDING_FILENAME,
            ATTEMPT_FILENAME,
            ATTEMPT_PENDING_FILENAME,
            OUTCOME_FILENAME,
            OUTCOME_PENDING_FILENAME,
        ):
            if _read_at(directory, existing) is not None:
                raise StateMachineError(
                    f"irreversible attempt state already exists: {existing}"
                )
        _atomic_publish_at(
            directory,
            RESERVATION_FILENAME,
            RESERVATION_PENDING_FILENAME,
            reservation_raw,
        )
        _fault_injection("attempt-reservation.json:published")
        if _read_at(directory, OUTCOME_FILENAME) is not None:
            raise StateMachineError("terminal outcome exists without a readable attempt marker")
        _atomic_publish_at(
            directory,
            ATTEMPT_FILENAME,
            ATTEMPT_PENDING_FILENAME,
            raw,
        )
    finally:
        os.close(directory)
    return marker


def _validate_reservation(
    reservation: dict[str, Any], *, filename: str = RESERVATION_FILENAME
) -> dict[str, Any]:
    expected_fields = {
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
    if set(reservation) != expected_fields:
        raise StateMachineError("attempt reservation fields differ from the canonical schema")
    if (
        reservation.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v2-attempt-reservation-v1"
        or reservation.get("suiteId") != SUITE_ID
        or reservation.get("status") != "RESERVED"
        or reservation.get("retryPermitted") is not False
        or reservation.get("countsTowardScientificVerdict") is not False
        or reservation.get("targetPulseTimestamp") != TARGET_PULSE_TIMESTAMP
    ):
        raise StateMachineError("attempt reservation state differs from the frozen protocol")
    if (
        not isinstance(reservation.get("attemptId"), str)
        or ATTEMPT_ID.fullmatch(reservation["attemptId"]) is None
    ):
        raise StateMachineError("attempt reservation ID differs from the canonical form")
    created = _validate_utc_second(
        reservation.get("createdAt"), "reservation createdAt"
    )
    if not ONE_SHOT_NOT_BEFORE <= created < HARD_DEADLINE:
        raise StateMachineError("attempt reservation is outside the frozen one-shot window")
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
        _validate_digest(reservation.get(field), f"reservation {field}")
    for field in ("codecCommit", "codecTree", "labCommit", "labTree"):
        _validate_git_object(reservation.get(field), f"reservation {field}")
    unsigned = dict(reservation)
    digest = unsigned.pop("reservationContentSHA256")
    if digest != sha256_bytes(canonical_json_bytes(unsigned)):
        raise StateMachineError("attempt reservation self-digest mismatch")
    return reservation


def load_attempt_reservation(result_root: Path) -> dict[str, Any] | None:
    directory, _ = _open_result_directory(result_root)
    try:
        raw = _read_at(directory, RESERVATION_FILENAME)
    finally:
        os.close(directory)
    if raw is None:
        return None
    return _validate_reservation(
        _load_canonical_object(raw, RESERVATION_FILENAME)
    )


def _validate_marker(marker: dict[str, Any]) -> dict[str, Any]:
    expected_fields = {
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
    if set(marker) != expected_fields:
        raise StateMachineError("attempt marker fields differ from the canonical schema")
    marker_digest = marker.get("markerContentSHA256")
    unsigned = dict(marker)
    unsigned.pop("markerContentSHA256", None)
    if marker_digest != sha256_bytes(canonical_json_bytes(unsigned)):
        raise StateMachineError("attempt marker self-digest mismatch")
    if (
        marker.get("schemaVersion") != "corelm-crossmodel-livewiki-v2-attempt-v1"
        or marker.get("suiteId") != SUITE_ID
        or marker.get("status") != "STARTED"
        or marker.get("retryPermitted") is not False
        or marker.get("countsTowardScientificVerdict") is not True
        or marker.get("targetPulseTimestamp") != TARGET_PULSE_TIMESTAMP
    ):
        raise StateMachineError("attempt marker state differs from the frozen protocol")
    if (
        not isinstance(marker.get("attemptId"), str)
        or ATTEMPT_ID.fullmatch(marker["attemptId"]) is None
    ):
        raise StateMachineError("attempt marker ID differs from the canonical form")
    created = _validate_utc_second(marker.get("createdAt"), "marker createdAt")
    if not ONE_SHOT_NOT_BEFORE <= created < HARD_DEADLINE:
        raise StateMachineError("attempt marker is outside the frozen one-shot window")
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
        _validate_digest(marker.get(field), f"marker {field}")
    for field in ("codecCommit", "codecTree", "labCommit", "labTree"):
        _validate_git_object(marker.get(field), f"marker {field}")
    return marker


def load_attempt_marker(result_root: Path) -> dict[str, Any] | None:
    directory, _ = _open_result_directory(result_root)
    try:
        raw = _read_at(directory, ATTEMPT_FILENAME)
    finally:
        os.close(directory)
    if raw is None:
        return None
    marker = _validate_marker(_load_canonical_object(raw, ATTEMPT_FILENAME))
    reservation = load_attempt_reservation(result_root)
    if reservation is None:
        raise StateMachineError(
            "attempt marker exists without its durable attempt reservation"
        )
    _assert_reservation_matches_marker(reservation, marker)
    return marker


def _assert_reservation_matches_marker(
    reservation: dict[str, Any], marker: dict[str, Any]
) -> None:
    for field in (
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
    ):
        if reservation[field] != marker[field]:
            raise StateMachineError(
                f"attempt marker differs from its durable reservation: {field}"
            )


def create_terminal_outcome(
    result_root: Path,
    *,
    terminal_state: str,
    result_sha256: str | None,
    evidence_manifest_sha256: str | None,
    independent_verifier_sha256: str | None,
    completed_at: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    if terminal_state not in TERMINAL_STATES:
        raise StateMachineError(f"invalid terminal state: {terminal_state}")
    marker = load_attempt_marker(result_root)
    if marker is None:
        raise StateMachineError("cannot create terminal outcome without an attempt marker")
    reservation = load_attempt_reservation(result_root)
    if reservation is None:
        raise StateMachineError(
            "cannot create terminal outcome without an attempt reservation"
        )
    _assert_reservation_matches_marker(reservation, marker)
    if terminal_state in {"PASS", "FAIL_GATES"}:
        result_digest = _validate_digest(result_sha256, "result_sha256")
        evidence = _validate_digest(
            evidence_manifest_sha256, "evidence_manifest_sha256"
        )
        verifier = _validate_digest(
            independent_verifier_sha256, "independent_verifier_sha256"
        )
        if failure_reason is not None:
            raise StateMachineError("gate terminal states must not carry a failure reason")
    else:
        result_digest = result_sha256
        evidence = evidence_manifest_sha256
        verifier = independent_verifier_sha256
        if result_digest is not None:
            _validate_digest(result_digest, "result_sha256")
        if evidence is not None:
            _validate_digest(evidence, "evidence_manifest_sha256")
        if verifier is not None:
            _validate_digest(verifier, "independent_verifier_sha256")
        if not isinstance(failure_reason, str) or not failure_reason:
            raise StateMachineError("execution/incomplete outcomes require a failure reason")
    completed = _validate_utc_second(
        completed_at or utc_now_seconds(), "completed_at"
    )
    if completed < marker["createdAt"]:
        raise StateMachineError("terminal outcome precedes its attempt marker")
    if terminal_state in {"PASS", "FAIL_GATES"} and completed >= HARD_DEADLINE:
        raise StateMachineError(
            "gate terminal outcome reached or exceeded the hard execution deadline"
        )
    outcome = {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-outcome-v1",
        "suiteId": marker["suiteId"],
        "attemptId": marker["attemptId"],
        "terminalState": terminal_state,
        "completedAt": completed,
        "attemptMarkerFileSHA256": sha256_bytes(
            canonical_json_bytes(marker) + b"\n"
        ),
        "resultSHA256": result_digest,
        "evidenceManifestSHA256": evidence,
        "independentVerifierSHA256": verifier,
        "failureReason": failure_reason,
        "retryPermitted": False,
        "countsTowardScientificVerdict": terminal_state in {"PASS", "FAIL_GATES"},
    }
    raw = canonical_json_bytes(outcome) + b"\n"
    directory, _ = _open_result_directory(result_root)
    try:
        if _read_at(directory, OUTCOME_PENDING_FILENAME) is not None:
            raise StateMachineError(
                f"pending irreversible state already exists: {OUTCOME_PENDING_FILENAME}"
            )
        _atomic_publish_at(
            directory,
            OUTCOME_FILENAME,
            OUTCOME_PENDING_FILENAME,
            raw,
        )
    finally:
        os.close(directory)
    return outcome


def _validate_outcome(
    outcome: dict[str, Any], *, marker: dict[str, Any], marker_raw: bytes
) -> dict[str, Any]:
    expected_fields = {
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
    if set(outcome) != expected_fields:
        raise StateMachineError("terminal outcome fields differ from the canonical schema")
    if outcome.get("schemaVersion") != "corelm-crossmodel-livewiki-v2-outcome-v1":
        raise StateMachineError("terminal outcome schemaVersion differs")
    if outcome.get("terminalState") not in TERMINAL_STATES:
        raise StateMachineError("outcome terminal state is invalid")
    if outcome.get("attemptMarkerFileSHA256") != sha256_bytes(marker_raw):
        raise StateMachineError("outcome is not bound to the attempt marker")
    if outcome.get("suiteId") != marker["suiteId"]:
        raise StateMachineError("outcome suiteId differs from the marker")
    if outcome.get("attemptId") != marker["attemptId"]:
        raise StateMachineError("outcome attemptId differs from the marker")
    if outcome.get("retryPermitted") is not False:
        raise StateMachineError("outcome incorrectly permits a retry")
    completed = _validate_utc_second(outcome.get("completedAt"), "outcome completedAt")
    if completed < marker["createdAt"]:
        raise StateMachineError("terminal outcome precedes its attempt marker")
    if (
        outcome["terminalState"] in {"PASS", "FAIL_GATES"}
        and completed >= HARD_DEADLINE
    ):
        raise StateMachineError(
            "gate terminal outcome reached or exceeded the hard execution deadline"
        )
    if outcome["terminalState"] in {"PASS", "FAIL_GATES"}:
        for field in (
            "resultSHA256",
            "evidenceManifestSHA256",
            "independentVerifierSHA256",
        ):
            _validate_digest(outcome.get(field), f"outcome {field}")
        if outcome.get("failureReason") is not None:
            raise StateMachineError("gate outcome must not contain a failure reason")
        if outcome.get("countsTowardScientificVerdict") is not True:
            raise StateMachineError("gate outcome must count toward the verdict")
    else:
        for field in (
            "resultSHA256",
            "evidenceManifestSHA256",
            "independentVerifierSHA256",
        ):
            if outcome.get(field) is not None:
                _validate_digest(outcome[field], f"outcome {field}")
        if not isinstance(outcome.get("failureReason"), str) or not outcome["failureReason"]:
            raise StateMachineError("execution outcome requires a failure reason")
        if outcome.get("countsTowardScientificVerdict") is not False:
            raise StateMachineError("execution outcome must not count as gate evidence")
    return outcome


def load_terminal_outcome(result_root: Path) -> dict[str, Any] | None:
    marker = load_attempt_marker(result_root)
    directory, _ = _open_result_directory(result_root)
    try:
        raw = _read_at(directory, OUTCOME_FILENAME)
    finally:
        os.close(directory)
    if raw is None:
        return None
    if marker is None:
        raise StateMachineError("terminal outcome exists without an attempt marker")
    return _validate_outcome(
        _load_canonical_object(raw, OUTCOME_FILENAME),
        marker=marker,
        marker_raw=canonical_json_bytes(marker) + b"\n",
    )


def classify_local_state(result_root: Path) -> str:
    """Classify every on-disk crash state without discarding forensic bytes.

    Invalid/partial marker or outcome bytes after a canonical reservation are
    never raised as a retry opportunity: they are consumed incomplete.  A
    canonical final outcome remains authoritative even if its now-unneeded
    pending hard link survived a crash during cleanup.
    """

    directory, _ = _open_result_directory(result_root)
    try:
        raw = {
            name: _read_at(directory, name)
            for name in (
                RESERVATION_FILENAME,
                RESERVATION_PENDING_FILENAME,
                ATTEMPT_FILENAME,
                ATTEMPT_PENDING_FILENAME,
                OUTCOME_FILENAME,
                OUTCOME_PENDING_FILENAME,
            )
        }
    finally:
        os.close(directory)

    reservation_raw = raw[RESERVATION_FILENAME]
    if reservation_raw is None:
        if any(
            raw[name] is not None
            for name in (
                ATTEMPT_FILENAME,
                ATTEMPT_PENDING_FILENAME,
                OUTCOME_FILENAME,
                OUTCOME_PENDING_FILENAME,
            )
        ):
            return "CONSUMED_INCOMPLETE"
        if raw[RESERVATION_PENDING_FILENAME] is not None:
            return "PRECOMMIT_INCOMPLETE"
        return "NO_ATTEMPT"

    try:
        reservation = _validate_reservation(
            _load_canonical_object(reservation_raw, RESERVATION_FILENAME)
        )
    except StateMachineError:
        return "CONSUMED_INCOMPLETE"
    marker_raw = raw[ATTEMPT_FILENAME]
    if marker_raw is None:
        return "CONSUMED_INCOMPLETE"
    try:
        marker = _validate_marker(
            _load_canonical_object(marker_raw, ATTEMPT_FILENAME)
        )
        _assert_reservation_matches_marker(reservation, marker)
    except StateMachineError:
        return "CONSUMED_INCOMPLETE"

    outcome_raw = raw[OUTCOME_FILENAME]
    if outcome_raw is None:
        return "CONSUMED_INCOMPLETE"
    try:
        outcome = _validate_outcome(
            _load_canonical_object(outcome_raw, OUTCOME_FILENAME),
            marker=marker,
            marker_raw=marker_raw,
        )
    except StateMachineError:
        return "CONSUMED_INCOMPLETE"
    return str(outcome["terminalState"])


__all__ = [
    "ATTEMPT_PENDING_FILENAME",
    "ATTEMPT_FILENAME",
    "HARD_DEADLINE",
    "ONE_SHOT_NOT_BEFORE",
    "OUTCOME_PENDING_FILENAME",
    "OUTCOME_FILENAME",
    "RESERVATION_FILENAME",
    "RESERVATION_PENDING_FILENAME",
    "SUITE_ID",
    "TARGET_PULSE_TIMESTAMP",
    "TERMINAL_STATES",
    "StateMachineError",
    "canonical_json_bytes",
    "classify_local_state",
    "create_attempt_marker",
    "create_terminal_outcome",
    "load_attempt_marker",
    "load_attempt_reservation",
    "load_terminal_outcome",
    "sha256_bytes",
]
