#!/usr/bin/env python3
"""Build and verify the pre-pulse public execution-reservation release.

This step performs no NIST request, corpus selection, model loading, or model
inference.  It binds the already frozen design and snapshot to a public,
signed release whose server timestamp must precede the registered pulse.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.protocol import (  # noqa: E402
    canonical_json_bytes,
    load_json_strict_bytes,
    require_scientific_schedule_open,
    validate_design_registration_lifecycle,
    validate_snapshot_registration,
)
from blind_v1.reproducibility import (  # noqa: E402
    verify_content_digest,
    write_new_bytes,
)


SUITE_ID = "corelm-blind-crossmodel-v1"
RESERVATION_SCHEMA = "corelm-blind-crossmodel-v1-execution-reservation-v1"
MANIFEST_SCHEMA = (
    "corelm-blind-crossmodel-v1-execution-reservation-release-manifest-v1"
)
SNAPSHOT_RECEIPT_SCHEMA = "corelm-github-release-receipt-v2"
PUBLISH_NOT_BEFORE = datetime(2026, 8, 20, 18, tzinfo=timezone.utc)
PUBLISH_DEADLINE = datetime(2026, 8, 21, 17, 45, tzinfo=timezone.utc)
TARGET_PULSE = "2026-08-21T18:00:00.000Z"
TARGET_ENDPOINT = (
    "https://beacon.nist.gov/beacon/2.0/pulse/time/1787335200000"
)
ONE_SHOT_NOT_BEFORE = "2026-08-21T18:00:00Z"
MARKER_NO_LATER_THAN = "2026-08-21T18:15:00Z"
HARD_DEADLINE = "2026-08-22T18:00:00Z"
OUTCOME_OBLIGATION = (
    "PUBLISH_TERMINAL_EVIDENCE_OR_CLOSEOUT_BY_2026-08-30T18:00:00Z"
)
ASSET_NAMES = {
    "execution-reservation": "execution-reservation.json",
    "snapshot-publication-receipt": "snapshot-publication-receipt.json",
    "sha256-manifest": "sha256-manifest.json",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ATTEMPT_ID = re.compile(r"20260821T180000Z-[0-9a-f]{16}\Z")
ATTEMPT_ID_PREFIX = "20260821T180000Z-"
MAX_JSON_BYTES = 64 * 1024 * 1024
RESERVATION_FIELDS = frozenset(
    {
        "schemaVersion",
        "suiteId",
        "status",
        "reservedAt",
        "targetPulseTimestamp",
        "targetPulseEndpoint",
        "oneShotNotBefore",
        "markerNoLaterThan",
        "hardDeadline",
        "designRegistration",
        "snapshotRegistration",
        "snapshotPublicationReceipt",
        "codecSource",
        "labSource",
        "candidateRuleSHA256",
        "confirmatoryModels",
        "outcomeObligation",
        "retryPermitted",
        "countsTowardScientificVerdict",
        "attemptId",
        "reservationContentSHA256",
    }
)


class ExecutionReservationError(RuntimeError):
    """The reservation package is incomplete or semantically inconsistent."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(path: Path, *, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ExecutionReservationError(f"{label} is absent or unsafe") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_JSON_BYTES
        ):
            raise ExecutionReservationError(f"{label} metadata differs")
        raw = b""
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(raw))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        )
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise ExecutionReservationError(f"{label} changed while being read")
        return raw
    finally:
        os.close(descriptor)


def _canonical_document(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise ExecutionReservationError(str(error)) from error
    if not isinstance(value, dict) or raw != canonical_json_bytes(value) + b"\n":
        raise ExecutionReservationError(f"{label} is not canonical JSON plus LF")
    return value


def _utc_second(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError) as error:
        raise ExecutionReservationError(
            "reservedAt must be canonical UTC with whole seconds"
        ) from error
    if not PUBLISH_NOT_BEFORE <= parsed < PUBLISH_DEADLINE:
        raise ExecutionReservationError(
            "reservation time is outside the registered pre-pulse window"
        )
    return parsed


def _file_binding(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": sha256_bytes(raw)}


def _source_binding(value: Any, *, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ExecutionReservationError(f"{label} source binding is absent")
    repository, commit, tree = (
        value.get("repository"),
        value.get("commit"),
        value.get("tree"),
    )
    if (
        not isinstance(repository, str)
        or not repository
        or not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or not isinstance(tree, str)
        or re.fullmatch(r"[0-9a-f]{40}", tree) is None
    ):
        raise ExecutionReservationError(f"{label} source binding is invalid")
    return {"repository": repository, "commit": commit, "tree": tree}


def derive_public_attempt_id(value: Mapping[str, Any]) -> str:
    """Derive the one public attempt identity without a self-hash cycle."""

    unsigned = dict(value)
    unsigned.pop("attemptId", None)
    unsigned.pop("reservationContentSHA256", None)
    expected = RESERVATION_FIELDS - {"attemptId", "reservationContentSHA256"}
    if set(unsigned) != expected:
        raise ExecutionReservationError(
            "reservation attempt-identity preimage fields differ"
        )
    digest = sha256_bytes(canonical_json_bytes(unsigned))
    return ATTEMPT_ID_PREFIX + digest[:16]


def build_execution_reservation(
    *,
    design_raw: bytes,
    snapshot_raw: bytes,
    snapshot_receipt_raw: bytes,
    reserved_at: str,
) -> dict[str, Any]:
    require_scientific_schedule_open(operation="build Blind V1 execution reservation")
    return _historical_build_execution_reservation(
        design_raw=design_raw,
        snapshot_raw=snapshot_raw,
        snapshot_receipt_raw=snapshot_receipt_raw,
        reserved_at=reserved_at,
    )


def _historical_build_execution_reservation(
    *,
    design_raw: bytes,
    snapshot_raw: bytes,
    snapshot_receipt_raw: bytes,
    reserved_at: str,
) -> dict[str, Any]:
    """Retain the former reservation shape for offline structural fixtures."""

    design = _canonical_document(design_raw, label="frozen design")
    snapshot = _canonical_document(snapshot_raw, label="snapshot registration")
    snapshot_receipt = _canonical_document(
        snapshot_receipt_raw, label="snapshot publication receipt"
    )
    try:
        validate_design_registration_lifecycle(design)
        validate_snapshot_registration(snapshot, design)
        verify_content_digest(snapshot_receipt)
    except ValueError as error:
        raise ExecutionReservationError(str(error)) from error
    if design.get("status") != "PUBLIC_DESIGN_FROZEN":
        raise ExecutionReservationError("execution reservation requires a frozen design")
    if snapshot_receipt.get("schemaVersion") != SNAPSHOT_RECEIPT_SCHEMA:
        raise ExecutionReservationError("snapshot publication receipt schema differs")
    if snapshot_receipt.get("kind") != "snapshot":
        raise ExecutionReservationError("publication receipt is not for the snapshot")
    _utc_second(reserved_at)

    release = design["reservationRelease"]
    if (
        release.get("publishNotBefore") != "2026-08-20T18:00:00Z"
        or release.get("publishNoLaterThan") != "2026-08-21T17:45:00Z"
        or release.get("requiredAssetRoles") != list(ASSET_NAMES)
    ):
        raise ExecutionReservationError("frozen reservation release plan differs")
    execution = design["execution"]
    beacon = design["beacon"]
    models = design["models"]
    payload: dict[str, Any] = {
        "schemaVersion": RESERVATION_SCHEMA,
        "suiteId": SUITE_ID,
        "status": "PUBLIC_EXECUTION_RESERVED",
        "reservedAt": reserved_at,
        "targetPulseTimestamp": beacon["targetTimestamp"],
        "targetPulseEndpoint": beacon["pulseEndpoint"],
        "oneShotNotBefore": execution["oneShotNotBefore"],
        "markerNoLaterThan": execution["markerNoLaterThan"],
        "hardDeadline": execution["hardDeadline"],
        "designRegistration": _file_binding(design_raw),
        "snapshotRegistration": _file_binding(snapshot_raw),
        "snapshotPublicationReceipt": _file_binding(snapshot_receipt_raw),
        "codecSource": _source_binding(design["codecSource"], label="codec"),
        "labSource": _source_binding(design["labSource"], label="lab"),
        "candidateRuleSHA256": design["candidate"]["candidateRuleSHA256"],
        "confirmatoryModels": [
            {
                "key": item["key"],
                "repository": item["repository"],
                "revision": item["revision"],
                "weightSHA256": item["weightSHA256"],
            }
            for item in models
        ],
        "outcomeObligation": OUTCOME_OBLIGATION,
        "retryPermitted": False,
        "countsTowardScientificVerdict": False,
    }
    if (
        payload["targetPulseTimestamp"] != TARGET_PULSE
        or payload["targetPulseEndpoint"] != TARGET_ENDPOINT
        or payload["oneShotNotBefore"] != ONE_SHOT_NOT_BEFORE
        or payload["markerNoLaterThan"] != MARKER_NO_LATER_THAN
        or payload["hardDeadline"] != HARD_DEADLINE
        or len(payload["confirmatoryModels"]) != 6
    ):
        raise ExecutionReservationError("reservation commitments differ")
    payload["attemptId"] = derive_public_attempt_id(payload)
    payload["reservationContentSHA256"] = sha256_bytes(
        canonical_json_bytes(payload)
    )
    return payload


def _manifest(reservation_raw: bytes, snapshot_receipt_raw: bytes) -> dict[str, Any]:
    assets = [
        {
            "role": "execution-reservation",
            "name": ASSET_NAMES["execution-reservation"],
            **_file_binding(reservation_raw),
        },
        {
            "role": "snapshot-publication-receipt",
            "name": ASSET_NAMES["snapshot-publication-receipt"],
            **_file_binding(snapshot_receipt_raw),
        },
    ]
    payload: dict[str, Any] = {
        "schemaVersion": MANIFEST_SCHEMA,
        "suiteId": SUITE_ID,
        "status": "COMPLETE_EXECUTION_RESERVATION_RELEASE_ASSETS",
        "assets": assets,
        "selfExcluded": True,
    }
    payload["contentSHA256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload


def verify_execution_reservation_package(
    asset_root: Path,
    *,
    design_raw: bytes | None = None,
    snapshot_raw: bytes | None = None,
) -> dict[str, Any]:
    reservation_raw = _read_regular(
        asset_root / ASSET_NAMES["execution-reservation"],
        label="execution reservation",
    )
    snapshot_receipt_raw = _read_regular(
        asset_root / ASSET_NAMES["snapshot-publication-receipt"],
        label="snapshot publication receipt",
    )
    manifest_raw = _read_regular(
        asset_root / ASSET_NAMES["sha256-manifest"],
        label="reservation SHA-256 manifest",
    )
    reservation = _canonical_document(
        reservation_raw, label="execution reservation"
    )
    manifest = _canonical_document(
        manifest_raw, label="reservation SHA-256 manifest"
    )
    if set(reservation) != RESERVATION_FIELDS:
        raise ExecutionReservationError("reservation fields differ")
    unsigned = dict(reservation)
    observed_self_digest = unsigned.pop("reservationContentSHA256", None)
    if (
        observed_self_digest != sha256_bytes(canonical_json_bytes(unsigned))
        or not isinstance(observed_self_digest, str)
        or SHA256.fullmatch(observed_self_digest) is None
    ):
        raise ExecutionReservationError("reservation self-digest differs")
    expected_manifest = _manifest(reservation_raw, snapshot_receipt_raw)
    if manifest != expected_manifest:
        raise ExecutionReservationError("reservation release manifest differs")
    try:
        verify_content_digest(manifest)
    except ValueError as error:
        raise ExecutionReservationError(str(error)) from error
    if (
        reservation.get("schemaVersion") != RESERVATION_SCHEMA
        or reservation.get("suiteId") != SUITE_ID
        or reservation.get("status") != "PUBLIC_EXECUTION_RESERVED"
        or reservation.get("targetPulseTimestamp") != TARGET_PULSE
        or reservation.get("targetPulseEndpoint") != TARGET_ENDPOINT
        or reservation.get("oneShotNotBefore") != ONE_SHOT_NOT_BEFORE
        or reservation.get("markerNoLaterThan") != MARKER_NO_LATER_THAN
        or reservation.get("hardDeadline") != HARD_DEADLINE
        or reservation.get("outcomeObligation") != OUTCOME_OBLIGATION
        or reservation.get("retryPermitted") is not False
        or reservation.get("countsTowardScientificVerdict") is not False
        or not isinstance(reservation.get("attemptId"), str)
        or ATTEMPT_ID.fullmatch(reservation["attemptId"]) is None
        or reservation["attemptId"] != derive_public_attempt_id(reservation)
    ):
        raise ExecutionReservationError("reservation protocol boundary differs")
    _utc_second(reservation.get("reservedAt"))
    if design_raw is not None and reservation.get("designRegistration") != _file_binding(
        design_raw
    ):
        raise ExecutionReservationError("reservation design binding differs")
    if snapshot_raw is not None and reservation.get(
        "snapshotRegistration"
    ) != _file_binding(snapshot_raw):
        raise ExecutionReservationError("reservation snapshot binding differs")
    if reservation.get("snapshotPublicationReceipt") != _file_binding(
        snapshot_receipt_raw
    ):
        raise ExecutionReservationError("reservation snapshot-receipt binding differs")
    models = reservation.get("confirmatoryModels")
    if not isinstance(models, list) or len(models) != 6:
        raise ExecutionReservationError("reservation model pool differs")
    return {
        "status": "VERIFIED_EXECUTION_RESERVATION_RELEASE_ASSETS",
        "reservationFileSHA256": sha256_bytes(reservation_raw),
        "snapshotReceiptFileSHA256": sha256_bytes(snapshot_receipt_raw),
        "manifestFileSHA256": sha256_bytes(manifest_raw),
        "reservedAt": reservation["reservedAt"],
        "attemptId": reservation["attemptId"],
        "markerNoLaterThan": reservation["markerNoLaterThan"],
        "networkUsed": False,
        "modelInferenceUsed": False,
        "selectionDerived": False,
    }


def package_execution_reservation(
    *,
    design_path: Path,
    snapshot_path: Path,
    snapshot_receipt_path: Path,
    output_directory: Path,
    reserved_at: str,
) -> dict[str, Any]:
    require_scientific_schedule_open(
        operation="package Blind V1 execution reservation"
    )
    return _historical_package_execution_reservation(
        design_path=design_path,
        snapshot_path=snapshot_path,
        snapshot_receipt_path=snapshot_receipt_path,
        output_directory=output_directory,
        reserved_at=reserved_at,
    )


def _historical_package_execution_reservation(
    *,
    design_path: Path,
    snapshot_path: Path,
    snapshot_receipt_path: Path,
    output_directory: Path,
    reserved_at: str,
) -> dict[str, Any]:
    """Retain the former reservation package for offline structural fixtures."""

    design_raw = _read_regular(design_path, label="frozen design")
    snapshot_raw = _read_regular(snapshot_path, label="snapshot registration")
    snapshot_receipt_raw = _read_regular(
        snapshot_receipt_path, label="snapshot publication receipt"
    )
    reservation = _historical_build_execution_reservation(
        design_raw=design_raw,
        snapshot_raw=snapshot_raw,
        snapshot_receipt_raw=snapshot_receipt_raw,
        reserved_at=reserved_at,
    )
    reservation_raw = canonical_json_bytes(reservation) + b"\n"
    manifest_raw = canonical_json_bytes(
        _manifest(reservation_raw, snapshot_receipt_raw)
    ) + b"\n"
    output_directory.mkdir(parents=True, exist_ok=True)
    if output_directory.is_symlink() or any(output_directory.iterdir()):
        raise ExecutionReservationError("output directory must be new or empty")
    write_new_bytes(
        output_directory / ASSET_NAMES["execution-reservation"], reservation_raw
    )
    write_new_bytes(
        output_directory / ASSET_NAMES["snapshot-publication-receipt"],
        snapshot_receipt_raw,
    )
    write_new_bytes(
        output_directory / ASSET_NAMES["sha256-manifest"], manifest_raw
    )
    verification = verify_execution_reservation_package(
        output_directory,
        design_raw=design_raw,
        snapshot_raw=snapshot_raw,
    )
    return {
        "status": "PACKAGED_EXECUTION_RESERVATION_RELEASE",
        "outputDirectory": str(output_directory),
        "reservationSHA256": sha256_bytes(reservation_raw),
        "snapshotReceiptSHA256": sha256_bytes(snapshot_receipt_raw),
        "manifestSHA256": sha256_bytes(manifest_raw),
        "networkUsed": False,
        "modelInferenceUsed": False,
        "selectionDerived": False,
        "verification": verification,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--snapshot-receipt", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--reserved-at", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        arguments = parse_arguments()
        require_scientific_schedule_open(
            operation="run Blind V1 execution-reservation packager"
        )
        result = package_execution_reservation(
            design_path=arguments.design,
            snapshot_path=arguments.snapshot,
            snapshot_receipt_path=arguments.snapshot_receipt,
            output_directory=arguments.output_directory,
            reserved_at=arguments.reserved_at,
        )
    except (ExecutionReservationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"EXECUTION RESERVATION FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
