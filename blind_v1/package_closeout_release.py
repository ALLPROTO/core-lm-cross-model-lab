#!/usr/bin/env python3
"""Build and independently verify the four canonical closeout release assets.

The package is intentionally small.  It contains the canonical public closeout,
the exact basis document, a deterministic verifier report, and a SHA-256
manifest.  A late-publication package references the already immutable evidence
release assets through their fully verified receipt; it does not duplicate or
silently repair those assets.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.experiment_closeout import (
    CLOSEOUT_PUBLICATION_DEADLINE,
    CLOSEOUT_SIGNING_KEY_FINGERPRINT,
    CLOSEOUT_SIGNING_PUBLIC_KEY_SHA256,
    CLOSEOUT_TAG,
    EVIDENCE_REPOSITORY,
    ExperimentCloseoutError,
    PublicationBindings,
    VerifiedExperimentCloseout,
    canonical_json_bytes,
    sha256_bytes,
    validate_empty_result_root_audit_report,
    verify_experiment_closeout,
)
from blind_v1.package_execution_reservation import (
    ASSET_NAMES as RESERVATION_ASSET_NAMES,
    ExecutionReservationError,
    verify_execution_reservation_package,
)
from blind_v1.release_receipt import (
    ReleaseAttestationCryptographicVerifier,
    ReleaseReceiptError,
    VerifiedReleaseReceipt,
    verify_release_receipt,
)
from blind_v1.release_attestation_crypto import (
    PinnedCosignReleaseAttestationVerifier,
)


REPORT_SCHEMA = "corelm-blind-crossmodel-v1-closeout-verifier-report-v1"
MANIFEST_SCHEMA = "corelm-blind-crossmodel-v1-closeout-release-manifest-v1"
SUITE_ID = "corelm-blind-crossmodel-v1"
STATEMENT_NAME = "experiment-closeout.json"
BASIS_NAME = "closeout-basis.json"
NO_ATTEMPT_PRIMARY_NAME = "empty-result-root-observation.json"
LATE_PRIMARY_NAME = "late-evidence-release-receipt.json"
HOST_ENVIRONMENT_NAME = "host-environment.json"
AUDIT_REPORT_NAME = "empty-result-root-audit-report.json"
AUDIT_IMPLEMENTATION_NAME = "experiment_closeout.py"
REPORT_NAME = "closeout-verifier-report.json"
MANIFEST_NAME = "sha256-manifest.json"
CLOSEOUT_RELEASE_ASSETS = (
    ("closeout-statement", STATEMENT_NAME),
    ("closeout-basis", BASIS_NAME),
    ("closeout-verifier-report", REPORT_NAME),
    ("sha256-manifest", MANIFEST_NAME),
)
BASIS_SCHEMA = "corelm-blind-crossmodel-v1-closeout-basis-v1"
MAXIMUM_FILE_BYTES = 128 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class CloseoutPackageError(ValueError):
    """The closeout release package is incomplete, unsafe, or inconsistent."""


@dataclass(frozen=True)
class VerifiedCloseoutPackage:
    classification: str
    closeout_sha256: str
    basis_sha256: str
    basis_bundle_sha256: str
    report_sha256: str
    manifest_sha256: str


@dataclass(frozen=True)
class VerifiedPublishedCloseoutRelease:
    """A verified package bound to its preregistered GitHub publication."""

    package: VerifiedCloseoutPackage
    release_receipt: VerifiedReleaseReceipt


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _validate_utc(value: str, *, label: str) -> str:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise CloseoutPackageError(f"{label} must be UTC with whole seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise CloseoutPackageError(f"{label} is not a real timestamp") from error
    return value


def _utc_datetime(value: str, *, label: str) -> datetime:
    return datetime.strptime(
        _validate_utc(value, label=label), "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_line(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _seal(value: Mapping[str, Any]) -> bytes:
    if "contentSHA256" in value:
        raise CloseoutPackageError("document is already sealed")
    result = dict(value)
    result["contentSHA256"] = _sha256(canonical_json_bytes(value))
    return _canonical_line(result)


def _load_canonical(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise CloseoutPackageError(f"{label} must end in exactly one LF")
    try:
        value = json.loads(raw[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CloseoutPackageError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict) or raw != _canonical_line(value):
        raise CloseoutPackageError(f"{label} is not canonical JSON plus LF")
    unsigned = dict(value)
    digest = unsigned.pop("contentSHA256", None)
    if not isinstance(digest, str) or digest != _sha256(canonical_json_bytes(unsigned)):
        raise CloseoutPackageError(f"{label} contentSHA256 differs")
    return value


def _safe_read(path: Path, *, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise CloseoutPackageError(f"{label} is not a no-follow file") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAXIMUM_FILE_BYTES:
            raise CloseoutPackageError(f"{label} type or size is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAXIMUM_FILE_BYTES:
                raise CloseoutPackageError(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or observed != before.st_size:
            raise CloseoutPackageError(f"{label} changed while reading")
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
                raise CloseoutPackageError("closeout package write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bindings_dict(bindings: PublicationBindings) -> dict[str, str]:
    return {
        "reservedAttemptId": bindings.reserved_attempt_id,
        "designRegistrationSHA256": bindings.design_registration_sha256,
        "designPublicationReceiptSHA256": bindings.design_publication_receipt_sha256,
        "snapshotRegistrationSHA256": bindings.snapshot_registration_sha256,
        "snapshotPublicationReceiptSHA256": bindings.snapshot_publication_receipt_sha256,
        "reservationPublicationReceiptSHA256": (
            bindings.reservation_publication_receipt_sha256
        ),
        "executionReservationSHA256": bindings.execution_reservation_sha256,
        "reservationReleaseManifestSHA256": (
            bindings.reservation_release_manifest_sha256
        ),
        "closeoutSourceCommit": bindings.closeout_source_commit,
        "closeoutSourceTree": bindings.closeout_source_tree,
    }


def _archived_document(*, role: str, name: str, raw: bytes) -> dict[str, Any]:
    return {
        "role": role,
        "name": name,
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _decode_archived_document(
    value: Any,
    *,
    expected_role: str,
    expected_name: str,
    label: str,
) -> bytes:
    fields = {"role", "name", "encoding", "bytes", "sha256", "dataBase64"}
    if not isinstance(value, dict) or set(value) != fields:
        raise CloseoutPackageError(f"{label} archived-document fields differ")
    if (
        value["role"] != expected_role
        or value["name"] != expected_name
        or value["encoding"] != "base64"
        or type(value["bytes"]) is not int
        or not 0 < value["bytes"] <= MAXIMUM_FILE_BYTES
        or not isinstance(value["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
        or not isinstance(value["dataBase64"], str)
    ):
        raise CloseoutPackageError(f"{label} archived-document boundary differs")
    try:
        raw = base64.b64decode(value["dataBase64"].encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise CloseoutPackageError(f"{label} archived-document base64 is invalid") from error
    if (
        base64.b64encode(raw).decode("ascii") != value["dataBase64"]
        or len(raw) != value["bytes"]
        or _sha256(raw) != value["sha256"]
    ):
        raise CloseoutPackageError(f"{label} archived-document digest differs")
    return raw


def _validate_no_attempt_support(
    *,
    observation_raw: bytes,
    host_environment_raw: bytes,
    audit_report_raw: bytes,
    audit_implementation_raw: bytes,
) -> None:
    try:
        report = validate_empty_result_root_audit_report(
            audit_report_raw,
            host_environment_raw=host_environment_raw,
        )
    except ExperimentCloseoutError as error:
        raise CloseoutPackageError(
            "empty-root environment and audit report differ"
        ) from error
    try:
        observation = json.loads(observation_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CloseoutPackageError("empty-root observation is not JSON") from error
    if not isinstance(observation, dict) or (
        observation.get("hostEnvironmentSHA256") != sha256_bytes(host_environment_raw)
        or observation.get("auditReportSHA256") != sha256_bytes(audit_report_raw)
        or observation.get("auditImplementationSHA256")
        != sha256_bytes(audit_implementation_raw)
        or observation.get("observedAt") != report["observedAt"]
        or observation.get("hostEnvironmentSHA256") != report["hostEnvironmentSHA256"]
        or observation.get("resultRootPathSHA256") != report["resultRootPathSHA256"]
        or observation.get("rootDevice") != report["rootDevice"]
        or observation.get("rootInode") != report["rootInode"]
    ):
        raise CloseoutPackageError(
            "empty-root observation, environment, and audit report differ"
        )


def _basis_bundle(
    *,
    closeout: Mapping[str, Any],
    primary_raw: bytes,
    host_environment_raw: bytes | None,
    audit_report_raw: bytes | None,
    audit_implementation_raw: bytes | None,
) -> bytes:
    classification = closeout.get("classification")
    if classification == "NO_ATTEMPT_EXPIRED":
        if not isinstance(host_environment_raw, bytes) or not isinstance(
            audit_report_raw, bytes
        ) or not isinstance(audit_implementation_raw, bytes):
            raise CloseoutPackageError(
                "no-attempt basis requires exact host environment and audit report"
            )
        _validate_no_attempt_support(
            observation_raw=primary_raw,
            host_environment_raw=host_environment_raw,
            audit_report_raw=audit_report_raw,
            audit_implementation_raw=audit_implementation_raw,
        )
        primary = _archived_document(
            role="empty-result-root-observation",
            name=NO_ATTEMPT_PRIMARY_NAME,
            raw=primary_raw,
        )
        supporting = [
            _archived_document(
                role="host-environment",
                name=HOST_ENVIRONMENT_NAME,
                raw=host_environment_raw,
            ),
            _archived_document(
                role="empty-result-root-audit-report",
                name=AUDIT_REPORT_NAME,
                raw=audit_report_raw,
            ),
            _archived_document(
                role="empty-result-root-audit-implementation",
                name=AUDIT_IMPLEMENTATION_NAME,
                raw=audit_implementation_raw,
            ),
        ]
        external_assets: list[dict[str, Any]] = []
    elif classification == "LATE_PUBLICATION_INVALID":
        if (
            host_environment_raw is not None
            or audit_report_raw is not None
            or audit_implementation_raw is not None
        ):
            raise CloseoutPackageError(
                "late-publication basis forbids no-attempt support documents"
            )
        primary = _archived_document(
            role="late-evidence-release-receipt",
            name=LATE_PRIMARY_NAME,
            raw=primary_raw,
        )
        supporting = []
        basis = closeout.get("basis")
        required_assets = basis.get("requiredAssets") if isinstance(basis, dict) else None
        if not isinstance(required_assets, list):
            raise CloseoutPackageError("late closeout external asset inventory is absent")
        external_assets = [
            {
                "role": item["role"],
                "name": item["name"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            }
            for item in required_assets
        ]
    else:
        raise CloseoutPackageError("unsupported closeout classification")
    return _seal(
        {
            "schemaVersion": BASIS_SCHEMA,
            "suiteId": SUITE_ID,
            "classification": classification,
            "primaryDocument": primary,
            "supportingDocuments": supporting,
            "externalEvidenceAssets": external_assets,
        }
    )


def _open_basis_bundle(
    raw: bytes,
    *,
    closeout: Mapping[str, Any],
) -> tuple[bytes, bytes | None, bytes | None]:
    bundle = _load_canonical(raw, label="closeout basis bundle")
    fields = {
        "schemaVersion",
        "suiteId",
        "classification",
        "primaryDocument",
        "supportingDocuments",
        "externalEvidenceAssets",
        "contentSHA256",
    }
    if set(bundle) != fields or (
        bundle["schemaVersion"] != BASIS_SCHEMA
        or bundle["suiteId"] != SUITE_ID
        or bundle["classification"] != closeout.get("classification")
    ):
        raise CloseoutPackageError("closeout basis bundle boundary differs")
    classification = bundle["classification"]
    supporting = bundle["supportingDocuments"]
    external_assets = bundle["externalEvidenceAssets"]
    if classification == "NO_ATTEMPT_EXPIRED":
        primary = _decode_archived_document(
            bundle["primaryDocument"],
            expected_role="empty-result-root-observation",
            expected_name=NO_ATTEMPT_PRIMARY_NAME,
            label="no-attempt primary",
        )
        if not isinstance(supporting, list) or len(supporting) != 3:
            raise CloseoutPackageError("no-attempt support inventory differs")
        host = _decode_archived_document(
            supporting[0],
            expected_role="host-environment",
            expected_name=HOST_ENVIRONMENT_NAME,
            label="host environment",
        )
        report = _decode_archived_document(
            supporting[1],
            expected_role="empty-result-root-audit-report",
            expected_name=AUDIT_REPORT_NAME,
            label="empty-root audit report",
        )
        implementation = _decode_archived_document(
            supporting[2],
            expected_role="empty-result-root-audit-implementation",
            expected_name=AUDIT_IMPLEMENTATION_NAME,
            label="empty-root audit implementation",
        )
        if external_assets != []:
            raise CloseoutPackageError("no-attempt bundle cannot name evidence assets")
        _validate_no_attempt_support(
            observation_raw=primary,
            host_environment_raw=host,
            audit_report_raw=report,
            audit_implementation_raw=implementation,
        )
        return primary, host, report
    if classification == "LATE_PUBLICATION_INVALID":
        primary = _decode_archived_document(
            bundle["primaryDocument"],
            expected_role="late-evidence-release-receipt",
            expected_name=LATE_PRIMARY_NAME,
            label="late evidence receipt",
        )
        if supporting != []:
            raise CloseoutPackageError("late bundle cannot contain no-attempt support")
        basis = closeout.get("basis")
        required_assets = basis.get("requiredAssets") if isinstance(basis, dict) else None
        expected_assets = [
            {
                "role": item["role"],
                "name": item["name"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            }
            for item in required_assets
        ] if isinstance(required_assets, list) else None
        if external_assets != expected_assets:
            raise CloseoutPackageError("late bundle external asset inventory differs")
        return primary, None, None
    raise CloseoutPackageError("unsupported closeout basis classification")


def _verify_closeout(
    closeout_raw: bytes,
    basis_raw: bytes,
    *,
    publication_bindings: PublicationBindings,
    evidence_asset_root: Path | None,
    expected_commit: str | None,
    expected_tree: str | None,
    expected_key_fingerprint: str | None,
    expected_public_key_sha256: str | None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ),
) -> VerifiedExperimentCloseout:
    try:
        untrusted = json.loads(closeout_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CloseoutPackageError("closeout statement is not JSON") from error
    classification = untrusted.get("classification") if isinstance(untrusted, dict) else None
    try:
        if classification == "NO_ATTEMPT_EXPIRED":
            if any(
                value is not None
                for value in (
                    evidence_asset_root,
                    expected_commit,
                    expected_tree,
                    expected_key_fingerprint,
                    expected_public_key_sha256,
                )
            ):
                raise CloseoutPackageError(
                    "no-attempt package forbids late-evidence verification inputs"
                )
            return verify_experiment_closeout(
                closeout_raw,
                expected_publication_bindings=publication_bindings,
                empty_result_root_observation_raw=basis_raw,
            )
        if classification == "LATE_PUBLICATION_INVALID":
            if evidence_asset_root is None or not all(
                isinstance(value, str)
                for value in (
                    expected_commit,
                    expected_tree,
                    expected_key_fingerprint,
                    expected_public_key_sha256,
                )
            ):
                raise CloseoutPackageError(
                    "late package requires exact evidence assets and source/signing expectations"
                )
            return verify_experiment_closeout(
                closeout_raw,
                expected_publication_bindings=publication_bindings,
                evidence_release_receipt_raw=basis_raw,
                evidence_asset_root=evidence_asset_root,
                expected_commit=expected_commit,
                expected_tree=expected_tree,
                expected_key_fingerprint=expected_key_fingerprint,
                expected_public_key_sha256=expected_public_key_sha256,
                cryptographic_attestation_verifier=cryptographic_attestation_verifier,
            )
    except ExperimentCloseoutError as error:
        raise CloseoutPackageError("canonical closeout verification failed") from error
    raise CloseoutPackageError("unsupported closeout classification")


def _report(
    verified: VerifiedExperimentCloseout,
    bindings: PublicationBindings,
    *,
    verified_at: str,
) -> bytes:
    if _utc_datetime(verified_at, label="verifiedAt") < _utc_datetime(
        verified.classified_at,
        label="classifiedAt",
    ):
        raise CloseoutPackageError("closeout verification predates classification")
    return _seal(
        {
            "schemaVersion": REPORT_SCHEMA,
            "suiteId": SUITE_ID,
            "status": "VERIFIED",
            "classification": verified.classification,
            "verificationMethod": "CANONICAL_EXPERIMENT_CLOSEOUT_OFFLINE_V1",
            "closeoutSHA256": verified.closeout_sha256,
            "basisSHA256": verified.basis_sha256,
            "evidenceReleaseReceiptSHA256": verified.evidence_release_receipt_sha256,
            "publicationBindings": _bindings_dict(bindings),
            "verifiedAt": verified_at,
            "countsTowardScientificVerdict": False,
        }
    )


def _manifest(
    *,
    classification: str,
    statement_raw: bytes,
    basis_bundle_raw: bytes,
    report_raw: bytes,
) -> bytes:
    entries = []
    for role, name, raw in (
        ("closeout-statement", STATEMENT_NAME, statement_raw),
        ("closeout-basis", BASIS_NAME, basis_bundle_raw),
        ("closeout-verifier-report", REPORT_NAME, report_raw),
    ):
        entries.append(
            {"role": role, "name": name, "bytes": len(raw), "sha256": _sha256(raw)}
        )
    return _seal(
        {
            "schemaVersion": MANIFEST_SCHEMA,
            "suiteId": SUITE_ID,
            "classification": classification,
            "entries": entries,
        }
    )


def package_closeout_release(
    *,
    closeout_path: Path,
    basis_path: Path,
    output_directory: Path,
    publication_bindings: PublicationBindings,
    verified_at: str | None = None,
    host_environment_path: Path | None = None,
    audit_report_path: Path | None = None,
    evidence_asset_root: Path | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_key_fingerprint: str | None = None,
    expected_public_key_sha256: str | None = None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> VerifiedCloseoutPackage:
    """Create an exact four-file release directory without overwriting."""

    if output_directory.exists() or output_directory.is_symlink():
        raise CloseoutPackageError("closeout output already exists")
    closeout_raw = _safe_read(closeout_path, label="closeout statement")
    basis_raw = _safe_read(basis_path, label="closeout basis")
    verified = _verify_closeout(
        closeout_raw,
        basis_raw,
        publication_bindings=publication_bindings,
        evidence_asset_root=evidence_asset_root,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )
    try:
        closeout = json.loads(closeout_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:  # already verified
        raise CloseoutPackageError("closeout statement is not JSON") from error
    host_environment_raw = (
        _safe_read(host_environment_path, label="host environment")
        if host_environment_path is not None
        else None
    )
    audit_report_raw = (
        _safe_read(audit_report_path, label="empty-root audit report")
        if audit_report_path is not None
        else None
    )
    basis_bundle_raw = _basis_bundle(
        closeout=closeout,
        primary_raw=basis_raw,
        host_environment_raw=host_environment_raw,
        audit_report_raw=audit_report_raw,
        audit_implementation_raw=(
            _safe_read(
                Path(__file__).with_name("experiment_closeout.py"),
                label="empty-root audit implementation",
            )
            if verified.classification == "NO_ATTEMPT_EXPIRED"
            else None
        ),
    )
    report_raw = _report(verified, publication_bindings, verified_at=verified_at or _utc_now())
    manifest_raw = _manifest(
        classification=verified.classification,
        statement_raw=closeout_raw,
        basis_bundle_raw=basis_bundle_raw,
        report_raw=report_raw,
    )
    output_directory.mkdir(mode=0o755, parents=False)
    try:
        for name, raw in (
            (STATEMENT_NAME, closeout_raw),
            (BASIS_NAME, basis_bundle_raw),
            (REPORT_NAME, report_raw),
            (MANIFEST_NAME, manifest_raw),
        ):
            _write_exclusive(output_directory, name, raw)
        descriptor = os.open(
            output_directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        raise
    return verify_closeout_release_package(
        release_root=output_directory,
        publication_bindings=publication_bindings,
        evidence_asset_root=evidence_asset_root,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )


def verify_closeout_release_package(
    *,
    release_root: Path,
    publication_bindings: PublicationBindings,
    evidence_asset_root: Path | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_key_fingerprint: str | None = None,
    expected_public_key_sha256: str | None = None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> VerifiedCloseoutPackage:
    """Independently re-hash and verify one extracted closeout asset set."""

    try:
        root_metadata = os.lstat(release_root)
    except OSError as error:
        raise CloseoutPackageError("closeout release root cannot be inspected") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise CloseoutPackageError("closeout release root is not a no-follow directory")
    statement_raw = _safe_read(release_root / STATEMENT_NAME, label="closeout statement")
    statement = _load_canonical(statement_raw, label="closeout statement")
    classification = statement.get("classification")
    if classification not in {"NO_ATTEMPT_EXPIRED", "LATE_PUBLICATION_INVALID"}:
        raise CloseoutPackageError("unsupported closeout classification")
    expected_names = {STATEMENT_NAME, BASIS_NAME, REPORT_NAME, MANIFEST_NAME}
    try:
        observed_names = set(os.listdir(release_root))
    except OSError as error:
        raise CloseoutPackageError("closeout release root is not a directory") from error
    if observed_names != expected_names:
        raise CloseoutPackageError("closeout release asset inventory differs")
    basis_bundle_raw = _safe_read(
        release_root / BASIS_NAME,
        label="closeout basis bundle",
    )
    basis_raw, _host_environment_raw, _audit_report_raw = _open_basis_bundle(
        basis_bundle_raw,
        closeout=statement,
    )
    report_raw = _safe_read(release_root / REPORT_NAME, label="closeout verifier report")
    manifest_raw = _safe_read(release_root / MANIFEST_NAME, label="closeout manifest")
    verified = _verify_closeout(
        statement_raw,
        basis_raw,
        publication_bindings=publication_bindings,
        evidence_asset_root=evidence_asset_root,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )
    report = _load_canonical(report_raw, label="closeout verifier report")
    expected_report = _report(
        verified,
        publication_bindings,
        verified_at=report.get("verifiedAt"),
    )
    if report_raw != expected_report:
        raise CloseoutPackageError("closeout verifier report differs")
    manifest = _load_canonical(manifest_raw, label="closeout manifest")
    expected_manifest = _manifest(
        classification=verified.classification,
        statement_raw=statement_raw,
        basis_bundle_raw=basis_bundle_raw,
        report_raw=report_raw,
    )
    if manifest_raw != expected_manifest:
        raise CloseoutPackageError("closeout manifest differs")
    if set(os.listdir(release_root)) != expected_names:
        raise CloseoutPackageError("closeout release changed during verification")
    return VerifiedCloseoutPackage(
        classification=verified.classification,
        closeout_sha256=verified.closeout_sha256,
        basis_sha256=verified.basis_sha256,
        basis_bundle_sha256=_sha256(basis_bundle_raw),
        report_sha256=_sha256(report_raw),
        manifest_sha256=_sha256(manifest_raw),
    )


def verify_published_closeout_release(
    *,
    release_root: Path,
    release_receipt_raw: bytes,
    publication_bindings: PublicationBindings,
    evidence_asset_root: Path | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_key_fingerprint: str | None = None,
    expected_public_key_sha256: str | None = None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> VerifiedPublishedCloseoutRelease:
    """Bind an offline package to the one preregistered signed publication.

    The closeout tag is required to target the exact commit and tree frozen in
    the design registration.  Callers cannot substitute a later source commit,
    deadline, tag, repository, or signing identity.
    """

    package = verify_closeout_release_package(
        release_root=release_root,
        publication_bindings=publication_bindings,
        evidence_asset_root=evidence_asset_root,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )
    try:
        release_receipt = verify_release_receipt(
            release_receipt_raw,
            release_root,
            expected_repository=EVIDENCE_REPOSITORY,
            expected_kind="closeout",
            expected_tag=CLOSEOUT_TAG,
            expected_commit=publication_bindings.closeout_source_commit,
            expected_tree=publication_bindings.closeout_source_tree,
            expected_deadline=CLOSEOUT_PUBLICATION_DEADLINE,
            expected_signature_type="SSH",
            expected_key_fingerprint=CLOSEOUT_SIGNING_KEY_FINGERPRINT,
            expected_public_key_sha256=CLOSEOUT_SIGNING_PUBLIC_KEY_SHA256,
            cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        )
    except ReleaseReceiptError as error:
        raise CloseoutPackageError(
            "signed closeout release receipt verification failed"
        ) from error

    # The generic receipt contract fixes semantic-role order but intentionally
    # permits arbitrary safe asset names.  This protocol additionally fixes the
    # four closeout filenames, so enforce the exact role/name pairing here.
    try:
        receipt_document = json.loads(
            release_receipt_raw.decode("utf-8", errors="strict")
        )
        role_names = tuple(
            (asset["role"], asset["name"])
            for asset in receipt_document["requiredAssets"]
        )
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise CloseoutPackageError(
            "closeout release receipt asset mapping is unreadable"
        ) from error
    if role_names != CLOSEOUT_RELEASE_ASSETS:
        raise CloseoutPackageError(
            "closeout release receipt role/name mapping differs"
        )

    statement = _load_canonical(
        _safe_read(release_root / STATEMENT_NAME, label="closeout statement"),
        label="closeout statement",
    )
    report = _load_canonical(
        _safe_read(release_root / REPORT_NAME, label="closeout verifier report"),
        label="closeout verifier report",
    )
    attested_at = _utc_datetime(
        release_receipt.attested_at,
        label="closeout release attestedAt",
    )
    if _utc_datetime(statement.get("classifiedAt"), label="classifiedAt") > attested_at:
        raise CloseoutPackageError("closeout release predates classification")
    if _utc_datetime(report.get("verifiedAt"), label="verifiedAt") > attested_at:
        raise CloseoutPackageError("closeout release predates offline verification")
    return VerifiedPublishedCloseoutRelease(
        package=package,
        release_receipt=release_receipt,
    )


def _bindings_from_args(
    args: argparse.Namespace,
    *,
    cryptographic_attestation_verifier: ReleaseAttestationCryptographicVerifier,
) -> PublicationBindings:
    design_raw = _safe_read(args.design_registration, label="design registration")
    design_receipt_raw = _safe_read(
        args.design_publication_receipt,
        label="design publication receipt",
    )
    snapshot_raw = _safe_read(
        args.snapshot_registration,
        label="snapshot registration",
    )
    snapshot_receipt_raw = _safe_read(
        args.snapshot_publication_receipt,
        label="snapshot publication receipt",
    )
    reservation_receipt_raw = _safe_read(
        args.reservation_publication_receipt,
        label="reservation publication receipt",
    )
    reservation_root = args.reservation_release_assets
    execution_reservation_raw = _safe_read(
        reservation_root / RESERVATION_ASSET_NAMES["execution-reservation"],
        label="execution reservation",
    )
    archived_snapshot_receipt_raw = _safe_read(
        reservation_root
        / RESERVATION_ASSET_NAMES["snapshot-publication-receipt"],
        label="reservation snapshot publication receipt",
    )
    reservation_manifest_raw = _safe_read(
        reservation_root / RESERVATION_ASSET_NAMES["sha256-manifest"],
        label="reservation release manifest",
    )
    if archived_snapshot_receipt_raw != snapshot_receipt_raw:
        raise CloseoutPackageError(
            "reservation package contains a different snapshot publication receipt"
        )
    bindings = PublicationBindings.from_exact_bytes(
        design_registration=design_raw,
        design_publication_receipt=design_receipt_raw,
        snapshot_registration=snapshot_raw,
        snapshot_publication_receipt=snapshot_receipt_raw,
        reservation_publication_receipt=reservation_receipt_raw,
        execution_reservation=execution_reservation_raw,
        reservation_release_manifest=reservation_manifest_raw,
    )
    try:
        reservation = verify_execution_reservation_package(
            reservation_root,
            design_raw=design_raw,
            snapshot_raw=snapshot_raw,
        )
    except ExecutionReservationError as error:
        raise CloseoutPackageError(
            "execution-reservation release assets failed verification"
        ) from error
    try:
        design = json.loads(design_raw.decode("utf-8", errors="strict"))
        release = design["reservationRelease"]
        verified_receipt = verify_release_receipt(
            reservation_receipt_raw,
            reservation_root,
            expected_repository=release["repository"],
            expected_kind="reservation",
            expected_tag=release["tag"],
            expected_commit=bindings.closeout_source_commit,
            expected_tree=bindings.closeout_source_tree,
            expected_deadline=release["publishNoLaterThan"],
            expected_signature_type=release["signatureType"],
            expected_key_fingerprint=release["signingKeyFingerprint"],
            expected_public_key_sha256=release["signingPublicKeySHA256"],
            cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        )
        receipt_document = json.loads(
            reservation_receipt_raw.decode("utf-8", errors="strict")
        )
        role_names = tuple(
            (item["role"], item["name"])
            for item in receipt_document["requiredAssets"]
        )
        expected_role_names = tuple(
            (role, RESERVATION_ASSET_NAMES[role])
            for role in RESERVATION_ASSET_NAMES
        )
        not_before = _utc_datetime(
            release["publishNotBefore"],
            label="reservation publishNotBefore",
        )
        deadline = _utc_datetime(
            release["publishNoLaterThan"],
            label="reservation publishNoLaterThan",
        )
        reserved_at = _utc_datetime(
            reservation["reservedAt"],
            label="reservation reservedAt",
        )
        published_at = _utc_datetime(
            verified_receipt.published_at,
            label="reservation publishedAt",
        )
        attested_at = _utc_datetime(
            verified_receipt.attested_at,
            label="reservation attestedAt",
        )
    except (
        KeyError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ReleaseReceiptError,
    ) as error:
        raise CloseoutPackageError(
            "signed execution-reservation publication failed verification"
        ) from error
    if (
        role_names != expected_role_names
        or release.get("requiredAssetRoles") != list(RESERVATION_ASSET_NAMES)
        or reservation["attemptId"] != bindings.reserved_attempt_id
        or verified_receipt.receipt_sha256
        != bindings.reservation_publication_receipt_sha256
        or reservation["reservationFileSHA256"]
        != bindings.execution_reservation_sha256
        or reservation["manifestFileSHA256"]
        != bindings.reservation_release_manifest_sha256
        or not not_before <= reserved_at <= published_at <= attested_at < deadline
    ):
        raise CloseoutPackageError(
            "execution-reservation publication binding or chronology differs"
        )
    return bindings


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--design-registration", type=Path, required=True)
    parser.add_argument("--design-publication-receipt", type=Path, required=True)
    parser.add_argument("--snapshot-registration", type=Path, required=True)
    parser.add_argument("--snapshot-publication-receipt", type=Path, required=True)
    parser.add_argument(
        "--reservation-publication-receipt",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--reservation-release-assets",
        type=Path,
        required=True,
    )
    parser.add_argument("--evidence-assets-dir", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--expected-key-fingerprint")
    parser.add_argument("--expected-public-key-sha256")
    parser.add_argument("--cosign", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package")
    _common_arguments(package)
    package.add_argument("--closeout", type=Path, required=True)
    package.add_argument("--basis", type=Path, required=True)
    package.add_argument("--host-environment", type=Path)
    package.add_argument("--audit-report", type=Path)
    package.add_argument("--verified-at")
    package.add_argument("--output-directory", type=Path, required=True)
    verify = commands.add_parser("verify")
    _common_arguments(verify)
    verify.add_argument("--release-root", type=Path, required=True)
    published = commands.add_parser("verify-published")
    _common_arguments(published)
    published.add_argument("--release-root", type=Path, required=True)
    published.add_argument("--release-receipt", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cryptographic_verifier = PinnedCosignReleaseAttestationVerifier(args.cosign)
        bindings = _bindings_from_args(
            args,
            cryptographic_attestation_verifier=cryptographic_verifier,
        )
        common = {
            "publication_bindings": bindings,
            "evidence_asset_root": args.evidence_assets_dir,
            "expected_commit": args.expected_commit,
            "expected_tree": args.expected_tree,
            "expected_key_fingerprint": args.expected_key_fingerprint,
            "expected_public_key_sha256": args.expected_public_key_sha256,
            "cryptographic_attestation_verifier": cryptographic_verifier,
        }
        if args.command == "package":
            result = package_closeout_release(
                closeout_path=args.closeout,
                basis_path=args.basis,
                output_directory=args.output_directory,
                verified_at=args.verified_at,
                host_environment_path=args.host_environment,
                audit_report_path=args.audit_report,
                **common,
            )
        elif args.command == "verify":
            result = verify_closeout_release_package(
                release_root=args.release_root,
                **common,
            )
        else:
            published_result = verify_published_closeout_release(
                release_root=args.release_root,
                release_receipt_raw=_safe_read(
                    args.release_receipt,
                    label="closeout release receipt",
                ),
                **common,
            )
            result = published_result.package
    except (CloseoutPackageError, ExperimentCloseoutError, OSError, ValueError):
        print("closeout package operation failed (fail-closed)", file=sys.stderr)
        return 2
    print(
        "closeout package verified: "
        f"classification={result.classification} "
        f"manifest_sha256={result.manifest_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CloseoutPackageError",
    "BASIS_NAME",
    "MANIFEST_NAME",
    "AUDIT_REPORT_NAME",
    "HOST_ENVIRONMENT_NAME",
    "LATE_PRIMARY_NAME",
    "NO_ATTEMPT_PRIMARY_NAME",
    "REPORT_NAME",
    "STATEMENT_NAME",
    "CLOSEOUT_RELEASE_ASSETS",
    "VerifiedCloseoutPackage",
    "VerifiedPublishedCloseoutRelease",
    "package_closeout_release",
    "verify_closeout_release_package",
    "verify_published_closeout_release",
]
